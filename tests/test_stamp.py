"""Behavioral tests for the authority timestamp (ADR-0032, issue #250).

`loxodonta stamp --authority URL` asks an RFC 3161 timestamp authority
for a token over the chain head and keeps the reply verbatim in its own
sidecar; the hook does the same at session end when `--stamp URL` is
wired, after the published head and before the anchor; `verify --stamps`
judges each token through openssl against the authority's chain file,
or says honestly that nobody judged it. It is not an anchor, and the
sidecar, the verb, the verdict and the messages never call it one.

Every test drives the public CLI against a fake authority on a free port
(the anchor suite's FakeCalendar pattern), the fake receiver and the fake
calendar where the order matters, and, where openssl is on PATH, an
authority the test makes with openssl itself: a key, a self-signed
certificate with the timestamping extended key usage, a `tsa` section,
and real tokens from `openssl ts -reply`. The DER reader below is written
here, independently of the recorder's encoder, so the request is checked
against RFC 3161 rather than against itself. No network, ever, and never
internals.
"""

import base64
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_stamp`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env
from test_publish import FakeReceiver, FakeReceiverHandler, PublishBase
from test_supervisor import (ago, chain_head, chains_by_session, keeper_env,
                             make_chain, run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"

SHA256_OID = "2.16.840.1.101.3.4.2.1"
QUERY_TYPE = "application/timestamp-query"
SIDECARS = (".anchors.jsonl", ".published.jsonl", ".stamps.jsonl")


def run_receipts(*args, cwd, env=None):
    return subprocess.run(
        [sys.executable, str(LOXODONTA), *args],
        cwd=cwd, capture_output=True, encoding="utf-8",
        env={**clean_env(), **(env or {})})


# --- An independent DER reader and writer (RFC 3161 §2.4) ---------------------

def der_read(data, at=0):
    """(tag, content, the offset after it) of the element at `at`."""
    tag, length = data[at], data[at + 1]
    at += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[at:at + size], "big")
        at += size
    return tag, data[at:at + length], at + length


def der_children(content):
    """The elements a constructed element holds, in order."""
    children, at = [], 0
    while at < len(content):
        tag, inner, at = der_read(content, at)
        children.append((tag, inner))
    return children


def der_int(content):
    return int.from_bytes(content, "big", signed=True)


def oid_bytes(dotted):
    """An OBJECT IDENTIFIER's content: the first two arcs folded into one
    byte, every later arc in base 128 with continuation bits."""
    arcs = [int(arc) for arc in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def parse_request(body):
    """The TimeStampReq fields of RFC 3161 §2.4.1, read here rather than
    by the recorder: exactly version, messageImprint, nonce and certReq,
    the imprint being an AlgorithmIdentifier and the hashed bytes."""
    tag, request, end = der_read(body)
    assert tag == 0x30 and end == len(body), "not one SEQUENCE"
    (v_tag, version), (i_tag, imprint), (n_tag, nonce), (c_tag, cert_req) \
        = der_children(request)
    (a_tag, algorithm), (h_tag, hashed) = der_children(imprint)
    (o_tag, oid), (p_tag, params) = der_children(algorithm)
    return {"tags": (v_tag, i_tag, n_tag, c_tag, a_tag, h_tag, o_tag, p_tag),
            "version": der_int(version), "oid": oid, "params": params,
            "hashed": hashed, "nonce": der_int(nonce), "cert_req": cert_req}


def der(tag, content):
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    size = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + length.to_bytes(size, "big") + content


def reply(status, token=b""):
    """A TimeStampResp: SEQUENCE { PKIStatusInfo SEQUENCE { INTEGER
    status }, then whatever token bytes follow }. The recorder reads the
    status and keeps the rest verbatim, so a placeholder token is a
    token as far as the wire is concerned."""
    return der(0x30, der(0x30, der(0x02, bytes([status]))) + token)


PLACEHOLDER_TOKEN = der(0x30, b"a placeholder token the recorder never reads")
GRANTED = reply(0, PLACEHOLDER_TOKEN)


# --- Fake authority -----------------------------------------------------------

class FakeAuthority(socketserver.ThreadingMixIn, FakeCalendar):
    """The calendar's server, made to answer each query on its own thread.
    A test that proves the recorder walks away from a slow authority has
    to out-wait the recorder by a wide margin — a narrow one is a CI
    flake, since the margin has to cover a whole interpreter start — and
    on one thread a `delay` that wide would also be a `delay` the
    teardown waits out. Daemon threads are left behind instead."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # a client that gave up on a slow reply is the point of one test


class FakeAuthorityHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep test output clean

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        server = self.server
        # What the world could see at the moment the query arrived: how
        # many heads the receiver had taken and how often the calendar
        # had been asked. The order test reads both.
        server.received.append({
            "path": self.path,
            "content_type": self.headers.get("Content-Type"),
            "body": body,
            "publishes_seen": (len(server.receiver.received)
                               if server.receiver is not None else None),
            "calendar_asks": (len(server.calendar.submitted)
                              if server.calendar is not None else None),
        })
        time.sleep(server.delay)  # a slow authority, when a test asks
        if server.status_code != 200:
            self.send_error(server.status_code)
            return
        answer = server.answer(body) if callable(server.answer) \
            else server.answer
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)


def start_authority(case, answer=GRANTED):
    """A fake authority on a free port, serving in a thread, closed when
    `case` finishes. `answer` is the reply bytes, or a callable given the
    query's bytes that returns them."""
    server = FakeAuthority(("127.0.0.1", 0), FakeAuthorityHandler)
    server.received = []
    server.answer = answer
    server.delay = 0
    server.status_code = 200
    server.receiver = None
    server.calendar = None
    server.url = f"http://127.0.0.1:{server.server_address[1]}/tsr"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


def rows_of(sidecar):
    if not sidecar.exists():
        return []
    return [json.loads(line) for line in
            sidecar.read_text(encoding="utf-8").splitlines()]


def token_rows(sidecar):
    return [row for row in rows_of(sidecar) if "response" in row]


def attempt_rows(sidecar):
    return [row for row in rows_of(sidecar) if row.get("kind") == "attempt"]


# --- The verb ----------------------------------------------------------------

class StampCommandTest(unittest.TestCase):
    """`loxodonta stamp --authority URL`: one query, one row; and the
    offline halves of `verify --stamps` that need no openssl."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.log = self.workdir / "receipts.jsonl"
        self.sidecar = self.workdir / "receipts.jsonl.stamps.jsonl"
        self.authority = start_authority(self)
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 2",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def stamp(self, url=None):
        return run_receipts("stamp", "--authority", url or self.authority.url,
                            cwd=self.workdir)

    def verify(self, *extra, env=None):
        return run_receipts("verify", "--stamps", *extra, cwd=self.workdir,
                            env=env)

    def test_stamp_asks_the_authority_and_writes_one_row(self):
        result = self.stamp()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(),
                         f"stamped head {self.head[:12]}… (entry 2) via "
                         f"{self.authority.url}")
        (query,) = self.authority.received
        self.assertEqual(query["content_type"], QUERY_TYPE)
        (row,) = rows_of(self.sidecar)
        self.assertEqual(set(row), {"head", "n", "ts", "authority", "response"})
        self.assertEqual(row["head"], self.head)
        self.assertEqual(row["n"], 2)
        self.assertEqual(row["authority"], self.authority.url)
        self.assertRegex(row["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        # The whole reply, verbatim: the placeholder token included and
        # untouched, since the recorder reads the status and nothing else.
        self.assertEqual(base64.b64decode(row["response"]), GRANTED)

    def test_the_query_is_the_timestamp_request_rfc_3161_describes(self):
        # ADR-0032 ruling 4, decoded here by the independent reader:
        # version 1, a sha256 imprint (with NULL parameters) over the
        # 32-byte head, a nonce, certReq true. Nothing else: no policy,
        # no extensions.
        self.stamp()

        (query,) = self.authority.received
        request = parse_request(query["body"])
        self.assertEqual(request["tags"],
                         (0x02, 0x30, 0x02, 0x01, 0x30, 0x04, 0x06, 0x05))
        self.assertEqual(request["version"], 1)
        self.assertEqual(request["oid"], oid_bytes(SHA256_OID))
        self.assertEqual(request["params"], b"")
        self.assertEqual(request["hashed"], bytes.fromhex(self.head))
        self.assertGreater(request["nonce"], 0)
        self.assertEqual(request["cert_req"], b"\xff")

    def test_every_query_carries_a_fresh_nonce(self):
        # Two heads, so two queries: the same head twice is the dedupe's
        # case below, not this one.
        self.stamp()
        run_receipts("log", "--actor", "agent", "--action", "step 3",
                     cwd=self.workdir)

        self.stamp()

        nonces = [parse_request(q["body"])["nonce"]
                  for q in self.authority.received]
        self.assertEqual(len(nonces), 2)
        self.assertNotEqual(nonces[0], nonces[1])
        self.assertEqual(len(token_rows(self.sidecar)), 2)

    def test_a_head_that_already_holds_a_token_is_not_asked_again(self):
        # The session-end step's rule, and the verb's for a sharper
        # reason: #251 puts `stamp` on the keeper's cadence, and a
        # cadence that asked again every tick would collect tokens for
        # one unchanged head all day. Nothing to do is exit 0.
        first = self.stamp()

        again = self.stamp()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(again.stdout.strip(),
                         f"already stamped head {self.head[:12]}… (entry 2)")
        self.assertEqual(len(self.authority.received), 1,
                         "the authority was asked about one head twice")
        self.assertEqual(len(token_rows(self.sidecar)), 1)
        self.assertEqual(attempt_rows(self.sidecar), [],
                         "nothing was tried, so nothing is written down")

    def test_a_new_head_is_stamped_although_the_old_one_holds_a_token(self):
        self.stamp()
        run_receipts("log", "--actor", "agent", "--action", "step 3",
                     cwd=self.workdir)
        newer = run_receipts("head", cwd=self.workdir).stdout.strip()

        result = self.stamp()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row["head"] for row in token_rows(self.sidecar)],
                         [self.head, newer])

    def test_a_token_that_cannot_be_written_is_not_a_granted_stamp(self):
        # A token the authority granted and this machine could not keep
        # is not a stamp. `granted` is an outcome the supervisor reads as
        # a head that left, so a full or read-only disk must never
        # produce it: the note names the write, and no token row exists
        # to back a claim the sidecar cannot hold.
        unwritable = self.workdir / "sealed"
        unwritable.mkdir()
        log = unwritable / "receipts.jsonl"
        run_receipts("init", "--log", str(log), cwd=self.workdir)
        run_receipts("log", "--log", str(log), "--actor", "agent",
                     "--action", "step 1", cwd=self.workdir)
        sidecar = unwritable / "receipts.jsonl.stamps.jsonl"
        # A directory where the sidecar's file belongs: every open for
        # append raises, on every platform, without touching permissions.
        sidecar.mkdir()

        result = run_receipts("stamp", "--log", str(log),
                              "--authority", self.authority.url,
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("the authority granted a token and it could not be "
                      "written", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(len(self.authority.received), 1)

    def test_a_reply_past_our_own_cap_says_whose_cap_it_is(self):
        # 64 KiB is this file's limit, not the authority's, and a token
        # with a long certificate chain could meet it. The line points
        # the operator here rather than at the token.
        self.authority.answer = reply(0, der(0x30, b"x" * (1 << 17)))

        result = self.stamp()

        self.assertEqual(result.returncode, 1)
        self.assertIn("the reply is larger than 64 KiB", result.stderr)
        self.assertNotIn("not a timestamp response", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertEqual(note["outcome"], "the reply is larger than 64 KiB")

    def test_granted_with_modifications_is_granted(self):
        # PKIStatus 1 comes with a token too (RFC 3161 §2.4.2).
        self.authority.answer = reply(1, PLACEHOLDER_TOKEN)

        result = self.stamp()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(token_rows(self.sidecar)), 1)

    def test_a_status_that_is_not_granted_is_an_error_and_no_row(self):
        self.authority.answer = reply(2)  # rejection, and no token

        result = self.stamp()

        self.assertEqual(result.returncode, 1)
        self.assertIn("the head was not stamped: the authority answered "
                      "status 2 (rejection)", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [],
                         "a refusal is nobody's word")
        (note,) = attempt_rows(self.sidecar)
        self.assertEqual(set(note), {"kind", "step", "ts", "budget", "outcome"})
        self.assertEqual(note["step"], "stamp")
        self.assertEqual(note["outcome"],
                         "the authority answered status 2 (rejection)")

    def test_a_reply_that_is_not_a_timestamp_response_is_named(self):
        self.authority.answer = b"<html>a captive portal, say</html>"

        result = self.stamp()

        self.assertEqual(result.returncode, 1)
        self.assertIn("not a timestamp response", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertIn("not a timestamp response", note["outcome"])

    def test_a_remote_that_answers_404_is_named_by_its_status(self):
        self.authority.status_code = 404

        result = self.stamp()

        self.assertEqual(result.returncode, 1)
        self.assertIn("the remote answered 404", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertEqual(note["outcome"], "the remote answered 404")

    def test_an_unreachable_authority_fails_cleanly(self):
        result = self.stamp("http://127.0.0.1:9/tsr")  # discard port

        self.assertEqual(result.returncode, 1)
        self.assertIn("not stamped", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertEqual(note["step"], "stamp")
        self.assertAlmostEqual(note["budget"], 15, delta=0.1)
        self.assertNotIn("127.0.0.1",
                         self.sidecar.read_text(encoding="utf-8"))

    def test_an_authority_that_is_not_http_is_a_usage_error(self):
        result = self.stamp("file:///tmp/tokens")

        self.assertEqual(result.returncode, 64)
        self.assertIn("--authority", result.stderr)
        self.assertFalse(self.sidecar.exists())

    def test_verify_stamps_with_no_sidecar_says_so(self):
        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NO-STAMPS", result.stdout)
        self.assertIn("VALID", result.stdout)

    def test_without_a_chain_file_the_token_is_present_not_judged(self):
        # ADR-0032 ruling 5, ADR-0026's posture: a note, never a verdict,
        # and the exit code stays the chain's.
        self.stamp()

        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("stamp not judged: no --authority-chain FILE given",
                      result.stdout)
        self.assertIn(f"head {self.head[:12]}… (entry 2)", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^VALID$")
        self.assertNotIn("STAMPED", result.stdout)
        self.assertNotIn("STAMP-INVALID", result.stdout)

    def test_a_chain_file_without_stamps_is_a_usage_error(self):
        # ADR-0032 ruling 5 exists to stop a verdict that sounds like the
        # tokens passed. An operator who names a chain file named it to
        # have them judged; ignoring the flag would answer `VALID` with
        # nothing judged, so the command is told it was spoken wrong.
        self.stamp()
        chain_file = self.workdir / "authority.pem"
        chain_file.write_text("not read: the flag is refused first\n",
                              encoding="utf-8")

        result = run_receipts("verify", "--authority-chain", str(chain_file),
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 64, result.stdout)
        self.assertIn("--authority-chain", result.stderr)
        self.assertIn("--stamps", result.stderr)
        self.assertNotIn("VALID", result.stdout)

    def test_a_chain_file_that_is_not_there_is_named_not_judged(self):
        self.stamp()

        result = self.verify("--authority-chain", "nowhere.pem")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("stamp not judged: --authority-chain nowhere.pem not "
                      "found", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^VALID$")

    def test_without_openssl_the_token_is_present_not_judged(self):
        # The same posture as the package-sign suite's for ssh-keygen: a
        # machine without the tool is told so, and the token is neither
        # earned nor failed. The child gets a PATH with nothing on it.
        self.stamp()
        chain_file = self.workdir / "authority.pem"
        chain_file.write_text("not read: openssl is not there to read it\n",
                              encoding="utf-8")
        nowhere = self.workdir / "empty-path"
        nowhere.mkdir()

        result = self.verify("--authority-chain", str(chain_file),
                             env={"PATH": str(nowhere)})

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("stamp not judged: openssl is not on PATH", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^VALID$")

    def test_verify_never_asks_the_authority(self):
        self.stamp()
        chain_file = self.workdir / "authority.pem"
        chain_file.write_text("not a certificate\n", encoding="utf-8")

        self.verify()
        self.verify("--authority-chain", str(chain_file))

        self.assertEqual(len(self.authority.received), 1,
                         "verify fetched something")

    def test_a_row_whose_head_is_not_in_the_chain_is_stamp_invalid_exit_3(self):
        # The regeneration signature, judged offline and without openssl:
        # a stamped head that appears nowhere in the chain means this is
        # not the stamped history, beside ANCHOR-MISMATCH's tier.
        self.stamp()
        self.log.unlink()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "innocent step",
                     cwd=self.workdir)

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("STAMP-INVALID", result.stdout)
        self.assertIn("appears nowhere in this log", result.stdout)
        self.assertNotRegex(result.stdout, r"(?m)^VALID$")

    def test_a_malformed_row_is_stamp_invalid_not_a_crash(self):
        self.sidecar.write_text(
            json.dumps({"n": 2, "ts": "2026-09-17T07:00:00Z"}) + "\n"
            + json.dumps({"head": self.head, "n": 2, "authority": "x",
                          "ts": "2026-09-17T07:00:00Z",
                          "response": "not base64!"}) + "\n",
            encoding="utf-8")

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("STAMP-INVALID: sidecar line is not a stamp record",
                      result.stdout)
        self.assertIn("the response is not base64", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_sidecar_of_attempt_rows_only_verifies_as_an_empty_one(self):
        # #240: an attempt row is a note on how a session-end step went,
        # never evidence for or against the chain.
        self.sidecar.write_text("", encoding="utf-8")
        empty = self.verify()
        self.sidecar.write_text(json.dumps({
            "kind": "attempt", "step": "stamp", "ts": "2026-09-17T07:00:00Z",
            "budget": 3.0, "outcome": "no answer within 3 seconds"}) + "\n",
            encoding="utf-8")

        noted = self.verify()

        self.assertEqual(empty.returncode, 0, empty.stdout + empty.stderr)
        self.assertEqual((noted.returncode, noted.stdout, noted.stderr),
                         (empty.returncode, empty.stdout, empty.stderr))

    def test_the_vocabulary_says_stamp_and_never_anchor(self):
        # ADR-0032 ruling 1: the mechanisms never share a word.
        self.stamp()
        self.authority.answer = reply(2)
        refused = self.stamp()
        judged = self.verify()

        for text in (refused.stderr, judged.stdout,
                     self.sidecar.read_text(encoding="utf-8")):
            self.assertNotIn("anchor", text.lower())
        self.assertNotIn("anchor", self.sidecar.name)


# --- Who waits for the reply's body ------------------------------------------

class SlowBodyHandler(BaseHTTPRequestHandler):
    """A remote that answers at once and then dawdles over its body: the
    status line and the headers go out immediately, the body `delay`
    seconds later. Real ones exist (a proxy that buffers, a service that
    streams its own bookkeeping), and the two POSTs this file makes want
    opposite things from one."""

    def log_message(self, *args):
        pass  # keep test output clean

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.received.append(time.monotonic())
        body = self.server.body
        self.send_response(200)
        self.send_header("Content-Type", self.server.content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.flush()
        time.sleep(self.server.delay)
        self.wfile.write(body)


def start_slow_body(case, body, content_type):
    server = FakeAuthority(("127.0.0.1", 0), SlowBodyHandler)
    server.received = []
    server.body = body
    server.content_type = content_type
    server.delay = 20
    server.url = f"http://127.0.0.1:{server.server_address[1]}/slow"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class ReplyBodyTest(unittest.TestCase):
    """The head publish is done when the status line arrives: its body is
    a chat service's bookkeeping nobody here reads, and waiting for one
    would let a remote that took the head be written down as a remote
    that never answered. The stamp is the opposite, because the body is
    the token. One parameter, `want_reply`, and this is the test that
    holds the two apart."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)

    def test_the_head_publish_returns_on_the_status_not_the_body(self):
        remote = start_slow_body(self, b"ok", "application/json")

        started = time.monotonic()
        result = run_receipts("publish", remote.url, cwd=self.workdir)
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("published head", result.stdout)
        self.assertLess(elapsed, remote.delay,
                        "the publish waited for a body it never reads")
        self.assertEqual(len(remote.received), 1)
        memo = self.workdir / "receipts.jsonl.published.jsonl"
        (row,) = [r for r in rows_of(memo) if r.get("kind") != "attempt"]
        self.assertEqual(row["head"],
                         run_receipts("head", cwd=self.workdir).stdout.strip())

    def test_the_stamp_waits_for_the_body_because_it_is_the_token(self):
        remote = start_slow_body(self, GRANTED, "application/timestamp-reply")

        started = time.monotonic()
        result = run_receipts("stamp", "--authority", remote.url,
                              cwd=self.workdir)
        elapsed = time.monotonic() - started

        # 15 seconds is the verb's own bound, well under the 20 the
        # remote sits on: it waited, and then gave up on its own clock.
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("no answer within 15 seconds", result.stderr)
        self.assertGreater(elapsed, 5, "the stamp did not wait for the token")
        self.assertFalse(
            (self.workdir / "receipts.jsonl.stamps.jsonl").exists()
            and token_rows(self.workdir / "receipts.jsonl.stamps.jsonl"),
            "no token arrived, so no token row")


# --- The session-end step ----------------------------------------------------

class StampAwareReceiverHandler(FakeReceiverHandler):
    """The fake receiver, also noting how many queries the authority had
    taken when each head arrived."""

    def do_POST(self):
        stamps = len(self.server.authority.received)
        super().do_POST()
        self.server.received[-1]["stamps_seen"] = stamps


class StampAwareCalendarHandler(FakeCalendarHandler):
    """The fake calendar, also noting how many heads the receiver and
    how many queries the authority had taken when each digest arrived."""

    def do_POST(self):
        self.server.seen_before.append(
            (len(self.server.receiver.received),
             len(self.server.authority.received)))
        super().do_POST()


class SessionEndStampTest(PublishBase):
    """`hook --stamp URL`: at SessionEnd, one query of the sealed head,
    after the published head and the published chain and before the
    anchor, quiet and best-effort, written down either way (#240). The
    whole run of five is here too, since this is where the servers can
    all watch each other."""

    def setUp(self):
        super().setUp()
        self.authority = start_authority(self)
        self.receiver = self.serve(FakeReceiver, StampAwareReceiverHandler)
        self.receiver.received = []
        self.receiver.delay = 0
        self.receiver.authority = self.authority
        self.receiver.url = (
            f"http://127.0.0.1:{self.receiver.server_address[1]}/hook")
        self.authority.receiver = self.receiver

    def chain(self):
        """The session's one chain, its three sidecars set aside."""
        found = [p for p in (self.store / "receipts").rglob(
                     f"receipts-{self.SESSION}*.jsonl")
                 if not p.name.endswith(SIDECARS)]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def stamps(self):
        return self.chain().with_name(self.chain().name + ".stamps.jsonl")

    def watched_calendar(self):
        calendar = self.serve(FakeCalendar, StampAwareCalendarHandler)
        calendar.nonce = b"fake-nonce"
        calendar.mode = "pending"
        calendar.submitted = []
        calendar.polled = []
        calendar.seen_before = []
        calendar.receiver = self.receiver
        calendar.authority = self.authority
        calendar.url = f"http://127.0.0.1:{calendar.server_address[1]}"
        self.receiver.calendar = calendar
        self.authority.calendar = calendar
        return calendar

    def test_session_end_with_stamp_writes_the_row_and_the_attempt_row(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--stamp", self.authority.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")  # quiet
        (query,) = self.authority.received
        self.assertEqual(query["content_type"], QUERY_TYPE)
        (row,) = token_rows(self.stamps())
        self.assertEqual(row["head"], self.head())
        self.assertEqual(row["authority"], self.authority.url)
        self.assertEqual(base64.b64decode(row["response"]), GRANTED)
        (note,) = attempt_rows(self.stamps())
        self.assertEqual(set(note), {"kind", "step", "ts", "budget", "outcome"})
        self.assertEqual(note["step"], "stamp")
        self.assertEqual(note["outcome"], "granted")
        self.assertAlmostEqual(note["budget"], 3, delta=0.1)

    def test_a_refused_query_leaves_an_attempt_row_and_no_token_row(self):
        self.authority.answer = reply(2)
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--stamp", self.authority.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(token_rows(self.stamps()), [])
        (note,) = attempt_rows(self.stamps())
        self.assertEqual(note["step"], "stamp")
        self.assertEqual(note["outcome"],
                         "the authority answered status 2 (rejection)")

    def test_an_authority_that_never_answers_is_abandoned_on_the_hooks_clock(self):
        # The one query has a bounded timeout well inside the budget, and
        # the anchor takes what is left: an authority that sits on the
        # request is left behind, the calendar is still asked, and the
        # abandonment is the outcome the sidecar records (#240).
        calendar = self.watched_calendar()
        self.authority.delay = 20  # seconds; far past the three the hook waits
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        started = time.monotonic()
        result = self.session_end("--stamp", self.authority.url,
                                  "--anchor", "--calendar", calendar.url)
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertLess(elapsed, self.authority.delay)
        self.assertEqual(len(self.authority.received), 1)
        self.assertEqual([d.hex() for d in calendar.submitted], [self.head()])
        self.assertEqual(token_rows(self.stamps()), [])
        (note,) = attempt_rows(self.stamps())
        self.assertEqual(note["outcome"], "no answer within 3 seconds")

    def test_a_codex_hook_waits_half_of_codexs_cap(self):
        # The same budget rule as the head publish (#183): a Codex hook
        # cuts its POST off at 1.5 seconds, and the row says so.
        self.authority.delay = 20
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        started = time.monotonic()
        result = self.session_end("--actor", "codex",
                                  "--stamp", self.authority.url)
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, self.authority.delay)
        (note,) = attempt_rows(self.stamps())
        self.assertEqual(note["outcome"], "no answer within 1.5 seconds")
        self.assertAlmostEqual(note["budget"], 1.5, delta=0.1)

    def test_an_unreachable_authority_is_quiet_and_the_row_names_no_url(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        closed = "http://127.0.0.1:9/tsr"  # discard port: nothing listens

        started = time.monotonic()
        result = self.session_end("--stamp", closed)

        self.assertLess(time.monotonic() - started, 12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(token_rows(self.stamps()), [])
        (note,) = attempt_rows(self.stamps())
        self.assertEqual(note["step"], "stamp")
        self.assertNotEqual(note["outcome"], "granted")
        self.assertNotIn("127.0.0.1", self.stamps().read_text("utf-8"))

    def test_order_is_commitment_then_head_then_stamp_then_anchor(self):
        # ADR-0032 ruling 3: the fast POSTs before the slow calendar. The
        # head arrives at the receiver before any query; the query
        # arrives at the authority after the one head and before any
        # digest; the calendar is asked last. And every one of them
        # carries the sealed head.
        calendar = self.watched_calendar()
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.receiver.chain = self.chain()

        result = self.session_end("--publish", self.receiver.url,
                                  "--stamp", self.authority.url,
                                  "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        (published,) = self.receiver.received
        self.assertEqual((published["stamps_seen"], published["calendar_asks"]),
                         (0, 0))
        tail = json.loads(published["chain_tail"])
        self.assertTrue(tail["action"].startswith("transcript-commitment:"),
                        tail)
        (query,) = self.authority.received
        self.assertEqual((query["publishes_seen"], query["calendar_asks"]),
                         (1, 0))
        self.assertEqual(calendar.seen_before, [(1, 1)])
        sealed = tail["entry_hash"]
        self.assertEqual(self.body()["head"], sealed)
        self.assertEqual(parse_request(query["body"])["hashed"],
                         bytes.fromhex(sealed))
        self.assertEqual([d.hex() for d in calendar.submitted], [sealed])
        (row,) = token_rows(self.stamps())
        self.assertEqual(row["head"], sealed)

    def test_the_five_steps_run_in_order_and_the_anchor_keeps_its_slice(self):
        # ADR-0031 beside ADR-0032, the whole session end at once:
        # commitment, publish head, publish chain, stamp, anchor. Each
        # arrival says what had already happened, so the order is read
        # off the servers rather than off the code, and the anchor's own
        # attempt row says how much of the twelve seconds three POSTs
        # before it had left.
        calendar = self.watched_calendar()
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.receiver.chain = self.chain()

        result = self.session_end("--publish", self.receiver.url,
                                  "--publish-chain", self.receiver.url,
                                  "--stamp", self.authority.url,
                                  "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")   # quiet, every step of it
        head, batch = self.receiver.received
        self.assertEqual(head["content_type"], "application/json")
        self.assertEqual(batch["content_type"], "application/x-ndjson")
        # Neither publish waited on the stamp or on the calendar.
        self.assertEqual([(sent["stamps_seen"], sent["calendar_asks"])
                          for sent in (head, batch)], [(0, 0), (0, 0)])
        # The batch ends in the seal, so the commitment came first, and
        # what the remote holds is the chain as it sits on disk.
        sealed = json.loads(batch["chain_tail"])
        self.assertTrue(sealed["action"].startswith("transcript-commitment:"),
                        sealed)
        self.assertEqual(batch["raw"], self.chain().read_bytes())
        # The query came after both publishes and before any digest.
        (query,) = self.authority.received
        self.assertEqual((query["publishes_seen"], query["calendar_asks"]),
                         (2, 0))
        # And the calendar last of all, of the same sealed head.
        self.assertEqual(calendar.seen_before, [(2, 1)])
        self.assertEqual([d.hex() for d in calendar.submitted],
                         [sealed["entry_hash"]])
        self.assertEqual(self.body()["head"], sealed["entry_hash"])
        (row,) = token_rows(self.stamps())
        self.assertEqual(row["head"], sealed["entry_hash"])
        # Three POSTs ahead of it, and the anchor still has a workable
        # slice of the budget: each of the three is capped at three
        # seconds, and none of them spent it.
        anchors = self.chain().with_name(self.chain().name + ".anchors.jsonl")
        (note,) = attempt_rows(anchors)
        self.assertEqual((note["step"], note["outcome"]),
                         ("anchor", "submitted"))
        self.assertGreater(note["budget"], 6.0,
                           "three quick POSTs must not eat the anchor's "
                           "share of the twelve seconds")

    def test_an_already_stamped_head_is_not_stamped_twice(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.session_end("--stamp", self.authority.url)

        self.session_end("--stamp", self.authority.url)

        self.assertEqual(len(self.authority.received), 1)
        self.assertEqual(len(token_rows(self.stamps())), 1)
        # Nothing was tried the second time, so nothing is written down.
        self.assertEqual(len(attempt_rows(self.stamps())), 1)

    def test_a_sidecar_that_cannot_be_written_keeps_the_hook_quiet(self):
        # The other half of the write-failure ruling. A token granted and
        # not kept is not a stamp, so `stamp_head` replaces `granted`
        # with the write's own outcome; what is portable to assert
        # through the CLI is the rest of the promise: the hook stays
        # quiet, exits 0, and nothing in the drawer says this head left.
        # The wording itself is asserted on the verb, which can report
        # it on stderr (StampCommandTest above), because a sidecar that
        # refuses the token row refuses the note beside it too.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.stamps().mkdir()  # a directory where the sidecar's file goes

        result = self.session_end("--stamp", self.authority.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(self.authority.received), 1)
        self.assertTrue(self.stamps().is_dir(), "the sidecar was replaced")
        # The sidecar itself is the directory this test made, and it
        # ends in .jsonl like the files beside it.
        self.assertNotIn("granted", "".join(
            p.read_text(encoding="utf-8")
            for p in self.chain().parent.glob("*.jsonl")
            if p.is_file()))

    def test_a_session_without_receipts_stamps_nothing(self):
        result = self.session_end("--stamp", self.authority.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.authority.received, [])


# --- Judged through openssl --------------------------------------------------

REQ_CONFIG = """[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = loxodonta test authority
[ tsa_cert ]
extendedKeyUsage = critical,timeStamping
"""
TSA_CONFIG = """[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
serial = serial
signer_cert = tsa.crt
signer_key = tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
"""


def missing_authority_tooling():
    """Why the judged cases cannot run on this machine, or None when they
    can. The posture is the package-sign suite's for a missing
    `ssh-keygen`: a tool the machine does not have is said out loud, and
    nothing about the recorder is guessed from its absence. An `openssl`
    that is present but has no working `ts` subcommand is the same case,
    since what is missing is still the tool, so the whole round trip is
    tried once here — a key and a self-signed timestamping certificate,
    a query, a reply, and a verdict on the reply — rather than met later
    as a fixture failure that would read as a verdict about the
    recorder."""
    if shutil.which("openssl") is None:
        return "openssl is not on PATH"
    digest = "11" * 32
    steps = (("req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", "tsa.key", "-out", "tsa.crt", "-days", "2",
              "-config", "req.cnf", "-extensions", "tsa_cert"),
             ("ts", "-query", "-digest", digest, "-sha256", "-cert",
              "-out", "trial.tsq"),
             ("ts", "-reply", "-queryfile", "trial.tsq", "-config",
              "tsa.cnf", "-out", "trial.tsr"),
             ("ts", "-verify", "-digest", digest, "-sha256", "-in",
              "trial.tsr", "-CAfile", "tsa.crt"))
    with tempfile.TemporaryDirectory() as scratch:
        (Path(scratch) / "req.cnf").write_text(REQ_CONFIG, "utf-8")
        (Path(scratch) / "tsa.cnf").write_text(TSA_CONFIG, "utf-8")
        for step in steps:
            tried = subprocess.run(["openssl", *step], cwd=scratch,
                                   capture_output=True, encoding="utf-8",
                                   errors="replace")
            if tried.returncode != 0:
                said = tried.stderr.strip().splitlines()
                return (f"this openssl cannot run `openssl {step[0]} "
                        f"{step[1]}`" + (f": {said[-1]}" if said else ""))
    return None


# Tried once for the whole module: four openssl runs, against ten minutes
# of suite.
MISSING_AUTHORITY_TOOLING = missing_authority_tooling()


@unittest.skipIf(MISSING_AUTHORITY_TOOLING,
                 f"{MISSING_AUTHORITY_TOOLING}; the authority timestamp is "
                 "judged by openssl, and this suite's authority is made by it")
class JudgedStampTest(unittest.TestCase):
    """`verify --stamps --authority-chain FILE` with a real token: an
    authority made here with openssl (a key, a self-signed certificate
    with the timestamping extended key usage, a `tsa` section) answers
    the recorder's own queries through `openssl ts -reply`, and the
    recorder judges what came back through `openssl ts -verify`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.sidecar = self.workdir / "receipts.jsonl.stamps.jsonl"
        self.authority_dir = self.workdir / "authority"
        self.authority_dir.mkdir()
        (self.authority_dir / "req.cnf").write_text(REQ_CONFIG, "utf-8")
        (self.authority_dir / "tsa.cnf").write_text(TSA_CONFIG, "utf-8")
        self.chain_file = self.authority_dir / "tsa.crt"
        made = self.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", "tsa.key", "-out", "tsa.crt",
                            "-days", "2", "-config", "req.cnf",
                            "-extensions", "tsa_cert")
        self.assertEqual(made.returncode, 0, made.stderr)
        self.queries = 0
        self.authority = start_authority(self, answer=self.sign)
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 2",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def openssl(self, *args):
        return subprocess.run(["openssl", *args], cwd=str(self.authority_dir),
                              capture_output=True, encoding="utf-8",
                              errors="replace")

    def sign(self, query):
        """What a real authority does with the recorder's query: answer
        it with `openssl ts -reply` under the test authority's key."""
        self.queries += 1
        name = f"query-{self.queries}"
        (self.authority_dir / f"{name}.tsq").write_bytes(query)
        answered = self.openssl("ts", "-reply", "-queryfile", f"{name}.tsq",
                                "-config", "tsa.cnf", "-out", f"{name}.tsr")
        assert answered.returncode == 0, answered.stderr
        return (self.authority_dir / f"{name}.tsr").read_bytes()

    def stamp(self):
        result = run_receipts("stamp", "--authority", self.authority.url,
                              cwd=self.workdir)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def verify(self, *extra):
        return run_receipts("verify", "--stamps", "--authority-chain",
                            str(self.chain_file), *extra, cwd=self.workdir)

    def rewrite_row(self, **changes):
        (row,) = rows_of(self.sidecar)
        row.update(changes)
        self.sidecar.write_text(json.dumps(row) + "\n", encoding="utf-8")

    def test_a_token_the_authority_issued_is_stamped_and_the_chain_valid(self):
        self.stamp()

        result = self.verify()

        out = result.stdout
        self.assertEqual(result.returncode, 0, out + result.stderr)
        self.assertIn(f"STAMPED: entries 0..2 existed when "
                      f"{self.authority.url} signed this head", out)
        self.assertIn(str(self.chain_file), out)
        self.assertRegex(out, r"(?m)^VALID$")
        self.assertNotIn("not judged", out)
        self.assertNotIn("STAMP-INVALID", out)
        self.assertNotIn("anchor", out.lower())

    def test_a_tampered_token_is_stamp_invalid_exit_3(self):
        self.stamp()
        (row,) = rows_of(self.sidecar)
        response = bytearray(base64.b64decode(row["response"]))
        response[-40] ^= 0x01  # one bit, inside the signature
        self.rewrite_row(response=base64.b64encode(bytes(response)).decode())

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("STAMP-INVALID", result.stdout)
        self.assertIn("evidence that does not verify is not evidence",
                      result.stdout)
        self.assertNotRegex(result.stdout, r"(?m)^VALID$")
        self.assertNotIn("Traceback", result.stderr)

    def test_a_token_over_another_head_in_the_chain_is_stamp_invalid(self):
        # The row's head is in the chain, but the token's imprint is not
        # that head: openssl says so, and the verdict is the same tier.
        self.stamp()
        run_receipts("log", "--actor", "agent", "--action", "step 3",
                     cwd=self.workdir)
        newer = run_receipts("head", cwd=self.workdir).stdout.strip()
        self.rewrite_row(head=newer, n=3)

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn(f"STAMP-INVALID: head {newer[:12]}… (entry 3)",
                      result.stdout)
        self.assertNotRegex(result.stdout, r"(?m)^VALID$")

    def test_a_token_from_an_authority_the_chain_file_does_not_name_is_invalid(self):
        # The chain file is whom the operator trusts: a token signed by
        # anyone else does not verify against it.
        self.stamp()
        stranger = self.workdir / "stranger"
        stranger.mkdir()
        (stranger / "req.cnf").write_text(REQ_CONFIG, "utf-8")
        made = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", "tsa.key", "-out", "tsa.crt", "-days", "2",
             "-config", "req.cnf", "-extensions", "tsa_cert"],
            cwd=str(stranger), capture_output=True, encoding="utf-8",
            errors="replace")
        self.assertEqual(made.returncode, 0, made.stderr)

        result = run_receipts("verify", "--stamps", "--authority-chain",
                              str(stranger / "tsa.crt"), cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("STAMP-INVALID", result.stdout)

    def test_without_the_chain_file_even_a_real_token_is_not_judged(self):
        self.stamp()

        result = run_receipts("verify", "--stamps", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("stamp not judged: no --authority-chain FILE given",
                      result.stdout)
        self.assertRegex(result.stdout, r"(?m)^VALID$")

    def test_the_stored_reply_is_what_the_authority_sent(self):
        # Verbatim: the bytes in the sidecar are the bytes openssl wrote,
        # so any reader with openssl can print the time the token states.
        self.stamp()

        (row,) = rows_of(self.sidecar)
        sent = (self.authority_dir / "query-1.tsr").read_bytes()
        self.assertEqual(base64.b64decode(row["response"]), sent)
        shown = self.openssl("ts", "-reply", "-in", "query-1.tsr", "-text")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("Status: Granted.", shown.stdout)
        self.assertIn("Time stamp:", shown.stdout)


# --- The installer ------------------------------------------------------------

class InstallAuthorityTest(unittest.TestCase):
    """`install-hook --authority URL` writes `--stamp URL` onto the wired
    SessionEnd command, the way `--publish-head` writes `--publish`, and
    the coverage marker's epoch records the authority; `uninstall-hook`
    removes it. In this release the flag lives under `custom`."""

    URL = "https://authority.example.test/tsr"
    WEBHOOK = "https://hooks.example.test/services/T000/B000/XXXX"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = self.root / "store"
        self.env = {"HOME": str(self.home), "USERPROFILE": str(self.home),
                    "LOXODONTA_HOME": str(self.store),
                    "CODEX_HOME": str(self.home / ".codex")}

    def install(self, *args):
        return run_receipts("install-hook", *args, cwd=self.root,
                            env=self.env)

    def settings(self):
        return json.loads((self.home / ".claude" / "settings.json")
                          .read_text(encoding="utf-8"))

    def commands(self, event):
        return [h["command"] for b in self.settings()["hooks"][event]
                for h in b["hooks"]]

    def codex_commands(self, event):
        settings = json.loads((self.home / ".codex" / "hooks.json")
                              .read_text(encoding="utf-8"))
        return [h["command"] for b in settings["hooks"][event]
                for h in b["hooks"]]

    def epochs(self):
        return json.loads((self.store / "coverage.json")
                          .read_text(encoding="utf-8"))["epochs"]

    def test_the_authority_rides_on_the_session_end_command(self):
        result = self.install("--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(f' --stamp "{self.URL}"'), end)
        self.assertNotIn("--stamp", json.dumps(self.commands("PostToolUse")))
        self.assertIn(f"stamps the head with {self.URL}", result.stdout)
        (epoch,) = self.epochs()
        self.assertEqual(epoch["profile"], "custom")
        self.assertEqual(epoch["authority"], self.URL)

    def test_profile_custom_names_the_authority_and_a_rerun_appends_nothing(self):
        result = self.install("--profile", "custom", "--authority", self.URL)
        self.assertEqual(result.returncode, 0, result.stderr)

        again = self.install("--profile", "custom", "--authority", self.URL)

        self.assertIn("already installed", again.stdout)
        self.assertEqual(len(self.commands("SessionEnd")), 1)
        self.assertEqual(len(self.epochs()), 1)

    def test_a_rerun_without_the_flag_turns_stamping_off_and_says_so(self):
        self.install("--authority", self.URL)

        result = self.install()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--stamp", json.dumps(self.settings()["hooks"]))
        self.assertNotIn(self.URL, json.dumps(self.settings()["hooks"]))
        self.assertIn("no longer stamps the head", result.stdout)
        self.assertEqual([e.get("authority") for e in self.epochs()],
                         [self.URL, None])

    def test_all_three_opt_ins_ride_on_the_one_command(self):
        result = self.install("--anchor-at-session-end",
                              "--publish-head", self.WEBHOOK,
                              "--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(f' --anchor --publish "{self.WEBHOOK}"'
                                     f' --stamp "{self.URL}"'), end)
        self.assertIn("anchors at session end", result.stdout)
        self.assertIn(self.WEBHOOK, result.stdout)
        self.assertIn(self.URL, result.stdout)

    def test_the_flag_composes_with_the_timestamped_tier(self):
        # ADR-0032 ruling 2: the authority is the one raw flag a tier
        # takes beside its own, because a tier can name the mechanism and
        # never the authority. The tier's anchor and the stamp ride on
        # the one command, and the marker records both.
        result = self.install("--profile", "timestamped",
                              "--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(f' --anchor --stamp "{self.URL}"'), end)
        self.assertIn("anchors at session end", result.stdout)
        self.assertIn(f"stamps the head with {self.URL}", result.stdout)
        (epoch,) = self.epochs()
        self.assertEqual(epoch["profile"], "timestamped")
        self.assertEqual(epoch["authority"], self.URL)

    def test_the_flag_is_refused_beside_local_where_nothing_leaves(self):
        # `local` is the tier that sends nothing at all, so an authority
        # beside it is a command spoken wrong, and the way out is named.
        result = self.install("--profile", "local", "--authority", self.URL)

        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("--profile custom", result.stderr)
        self.assertFalse((self.home / ".claude" / "settings.json").exists())

    def test_another_raw_flag_beside_the_tier_is_still_refused(self):
        # Only the authority composes: the tier already says what else
        # leaves the machine (ADR-0031 ruling 1).
        result = self.install("--profile", "timestamped",
                              "--publish-head", self.WEBHOOK,
                              "--authority", self.URL)

        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("--profile custom", result.stderr)
        self.assertFalse((self.home / ".claude" / "settings.json").exists())

    def test_a_tier_rerun_without_the_flag_turns_stamping_off(self):
        # The install command states the choice each time, at a tier as
        # under `custom` (ADR-0025 ruling 3).
        self.install("--profile", "timestamped", "--authority", self.URL)

        result = self.install("--profile", "timestamped")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.URL, json.dumps(self.settings()["hooks"]))
        self.assertIn("no longer stamps the head", result.stdout)
        self.assertEqual([e.get("authority") for e in self.epochs()],
                         [self.URL, None])

    def test_the_installer_refuses_a_url_a_shell_could_act_on(self):
        for bad in ("file:///tmp/tokens", "authority.example.test/tsr",
                    "https://a.example.test/$(id)"):
            result = self.install("--authority", bad)
            self.assertEqual(result.returncode, 64, bad + ": " + result.stderr)
            self.assertIn("--authority", result.stderr)
            self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                             bad)

    def test_codex_gets_the_flag_now_that_the_post_is_measured(self):
        # PRD #244 held the flag back until the stamp's one POST had
        # been measured inside Codex's three-second cap, as #183
        # measured the head. It has been (#251, docs/HOOK.md): the hook
        # cuts the POST off at half the cap, so the flag is wired here
        # like the two publishes.
        (self.home / ".codex").mkdir(exist_ok=True)

        result = self.install("--codex", "--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.codex_commands("SessionEnd")
        self.assertTrue(end.endswith(f' --stamp "{self.URL}"'), end)
        self.assertIn("--actor codex", end)
        self.assertIn(f"stamps the head with {self.URL}", result.stdout)
        (epoch,) = self.epochs()
        self.assertEqual(epoch["harness"], "codex")
        self.assertEqual(epoch["authority"], self.URL)

    def test_codex_at_the_tier_stamps_and_still_leaves_the_anchor_alone(self):
        # The session-end anchor stays refused on Codex (ADR-0024), so
        # the tier's other half is the supervisor's cadence; the stamp
        # is wired all the same, and the notice says which is which.
        (self.home / ".codex").mkdir(exist_ok=True)

        result = self.install("--codex", "--profile", "timestamped",
                              "--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.codex_commands("SessionEnd")
        self.assertNotIn("--anchor", end)
        self.assertTrue(end.endswith(f' --stamp "{self.URL}"'), end)
        self.assertIn("the session-end anchor stays refused for Codex",
                      result.stdout)

    def test_uninstall_removes_the_stamping_session_end_hook(self):
        self.install("--authority", self.URL)

        result = run_receipts("uninstall-hook", cwd=self.root, env=self.env)

        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.home / ".claude" / "settings.json"
        left = path.read_text(encoding="utf-8") if path.exists() else "{}"
        self.assertNotIn("loxodonta.py", left)
        self.assertNotIn(self.URL, left)


# --- The supervisor reads the sidecar ------------------------------------------

class ScanStampTest(unittest.TestCase):
    """The stamps sidecar sits beside the chain like the other two: the
    census never mistakes it for a chain, `left` reads a token as a head
    that left by the third door, and `last_failed` reads its attempt
    rows (#240)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()

    def write_rows(self, log, rows):
        with open(str(log) + ".stamps.jsonl", "a", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps(row) + "\n")

    def test_the_sidecar_is_not_a_chain_and_its_rows_are_read(self):
        stamped = make_chain(self.root / "alpha" / "receipts", "sess-stamped")
        left_at = ago(60)
        self.write_rows(stamped, [
            {"head": chain_head(stamped), "n": 2, "ts": left_at,
             "authority": "https://authority.example.test/tsr",
             "response": base64.b64encode(GRANTED).decode()},
            {"kind": "attempt", "step": "stamp", "ts": left_at, "budget": 3.0,
             "outcome": "granted"}])
        refused = make_chain(self.root / "alpha" / "receipts", "sess-refused")
        refused_at = ago(30)
        self.write_rows(refused, [
            {"kind": "attempt", "step": "stamp", "ts": refused_at,
             "budget": 3.0,
             "outcome": "the authority answered status 2 (rejection)"}])

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        self.assertEqual({s for _, s in sessions},
                         {"sess-stamped", "sess-refused"})
        (chain,) = sessions[("alpha", "sess-stamped")]
        self.assertEqual(chain["left"], {"ts": left_at, "via": "stamped"})
        self.assertIsNone(chain["last_failed"])
        (chain,) = sessions[("alpha", "sess-refused")]
        self.assertEqual(chain["left"], {"ts": None, "via": None})
        self.assertEqual(chain["last_failed"],
                         {"step": "stamp", "ts": refused_at,
                          "outcome": "the authority answered status 2 "
                                     "(rejection)"})


if __name__ == "__main__":
    unittest.main()
