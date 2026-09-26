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
and real tokens from `openssl ts -reply`; one dated to the second with
`openssl ca` stands for an authority whose certificate ran out (#264).
The DER reader below is written here, independently of the recorder's
encoder, so the request is checked against RFC 3161 rather than against
itself. No network, ever, and never internals.
"""

import base64
import json
import math
import os
import re
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
from types import SimpleNamespace

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_stamp`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import (HOSTILE, HOSTILE_HEAD, SHOWN, SHOWN_HEAD,
                         FakeCalendar, FakeCalendarHandler,
                         assert_printed_escaped, clean_env)
from test_publish import FakeReceiver, FakeReceiverHandler, PublishBase
from test_supervisor import (ago, chain_head, chains_by_session,
                             home_outside, isolated_env, make_chain,
                             run_scan)

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

# The `response` of a token row holding no reply the authority granted
# (#366): not a string, not base64, base64 of bytes that are not a
# TimeStampResp, and base64 of a reply the authority refused. None of
# them stamps the head it names.
NO_GRANTED_REPLY = (
    5, None, "not base64!",
    base64.b64encode(b"no timestamp response").decode(),
    base64.b64encode(reply(2)).decode(),
)
# A granted reply in seven bytes, made by nobody: status 0, and no token.
FORGED_GRANTED = base64.b64encode(reply(0)).decode()


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
        self.assertEqual(set(row), {"kind", "head", "n", "ts", "authority",
                                    "response"})
        self.assertEqual(row["kind"], "stamp")
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

        self.assertEqual(result.returncode, 73, result.stdout)
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

        self.assertEqual(result.returncode, 69)
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

        self.assertEqual(result.returncode, 69)
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

        self.assertEqual(result.returncode, 69)
        self.assertIn("not a timestamp response", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertIn("not a timestamp response", note["outcome"])

    def test_a_remote_that_answers_404_is_named_by_its_status(self):
        self.authority.status_code = 404

        result = self.stamp()

        self.assertEqual(result.returncode, 69)
        self.assertIn("the remote answered 404", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertEqual(note["outcome"], "the remote answered 404")

    def test_an_unreachable_authority_fails_cleanly(self):
        result = self.stamp("http://127.0.0.1:9/tsr")  # discard port

        self.assertEqual(result.returncode, 69)
        self.assertIn("not stamped", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(token_rows(self.sidecar), [])
        (note,) = attempt_rows(self.sidecar)
        self.assertEqual(note["step"], "stamp")
        # The budget is rounded to a tenth, and a tenth short of the target
        # differs by a hair over 0.1 in floating point: allow 0.15.
        self.assertAlmostEqual(note["budget"], 15, delta=0.15)
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


class StampRowKindTest(unittest.TestCase):
    """ADR-0038: every row of the stamps sidecar names its kind. A new
    token row is written `"kind": "stamp"`; a row with no kind reads as a
    token, whenever it was written, so every sidecar already shipped
    verifies as it did; and a row of a kind this verifier does not know,
    or a kind that belongs in another sidecar, is named by its line and
    never judged, so a newer recorder's row is never evidence against an
    honest log. None of it needs openssl: with no chain file given, a
    token is present and not judged, which is the same line for a
    kind-less row as for a named one."""

    UNKNOWN = "STAMP-UNKNOWN-KIND"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.sidecar = self.workdir / "receipts.jsonl.stamps.jsonl"
        self.authority = start_authority(self)
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def token_row(self, **extra):
        """A token row over the head, as the recorder writes one, keys
        sorted and compact; `extra` adds fields (a kind) or replaces them."""
        row = {"head": self.head, "n": 1, "ts": "2026-09-24T10:00:00Z",
               "authority": self.authority.url,
               "response": base64.b64encode(GRANTED).decode()}
        row.update(extra)
        return json.dumps(row, sort_keys=True, separators=(",", ":"))

    def write_sidecar(self, *lines):
        self.sidecar.write_text("".join(line + "\n" for line in lines),
                                encoding="utf-8")

    def stamp(self):
        return run_receipts("stamp", "--authority", self.authority.url,
                            cwd=self.workdir)

    def verify(self):
        return run_receipts("verify", "--stamps", cwd=self.workdir)

    def without_notes(self, stdout):
        return [line for line in stdout.splitlines()
                if not line.startswith(self.UNKNOWN)]

    def test_a_new_stamp_row_names_its_kind_and_nothing_else_changes(self):
        result = self.stamp()
        self.assertEqual(result.returncode, 0, result.stderr)

        lines = self.sidecar.read_text("utf-8").splitlines()
        (line,) = [l for l in lines if '"kind":"attempt"' not in l]
        row = json.loads(line)
        self.assertEqual(row["kind"], "stamp")
        self.assertEqual(set(row),
                         {"kind", "head", "n", "ts", "authority", "response"})
        # Written compact and key-sorted, as every sidecar row is.
        self.assertEqual(line, json.dumps(row, sort_keys=True,
                                          separators=(",", ":")))

    def test_a_row_with_no_kind_reads_as_a_stamp(self):
        self.write_sidecar(self.token_row())
        kindless = self.verify()
        self.write_sidecar(self.token_row(kind="stamp"))
        named = self.verify()

        self.assertEqual(kindless.returncode, 0,
                         kindless.stdout + kindless.stderr)
        self.assertIn("stamp not judged: no --authority-chain FILE given",
                      kindless.stdout)
        self.assertRegex(kindless.stdout, r"(?m)^VALID$")
        self.assertEqual((named.returncode, named.stdout, named.stderr),
                         (kindless.returncode, kindless.stdout,
                          kindless.stderr))

    def test_a_kindless_row_for_another_head_is_still_stamp_invalid(self):
        self.write_sidecar(self.token_row(head="ab" * 32))

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("STAMP-INVALID: stamped head", result.stdout)
        self.assertIn("appears nowhere in this log", result.stdout)

    def test_an_unknown_kind_is_named_by_its_line_and_not_judged(self):
        self.write_sidecar(self.token_row())
        before = self.verify()
        # Shaped like a token over another head: judged, it would be
        # STAMP-INVALID, exit 3.
        self.write_sidecar(self.token_row(),
                           self.token_row(kind="witness-note",
                                          head="ab" * 32))

        result = self.verify()

        self.assertEqual(result.returncode, before.returncode,
                         result.stdout + result.stderr)
        self.assertIn(f'{self.UNKNOWN}: line 2 of {self.sidecar.name} is of '
                      'kind "witness-note" — this verifier does not know the '
                      'kind in this sidecar, and does not judge it',
                      result.stdout)
        self.assertEqual(result.stdout.count(self.UNKNOWN), 1)
        self.assertNotIn("STAMP-INVALID", result.stdout)
        self.assertEqual(self.without_notes(result.stdout),
                         before.stdout.splitlines())

    def test_a_head_or_anchor_row_in_the_stamps_sidecar_is_named_not_judged(self):
        # Known kinds, but the memo's and the anchors sidecar's
        # (ADR-0038), not this sidecar's.
        for line, kind in ((1, "head"), (2, "anchor")):
            with self.subTest(kind=kind):
                misplaced = self.token_row(kind=kind, head="ab" * 32)
                rows = [self.token_row()]
                rows.insert(line - 1, misplaced)
                self.write_sidecar(*rows)

                result = self.verify()

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn(f'{self.UNKNOWN}: line {line} of '
                              f'{self.sidecar.name} is of kind "{kind}"',
                              result.stdout)
                self.assertIn("stamp not judged", result.stdout)
                self.assertNotIn("STAMP-INVALID", result.stdout)
                self.assertRegex(result.stdout, r"(?m)^VALID$")

    def test_an_unknown_kind_leaves_an_exit_3_as_it_was(self):
        # Beside evidence against the log, the note moves nothing: the
        # exit is 3, and the last line is still the finding's, which is
        # where the supervisor's scan reads a verdict.
        mismatch = self.token_row(head="ab" * 32)
        self.write_sidecar(mismatch)
        before = self.verify()
        self.write_sidecar(mismatch, json.dumps({"kind": "later-kind"}))

        result = self.verify()

        self.assertEqual(before.returncode, 3, before.stdout + before.stderr)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1],
                         before.stdout.splitlines()[-1])
        self.assertIn(f"{self.UNKNOWN}: line 2 of", result.stdout)

    def test_a_kind_that_is_not_a_string_is_named_by_its_type(self):
        for kind, word in ((5, "a number"), (None, "null"),
                           (True, "true or false"), (["stamp"], "an array"),
                           ({"k": "stamp"}, "an object")):
            with self.subTest(kind=kind):
                self.write_sidecar(self.token_row(),
                                   json.dumps({"kind": kind}))

                result = self.verify()

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn(f"{self.UNKNOWN}: line 2 of {self.sidecar.name} "
                              f"is of a kind that is {word}, not a string — "
                              "this verifier does not know the kind in this "
                              "sidecar, and does not judge it", result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_a_kind_is_printed_escaped_never_raw(self):
        # The kind is the writer's text, printed to a terminal: a newline
        # in it could forge a verdict line, an escape repaint the screen.
        self.write_sidecar(self.token_row(),
                           json.dumps({"kind": "x\x1b[2J\nVALID‮"}))

        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('is of kind "x\\x1b[2J\\nVALID\\u202e"', result.stdout)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("‮", result.stdout)
        self.assertEqual(result.stdout.splitlines().count("VALID"), 1)

    def test_an_unreadable_line_is_still_stamp_invalid(self):
        too_long = '{"kind": ' + "9" * 5000 + "}"
        too_deep = '{"kind": ' + "[" * 100000 + "]" * 100000 + "}"
        for line in ("not a record", "[1, 2]", too_long, too_deep):
            with self.subTest(line=line[:20]):
                self.write_sidecar(self.token_row(), line)

                result = self.verify()

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertIn("STAMP-INVALID: sidecar line is not a stamp "
                              "record", result.stdout)
                self.assertNotIn(self.UNKNOWN, result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_a_line_that_is_not_utf8_is_still_stamp_invalid(self):
        self.sidecar.write_bytes(self.token_row().encode() + b"\n"
                                 + b'{"kind": "\xff"}\n')

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("STAMP-INVALID: sidecar line is not a stamp record",
                      result.stdout)

    def test_a_kindless_or_a_named_token_row_is_already_stamped(self):
        # The dedupe asks the reader too: a token row from before rows
        # named their kind holds the head exactly as a named one does, so
        # neither sends a second query.
        for row in (self.token_row(), self.token_row(kind="stamp")):
            with self.subTest(row=row[:30]):
                self.write_sidecar(row)

                result = self.stamp()

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(),
                                 f"already stamped head {self.head[:12]}… "
                                 "(entry 1)")
                self.assertEqual(self.authority.received, [])
                self.assertEqual(self.sidecar.read_text("utf-8"), row + "\n")

    def test_a_token_row_whose_head_is_not_a_string_does_not_stop_the_verb(self):
        # A writer-reachable row, so it must not crash the dedupe: it
        # names no head, holds no token, and the head is asked about.
        malformed = json.dumps({"head": ["x"], "response": "AA=="})
        self.write_sidecar(malformed)

        result = self.stamp()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(len(self.authority.received), 1)
        rows = rows_of(self.sidecar)
        self.assertEqual(rows[0], json.loads(malformed))
        self.assertEqual((rows[1]["head"], rows[1]["kind"]),
                         (self.head, "stamp"))

    def test_a_row_holding_no_granted_reply_is_not_the_heads_token(self):
        # #366: a row naming the head and holding no granted reply is
        # not its token. Only a reply whose status says granted stamps a
        # head, read as the query reads it, so for each of these the
        # verb still asks, and writes the token it is granted.
        for response in NO_GRANTED_REPLY:
            with self.subTest(response=response):
                self.authority.received.clear()
                planted = self.token_row(response=response)
                self.write_sidecar(planted)

                result = self.stamp()

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(),
                                 f"stamped head {self.head[:12]}… (entry 1) "
                                 f"via {self.authority.url}")
                self.assertEqual(len(self.authority.received), 1)
                rows = rows_of(self.sidecar)
                self.assertEqual(rows[0], json.loads(planted))
                self.assertEqual(
                    (rows[1]["head"], rows[1]["kind"],
                     base64.b64decode(rows[1]["response"])),
                    (self.head, "stamp", GRANTED))

    def test_the_limit_a_forged_or_copied_granted_reply_stops_a_new_stamp(self):
        # #366, the limit SPEC 9.7 names, pinned so it stays visible: a
        # granted status is not signed, so a reply forged in seven bytes,
        # or a real one copied from another head's row, is taken for the
        # head's token and nothing is asked. Without openssl verify says
        # the token is not judged, never that it is stamped.
        first = self.stamp()
        self.assertEqual(first.returncode, 0, first.stderr)
        (token,) = [r for r in rows_of(self.sidecar)
                    if r.get("kind") == "stamp"]
        run_receipts("log", "--actor", "agent", "--action", "step 2",
                     cwd=self.workdir)
        newer = run_receipts("head", cwd=self.workdir).stdout.strip()
        for name, response in (("forged", FORGED_GRANTED),
                               ("copied", token["response"])):
            with self.subTest(row=name):
                self.authority.received.clear()
                self.write_sidecar(self.token_row(head=newer, n=2,
                                                  response=response))

                result = self.stamp()
                judged = self.verify()

                self.assertEqual(result.stdout.strip(),
                                 f"already stamped head {newer[:12]}… "
                                 "(entry 2)")
                self.assertEqual(self.authority.received, [])
                self.assertEqual(judged.returncode, 0,
                                 judged.stdout + judged.stderr)
                self.assertIn("stamp not judged: no --authority-chain FILE "
                              "given", judged.stdout)
                self.assertNotIn("STAMPED", judged.stdout)

    def test_a_row_of_an_unknown_kind_naming_the_head_is_not_its_token(self):
        # Only a token stamps a head. A row of a kind the recorder does
        # not know is not one, whatever head it names, so the verb still
        # asks, and the new row says it is a stamp.
        foreign = self.token_row(kind="witness-note")
        self.write_sidecar(foreign)

        result = self.stamp()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.authority.received), 1)
        rows = rows_of(self.sidecar)
        self.assertEqual(rows[0], json.loads(foreign))
        self.assertEqual((rows[1]["head"], rows[1]["kind"]),
                         (self.head, "stamp"))


class StampFieldEscapeTest(unittest.TestCase):
    """#349: a field of a stamp row that `verify --stamps` prints is the
    writer's text, and is printed escaped (#295). The row's authority is
    printed only beside a token openssl accepted, so that one is
    JudgedStampTest's. The fixture is StampRowKindTest's."""

    setUp = StampRowKindTest.setUp
    token_row = StampRowKindTest.token_row
    write_sidecar = StampRowKindTest.write_sidecar
    verify = StampRowKindTest.verify

    def test_a_head_that_appears_nowhere_prints_escaped(self):
        self.write_sidecar(self.token_row(head=HOSTILE_HEAD))

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        assert_printed_escaped(self, result.stdout,
                               f"STAMP-INVALID: stamped head {SHOWN_HEAD} "
                               "appears nowhere in this log")

    def test_no_sidecar_is_named_by_its_bare_name(self):
        log = self.workdir / "receipts.jsonl"

        result = run_receipts("verify", "--stamps", "--log", str(log),
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NO-STAMPS: receipts.jsonl.stamps.jsonl not found — ",
                      result.stdout)
        self.assertNotIn(str(self.workdir), result.stdout)


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
        self.assertEqual(result.returncode, 69, result.stdout)
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
        # The budget is rounded to a tenth, and a tenth short of the target
        # differs by a hair over 0.1 in floating point: allow 0.15.
        self.assertAlmostEqual(note["budget"], 3, delta=0.15)

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

    def test_a_malformed_stamps_row_leaves_the_stamp_and_the_anchor_working(self):
        # A row whose head is not a string sits in a file the writer can
        # reach. The dedupe skips it, so the session end still stamps the
        # sealed head and still reaches the anchor after it.
        calendar = self.watched_calendar()
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        malformed = {"head": ["x"], "response": "AA=="}
        self.stamps().write_text(json.dumps(malformed) + "\n", "utf-8")

        result = self.session_end("--stamp", self.authority.url,
                                  "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(self.authority.received), 1)
        self.assertEqual([d.hex() for d in calendar.submitted], [self.head()])
        rows = rows_of(self.stamps())
        self.assertEqual(rows[0], malformed)
        (token,) = [r for r in rows if r.get("kind") == "stamp"]
        self.assertEqual(token["head"], self.head())
        (note,) = attempt_rows(self.stamps())
        self.assertEqual(note["outcome"], "granted")

    def test_a_row_holding_no_granted_reply_does_not_skip_the_stamp(self):
        # #366: a row naming the sealed head with no granted reply in it
        # is no token, so the session end still asks, and keeps the token.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        # The commitment the session end seals comes first, and that
        # entry is the head the planted row must name.
        self.session_end()
        head = self.head()
        for response in NO_GRANTED_REPLY:
            with self.subTest(response=response):
                self.authority.received.clear()
                planted = {"kind": "stamp", "head": head,
                           "response": response}
                self.stamps().write_text(json.dumps(planted) + "\n", "utf-8")

                result = self.session_end("--stamp", self.authority.url)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(len(self.authority.received), 1)
                rows = rows_of(self.stamps())
                self.assertEqual(rows[0], planted)
                (token,) = [r for r in rows[1:] if r.get("kind") == "stamp"]
                self.assertEqual((token["head"], self.head()), (head, head))
                (note,) = attempt_rows(self.stamps())
                self.assertEqual(note["outcome"], "granted")

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
        # The row says what the session-end window had left when the
        # step began, to a tenth, and a busy machine spends a tenth
        # before it: the wording holds the same tolerance the budget does.
        self.assertRegex(note["outcome"],
                         r"^no answer within 1\.[456] seconds$")
        # The budget is rounded to a tenth, and a tenth short of the target
        # differs by a hair over 0.1 in floating point: allow 0.15.
        self.assertAlmostEqual(note["budget"], 1.5, delta=0.15)

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
        # What openssl checked, and the name as what it is: the key the
        # chain file certifies is the signer, and the record's URL is the
        # writer's note of whom it asked (ADR-0008 ruling 4's rule).
        self.assertIn(f"STAMPED: entries 0..2 existed when a key certified "
                      f"by {self.chain_file} signed this head under its own "
                      f"clock (the record names {self.authority.url}, "
                      "testimony)", out)
        self.assertNotIn(f"{self.authority.url} signed", out)
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

    def test_the_limit_a_forged_or_copied_reply_stops_a_new_stamp(self):
        # #366, the limit SPEC 9.7 names: a reply's status sits outside
        # the token's signature, so a forged granted status, or a real
        # token moved to another head, is taken for the head's token and
        # no query is sent. With openssl and the chain file, verify calls
        # either one STAMP-INVALID, never STAMPED.
        self.stamp()
        run_receipts("log", "--actor", "agent", "--action", "step 3",
                     cwd=self.workdir)
        newer = run_receipts("head", cwd=self.workdir).stdout.strip()
        (row,) = rows_of(self.sidecar)
        for name, response in (("forged", FORGED_GRANTED),
                               ("copied", row["response"])):
            with self.subTest(row=name):
                self.sidecar.write_text(json.dumps(
                    {**row, "head": newer, "n": 3, "response": response})
                    + "\n", encoding="utf-8")
                asked = self.queries

                again = self.stamp()
                judged = self.verify()

                self.assertEqual(again.stdout.strip(),
                                 f"already stamped head {newer[:12]}… "
                                 "(entry 3)")
                self.assertEqual(self.queries, asked)
                self.assertEqual(judged.returncode, 3,
                                 judged.stdout + judged.stderr)
                self.assertIn(f"STAMP-INVALID: head {newer[:12]}… (entry 3)",
                              judged.stdout)
                self.assertNotIn("STAMPED", judged.stdout)

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

    def test_the_authority_a_row_names_prints_escaped(self):
        # #349: the name is the writer's note, printed as testimony, and
        # escaped like every other field of the row.
        self.stamp()
        self.rewrite_row(authority=HOSTILE)

        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        assert_printed_escaped(self, result.stdout,
                               f"(the record names {SHOWN}, testimony)")
        self.assertEqual(result.stdout.splitlines()[-1], "VALID")

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


# --- Judged after the authority's certificate expired (#264) ------------------

# `openssl ca` dates a certificate to the second: `-startdate` and
# `-enddate` are as old as the command, where `x509 -not_after` is
# OpenSSL 3.4 and later and CI's Ubuntu runners carry 3.0. `-selfsign`
# keeps the shape of the authority above, one self-signed certificate
# that is its own chain file; the database and the serial file are the
# bookkeeping `ca` insists on.
CA_CONFIG = """[ ca ]
default_ca = dated
[ dated ]
database = index.txt
new_certs_dir = .
serial = ca-serial
default_md = sha256
policy = any_name
unique_subject = no
[ any_name ]
commonName = supplied
[ tsa_cert ]
extendedKeyUsage = critical,timeStamping
"""
# Seconds a short-lived certificate stays in date: room for one stamp to
# finish inside it on a slow runner (under a second and a half here),
# and short enough that waiting it out costs the class a few seconds,
# once. The package suite's fixture does more inside the life and has a
# longer one of its own.
CERTIFICATE_LIFE = 4


def openssl_in(folder, *args):
    return subprocess.run(["openssl", *args], cwd=str(folder),
                          capture_output=True, encoding="utf-8",
                          errors="replace")


def openssl_date(epoch):
    """A moment as `openssl ca -startdate` and `-enddate` read it."""
    return time.strftime("%y%m%d%H%M%SZ", time.gmtime(epoch))


def openssl_print_time(epoch):
    """A moment as `openssl ts -reply -text` prints a token's time."""
    return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(epoch))


def with_status_text(reply, text):
    """The same TimeStampResp with `text` as its PKIStatusInfo's
    statusString (RFC 3161 §2.4.2): the words around the token, which
    nobody signed, so a writer can set them to anything without touching
    a byte the authority's signature covers."""
    _, response, _ = der_read(reply)
    (_, info), *token = der_children(response)
    (status_tag, status), *_ = der_children(info)
    free_text = der(0x30, der(0x0C, text.encode("utf-8")))
    return der(0x30, der(0x30, der(status_tag, status) + free_text)
               + b"".join(der(tag, content) for tag, content in token))


def dated_authority(folder, name, starts, ends):
    """An authority of its own, made here with openssl in `folder`, whose
    certificate is in date from `starts` to `ends` seconds either side
    of the moment it is signed, rounded up to the next whole second so
    the part of a second already gone never shortens a short life. The
    key is made first, so a slow key costs that life nothing either. The
    subject carries `name`, as two real authorities' subjects differ, so
    one chain file can hold two of them. Returns (the certificate, which
    is also the chain file a recipient saves, and the epoch second it
    expires)."""
    folder.mkdir()
    subject = REQ_CONFIG.replace("CN = loxodonta test authority",
                                 f"CN = loxodonta test authority {name}")
    for file_name, text in (("req.cnf", subject), ("ca.cnf", CA_CONFIG),
                            ("tsa.cnf", TSA_CONFIG), ("index.txt", ""),
                            ("ca-serial", "01\n")):
        (folder / file_name).write_text(text, "utf-8")
    keyed = openssl_in(folder, "req", "-new", "-newkey", "rsa:2048",
                       "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr",
                       "-config", "req.cnf")
    assert keyed.returncode == 0, keyed.stderr
    signed_at = math.ceil(time.time())
    made = openssl_in(folder, "ca", "-selfsign", "-batch", "-notext",
                      "-config", "ca.cnf", "-keyfile", "tsa.key",
                      "-in", "tsa.csr", "-out", "tsa.crt",
                      "-startdate", openssl_date(signed_at + starts),
                      "-enddate", openssl_date(signed_at + ends),
                      "-extensions", "tsa_cert")
    assert made.returncode == 0, made.stderr
    return folder / "tsa.crt", signed_at + ends


def answering(folder):
    """What a real authority does with a query, as a fake authority's
    `answer`: `openssl ts -reply` under the key made in `folder`."""
    answered = []

    def sign(query):
        stem = f"query-{len(answered) + 1}"
        (folder / f"{stem}.tsq").write_bytes(query)
        replied = openssl_in(folder, "ts", "-reply", "-queryfile",
                             f"{stem}.tsq", "-config", "tsa.cnf",
                             "-out", f"{stem}.tsr")
        assert replied.returncode == 0, replied.stderr
        answered.append(stem)
        return (folder / f"{stem}.tsr").read_bytes()

    return sign


def openssl_without_attime(folder):
    """A stand-in openssl in `folder` (created here) that hides -attime
    from `ts -help` and refuses it the way OpenSSL 3 refuses an option
    it lacks, handing everything else to the real one. Returns a PATH
    with it first. POSIX only: a script needs a shebang."""
    real = shutil.which("openssl")
    folder.mkdir()
    script = folder / "openssl"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, subprocess, sys\n"
        f"REAL = {real!r}\n"
        "args = sys.argv[1:]\n"
        'if args[:1] == ["ts"] and "-help" in args:\n'
        "    shown = subprocess.run([REAL] + args, capture_output=True,\n"
        "                           text=True)\n"
        "    for stream, text in ((sys.stdout, shown.stdout),\n"
        "                         (sys.stderr, shown.stderr)):\n"
        '        stream.write("".join(line for line in\n'
        "                             text.splitlines(True)\n"
        '                             if "-attime" not in line))\n'
        "    sys.exit(shown.returncode)\n"
        'if "-attime" in args:\n'
        '    print("ts: Unknown option: -attime", file=sys.stderr)\n'
        '    print("ts: Use -help for summary.", file=sys.stderr)\n'
        "    sys.exit(1)\n"
        "os.execv(REAL, [REAL] + args)\n", encoding="utf-8")
    script.chmod(0o755)
    return str(folder) + os.pathsep + os.environ.get("PATH", "")


def outlive(expires):
    """Wait out a certificate's life, with a second to spare. openssl
    counts a certificate expired from the very second of its end date,
    so the spare second is margin for a clock read a moment apart, not
    a second the certificate is still in date."""
    time.sleep(max(0.0, expires + 1 - time.time()))


def missing_expiry_tooling():
    """Why the cases below cannot run here, or None when they can: all
    the judged cases need, and an openssl that dates a certificate with
    `ca -selfsign -startdate -enddate` and judges a token as of a given
    moment with `ts -verify -attime`. Tried once as a round trip, in
    missing_authority_tooling's posture: a tool the machine lacks is
    said out loud, and never met later as a failure that would read as
    a verdict about the recorder."""
    if MISSING_AUTHORITY_TOOLING:
        return MISSING_AUTHORITY_TOOLING
    digest = "11" * 32
    now = int(time.time())
    steps = (("req -new", ("req", "-new", "-newkey", "rsa:2048", "-nodes",
                           "-keyout", "tsa.key", "-out", "tsa.csr",
                           "-config", "req.cnf")),
             ("ca -selfsign -startdate -enddate",
              ("ca", "-selfsign", "-batch", "-notext", "-config", "ca.cnf",
               "-keyfile", "tsa.key", "-in", "tsa.csr", "-out", "tsa.crt",
               "-startdate", openssl_date(now - 3600),
               "-enddate", openssl_date(now + 3600),
               "-extensions", "tsa_cert")),
             ("ts -query", ("ts", "-query", "-digest", digest, "-sha256",
                            "-cert", "-out", "trial.tsq")),
             ("ts -reply", ("ts", "-reply", "-queryfile", "trial.tsq",
                            "-config", "tsa.cnf", "-out", "trial.tsr")),
             ("ts -verify -attime", ("ts", "-verify", "-digest", digest,
                                     "-sha256", "-in", "trial.tsr",
                                     "-CAfile", "tsa.crt",
                                     "-attime", str(now))))
    with tempfile.TemporaryDirectory() as scratch:
        for file_name, text in (("req.cnf", REQ_CONFIG), ("ca.cnf", CA_CONFIG),
                                ("tsa.cnf", TSA_CONFIG), ("index.txt", ""),
                                ("ca-serial", "01\n")):
            (Path(scratch) / file_name).write_text(text, "utf-8")
        for label, step in steps:
            tried = openssl_in(scratch, *step)
            if tried.returncode != 0:
                said = tried.stderr.strip().splitlines()
                return (f"this openssl cannot run `openssl {label}`"
                        + (f": {said[-1]}" if said else ""))
    return None


MISSING_EXPIRY_TOOLING = missing_expiry_tooling()


@unittest.skipIf(MISSING_EXPIRY_TOOLING,
                 f"{MISSING_EXPIRY_TOOLING}; the authority timestamp is "
                 "judged by openssl, and this suite's authority is made by it")
class OutlivedCertificateTest(unittest.TestCase):
    """#264: `verify --stamps` once the authority's certificate has
    expired. openssl checks a chain as of the moment it verifies, so a
    genuine token fails on the calendar alone; the recorder says it was
    not judged and why, and a token that fails for any other reason is
    STAMP-INVALID as before.

    One chain is stamped in setUpClass by an authority whose certificate
    expires CERTIFICATE_LIFE seconds after it is made, and the class
    waits that out once; each test judges its own copy of the chain."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        root = Path(cls._tmp.name).resolve()
        cls.stamped = root / "stamped"
        cls.stamped.mkdir()
        run_receipts("init", cwd=cls.stamped)
        for step in ("step 1", "step 2"):
            run_receipts("log", "--actor", "agent", "--action", step,
                         cwd=cls.stamped)
        cls.head = run_receipts("head", cwd=cls.stamped).stdout.strip()
        cls.chain_file, expires = dated_authority(
            root / "authority", "short-lived", -3600, CERTIFICATE_LIFE)
        # start_authority closes its server when the case it is given
        # finishes; for a class, that is when the class does.
        authority = start_authority(
            SimpleNamespace(addCleanup=cls.addClassCleanup),
            answer=answering(root / "authority"))
        stamped = run_receipts("stamp", "--authority", authority.url,
                               cwd=cls.stamped)
        assert stamped.returncode == 0, stamped.stdout + stamped.stderr
        # The premise every test here stands on: the token was issued
        # while the certificate was in date.
        assert time.time() < expires, (
            f"stamping took longer than the certificate's "
            f"{CERTIFICATE_LIFE}-second life; raise CERTIFICATE_LIFE")
        outlive(expires)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.scratch = Path(self._tmp.name).resolve()
        self.workdir = self.scratch / "chain"
        shutil.copytree(self.stamped, self.workdir)
        self.sidecar = self.workdir / "receipts.jsonl.stamps.jsonl"

    def verify(self, env=None):
        return run_receipts("verify", "--stamps", "--authority-chain",
                            str(self.chain_file), cwd=self.workdir, env=env)

    def rewrite_row(self, **changes):
        (row,) = rows_of(self.sidecar)
        row.update(changes)
        self.sidecar.write_text(json.dumps(row) + "\n", encoding="utf-8")

    def test_a_token_judged_after_its_certificate_expired_is_not_judged(self):
        # The token did not change; the certificate's life ran out. That
        # is the calendar and not evidence, so it is a note and never a
        # verdict, and the exit stays the chain's (ADR-0032 ruling 5,
        # ADR-0026's posture).
        result = self.verify()

        out = result.stdout
        self.assertEqual(result.returncode, 0, out + result.stderr)
        self.assertIn("stamp not judged: the authority's certificate expired "
                      "after the token was issued", out)
        self.assertIn(f"head {self.head[:12]}… (entry 2) holds a token", out)
        self.assertRegex(out, r"(?m)^VALID$")
        self.assertNotIn("STAMP-INVALID", out)
        self.assertNotIn("STAMPED", out)
        self.assertNotIn("anchor", out.lower())

    def test_a_tampered_token_is_still_stamp_invalid(self):
        # openssl checks the certificate before the signature, so after
        # expiry, expiry is all it says about a token with a flipped bit
        # too. Judged again as of the time the token states, it is the
        # signature that fails, and that is evidence.
        (row,) = rows_of(self.sidecar)
        response = bytearray(base64.b64decode(row["response"]))
        response[-40] ^= 0x01  # one bit, inside the signature
        self.rewrite_row(response=base64.b64encode(bytes(response)).decode())

        result = self.verify()

        out = result.stdout
        self.assertEqual(result.returncode, 3, out + result.stderr)
        self.assertIn(f"STAMP-INVALID: head {self.head[:12]}… (entry 2)", out)
        self.assertIn("as of the time the token states", out)
        self.assertNotIn("not judged", out)
        self.assertNotRegex(out, r"(?m)^VALID$")
        self.assertNotIn("Traceback", result.stderr)

    def test_a_token_whose_stated_time_is_not_a_time_is_still_stamp_invalid(self):
        # The token's time is the one field a tamperer could spoil to
        # dodge the second check, and openssl still reports only expiry
        # at the first. A month of 13 in the GeneralizedTime, the one
        # 14-digit time a token carries (its certificate's are UTCTime,
        # 12 digits): no time to judge as of, so the refusal stands.
        (row,) = rows_of(self.sidecar)
        response = base64.b64decode(row["response"])
        (stated,) = re.finditer(rb"\d{14}Z", response)
        at = stated.start() + 4  # past the year, at the month
        spoiled = response[:at] + b"13" + response[at + 2:]
        self.rewrite_row(response=base64.b64encode(spoiled).decode())

        result = self.verify()

        out = result.stdout
        self.assertEqual(result.returncode, 3, out + result.stderr)
        self.assertIn(f"STAMP-INVALID: head {self.head[:12]}… (entry 2)", out)
        self.assertIn("the time the token states could not be read", out)
        self.assertNotIn("not judged", out)
        self.assertNotRegex(out, r"(?m)^VALID$")
        self.assertNotIn("Traceback", result.stderr)

    def test_a_token_over_another_head_is_still_stamp_invalid(self):
        # The row's head is in the chain and the token's imprint is not
        # that head: a reason of its own, which expiry must not hide.
        run_receipts("log", "--actor", "agent", "--action", "step 3",
                     cwd=self.workdir)
        newer = run_receipts("head", cwd=self.workdir).stdout.strip()
        self.rewrite_row(head=newer, n=3)

        result = self.verify()

        out = result.stdout
        self.assertEqual(result.returncode, 3, out + result.stderr)
        self.assertIn(f"STAMP-INVALID: head {newer[:12]}… (entry 3)", out)
        self.assertNotIn("not judged", out)
        self.assertNotRegex(out, r"(?m)^VALID$")

    def stamped_after_expiry(self):
        """A fresh chain stamped today by an authority whose certificate
        ran out yesterday. Returns (the chain's folder, the chain file)."""
        chain_file, _ = dated_authority(self.scratch / "lapsed", "lapsed",
                                        -2 * 86400, -86400)
        lapsed = start_authority(self, answer=answering(self.scratch / "lapsed"))
        fresh = self.scratch / "fresh"
        fresh.mkdir()
        run_receipts("init", cwd=fresh)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=fresh)
        stamped = run_receipts("stamp", "--authority", lapsed.url, cwd=fresh)
        self.assertEqual(stamped.returncode, 0,
                         stamped.stdout + stamped.stderr)
        return fresh, chain_file

    def test_a_token_issued_after_its_certificate_expired_is_stamp_invalid(self):
        # An authority that signs under a certificate already past its
        # end date: the time the token states is outside the
        # certificate's life too, so no calendar excuses it.
        fresh, chain_file = self.stamped_after_expiry()

        result = run_receipts("verify", "--stamps", "--authority-chain",
                              str(chain_file), cwd=fresh)

        out = result.stdout
        self.assertEqual(result.returncode, 3, out + result.stderr)
        self.assertIn("STAMP-INVALID", out)
        self.assertIn("certificate has expired", out)
        self.assertIn("as of the time the token states", out)
        self.assertNotIn("not judged", out)
        self.assertNotRegex(out, r"(?m)^VALID$")

    def test_a_time_written_beside_the_token_is_not_the_time_it_states(self):
        # The reply's status text is unsigned and sits in a sidecar the
        # writer can edit. A second `Time stamp:` line written there,
        # inside the certificate's life, must not become the moment the
        # second check asks about: only the token's own signed time is.
        fresh, chain_file = self.stamped_after_expiry()
        sidecar = fresh / "receipts.jsonl.stamps.jsonl"
        (row,) = rows_of(sidecar)
        inside = time.time() - 1.5 * 86400
        row["response"] = base64.b64encode(with_status_text(
            base64.b64decode(row["response"]),
            "ok\nTime stamp: " + openssl_print_time(inside))).decode()
        sidecar.write_text(json.dumps(row) + "\n", encoding="utf-8")

        result = run_receipts("verify", "--stamps", "--authority-chain",
                              str(chain_file), cwd=fresh)

        out = result.stdout
        self.assertEqual(result.returncode, 3, out + result.stderr)
        self.assertIn("STAMP-INVALID", out)
        self.assertIn("certificate has expired", out)
        self.assertNotIn("not judged", out)
        self.assertNotRegex(out, r"(?m)^VALID$")

    @unittest.skipIf(os.name == "nt", "a stand-in openssl needs a shebang, "
                     "which Windows does not run")
    def test_an_openssl_that_cannot_judge_as_of_a_moment_says_so(self):
        # An openssl whose `ts -verify` has no -attime cannot ask the one
        # question that would tell expiry from a reason of the token's
        # own. The tool is there and the check could not run, which is
        # ADR-0026's posture for an ssh-keygen that predates -Y verify:
        # a note that says why, and never a verdict.
        result = self.verify(env={
            "PATH": openssl_without_attime(self.scratch / "old-bin")})

        out = result.stdout
        self.assertEqual(result.returncode, 0, out + result.stderr)
        self.assertIn("stamp not judged: the authority's certificate has "
                      "expired, and this openssl cannot judge a token as of "
                      "the time it states", out)
        self.assertRegex(out, r"(?m)^VALID$")
        self.assertNotIn("STAMP-INVALID", out)
        self.assertNotIn("Traceback", result.stderr)


# --- The installer ------------------------------------------------------------

class InstallAuthorityTest(unittest.TestCase):
    """`install-hook --authority URL` writes `--stamp URL` onto the wired
    SessionEnd command, the way `--publish-head` writes `--publish`, and
    the coverage marker's epoch records the authority; `uninstall-hook`
    removes it. The flag lives under `custom` and beside the tier that
    commits the head, where it is the only raw flag accepted (ADR-0032
    ruling 2), and on Codex as well as Claude Code."""

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

    REMOTE = "https://shelf.example.test:8790/7qpsWUkU86ML-NOuaGjSaetfYCGg"

    def test_full_with_an_authority_wires_all_four_flags(self):
        # Where #249 and #251 meet: `full` resolves to the anchor and
        # both publishes to the one remote, and the authority is the one
        # raw flag a tier takes beside its own, so it must survive the
        # tier's resolution rather than be dropped by it.
        result = self.install("--profile", "full", "--remote", self.REMOTE,
                              "--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(
            f' --anchor --publish "{self.REMOTE}"'
            f' --publish-chain "{self.REMOTE}" --stamp "{self.URL}"'), end)
        self.assertIn(f"stamps the head with {self.URL}", result.stdout)
        (epoch,) = self.epochs()
        self.assertEqual(
            (epoch["profile"], epoch["remote"], epoch["authority"]),
            ("full", self.REMOTE, self.URL))

    def test_full_with_an_authority_on_codex_wires_all_but_the_anchor(self):
        # The Codex twin: the session-end anchor stays refused there
        # (ADR-0024), and the two publishes and the stamp share one
        # window (#262), so three flags and no `--anchor`.
        (self.home / ".codex").mkdir(exist_ok=True)

        result = self.install("--codex", "--profile", "full",
                              "--remote", self.REMOTE, "--authority", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.codex_commands("SessionEnd")
        self.assertIn("--actor codex", end)
        self.assertNotIn("--anchor", end)
        self.assertTrue(end.endswith(
            f' --publish "{self.REMOTE}"'
            f' --publish-chain "{self.REMOTE}" --stamp "{self.URL}"'), end)
        (epoch,) = self.epochs()
        self.assertEqual(
            (epoch["harness"], epoch["profile"], epoch["remote"],
             epoch["authority"]),
            ("codex", "full", self.REMOTE, self.URL))

    def test_full_with_an_authority_and_no_remote_writes_nothing(self):
        # The authority composing with the tier does not make the tier
        # whole: `full` without a remote is still no tier at all.
        result = self.install("--profile", "full", "--authority", self.URL)

        self.assertEqual(result.returncode, 64, result.stdout)
        self.assertIn("--remote", result.stderr)
        self.assertFalse((self.home / ".claude" / "settings.json").exists())
        self.assertFalse((self.store / "coverage.json").exists())

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

        result = run_scan(self.root, env=isolated_env(home_outside(self)))

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
