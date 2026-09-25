"""Behavioral tests for Stage B anchoring (docs/ANCHORING.md, ADR-0003).

Every test drives the public CLI against a local fake calendar server —
no network, ever. The OTS wire subset is deliberately reimplemented here
(like spec_hash in test_cli.py), so the tests prove the tool matches the
documented format rather than matching itself.
"""

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_anchor`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_supervisor import home_outside, isolated_env  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"

TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")


def clean_env():
    """Subprocess env with proxy variables stripped, so urllib in the CLI
    talks straight to the fake calendar on 127.0.0.1 — and with the child
    pinned to UTF-8 output, so it agrees with the encoding= below no matter
    what the invoking shell's locale is (cp1252 on Windows)."""
    env = dict(os.environ)
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            del env[key]
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_receipts(*args, cwd):
    return subprocess.run(
        [sys.executable, str(LOXODONTA), *args],
        cwd=cwd,
        capture_output=True,
        encoding="utf-8",
        env=clean_env(),
    )


# --- Independent OTS wire subset (docs/ANCHORING.md §4) -----------------------

def ots_varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def ots_varbytes(b):
    return ots_varint(len(b)) + b


def pending_proof(nonce, uri):
    """ops: append nonce, sha256 → pending attestation naming the calendar."""
    return (
        b"\xf0" + ots_varbytes(nonce) + b"\x08"
        + b"\x00" + TAG_PENDING + ots_varbytes(ots_varbytes(uri.encode()))
    )


def bitcoin_continuation(prefix, suffix, height):
    """ops: prepend prefix, append suffix, sha256, sha256 → Bitcoin block H."""
    return (
        b"\xf1" + ots_varbytes(prefix) + b"\xf0" + ots_varbytes(suffix)
        + b"\x08\x08"
        + b"\x00" + TAG_BITCOIN + ots_varbytes(ots_varint(height))
    )


def replayed_root(head_hex, nonce, prefix, suffix):
    """Replay the fake proofs by hand: the digest the Bitcoin attestation
    claims as block merkle root, as the proof computes it. That is the
    order a block header stores its merkle root in: the proof's last two
    operations are the double sha256 that makes a transaction id, and
    Bitcoin hashes ids into the root in the order the hash comes out."""
    commitment = hashlib.sha256(bytes.fromhex(head_hex) + nonce).digest()
    return hashlib.sha256(
        hashlib.sha256(prefix + commitment + suffix).digest()
    ).digest()


def expected_merkle_root(head_hex, nonce, prefix, suffix):
    """The same root in explorer display order (reversed)."""
    return replayed_root(head_hex, nonce, prefix, suffix)[::-1].hex()


def block_header(merkle_root, prev=b"\x11" * 32, time=1720000000,
                 bits=0x17034219, nonce=7):
    """An 80-byte block header in Bitcoin's layout: version, the previous
    block's hash, the merkle root, time, bits, nonce, every integer
    little-endian. Synthetic, so a test can hold a header whose root is a
    fake proof's; nothing checks that it was ever mined, and the
    verifier does not claim to."""
    return (struct.pack("<I", 0x20000000) + prev + merkle_root
            + struct.pack("<III", time, bits, nonce))


def header_hash(header):
    """A header's hash as explorers print it: double sha256, reversed."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


# The Bitcoin genesis block's header, a real one: its hash and its merkle
# root are the two most printed values in Bitcoin, so they pin the display
# order of both against the world rather than against this file.
GENESIS_HEADER = (
    "01000000" + "00" * 32
    + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    + "29ab5f49" + "ffff001d" + "1dac2b7c")
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_ROOT = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


# --- Fake calendar ------------------------------------------------------------

class FakeCalendar(HTTPServer):
    def server_bind(self):
        # Skip the stdlib's reverse DNS lookup of the bound host: unused
        # here, and a ~35 s stall on macOS runners.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class FakeCalendarHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep test output clean

    def do_POST(self):
        if self.path != "/digest":
            self.send_error(404)
            return
        digest = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.submitted.append(digest)
        body = pending_proof(self.server.nonce, self.server.url)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.path.startswith("/timestamp/"):
            self.send_error(404)
            return
        self.server.polled.append(self.path.rsplit("/", 1)[-1])
        if self.server.mode == "pending":
            self.send_error(404, "Pending confirmation")
            return
        body = bitcoin_continuation(
            self.server.prefix, self.server.suffix, self.server.height
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StallingCalendar(FakeCalendar):
    def handle_error(self, request, client_address):
        pass  # a client that gave up waiting is the point of one test


class StallingCalendarHandler(FakeCalendarHandler):
    """A calendar that takes the digest and sits on it past the hook's
    per-call bound, then answers a client that has already left."""

    def do_POST(self):
        time.sleep(self.server.stall)
        super().do_POST()


class SessionEndAnchorTest(unittest.TestCase):
    """ADR-0024: a hook wired with --anchor anchors the session's chain
    head at SessionEnd, quietly and best-effort, and spends what is left
    of its budget upgrading the drawer's pending proofs. Driven through
    `loxodonta hook` with a SessionEnd payload, against the fake
    calendar, exactly as the harness would run it."""

    SESSION = "sess-end-0001"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
        self.server.nonce = b"fake-nonce"
        self.server.prefix = b"left-branch"
        self.server.suffix = b"right-branch"
        self.server.height = 850000
        self.server.mode = "pending"
        self.server.submitted = []
        self.server.polled = []
        self.server.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.chain = self.workdir / f"receipts-{self.SESSION}.jsonl"
        self.sidecar = self.workdir / f"receipts-{self.SESSION}.jsonl.anchors.jsonl"
        self.home = home_outside(self)

    def hook(self, payload, *extra):
        # No CLAUDE_PROJECT_DIR, so the chain lands in the working
        # directory; every home one of the test's own (#274).
        env = isolated_env(self.home, PYTHONIOENCODING="utf-8")
        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook", *extra],
            cwd=self.workdir, input=json.dumps(payload).encode("utf-8"),
            capture_output=True, env=env)
        result.stdout = result.stdout.decode("utf-8", "replace")
        result.stderr = result.stderr.decode("utf-8", "replace")
        return result

    def tool_call(self):
        return self.hook({"session_id": self.SESSION,
                          "hook_event_name": "PostToolUse",
                          "tool_name": "Bash",
                          "tool_input": {"command": "ls"},
                          "tool_response": {}})

    def session_end(self, *extra):
        return self.hook({"session_id": self.SESSION,
                          "hook_event_name": "SessionEnd"}, *extra)

    def records(self):
        return [json.loads(line) for line in
                self.sidecar.read_text(encoding="utf-8").splitlines()]

    def proofs(self):
        """The sidecar's anchor records: the rows that carry a proof."""
        return [r for r in self.records() if "proof" in r]

    def attempts(self):
        """The sidecar's attempt rows (#240): how each session-end
        anchor went, beside the proofs and never one of them."""
        return [r for r in self.records() if r.get("kind") == "attempt"]

    def test_session_end_with_anchor_writes_a_sidecar_for_the_head(self):
        self.tool_call()
        head = run_receipts("head", "--log", str(self.chain),
                            cwd=self.workdir).stdout.strip()
        result = self.session_end("--anchor", "--calendar", self.server.url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")  # quiet
        self.assertTrue(self.sidecar.exists(), "no sidecar written")
        proofs = self.proofs()
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0]["head"], head)
        self.assertEqual(len(self.server.submitted), 1)

    def test_a_submitted_anchor_leaves_an_attempt_row_beside_the_proof(self):
        # #240, the sidecar form: after the step, one row of kind
        # `attempt` saying how it went. Beside the proof record, never
        # a proof itself: the step, the time, the budget, the outcome.
        self.tool_call()
        self.session_end("--anchor", "--calendar", self.server.url)
        (row,) = self.attempts()
        self.assertEqual(set(row), {"kind", "step", "ts", "budget", "outcome"})
        self.assertEqual(row["step"], "anchor")
        self.assertEqual(row["outcome"], "submitted")
        self.assertRegex(row["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertAlmostEqual(row["budget"], 12, delta=1)
        self.assertEqual(len(self.proofs()), 1)

    def test_an_unanswered_anchor_leaves_an_attempt_row_and_no_proof(self):
        # The store now says why nothing anchored, in the recorder's
        # own line, so the supervisor can tell a hook that never fired
        # from one that fired and got no answer (#240). The calendar's
        # URL is not in the row: what is written is the outcome, not
        # where it was tried.
        self.tool_call()
        closed = "http://127.0.0.1:9"  # discard port: nothing listens
        result = self.session_end("--anchor", "--calendar", closed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertEqual(self.proofs(), [])
        (row,) = self.attempts()
        self.assertEqual(row["step"], "anchor")
        self.assertTrue(row["outcome"].startswith("no calendar answered"),
                        row["outcome"])
        self.assertAlmostEqual(row["budget"], 12, delta=1)
        self.assertNotIn("127.0.0.1", self.sidecar.read_text("utf-8"))

    def test_session_end_without_anchor_leaves_no_sidecar(self):
        self.tool_call()
        result = self.session_end()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.sidecar.exists())
        self.assertEqual(self.server.submitted, [])

    def test_unreachable_calendar_is_quiet_fast_and_exits_zero(self):
        self.tool_call()
        closed = "http://127.0.0.1:9"  # discard port: nothing listens
        started = time.monotonic()
        result = self.session_end("--anchor", "--calendar", closed)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertEqual(self.proofs(), [])

    def test_a_calendar_that_never_answers_leaves_the_attempt_row(self):
        # The other way a session-end anchor fails: a calendar that takes
        # the connection and never answers inside the hook's per-call
        # bound. No proof, and the row says no calendar answered inside
        # the budget (#240), so the store can tell this from a hook
        # that never fired.
        stalling = StallingCalendar(("127.0.0.1", 0), StallingCalendarHandler)
        stalling.stall = 7  # seconds; past the five the hook waits per calendar
        stalling.nonce = b"fake-nonce"
        stalling.submitted = []
        stalling.url = f"http://127.0.0.1:{stalling.server_address[1]}"
        threading.Thread(target=stalling.serve_forever, daemon=True).start()
        self.addCleanup(stalling.server_close)
        self.addCleanup(stalling.shutdown)
        self.tool_call()

        started = time.monotonic()
        result = self.session_end("--anchor", "--calendar", stalling.url)
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertLess(elapsed, 12, "the per-call bound, not the budget")
        self.assertEqual(self.proofs(), [])
        (row,) = self.attempts()
        self.assertEqual(row["step"], "anchor")
        self.assertEqual(row["outcome"],
                         "no calendar answered within 12 seconds")

    def test_an_already_anchored_head_is_not_anchored_twice(self):
        self.tool_call()
        self.session_end("--anchor", "--calendar", self.server.url)
        self.session_end("--anchor", "--calendar", self.server.url)
        self.assertEqual(len(self.server.submitted), 1)
        self.assertEqual(len(self.proofs()), 1)
        # Nothing was tried the second time, so nothing is written
        # down: an attempt row says how a step went, and a head that
        # is already anchored is not a step.
        self.assertEqual(len(self.attempts()), 1)

    def test_a_row_of_an_unknown_kind_naming_the_head_is_not_its_anchor(self):
        # ADR-0038: only a proof anchors a head. A row of a kind the
        # recorder does not know is not one, whatever head it names, so
        # the session end still submits the head, and the new row says
        # it is an anchor.
        self.tool_call()
        head = run_receipts("head", "--log", str(self.chain),
                            cwd=self.workdir).stdout.strip()
        self.sidecar.write_text(json.dumps({"kind": "witness-note",
                                            "head": head}) + "\n",
                                encoding="utf-8")

        result = self.session_end("--anchor", "--calendar", self.server.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.server.submitted, [bytes.fromhex(head)])
        (proof,) = self.proofs()
        self.assertEqual((proof["head"], proof["kind"]), (head, "anchor"))

    def test_a_malformed_row_leaves_the_session_end_anchor_working(self):
        # #348: one row the writer shaped wrong must not turn the anchor
        # off. A row naming the head with a proof that is not a string is
        # not its anchor, so the head is still submitted, and the step
        # still writes down how it went.
        self.tool_call()
        head = run_receipts("head", "--log", str(self.chain),
                            cwd=self.workdir).stdout.strip()
        self.sidecar.write_text(
            json.dumps({"head": [1]}) + "\n"
            + json.dumps({"head": head, "proof": 5}) + "\n",
            encoding="utf-8")

        result = self.session_end("--anchor", "--calendar", self.server.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertEqual(self.server.submitted, [bytes.fromhex(head)])
        (row,) = self.attempts()
        self.assertEqual((row["step"], row["outcome"]), ("anchor", "submitted"))
        anchors = [r for r in self.records() if r.get("kind") == "anchor"]
        self.assertEqual([r["head"] for r in anchors], [head])

    def test_a_proof_that_does_not_replay_is_not_the_heads_anchor(self):
        # A string, and base64, so the row has its shape; but verify calls
        # it ANCHOR-INVALID, so it anchors nothing, and the session end
        # still submits the head and writes down how it went.
        self.tool_call()
        head = run_receipts("head", "--log", str(self.chain),
                            cwd=self.workdir).stdout.strip()
        for proof in ("", "AAAA"):
            with self.subTest(proof=proof):
                self.server.submitted.clear()
                self.sidecar.write_text(
                    json.dumps({"kind": "anchor", "head": head, "n": 1,
                                "proof": proof}) + "\n", encoding="utf-8")

                result = self.session_end("--anchor", "--calendar",
                                          self.server.url)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.server.submitted, [bytes.fromhex(head)])
                (row,) = self.attempts()
                self.assertEqual(row["outcome"], "submitted")

    def test_a_malformed_row_leaves_the_session_end_upgrade_working(self):
        # The upgrade half reads every sidecar in the folder: rows it
        # cannot act on ahead of a pending proof are skipped, and the
        # proof is still completed.
        self.tool_call()
        self.session_end("--anchor", "--calendar", self.server.url)
        rows = self.sidecar.read_text("utf-8")
        (pending,) = [r for r in self.records() if r.get("kind") == "anchor"]
        no_calendar = {k: v for k, v in pending.items() if k != "calendar"}
        self.sidecar.write_text(
            json.dumps(no_calendar) + "\n"
            + json.dumps({**pending, "proof": 5}) + "\n"
            + json.dumps({**pending, "calendar": [1]}) + "\n" + rows,
            encoding="utf-8")
        self.server.mode = "complete"
        self.tool_call()

        result = self.session_end("--anchor", "--calendar", self.server.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        commitment = hashlib.sha256(bytes.fromhex(pending["head"])
                                    + self.server.nonce).hexdigest()
        self.assertIn(commitment, self.server.polled)
        upgraded = [r for r in self.records()[5:]
                    if r.get("kind") == "anchor" and r["head"] == pending["head"]]
        self.assertEqual(len(upgraded), 1, self.records())

    def test_a_later_session_end_upgrades_the_pending_proof(self):
        self.tool_call()
        self.session_end("--anchor", "--calendar", self.server.url)
        self.server.mode = "complete"
        # A new head (one more receipt), so the next session end anchors
        # again and, with its leftover budget, upgrades the older proof.
        self.tool_call()
        result = self.session_end("--anchor", "--calendar", self.server.url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(len(self.server.polled), 1, "no upgrade tried")
        verify = run_receipts("verify", "--anchors", "--log",
                              str(self.chain), cwd=self.workdir)
        self.assertIn("ANCHORED", verify.stdout)


class AnchorTest(unittest.TestCase):
    HEIGHT = 850000

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.log_path = self.workdir / "receipts.jsonl"
        self.sidecar = self.workdir / "receipts.jsonl.anchors.jsonl"

        self.server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
        self.server.nonce = b"fake-nonce"
        self.server.prefix = b"left-branch"
        self.server.suffix = b"right-branch"
        self.server.height = self.HEIGHT
        self.server.mode = "pending"
        self.server.submitted = []
        self.server.polled = []
        self.server.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def anchor(self, *extra):
        return run_receipts(
            "anchor", "--calendar", self.server.url, *extra, cwd=self.workdir
        )

    def sidecar_records(self):
        return [
            json.loads(line)
            for line in self.sidecar.read_text(encoding="utf-8").splitlines()
        ]

    def test_anchor_submits_head_digest_and_writes_sidecar_record(self):
        result = self.anchor()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.server.submitted, [bytes.fromhex(self.head)])
        records = self.sidecar_records()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["head"], self.head)
        self.assertEqual(record["n"], 1)
        self.assertEqual(record["calendar"], self.server.url)
        self.assertEqual(
            base64.b64decode(record["proof"]),
            pending_proof(self.server.nonce, self.server.url),
        )

    def test_anchor_with_unreachable_calendar_fails_cleanly(self):
        result = run_receipts(
            "anchor", "--calendar", "http://127.0.0.1:1", cwd=self.workdir
        )

        self.assertEqual(result.returncode, 69)  # EX_UNAVAILABLE (ADR-0037)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.sidecar.exists())

    def test_anchor_without_log_errors_cleanly(self):
        empty = self.workdir / "elsewhere"
        empty.mkdir()

        result = run_receipts(
            "anchor", "--calendar", self.server.url, cwd=empty
        )

        self.assertEqual(result.returncode, 66)  # EX_NOINPUT (ADR-0037)
        self.assertIn("init", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_verify_anchors_reports_pending(self):
        self.anchor()

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ANCHOR-PENDING", result.stdout)
        self.assertIn("upgrade", result.stdout)
        self.assertIn("VALID", result.stdout)

    def test_upgrade_completes_pending_and_verify_reports_anchored(self):
        self.anchor()
        self.server.mode = "complete"

        upgrade = self.anchor("--upgrade")
        self.assertEqual(upgrade.returncode, 0, upgrade.stderr)
        # The calendar was asked for the commitment our proof replays to.
        commitment = hashlib.sha256(
            bytes.fromhex(self.head) + self.server.nonce
        ).hexdigest()
        self.assertEqual(self.server.polled, [commitment])
        self.assertEqual(len(self.sidecar_records()), 2)

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # With no block header given, the attestation's height is its own
        # claim: a regenerated chain can carry a made-up one, so the line
        # says the block was not checked and never that the entries
        # existed by it (ruling 3 on #299).
        self.assertIn(f"ANCHORED: entries 0..1: the attestation claims "
                      f"Bitcoin block {self.HEIGHT}, and the block was not "
                      "checked", result.stdout)
        self.assertNotIn("existed by", result.stdout)
        self.assertIn("--block-header", result.stdout)
        self.assertIn(
            expected_merkle_root(self.head, self.server.nonce,
                                 self.server.prefix, self.server.suffix),
            result.stdout,
        )
        self.assertIn("VALID", result.stdout)
        # The completed record supersedes the pending one for this head.
        self.assertNotIn("ANCHOR-PENDING", result.stdout)

    def test_upgrade_while_still_pending_leaves_proof_alone(self):
        self.anchor()

        upgrade = self.anchor("--upgrade")

        self.assertEqual(upgrade.returncode, 0, upgrade.stderr)
        self.assertIn("pending", (upgrade.stdout + upgrade.stderr).lower())
        self.assertEqual(len(self.sidecar_records()), 1)

    def test_regenerated_chain_is_anchor_mismatch_exit_3(self):
        self.anchor()
        # The adversary rewrites history wholesale: a fresh, internally
        # valid chain. The anchored head no longer appears anywhere.
        self.log_path.unlink()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "innocent step",
                     cwd=self.workdir)

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-MISMATCH", result.stdout)
        self.assertNotIn("VALID", result.stdout)

    def test_proof_with_unimplemented_op_is_anchor_invalid_exit_3(self):
        # keccak256 (0x67) is outside the subset: refused by name (ADR-0003).
        bad = (b"\x67"
               + b"\x00" + TAG_BITCOIN + ots_varbytes(ots_varint(1)))
        self.sidecar.write_text(
            json.dumps({
                "head": self.head, "n": 1, "ts": "2026-08-13T14:00:00Z",
                "calendar": self.server.url,
                "proof": base64.b64encode(bad).decode(),
            }) + "\n",
            encoding="utf-8",
        )

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-INVALID", result.stdout)
        self.assertIn("0x67", result.stdout)
        # "VALID" as a verdict line, not as a substring of "ANCHOR-INVALID".
        self.assertNotRegex(result.stdout, r"(?m)^VALID$")

    def test_deeply_nested_proof_is_anchor_invalid_not_a_crash(self):
        # Each chained op nests one level of recursion; ~1500 sha256 ops fit
        # well under the 8KB field cap but sail past Python's default
        # recursion limit. The sidecar is writer-reachable, so a crafted
        # proof must earn a verdict (ANCHOR-INVALID), never a crash — found
        # in the 2026-08-21 readability walk.
        deep = (b"\x08" * 1500
                + b"\x00" + TAG_BITCOIN + ots_varbytes(ots_varint(1)))
        self.sidecar.write_text(
            json.dumps({
                "head": self.head, "n": 1, "ts": "2026-08-13T14:00:00Z",
                "calendar": self.server.url,
                "proof": base64.b64encode(deep).decode(),
            }) + "\n",
            encoding="utf-8",
        )

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-INVALID", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_record_without_a_head_is_anchor_invalid_not_none_mismatch(self):
        # A record lacking its head is malformed evidence (ANCHOR-INVALID),
        # not a mismatch against a head called "None".
        self.sidecar.write_text(
            json.dumps({"n": 1, "ts": "2026-08-13T14:00:00Z",
                        "calendar": self.server.url, "proof": "AA=="}) + "\n",
            encoding="utf-8",
        )

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-INVALID", result.stdout)
        self.assertNotIn("None", result.stdout)

    def test_garbage_proof_bytes_are_anchor_invalid_not_traceback(self):
        self.sidecar.write_text(
            json.dumps({
                "head": self.head, "n": 1, "ts": "2026-08-13T14:00:00Z",
                "calendar": self.server.url,
                "proof": base64.b64encode(b"\x00\x01garbage").decode(),
            }) + "\n",
            encoding="utf-8",
        )

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-INVALID", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_verify_anchors_with_no_sidecar_says_so(self):
        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NO-ANCHORS", result.stdout)
        self.assertIn("VALID", result.stdout)

    def test_a_sidecar_of_attempt_rows_only_verifies_as_an_empty_one(self):
        # #240: an attempt row is a note on how a session-end step went,
        # never evidence for or against the chain, so the verifier
        # reads a sidecar holding only notes exactly as it reads one
        # holding nothing: same words, same exit code.
        self.sidecar.write_text("", encoding="utf-8")
        empty = run_receipts("verify", "--anchors", cwd=self.workdir)
        self.sidecar.write_text(json.dumps({
            "kind": "attempt", "step": "anchor", "ts": "2026-09-16T05:35:42Z",
            "budget": 12.0,
            "outcome": "no calendar answered within 12 seconds"}) + "\n",
            encoding="utf-8")

        noted = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(empty.returncode, 0, empty.stdout + empty.stderr)
        self.assertEqual((noted.returncode, noted.stdout, noted.stderr),
                         (empty.returncode, empty.stdout, empty.stderr))
        self.assertNotIn("ANCHOR-INVALID", noted.stdout)

    def test_anchor_grows_sidecar_as_chain_grows(self):
        self.anchor()
        run_receipts("log", "--actor", "agent", "--action", "step 2",
                     cwd=self.workdir)
        new_head = run_receipts("head", cwd=self.workdir).stdout.strip()

        self.anchor()

        records = self.sidecar_records()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["head"], new_head)
        self.assertEqual(records[1]["n"], 2)
        # Both anchored heads appear in the chain: both verify cleanly.
        result = run_receipts("verify", "--anchors", cwd=self.workdir)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("ANCHOR-PENDING"), 2)


class BlockHeaderTest(unittest.TestCase):
    """Ruling 3 on #299: `verify --anchors` grades an anchor honestly. A
    Bitcoin attestation names a height, and replaying the proof gives a
    merkle root, and neither says a block with that root exists: a
    regenerated chain can carry an attestation made up whole. So without
    a header the line says the attestation claims block H and the block
    was not checked; `--block-header HEX`, an 80-byte header the recipient
    got from a source they trust, checks the replayed root against the
    header's own, and only a match says the entries existed by that block.
    A header carries no height, so headers are matched to attestations by
    root, and the line names the header by its hash, the value a second
    source can confirm."""

    HEIGHT = 850000

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.server = start_calendar(self, b"fake-nonce", self.HEIGHT)
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()
        submitted = run_receipts("anchor", "--calendar", self.server.url,
                                 cwd=self.workdir)
        self.assertEqual(submitted.returncode, 0, submitted.stderr)
        self.server.mode = "complete"
        upgraded = run_receipts("anchor", "--upgrade", cwd=self.workdir)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        self.root = replayed_root(self.head, self.server.nonce,
                                  self.server.prefix, self.server.suffix)

    def verify(self, *headers, anchors=True):
        flags = [arg for header in headers
                 for arg in ("--block-header", header)]
        return run_receipts("verify", *(["--anchors"] if anchors else []),
                            *flags, cwd=self.workdir)

    def test_a_header_holding_the_replayed_root_says_existed_by_that_block(self):
        header = block_header(self.root)

        result = self.verify(header.hex())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.strip().splitlines()
        self.assertEqual(lines[-1], "VALID")
        line = next(l for l in lines if l.startswith("ANCHORED"))
        self.assertTrue(line.startswith(
            "ANCHORED: entries 0..1 existed by the block whose header hashes "
            f"to {header_hash(header)}"), line)
        self.assertIn(self.root[::-1].hex(), line)
        # The height is the attestation's word and the header source's;
        # the verifier saw no height in the header, and says so.
        self.assertIn(f"calls it Bitcoin block {self.HEIGHT}", line)
        self.assertNotIn("not checked", result.stdout)
        self.assertNotIn("HEADER-UNMATCHED", result.stdout)

    def test_the_header_stores_the_root_as_the_proof_computes_it(self):
        # The byte order, pinned: a header written with the root reversed
        # (the explorer's display order) holds a different 32 bytes, and
        # checks nothing. The root goes in as the double sha256 left it.
        reversed_root = block_header(self.root[::-1])

        result = self.verify(reversed_root.hex())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("the block was not checked", result.stdout)
        self.assertNotIn("existed by", result.stdout)
        self.assertIn("HEADER-UNMATCHED", result.stdout)

    def test_a_real_header_that_matches_nothing_is_noted_by_its_hash(self):
        # The genesis block's header, real bytes: its hash and its merkle
        # root print in the order every explorer prints them. It is not
        # this anchor's block, so it checked nothing, which is a note: the
        # verdict stays the chain's, and the anchor stays not checked.
        result = self.verify(GENESIS_HEADER)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.strip().splitlines()
        self.assertEqual(lines[-1], "VALID")
        note = next(l for l in lines if l.startswith("HEADER-UNMATCHED"))
        self.assertIn(GENESIS_HASH, note)
        self.assertIn(GENESIS_ROOT, note)
        self.assertIn("checked nothing", note)
        self.assertIn(f"claims Bitcoin block {self.HEIGHT}, and the block "
                      "was not checked", result.stdout)

    def test_headers_repeat_and_each_is_matched_by_its_root(self):
        header = block_header(self.root)

        result = self.verify(GENESIS_HEADER, header.hex().upper())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"existed by the block whose header hashes to "
                      f"{header_hash(header)}", result.stdout)
        self.assertEqual(result.stdout.count("HEADER-UNMATCHED"), 1)
        self.assertIn(GENESIS_HASH, result.stdout)

    def test_with_no_sidecar_a_header_is_still_noted(self):
        (self.workdir / "receipts.jsonl.anchors.jsonl").unlink()

        result = self.verify(GENESIS_HEADER)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NO-ANCHORS", result.stdout)
        self.assertIn("HEADER-UNMATCHED", result.stdout)

    def test_a_regenerated_chain_is_still_anchor_mismatch_exit_3(self):
        # A header changes what a completed proof is said to show; it
        # changes nothing about a proof for a head this log does not hold.
        header = block_header(self.root)
        (self.workdir / "receipts.jsonl").unlink()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "innocent step",
                     cwd=self.workdir)

        result = self.verify(header.hex())

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-MISMATCH", result.stdout)

    def test_a_header_without_anchors_is_a_usage_error(self):
        # The header was given in order to check an anchor; a run that
        # ignored it would answer VALID with nothing checked.
        result = self.verify(block_header(self.root).hex(), anchors=False)

        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("--anchors", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_header_that_is_not_80_bytes_of_hex_is_a_usage_error(self):
        whole = block_header(self.root).hex()
        for bad in (whole[:-2], whole + "00", "zz" + whole[2:], ""):
            with self.subTest(length=len(bad)):
                result = self.verify(bad)
                self.assertEqual(result.returncode, 64,
                                 result.stdout + result.stderr)
                self.assertIn("160 hex characters", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


def start_calendar(case, nonce, height=850000):
    """A fake calendar, bound to a free port, serving in a thread, closed
    when `case` finishes. Each one carries its own nonce, the way real
    calendars do, so two of them commit a head to two digests."""
    server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
    server.nonce = nonce
    server.prefix = b"left-branch"
    server.suffix = b"right-branch"
    server.height = height
    server.mode = "pending"
    server.submitted = []
    server.polled = []
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class CalendarsDisagreeTest(unittest.TestCase):
    """#199: four calendars is the default and calendars disagree, so a
    head settled by one while another never answers is the ordinary case,
    not the exotic one. The anchor's claim is about the head, so once any
    calendar settles it, the straggler's record is evidence of where the
    submission went and not work anyone still owes. Two fake calendars
    here: one comes back, one stays 404 forever."""

    HEIGHT = 962604

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.settles = start_calendar(self, b"nonce-settles", self.HEIGHT)
        self.lags = start_calendar(self, b"nonce-lags")

        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()
        submitted = run_receipts("anchor", "--calendar", self.settles.url,
                                 "--calendar", self.lags.url,
                                 cwd=self.workdir)
        self.assertEqual(submitted.returncode, 0, submitted.stderr)
        # One of the two gets its Bitcoin attestation; the other keeps
        # answering 404, as the opentimestamps.org pools did for 27 days.
        self.settles.mode = "complete"
        upgraded = run_receipts("anchor", "--upgrade", cwd=self.workdir)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)

    def verify(self):
        return run_receipts("verify", "--anchors", cwd=self.workdir)

    def test_a_settled_head_stops_advising_an_upgrade_that_cannot_help(self):
        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"block {self.HEIGHT}", result.stdout)
        self.assertNotIn("ANCHOR-PENDING", result.stdout)
        self.assertNotIn("--upgrade", result.stdout)
        self.assertIn("VALID", result.stdout)

    def test_the_calendar_that_never_came_back_is_still_named(self):
        result = self.verify()

        self.assertIn("ANCHOR-UNANSWERED", result.stdout)
        self.assertIn(self.lags.url, result.stdout)
        # The settled calendar's own pending record is superseded by its
        # upgrade, so it is not named twice.
        self.assertEqual(result.stdout.count("ANCHOR-UNANSWERED"), 1)

    def test_upgrade_stops_re_asking_for_a_head_another_calendar_settled(self):
        self.lags.polled.clear()

        result = run_receipts("anchor", "--upgrade", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lags.polled, [],
                         "the dead pool was asked again")
        self.assertIn("skipped", result.stdout)
        self.assertIn(self.lags.url, result.stdout)
        self.assertNotIn("still pending", result.stdout)

    def test_a_head_no_calendar_settled_still_advises_the_upgrade(self):
        run_receipts("log", "--actor", "agent", "--action", "step 2",
                     cwd=self.workdir)
        run_receipts("anchor", "--calendar", self.lags.url, cwd=self.workdir)

        result = self.verify()

        # The old head is settled; the new one is not, and says so.
        self.assertIn("ANCHOR-PENDING", result.stdout)
        self.assertIn("`loxodonta anchor --upgrade`", result.stdout)
        self.assertIn("ANCHOR-UNANSWERED", result.stdout)


class AnchorRowKindTest(unittest.TestCase):
    """ADR-0038: every row of the anchors sidecar names its kind. A new
    proof is written `"kind": "anchor"`; a row with no kind reads as a
    proof, whenever it was written, so every sidecar already shipped
    verifies as it did; and a row of a kind this verifier does not know,
    or a kind that belongs in another sidecar, is named by its line and
    never judged, so a newer recorder's row is never evidence against an
    honest log."""

    UNKNOWN = "ANCHOR-UNKNOWN-KIND"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.sidecar = self.workdir / "receipts.jsonl.anchors.jsonl"
        self.server = start_calendar(self, b"fake-nonce")
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def pending_row(self, **extra):
        """A pending proof of the head, as the recorder writes one, keys
        sorted and compact; `extra` adds fields (a kind) or replaces them."""
        row = {"head": self.head, "n": 1, "ts": "2026-09-24T10:00:00Z",
               "calendar": self.server.url,
               "proof": base64.b64encode(pending_proof(
                   self.server.nonce, self.server.url)).decode()}
        row.update(extra)
        return json.dumps(row, sort_keys=True, separators=(",", ":"))

    def write_sidecar(self, *lines):
        self.sidecar.write_text("".join(line + "\n" for line in lines),
                                encoding="utf-8")

    def verify(self):
        return run_receipts("verify", "--anchors", cwd=self.workdir)

    def without_notes(self, stdout):
        return [line for line in stdout.splitlines()
                if not line.startswith(self.UNKNOWN)]

    def test_a_new_anchor_row_names_its_kind_and_nothing_else_changes(self):
        submitted = run_receipts("anchor", "--calendar", self.server.url,
                                 cwd=self.workdir)
        self.assertEqual(submitted.returncode, 0, submitted.stderr)
        self.server.mode = "complete"
        upgraded = run_receipts("anchor", "--upgrade", cwd=self.workdir)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)

        lines = self.sidecar.read_text("utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            row = json.loads(line)
            self.assertEqual(row["kind"], "anchor")
            self.assertEqual(set(row),
                             {"kind", "head", "n", "ts", "calendar", "proof"})
            # Written compact and key-sorted, as every sidecar row is.
            self.assertEqual(line, json.dumps(row, sort_keys=True,
                                              separators=(",", ":")))

    def test_a_row_with_no_kind_reads_as_an_anchor(self):
        self.write_sidecar(self.pending_row())
        kindless = self.verify()
        self.write_sidecar(self.pending_row(kind="anchor"))
        named = self.verify()

        self.assertEqual(kindless.returncode, 0,
                         kindless.stdout + kindless.stderr)
        self.assertIn("ANCHOR-PENDING", kindless.stdout)
        self.assertRegex(kindless.stdout, r"(?m)^VALID$")
        self.assertEqual((named.returncode, named.stdout, named.stderr),
                         (kindless.returncode, kindless.stdout,
                          kindless.stderr))

    def test_a_kindless_row_for_another_head_is_still_a_mismatch(self):
        self.write_sidecar(self.pending_row(head="ab" * 32))

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-MISMATCH", result.stdout)

    def test_an_unknown_kind_is_named_by_its_line_and_not_judged(self):
        self.write_sidecar(self.pending_row())
        before = self.verify()
        self.write_sidecar(self.pending_row(),
                           json.dumps({"kind": "witness-note",
                                       "ts": "2026-09-24T10:00:00Z"}))

        result = self.verify()

        self.assertEqual(result.returncode, before.returncode,
                         result.stdout + result.stderr)
        self.assertIn(f'{self.UNKNOWN}: line 2 of {self.sidecar.name} is of kind '
                      '"witness-note" — this verifier does not know the kind '
                      'in this sidecar, and does not judge it', result.stdout)
        self.assertEqual(result.stdout.count(self.UNKNOWN), 1)
        self.assertNotIn("ANCHOR-INVALID", result.stdout)
        self.assertEqual(self.without_notes(result.stdout),
                         before.stdout.splitlines())

    def test_a_chain_row_in_the_anchors_sidecar_is_named_not_judged(self):
        # A known kind, but the memo's (ADR-0031), not this sidecar's.
        chain_row = json.dumps({"kind": "chain", "first": 0, "last": 1,
                                "head": self.head,
                                "ts": "2026-09-24T10:00:00Z"})
        self.write_sidecar(chain_row, self.pending_row())

        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'{self.UNKNOWN}: line 1 of {self.sidecar.name} is of kind '
                      '"chain"', result.stdout)
        self.assertIn("ANCHOR-PENDING", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^VALID$")

    def test_an_unknown_kind_leaves_an_exit_3_as_it_was(self):
        # Beside evidence against the log, the note moves nothing: the
        # exit is 3, and the last line is still the finding's, which is
        # where the supervisor's scan reads a verdict.
        mismatch = self.pending_row(head="ab" * 32)
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
        for kind, word in ((5, "a number"), (None, "null"), (True, "true or false"),
                           (["anchor"], "an array"), ({"k": "anchor"}, "an object")):
            with self.subTest(kind=kind):
                self.write_sidecar(self.pending_row(),
                                   json.dumps({"kind": kind}))

                result = self.verify()

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn(f"{self.UNKNOWN}: line 2 of {self.sidecar.name} is "
                              f"of a kind that is {word}, not a string — this "
                              "verifier does not know the kind in this "
                              "sidecar, and does not judge it", result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_a_kind_is_printed_escaped_never_raw(self):
        # The kind is the writer's text, printed to a terminal: a newline
        # in it could forge a verdict line, an escape repaint the screen.
        self.write_sidecar(self.pending_row(),
                           json.dumps({"kind": "x\x1b[2J\nVALID‮"}))

        result = self.verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('is of kind "x\\x1b[2J\\nVALID\\u202e"', result.stdout)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("‮", result.stdout)
        self.assertEqual(result.stdout.splitlines().count("VALID"), 1)

    def test_an_unreadable_line_is_still_anchor_invalid(self):
        too_long = '{"kind": ' + "9" * 5000 + "}"
        too_deep = '{"kind": ' + "[" * 100000 + "]" * 100000 + "}"
        for line in ("not a record", "[1, 2]", too_long, too_deep):
            with self.subTest(line=line[:20]):
                self.write_sidecar(self.pending_row(), line)

                result = self.verify()

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertIn("ANCHOR-INVALID: sidecar line is not a record",
                              result.stdout)
                self.assertNotIn(self.UNKNOWN, result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_a_line_that_is_not_utf8_is_still_anchor_invalid(self):
        self.sidecar.write_bytes(self.pending_row().encode() + b"\n"
                                 + b'{"kind": "\xff"}\n')

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-INVALID: sidecar line is not a record",
                      result.stdout)

    def test_upgrade_asks_about_no_row_of_an_unknown_kind(self):
        # A row of a kind the recorder does not know is not a proof, so
        # `anchor --upgrade` asks no calendar about it, whatever it holds.
        other = start_calendar(self, b"other-nonce")
        other.mode = "complete"
        foreign = self.pending_row(kind="witness-note", calendar=other.url)
        self.write_sidecar(foreign)

        result = run_receipts("anchor", "--upgrade", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(other.polled, [])
        self.assertEqual(self.sidecar.read_text("utf-8").splitlines(),
                         [foreign])


class LeftOut:
    """A field left out of a row rather than given a value."""

    def __repr__(self):
        return "<left out>"


DROP = LeftOut()

# Anchor rows that are JSON objects but not the shape of one (#348): the
# fields changed from a good pending row, and the reason the judge gives.
# Each value is one a reader would crash on or misread, and none of them
# may reach a verdict line: the reason names the field and its JSON type.
MALFORMED_ROWS = (
    ({"head": [1]}, "record's head is an array, not a string"),
    ({"head": 7}, "record's head is a number, not a string"),
    ({"proof": DROP}, "record has no proof"),
    ({"proof": 5}, "record's proof is a number, not a string"),
    ({"proof": None}, "record's proof is null, not a string"),
    ({"proof": "zz!not-base64!zz"}, "record's proof is not base64"),
    ({"calendar": ["http://sneaky.test"]},
     "record's calendar is an array, not a string"),
    ({"ts": {"when": "sneaky"}}, "record's ts is an object, not a string"),
    ({"n": "sneaky"}, "record's n is a string, not an integer"),
    ({"n": True}, "record's n is true or false, not an integer"),
)


class MalformedAnchorRowTest(unittest.TestCase):
    """#348: the anchors sidecar is writer-reachable, so a row that is a
    JSON object but not the shape of an anchor row is judged, never
    trusted: `ANCHOR-INVALID`, exit 3, with a reason naming the field and
    its type and never its value. The recorder's own paths skip such a
    row, since it is not a proof they can act on, and never crash."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.sidecar = self.workdir / "receipts.jsonl.anchors.jsonl"
        self.server = start_calendar(self, b"fake-nonce")
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def row(self, change=None):
        """A pending proof of the head, as the recorder writes one, with
        `change` applied: a field replaced, or left out for DROP."""
        row = {"kind": "anchor", "head": self.head, "n": 1,
               "ts": "2026-09-25T10:00:00Z", "calendar": self.server.url,
               "proof": base64.b64encode(pending_proof(
                   self.server.nonce, self.server.url)).decode()}
        for field, value in (change or {}).items():
            if value is DROP:
                del row[field]
            else:
                row[field] = value
        return json.dumps(row, sort_keys=True, separators=(",", ":"))

    def write_sidecar(self, *lines):
        self.sidecar.write_text("".join(line + "\n" for line in lines),
                                encoding="utf-8")

    def test_a_malformed_row_is_anchor_invalid_naming_the_field(self):
        for change, reason in MALFORMED_ROWS:
            with self.subTest(change=change):
                self.write_sidecar(self.row(), self.row(change))

                result = run_receipts("verify", "--anchors", cwd=self.workdir)

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertIn(f"ANCHOR-INVALID: {reason} — evidence that "
                              "does not verify is not evidence", result.stdout)
                self.assertNotIn("Traceback", result.stderr)
                # The good row beside it is still judged.
                self.assertIn("ANCHOR-PENDING", result.stdout)
                self.assertNotIn("sneaky", result.stdout)
                self.assertNotIn("not-base64", result.stdout)

    def test_a_pending_row_naming_no_calendar_is_still_judged(self):
        # A calendar is where an upgrade asks, not part of the proof: a
        # row without one still replays, so it is no evidence against.
        self.write_sidecar(self.row({"calendar": DROP}))

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ANCHOR-PENDING", result.stdout)

    def test_upgrade_skips_a_malformed_row_and_upgrades_the_good_one(self):
        self.server.mode = "complete"
        malformed = [self.row(change) for change, _ in MALFORMED_ROWS]
        # A calendar left out is no fault in a proof, but nothing to ask.
        malformed.append(self.row({"calendar": DROP}))
        self.write_sidecar(*malformed, self.row())

        result = run_receipts("anchor", "--upgrade", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("upgraded:", result.stdout)
        self.assertEqual(len(self.server.polled), 1)
        lines = self.sidecar.read_text("utf-8").splitlines()
        self.assertEqual(lines[:-1], malformed + [self.row()])
        upgraded = json.loads(lines[-1])
        self.assertEqual((upgraded["kind"], upgraded["head"], upgraded["n"]),
                         ("anchor", self.head, 1))

    def test_upgrade_skips_a_calendar_that_is_not_a_url(self):
        # A string, so the row has its shape, but no URL urllib can open:
        # the row is skipped with a line naming the field, and the good
        # pending proof behind it is still asked about and upgraded.
        other = start_calendar(self, b"other-nonce")
        other.mode = "complete"
        good = json.dumps({
            "kind": "anchor", "head": self.head, "n": 1,
            "ts": "2026-09-25T10:00:00Z", "calendar": other.url,
            "proof": base64.b64encode(pending_proof(
                other.nonce, other.url)).decode()},
            sort_keys=True, separators=(",", ":"))
        for calendar in ("not a sneaky url", "http://[sneaky"):
            with self.subTest(calendar=calendar):
                other.polled.clear()
                bad = self.row({"calendar": calendar})
                self.write_sidecar(bad, good)

                result = run_receipts("anchor", "--upgrade", cwd=self.workdir)

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("the record's calendar is not a URL this "
                              "recorder can ask", result.stderr)
                self.assertNotIn("sneaky", result.stdout + result.stderr)
                self.assertEqual(len(other.polled), 1)
                self.assertIn("upgraded:", result.stdout)
                lines = self.sidecar.read_text("utf-8").splitlines()
                self.assertEqual(lines[:2], [bad, good])
                self.assertEqual(len(lines), 3)


# A pending proof in twelve bytes, made by nobody: a pending attestation
# naming "http://x" and no operation before it. It replays from any head.
FORGED_PENDING = "AIPf4w0u+QyOCQhodHRwOi8veA=="


class AnchorDedupeTest(unittest.TestCase):
    """#366: `anchor` asks the session end's question before it asks a
    calendar. A head the sidecar holds a proof for that replays is
    `already anchored`, exit 0, and no calendar is asked, unless `--force`
    says otherwise, so the supervisor's keeper can run the verb on every
    turn a head is ripe and leave the answer to it. A row that does not
    replay is not the head's anchor. A row that does replay, forged or
    copied from another head, is taken for one: nothing offline tells a
    pending proof from a calendar's apart, and the tests below that say
    so pin the limit SPEC 9.4 names, and what verify says of such a row."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.sidecar = self.workdir / "receipts.jsonl.anchors.jsonl"
        self.server = start_calendar(self, b"fake-nonce")
        run_receipts("init", cwd=self.workdir)
        self.log_step("step 1")

    def log_step(self, action):
        run_receipts("log", "--actor", "agent", "--action", action,
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()

    def anchor(self, *extra):
        return run_receipts("anchor", "--calendar", self.server.url, *extra,
                            cwd=self.workdir)

    def anchor_rows(self):
        return [json.loads(line) for line in
                self.sidecar.read_text("utf-8").splitlines()]

    def test_an_anchored_head_is_already_anchored_and_no_calendar_is_asked(self):
        first = self.anchor()
        rows = self.sidecar.read_text("utf-8")

        again = self.anchor()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual((again.returncode, again.stdout.strip()),
                         (0, f"already anchored head {self.head[:12]}… "
                             "(entry 1)"), again.stderr)
        self.assertEqual(len(self.server.submitted), 1)
        self.assertEqual(self.sidecar.read_text("utf-8"), rows,
                         "nothing was tried, so nothing is written down")

    def test_a_completed_proof_is_already_anchored_too(self):
        self.anchor()
        self.server.mode = "complete"
        upgraded = run_receipts("anchor", "--upgrade", cwd=self.workdir)
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        self.sidecar.write_text(json.dumps(self.anchor_rows()[-1]) + "\n",
                                encoding="utf-8")

        again = self.anchor()

        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already anchored", again.stdout)
        self.assertEqual(len(self.server.submitted), 1)

    def test_force_submits_an_anchored_head_again(self):
        self.anchor()

        forced = self.anchor("--force")

        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertIn(f"anchored head {self.head[:12]}… (entry 1) via "
                      f"{self.server.url}", forced.stdout)
        self.assertNotIn("already", forced.stdout)
        self.assertEqual(self.server.submitted, [bytes.fromhex(self.head)] * 2)
        self.assertEqual([r["head"] for r in self.anchor_rows()],
                         [self.head, self.head])

    def test_force_beside_upgrade_is_a_usage_error(self):
        self.anchor()

        result = run_receipts("anchor", "--upgrade", "--force",
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("--force", result.stderr)
        self.assertEqual(self.server.polled, [])

    def test_a_new_head_is_anchored_although_the_old_one_holds_a_proof(self):
        self.anchor()
        old = self.head
        self.log_step("step 2")

        result = self.anchor()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r["head"] for r in self.anchor_rows()],
                         [old, self.head])

    def test_a_row_whose_proof_does_not_replay_is_not_the_heads_anchor(self):
        for proof in ("", "AAAA", "not base64!", 5, None):
            with self.subTest(proof=proof):
                self.server.submitted.clear()
                planted = {"kind": "anchor", "head": self.head, "n": 1,
                           "proof": proof}
                self.sidecar.write_text(json.dumps(planted) + "\n",
                                        encoding="utf-8")

                result = self.anchor()

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertNotIn("already", result.stdout)
                self.assertEqual(self.server.submitted,
                                 [bytes.fromhex(self.head)])
                self.assertEqual(self.anchor_rows()[0], planted)

    def test_the_limit_a_forged_pending_proof_stops_a_new_anchor(self):
        # The limit, pinned: nobody signs a pending attestation, so a
        # dozen bytes naming the head replay and are taken for its
        # anchor. verify never reads it as a checked one: it is pending.
        self.sidecar.write_text(json.dumps(
            {"kind": "anchor", "head": self.head, "n": 1,
             "proof": FORGED_PENDING}) + "\n", encoding="utf-8")

        result = self.anchor()
        judged = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already anchored", result.stdout)
        self.assertEqual(self.server.submitted, [])
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn(f"ANCHOR-PENDING: head {self.head[:12]}…",
                      judged.stdout)
        self.assertNotIn("ANCHORED", judged.stdout)

    def test_the_limit_a_pending_proof_copied_from_another_head_stops_it(self):
        # A calendar's own pending proof, moved to the next head: it
        # still replays, to another commitment, so it is taken for that
        # head's anchor, and verify reads it as pending, never anchored.
        self.anchor()
        (row,) = self.anchor_rows()
        self.log_step("step 2")
        self.sidecar.write_text(json.dumps({**row, "head": self.head, "n": 2})
                                + "\n", encoding="utf-8")

        result = self.anchor()
        judged = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertIn("already anchored", result.stdout)
        self.assertEqual(len(self.server.submitted), 1)
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn(f"ANCHOR-PENDING: head {self.head[:12]}…",
                      judged.stdout)
        self.assertNotIn("ANCHORED", judged.stdout)

    def test_the_limit_a_completed_proof_copied_from_another_head(self):
        # A completed proof moved to the next head replays too, but to a
        # root that is not its block's: verify reads the claim as not
        # checked, and the block's own header checks the row it came
        # from and never the copy, which alone is HEADER-UNMATCHED.
        self.anchor()
        self.server.mode = "complete"
        run_receipts("anchor", "--upgrade", cwd=self.workdir)
        completed = self.anchor_rows()[-1]
        header = block_header(replayed_root(
            completed["head"], self.server.nonce, self.server.prefix,
            self.server.suffix))
        self.log_step("step 2")
        copied = {**completed, "head": self.head, "n": 2}
        self.sidecar.write_text(json.dumps(copied) + "\n", encoding="utf-8")

        result = self.anchor()
        judged = run_receipts("verify", "--anchors", "--block-header",
                              header.hex(), cwd=self.workdir)

        self.assertIn("already anchored", result.stdout)
        self.assertEqual(len(self.server.submitted), 1)
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn("ANCHORED: entries 0..2: the attestation claims Bitcoin "
                      "block 850000, and the block was not checked",
                      judged.stdout)
        self.assertIn("HEADER-UNMATCHED", judged.stdout)
        self.assertNotIn("existed by the block", judged.stdout)


if __name__ == "__main__":
    unittest.main()
