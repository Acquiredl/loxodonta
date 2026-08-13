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
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RECEIPTS = REPO_ROOT / "receipts.py"

TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")


def clean_env():
    """Subprocess env with proxy variables stripped, so urllib in the CLI
    talks straight to the fake calendar on 127.0.0.1."""
    env = dict(os.environ)
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            del env[key]
    return env


def run_receipts(*args, cwd):
    return subprocess.run(
        [sys.executable, str(RECEIPTS), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
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


def expected_merkle_root(head_hex, nonce, prefix, suffix):
    """Replay the fake proofs by hand: the digest the Bitcoin attestation
    claims as block merkle root, in explorer display order (reversed)."""
    commitment = hashlib.sha256(bytes.fromhex(head_hex) + nonce).digest()
    root = hashlib.sha256(
        hashlib.sha256(prefix + commitment + suffix).digest()
    ).digest()
    return root[::-1].hex()


# --- Fake calendar ------------------------------------------------------------

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


class AnchorTest(unittest.TestCase):
    HEIGHT = 850000

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.log_path = self.workdir / "receipts.jsonl"
        self.sidecar = self.workdir / "receipts.jsonl.anchors.jsonl"

        self.server = HTTPServer(("127.0.0.1", 0), FakeCalendarHandler)
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

        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.sidecar.exists())

    def test_anchor_without_log_errors_cleanly(self):
        empty = self.workdir / "elsewhere"
        empty.mkdir()

        result = run_receipts(
            "anchor", "--calendar", self.server.url, cwd=empty
        )

        self.assertEqual(result.returncode, 1)
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
        self.assertIn("ANCHORED", result.stdout)
        self.assertIn(f"block {self.HEIGHT}", result.stdout)
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


if __name__ == "__main__":
    unittest.main()
