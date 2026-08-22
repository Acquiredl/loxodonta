"""Endpoint smoke tests for the supervisor's HTTP face (`supervisor.py serve`).

The face is serialization only, zero decisions (ADR-0005): a localhost-only
stdlib server, a status endpoint speaking the scan shape unchanged, and an
inline single-page frontend — no framework, no build step, nothing fetched
from anywhere but this machine. Tests drive real HTTP against an ephemeral
port; how the browser paints the band is manual fire-drill territory, but
the claims the page is built from are strings we can hold still here.
"""

import base64
import json
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECEIPTS = REPO_ROOT / "receipts.py"

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")

# Straight to 127.0.0.1 — never through a proxy someone's shell configured.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def make_chain(log_dir, session, entries=2):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the face is tested against what the tool writes."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"receipts-{session}.jsonl"
    subprocess.run([sys.executable, str(RECEIPTS), "init", "--log", str(log)],
                   capture_output=True, check=True)
    for i in range(entries):
        subprocess.run(
            [sys.executable, str(RECEIPTS), "log", "--log", str(log),
             "--actor", "claude-code", "--action", f"step {i}"],
            capture_output=True, check=True)
    return log


def ots_varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | 0x80 if n else byte)
        if not n:
            return bytes(out)


def write_completed_anchor(log, height=850000):
    """A minimal but genuine OTS timestamp: one sha256 op, then a Bitcoin
    attestation — enough for `verify --anchors` to replay offline and
    report ANCHORED, with no network and no calendar (ANCHORING.md §4)."""
    head = subprocess.run(
        [sys.executable, str(RECEIPTS), "head", "--log", str(log)],
        capture_output=True, text=True, check=True).stdout.strip()
    payload = ots_varint(height)
    proof = (b"\x08"
             + b"\x00" + TAG_BITCOIN + ots_varint(len(payload)) + payload)
    record = {"head": head, "n": 2, "ts": "2026-08-22T09:00:00Z",
              "calendar": "https://calendar.example.test",
              "proof": base64.b64encode(proof).decode()}
    Path(str(log) + ".anchors.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8")


class ServeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def serve(self):
        """Start `serve` on an ephemeral port and read the announced URL."""
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if match is None:
            self.proc.kill()
            _, err = self.proc.communicate()
            self.fail(f"serve announced no localhost URL: {line!r}\n{err}")
        self.url = match.group()

    def _stop(self):
        self.proc.kill()
        self.proc.communicate()

    def get(self, path):
        with OPENER.open(self.url + path, timeout=30) as response:
            return (response.status, response.headers.get("Content-Type", ""),
                    response.read().decode("utf-8"))

    def test_serve_binds_localhost_only(self):
        # The announcement is the bind: an ephemeral port on 127.0.0.1,
        # answering — nothing is offered to any other interface.
        self.serve()

        status, _, _ = self.get("/")

        self.assertEqual(status, 200)
        self.assertTrue(self.url.startswith("http://127.0.0.1:"))

    def test_status_endpoint_speaks_the_scan_shape_unchanged(self):
        # One valid chain, one anchored, one tampered: the endpoint must
        # return byte-for-byte the same report the scan CLI prints —
        # serialization only, zero decisions.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        anchored = make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        write_completed_anchor(anchored)
        tampered = make_chain(self.root / "gamma" / "receipts", "sess-cccc")
        lines = tampered.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["action"] = "something else entirely"
        lines[1] = json.dumps(entry)
        tampered.write_text("".join(l + "\n" for l in lines),
                            encoding="utf-8")
        self.serve()

        status, ctype, body = self.get("/api/status")

        self.assertEqual(status, 200)
        self.assertIn("application/json", ctype)
        cli = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--root",
             str(self.root), "--json"],
            capture_output=True, text=True)
        self.assertEqual(json.loads(body), json.loads(cli.stdout))

    def test_front_page_is_inline_html_with_no_outside_dependencies(self):
        self.serve()

        status, ctype, page = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn("/api/status", page, "the band renders the scan")
        self.assertNotIn("<script src", page, "no framework, no CDN")
        self.assertNotIn("<link", page, "nothing fetched from off-machine")

    def test_front_page_renders_tiers_as_distinct_claims(self):
        # The strings the band is built from: VALID and ANCHORED are
        # different claims, the exit-3 tier reads gravest, and superseded
        # damage is quiet evidence rather than a live alarm.
        self.serve()

        _, _, page = self.get("/")

        self.assertIn("ANCHORED", page)
        self.assertIn("VALID", page)
        self.assertIn("not the recorded history", page)
        self.assertIn("superseded", page)
        self.assertIn("verify", page, "verdicts come from receipts verify")

    def test_no_anti_terms_in_the_user_visible_surface(self):
        self.serve()

        _, _, page = self.get("/")

        lowered = page.lower()
        for anti_term in ("blockchain", "immutable", "audit"):
            self.assertNotIn(anti_term, lowered)

    def test_unknown_path_is_404(self):
        self.serve()

        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/no-such-surface")
        self.assertEqual(caught.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
