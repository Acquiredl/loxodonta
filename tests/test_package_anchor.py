"""Behavioral tests for the package's first seal (ADR-0026 rulings 4, 6
and 7, applying ADR-0007; #180): `supervisor package --anchor` posts the
manifest's sha256 to the calendars once and writes
`manifest.json.anchors.jsonl`; `loxodonta verify-package` judges that
anchor offline and earns `+ ANCHORED` on the verdict line only from it.

The store is written through `loxodonta hook`, with a completed anchor
on the chain's own sidecar, so every package here carries a chain
anchor that must stay detail and never earn the package rung. The
calendar is test_anchor's fake, so no network, ever. Every test drives
the public CLI as an issuer or a recipient would.
"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from test_anchor import (FakeCalendar, FakeCalendarHandler, clean_env,
                         expected_merkle_root)
from test_package import (LOXODONTA, SUPERVISOR, PackageCase, completed_anchor,
                          neutral_env, run)

SESSION = "d0d0d0d0-aaaa-bbbb-cccc-000000000001"
SIDECAR = "manifest.json.anchors.jsonl"


class SealedPackageTest(PackageCase):
    """One session, recorded through the hook, its chain head anchored
    (a completed proof in the chain's sidecar); a fake calendar that
    answers pending and can complete on request."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.witness = self.root / "no-witness"
        self.witness.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        # The neutral home, and no proxy in the way of 127.0.0.1.
        self.env = {**clean_env(), **neutral_env(self.home)}
        for command in ("pytest -q", "git status"):
            self.hook(SESSION, "Bash", {"command": command})
        (drawer,) = [p for p in (self.home / ".loxodonta" / "receipts").iterdir()
                     if p.is_dir()]
        self.chain = drawer / f"receipts-{SESSION}.jsonl"
        head = run(LOXODONTA, "head", "--log", str(self.chain)).stdout.strip()
        self.chain.with_name(self.chain.name + ".anchors.jsonl").write_text(
            completed_anchor(head), encoding="utf-8")

        self.server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
        self.server.nonce = b"fake-nonce"
        self.server.prefix = b"left-branch"
        self.server.suffix = b"right-branch"
        self.server.height = 850123
        self.server.mode = "pending"
        self.server.submitted = []
        self.server.polled = []
        self.server.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def hook(self, session, tool, tool_input):
        payload = json.dumps({"session_id": session,
                              "hook_event_name": "PostToolUse",
                              "tool_name": tool, "tool_input": tool_input,
                              "tool_response": {}})
        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook"],
            input=payload.encode("utf-8"), capture_output=True,
            env={**self.env, "PYTHONIOENCODING": "utf-8",
                 "CLAUDE_PROJECT_DIR": str(self.project)})
        self.assertEqual(result.returncode, 0, result.stderr)

    def anchored_folder(self, name="pkg"):
        """A folder package of the session, its manifest anchored with
        the fake calendar. Returns the folder."""
        folder = self.work / name
        result = self.package(SESSION, "--folder", "--out", str(folder),
                              "--anchor", "--calendar", self.server.url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return folder

    @staticmethod
    def manifest_digest(folder):
        return hashlib.sha256((folder / "manifest.json").read_bytes()).hexdigest()

    @staticmethod
    def sidecar_records(folder):
        return [json.loads(line) for line in
                (folder / SIDECAR).read_text("utf-8").splitlines()]

    def test_anchor_posts_the_manifest_digest_and_declares_the_seal(self):
        # ADR-0026 ruling 4: the manifest's sha256 goes to the calendars
        # once, after the manifest is written; the proof is an ordinary
        # anchor record whose head is that digest and which has no n;
        # and the manifest, written before the proof exists, declares
        # the seal so a stripped sidecar is caught.
        folder = self.anchored_folder()

        digest = self.manifest_digest(folder)
        self.assertEqual(self.server.submitted, [bytes.fromhex(digest)])
        records = self.sidecar_records(folder)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["head"], digest)
        self.assertNotIn("n", records[0])
        self.assertEqual(records[0]["calendar"], self.server.url)
        self.assertEqual(self.manifest_of(folder)["seals"], ["anchor"])

    def test_the_zip_carries_the_sidecar_after_the_manifest(self):
        # The zip keeps the write order, and the seal is applied after
        # the manifest exists, so its proof is the member after it.
        zipped = self.work / "sealed.zip"
        result = self.package(SESSION, "--out", str(zipped), "--anchor",
                              "--calendar", self.server.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with zipfile.ZipFile(zipped) as package:
            names = package.namelist()
            self.assertEqual(names[-2:], ["manifest.json", SIDECAR], names)
            digest = hashlib.sha256(package.read("manifest.json")).hexdigest()
            (record,) = [json.loads(line) for line in
                         package.read(SIDECAR).decode("utf-8").splitlines()]
        self.assertEqual(record["head"], digest)
        self.assertEqual(self.server.submitted, [bytes.fromhex(digest)])
        self.assertIn("anchored", result.stdout)
        self.assertIn("--upgrade --manifest", result.stdout)


if __name__ == "__main__":
    unittest.main()
