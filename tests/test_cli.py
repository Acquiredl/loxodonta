"""Behavioral tests for the receipts CLI.

Every test drives the public CLI surface (subprocess on receipts.py) and
asserts on stdout, exit codes, and file state — never internals. See
docs/SPEC.md; entries, genesis, canonical form, and verdicts are defined
there.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RECEIPTS = REPO_ROOT / "receipts.py"


def run_receipts(*args, cwd):
    """Invoke the receipts CLI as an operator would."""
    return subprocess.run(
        [sys.executable, str(RECEIPTS), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class ReceiptsCliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.log_path = self.workdir / "receipts.jsonl"


class InitTest(ReceiptsCliTest):
    def test_init_writes_one_line_pinned_genesis(self):
        result = run_receipts("init", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)

        genesis = json.loads(lines[0])
        self.assertEqual(genesis["v"], "0.1")
        self.assertEqual(genesis["n"], 0)
        self.assertEqual(genesis["actor"], "receipts")
        self.assertEqual(genesis["action"], "genesis")
        self.assertEqual(genesis["files"], [])
        self.assertIsNone(genesis["prev"])
        self.assertRegex(genesis["entry_hash"], r"^[0-9a-f]{64}$")
        self.assertRegex(genesis["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(
            set(genesis),
            {"v", "n", "ts", "actor", "action", "files", "prev", "entry_hash"},
        )


class VerifyTest(ReceiptsCliTest):
    def test_verify_genesis_only_chain_is_valid(self):
        run_receipts("init", cwd=self.workdir)

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALID", result.stdout)

    def test_verify_catches_edited_entry(self):
        run_receipts("init", cwd=self.workdir)
        genesis = json.loads(self.log_path.read_text(encoding="utf-8"))
        genesis["entry_hash"] = "0" * 64
        self.log_path.write_text(json.dumps(genesis) + "\n", encoding="utf-8")

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 1)
        self.assertIn("BROKEN at entry 0", result.stdout)
        self.assertNotIn("VALID", result.stdout)


if __name__ == "__main__":
    unittest.main()
