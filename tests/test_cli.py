"""Behavioral tests for the receipts CLI.

Every test drives the public CLI surface (subprocess on receipts.py) and
asserts on stdout, exit codes, and file state — never internals. See
docs/SPEC.md; entries, genesis, canonical form, and verdicts are defined
there.
"""

import hashlib
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


    def test_init_refuses_to_overwrite_existing_log(self):
        run_receipts("init", cwd=self.workdir)
        original = self.log_path.read_text(encoding="utf-8")

        result = run_receipts("init", cwd=self.workdir)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exists", result.stderr)
        self.assertEqual(self.log_path.read_text(encoding="utf-8"), original)


class LogFlagTest(ReceiptsCliTest):
    def test_all_commands_accept_log_flag(self):
        custom = self.workdir / "custom.jsonl"

        init_result = run_receipts("init", "--log", "custom.jsonl", cwd=self.workdir)
        verify_result = run_receipts("verify", "--log", "custom.jsonl", cwd=self.workdir)

        self.assertEqual(init_result.returncode, 0, init_result.stderr)
        self.assertTrue(custom.exists())
        self.assertFalse(self.log_path.exists())
        self.assertEqual(verify_result.returncode, 0, verify_result.stderr)
        self.assertIn("VALID", verify_result.stdout)


class LogTest(ReceiptsCliTest):
    def test_log_three_entries_then_verify_valid(self):
        run_receipts("init", cwd=self.workdir)
        for i in range(1, 4):
            result = run_receipts(
                "log", "--actor", "agent", "--action", f"step {i}", cwd=self.workdir
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 4)

        verify_result = run_receipts("verify", cwd=self.workdir)
        self.assertEqual(verify_result.returncode, 0, verify_result.stdout)
        self.assertIn("VALID", verify_result.stdout)


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

    def test_genesis_hash_matches_independent_spec_canonicalization(self):
        # Independent SPEC §4 implementation: keys sorted, compact separators,
        # UTF-8, no trailing newline — written here, not imported from the tool.
        genesis = {
            "v": "0.1",
            "n": 0,
            "ts": "2026-08-10T12:00:00Z",
            "actor": "receipts",
            "action": "genesis",
            "files": [],
            "prev": None,
        }
        canonical = json.dumps(
            genesis, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        genesis["entry_hash"] = hashlib.sha256(canonical).hexdigest()
        # Deliberately non-canonical on disk (unsorted keys, spaces): the hash
        # is over canonical form, not file bytes (SPEC §4).
        self.log_path.write_text(json.dumps(genesis) + "\n", encoding="utf-8")

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALID", result.stdout)

    def test_verify_refuses_unknown_format_version_before_any_other_rule(self):
        genesis = {
            "v": "9.9",
            "n": 0,
            "ts": "2026-08-10T00:00:00Z",
            "actor": "receipts",
            "action": "genesis",
            "files": [],
            "prev": None,
            "entry_hash": "f" * 64,  # garbage — version refusal must win over hash check
        }
        self.log_path.write_text(json.dumps(genesis) + "\n", encoding="utf-8")

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 4)
        output = result.stdout + result.stderr
        self.assertIn("UNSUPPORTED-VERSION", output)
        self.assertIn('"9.9"', output)
        self.assertIn('"0.1"', output)
        self.assertNotIn("BROKEN", output)


    def test_log_rejects_empty_actor_and_action(self):
        run_receipts("init", cwd=self.workdir)
        before = self.log_path.read_text(encoding="utf-8")

        for flags in (("--actor", "", "--action", "did a thing"),
                      ("--actor", "agent", "--action", "")):
            result = run_receipts("log", *flags, cwd=self.workdir)
            self.assertNotEqual(result.returncode, 0, flags)
            self.assertIn("non-empty", result.stderr)

        self.assertEqual(self.log_path.read_text(encoding="utf-8"), before)

    def test_log_without_init_errors_cleanly(self):
        result = run_receipts(
            "log", "--actor", "agent", "--action", "step 1", cwd=self.workdir
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("init", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.log_path.exists())


class TamperTest(ReceiptsCliTest):
    """The core battery: each way a writer might rewrite history is caught."""

    def setUp(self):
        super().setUp()
        run_receipts("init", cwd=self.workdir)
        for i in range(1, 4):
            run_receipts(
                "log", "--actor", "agent", "--action", f"step {i}", cwd=self.workdir
            )

    def read_lines(self):
        return self.log_path.read_text(encoding="utf-8").splitlines()

    def write_lines(self, lines):
        self.log_path.write_text("".join(l + "\n" for l in lines), encoding="utf-8")

    def assert_broken(self, at_entry):
        result = run_receipts("verify", cwd=self.workdir)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"BROKEN at entry {at_entry}", result.stdout)
        self.assertNotIn("VALID", result.stdout)
        return result

    def test_editing_past_entry_text_is_caught(self):
        lines = self.read_lines()
        entry = json.loads(lines[2])
        entry["action"] = "step 2 (rewritten to look innocent)"
        lines[2] = json.dumps(entry)
        self.write_lines(lines)

        self.assert_broken(at_entry=2)

    def test_deleting_middle_entry_is_caught(self):
        lines = self.read_lines()
        del lines[2]
        self.write_lines(lines)

        self.assert_broken(at_entry=2)

    def test_swapping_two_entries_is_caught(self):
        lines = self.read_lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.write_lines(lines)

        self.assert_broken(at_entry=1)

    def test_splicing_foreign_well_formed_entry_is_caught(self):
        # Correct n, internally valid hash — but prev commits to a history
        # this chain never had. Only the chain rule can catch it.
        foreign = {
            "n": 3,
            "ts": "2026-08-10T12:00:00Z",
            "actor": "agent",
            "action": "step 3 (from a parallel universe)",
            "files": [],
            "prev": hashlib.sha256(b"some other history").hexdigest(),
        }
        canonical = json.dumps(
            foreign, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        foreign["entry_hash"] = hashlib.sha256(canonical).hexdigest()
        lines = self.read_lines()
        lines[3] = json.dumps(foreign, sort_keys=True, separators=(",", ":"))
        self.write_lines(lines)

        self.assert_broken(at_entry=3)

    def test_extra_schema_field_is_caught_even_with_consistent_hash(self):
        # An entry with a smuggled extra field, hash recomputed over the
        # tampered form: internally consistent, but not v0.1 schema.
        lines = self.read_lines()
        entry = json.loads(lines[2])
        del entry["entry_hash"]
        entry["note"] = "smuggled"
        canonical = json.dumps(
            entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        entry["entry_hash"] = hashlib.sha256(canonical).hexdigest()
        lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        self.write_lines(lines)

        self.assert_broken(at_entry=2)

    def test_two_breaks_are_both_reported_first_named_first(self):
        lines = self.read_lines()
        for i in (1, 3):
            entry = json.loads(lines[i])
            entry["action"] = f"step {i} (rewritten)"
            lines[i] = json.dumps(entry)
        self.write_lines(lines)

        result = self.assert_broken(at_entry=1)
        self.assertIn("BROKEN at entry 3", result.stdout)
        self.assertTrue(result.stdout.startswith("BROKEN at entry 1"))


if __name__ == "__main__":
    unittest.main()
