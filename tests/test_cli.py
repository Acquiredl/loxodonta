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


def spec_hash(entry_without_hash):
    """Independent SPEC §4 canonicalization — deliberately reimplemented here,
    never imported from receipts.py, so tests prove the tool matches the spec
    rather than matching itself."""
    canonical = json.dumps(
        entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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
        genesis["entry_hash"] = spec_hash(genesis)
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


class FileReferenceTest(ReceiptsCliTest):
    def setUp(self):
        super().setUp()
        run_receipts("init", cwd=self.workdir)

    def write_file(self, relpath, content):
        path = self.workdir / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def last_entry(self):
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])

    def test_log_with_file_records_path_and_sha256(self):
        self.write_file("report.md", "elephants never forget\n")
        expected_sha = hashlib.sha256(
            (self.workdir / "report.md").read_bytes()
        ).hexdigest()

        result = run_receipts(
            "log", "--actor", "agent", "--action", "wrote report",
            "--file", "report.md", cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.last_entry()["files"],
            [{"path": "report.md", "sha256": expected_sha}],
        )
        verify_result = run_receipts("verify", cwd=self.workdir)
        self.assertEqual(verify_result.returncode, 0, verify_result.stdout)


    def test_case_only_differing_reference_warns_at_write_time(self):
        self.write_file("report.md", "content\n")
        run_receipts(
            "log", "--actor", "agent", "--action", "first spelling",
            "--file", "report.md", cwd=self.workdir,
        )

        result = run_receipts(
            "log", "--actor", "agent", "--action", "second spelling",
            "--file", "Report.md", cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("case", result.stderr.lower())
        self.assertIn("report.md", result.stderr.lower())
        self.assertEqual(self.last_entry()["files"][0]["path"], "Report.md")

    def test_log_with_nonexistent_file_errors_cleanly(self):
        before = self.log_path.read_text(encoding="utf-8")

        result = run_receipts(
            "log", "--actor", "agent", "--action", "phantom file",
            "--file", "not-there.md", cwd=self.workdir,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not-there.md", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.log_path.read_text(encoding="utf-8"), before)

    def test_backslash_path_stores_forward_slash_spelling(self):
        self.write_file("sub/report.md", "nested\n")

        run_receipts(
            "log", "--actor", "agent", "--action", "backslash intake",
            "--file", "sub\\report.md", cwd=self.workdir,
        )
        backslash_files = self.last_entry()["files"]

        run_receipts(
            "log", "--actor", "agent", "--action", "forward-slash intake",
            "--file", "sub/report.md", cwd=self.workdir,
        )
        forward_files = self.last_entry()["files"]

        self.assertEqual(backslash_files[0]["path"], "sub/report.md")
        self.assertEqual(backslash_files, forward_files)

    def test_absolute_and_dotdot_paths_are_rejected(self):
        self.write_file("report.md", "content\n")
        before = self.log_path.read_text(encoding="utf-8")

        for bad_path in (str(self.workdir / "report.md"), "../escape.md"):
            result = run_receipts(
                "log", "--actor", "agent", "--action", "bad path",
                "--file", bad_path, cwd=self.workdir,
            )
            self.assertNotEqual(result.returncode, 0, bad_path)
            self.assertIn("error", result.stderr.lower())

        self.assertEqual(self.log_path.read_text(encoding="utf-8"), before)

    def test_multiple_files_sorted_by_path_bytes(self):
        for name in ("b.md", "a.md", "sub/c.md"):
            self.write_file(name, f"{name}\n")

        run_receipts(
            "log", "--actor", "agent", "--action", "multi-file",
            "--file", "b.md", "--file", "sub/c.md", "--file", "a.md",
            cwd=self.workdir,
        )

        paths = [ref["path"] for ref in self.last_entry()["files"]]
        self.assertEqual(paths, ["a.md", "b.md", "sub/c.md"])

    def test_verify_files_reports_modified_file_chain_intact(self):
        self.write_file("report.md", "original\n")
        run_receipts(
            "log", "--actor", "agent", "--action", "wrote report",
            "--file", "report.md", cwd=self.workdir,
        )
        self.write_file("report.md", "sneakily changed after logging\n")

        result = run_receipts("verify", "--files", cwd=self.workdir)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("FILES-DIVERGED", result.stdout)
        self.assertIn("MODIFIED-SINCE-LOGGED", result.stdout)
        self.assertIn("report.md", result.stdout)
        self.assertNotIn("BROKEN", result.stdout)

    def test_verify_files_current_and_missing(self):
        self.write_file("kept.md", "kept\n")
        self.write_file("doomed.md", "doomed\n")
        run_receipts(
            "log", "--actor", "agent", "--action", "wrote both",
            "--file", "kept.md", "--file", "doomed.md", cwd=self.workdir,
        )
        (self.workdir / "doomed.md").unlink()

        result = run_receipts("verify", "--files", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CURRENT: kept.md", result.stdout)
        self.assertIn("doomed.md", result.stdout)
        self.assertIn("VALID", result.stdout)
        self.assertNotIn("BROKEN", result.stdout)

    def test_latest_reference_per_path_is_authoritative(self):
        self.write_file("report.md", "draft\n")
        run_receipts(
            "log", "--actor", "agent", "--action", "draft",
            "--file", "report.md", cwd=self.workdir,
        )
        self.write_file("report.md", "final\n")
        run_receipts(
            "log", "--actor", "agent", "--action", "final",
            "--file", "report.md", cwd=self.workdir,
        )

        result = run_receipts("verify", "--files", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("CURRENT: report.md", result.stdout)


class HeadTest(ReceiptsCliTest):
    def test_head_prints_last_entry_hash(self):
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 2", cwd=self.workdir)
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        last_hash = json.loads(lines[-1])["entry_hash"]

        result = run_receipts("head", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), last_hash)

    def test_verify_expect_head_with_true_head_is_valid(self):
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1", cwd=self.workdir)
        head = run_receipts("head", cwd=self.workdir).stdout.strip()

        result = run_receipts("verify", "--expect-head", head, cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALID", result.stdout)

    def test_regenerated_chain_passes_plain_verify_but_fails_head_record(self):
        run_receipts("init", cwd=self.workdir)
        for action in ("step 1", "the incriminating step", "step 3"):
            run_receipts(
                "log", "--actor", "agent", "--action", action, cwd=self.workdir
            )
        recorded_head = run_receipts("head", cwd=self.workdir).stdout.strip()

        # The adversary: drop entry 2, renumber, recompute every hash so the
        # chain is internally consistent again (independent canonicalization).
        entries = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        del entries[2]
        prev = entries[0]["entry_hash"]  # genesis untouched
        for i, entry in enumerate(entries[1:], start=1):
            entry.pop("entry_hash")
            entry["n"] = i
            entry["prev"] = prev
            entry["entry_hash"] = prev = spec_hash(entry)
        self.log_path.write_text(
            "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n"
                    for e in entries),
            encoding="utf-8",
        )

        plain = run_receipts("verify", cwd=self.workdir)
        self.assertEqual(plain.returncode, 0, plain.stdout)
        self.assertIn("VALID", plain.stdout)

        against_record = run_receipts(
            "verify", "--expect-head", recorded_head, cwd=self.workdir
        )
        self.assertEqual(against_record.returncode, 3, against_record.stdout)
        self.assertIn("HEAD-MISMATCH", against_record.stdout)
        self.assertIn("not the recorded history", against_record.stdout)
        self.assertNotIn("BROKEN", against_record.stdout)

    def test_head_on_missing_or_empty_log_errors_cleanly(self):
        missing = run_receipts("head", cwd=self.workdir)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("init", missing.stderr)
        self.assertNotIn("Traceback", missing.stderr)

        self.log_path.write_text("", encoding="utf-8")
        empty = run_receipts("head", cwd=self.workdir)
        self.assertNotEqual(empty.returncode, 0)
        self.assertIn("empty", empty.stderr)
        self.assertNotIn("Traceback", empty.stderr)

    def test_malformed_expect_head_is_usage_error_not_verdict(self):
        run_receipts("init", cwd=self.workdir)

        for bad in ("not-hex-at-all", "abc123"):  # garbage; wrong length
            result = run_receipts(
                "verify", "--expect-head", bad, cwd=self.workdir
            )
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertIn("expect-head", result.stderr)
            for verdict in ("VALID", "BROKEN", "HEAD-MISMATCH"):
                self.assertNotIn(verdict, result.stdout, bad)


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
        foreign["entry_hash"] = spec_hash(foreign)
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
        entry["entry_hash"] = spec_hash(entry)
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


class TornTailTest(ReceiptsCliTest):
    def setUp(self):
        super().setUp()
        run_receipts("init", cwd=self.workdir)
        for i in range(1, 4):
            run_receipts(
                "log", "--actor", "agent", "--action", f"step {i}", cwd=self.workdir
            )

    def truncate_line(self, index):
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        lines[index] = lines[index][: len(lines[index]) // 2]
        self.log_path.write_text(
            "".join(l + "\n" for l in lines), encoding="utf-8"
        )

    def test_torn_final_line_reports_torn_tail_and_intact_prefix(self):
        self.truncate_line(3)

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("torn tail at line 3", result.stdout)
        self.assertIn("intact", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_torn_middle_line_is_ordinary_broken(self):
        self.truncate_line(2)

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("BROKEN at entry 2", result.stdout)
        self.assertNotIn("torn tail", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_backward_ts_warns_but_verdict_stays_valid(self):
        # Rewrite the last entry with a ts before its predecessor's and a
        # correctly recomputed hash: mechanically valid, suspicious testimony.
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[3])
        prev_entry = json.loads(lines[2])
        entry.pop("entry_hash")
        entry["ts"] = "2020-01-01T00:00:00Z"
        entry["prev"] = prev_entry["entry_hash"]
        entry["entry_hash"] = spec_hash(entry)
        lines[3] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        self.log_path.write_text(
            "".join(l + "\n" for l in lines), encoding="utf-8"
        )

        result = run_receipts("verify", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALID", result.stdout)
        combined = result.stdout + result.stderr
        self.assertIn("WARN", combined)
        self.assertIn("entry 3", combined)

    def test_no_repair_or_trim_command_exists(self):
        help_result = run_receipts("--help", cwd=self.workdir)
        self.assertNotIn("repair", help_result.stdout.lower())
        self.assertNotIn("trim", help_result.stdout.lower())

        for forbidden in ("repair", "trim"):
            result = run_receipts(forbidden, cwd=self.workdir)
            self.assertNotEqual(result.returncode, 0, forbidden)


if __name__ == "__main__":
    unittest.main()
