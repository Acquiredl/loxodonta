"""Behavioral tests for the Stage C hook adapter (`receipts hook`).

The adapter turns a Claude Code PostToolUse payload (JSON on stdin) into
one chained entry — the completeness mechanism of SPEC §8: the log call
sits in the harness, outside the writer's volition. Tests drive the
public CLI with stdin payloads, never internals.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RECEIPTS = REPO_ROOT / "receipts.py"


def run_hook(payload, cwd, *args):
    return subprocess.run(
        [sys.executable, str(RECEIPTS), "hook", *args],
        cwd=cwd,
        input=payload if isinstance(payload, str) else json.dumps(payload),
        capture_output=True,
        text=True,
    )


def run_receipts(*args, cwd):
    return subprocess.run(
        [sys.executable, str(RECEIPTS), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def payload(session="sess-1234abcd", tool="Write", tool_input=None):
    return {
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_input": tool_input if tool_input is not None else {},
        "tool_response": {},
    }


class HookTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)

    def session_log(self, session="sess-1234abcd"):
        return self.workdir / f"receipts-{session}.jsonl"

    def entries(self, session="sess-1234abcd"):
        return [
            json.loads(line)
            for line in self.session_log(session).read_text(
                encoding="utf-8").splitlines()
        ]

    def test_hook_starts_a_session_chain_and_logs_the_tool_call(self):
        (self.workdir / "notes.md").write_text("hello\n", encoding="utf-8")

        result = run_hook(
            payload(tool="Write", tool_input={"file_path": "notes.md"}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        entries = self.entries()
        self.assertEqual(len(entries), 2)  # genesis + the tool call
        self.assertEqual(entries[0]["action"], "genesis")
        entry = entries[1]
        self.assertEqual(entry["actor"], "claude-code")
        self.assertIn("Write", entry["action"])
        self.assertIn("notes.md", entry["action"])
        self.assertEqual(entry["files"][0]["path"], "notes.md")

        verify = run_receipts(
            "verify", "--log", self.session_log().name, cwd=self.workdir
        )
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_hook_chains_repeated_calls_in_one_session(self):
        run_hook(payload(tool="Bash",
                         tool_input={"command": "pytest -q"}), cwd=self.workdir)
        run_hook(payload(tool="Bash",
                         tool_input={"command": "git status"}), cwd=self.workdir)

        entries = self.entries()
        self.assertEqual([e["n"] for e in entries], [0, 1, 2])
        self.assertIn("pytest -q", entries[1]["action"])
        self.assertIn("git status", entries[2]["action"])

    def test_two_sessions_get_sibling_chains(self):
        run_hook(payload(session="sess-aaaa"), cwd=self.workdir)
        run_hook(payload(session="sess-bbbb"), cwd=self.workdir)

        self.assertTrue(self.session_log("sess-aaaa").exists())
        self.assertTrue(self.session_log("sess-bbbb").exists())
        self.assertEqual(len(self.entries("sess-aaaa")), 2)
        self.assertEqual(len(self.entries("sess-bbbb")), 2)

    def test_absolute_file_path_inside_project_is_fingerprinted(self):
        target = self.workdir / "src" / "main.py"
        target.parent.mkdir()
        target.write_text("print('hi')\n", encoding="utf-8")

        result = run_hook(
            payload(tool="Edit", tool_input={"file_path": str(target)}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        entry = self.entries()[1]
        self.assertEqual(entry["files"][0]["path"], "src/main.py")

    def test_file_outside_project_is_logged_without_fingerprint(self):
        # The receipt still records the action; only the file reference is
        # dropped — a hook must never fail the session over path layout.
        result = run_hook(
            payload(tool="Edit", tool_input={"file_path": "/etc/hostname"}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        entry = self.entries()[1]
        self.assertEqual(entry["files"], [])
        self.assertIn("/etc/hostname", entry["action"])

    def test_missing_or_vanished_file_is_logged_without_fingerprint(self):
        result = run_hook(
            payload(tool="Write", tool_input={"file_path": "never-written.md"}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries()[1]["files"], [])

    def test_long_command_is_truncated_to_one_line(self):
        long_command = "echo " + "x" * 500 + "\nsecond line"

        run_hook(payload(tool="Bash", tool_input={"command": long_command}),
                 cwd=self.workdir)

        action = self.entries()[1]["action"]
        self.assertNotIn("\n", action)
        self.assertLess(len(action), 200)
        self.assertIn("echo xxxx", action)

    def test_malformed_stdin_errors_cleanly(self):
        for bad in ("not json at all", '["a", "list"]', ""):
            result = run_hook(bad, cwd=self.workdir)

            self.assertEqual(result.returncode, 1, repr(bad))
            self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(self.workdir.iterdir()), [])

    def test_payload_without_session_or_tool_errors_cleanly(self):
        result = run_hook({"hook_event_name": "PostToolUse"}, cwd=self.workdir)

        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_log_dir_is_created_with_protective_gitignore(self):
        # Global wiring points every repo at <project>/receipts without any
        # per-repo setup: the hook creates the directory on first use, and
        # seeds a .gitignore so command history can't ride into a commit.
        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir, "--log-dir", "fresh/receipts",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        log_dir = self.workdir / "fresh" / "receipts"
        self.assertTrue((log_dir / "receipts-sess-1234abcd.jsonl").exists())
        gitignore = (log_dir / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("*", gitignore.splitlines())

    def test_existing_log_dir_gitignore_is_left_alone(self):
        vault = self.workdir / "vault"
        vault.mkdir()
        (vault / ".gitignore").write_text("mine\n", encoding="utf-8")

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir, "--log-dir", "vault",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((vault / ".gitignore").read_text(encoding="utf-8"),
                         "mine\n")

    def test_log_dir_flag_places_session_chains(self):
        vault = self.workdir / "vault"
        vault.mkdir()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir, "--log-dir", "vault",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (vault / "receipts-sess-1234abcd.jsonl").exists()
        )


if __name__ == "__main__":
    unittest.main()
