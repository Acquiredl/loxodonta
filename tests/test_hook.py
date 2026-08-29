"""Behavioral tests for the Stage C hook adapter (`receipts hook`).

The adapter turns a Claude Code PostToolUse payload (JSON on stdin) into
one chained entry — the completeness mechanism of SPEC §8: the log call
sits in the harness, outside the writer's volition. Tests drive the
public CLI with stdin payloads, never internals.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"


def run_hook(payload, cwd, *args, extra_env=None):
    # CLAUDE_PROJECT_DIR steers the default log dir; scrub the ambient one
    # so tests are deterministic wherever they run, and inject it only when
    # a test is exercising that resolution.
    env = dict(os.environ)
    env.pop("CLAUDE_PROJECT_DIR", None)
    # The decode below assumes UTF-8, so tell the child to emit UTF-8 —
    # otherwise a cp1252 console codepage on Windows breaks the agreement.
    env["PYTHONIOENCODING"] = "utf-8"
    if extra_env:
        env.update(extra_env)
    # The harness pipes the payload as raw UTF-8 bytes; feeding the hook the
    # same way keeps the console codepage out of the test's path (bytes in,
    # decoded output out — never `text=True`, whose locale codec would mask
    # an encoding fault on Windows).
    if isinstance(payload, str):
        stdin = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        stdin = payload
    else:
        stdin = json.dumps(payload).encode("utf-8")
    result = subprocess.run(
        [sys.executable, str(LOXODONTA), "hook", *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        env=env,
    )
    result.stdout = result.stdout.decode("utf-8", errors="replace")
    result.stderr = result.stderr.decode("utf-8", errors="replace")
    return result


def run_receipts(*args, cwd):
    # Both ends of the pipe pinned to UTF-8 (PYTHONIOENCODING for the child,
    # encoding= for the parent) — `text=True` alone decodes with the locale
    # codec, cp1252 on Windows, and disagrees with a UTF-8-emitting child.
    return subprocess.run(
        [sys.executable, str(LOXODONTA), *args],
        cwd=cwd,
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
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

    def test_non_ascii_in_payload_is_recorded_verbatim(self):
        # The harness sends the payload as UTF-8 bytes regardless of the
        # console codepage. Decoding it with anything else seals mojibake
        # into the chain — an em-dash arriving as "â€”" — and a receipt that
        # misquotes the command is testimony against the tool itself. Caught
        # in the field 2026-08-21: every merge-commit em-dash on this
        # machine was recorded mangled.
        command = 'git merge -m "chains — durable"'
        raw = json.dumps(payload(tool="Bash", tool_input={"command": command}),
                         ensure_ascii=False).encode("utf-8")

        result = run_hook(raw, cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Bash: {command}", self.entries()[1]["action"])

    def test_malformed_stdin_errors_cleanly(self):
        for bad in ("not json at all", '["a", "list"]', "",
                    b"\xff\xfe not utf-8 \x80"):
            result = run_hook(bad, cwd=self.workdir)

            self.assertEqual(result.returncode, 1, repr(bad))
            self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(self.workdir.iterdir()), [])

    def test_payload_without_session_or_tool_errors_cleanly(self):
        result = run_hook({"hook_event_name": "PostToolUse"}, cwd=self.workdir)

        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_claude_project_dir_env_places_chains_without_any_flags(self):
        # The global wiring passes no arguments at all: the hook reads
        # CLAUDE_PROJECT_DIR from the environment (set by the harness) and
        # logs to <project>/receipts. No shell expansion, so the same
        # settings command works on every platform.
        project = self.workdir / "someproject"
        project.mkdir()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,  # cwd differs from the project dir on purpose
            extra_env={"CLAUDE_PROJECT_DIR": str(project)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        log_dir = project / "receipts"
        self.assertTrue((log_dir / "receipts-sess-1234abcd.jsonl").exists())
        self.assertTrue((log_dir / ".gitignore").exists())

    def test_explicit_log_dir_flag_outranks_the_env(self):
        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir, "--log-dir", "chosen",
            extra_env={"CLAUDE_PROJECT_DIR": str(self.workdir / "ignored")},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (self.workdir / "chosen" / "receipts-sess-1234abcd.jsonl").exists()
        )
        self.assertFalse((self.workdir / "ignored").exists())

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


class HookWorktreeTest(unittest.TestCase):
    """A session run in a git worktree must leave its chain in the main
    repository, not in the worktree.

    Worktrees are disposable by convention — pruned once their branch
    merges — so a chain written inside one is deleted by routine hygiene.
    A flight recorder that stores recordings in the most disposable
    directory on the machine loses exactly the sessions worth keeping.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)

    def make_worktree(self, main_name="mainrepo", worktree_name="feature"):
        """Lay out on disk exactly what `git worktree add` produces: the
        worktree's .git is a *file* pointing at <main>/.git/worktrees/<name>,
        and that directory holds a `commondir` pointing back at <main>/.git.
        Built by hand so the test needs no git binary."""
        main = self.workdir / main_name
        (main / ".git").mkdir(parents=True, exist_ok=True)
        worktree = self.workdir / worktree_name
        worktree.mkdir()
        gitdir = main / ".git" / "worktrees" / worktree_name
        gitdir.mkdir(parents=True)
        (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
        (worktree / ".git").write_text(
            f"gitdir: {gitdir.as_posix()}\n", encoding="utf-8")
        return main, worktree

    def test_worktree_session_logs_to_the_main_repo(self):
        main, worktree = self.make_worktree()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env={"CLAUDE_PROJECT_DIR": str(worktree)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (main / "receipts" / "receipts-sess-1234abcd.jsonl").exists(),
            "chain should land in the main repo",
        )
        self.assertFalse(
            (worktree / "receipts").exists(),
            "nothing should be written into the disposable worktree",
        )

    def test_sessions_from_two_worktrees_collect_in_one_place(self):
        main, first = self.make_worktree(worktree_name="feature-one")
        _, second = self.make_worktree(main_name="mainrepo",
                                       worktree_name="feature-two")

        run_hook(payload(session="sess-aaaa"), self.workdir,
                 extra_env={"CLAUDE_PROJECT_DIR": str(first)})
        run_hook(payload(session="sess-bbbb"), self.workdir,
                 extra_env={"CLAUDE_PROJECT_DIR": str(second)})

        chains = sorted(p.name for p in (main / "receipts").glob("*.jsonl"))
        self.assertEqual(
            chains, ["receipts-sess-aaaa.jsonl", "receipts-sess-bbbb.jsonl"])

    def test_ordinary_repo_still_logs_to_its_own_root(self):
        project = self.workdir / "plainrepo"
        (project / ".git").mkdir(parents=True)

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env={"CLAUDE_PROJECT_DIR": str(project)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (project / "receipts" / "receipts-sess-1234abcd.jsonl").exists())

    def test_project_outside_any_repo_still_logs(self):
        project = self.workdir / "notarepo"
        project.mkdir()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env={"CLAUDE_PROJECT_DIR": str(project)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (project / "receipts" / "receipts-sess-1234abcd.jsonl").exists())

    def test_unreadable_git_linkage_falls_back_to_the_project_dir(self):
        # Never fail a session over path layout (SPEC §8): a .git file the
        # hook cannot follow degrades to logging in place.
        project = self.workdir / "brokenlink"
        project.mkdir()
        (project / ".git").write_text("gitdir: nowhere-at-all\n",
                                      encoding="utf-8")

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env={"CLAUDE_PROJECT_DIR": str(project)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (project / "receipts" / "receipts-sess-1234abcd.jsonl").exists())

    def test_explicit_log_dir_flag_outranks_worktree_resolution(self):
        main, worktree = self.make_worktree()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir, "--log-dir", str(self.workdir / "chosen"),
            extra_env={"CLAUDE_PROJECT_DIR": str(worktree)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (self.workdir / "chosen" / "receipts-sess-1234abcd.jsonl").exists())
        self.assertFalse((main / "receipts").exists())


if __name__ == "__main__":
    unittest.main()
