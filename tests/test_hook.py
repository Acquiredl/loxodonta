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
    env.pop("LOXODONTA_HOME", None)
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


def drawer_of(store_home, project_name):
    """The store subfolder for a project, found behaviorally: exactly one
    drawer whose name is the project's basename plus a dash and 8 hex —
    tests never re-implement the slug math."""
    drawers = [p for p in (Path(store_home) / "receipts").iterdir()
               if p.is_dir() and p.name.startswith(project_name + "-")]
    assert len(drawers) == 1, [p.name for p in drawers]
    suffix = drawers[0].name.rsplit("-", 1)[1]
    assert len(suffix) == 8 and all(c in "0123456789abcdef" for c in suffix)
    return drawers[0]


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

    @unittest.skipUnless(os.name == "nt",
                         "only Windows has drive letters to cross")
    def test_file_on_another_drive_is_logged_without_fingerprint(self):
        # The same rule as the test above, on the one path shape that
        # reaches it differently: os.path.relpath RAISES across drives
        # on Windows instead of returning a '..' path, so the "outside
        # the project" branch was never reached and the hook died
        # before writing anything. A scratchpad on C: and a repo on S:
        # is an ordinary layout, and every receipt for it went missing.
        here = str(self.workdir)[:1].upper()
        other = next((d for d in "CDEFGHIJKLMNOPQRSTUVWXYZ"
                      if d != here and os.path.isdir(d + ":\\")), None)
        if other is None:
            self.skipTest("this machine has only one drive")
        away = other + ":\\loxodonta-probe\\notes.md"

        result = run_hook(
            payload(tool="Write", tool_input={"file_path": away}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        entry = self.entries()[1]
        self.assertEqual(entry["files"], [],
                         "a file off the project is never fingerprinted")
        self.assertIn("notes.md", entry["action"],
                      "but the action is still recorded")

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

    def test_claude_project_dir_env_routes_chains_to_the_store(self):
        # The global wiring passes no arguments at all: the hook reads
        # CLAUDE_PROJECT_DIR from the environment (set by the harness) and
        # logs to the store's drawer for that project (ADR-0011). No shell
        # expansion, so the same settings command works on every platform.
        project = self.workdir / "someproject"
        project.mkdir()
        store = self.workdir / "storehome"

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,  # cwd differs from the project dir on purpose
            extra_env={"CLAUDE_PROJECT_DIR": str(project),
                       "LOXODONTA_HOME": str(store)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(store, "someproject")
        self.assertTrue((drawer / "receipts-sess-1234abcd.jsonl").exists())
        self.assertFalse((project / "receipts").exists(),
                         "nothing is written into the project any more")

    def test_first_receipt_writes_the_project_record(self):
        project = self.workdir / "someproject"
        project.mkdir()
        store = self.workdir / "storehome"
        env = {"CLAUDE_PROJECT_DIR": str(project),
               "LOXODONTA_HOME": str(store)}

        run_hook(payload(session="sess-aaaa"), self.workdir, extra_env=env)
        drawer = drawer_of(store, "someproject")
        record = json.loads((drawer / "project.json").read_text(
            encoding="utf-8"))
        self.assertEqual(Path(record["path"]).resolve(), project.resolve())

        # A second session appends beside the first and never rewrites
        # the record.
        before = (drawer / "project.json").read_bytes()
        run_hook(payload(session="sess-bbbb"), self.workdir, extra_env=env)
        self.assertEqual((drawer / "project.json").read_bytes(), before)
        chains = sorted(p.name for p in drawer.glob("receipts-*.jsonl"))
        self.assertEqual(chains, ["receipts-sess-aaaa.jsonl",
                                  "receipts-sess-bbbb.jsonl"])

    def test_store_receipt_fingerprints_files_relative_to_the_project(self):
        # ADR-0012: the reference base is the project root, so a chain
        # far away in the store still fingerprints the files the agent
        # touched — the claim the old log-relative rule silently broke.
        project = self.workdir / "someproject"
        target = project / "src" / "main.py"
        target.parent.mkdir(parents=True)
        target.write_text("print('hi')\n", encoding="utf-8")
        store = self.workdir / "storehome"

        result = run_hook(
            payload(tool="Write", tool_input={"file_path": str(target)}),
            self.workdir,
            extra_env={"CLAUDE_PROJECT_DIR": str(project),
                       "LOXODONTA_HOME": str(store)},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(store, "someproject")
        entries = [json.loads(line) for line in
                   (drawer / "receipts-sess-1234abcd.jsonl").read_text(
                       encoding="utf-8").splitlines()]
        (ref,) = entries[1]["files"]
        self.assertEqual(ref["path"], "src/main.py")
        self.assertEqual(len(ref["sha256"]), 64)

    def test_store_receipt_skips_files_outside_the_project(self):
        # The boundary moved from the log's folder to the project, not
        # to the machine (ADR-0012): an edit to something like the
        # harness settings is recorded as an action, never fingerprinted.
        project = self.workdir / "someproject"
        project.mkdir()
        outside = self.workdir / "elsewhere.txt"
        outside.write_text("out\n", encoding="utf-8")
        store = self.workdir / "storehome"

        run_hook(
            payload(tool="Write", tool_input={"file_path": str(outside)}),
            self.workdir,
            extra_env={"CLAUDE_PROJECT_DIR": str(project),
                       "LOXODONTA_HOME": str(store)},
        )

        drawer = drawer_of(store, "someproject")
        entries = [json.loads(line) for line in
                   (drawer / "receipts-sess-1234abcd.jsonl").read_text(
                       encoding="utf-8").splitlines()]
        self.assertEqual(entries[1]["files"], [])
        self.assertIn("elsewhere.txt", entries[1]["action"])

    def test_two_projects_with_the_same_name_get_distinct_drawers(self):
        # The slug carries a hash of the full path: two folders both named
        # "app" can never interleave chains in one drawer (ADR-0011).
        first = self.workdir / "clients" / "app"
        second = self.workdir / "internal" / "app"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        store = self.workdir / "storehome"

        run_hook(payload(session="sess-aaaa"), self.workdir,
                 extra_env={"CLAUDE_PROJECT_DIR": str(first),
                            "LOXODONTA_HOME": str(store)})
        run_hook(payload(session="sess-bbbb"), self.workdir,
                 extra_env={"CLAUDE_PROJECT_DIR": str(second),
                            "LOXODONTA_HOME": str(store)})

        drawers = sorted(p.name for p in (store / "receipts").iterdir()
                         if p.is_dir())
        self.assertEqual(len(drawers), 2, drawers)
        self.assertTrue(all(d.startswith("app-") for d in drawers))
        self.assertNotEqual(drawers[0], drawers[1])

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
    """A session run in a git worktree must leave its chain in its main
    repository's drawer, never in the worktree.

    Worktrees are disposable by convention — pruned once their branch
    merges — so a chain written inside one is deleted by routine hygiene.
    With the store (ADR-0011) the resolution survives one step further:
    the drawer is keyed by the *main repo's* path, so however many
    worktrees a project runs, its history collects in one place.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.store = self.workdir / "storehome"

    def env_for(self, project):
        return {"CLAUDE_PROJECT_DIR": str(project),
                "LOXODONTA_HOME": str(self.store)}

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

    def test_worktree_session_logs_to_the_main_repos_drawer(self):
        main, worktree = self.make_worktree()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env=self.env_for(worktree),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(self.store, "mainrepo")
        self.assertTrue(
            (drawer / "receipts-sess-1234abcd.jsonl").exists(),
            "chain should land in the main repo's drawer",
        )
        record = json.loads((drawer / "project.json").read_text(
            encoding="utf-8"))
        self.assertEqual(Path(record["path"]).resolve(), main.resolve())
        self.assertFalse(
            (worktree / "receipts").exists(),
            "nothing should be written into the disposable worktree",
        )

    def test_sessions_from_two_worktrees_collect_in_one_drawer(self):
        _, first = self.make_worktree(worktree_name="feature-one")
        _, second = self.make_worktree(main_name="mainrepo",
                                       worktree_name="feature-two")

        run_hook(payload(session="sess-aaaa"), self.workdir,
                 extra_env=self.env_for(first))
        run_hook(payload(session="sess-bbbb"), self.workdir,
                 extra_env=self.env_for(second))

        drawer = drawer_of(self.store, "mainrepo")
        chains = sorted(p.name for p in drawer.glob("receipts-*.jsonl"))
        self.assertEqual(
            chains, ["receipts-sess-aaaa.jsonl", "receipts-sess-bbbb.jsonl"])

    def test_ordinary_repo_gets_its_own_drawer(self):
        project = self.workdir / "plainrepo"
        (project / ".git").mkdir(parents=True)

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env=self.env_for(project),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(self.store, "plainrepo")
        self.assertTrue((drawer / "receipts-sess-1234abcd.jsonl").exists())

    def test_project_outside_any_repo_still_logs_to_the_store(self):
        project = self.workdir / "notarepo"
        project.mkdir()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env=self.env_for(project),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(self.store, "notarepo")
        self.assertTrue((drawer / "receipts-sess-1234abcd.jsonl").exists())

    def test_unreadable_git_linkage_falls_back_to_the_project_dir(self):
        # Never fail a session over path layout (SPEC §8): a .git file the
        # hook cannot follow degrades to the project dir's own drawer.
        project = self.workdir / "brokenlink"
        project.mkdir()
        (project / ".git").write_text("gitdir: nowhere-at-all\n",
                                      encoding="utf-8")

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir,
            extra_env=self.env_for(project),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(self.store, "brokenlink")
        self.assertTrue((drawer / "receipts-sess-1234abcd.jsonl").exists())

    def test_explicit_log_dir_flag_outranks_the_store(self):
        main, worktree = self.make_worktree()

        result = run_hook(
            payload(tool="Bash", tool_input={"command": "ls"}),
            self.workdir, "--log-dir", str(self.workdir / "chosen"),
            extra_env=self.env_for(worktree),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (self.workdir / "chosen" / "receipts-sess-1234abcd.jsonl").exists())
        self.assertFalse((self.store / "receipts").exists(),
                         "an explicit --log-dir bypasses the store entirely")
        self.assertFalse((main / "receipts").exists())


class TranscriptCommitmentTest(unittest.TestCase):
    """ADR-0017: every 25 entries the hook commits the harness
    transcript's byte-prefix as a bookkeeping entry — the chain commits
    the flesh by reference. Driven through the public CLI with stdin
    payloads, like every hook behavior."""

    CADENCE = 25

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.transcript = self.workdir / "transcript.jsonl"

    def entries(self, session="sess-1234abcd"):
        log = self.workdir / f"receipts-{session}.jsonl"
        return [json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()]

    def commitments(self):
        return [e for e in self.entries()
                if e["action"].startswith("transcript-commitment:")]

    def drive(self, calls, transcript=True):
        for i in range(calls):
            body = payload(tool="Bash", tool_input={"command": f"step {i}"})
            if transcript:
                body["transcript_path"] = str(self.transcript)
            result = run_hook(body, cwd=self.workdir)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_25th_entry_triggers_a_transcript_commitment(self):
        self.transcript.write_bytes(b"the diary, page one\n")

        self.drive(self.CADENCE)

        entries = self.entries()
        # genesis + 25 tool receipts + 1 commitment
        self.assertEqual(len(entries), self.CADENCE + 2)
        commitment = entries[-1]
        self.assertEqual(commitment["n"], self.CADENCE + 1)
        self.assertEqual(commitment["actor"], "receipts")
        self.assertEqual(commitment["files"], [])
        # The pinned grammar — a golden line, like canonical form: an
        # independent implementation must produce these exact bytes.
        self.assertEqual(
            commitment["action"],
            "transcript-commitment: bytes=20 sha256=f29203b62a3754c1"
            "0035541fc436ac31ef426b6d56cfd9bf81e89fc44cac08a7")
        verify = run_receipts("verify", "--log",
                              "receipts-sess-1234abcd.jsonl",
                              cwd=self.workdir)
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_cadence_repeats_and_commits_the_grown_prefix(self):
        self.transcript.write_bytes(b"page one\n")
        self.drive(self.CADENCE)
        # The diary grows between boundaries; the next commitment must
        # cover the whole prefix from byte zero, not the delta.
        with open(self.transcript, "ab") as f:
            f.write(b"page two\n")
        # 24 more tool receipts land n=27..50 -> second boundary at 50.
        self.drive(self.CADENCE - 1)

        marks = self.commitments()
        self.assertEqual([m["n"] for m in marks],
                         [self.CADENCE + 1, 2 * self.CADENCE + 1])
        first, second = (int(m["action"].split("bytes=")[1].split()[0])
                         for m in marks)
        self.assertEqual(first, len(b"page one\n"))
        self.assertEqual(second, len(b"page one\npage two\n"))

    def test_without_a_transcript_path_no_commitment_is_written(self):
        self.drive(self.CADENCE, transcript=False)

        entries = self.entries()
        self.assertEqual(len(entries), self.CADENCE + 1)
        self.assertEqual(self.commitments(), [])

    def end_payload(self, session="sess-1234abcd", transcript=True,
                    reason="prompt_input_exit"):
        body = {"session_id": session, "hook_event_name": "SessionEnd",
                "reason": reason}
        if transcript:
            body["transcript_path"] = str(self.transcript)
        return body

    def test_session_end_seals_the_tail(self):
        # Issue #79: a clean exit closes the uncommitted-tail window —
        # one final commitment over the whole prefix, whatever the
        # cadence position.
        self.transcript.write_bytes(b"page one\n")
        self.drive(3)
        with open(self.transcript, "ab") as f:
            f.write(b"the tail\n")

        result = run_hook(self.end_payload(), cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        marks = self.commitments()
        self.assertEqual(len(marks), 1)
        self.assertEqual(marks[0]["n"], 4)
        self.assertEqual(marks[0]["actor"], "receipts")
        self.assertIn("bytes=" + str(len(b"page one\nthe tail\n")),
                      marks[0]["action"])

    def test_session_end_never_manufactures_a_chain(self):
        # A chat-only session owes nothing: SessionEnd on a session
        # with no receipts must not create a chain just to seal it.
        self.transcript.write_bytes(b"just talk\n")

        result = run_hook(self.end_payload(session="sess-chatonly"),
                          cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(
            (self.workdir / "receipts-sess-chatonly.jsonl").exists())

    def test_session_end_on_a_boundary_writes_no_duplicate(self):
        # Ending right after a cadence commitment with unchanged bytes
        # must not write the same commitment twice.
        self.transcript.write_bytes(b"the diary, page one\n")
        self.drive(self.CADENCE)

        result = run_hook(self.end_payload(), cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.commitments()), 1)

    def test_session_end_without_a_transcript_is_a_quiet_no_op(self):
        self.drive(2)  # transcript_path points at a missing file

        result = run_hook(self.end_payload(), cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commitments(), [])

    def test_install_hook_wires_session_end(self):
        # The installer's third event: SessionEnd calls the same
        # recorder command, with an explicit timeout (the harness's
        # default SessionEnd budget is too small for a big transcript).
        home = self.workdir / "home"
        (home / ".claude").mkdir(parents=True)
        env = {"HOME": str(home), "USERPROFILE": str(home)}
        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook"],
            capture_output=True, encoding="utf-8",
            env={**os.environ, **env, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = json.loads(
            (home / ".claude" / "settings.json").read_text(
                encoding="utf-8"))
        end = settings["hooks"]["SessionEnd"]
        self.assertTrue(any("loxodonta.py" in h.get("command", "")
                            and "hook" in h.get("command", "")
                            for b in end for h in b.get("hooks", [])))
        self.assertTrue(all(h.get("timeout")
                            for b in end for h in b.get("hooks", [])))
        again = subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook"],
            capture_output=True, encoding="utf-8",
            env={**os.environ, **env, "PYTHONIOENCODING": "utf-8"})
        self.assertIn("already installed", again.stdout)

    def test_unreadable_transcript_skips_the_commitment_never_fails(self):
        # Skipped, never fatal: a hook that failed the session over the
        # transcript would teach the operator to turn the hook off.
        self.drive(self.CADENCE)  # transcript_path points at nothing

        self.assertFalse(self.transcript.exists())
        entries = self.entries()
        self.assertEqual(len(entries), self.CADENCE + 1)
        self.assertEqual(self.commitments(), [])


if __name__ == "__main__":
    unittest.main()
