"""Behavioral tests for the Stage C hook adapter (`receipts hook`).

The adapter turns a Claude Code PostToolUse payload (JSON on stdin) into
one chained entry — the completeness mechanism of SPEC §8: the log call
sits in the harness, outside the writer's volition. Tests drive the
public CLI with stdin payloads, never internals.
"""

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_hook`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import LOXODONTA, isolated_env, run, temp_folder  # noqa: E402




def run_hook(payload, cwd, *args, extra_env=None, timeout=120):
    # The harness pipes the payload as raw UTF-8 bytes; feeding the hook the
    # same way keeps the console codepage out of the test's path.
    if isinstance(payload, str):
        stdin = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        stdin = payload
    else:
        stdin = json.dumps(payload).encode("utf-8")
    # Every home is one of this call's own (#274), so a store the test did
    # not name is a throwaway, never the machine's.
    with tempfile.TemporaryDirectory() as home:
        # CLAUDE_PROJECT_DIR steers the default log dir; isolated_env
        # scrubs the ambient one so tests are deterministic wherever they
        # run, and a test exercising that resolution injects it.
        env = isolated_env(Path(home).resolve())
        if extra_env:
            env.update(extra_env)
        return run(LOXODONTA, "hook", *args, cwd=cwd, stdin=stdin, env=env,
                   timeout=timeout)


def suffix(tool_input, call=None):
    """The suffix ADR-0047 pins for a call, computed here from its input
    by SPEC section 4's rules: keys sorted, no whitespace, UTF-8."""
    form = json.dumps(tool_input, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    fields = ([f"call={call}"] if call else []) + [
        f"input sha256={hashlib.sha256(form).hexdigest()} bytes={len(form)}"]
    return " [" + " ".join(fields) + "]"


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
        self.workdir = temp_folder(self)

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

        verify = run(LOXODONTA, 
            "verify", "--log", self.session_log().name, cwd=self.workdir
        )
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_a_failed_call_leaves_the_receipt_a_completed_one_would(self):
        # #239: the harness sends PostToolUseFailure for a call that ran
        # and failed. The field names are the ones measured against a
        # live failing call (Claude Code 2.1.259); the recorder reads the
        # same fields it reads for PostToolUse, so the receipt records
        # the action attempted, and never the error it met (ADR-0027).
        command = {"command": "python -c \"import sys; sys.exit(3)\"",
                   "description": "Exit with status 3"}
        completed = payload(session="sess-completed", tool="Bash",
                            tool_input=command)
        failed = {"session_id": "sess-failed",
                  "transcript_path": str(self.workdir / "absent.jsonl"),
                  "cwd": str(self.workdir),
                  "permission_mode": "default",
                  "hook_event_name": "PostToolUseFailure",
                  "tool_name": "Bash",
                  "tool_input": command,
                  "tool_use_id": "toolu_01failed",
                  "error": "Exit code 3\nsecret-looking-output",
                  "is_interrupt": False,
                  "duration_ms": 1738,
                  "prompt_id": "prompt-1"}

        # The payload names a real `cwd`, which routes to the store; an
        # explicit --log-dir outranks it, and the store is pinned inside
        # the test besides, so nothing reaches a real home.
        pinned = {"LOXODONTA_HOME": str(self.workdir / "store")}
        first = run_hook(completed, self.workdir, "--log-dir",
                         str(self.workdir), extra_env=pinned)
        second = run_hook(failed, self.workdir, "--log-dir",
                          str(self.workdir), extra_env=pinned)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        was, fell = (self.entries("sess-completed")[1],
                     self.entries("sess-failed")[1])
        # The failed call's payload names its call; the completed one's
        # names none, so its suffix holds the input alone (ADR-0047).
        self.assertEqual(
            (fell["actor"], fell["action"], fell["files"]),
            (was["actor"], was["action"].replace(
                " [input ", " [call=toolu_01failed input ", 1),
             was["files"]))
        self.assertNotIn("secret-looking-output",
                         self.session_log("sess-failed").read_text(
                             encoding="utf-8"))

    def test_hook_chains_repeated_calls_in_one_session(self):
        run_hook(payload(tool="Bash",
                         tool_input={"command": "pytest -q"}), cwd=self.workdir)
        run_hook(payload(tool="Bash",
                         tool_input={"command": "git status"}), cwd=self.workdir)

        entries = self.entries()
        self.assertEqual([e["n"] for e in entries], [0, 1, 2])
        self.assertIn("pytest -q", entries[1]["action"])
        self.assertIn("git status", entries[2]["action"])

    def cut_action(self, tool, value, key="command"):
        """Run one call and split its cut action line into the kept
        start and the count of characters dropped (#470)."""
        run_hook(payload(tool=tool, tool_input={key: value}),
                 cwd=self.workdir)
        action = self.entries()[1]["action"]
        # The suffix follows the cut and its count (ADR-0047).
        tail = suffix({key: value})
        self.assertTrue(action.endswith(tail), action)
        action = action[:-len(tail)]
        match = re.fullmatch(re.escape(tool) + r": (.*)… \(\+(\d+)\)",
                             action, re.DOTALL)
        self.assertIsNotNone(match, f"not a cut line with a count: {action!r}")
        return match.group(1), int(match.group(2))

    def test_long_action_is_cut_at_a_word_boundary(self):
        # A receipt's action is one line (SPEC §2), cut with an ellipsis.
        # The cut lands between words, never inside one: the todo chain's
        # receipts read "publi…" and "noreply@ant…" before this (#157).
        words = " ".join(f"word{i:03d}" for i in range(40))  # 319 chars
        body, _ = self.cut_action("Bash", words)
        self.assertLessEqual(len(body), 160)
        self.assertTrue(body.endswith(tuple(f"word{i:03d}" for i in range(40))),
                        f"cut inside a word: {body[-12:]!r}")

    def test_long_action_without_spaces_is_cut_at_the_limit(self):
        # No word boundary anywhere near the limit (one long URL): the
        # hard cut at the limit stands rather than dropping most of it.
        url = "https://example.com/" + "a" * 300
        body, _ = self.cut_action("WebFetch", url, key="url")
        self.assertEqual(len(body), 160)

    def test_long_action_never_splits_a_combining_sequence(self):
        # A base letter and its combining accent straddling the limit:
        # the cut backs up so the accent is never orphaned at the edge.
        head = "x" * 159
        text = head + "e\u0301 tail words follow here"  # e + combining acute
        body, _ = self.cut_action("Bash", text)
        self.assertNotEqual(body[-1], "e",
                            "cut between a base letter and its accent")
        self.assertLessEqual(len(body), 160)

    # #470: a cut action line says how many characters it dropped, so a
    # command whose telling part comes after a long harmless start does
    # not read as the harmless start alone. The cases are the ruling's.

    def test_a_command_that_fits_is_recorded_unchanged(self):
        command = "echo " + "a" * 95  # 100 characters
        run_hook(payload(tool="Bash", tool_input={"command": command}),
                 cwd=self.workdir)
        self.assertEqual(self.entries()[1]["action"],
                         f"Bash: {command}" + suffix({"command": command}))

    def test_a_cut_command_says_how_many_characters_it_dropped(self):
        kept, dropped = self.cut_action("Bash", "a" * 3000)
        self.assertEqual((kept, dropped), ("a" * 160, 2840))

    def test_the_count_includes_what_a_cut_between_words_dropped(self):
        # The space at 150 sits within the last forty characters before
        # the limit, so the cut lands on it: the space and the ten
        # characters after it are dropped too, and counted.
        command = "x" * 150 + " " + "y" * 2849  # 3,000 characters
        kept, dropped = self.cut_action("Bash", command)
        self.assertEqual((kept, dropped), ("x" * 150, 2850))

    def test_the_count_is_of_the_collapsed_line(self):
        # Whitespace collapses before anything is cut, so each run below
        # is one space in the line, and the count is of 3,000 characters.
        command = "  " + "a" * 1000 + "\n\t   " + "b" * 1999 + " " * 2000
        kept, dropped = self.cut_action("Bash", command)
        self.assertEqual((kept, dropped), ("a" * 160, 2840))

    def test_a_short_command_padded_with_spaces_is_unchanged(self):
        command = "echo" + " " * 2000 + "hi" + " " * 2000
        run_hook(payload(tool="Bash", tool_input={"command": command}),
                 cwd=self.workdir)
        self.assertEqual(self.entries()[1]["action"],
                         "Bash: echo hi" + suffix({"command": command}))

    def test_a_read_of_a_long_path_is_cut_by_the_same_rule(self):
        path = "src/" + "deep/" * 80 + "file.py"  # 411 characters, no spaces
        kept, dropped = self.cut_action("Read", path, key="file_path")
        self.assertEqual((kept, dropped), (path[:160], 251))

    def test_the_count_includes_a_combining_mark_dropped_whole(self):
        # The limit falls between "e" and its accent, so both are
        # dropped, and counted: kept plus dropped is the whole line.
        command = "x" * 159 + "e" + chr(0x301) + "y" * 1000
        kept, dropped = self.cut_action("Bash", command)
        self.assertEqual((kept, dropped), ("x" * 159, 1002))

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
        # before writing anything. A scratchpad on C: and a repo on D:
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

    def test_symlink_inside_project_is_fingerprinted_by_its_own_path(self):
        # "Under the project" is judged on the path as given (SPEC §3,
        # #224): a link inside it is followed wherever it points, and the
        # receipt carries the link's path with the target's bytes.
        target = temp_folder(self) / "outside.md"
        target.write_text("bytes that live outside the project\n",
                          encoding="utf-8")
        link = self.workdir / "link.md"
        try:
            os.symlink(str(target), str(link))
        except OSError as e:
            self.skipTest("symlinks cannot be created here "
                          f"({e.strerror or type(e).__name__}); this test "
                          "runs wherever they can")

        result = run_hook(
            payload(tool="Read", tool_input={"file_path": str(link)}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.entries()[1]["files"],
            [{"path": "link.md",
              "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}],
        )

    def test_directory_at_the_path_is_logged_without_fingerprint(self):
        # Only a regular file is fingerprinted (docs/HOOK.md); anything
        # else at the path is skipped like a file that is gone.
        (self.workdir / "src").mkdir()

        result = run_hook(
            payload(tool="Read", tool_input={"file_path": "src"}),
            cwd=self.workdir,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        entry = self.entries()[1]
        self.assertEqual(entry["files"], [])
        self.assertIn("src", entry["action"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "os.mkfifo is POSIX only")
    def test_fifo_at_the_path_is_logged_without_fingerprint(self):
        # Opening a FIFO waits for a writer, so a hook that hashed one
        # would hang the tool call; the timeout raises rather than stall
        # the suite.
        os.mkfifo(str(self.workdir / "pipe"))

        result = run_hook(
            payload(tool="Read", tool_input={"file_path": "pipe"}),
            cwd=self.workdir, timeout=60,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries()[1]["files"], [])

    def test_long_command_is_truncated_to_one_line(self):
        long_command = "echo " + "x" * 500 + "\nsecond line"

        run_hook(payload(tool="Bash", tool_input={"command": long_command}),
                 cwd=self.workdir)

        action = self.entries()[1]["action"]
        self.assertNotIn("\n", action)
        tail = suffix({"command": long_command})
        self.assertTrue(action.endswith(tail), action)
        self.assertLess(len(action) - len(tail), 200)
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

    def test_a_lone_surrogate_in_the_tool_input_is_recorded_as_escape_text(self):
        # #292: JSON lets a model type half a UTF-16 pair into any tool
        # argument. It has no UTF-8 form, so the receipt was lost to a
        # traceback and the chain went on verifying VALID with a gap.
        # The ruling: the receipt holds its six characters of escape
        # text. The payload is built as the harness sends it, the escape
        # spelled with chr(92) so nothing on the way can read it early.
        escape = chr(92) + "ud800"
        raw = ('{"session_id":"sess-1234abcd","hook_event_name":"PostToolUse",'
               '"tool_name":"Bash","tool_input":{"command":"echo ' + escape
               + ' hi"},"tool_response":{}}')

        result = run_hook(raw, cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        # A lone surrogate has no canonical form, so the input is named
        # and not hashed (ADR-0047 ruling 3).
        self.assertEqual(self.entries()[1]["action"],
                         "Bash: echo " + escape + " hi [input=unhashed]")
        # The chain keeps receipting after the escaped call, and walks.
        run_hook(payload(tool="Bash", tool_input={"command": "ls"}),
                 cwd=self.workdir)
        self.assertEqual([e["n"] for e in self.entries()], [0, 1, 2])
        verify = run(LOXODONTA, "verify", "--log", self.session_log().name,
                              cwd=self.workdir)
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertEqual(verify.stdout.strip(), "VALID")

    def test_malformed_stdin_errors_cleanly(self):
        # The last two are JSON a reader cannot hold: an integer past
        # the digit limit, and nesting past the recursion limit (#331).
        for bad in ("not json at all", '["a", "list"]', "",
                    b"\xff\xfe not utf-8 \x80",
                    '{"session_id": "s", "n": ' + "1" * 5000 + "}",
                    "[" * 100000 + "]" * 100000):
            result = run_hook(bad, cwd=self.workdir)

            # EX_DATAERR (ADR-0037); never 2, which Claude Code reads as
            # "block the session" (docs/HOOK.md).
            self.assertEqual(result.returncode, 65, repr(bad)[:40])
            self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(self.workdir.iterdir()), [])

    def test_payload_without_session_or_tool_errors_cleanly(self):
        result = run_hook({"hook_event_name": "PostToolUse"}, cwd=self.workdir)

        self.assertEqual(result.returncode, 65)
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
        self.workdir = temp_folder(self)
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

    def test_deregistered_worktree_still_logs_to_the_main_repos_drawer(self):
        # The case that found ADR-0023: the harness deregistered the
        # worktree under a running session. <main>/.git/worktrees/<name>
        # is gone; the folder and its .git file remain, and that file
        # still names the main repository.
        main, worktree = self.make_worktree()
        shutil.rmtree(main / ".git" / "worktrees")

        result = run_hook(payload(session="sess-dereg"), self.workdir,
                          extra_env=self.env_for(worktree))

        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(self.store, "mainrepo")
        self.assertTrue((drawer / "receipts-sess-dereg.jsonl").exists())
        names = [p.name for p in (self.store / "receipts").iterdir()]
        self.assertFalse(any(n.startswith("feature-") for n in names),
                         f"a drawer opened for the worktree's own path: {names}")

    def test_a_sessions_receipts_follow_its_first_drawer(self):
        # One session, one drawer (ADR-0023): the first receipt decides,
        # and a later receipt whose project resolves somewhere else still
        # lands in that drawer, never in a second one.
        first = self.workdir / "alpha"
        first.mkdir()
        elsewhere = self.workdir / "beta"
        elsewhere.mkdir()
        run_hook(payload(session="sess-sticky"), self.workdir,
                 extra_env=self.env_for(first))

        result = run_hook(
            payload(session="sess-sticky", tool="Bash",
                    tool_input={"command": "ls"}),
            self.workdir, extra_env=self.env_for(elsewhere))

        self.assertEqual(result.returncode, 0, result.stderr)
        chain = drawer_of(self.store, "alpha") / "receipts-sess-sticky.jsonl"
        lines = chain.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3, lines)  # genesis + two receipts
        self.assertIn("Bash: ls", lines[-1])
        names = [p.name for p in (self.store / "receipts").iterdir()]
        self.assertFalse(any(n.startswith("beta-") for n in names),
                         f"a second drawer opened for the session: {names}")

    def unlistable_store(self):
        """A session's first receipt in alpha's drawer, then the store's
        receipts folder closed to listing and left open to lookups and
        writes, as a chmod by the writer leaves it."""
        first = self.workdir / "alpha"
        first.mkdir()
        elsewhere = self.workdir / "beta"
        elsewhere.mkdir()
        run_hook(payload(session="sess-split"), self.workdir,
                 extra_env=self.env_for(first))
        receipts = self.store / "receipts"
        os.chmod(receipts, 0o300)
        self.addCleanup(os.chmod, receipts, 0o755)
        return receipts, elsewhere

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not list")
    def test_an_unlistable_store_names_the_split_it_cannot_rule_out(self):
        # #452: the drawer lookup caught every OSError and opened a second
        # drawer for the session in silence (ADR-0023).
        receipts, elsewhere = self.unlistable_store()

        result = run_hook(
            payload(session="sess-split", tool="Bash",
                    tool_input={"command": "ls"}),
            self.workdir, extra_env=self.env_for(elsewhere))

        self.assertEqual(result.returncode, 0,
                         "the receipt is kept, never lost to the warning")
        said = result.stderr.splitlines()
        self.assertEqual(len(said), 1, result.stderr)
        self.assertIn(f"{receipts} cannot be listed", said[0])
        self.assertIn("ADR-0023", said[0])
        # Once per session: the drawer it chose now holds the chain, so
        # the next call never looks for another.
        again = run_hook(
            payload(session="sess-split", tool="Bash",
                    tool_input={"command": "pwd"}),
            self.workdir, extra_env=self.env_for(elsewhere))
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(again.stderr, "")
        os.chmod(receipts, 0o755)
        chain = drawer_of(self.store, "beta") / "receipts-sess-split.jsonl"
        self.assertIn("Bash: ls", chain.read_text(encoding="utf-8"))

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not list")
    def test_an_unlistable_store_leaves_the_session_end_silent(self):
        # An exit hook that complains is noise nobody can act on
        # (ADR-0017): SessionEnd skips in silence, as it always has.
        _, elsewhere = self.unlistable_store()
        ending = {"session_id": "sess-split",
                  "hook_event_name": "SessionEnd"}

        result = run_hook(ending, self.workdir,
                          extra_env=self.env_for(elsewhere))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def assert_refused_by_name(self, result):
        """A receipt the hook cannot file: the refusal `unwritable_log`
        gives, alone on stderr, exit 73, never a traceback (#555). Alone:
        the #452 warning says where the receipt goes, and it goes
        nowhere."""
        self.assertEqual(result.returncode, 73, result.stderr)
        lines = result.stderr.splitlines()
        self.assertEqual(len(lines), 1, result.stderr)
        said = lines[0]
        self.assertTrue(said.startswith("error: "), said)
        self.assertIn(str(self.store / "receipts"), said)
        self.assertIn("could not be written", said)
        self.assertIn("no entry was written", said)

    def test_a_file_at_a_store_folders_name_is_refused_by_name(self):
        # #555: the first receipt of a session whose drawer does not
        # exist yet makes the drawer, and a file in the way of it, at the
        # receipts folder's name or the drawer's, is one command away.
        project = self.workdir / "alpha"
        project.mkdir()
        self.store.mkdir()
        receipts = self.store / "receipts"
        receipts.write_text("in the way\n", encoding="utf-8")
        with self.subTest(at="receipts"):
            result = run_hook(
                payload(session="sess-blocked", tool="Bash",
                        tool_input={"command": "ls"}),
                self.workdir, extra_env=self.env_for(project))

            self.assert_refused_by_name(result)
            self.assertEqual(receipts.read_text(encoding="utf-8"),
                             "in the way\n")
        receipts.unlink()
        run_hook(payload(session="sess-first"), self.workdir,
                 extra_env=self.env_for(project))
        drawer = drawer_of(self.store, "alpha")
        shutil.rmtree(drawer)
        drawer.write_text("in the way\n", encoding="utf-8")
        with self.subTest(at="drawer"):
            result = run_hook(
                payload(session="sess-blocked", tool="Bash",
                        tool_input={"command": "ls"}),
                self.workdir, extra_env=self.env_for(project))

            self.assert_refused_by_name(result)
            self.assertEqual(drawer.read_text(encoding="utf-8"),
                             "in the way\n")

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not enter")
    def test_a_closed_receipts_folder_is_refused_by_name(self):
        # #555: one chmod by the writer, and the drawer of a session's
        # first receipt cannot be made in it.
        project = self.workdir / "alpha"
        project.mkdir()
        receipts = self.store / "receipts"
        receipts.mkdir(parents=True)
        os.chmod(receipts, 0)
        self.addCleanup(os.chmod, receipts, 0o755)

        result = run_hook(
            payload(session="sess-closed", tool="Bash",
                    tool_input={"command": "ls"}),
            self.workdir, extra_env=self.env_for(project))

        self.assert_refused_by_name(result)
        os.chmod(receipts, 0o755)
        self.assertEqual(list(receipts.iterdir()), [])

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
        self.workdir = temp_folder(self)
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
        verify = run(LOXODONTA, "verify", "--log",
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
        env = isolated_env(home, PYTHONIOENCODING="utf-8")
        result = run(LOXODONTA, "install-hook", env=env)
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
        again = run(LOXODONTA, "install-hook", env=env)
        self.assertIn("already installed", again.stdout)

    def test_unreadable_transcript_skips_the_commitment_never_fails(self):
        # Skipped, never fatal: a hook that failed the session over the
        # transcript would teach the operator to turn the hook off.
        self.drive(self.CADENCE)  # transcript_path points at nothing

        self.assertFalse(self.transcript.exists())
        entries = self.entries()
        self.assertEqual(len(entries), self.CADENCE + 1)
        self.assertEqual(self.commitments(), [])

    def test_a_transcript_path_no_filesystem_can_name_is_skipped(self):
        # #292: a NUL anywhere, or on POSIX a lone surrogate, makes the
        # open raise ValueError rather than OSError. It is skipped like
        # a missing transcript, on the cadence and at SessionEnd, never
        # a traceback after the receipt was already written.
        self.drive(2)
        for spelling in ("u0000", "ud800"):
            with self.subTest(spelling=spelling):
                raw = ('{"session_id":"sess-1234abcd",'
                       '"hook_event_name":"SessionEnd",'
                       '"transcript_path":"diary' + chr(92) + spelling
                       + '.jsonl"}')

                result = run_hook(raw, cwd=self.workdir)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.commitments(), [])

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_session_end_in_a_folder_that_refuses_the_lock_is_silent(self):
        # #430: a folder made read-only after the chain exists refuses
        # the lock file, and SessionEnd skips the seal without a word,
        # as every other failure there, never a traceback and exit 70.
        self.transcript.write_bytes(b"page one\n")
        self.drive(3)
        with open(self.transcript, "ab") as f:
            f.write(b"the tail\n")
        chain = self.workdir / "receipts-sess-1234abcd.jsonl"
        before = chain.read_bytes()
        os.chmod(self.workdir, 0o555)
        self.addCleanup(os.chmod, self.workdir, 0o755)

        result = run_hook(self.end_payload(), cwd=self.workdir, timeout=120)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(chain.read_bytes(), before)


# The pin as `install-hook --managed --profile full` writes it, for a
# receiver at PINNED (ADR-0041 ruling 7).
PINNED = "http://127.0.0.1:9/abc"
PIN = {"env": {"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
               "OTEL_LOGS_EXPORTER": "otlp",
               "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
               "OTEL_EXPORTER_OTLP_ENDPOINT": PINNED}}
# What the hook compares with the pin, scrubbed from the environment a
# test hands it so the shell this runs in says nothing.
TELEMETRY_VARIABLES = ("CLAUDE_CODE_ENABLE_TELEMETRY", "OTEL_LOGS_EXPORTER",
                       "OTEL_EXPORTER_OTLP_PROTOCOL",
                       "OTEL_EXPORTER_OTLP_ENDPOINT",
                       "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
# An environment the pin is in force in: the harness's events reach
# the receiver, and the hook has nothing to note.
IN_FORCE = {"CLAUDE_CODE_ENABLE_TELEMETRY": "1", "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_EXPORTER_OTLP_ENDPOINT": PINNED}
NOTE = "second-record-cut: reason="
STEP = "Bash: step" + suffix({"command": "step"})


class SecondRecordCutTest(unittest.TestCase):
    """ADR-0041 ruling 8: the hook runs in the harness's environment,
    and when the installer's pin is there and that environment has the
    events off or pointed elsewhere, the hook writes one bookkeeping
    entry per chain saying the second record was cut. Driven through
    the public CLI with a planted pin under LOXODONTA_MANAGED_DIR and a
    controlled environment, like every hook behavior."""

    def setUp(self):
        self.workdir = temp_folder(self)
        self.transcript = self.workdir / "transcript.jsonl"
        self.managed = self.workdir / "managed"
        self.pin = (self.managed / "managed-settings.d"
                    / "loxodonta-telemetry.json")
        self.plant(PIN)
        # run_hook copies this process's environment: a telemetry
        # variable set in the shell this runs in would be the harness's
        # word here, so none of them is.
        previous = {name: os.environ.pop(name)
                    for name in TELEMETRY_VARIABLES if name in os.environ}
        self.addCleanup(os.environ.update, previous)

    def plant(self, content):
        self.pin.parent.mkdir(parents=True, exist_ok=True)
        self.pin.write_text(content if isinstance(content, str)
                            else json.dumps(content), encoding="utf-8")

    def hook(self, env, body=None, *args, session="sess-1234abcd"):
        if body is None:
            body = payload(session=session, tool="Bash",
                           tool_input={"command": "step"})
        result = run_hook(body, self.workdir, *args, timeout=120,
                          extra_env={"LOXODONTA_MANAGED_DIR": str(self.managed),
                                     **env})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def entries(self, session="sess-1234abcd"):
        log = self.workdir / f"receipts-{session}.jsonl"
        return [json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()]

    def notes(self, session="sess-1234abcd"):
        return [e for e in self.entries(session)
                if e["action"].startswith(NOTE)]

    def test_a_cut_environment_leaves_one_note_after_the_first_receipt(self):
        for _ in range(3):
            self.hook({})

        entries = self.entries()
        self.assertEqual([e["action"] for e in entries],
                         ["genesis", STEP,
                          "second-record-cut: reason=telemetry-off",
                          STEP, STEP])
        note = entries[2]
        self.assertEqual(note["actor"], "receipts")
        self.assertEqual(note["files"], [])
        verify = run(LOXODONTA, "verify", "--log",
                              "receipts-sess-1234abcd.jsonl",
                              cwd=self.workdir)
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_the_reason_is_the_first_that_applies(self):
        cases = (
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "0"}, "telemetry-off"),
            # The switch absent still reads off: the harness hands it to
            # every hook, so its absence is not the harness's habit.
            ({}, "telemetry-off"),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
              "OTEL_LOGS_EXPORTER": "console"}, "exporter-off"),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
              "OTEL_LOGS_EXPORTER": ""}, "exporter-off"),
            ({**IN_FORCE, "OTEL_EXPORTER_OTLP_ENDPOINT":
              "http://127.0.0.1:9/other"}, "endpoint-elsewhere"),
            ({**IN_FORCE, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":
              "http://127.0.0.1:9/other/v1/logs"}, "endpoint-elsewhere"),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
              "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":
              "http://127.0.0.1:9/other/v1/logs"}, "endpoint-elsewhere"),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
              "OTEL_EXPORTER_OTLP_ENDPOINT":
              "http://127.0.0.1:9/other"}, "endpoint-elsewhere"),
            # A logs endpoint set but empty yields to the base one, and
            # with no base one the events go to no pinned URL (#495).
            ({**IN_FORCE, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": ""}, None),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
              "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": ""}, "endpoint-elsewhere"),
            # A key the hook's environment does not hold is not a cut
            # (#495): Claude Code 2.1.294 keeps every OTEL_* variable
            # away from the hooks it runs, pinned or not.
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1"}, None),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
              "OTEL_LOGS_EXPORTER": "otlp"}, None),
            # The pin in force, four spellings: no note.
            (IN_FORCE, None),
            ({**IN_FORCE, "OTEL_EXPORTER_OTLP_ENDPOINT": PINNED + "/"}, None),
            ({"CLAUDE_CODE_ENABLE_TELEMETRY": "1", "OTEL_LOGS_EXPORTER": "otlp",
              "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": PINNED + "/v1/logs"}, None),
            ({**IN_FORCE, "OTEL_LOGS_EXPORTER": "otlp,console"}, None),
        )
        for i, (env, reason) in enumerate(cases):
            session = f"sess-{i:04d}aaaa"
            with self.subTest(env=env, reason=reason):
                self.hook(env, session=session)

                notes = [e["action"] for e in self.notes(session)]
                self.assertEqual(notes, [NOTE + reason] if reason else [])

    def test_without_the_installers_pin_there_is_no_note(self):
        for i, content in enumerate((
                None,                                   # no file
                "{not json",
                '{"hooks": {}}',                        # not a pin
                '{"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "%s", '
                '"THEIR_OWN": "1"}}' % PINNED)):        # somebody else's
            session = f"sess-{i:04d}bbbb"
            with self.subTest(content=content):
                if content is None:
                    self.pin.unlink()
                else:
                    self.plant(content)

                self.hook({}, session=session)

                self.assertEqual(self.notes(session), [])

    def test_a_session_end_run_writes_no_note(self):
        # The seal is written; the note is a completed-call or
        # failed-call matter, and the tail keeper's payload, whose
        # environment is the supervisor's, never gets one.
        self.transcript.write_bytes(b"page one\n")
        self.hook(IN_FORCE)
        for reason in ("prompt_input_exit", "tail-keeper"):
            with self.subTest(reason=reason):
                body = {"session_id": "sess-1234abcd",
                        "hook_event_name": "SessionEnd", "reason": reason,
                        "transcript_path": str(self.transcript)}

                self.hook({}, body)

                self.assertEqual(self.notes(), [])
        actions = [e["action"] for e in self.entries()]
        self.assertEqual(len(actions), 3, actions)
        self.assertTrue(actions[-1].startswith("transcript-commitment:"))

    def test_a_failed_call_run_leaves_the_note_too(self):
        body = payload(tool="Bash", tool_input={"command": "step"})
        body["hook_event_name"] = "PostToolUseFailure"

        self.hook({}, body)

        self.assertEqual([e["action"] for e in self.notes()],
                         [NOTE + "telemetry-off"])

    def test_another_harness_gets_no_note(self):
        # The pin is Claude Code's: Codex reads no managed settings and
        # has no second record to cut (docs/CLAIMS.md), so its receipts
        # carry no note about it.
        self.hook({}, None, "--actor", "codex")

        self.assertEqual(self.notes(), [])

    def test_the_note_stays_once_the_record_is_cut_and_back(self):
        self.hook({})
        self.hook(IN_FORCE)
        self.hook({})

        self.assertEqual(len(self.notes()), 1)


if __name__ == "__main__":
    unittest.main()


class CoverageMarkerTest(unittest.TestCase):
    """ADR-0030: the recorder writes down what coverage it wired, and the
    supervisor reads it. Without this the supervisor can date the
    beginning of coverage no earlier than its own first look, and
    docs/START.md puts a week of work between the two: install, work,
    then scan. Every session in that week fell outside the memory
    watching it."""

    def setUp(self):
        self.work = temp_folder(self)
        self.home = self.work / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = self.work / "store"
        self.codex = self.work / "codex"
        self.env = isolated_env(self.home, LOXODONTA_HOME=str(self.store),
                                CODEX_HOME=str(self.codex),
                                PYTHONIOENCODING="utf-8")

    def marker(self):
        path = self.store / "coverage.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def test_install_writes_down_the_coverage_it_wired(self):
        result = run(LOXODONTA, "install-hook", env=self.env)

        self.assertEqual(result.returncode, 0, result.stderr)
        marker = self.marker()
        self.assertIsNotNone(marker, "the installer records what it wired")
        self.assertEqual(len(marker["epochs"]), 1)
        epoch = marker["epochs"][0]
        self.assertEqual(epoch["matchers"], ["*"])
        self.assertEqual(epoch["harness"], "claude-code")
        self.assertRegex(epoch["since"],
                         r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$")

    def test_the_marker_says_which_profile_was_chosen(self):
        # ADR-0031 ruling 1: the profile is written beside the matchers,
        # so a profile that later changes is as visible to the supervisor
        # as a matcher change. The flagless install is `local`.
        run(LOXODONTA, "install-hook", env=self.env)
        self.assertEqual(self.marker()["epochs"][-1]["profile"], "local")

        result = run(LOXODONTA, "install-hook", "--profile", "timestamped", env=self.env)

        self.assertEqual(result.returncode, 0, result.stderr)
        epochs = self.marker()["epochs"]
        self.assertEqual([e["profile"] for e in epochs],
                         ["local", "timestamped"])
        self.assertEqual({e["matchers"][0] for e in epochs}, {"*"},
                         "a profile widens no coverage")

    def test_the_raw_flags_are_written_down_as_custom(self):
        # With no profile named, the raw flags speak for themselves and
        # the marker says so; naming `custom` says the same thing.
        run(LOXODONTA, "install-hook", "--anchor-at-session-end", env=self.env)
        self.assertEqual(self.marker()["epochs"][-1]["profile"], "custom")

        run(LOXODONTA, "install-hook", "--profile", "custom",
                      "--anchor-at-session-end", env=self.env)

        self.assertEqual([e["profile"] for e in self.marker()["epochs"]],
                         ["custom"], "the same choice appends nothing")

    def test_a_second_install_appends_nothing(self):
        # The heal rule applied to matchers: re-running the installer is
        # the documented way to fix a moved script, and it must not grow
        # a file every time.
        run(LOXODONTA, "install-hook", env=self.env)

        run(LOXODONTA, "install-hook", env=self.env)

        self.assertEqual(len(self.marker()["epochs"]), 1)

    def test_codex_coverage_never_speaks_for_claude_code(self):
        # Codex wires `.*` into a different settings file, and the
        # completeness witness reads Claude Code's transcripts alone.
        run(LOXODONTA, "install-hook", env=self.env)
        run(LOXODONTA, "install-hook", "--codex", env=self.env)

        harnesses = {epoch["harness"]: epoch["matchers"]
                     for epoch in self.marker()["epochs"]}

        self.assertEqual(harnesses, {"claude-code": ["*"], "codex": [".*"]})

    def test_the_marker_says_failed_calls_are_wired(self):
        # #239: the witness owes a failed command a receipt only under an
        # install that wired the failure event, so the marker says which
        # installs did. Codex has no such event, and its epoch says none.
        run(LOXODONTA, "install-hook", env=self.env)
        run(LOXODONTA, "install-hook", "--codex", env=self.env)

        epochs = {epoch["harness"]: epoch
                  for epoch in self.marker()["epochs"]}

        self.assertEqual(epochs["claude-code"]["failures"], ["*"])
        self.assertNotIn("failures", epochs["codex"])

    def test_a_rerun_that_newly_wires_failed_calls_appends_an_epoch(self):
        # An install from before #239: PostToolUse alone in the settings
        # and a marker epoch naming no failures. The re-run that adds the
        # failure event writes that down once, and the next writes
        # nothing, because nothing changed.
        run(LOXODONTA, "install-hook", env=self.env)
        path = self.home / ".claude" / "settings.json"
        settings = json.loads(path.read_text(encoding="utf-8"))
        del settings["hooks"]["PostToolUseFailure"]
        path.write_text(json.dumps(settings), encoding="utf-8")
        marker = self.marker()
        del marker["epochs"][0]["failures"]
        (self.store / "coverage.json").write_text(json.dumps(marker),
                                                  encoding="utf-8")

        run(LOXODONTA, "install-hook", env=self.env)
        run(LOXODONTA, "install-hook", env=self.env)

        self.assertEqual([epoch.get("failures")
                          for epoch in self.marker()["epochs"]],
                         [None, ["*"]])

    def test_uninstall_writes_nothing(self):
        # Ruling 2, and the asymmetry is the whole argument: a start
        # claim says more calls owe receipts, an end claim says fewer,
        # and "nothing was owed from here" is the silence the
        # completeness alarm exists to catch.
        run(LOXODONTA, "install-hook", env=self.env)
        before = self.marker()

        run(LOXODONTA, "uninstall-hook", env=self.env)

        self.assertEqual(self.marker(), before,
                         "removing the hook never records an end")


class ClockOverrideTest(unittest.TestCase):
    """SOURCE_DATE_EPOCH (the reproducible-builds convention) pins the
    recorder's clock so a demo store (tools/demo_store.py) writes the
    same bytes on every run. Timestamps are testimony either way: the
    writer is the adversary and always could have said any time it
    liked (ADR-0002)."""

    def setUp(self):
        self.workdir = temp_folder(self)

    def entries(self):
        log = self.workdir / "receipts-sess-1234abcd.jsonl"
        return [json.loads(line) for line in
                log.read_text(encoding="utf-8").splitlines()]

    def test_source_date_epoch_pins_the_timestamp(self):
        from datetime import datetime, timezone
        epoch = 1756000000
        expected = datetime.fromtimestamp(epoch, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

        result = run_hook(payload(tool="Bash", tool_input={"command": "ls"}),
                          cwd=self.workdir,
                          extra_env={"SOURCE_DATE_EPOCH": str(epoch)})

        self.assertEqual(result.returncode, 0, result.stderr)
        entries = self.entries()
        self.assertEqual([e["ts"] for e in entries], [expected, expected])

    def test_without_the_variable_the_wall_clock_stamps_the_entry(self):
        result = run_hook(payload(tool="Bash", tool_input={"command": "ls"}),
                          cwd=self.workdir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.entries()[1]["ts"].startswith("20"))
        self.assertNotEqual(self.entries()[1]["ts"], "2025-08-24T01:46:40Z")


class ReceiptSuffixTest(unittest.TestCase):
    """ADR-0047: a hook receipt names its call and commits to its whole
    input, in one bracketed group at the end of the action line. Each
    case is a payload in and the exact line out."""

    # The canonical form of INPUT, written out by hand from SPEC section
    # 4's rules: keys sorted, no whitespace, UTF-8, so the e with an
    # acute accent is two bytes.
    INPUT = {"description": "Say café", "command": "echo hi"}
    FORM = '{"command":"echo hi","description":"Say café"}'.encode()
    DIGEST = hashlib.sha256(FORM).hexdigest()

    def setUp(self):
        self.workdir = temp_folder(self)

    def actions(self, session="sess-1234abcd"):
        log = self.workdir / f"receipts-{session}.jsonl"
        return [json.loads(line)["action"]
                for line in log.read_text(encoding="utf-8").splitlines()]

    def hook(self, body, code=0):
        result = run_hook(body, cwd=self.workdir)
        self.assertEqual(result.returncode, code, result.stderr)
        return result

    def call(self, tool="Bash", tool_input=None, call=None, **extra):
        body = payload(tool=tool, tool_input=tool_input)
        if call is not None:
            body["tool_use_id"] = call
        body.update(extra)
        return body

    def test_a_call_id_and_an_input_end_the_line_in_the_pinned_suffix(self):
        self.hook(self.call(tool_input=self.INPUT, call="toolu_01AbC-9"))

        self.assertEqual(len(self.FORM), 47)  # 46 characters, 47 bytes
        self.assertEqual(
            self.actions()[1],
            f"Bash: echo hi [call=toolu_01AbC-9 input sha256={self.DIGEST} "
            f"bytes={len(self.FORM)}]")
        verify = run(LOXODONTA, "verify", "--log",
                     "receipts-sess-1234abcd.jsonl", cwd=self.workdir)
        self.assertEqual((verify.returncode, verify.stdout.strip()),
                         (0, "VALID"), verify.stderr)

    def test_the_released_verifier_reads_a_suffixed_chain_valid(self):
        # A verifier that knows nothing of the suffix reads the line as
        # text (ADR-0047 ruling 6).
        from test_package_anchor import released_verifier
        self.hook(self.call(tool_input=self.INPUT, call="toolu_01AbC"))
        self.hook(self.call(tool="TodoWrite", tool_input={"n": 1.5}))
        self.assertEqual(self.actions()[1:], [
            f"Bash: echo hi [call=toolu_01AbC input sha256={self.DIGEST} "
            f"bytes={len(self.FORM)}]", "TodoWrite [input=unhashed]"])
        released = released_verifier(self, self.workdir)

        verify = run(released, "verify", "--log",
                     "receipts-sess-1234abcd.jsonl", cwd=self.workdir,
                     isolated=True)

        self.assertEqual((verify.returncode, verify.stdout.strip()),
                         (0, "VALID"), verify.stderr)

    def test_a_cut_command_keeps_its_cut_and_count_before_the_suffix(self):
        command = "a" * 600
        self.hook(self.call(tool_input={"command": command}, call="toolu_1"))

        form = ('{"command":"' + command + '"}').encode()
        self.assertEqual(
            self.actions()[1],
            "Bash: " + "a" * 160 + "… (+440) [call=toolu_1 input "
            f"sha256={hashlib.sha256(form).hexdigest()} bytes=614]")

    def test_a_payload_with_no_id_writes_the_input_field_alone(self):
        self.hook(self.call(tool_input=self.INPUT))

        self.assertEqual(self.actions()[1],
                         f"Bash: echo hi [input sha256={self.DIGEST} "
                         f"bytes={len(self.FORM)}]")

    def test_an_id_that_fails_the_test_is_left_out(self):
        bad = ("toolu 01", "t" * 129, "toolu_01]", "toolu_é01", "", 7,
               None)
        for session, call in enumerate(bad):
            with self.subTest(call=call):
                body = self.call(tool_input=self.INPUT)
                body["tool_use_id"] = call
                body["session_id"] = f"sess-{session}"
                self.hook(body)
                self.assertEqual(self.actions(f"sess-{session}")[1],
                                 f"Bash: echo hi [input sha256={self.DIGEST} "
                                 f"bytes={len(self.FORM)}]")

    def test_an_id_of_200_characters_is_left_out_and_128_is_kept(self):
        self.hook(self.call(tool_input={}, call="x" * 200,
                            session_id="sess-long"))
        self.hook(self.call(tool_input={}, call="x" * 128,
                            session_id="sess-edge"))

        empty = hashlib.sha256(b"{}").hexdigest()
        self.assertEqual(self.actions("sess-long")[1],
                         f"Bash [input sha256={empty} bytes=2]")
        self.assertEqual(self.actions("sess-edge")[1],
                         f"Bash [call={'x' * 128} input sha256={empty} "
                         "bytes=2]")

    def test_an_input_with_a_fraction_is_named_unhashed(self):
        for session, tool_input in enumerate((
                {"command": "sleep", "seconds": 1.5},
                {"command": "sleep", "steps": [1, {"at": 2.0}]})):
            with self.subTest(tool_input=tool_input):
                self.hook(self.call(tool_input=tool_input, call="toolu_1",
                                    session_id=f"sess-{session}"))
                self.assertEqual(self.actions(f"sess-{session}")[1],
                                 "Bash: sleep [call=toolu_1 input=unhashed]")

    def test_integers_booleans_and_null_are_hashed(self):
        tool_input = {"limit": 2, "replace_all": False, "offset": None}
        self.hook(self.call(tool="Grep", tool_input=tool_input))

        form = b'{"limit":2,"offset":null,"replace_all":false}'
        self.assertEqual(self.actions()[1],
                         f"Grep [input sha256={hashlib.sha256(form).hexdigest()}"
                         f" bytes={len(form)}]")

    def test_an_input_with_no_summary_key_writes_the_name_then_the_suffix(self):
        tool_input = {"todos": [{"content": "ship it", "status": "pending"}]}
        self.hook(self.call(tool="TodoWrite", tool_input=tool_input,
                            call="toolu_9"))

        form = b'{"todos":[{"content":"ship it","status":"pending"}]}'
        self.assertEqual(self.actions()[1],
                         "TodoWrite [call=toolu_9 input "
                         f"sha256={hashlib.sha256(form).hexdigest()} "
                         f"bytes={len(form)}]")

    def test_a_payload_with_no_input_leaves_the_input_field_out(self):
        body = self.call(call="toolu_2")
        del body["tool_input"]
        self.hook(body)
        bare = self.call(session_id="sess-bare")
        del bare["tool_input"]
        self.hook(bare)

        self.assertEqual(self.actions()[1], "Bash [call=toolu_2]")
        self.assertEqual(self.actions("sess-bare")[1], "Bash")

    def test_bookkeeping_entries_carry_no_suffix(self):
        transcript = self.workdir / "t.jsonl"
        transcript.write_text("{}\n", encoding="utf-8")
        for _ in range(25):
            self.hook(self.call(tool_input={"command": "ls"}, call="toolu_3",
                                transcript_path=str(transcript)))
        transcript.write_text("{}\n{}\n", encoding="utf-8")
        self.hook({"session_id": "sess-1234abcd",
                   "hook_event_name": "SessionEnd",
                   "transcript_path": str(transcript)})

        commitments = [a for a in self.actions()
                       if a.startswith("transcript-commitment:")]
        self.assertEqual(len(commitments), 2)
        for line in commitments:
            self.assertRegex(line, r"^transcript-commitment: bytes=\d+ "
                                   r"sha256=[0-9a-f]{64}$")

    def test_run_and_log_write_no_suffix(self):
        log = self.workdir / "receipts.jsonl"
        run(LOXODONTA, "init", "--log", str(log), check=True)
        logged = run(LOXODONTA, "log", "--log", str(log), "--actor", "me",
                     "--action", "Bash: echo hi")
        ran = run(LOXODONTA, "run", "--log", str(log), "--actor", "me", "--",
                  sys.executable, "-c", "pass")
        self.assertEqual((logged.returncode, ran.returncode), (0, 0),
                         logged.stderr + ran.stderr)

        actions = [json.loads(line)["action"]
                   for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(actions[1], "Bash: echo hi")
        self.assertTrue(actions[2].startswith("run: "), actions[2])
        self.assertTrue(actions[2].endswith(" -c pass (exit 0)"), actions[2])

    def locked(self, path):
        """Hold `path` so the hook cannot read it, for as long as the test
        runs: a byte-range lock on Windows, no read permission on POSIX."""
        if sys.platform == "win32":
            import msvcrt
            size = path.stat().st_size
            held = open(path, "r+b")
            self.addCleanup(held.close)
            msvcrt.locking(held.fileno(), msvcrt.LK_NBLCK, size)
            self.addCleanup(msvcrt.locking, held.fileno(), msvcrt.LK_UNLCK,
                            size)
            return
        if os.geteuid() == 0:
            self.skipTest("root reads a file with no read permission")
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o644)

    def warnings(self, result):
        """The hook's stderr lines, which must all be warnings: a receipt
        written is exit 0 and never an `error:` line (ADR-0047)."""
        lines = result.stderr.splitlines()
        self.assertTrue(all(line.startswith("warning: ") for line in lines),
                        result.stderr)
        return lines

    def test_a_file_that_cannot_be_fingerprinted_still_leaves_its_receipt(self):
        # ADR-0047 ruling 4: the receipt is appended without the
        # reference, the line says so before the suffix, a warning names
        # the file, and the exit is the receipt's: 0, it is on the chain.
        notes = self.workdir / "notes.md"
        notes.write_text("hello\n", encoding="utf-8")
        tool_input = {"file_path": "notes.md", "content": "hello\n"}
        self.locked(notes)

        result = self.hook(self.call(tool="Write", tool_input=tool_input,
                                     call="toolu_4"))

        (warning,) = self.warnings(result)
        self.assertIn("notes.md", warning)
        form = b'{"content":"hello\\n","file_path":"notes.md"}'
        log = self.workdir / "receipts-sess-1234abcd.jsonl"
        entry = json.loads(log.read_text(encoding="utf-8").splitlines()[1])
        self.assertEqual(entry["action"],
                         "Write: notes.md (1 not fingerprinted) [call=toolu_4 "
                         f"input sha256={hashlib.sha256(form).hexdigest()} "
                         f"bytes={len(form)}]")
        self.assertEqual(entry["files"], [])
        verify = run(LOXODONTA, "verify", "--log", str(log))
        self.assertEqual((verify.returncode, verify.stdout.strip()),
                         (0, "VALID"), verify.stderr)

    def test_of_two_files_the_one_that_can_be_read_is_fingerprinted(self):
        good = self.workdir / "good.ipynb"
        good.write_text("{}\n", encoding="utf-8")
        held = self.workdir / "held.md"
        held.write_text("hello\n", encoding="utf-8")
        tool_input = {"file_path": "held.md", "notebook_path": "good.ipynb"}
        self.locked(held)

        result = self.hook(self.call(tool="Edit", tool_input=tool_input))

        (warning,) = self.warnings(result)
        self.assertIn("held.md", warning)
        self.assertNotIn("good.ipynb", warning)
        form = b'{"file_path":"held.md","notebook_path":"good.ipynb"}'
        log = self.workdir / "receipts-sess-1234abcd.jsonl"
        entry = json.loads(log.read_text(encoding="utf-8").splitlines()[1])
        self.assertEqual(entry["action"],
                         "Edit: held.md (1 not fingerprinted) [input "
                         f"sha256={hashlib.sha256(form).hexdigest()} "
                         f"bytes={len(form)}]")
        self.assertEqual(entry["files"], [{
            "path": "good.ipynb",
            "sha256": hashlib.sha256(good.read_bytes()).hexdigest()}])

    FOLDED_NOTE = "a line ending [...] is listed without its last group"

    def report(self):
        report = run(LOXODONTA, "report", "--log",
                     "receipts-sess-1234abcd.jsonl", cwd=self.workdir)
        self.assertEqual(report.returncode, 0, report.stderr)
        return report.stdout

    def test_report_folds_the_suffix_and_the_chain_keeps_it(self):
        # A listing for a person leaves the suffix out and marks the line
        # it shortened; the line in the chain is whole (ADR-0047, #619).
        self.hook(self.call(tool_input=self.INPUT, call="toolu_5"))

        out = self.report()

        (row,) = [line for line in out.splitlines()
                  if "claude-code:" in line]
        self.assertTrue(row.endswith("  claude-code: Bash: echo hi [...]"),
                        row)
        self.assertIn(self.FOLDED_NOTE, out)
        self.assertTrue(self.actions()[1].endswith(" bytes=47]"))

    def test_report_marks_a_hand_written_line_ending_in_a_suffix(self):
        # #619: nothing in an entry the writer cannot set tells a hook's
        # receipt from a line logged by hand, the actor included, so a
        # hand-written group is folded and marked like the hook's.
        self.hook(self.call(tool_input=self.INPUT, call="toolu_5"))
        group = f"[call=toolu_x input sha256={self.DIGEST} bytes=72]"
        logged = run(LOXODONTA, "log", "--log", "receipts-sess-1234abcd.jsonl",
                     "--actor", "claude-code", "--action",
                     f"Bash: rm -rf build {group}", cwd=self.workdir)
        self.assertEqual(logged.returncode, 0, logged.stderr)

        out = self.report()

        self.assertIn("  claude-code: Bash: rm -rf build [...]\n", out)
        self.assertIn(self.FOLDED_NOTE, out)
        self.assertEqual(self.actions()[2], f"Bash: rm -rf build {group}")

    def test_report_of_lines_without_a_suffix_has_no_mark(self):
        made = run(LOXODONTA, "init", "--log", "receipts-sess-1234abcd.jsonl",
                   cwd=self.workdir)
        self.assertEqual(made.returncode, 0, made.stderr)
        logged = run(LOXODONTA, "log", "--log", "receipts-sess-1234abcd.jsonl",
                     "--actor", "agent", "--action", "wrote [notes]",
                     cwd=self.workdir)
        self.assertEqual(logged.returncode, 0, logged.stderr)

        out = self.report()

        self.assertIn("  agent: wrote [notes]\n", out)
        self.assertNotIn("[...]", out)
        self.assertNotIn(self.FOLDED_NOTE, out)

    @unittest.skipIf(sys.platform == "win32",
                     "Windows cannot name a file with a colon in it")
    def test_a_path_the_spelling_rule_refuses_still_leaves_its_receipt(self):
        # SPEC section 3 refuses a stored path whose second character is
        # a colon: the reference is left out and named in a warning, and
        # the receipt is written, exit 0.
        (self.workdir / "a:b.txt").write_text("x\n", encoding="utf-8")

        result = self.hook(self.call(tool="Read",
                                     tool_input={"file_path": "a:b.txt"}))

        (warning,) = self.warnings(result)
        self.assertIn("a drive", warning)
        form = b'{"file_path":"a:b.txt"}'
        self.assertEqual(self.actions()[1],
                         "Read: a:b.txt (1 not fingerprinted) [input "
                         f"sha256={hashlib.sha256(form).hexdigest()} "
                         f"bytes={len(form)}]")
