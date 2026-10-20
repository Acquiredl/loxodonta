"""A managed install (ADR-0040, #259): `install-hook --managed` wires the
hook in a file of the recorder's own, in the harness's managed settings
folder, and the hook then has one home. Since ADR-0042 (#460) it first
copies the recorder and the supervisor into a folder of their own under
the system program area, and the commands name the copy.

Every test here points the installer and the supervisor at a folder of
its own through LOXODONTA_MANAGED_DIR, and the copy at another through
LOXODONTA_PROGRAM_DIR, the suite's two seams: no test reads or writes
the machine's managed settings folder or its program area, and none
needs rights it does not have. The one test that leaves the first seam
unset is the installer's refusal, which stops before it reads or writes
anything. The cases that need a real session and a real managed
file (one receipt and not two, a run that sets `disableAllHooks`,
`--bare`) are the author's to run and are not here.
"""

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_managed_install`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import home_guard  # noqa: E402
from support import (LOXODONTA, REPO_ROOT, SUPERVISOR,  # noqa: E402
                     isolated_env, run, temp_folder)

from test_supervisor import (ago, chain_head, make_chain,  # noqa: E402
                             prime_memory, run_scan, write_transcript)

OURS = ("loxodonta.py", "supervisor.py")
# The harness's own managed settings folder, as its documentation names
# it: what a variable naming it in any spelling stands in for nothing.
HARNESS_FOLDER = {"win32": "C:\\Program Files\\ClaudeCode",
                  "darwin": "/Library/Application Support/ClaudeCode",
                  }.get(sys.platform, "/etc/claude-code")
REMOTE = "http://127.0.0.1:9/hook"


class ManagedBase(unittest.TestCase):

    def setUp(self):
        self.work = temp_folder(self)
        self.home = self.work / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = self.work / "store"
        # Stands in for the harness's managed settings folder.
        self.managed = self.work / "managed"
        # Stands in for the copy's folder under the system program area
        # (ADR-0042 ruling 1).
        self.program = self.work / "program"
        self.copy = self.program / "loxodonta.py"
        self.copy_supervisor = self.program / "supervisor.py"
        self.env = isolated_env(self.home, LOXODONTA_HOME=str(self.store),
                                LOXODONTA_MANAGED_DIR=str(self.managed),
                                LOXODONTA_PROGRAM_DIR=str(self.program),
                                PYTHONIOENCODING="utf-8")
        self.operator_file = self.home / ".claude" / "settings.json"
        self.managed_file = (self.managed / "managed-settings.d"
                             / "loxodonta.json")
        # The telemetry pin, beside the hooks file (ADR-0041 ruling 7).
        self.pin_file = (self.managed / "managed-settings.d"
                         / "loxodonta-telemetry.json")

    def install(self, *args, env=None):
        done = run(LOXODONTA, "install-hook", *args,
                   env=self.env if env is None else env)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return done

    def read(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def epochs(self):
        return self.read(self.store / "coverage.json")["epochs"]

    def commands(self, settings, event):
        return [hook["command"]
                for block in settings.get("hooks", {}).get(event, [])
                for hook in block["hooks"]]

    def ours_in(self, path):
        """The commands in the hooks file at `path` that name one of the
        project's two scripts."""
        if not os.path.exists(path):
            return []
        settings = self.read(path)
        return [command for event in settings.get("hooks", {})
                for command in self.commands(settings, event)
                if any(name in command for name in OURS)]

    def everything(self):
        """Every file and folder under the test's folder, files as their
        bytes: what "writes nothing anywhere" is held to."""
        return {str(path.relative_to(self.work)):
                path.read_bytes() if path.is_file() else None
                for path in sorted(self.work.rglob("*"))}


class ManagedInstallTest(ManagedBase):

    def without_the_right(self):
        """An environment whose managed folder cannot be made on any
        platform, by any account: its parent is a file."""
        blocker = self.work / "blocker"
        blocker.write_text("a file, not a folder", encoding="utf-8")
        return {**self.env,
                "LOXODONTA_MANAGED_DIR": str(blocker / "managed")}

    def test_without_the_right_to_write_it_writes_nothing_anywhere(self):
        # Case 1. The hook is wired in the operator's file, and stays.
        self.install()
        env = self.without_the_right()
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", env=env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(os.path.join(env["LOXODONTA_MANAGED_DIR"],
                                   "managed-settings.d", "loxodonta.json"),
                      done.stderr)
        self.assertEqual(self.everything(), before)
        self.assertTrue(self.ours_in(self.operator_file))

    def test_without_the_right_a_first_install_leaves_no_file_behind(self):
        env = self.without_the_right()
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                             "timestamped", env=env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertEqual(self.everything(), before)

    def test_the_managed_file_holds_hooks_and_nothing_else(self):
        # Case 2, on a machine with nothing wired yet.
        done = self.install("--managed")

        managed = self.read(self.managed_file)
        self.assertEqual(list(managed), ["hooks"])
        self.assertEqual(sorted(managed["hooks"]),
                         ["PostToolUse", "PostToolUseFailure", "SessionEnd",
                          "SessionStart"])
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertFalse(self.operator_file.exists(),
                         "nothing of the operator's was there to touch")
        self.assertEqual(os.listdir(self.managed), ["managed-settings.d"])
        self.assertEqual(os.listdir(self.managed_file.parent),
                         ["loxodonta.json"])

    @unittest.skipIf(sys.platform == "win32", "permission bits are POSIX")
    def test_every_account_can_read_what_it_wrote(self):
        # The harness that reads the file runs as the operator, not as
        # whoever installed: under an installer's tight umask the file
        # would otherwise be the installer's alone, and no other
        # account's session would run the hook.
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)

        self.install("--managed")

        modes = {path: os.stat(path).st_mode & 0o777
                 for path in (self.managed, self.managed_file.parent,
                              self.managed_file)}
        self.assertEqual(list(modes.values()), [0o755, 0o755, 0o644], modes)

    def test_it_writes_the_entries_a_plain_install_writes(self):
        for flags in ((), ("--profile", "timestamped"),
                      ("--profile", "full", "--remote", REMOTE,
                       "--authority", "http://127.0.0.1:9/tsa")):
            with self.subTest(flags=flags), \
                    tempfile.TemporaryDirectory() as other:
                other = Path(other).resolve()
                (other / ".claude").mkdir()
                self.install(*flags, env=isolated_env(
                    other, PYTHONIOENCODING="utf-8"))
                plain = self.read(other / ".claude" / "settings.json")

                self.install("--managed", *flags)

                # The same entries, naming the copy (ADR-0042 ruling 2).
                copied = json.loads(
                    json.dumps({"hooks": plain["hooks"]})
                    .replace(LOXODONTA.as_posix(), self.copy.as_posix())
                    .replace(SUPERVISOR.as_posix(),
                             self.copy_supervisor.as_posix()))
                self.assertEqual(self.read(self.managed_file), copied)

    def test_the_entries_leave_the_operators_file_and_nothing_else_does(self):
        # Case 2: one home. Everything that was not the installer's is
        # as it lay, another tool's hook on the same event included.
        original = {
            "cleanupPeriodDays": 45,
            "permissions": {"allow": ["Bash(ls:*)"]},
            "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "somebody-else --flag"}]}]},
        }
        self.operator_file.write_text(json.dumps(original), encoding="utf-8")
        self.install()
        self.assertTrue(self.ours_in(self.operator_file))

        done = self.install("--managed")

        self.assertEqual(self.ours_in(self.operator_file), [])
        self.assertEqual(self.read(self.operator_file), original)
        self.assertEqual(len(self.ours_in(self.managed_file)), 4)
        self.assertIn(str(self.operator_file), done.stdout)

    def test_a_narrowed_matcher_moves_with_the_entries(self):
        # A plain install leaves a matcher the operator narrowed, and
        # says so; the same choice in another home.
        self.install()
        settings = self.read(self.operator_file)
        for event in ("PostToolUse", "PostToolUseFailure"):
            settings["hooks"][event][0]["matcher"] = "Edit|Write|Bash"
        self.operator_file.write_text(json.dumps(settings), encoding="utf-8")

        done = self.install("--managed")

        managed = self.read(self.managed_file)
        self.assertEqual(managed["hooks"]["PostToolUse"][0]["matcher"],
                         "Edit|Write|Bash")
        self.assertIn("narrower", done.stdout)
        self.assertEqual(self.epochs()[-1]["matchers"], ["Edit|Write|Bash"])

    def test_the_marker_says_the_hook_moved(self):
        # Case 2, and ruling 6: the matchers did not change, the home
        # did, and that is a change the marker records.
        self.install()

        self.install("--managed")

        first, second = self.epochs()
        self.assertNotIn("level", first)
        self.assertEqual(second["level"], "managed")
        self.assertEqual(second["matchers"], first["matchers"])
        self.assertEqual(second["harness"], "claude-code")

    def test_a_second_run_changes_nothing_and_says_so(self):
        # Case 3.
        self.install()
        self.install("--managed")
        before = self.everything()

        done = self.install("--managed")

        self.assertEqual(self.everything(), before)
        self.assertIn("already installed", done.stdout)
        self.assertIn("nothing changed", done.stdout)
        self.assertIn(str(self.managed_file), done.stdout)

    def test_a_second_run_with_other_flags_rewrites_the_managed_file(self):
        self.install("--managed")
        (end,) = self.commands(self.read(self.managed_file), "SessionEnd")
        self.assertNotIn("--anchor", end)

        done = self.install("--managed", "--profile", "timestamped")

        (end,) = self.commands(self.read(self.managed_file), "SessionEnd")
        self.assertTrue(end.endswith(" --anchor"), end)
        self.assertIn("anchors at session end", done.stdout)
        self.assertEqual([(e["profile"], e.get("level"))
                          for e in self.epochs()],
                         [("local", "managed"), ("timestamped", "managed")])

        back = self.install("--managed")

        (end,) = self.commands(self.read(self.managed_file), "SessionEnd")
        self.assertNotIn("--anchor", end)
        self.assertIn("no longer anchors at session end", back.stdout)

    def test_managed_with_codex_is_a_usage_error(self):
        before = self.everything()
        for verb in ("install-hook", "uninstall-hook"):
            with self.subTest(verb=verb):
                done = run(LOXODONTA, verb, "--managed", "--codex", env=self.env)

                self.assertEqual(done.returncode, 64,
                                 done.stdout + done.stderr)
                self.assertIn("--codex", done.stderr)
                self.assertEqual(self.everything(), before)

    def test_a_plain_install_refuses_while_the_managed_file_holds_them(self):
        # Case 7.
        self.install("--managed")
        before = self.everything()

        done = run(LOXODONTA, "install-hook", env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("install-hook --managed", done.stderr)
        self.assertIn("uninstall-hook --managed", done.stderr)
        self.assertEqual(self.everything(), before)

    def test_a_plain_install_for_codex_is_another_harness_and_goes_ahead(self):
        self.install("--managed")

        done = run(LOXODONTA, "install-hook", "--codex", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_the_override_is_said_out_loud_by_every_verb_that_reads_it(self):
        # The seam moves where the installer writes, never where the
        # harness reads, so each verb that reads it says which folder
        # the harness does read: when it goes through and when it
        # refuses, since a refusal is where a wrong folder is found.
        refused = self.without_the_right()
        (self.work / "folder" / "managed-settings.d" / "loxodonta.json"
         / "kept").mkdir(parents=True)
        folder = {**self.env,
                  "LOXODONTA_MANAGED_DIR": str(self.work / "folder")}
        for verb, flags, env, code in (
                ("install-hook", ("--managed",), refused, 73),
                ("install-hook", ("--managed",), self.env, 0),
                ("install-hook", (), self.env, 73),
                ("uninstall-hook", (), self.env, 0),
                ("uninstall-hook", ("--managed",), folder, 73),
                ("uninstall-hook", ("--managed",), self.env, 0),
                ("uninstall-hook", ("--managed",), self.env, 0),
                ("install-hook", (), self.env, 0)):
            with self.subTest(verb=verb, flags=flags, code=code):
                done = run(LOXODONTA, verb, *flags, env=env)

                self.assertEqual(done.returncode, code,
                                 done.stdout + done.stderr)
                self.assertIn("LOXODONTA_MANAGED_DIR", done.stderr)
                self.assertIn(
                    os.path.join(env["LOXODONTA_MANAGED_DIR"],
                                 "managed-settings.d", "loxodonta.json"),
                    done.stderr)
                # The copy's seam, beside it (ADR-0042).
                self.assertIn("LOXODONTA_PROGRAM_DIR", done.stderr)
                self.assertIn(str(self.program), done.stderr)

    def test_codex_reads_no_managed_folder_and_says_nothing_of_one(self):
        for verb in ("install-hook", "uninstall-hook"):
            with self.subTest(verb=verb):
                done = run(LOXODONTA, verb, "--codex", env=self.env)

                self.assertEqual(done.returncode, 0,
                                 done.stdout + done.stderr)
                self.assertNotIn("LOXODONTA_MANAGED_DIR", done.stderr)
                self.assertNotIn("LOXODONTA_PROGRAM_DIR", done.stderr)

    def test_the_help_says_whose_word_the_claim_is(self):
        # The harness documents it and ADR-0040 measured it: the help
        # names both, and never states the claim with no source.
        done = run(LOXODONTA, "install-hook", "--help", env=self.env)

        said = " ".join(done.stdout.split())
        self.assertIn("documented by the harness", said)
        self.assertIn("measured in ADR-0040", said)
        self.assertNotIn("not yet measured", said)

    def test_a_refused_write_says_what_stands_in_the_way(self):
        # An administrator's shell mends a missing right and nothing
        # else: for a file where a folder belongs, or a folder where the
        # file belongs, the refusal names that and does not send the
        # reader for rights that would not help.
        blocked = self.without_the_right()
        done = run(LOXODONTA, "install-hook", "--managed", env=blocked)
        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.work / "blocker"), done.stderr)
        self.assertIn("is a file", done.stderr)
        self.assertNotIn("sudo", done.stderr)

        (self.managed_file / "kept").mkdir(parents=True)
        before = self.everything()
        done = run(LOXODONTA, "install-hook", "--managed", env=self.env)
        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("a folder", done.stderr)
        self.assertNotIn("sudo", done.stderr)
        self.assertEqual(self.everything(), before)

    @unittest.skipUnless(sys.platform == "win32",
                         "a read-only file refuses a replace on Windows")
    def test_a_read_only_managed_file_is_named_as_that(self):
        self.install("--managed")
        os.chmod(self.managed_file, stat.S_IREAD)
        self.addCleanup(os.chmod, self.managed_file, stat.S_IWRITE)
        for verb, flags in (("install-hook", ("--managed", "--profile",
                                              "timestamped")),
                            ("uninstall-hook", ("--managed",))):
            with self.subTest(verb=verb):
                done = run(LOXODONTA, verb, *flags, env=self.env)

                self.assertEqual(done.returncode, 73,
                                 done.stdout + done.stderr)
                self.assertIn(str(self.managed_file), done.stderr)
                self.assertIn("read-only", done.stderr)
                self.assertNotIn("sudo", done.stderr)

    def test_a_plain_install_goes_ahead_over_a_managed_file_it_cannot_read(self):
        # Not JSON, or JSON of another shape: nothing says the hook is
        # wired there, and refusing would leave it wired nowhere, over
        # a file the operator may have no right to mend.
        for what, content in (("not JSON", "{not json"),
                              ("another shape", '{"hooks": "none"}')):
            with self.subTest(content=what):
                self.managed_file.parent.mkdir(parents=True, exist_ok=True)
                self.managed_file.write_text(content, encoding="utf-8")

                done = run(LOXODONTA, "install-hook", env=self.env)

                self.assertEqual(done.returncode, 0,
                                 done.stdout + done.stderr)
                self.assertEqual(len(self.ours_in(self.operator_file)), 4)
                self.assertEqual(
                    self.managed_file.read_text(encoding="utf-8"), content,
                    "a plain install never writes the managed file")
                run(LOXODONTA, "uninstall-hook", env=self.env)

    def hold_two_homes(self):
        self.install()
        self.assertTrue(self.ours_in(self.operator_file))

    def two_homes_then_one(self, done):
        """What a failure between the two steps leaves, and what the
        next run makes of it."""
        self.assertNotIn(done.returncode, (0, 1), done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.operator_file), done.stderr)
        self.assertEqual(len(self.ours_in(self.managed_file)), 4,
                         "the managed file is written first")
        self.assertTrue(self.ours_in(self.operator_file),
                        "two homes, never none")

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_a_failure_between_the_steps_leaves_two_homes_posix(self):
        self.hold_two_homes()
        os.chmod(self.operator_file.parent, 0o555)
        self.addCleanup(os.chmod, self.operator_file.parent, 0o755)

        done = run(LOXODONTA, "install-hook", "--managed", env=self.env)

        self.two_homes_then_one(done)
        os.chmod(self.operator_file.parent, 0o755)
        again = self.install("--managed")
        self.assertEqual(self.ours_in(self.operator_file), [])
        self.assertIn(str(self.operator_file), again.stdout)

    @unittest.skipUnless(sys.platform == "win32",
                         "a file held open refuses a replace on Windows")
    def test_a_failure_between_the_steps_leaves_two_homes_windows(self):
        self.hold_two_homes()

        with open(self.operator_file, "rb"):
            done = run(LOXODONTA, "install-hook", "--managed", env=self.env)

        self.two_homes_then_one(done)
        again = self.install("--managed")
        self.assertEqual(self.ours_in(self.operator_file), [])
        self.assertIn(str(self.operator_file), again.stdout)

    def test_it_says_to_restart_serve_as_well(self):
        # #465: `serve` reads what is wired once, at its start, so one
        # started before the hook moved reads it where it was.
        for flags in ((), ("--profile", "timestamped")):
            with self.subTest(flags=flags):
                done = self.install("--managed", *flags)

                self.assertIn("`supervisor serve`",
                              " ".join(done.stdout.split()))

    def test_an_operators_file_it_cannot_read_stops_it_before_it_writes(self):
        self.operator_file.write_text("{not json", encoding="utf-8")
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 65, done.stdout + done.stderr)
        self.assertEqual(self.everything(), before)


def words(command):
    """A hook command split as the installer reads one: a backslash is an
    ordinary character, so a Windows path stays one word."""
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""
    return list(lexer)


def version_of(script):
    """The version a script's TOOL_VERSION line says."""
    return re.search(r'^TOOL_VERSION = "([^"]+)"',
                     script.read_text(encoding="utf-8"), re.M).group(1)


def interpreter_in_reach():
    """Why this test's own interpreter fails the installer's check, read
    here and not from the installer, or None when it may pass: on POSIX a
    component of its path, resolved, that is not root's or that its
    group or every account may write; on Windows a path outside
    C:\\Program Files and C:\\Windows (ADR-0042 ruling 3)."""
    if sys.platform == "win32":
        real = os.path.normcase(os.path.realpath(sys.executable))
        for system in ("C:\\Program Files", "C:\\Windows"):
            system = os.path.normcase(system)
            if real.startswith(system + os.sep):
                return None
        return real + " is outside C:\\Program Files and C:\\Windows"
    place = os.path.realpath(sys.executable)
    while True:
        status = os.lstat(place)
        if status.st_uid != 0 or status.st_mode & 0o022:
            return place + " is not root's alone"
        if os.path.dirname(place) == place:
            return None
        place = os.path.dirname(place)


class ManagedCopyTest(ManagedBase):
    """ADR-0042: the managed install copies the recorder and the
    supervisor into a folder of their own where only an administrator
    writes, after one check of the interpreter and that folder, and the
    same verb moves the copy again."""

    def release(self, version):
        """The recorder as a release `version` would ship it, in a folder
        of its own with the supervisor beside it: this checkout's two
        files, their version line saying `version`."""
        folder = self.work / ("release-" + version)
        folder.mkdir()
        for script in (LOXODONTA, SUPERVISOR):
            (folder / script.name).write_bytes(script.read_bytes().replace(
                f'TOOL_VERSION = "{version_of(script)}"'.encode(),
                f'TOOL_VERSION = "{version}"'.encode()))
        return folder / "loxodonta.py"

    def every_command(self, path):
        settings = self.read(path)
        return [command for event in settings["hooks"]
                for command in self.commands(settings, event)]

    def test_the_commands_name_a_copy_of_the_two_files(self):
        done = self.install("--managed")

        self.assertEqual(self.copy.read_bytes(), LOXODONTA.read_bytes())
        self.assertEqual(self.copy_supervisor.read_bytes(),
                         SUPERVISOR.read_bytes())
        self.assertEqual(sorted(os.listdir(self.program)),
                         ["loxodonta.py", "supervisor.py"])
        commands = self.every_command(self.managed_file)
        self.assertEqual(len(commands), 4)
        for command in commands:
            self.assertEqual(words(command)[1], "-I", command)
            self.assertIn(Path(words(command)[2]),
                          (self.copy, self.copy_supervisor), command)
        self.assertIn(str(self.copy), done.stdout)
        self.assertIn(version_of(LOXODONTA), done.stdout)
        # Ruling 8: the sum is the administrator's to take.
        for script in (LOXODONTA, SUPERVISOR):
            self.assertNotIn(hashlib.sha256(script.read_bytes()).hexdigest(),
                             done.stdout + done.stderr)

    def test_the_command_it_wires_runs_the_copy(self):
        self.install("--managed")
        (post,) = self.commands(self.read(self.managed_file), "PostToolUse")

        ran = subprocess.run(words(post) + ["--help"], capture_output=True,
                             encoding="utf-8", env=self.env, timeout=120)

        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertIn("usage", ran.stdout)

    @unittest.skipIf(sys.platform == "win32", "permission bits are POSIX")
    def test_every_account_can_read_the_copy(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)

        self.install("--managed")

        modes = [os.stat(path).st_mode & 0o777
                 for path in (self.program, self.copy, self.copy_supervisor)]
        self.assertEqual(modes, [0o755, 0o644, 0o644])

    def test_every_command_a_plain_install_writes_carries_I(self):
        # Ruling 4: one command shape, managed and plain, both harnesses.
        for flags, path in (((), self.operator_file),
                            (("--codex",),
                             self.home / ".codex" / "hooks.json")):
            with self.subTest(flags=flags):
                self.install(*flags)

                commands = self.every_command(path)
                self.assertTrue(commands)
                for command in commands:
                    self.assertEqual(words(command)[1], "-I", command)

    def test_an_entry_of_the_old_shape_heals_once(self):
        # The first plain install after the change rewrites what an
        # earlier one wrote without -I; the next finds nothing to do.
        python = Path(sys.executable).as_posix()
        old = f'"{python}" "{LOXODONTA.as_posix()}" hook'
        old_digest = f'"{python}" "{SUPERVISOR.as_posix()}" digest'
        self.operator_file.write_text(json.dumps({"hooks": {
            "PostToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": old}]}],
            "PostToolUseFailure": [{"matcher": "*", "hooks": [
                {"type": "command", "command": old}]}],
            "SessionEnd": [{"hooks": [
                {"type": "command", "command": old, "timeout": 20}]}],
            "SessionStart": [{"matcher": "startup|clear|compact", "hooks": [
                {"type": "command", "command": old_digest, "timeout": 5}]}],
        }}), encoding="utf-8")

        done = self.install()

        commands = self.every_command(self.operator_file)
        self.assertEqual(len(commands), 4, commands)
        for command in commands:
            self.assertEqual(words(command)[1], "-I", command)
        self.assertIn("healed 4 hook command(s)", done.stdout)
        again = self.install()
        self.assertIn("already installed", again.stdout)

    def test_a_managed_file_of_the_old_shape_moves_to_the_copy(self):
        # A managed install made before the copy named the checkout.
        self.install("--managed")
        python = Path(sys.executable).as_posix()
        text = self.managed_file.read_text(encoding="utf-8")
        for script in (self.copy, self.copy_supervisor):
            text = text.replace(f'\\"{python}\\" -I \\"{script.as_posix()}',
                                f'\\"{python}\\" \\"{(REPO_ROOT / script.name).as_posix()}')
        self.managed_file.write_text(text, encoding="utf-8")
        self.assertNotIn("-I", text)

        done = self.install("--managed")

        for command in self.every_command(self.managed_file):
            self.assertEqual(words(command)[1], "-I", command)
            self.assertEqual(Path(words(command)[2]).parent, self.program)
        self.assertNotIn("nothing changed", done.stdout)

    def test_the_same_verb_from_newer_files_moves_the_copy(self):
        # Ruling 5: both versions said, the managed file left alone.
        self.install("--managed")
        managed = self.managed_file.read_bytes()
        newer = self.release("99.0.0")

        up = run(newer, "install-hook", "--managed", env=self.env)

        self.assertEqual(up.returncode, 0, up.stdout + up.stderr)
        self.assertEqual(self.copy.read_bytes(), newer.read_bytes())
        self.assertEqual(self.copy_supervisor.read_bytes(),
                         (newer.parent / "supervisor.py").read_bytes())
        said = " ".join(up.stdout.split())
        self.assertIn(f"from {version_of(LOXODONTA)} to 99.0.0", said)
        self.assertEqual(self.managed_file.read_bytes(), managed,
                         "the flags did not change")
        self.assertNotIn("nothing changed", said)

        before = self.everything()
        again = run(newer, "install-hook", "--managed", env=self.env)

        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn("nothing changed", again.stdout)
        self.assertEqual(self.everything(), before)

    def test_the_same_verb_from_older_files_moves_it_back_and_says_so(self):
        self.install("--managed")
        newer = self.release("99.0.0")
        self.assertEqual(run(newer, "install-hook", "--managed",
                             env=self.env).returncode, 0)

        back = self.install("--managed")

        self.assertEqual(self.copy.read_bytes(), LOXODONTA.read_bytes())
        said = " ".join(back.stdout.split())
        self.assertIn(f"back from 99.0.0 to {version_of(LOXODONTA)}", said)

    def test_without_the_right_to_write_the_copys_folder_nothing_is_written(self):
        # Ruling 2, as ADR-0040 ruling 2: nothing anywhere, the folder
        # named, exit 73.
        blocker = self.work / "blocker"
        blocker.write_text("a file, not a folder", encoding="utf-8")
        env = {**self.env, "LOXODONTA_PROGRAM_DIR": str(blocker / "program")}
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", env=env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(f"cannot write {blocker / 'program'}", done.stderr)
        self.assertIn("is a file", done.stderr)
        self.assertEqual(self.everything(), before)

    def test_a_refused_managed_write_puts_the_copy_back(self):
        # The copy is written first, and a refusal after it leaves the
        # copy as it stood: a refused install has written nothing.
        self.install("--managed")
        newer = self.release("99.0.0")
        blocker = self.work / "blocker"
        blocker.write_text("a file, not a folder", encoding="utf-8")
        env = {**self.env, "LOXODONTA_MANAGED_DIR": str(blocker / "managed")}
        before = self.everything()

        done = run(newer, "install-hook", "--managed", env=env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertEqual(self.everything(), before)
        self.assertEqual(self.copy.read_bytes(), LOXODONTA.read_bytes())

    def test_under_the_stand_in_a_failed_check_is_a_warning(self):
        # The copy's stand-in sits in a temporary folder, which no check
        # passes, and the harness reads nothing the installer writes
        # while LOXODONTA_MANAGED_DIR is set: the refusal's own words, as
        # a warning, and the install goes on.
        done = self.install("--managed")

        (line,) = [line for line in done.stderr.splitlines()
                   if "ordinary account's reach" in line
                   and str(self.program) in line]
        self.assertTrue(line.startswith("warning:"), line)
        self.assertIn("LOXODONTA_MANAGED_DIR names a folder the harness does "
                      "not read", line)
        self.assertTrue(self.copy.is_file())

    def test_a_reachable_interpreter_is_refused_before_anything_is_written(self):
        # Ruling 3, without a stand-in for the managed folder: unset, or
        # naming the harness's own folder in any spelling, which an
        # account can set without rights for an elevated shell to
        # inherit. Only where this test sees for itself that its
        # interpreter fails the check, so the start can never reach the
        # machine's own folder.
        why = interpreter_in_reach()
        if why is None:
            self.skipTest("this interpreter may pass the check")
        real = HARNESS_FOLDER
        for managed in (None, real, real.upper(), real + os.sep):
            with self.subTest(managed=managed):
                env = {name: value for name, value in self.env.items()
                       if name != "LOXODONTA_MANAGED_DIR"}
                if managed is not None:
                    env["LOXODONTA_MANAGED_DIR"] = managed
                before = self.everything()

                with home_guard.left_to_the_machine("LOXODONTA_MANAGED_DIR"):
                    done = run(LOXODONTA, "install-hook", "--managed",
                               env=env)

                self.assertEqual(done.returncode, 64,
                                 done.stdout + done.stderr)
                self.assertNotIn("Traceback", done.stderr)
                self.assertIn(sys.executable, done.stderr)
                self.assertIn("a Python installed for all users",
                              done.stderr)
                self.assertNotIn("warning: the interpreter", done.stderr)
                self.assertEqual(self.everything(), before, why)

    def test_a_stand_in_for_the_managed_folder_needs_one_for_the_copy(self):
        # A check waived for the stand-in never writes or deletes the
        # copy in the system program area.
        env = {name: value for name, value in self.env.items()
               if name != "LOXODONTA_PROGRAM_DIR"}
        before = self.everything()
        for verb in ("install-hook", "uninstall-hook"):
            with self.subTest(verb=verb):
                with home_guard.left_to_the_machine("LOXODONTA_PROGRAM_DIR"):
                    done = run(LOXODONTA, verb, "--managed", env=env)

                self.assertEqual(done.returncode, 64,
                                 done.stdout + done.stderr)
                self.assertIn("LOXODONTA_PROGRAM_DIR must name", done.stderr)
                self.assertEqual(self.everything(), before)

    def test_the_check_reads_the_interpreter_as_the_command_names_it(self):
        # A link to the folder of a Python only root writes, in a folder
        # an ordinary account writes: what the command names goes
        # through the link, which that account retargets later.
        system = "/usr/bin/python3"
        if sys.platform == "win32" or not os.path.isfile(system):
            self.skipTest("needs POSIX and a system Python")
        place = os.path.realpath(system)
        while True:
            status = os.lstat(place)
            if status.st_uid != 0 or status.st_mode & 0o022:
                self.skipTest(f"{place} is not root's alone here")
            if os.path.dirname(place) == place:
                break
            place = os.path.dirname(place)
        (self.work / "bin").symlink_to(os.path.dirname(system),
                                       target_is_directory=True)
        link = self.work / "bin" / "python3"

        done = subprocess.run(
            [str(link), str(LOXODONTA), "install-hook", "--managed"],
            capture_output=True, encoding="utf-8", env=self.env, timeout=120)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(f"warning: the interpreter the hook command would "
                      f"name, {link}", done.stderr)

    @unittest.skipIf(sys.platform == "win32",
                     "a symbolic link needs a right of its own on Windows")
    def test_a_link_at_the_copys_name_is_checked_and_never_written_through(self):
        self.install("--managed")
        elsewhere = self.work / "writers" / "loxodonta.py"
        elsewhere.parent.mkdir()
        elsewhere.write_bytes(LOXODONTA.read_bytes())
        self.copy.unlink()
        self.copy.symlink_to(elsewhere)

        done = self.install("--managed")

        self.assertIn(f"warning: the file at the copy's name, {self.copy}",
                      done.stderr)
        self.assertFalse(self.copy.is_symlink(), "the name itself replaced")
        self.assertEqual(self.copy.read_bytes(), LOXODONTA.read_bytes())
        self.assertEqual(elsewhere.read_bytes(), LOXODONTA.read_bytes())

    def test_a_copy_without_a_supervisor_wires_no_digest(self):
        # A command never names a file the copy does not hold.
        alone = self.work / "alone"
        alone.mkdir()
        (alone / "loxodonta.py").write_bytes(LOXODONTA.read_bytes())
        self.install("--managed")
        self.assertTrue(self.commands(self.read(self.managed_file),
                                      "SessionStart"))
        self.copy_supervisor.unlink()

        done = run(alone / "loxodonta.py", "install-hook", "--managed",
                   env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.commands(self.read(self.managed_file),
                                       "SessionStart"), [])
        for command in self.every_command(self.managed_file):
            self.assertTrue(Path(words(command)[2]).is_file(), command)

    def test_the_heal_never_drops_a_session_end_step_quietly(self):
        # An entry of the old shape whose flags differ is not the heal's:
        # the session-end loop rewrites it and says what it stopped.
        python = Path(sys.executable).as_posix()
        old = f'"{python}" "{LOXODONTA.as_posix()}" hook'
        self.operator_file.write_text(json.dumps({"hooks": {
            "SessionEnd": [{"hooks": [
                {"type": "command", "command": old + " --anchor",
                 "timeout": 20}]}],
        }}), encoding="utf-8")

        done = self.install()

        (end,) = self.commands(self.read(self.operator_file), "SessionEnd")
        self.assertEqual(words(end)[1], "-I", end)
        self.assertNotIn("--anchor", end)
        self.assertIn("no longer anchors at session end", done.stdout)


class ManagedUninstallTest(ManagedBase):

    def test_it_deletes_that_one_file_and_nothing_else(self):
        # Case 6.
        self.install()
        self.install("--managed")
        policy = self.managed / "managed-settings.json"
        policy.write_text('{"cleanupPeriodDays": 90}', encoding="utf-8")
        sibling = self.managed_file.parent / "another-tool.json"
        sibling.write_text('{"hooks": {}}', encoding="utf-8")
        expected = self.everything()
        for gone in (self.managed_file, self.copy, self.copy_supervisor,
                     self.program):
            del expected[str(gone.relative_to(self.work))]

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertIn(str(self.copy), done.stdout)
        self.assertEqual(self.everything(), expected,
                         "the file and the copy are gone; the folder, its "
                         "other files, the operator's file and the marker "
                         "are as they lay")
        self.assertEqual(self.ours_in(self.operator_file), [],
                         "nothing is put back")

    def test_a_file_of_anyone_elses_keeps_the_copys_folder(self):
        # Ruling 7: the copy's two files, and the folder only when that
        # leaves it empty.
        self.install("--managed")
        stray = self.program / "notes.txt"
        stray.write_text("the administrator's", encoding="utf-8")

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(os.listdir(self.program), ["notes.txt"])
        self.assertIn(str(self.program), done.stdout)

    def test_a_copy_nothing_points_at_is_removed_too(self):
        # What a failure after the copy leaves (ruling 2).
        self.install("--managed")
        self.managed_file.unlink()

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(os.path.lexists(self.program))

    def refused_copy_delete(self):
        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.copy), done.stderr)
        self.assertFalse(self.managed_file.exists(),
                         "the command goes first, so none names nothing")
        self.assertTrue(self.copy.exists())
        return done

    @unittest.skipUnless(sys.platform == "win32",
                         "a read-only file refuses a delete on Windows")
    def test_a_copy_it_cannot_delete_is_named_windows(self):
        self.install("--managed")
        os.chmod(self.copy, stat.S_IREAD)
        self.addCleanup(os.chmod, self.copy, stat.S_IWRITE)

        self.assertIn("read-only", self.refused_copy_delete().stderr)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_a_copy_it_cannot_delete_is_named_posix(self):
        self.install("--managed")
        os.chmod(self.program, 0o555)
        self.addCleanup(os.chmod, self.program, 0o755)

        self.assertIn("sudo", self.refused_copy_delete().stderr)

    def test_with_nothing_there_it_says_so(self):
        before = self.everything()

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("nothing installed", done.stdout)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertEqual(self.everything(), before)

    def test_a_delete_the_system_refuses_names_the_file(self):
        # No platform deletes a folder as a file, whoever asks.
        (self.managed_file / "kept").mkdir(parents=True)
        before = self.everything()

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("a folder", done.stderr)
        self.assertNotIn("sudo", done.stderr)
        self.assertEqual(self.everything(), before)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_without_the_right_to_delete_it_refuses_and_names_the_file(self):
        self.install("--managed")
        os.chmod(self.managed_file.parent, 0o555)
        self.addCleanup(os.chmod, self.managed_file.parent, 0o755)
        before = self.everything()

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("sudo", done.stderr)
        self.assertEqual(self.everything(), before)

    @unittest.skipUnless(sys.platform == "win32",
                         "a file held open refuses a delete on Windows")
    def test_a_file_another_program_holds_open_is_named_as_that(self):
        # #465: Windows answers a file held open with a PermissionError
        # too, and no administrator's shell lets go of another's hold.
        self.install("--managed")
        before = self.everything()

        with open(self.managed_file, "rb"):
            done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("close it, then run this again", done.stderr)
        self.assertNotIn("administrator", done.stderr)
        self.assertEqual(self.everything(), before)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_without_the_right_to_write_the_folder_it_says_whose_right(self):
        self.install("--managed")
        os.chmod(self.managed_file.parent, 0o555)
        self.addCleanup(os.chmod, self.managed_file.parent, 0o755)
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                             "timestamped", env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("sudo", done.stderr)
        self.assertEqual(self.everything(), before)

    def test_it_says_when_the_operators_file_still_holds_the_entries(self):
        # Two homes, as a failure between the steps or a run as another
        # account leaves them: the managed uninstall removes its own
        # file, touches nothing of the operator's, and says the hook is
        # still wired there.
        self.install("--managed")
        managed = self.managed_file.read_bytes()
        run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)
        self.install()
        self.managed_file.write_bytes(managed)
        operators = self.operator_file.read_bytes()

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.managed_file.exists())
        self.assertEqual(self.operator_file.read_bytes(), operators)
        self.assertIn(f"still wired in {self.operator_file}", done.stdout)
        self.assertIn("`uninstall-hook`", done.stdout)

    def test_a_plain_uninstall_says_where_the_hook_is_and_what_removes_it(self):
        self.install("--managed")
        before = self.everything()

        done = run(LOXODONTA, "uninstall-hook", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertIn("uninstall-hook --managed", done.stdout)
        self.assertEqual(self.everything(), before)

    def test_a_plain_install_afterwards_is_marked_as_the_operators_file(self):
        # Ruling 6: an entry without `level` is the operator's own
        # settings file, as every entry written before this was.
        self.install("--managed")
        run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)
        self.assertEqual(len(self.epochs()), 1,
                         "an uninstall writes no coverage marker")

        self.install()

        managed, plain = self.epochs()
        self.assertEqual(managed["level"], "managed")
        self.assertNotIn("level", plain)
        self.assertEqual(len(self.ours_in(self.operator_file)), 4)


class AnotherAccountTest(ManagedBase):
    """Run as another account than the one that owns the home (a `sudo`
    that keeps HOME, as macOS's does), a managed install writes the
    managed file and touches nothing under that home: a file root
    rewrote there would be root's, closed to the operator's harness, and
    a root process writing in a folder the writer owns follows whatever
    the writer planted in it (ADR-0002).

    Through `sudo -n`, against this test's temporary folders only, and
    skipped wherever sudo asks for a password."""

    HANDED = ("HOME", "USERPROFILE", "LOXODONTA_HOME", "CODEX_HOME",
              "LOXODONTA_MANAGED_DIR", "LOXODONTA_PROGRAM_DIR",
              "PYTHONIOENCODING")

    def setUp(self):
        super().setUp()
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            self.skipTest("needs an account that is not root, and sudo")
        # sudo strips what a hosted Python needs to find its library.
        library = os.environ.get("LD_LIBRARY_PATH")
        self.root_python = (["sudo", "-n", "env"]
                            + ([f"LD_LIBRARY_PATH={library}"]
                               if library else []))
        try:
            probe = subprocess.run(
                self.root_python + [sys.executable, "-c",
                                    "import os; print(os.geteuid())"],
                capture_output=True, encoding="utf-8", timeout=60)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("no sudo here")
        if probe.returncode != 0 or probe.stdout.strip() != "0":
            self.skipTest("sudo asks for a password here")
        # What root made is handed back before the folder is removed.
        self.addCleanup(subprocess.run, [
            "sudo", "-n", "chown", "-R", f"{os.geteuid()}:{os.getegid()}",
            str(self.work)], capture_output=True, timeout=60)

    def as_root(self, *args):
        return subprocess.run(
            self.root_python + [f"{name}={self.env[name]}"
                                for name in self.HANDED]
            + [sys.executable, str(LOXODONTA), *args],
            capture_output=True, encoding="utf-8", timeout=120,
            env=self.env)

    def under_the_home(self):
        """Every file and folder of the home and the store, with its
        owner, files with their bytes."""
        found = {}
        for top in (self.home, self.store):
            for path in [top] + sorted(top.rglob("*")):
                if os.path.lexists(path):
                    found[str(path.relative_to(self.work))] = (
                        os.lstat(path).st_uid,
                        path.read_bytes() if path.is_file() else None)
        return found

    def test_as_another_account_it_touches_nothing_under_the_home(self):
        self.install()
        before = self.under_the_home()

        done = self.as_root("install-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.under_the_home(), before,
                         "no rewrite, no backup, no coverage marker, and "
                         "every file still the operator's")
        self.assertEqual(len(self.ours_in(self.managed_file)), 4)
        self.assertEqual(os.stat(self.managed_file).st_uid, 0)
        self.assertIn("two homes", done.stdout)
        self.assertIn(str(self.operator_file), done.stdout)
        self.assertIn("`uninstall-hook`", done.stdout)

        # What finishes it, run as the operator.
        finished = run(LOXODONTA, "uninstall-hook", env=self.env)
        self.assertEqual(finished.returncode, 0,
                         finished.stdout + finished.stderr)
        self.assertEqual(self.ours_in(self.operator_file), [])
        self.assertEqual(os.lstat(self.operator_file).st_uid, os.geteuid())

    def test_as_another_account_a_first_install_makes_no_store(self):
        before = self.under_the_home()

        done = self.as_root("install-hook", "--managed", "--profile",
                            "timestamped")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.under_the_home(), before)
        self.assertFalse(os.path.lexists(self.store),
                         "a store root made would refuse the operator's "
                         "hook its drawer")
        self.assertEqual(len(self.ours_in(self.managed_file)), 4)
        self.assertIn("coverage marker", done.stdout)
        self.assertNotIn("two homes", done.stdout)

    def test_as_another_account_the_uninstall_touches_nothing_either(self):
        self.install()
        self.as_root("install-hook", "--managed")
        before = self.under_the_home()

        done = self.as_root("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.managed_file.exists())
        self.assertEqual(self.under_the_home(), before)
        self.assertIn(f"still wired in {self.operator_file}", done.stdout)

    def shared_folder(self, owner):
        """A folder the account `owner` owns and every account may write
        into, made through sudo: where the store is not made yet."""
        shared = self.work / "shared"
        for command in (["mkdir", str(shared)], ["chmod", "0777", str(shared)],
                        ["chown", str(owner), str(shared)]):
            done = subprocess.run(["sudo", "-n", *command],
                                  capture_output=True, encoding="utf-8",
                                  timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
        return shared

    def test_a_store_not_made_yet_in_a_folder_root_owns_is_marked(self):
        # #465: the store this account makes there is its own, and a
        # folder root owns holds nothing another account planted.
        shared = self.shared_folder(0)
        env = {**self.env, "LOXODONTA_HOME": str(shared / "store")}

        done = self.install("--managed", env=env)

        self.assertTrue((shared / "store" / "coverage.json").is_file(),
                        done.stdout)
        self.assertNotIn("another account", done.stdout)

    def test_a_store_not_made_yet_in_another_accounts_folder_is_said_so(self):
        # #465: the store-only branch, which named a store that was not
        # there as another account's.
        shared = self.shared_folder(65534)
        env = {**self.env, "LOXODONTA_HOME": str(shared / "store")}

        done = self.install("--managed", env=env)

        self.assertFalse(os.path.lexists(shared / "store"))
        said = " ".join(done.stdout.split())
        self.assertIn(f"the store at {shared / 'store'} is not made yet", said)
        self.assertIn(f"{shared} belongs to another account", said)
        self.assertIn("no coverage marker was written", said)


class SupervisorReadsBothHomesTest(ManagedBase):
    """Ruling 7: whatever reads what is wired reads the operator's file
    and the recorder's managed file, by the same rule."""

    def setUp(self):
        super().setUp()
        # The witness layout beside the operator's settings file.
        self.witness = self.home / ".claude" / "projects"
        self.witness.mkdir()
        self.root = self.work / "repos"
        self.root.mkdir()
        prime_memory(self.root, matcher="*", failures="*")

    def scan(self):
        return run_scan(self.root, "--witness", str(self.witness),
                        env=self.env)

    def test_a_silent_session_under_a_managed_install_still_alarms(self):
        # The operator's file wires nothing once the hook has moved. The
        # matchers in the managed file are what say a receipt is owed.
        self.install()
        self.install("--managed")
        write_transcript(self.witness, self.root / "beta", "sess-ghost",
                         event_times=[ago(120), ago(110), ago(100)])

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        (ghost,) = report["completeness"]["sessions"]
        self.assertEqual(ghost["state"], "ALARM-SILENT")
        self.assertEqual(ghost["receipts"], 0)

    def test_the_session_end_command_is_read_from_the_managed_file(self):
        self.install("--managed", "--profile", "custom", "--publish-head",
                     REMOTE)

        report = json.loads(self.scan().stdout)

        self.assertTrue(report["published"]["wired"])
        self.assertIn("--publish", report["published"]["note"])
        self.assertNotEqual(report["recorder"]["state"], "unwired")
        # The copy the managed command names (ADR-0042).
        self.assertEqual(Path(report["recorder"]["path"]), self.copy)

    def test_the_recorder_is_read_from_either_command_shape(self):
        # ADR-0042 ruling 4 through the supervisor's own reading (the
        # owned_script twin): a command with -I after the interpreter
        # names the recorder as one without it does, in either home,
        # and never reads "-I" as the script and the recorder unwired.
        python = Path(sys.executable).as_posix()
        for shape in (f'"{python}" -I "{LOXODONTA.as_posix()}" hook',
                      f'"{python}" "{LOXODONTA.as_posix()}" hook'):
            for settings in (self.operator_file, self.managed_file):
                with self.subTest(shape=shape, file=settings.name):
                    settings.parent.mkdir(parents=True, exist_ok=True)
                    settings.write_text(json.dumps({"hooks": {
                        "PostToolUse": [{"matcher": "*", "hooks": [
                            {"type": "command", "command": shape}]}],
                        "SessionEnd": [{"hooks": [
                            {"type": "command", "command": shape}]}],
                    }}), encoding="utf-8")

                    report = json.loads(self.scan().stdout)

                    self.assertNotEqual(report["recorder"]["state"],
                                        "unwired", report["recorder"])
                    self.assertEqual(Path(report["recorder"]["path"]),
                                     LOXODONTA)
                    settings.unlink()

    def test_the_copy_a_managed_install_wires_reads_as_versioned(self):
        # The copy sits outside any checkout and its command carries -I:
        # the notice reads it by its version line and its hash (#570).
        self.install("--managed")
        (post,) = self.commands(self.read(self.managed_file), "PostToolUse")
        self.assertEqual(words(post)[1], "-I", post)

        recorder = json.loads(self.scan().stdout)["recorder"]

        self.assertEqual(recorder["state"], "versioned", recorder)
        self.assertEqual(Path(recorder["path"]), self.copy)
        self.assertEqual(recorder["version"], version_of(LOXODONTA))
        self.assertEqual(recorder["sha256"],
                         hashlib.sha256(LOXODONTA.read_bytes()).hexdigest())

    def an_entry_of_the_writers_own(self):
        """A recorder entry added to the operator's file after a managed
        install, which the writer can do and the installer did not:
        another recorder, another remote."""
        elsewhere = "python /elsewhere/loxodonta.py hook"
        self.operator_file.write_text(json.dumps({"hooks": {
            "PostToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": elsewhere}]}],
            "SessionEnd": [{"hooks": [
                {"type": "command", "command": elsewhere
                 + ' --publish-chain "http://127.0.0.1:9/elsewhere"'}]}],
        }}), encoding="utf-8")

    def test_the_managed_recorder_is_the_one_the_notice_names(self):
        # ADR-0040: the managed file is the home the writer cannot edit,
        # so an entry in the operator's file never shadows it.
        self.install("--managed")
        self.an_entry_of_the_writers_own()

        report = json.loads(self.scan().stdout)

        # The copy the managed command names (ADR-0042).
        self.assertEqual(Path(report["recorder"]["path"]), self.copy)

    def test_the_managed_remote_is_the_one_a_sent_chain_is_held_to(self):
        self.install("--managed", "--profile", "custom", "--publish-chain",
                     REMOTE)
        self.an_entry_of_the_writers_own()
        log = make_chain(self.root / "alpha" / "receipts", "sess-sent")
        Path(str(log) + ".published.jsonl").write_text(json.dumps({
            "kind": "chain", "first": 0, "last": 2, "head": chain_head(log),
            "ts": ago(60), "event": "session-end",
            "remote_id": hashlib.sha256(REMOTE.encode()).hexdigest()[:16],
        }) + "\n", encoding="utf-8")

        report = json.loads(self.scan().stdout)

        self.assertTrue(report["published"]["wired"])
        self.assertIsNone(report["published"]["note"],
                          "the batch the managed remote took counts")

    def test_a_managed_uninstall_is_dated_when_it_happened(self):
        # The supervisor dates a change of coverage by the mtime of what
        # was wired (ADR-0016). The managed file is gone after its
        # uninstall, and the operator's file was last written when the
        # hook moved out of it: dated by that, every session between the
        # move and the uninstall would be judged as owed nothing.
        self.install()
        self.install("--managed")
        long_ago = time.time() - 5 * 86400
        os.utime(self.operator_file, (long_ago, long_ago))
        self.scan()
        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

        report = json.loads(self.scan().stdout)

        last = report["completeness"]["calibration"]["epochs"][-1]
        self.assertEqual(last["matchers"], [])
        self.assertGreater(last["since"], ago(3600))

    def wire(self, settings, *matchers, written=None):
        """A hooks file at `settings` wiring the recorder on `matchers`,
        dated `written` when given."""
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text(json.dumps({"hooks": {"PostToolUse": [
            {"matcher": matcher, "hooks": [
                {"type": "command", "command": "python loxodonta.py hook"}]}
            for matcher in matchers]}}), encoding="utf-8")
        if written is not None:
            os.utime(settings, (written, written))

    def test_a_session_judged_clean_stays_clean_after_a_later_widening(self):
        # #548 review: the last epoch is not the last look, so a widening
        # dated by the operator's older write re-judged a session a look
        # had already found clean (ADR-0016 ruling 2).
        prime_memory(self.root, matcher="Bash")
        self.wire(self.operator_file, "Bash", written=time.time() - 5 * 86400)
        write_transcript(self.witness, self.root / "beta", "sess-read",
                         event_times=[ago(3 * 86400), ago(3 * 86400 - 60)],
                         tool="Read")
        (first,) = json.loads(self.scan().stdout)["completeness"]["sessions"]
        self.assertEqual(first["state"], "ENDED-CLEAN")

        self.wire(self.managed_file, "*")
        result = self.scan()

        (second,) = json.loads(result.stdout)["completeness"]["sessions"]
        self.assertEqual(second["state"], "ENDED-CLEAN", result.stdout)

    def operators_change_then_another_tools_file(self, *matchers):
        """The operator's file wiring `matchers`, written two hours ago,
        and another tool's file written in the managed folder now, with
        no managed file of the recorder's: the folder's date then
        stands in for that file's and is later than the change."""
        self.wire(self.operator_file, *matchers, written=time.time() - 7200)
        self.managed_file.parent.mkdir(parents=True)
        (self.managed_file.parent / "another-tool.json").write_text(
            '{"env": {}}', encoding="utf-8")
        report = json.loads(self.scan().stdout)
        last = report["completeness"]["calibration"]["epochs"][-1]
        self.assertEqual(last["matchers"], list(matchers))
        return last["since"]

    def test_a_widening_is_dated_by_the_files_never_the_folder(self):
        # #465: the newly wired tools are owed from the operator's
        # write, not from whenever another tool touched the folder.
        prime_memory(self.root, matcher="Bash")

        since = self.operators_change_then_another_tools_file("Bash", "Edit")

        self.assertLess(since, ago(3600))

    def test_a_narrowing_is_still_dated_by_the_folder(self):
        # A deleted managed file can only take matchers away, so the
        # folder's date still stands in for one (#465).
        since = self.operators_change_then_another_tools_file("Bash")

        self.assertGreater(since, ago(3600))

    def test_a_hooks_file_that_is_no_settings_is_named(self):
        # #465: it reads as no hook wired, and that was all the scan
        # said, in either home.
        for content, why in (("{not json", "it is not JSON"),
                             ("[" * 100000 + "]" * 100000,
                              "it nests too deep to read"),
                             ('["hooks"]', "it is not a JSON object")):
            for settings in (self.operator_file, self.managed_file):
                with self.subTest(file=settings.name, why=why):
                    settings.parent.mkdir(parents=True, exist_ok=True)
                    settings.write_text(content, encoding="utf-8")

                    result = self.scan()

                    self.assertEqual(result.returncode, 0,
                                     result.stdout + result.stderr)
                    note = json.loads(result.stdout)["settings_note"]
                    self.assertIn(f"{settings.as_posix()} cannot be read as "
                                  f"harness settings: {why}", note)
                    settings.unlink()

    def test_a_folder_where_the_managed_file_belongs_is_named(self):
        # #405's rule for the operator's file, held for the second home.
        self.managed_file.mkdir(parents=True)

        report = json.loads(self.scan().stdout)

        self.assertIn(self.managed_file.as_posix(), report["settings_note"])
        self.assertIn("it is a folder", report["settings_note"])

    def test_no_other_file_in_the_managed_folder_is_read(self):
        # managed-settings.json is an administrator's, and a sibling in
        # the drop-in folder is another tool's.
        self.install("--managed", "--profile", "custom", "--publish-head",
                     REMOTE)
        ours = self.managed_file.read_bytes()
        self.managed_file.unlink()
        (self.managed / "managed-settings.json").write_bytes(ours)
        (self.managed_file.parent / "another-tool.json").write_bytes(ours)

        report = json.loads(self.scan().stdout)

        self.assertFalse(report["published"]["wired"])
        self.assertEqual(report["recorder"]["state"], "unwired")


# The pin as the installer writes it for REMOTE: the four switches and
# nothing else (ADR-0041 ruling 7).
PIN_ENV = {"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
           "OTEL_LOGS_EXPORTER": "otlp",
           "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
           "OTEL_EXPORTER_OTLP_ENDPOINT": REMOTE}
# What a hook run reads for the harness's telemetry: scrubbed from the
# environment a test hands it, so the shell this runs in says nothing.
TELEMETRY_VARIABLES = ("CLAUDE_CODE_ENABLE_TELEMETRY", "OTEL_LOGS_EXPORTER",
                       "OTEL_EXPORTER_OTLP_PROTOCOL",
                       "OTEL_EXPORTER_OTLP_ENDPOINT",
                       "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")


class TelemetryPinTest(ManagedBase):
    """ADR-0041 ruling 7: at `full`, a managed install also pins the
    harness's events to the receiver, in a second managed file of the
    recorder's own beside the hooks file, which keeps holding hooks
    alone. Written, removed and refused as the hooks file is."""

    def full(self, *args, env=None):
        return self.install("--managed", "--profile", "full", "--remote",
                            REMOTE, *args, env=env)

    def plant(self, path, content):
        """A file in the managed folder: `content` as given when it is
        text, else as the installer writes JSON (two spaces, a final
        newline), so a pin put back as it stood is byte for byte."""
        path.parent.mkdir(parents=True, exist_ok=True)
        text = (content if isinstance(content, str)
                else json.dumps(content, indent=2) + "\n")
        path.write_bytes(text.encode("utf-8"))

    def test_full_writes_the_pin_with_the_four_keys_and_nothing_else(self):
        done = self.full()

        self.assertEqual(self.read(self.pin_file), {"env": PIN_ENV})
        self.assertEqual(list(self.read(self.managed_file)), ["hooks"],
                         "the hooks file keeps holding hooks only")
        self.assertEqual(sorted(os.listdir(self.managed_file.parent)),
                         ["loxodonta-telemetry.json", "loxodonta.json"])
        self.assertIn(str(self.pin_file), done.stdout)
        text = self.pin_file.read_text(encoding="utf-8")
        for never in ("OTEL_LOG_USER_PROMPTS", "OTEL_LOG_TOOL_DETAILS",
                      "METRICS"):
            self.assertNotIn(never, text)

    def test_it_says_what_leaves_through_the_events(self):
        done = self.full()

        said = " ".join(done.stdout.split()).lower()
        self.assertLess(said.index("events will leave"),
                        said.index(str(self.pin_file).lower()),
                        "said before the pin is written")
        for words in ("tool call", "model", "session id", "never a command",
                      "prompt", "identity"):
            self.assertIn(words, said)

    @unittest.skipIf(sys.platform == "win32", "permission bits are POSIX")
    def test_every_account_can_read_the_pin(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)

        self.full()

        self.assertEqual(os.stat(self.pin_file).st_mode & 0o777, 0o644)

    def test_at_another_profile_no_pin_is_written(self):
        for flags in ((), ("--profile", "timestamped"),
                      ("--profile", "custom", "--publish-chain", REMOTE)):
            with self.subTest(flags=flags):
                done = self.install("--managed", *flags)

                self.assertFalse(self.pin_file.exists())
                self.assertNotIn(str(self.pin_file), done.stdout)
                self.assertEqual(os.listdir(self.managed_file.parent),
                                 ["loxodonta.json"])

    def test_a_run_at_another_profile_removes_the_installers_pin(self):
        self.full()

        done = self.install("--managed", "--profile", "timestamped")

        self.assertFalse(self.pin_file.exists())
        self.assertIn(f"removed {self.pin_file}", done.stdout)
        self.assertTrue(self.managed_file.exists())
        self.assertEqual(os.listdir(self.managed_file.parent),
                         ["loxodonta.json"])

    def test_a_full_rerun_that_changes_nothing_says_so(self):
        self.full()
        before = self.everything()

        done = self.full()

        self.assertEqual(self.everything(), before)
        self.assertIn("already installed", done.stdout)
        self.assertIn("nothing changed", done.stdout)

    def test_a_pin_gone_missing_is_written_again(self):
        self.full()
        self.pin_file.unlink()

        done = self.full()

        self.assertEqual(self.read(self.pin_file), {"env": PIN_ENV})
        self.assertNotIn("nothing changed", done.stdout)
        self.assertIn(str(self.pin_file), done.stdout)

    def test_the_url_is_written_as_given_and_a_new_one_rewrites_the_pin(self):
        other = "http://127.0.0.1:9/other/"
        self.full()

        self.install("--managed", "--profile", "full", "--remote", other)

        self.assertEqual(self.read(self.pin_file),
                         {"env": {**PIN_ENV,
                                  "OTEL_EXPORTER_OTLP_ENDPOINT": other}})

    def test_uninstall_removes_the_pin_with_the_hooks_file(self):
        self.full()
        self.plant(self.managed / "managed-settings.json",
                   {"cleanupPeriodDays": 90})
        self.plant(self.managed_file.parent / "another-tool.json",
                   {"hooks": {}})
        expected = self.everything()
        for ours in (self.managed_file, self.pin_file, self.copy,
                     self.copy_supervisor, self.program):
            del expected[str(ours.relative_to(self.work))]

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(str(self.pin_file), done.stdout)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertEqual(self.everything(), expected,
                         "both files and the copy are gone; nothing else "
                         "moved")

    def test_uninstall_with_only_the_pin_standing_removes_it(self):
        self.full()
        self.managed_file.unlink()

        done = run(LOXODONTA, "uninstall-hook", "--managed", env=self.env)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.pin_file.exists())
        self.assertIn(f"removed {self.pin_file}", done.stdout)

    def test_a_refused_pin_write_writes_nothing_anywhere(self):
        # A folder where the pin belongs: no right would move it, the
        # install is refused before anything is said or written, and
        # the hooks file, written after the pin, is not written at all.
        (self.pin_file / "kept").mkdir(parents=True)
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                             "full", "--remote", REMOTE, env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.pin_file), done.stderr)
        self.assertIn("a folder", done.stderr)
        self.assertNotIn("sudo", done.stderr)
        self.assertNotIn("will leave", done.stdout,
                         "a refused install says nothing about what leaves")
        self.assertEqual(self.everything(), before)

    def refuse_the_hooks_write(self):
        """Make the hooks file's write fail after the pin's has gone
        through, and return what undoes it: on Windows a read-only file
        at its name, which refuses a replace; on POSIX a link from its
        name into a folder nobody may write. A folder at its name is
        refused before anything is written (#487), so it cannot."""
        self.managed_file.parent.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            self.plant(self.managed_file, {"hooks": {}})
            os.chmod(self.managed_file, stat.S_IREAD)

            def undo():
                os.chmod(self.managed_file, stat.S_IWRITE)
                self.managed_file.unlink()
            return undo
        if os.geteuid() == 0:
            self.skipTest("root writes in a folder whatever its bits")
        closed = self.work / "closed"
        closed.mkdir(exist_ok=True)
        os.chmod(closed, 0o555)
        self.addCleanup(os.chmod, closed, 0o755)
        self.managed_file.symlink_to(closed / "loxodonta.json")
        return self.managed_file.unlink

    def test_a_refused_hooks_write_puts_the_pin_back_as_it_was(self):
        # The pin is written first; a refused hooks write afterwards
        # puts back the very bytes that stood there, a file that was
        # not JSON included, so a refused install has written nothing.
        old = {"env": {**PIN_ENV,
                       "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/old"}}
        for standing in (None, old, "{not json"):
            with self.subTest(standing=standing):
                if standing is not None:
                    self.plant(self.pin_file, standing)
                undo = self.refuse_the_hooks_write()
                before = self.everything()

                done = run(LOXODONTA, "install-hook", "--managed",
                                     "--profile", "full", "--remote", REMOTE, env=self.env)

                self.assertEqual(done.returncode, 73,
                                 done.stdout + done.stderr)
                self.assertIn("pinned the harness's events", done.stdout,
                              "the pin was written before the refusal")
                self.assertIn(str(self.managed_file), done.stderr)
                self.assertIn("Nothing was written", done.stderr)
                self.assertEqual(self.everything(), before,
                                 "the pin as it stood, byte for byte, or "
                                 "no pin")
                undo()
                if standing is not None:
                    self.pin_file.unlink()

    @unittest.skipIf(sys.platform == "win32", "permission bits are POSIX")
    def test_a_pin_put_back_keeps_the_mode_it_had(self):
        # #487: the bytes go back under their own bits, not the 0o644 a
        # pin of the installer's is written with.
        self.plant(self.pin_file, {"env": {
            **PIN_ENV, "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/old"}})
        os.chmod(self.pin_file, 0o600)
        self.refuse_the_hooks_write()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                   "full", "--remote", REMOTE, env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertEqual(os.stat(self.pin_file).st_mode & 0o777, 0o600)

    def test_a_folder_at_the_hooks_files_name_is_refused_before_a_word(self):
        # #487: as a folder at the pin's name is, before the notices and
        # before the pin is written.
        (self.managed_file / "kept").mkdir(parents=True)
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                   "full", "--remote", REMOTE, env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertEqual(done.stdout, "", "nothing said before the refusal")
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("a folder", done.stderr)
        self.assertIn("Nothing was written", done.stderr)
        self.assertNotIn("sudo", done.stderr)
        self.assertEqual(self.everything(), before)

    def test_what_is_not_json_at_the_pins_name_is_nobodys_pin(self):
        # Left alone and named when no pin is wanted; written over at
        # `full`, as the hooks file is over one it cannot read.
        self.plant(self.pin_file, "{not json")

        done = self.install("--managed", "--profile", "timestamped")

        self.assertIn(str(self.pin_file), done.stderr)
        self.assertEqual(self.pin_file.read_text(encoding="utf-8"),
                         "{not json")

        done = self.full()

        self.assertEqual(self.read(self.pin_file), {"env": PIN_ENV})
        self.assertNotIn(str(self.pin_file), done.stderr)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_a_refused_pin_delete_is_named_posix(self):
        self.full()
        os.chmod(self.managed_file.parent, 0o555)
        self.addCleanup(os.chmod, self.managed_file.parent, 0o755)
        before = self.everything()
        for verb, flags in (("install-hook", ("--managed", "--profile",
                                              "timestamped")),
                            ("uninstall-hook", ("--managed",))):
            with self.subTest(verb=verb):
                done = run(LOXODONTA, verb, *flags, env=self.env)

                self.assertEqual(done.returncode, 73,
                                 done.stdout + done.stderr)
                self.assertNotIn("Traceback", done.stderr)
                self.assertIn(str(self.pin_file), done.stderr)
                self.assertIn("sudo", done.stderr)
                self.assertEqual(self.everything(), before)

    @unittest.skipUnless(sys.platform == "win32",
                         "a read-only file refuses a delete on Windows")
    def test_a_read_only_pin_is_named_as_that(self):
        self.full()
        os.chmod(self.pin_file, stat.S_IREAD)
        self.addCleanup(os.chmod, self.pin_file, stat.S_IWRITE)
        before = self.everything()
        for verb, flags in (("install-hook", ("--managed", "--profile",
                                              "timestamped")),
                            ("uninstall-hook", ("--managed",))):
            with self.subTest(verb=verb):
                done = run(LOXODONTA, verb, *flags, env=self.env)

                self.assertEqual(done.returncode, 73,
                                 done.stdout + done.stderr)
                self.assertIn(str(self.pin_file), done.stderr)
                self.assertIn("read-only", done.stderr)
                self.assertNotIn("sudo", done.stderr)
                self.assertEqual(self.everything(), before)

    def test_a_file_at_the_pins_name_that_is_not_the_installers(self):
        # Decided by content, as the hooks file's entries are: a file
        # there holding more than the installer's keys is somebody
        # else's. A `full` install, which wants the name, is refused
        # before anything is said or written; every other verb leaves
        # it alone and names it.
        foreign = ('{"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": '
                   '"http://127.0.0.1:9/theirs", "THEIR_OWN": "1"}}')
        self.plant(self.pin_file, foreign)
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                             "full", "--remote", REMOTE, env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.pin_file), done.stderr)
        self.assertIn("move it away by hand", done.stderr)
        self.assertNotIn("sudo", done.stderr)
        self.assertNotIn("will leave", done.stdout,
                         "a refused install says nothing about what leaves")
        self.assertEqual(self.everything(), before)

        for verb, flags in (
                ("install-hook", ("--managed", "--profile", "timestamped")),
                ("uninstall-hook", ("--managed",))):
            with self.subTest(verb=verb):
                done = run(LOXODONTA, verb, *flags, env=self.env)

                self.assertEqual(done.returncode, 0,
                                 done.stdout + done.stderr)
                self.assertIn(str(self.pin_file), done.stderr)
                self.assertEqual(self.pin_file.read_text(encoding="utf-8"),
                                 foreign)
        self.assertFalse(self.managed_file.exists())

    def test_a_foreign_pin_with_a_byte_order_mark_is_refused_as_foreign(self):
        # #487: an editor that saves with a byte-order mark leaves JSON
        # all the same, and somebody else's JSON is refused, not
        # written over as a file that is not JSON would be.
        foreign = ('﻿{"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": '
                   '"http://127.0.0.1:9/theirs", "THEIR_OWN": "1"}}')
        self.plant(self.pin_file, foreign)
        before = self.everything()

        done = run(LOXODONTA, "install-hook", "--managed", "--profile",
                   "full", "--remote", REMOTE, env=self.env)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.pin_file), done.stderr)
        self.assertIn("move it away by hand", done.stderr)
        self.assertEqual(self.everything(), before)

    def assert_rewritten_without_a_bom(self, own):
        # #487: whether the harness reads a file behind a byte-order
        # mark is not known, so the installer's own content behind one
        # is no install, and a re-run writes it clean.
        self.full()
        clean = own.read_bytes()
        own.write_bytes(b"\xef\xbb\xbf" + clean)

        done = self.full()

        self.assertFalse(own.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertEqual(self.read(own), json.loads(clean))
        self.assertNotIn("nothing changed", done.stdout)

    def test_a_bom_led_copy_of_the_installers_hooks_file_is_rewritten(self):
        self.assert_rewritten_without_a_bom(self.managed_file)

    def test_a_bom_led_copy_of_the_installers_pin_is_rewritten(self):
        self.assert_rewritten_without_a_bom(self.pin_file)

    def test_another_managed_source_of_the_events_is_named_not_quoted(self):
        policy = self.managed / "managed-settings.json"
        self.plant(policy, {"cleanupPeriodDays": 30, "env": {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.test/secret"}})
        theirs = self.managed_file.parent / "zz-org.json"
        self.plant(theirs, {"env": {"CLAUDE_CODE_ENABLE_TELEMETRY": "0",
                                    "THEIR_OWN": "x"}})
        quiet = self.managed_file.parent / "aa-quiet.json"
        self.plant(quiet, {"env": {"UNRELATED": "1"}, "hooks": {}})

        done = self.full()

        warnings = [line for line in done.stderr.splitlines()
                    if line.startswith("warning:") and " sets " in line]
        self.assertEqual(len(warnings), 2, done.stderr)
        self.assertIn(str(policy), warnings[0])
        self.assertIn("OTEL_EXPORTER_OTLP_ENDPOINT", warnings[0])
        self.assertIn(str(theirs), warnings[1])
        self.assertIn("CLAUDE_CODE_ENABLE_TELEMETRY", warnings[1])
        self.assertNotIn("secret", done.stderr)
        self.assertNotIn(str(quiet), done.stderr)
        self.assertEqual(self.read(self.pin_file), {"env": PIN_ENV},
                         "the pin is written all the same")
        self.assertEqual(self.read(policy)["cleanupPeriodDays"], 30,
                         "read, never written")

        # The installer's own two files are no other source.
        again = self.full()
        named = [line for line in again.stderr.splitlines() if " sets " in line]
        self.assertEqual(len(named), 2, again.stderr)
        for ours in (self.pin_file, self.managed_file):
            self.assertFalse(any(str(ours) in line for line in named), named)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a file's read bit is POSIX")
    def test_a_managed_file_it_cannot_read_is_named_as_unread(self):
        # A look that saw nothing is told apart from one that could
        # not look: the file is named, its content never.
        closed = self.managed_file.parent / "zz-closed.json"
        self.plant(closed, {"env": {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.test/secret"}})
        os.chmod(closed, 0)
        self.addCleanup(os.chmod, closed, 0o644)

        done = self.full()

        self.assertIn(f"could not read {closed}", done.stderr)
        self.assertNotIn("secret", done.stderr)
        self.assertEqual(self.read(self.pin_file), {"env": PIN_ENV})

    def test_without_a_pin_wanted_no_other_file_is_read_for_one(self):
        self.plant(self.managed / "managed-settings.json", {"env": {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.test/secret"}})

        done = self.install("--managed", "--profile", "timestamped")

        self.assertNotIn("warning: " + str(self.managed), done.stderr)

    def test_the_help_names_the_pin(self):
        done = run(LOXODONTA, "install-hook", "--help", env=self.env)

        self.assertIn("loxodonta-telemetry.json", " ".join(done.stdout.split()))


class SecondRecordNoteWitnessTest(ManagedBase):
    """The hook's note is a bookkeeping entry (ADR-0041 ruling 8): the
    witness's receipt count and the digest's rows ignore it, as they
    ignore genesis and the transcript commitment."""

    SESSION = "sess-cut-1111"

    def setUp(self):
        super().setUp()
        self.witness = self.home / ".claude" / "projects"
        self.witness.mkdir()
        self.project = self.work / "repos" / "beta"
        self.project.mkdir(parents=True)
        # A store-mode scan keeps its memory beside the store's receipts
        # folder: a calibration older than the fixtures, as prime_memory
        # gives a --root scan.
        self.store.mkdir()
        (self.store / "baseline.json").write_text(json.dumps({
            "chains": {}, "calibration": [{
                "since": ago(864000), "matchers": ["*"], "failures": ["*"]}],
        }), encoding="utf-8")
        for name in TELEMETRY_VARIABLES:
            self.env.pop(name, None)

    def hook(self, command):
        payload = json.dumps({"session_id": self.SESSION,
                              "hook_event_name": "PostToolUse",
                              "tool_name": "Bash",
                              "tool_input": {"command": command},
                              "tool_response": {}})
        done = run(LOXODONTA, "hook", stdin=payload,
                   env={**self.env, "CLAUDE_PROJECT_DIR": str(self.project)})
        self.assertEqual(done.returncode, 0, done.stderr)

    def chain(self):
        (drawer,) = [p for p in (self.store / "receipts").iterdir()
                     if p.is_dir()]
        return [json.loads(line) for line in
                (drawer / f"receipts-{self.SESSION}.jsonl").read_text(
                    encoding="utf-8").splitlines()]

    def test_the_witness_and_the_digest_ignore_the_note(self):
        self.install("--managed", "--profile", "full", "--remote", REMOTE)
        self.hook("step 0")
        self.hook("step 1")
        actions = [e["action"] for e in self.chain()]
        self.assertEqual(actions, ["genesis", "Bash: step 0",
                                   "second-record-cut: reason=telemetry-off",
                                   "Bash: step 1"])
        write_transcript(self.witness, self.project, self.SESSION,
                         event_times=[ago(6000), ago(5990)])

        result = run(SUPERVISOR, "scan", "--json", "--witness",
                     str(self.witness), env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (judged,) = json.loads(result.stdout)["completeness"]["sessions"]
        self.assertEqual(judged["receipts"], 2)
        self.assertEqual(judged["state"], "ENDED-CLEAN")

        digest = run(SUPERVISOR, "digest", "--repo", str(self.project),
                     env={**self.env, "CLAUDE_PROJECT_DIR": str(self.project)})

        self.assertEqual(digest.returncode, 0, digest.stdout + digest.stderr)
        self.assertIn("step 1", digest.stdout)
        self.assertNotIn("second-record-cut", digest.stdout)


if __name__ == "__main__":
    unittest.main()
