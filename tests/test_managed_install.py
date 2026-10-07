"""A managed install (ADR-0040, #259): `install-hook --managed` wires the
hook in a file of the recorder's own, in the harness's managed settings
folder, and the hook then has one home.

Every test here points the installer and the supervisor at a folder of
its own through LOXODONTA_MANAGED_DIR, the suite's seam: no test reads
or writes the machine's managed settings folder, and none needs rights
it does not have. The cases that need a real session and a real managed
file (one receipt and not two, a run that sets `disableAllHooks`,
`--bare`) are the author's to run and are not here.
"""

import hashlib
import json
import os
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

from test_supervisor import (ago, chain_head, isolated_env,  # noqa: E402
                             make_chain, prime_memory, run_scan,
                             write_transcript)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
OURS = ("loxodonta.py", "supervisor.py")
REMOTE = "http://127.0.0.1:9/hook"


class ManagedBase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name).resolve()
        self.home = self.work / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = self.work / "store"
        # Stands in for the harness's managed settings folder.
        self.managed = self.work / "managed"
        self.env = isolated_env(self.home, LOXODONTA_HOME=str(self.store),
                                LOXODONTA_MANAGED_DIR=str(self.managed),
                                PYTHONIOENCODING="utf-8")
        self.operator_file = self.home / ".claude" / "settings.json"
        self.managed_file = (self.managed / "managed-settings.d"
                             / "loxodonta.json")
        # The telemetry pin, beside the hooks file (ADR-0041 ruling 7).
        self.pin_file = (self.managed / "managed-settings.d"
                         / "loxodonta-telemetry.json")

    def run_tool(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(LOXODONTA), *args], capture_output=True,
            encoding="utf-8", timeout=120,
            env=self.env if env is None else env)

    def install(self, *args, env=None):
        done = self.run_tool("install-hook", *args, env=env)
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

        done = self.run_tool("install-hook", "--managed", env=env)

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

        done = self.run_tool("install-hook", "--managed", "--profile",
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

                self.assertEqual(self.read(self.managed_file),
                                 {"hooks": plain["hooks"]})

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
                done = self.run_tool(verb, "--managed", "--codex")

                self.assertEqual(done.returncode, 64,
                                 done.stdout + done.stderr)
                self.assertIn("--codex", done.stderr)
                self.assertEqual(self.everything(), before)

    def test_a_plain_install_refuses_while_the_managed_file_holds_them(self):
        # Case 7.
        self.install("--managed")
        before = self.everything()

        done = self.run_tool("install-hook")

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("install-hook --managed", done.stderr)
        self.assertIn("uninstall-hook --managed", done.stderr)
        self.assertEqual(self.everything(), before)

    def test_a_plain_install_for_codex_is_another_harness_and_goes_ahead(self):
        self.install("--managed")

        done = self.run_tool("install-hook", "--codex")

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
                done = self.run_tool(verb, *flags, env=env)

                self.assertEqual(done.returncode, code,
                                 done.stdout + done.stderr)
                self.assertIn("LOXODONTA_MANAGED_DIR", done.stderr)
                self.assertIn(
                    os.path.join(env["LOXODONTA_MANAGED_DIR"],
                                 "managed-settings.d", "loxodonta.json"),
                    done.stderr)

    def test_codex_reads_no_managed_folder_and_says_nothing_of_one(self):
        for verb in ("install-hook", "uninstall-hook"):
            with self.subTest(verb=verb):
                done = self.run_tool(verb, "--codex")

                self.assertEqual(done.returncode, 0,
                                 done.stdout + done.stderr)
                self.assertNotIn("LOXODONTA_MANAGED_DIR", done.stderr)

    def test_the_help_says_whose_word_the_claim_is(self):
        # The harness documents it and ADR-0040 measured it: the help
        # names both, and never states the claim with no source.
        done = self.run_tool("install-hook", "--help")

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
        done = self.run_tool("install-hook", "--managed", env=blocked)
        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertIn(str(self.work / "blocker"), done.stderr)
        self.assertIn("is a file", done.stderr)
        self.assertNotIn("sudo", done.stderr)

        (self.managed_file / "kept").mkdir(parents=True)
        before = self.everything()
        done = self.run_tool("install-hook", "--managed")
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
                done = self.run_tool(verb, *flags)

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

                done = self.run_tool("install-hook")

                self.assertEqual(done.returncode, 0,
                                 done.stdout + done.stderr)
                self.assertEqual(len(self.ours_in(self.operator_file)), 4)
                self.assertEqual(
                    self.managed_file.read_text(encoding="utf-8"), content,
                    "a plain install never writes the managed file")
                self.run_tool("uninstall-hook")

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

        done = self.run_tool("install-hook", "--managed")

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
            done = self.run_tool("install-hook", "--managed")

        self.two_homes_then_one(done)
        again = self.install("--managed")
        self.assertEqual(self.ours_in(self.operator_file), [])
        self.assertIn(str(self.operator_file), again.stdout)

    def test_an_operators_file_it_cannot_read_stops_it_before_it_writes(self):
        self.operator_file.write_text("{not json", encoding="utf-8")
        before = self.everything()

        done = self.run_tool("install-hook", "--managed")

        self.assertEqual(done.returncode, 65, done.stdout + done.stderr)
        self.assertEqual(self.everything(), before)


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
        del expected[str(self.managed_file.relative_to(self.work))]

        done = self.run_tool("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertEqual(self.everything(), expected,
                         "the file is gone; the folder, its other files, "
                         "the operator's file and the marker are as they "
                         "lay")
        self.assertEqual(self.ours_in(self.operator_file), [],
                         "nothing is put back")

    def test_with_nothing_there_it_says_so(self):
        before = self.everything()

        done = self.run_tool("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("nothing installed", done.stdout)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertEqual(self.everything(), before)

    def test_a_delete_the_system_refuses_names_the_file(self):
        # No platform deletes a folder as a file, whoever asks.
        (self.managed_file / "kept").mkdir(parents=True)
        before = self.everything()

        done = self.run_tool("uninstall-hook", "--managed")

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

        done = self.run_tool("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.managed_file), done.stderr)
        self.assertIn("sudo", done.stderr)
        self.assertEqual(self.everything(), before)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "a folder's write bit is POSIX")
    def test_without_the_right_to_write_the_folder_it_says_whose_right(self):
        self.install("--managed")
        os.chmod(self.managed_file.parent, 0o555)
        self.addCleanup(os.chmod, self.managed_file.parent, 0o755)
        before = self.everything()

        done = self.run_tool("install-hook", "--managed", "--profile",
                             "timestamped")

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
        self.run_tool("uninstall-hook", "--managed")
        self.install()
        self.managed_file.write_bytes(managed)
        operators = self.operator_file.read_bytes()

        done = self.run_tool("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.managed_file.exists())
        self.assertEqual(self.operator_file.read_bytes(), operators)
        self.assertIn(f"still wired in {self.operator_file}", done.stdout)
        self.assertIn("`uninstall-hook`", done.stdout)

    def test_a_plain_uninstall_says_where_the_hook_is_and_what_removes_it(self):
        self.install("--managed")
        before = self.everything()

        done = self.run_tool("uninstall-hook")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertIn("uninstall-hook --managed", done.stdout)
        self.assertEqual(self.everything(), before)

    def test_a_plain_install_afterwards_is_marked_as_the_operators_file(self):
        # Ruling 6: an entry without `level` is the operator's own
        # settings file, as every entry written before this was.
        self.install("--managed")
        self.run_tool("uninstall-hook", "--managed")
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
              "LOXODONTA_MANAGED_DIR", "PYTHONIOENCODING")

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
        finished = self.run_tool("uninstall-hook")
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
        self.assertEqual(Path(report["recorder"]["path"]), LOXODONTA)

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

        self.assertEqual(Path(report["recorder"]["path"]), LOXODONTA)

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
        done = self.run_tool("uninstall-hook", "--managed")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

        report = json.loads(self.scan().stdout)

        last = report["completeness"]["calibration"]["epochs"][-1]
        self.assertEqual(last["matchers"], [])
        self.assertGreater(last["since"], ago(3600))

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
        path.write_text(content if isinstance(content, str)
                        else json.dumps(content, indent=2) + "\n",
                        encoding="utf-8", newline="\n")

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
        for ours in (self.managed_file, self.pin_file):
            del expected[str(ours.relative_to(self.work))]

        done = self.run_tool("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(str(self.pin_file), done.stdout)
        self.assertIn(str(self.managed_file), done.stdout)
        self.assertEqual(self.everything(), expected,
                         "both files are gone; nothing else moved")

    def test_uninstall_with_only_the_pin_standing_removes_it(self):
        self.full()
        self.managed_file.unlink()

        done = self.run_tool("uninstall-hook", "--managed")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.pin_file.exists())
        self.assertIn(f"removed {self.pin_file}", done.stdout)

    def test_a_refused_pin_write_writes_nothing_anywhere(self):
        # A folder where the pin belongs: no right would move it, and
        # the hooks file, written after the pin, is not written at all.
        (self.pin_file / "kept").mkdir(parents=True)
        before = self.everything()

        done = self.run_tool("install-hook", "--managed", "--profile",
                             "full", "--remote", REMOTE)

        self.assertEqual(done.returncode, 73, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn(str(self.pin_file), done.stderr)
        self.assertIn("a folder", done.stderr)
        self.assertNotIn("sudo", done.stderr)
        self.assertIn("events will leave", done.stdout,
                      "what leaves is said before the pin is written")
        self.assertEqual(self.everything(), before)

    def test_a_refused_hooks_write_puts_the_pin_back_as_it_was(self):
        # The pin is written first; a refused hooks write afterwards
        # puts it back, so a refused install has written nothing.
        old = {"env": {**PIN_ENV,
                       "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/old"}}
        for standing in (None, old):
            with self.subTest(standing=bool(standing)):
                if standing:
                    self.plant(self.pin_file, standing)
                (self.managed_file / "kept").mkdir(parents=True)
                before = self.everything()

                done = self.run_tool("install-hook", "--managed",
                                     "--profile", "full", "--remote", REMOTE)

                self.assertEqual(done.returncode, 73,
                                 done.stdout + done.stderr)
                self.assertIn(str(self.managed_file), done.stderr)
                self.assertEqual(self.everything(), before)
                self.assertEqual(self.pin_file.exists(), bool(standing))
                if standing:
                    self.assertEqual(self.read(self.pin_file), standing)
                (self.managed_file / "kept").rmdir()
                self.managed_file.rmdir()

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
                done = self.run_tool(verb, *flags)

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
                done = self.run_tool(verb, *flags)

                self.assertEqual(done.returncode, 73,
                                 done.stdout + done.stderr)
                self.assertIn(str(self.pin_file), done.stderr)
                self.assertIn("read-only", done.stderr)
                self.assertNotIn("sudo", done.stderr)
                self.assertEqual(self.everything(), before)

    def test_a_file_at_the_pins_name_that_is_not_the_installers_is_left(self):
        # Decided by content, as the hooks file's entries are: a file
        # there holding more than the installer's keys is somebody
        # else's, left alone and named, whichever verb meets it.
        foreign = ('{"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": '
                   '"http://127.0.0.1:9/theirs", "THEIR_OWN": "1"}}')
        self.plant(self.pin_file, foreign)
        for verb, flags in (
                ("install-hook", ("--managed", "--profile", "full",
                                  "--remote", REMOTE)),
                ("install-hook", ("--managed", "--profile", "timestamped")),
                ("uninstall-hook", ("--managed",))):
            with self.subTest(verb=verb, flags=flags):
                done = self.run_tool(verb, *flags)

                self.assertEqual(done.returncode, 0,
                                 done.stdout + done.stderr)
                self.assertIn(str(self.pin_file), done.stderr)
                self.assertEqual(self.pin_file.read_text(encoding="utf-8"),
                                 foreign)
        self.assertFalse(self.managed_file.exists())

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

    def test_without_a_pin_wanted_no_other_file_is_read_for_one(self):
        self.plant(self.managed / "managed-settings.json", {"env": {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.test/secret"}})

        done = self.install("--managed", "--profile", "timestamped")

        self.assertNotIn("warning: " + str(self.managed), done.stderr)

    def test_the_help_names_the_pin(self):
        done = self.run_tool("install-hook", "--help")

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
        done = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook"],
            input=payload.encode("utf-8"), capture_output=True, timeout=120,
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

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "supervisor.py"), "scan",
             "--json", "--witness", str(self.witness)],
            capture_output=True, encoding="utf-8", timeout=120,
            env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (judged,) = json.loads(result.stdout)["completeness"]["sessions"]
        self.assertEqual(judged["receipts"], 2)
        self.assertEqual(judged["state"], "ENDED-CLEAN")

        digest = subprocess.run(
            [sys.executable, str(REPO_ROOT / "supervisor.py"), "digest",
             "--repo", str(self.project)],
            capture_output=True, encoding="utf-8", timeout=120,
            env={**self.env, "CLAUDE_PROJECT_DIR": str(self.project)})

        self.assertEqual(digest.returncode, 0, digest.stdout + digest.stderr)
        self.assertIn("step 1", digest.stdout)
        self.assertNotIn("second-record-cut", digest.stdout)


if __name__ == "__main__":
    unittest.main()
