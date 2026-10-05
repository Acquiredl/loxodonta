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


if __name__ == "__main__":
    unittest.main()
