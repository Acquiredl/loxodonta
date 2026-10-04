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

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_managed_install`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_supervisor import (ago, isolated_env, prime_memory,  # noqa: E402
                             run_scan, write_transcript)

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

    def test_the_override_is_said_out_loud(self):
        # The seam moves where the installer writes, never where the
        # harness reads, so an install through it says which folder the
        # harness does read.
        done = self.install("--managed")

        self.assertIn("LOXODONTA_MANAGED_DIR", done.stderr)

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
        self.assertEqual(self.everything(), before)

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
