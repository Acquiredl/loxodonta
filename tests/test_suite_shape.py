"""The suite's own shape: tests about the suite, not about the recorder.

Every test module imports on its own (#118). `python -m unittest discover
-s tests` puts `tests/` on `sys.path`, so a module that says `from
test_recall import forge_chain` resolves under discovery and nowhere else.
CI runs discovery, so the suite stays green while `python -m unittest
tests.test_mcp` — the single-module red/green loop a contributor runs
while fixing one thing — dies on an import error before a test ever runs.
That test imports every `tests/test_*.py` the way that loop does, as
`tests.<name>` from the repo root, each in its own subprocess so a broken
module names itself instead of taking the parent interpreter with it.

The home guard is armed and says where a start came from (#242). The
guard itself lives in tests/home_guard.py, which says what it covers;
these tests hold it to refusing the six home-reading supervisor verbs and
the four home-writing verbs (#274) when any one home is the machine's,
and to naming the line that made the start.
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_suite_shape`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_supervisor import isolated_env

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECORDER = REPO_ROOT / "loxodonta.py"
# Written out here rather than read from the guard, so a home dropped
# from the guard's list fails these tests instead of passing with it.
EVERY_HOME = {"LOXODONTA_HOME", "HOME", "USERPROFILE", "CODEX_HOME"}


class EveryModuleRunsAlone(unittest.TestCase):

    def test_every_test_module_imports_from_the_repo_root(self):
        modules = sorted(p.stem for p in TESTS_DIR.glob("test_*.py"))
        # A glob that found nothing would pass this test by saying nothing.
        self.assertGreater(len(modules), 1, "no test modules found to import")
        for name in modules:
            with self.subTest(module=name):
                done = subprocess.run(
                    [sys.executable, "-c",
                     "import importlib; "
                     "importlib.import_module('tests.%s')" % name],
                    cwd=str(REPO_ROOT), capture_output=True, encoding="utf-8",
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"})
                self.assertEqual(
                    done.returncode, 0,
                    "tests/%s.py does not import on its own — a contributor "
                    "cannot run `python -m unittest tests.%s`:\n%s"
                    % (name, name, done.stderr))


def named_homes(refusal):
    """The names a refusal says were the machine's, as a set of whole
    names: "HOME" alone is not found inside "CODEX_HOME"."""
    listed = re.search(r"this machine's (.+?) \(#242", str(refusal))
    return set(listed.group(1).split(", ")) if listed else set()


class HomeGuardTest(unittest.TestCase):
    """`--help` is the verb's whole run in every probe here: it reads no
    home, so a probe that got past a disarmed guard would still read
    nothing of this machine."""

    command = [sys.executable, str(SUPERVISOR), "scan", "--help"]

    def test_a_start_with_the_inherited_home_is_refused_where_it_was_made(self):
        with self.assertRaises(AssertionError) as refused:
            subprocess.run(self.command, capture_output=True)

        said = str(refused.exception)
        self.assertIn("supervisor.py scan", said)
        # A project inherited from a harness is refused with the homes.
        inherited = ({"CLAUDE_PROJECT_DIR"}
                     if os.environ.get("CLAUDE_PROJECT_DIR") else set())
        self.assertEqual(named_homes(said), EVERY_HOME | inherited, said)
        # It names the line that started it, so the offender is found
        # without a search.
        where = re.search(r"tests/test_suite_shape\.py:(\d+) in (\w+)", said)
        self.assertIsNotNone(where, said)
        self.assertEqual(where.group(2), self._testMethodName)
        line = Path(__file__).read_text(
            encoding="utf-8").splitlines()[int(where.group(1)) - 1]
        self.assertIn("subprocess.run(self.command", line)

    def test_each_home_left_to_the_machine_is_refused_by_its_own_name(self):
        with tempfile.TemporaryDirectory() as home:
            isolated = {**isolated_env(Path(home).resolve()),
                        "PYTHONIOENCODING": "utf-8"}

            for name in sorted(EVERY_HOME):
                with self.subTest(home=name):
                    # The machine's own, or where it has none, a folder
                    # that is no temporary one: an unset store or Codex
                    # home is allowed beside the test's HOME (#274).
                    leaky = {**isolated,
                             name: os.environ.get(name) or str(REPO_ROOT)}
                    with self.assertRaises(AssertionError) as refused:
                        subprocess.run(self.command, capture_output=True,
                                       env=leaky)
                    self.assertEqual(named_homes(refused.exception), {name})

            # All four of the test's own, and the same start goes ahead.
            done = subprocess.run(self.command, capture_output=True,
                                  encoding="utf-8", env=isolated)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage", done.stdout)


class WriterHomeGuardTest(unittest.TestCase):
    """The verbs that write into a home, the recorder's three and the
    supervisor's `adopt`, under the same guard (#274). `--help` again, so
    a probe past a disarmed guard writes nothing."""

    def command(self, verb):
        return [sys.executable, str(RECORDER), verb, "--help"]

    def test_each_home_writing_verb_is_refused_with_the_inherited_home(self):
        for verb in ("hook", "install-hook", "uninstall-hook"):
            with self.subTest(verb=verb):
                with self.assertRaises(AssertionError) as refused:
                    subprocess.run(self.command(verb), capture_output=True)
                said = str(refused.exception)
                self.assertIn("loxodonta.py %s started" % verb, said)
                # Only a hook reads the project, so only a hook is
                # refused one inherited from a harness.
                inherited = ({"CLAUDE_PROJECT_DIR"}
                             if verb == "hook"
                             and os.environ.get("CLAUDE_PROJECT_DIR")
                             else set())
                self.assertEqual(named_homes(said), EVERY_HOME | inherited,
                                 said)
                self.assertIn("tests/test_suite_shape.py:", said)

    def test_adopt_is_refused_with_the_inherited_home(self):
        with self.assertRaises(AssertionError) as refused:
            subprocess.run([sys.executable, str(SUPERVISOR), "adopt",
                            "--help"], capture_output=True)
        self.assertIn("supervisor.py adopt started", str(refused.exception))

    def test_an_unset_store_or_codex_home_falls_back_inside_the_test(self):
        # The tools fall back to ~/.loxodonta and ~/.codex, so with the
        # test's own HOME and USERPROFILE an unset one stays inside the
        # test; with the machine's HOME it is refused with it.
        with tempfile.TemporaryDirectory() as home:
            isolated = {**isolated_env(Path(home).resolve()),
                        "PYTHONIOENCODING": "utf-8"}
            fallback = {k: v for k, v in isolated.items()
                        if k not in ("LOXODONTA_HOME", "CODEX_HOME")}
            done = subprocess.run(self.command("install-hook"),
                                  capture_output=True, encoding="utf-8",
                                  env=fallback)
            self.assertEqual(done.returncode, 0, done.stderr)

            machine = {**fallback,
                       "HOME": os.environ.get("HOME") or str(REPO_ROOT)}
            with self.assertRaises(AssertionError) as refused:
                subprocess.run(self.command("install-hook"),
                               capture_output=True, env=machine)
        self.assertEqual(named_homes(refused.exception),
                         {"HOME", "LOXODONTA_HOME", "CODEX_HOME"})

    def test_a_hook_with_a_project_the_test_did_not_choose_is_refused(self):
        # The project names the drawer a hook writes into: the inherited
        # one if this process runs under a harness, else a folder that is
        # no temporary one of the test's own.
        project = os.environ.get("CLAUDE_PROJECT_DIR") or str(REPO_ROOT)
        with tempfile.TemporaryDirectory() as home:
            isolated = {**isolated_env(Path(home).resolve()),
                        "PYTHONIOENCODING": "utf-8"}
            with self.assertRaises(AssertionError) as refused:
                subprocess.run(self.command("hook"), capture_output=True,
                               env={**isolated, "CLAUDE_PROJECT_DIR": project})
            self.assertEqual(named_homes(refused.exception),
                             {"CLAUDE_PROJECT_DIR"})

            # The test's own homes and no project: the same start goes ahead.
            done = subprocess.run(self.command("hook"), capture_output=True,
                                  encoding="utf-8", env=isolated)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage", done.stdout)

    def test_a_recorder_verb_that_stays_in_its_log_is_not_guarded(self):
        done = subprocess.run(
            [sys.executable, str(RECORDER), "verify", "--help"],
            capture_output=True, encoding="utf-8")
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
