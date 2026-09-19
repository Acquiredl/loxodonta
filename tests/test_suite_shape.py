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
guard itself lives in tests/home_guard.py, which says what it covers and
what it leaves to #274; these tests hold it to refusing the six
home-reading supervisor verbs when any one home is the machine's, and to
naming the line that made the start.
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
        self.assertEqual(named_homes(said), EVERY_HOME, said)
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
                    leaky = dict(isolated)
                    if name in os.environ:
                        leaky[name] = os.environ[name]
                    else:
                        del leaky[name]
                    with self.assertRaises(AssertionError) as refused:
                        subprocess.run(self.command, capture_output=True,
                                       env=leaky)
                    self.assertEqual(named_homes(refused.exception), {name})

            # All four of the test's own, and the same start goes ahead.
            done = subprocess.run(self.command, capture_output=True,
                                  encoding="utf-8", env=isolated)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage", done.stdout)


if __name__ == "__main__":
    unittest.main()
