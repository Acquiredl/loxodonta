"""The suite's own shape: two tests about the suite, not about the recorder.

Every test module imports on its own (#118). `python -m unittest discover
-s tests` puts `tests/` on `sys.path`, so a module that says `from
test_recall import forge_chain` resolves under discovery and nowhere else.
CI runs discovery, so the suite stays green while `python -m unittest
tests.test_mcp` — the single-module red/green loop a contributor runs
while fixing one thing — dies on an import error before a test ever runs.
That test imports every `tests/test_*.py` the way that loop does, as
`tests.<name>` from the repo root, each in its own subprocess so a broken
module names itself instead of taking the parent interpreter with it.

No test reads this machine's home (#242). `scan` reads the coverage
marker from the machine-wide store whatever `--root` says (ADR-0030),
and the harness settings beside the default witness; `serve`, `export`
and `package` read both, `drill` the marker's profile, and `calibrate`
with no `--root` the store's own baseline. A test that starts one of
them with the environment it inherited is judging the machine it runs
on. BeforeMemoryTest did that:
green in CI, whose runner has never run `install-hook`, and four failures
on every machine that had. The tripwire below refuses such a start before
the process exists, and names where it came from.
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


# --- The tripwire (#242) ------------------------------------------------------
# The supervisor verbs that read machine-wide state: the coverage marker,
# the harness settings or the store's baseline. The recall verbs read the
# store as well, but only the drawer of the `--repo` a test names, which
# is a folder of the test's own.
HOME_READERS = {"scan", "serve", "calibrate", "drill", "export", "package"}
# Every home those verbs reach: the store, the user's home as either
# platform spells it (Path.home() reads USERPROFILE on Windows and HOME
# elsewhere, and the default witness hangs off it), and Codex's hooks.
HOMES = ("LOXODONTA_HOME", "HOME", "USERPROFILE", "CODEX_HOME")
# The verb after `supervisor.py` in the command. On Windows subprocess
# hands the audit hook one command line, elsewhere a list, which is
# joined with spaces first, so one pattern reads both.
SUPERVISOR_VERB = re.compile(r'(?:^|[\s"/\\])supervisor\.py"?\s+"?([a-z-]+)')


def inside_the_temp_root(value):
    """Whether `value` names a folder under the temp root, which is where
    every test's own home lives and where no machine keeps its real one."""
    if not value:
        return False
    temp = os.path.realpath(tempfile.gettempdir())
    try:
        return os.path.commonpath([os.path.realpath(value), temp]) == temp
    except ValueError:  # another drive, on Windows: not under it
        return False


def strays(env):
    """The names in `env` that could still reach this machine's home: a
    home unset, outside the temp root, or no different from the one this
    process runs under; and a CLAUDE_PROJECT_DIR the test did not choose."""
    found = [name for name in HOMES
             if not inside_the_temp_root(env.get(name))
             or env.get(name) == os.environ.get(name)]
    project = env.get("CLAUDE_PROJECT_DIR")
    if project and (not inside_the_temp_root(project)
                    or project == os.environ.get("CLAUDE_PROJECT_DIR")):
        found.append("CLAUDE_PROJECT_DIR")
    return found


def started_from():
    """Where in tests/ the start came from, outermost first: the test,
    then any helper it went through."""
    frames = []
    frame = sys._getframe(2)  # past this function and the hook
    while frame is not None:
        path = Path(frame.f_code.co_filename).resolve()
        if path.parent == TESTS_DIR:
            frames.append("tests/%s:%d in %s" % (
                path.name, frame.f_lineno, frame.f_code.co_name))
        frame = frame.f_back
    return list(reversed(frames))


def refuse_this_machines_home(event, args):
    """An audit hook: every process a test starts passes through
    `subprocess.Popen`, whichever helper started it, so this is the one
    place a home-reading verb can be stopped before it reads anything.
    Raising here fails the test that started it, at the start."""
    if event != "subprocess.Popen":
        return
    _, command, _, env = args
    if isinstance(command, (str, bytes, os.PathLike)):
        command = os.fsdecode(command)
    else:
        command = " ".join(os.fsdecode(part) for part in command)
    verb = SUPERVISOR_VERB.search(command)
    if verb is None or verb.group(1) not in HOME_READERS:
        return
    names = strays(os.environ if env is None else env)
    if names:
        raise AssertionError(
            "supervisor.py %s started with this machine's %s (#242). Give "
            "it isolated_env(home) from tests/test_supervisor.py, with the "
            "home in a temporary folder of the test's own. Started from:\n  "
            "%s" % (verb.group(1), ", ".join(names),
                    "\n  ".join(started_from()) or "outside tests/"))


# Discovery imports every module before it runs a single test, so the
# tripwire is armed for the whole suite, CI's run included. A module run
# on its own runs without it.
sys.addaudithook(refuse_this_machines_home)


class NoTestReadsThisMachinesHome(unittest.TestCase):

    def test_a_home_reading_verb_started_with_the_inherited_home_is_refused(self):
        # `--help` reads no home even if the tripwire were not armed.
        command = [sys.executable, str(SUPERVISOR), "scan", "--help"]

        with self.assertRaises(AssertionError) as refused:
            subprocess.run(command, capture_output=True)

        said = str(refused.exception)
        self.assertIn("supervisor.py scan", said)
        for name in ("LOXODONTA_HOME", "HOME", "USERPROFILE", "CODEX_HOME"):
            self.assertIn(name, said)
        # It names the line that started it, so the offender is found
        # without a search.
        where = re.search(r"tests/test_suite_shape\.py:(\d+) in (\w+)", said)
        self.assertIsNotNone(where, said)
        self.assertEqual(where.group(2), self._testMethodName)
        line = Path(__file__).read_text(
            encoding="utf-8").splitlines()[int(where.group(1)) - 1]
        self.assertIn("subprocess.run(command", line)

        # The same start in a home of the test's own goes ahead.
        with tempfile.TemporaryDirectory() as home:
            done = subprocess.run(
                command, capture_output=True, encoding="utf-8",
                env={**isolated_env(Path(home).resolve()),
                     "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage", done.stdout)


if __name__ == "__main__":
    unittest.main()
