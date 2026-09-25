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

The rules written in more than one of the three scripts, which never
import each other (ADR-0035), are listed in tools/twin_check.py and
docs/TWINS.md. The suite runs the tool's `--check` on the tree, and on
a spoiled copy of the scripts to see it fail, then its `--write` on the
copy to see it mend only what was spoiled.
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


TWIN_CHECK = REPO_ROOT / "tools" / "twin_check.py"
SCRIPTS = ("loxodonta.py", "supervisor.py", "receiver.py")
POINTER = ("# Copy of loxodonta.py's; edit there, then run "
           "tools/twin_check.py --write.")


def twin_check(*args):
    return subprocess.run([sys.executable, str(TWIN_CHECK), *args],
                          capture_output=True, encoding="utf-8",
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"})


class TwinCheckTest(unittest.TestCase):
    """The rules written in more than one file (ADR-0035) are listed in
    tools/twin_check.py and held by its `--check`: on the tree, and on a
    copy of the three scripts and the page that each test spoils."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        (self.root / "docs").mkdir()
        # Bytes, with LF endings: write_text takes no newline before 3.10.
        for name in SCRIPTS + ("docs/TWINS.md",):
            (self.root / name).write_bytes(
                (REPO_ROOT / name).read_text(encoding="utf-8").encode())

    def edit(self, name, old, new):
        path = self.root / name
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, f"{old!r} in {name}")
        path.write_bytes(text.replace(old, new).encode())

    def append(self, name, text):
        with (self.root / name).open("a", encoding="utf-8",
                                     newline="\n") as script:
            script.write(text)

    def check(self):
        return twin_check("--check", "--root", str(self.root))

    def write(self):
        return twin_check("--write", "--root", str(self.root))

    def snapshot(self):
        """Every file of the copy, as bytes."""
        return {name: (self.root / name).read_bytes()
                for name in SCRIPTS + ("docs/TWINS.md",)}

    def text(self, name):
        return (self.root / name).read_bytes().decode("utf-8")

    def test_the_tree_holds_its_twins(self):
        done = twin_check("--check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_the_copy_holds_its_twins_before_it_is_spoiled(self):
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_copy_that_differs_from_its_original_fails_by_name(self):
        self.edit("supervisor.py",
                  'record.get("kind") == ATTEMPT_KIND',
                  'record.get("kind") == "attempt"')
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("Attempt rows: is_attempt in supervisor.py differs "
                      "from loxodonta.py, its original: run python "
                      "tools/twin_check.py --write", done.stderr)

    def test_a_name_a_file_no_longer_defines_fails(self):
        self.edit("receiver.py", "def checkout_commit(home):",
                  "def commit_of(home):")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("receiver.py no longer defines checkout_commit",
                      done.stderr)

    def test_a_decorator_added_to_a_copy_fails_by_name(self):
        before = self.snapshot()
        self.edit("supervisor.py", "\ndef visible(",
                  "\n@functools.lru_cache(maxsize=None)\ndef visible(")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("visible in supervisor.py differs from loxodonta.py",
                      done.stderr)

        written = self.write()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_a_copy_changed_by_an_augmented_assignment_fails(self):
        self.append("receiver.py", "\nEX_USAGE += 1\n")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("EX_USAGE in receiver.py differs from loxodonta.py",
                      done.stderr)

    def test_an_import_that_shadows_a_twin_fails(self):
        self.append("supervisor.py", "\nfrom json import dumps as visible\n")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("visible is bound by an import in supervisor.py",
                      done.stderr)

    def test_an_undeclared_name_in_two_scripts_fails(self):
        for name in ("supervisor.py", "receiver.py"):
            self.append(name, "\n\ndef twin_probe():\n    return 1\n")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("twin_probe is defined in supervisor.py and "
                      "receiver.py and declared neither", done.stderr)

    def test_a_stale_page_fails_and_page_rewrites_it(self):
        self.append("docs/TWINS.md", "\nA line the list does not hold.\n")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("docs/TWINS.md is stale", done.stderr)

        rewritten = twin_check("--page", "--root", str(self.root))
        self.assertEqual(rewritten.returncode, 0, rewritten.stderr)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(
            (self.root / "docs" / "TWINS.md").read_text(encoding="utf-8"),
            (REPO_ROOT / "docs" / "TWINS.md").read_text(encoding="utf-8"))

    def test_write_on_a_clean_tree_changes_no_byte(self):
        before = self.snapshot()
        done = self.write()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("every copy already holds", done.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_write_copies_an_edited_original_over_each_copy_alone(self):
        # split_lines lives in all three scripts, inside the verifier
        # region of the recorder.
        old, new = "reader keeps (SPEC §1, #299)", "reader keeps (SPEC 1)"
        copies = {name: self.text(name).replace(old, new)
                  for name in ("supervisor.py", "receiver.py")}
        self.edit("loxodonta.py", old, new)
        recorder = self.text("loxodonta.py")
        failed = self.check()
        self.assertEqual(failed.returncode, 1, failed.stdout)
        self.assertIn("split_lines in receiver.py differs", failed.stderr)

        done = self.write()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("wrote split_lines in supervisor.py", done.stdout)
        self.assertIn("wrote split_lines in receiver.py", done.stdout)
        self.assertIn("tools/build_verifier.py", done.stdout)
        # Each copy differs from what it was by the one edit and nothing
        # else, and the original is untouched.
        for name, expected in copies.items():
            self.assertEqual(self.text(name), expected, name)
        self.assertEqual(self.text("loxodonta.py"), recorder)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_write_copies_a_decorated_original_from_its_decorator(self):
        decorated = "\n@functools.lru_cache(maxsize=None)\ndef visible("
        self.edit("loxodonta.py", "\ndef visible(", decorated)
        expected = self.text("supervisor.py").replace(
            POINTER + "\ndef visible(", POINTER + decorated)
        done = self.write()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.text("supervisor.py"), expected)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_missing_pointer_fails_and_write_puts_it_back(self):
        before = self.snapshot()
        self.edit("supervisor.py", POINTER + "\ndef is_attempt(",
                  "def is_attempt(")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("is_attempt in supervisor.py has no pointer to "
                      "loxodonta.py above it", done.stderr)

        written = self.write()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertIn("added the pointer above is_attempt in supervisor.py",
                      written.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_a_copy_directly_below_another_shares_its_pointer(self):
        self.edit("supervisor.py", POINTER + "\nRECORDER_NAMES = ",
                  "RECORDER_NAMES = ")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("RECORDER_NAMES in supervisor.py has no pointer",
                      done.stderr)
        self.assertNotIn("DIGEST_NAMES", done.stderr)

    def test_a_copy_that_went_missing_is_named_and_never_added(self):
        self.edit("receiver.py", "def checkout_commit(home):",
                  "def commit_of(home):")
        before = self.snapshot()
        done = self.write()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("receiver.py no longer defines checkout_commit, and "
                      "--write never adds a copy", done.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_write_keeps_crlf_line_endings(self):
        old, new = "reader keeps (SPEC §1, #299)", "reader keeps (SPEC 1)"
        self.edit("supervisor.py", POINTER + "\ndef is_attempt(",
                  "def is_attempt(")
        expected = {name: self.text(name).replace(old, new).replace(
                        "def is_attempt(", POINTER + "\ndef is_attempt(")
                    for name in ("supervisor.py", "receiver.py")}
        self.edit("loxodonta.py", old, new)
        for name in SCRIPTS:
            path = self.root / name
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))

        done = self.write()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        for name, text in expected.items():
            self.assertEqual(self.text(name), text.replace("\n", "\r\n"),
                             name)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
