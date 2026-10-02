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
the five home-writing verbs (#274) when any one home is the machine's,
and to naming the line that made the start.

The rules written in more than one of the three scripts, which never
import each other (ADR-0035), are listed in tools/twin_check.py and
docs/TWINS.md. The suite runs the tool's `--check` on the tree, and on
a spoiled copy of the scripts to see it fail, then its `--write` on the
copy to see it mend only what was spoiled.

Every call in the three scripts that opens, reads, writes, copies or
moves a file by its name goes through `open_regular`, which never
waits, or is on a list kept here (#405): an ordinary open of a pipe
waits for the other end, and four issues before this one each fixed the
opens somebody happened to find. The test walks each script's syntax
tree, holds every such call to the list by script and function, and
spoils a copy to see it fail. An entry on the list is a stated reason,
never a waiver: it gives the number of calls its function may make and
one line of why, so a call added beside a listed one fails too. It
sees the calls it names and no others, and its class says which it
does not: a path handed to another program, an alias, a call made
through `getattr`.

Every question a script asks of whether something is there goes
through `os.path` (#421). Before Python 3.14, pathlib's `exists()`,
`is_file()`, `is_dir()` and `is_symlink()` raise for a path in a folder
the user may not look into, where `os.path`'s answer False, so one
`chmod` in the writer's reach ended a reader in a traceback. A second
walk of each script fails on any such method call, naming its function
and line, and spoils a copy to see it fail. It keeps no list: no call
needs one.

Every LOXODONTA_*, RECEIPTS_*, SUPERVISOR_* or RECEIVER_* variable a
page under docs/ or the README names is one the scripts read (#397).
"""

import ast
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
    supervisor's `adopt` and `acknowledge`, under the same guard (#274).
    `--help` again, so
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

    def test_acknowledge_is_refused_with_the_inherited_home(self):
        # It writes the store's baseline when given no --root (ADR-0039).
        with self.assertRaises(AssertionError) as refused:
            subprocess.run([sys.executable, str(SUPERVISOR), "acknowledge",
                            "--help"], capture_output=True)
        self.assertIn("supervisor.py acknowledge started",
                      str(refused.exception))

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
                  'row_kind("memo", record) == CHAIN_KIND',
                  'row_kind("memo", record) == "chain"')
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("What a sidecar row is: is_chain_record in "
                      "supervisor.py differs from loxodonta.py, its "
                      "original: run python tools/twin_check.py --write",
                      done.stderr)

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

    def test_page_writes_lf_whatever_the_checkout_holds(self):
        page = self.root / "docs" / "TWINS.md"
        page.write_bytes(b"stale\r\n")
        done = twin_check("--page", "--root", str(self.root))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("wrote docs/TWINS.md", done.stdout)
        written = page.read_bytes()
        self.assertNotIn(b"\r", written)
        self.assertEqual(written.decode("utf-8"),
                         (REPO_ROOT / "docs" / "TWINS.md").read_text(
                             encoding="utf-8"))

    def test_page_with_nothing_changed_leaves_the_file_alone(self):
        # A current page that a Windows checkout wrote with CRLF, rewritten
        # as LF, reads as modified to git status with an empty diff (#402).
        page = self.root / "docs" / "TWINS.md"
        crlf = page.read_bytes().replace(b"\n", b"\r\n")
        page.write_bytes(crlf)
        done = twin_check("--page", "--root", str(self.root))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("docs/TWINS.md is current", done.stdout)
        self.assertEqual(page.read_bytes(), crlf)
        checked = self.check()
        self.assertEqual(checked.returncode, 0,
                         checked.stdout + checked.stderr)

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
        self.edit("supervisor.py", POINTER + "\ndef is_chain_record(",
                  "def is_chain_record(")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("is_chain_record in supervisor.py has no pointer to "
                      "loxodonta.py above it", done.stderr)

        written = self.write()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertIn("added the pointer above is_chain_record in supervisor.py",
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

    def assert_refused(self, done, *said):
        """`--write` exited 1, named each of `said`, and raised nothing."""
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        for words in said:
            self.assertIn(words, done.stderr)

    def test_a_copy_sharing_its_first_line_is_refused(self):
        self.edit("supervisor.py", '\nATTEMPT_KIND = "attempt"\n',
                  '\n_Z = 1; ATTEMPT_KIND = "attempt"\n')
        before = self.snapshot()
        self.assert_refused(self.write(),
                            "ATTEMPT_KIND in supervisor.py shares its first "
                            "line with other code",
                            "supervisor.py is left as it was")
        self.assertEqual(self.snapshot(), before)

    def test_an_original_sharing_its_first_line_is_refused(self):
        self.edit("loxodonta.py", '\nATTEMPT_KIND = "attempt"\n',
                  '\nif True: ATTEMPT_KIND = "attempt"\n')
        before = self.snapshot()
        self.assert_refused(self.write(),
                            "ATTEMPT_KIND in loxodonta.py shares its first "
                            "line with other code")
        self.assertEqual(self.snapshot(), before)

    def test_two_copies_on_one_line_are_refused_and_that_file_kept(self):
        self.edit("loxodonta.py", "EX_USAGE = 64     #", "EX_USAGE = 65     #")
        self.edit("loxodonta.py", "EX_NOINPUT = 66   #", "EX_NOINPUT = 67   #")
        self.edit("supervisor.py",
                  "EX_USAGE = 64  # sysexits(3) EX_USAGE: the command was "
                  "spoken wrong\nEX_NOINPUT = 66  #",
                  "EX_USAGE = 64; EX_NOINPUT = 66  #")
        supervisor = self.text("supervisor.py")
        self.assert_refused(self.write(), "supervisor.py is left as it was")
        self.assertEqual(self.text("supervisor.py"), supervisor)
        # The receiver's copy has a line of its own, and is written.
        self.assertIn("\nEX_USAGE = 65  #", self.text("receiver.py"))

    def test_a_statement_binding_other_names_is_refused_whole(self):
        self.edit("supervisor.py",
                  "EX_USAGE = 64  # sysexits(3) EX_USAGE: the command was "
                  "spoken wrong\nEX_NOINPUT = 66  #",
                  "EX_USAGE, EX_NOINPUT = 64, 66  #")
        before = self.snapshot()
        self.assert_refused(self.write(),
                            "is bound by a statement binding EX_USAGE, "
                            "EX_NOINPUT",
                            "supervisor.py is left as it was")
        self.assertEqual(self.snapshot(), before)

    def test_a_pointer_never_lands_inside_a_string(self):
        self.edit("supervisor.py", POINTER + "\ndef is_chain_record(",
                  '_NOTE = """\n# not a comment"""\ndef is_chain_record(')
        expected = self.text("supervisor.py").replace(
            '"""\ndef is_chain_record(', '"""\n' + POINTER + "\ndef is_chain_record(")
        done = self.write()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.text("supervisor.py"), expected)

    def test_a_string_line_is_not_a_comment_that_leaves_a_run_alone(self):
        # A string whose last line starts with # sits between the run
        # and the blank line above it: the run is not alone in its block.
        self.edit("supervisor.py", POINTER + "\nRECORDER_NAMES = ",
                  '_NOTE = """\n\n# x"""\n' + POINTER + "\nRECORDER_NAMES = ")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("DIGEST_NAMES in supervisor.py has no pointer",
                      done.stderr)

    def test_a_copy_beside_other_code_has_a_pointer_of_its_own(self):
        hazards = "# a quote, a backtick, a dollar sign, a backslash\n"
        self.edit("supervisor.py", hazards, hazards + "_OTHER = 1\n")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("SHELL_HAZARDS in supervisor.py has no pointer",
                      done.stderr)
        written = self.write()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertIn(POINTER + "\nSHELL_HAZARDS = ",
                      self.text("supervisor.py"))
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_byte_order_mark_is_named_and_nothing_written(self):
        path = self.root / "supervisor.py"
        path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
        before = self.snapshot()
        for done in (self.check(), self.write()):
            self.assert_refused(done, "supervisor.py starts with a byte "
                                      "order mark")
        self.assertEqual(self.snapshot(), before)

    def test_an_original_that_does_not_parse_is_named_and_nothing_written(self):
        self.append("loxodonta.py", "\ndef (\n")
        before = self.snapshot()
        for done in (self.check(), self.write()):
            self.assert_refused(done, "loxodonta.py is not readable as "
                                      "Python")
        self.assertEqual(self.snapshot(), before)

    def test_write_keeps_crlf_line_endings(self):
        old, new = "reader keeps (SPEC §1, #299)", "reader keeps (SPEC 1)"
        self.edit("supervisor.py", POINTER + "\ndef is_chain_record(",
                  "def is_chain_record(")
        expected = {name: self.text(name).replace(old, new).replace(
                        "def is_chain_record(", POINTER + "\ndef is_chain_record(")
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

    def test_a_pointer_that_would_split_a_continued_line_is_refused(self):
        # A trailing backslash joins the line above to the copy's, so a
        # pointer put between them would leave a file that does not
        # parse (#354).
        self.edit("receiver.py", POINTER + "\nEX_USAGE = 64  #",
                  "if True: \\\nEX_USAGE = 64  #")
        before = self.snapshot()
        self.assert_refused(self.write(),
                            "receiver.py is not readable as Python (",
                            "once a pointer goes above EX_USAGE",
                            "receiver.py is left as it was")
        self.assertEqual(self.snapshot(), before)

    def test_a_nul_byte_is_named_and_nothing_written(self):
        # Before Python 3.12 a NUL byte raises ValueError, and from 3.12
        # a SyntaxError with no line (#354).
        self.append("supervisor.py", "\n_NUL = 1  # \x00\n")
        before = self.snapshot()
        for done in (self.check(), self.write()):
            self.assert_refused(done, "supervisor.py is not readable as "
                                      "Python (source code string cannot "
                                      "contain null bytes")
            self.assertNotIn("None", done.stderr)
        self.assertEqual(self.snapshot(), before)

    def in_split_lines(self, text, change):
        """`text`, the supervisor's, with `change` made to its copy of
        split_lines alone."""
        start = text.index("def split_lines(")
        end = text.index("\n\n\n", start)
        return text[:start] + change(text[start:end]) + text[end:]

    def test_write_keeps_each_line_its_own_ending(self):
        # A file whose endings a tool already mixed: each line of a
        # rewritten copy keeps its own ending, and a line the original
        # gained takes the ending of the line above it (#354).
        split = '    lines = data.split(b"\\n")\n'
        added = "    # The bytes after the last newline are a line too.\n"
        self.edit("loxodonta.py", split, split + added)
        # The copy's first line ends LF and the line above the gained one
        # CRLF, so the gained line's ending shows which it took.
        above, popped = split[:-1], "        lines.pop()"

        def crlf(block):
            for line in (above, popped):
                block = block.replace(line + "\n", line + "\r\n")
            return block

        mixed = self.in_split_lines(self.text("supervisor.py"), crlf)
        self.assertEqual(mixed.count("\r\n"), 2)
        expected = self.in_split_lines(
            mixed, lambda block: block.replace(
                above + "\r\n", above + "\r\n" + added[:-1] + "\r\n"))
        (self.root / "supervisor.py").write_bytes(mixed.encode("utf-8"))

        done = self.write()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("wrote split_lines in supervisor.py", done.stdout)
        self.assertEqual(self.text("supervisor.py"), expected)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_pointer_not_directly_above_a_copy_is_stale(self):
        # What --write left before #354 when a comment went in between a
        # pointer and its copy: a second pointer, the first one stale.
        self.edit("supervisor.py", POINTER + "\ndef is_chain_record(",
                  POINTER + "\n# A note.\n" + POINTER
                  + "\ndef is_chain_record(")
        text = self.text("supervisor.py")
        stale = text[:text.index(POINTER + "\n# A note.")].count("\n") + 1
        expected = text.replace(POINTER + "\n# A note.\n" + POINTER,
                                "# A note.\n" + POINTER)
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn(f"the pointer on line {stale} of supervisor.py is "
                      "stale, not directly above a copy", done.stderr)

        written = self.write()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertIn("took off a stale pointer in supervisor.py",
                      written.stdout)
        self.assertEqual(self.text("supervisor.py"), expected)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_comment_below_a_pointer_puts_the_pointer_below_it(self):
        self.edit("supervisor.py", POINTER + "\ndef is_chain_record(",
                  POINTER + "\n# A note.\ndef is_chain_record(")
        expected = self.text("supervisor.py").replace(
            POINTER + "\n# A note.\n", "# A note.\n" + POINTER + "\n")
        done = self.check()
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("is_chain_record in supervisor.py has no pointer",
                      done.stderr)
        self.assertIn("of supervisor.py is stale", done.stderr)

        written = self.write()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(self.text("supervisor.py"), expected)
        done = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


# What the walk collects (#405): a call that opens, reads, writes,
# copies or moves a file by its name, or fetches an address urllib could
# read as one. The builtin `open`; any object's `.open(`, its four
# whole-file reads and writes, `.ZipFile(`, `.is_zipfile(` and
# `.urlopen(`, so `os.open` and a URL opener are collected too and
# listed for what they are; and `shutil`'s copies and its move by that
# name alone, since a hash object's `.copy()` opens nothing.
# `open_regular` is the open that never waits, and is never collected.
# A helper that wraps a plain open is collected at that open, and listed
# for what its callers hand it.
FILE_METHODS = {"open", "read_text", "read_bytes", "write_text",
                "write_bytes", "ZipFile", "is_zipfile", "urlopen"}
SHUTIL_CALLS = {"copy", "copy2", "copyfile", "copyfileobj", "copytree",
                "move"}

RECEIVER_DATA = ("the receiver's own data folder, on a machine the writer "
                 "cannot reach (ADR-0031)")
NEVER_WAITS = ("the open that never waits: O_NONBLOCK, and the type asked "
               "of the open file")

# Every function that still opens a file by its name without
# `open_regular`: (script, function) -> (how many such calls, and why).
ALLOWED_OPENS = {
    ("loxodonta.py", "open_regular"): (1, NEVER_WAITS),
    ("loxodonta.py", "write_line_to_disk"): (1, NEVER_WAITS),
    ("loxodonta.py", "append_sidecar_record"): (1, NEVER_WAITS),
    ("loxodonta.py", "run_main"): (
        1, "the null device, a sink for a reader that has gone"),
    ("loxodonta.py", "post_for_reply"): (
        1, "a URL, held to http or https by every caller"),
    ("loxodonta.py", "calendar_request"): (
        1, "a URL held to http or https before it is asked (#414)"),
    ("loxodonta.py", "cmd_verify_package"): (
        2, "is_zipfile and ZipFile read the one file open_regular opened, "
           "never the name"),
    ("loxodonta.py", "judge_stamp"): (
        1, "writes the token into a temporary folder of its own"),
    ("loxodonta.py", "judge_manifest_signature"): (
        1, "writes the allowed-signers line into a temporary folder of "
           "its own"),
    ("supervisor.py", "open_regular"): (1, NEVER_WAITS),
    ("supervisor.py", "copy_regular"): (
        1, "copies between two files already open: the source by "
           "open_regular, the target created exclusively"),
    ("supervisor.py", "write_lf"): (
        1, "writes into a folder the supervisor has just made: a "
           "package's staging folder, or a temporary one"),
    ("supervisor.py", "raw_archive"): (
        1, "builds the raw archive in memory; write_export puts it at its "
           "name"),
    ("supervisor.py", "zip_package"): (
        1, "the package's zip at --out, created exclusively (mode x): "
           "whatever stands there is kept and never opened"),
    ("supervisor.py", "sign_manifest"): (
        2, "the .pub beside the issuer's key, out of the writer's reach "
           "(ADR-0008), and the manifest it has just staged"),
    ("supervisor.py", "write_lines"): (
        1, "writes the drill's copies into the sandbox it has just made "
           "afresh"),
    ("supervisor.py", "cmd_adopt"): (
        2, "moves a legacy chain and its sidecars, each asked first "
           "whether it is a file (file_problem): a rename within one "
           "filesystem opens nothing, and across two shutil refuses a "
           "named pipe put there after the question"),
    ("supervisor.py", "Face.do_GET"): (
        1, "serves docs/FIRE-DRILL.md from the supervisor's own checkout"),
    ("receiver.py", "mint_token"): (1, RECEIVER_DATA),
    ("receiver.py", "current_token"): (1, RECEIVER_DATA),
    ("receiver.py", "ends_mid_line"): (1, RECEIVER_DATA),
    ("receiver.py", "append_durably"): (1, RECEIVER_DATA),
    ("receiver.py", "known_pairs"): (1, RECEIVER_DATA),
}


def argument(call, place, keyword):
    """What a call passes at `place`, or as `keyword`; None if neither."""
    if len(call.args) > place:
        return call.args[place]
    return next((given.value for given in call.keywords
                 if given.arg == keyword), None)


def or_operands(node):
    """The operands of `a | b | c` as written; [node] for anything else."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return or_operands(node.left) + or_operands(node.right)
    return [node]


def creates_exclusively(call, os_open):
    """Whether the call creates its file exclusively, which never opens
    one already there, so nothing put at the name can be waited on: the
    builtin `open` with a literal mode holding `x`, or `os.open` with
    `os.O_CREAT` and `os.O_EXCL` written among the flags it ORs, since
    an OR sets bits and never clears one. A starred argument hides which
    argument is which, so a call with one is never read as exclusive. A
    non-waiting open (`O_NONBLOCK`) passes nowhere here: it still reads
    a device without end unless the type is asked of the open file,
    which no syntax shows, so each one is listed with its reason."""
    if any(isinstance(given, ast.Starred) for given in call.args) \
            or any(given.arg is None for given in call.keywords):
        return False
    if os_open:
        flags = argument(call, 1, "flags")
        written = ({ast.unparse(operand) for operand in or_operands(flags)}
                   if flags is not None else set())
        return {"os.O_CREAT", "os.O_EXCL"} <= written
    mode = argument(call, 1, "mode")
    return (isinstance(mode, ast.Constant) and isinstance(mode.value, str)
            and "x" in mode.value)


def opens_a_file(call):
    """Whether the walk collects `call` (FILE_METHODS, SHUTIL_CALLS)."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id == "open" and not creates_exclusively(call, False)
    if not isinstance(func, ast.Attribute):
        return False
    base = func.value.id if isinstance(func.value, ast.Name) else None
    if func.attr in FILE_METHODS:
        return not (base == "os" and func.attr == "open"
                    and creates_exclusively(call, True))
    return func.attr in SHUTIL_CALLS and base == "shutil"


class FileCalls(ast.NodeVisitor):
    """One script's walk. `opens` maps each function, named with the
    classes and functions around it (`Face.do_GET`), to the lines of
    the calls collected in it; `defined` holds every such name.
    `collects` says which calls are collected: by default those that
    open a file."""

    def __init__(self, collects=opens_a_file):
        self.collects = collects
        self.scope, self.opens, self.defined = [], {}, set()

    def visit_FunctionDef(self, node):
        self.scope.append(node.name)
        self.defined.add(".".join(self.scope))
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_ClassDef = visit_FunctionDef

    def visit_Call(self, node):
        if self.collects(node):
            where = ".".join(self.scope) or "<module>"
            self.opens.setdefault(where, []).append(node.lineno)
        self.generic_visit(node)


def file_calls(path, collects=opens_a_file):
    """The walk of the script at `path`."""
    calls = FileCalls(collects)
    calls.visit(ast.parse(Path(path).read_bytes()))
    return calls


def beyond_the_list(name, calls):
    """Each function of script `name` making more collected calls than
    the list allows it, as (function, allowed, lines)."""
    over = []
    for where, lines in sorted(calls.opens.items()):
        allowed = ALLOWED_OPENS.get((name, where), (0, None))[0]
        if len(lines) > allowed:
            over.append((where, allowed, lines))
    return over


def stale_entries(walks, allowed=ALLOWED_OPENS):
    """Each entry of `allowed` that the walks, {script: FileCalls}, no
    longer meet, in words: its function gone, or making fewer collected
    calls than the entry allows."""
    stale = []
    for (name, where), (count, _) in sorted(allowed.items()):
        made = len(walks[name].opens.get(where, []))
        if where not in walks[name].defined:
            stale.append(f"{name} no longer defines {where}")
        elif made < count:
            stale.append(f"{name} {where} makes {made} call(s), and the "
                         f"list allows {count}")
    return stale


def aliases(path):
    """Each way the script at `path` could reach a call the walk
    collects by a name the walk does not match, as (line, what): a
    `from` import of a name it collects, any import renamed with `as`,
    and the builtin `open` named anywhere but as the function of a
    call."""
    tree = ast.parse(Path(path).read_bytes())
    called = {id(node.func) for node in ast.walk(tree)
              if isinstance(node, ast.Call)}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for name in node.names:
                if name.asname:
                    found.append((node.lineno,
                                  f"import {name.name} as {name.asname}"))
                elif isinstance(node, ast.ImportFrom) \
                        and name.name in FILE_METHODS | SHUTIL_CALLS:
                    found.append((node.lineno, f"from {node.module} "
                                               f"import {name.name}"))
        elif isinstance(node, ast.Name) and node.id == "open" \
                and id(node) not in called:
            found.append((node.lineno, "open, not called"))
    return sorted(found)


class SpoiledScript:
    """A copy of one of the three scripts with one edit made, for a
    check to be seen failing on it."""

    def spoiled_copy(self, name, old, new):
        """A copy of script `name` with `old`, which it holds once, made
        `new`."""
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, f"{old!r} in {name}")
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        copy = Path(scratch.name) / name
        copy.write_bytes(text.replace(old, new).encode())
        return copy

    def spoiled(self, name, old, new, collects=opens_a_file):
        """The walk of a copy of script `name` with `old` made `new`, and
        the copy's text, to find the lines in."""
        copy = self.spoiled_copy(name, old, new)
        return file_calls(copy, collects), copy.read_text(encoding="utf-8")

    def line_of(self, text, line):
        """The number of the one line of `text` that is `line`."""
        found = [number for number, said in enumerate(text.split("\n"), 1)
                 if said == line]
        self.assertEqual(len(found), 1, line)
        return found[0]

    def added_to_anchors_path(self, *lines, collects=opens_a_file):
        """The walk of the recorder with `lines` added to anchors_path,
        which the list does not name, and the line numbers they got."""
        old = "def anchors_path(log):\n"
        calls, text = self.spoiled("loxodonta.py", old, old + "".join(
            line + "\n" for line in lines), collects)
        return calls, [self.line_of(text, line) for line in lines]


class EveryOpenIsListedTest(SpoiledScript, unittest.TestCase):
    """The rule of #364, #374, #385, #386 and #405 as a check: a call
    that opens, reads, writes, copies or moves a file by its name goes
    through `open_regular`, or its function is on ALLOWED_OPENS with
    the number of such calls it makes and why. An exclusive create
    passes on its own. `verifier.py` is not walked: it is copied from
    the recorder, and `tools/build_verifier.py --check` holds it
    equal.

    What the walk does not see: a path handed by name to another
    program (ssh-keygen opens a package's `.pub` and `.sig` itself), or
    to a library method that opens it itself (a zip's `write` and
    `extractall`, which today read and fill only a folder the script
    has just made, and the receiver's `load_cert_chain`); a
    renamed import or an alias, `from shutil import copyfile` or
    `opener = open`, which a test here holds the three scripts free of;
    and a call reached through `getattr`, `functools.partial` or `map`.
    An entry holds how many such calls its function makes, not which:
    one swapped for another at the same count passes."""

    def test_every_file_call_on_the_tree_is_listed_at_its_count(self):
        found = [f"{name} {where}, line {', '.join(map(str, lines))}: "
                 f"{len(lines)} call(s), and the list allows {allowed}"
                 for name in SCRIPTS
                 for where, allowed, lines in beyond_the_list(
                     name, file_calls(REPO_ROOT / name))]
        self.assertEqual(found, [], "a file opened by its name, not "
                         "through open_regular: read it through that, or "
                         "list its function with the count and why (#405)")

    def test_no_entry_on_the_list_is_stale(self):
        for (name, where), (_, why) in ALLOWED_OPENS.items():
            self.assertIn(name, SCRIPTS)
            self.assertTrue(why, f"{name} {where} is listed with no reason")
        walks = {name: file_calls(REPO_ROOT / name) for name in SCRIPTS}
        self.assertEqual(stale_entries(walks), [],
                         "take the entry off, or lower its count")

    def test_an_entry_the_walk_no_longer_meets_is_named_stale(self):
        walks = {name: file_calls(REPO_ROOT / name) for name in SCRIPTS}
        spoiled = {**ALLOWED_OPENS,
                   ("receiver.py", "token_path"): (1, "a call not there"),
                   ("receiver.py", "no_such_function"): (1, "nor this")}
        self.assertEqual(stale_entries(walks, spoiled),
                         ["receiver.py no longer defines no_such_function",
                          "receiver.py token_path makes 0 call(s), and the "
                          "list allows 1"])

    def test_a_plain_read_added_to_a_function_is_named_at_its_line(self):
        calls, lines = self.added_to_anchors_path(
            "    with open(log) as spoiled:", "        spoiled.read()")
        self.assertEqual(beyond_the_list("loxodonta.py", calls),
                         [("anchors_path", 0, lines[:1])])

    def test_a_plain_write_added_to_a_function_is_named_at_its_line(self):
        # A pipe opened for writing waits for a reader, as #385's did.
        added = '    with open(path, "w") as spoiled:'
        old = '    return re.sub(r"[^A-Za-z0-9-]", "-", str(path))\n'
        calls, text = self.spoiled(
            "supervisor.py", old,
            added + '\n        spoiled.write("")\n' + old)
        self.assertEqual(beyond_the_list("supervisor.py", calls),
                         [("munge", 0, [self.line_of(text, added)])])

    def test_a_call_added_beside_a_listed_one_fails_on_the_count(self):
        listed = '    with open(path, "ab") as f:'
        added = '    with open(path, "ab") as spoiled:'
        calls, text = self.spoiled(
            "receiver.py", listed + "\n",
            added + '\n        spoiled.write(b"")\n' + listed + "\n")
        self.assertEqual(beyond_the_list("receiver.py", calls),
                         [("append_durably", 1,
                           [self.line_of(text, added),
                            self.line_of(text, listed)])])

    def test_a_zip_or_an_address_opened_by_name_is_collected(self):
        calls, lines = self.added_to_anchors_path(
            "    zipfile.is_zipfile(log)",
            "    zipfile.ZipFile(log).close()",
            "    urllib.request.urlopen(log).close()")
        self.assertEqual(beyond_the_list("loxodonta.py", calls),
                         [("anchors_path", 0, lines)])

    def test_an_exclusive_create_passes_and_only_an_exclusive_one(self):
        exclusive = "os.O_WRONLY | os.O_CREAT | os.O_EXCL"
        calls, lines = self.added_to_anchors_path(
            '    open(log, "x").close()',
            f"    os.close(os.open(log, {exclusive}))",
            "    os.close(os.open(log, os.O_WRONLY | os.O_CREAT))")
        self.assertEqual(beyond_the_list("loxodonta.py", calls),
                         [("anchors_path", 0, lines[2:])])

    def test_a_starred_argument_is_never_read_as_an_exclusive_create(self):
        # Which argument is the mode, or the flags, is unknown past one.
        calls, lines = self.added_to_anchors_path(
            '    open(*[log], "x").close()',
            "    os.close(os.open(*[log], os.O_CREAT | os.O_EXCL))",
            '    open(log, **{"mode": "x"}).close()')
        self.assertEqual(beyond_the_list("loxodonta.py", calls),
                         [("anchors_path", 0, lines)])

    def test_no_script_reaches_a_collected_call_by_another_name(self):
        found = [f"{name}, line {line}: {what}"
                 for name in SCRIPTS
                 for line, what in aliases(REPO_ROOT / name)]
        self.assertEqual(found, [], "the walk knows a call by the name it "
                         "collects: import the module and call it by that "
                         "name, and only ever call open (#421)")

    def aliased(self, name, old, added):
        """The aliases of a copy of script `name` with the line `added`
        put after `old`, and the line number it got."""
        copy = self.spoiled_copy(name, old, old + added + "\n")
        text = copy.read_text(encoding="utf-8")
        return aliases(copy), self.line_of(text, added)

    def test_a_from_import_of_a_collected_name_is_named_at_its_line(self):
        found, line = self.aliased("supervisor.py", "import shutil\n",
                                   "from shutil import copyfile")
        self.assertEqual(found, [(line, "from shutil import copyfile")])

    def test_a_renamed_import_is_named_at_its_line(self):
        found, line = self.aliased("receiver.py", "import json\n",
                                   "import shutil as sh")
        self.assertEqual(found, [(line, "import shutil as sh")])

    def test_open_held_as_a_value_is_named_and_a_call_is_not(self):
        old = "def anchors_path(log):\n"
        found, line = self.aliased("loxodonta.py", old,
                                   "    opener = open")
        self.assertEqual(found, [(line, "open, not called")])


# What the existence walk collects (#421): a method call that asks
# whether something is there, of anything but os.path. Before Python
# 3.14 pathlib's raise PermissionError for a path in a folder this user
# may not look into, as an os.DirEntry's do on every version; os.path's
# answer False there on every version.
EXISTENCE_METHODS = {"exists", "is_file", "is_dir", "is_symlink"}


def asks_by_method(call):
    """Whether the existence walk collects `call` (EXISTENCE_METHODS)."""
    func = call.func
    return (isinstance(func, ast.Attribute)
            and func.attr in EXISTENCE_METHODS
            and ast.unparse(func.value) != "os.path")


class ExistenceIsAskedThroughOsPathTest(SpoiledScript, unittest.TestCase):
    """The rule of #421 as a check: the three scripts ask whether
    something is there through `os.path.exists`, `isfile`, `isdir`,
    `islink` and `lexists`, never through a method named `exists`,
    `is_file`, `is_dir` or `is_symlink` of anything else, so a folder
    closed to the reader reads as nothing there on every Python. No
    call needs a list. The walk cannot tell a Path from an os.DirEntry,
    whose methods raise there too, and holds both. `verifier.py` is not
    walked: it is copied from the recorder, which asks none of these by
    method. `tools/` and `tests/` are not walked either: they read the
    repository and folders of their own, never the writer's.

    What the walk does not see: the same question asked inside the
    standard library, as `Path.glob` asks `is_dir` of the folder it
    starts from before Python 3.13; and a method reached through
    `getattr`."""

    def test_every_script_asks_through_os_path(self):
        found = [f"{name} {where}, line {', '.join(map(str, lines))}"
                 for name in SCRIPTS
                 for where, lines in sorted(file_calls(
                     REPO_ROOT / name, asks_by_method).opens.items())]
        self.assertEqual(found, [], "ask through os.path.exists, isfile, "
                         "isdir, islink or lexists, which answer False for "
                         "a folder this user may not look into (#421)")

    def test_a_method_asking_whether_a_path_is_there_is_named(self):
        calls, lines = self.added_to_anchors_path(
            "    Path(log).exists()", "    Path(log).is_file()",
            "    Path(log).is_dir()", "    Path(log).is_symlink()",
            collects=asks_by_method)
        self.assertEqual(calls.opens, {"anchors_path": lines})

    def test_the_same_questions_through_os_path_pass(self):
        calls, _ = self.added_to_anchors_path(
            "    os.path.exists(log)", "    os.path.isfile(log)",
            "    os.path.isdir(log)", "    os.path.islink(log)",
            "    os.path.lexists(log)", collects=asks_by_method)
        self.assertEqual(calls.opens, {})


# The prefixes of the variables the scripts read for themselves; a name
# another program reads (CLAUDE_PROJECT_DIR, SSL_CERT_FILE) is not ours.
ENV_NAME = re.compile(
    r"\b(?:LOXODONTA|RECEIPTS|SUPERVISOR|RECEIVER)_[A-Z0-9_]*[A-Z0-9]\b")


def env_names_read(paths):
    """Every such name the scripts hold as a string: what os.environ is
    asked for. A name only a comment or a docstring mentions is not
    read, so it does not count."""
    names = set()
    for path in paths:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and ENV_NAME.fullmatch(node.value)):
                names.add(node.value)
    return names


def env_names_unread(pages, code, root):
    """(page relative to root, name) for each variable a page names that
    the code never reads."""
    read = env_names_read(code)
    unread = set()
    for page in pages:
        text = Path(page).read_text(encoding="utf-8")
        for name in ENV_NAME.findall(text):
            if name not in read:
                unread.add((Path(page).relative_to(root).as_posix(), name))
    return sorted(unread)


class DocumentedVariablesAreReadTest(unittest.TestCase):
    """A variable the docs tell an operator to set is one the scripts
    read (#397): two pages still named RECEIPTS_LOCK_TIMEOUT after the
    rename to LOXODONTA_LOCK_TIMEOUT, so setting it changed nothing.
    The ADRs are left out, since each records the names of its day."""

    def test_every_documented_variable_is_read(self):
        pages = sorted((REPO_ROOT / "docs").rglob("*.md"))
        pages.append(REPO_ROOT / "README.md")
        code = [RECORDER, SUPERVISOR, REPO_ROOT / "receiver.py"]
        code += sorted((REPO_ROOT / "adapters").glob("*.py"))
        self.assertEqual(env_names_unread(pages, code, REPO_ROOT), [])

    def test_a_name_only_a_comment_mentions_is_unread(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "PAGE.md"
            page.write_text("Set `LOXODONTA_HOME` or `RECEIPTS_GONE`.\n",
                            encoding="utf-8")
            script = root / "script.py"
            script.write_text(
                "import os\n"
                "# RECEIPTS_GONE was the old name.\n"
                'HOME = os.environ.get("LOXODONTA_HOME")\n',
                encoding="utf-8")
            self.assertEqual(env_names_unread([page], [script], root),
                             [("PAGE.md", "RECEIPTS_GONE")])


if __name__ == "__main__":
    unittest.main()
