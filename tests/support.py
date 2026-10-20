"""What every test module shares: where the tools are, one way to run
one, the environment that keeps a start inside homes of the test's own,
and the temporary folders a test stands in.

The tools are run as a user runs them, through the command line, never
imported (ADR-0035). One `run` for all of them, so the suite agrees on
how a child's output is read: UTF-8 on both pipes whatever the console
(#294), and a bound on every start, so a regression fails and never
hangs.

Importing this module arms the home guard (tests/home_guard.py): a verb
that reads or writes machine-wide state is refused a start whose homes
are not a temporary folder of the test's own. Every module that starts
one of those verbs imports from here, so the guard is on whether the
suite runs under discovery or one module at a time, and `isolated_env`
is the way to give such a start its homes. Not a test module: discovery
collects `test_*.py` only.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This folder on sys.path, so `home_guard` resolves when a test module
# runs alone (`python -m unittest tests.test_cli`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import home_guard  # noqa: E402

home_guard.arm()

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECEIVER = REPO_ROOT / "receiver.py"
VERIFIER = REPO_ROOT / "verifier.py"


def clean_env(**knobs):
    """This process's environment without its proxy variables, so urllib
    in a child reaches a fake calendar or receiver on 127.0.0.1 directly,
    the child told to write UTF-8 (PYTHONIOENCODING), so what it prints
    reads the same on every console (#294), and `knobs` on top. What
    `run` starts a child from unless given a whole environment."""
    env = {name: value for name, value in os.environ.items()
           if name.lower() not in ("http_proxy", "https_proxy",
                                   "all_proxy", "no_proxy")}
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(knobs)
    return env


def isolated_env(home, **knobs):
    """`clean_env` with every home the tools read pointed inside `home`:
    the store, the user's settings and Codex's hooks, so a scan reads
    neither this machine's own wiring nor its coverage marker, and the
    folder that stands in for the harness's managed settings folder
    (#259), which nothing creates until a test asks for a managed
    install, and the folder that stands in for the managed install's
    copy of the recorder (ADR-0042). Pair it with a `--witness` under a
    temporary folder. The
    knobs land last, so a test that keeps its store or its project
    somewhere of its own names it here (`LOXODONTA_HOME=...`,
    `CLAUDE_PROJECT_DIR=...`). Every start of scan, serve, calibrate,
    drill, export or package (#242), and of adopt, hook, install-hook or
    uninstall-hook (#274), goes through this or sets all four homes
    itself, and the managed folder where the verb reads it; the home
    guard (tests/home_guard.py) refuses one that does neither."""
    env = clean_env(LOXODONTA_HOME=str(Path(home) / ".loxodonta"),
                    HOME=str(home), USERPROFILE=str(home),
                    CODEX_HOME=str(Path(home) / ".codex"),
                    LOXODONTA_MANAGED_DIR=str(Path(home) / "managed"),
                    LOXODONTA_PROGRAM_DIR=str(Path(home) / "program"))
    env.pop("CLAUDE_PROJECT_DIR", None)
    env.update(knobs)
    return env


def temp_folder(case):
    """A temporary folder of the test's own, removed when it ends (when
    the class does, given a class). Resolved: macOS's temp root is a
    symlink (/var -> /private/var), and a tool that judges a path by its
    spelling against the cwd it reports is reporting the real one."""
    folder = tempfile.TemporaryDirectory()
    cleanup = (case.addClassCleanup if isinstance(case, type)
               else case.addCleanup)
    cleanup(folder.cleanup)
    return Path(folder.name).resolve()


def run(tool, *args, cwd=None, env=None, stdin=None, timeout=120,
        check=False, console=None, isolated=False, preexec_fn=None):
    """`tool` run as a user runs it, `python tool args...`, both pipes
    captured, as the CompletedProcess.

    `env` is the whole environment the child starts from, `clean_env()`
    unless given, so what it leaves out stays out. The child is told to
    write UTF-8 (PYTHONIOENCODING), and both pipes are read as UTF-8
    with replacement and newlines normalized, as text mode reads them,
    whatever console this process runs in (#294). `stdin` is text, or
    bytes for a payload that is not UTF-8 on purpose. `timeout` bounds
    every start, so a regression fails and never hangs.

    `console` names an encoding to tell the child instead of UTF-8, and
    the pipes then come back as the bytes they carried, for a test of
    what a tool writes through such a console. `isolated` runs the
    interpreter with -I, as a recipient is told to run the verifier
    (ADR-0035): no site-packages, and no PYTHON* variable read, the
    encoding told above included. `check` and `preexec_fn` are
    subprocess's own: raise on a non-zero exit, and a hook run in the
    child before the tool is (POSIX only), for a test that limits what
    it may write."""
    command = [sys.executable, *(["-I"] if isolated else []), str(tool),
               *(str(arg) for arg in args)]
    environment = {**(clean_env() if env is None else env),
                   "PYTHONIOENCODING": console or "utf-8"}
    if isinstance(stdin, str):
        stdin = stdin.encode("utf-8")
    done = subprocess.run(command, cwd=cwd, env=environment, input=stdin,
                          capture_output=True, timeout=timeout, check=check,
                          preexec_fn=preexec_fn)
    if console is None:
        done.stdout = as_text(done.stdout)
        done.stderr = as_text(done.stderr)
    return done


def as_text(data):
    """`data` as text mode reads a pipe: UTF-8 with replacement, every
    line ending a bare newline."""
    return (data.decode("utf-8", "replace")
            .replace("\r\n", "\n").replace("\r", "\n"))


class StoreCase(unittest.TestCase):
    """A test with a chain of its own. `workdir` is a temporary folder
    where the recorder has run `init`, so `receipts.jsonl` is there and
    the verbs that take no `--log` find it from the cwd. `home` is a
    second temporary folder, outside the workdir, and `env` points every
    home the tools read at it (`isolated_env`): a home inside the
    workdir would sit in the census of a scan of it."""

    def setUp(self):
        self.workdir = temp_folder(self)
        self.home = temp_folder(self)
        self.env = isolated_env(self.home)
        made = run(LOXODONTA, "init", cwd=self.workdir)
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
