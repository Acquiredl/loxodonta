"""The home guard (#242, #274): no test starts a verb that reads or
writes machine-wide state with this machine's home.

`scan` reads the coverage marker from the machine-wide store whatever
`--root` says (ADR-0030), and the harness settings beside the default
witness; `serve`, `export` and `package` read both, `drill` the marker's
profile, and `calibrate` with no `--root` the store's own baseline. A
test that starts one of them with the environment it inherited is
judging the machine it runs on. BeforeMemoryTest did that: green in CI,
whose runner has never run `install-hook`, and four failures on every
machine that had.

The guard is an audit hook on `subprocess.Popen`, which `subprocess.run`
and every helper in this suite go through, so it sees each start of
those six verbs whichever helper made it. It refuses one whose homes are
not a temporary folder of the test's own, before the process exists,
and the refusal fails the test that made the start and names its file
and line.

Since #274 it covers the verbs that write into a home as well: the
recorder's `hook` (a drawer in the store, named by CLAUDE_PROJECT_DIR or
the payload's `cwd`), `install-hook` and `uninstall-hook` (the harness
settings, Codex's hooks file and the coverage marker), and the
supervisor's `adopt` (chains moved into the store). What opened #274:
with LOXODONTA_HOME and CODEX_HOME exported, one run of the suite wrote
seven epochs into that coverage marker and a hooks.json into that Codex
home. A `hook` is refused a CLAUDE_PROJECT_DIR the test did not choose
as well, since that names the drawer it writes into; the other recorder
verbs never read it.

The recall verbs (`digest`, `show`, `search`, `timeline`, `mcp`) read
the home and write nothing to it, so their tests are isolated but not
guarded. A process started another way (`os.system`, `os.spawn*`; this
suite uses neither) passes the guard unseen.

tests/test_supervisor.py arms it, and every suite that starts one of
those verbs imports from there (directly, or through test_anchor or
test_recall), so the guard is on whether the suite runs under discovery
or one module at a time. `isolated_env` there is the way to give a start
its homes; a start that sets all four by hand passes too. Every importer
names this module `home_guard`, so there is one of it and the hook goes
in once. Not a test module: discovery collects `test_*.py` only.
"""

import os
import re
import sys
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# The supervisor verbs that read machine-wide state: the coverage marker,
# the harness settings or the store's baseline.
HOME_READERS = {"scan", "serve", "calibrate", "drill", "export", "package"}
# Every home those verbs reach: the store, the user's home as either
# platform spells it (Path.home() reads USERPROFILE on Windows and HOME
# elsewhere, and the default witness hangs off it), and Codex's hooks.
HOMES = ("LOXODONTA_HOME", "HOME", "USERPROFILE", "CODEX_HOME")
# The verb after `supervisor.py` in the command. On Windows subprocess
# hands the audit hook one command line, elsewhere a list, which is
# joined with spaces first, so one pattern reads both.
SUPERVISOR_VERB = re.compile(r'(?:^|[\s"/\\])supervisor\.py"?\s+"?([a-z-]+)')
# The verbs that write into a home (#274): the supervisor's one, and the
# recorder's three, whose verb after `loxodonta.py` is read the same way.
SUPERVISOR_WRITERS = {"adopt"}
RECORDER_WRITERS = {"hook", "install-hook", "uninstall-hook"}
RECORDER_VERB = re.compile(r'(?:^|[\s"/\\])loxodonta\.py"?\s+"?([a-z-]+)')


def inside_the_temp_root(value, cwd):
    """Whether `value` names a folder under the temp root, which is where
    every test's own home lives and where no machine keeps its real one.
    A relative `value` is read from `cwd`, as the child will read it."""
    if not value:
        return False
    temp = os.path.normcase(os.path.realpath(tempfile.gettempdir()))
    folder = os.path.normcase(os.path.realpath(os.path.join(cwd, value)))
    try:
        return os.path.commonpath([folder, temp]) == temp
    except ValueError:  # another drive, on Windows: not under it
        return False


def strays(env, cwd, project_too=True):
    """The names in `env` that could still reach this machine's home: a
    home unset, outside the temp root, or no different from the one this
    process was started with; and, when `project_too`, a
    CLAUDE_PROJECT_DIR the test did not choose.

    Unset LOXODONTA_HOME and CODEX_HOME are the exception, when HOME and
    USERPROFILE both pass: the tools then fall back to `~/.loxodonta` and
    `~/.codex`, inside the test's home, and a test of that fallback needs
    them unset (#274).

    "Started with" is the environment as the guard was armed, not as it
    is now: a test that points os.environ at a home of its own for an
    in-process adapter has chosen that home, and the machine's is the one
    it replaced. The price: a test that changed os.environ and never put
    it back would pass every start after it that inherits the change, so
    such a test restores it in a cleanup."""
    def stray(name):
        value = env.get(name)
        return (not inside_the_temp_root(value, cwd)
                or value == _started_with.get(name))
    found = [name for name in HOMES if stray(name)]
    if "HOME" not in found and "USERPROFILE" not in found:
        found = [name for name in found
                 if name not in ("LOXODONTA_HOME", "CODEX_HOME")
                 or env.get(name)]
    if (project_too and env.get("CLAUDE_PROJECT_DIR")
            and stray("CLAUDE_PROJECT_DIR")):
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
    """The audit hook. Raising here fails the test that made the start,
    at the start."""
    if event != "subprocess.Popen":
        return
    _, command, cwd, env = args
    if isinstance(command, (str, bytes, os.PathLike)):
        command = os.fsdecode(command)
    else:
        command = " ".join(os.fsdecode(part) for part in command)
    tool, verb = "supervisor.py", SUPERVISOR_VERB.search(command)
    if verb is None or verb.group(1) not in HOME_READERS | SUPERVISOR_WRITERS:
        tool, verb = "loxodonta.py", RECORDER_VERB.search(command)
        if verb is None or verb.group(1) not in RECORDER_WRITERS:
            return
    # Only `hook`, of the recorder's verbs, reads CLAUDE_PROJECT_DIR.
    names = strays(os.environ if env is None else env,
                   os.getcwd() if cwd is None else os.fsdecode(cwd),
                   project_too=tool == "supervisor.py"
                   or verb.group(1) == "hook")
    if names:
        raise AssertionError(
            "%s %s started with this machine's %s (#242, the "
            "home guard). Give it isolated_env(home) from "
            "tests/test_supervisor.py, with the home in a temporary folder "
            "of the test's own. Started from:\n  %s"
            % (tool, verb.group(1), ", ".join(names),
               "\n  ".join(started_from()) or "outside tests/"))


_armed = False
# The machine's homes, as this process was started with them.
_started_with = {}


def arm():
    """Install the guard; a second call changes nothing. An audit hook
    stays for the life of the process, so the whole run is guarded from
    the first import that arms it."""
    global _armed
    if not _armed:
        _started_with.update(
            (name, os.environ[name])
            for name in HOMES + ("CLAUDE_PROJECT_DIR",) if name in os.environ)
        sys.addaudithook(refuse_this_machines_home)
        _armed = True
