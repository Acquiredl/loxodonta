"""The front-door pin (#129): every command the README shows still runs,
and every verdict it prints is still what the tool says.

The README is the front door, and the arc's rule is that everything on it
is true of `main`. This test reads the README, finds the fenced blocks
marked `<!-- pin:NAME -->`, runs their commands in a temporary directory
against the working tree's `loxodonta.py` and `supervisor.py`, and checks
the output and exit codes the README claims. A renamed flag, a changed
verdict line, or a demo that no longer breaks makes the suite fail and
names the block. No mocking: the commands run exactly as written, the way
a reader would run them.

The blocks pinned:

- `tamper-demo` — the first-screen transcript: record, verify VALID,
  tamper one entry, verify BROKEN at that entry with exit 1.
- `quickstart-tryit` — the by-hand chain a reader copies into a folder.
- `bad-day-check` — verify and drill over the committed demo chain.

Commands run cross-platform: `python loxodonta.py ...` runs through the
copy in the working directory, and `sed -i 's/A/B/' FILE` is applied as
the substitution it expresses (Windows runners have no `sed`). Nothing is
rewritten: the bad-day block runs as written, from the root of a copy of
the repository's files it names, so the drill's sandbox lands in the copy
and the repo is never touched (#297).
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_readme_pins`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_supervisor import isolated_env

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

# A verify verdict on stdout implies an exit code (README "Exit codes").
VERDICT_EXIT = [
    ("VALID", 0),
    ("BROKEN", 1),
    ("MODIFIED-SINCE-LOGGED", 2),
    ("FILES-DIVERGED", 2),
    ("HEAD-MISMATCH", 3),
]

MARKER = re.compile(r"<!--\s*pin:([A-Za-z0-9-]+)\s*-->")
SED = re.compile(r"""^sed -i (['"])s/(.+?)/(.*?)/\1 (\S+)$""")


def pinned_blocks(text):
    """Every `<!-- pin:NAME -->` marker mapped to the lines of the fenced
    block that follows it. Located by marker, never by line number."""
    lines = text.splitlines()
    blocks = {}
    for i, line in enumerate(lines):
        found = MARKER.search(line)
        if not found:
            continue
        fence = next((j for j in range(i + 1, len(lines))
                      if lines[j].strip() == "```"), None)
        assert fence is not None, f"pin:{found.group(1)} has no code fence"
        close = next((j for j in range(fence + 1, len(lines))
                      if lines[j].strip() == "```"), None)
        assert close is not None, f"pin:{found.group(1)} fence is unclosed"
        blocks[found.group(1)] = lines[fence + 1:close]
    return blocks


def strip_comment(command):
    """Drop a trailing `   # ...` note the README adds for the reader.
    Only whitespace-then-hash outside the command's own quotes; the
    commands here carry no `#` inside quotes."""
    return re.split(r"\s{2,}#", command, maxsplit=1)[0].rstrip()


def implied_exit(output_lines):
    """The exit code a block's expected output implies, or 0."""
    joined = "\n".join(output_lines)
    for token, code in VERDICT_EXIT:
        if token in joined:
            return code
    return 0


class Runner:
    """Runs one pinned command in `cwd`, cross-platform. Raises
    AssertionError naming the block when a command it does not recognize
    appears, so an unrunnable line can never pass in silence."""

    def __init__(self, name, cwd, env=None):
        self.name = name
        self.cwd = Path(cwd)
        self.env = env

    def fail(self, why):
        raise AssertionError(f"[pin:{self.name}] {why}")

    def run(self, command):
        command = strip_comment(command)
        argv = command.split()
        if argv[:1] == ["sed"]:
            return self._sed(command)
        if argv[:1] == ["python"]:
            # `python loxodonta.py ...` / `python supervisor.py ...` run
            # through the copies placed in cwd, or the repo's own files.
            import shlex
            parts = shlex.split(command, posix=True)
            return subprocess.run(
                [sys.executable, *parts[1:]], cwd=str(self.cwd),
                capture_output=True, text=True, env=self.env)
        self.fail(f"don't know how to run {command!r}")

    def _sed(self, command):
        m = SED.match(command)
        if not m:
            self.fail(f"unrecognized sed form: {command!r}")
        _, old, new, name = m.groups()
        target = self.cwd / name
        if not target.is_file():
            self.fail(f"sed target {name!r} is not in the working dir")
        text = target.read_text(encoding="utf-8")
        if old not in text:
            self.fail(f"sed pattern {old!r} not found in {name}")
        target.write_text(text.replace(old, new), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")


class TranscriptPinTest(unittest.TestCase):
    """A `$`-prefixed block: each command, then the output the README
    shows, then the exit code that output implies."""

    def check_transcript(self, name, lines, cwd):
        runner = Runner(name, cwd)
        steps, command, expected = [], None, []
        for line in lines:
            if line.startswith("$ "):
                if command is not None:
                    steps.append((command, expected))
                command, expected = line[2:], []
            elif command is not None and line.strip():
                expected.append(line)
        if command is not None:
            steps.append((command, expected))
        self.assertTrue(steps, f"[pin:{name}] no $ commands in the block")
        for command, expected in steps:
            done = runner.run(command)
            for want in expected:
                self.assertIn(
                    want.strip(), (done.stdout + done.stderr),
                    f"[pin:{name}] {command!r} did not print {want.strip()!r}"
                    f"\n--- got ---\n{done.stdout}{done.stderr}")
            self.assertEqual(
                done.returncode, implied_exit(expected),
                f"[pin:{name}] {command!r} exited {done.returncode}, the "
                f"README implies {implied_exit(expected)}")

    def test_tamper_demo_records_verifies_and_breaks(self):
        blocks = pinned_blocks(README.read_text(encoding="utf-8"))
        self.assertIn("tamper-demo", blocks, "the demo block lost its marker")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(LOXODONTA, Path(tmp) / "loxodonta.py")
            self.check_transcript("tamper-demo", blocks["tamper-demo"], tmp)


class CommandListPinTest(unittest.TestCase):
    """A block with no `$`: each line is a command that must exit 0
    (a comment may explain it, but the chain here stays intact)."""

    def check_commands(self, name, lines, cwd, tool_copies=(), env=None):
        runner = Runner(name, cwd, env)
        for tool in tool_copies:
            shutil.copy(tool, Path(cwd) / tool.name)
        ran = 0
        for line in lines:
            if not line.strip():
                continue
            done = runner.run(line)
            self.assertEqual(
                done.returncode, 0,
                f"[pin:{name}] {strip_comment(line)!r} exited "
                f"{done.returncode}\n{done.stdout}{done.stderr}")
            ran += 1
        self.assertTrue(ran, f"[pin:{name}] the block ran no commands")

    def test_quickstart_tryit_block_runs_clean(self):
        blocks = pinned_blocks(README.read_text(encoding="utf-8"))
        self.assertIn("quickstart-tryit", blocks,
                      "the quick-start try-it block lost its marker")
        with tempfile.TemporaryDirectory() as tmp:
            self.check_commands("quickstart-tryit",
                                blocks["quickstart-tryit"], tmp,
                                tool_copies=(LOXODONTA,))

    def test_bad_day_check_verifies_and_drills(self):
        blocks = pinned_blocks(README.read_text(encoding="utf-8"))
        self.assertIn("bad-day-check", blocks,
                      "the bad-day check block lost its marker")
        # The lines a reader copies, run as written from the root of a
        # clone (#297): a copy of the two tools and docs/demo, so the
        # drill's sandbox (<root>/.supervisor-drill) lands in the copy
        # and never in this working tree. The drill reads the coverage
        # marker to name the tier, so every line runs in a home of its
        # own, never the machine's (#242).
        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "clone"
            shutil.copytree(REPO_ROOT / "docs" / "demo",
                            clone / "docs" / "demo",
                            ignore=shutil.ignore_patterns(".supervisor-drill"))
            self.check_commands("bad-day-check", blocks["bad-day-check"],
                                clone, tool_copies=(LOXODONTA, SUPERVISOR),
                                env=isolated_env(Path(tmp) / "home"))
            self.assertTrue(
                (clone / "docs" / "demo" / ".supervisor-drill").is_dir(),
                "[pin:bad-day-check] the drill line ran no drill")


class PinGuardTest(unittest.TestCase):
    """The pin itself fails loudly when the README and the tool disagree,
    and names the block that drifted."""

    def test_a_wrong_expected_verdict_fails_naming_the_block(self):
        # A README that claimed the tamper leaves the chain VALID would be
        # a lie; the pin must catch it, not wave it through.
        doctored = ["$ python loxodonta.py init",
                    "initialized receipts.jsonl",
                    "$ python loxodonta.py log --actor a --action x",
                    "logged entry 1",
                    "$ sed -i 's/x/y/' receipts.jsonl",
                    "$ python loxodonta.py verify",
                    "VALID"]  # the lie: it is BROKEN after the edit
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(LOXODONTA, Path(tmp) / "loxodonta.py")
            with self.assertRaises(AssertionError) as caught:
                TranscriptPinTest().check_transcript("demo-probe",
                                                     doctored, tmp)
        self.assertIn("demo-probe", str(caught.exception))

    def test_an_unknown_command_fails_naming_the_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AssertionError) as caught:
                CommandListPinTest().check_commands(
                    "junk", ["rm -rf /"], tmp)
        self.assertIn("junk", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
