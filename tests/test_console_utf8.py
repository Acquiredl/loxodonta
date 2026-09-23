"""Every tool speaks UTF-8 on stdout and stderr, whatever the console
encoding (#294).

On Windows a piped stdout is written in the ANSI code page, cp1252, which
has no CJK and no emoji. One such character in a receipt made `digest`
exit 1 with nothing on stdout, and the SessionStart hook reads `digest`
through a pipe, so an agent could switch off start-of-session recall for
its project with one character in one action. `show`, `search`,
`timeline` and `loxodonta report` died the same way.

These tests force that console on every OS: the child runs with
PYTHONIOENCODING=cp1252, and what it printed is read as raw bytes and
decoded as UTF-8. The chain is the recorder's own, written by `init` and
`log` in a home of the test's own.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_console_utf8`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_supervisor import isolated_env

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECORDER = REPO_ROOT / "loxodonta.py"
RECEIVER = REPO_ROOT / "receiver.py"

CJK = "漢字"        # two ideographs cp1252 cannot encode
EMOJI = "\U0001F418"        # an elephant, outside the BMP as well
ACTION = f"Bash: echo {CJK} {EMOJI}"
SESSION = "cccc3333-3333-3333-3333-333333333333"


class Utf8ConsoleTest(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        self.env = isolated_env(root / "home")
        self.repo = root / "project"
        self.log = self.repo / "receipts" / f"receipts-{SESSION}.jsonl"
        self.log.parent.mkdir(parents=True)
        for args in (["init"],
                     ["log", "--actor", "agent", "--action", ACTION]):
            built = self.run_tool(RECORDER, *args, "--log", str(self.log),
                                  console="utf-8")
            self.assertEqual(built.returncode, 0, built.stderr)
        last = self.log.read_text(encoding="utf-8").splitlines()[-1]
        self.address = json.loads(last)["entry_hash"][:8]

    def run_tool(self, tool, *args, console="cp1252", stdin=None):
        """The tool run as a hook or a pipe runs it: stdout a pipe, in the
        console encoding named. Bytes back, never decoded by us first."""
        return subprocess.run(
            [sys.executable, str(tool), *args], input=stdin,
            capture_output=True,
            env={**self.env, "PYTHONIOENCODING": console})

    def assertSpeaksUtf8(self, done):
        # The child's stderr read leniently, so a traceback still shows.
        said = done.stderr.decode("utf-8", "replace")
        self.assertEqual(done.returncode, 0, said)
        self.assertNotIn("UnicodeEncodeError", said)
        out = done.stdout.decode("utf-8")  # raises if it is not UTF-8
        self.assertIn(CJK, out)
        self.assertIn(EMOJI, out)
        return out

    def test_digest_prints_the_action_through_a_cp1252_pipe(self):
        out = self.assertSpeaksUtf8(
            self.run_tool(SUPERVISOR, "digest", "--repo", str(self.repo)))
        self.assertIn(self.address, out)

    def test_show_prints_the_entry_through_a_cp1252_pipe(self):
        self.assertSpeaksUtf8(self.run_tool(
            SUPERVISOR, "show", self.address, "--repo", str(self.repo)))

    def test_search_finds_and_prints_the_characters_through_a_cp1252_pipe(self):
        out = self.assertSpeaksUtf8(self.run_tool(
            SUPERVISOR, "search", CJK, "--repo", str(self.repo)))
        self.assertIn(self.address, out)

    def test_timeline_prints_the_action_through_a_cp1252_pipe(self):
        self.assertSpeaksUtf8(self.run_tool(
            SUPERVISOR, "timeline", self.address, "--repo", str(self.repo)))

    def test_report_prints_the_action_through_a_cp1252_pipe(self):
        self.assertSpeaksUtf8(
            self.run_tool(RECORDER, "report", "--log", str(self.log)))

    def test_an_error_naming_the_characters_reaches_stderr_as_utf8(self):
        # stderr is a pipe too: a message that quotes a path with these
        # characters in it must arrive, not die while being written.
        missing = str(self.repo / f"{CJK}{EMOJI}.jsonl")
        done = self.run_tool(RECORDER, "report", "--log", missing)
        said = done.stderr.decode("utf-8")  # raises if it is not UTF-8
        self.assertNotIn("Traceback", said)
        self.assertIn(CJK, said)
        self.assertIn(EMOJI, said)

    def test_the_receiver_speaks_utf8_too(self):
        # Its one verb serves forever, so its help stands in: what matters
        # is that it starts in UTF-8 whatever the console said.
        done = self.run_tool(RECEIVER, "--help")
        self.assertEqual(done.returncode, 0,
                         done.stderr.decode("utf-8", "replace"))
        done.stdout.decode("utf-8")

    def test_mcp_frames_stay_utf8_json_lines_under_a_cp1252_console(self):
        # The mcp verb writes its own bytes to the wire; the console
        # encoding must not reach them, nor the text layer set up at start.
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "search",
                              "arguments": {"text": CJK,
                                            "repo": str(self.repo)}}}
        done = self.run_tool(
            SUPERVISOR, "mcp", "--repo", str(self.repo),
            stdin=(json.dumps(request) + "\n").encode("utf-8"))
        self.assertEqual(done.returncode, 0,
                         done.stderr.decode("utf-8", "replace"))
        lines = done.stdout.split(b"\n")
        # One reply, one line, ended by a bare newline: no CR on any OS.
        self.assertEqual(lines[-1], b"")
        self.assertEqual(len(lines), 2, done.stdout)
        self.assertNotIn(b"\r", done.stdout)
        reply = json.loads(lines[0].decode("utf-8"))
        self.assertEqual(reply["id"], 1)
        text = reply["result"]["content"][0]["text"]
        self.assertIn(CJK, text)
        self.assertIn(EMOJI, text)


if __name__ == "__main__":
    unittest.main()
