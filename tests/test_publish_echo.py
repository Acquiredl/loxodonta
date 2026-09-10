"""Behavioral tests for `tools/publish_echo.py`: the loopback echo an
operator runs to read what `--publish-head` posts before wiring a real
remote (docs/HOOK.md, ADR-0025).

Every test starts the echo as a command on a free port, sends it a real
head through `loxodonta publish`, and reads what it printed. Nothing is
mocked: the body under test is the one the recorder actually builds.
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
ECHO = REPO_ROOT / "tools" / "publish_echo.py"

LISTENING = re.compile(r"http://127\.0\.0\.1:(\d+)/")

# What ADR-0025 says leaves the machine, and nothing besides.
PUBLISHED_FIELDS = {"head", "n", "session", "ts", "event", "text", "content"}


def run(*argv, cwd=None):
    return subprocess.run(
        [sys.executable, *map(str, argv)], cwd=cwd, capture_output=True,
        encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})


class EchoTest(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.log = self.root / "receipts-echo-test.jsonl"
        run(LOXODONTA, "init", "--log", self.log)
        run(LOXODONTA, "log", "--log", self.log,
            "--actor", "echo-test", "--action", "a receipt to give it a head")

    def start_echo(self, *extra):
        """The echo on a free port, and the port it actually bound."""
        proc = subprocess.Popen(
            [sys.executable, str(ECHO), "--port", "0", *extra],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.addCleanup(self.shut_down, proc)
        first = proc.stdout.readline()
        match = LISTENING.search(first)
        self.assertIsNotNone(match, f"no listening line, got {first!r}")
        return proc, int(match.group(1))

    @staticmethod
    def shut_down(proc):
        """Stop the echo and close its pipe, so a test that never posts
        to it leaves no process and no open file behind."""
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
        proc.stdout.close()

    def publish_to(self, port):
        return run(LOXODONTA, "publish", "--log", self.log,
                   f"http://127.0.0.1:{port}/head")

    def test_once_takes_one_post_and_exits(self):
        proc, port = self.start_echo("--once")
        published = self.publish_to(port)
        self.assertEqual(published.returncode, 0, published.stderr)
        printed = proc.communicate(timeout=30)[0]
        self.assertEqual(proc.returncode, 0)
        self.assertIn("POST /head", printed)

    def test_it_prints_the_head_the_recorder_sent(self):
        proc, port = self.start_echo("--once")
        self.publish_to(port)
        printed = proc.communicate(timeout=30)[0]
        head = run(LOXODONTA, "head", "--log", self.log).stdout
        digest = re.search(r"\b[0-9a-f]{64}\b", head)
        self.assertIsNotNone(digest, f"no head digest in {head!r}")
        self.assertIn(digest.group(0), printed)

    def test_the_fields_line_names_what_left_and_no_more(self):
        proc, port = self.start_echo("--once")
        self.publish_to(port)
        printed = proc.communicate(timeout=30)[0]
        line = [l for l in printed.splitlines() if l.startswith("fields: ")]
        self.assertEqual(len(line), 1, printed)
        fields = set(line[0][len("fields: "):].split(", "))
        self.assertEqual(fields, PUBLISHED_FIELDS)

    def test_no_path_or_project_name_reaches_the_echo(self):
        # The claim the tool exists to let an operator check: the body
        # carries no path off the machine, so the log's own path, which
        # the recorder plainly knows, must appear nowhere in it.
        proc, port = self.start_echo("--once")
        self.publish_to(port)
        printed = proc.communicate(timeout=30)[0]
        body = printed.split("POST /head", 1)[1]
        self.assertNotIn(self.log.name, body)
        self.assertNotIn(str(self.log.parent), body)

    def test_it_says_it_is_not_a_head_record(self):
        proc, _ = self.start_echo("--once")
        self.assertIn("not a head record", proc.stdout.readline())


if __name__ == "__main__":
    unittest.main()
