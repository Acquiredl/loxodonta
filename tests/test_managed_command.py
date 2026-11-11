"""A managed hook takes its orders from its command (ADR-0043).

`install-hook --managed` writes `--managed` on the hook's and the
digest's commands. Under that word the recorder and the digest read no
environment variable but CLAUDE_PROJECT_DIR, and the recorder sends
through no proxy the environment names. Each test runs the same command
with the word and without it, under one environment that sets the
variable, and says where the two differ.

A managed hook ignores LOXODONTA_HOME, so these tests move the home
folder itself (HOME and USERPROFILE), as the ADR says the suite does.
It also ignores LOXODONTA_MANAGED_DIR, so it reads the telemetry pin
from the harness's own folder: no test here asserts on the entries a
pin there could add.
"""

import json
import socket
import sys
import threading
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_managed_command`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import LOXODONTA, SUPERVISOR, isolated_env, run, temp_folder  # noqa: E402

from test_publish import FakeReceiver, FakeReceiverHandler  # noqa: E402

SESSION = "sess-managed-0043"
CHAIN_TYPE = "application/x-ndjson"


def dead_port():
    """A port on 127.0.0.1 nothing listens on: bound, then let go."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ManagedCommandBase(unittest.TestCase):

    def setUp(self):
        self.work = temp_folder(self)
        self.home = self.work / "home"
        self.home.mkdir()
        self.project = self.work / "project"
        self.project.mkdir()
        # Where LOXODONTA_HOME points: another store than the home's.
        self.elsewhere = self.work / "elsewhere"
        self.transcript = self.work / "transcript.jsonl"
        self.transcript.write_bytes(b"page one\n")
        self.env = isolated_env(self.home, LOXODONTA_HOME=str(self.elsewhere),
                                CLAUDE_PROJECT_DIR=str(self.project))

    def hook(self, event, *flags, env=None, **payload):
        body = {"session_id": SESSION, "hook_event_name": event,
                "transcript_path": str(self.transcript), **payload}
        if event == "PostToolUse":
            body.update(tool_name="Bash", tool_input={"command": "ls"},
                        tool_response={})
        return run(LOXODONTA, "hook", *flags, cwd=self.project,
                   stdin=json.dumps(body), env=env or self.env, timeout=60)

    def chains_under(self, store):
        """The session's chains under one store, by path."""
        return sorted(p for p in (store / "receipts").rglob(
            f"receipts-{SESSION}*.jsonl")
            if p.name.count(".") == 1) if store.exists() else []

    def entries(self, chain):
        return [json.loads(line) for line in
                chain.read_text(encoding="utf-8").splitlines()]


class TheStoreTest(ManagedCommandBase):

    def test_under_the_word_the_store_is_the_home_folders(self):
        # LOXODONTA_HOME set in the environment the session launched
        # with: the managed hook writes under ~/.loxodonta all the same.
        done = self.hook("PostToolUse", "--managed")

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(self.chains_under(self.home / ".loxodonta")), 1)
        self.assertEqual(self.chains_under(self.elsewhere), [])

    def test_without_the_word_the_store_follows_the_variable(self):
        done = self.hook("PostToolUse")

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(self.chains_under(self.elsewhere)), 1)
        self.assertEqual(self.chains_under(self.home / ".loxodonta"), [])

    def test_under_the_word_the_clock_is_not_the_environments(self):
        # SOURCE_DATE_EPOCH=0 dates a plain hook's entries 1970; the
        # managed hook's carry the wall clock.
        env = {**self.env, "SOURCE_DATE_EPOCH": "0"}

        self.hook("PostToolUse", "--managed", env=env)
        self.hook("PostToolUse", env=env)

        (managed,) = self.chains_under(self.home / ".loxodonta")
        (plain,) = self.chains_under(self.elsewhere)
        self.assertNotEqual(self.entries(managed)[-1]["ts"][:4], "1970")
        self.assertEqual(self.entries(plain)[-1]["ts"],
                         "1970-01-01T00:00:00Z")


class TheLockTest(ManagedCommandBase):

    def held_for(self, chain, seconds):
        """Hold the chain's lock now, and let it go after `seconds`."""
        lock = Path(str(chain) + ".lock")
        lock.write_text("held\n", encoding="utf-8")
        timer = threading.Timer(seconds, lock.unlink)
        timer.start()
        self.addCleanup(timer.cancel)

    def test_under_the_word_the_lock_waits_its_ten_seconds(self):
        # LOXODONTA_LOCK_TIMEOUT=0.5 and a lock held for two seconds: the
        # managed hook waits it out.
        self.assertEqual(self.hook("PostToolUse", "--managed").returncode, 0)
        (chain,) = self.chains_under(self.home / ".loxodonta")
        self.held_for(chain, 2.0)

        done = self.hook("PostToolUse", "--managed",
                         env={**self.env, "LOXODONTA_LOCK_TIMEOUT": "0.5"})

        self.assertEqual(done.returncode, 0, done.stderr)

    def test_without_the_word_the_lock_waits_what_the_variable_says(self):
        # The same lock: the plain hook gives up after half a second, 75.
        self.assertEqual(self.hook("PostToolUse").returncode, 0)
        (chain,) = self.chains_under(self.elsewhere)
        self.held_for(chain, 2.0)

        done = self.hook("PostToolUse",
                         env={**self.env, "LOXODONTA_LOCK_TIMEOUT": "0.5"})

        self.assertEqual(done.returncode, 75, done.stderr)


class TheSendTest(ManagedCommandBase):

    def setUp(self):
        super().setUp()
        self.receiver = FakeReceiver(("127.0.0.1", 0), FakeReceiverHandler)
        self.receiver.received = []
        self.receiver.delay = 0
        thread = threading.Thread(target=self.receiver.serve_forever,
                                  daemon=True)
        thread.start()
        self.addCleanup(self.receiver.server_close)
        self.addCleanup(self.receiver.shutdown)
        self.url = f"http://127.0.0.1:{self.receiver.server_address[1]}/hook"

    def test_under_the_word_a_proxy_in_the_environment_is_not_taken(self):
        # HTTPS_PROXY and HTTP_PROXY name a port nothing listens on: the
        # plain hook's publish goes there and is lost, the managed hook's
        # arrives at the receiver.
        proxy = f"http://127.0.0.1:{dead_port()}"
        env = {**self.env, "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy,
               "https_proxy": proxy, "http_proxy": proxy}
        for flags, arrived in ((("--managed",), 1), ((), 0)):
            with self.subTest(flags=flags):
                self.receiver.received.clear()
                self.hook("PostToolUse", *flags, env=env)

                done = self.hook("SessionEnd", *flags, "--publish", self.url,
                                 env=env, reason="prompt_input_exit")

                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(len(self.receiver.received), arrived)

    def test_under_the_word_a_send_carries_its_default_batch(self):
        # LOXODONTA_CHAIN_BATCH_BYTES=1, smaller than any entry, to a
        # remote that does not say what it holds: the plain hook sends the
        # chain's last entry, which goes whatever the cap, and then from
        # the memo nothing, every entry being over that cap; the managed
        # hook sends under the default, the chain's last entry and then
        # the chain in one batch (ADR-0045 ruling 4).
        env = {**self.env, "LOXODONTA_CHAIN_BATCH_BYTES": "1"}
        for flags, sent in ((("--managed",), 2), ((), 1)):
            with self.subTest(flags=flags):
                self.receiver.received.clear()
                for _ in range(3):
                    self.hook("PostToolUse", *flags, env=env)

                done = self.hook("SessionEnd", *flags, "--publish-chain",
                                 self.url, env=env,
                                 reason="prompt_input_exit")

                self.assertEqual(done.returncode, 0, done.stderr)
                batches = [r for r in self.receiver.received
                           if r["content_type"] == CHAIN_TYPE]
                self.assertEqual(len(batches), sent)


class TheDigestTest(ManagedCommandBase):

    def test_under_the_word_the_digest_reads_the_home_folders_store(self):
        # A chain in the store LOXODONTA_HOME names: the plain digest
        # renders it, the managed one reads ~/.loxodonta, which is empty.
        self.assertEqual(self.hook("PostToolUse").returncode, 0)

        plain = run(SUPERVISOR, "digest", env=self.env, timeout=60)
        managed = run(SUPERVISOR, "digest", "--managed", env=self.env,
                      timeout=60)

        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertIn("recall digest", plain.stdout)
        self.assertEqual(managed.returncode, 0, managed.stderr)
        self.assertEqual(managed.stdout, "")

    def test_under_the_word_a_malformed_knob_does_not_silence_it(self):
        # The supervisor reads its knobs at import, before the parser:
        # SUPERVISOR_HOT_TIMES=x stops a plain digest with 64, and a
        # managed one never reads it.
        env = {**self.env, "SUPERVISOR_HOT_TIMES": "x"}

        plain = run(SUPERVISOR, "digest", env=env, timeout=60)
        managed = run(SUPERVISOR, "digest", "--managed", env=env, timeout=60)

        self.assertEqual(plain.returncode, 64, plain.stderr)
        self.assertIn("SUPERVISOR_HOT_TIMES", plain.stderr)
        self.assertEqual(managed.returncode, 0, managed.stderr)


class TheWordIsWholeTest(ManagedCommandBase):
    """The word is read from the command at import, before the parser, so
    the parser takes it whole or not at all: an abbreviation argparse
    would expand is refused, and the run does nothing."""

    def test_the_hook_refuses_an_abbreviated_word_and_writes_nothing(self):
        done = self.hook("PostToolUse", "--manag")

        self.assertEqual(done.returncode, 64, done.stdout + done.stderr)
        self.assertIn("--manag", done.stderr)
        self.assertEqual(self.chains_under(self.home / ".loxodonta"), [])
        self.assertEqual(self.chains_under(self.elsewhere), [])

    def test_the_digest_refuses_an_abbreviated_word_and_says_nothing(self):
        self.assertEqual(self.hook("PostToolUse").returncode, 0)

        done = run(SUPERVISOR, "digest", "--manag", env=self.env, timeout=60)

        self.assertEqual(done.returncode, 64, done.stdout + done.stderr)
        self.assertIn("--manag", done.stderr)
        self.assertEqual(done.stdout, "")


if __name__ == "__main__":
    unittest.main()
