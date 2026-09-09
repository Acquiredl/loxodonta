"""Behavioral tests for the keeper's half of publishing (ADR-0025 ruling 3,
issue #182).

The session-end publish covers a session that reached its end. The bad
day is the other case: the hook was stripped, so no session end ever
fired. The supervisor's keeper, on `--publish-every`, posts an aged head
once, remembers what it posted in a memo beside the chain, and the scan
report says how long since a head last left the machine at all. Every
test drives the public CLI against a local fake receiver: no network,
ever, and never internals.
"""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from test_anchor import clean_env
from test_publish import (FakeReceiver, FakeReceiverHandler,
                          RedirectingHandler)
from test_supervisor import (chain_head, chains_by_session, keeper_env,
                             make_chain, run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

PUBLISHED_FIELDS = {"head", "n", "session", "ts", "event", "text", "content"}


def memo_of(log):
    """The publish memo beside a chain, parsed; [] when none was written."""
    memo = Path(str(log) + ".published.jsonl")
    if not memo.exists():
        return []
    return [json.loads(line) for line in
            memo.read_text(encoding="utf-8").splitlines()]


class ReceiverFixture(unittest.TestCase):
    """A temp root of legacy repos and a fake webhook that keeps every
    POST it was sent."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.receiver = FakeReceiver(("127.0.0.1", 0), FakeReceiverHandler)
        self.receiver.received = []
        self.receiver.delay = 0
        self.receiver.url = (
            f"http://127.0.0.1:{self.receiver.server_address[1]}/hook")
        threading.Thread(target=self.receiver.serve_forever,
                         daemon=True).start()
        self.addCleanup(self.receiver.server_close)
        self.addCleanup(self.receiver.shutdown)

    def body(self, index=0):
        return json.loads(self.receiver.received[index]["raw"].decode("utf-8"))


class PublishCommandTest(ReceiverFixture):
    """`loxodonta publish --log LOG URL`: the operator's (and the
    keeper's) one POST of the current head, remembered in the memo."""

    def publish(self, log, url):
        return subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", "--log", str(log),
             url],
            cwd=self.root, capture_output=True, encoding="utf-8",
            env=clean_env())

    def test_publish_posts_the_head_as_a_cadence_event_and_remembers_it(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-pub1",
                         action="echo secret-wren-{i}")
        head = chain_head(log)

        result = self.publish(log, self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(),
                         f"published head {head[:12]}… (entry 2)")
        self.assertEqual(result.stderr, "")
        # The same body the hook sends, event `cadence` (ADR-0025 ruling 2).
        self.assertEqual(len(self.receiver.received), 1)
        sent = self.receiver.received[0]
        self.assertEqual(sent["content_type"], "application/json")
        body = self.body()
        self.assertEqual(set(body), PUBLISHED_FIELDS)
        self.assertEqual(body["head"], head)
        self.assertEqual(body["n"], 2)
        self.assertEqual(body["session"], "sess-pub1")
        self.assertEqual(body["event"], "cadence")
        self.assertRegex(body["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(body["text"], body["content"])
        for field in ("head", "n", "session", "ts", "event"):
            self.assertIn(str(body[field]), body["text"])
        raw = sent["raw"].decode("utf-8")
        for secret in (self.root.name, "alpha", "secret-wren", "receipts-",
                       ".jsonl"):
            self.assertNotIn(secret, raw)
        # The memo: head, n, ts, event, and nothing else. Never the URL —
        # a webhook URL is a credential.
        self.assertEqual(memo_of(log),
                         [{"head": head, "n": 2, "ts": body["ts"],
                           "event": "cadence"}])
        memo_text = Path(str(log) + ".published.jsonl").read_text(
            encoding="utf-8")
        self.assertNotIn("127.0.0.1", memo_text)
        self.assertNotIn("/hook", memo_text)

    def test_a_url_that_is_not_http_is_a_usage_error_and_nothing_moves(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-pub2")
        target = self.root / "never-opened.txt"
        for bad in (f"file:///{target.as_posix()}", "hooks.example.test/x",
                    "ftp://h.example.test/x"):
            result = self.publish(log, bad)
            self.assertEqual(result.returncode, 64, bad + ": " + result.stderr)
            self.assertIn("http", result.stderr)
        self.assertEqual(self.receiver.received, [])
        self.assertFalse(target.exists())
        self.assertEqual(memo_of(log), [])

    def test_a_remote_that_does_not_take_the_head_leaves_no_memo(self):
        # Exit 1 and one line naming the failure, never the URL; the memo
        # is written only for a head the remote took, or the keeper would
        # stand down on a POST that never landed. A redirect is a failure
        # too: nothing reaches the host it points at.
        log = make_chain(self.root / "alpha" / "receipts", "sess-pub3")
        closed = "http://127.0.0.1:9/hook"  # discard port: nothing listens
        redirector = FakeReceiver(("127.0.0.1", 0), RedirectingHandler)
        redirector.target = self.receiver.url
        threading.Thread(target=redirector.serve_forever, daemon=True).start()
        self.addCleanup(redirector.server_close)
        self.addCleanup(redirector.shutdown)
        moved = f"http://127.0.0.1:{redirector.server_address[1]}/moved"

        for url in (closed, moved):
            result = self.publish(log, url)
            self.assertEqual(result.returncode, 1, url + ": " + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("not published", result.stderr)
            self.assertNotIn("127.0.0.1", result.stderr)
        self.assertEqual(self.receiver.received, [])
        self.assertEqual(memo_of(log), [])


class PublishKeeperTest(ReceiverFixture):
    """`scan --publish-every AGE --publish-url URL`: on each tick, every
    chain whose head has aged past the cadence and is not in its memo is
    published once, through `loxodonta publish`, throttled like the
    anchor keeper. Off by default."""

    def scan(self, *extra, **knobs):
        return run_scan(self.root, *extra, env=keeper_env(**knobs))

    def publishing(self, *extra, **knobs):
        return self.scan("--publish-every", "0s",
                         "--publish-url", self.receiver.url, *extra, **knobs)

    def test_an_aged_head_with_no_memo_is_published_once(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-keep1")
        head = chain_head(log)

        result = self.publishing()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(len(self.receiver.received), 1)
        body = self.body()
        self.assertEqual(set(body), PUBLISHED_FIELDS)
        self.assertEqual(body["head"], head)
        self.assertEqual(body["n"], 2)
        self.assertEqual(body["session"], "sess-keep1")
        self.assertEqual(body["event"], "cadence")
        self.assertEqual([m["head"] for m in memo_of(log)], [head])

        again = self.publishing(SUPERVISOR_UPGRADE_EVERY_SECONDS="0")

        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(len(self.receiver.received), 1,
                         "a head already in the memo is never re-posted")
        self.assertEqual(len(memo_of(log)), 1)

    def test_a_chain_that_grew_has_its_new_head_published_and_the_old_memo_kept(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-grow")
        first = chain_head(log)
        self.publishing()
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "step 2"],
            capture_output=True, check=True)
        second = chain_head(log)

        result = self.publishing(SUPERVISOR_UPGRADE_EVERY_SECONDS="0")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([self.body(i)["head"] for i in range(2)],
                         [first, second])
        self.assertEqual([(m["head"], m["n"]) for m in memo_of(log)],
                         [(first, 2), (second, 3)],
                         "the memo is appended to, never rewritten")

    def test_default_is_off_and_nothing_is_posted_without_the_flags(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-off")

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.receiver.received, [])
        self.assertEqual(memo_of(log), [])
        self.assertFalse(Path(str(log) + ".published.jsonl").exists())

    def test_one_flag_without_the_other_is_a_usage_error(self):
        make_chain(self.root / "alpha" / "receipts", "sess-half")
        for half in (("--publish-every", "0s"),
                     ("--publish-url", self.receiver.url)):
            result = self.scan(*half)
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("--publish-every", result.stderr)
            self.assertIn("--publish-url", result.stderr)
        bad = self.scan("--publish-every", "0s",
                        "--publish-url", "hooks.example.test/no-scheme")
        self.assertEqual(bad.returncode, 64, bad.stderr)
        self.assertEqual(self.receiver.received, [])

    def test_a_young_head_waits_for_its_cadence(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-young")

        result = self.scan("--publish-every", "1d",
                           "--publish-url", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.receiver.received, [])
        self.assertEqual(memo_of(log), [])


if __name__ == "__main__":
    unittest.main()
