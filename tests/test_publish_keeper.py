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
import re
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_publish_keeper`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env
from test_publish import (FakeReceiver, FakeReceiverHandler,
                          RedirectingHandler)
from test_supervisor import (ago, chain_head, chains_by_session, keeper_env,
                             make_chain, run_scan, write_completed_anchor,
                             write_pending_anchor)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

PUBLISHED_FIELDS = {"head", "n", "session", "ts", "event", "text", "content"}

# Straight to 127.0.0.1 — never through a proxy someone's shell configured.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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


class LeftReadingTest(ReceiverFixture):
    """The scan report says, per chain, when a head last left the machine
    and by which door, published or anchored: `left` beside `anchors`, a
    timestamp the reader ages. Quiet staleness evidence in the keeper's
    voice: never an alarm, never the exit code."""

    def publish_by_hand(self, log):
        subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", "--log", str(log),
             self.receiver.url],
            capture_output=True, check=True, env=clean_env())

    def test_left_is_the_newest_departure_published_or_anchored(self):
        both = make_chain(self.root / "alpha" / "receipts", "sess-both")
        write_pending_anchor(both, chain_head(both), submitted=ago(100000))
        self.publish_by_hand(both)  # newer than the anchor by a day
        anchored = make_chain(self.root / "alpha" / "receipts", "sess-anch")
        write_completed_anchor(anchored, chain_head(anchored))
        never = make_chain(self.root / "beta" / "receipts", "sess-never")

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (chain,) = sessions[("alpha", "sess-both")]
        self.assertEqual(chain["left"],
                         {"ts": memo_of(both)[0]["ts"], "via": "published"})
        (chain,) = sessions[("alpha", "sess-anch")]
        self.assertEqual(chain["left"],
                         {"ts": "2026-08-22T09:00:00Z", "via": "anchored"})
        (chain,) = sessions[("beta", "sess-never")]
        self.assertEqual(chain["left"], {"ts": None, "via": None})
        self.assertEqual(memo_of(never), [])

    def test_an_anchored_heads_departure_is_its_first_record(self):
        # An upgrade appends a second record for the same head, stamped
        # when the proof completed; the head left when it was first
        # submitted, and an idle chain must not read fresh because a
        # calendar answered a poll.
        log = make_chain(self.root / "alpha" / "receipts", "sess-upgraded")
        head = chain_head(log)
        write_pending_anchor(log, head, submitted=ago(200000))
        write_pending_anchor(log, head, submitted=ago(10))
        sidecar = Path(str(log) + ".anchors.jsonl")
        first = json.loads(sidecar.read_text("utf-8").splitlines()[0])["ts"]

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (chain,) = chains_by_session(json.loads(result.stdout))[
            ("alpha", "sess-upgraded")]
        self.assertEqual(chain["left"], {"ts": first, "via": "anchored"})

    def test_a_dead_remote_is_a_note_in_left_and_never_the_exit(self):
        # The keeper's existing voice for aging heads: the failure is said
        # in the report, the exit code stays the chains' own, and no memo
        # is written for a POST that never landed.
        log = make_chain(self.root / "alpha" / "receipts", "sess-dead")

        result = run_scan(self.root, "--publish-every", "0s",
                          "--publish-url", "http://127.0.0.1:9/hook",
                          env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["exit"], 0)
        (chain,) = chains_by_session(report)[("alpha", "sess-dead")]
        self.assertTrue(chain["left"]["failed"])
        self.assertIn("publishing failed", chain["left"]["note"])
        self.assertIsNone(chain["left"]["ts"])
        self.assertNotIn("127.0.0.1:9", result.stdout,
                         "the URL is a credential; the report never holds it")
        self.assertEqual(memo_of(log), [])


class DashboardLeftTest(ReceiverFixture):
    """`serve` carries the same flags, publishes on its own tick, and the
    page renders when a head last left as staleness beside the anchor
    age: the same quiet class the unanchored head wears, never an alarm."""

    def serve(self, *extra):
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0", *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env=keeper_env())
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if match is None:
            self.proc.kill()
            _, err = self.proc.communicate()
            self.fail(f"serve announced no localhost URL: {line!r}\n{err}")
        return match.group()

    def _stop(self):
        self.proc.kill()
        self.proc.communicate()

    def get(self, url, path):
        with OPENER.open(url + path, timeout=30) as response:
            return response.read().decode("utf-8")

    def test_serve_publishes_on_its_tick_and_the_page_shows_the_departure(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-face")
        url = self.serve("--publish-every", "0s",
                         "--publish-url", self.receiver.url)

        status = json.loads(self.get(url, "/api/status"))

        self.assertEqual(len(self.receiver.received), 1)
        self.assertEqual(self.body()["event"], "cadence")
        (chain,) = chains_by_session(status)[("alpha", "sess-face")]
        self.assertEqual(chain["left"],
                         {"ts": memo_of(log)[0]["ts"], "via": "published"})
        self.assertEqual(status["exit"], 0)

        page = self.get(url, "/")

        # The claims the page is built from, held still: the departure is
        # read from `left`, worded as an age, and painted with the anchor
        # panel's staleness class rather than a new alarm.
        self.assertIn("chain.left", page)
        self.assertIn("last left", page)
        self.assertIn("has left this machine", page)


if __name__ == "__main__":
    unittest.main()
