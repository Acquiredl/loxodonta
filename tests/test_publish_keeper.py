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

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_publish_keeper`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env
from test_publish import (FakeReceiver, FakeReceiverHandler,
                          RedirectingHandler)
from test_supervisor import (ago, chain_head, chains_by_session,
                             install_witness_hook, keeper_env, make_chain,
                             run_scan, write_attempt_row, write_chain_row,
                             write_completed_anchor, write_pending_anchor)

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
        # The memo: head, n, ts, event, and which remote took it by a
        # fingerprint of the URL (#263), the first 16 hex characters of
        # its SHA-256, and nothing else. Never the URL — a webhook URL
        # is a credential.
        fingerprint = hashlib.sha256(
            self.receiver.url.encode("utf-8")).hexdigest()[:16]
        self.assertEqual(memo_of(log),
                         [{"head": head, "n": 2, "ts": body["ts"],
                           "event": "cadence", "remote_id": fingerprint}])
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

    def test_an_attempt_row_never_stands_the_keeper_down(self):
        # #240: a session end whose POST was refused leaves a note in
        # the memo and no head row. The keeper reads the note as a
        # note: the head was never sent, so it is posted on the tick.
        log = make_chain(self.root / "alpha" / "receipts", "sess-noted")
        head = chain_head(log)
        write_attempt_row(log, "publish-head", "the remote answered 404",
                          when=ago(600), budget=3.0)

        result = self.publishing()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.receiver.received), 1)
        self.assertEqual(self.body()["head"], head)
        self.assertEqual([m["head"] for m in memo_of(log) if "head" in m],
                         [head])

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
    """The scan report says, per chain, when something last left the
    machine and by which door — `published` for a head, `published-chain`
    for a batch of the entries, `anchored` for a digest: `left` beside
    `anchors`, a timestamp the reader ages. Quiet staleness evidence in
    the keeper's voice: never an alarm, never the exit code."""

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

    def test_left_names_the_route_the_entries_or_the_head_left_by(self):
        # #248: an acknowledged batch of entries is a departure, and a
        # larger one than a head's — the work itself is off the machine,
        # not just its fingerprint — but it is not the head route's, so
        # `via` names the route. A chain route alive beside a head route
        # that has been refused all week then reads as what it is, with
        # the refusal in `last_failed` where it belongs.
        chain_only = make_chain(self.root / "alpha" / "receipts", "sess-only")
        batch_at = ago(600)
        write_chain_row(chain_only, 0, 2, chain_head(chain_only),
                        when=batch_at)
        write_attempt_row(chain_only, "publish-head",
                          "the remote answered 404", when=ago(300),
                          budget=3.0)
        both = make_chain(self.root / "alpha" / "receipts", "sess-doors")
        write_chain_row(both, 0, 2, chain_head(both), when=ago(90000))
        self.publish_by_hand(both)   # a head row, newer by a day

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (chain,) = sessions[("alpha", "sess-only")]
        self.assertEqual(chain["left"],
                         {"ts": batch_at, "via": "published-chain"})
        self.assertEqual(chain["last_failed"]["step"], "publish-head")
        (chain,) = sessions[("alpha", "sess-doors")]
        head_row = [row for row in memo_of(both) if "kind" not in row]
        self.assertEqual(chain["left"],
                         {"ts": head_row[0]["ts"], "via": "published"})

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

    def test_an_attempt_row_is_never_a_departure_and_the_last_failure_is_read(self):
        # #240 part 3, with no keeper cadence set: `left` reads the
        # head rows and the proofs, never a note that a step was tried,
        # and `last_failed` reads the newest note that a step failed,
        # across both sidecars, as step, time and outcome.
        refused = make_chain(self.root / "alpha" / "receipts", "sess-refused")
        refused_at = ago(600)
        write_attempt_row(refused, "publish-head", "the remote answered 404",
                          when=refused_at, budget=3.0)
        mixed = make_chain(self.root / "alpha" / "receipts", "sess-mixed")
        self.publish_by_hand(mixed)
        write_attempt_row(mixed, "anchor",
                          "no calendar answered within 12 seconds",
                          when=ago(60))
        quiet = make_chain(self.root / "beta" / "receipts", "sess-quiet")

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (chain,) = sessions[("alpha", "sess-refused")]
        self.assertEqual(chain["left"], {"ts": None, "via": None})
        self.assertEqual(chain["last_failed"],
                         {"step": "publish-head", "ts": refused_at,
                          "outcome": "the remote answered 404"})
        (chain,) = sessions[("alpha", "sess-mixed")]
        self.assertEqual(chain["left"],
                         {"ts": memo_of(mixed)[0]["ts"], "via": "published"})
        self.assertEqual(chain["last_failed"]["step"], "anchor")
        self.assertEqual(chain["last_failed"]["outcome"],
                         "no calendar answered within 12 seconds")
        (chain,) = sessions[("beta", "sess-quiet")]
        self.assertIsNone(chain["last_failed"])
        self.assertEqual(memo_of(quiet), [])

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


class NeverPublishedTest(ReceiverFixture):
    """#240 part 3: when the wired SessionEnd command carries a publish
    flag and no chain holds a sent head, the scan says so in one
    sentence. Publishing wired in name only, with a remote that was
    never listening, is otherwise invisible for as long as nobody
    reads the memos; this catches it the first morning."""

    def setUp(self):
        super().setUp()
        self.witness = self.root / "witness"

    def wire(self, command):
        install_witness_hook(self.witness, sessionend=True, command=command)

    def scan(self, *extra):
        return run_scan(self.root, "--witness", str(self.witness), *extra,
                        env=keeper_env())

    def test_a_wired_publish_that_never_sent_is_one_sentence(self):
        self.wire(f'python loxodonta.py hook --publish "{self.receiver.url}"')
        log = make_chain(self.root / "alpha" / "receipts", "sess-never")

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        published = report["published"]
        self.assertTrue(published["wired"])
        self.assertFalse(published["sent"])
        self.assertIn("no chain", published["note"])
        self.assertNotIn("127.0.0.1", result.stdout,
                         "the URL is a credential; the report never holds it")
        self.assertEqual(report["exit"], 0, "a sentence, never the exit")

        # Once a head has left by that door, to the remote the command
        # names (#263), the sentence is gone.
        subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", "--log", str(log),
             self.receiver.url],
            capture_output=True, check=True, env=clean_env())

        published = json.loads(self.scan().stdout)["published"]

        self.assertEqual(published, {"wired": True, "sent": True,
                                     "note": None})

    def test_the_plain_scan_prints_the_same_sentence(self):
        # One shape, two dressings: the plain scan is the same report,
        # pretty-printed, so the sentence is on the operator's screen.
        self.wire('python loxodonta.py hook --publish "http://127.0.0.1:9/hook"')
        make_chain(self.root / "alpha" / "receipts", "sess-never")

        plain = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--root",
             str(self.root), "--witness", str(self.witness)],
            capture_output=True, encoding="utf-8",
            env={**keeper_env(), "PYTHONIOENCODING": "utf-8"})

        self.assertEqual(plain.returncode, 0, plain.stdout + plain.stderr)
        self.assertEqual(json.loads(plain.stdout)["published"]["note"],
                         json.loads(self.scan().stdout)["published"]["note"])
        self.assertIn("no chain", plain.stdout)

    def test_without_a_publish_flag_wired_there_is_no_sentence(self):
        self.wire("python loxodonta.py hook --anchor")
        make_chain(self.root / "alpha" / "receipts", "sess-anchors")

        published = json.loads(self.scan().stdout)["published"]

        self.assertEqual(published, {"wired": False, "sent": False,
                                     "note": None})

    def test_sent_is_measured_per_route_so_a_chain_wired_alone_is_read_as_its_own(self):
        # #248: the chain route (`--publish-chain`) is wired in name only
        # until a batch lands, whatever the head route did. A chain-only
        # wiring, then a batch sent by hand to the remote it names, then
        # the sentence is gone.
        self.wire(f'python loxodonta.py hook --publish-chain '
                  f'"{self.receiver.url}"')
        log = make_chain(self.root / "alpha" / "receipts", "sess-chain")

        published = json.loads(self.scan().stdout)["published"]

        self.assertTrue(published["wired"])
        self.assertFalse(published["sent"])
        self.assertIn("--publish-chain", published["note"])
        self.assertIn("a sent chain", published["note"])
        self.assertNotIn("sent head", published["note"])

        subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", "--chain", "--log",
             str(log), self.receiver.url],
            capture_output=True, check=True, env=clean_env())

        published = json.loads(self.scan().stdout)["published"]

        self.assertEqual(published, {"wired": True, "sent": True,
                                     "note": None})

    def test_a_head_that_left_does_not_answer_for_a_chain_that_never_did(self):
        # Both routes wired, the head sent, the chain never: the sentence
        # names the chain route alone, and `sent` says something left.
        self.wire(f'python loxodonta.py hook --publish "{self.receiver.url}" '
                  '--publish-chain "http://127.0.0.1:9/c"')
        log = make_chain(self.root / "alpha" / "receipts", "sess-both")
        subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", "--log", str(log),
             self.receiver.url],
            capture_output=True, check=True, env=clean_env())

        published = json.loads(self.scan().stdout)["published"]

        self.assertEqual((published["wired"], published["sent"]), (True, True))
        self.assertIn("--publish-chain", published["note"])
        self.assertIn("a sent chain", published["note"])
        self.assertNotIn("sent head", published["note"])
        self.assertNotIn("127.0.0.1", json.dumps(published))


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

    def test_the_tile_reads_the_departure_and_the_last_failed_attempt(self):
        # #240 part 3 on the page: the project tile says when a head
        # last left this drawer by any route and which session-end
        # step last failed, read from the same fields `scan --json`
        # carries, with no keeper cadence set.
        log = make_chain(self.root / "alpha" / "receipts", "sess-tile")
        write_attempt_row(log, "publish-head", "no answer within 3 seconds",
                          when=ago(120), budget=3.0)
        url = self.serve()

        status = json.loads(self.get(url, "/api/status"))
        page = self.get(url, "/")

        (chain,) = chains_by_session(status)[("alpha", "sess-tile")]
        self.assertEqual(chain["last_failed"]["step"], "publish-head")
        self.assertEqual(chain["last_failed"]["outcome"],
                         "no answer within 3 seconds")
        self.assertIn("published", status)
        # The tile is built from `left` and `last_failed`, worded as ages.
        tiles = page[page.index("function renderTiles"):
                     page.index("function renderSpark")]
        self.assertIn("c.left", tiles)
        self.assertIn("c.last_failed", tiles)
        self.assertIn("last left", tiles)
        self.assertIn("last failed", tiles)


class ProfileKeeperTest(unittest.TestCase):
    """`serve` reads the coverage marker's newest epoch (ADR-0031 ruling
    1): with no `--anchor-every` and a `timestamped` profile, the anchor
    keeper runs on a six-hour default; an explicit flag wins; `local`,
    or `custom` without a flag, runs no keeper. The startup line says
    which cadence is in force and where it came from. The marker is the
    real installer's, the chain is aged through the recorder's clock
    override, and the calendar is a fake on a free port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.home = Path(self._tmp.name).resolve() / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = Path(self._tmp.name).resolve() / "store"
        # The witness is the layout beside the settings the installer
        # writes, because the keeper follows a profile only while that
        # harness's recorder is still wired there (#249).
        self.witness = self.home / ".claude" / "projects"
        self.witness.mkdir()
        self.calendar = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
        self.calendar.mode = "pending"
        self.calendar.nonce = b"fake-nonce"
        self.calendar.submitted = []
        self.calendar.polled = []
        self.calendar.url = (
            f"http://127.0.0.1:{self.calendar.server_address[1]}")
        threading.Thread(target=self.calendar.serve_forever,
                         daemon=True).start()
        self.addCleanup(self.calendar.server_close)
        self.addCleanup(self.calendar.shutdown)

    def install(self, *args, age=0):
        """The real installer writes the marker the keeper reads, into
        this test's store; its settings land in a throwaway home. `age`
        stamps the epoch that many seconds into the past (the recorder's
        clock override), so one install can be older than another."""
        knobs = {"HOME": str(self.home), "USERPROFILE": str(self.home),
                 "LOXODONTA_HOME": str(self.store),
                 "CODEX_HOME": str(self.home / ".codex")}
        if age:
            knobs["SOURCE_DATE_EPOCH"] = str(int(time.time()) - age)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook", *args],
            capture_output=True, check=True, env=keeper_env(**knobs))

    def aged_chain(self, session, age):
        """A chain through the public CLI whose entries are `age`
        seconds old (SOURCE_DATE_EPOCH, the recorder's clock override),
        so a keeper cadence shorter than `age` finds its head ripe."""
        env = keeper_env(SOURCE_DATE_EPOCH=str(int(time.time()) - age))
        log_dir = self.root / "alpha" / "receipts"
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / f"receipts-{session}.jsonl"
        subprocess.run([sys.executable, str(LOXODONTA), "init",
                        "--log", str(log)],
                       capture_output=True, check=True, env=env)
        subprocess.run([sys.executable, str(LOXODONTA), "log",
                        "--log", str(log), "--actor", "claude-code",
                        "--action", "step"],
                       capture_output=True, check=True, env=env)
        return log

    def serve(self, *extra):
        """Start `serve` against the store's marker and read the URL."""
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0", "--witness", str(self.witness),
             "--calendar", self.calendar.url, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env=keeper_env(LOXODONTA_HOME=str(self.store),
                           CODEX_HOME=str(self.home / ".codex"),
                           PYTHONIOENCODING="utf-8"))
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if match is None:
            self.proc.kill()
            _, err = self.proc.communicate()
            self.fail(f"serve announced no localhost URL: {line!r}\n{err}")
        self.url = match.group()

    def _stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.communicate()

    def tick(self):
        """One request, which is one tick of the keeper."""
        with OPENER.open(self.url + "/api/status", timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))

    def said_at_startup(self):
        """The keeper line: what `serve` prints right after the URL line.

        Read it before stopping the process. `serve` writes the two lines
        as two flushes, and a kill sent the instant the first arrives can
        land before the second is written, which is what CI on Linux and
        macOS showed; the line is deterministic, the race was the test's."""
        line = self.proc.stdout.readline()
        self.proc.kill()
        self.proc.communicate()
        return line

    def test_a_timestamped_marker_puts_the_anchor_keeper_on_six_hours(self):
        self.install("--profile", "timestamped")
        log = self.aged_chain("sess-prof", age=7 * 3600)

        self.serve()
        self.tick()
        said = self.said_at_startup()

        self.assertIn("anchor every 6h (profile timestamped, claude-code)",
                      said)
        self.assertEqual(self.calendar.submitted,
                         [bytes.fromhex(chain_head(log))],
                         "the keeper anchored the ripe head on the "
                         "profile's cadence, with no flag typed")

    def test_an_explicit_flag_overrides_the_marker_and_says_so(self):
        self.install("--profile", "timestamped")
        self.aged_chain("sess-flag", age=7 * 3600)

        self.serve("--anchor-every", "1h")
        said = self.said_at_startup()

        self.assertIn("anchor every 1h (flag --anchor-every)", said)
        self.assertNotIn("6h", said)

    def test_a_local_marker_runs_no_keeper(self):
        self.install()
        log = self.aged_chain("sess-local", age=7 * 3600)

        self.serve()
        self.tick()
        said = self.said_at_startup()

        self.assertIn("anchor off (profile local, claude-code", said)
        self.assertEqual(self.calendar.submitted, [])
        self.assertFalse(Path(str(log) + ".anchors.jsonl").exists())

    def test_custom_without_a_flag_runs_no_keeper(self):
        self.install("--profile", "custom")
        self.aged_chain("sess-custom", age=7 * 3600)

        self.serve()
        self.tick()
        said = self.said_at_startup()

        self.assertIn("anchor off (profile custom, claude-code", said)
        self.assertEqual(self.calendar.submitted, [])

    def test_a_later_local_install_for_another_harness_stands_no_keeper_down(self):
        # The keeper follows the strongest tier any harness declares,
        # each harness speaking through its newest epoch. A Claude Code
        # install at `timestamped` a day ago, then a flagless Codex
        # install today: the newest epoch of all says `local`, but
        # reading it as the choice withdrawn would stand the keeper down
        # with nothing saying a Codex install did it, the end claim
        # ADR-0030 ruling 2 refuses. The line names the harness whose
        # profile set the cadence.
        (self.home / ".codex").mkdir()
        self.install("--profile", "timestamped", age=86400)
        self.install("--codex")
        log = self.aged_chain("sess-two", age=7 * 3600)

        self.serve()
        self.tick()
        said = self.said_at_startup()

        self.assertIn("anchor every 6h (profile timestamped, claude-code)",
                      said)
        self.assertEqual(self.calendar.submitted,
                         [bytes.fromhex(chain_head(log))])


if __name__ == "__main__":
    unittest.main()
