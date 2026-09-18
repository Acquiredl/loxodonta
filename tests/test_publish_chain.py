"""Behavioral tests for the published chain (ADR-0031 rulings 2 and 3,
issue #248, slice four of PRD #244).

`publish --chain URL` sends the chain's lines exactly as they sit on
disk, from the entry after the last one the remote acknowledged, and
the hook does the same at session end when `--publish-chain URL` is
wired; the keeper's publish turn sends the chain after the head. Every
test drives the public CLI: against the repo's own receiver as a
subprocess where the far end's file is the point, and against the
publish suite's fake receiver where what arrived, in what order, or
what was refused is the point. No network, ever, and never internals.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_publish_chain`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env
from test_publish import FakeReceiver, FakeReceiverHandler, PublishBase
from test_receiver import make_chain, run_recorder
from test_supervisor import (chain_head, chains_by_session, keeper_env,
                             make_chain as make_store_chain, run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
RECEIVER = REPO_ROOT / "receiver.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

NDJSON = "application/x-ndjson"
# What a quick session-end step writes when the window has closed on
# it (#262): the recorder's words, pinned here as the operator reads
# them in the sidecar.
WINDOW_CLOSED = "the session-end window closed before this step"
PUBLISH_TO = re.compile(r"^publish to (https?://\S+)$", re.M)


def start_receiver(case, data):
    """The repo's own receiver as a subprocess on a free port, narrowed
    to 127.0.0.1, its URL read from what it printed. Stopped when the
    test ends."""
    proc = subprocess.Popen(
        [sys.executable, str(RECEIVER), "serve", "--data", str(data),
         "--port", "0", "--bind", "127.0.0.1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
        env=clean_env())

    def stop():
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()

    case.addCleanup(stop)
    said = []
    while True:
        line = proc.stdout.readline()
        if not line:
            proc.kill()
            case.fail("the receiver printed no URL:\n%s%s"
                      % ("".join(said), proc.stderr.read()))
        said.append(line)
        found = PUBLISH_TO.search(line)
        if found:
            break
    proc.url = found.group(1)
    return proc


def run_capped(cap, *args):
    """The recorder with the batch cap set to `cap` bytes. The cap in
    the field is the receiver's 8 MiB, which no test can reach in a
    reasonable chain, so the batching rule is exercised through the
    env knob the recorder reads (LOXODONTA_CHAIN_BATCH_BYTES)."""
    env = clean_env()
    env["LOXODONTA_CHAIN_BATCH_BYTES"] = str(cap)
    return subprocess.run([sys.executable, str(LOXODONTA), *map(str, args)],
                          capture_output=True, encoding="utf-8", env=env)


def memo_of(log):
    """The publish memo beside a chain, parsed; [] when none was written."""
    memo = Path(str(log) + ".published.jsonl")
    if not memo.exists():
        return []
    return [json.loads(line) for line in
            memo.read_text(encoding="utf-8").splitlines()]


def chain_rows(log):
    return [row for row in memo_of(log) if row.get("kind") == "chain"]


def head_rows(log):
    return [row for row in memo_of(log) if "kind" not in row]


def attempt_rows(log):
    return [row for row in memo_of(log) if row.get("kind") == "attempt"]


class ChainReceiverHandler(FakeReceiverHandler):
    """The fake receiver's handler, also keeping each POST's tool headers,
    answering the status a test chose, and sitting on a chain batch alone
    when a test wants the chain send slow and the head send quick."""

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        kind = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        chain = getattr(self.server, "chain", None)
        calendar = getattr(self.server, "calendar", None)
        self.server.received.append({
            "path": self.path,
            "content_type": kind,
            "headers": {name.lower(): value
                        for name, value in self.headers.items()
                        if name.lower().startswith("x-loxodonta-")},
            "raw": raw,
            "chain_tail": (chain.read_text(encoding="utf-8").splitlines()[-1]
                           if chain and chain.exists() else None),
            "calendar_asks": (len(calendar.submitted)
                              if calendar is not None else None),
        })
        if kind == NDJSON:
            time.sleep(getattr(self.server, "chain_delay", 0))
        else:
            time.sleep(self.server.delay)
        status = getattr(self.server, "status", 200)
        body = (b'{"appended": 1, "dropped": 0}' if status == 200
                else b"refused\n")
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve_fake(case):
    """The publish suite's fake receiver with the chain-aware handler."""
    server = FakeReceiver(("127.0.0.1", 0), ChainReceiverHandler)
    server.received = []
    server.delay = 0
    server.chain_delay = 0
    server.status = 200
    server.url = f"http://127.0.0.1:{server.server_address[1]}/hook"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class PublishChainCommandTest(unittest.TestCase):
    """`loxodonta publish --chain --log LOG URL`: the operator's (and the
    keeper's) send of the chain's lines since the last acknowledged one,
    remembered in the memo as a chain row."""

    SESSION = "sess-chain-0001"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.data = self.root / "receiver"
        self.log = self.root / f"receipts-{self.SESSION}.jsonl"

    def publish_chain(self, url, log=None):
        return run_recorder("publish", "--chain", "--log", log or self.log,
                            url)

    def verify_receivers_file(self):
        return run_recorder("verify", "--log", self.data / self.log.name)

    def test_a_fresh_chain_goes_from_genesis_verbatim_and_verifies_there(self):
        # ADR-0031 ruling 2: the first send starts at genesis and the
        # body is the chain's bytes exactly, so the receiver's file is a
        # receipt log the recorder judges with no new code (ruling 4).
        receiver = start_receiver(self, self.data)
        lines = make_chain(self.log, ["step 1", "step 2"], epoch=1700000000)

        result = self.publish_chain(receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertRegex(result.stdout.strip(),
                         r"^published chain entries 0-2 \(head [0-9a-f]{12}…\)$")
        self.assertEqual((self.data / self.log.name).read_bytes(), lines)
        judged = self.verify_receivers_file()
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertEqual(judged.stdout.strip(), "VALID")
        # The memo: one chain row with the range, the head after the
        # last entry sent, the time, the event kind; never the URL.
        (row,) = memo_of(self.log)
        last = json.loads(lines.splitlines()[-1])
        self.assertEqual(row, {"kind": "chain", "first": 0, "last": 2,
                               "head": last["entry_hash"], "ts": row["ts"],
                               "event": "cadence"})
        self.assertRegex(row["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        memo_text = Path(str(self.log) + ".published.jsonl").read_text("utf-8")
        self.assertNotIn("127.0.0.1", memo_text)
        self.assertNotIn(receiver.url.rsplit("/", 1)[-1], memo_text)

    def test_the_batch_carries_the_ndjson_type_and_the_four_headers(self):
        # docs/RECEIVER.md section 4: the chain's file name, the session
        # id, the n range and the head ride in headers named for the
        # tool; the receiver reads the first and stores chain bytes only.
        fake = serve_fake(self)
        lines = make_chain(self.log, ["step 1"], epoch=1700000000)

        result = self.publish_chain(fake.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        (sent,) = fake.received
        self.assertEqual(sent["content_type"], NDJSON)
        self.assertEqual(sent["raw"], lines)
        last = json.loads(lines.splitlines()[-1])
        self.assertEqual(sent["headers"], {
            "x-loxodonta-chain": self.log.name,
            "x-loxodonta-session": self.SESSION,
            "x-loxodonta-range": "0-1",
            "x-loxodonta-head": last["entry_hash"],
        })

    def test_a_second_send_starts_after_the_last_acknowledged_entry(self):
        # The cursor: the memo's last chain row says up to which n the
        # remote acknowledged, and the next send starts after it.
        fake = serve_fake(self)
        make_chain(self.log, ["step 1"], epoch=1700000000)
        self.assertEqual(self.publish_chain(fake.url).returncode, 0)
        for action in ("step 2", "step 3"):
            run_recorder("log", "--log", self.log, "--actor", "claude-code",
                         "--action", action, epoch=1700000000)
        on_disk = self.log.read_bytes().splitlines(True)

        result = self.publish_chain(fake.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("published chain entries 2-3", result.stdout)
        self.assertEqual(len(fake.received), 2)
        self.assertEqual(fake.received[1]["raw"], b"".join(on_disk[2:]))
        self.assertEqual(fake.received[1]["headers"]["x-loxodonta-range"],
                         "2-3")
        self.assertEqual([(r["first"], r["last"]) for r in chain_rows(self.log)],
                         [(0, 1), (2, 3)],
                         "the memo is appended to, never rewritten")

    def test_nothing_after_the_cursor_sends_nothing_and_says_so(self):
        fake = serve_fake(self)
        make_chain(self.log, ["step 1"], epoch=1700000000)
        self.assertEqual(self.publish_chain(fake.url).returncode, 0)

        result = self.publish_chain(fake.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing to send", result.stdout)
        self.assertIn("entry 1", result.stdout)
        self.assertEqual(len(fake.received), 1)
        self.assertEqual(len(chain_rows(self.log)), 1)

    def test_a_memo_without_a_chain_row_starts_from_genesis_and_duplicates_drop(self):
        # A memo lost (or never written) means the whole chain goes
        # again; the receiver drops the exact duplicates and its file is
        # unchanged and still VALID (ADR-0031 ruling 4).
        receiver = start_receiver(self, self.data)
        lines = make_chain(self.log, ["step 1", "step 2"], epoch=1700000000)
        self.assertEqual(self.publish_chain(receiver.url).returncode, 0)
        Path(str(self.log) + ".published.jsonl").unlink()

        result = self.publish_chain(receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("published chain entries 0-2", result.stdout)
        self.assertEqual((self.data / self.log.name).read_bytes(), lines)
        judged = self.verify_receivers_file()
        self.assertEqual(judged.stdout.strip(), "VALID")
        self.assertEqual([(r["first"], r["last"]) for r in chain_rows(self.log)],
                         [(0, 2)])

    def test_a_refused_batch_leaves_no_chain_row_and_the_next_send_resumes(self):
        # The memo advances on a 2xx and on nothing else: a refused batch
        # is said on stderr, never with the URL, and the cursor stays
        # where it was so the next send carries the same lines.
        fake = serve_fake(self)
        fake.status = 400
        lines = make_chain(self.log, ["step 1"], epoch=1700000000)

        refused = self.publish_chain(fake.url)

        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertEqual(refused.stdout, "")
        self.assertIn("the chain was not published", refused.stderr)
        self.assertIn("the remote answered 400", refused.stderr)
        self.assertNotIn("127.0.0.1", refused.stderr)
        self.assertEqual(chain_rows(self.log), [])
        # What the memo does gain is the note (#240, #251): this verb is
        # what the keeper's cadence runs, so a batch it could not send is
        # written down where the session end writes its own attempts.
        (note,) = attempt_rows(self.log)
        self.assertEqual(note["step"], "publish-chain")
        self.assertEqual(note["outcome"], "the remote answered 400")

        fake.status = 200
        again = self.publish_chain(fake.url)

        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual([sent["raw"] for sent in fake.received],
                         [lines, lines])
        self.assertEqual([(r["first"], r["last"]) for r in chain_rows(self.log)],
                         [(0, 1)])

    def test_a_tail_past_the_cap_goes_in_several_batches_each_written_down(self):
        # docs/RECEIVER.md section 4: one body stays under the cap, so a
        # longer tail is several POSTs, each acknowledged and written
        # down on its own. What the receiver ends up holding is the
        # chain, byte for byte, whatever the batching did on the way.
        receiver = start_receiver(self, self.data)
        lines = make_chain(self.log, ["step 1", "step 2"], epoch=1700000000)
        on_disk = lines.splitlines(True)
        cap = len(on_disk[0]) + len(on_disk[1])

        result = run_capped(cap, "publish", "--chain", "--log", self.log,
                            receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("published chain entries 0-2", result.stdout)
        self.assertEqual([(row["first"], row["last"])
                          for row in chain_rows(self.log)],
                         [(0, 1), (2, 2)])
        self.assertEqual((self.data / self.log.name).read_bytes(), lines)
        judged = self.verify_receivers_file()
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertEqual(judged.stdout.strip(), "VALID")

    def test_an_entry_larger_than_the_cap_is_named_and_never_sent(self):
        # The receiver refuses a body past its cap on the Content-Length
        # and closes, which would reach the sender as a bare connection
        # word and stall this chain on this line forever, since the
        # cursor cannot pass what never landed. Refused here instead,
        # by name, with everything before it already sent.
        fake = serve_fake(self)
        make_chain(self.log, ["step 1", "x" * 150], epoch=1700000000)
        on_disk = self.log.read_bytes().splitlines(True)
        cap = max(len(on_disk[0]), len(on_disk[1]))
        self.assertGreater(len(on_disk[2]), cap, "entry 2 must be the big one")

        result = run_capped(cap, "publish", "--chain", "--log", self.log,
                            fake.url)

        self.assertEqual(result.returncode, 1)
        self.assertIn("entry 2 is larger than the receiver's cap",
                      result.stderr)
        # Everything before it left, and the cursor stops where it did.
        self.assertEqual([(row["first"], row["last"])
                          for row in chain_rows(self.log)], [(0, 0), (1, 1)])
        self.assertEqual(b"".join(sent["raw"] for sent in fake.received),
                         b"".join(on_disk[:2]))
        # And it stays refused rather than stalling on a socket word.
        again = run_capped(cap, "publish", "--chain", "--log", self.log,
                           fake.url)
        self.assertEqual(again.returncode, 1)
        self.assertIn("entry 2 is larger than the receiver's cap",
                      again.stderr)
        self.assertEqual(len(fake.received), 2)

    def test_a_url_that_is_not_http_is_a_usage_error_and_nothing_moves(self):
        make_chain(self.log, ["step 1"], epoch=1700000000)
        target = self.root / "never-opened.txt"
        for bad in (f"file:///{target.as_posix()}", "hooks.example.test/x"):
            result = self.publish_chain(bad)
            self.assertEqual(result.returncode, 64, bad + ": " + result.stderr)
        self.assertFalse(target.exists())
        self.assertEqual(memo_of(self.log), [])

    def test_a_torn_tail_is_never_sent_and_the_line_says_where_it_tore(self):
        # The receiver refuses a batch whole when a line is not an entry,
        # so the sender stops at the last complete line: the torn line
        # stays on the writer's machine as the damage verify reports.
        # The intact prefix still goes — a remote that can only add is
        # exactly where the evidence up to the tear belongs — and the
        # command says so rather than reading like an ordinary success.
        fake = serve_fake(self)
        lines = make_chain(self.log, ["step 1"], epoch=1700000000)
        with open(self.log, "ab") as f:
            f.write(b'{"n": 2, "ts": "2026-')

        result = self.publish_chain(fake.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("published chain entries 0-1", result.stdout)
        self.assertIn("the tail after 1 is damaged", result.stdout)
        (sent,) = fake.received
        self.assertEqual(sent["raw"], lines)
        self.assertEqual(sent["headers"]["x-loxodonta-range"], "0-1")
        # And again with nothing left to send: the damage is still said.
        again = self.publish_chain(fake.url)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("nothing to send", again.stdout)
        self.assertIn("the tail after 1 is damaged", again.stdout)
        self.assertEqual(len(fake.received), 1)


class PublishChainAtSessionEndTest(PublishBase):
    """`hook --publish-chain URL`: at SessionEnd, after the tail
    commitment and the published head, before the anchor, the chain's
    lines since the cursor leave, quietly and under the head's budget."""

    def setUp(self):
        super().setUp()
        # The publish suite's fake receiver, with the handler that keeps
        # the tool headers and can sit on a chain batch alone.
        self.receiver = serve_fake(self)

    def chain_lines(self):
        return self.chain().read_bytes()

    def test_order_is_commitment_head_chain_then_anchor(self):
        # ADR-0031 ruling 3, in ADR-0025's order: the seal is on the
        # chain before anything leaves, the head goes first, the chain
        # batch second and carries the seal as its last line, and the
        # calendar is asked only after both.
        calendar = self.calendar()
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.receiver.chain = self.chain()

        result = self.session_end("--publish", self.receiver.url,
                                  "--publish-chain", self.receiver.url,
                                  "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "logged entry 2")
        self.assertEqual(result.stderr, "")
        head, batch = self.receiver.received
        self.assertEqual(head["content_type"], "application/json")
        self.assertEqual(batch["content_type"], NDJSON)
        self.assertEqual(batch["calendar_asks"], 0)
        sealed = json.loads(batch["chain_tail"])
        self.assertTrue(sealed["action"].startswith("transcript-commitment:"))
        self.assertEqual(batch["raw"], self.chain_lines())
        self.assertEqual(batch["raw"].splitlines()[-1],
                         self.chain_lines().splitlines()[-1])
        self.assertEqual(batch["headers"], {
            "x-loxodonta-chain": self.chain().name,
            "x-loxodonta-session": self.SESSION,
            "x-loxodonta-range": "0-2",
            "x-loxodonta-head": sealed["entry_hash"],
        })
        # The digest was asked after both POSTs, of the sealed head.
        self.assertEqual(calendar.publishes_seen, [2])
        self.assertEqual([d.hex() for d in calendar.submitted],
                         [sealed["entry_hash"]])
        # The memo: a head row, a chain row, and one attempt row per
        # step, both `sent`, under the head's budget.
        (row,) = chain_rows(self.chain())
        self.assertEqual((row["first"], row["last"], row["head"],
                          row["event"]),
                         (0, 2, sealed["entry_hash"], "session-end"))
        self.assertEqual(len(head_rows(self.chain())), 1)
        self.assertEqual([(a["step"], a["outcome"], a["budget"])
                          for a in attempt_rows(self.chain())],
                         [("publish-head", "sent", 3.0),
                          ("publish-chain", "sent", 3.0)])

    def test_a_stalled_chain_send_costs_the_anchor_nothing_beyond_the_budget(self):
        # The chain send shares the head's bound: a remote that sits on
        # the batch is left behind on the hook's own clock, the calendar
        # is still asked, and the memo says so with no chain row.
        calendar = self.calendar()
        self.receiver.chain_delay = 4  # just past the three the hook waits
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        started = time.monotonic()
        result = self.session_end("--publish", self.receiver.url,
                                  "--publish-chain", self.receiver.url,
                                  "--anchor", "--calendar", calendar.url)
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertLess(elapsed, 12)
        self.assertEqual([s["content_type"] for s in self.receiver.received],
                         ["application/json", NDJSON])
        self.assertEqual([d.hex() for d in calendar.submitted], [self.head()])
        self.assertEqual(len(head_rows(self.chain())), 1)
        self.assertEqual(chain_rows(self.chain()), [])
        self.assertEqual([(a["step"], a["outcome"])
                          for a in attempt_rows(self.chain())],
                         [("publish-head", "sent"),
                          ("publish-chain", "no answer within 3 seconds")])

    def test_a_refused_chain_send_leaves_an_attempt_row_and_never_the_url(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish-chain", "http://127.0.0.1:9/hook")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "logged entry 2")
        self.assertEqual(result.stderr, "")
        self.assertEqual(chain_rows(self.chain()), [])
        (row,) = attempt_rows(self.chain())
        self.assertEqual(set(row), {"kind", "step", "ts", "budget", "outcome"})
        self.assertEqual(row["step"], "publish-chain")
        self.assertEqual(row["budget"], 3.0)
        self.assertNotEqual(row["outcome"], "sent")
        self.assertTrue(row["outcome"], "the outcome must say what happened")
        memo = self.chain().with_name(
            self.chain().name + ".published.jsonl").read_text("utf-8")
        self.assertNotIn("127.0.0.1", memo)
        self.assertNotIn("/hook", memo)
        # The next send resumes from the same cursor: genesis.
        self.receiver.chain = self.chain()
        self.session_end("--publish-chain", self.receiver.url)
        (sent,) = self.receiver.received
        self.assertEqual(sent["headers"]["x-loxodonta-range"], "0-2")
        self.assertEqual(sent["raw"], self.chain_lines())

    def test_a_memo_that_cannot_be_read_is_a_note_and_never_a_traceback(self):
        # Without the cursor there is no send, and a memo that exists
        # and cannot be read at all — here, bytes that are not UTF-8 —
        # must not turn the quiet path into a traceback and a failed
        # hook. The row says which bookkeeping failed; the entries wait.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        memo = self.chain().with_name(self.chain().name + ".published.jsonl")
        memo.write_bytes(b"\xff\xfe not a memo\n")

        result = self.session_end("--publish-chain", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "logged entry 2")
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.receiver.received, [])
        row = json.loads(memo.read_bytes().splitlines()[-1]
                         .decode("utf-8", "replace"))
        self.assertEqual((row["kind"], row["step"], row["outcome"]),
                         ("attempt", "publish-chain",
                          "the memo could not be read"))

    def test_a_second_session_end_with_nothing_new_sends_nothing_and_leaves_no_row(self):
        # An unchanged transcript seals nothing, so the chain holds
        # nothing after the cursor: the step did not run, and the memo
        # gains neither a chain row nor a note.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.session_end("--publish-chain", self.receiver.url)
        self.assertEqual(len(self.receiver.received), 1)

        result = self.session_end("--publish-chain", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.receiver.received), 1)
        self.assertEqual(len(chain_rows(self.chain())), 1)
        self.assertEqual(len(attempt_rows(self.chain())), 1)

    def one_entry_per_batch(self):
        """The batch cap set to the longest line this chain holds, so
        every batch is one entry and the loop above `post_bounded` is
        something a test can watch. Restored when the test ends."""
        cap = max(len(line) for line
                  in self.chain().read_bytes().splitlines(True))
        os.environ["LOXODONTA_CHAIN_BATCH_BYTES"] = str(cap)
        self.addCleanup(os.environ.pop, "LOXODONTA_CHAIN_BATCH_BYTES", None)

    def test_a_budget_that_runs_out_between_batches_keeps_what_landed(self):
        # Each batch is acknowledged on its own, so a window spent
        # part-way through a tail leaves the batches that landed, their
        # rows, and a cursor, and the next send starts at the entry after
        # it. Where the window closes is the clock's business. Between
        # two batches, the one attempt row names the entry it stopped
        # short of. Inside one, the batch is cut off at what the window
        # had left, never past it (#262): it is not written down, so it
        # goes again next time and a receiver that already took it drops
        # the duplicate.
        self.transcript.write_bytes(b"page one\n")
        # The first call is deliberately the longest line this chain
        # will hold, so the cap taken from it also fits the commitment
        # the session end is about to seal in.
        self.tool_call("x" * 150)
        for step in range(3):
            self.tool_call(f"step {step}")
        self.one_entry_per_batch()
        self.receiver.chain_delay = 0.6   # of the Codex budget's 1.5

        result = self.session_end("--publish-chain", self.receiver.url,
                                  "--actor", "codex")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        rows = chain_rows(self.chain())
        self.assertTrue(rows, "the batches that landed keep their rows")
        self.assertEqual([(row["first"], row["last"]) for row in rows],
                         [(n, n) for n in range(len(rows))])
        (attempt,) = attempt_rows(self.chain())
        between = re.fullmatch(
            r"the budget of 1\.5 seconds ran out before entry (\d+)",
            attempt["outcome"])
        inside = re.fullmatch(r"no answer within (\d\.\d) seconds",
                              attempt["outcome"])
        self.assertTrue(between or inside, attempt["outcome"])
        if between:
            self.assertEqual(int(between.group(1)), rows[-1]["last"] + 1,
                             "the budget stops at the entry after the cursor")
        else:
            self.assertLess(float(inside.group(1)), 1.5,
                            "a later batch waits only what the window left")

        # The rest is the next turn's, resumed from the same cursor.
        self.receiver.chain_delay = 0
        before = len(self.receiver.received)
        rest = run_recorder("publish", "--chain", "--log", self.chain(),
                            self.receiver.url)

        self.assertEqual(rest.returncode, 0, rest.stderr)
        resumed = self.receiver.received[before]["headers"]["x-loxodonta-range"]
        self.assertEqual(int(resumed.split("-")[0]), rows[-1]["last"] + 1)
        # Every line reached the far end, in order; the one repeat a
        # receiver can see is the batch the window cut off, which the
        # receiver's append rule drops (docs/RECEIVER.md section 4).
        self.assertEqual(b"".join(dict.fromkeys(
                             sent["raw"] for sent in self.receiver.received)),
                         self.chain_lines(),
                         "every line, in order, across both turns")

    def test_a_codex_hook_gives_the_chain_half_the_cap(self):
        # The same budget rule as the head (#183): a Codex hook waits
        # 1.5 seconds for its POST, and the attempt row says so.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish-chain", self.receiver.url,
                                  "--actor", "codex")

        self.assertEqual(result.returncode, 0, result.stderr)
        (row,) = attempt_rows(self.chain())
        self.assertEqual((row["step"], row["outcome"], row["budget"]),
                         ("publish-chain", "sent", 1.5))

    def test_a_non_http_url_publishes_nothing_and_still_seals(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        target = self.root / "never-opened.txt"

        result = self.session_end("--publish-chain",
                                  f"file:///{target.as_posix()}")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertFalse(target.exists())
        self.assertEqual(memo_of(self.chain()), [])
        last = json.loads(self.chain_lines().splitlines()[-1])
        self.assertTrue(last["action"].startswith("transcript-commitment:"))

    def test_a_session_without_receipts_publishes_nothing(self):
        result = self.hook({"session_id": "sess-chat-only",
                            "hook_event_name": "SessionEnd",
                            "reason": "prompt_input_exit",
                            "transcript_path": str(self.transcript)},
                           "--publish-chain", self.receiver.url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receiver.received, [])

    def test_the_receivers_file_verifies_valid_after_a_session_ends(self):
        # The acceptance test, end to end: the hook at session end sends
        # to the repo's own receiver, whose file is then a receipt log
        # the recorder judges VALID; a second session end carries only
        # what came after, and the file still verifies.
        receiver = start_receiver(self, self.root / "receiver")
        self.transcript.write_bytes(b"page one\n")
        self.tool_call("echo one")
        self.tool_call("echo two")

        result = self.session_end("--publish", receiver.url,
                                  "--publish-chain", receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        copy = self.root / "receiver" / self.chain().name
        self.assertEqual(copy.read_bytes(), self.chain_lines())
        heads = (self.root / "receiver" / "heads.jsonl").read_text("utf-8")
        self.assertEqual(json.loads(heads)["head"], self.head())

        self.transcript.write_bytes(b"page one\npage two\n")
        self.tool_call("echo three")
        self.session_end("--publish-chain", receiver.url)

        self.assertEqual(copy.read_bytes(), self.chain_lines())
        self.assertEqual([(r["first"], r["last"])
                          for r in chain_rows(self.chain())],
                         [(0, 3), (4, 5)])
        judged = run_recorder("verify", "--log", copy)
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertEqual(judged.stdout.strip(), "VALID")


class SessionEndWindowTest(PublishBase):
    """One session-end window, not one budget per step (#262). Codex caps
    the whole SessionEnd hook at three seconds, and every quick step of
    a Codex session end shares half of it: the head, then the chain,
    then the stamp, each waiting its own bound or what the steps before
    it left, whichever is less. A step with nothing left does not start
    and writes that down, so the harness's cap is never what stops a
    step before its row is written. In the #183 pattern: silent local
    servers, the hook's own clock judged against the cap, and the rows
    saying what the clock cannot."""

    def silent(self):
        """A remote that takes the request and never answers in time."""
        server = serve_fake(self)
        server.delay = 6
        server.chain_delay = 6
        return server

    def stamp_attempts(self):
        stamps = self.chain().with_name(self.chain().name + ".stamps.jsonl")
        if not stamps.exists():
            return []
        return [row for row in map(json.loads, stamps.read_text(
                    encoding="utf-8").splitlines())
                if row.get("kind") == "attempt"]

    def rows_by_step(self):
        return {row["step"]: (row["budget"], row["outcome"])
                for row in attempt_rows(self.chain()) + self.stamp_attempts()}

    def ended_codex(self, head, chain, stamp):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        started = time.monotonic()
        result = self.session_end("--actor", "codex", "--publish", head.url,
                                  "--publish-chain", chain.url,
                                  "--stamp", stamp.url)
        took = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return took

    def test_three_silent_remotes_end_inside_codexs_cap_with_a_row_each(self):
        # Before the window each step waited its own 1.5 seconds, and
        # three silent remotes held a Codex hook to 4.7 (#262): killed,
        # and the steps after the one running never said so.
        head, chain, stamp = self.silent(), self.silent(), self.silent()

        took = self.ended_codex(head, chain, stamp)

        self.assertLess(took, 3, "Codex would have killed the hook")
        self.assertGreater(took, 1, "the head was never waited on")
        self.assertEqual(self.rows_by_step(), {
            "publish-head": (1.5, "no answer within 1.5 seconds"),
            "publish-chain": (0.0, WINDOW_CLOSED),
            "stamp": (0.0, WINDOW_CLOSED)})
        self.assertEqual((len(chain.received), len(stamp.received)), (0, 0),
                         "a step the window closed on never starts")
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("transcript-commitment:"))

    def test_a_head_that_answers_leaves_the_rest_of_the_window_to_the_chain(self):
        head = serve_fake(self)
        chain, stamp = self.silent(), self.silent()

        took = self.ended_codex(head, chain, stamp)

        self.assertLess(took, 3, "Codex would have killed the hook")
        rows = self.rows_by_step()
        self.assertEqual(rows["publish-head"], (1.5, "sent"))
        waited, outcome = rows["publish-chain"]
        self.assertTrue(0 < waited <= 1.5, waited)
        self.assertEqual(outcome, f"no answer within {waited:g} seconds")
        self.assertEqual(rows["stamp"], (0.0, WINDOW_CLOSED))
        self.assertEqual(len(stamp.received), 0)

    def test_claude_code_keeps_three_seconds_a_step(self):
        # Claude Code's twenty-second hook already fits three silent
        # steps and the anchor inside its twelve-second window, so its
        # bounds are unchanged: each quick step still waits three
        # seconds, and nothing closes on the chain.
        head, chain = self.silent(), self.silent()
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish", head.url,
                                  "--publish-chain", chain.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rows_by_step(), {
            "publish-head": (3.0, "no answer within 3 seconds"),
            "publish-chain": (3.0, "no answer within 3 seconds")})


class InstallPublishChainTest(unittest.TestCase):
    """`install-hook --profile custom --publish-chain URL` writes
    `--publish-chain URL` onto the wired SessionEnd command, the way
    `--publish-head` writes `--publish` (ADR-0031 ruling 1, under
    `custom` in this slice): readable in the settings file, recorded in
    the coverage marker as the remote the entries go to, said before
    anything is written, idempotent, removed by `uninstall-hook`."""

    URL = "https://shelf.example.test:8790/7qpsWUkU86ML-NOuaGjSaetfYCGg"
    HEAD_URL = "https://hooks.example.test/services/T000/B000/XXXX"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = self.root / "store"
        # CODEX_HOME inside the temp home too: a machine that sets it
        # would otherwise get this test's hooks in its real hooks.json.
        self.env = {"HOME": str(self.home), "USERPROFILE": str(self.home),
                    "LOXODONTA_HOME": str(self.store),
                    "CODEX_HOME": str(self.home / ".codex")}

    def install(self, *args):
        return subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook", *args],
            cwd=self.root, capture_output=True, encoding="utf-8",
            env={**clean_env(), **self.env})

    def settings_text(self):
        path = self.home / ".claude" / "settings.json"
        return path.read_text(encoding="utf-8") if path.exists() else "{}"

    def commands(self, event):
        hooks = json.loads(self.settings_text())["hooks"]
        return [h["command"] for b in hooks[event] for h in b["hooks"]]

    def epochs(self):
        return json.loads((self.store / "coverage.json")
                          .read_text(encoding="utf-8"))["epochs"]

    def test_custom_with_publish_chain_wires_the_flag_and_records_the_remote(self):
        result = self.install("--profile", "custom", "--publish-chain", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(f' --publish-chain "{self.URL}"'), end)
        # No network call in the recording path (ADR-0024 ruling 1).
        self.assertNotIn("--publish", json.dumps(self.commands("PostToolUse")))
        # The installer states the choice, URL included.
        self.assertIn("publishes the chain to " + self.URL, result.stdout)
        self.assertIn("profile custom", result.stdout)
        # The marker's epoch records the remote beside the profile: it
        # never travels, so unlike the memo it may hold the URL.
        (epoch,) = self.epochs()
        self.assertEqual((epoch["profile"], epoch["remote"]),
                         ("custom", self.URL))
        # The flag with the word left off is the same install.
        again = self.install("--publish-chain", self.URL)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already installed", again.stdout)
        self.assertEqual(len(self.commands("SessionEnd")), 1)
        self.assertEqual(len(self.epochs()), 1, "a re-run never grows the marker")

    def test_the_installer_says_what_leaves_before_it_writes(self):
        # ADR-0031: the entries carry action lines, which are command
        # lines, and file paths, and the install text says so before the
        # first send. The what-leaves text comes before the write line.
        result = self.install("--profile", "custom", "--publish-chain", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        said = result.stdout
        self.assertIn("every entry", said)
        self.assertIn("action line", said)
        self.assertIn("command lines", said)
        self.assertIn("anything the agent typed", said)
        # And the store's past: the keeper walks every chain there and
        # sends each from genesis, once a `serve` is given the flag.
        self.assertIn("A `supervisor serve` run with --publish-chain also "
                      "sends every chain already in the store, from its "
                      "first entry.", said)
        self.assertLess(said.index("every entry"), said.index("installed in"))
        # A head-only install says nothing of the kind: only the head
        # leaves, and ADR-0025 said what that is.
        head_only = self.install("--publish-head", self.HEAD_URL)
        self.assertNotIn("anything the agent typed", head_only.stdout)

    def test_a_raw_flag_beside_a_named_profile_is_refused_naming_custom(self):
        for profile in ("local", "timestamped"):
            result = self.install("--profile", profile,
                                  "--publish-chain", self.URL)
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("--profile custom", result.stderr)
            self.assertIn("--publish-chain", result.stderr)
            self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                             "a refusal writes nothing")

    def test_both_publishes_and_the_anchor_ride_on_the_one_command(self):
        result = self.install("--anchor-at-session-end",
                              "--publish-head", self.HEAD_URL,
                              "--publish-chain", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertIn(" --anchor", end)
        self.assertIn(f' --publish "{self.HEAD_URL}"', end)
        self.assertTrue(end.endswith(f' --publish-chain "{self.URL}"'), end)
        self.assertIn("anchors at session end", result.stdout)
        self.assertIn(self.HEAD_URL, result.stdout)
        self.assertIn(self.URL, result.stdout)

    def test_a_rerun_without_the_flag_turns_the_chain_off_and_says_so(self):
        self.install("--publish-chain", self.URL)

        result = self.install()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--publish-chain", self.settings_text())
        self.assertNotIn(self.URL, self.settings_text())
        self.assertIn("no longer publishes the chain", result.stdout)
        # The marker's newest epoch no longer names the remote.
        self.assertEqual([e.get("remote") for e in self.epochs()],
                         [self.URL, None])

    def test_uninstall_removes_the_flag_with_the_hook(self):
        self.install("--publish-chain", self.URL)

        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "uninstall-hook"],
            cwd=self.root, capture_output=True, encoding="utf-8",
            env={**clean_env(), **self.env})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("loxodonta.py", self.settings_text())
        self.assertNotIn("--publish-chain", self.settings_text())
        self.assertNotIn(self.URL, self.settings_text())

    def test_the_installer_refuses_a_url_a_shell_could_act_on(self):
        for bad in ("file:///tmp/receipts.jsonl", "shelf.example.test/x",
                    "https://shelf.example.test/$(id)",
                    "https://shelf.example.test/a b"):
            result = self.install("--publish-chain", bad)
            self.assertEqual(result.returncode, 64, bad + ": " + result.stderr)
            self.assertIn("--publish-chain", result.stderr)
            self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                             bad)

    def test_codex_wires_the_chain_on_its_shorter_clock(self):
        # Codex caps the whole SessionEnd hook at three seconds, so the
        # send gets half of it, as the head's POST does (#183). A short
        # clock costs batches and never entries: what did not fit stays
        # at the cursor for the keeper, which is what the cursor is for.
        # (The anchor stays refused there because a calendar round trip
        # has nothing to resume from.)
        (self.home / ".codex").mkdir()

        result = self.install("--codex", "--profile", "custom",
                              "--publish-chain", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = json.loads((self.home / ".codex" / "hooks.json")
                           .read_text(encoding="utf-8"))["hooks"]
        [block] = hooks["SessionEnd"]
        [wired] = block["hooks"]
        self.assertTrue(
            wired["command"].endswith(f' --publish-chain "{self.URL}"'),
            wired["command"])
        self.assertEqual(wired["timeout"], 3)
        self.assertIn("publishes the chain to " + self.URL, result.stdout)
        self.assertIn("every entry", result.stdout)
        (epoch,) = self.epochs()
        self.assertEqual((epoch["harness"], epoch["remote"]),
                         ("codex", self.URL))


class PublishChainKeeperTest(unittest.TestCase):
    """`scan|serve --publish-every AGE --publish-url URL --publish-chain
    URL`: on the keeper's turn the head goes first and the chain's
    entries since the cursor after it, through the recorder's command,
    at most once each per throttle window (ADR-0031 ruling 3). The
    chain route is its own opt-in: the head's flags alone never send
    an entry anywhere."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.receiver = serve_fake(self)

    def scan(self, *extra, **knobs):
        return run_scan(self.root, *extra, env=keeper_env(**knobs))

    def kinds(self):
        return [sent["content_type"] for sent in self.receiver.received]

    def test_the_turn_sends_the_head_then_the_chain_once_per_window(self):
        log = make_store_chain(self.root / "alpha" / "receipts", "sess-turn")
        head = chain_head(log)

        result = self.scan("--publish-every", "0s",
                           "--publish-url", self.receiver.url,
                           "--publish-chain", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.kinds(), ["application/json", NDJSON])
        self.assertEqual(json.loads(self.receiver.received[0]["raw"])["head"],
                         head)
        batch = self.receiver.received[1]
        self.assertEqual(batch["raw"], log.read_bytes())
        self.assertEqual(batch["headers"]["x-loxodonta-range"], "0-2")
        self.assertEqual(batch["headers"]["x-loxodonta-session"], "sess-turn")
        self.assertEqual([row.get("kind") for row in memo_of(log)],
                         [None, "chain"])
        self.assertEqual(chain_rows(log)[0]["event"], "cadence")

        # The same tick again, inside the throttle window: nothing moves.
        again = self.scan("--publish-every", "0s",
                          "--publish-url", self.receiver.url,
                          "--publish-chain", self.receiver.url)
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(len(self.receiver.received), 2)

        # A chain that grew, on the next window: the new head, and only
        # the lines after the cursor.
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "step 3"],
            capture_output=True, check=True)
        grown = self.scan("--publish-every", "0s",
                          "--publish-url", self.receiver.url,
                          "--publish-chain", self.receiver.url,
                          SUPERVISOR_UPGRADE_EVERY_SECONDS="0")
        self.assertEqual(grown.returncode, 0, grown.stdout + grown.stderr)
        self.assertEqual(self.kinds(),
                         ["application/json", NDJSON,
                          "application/json", NDJSON])
        self.assertEqual(self.receiver.received[3]["headers"]
                         ["x-loxodonta-range"], "3-3")
        self.assertEqual(self.receiver.received[3]["raw"],
                         log.read_bytes().splitlines(True)[-1])
        self.assertEqual([(r["first"], r["last"]) for r in chain_rows(log)],
                         [(0, 2), (3, 3)])

    def test_the_heads_flags_alone_send_no_entry_and_the_chain_flag_alone_no_head(self):
        # Each route is its own opt-in (ADR-0031 rulings 1 and 6): an
        # operator whose --publish-url is a chat webhook never has
        # command lines posted to it because a release added a route.
        log = make_store_chain(self.root / "alpha" / "receipts", "sess-routes")

        head_only = self.scan("--publish-every", "0s",
                              "--publish-url", self.receiver.url)

        self.assertEqual(head_only.returncode, 0, head_only.stderr)
        self.assertEqual(self.kinds(), ["application/json"])
        self.assertEqual(chain_rows(log), [])

        chain_only = self.scan("--publish-every", "0s",
                               "--publish-chain", self.receiver.url,
                               SUPERVISOR_UPGRADE_EVERY_SECONDS="0")

        self.assertEqual(chain_only.returncode, 0, chain_only.stderr)
        self.assertEqual(self.kinds(), ["application/json", NDJSON])
        self.assertEqual(len(head_rows(log)), 1)
        self.assertEqual(len(chain_rows(log)), 1)

    def test_a_chain_row_never_stands_the_head_keeper_down(self):
        # A chain row carries the head after its last entry, for the
        # operator's reading; it is not a head row, and the head route
        # still owes this head to its own remote.
        log = make_store_chain(self.root / "alpha" / "receipts", "sess-apart")
        sent = run_recorder("publish", "--chain", "--log", log,
                            self.receiver.url)
        self.assertEqual(sent.returncode, 0, sent.stderr)
        self.assertEqual(self.kinds(), [NDJSON])

        result = self.scan("--publish-every", "0s",
                           "--publish-url", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.kinds(), [NDJSON, "application/json"])
        self.assertEqual(json.loads(self.receiver.received[1]["raw"])["head"],
                         chain_head(log))

    def test_a_dead_chain_remote_is_a_note_in_left_and_never_the_exit(self):
        log = make_store_chain(self.root / "alpha" / "receipts", "sess-dead")

        result = self.scan("--publish-every", "0s",
                           "--publish-chain", "http://127.0.0.1:9/hook")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["exit"], 0)
        (chain,) = chains_by_session(report)[("alpha", "sess-dead")]
        self.assertTrue(chain["left"]["failed"])
        self.assertIn("publishing failed", chain["left"]["note"])
        self.assertIn("entries stay unsent", chain["left"]["note"])
        self.assertIsNone(chain["left"]["ts"])
        self.assertNotIn("127.0.0.1:9", result.stdout,
                         "the URL is a credential; the report never holds it")
        self.assertEqual(chain_rows(log), [])
        # The note outlives this tick's report (#251): the keeper's turn
        # ran the verb, and the verb wrote down how it went.
        (note,) = attempt_rows(log)
        self.assertEqual(note["step"], "publish-chain")
        self.assertNotEqual(note["outcome"], "sent")
        self.assertNotIn("127.0.0.1", json.dumps(memo_of(log)))
        self.assertEqual(chain["last_failed"]["step"], "publish-chain")

    def test_a_url_without_a_cadence_is_a_usage_error(self):
        make_store_chain(self.root / "alpha" / "receipts", "sess-half")
        for half in (("--publish-every", "0s"),
                     ("--publish-chain", self.receiver.url)):
            result = self.scan(*half)
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("--publish-every", result.stderr)
            self.assertIn("--publish-chain", result.stderr)
        self.assertEqual(self.receiver.received, [])

    def test_serve_sends_both_on_its_tick_and_says_so_at_startup(self):
        log = make_store_chain(self.root / "alpha" / "receipts", "sess-face")
        proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0",
             "--publish-every", "0s",
             "--publish-url", self.receiver.url,
             "--publish-chain", self.receiver.url],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env=keeper_env(PYTHONIOENCODING="utf-8"))

        def stop():
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

        self.addCleanup(stop)
        line = proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if match is None:
            proc.kill()
            _, err = proc.communicate()
            self.fail(f"serve announced no localhost URL: {line!r}\n{err}")
        # The keeper line, read before anything stops the process: a
        # kill sent the instant the URL line arrives can beat the second
        # flush (what CI on Linux and macOS showed the last wave).
        said = proc.stdout.readline()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(match.group() + "/api/status", timeout=30) as answer:
            status = json.loads(answer.read().decode("utf-8"))
        stop()

        self.assertIn("publish head and chain every", said)
        self.assertIn("flag --publish-every", said)
        self.assertEqual(self.kinds(), ["application/json", NDJSON])
        (chain,) = chains_by_session(status)[("alpha", "sess-face")]
        # Both routes sent on this one tick, a second apart at most, so
        # which of the two doors is the newer is a coin toss; that the
        # door is a publish door and not the anchor is the reading.
        # Which route `via` names is pinned at the reader, in
        # test_publish_keeper.LeftReadingTest.
        self.assertIn(chain["left"]["via"], ("published", "published-chain"))
        self.assertEqual(status["exit"], 0)
        self.assertEqual([row.get("kind") for row in memo_of(log)],
                         [None, "chain"])


class InstallProfileFullTest(unittest.TestCase):
    """`install-hook --profile full --remote URL` (ADR-0031 ruling 1,
    issue #249): the tier that sends the entries themselves. One word
    wires the session-end anchor, the head publish and the chain publish,
    and all three go to the one URL the operator names, because the far
    end tells a head from a batch by content type and a second URL would
    only be a way to get it wrong. Without a remote there is no such
    tier: refused, nothing written, and the two ways to get one printed.
    `custom` keeps the raw flags."""

    URL = "https://shelf.example.test:8790/7qpsWUkU86ML-NOuaGjSaetfYCGg"
    OTHER = "https://hooks.example.test/services/T000/B000/XXXX"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = self.root / "store"
        # CODEX_HOME inside the temp home too: a machine that sets it
        # would otherwise get this test's hooks in its real hooks.json.
        self.env = {"HOME": str(self.home), "USERPROFILE": str(self.home),
                    "LOXODONTA_HOME": str(self.store),
                    "CODEX_HOME": str(self.home / ".codex")}

    def install(self, *args):
        return subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook", *args],
            cwd=self.root, capture_output=True, encoding="utf-8",
            env={**clean_env(), **self.env})

    def settings_text(self):
        path = self.home / ".claude" / "settings.json"
        return path.read_text(encoding="utf-8") if path.exists() else "{}"

    def commands(self, event):
        hooks = json.loads(self.settings_text())["hooks"]
        return [h["command"] for b in hooks[event] for h in b["hooks"]]

    def codex_hook(self):
        hooks = json.loads((self.home / ".codex" / "hooks.json")
                           .read_text(encoding="utf-8"))["hooks"]
        [block] = hooks["SessionEnd"]
        [wired] = block["hooks"]
        return wired

    def epochs(self):
        marker = self.store / "coverage.json"
        if not marker.exists():
            return []
        return json.loads(marker.read_text(encoding="utf-8"))["epochs"]

    def test_full_wires_the_anchor_and_both_publishes_to_the_one_remote(self):
        result = self.install("--profile", "full", "--remote", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(
            end.endswith(f' --anchor --publish "{self.URL}"'
                         f' --publish-chain "{self.URL}"'), end)
        # No network call in the recording path (ADR-0024 ruling 1).
        self.assertNotIn("--publish", json.dumps(self.commands("PostToolUse")))
        # The installer reads all three choices back, in the mechanisms'
        # own words, and the tier in one line.
        self.assertIn("anchors at session end", result.stdout)
        self.assertIn("publishes the head to " + self.URL, result.stdout)
        self.assertIn("publishes the chain to " + self.URL, result.stdout)
        self.assertIn("profile full", result.stdout)
        # The marker's newest epoch carries the tier and the remote; it
        # never travels, so unlike the memo it may hold the URL.
        (epoch,) = self.epochs()
        self.assertEqual((epoch["profile"], epoch["remote"]),
                         ("full", self.URL))
        # A re-run at the same tier rewires nothing and never grows the
        # marker (ADR-0030 ruling 1).
        again = self.install("--profile", "full", "--remote", self.URL)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already installed", again.stdout)
        self.assertEqual(len(self.commands("SessionEnd")), 1)
        self.assertEqual(len(self.epochs()), 1)

    def test_full_without_a_remote_writes_nothing_and_says_how_to_get_one(self):
        # The tier is the two publishes to a URL the operator names, so
        # there is no tier without one. A command spoken wrong is exit
        # 64 (ADR-0026 ruling 7), and the refusal is where the beginner
        # is standing, so it carries both ways to have a remote.
        result = self.install("--profile", "full")

        self.assertEqual(result.returncode, 64, result.stdout)
        said = result.stderr
        self.assertIn("--remote URL", said)
        self.assertIn("receiver.py", said)
        self.assertIn("docs/RECEIVER.md", said)
        self.assertIn("appends", said)
        self.assertIn("refuses delete", said)
        self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                         "a refusal writes nothing")
        self.assertEqual(self.epochs(), [], "and marks no coverage")

    def test_a_remote_beside_any_other_profile_is_refused(self):
        # A remote nothing sends to is worse than no remote: the operator
        # would read their own command as the entries leaving.
        for spoken_wrong in (("--remote", self.URL),
                             ("--profile", "local", "--remote", self.URL),
                             ("--profile", "timestamped", "--remote", self.URL),
                             ("--profile", "custom", "--remote", self.URL)):
            result = self.install(*spoken_wrong)
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("--profile full", result.stderr)
            self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                             " ".join(spoken_wrong))

    def test_a_raw_flag_beside_full_is_refused_naming_custom(self):
        result = self.install("--profile", "full", "--remote", self.URL,
                              "--publish-head", self.OTHER)

        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("--profile custom", result.stderr)
        self.assertFalse((self.home / ".claude" / "settings.json").exists())

    def test_the_what_leaves_text_is_said_once_before_the_settings_file(self):
        # ADR-0031: at `full` every entry leaves, and the installer says
        # so before it writes anything. Once, not once per route. Not
        # only the sessions still to come: `serve` follows the profile
        # with no flag typed and walks every chain in the store, so on
        # its first turn last month's sessions leave too, each from its
        # first entry, and the text says that as well.
        result = self.install("--profile", "full", "--remote", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        said = result.stdout
        self.assertIn("every entry", said)
        self.assertIn("the timestamp, the actor, the action line and the "
                      "file references", said)
        self.assertIn("command lines", said)
        self.assertIn("anything the agent typed", said)
        self.assertIn("`supervisor serve`, when it runs, then also sends "
                      "every chain already in the store, from its first "
                      "entry.", said)
        self.assertEqual(said.count("anything the agent typed"), 1)
        self.assertLess(said.index("every entry"), said.index("installed in"))

    def test_the_codex_half_says_it_once_before_its_settings_file_too(self):
        (self.home / ".codex").mkdir()

        result = self.install("--codex", "--profile", "full",
                              "--remote", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        said = result.stdout
        self.assertEqual(said.count("anything the agent typed"), 1)
        self.assertLess(said.index("every entry"), said.index("installed in"))

    def test_codex_wires_both_publishes_and_the_anchor_stays_refused(self):
        # Codex caps the whole SessionEnd hook at three seconds, so each
        # send gets half of it (#183), and a calendar round trip has no
        # cursor to resume from, so the anchor stays refused there
        # (ADR-0024) and the notice says who anchors instead.
        (self.home / ".codex").mkdir()

        result = self.install("--codex", "--profile", "full",
                              "--remote", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        wired = self.codex_hook()
        self.assertTrue(
            wired["command"].endswith(f' --publish "{self.URL}"'
                                      f' --publish-chain "{self.URL}"'),
            wired["command"])
        self.assertNotIn("--anchor", wired["command"])
        self.assertEqual(wired["timeout"], 3)
        self.assertIn("profile full", result.stdout)
        self.assertIn("the session-end anchor stays refused for Codex",
                      result.stdout)
        self.assertIn("anchors every six hours", result.stdout)
        (epoch,) = self.epochs()
        self.assertEqual((epoch["harness"], epoch["profile"], epoch["remote"]),
                         ("codex", "full", self.URL))

    def test_uninstall_after_full_leaves_no_flag_and_writes_no_epoch(self):
        self.install("--profile", "full", "--remote", self.URL)
        before = self.epochs()

        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "uninstall-hook"],
            cwd=self.root, capture_output=True, encoding="utf-8",
            env={**clean_env(), **self.env})

        self.assertEqual(result.returncode, 0, result.stderr)
        left = self.settings_text()
        self.assertNotIn("loxodonta.py", left)
        for flag in ("--anchor", "--publish", "--publish-chain"):
            self.assertNotIn(flag, left)
        self.assertNotIn(self.URL, left)
        # ADR-0030's asymmetry: a start claim says more calls owe
        # receipts and an end claim says fewer, and "nothing was owed
        # from here" is the one sentence that could retire the
        # completeness alarm. So uninstall writes nothing down.
        self.assertEqual(self.epochs(), before)

    def test_custom_writes_down_the_head_url_when_no_chain_is_wired(self):
        # The marker's `remote` is where publishing goes: at `full` the
        # one URL, and under `custom` the chain's when one was given,
        # the head's otherwise (#249). `serve` follows it only at `full`.
        head_only = self.install("--publish-head", self.OTHER)

        self.assertEqual(head_only.returncode, 0, head_only.stderr)
        self.assertEqual(self.epochs()[-1]["profile"], "custom")
        self.assertEqual(self.epochs()[-1]["remote"], self.OTHER)

        both = self.install("--publish-head", self.OTHER,
                            "--publish-chain", self.URL)

        self.assertEqual(both.returncode, 0, both.stderr)
        self.assertEqual(self.epochs()[-1]["remote"], self.URL)


class SessionEndUnderFullTest(PublishBase):
    """The tier end to end (#249, ADR-0031 ruling 1). What `install-hook
    --profile full --remote URL` wrote onto the SessionEnd command is the
    command this test runs, and at the far end sits the repo's own
    receiver as a subprocess. One URL takes both routes — the head as
    ADR-0025's JSON body, the entries as their own bytes — and the file
    the receiver wrote is then a receipt log the recorder judges on that
    box, with no new code."""

    def setUp(self):
        super().setUp()
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)

    def install(self, *args):
        return subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook", *args],
            cwd=self.root, capture_output=True, encoding="utf-8",
            env={**clean_env(), "HOME": str(self.home),
                 "USERPROFILE": str(self.home),
                 "LOXODONTA_HOME": str(self.store),
                 "CODEX_HOME": str(self.home / ".codex")})

    def wired_session_end(self):
        """The argv the installer wrote, read back out of the settings
        file: what the harness would run at a session end, run here."""
        settings = json.loads((self.home / ".claude" / "settings.json")
                              .read_text(encoding="utf-8"))
        [command] = [hook["command"]
                     for block in settings["hooks"]["SessionEnd"]
                     for hook in block["hooks"]]
        return shlex.split(command)

    def test_a_session_that_ends_under_full_fills_the_one_remote(self):
        receiver = start_receiver(self, self.root / "receiver")
        # The wired command carries --anchor and names no calendar, so
        # this one flag is appended to keep the digest on this machine.
        # Every other word of the command is the installer's own.
        calendar = self.calendar()
        installed = self.install("--profile", "full", "--remote", receiver.url)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.transcript.write_bytes(b"page one\n")
        self.tool_call("echo one")
        self.tool_call("echo two")

        env = clean_env()
        env["CLAUDE_PROJECT_DIR"] = str(self.project)
        env["LOXODONTA_HOME"] = str(self.store)
        payload = {"session_id": self.SESSION,
                   "hook_event_name": "SessionEnd",
                   "reason": "prompt_input_exit",
                   "transcript_path": str(self.transcript)}
        ended = subprocess.run(
            self.wired_session_end() + ["--calendar", calendar.url],
            cwd=self.project, input=json.dumps(payload).encode("utf-8"),
            capture_output=True, env=env)

        self.assertEqual(ended.returncode, 0,
                         ended.stderr.decode("utf-8", "replace"))
        # The head is the sealed one, and it went as JSON to the heads file.
        heads = (self.root / "receiver" / "heads.jsonl").read_text("utf-8")
        self.assertEqual(json.loads(heads)["head"], self.head())
        # The entries went to the same URL, as the chain's own bytes, into
        # a file the receiver named from the header.
        copy = self.root / "receiver" / self.chain().name
        self.assertEqual(copy.read_bytes(), self.chain().read_bytes())
        # And the digest reached a calendar: the third step `full` wired.
        self.assertEqual([d.hex() for d in calendar.submitted], [self.head()])
        # The acceptance test: the receiver's file is a receipt log, and
        # the operator on that box judges it with the recorder they have.
        judged = run_recorder("verify", "--log", copy)
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertEqual(judged.stdout.strip(), "VALID")


class FullProfileKeeperTest(unittest.TestCase):
    """`serve` with a `full` marker and no publish flags (#249, ADR-0031
    ruling 1, #246): the publish keeper runs on the six-hour default to
    the remote the install wrote down, the head first and the chain
    after it, beside the anchor keeper on the same default. The startup
    line names both routes, the cadence and where the choice came from.
    A flag typed at `serve` wins, and wins whole — the cadence and the
    target — so the marker's remote is never a second place the entries
    also go."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.root = base / "repos"
        self.root.mkdir()
        self.home = base / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = base / "store"
        # Beside the settings the installer writes: the keeper follows
        # a profile only while that harness's recorder is wired there.
        self.witness = self.home / ".claude" / "projects"
        self.witness.mkdir()
        self.receiver = serve_fake(self)
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

    def install(self, *args):
        """The real installer writes the marker the keeper reads, into
        this test's store; its settings land in a throwaway home."""
        subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook", *args],
            capture_output=True, check=True,
            env=keeper_env(HOME=str(self.home), USERPROFILE=str(self.home),
                           LOXODONTA_HOME=str(self.store),
                           CODEX_HOME=str(self.home / ".codex")))

    def aged_chain(self, session, age):
        """A chain through the public CLI whose entries are `age` seconds
        old (SOURCE_DATE_EPOCH, the recorder's clock override), so a
        cadence shorter than `age` finds its head ripe."""
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
        # The keeper line, read here rather than after the tick: `serve`
        # writes the two lines as two flushes, and a kill sent the
        # instant the first arrives can land before the second is
        # written, which is what CI on Linux and macOS showed.
        self.said = self.proc.stdout.readline()

    def _stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.communicate()

    def tick(self):
        """One request, which is one tick of both keepers."""
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(self.url + "/api/status", timeout=30) as answer:
            return json.loads(answer.read().decode("utf-8"))

    def kinds(self, server=None):
        return [sent["content_type"]
                for sent in (server or self.receiver).received]

    def test_a_full_marker_sends_both_routes_on_the_six_hour_default(self):
        self.install("--profile", "full", "--remote", self.receiver.url)
        log = self.aged_chain("sess-full", age=7 * 3600)

        self.serve()
        self.tick()
        self._stop()

        self.assertIn("anchor every 6h (profile full, claude-code)", self.said)
        self.assertIn("publish head and chain every 6h "
                      "(profile full, claude-code)", self.said)
        self.assertEqual(self.kinds(), ["application/json", NDJSON])
        self.assertEqual(json.loads(self.receiver.received[0]["raw"])["head"],
                         chain_head(log))
        self.assertEqual(self.receiver.received[1]["raw"], log.read_bytes())
        self.assertEqual([row.get("kind") for row in memo_of(log)],
                         [None, "chain"])
        # The anchor keeper ran beside it, on the same default, with no
        # flag typed for either.
        self.assertEqual(self.calendar.submitted,
                         [bytes.fromhex(chain_head(log))])

    def test_explicit_flags_override_the_cadence_and_the_target(self):
        elsewhere = serve_fake(self)
        self.install("--profile", "full", "--remote", self.receiver.url)
        self.aged_chain("sess-flagged", age=7 * 3600)

        self.serve("--publish-every", "1h", "--publish-url", elsewhere.url)
        self.tick()
        self._stop()

        self.assertIn("publish head every 1h (flag --publish-every)",
                      self.said)
        self.assertEqual(self.kinds(elsewhere), ["application/json"])
        self.assertEqual(self.receiver.received, [],
                         "a flag names the target, and names it alone")

    def uninstall(self, *args):
        subprocess.run(
            [sys.executable, str(LOXODONTA), "uninstall-hook", *args],
            capture_output=True, check=True,
            env=keeper_env(HOME=str(self.home), USERPROFILE=str(self.home),
                           LOXODONTA_HOME=str(self.store),
                           CODEX_HOME=str(self.home / ".codex")))

    def serve_refused(self, *extra):
        """`serve` as a command that is refused before it binds a port."""
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0", "--witness", str(self.witness),
             *extra],
            capture_output=True, encoding="utf-8", timeout=60,
            env=keeper_env(LOXODONTA_HOME=str(self.store),
                           CODEX_HOME=str(self.home / ".codex"),
                           PYTHONIOENCODING="utf-8"))

    def test_uninstall_stands_both_keepers_down(self):
        # PRD #244 story 40: the receiver stops hearing from me when I say
        # so. `uninstall-hook` writes nothing to the marker (ADR-0030), so
        # the wired command is what says the operator stopped, and the
        # keeper follows a profile only while its recorder is wired.
        self.install("--profile", "full", "--remote", self.receiver.url)
        self.uninstall()
        self.aged_chain("sess-gone", age=7 * 3600)

        self.serve()
        self.tick()
        self._stop()

        self.assertIn("anchor off (profile full, claude-code; no recorder "
                      "wired)", self.said)
        self.assertIn("publish off (profile full, claude-code; no recorder "
                      "wired)", self.said)
        self.assertEqual(self.receiver.received, [])
        self.assertEqual(self.calendar.submitted, [])

    def test_the_keeper_reads_codexs_wiring_too(self):
        # Both harnesses at `full`, then Claude Code uninstalled: Codex is
        # still wired and its profile speaks. Then Codex uninstalled as
        # well: nothing speaks, and nothing more is sent.
        (self.home / ".codex").mkdir()
        self.install("--profile", "full", "--remote", self.receiver.url)
        self.install("--codex", "--profile", "full",
                     "--remote", self.receiver.url)
        self.uninstall()
        self.aged_chain("sess-codex", age=7 * 3600)

        self.serve()
        self.tick()
        self._stop()

        self.assertIn("publish head and chain every 6h (profile full, codex)",
                      self.said)
        sent = len(self.receiver.received)
        self.assertEqual(sent, 2)

        self.uninstall("--codex")
        self.serve()
        self.tick()
        self._stop()

        self.assertIn("publish off (profile full, codex; no recorder wired)",
                      self.said)
        self.assertEqual(len(self.receiver.received), sent)

    def test_a_lone_cadence_at_full_keeps_the_markers_remote(self):
        # As `--anchor-every` alone keeps the profile's anchor, a cadence
        # typed alone at `full` keeps the marker's remote for both routes;
        # only a URL flag replaces the target.
        self.install("--profile", "full", "--remote", self.receiver.url)
        self.aged_chain("sess-lone", age=7 * 3600)

        self.serve("--publish-every", "1h")
        self.tick()
        self._stop()

        self.assertIn("publish head and chain every 1h (flag --publish-every, "
                      "to the remote of profile full, claude-code)", self.said)
        self.assertEqual(self.kinds(), ["application/json", NDJSON])

    def test_a_lone_cadence_below_full_is_still_a_command_spoken_wrong(self):
        self.install("--profile", "timestamped")

        refused = self.serve_refused("--publish-every", "1h")

        self.assertEqual(refused.returncode, 64, refused.stderr)
        self.assertIn("--publish-every goes with --publish-url or "
                      "--publish-chain", refused.stderr)
        self.assertIn("(profile timestamped, claude-code; no flag)",
                      refused.stderr)

    def test_a_marker_remote_that_is_not_a_plain_url_is_never_followed(self):
        # The marker is writer-reachable (ADR-0030): its remote is held to
        # the installer's own rule before anything is sent there, and the
        # startup line names the marker, never a flag nobody typed.
        self.install("--profile", "full", "--remote", self.receiver.url)
        marker = self.store / "coverage.json"
        data = json.loads(marker.read_text(encoding="utf-8"))
        data["epochs"][-1]["remote"] = "https://shelf.example.test/$(id)"
        marker.write_text(json.dumps(data), encoding="utf-8")
        self.aged_chain("sess-edited", age=7 * 3600)

        self.serve()
        self.tick()
        self._stop()

        self.assertIn("publish off (profile full, claude-code; the marker's "
                      "remote is not a plain http or https URL)", self.said)
        self.assertEqual(self.receiver.received, [])
        refused = self.serve_refused("--publish-every", "1h")
        self.assertEqual(refused.returncode, 64, refused.stderr)
        self.assertIn("the marker's remote is not a plain http or https URL",
                      refused.stderr)

    def test_a_timestamped_marker_still_runs_no_publish_keeper(self):
        # The publish cadence is `full`'s alone (ADR-0031 ruling 1): a
        # tier that never asked for the entries to leave never has them
        # leave because a release added a route.
        self.install("--profile", "timestamped")
        self.aged_chain("sess-ts", age=7 * 3600)

        self.serve()
        self.tick()
        self._stop()

        self.assertIn("publish off (profile timestamped, claude-code; no flag)",
                      self.said)
        self.assertEqual(self.receiver.received, [])


class DrillUnderFullTest(unittest.TestCase):
    """`drill` on a store wired at `full` (#249): the rehearsal plays
    with sandbox copies, sends nothing to the remote — the fake receiver
    sees no request at all — and its report names the tier it found, so
    an operator reading a rehearsal knows which of their heads are
    already somewhere else."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.root = base / "repos"
        self.root.mkdir()
        self.home = base / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.store = base / "store"
        self.receiver = serve_fake(self)

    def drill(self, log):
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "drill", "--root",
             str(self.root), "--log", log, "--json"],
            capture_output=True, encoding="utf-8",
            env=keeper_env(LOXODONTA_HOME=str(self.store),
                           CODEX_HOME=str(self.home / ".codex"),
                           PYTHONIOENCODING="utf-8"))

    def test_a_rehearsal_names_the_tier_and_sends_nothing(self):
        subprocess.run(
            [sys.executable, str(LOXODONTA), "install-hook", "--profile",
             "full", "--remote", self.receiver.url],
            capture_output=True, check=True,
            env=keeper_env(HOME=str(self.home), USERPROFILE=str(self.home),
                           LOXODONTA_HOME=str(self.store),
                           CODEX_HOME=str(self.home / ".codex")))
        make_store_chain(self.root / "alpha" / "receipts", "sess-drill",
                         entries=3)

        result = self.drill("alpha/receipts/receipts-sess-drill.jsonl")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["profile"], "full")
        self.assertTrue(report["all_fired"])
        self.assertEqual(self.receiver.received, [],
                         "a rehearsal sends nothing to the remote")

    def test_a_store_no_install_has_spoken_for_names_no_tier(self):
        make_store_chain(self.root / "alpha" / "receipts", "sess-bare",
                         entries=3)

        result = self.drill("alpha/receipts/receipts-sess-bare.jsonl")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNone(json.loads(result.stdout)["profile"])


class ChainRowsTravelNowhereTest(unittest.TestCase):
    """What a chain row does to the two things that leave a machine on
    purpose: nothing. The field-data export is the allowlisted shape it
    always was (ADR-0021), and a package carries each chain with its
    anchors sidecar and never the publish memo (ADR-0026) — a proof
    travels, a note about network luck does not."""

    SESSION = "c4c4c4c4-aaaa-bbbb-cccc-000000000001"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        self.work = self.root / "work"
        self.witness = self.root / "no-witness"
        for folder in (self.home, self.work, self.witness):
            folder.mkdir()
        self.env = {**clean_env(),
                    "LOXODONTA_HOME": str(self.home / ".loxodonta"),
                    "HOME": str(self.home),
                    "USERPROFILE": str(self.home)}
        self.env.pop("CLAUDE_PROJECT_DIR", None)
        self.receiver = serve_fake(self)
        self.log = make_store_chain(
            self.home / ".loxodonta" / "receipts" / "proj-1", self.SESSION)
        sent = run_recorder("publish", "--chain", "--log", self.log,
                            self.receiver.url)
        self.assertEqual(sent.returncode, 0, sent.stderr)
        self.assertEqual(len(chain_rows(self.log)), 1)

    def supervise(self, *args):
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), *map(str, args),
             "--witness", str(self.witness)],
            capture_output=True, encoding="utf-8", cwd=str(self.work),
            env=self.env)

    def test_the_export_keeps_its_shape_and_never_sees_the_memo(self):
        result = self.supervise("export")

        self.assertEqual(result.returncode, 0, result.stderr)
        (written,) = list(self.work.glob("loxodonta-export-*.json"))
        body = written.read_text("utf-8")
        self.assertEqual(list(json.loads(body)),
                         ["redaction", "export", "machine", "sessions"])
        for absent in ("publish", "127.0.0.1", "/hook", "x-loxodonta"):
            self.assertNotIn(absent, body.lower(), absent)

    def test_a_package_carries_the_chain_and_not_the_memo(self):
        folder = self.work / "package"

        result = self.supervise("package", self.SESSION, "--folder",
                                "--out", folder)

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        packed = sorted(path.name for path in folder.iterdir())
        self.assertIn(self.log.name, packed)
        self.assertEqual([name for name in packed
                          if name.endswith(".published.jsonl")], [])
        # And the memo is still where it was written, unpacked.
        self.assertEqual(len(chain_rows(self.log)), 1)


if __name__ == "__main__":
    unittest.main()
