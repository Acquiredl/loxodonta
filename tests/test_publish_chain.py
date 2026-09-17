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
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_publish_chain`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env
from test_publish import FakeReceiver, FakeReceiverHandler, PublishBase
from test_receiver import make_chain, run_recorder

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
RECEIVER = REPO_ROOT / "receiver.py"

NDJSON = "application/x-ndjson"
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
        self.assertEqual(memo_of(self.log), [])

        fake.status = 200
        again = self.publish_chain(fake.url)

        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual([sent["raw"] for sent in fake.received],
                         [lines, lines])
        self.assertEqual([(r["first"], r["last"]) for r in chain_rows(self.log)],
                         [(0, 1)])

    def test_a_url_that_is_not_http_is_a_usage_error_and_nothing_moves(self):
        make_chain(self.log, ["step 1"], epoch=1700000000)
        target = self.root / "never-opened.txt"
        for bad in (f"file:///{target.as_posix()}", "hooks.example.test/x"):
            result = self.publish_chain(bad)
            self.assertEqual(result.returncode, 64, bad + ": " + result.stderr)
        self.assertFalse(target.exists())
        self.assertEqual(memo_of(self.log), [])

    def test_a_torn_tail_is_never_sent(self):
        # The receiver refuses a batch whole when a line is not an entry,
        # so the sender stops at the last complete line: the torn line
        # stays on the writer's machine as the damage verify reports.
        fake = serve_fake(self)
        lines = make_chain(self.log, ["step 1"], epoch=1700000000)
        with open(self.log, "ab") as f:
            f.write(b'{"n": 2, "ts": "2026-')

        result = self.publish_chain(fake.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        (sent,) = fake.received
        self.assertEqual(sent["raw"], lines)
        self.assertEqual(sent["headers"]["x-loxodonta-range"], "0-1")


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


if __name__ == "__main__":
    unittest.main()
