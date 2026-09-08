"""Behavioral tests for the published head (ADR-0025, issue #177).

A hook wired with --publish URL posts the session's chain head at
SessionEnd, after the tail commitment and before the anchor, to a remote
the credentials on this machine cannot delete from (a chat incoming
webhook, a retention-locked bucket). Every test drives the public CLI
against a local fake receiver, and the fake calendar from test_anchor
where the order matters: no network, ever, and never internals.
"""

import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"


def run_receipts(*args, cwd, env=None):
    return subprocess.run(
        [sys.executable, str(LOXODONTA), *args],
        cwd=cwd, capture_output=True, encoding="utf-8",
        env={**clean_env(), **(env or {})})


# --- Fake receiver ------------------------------------------------------------

class FakeReceiver(FakeCalendar):
    """A webhook stand-in: the same quick-binding HTTPServer as the fake
    calendar, with a handler that keeps every POST it was sent."""

    def handle_error(self, request, client_address):
        pass  # a client that gave up on a slow reply is the point of one test


class FakeReceiverHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep test output clean

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        # What the world could see at the moment the POST arrived: the
        # chain's last line on disk, and how often the calendar had been
        # asked so far. The order test reads both.
        chain = getattr(self.server, "chain", None)
        calendar = getattr(self.server, "calendar", None)
        self.server.received.append({
            "path": self.path,
            "content_type": self.headers.get("Content-Type"),
            "raw": raw,
            "chain_tail": (chain.read_text(encoding="utf-8").splitlines()[-1]
                           if chain and chain.exists() else None),
            "calendar_asks": (len(calendar.submitted)
                              if calendar is not None else None),
        })
        time.sleep(self.server.delay)  # a slow remote, when a test asks for one
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class OrderedCalendarHandler(FakeCalendarHandler):
    """The fake calendar, also noting how many published heads the
    receiver had been sent by the time each digest arrived."""

    def do_POST(self):
        self.server.publishes_seen.append(len(self.server.receiver.received))
        super().do_POST()


class PublishBase(unittest.TestCase):
    """A project with a distinctive name, routed to a private store, a
    transcript so the session end has a tail to seal, and a receiver."""

    SESSION = "sess-publish-0001"
    PROJECT_NAME = "nightingale-project"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.project = self.root / self.PROJECT_NAME
        self.project.mkdir()
        self.store = self.root / "store"
        self.transcript = self.root / "transcript.jsonl"
        self.receiver = self.serve(FakeReceiver, FakeReceiverHandler)
        self.receiver.received = []
        self.receiver.delay = 0
        self.receiver.url = (
            f"http://127.0.0.1:{self.receiver.server_address[1]}/hook")

    def serve(self, server_class, handler):
        server = server_class(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def calendar(self):
        """A fake calendar that answers pending, wired to watch the
        receiver so the order of the two POSTs is observable."""
        calendar = self.serve(FakeCalendar, OrderedCalendarHandler)
        calendar.nonce = b"fake-nonce"
        calendar.mode = "pending"
        calendar.submitted = []
        calendar.polled = []
        calendar.publishes_seen = []
        calendar.receiver = self.receiver
        calendar.url = f"http://127.0.0.1:{calendar.server_address[1]}"
        self.receiver.calendar = calendar
        return calendar

    def hook(self, payload, *extra):
        env = clean_env()
        env["CLAUDE_PROJECT_DIR"] = str(self.project)
        env["LOXODONTA_HOME"] = str(self.store)
        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook", *extra],
            cwd=self.project, input=json.dumps(payload).encode("utf-8"),
            capture_output=True, env=env)
        result.stdout = result.stdout.decode("utf-8", "replace")
        result.stderr = result.stderr.decode("utf-8", "replace")
        return result

    def tool_call(self, command="ls"):
        return self.hook({"session_id": self.SESSION,
                          "hook_event_name": "PostToolUse",
                          "tool_name": "Bash",
                          "tool_input": {"command": command},
                          "tool_response": {},
                          "transcript_path": str(self.transcript)})

    def session_end(self, *extra):
        return self.hook({"session_id": self.SESSION,
                          "hook_event_name": "SessionEnd",
                          "reason": "prompt_input_exit",
                          "transcript_path": str(self.transcript)}, *extra)

    def chain(self):
        """The session's one chain, wherever the store filed it."""
        found = [p for p in (self.store / "receipts").rglob(
                     f"receipts-{self.SESSION}*.jsonl")
                 if not p.name.endswith(".anchors.jsonl")]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def head(self):
        result = run_receipts("head", "--log", str(self.chain()),
                              cwd=self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def body(self, index=0):
        return json.loads(self.receiver.received[index]["raw"].decode("utf-8"))


class PublishAtSessionEndTest(PublishBase):
    """`hook --publish URL`: at SessionEnd, one POST of the sealed head."""

    def test_session_end_posts_the_sealed_head_to_the_url(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        result = self.session_end("--publish", self.receiver.url)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Quiet: the seal's own receipt line is all the hook says; the
        # publish adds nothing to it, on either stream.
        self.assertEqual(result.stdout.strip(), "logged entry 2")
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(self.receiver.received), 1)
        self.assertEqual(self.body()["head"], self.head())

    def test_the_body_is_the_fingerprint_and_never_the_work(self):
        # ADR-0025 ruling 2: head, n, session, ts, event, and one readable
        # line under both `text` (Slack, Teams) and `content` (Discord).
        # No path, no project name, no action line, no chain bytes.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call(command="echo secret-wren-42")
        self.session_end("--publish", self.receiver.url)

        sent = self.receiver.received[0]
        self.assertEqual(sent["content_type"], "application/json")
        body = self.body()
        self.assertEqual(set(body),
                         {"head", "n", "session", "ts", "event",
                          "text", "content"})
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertEqual(body["head"], last["entry_hash"])
        self.assertEqual(body["n"], last["n"])
        self.assertEqual(body["session"], self.SESSION)
        self.assertEqual(body["event"], "session-end")
        self.assertRegex(body["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(body["text"], body["content"])
        for field in ("head", "n", "session", "ts", "event"):
            self.assertIn(str(body[field]), body["text"])

        raw = sent["raw"].decode("utf-8")
        for secret in (self.PROJECT_NAME, self.root.name, "secret-wren",
                       "receipts-", ".jsonl", "transcript-commitment"):
            self.assertNotIn(secret, raw)

    def test_order_is_commitment_then_publish_then_anchor(self):
        # ADR-0025 ruling 3: the tail commitment is on the chain before
        # the POST leaves, so the head that leaves is the sealed one, and
        # the calendar is asked only after the POST, so a slow calendar
        # can never cost it.
        calendar = self.calendar()
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.receiver.chain = self.chain()

        result = self.session_end("--publish", self.receiver.url,
                                  "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        sent = self.receiver.received[0]
        tail = json.loads(sent["chain_tail"])
        self.assertTrue(tail["action"].startswith("transcript-commitment:"),
                        tail)
        self.assertEqual(tail["entry_hash"], self.body()["head"])
        self.assertEqual(sent["calendar_asks"], 0)
        # One digest, asked after the one publish, of the same head.
        self.assertEqual(calendar.publishes_seen, [1])
        self.assertEqual([d.hex() for d in calendar.submitted],
                         [self.body()["head"]])
        sidecar = self.chain().with_name(self.chain().name + ".anchors.jsonl")
        self.assertTrue(sidecar.exists(), "the anchor did not happen")

    def test_unreachable_url_is_quiet_exits_zero_and_still_seals(self):
        # Quiet and best-effort, like the anchor: nothing printed, exit
        # 0, done inside the twelve-second session-end budget, and the
        # seal is on the chain regardless. Staleness is the supervisor's.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        closed = "http://127.0.0.1:9/hook"  # discard port: nothing listens

        started = time.monotonic()
        result = self.session_end("--publish", closed)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "logged entry 2")
        self.assertEqual(result.stderr, "")
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("transcript-commitment:"))

    def test_a_slow_receiver_is_abandoned_and_never_costs_the_anchor(self):
        # The one POST has a bounded timeout well inside the budget, and
        # the anchor takes what is left: a remote that sits on the request
        # is left behind on the hook's own clock, and the calendar is
        # still asked.
        calendar = self.calendar()
        self.receiver.delay = 5  # seconds; longer than the hook will wait
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        started = time.monotonic()
        result = self.session_end("--publish", self.receiver.url,
                                  "--anchor", "--calendar", calendar.url)
        elapsed = time.monotonic() - started

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertLess(elapsed, self.receiver.delay)
        self.assertEqual(len(self.receiver.received), 1)
        self.assertEqual([d.hex() for d in calendar.submitted], [self.head()])

    def test_a_session_without_receipts_publishes_nothing(self):
        # SessionEnd never manufactures a chain for a chat-only session,
        # so there is no head, and nothing leaves.
        result = self.hook({"session_id": "sess-chat-only",
                            "hook_event_name": "SessionEnd",
                            "reason": "prompt_input_exit",
                            "transcript_path": str(self.transcript)},
                           "--publish", self.receiver.url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receiver.received, [])


if __name__ == "__main__":
    unittest.main()
