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

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_publish`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"

# The ladder's third rung, word for word as ratified in the #244 grill
# (#249). Shared so the two ladder tests read the same string and a
# looser rewrite of the claim fails both.
FULL_LADDER_ROW = (
    "  full         --profile full --remote URL   head and receipts go "
    "to a remote you name; a wiped log survives there as of the last "
    "send.")


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
    def do_GET(self):
        # urllib re-sends a followed redirect as a GET; recording one here
        # is how a test would see the publisher follow, which it must not.
        self.server.received.append({"method": "GET", "path": self.path})
        self.send_response(200)
        self.end_headers()

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


class RedirectingHandler(BaseHTTPRequestHandler):
    """A remote that answers every POST with a redirect to the receiver."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(302)
        self.send_header("Location", self.server.target)
        self.end_headers()

    def log_message(self, *args):
        pass


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
                 if not p.name.endswith((".anchors.jsonl", ".published.jsonl",
                                         ".stamps.jsonl"))]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def head(self):
        result = run_receipts("head", "--log", str(self.chain()),
                              cwd=self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def body(self, index=0):
        return json.loads(self.receiver.received[index]["raw"].decode("utf-8"))

    def memo(self):
        """The publish memo beside the chain, parsed; [] when none."""
        memo = self.chain().with_name(self.chain().name + ".published.jsonl")
        if not memo.exists():
            return []
        return [json.loads(line) for line in
                memo.read_text(encoding="utf-8").splitlines()]

    def memo_heads(self):
        """The memo's head rows: one per head the remote took."""
        return [row for row in self.memo() if "head" in row]

    def memo_attempts(self):
        """The memo's attempt rows (#240): how each session-end
        publish went, sent or not."""
        return [row for row in self.memo() if row.get("kind") == "attempt"]


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

    def test_the_hook_leaves_the_memo_the_keeper_reads(self):
        # The same note `loxodonta publish` leaves (ADR-0025 ruling 3), so
        # a head the hook sent is never posted again by the keeper.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        memo = self.chain().with_name(self.chain().name + ".published.jsonl")
        self.assertTrue(memo.exists(), list(self.chain().parent.iterdir()))
        (record,) = self.memo_heads()
        self.assertEqual(record["head"], self.body()["head"])
        self.assertEqual(record["event"], "session-end")
        self.assertNotIn(self.receiver.url, memo.read_text("utf-8"))

    def test_a_sent_head_leaves_an_attempt_row_beside_the_head_row(self):
        # #240, the sidecar form: after the step, one row of kind
        # `attempt` saying how it went, beside the head row and never
        # one: the step, the time, the budget, the outcome.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        self.session_end("--publish", self.receiver.url)

        self.assertEqual(len(self.memo_heads()), 1)
        (row,) = self.memo_attempts()
        self.assertEqual(set(row), {"kind", "step", "ts", "budget", "outcome"})
        self.assertEqual(row["step"], "publish-head")
        self.assertEqual(row["outcome"], "sent")
        self.assertEqual(row["budget"], 3.0)
        self.assertRegex(row["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_a_failed_publish_leaves_no_head_row_and_says_why(self):
        # The memo holds no head row for a POST that never landed, so the
        # keeper still owes this head; it does hold the recorder's one
        # line on what happened, so the store can say the hook fired
        # and was refused (#240). Never the URL: it is a credential.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish", "http://127.0.0.1:9/hook")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.memo_heads(), [])
        (row,) = self.memo_attempts()
        self.assertEqual(row["step"], "publish-head")
        self.assertEqual(row["budget"], 3.0)
        self.assertNotEqual(row["outcome"], "sent")
        self.assertTrue(row["outcome"], "the outcome must say what happened")
        memo = self.chain().with_name(self.chain().name + ".published.jsonl")
        self.assertNotIn("127.0.0.1", memo.read_text("utf-8"))
        self.assertNotIn("/hook", memo.read_text("utf-8"))

    def test_a_url_the_client_refuses_leaves_its_name_and_never_its_path(self):
        # http.client refuses a request path holding a control character
        # and quotes the whole path in its message. The memo rides in
        # every package and in the raw export, and a webhook's path is
        # where its token lives, so the row holds the exception's bare
        # name and neither the host nor the path.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        port = self.receiver.server_address[1]
        refused = f"http://127.0.0.1:{port}/secret\x01token"

        result = self.session_end("--publish", refused)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.receiver.received, [])
        self.assertEqual(self.memo_heads(), [])
        (row,) = self.memo_attempts()
        self.assertEqual(row["outcome"], "InvalidURL")
        memo = self.chain().with_name(
            self.chain().name + ".published.jsonl").read_text("utf-8")
        for leak in ("127.0.0.1", str(port), "secret", "token", "u0001"):
            self.assertNotIn(leak, memo)

    def test_a_chain_whose_memo_holds_only_attempt_rows_still_verifies(self):
        # The memo is beside the chain, not in it: a session whose every
        # publish failed leaves notes there and nothing on the chain, so
        # the verdict is the chain's own.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        self.session_end("--publish", "http://127.0.0.1:9/hook")
        self.assertEqual(self.memo_heads(), [])
        self.assertEqual(len(self.memo_attempts()), 1)

        verify = run_receipts("verify", "--anchors", "--log",
                              str(self.chain()), cwd=self.project)

        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertTrue(verify.stdout.strip().splitlines()[-1]
                        .startswith("VALID"), verify.stdout)

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
        self.receiver.delay = 4  # seconds; just past the three the hook waits
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
        # The abandonment is the outcome the memo records (#240): the
        # one line the bounded POST produces, and no head row.
        self.assertEqual(self.memo_heads(), [])
        (row,) = self.memo_attempts()
        self.assertEqual(row["outcome"], "no answer within 3 seconds")

    def test_a_codex_hook_cuts_the_post_off_inside_codexs_three_seconds(self):
        # Codex caps the whole SessionEnd hook at three seconds, where
        # Claude Code gives it twenty, so a Codex hook waits half the cap
        # for its POST instead of the full three (#183, the numbers in
        # docs/HOOK.md). A remote that sits on the request is left behind
        # early enough that Codex never kills the hook; the same remote
        # holds the default wait past the cap. The seal is on the chain
        # either way, since the commitment goes first.
        self.receiver.delay = 6   # longer than either bound waits
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        started = time.monotonic()
        default = self.session_end("--publish", self.receiver.url)
        default_took = time.monotonic() - started
        started = time.monotonic()
        codex = self.session_end("--publish", self.receiver.url,
                                 "--actor", "codex")
        codex_took = time.monotonic() - started

        for result in (default, codex):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
        # The property #183 measured: the Codex hook comes back inside
        # Codex's cap, and it is the bound that brought it back. Each run
        # is judged on its own clock against the cap, never one against
        # the other: the difference of two runs carries both runs' noise,
        # and on a loaded runner it drifted far enough to fail a window
        # the bounds themselves were nowhere near leaving.
        #
        # Waiting is a floor, since the bound is a join the elapsed time
        # can only exceed, so the two lower bounds here cannot be crossed
        # by a slow machine — only by a wait that really is shorter. The
        # control comes first: the same remote holds the default wait
        # past three, so it truly sat, and the Codex run's early return
        # is the bound and not a remote that answered.
        self.assertGreater(default_took, 3,
                           "the remote answered, so nothing sat")
        # Three seconds of waiting cannot fit inside three seconds, so
        # this fails by construction if the Codex hook is ever handed the
        # default bound. It is the one line load could break, and to
        # break it load has to eat the whole gap between the wait and the
        # cap, where the difference had only half a second to give.
        self.assertLess(codex_took, 3, "Codex would have killed the hook")
        self.assertGreater(codex_took, 1, "the POST was never waited on")
        # What the clock cannot prove, the memo says outright (#240):
        # each attempt row carries the budget the hook waited under,
        # the decision (CODEX_SESSION_END_PUBLISH) quoted in docs/HOOK.md.
        # Any wait between one second and the cap passes the clock
        # above; the rows pin the two bounds themselves.
        self.assertEqual([row["budget"] for row in self.memo_attempts()],
                         [3.0, 1.5])
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("transcript-commitment:"))

    def test_a_redirect_is_a_failure_and_nothing_reaches_the_new_host(self):
        # Left to itself urllib would re-send the POST as a GET with no
        # body to wherever the redirect points; the publisher refuses to
        # follow, quietly, and the seal is on the chain regardless.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        redirector = self.serve(FakeReceiver, RedirectingHandler)
        redirector.target = self.receiver.url
        moved = f"http://127.0.0.1:{redirector.server_address[1]}/moved"

        result = self.session_end("--publish", moved)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.receiver.received, [])
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("transcript-commitment:"))

    def test_a_non_http_url_publishes_nothing_and_still_seals(self):
        # The installer refuses these; a hand-edited settings file gets a
        # quiet skip, and urllib never opens a local file for a file: URL.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        target = self.root / "never-opened.txt"

        result = self.session_end("--publish", f"file:///{target.as_posix()}")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertFalse(target.exists())
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("transcript-commitment:"))

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


class InstallPublishHeadTest(unittest.TestCase):
    """`install-hook --publish-head URL` writes `--publish URL` onto the
    wired SessionEnd command, the way `--anchor-at-session-end` writes
    `--anchor` (ADR-0024 ruling 1, ADR-0025 ruling 3): readable in the
    settings file, idempotent, removed by `uninstall-hook`. The profile
    (ADR-0031 ruling 1) is the one word for a set of those flags, and
    its install cases live here too: each tier's wired command, the
    refusals, the ladder, and Codex's lines."""

    URL = "https://hooks.example.test/services/T000/B000/XXXX"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        # A private store, so the coverage marker the installer writes
        # (ADR-0030) lands here and never in the developer's own.
        self.store = self.root / "store"
        # CODEX_HOME inside the temp home too: a machine that sets it
        # would otherwise get this test's hooks in its real hooks.json.
        self.env = {"HOME": str(self.home), "USERPROFILE": str(self.home),
                    "LOXODONTA_HOME": str(self.store),
                    "CODEX_HOME": str(self.home / ".codex")}

    def install(self, *args):
        return run_receipts("install-hook", *args, cwd=self.root,
                            env=self.env)

    def settings(self):
        return json.loads((self.home / ".claude" / "settings.json")
                          .read_text(encoding="utf-8"))

    def commands(self, event):
        return [h["command"] for b in self.settings()["hooks"][event]
                for h in b["hooks"]]

    def test_profile_timestamped_is_the_session_end_anchor_under_one_word(self):
        # ADR-0031 ruling 1: the tier name is the beginner's word and the
        # mechanism keeps its own. `--profile timestamped` wires exactly
        # the SessionEnd command `--anchor-at-session-end` wires, and the
        # installer states the choice in the mechanism's words.
        result = self.install("--profile", "timestamped")

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(" --anchor"), end)
        self.assertNotIn("--anchor", json.dumps(self.commands("PostToolUse")))
        self.assertIn("anchors at session end", result.stdout)

        # The raw flag finds nothing to rewire: same command, same install.
        by_flag = self.install("--anchor-at-session-end")
        self.assertEqual(by_flag.returncode, 0, by_flag.stderr)
        self.assertIn("already installed", by_flag.stdout)
        self.assertEqual(self.commands("SessionEnd"), [end])

    def test_a_raw_flag_beside_a_named_profile_is_refused_naming_custom(self):
        # A profile already says what leaves the machine; a raw flag
        # beside it is a command spoken wrong (exit 64, ADR-0026 ruling
        # 7), and the refusal names the way out.
        for spoken_wrong in (("--profile", "timestamped",
                              "--anchor-at-session-end"),
                             ("--profile", "local",
                              "--publish-head", self.URL),
                             ("--profile", "timestamped",
                              "--publish-head", self.URL)):
            result = self.install(*spoken_wrong)
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("--profile custom", result.stderr)
            self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                             "a refusal writes nothing")

    def test_profile_custom_is_the_raw_flags_exactly_as_before(self):
        result = self.install("--profile", "custom", "--anchor-at-session-end",
                              "--publish-head", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(f' --anchor --publish "{self.URL}"'), end)
        self.assertIn("anchors at session end", result.stdout)
        self.assertIn(self.URL, result.stdout)
        # The same flags with the word left off are the same install.
        again = self.install("--anchor-at-session-end",
                             "--publish-head", self.URL)
        self.assertIn("already installed", again.stdout)
        # `custom` with no raw flag at all wires nothing that leaves.
        bare = self.install("--profile", "custom")
        self.assertEqual(bare.returncode, 0, bare.stderr)
        [end] = self.commands("SessionEnd")
        self.assertNotIn("--anchor", end)
        self.assertNotIn("--publish", end)

    def test_profile_full_without_a_remote_is_a_usage_error(self):
        # The strongest tier is the two publishes to a URL the operator
        # names (ADR-0031 ruling 1), so there is no such tier without
        # one: refused, exit 64, nothing written. What the refusal says
        # is pinned in test_publish_chain.InstallProfileFullTest.
        result = self.install("--profile", "full")

        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertIn("--remote", result.stderr)
        self.assertFalse((self.home / ".claude" / "settings.json").exists())

    def test_publish_head_rides_on_the_session_end_command(self):
        result = self.install("--publish-head", self.URL)
        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertTrue(end.endswith(f' --publish "{self.URL}"'), end)
        # PostToolUse is untouched: no network call in the recording path.
        self.assertNotIn("--publish", json.dumps(self.commands("PostToolUse")))
        # The installer states the choice, URL included.
        self.assertIn(self.URL, result.stdout)

    def test_install_is_idempotent(self):
        self.install("--publish-head", self.URL)
        again = self.install("--publish-head", self.URL)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already installed", again.stdout)
        self.assertEqual(len(self.commands("SessionEnd")), 1)

    def test_a_rerun_without_the_flag_turns_publishing_off_and_says_so(self):
        self.install("--publish-head", self.URL)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--publish", json.dumps(self.settings()["hooks"]))
        self.assertNotIn(self.URL, json.dumps(self.settings()["hooks"]))
        self.assertIn("no longer", result.stdout)
        self.assertIn("publish", result.stdout)

    def ladder(self, stdout):
        """The tier rows the installer printed, keyed by tier name."""
        rows = [line for line in stdout.splitlines()
                if line.startswith("  local ")
                or line.startswith("  timestamped ")
                or line.startswith("  full ")]
        return {row.split()[0]: row for row in rows}

    def test_a_flagless_install_prints_the_ladder(self):
        # ADR-0031 ruling 1: the flagless install is `local`, and the
        # installer prints the ladder in place of #221's note, one row
        # per tier the operator can reach, each naming its flag and
        # what leaves. The `local` row keeps #221's sentence: a
        # regenerated chain is caught only against a head kept off the
        # machine, and the `full` row the phrase that says what the
        # strongest tier does and does not promise (#249). Printed on
        # first install and on every re-run.
        first = self.install()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("wired: Claude Code, every tool call, profile local",
                      first.stdout)
        ladder = self.ladder(first.stdout)
        self.assertEqual(sorted(ladder), ["full", "local", "timestamped"])
        self.assertIn("a regenerated chain only against a head you keep "
                      "(`head`, then `verify --expect-head`)",
                      ladder["local"])
        self.assertIn("--profile timestamped", ladder["timestamped"])
        self.assertIn("a 32-byte digest leaves at each session end",
                      ladder["timestamped"])
        self.assertIn("once the anchor matures", ladder["timestamped"])
        # The third rung, word for word as ratified in the #244 grill:
        # the flag that reaches the tier, and the claim in the
        # phrase the PRD fixed so it is never rewritten looser.
        self.assertEqual(ladder["full"], FULL_LADDER_ROW)
        self.assertIn("as of the last send", ladder["full"])
        # The ladder is the only notice: #221's line is gone.
        self.assertNotIn("no head record", first.stdout)
        self.assertNotIn("note:", first.stdout)

        again = self.install()
        self.assertIn("already installed", again.stdout)
        self.assertEqual(self.ladder(again.stdout), ladder)

    def test_an_install_above_local_reads_its_profile_back_without_the_ladder(self):
        # The ladder is for the install that reached no tier above
        # `local`; any other install states its profile in one line.
        with_publish = self.install("--publish-head", self.URL)
        self.assertEqual(with_publish.returncode, 0, with_publish.stderr)
        self.assertIn("profile custom", with_publish.stdout)
        self.assertEqual(self.ladder(with_publish.stdout), {})

        timestamped = self.install("--profile", "timestamped")
        self.assertEqual(timestamped.returncode, 0, timestamped.stderr)
        self.assertIn("profile timestamped", timestamped.stdout)
        self.assertEqual(self.ladder(timestamped.stdout), {})

    def test_a_flagless_codex_install_prints_the_ladder_in_codexs_terms(self):
        # Codex refuses the session-end anchor (ADR-0024), so its
        # `timestamped` row says the digest leaves on the supervisor's
        # cadence and never names the flag Codex cannot take.
        (self.home / ".codex").mkdir()

        result = self.install("--codex")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("wired: Codex, every tool call, profile local",
                      result.stdout)
        ladder = self.ladder(result.stdout)
        self.assertEqual(sorted(ladder), ["full", "local", "timestamped"])
        self.assertIn("--profile timestamped", ladder["timestamped"])
        self.assertIn("supervisor", ladder["timestamped"])
        self.assertIn("cadence", ladder["timestamped"])
        # The `full` row is the same on both harnesses: what it
        # promises is the two publishes, which Codex does wire, and it
        # names no anchor, which Codex does not.
        self.assertEqual(ladder["full"], FULL_LADDER_ROW)
        self.assertNotIn("--anchor-at-session-end", result.stdout)
        self.assertNotIn("no head record", result.stdout)

    def test_both_opt_ins_ride_on_the_one_command(self):
        result = self.install("--anchor-at-session-end",
                              "--publish-head", self.URL)
        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertIn(" --anchor", end)
        self.assertIn(f' --publish "{self.URL}"', end)
        self.assertIn("anchors", result.stdout)
        self.assertIn(self.URL, result.stdout)

    def test_uninstall_removes_the_publishing_session_end_hook(self):
        self.install("--publish-head", self.URL)
        result = run_receipts("uninstall-hook", cwd=self.root, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.home / ".claude" / "settings.json"
        left = path.read_text(encoding="utf-8") if path.exists() else "{}"
        self.assertNotIn("loxodonta.py", left)
        self.assertNotIn(self.URL, left)

    def test_the_installer_refuses_a_url_a_shell_could_act_on(self):
        # The wired command runs through a shell at every session end, so
        # the URL is refused rather than escaped: http or https only, and
        # nothing a shell could expand or unquote.
        for bad in ("file:///tmp/heads.jsonl", "ftp://h.example.test/x",
                    "hooks.example.test/no-scheme",
                    "https://h.example.test/$(id)",
                    'https://h.example.test/a"b',
                    "https://h.example.test/a b"):
            result = self.install("--publish-head", bad)
            self.assertEqual(result.returncode, 64, bad + ": " + result.stderr)
            self.assertIn("--publish-head", result.stderr)
            self.assertFalse((self.home / ".claude" / "settings.json").exists(),
                             bad)

    def test_a_rerun_that_keeps_one_flag_says_which_step_stopped(self):
        # The install command states the choice each time: a flag left out
        # turns that step off, and the notice names the step, even when
        # the other step stays on.
        self.install("--anchor-at-session-end")
        result = self.install("--publish-head", self.URL)
        self.assertEqual(result.returncode, 0, result.stderr)
        [end] = self.commands("SessionEnd")
        self.assertNotIn(" --anchor", end)
        self.assertIn(f' --publish "{self.URL}"', end)
        self.assertIn("no longer anchors", result.stdout)
        self.assertIn(self.URL, result.stdout)

    def codex_hooks(self):
        return json.loads((self.home / ".codex" / "hooks.json")
                          .read_text(encoding="utf-8"))["hooks"]

    def test_codex_gets_the_flag_and_the_publish_rides_on_session_end(self):
        # ADR-0025 ruling 3 held the flag back until one POST inside
        # Codex's three-second cap was measured; #183 measured it, so the
        # refusal is lifted and the URL rides on the SessionEnd command
        # exactly as it does for Claude Code. The block keeps Codex's own
        # three-second timeout: the hook fits inside it, not the reverse.
        (self.home / ".codex").mkdir()

        result = self.install("--codex", "--publish-head", self.URL)

        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = self.codex_hooks()
        [end] = [h for b in hooks["SessionEnd"] for h in b["hooks"]]
        self.assertTrue(end["command"].endswith(f' --publish "{self.URL}"'),
                        end["command"])
        self.assertIn("--actor codex", end["command"])
        self.assertEqual(end["timeout"], 3)
        # No network call in the recording path, on any harness.
        self.assertNotIn("--publish", json.dumps(hooks["PostToolUse"]))
        self.assertIn(self.URL, result.stdout)

    def test_a_codex_rerun_without_the_flag_turns_publishing_off_and_says_so(self):
        # The install command states the choice each time, Codex included.
        (self.home / ".codex").mkdir()
        self.install("--codex", "--publish-head", self.URL)

        result = self.install("--codex")

        self.assertEqual(result.returncode, 0, result.stderr)
        left = json.dumps(self.codex_hooks())
        self.assertNotIn("--publish", left)
        self.assertNotIn(self.URL, left)
        self.assertIn("no longer", result.stdout)
        self.assertIn("publish", result.stdout)
        self.assertEqual(len([h for b in self.codex_hooks()["SessionEnd"]
                              for h in b["hooks"]]), 1)

    def test_codex_profile_timestamped_records_the_profile_and_wires_no_anchor(self):
        # ADR-0031 ruling 1 on Codex: the profile is written down, the
        # session-end anchor stays refused (ADR-0024: three seconds is a
        # POST, not a calendar round trip), so nothing extra is wired and
        # the notice says the supervisor anchors on its cadence.
        (self.home / ".codex").mkdir()

        result = self.install("--codex", "--profile", "timestamped")

        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = self.codex_hooks()
        [end] = [h for b in hooks["SessionEnd"] for h in b["hooks"]]
        self.assertNotIn("--anchor", end["command"])
        self.assertEqual(end["timeout"], 3)
        marker = json.loads((self.store / "coverage.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual((marker["epochs"][-1]["harness"],
                          marker["epochs"][-1]["profile"]),
                         ("codex", "timestamped"))
        self.assertIn("profile timestamped", result.stdout)
        self.assertIn("supervisor", result.stdout)
        self.assertIn("cadence", result.stdout)
        self.assertNotIn("--anchor-at-session-end", result.stdout)
        # Not a tier reached by a flag Codex refuses: the raw flag is
        # still refused, profile or no profile.
        refused = self.install("--codex", "--profile", "custom",
                               "--anchor-at-session-end")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("--anchor-every", refused.stderr)

    def test_codex_still_refuses_the_session_end_anchor(self):
        # #183 measured a POST, not a calendar round trip: the anchor's
        # refusal (ADR-0024) stands, and names the supervisor instead.
        (self.home / ".codex").mkdir()

        result = self.install("--codex", "--anchor-at-session-end")

        self.assertEqual(result.returncode, 1)
        self.assertIn("--anchor-at-session-end", result.stderr)
        self.assertIn("--anchor-every", result.stderr)
        self.assertFalse((self.home / ".codex" / "hooks.json").exists())
        # A refusal writes neither harness's file, whichever was asked for.
        self.assertFalse((self.home / ".claude" / "settings.json").exists())


if __name__ == "__main__":
    unittest.main()
