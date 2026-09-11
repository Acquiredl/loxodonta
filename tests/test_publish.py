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
                 if not p.name.endswith((".anchors.jsonl", ".published.jsonl"))]
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

    def test_the_hook_leaves_the_memo_the_keeper_reads(self):
        # The same note `loxodonta publish` leaves (ADR-0025 ruling 3), so
        # a head the hook sent is never posted again by the keeper.
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish", self.receiver.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        memo = self.chain().with_name(self.chain().name + ".published.jsonl")
        self.assertTrue(memo.exists(), list(self.chain().parent.iterdir()))
        (record,) = [json.loads(l) for l in memo.read_text("utf-8").splitlines()]
        self.assertEqual(record["head"], self.body()["head"])
        self.assertEqual(record["event"], "session-end")
        self.assertNotIn(self.receiver.url, memo.read_text("utf-8"))

    def test_a_failed_publish_leaves_no_memo(self):
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()

        result = self.session_end("--publish", "http://127.0.0.1:9/hook")

        self.assertEqual(result.returncode, 0, result.stderr)
        memo = self.chain().with_name(self.chain().name + ".published.jsonl")
        self.assertFalse(memo.exists())

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
        # What this cannot prove: that the bound is 1.5 exactly. Any wait
        # between one second and the cap passes. The 1.5 is a decision
        # (CODEX_SESSION_END_PUBLISH) and the worst case it buys is a
        # measurement, both quoted in docs/HOOK.md; this test guards the
        # property those numbers exist to serve.
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
    settings file, idempotent, removed by `uninstall-hook`."""

    URL = "https://hooks.example.test/services/T000/B000/XXXX"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.env = {"HOME": str(self.home), "USERPROFILE": str(self.home)}

    def install(self, *args):
        return run_receipts("install-hook", *args, cwd=self.root,
                            env=self.env)

    def settings(self):
        return json.loads((self.home / ".claude" / "settings.json")
                          .read_text(encoding="utf-8"))

    def commands(self, event):
        return [h["command"] for b in self.settings()["hooks"][event]
                for h in b["hooks"]]

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
