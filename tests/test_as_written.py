"""Behavioral tests for ADR-0045: entries leave as they are written, and
the receiver says what it holds.

The receiver answers each chain batch with the `n` and the `entry_hash`
of the last entry it holds, and refuses with 409 a batch that would
leave a hole after it. At `full` the installer writes the chain's URL on
the recording command too, and each recording hook sends what the
receiver does not hold before it returns, under one second, quietly. The
anchor and stamp rows beside a chain travel to the same URL and are kept
beside the receiver's copy. Every test drives the public CLI against the
repo's own `receiver.py serve` on a loopback port, or a socket that
records whether anything connected. No network, never internals.
"""

import hashlib
import json
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_as_written`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import (LOXODONTA, RECEIVER, SUPERVISOR, clean_env,  # noqa: E402
                     isolated_env, run, temp_folder)

from test_anchor import start_calendar  # noqa: E402
from test_receiver import (NDJSON, ReceiverFixture, free_port,  # noqa: E402
                           make_chain, post, request, run_recorder)
from test_stamp import start_authority  # noqa: E402
from test_supervisor import make_chain as make_store_chain  # noqa: E402
from test_supervisor import run_scan  # noqa: E402

PUBLISH_TO = re.compile(r"^publish to (https?://\S+)$", re.M)
SIDECAR = "application/x-loxodonta-sidecar"
CHAIN = "receipts-sess-0045.jsonl"
SESSION = "sess-as-written-0045"


def lines_of(path):
    """The entries a chain file holds, parsed, in file order."""
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines()]


def memo_rows(log):
    memo = Path(str(log) + ".published.jsonl")
    if not memo.exists():
        return []
    return [json.loads(line) for line in
            memo.read_text(encoding="utf-8").splitlines()]


def entry_attempts(log):
    """The per-entry send's attempt rows: step publish-chain, event
    receipt (ADR-0045 ruling 3)."""
    return [row for row in memo_rows(log) if row.get("kind") == "attempt"
            and row.get("step") == "publish-chain"
            and row.get("event") == "receipt"]


def remote_id(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def start_receiver(case, data, port=0):
    """The repo's receiver as a subprocess on 127.0.0.1, its URL read
    from what it printed; `port` fixed when a test stops it and starts
    it again on the same URL. Returns the process; `stop` it to stop."""
    proc = subprocess.Popen(
        [sys.executable, str(RECEIVER), "serve", "--data", str(data),
         "--port", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
        env=clean_env())

    def stop():
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()

    proc.stop = stop
    case.addCleanup(stop)
    said = []
    while True:
        line = proc.stdout.readline()
        if not line:
            proc.kill()
            case.fail("the receiver printed no URL:\n" + "".join(said))
        said.append(line)
        found = PUBLISH_TO.search(line)
        if found:
            proc.url = found.group(1)
            return proc


class Listener:
    """A socket on 127.0.0.1 that counts the connections it is offered,
    and answers none of them: what a recording hook below `full` must
    never reach."""

    def __init__(self, case):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.accepted = 0
        self.done = threading.Event()
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}/token"
        thread = threading.Thread(target=self.watch, daemon=True)
        thread.start()
        case.addCleanup(self.close)

    def watch(self):
        while not self.done.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.accepted += 1
            conn.close()

    def close(self):
        self.done.set()
        self.sock.close()


# --- The receiver's side -------------------------------------------------------

class StatementTest(ReceiverFixture):
    """Rulings 1, 2 and 6 at the receiver: each answer to a batch says
    what it holds of that chain, a batch past the entry after it is 409,
    and there is still no route that reads."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.log = self.root / CHAIN
        self.lines = make_chain(self.log, ["step 1", "step 2", "step 3"],
                                epoch=1700000000)
        self.entries = lines_of(self.log)

    def send(self, body, name=CHAIN):
        return post(self.proc.url, body, NDJSON, {"X-Loxodonta-Chain": name})

    def batch(self, first, last=None):
        rows = self.lines.splitlines(True)
        return b"".join(rows[first:(last if last is None else last + 1)])

    def test_a_batch_is_answered_with_what_the_receiver_holds(self):
        status, answer = self.send(self.batch(0, 1))
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer),
                         {"appended": 2, "dropped": 0, "held_n": 1,
                          "held_hash": self.entries[1]["entry_hash"]})
        # A resend of what it holds adds nothing and says the same.
        status, answer = self.send(self.batch(0, 1))
        self.assertEqual(json.loads(answer)["held_n"], 1)
        self.assertEqual(json.loads(answer)["dropped"], 2)

    def test_a_batch_past_the_entry_after_the_last_held_is_409(self):
        self.send(self.batch(0, 1))
        kept = (self.data / CHAIN).read_bytes()

        status, answer = self.send(self.batch(3))

        self.assertEqual(status, 409, answer)
        said = json.loads(answer)
        self.assertEqual((said["held_n"], said["held_hash"]),
                         (1, self.entries[1]["entry_hash"]))
        self.assertIn("starts at entry 3", said["refused"])
        self.assertEqual((self.data / CHAIN).read_bytes(), kept)
        self.assertIn("starts at entry 3", self.logged(self.proc, 409))
        # The entry after it is taken.
        status, answer = self.send(self.batch(2))
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer)["held_n"], 3)

    def test_a_first_batch_that_does_not_start_at_genesis_is_409(self):
        status, answer = self.send(self.batch(1))

        self.assertEqual(status, 409, answer)
        said = json.loads(answer)
        self.assertEqual((said["held_n"], said["held_hash"]), (None, None))
        self.assertIn("holds no entry", said["refused"])
        self.assertEqual(self.stored(), ["token"])

    def test_a_regenerated_entry_at_an_old_n_is_appended_and_breaks_there(self):
        # Ruling 2: at or before the last entry held, a line that is not
        # the one held is appended as before; the collision is the copy's
        # point (ADR-0031 ruling 4).
        self.send(self.batch(0))
        other = self.root / "again.jsonl"
        regenerated = make_chain(other, ["step 1", "rewritten"],
                                 epoch=1700009999).splitlines(True)

        status, answer = self.send(regenerated[2])

        self.assertEqual(status, 200, answer)
        said = json.loads(answer)
        self.assertEqual(said["appended"], 1)
        # The highest n held is still the original's 3.
        self.assertEqual((said["held_n"], said["held_hash"]),
                         (3, self.entries[3]["entry_hash"]))
        judged = run_recorder("verify", "--log", self.data / CHAIN)
        self.assertEqual(judged.returncode, 1, judged.stdout)
        self.assertTrue(judged.stdout.startswith("BROKEN at entry 4"),
                        judged.stdout)

    def test_every_verb_but_post_at_the_chain_path_is_refused_as_before(self):
        self.send(self.batch(0))
        for verb in ("GET", "HEAD", "PUT", "DELETE"):
            with self.subTest(verb=verb):
                status, headers, body = request(verb, self.proc.url)
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "POST")
                self.assertNotIn(b"held_n", body)
                self.assertNotIn(self.entries[3]["entry_hash"].encode(), body)


class SidecarDoorTest(ReceiverFixture):
    """Ruling 5 at the receiver: a chain's anchor and stamp rows, kept
    beside its copy, a row it holds dropped, anything that is not an
    evidence row refused whole."""

    ROW = {"kind": "anchor", "head": "ab" * 32, "n": 2,
           "ts": "2026-11-11T00:00:00Z", "calendar": "https://c.test",
           "proof": "AAAA"}

    def setUp(self):
        super().setUp()
        self.proc = self.start()

    def send(self, body, sidecar="anchors", name=CHAIN):
        headers = {"X-Loxodonta-Chain": name}
        if sidecar is not None:
            headers["X-Loxodonta-Sidecar"] = sidecar
        return post(self.proc.url, body, SIDECAR, headers)

    def line(self, **change):
        return (json.dumps({**self.ROW, **change}, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("utf-8")

    def test_rows_land_beside_the_copy_and_a_resend_appends_nothing(self):
        body = self.line() + self.line(n=3)
        status, answer = self.send(body)
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer), {"appended": 2, "dropped": 0})
        kept = self.data / (CHAIN + ".anchors.jsonl")
        self.assertEqual(kept.read_bytes(), body)

        status, answer = self.send(body + self.line(n=4))
        self.assertEqual(json.loads(answer), {"appended": 1, "dropped": 2})
        self.assertEqual(kept.read_bytes(), body + self.line(n=4))

    def test_a_stamp_row_goes_to_the_stamps_file(self):
        row = self.line(kind="stamp")
        self.assertEqual(self.send(row, "stamps")[0], 200)
        self.assertEqual((self.data / (CHAIN + ".stamps.jsonl")).read_bytes(),
                         row)
        # An anchor row is not a stamps sidecar's row.
        self.assertEqual(self.send(self.line(), "stamps")[0], 400)

    def test_what_is_not_an_evidence_row_is_refused_whole(self):
        not_rows = (
            b"",
            self.line(kind="attempt"),
            self.line() + b"not json\n",
            b'{"kind":"anchor","kind":"anchor"}\n',
            b'{"kind":"anchor","n":NaN}\n',
            b"[1]\n",
        )
        for body in not_rows:
            with self.subTest(body=body):
                self.assertEqual(self.send(body)[0], 400)
        for sidecar in (None, "", "published", "anchors.jsonl"):
            with self.subTest(sidecar=sidecar):
                self.assertEqual(self.send(self.line(), sidecar)[0], 400)
        self.assertEqual(self.send(self.line(), name="x.jsonl")[0], 400)
        self.assertEqual(self.stored(), ["token"])


# --- Each entry as it is written --------------------------------------------

class AsWrittenBase(unittest.TestCase):
    """A project routed to a private store, and the hook run as the
    recording command a `full` install writes."""

    def setUp(self):
        self.root = temp_folder(self)
        self.project = self.root / "project"
        self.project.mkdir()
        self.store = self.root / "store"
        self.home = temp_folder(self)
        self.data = self.root / "receiver"

    def env(self, **more):
        return isolated_env(self.home, CLAUDE_PROJECT_DIR=str(self.project),
                            LOXODONTA_HOME=str(self.store), **more)

    def call(self, *flags, session=SESSION, command="ls", env=None):
        payload = {"session_id": session, "hook_event_name": "PostToolUse",
                   "tool_name": "Bash", "tool_input": {"command": command},
                   "tool_use_id": "toolu_0045", "tool_response": {}}
        return run(LOXODONTA, "hook", *flags, cwd=self.project,
                   stdin=json.dumps(payload), env=env or self.env(),
                   timeout=60)

    def chains(self):
        return sorted(p for p in (self.store / "receipts").rglob(
            "receipts-*.jsonl") if p.name.count(".") == 1)

    def chain(self):
        (found,) = self.chains()
        return found


class AsWrittenTest(AsWrittenBase):

    def test_each_entry_is_at_the_receiver_before_the_hook_returns(self):
        receiver = start_receiver(self, self.data)
        for calls in (1, 2, 3):
            done = self.call("--publish-chain", receiver.url)

            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stderr, "")
            self.assertEqual(done.stdout, f"logged entry {calls}\n")
            log = self.chain()
            kept = self.data / log.name
            # The session is still open: every entry, genesis on, is
            # held, in order, byte for byte.
            self.assertEqual([e["n"] for e in lines_of(kept)],
                             list(range(calls + 1)))
            self.assertEqual(kept.read_bytes(), log.read_bytes())
        judged = run_recorder("verify", "--log", kept)
        self.assertEqual(judged.stdout.strip(), "VALID")
        # A session whose sends all landed writes no attempt row.
        self.assertEqual(entry_attempts(log), [])
        self.assertEqual([r["event"] for r in memo_rows(log)
                          if r["kind"] == "chain"], ["receipt"] * 3)

    def test_a_memo_row_forged_far_ahead_does_not_stop_the_send(self):
        receiver = start_receiver(self, self.data)
        self.call("--publish-chain", receiver.url)       # 0, 1 held
        self.call()                                      # 2, not sent
        self.call()                                      # 3, not sent
        log = self.chain()
        with open(str(log) + ".published.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"kind": "chain", "first": 0, "last": 900,
                                "head": "ab" * 32,
                                "ts": "2026-11-11T00:00:00Z",
                                "event": "cadence",
                                "remote_id": remote_id(receiver.url)}) + "\n")

        done = self.call("--publish-chain", receiver.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        kept = self.data / log.name
        self.assertEqual([e["n"] for e in lines_of(kept)], [0, 1, 2, 3, 4])
        self.assertEqual(kept.read_bytes(), log.read_bytes())
        (said,) = entry_attempts(log)
        self.assertEqual(said["outcome"],
                         "sent; the memo named entry 900 as sent there, and "
                         "the remote holds through entry 1")
        # The next call's hint is the row that send wrote: no note again,
        # and one row back to `sent`.
        self.call("--publish-chain", receiver.url)
        self.assertEqual([r["outcome"] for r in entry_attempts(log)][1:],
                         ["sent"])
        self.call("--publish-chain", receiver.url)
        self.assertEqual(len(entry_attempts(log)), 2)

    def test_a_receiver_that_is_down_costs_a_second_a_call_and_one_row(self):
        port = free_port()
        receiver = start_receiver(self, self.data, port=port)
        url = receiver.url
        self.call("--publish-chain", url)
        receiver.stop()

        for _ in range(5):
            started = time.monotonic()
            done = self.call("--publish-chain", url)
            took = time.monotonic() - started

            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stderr, "")
            # The one-second cap, and a margin for a cold interpreter on
            # a loaded runner.
            self.assertLess(took, 6.0)
        log = self.chain()
        (down,) = entry_attempts(log)
        self.assertNotEqual(down["outcome"], "sent")
        self.assertEqual(down["budget"], 1.0)
        self.assertNotIn(url.rsplit("/", 1)[1],
                         Path(str(log) + ".published.jsonl").read_text("utf-8"))

        again = start_receiver(self, self.data, port=port)
        self.assertEqual(again.url, url)
        done = self.call("--publish-chain", url)

        self.assertEqual(done.returncode, 0, done.stderr)
        kept = self.data / log.name
        self.assertEqual([e["n"] for e in lines_of(kept)], list(range(8)))
        self.assertEqual([r["outcome"] for r in entry_attempts(log)],
                         [down["outcome"], "sent"])

    def test_below_full_the_recording_hook_opens_no_socket(self):
        # A head-only install: the head goes at session end, and the
        # recording command it writes carries nothing that sends.
        listener = Listener(self)
        installed = run(LOXODONTA, "install-hook", "--profile", "custom",
                        "--publish-head", listener.url,
                        "--anchor-at-session-end", cwd=self.root,
                        env=self.env())
        self.assertEqual(installed.returncode, 0, installed.stderr)
        settings = json.loads((self.home / ".claude" / "settings.json")
                              .read_text(encoding="utf-8"))
        (command,) = [h["command"] for b in settings["hooks"]["PostToolUse"]
                      for h in b["hooks"]]
        words = shlex.split(command)
        flags = words[words.index("hook") + 1:]
        self.assertNotIn("--publish-chain", flags)

        for _ in range(2):
            done = self.call(*flags)
            self.assertEqual(done.returncode, 0, done.stderr)
        time.sleep(0.5)
        self.assertEqual(listener.accepted, 0)

    def test_a_sibling_chain_arrives_under_its_own_name(self):
        receiver = start_receiver(self, self.data)
        self.call("--publish-chain", receiver.url)
        first = self.chain()
        with open(first, "ab") as f:
            f.write(b'{"n": 2, "torn')             # a damaged tail

        done = self.call("--publish-chain", receiver.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        sibling = first.with_name(f"receipts-{SESSION}-002.jsonl")
        self.assertTrue(sibling.exists())
        self.assertEqual([e["n"] for e in lines_of(self.data / first.name)],
                         [0, 1])
        self.assertEqual((self.data / sibling.name).read_bytes(),
                         sibling.read_bytes())

    def test_under_managed_the_send_takes_no_proxy(self):
        receiver = start_receiver(self, self.data)
        proxy = f"http://127.0.0.1:{free_port()}"
        env = {**self.env(), "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy,
               "https_proxy": proxy, "http_proxy": proxy}

        done = self.call("--managed", "--publish-chain", receiver.url,
                         env=env)

        self.assertEqual(done.returncode, 0, done.stderr)
        (log,) = sorted(p for p in (self.home / ".loxodonta" / "receipts")
                        .rglob("receipts-*.jsonl") if p.name.count(".") == 1)
        self.assertEqual((self.data / log.name).read_bytes(),
                         log.read_bytes())


class SessionEndAfterTest(AsWrittenBase):
    """Ruling 4: the session end sends what the per-entry sends left, by
    the same rule."""

    def test_the_session_end_sends_the_seal_and_nothing_twice(self):
        receiver = start_receiver(self, self.data)
        transcript = self.root / "transcript.jsonl"
        transcript.write_bytes(b"page one\n")
        for _ in range(2):
            self.call("--publish-chain", receiver.url)
        payload = {"session_id": SESSION, "hook_event_name": "SessionEnd",
                   "reason": "prompt_input_exit",
                   "transcript_path": str(transcript)}

        done = run(LOXODONTA, "hook", "--publish-chain", receiver.url,
                   cwd=self.project, stdin=json.dumps(payload),
                   env=self.env(), timeout=60)

        self.assertEqual(done.returncode, 0, done.stderr)
        log = self.chain()
        kept = self.data / log.name
        self.assertEqual(kept.read_bytes(), log.read_bytes())
        self.assertEqual(lines_of(kept)[-1]["actor"], "receipts")  # the seal
        self.assertEqual(run_recorder("verify", "--log", kept).stdout.strip(),
                         "VALID")


class ByHandAndKeeperTest(unittest.TestCase):
    """`publish --chain` typed by hand says what the receiver said it
    holds, and the keeper's turn is not stood down by a memo row past
    the chain's end (ruling 4)."""

    def setUp(self):
        self.root = temp_folder(self)
        self.data = self.root / "receiver"
        self.receiver = start_receiver(self, self.data)

    def forge(self, log):
        with open(str(log) + ".published.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"kind": "chain", "first": 0, "last": 900,
                                "head": "ab" * 32,
                                "ts": "2026-11-11T00:00:00Z",
                                "event": "cadence",
                                "remote_id": remote_id(self.receiver.url)})
                    + "\n")

    def test_by_hand_the_command_says_what_the_remote_holds(self):
        log = self.root / CHAIN
        make_chain(log, ["step 1", "step 2"], epoch=1700000000)

        done = run_recorder("publish", "--chain", "--log", log,
                            self.receiver.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertRegex(done.stdout.strip(),
                         r"^published chain entries 0-2 \(head [0-9a-f]{12}…\)"
                         r"; the remote says it holds through entry 2$")

        self.forge(log)
        again = run_recorder("publish", "--chain", "--log", log,
                             self.receiver.url)

        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("note: the memo named entry 900 as sent there, and the "
                      "remote holds through entry 2", again.stdout)
        (row,) = [r for r in memo_rows(log) if r["kind"] == "attempt"]
        self.assertIn("the memo named entry 900", row["outcome"])

    def test_a_memo_row_past_the_end_does_not_stand_the_keeper_down(self):
        log = make_store_chain(self.root / "alpha" / "receipts", "sess-kept")
        run(LOXODONTA, "publish", "--chain", "--log", str(log),
            self.receiver.url, env=clean_env(), check=True)
        run(LOXODONTA, "log", "--log", str(log), "--actor", "claude-code",
            "--action", "step 3", env=clean_env(), check=True)
        self.forge(log)

        scan = run_scan(self.root, "--publish-every", "0s",
                        "--publish-chain", self.receiver.url,
                        env=isolated_env(temp_folder(self)))

        self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
        self.assertEqual((self.data / log.name).read_bytes(), log.read_bytes())
        notes = [r["outcome"] for r in memo_rows(log)
                 if r["kind"] == "attempt"]
        self.assertTrue(any("the memo named entry 900" in note
                            for note in notes), notes)


# --- The proofs travel ------------------------------------------------------------

class ProofsTravelTest(unittest.TestCase):
    """Ruling 5: after a step that adds or upgrades a row, the sidecar's
    evidence rows go to the chain's URL and are kept beside its copy,
    where the recorder's `verify` reads them as it reads its own."""

    def setUp(self):
        self.root = temp_folder(self)
        self.data = self.root / "receiver"
        self.log = self.root / CHAIN
        make_chain(self.log, ["step 1", "step 2"], epoch=1700000000)
        self.receiver = start_receiver(self, self.data)
        self.assertEqual(run_recorder("publish", "--chain", "--log", self.log,
                                      self.receiver.url).returncode, 0)

    def judged(self, log, *flags):
        done = run_recorder("verify", "--log", log, *flags)
        return done.returncode, done.stdout.replace(str(log.parent), "DIR")

    def test_anchor_rows_arrive_and_verify_judges_them_alike(self):
        calendar = start_calendar(self, b"nonce-0045")

        done = run_recorder("anchor", "--log", self.log, "--calendar",
                            calendar.url, "--publish-chain", self.receiver.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("sent the anchors sidecar's 1 row(s)", done.stdout)
        kept = self.data / (CHAIN + ".anchors.jsonl")
        local = Path(str(self.log) + ".anchors.jsonl")
        self.assertEqual(kept.read_bytes(), local.read_bytes())
        self.assertEqual(self.judged(self.data / CHAIN, "--anchors"),
                         self.judged(self.log, "--anchors"))

        # An attempt row beside the proof never travels, and a resend of
        # the rows the receiver holds appends nothing.
        with open(local, "a", encoding="utf-8") as f:
            f.write('{"budget":12.0,"kind":"attempt","outcome":"submitted",'
                    '"step":"anchor","ts":"2026-11-11T00:00:00Z"}\n')
        again = run_recorder("publish", "--chain", "--log", self.log,
                             self.receiver.url)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertNotIn(b'"attempt"', kept.read_bytes())
        self.assertEqual(len(kept.read_bytes().splitlines()), 1)
        self.assertEqual(self.judged(self.data / CHAIN, "--anchors"),
                         self.judged(self.log, "--anchors"))

    def test_stamp_rows_arrive_and_verify_judges_them_alike(self):
        authority = start_authority(self)

        done = run_recorder("stamp", "--log", self.log, "--authority",
                            authority.url, "--publish-chain",
                            self.receiver.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        kept = self.data / (CHAIN + ".stamps.jsonl")
        local = Path(str(self.log) + ".stamps.jsonl")
        self.assertEqual(kept.read_bytes(), local.read_bytes())
        self.assertEqual(self.judged(self.data / CHAIN, "--stamps"),
                         self.judged(self.log, "--stamps"))
        # A head already stamped adds no row, and sends none.
        again = run_recorder("stamp", "--log", self.log, "--authority",
                             authority.url, "--publish-chain",
                             self.receiver.url)
        self.assertNotIn("sent the stamps", again.stdout)

    def test_a_manifest_with_the_chains_url_is_a_usage_error(self):
        manifest = self.root / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        for verb, flag, value in (("anchor", "--calendar", "http://c.test"),
                                  ("stamp", "--authority", "http://a.test")):
            with self.subTest(verb=verb):
                done = run_recorder(verb, "--manifest", manifest, flag, value,
                                    "--publish-chain", self.receiver.url)
                self.assertEqual(done.returncode, 64, done.stderr)

    def test_a_receivers_scan_takes_no_sidecar_for_a_chain(self):
        calendar = start_calendar(self, b"nonce-0045")
        run_recorder("anchor", "--log", self.log, "--calendar", calendar.url,
                     "--publish-chain", self.receiver.url)
        self.assertTrue((self.data / (CHAIN + ".anchors.jsonl")).exists())
        home = temp_folder(self)

        scan = run(SUPERVISOR, "scan", "--receiver", str(self.data), "--json",
                   env=isolated_env(home), timeout=120)

        report = json.loads(scan.stdout)
        logs = [Path(chain["log"]).name for repo in report["repos"]
                for session in repo["sessions"] for chain in session["chains"]]
        self.assertEqual(logs, [CHAIN])


# --- The installer -------------------------------------------------------------

class InstallAsWrittenTest(unittest.TestCase):
    """Ruling 3 at install: at `full`, and under `custom` with the
    chain's flag, the recording command carries the chain's URL."""

    URL = "https://shelf.example.test:8790/7qpsWUkU86ML-NOuaGjSaetfYCGg"

    def setUp(self):
        self.root = temp_folder(self)
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        self.env = isolated_env(self.home,
                                LOXODONTA_HOME=str(self.root / "store"))

    def install(self, *args, verb="install-hook"):
        return run(LOXODONTA, verb, *args, cwd=self.root, env=self.env)

    def settings_path(self):
        return self.home / ".claude" / "settings.json"

    def commands(self, event):
        hooks = json.loads(self.settings_path().read_text("utf-8"))["hooks"]
        return [h["command"] for b in hooks.get(event, []) for h in b["hooks"]]

    def test_full_writes_the_chains_url_on_the_recording_commands(self):
        done = self.install("--profile", "full", "--remote", self.URL)

        self.assertEqual(done.returncode, 0, done.stderr)
        for event in ("PostToolUse", "PostToolUseFailure"):
            (command,) = self.commands(event)
            self.assertTrue(command.endswith(f' hook --publish-chain '
                                             f'"{self.URL}"'), command)
        self.assertIn("every entry will leave this machine as it is "
                      "written", done.stdout)
        again = self.install("--profile", "full", "--remote", self.URL)
        self.assertIn("already installed", again.stdout)

        self.assertEqual(self.install(verb="uninstall-hook").returncode, 0)
        self.assertNotIn(self.URL, self.settings_path().read_text("utf-8"))

    def test_an_older_install_is_rewritten_once_and_then_says_nothing(self):
        self.install("--profile", "full", "--remote", self.URL)
        text = self.settings_path().read_text("utf-8")
        recording = self.commands("PostToolUse")[0]
        older = recording.replace(f' --publish-chain "{self.URL}"', "")
        self.settings_path().write_text(text.replace(
            json.dumps(recording)[1:-1], json.dumps(older)[1:-1]), "utf-8")
        self.assertEqual(self.commands("PostToolUse"), [older])

        done = self.install("--profile", "full", "--remote", self.URL)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("now sends each entry as it is written", done.stdout)
        self.assertEqual(self.commands("PostToolUse"), [recording])
        self.assertEqual(self.commands("PostToolUseFailure"), [recording])
        again = self.install("--profile", "full", "--remote", self.URL)
        self.assertIn("already installed", again.stdout)
        self.assertNotIn("now sends", again.stdout)

    def test_a_rerun_below_full_takes_the_url_off_and_says_so(self):
        self.install("--profile", "full", "--remote", self.URL)

        done = self.install("--profile", "timestamped")

        self.assertIn("no longer sends each entry as it is written",
                      done.stdout)
        for event in ("PostToolUse", "PostToolUseFailure"):
            self.assertNotIn("--publish-chain", self.commands(event)[0])

    def test_custom_with_the_chains_flag_sends_as_written_and_codex_too(self):
        done = self.install("--profile", "custom", "--publish-chain", self.URL)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f'--publish-chain "{self.URL}"',
                      self.commands("PostToolUse")[0])

        codex = self.install("--codex", "--profile", "full", "--remote",
                             self.URL)
        self.assertEqual(codex.returncode, 0, codex.stderr)
        hooks = json.loads((self.home / ".codex" / "hooks.json")
                           .read_text("utf-8"))["hooks"]
        (wired,) = [h for b in hooks["PostToolUse"] for h in b["hooks"]]
        self.assertTrue(wired["command"].endswith(
            f' hook --actor codex --publish-chain "{self.URL}"'),
            wired["command"])


if __name__ == "__main__":
    unittest.main()
