"""Behavioral tests for ADR-0045, in its second form: entries leave as
they are written, and the receiver says what it holds.

The receiver keeps a line only when it is an entry, its hash recomputed
there; it refuses with 409 a batch that would leave a hole; and every
answer to a batch says the highest n it holds and whether the batch's
first entry connects. At `full` the recording hook posts the lines it
has just appended, from memory, and goes on from the answer alone: a
hole is filled from the entry after the highest held, an entry that does
not connect is followed by the one before it. The session end, the
keeper and `publish --chain` start from the chain's last entry and go on
the same way, the memo deciding nothing. Every test drives the public
CLI against the repo's own `receiver.py serve` on a loopback port, or a
socket of the test's own. No network, never internals.
"""

import hashlib
import http.server
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
DOES_NOT_SAY = "the remote does not say what it holds"


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


def hashed(entry):
    """`entry` with its entry_hash, by SPEC section 4."""
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return {**entry, "entry_hash": hashlib.sha256(canonical).hexdigest()}


def line_of(entry):
    return json.dumps(entry, sort_keys=True,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def forged_chain(count, action="Bash: ls"):
    """A chain of a genesis and `count` entries, each hashed and chained
    by SPEC sections 4 and 5, as bytes: what the recorder would write,
    made at a speed no run of the CLI reaches."""
    prev, lines = None, []
    for n in range(count + 1):
        entry = {"n": n, "ts": "2026-11-11T00:00:00Z",
                 "actor": "receipts" if n == 0 else "claude-code",
                 "action": "genesis" if n == 0 else f"{action} {n}",
                 "files": [], "prev": prev}
        if n == 0:
            entry["v"] = "0.1"
        entry = hashed(entry)
        prev = entry["entry_hash"]
        lines.append(line_of(entry))
    return b"".join(lines)


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


class Silent:
    """A socket on 127.0.0.1 that takes every connection into its backlog
    and never reads or answers one: a receiver that hangs."""

    def __init__(self, case):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}/token"
        case.addCleanup(self.sock.close)


class EmptyHandler(http.server.BaseHTTPRequestHandler):
    """A remote that takes every POST with a 200 and an empty body, as a
    chat webhook or an object store may: it says nothing of what it
    holds."""

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.received.append(
            (self.headers.get("X-Loxodonta-Range"), body))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


def serve_empty(case):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EmptyHandler)
    server.received = []
    server.url = f"http://127.0.0.1:{server.server_address[1]}/hook"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


# --- The receiver's side -------------------------------------------------------

class AnswerTest(ReceiverFixture):
    """Rulings 2 and 6 at the receiver: each answer to a batch says the
    highest n held and whether the batch's first entry connects; a hole
    is 409, nothing appended; and there is still no route that reads."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.log = self.root / CHAIN
        self.lines = make_chain(self.log, ["step 1", "step 2", "step 3"],
                                epoch=1700000000)
        self.rows = self.lines.splitlines(True)

    def send(self, body, name=CHAIN):
        return post(self.proc.url, body, NDJSON, {"X-Loxodonta-Chain": name})

    def test_an_answer_says_the_highest_n_held_and_whether_it_connects(self):
        status, answer = self.send(b"".join(self.rows[:2]))
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer),
                         {"appended": 2, "dropped": 0, "held_n": 1,
                          "chains": True})
        # A resend of what it holds adds nothing and says the same.
        status, answer = self.send(b"".join(self.rows[:2]))
        self.assertEqual(json.loads(answer),
                         {"appended": 0, "dropped": 2, "held_n": 1,
                          "chains": True})

    def test_a_hole_is_409_and_nothing_is_appended(self):
        self.send(b"".join(self.rows[:2]))
        kept = (self.data / CHAIN).read_bytes()

        for body in (self.rows[3], self.rows[3] + self.rows[2],
                     self.rows[1] + self.rows[3]):
            with self.subTest(body=body):
                status, answer = self.send(body)
                self.assertEqual(status, 409, answer)
                said = json.loads(answer)
                self.assertEqual(said["held_n"], 1)
                self.assertIn("entry 3", said["refused"])
                self.assertEqual((self.data / CHAIN).read_bytes(), kept)
        # Consecutive enough: the entry after the highest held, and on.
        status, answer = self.send(self.rows[2] + self.rows[3])
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer)["held_n"], 3)

    def test_a_first_batch_that_does_not_start_at_genesis_is_409(self):
        status, answer = self.send(self.rows[1])

        self.assertEqual(status, 409, answer)
        said = json.loads(answer)
        self.assertEqual((said["held_n"], said["chains"]), (None, False))
        self.assertEqual(self.stored(), ["token"])

    def test_an_entry_held_at_another_n_does_not_connect(self):
        # The answer's `chains` is about the batch's first entry only: its
        # prev must be the hash of an entry held at the n before it.
        other = self.root / "other.jsonl"
        theirs = make_chain(other, ["their 1", "their 2"],
                            epoch=1700009999).splitlines(True)
        self.send(b"".join(theirs))

        status, answer = self.send(self.rows[3])

        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer),
                         {"appended": 1, "dropped": 0, "held_n": 3,
                          "chains": False})

    def test_a_regenerated_entry_at_an_old_n_is_appended_and_breaks_there(self):
        # At or below the highest held, a line that is not the one held
        # is appended as before; the collision is the copy's point
        # (ADR-0031 ruling 4).
        self.send(self.lines)
        other = self.root / "again.jsonl"
        regenerated = make_chain(other, ["step 1", "rewritten"],
                                 epoch=1700009999).splitlines(True)

        status, answer = self.send(regenerated[2])

        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer)["appended"], 1)
        self.assertEqual(json.loads(answer)["held_n"], 3)
        judged = run_recorder("verify", "--log", self.data / CHAIN)
        self.assertEqual(judged.returncode, 1, judged.stdout)
        self.assertTrue(judged.stdout.startswith("BROKEN at entry 4"),
                        judged.stdout)

    def test_every_verb_but_post_at_the_chain_path_is_refused_as_before(self):
        self.send(self.lines)
        for verb in ("GET", "HEAD", "PUT", "DELETE"):
            with self.subTest(verb=verb):
                status, headers, body = request(verb, self.proc.url)
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "POST")
                self.assertNotIn(b"held_n", body)
                self.assertNotIn(json.loads(self.rows[3])["entry_hash"]
                                 .encode(), body)


class OnlyEntriesTest(ReceiverFixture):
    """Ruling 1: a batch is kept only when every line is an entry, read
    strictly and its hash recomputed; any other line refuses the whole
    batch, 400, naming the line and why, and nothing is appended."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.log = self.root / CHAIN
        self.lines = make_chain(self.log, ["step 1", "step 2"],
                                epoch=1700000000)
        self.rows = self.lines.splitlines(True)

    def send(self, body):
        return post(self.proc.url, body, NDJSON, {"X-Loxodonta-Chain": CHAIN})

    def test_a_line_that_is_not_an_entry_refuses_the_batch_and_the_chain_still_lands(self):
        first = json.loads(self.rows[1])
        below = {key: value for key, value in first.items()
                 if key != "entry_hash"}
        below["n"] = -1
        edited = dict(first, action="step 1, said otherwise")
        twice = self.rows[1].decode("utf-8").replace(
            '{"action"', '{"n":1,"action"', 1).encode("utf-8")
        not_entries = {
            "an n below 0": line_of(hashed(below)),
            "a hash that does not recompute": line_of(edited),
            "a line that is not JSON": b"not json at all\n",
            "a key given twice": twice,
        }
        for what, bad in not_entries.items():
            with self.subTest(what=what):
                status, answer = self.send(self.rows[0] + bad)

                self.assertEqual(status, 400, answer)
                self.assertIn(b"line 2 is not an entry", answer)
                self.assertEqual(self.stored(), ["token"])
        status, answer = self.send(self.lines)
        self.assertEqual(status, 200, answer)
        self.assertEqual((self.data / CHAIN).read_bytes(), self.lines)
        judged = run_recorder("verify", "--log", self.data / CHAIN)
        self.assertEqual(judged.stdout.strip(), "VALID")


class MemoryTest(ReceiverFixture):
    """The cost at the receiver: one new entry on top of what it holds is
    answered from memory, without reading the file it appends to."""

    def test_a_new_entry_on_a_large_file_does_not_read_the_file_again(self):
        count = 40000
        lines = forged_chain(count + 6).splitlines(True)
        self.data.mkdir(parents=True)
        (self.data / CHAIN).write_bytes(b"".join(lines[:count + 1]))
        proc = self.start()

        def timed(n):
            started = time.monotonic()
            status, answer = post(proc.url, lines[n], NDJSON,
                                  {"X-Loxodonta-Chain": CHAIN})
            took = time.monotonic() - started
            self.assertEqual(status, 200, answer)
            self.assertEqual(json.loads(answer)["chains"], True)
            return took

        # The first touch reads the file; every one after it does not.
        cold = timed(count + 1)
        warm = [timed(n) for n in range(count + 2, count + 7)]

        self.assertLess(max(warm), cold / 3,
                        f"a warm answer took {max(warm):.3f} s, the cold one "
                        f"{cold:.3f} s")
        self.assertEqual((self.data / CHAIN).read_bytes(), b"".join(lines))


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

    def session_end(self, *flags, session=SESSION):
        payload = {"session_id": session, "hook_event_name": "SessionEnd",
                   "reason": "prompt_input_exit"}
        return run(LOXODONTA, "hook", *flags, cwd=self.project,
                   stdin=json.dumps(payload), env=self.env(), timeout=60)

    def chains(self):
        return sorted(p for p in (self.store / "receipts").rglob(
            "receipts-*.jsonl") if p.name.count(".") == 1)

    def chain(self):
        (found,) = self.chains()
        return found

    def assertHeld(self, log):
        """The receiver holds every entry of the local chain, its copy
        the local file byte for byte."""
        self.assertEqual((self.data / log.name).read_bytes(), log.read_bytes())


class AsWrittenTest(AsWrittenBase):

    def test_each_entry_is_at_the_receiver_before_the_hook_returns(self):
        receiver = start_receiver(self, self.data)
        for calls in (1, 2, 3):
            done = self.call("--publish-chain", receiver.url)

            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stderr, "")
            self.assertEqual(done.stdout, f"logged entry {calls}\n")
            log = self.chain()
            # The session is still open: every entry, genesis on, is
            # held, in order, byte for byte.
            self.assertEqual([e["n"] for e in lines_of(self.data / log.name)],
                             list(range(calls + 1)))
            self.assertHeld(log)
        judged = run_recorder("verify", "--log", self.data / log.name)
        self.assertEqual(judged.stdout.strip(), "VALID")
        # Sends that all landed write nothing: no attempt row, and no
        # chain row, so the memo was never made.
        self.assertFalse(Path(str(log) + ".published.jsonl").exists())

    def test_a_line_sent_then_overwritten_does_not_stop_the_later_ones(self):
        receiver = start_receiver(self, self.data)
        for _ in range(3):
            self.call("--publish-chain", receiver.url)
        log = self.chain()
        sent = log.read_bytes().splitlines(True)
        sent[1] = b"this line was an entry\n"
        log.write_bytes(b"".join(sent))

        for _ in range(3):
            done = self.call("--publish-chain", receiver.url)
            self.assertEqual(done.returncode, 0, done.stderr)

        kept = lines_of(self.data / log.name)
        self.assertEqual([e["n"] for e in kept], list(range(7)))
        judged = run_recorder("verify", "--log", self.data / log.name)
        self.assertEqual(judged.stdout.strip(), "VALID")
        self.assertEqual(entry_attempts(log), [])

    def test_a_stray_byte_or_a_folder_at_the_memo_stops_no_send(self):
        receiver = start_receiver(self, self.data)
        for session, spoil in (("sess-stray", "byte"),
                               ("sess-folder", "folder")):
            with self.subTest(spoil=spoil):
                self.call("--publish-chain", receiver.url, session=session)
                (log,) = [p for p in self.chains() if session in p.name]
                memo = Path(str(log) + ".published.jsonl")
                if spoil == "byte":
                    with open(memo, "ab") as f:
                        f.write(b"\xff")
                else:
                    memo.mkdir()

                for _ in range(2):
                    done = self.call("--publish-chain", receiver.url,
                                     session=session)
                    self.assertEqual(done.returncode, 0, done.stderr)
                    self.assertEqual(done.stderr, "")

                self.assertHeld(log)

    def test_a_receiver_down_for_two_calls_gets_the_rest_from_the_hole(self):
        port = free_port()
        receiver = start_receiver(self, self.data, port=port)
        url = receiver.url
        self.call("--publish-chain", url)
        receiver.stop()
        for _ in range(2):
            self.assertEqual(self.call("--publish-chain", url).returncode, 0)
        log = self.chain()
        (down,) = entry_attempts(log)

        again = start_receiver(self, self.data, port=port)
        self.assertEqual(again.url, url)
        done = self.call("--publish-chain", url)

        self.assertEqual(done.returncode, 0, done.stderr)
        # Its own entry was a hole after entry 1; the answer said so, and
        # entries 2 to 4 went in the same second.
        self.assertHeld(log)
        self.assertEqual([r["outcome"] for r in entry_attempts(log)],
                         [down["outcome"], "sent"])

    def test_an_entry_missing_below_the_top_is_walked_back_to(self):
        port = free_port()
        receiver = start_receiver(self, self.data, port=port)
        for _ in range(3):
            self.call("--publish-chain", receiver.url)
        log = self.chain()
        receiver.stop()
        # In the receiver's folder: entry 3 taken out, and in its place
        # an entry 3 of another chain, so the highest n held is 3 and
        # what is held there is not this chain's.
        other = self.root / "other.jsonl"
        theirs = make_chain(other, ["a", "b", "c"],
                            epoch=1700009999).splitlines(True)
        kept = (self.data / log.name).read_bytes().splitlines(True)
        (self.data / log.name).write_bytes(b"".join(kept[:3] + [theirs[3]]))

        again = start_receiver(self, self.data, port=port)
        done = self.call("--publish-chain", again.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        # Entry 4 did not connect, the hook sent entry 3 alone, and that
        # one did: every line of the local chain is held.
        held = (self.data / log.name).read_bytes().splitlines(True)
        for line in log.read_bytes().splitlines(True):
            self.assertIn(line, held)
        self.assertEqual(entry_attempts(log), [])

    def test_entries_posted_ahead_by_the_urls_holder_do_not_stop_ours(self):
        # The writer holds the URL and posts a chain of its own making
        # under this chain's name first, entries 0 to 5, valid entries
        # all. Ours, at 0 to 3, still all arrive, and the copy reads
        # BROKEN where the two collide.
        receiver = start_receiver(self, self.data)
        for _ in range(2):
            self.call()                                  # 0, 1, 2: not sent
        log = self.chain()
        other = self.root / "forged.jsonl"
        forged = make_chain(other, ["x1", "x2", "x3", "x4", "x5"],
                            epoch=1700009999)
        status, _ = post(receiver.url, forged, NDJSON,
                         {"X-Loxodonta-Chain": log.name})
        self.assertEqual(status, 200)

        done = self.call("--publish-chain", receiver.url)          # 3

        self.assertEqual(done.returncode, 0, done.stderr)
        held = (self.data / log.name).read_bytes().splitlines(True)
        for line in log.read_bytes().splitlines(True):
            self.assertIn(line, held)
        judged = run_recorder("verify", "--log", self.data / log.name)
        self.assertEqual(judged.returncode, 1, judged.stdout)
        self.assertTrue(judged.stdout.startswith("BROKEN at entry 6"),
                        judged.stdout)

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

    def test_a_receiver_that_never_answers_costs_the_cap_and_no_more(self):
        silent = Silent(self)
        self.call()
        for _ in range(3):
            started = time.monotonic()
            done = self.call("--publish-chain", silent.url)
            took = time.monotonic() - started

            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stderr, "")
            self.assertGreaterEqual(took, 0.9, "the second was spent waiting")
            self.assertLess(took, 6.0)
        (row,) = entry_attempts(self.chain())
        self.assertEqual(row["outcome"], "no answer within 1 seconds")

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
        self.assertHeld(sibling)

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
        self.assertHeld(log)


class LongHistoryTest(unittest.TestCase):
    """The cost at the hook: a recording call at `full` reads neither the
    whole chain nor the whole memo to send what it wrote. The recording
    itself reads the chain's tail, as it always has; what the send adds
    is measured against the same call without it."""

    def test_a_long_chain_and_a_long_memo_cost_the_send_nothing(self):
        root = temp_folder(self)
        drawer, data = root / "drawer", root / "receiver"
        drawer.mkdir()
        data.mkdir()
        log = drawer / f"receipts-{SESSION}.jsonl"
        chain = forged_chain(5000)
        log.write_bytes(chain)
        (data / log.name).write_bytes(chain)
        # Some 60 MB of memo rows, none of them about this step.
        row = (json.dumps({"budget": 3.0, "kind": "attempt",
                           "outcome": "no answer within 3 seconds",
                           "step": "publish-head",
                           "ts": "2026-11-11T00:00:00Z"},
                          sort_keys=True) + "\n").encode("utf-8")
        Path(str(log) + ".published.jsonl").write_bytes(row * 400000)
        receiver = start_receiver(self, data)
        env = isolated_env(temp_folder(self))

        def call(*flags):
            payload = {"session_id": SESSION, "hook_event_name": "PostToolUse",
                       "tool_name": "Bash", "tool_input": {"command": "ls"}}
            started = time.monotonic()
            done = run(LOXODONTA, "hook", "--log-dir", str(drawer), *flags,
                       stdin=json.dumps(payload), env=env, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
            return time.monotonic() - started

        without = min(call() for _ in range(3))
        # The receiver is told of the three calls' entries by the first
        # call that sends, filling the hole from the entry after its own.
        sending = min(call("--publish-chain", receiver.url) for _ in range(3))

        self.assertLess(sending - without, 0.75,
                        f"with the send {sending:.2f} s, without {without:.2f} s")
        self.assertEqual((data / log.name).read_bytes(), log.read_bytes())


class SessionEndAfterTest(AsWrittenBase):
    """Ruling 4: the session end posts the chain's last entry and goes on
    from the answer, by the same rule as the hook."""

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
        self.assertHeld(log)
        self.assertEqual(lines_of(self.data / log.name)[-1]["actor"],
                         "receipts")  # the seal
        self.assertEqual(run_recorder("verify", "--log", self.data / log.name)
                         .stdout.strip(), "VALID")


class ForgedEndTest(AsWrittenBase):
    """A memo row forged with `last` at the chain's end, while the
    receiver lacks the chain's last two entries: `publish --chain`, the
    session end and the keeper each still deliver them, since the memo
    decides nothing (ADR-0045 ruling 4)."""

    def forge(self, log, url):
        end = lines_of(log)[-1]
        with open(str(log) + ".published.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"kind": "chain", "first": 0,
                                "last": end["n"], "head": end["entry_hash"],
                                "ts": "2026-11-11T00:00:00Z",
                                "event": "cadence",
                                "remote_id": remote_id(url)}) + "\n")

    def lacking_two(self, session, receiver):
        """A session whose first calls went to the receiver and whose last
        two did not, with the forged row beside it."""
        self.call("--publish-chain", receiver.url, session=session)
        self.call(session=session)
        self.call(session=session)
        (log,) = [p for p in self.chains() if session in p.name]
        self.assertEqual(len(lines_of(self.data / log.name)), 2)
        self.forge(log, receiver.url)
        return log

    def test_publish_chain_by_hand_delivers_them(self):
        receiver = start_receiver(self, self.data)
        log = self.lacking_two("sess-by-hand", receiver)

        done = run_recorder("publish", "--chain", "--log", log, receiver.url)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("published chain entries 2-3", done.stdout)
        self.assertHeld(log)

    def test_the_session_end_delivers_them(self):
        receiver = start_receiver(self, self.data)
        log = self.lacking_two("sess-ended", receiver)

        done = self.session_end("--publish-chain", receiver.url,
                                session="sess-ended")

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertHeld(log)

    def test_the_keeper_delivers_them(self):
        receiver = start_receiver(self, self.data)
        root = self.root / "repos"
        log = make_store_chain(root / "alpha" / "receipts", "sess-kept")
        home = temp_folder(self)

        def tick(**knobs):
            scan = run_scan(root, "--publish-every", "0s", "--publish-chain",
                            receiver.url, env=isolated_env(home, **knobs))
            self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)

        tick()
        self.assertEqual((self.data / log.name).read_bytes(), log.read_bytes())
        time.sleep(1.1)   # past the second the keeper's turn is kept by
        for action in ("step 3", "step 4"):
            run(LOXODONTA, "log", "--log", str(log), "--actor", "claude-code",
                "--action", action, env=clean_env(), check=True)
        self.forge(log, receiver.url)

        tick(SUPERVISOR_UPGRADE_EVERY_SECONDS="0")

        self.assertEqual((self.data / log.name).read_bytes(), log.read_bytes())


class SaysNothingTest(AsWrittenBase):
    """A remote that takes a batch with a 200 and an empty body says
    nothing of what it holds: the entries are sent from the memo as
    before ADR-0045, one note says so, and no reader counts the note a
    failed step (ADR-0045 ruling 4)."""

    def test_entries_go_from_the_memo_and_one_note_is_written(self):
        remote = serve_empty(self)
        drawer = self.root / "repos" / "alpha" / "receipts"
        flags = ("--log-dir", str(drawer), "--publish-chain", remote.url)
        for _ in range(2):
            self.assertEqual(self.call(*flags).returncode, 0)
        log = drawer / f"receipts-{SESSION}.jsonl"

        ended = run(LOXODONTA, "hook", *flags, cwd=self.project,
                    stdin=json.dumps({"session_id": SESSION,
                                      "hook_event_name": "SessionEnd",
                                      "reason": "prompt_input_exit"}),
                    env=self.env(), timeout=60)
        by_hand = run_recorder("publish", "--chain", "--log", log, remote.url)

        self.assertEqual(ended.returncode, 0, ended.stderr)
        self.assertEqual(by_hand.returncode, 0, by_hand.stderr)
        self.assertIn(DOES_NOT_SAY, by_hand.stdout)
        # From the memo: the session end found no chain row and sent the
        # chain from genesis; by hand, nothing after it.
        rows = [r for r in memo_rows(log) if r["kind"] == "chain"]
        self.assertEqual([(r["first"], r["last"]) for r in rows], [(0, 2)])
        self.assertIn(("0-2", log.read_bytes()), remote.received)
        notes = [r for r in memo_rows(log) if r["kind"] == "attempt"
                 and r.get("note") == DOES_NOT_SAY]
        self.assertEqual(len(notes), 1, memo_rows(log))
        self.assertEqual(notes[0]["outcome"], "sent")

        scan = run_scan(self.root / "repos", env=isolated_env(temp_folder(self)))
        report = json.loads(scan.stdout)
        (chain,) = [c for repo in report["repos"] for s in repo["sessions"]
                    for c in s["chains"]]
        self.assertIsNone(chain["last_failed"])


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

    def test_a_failed_send_of_rows_is_one_row_and_the_rows_go_next_time(self):
        calendar = start_calendar(self, b"nonce-0045")
        dead = "http://127.0.0.1:9/token"
        self.assertEqual(run_recorder("anchor", "--log", self.log,
                                      "--calendar", calendar.url).returncode, 0)
        local = Path(str(self.log) + ".anchors.jsonl")
        proofs = local.read_bytes()

        for _ in range(2):
            done = run_recorder("anchor", "--log", self.log, "--calendar",
                                calendar.url, "--force",
                                "--publish-chain", dead)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("rows were not sent", done.stderr)

        rows = [json.loads(line) for line in local.read_text("utf-8")
                .splitlines()]
        failed = [r for r in rows if r.get("step") == "publish-rows"]
        self.assertEqual(len(failed), 1, rows)
        self.assertNotEqual(failed[0]["outcome"], "sent")
        self.assertNotIn(":9/token", local.read_text("utf-8"),
                         "the chain's URL is a credential")

        again = run_recorder("publish", "--chain", "--log", self.log,
                             self.receiver.url)

        self.assertEqual(again.returncode, 0, again.stderr)
        kept = self.data / (CHAIN + ".anchors.jsonl")
        evidence = [line for line in local.read_bytes().splitlines(True)
                    if b'"attempt"' not in line]
        self.assertEqual(kept.read_bytes().splitlines(True), evidence)
        self.assertTrue(proofs.splitlines(True)[0] in evidence)
        newest = [json.loads(line) for line in local.read_text("utf-8")
                  .splitlines()
                  if json.loads(line).get("step") == "publish-rows"][-1]
        self.assertEqual(newest["outcome"], "sent")

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
