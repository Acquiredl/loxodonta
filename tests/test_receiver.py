"""Behavioral tests for the receiver (`receiver.py`, ADR-0031 rulings 4
and 5, issue #247): the far end of the published chain and the
published head, a URL that can only add, never delete.

Every test starts the receiver as a subprocess on a free port and talks
to it the way the world does: raw HTTP through urllib, or the recorder's
own `publish`. Nothing is imported from the tool and nothing is mocked.
The acceptance test is the recorder's: after honest batches the
receiver's chain file verifies VALID, and a regenerated chain's batch
lands beside the entries it replaced and verifies BROKEN there.
"""

import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_receiver`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env

REPO_ROOT = Path(__file__).resolve().parent.parent
RECEIVER = REPO_ROOT / "receiver.py"
LOXODONTA = REPO_ROOT / "loxodonta.py"

PUBLISH_TO = re.compile(r"^publish to (https?://\S+)$", re.M)

# Straight to 127.0.0.1, never through a proxy someone's shell configured.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run_recorder(*args, epoch=None):
    """The recorder as a subprocess. `epoch` pins SOURCE_DATE_EPOCH so two
    chains built by one test differ (or agree) by design, not by clock."""
    env = clean_env()
    if epoch is not None:
        env["SOURCE_DATE_EPOCH"] = str(epoch)
    return subprocess.run([sys.executable, str(LOXODONTA), *map(str, args)],
                          capture_output=True, encoding="utf-8", env=env)


def make_chain(log, actions, epoch=None):
    """A real chain through the public CLI: genesis, then one receipt per
    action. Returns its lines as bytes, the way the sender ships them."""
    done = run_recorder("init", "--log", log, epoch=epoch)
    assert done.returncode == 0, done.stderr
    for action in actions:
        done = run_recorder("log", "--log", log, "--actor", "claude-code",
                            "--action", action, epoch=epoch)
        assert done.returncode == 0, done.stderr
    return log.read_bytes()


def free_port():
    """A port nothing is listening on right now, for the tests that need
    the same URL across two starts (a port the receiver picks itself
    would change with every start)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def post(url, body, content_type, headers=None, timeout=30):
    """One POST; (status, body) whatever the status was."""
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": content_type, **(headers or {})})
    try:
        with OPENER.open(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as refused:
        return refused.code, refused.read()


def request(method, url):
    """One bodiless request of any verb; (status, headers, body)."""
    try:
        with OPENER.open(urllib.request.Request(url, method=method),
                         timeout=30) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as refused:
        return refused.code, refused.headers, refused.read()


def raw_request(url, request_bytes):
    """Bytes on a socket, and every byte that came back: for the request
    urllib would not send, such as a declared length with no body."""
    parts = urllib.parse.urlsplit(url)
    with socket.create_connection((parts.hostname, parts.port),
                                  timeout=30) as sock:
        sock.sendall(request_bytes)
        answered = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return answered
            answered += chunk


class ReceiverFixture(unittest.TestCase):
    """A private data directory and a real `receiver.py serve` on a free
    port, narrowed to 127.0.0.1 unless a test says otherwise."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.data = self.root / "receiver"

    def start(self, *extra, port=0, bind="127.0.0.1", env=None):
        """Start the receiver and read what it printed up to the URL.
        Returns the process, with `.url` and `.said` set on it."""
        argv = [sys.executable, str(RECEIVER), "serve",
                "--data", str(self.data), "--port", str(port)]
        if bind:
            argv += ["--bind", bind]
        proc = subprocess.Popen(
            argv + list(extra), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, encoding="utf-8",
            env={**clean_env(), **(env or {})})
        self.addCleanup(self.stop, proc)
        said = []
        while True:
            line = proc.stdout.readline()
            if not line:
                proc.kill()
                self.fail("the receiver printed no URL:\n%s%s"
                          % ("".join(said), proc.stderr.read()))
            said.append(line)
            found = PUBLISH_TO.search(line)
            if found:
                break
        proc.url = found.group(1)
        proc.said = "".join(said)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()

    def stored(self):
        """Every file the receiver keeps, by name."""
        return sorted(p.name for p in self.data.iterdir())

    @staticmethod
    def logged(proc, status):
        """The receiver's next log line for a POST answered `status`,
        read before the process is stopped. The line is printed just
        after the answer is sent, so it is always on its way."""
        while True:
            line = proc.stdout.readline()
            if not line:
                raise AssertionError(f"the receiver logged no {status}")
            if f" POST {status} " in line:
                return line


class UrlTest(ReceiverFixture):
    """The URL is the credential: minted once, reprinted on every start,
    rotated on request, and the old one then answers nothing."""

    def test_the_url_is_minted_once_reprinted_and_rotated(self):
        port = free_port()
        first = self.start(port=port)
        self.stop(first)
        self.assertIn("token", self.stored())

        again = self.start(port=port)
        self.assertEqual(again.url, first.url)
        self.stop(again)

        rotated = self.start("--new-token", port=port)
        self.assertNotEqual(rotated.url, first.url)

        head = json.dumps({"head": "a" * 64, "n": 1}).encode("utf-8")
        status, _ = post(first.url, head, "application/json")
        self.assertEqual(status, 404)
        status, _ = post(rotated.url, head, "application/json")
        self.assertEqual(status, 200)


class RefusalTest(ReceiverFixture):
    """The token's door, POST at the token's path; everything else is
    turned away, and nothing that arrived is ever handed back. The
    events door under it is EventsDoorTest's."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.token = self.proc.url.rsplit("/", 1)[1]
        self.base = self.proc.url[:-len(self.token)]  # http://127.0.0.1:P/

    def test_every_verb_but_post_is_405_at_the_token_path(self):
        for verb in ("GET", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(verb=verb):
                status, headers, _ = request(verb, self.proc.url)
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "POST")

    def test_any_other_path_is_404_whatever_the_verb(self):
        elsewhere = ("", "heads.jsonl", "receipts-abc.jsonl",
                     self.token + "/heads.jsonl", self.token[:-1],
                     self.token.upper())
        for path in elsewhere:
            with self.subTest(path=path):
                status, _, _ = request("GET", self.base + path)
                self.assertEqual(status, 404)
                status, _ = post(self.base + path, b"{}", "application/json")
                self.assertEqual(status, 404)
        self.assertEqual(self.stored(), ["token"])

    def test_a_path_that_is_not_ascii_is_404_not_a_dropped_connection(self):
        # urllib cannot send this path; the bytes go on a socket. A token
        # is ASCII, so a path that is not can never be the token's.
        answered = raw_request(
            self.proc.url,
            b"POST /caf\xc3\xa9 HTTP/1.0\r\nHost: receiver\r\n"
            b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
        self.assertTrue(answered.startswith(b"HTTP/1.0 404 "), answered)

    def test_a_body_over_the_cap_is_413_and_nothing_is_written(self):
        # A declared length far past any cap, and no body behind it: the
        # receiver must refuse on the declaration, before reading a byte.
        answered = raw_request(
            self.proc.url,
            ("POST /%s HTTP/1.0\r\nHost: receiver\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: 1000000000000\r\n\r\n" % self.token).encode())
        self.assertTrue(answered.startswith(b"HTTP/1.0 413 "), answered)
        self.assertEqual(self.stored(), ["token"])

    def test_no_route_returns_what_the_receiver_holds(self):
        digest = "f" * 64
        head = json.dumps({"head": digest, "n": 7}).encode("utf-8")
        status, _ = post(self.proc.url, head, "application/json")
        self.assertEqual(status, 200)
        self.assertIn("heads.jsonl", self.stored())
        for path in ("", "heads.jsonl", self.token, self.token + "/",
                     self.token + "/heads.jsonl", self.token + "?file=heads.jsonl",
                     "receipts-abc.jsonl"):
            with self.subTest(path=path):
                status, _, body = request("GET", self.base + path)
                self.assertIn(status, (404, 405))
                self.assertNotIn(digest.encode(), body)


CHAIN = "receipts-sess-0001.jsonl"
NDJSON = "application/x-ndjson"


class ContentTest(ReceiverFixture):
    """Two content types, two destinations: a JSON head to the heads
    file, an NDJSON batch to the chain file the header names."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.log = self.root / CHAIN
        self.lines = make_chain(self.log, ["step 1", "step 2"], epoch=1700000000)

    def send_chain(self, body, name=CHAIN):
        headers = {} if name is None else {"X-Loxodonta-Chain": name}
        return post(self.proc.url, body, NDJSON, headers)

    def test_a_json_post_from_the_recorder_lands_as_one_head_line(self):
        for expected in (1, 2):
            done = run_recorder("publish", "--log", self.log, self.proc.url)
            self.assertEqual(done.returncode, 0, done.stderr)
            heads = (self.data / "heads.jsonl").read_text("utf-8").splitlines()
            self.assertEqual(len(heads), expected)
        head = run_recorder("head", "--log", self.log).stdout.strip()
        self.assertEqual(json.loads(heads[-1])["head"], head)
        self.assertEqual(self.stored(), ["heads.jsonl", "token"])

    def test_an_ndjson_post_lands_in_the_file_the_chain_header_names(self):
        status, answer = self.send_chain(self.lines)
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer), {"appended": 3, "dropped": 0})
        self.assertEqual((self.data / CHAIN).read_bytes(), self.lines)
        # The sibling name is a receipt file name too (GLOSSARY: sibling chain).
        status, _ = self.send_chain(self.lines, "receipts-sess-0001-002.jsonl")
        self.assertEqual(status, 200)
        self.assertEqual(self.stored(),
                         ["receipts-sess-0001-002.jsonl", CHAIN, "token"])

    def test_a_chain_name_that_is_not_a_receipt_file_name_is_refused(self):
        not_a_chain = (None, "", "receipts-x.txt", "x.jsonl", "receipts-.jsonl",
                       "receipts-x.JSONL", "receipts-a b.jsonl", "heads.jsonl",
                       "token", "../receipts-x.jsonl", "receipts/x.jsonl",
                       "receipts\\x.jsonl", "/receipts-x.jsonl",
                       "receipts-x.jsonl/", "receipts-..jsonl",
                       "receipts-x.jsonl\tzzz", "receipts-" + "x" * 300 + ".jsonl")
        for name in not_a_chain:
            with self.subTest(name=name):
                status, _ = self.send_chain(self.lines, name)
                self.assertEqual(status, 400)
        self.assertEqual(self.stored(), ["token"])

    def test_the_200_answer_says_it_is_json(self):
        request = urllib.request.Request(
            self.proc.url, data=self.lines, method="POST",
            headers={"Content-Type": NDJSON, "X-Loxodonta-Chain": CHAIN})
        with OPENER.open(request, timeout=30) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get("Content-Type"),
                             "application/json")
            self.assertEqual(json.loads(response.read()),
                             {"appended": 3, "dropped": 0})

    def test_an_exact_duplicate_line_is_dropped(self):
        # A batch the sender retried after a lost acknowledgement: every
        # line is already there, n and entry_hash alike, so none lands.
        self.send_chain(self.lines)
        status, answer = self.send_chain(self.lines)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(answer), {"appended": 0, "dropped": 3})
        self.assertEqual((self.data / CHAIN).read_bytes(), self.lines)
        # And a resend that overlaps only partly lands only the new tail
        # (the chain grows through the CLI, as the sender's would).
        run_recorder("log", "--log", self.log, "--actor", "claude-code",
                     "--action", "step 3", epoch=1700000000)
        grown = self.log.read_bytes()
        status, answer = self.send_chain(grown)
        self.assertEqual(json.loads(answer), {"appended": 1, "dropped": 3})
        self.assertEqual((self.data / CHAIN).read_bytes(), grown)

    def test_a_torn_tail_never_glues_the_next_batch_onto_it(self):
        # The receiver's box crashed mid-append and left the last line
        # partial. The sender's retry must land as whole lines after it,
        # so the torn line stands alone as the one bad entry verify
        # reports, and nothing else is corrupted by the glue.
        self.send_chain(self.lines)
        kept = self.data / CHAIN
        whole = kept.read_bytes()
        kept.write_bytes(whole[:-20])            # mid-line, no newline
        status, answer = self.send_chain(self.lines)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(answer), {"appended": 1, "dropped": 2})
        lines = kept.read_bytes().split(b"\n")
        self.assertEqual(lines[:2], self.lines.split(b"\n")[:2])
        self.assertEqual(lines[2], whole[:-20].split(b"\n")[2])   # torn, alone
        self.assertEqual(lines[3], self.lines.split(b"\n")[2])    # whole again
        self.assertEqual(lines[4], b"")
        self.assertEqual(json.loads(lines[3])["n"], 2)

    def test_a_known_n_with_a_different_hash_is_appended(self):
        # A regenerated chain arriving after the original: the collision
        # the copy exists to show, a second entry at the same n.
        self.send_chain(self.lines)
        other = self.root / "regenerated.jsonl"
        regenerated = make_chain(other, ["step 1", "step 2"], epoch=1700009999)
        status, answer = self.send_chain(regenerated)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(answer), {"appended": 3, "dropped": 0})
        self.assertEqual((self.data / CHAIN).read_bytes(),
                         self.lines + regenerated)
        stored = [json.loads(l) for l in
                  (self.data / CHAIN).read_text("utf-8").splitlines()]
        self.assertEqual([e["n"] for e in stored], [0, 1, 2, 0, 1, 2])
        self.assertNotEqual(stored[0]["entry_hash"], stored[3]["entry_hash"])

    def test_a_batch_that_is_not_receipts_is_refused_whole(self):
        good = self.lines.splitlines()[0]
        not_receipts = (
            b"",                                   # nothing to append
            b"not json\n",
            b"[1, 2]\n",                           # not an object
            b'{"n": "0", "entry_hash": "ab"}\n',   # n is not an integer
            b'{"n": 0}\n',                         # no entry_hash
            b'{"n": true, "entry_hash": "ab"}\n',  # a bool is not a count
            good + b"\n\n" + good + b"\n",         # a blank line inside
            good + b"\nnot json\n",                # one bad line refuses all
        )
        for body in not_receipts:
            with self.subTest(body=body):
                status, _ = self.send_chain(body)
                self.assertEqual(status, 400)
        self.assertEqual(self.stored(), ["token"])

    def test_a_deeply_nested_body_is_refused_not_a_crash(self):
        # RED-TEAM (area C, C8): the sender holding the URL is the
        # adversary. A deeply nested but valid JSON body, well under the
        # 8 MiB body cap, makes json.loads raise RecursionError in
        # head_line (and receipt_of for a batch), which neither catches
        # (both catch ValueError/UnicodeDecodeError only). keep_batch
        # catches ValueError but not RecursionError. So the handler
        # crashes with a traceback and the connection is dropped, instead
        # of the 400 a malformed body gets everywhere else here
        # (test_a_batch_that_is_not_receipts_is_refused_whole). RECEIVER.md
        # and #300 say a malformed body is refused. Same RecursionError
        # omission as #463 and the serve/mcp readers; catch it beside
        # ValueError. The receiver survives for the next sender (threaded),
        # which is tested last.
        deep = ("[" * 6000 + "]" * 6000).encode("utf-8")
        status, _ = post(self.proc.url, deep, "application/json")
        self.assertEqual(status, 400)
        status, _ = self.send_chain(deep)
        self.assertEqual(status, 400)
        # Nothing of either landed, and a valid head still works after.
        self.assertEqual(self.stored(), ["token"])
        ok, _ = post(self.proc.url,
                     json.dumps({"n": 1, "head": "ab"}).encode("utf-8"),
                     "application/json")
        self.assertEqual(ok, 200)

    def test_any_other_content_type_is_415(self):
        status, _ = post(self.proc.url, self.lines, "text/plain",
                         {"X-Loxodonta-Chain": CHAIN})
        self.assertEqual(status, 415)
        status, _ = post(self.proc.url, b"{}", "")
        self.assertEqual(status, 415)
        self.assertEqual(self.stored(), ["token"])


EVENTS = "application/json"
EVENTS_FILE = re.compile(r"events-\d{4}-\d{2}-\d{2}\.jsonl")
IDENTITY = ("user.", "organization.")
# One real session's events, scrubbed: seven requests as the harness
# posted them, 51 log records, with the five identity values replaced by
# obvious fakes. The fakes are there so a test can show they are dropped.
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "harness_events.jsonl"


def fixture_bodies():
    """The `logs` object of each line of the capture: the bodies a
    sender posts, in the order they were sent."""
    return [json.loads(line)["logs"]
            for line in FIXTURE.read_text("utf-8").splitlines()]


def is_identity(entry):
    return (isinstance(entry, dict) and isinstance(entry.get("key"), str)
            and entry["key"].startswith(IDENTITY))


def without_identity(node):
    """The expected shape of a kept object: every attribute whose key
    begins `user.` or `organization.` gone from every `attributes` list
    and from the `values` of every `kvlistValue` at any depth, and
    nothing else changed, list order included."""
    if isinstance(node, dict):
        kept = {}
        for key, value in node.items():
            if key == "attributes" and isinstance(value, list):
                value = [a for a in value if not is_identity(a)]
            elif (key == "kvlistValue" and isinstance(value, dict)
                  and isinstance(value.get("values"), list)):
                value = {**value, "values": [a for a in value["values"]
                                             if not is_identity(a)]}
            kept[key] = without_identity(value)
        return kept
    if isinstance(node, list):
        return [without_identity(item) for item in node]
    return node


def log_records(logs):
    """Every log record in a posted object, in order."""
    return [record
            for resource in logs.get("resourceLogs", [])
            for scope in resource.get("scopeLogs", [])
            for record in scope.get("logRecords", [])]


def attribute(key, value):
    return {"key": key, "value": {"stringValue": value}}


class EventsDoorTest(ReceiverFixture):
    """The second door (ADR-0041 rulings 2 and 3, #479): POST at
    /<token>/v1/logs takes a harness's events as one JSON object, drops
    the identity attributes, and keeps each request as one line in the
    file of its UTC day of arrival, under the first door's lock, fsync
    and caps. The receiver understands nothing else about the body."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.token = self.proc.url.rsplit("/", 1)[1]
        self.base = self.proc.url[:-len(self.token)]  # http://127.0.0.1:P/
        self.door = self.proc.url + "/v1/logs"

    def send(self, body, content_type=EVENTS, headers=None):
        return post(self.door, body, content_type, headers)

    def event_files(self):
        return [name for name in self.stored() if name.startswith("events-")]

    def lines(self):
        """Every kept line across the day files, raw and parsed, in
        order."""
        kept = []
        for name in self.event_files():
            for raw in (self.data / name).read_bytes().split(b"\n"):
                if raw:
                    kept.append((raw, json.loads(raw)))
        return kept

    def test_the_capture_lands_one_line_a_request_with_identity_dropped(self):
        bodies = fixture_bodies()
        self.assertEqual(sum(len(log_records(b)) for b in bodies), 51)
        before = datetime.now(timezone.utc)
        for body in bodies:
            status, answer = self.send(json.dumps(body).encode("utf-8"))
            self.assertEqual(status, 200, answer)
            self.assertEqual(json.loads(answer), {})
            said = self.logged(self.proc, 200)
            dropped = 5 * len(log_records(body))
            self.assertIn(f"events: {dropped} identity attribute(s) dropped",
                          said)
            self.assertNotIn(self.token, said)
            self.assertNotIn("/v1/logs", said)
        after = datetime.now(timezone.utc)

        # None of the fakes, and no identity key at all, on disk.
        on_disk = b"".join((self.data / name).read_bytes()
                           for name in self.event_files())
        for fake in (b"operator@example.invalid", b'"user.', b'"organization.'):
            self.assertNotIn(fake, on_disk)

        lines = self.lines()
        self.assertEqual(len(lines), 7)
        for (raw, line), body in zip(lines, bodies):
            self.assertEqual(sorted(line), ["from", "logs", "received"])
            self.assertEqual(line["from"], "127.0.0.1")
            self.assertEqual(line["logs"], without_identity(body))
            self.assertEqual(len(log_records(line["logs"])),
                             len(log_records(body)))
            received = datetime.fromisoformat(line["received"])
            self.assertIsNotNone(received.tzinfo)
            self.assertTrue(before <= received <= after, line["received"])
            # Compact and key-sorted, whatever whitespace the sender used.
            self.assertEqual(raw, json.dumps(line, sort_keys=True,
                                             separators=(",", ":")).encode())

    def test_identity_goes_from_every_level_and_nothing_else_moves(self):
        # The two list shapes the standard keeps attributes in: an
        # `attributes` list, and the `values` of a `kvlistValue`, which
        # an `arrayValue` may hold in turn (the fixture's own
        # `managed_settings.sources` is the sibling `arrayValue`). The
        # match is exact, case included: `User.email` stays.
        body = {
            "attributes": [attribute("user.id", "top"),
                           attribute("kept.top", "1")],
            "resourceLogs": [{
                "resource": {"attributes": [attribute("organization.id", "r"),
                                            attribute("service.name", "x")]},
                "scopeLogs": [{
                    "scope": {"attributes": [attribute("user.email", "s")]},
                    "logRecords": [{
                        "attributes": [
                            attribute("user.account_uuid", "a"),
                            attribute("event.name", "tool_result"),
                            {"key": "deep", "value": {"kvlistValue": {
                                "values": [attribute("user.account_id", "d"),
                                           attribute("kept.deep", "2")]}}},
                            {"key": "list", "value": {"arrayValue": {
                                "values": [{"stringValue": "file"},
                                           {"kvlistValue": {"values": [
                                               attribute("organization.id", "listed"),
                                               attribute("kept.listed", "3")]}}]}}},
                            attribute("User.email", "kept, the case differs"),
                            attribute("user", "no dot, so kept"),
                            attribute("users.x", "kept"),
                            attribute("organizations", "kept"),
                            {"key": 7, "value": {}},
                            "not an attribute at all",
                        ],
                        "body": {"stringValue": "a tool ran"},
                        "timeUnixNano": "1791339677262000000",
                    }]}]}]}
        status, answer = self.send(json.dumps(body, indent=2).encode("utf-8"))
        self.assertEqual(status, 200, answer)
        [(raw, line)] = self.lines()
        self.assertEqual(line["logs"], without_identity(body))
        for gone in (b'"user.', b'"organization.'):
            self.assertNotIn(gone, raw)
        for kept in (b'"kept.deep"', b'"kept.listed"', b'"User.email"'):
            self.assertIn(kept, raw)
        record = log_records(line["logs"])[0]
        self.assertEqual([a["key"] for a in record["attributes"]
                          if isinstance(a, dict)],
                         ["event.name", "deep", "list", "User.email", "user",
                          "users.x", "organizations", 7])
        self.assertIn("events: 6 identity attribute(s) dropped",
                      self.logged(self.proc, 200))

    def test_a_body_without_identity_is_kept_whole(self):
        body = {"resourceLogs": [], "other": {"attributes": [
            {"key": "a.b", "value": {"intValue": 1}}]},
            "z": [1, "two", None, 3.5, True, {"attributes": "not a list"}]}
        status, _ = self.send(json.dumps(body).encode("utf-8"))
        self.assertEqual(status, 200)
        [(_, line)] = self.lines()
        self.assertEqual(line["logs"], body)
        self.assertIn("events: 0 identity attribute(s) dropped",
                      self.logged(self.proc, 200))

    def test_each_request_is_one_line_in_the_file_of_its_arrival_day(self):
        # The receiver's clock cannot be moved from here, so the day is
        # read from the line: the file a line sits in is named by its own
        # `received`, and that is today, UTC, on this machine.
        days = {datetime.now(timezone.utc).strftime("%Y-%m-%d")}
        for n in (1, 2, 3):
            status, _ = self.send(json.dumps({"n": n}).encode("utf-8"))
            self.assertEqual(status, 200)
        days.add(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        files = self.event_files()
        self.assertEqual(self.stored(), sorted(files + ["token"]))
        self.assertTrue(set(files) <= {f"events-{day}.jsonl" for day in days},
                        files)
        for name in files:
            self.assertTrue(EVENTS_FILE.fullmatch(name), name)
            for raw in (self.data / name).read_bytes().split(b"\n"):
                if raw:
                    day = json.loads(raw)["received"][:10]
                    self.assertEqual(name, f"events-{day}.jsonl")
        self.assertEqual([line["logs"] for _, line in self.lines()],
                         [{"n": 1}, {"n": 2}, {"n": 3}])

    def test_the_answer_is_an_empty_json_object_said_to_be_json(self):
        request = urllib.request.Request(
            self.door, data=b"{}", method="POST",
            headers={"Content-Type": EVENTS})
        with OPENER.open(request, timeout=30) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get("Content-Type"),
                             "application/json")
            self.assertEqual(json.loads(response.read()), {})

    def test_a_body_that_is_not_one_json_object_is_400_and_nothing_is_written(self):
        deep = b"[" * 6000 + b"]" * 6000
        for body in (b"[]", b'[{"a": 1}]', b"1", b'"text"', b"null", b"true",
                     b"\xff\xfe{}", b"{", b"", deep):
            with self.subTest(body=body[:12]):
                status, answer = self.send(body)
                self.assertEqual(status, 400, answer)
                self.assertNotIn(b"Traceback", answer)
        self.assertEqual(self.stored(), ["token"])
        # Still answering, and the first door is unmoved by it.
        status, _ = self.send(b"{}")
        self.assertEqual(status, 200)
        status, _ = post(self.proc.url, deep, "application/json")
        self.assertEqual(status, 400)

    def test_a_number_json_cannot_carry_is_400_at_either_door(self):
        # Python's reader takes NaN, Infinity and a float past its range;
        # JSON has none of them, and a line holding one is a line most
        # line-oriented readers refuse. So the body is refused instead.
        for body in (b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}',
                     b'{"a": 1e400}', b'{"a": [{"attributes": [], "b": NaN}]}'):
            with self.subTest(body=body):
                status, _ = self.send(body)
                self.assertEqual(status, 400)
                status, _ = post(self.proc.url, body, "application/json")
                self.assertEqual(status, 400)
        self.assertEqual(self.stored(), ["token"])

    def test_what_the_door_refuses_by_verb_path_type_and_encoding(self):
        for verb in ("GET", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(verb=verb):
                status, headers, _ = request(verb, self.door)
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "POST")
        for path in (self.token + "/v1/metrics", self.token + "/v1/traces",
                     self.token + "/v1/logs/", self.token + "/v1",
                     self.token + "/V1/LOGS", self.token[:-1] + "/v1/logs",
                     self.token.upper() + "/v1/logs", "v1/logs"):
            with self.subTest(path=path):
                status, _ = post(self.base + path, b"{}", EVENTS)
                self.assertEqual(status, 404)
                status, _, _ = request("GET", self.base + path)
                self.assertEqual(status, 404)
        for kind in ("text/plain", "application/x-ndjson",
                     "application/x-protobuf"):
            with self.subTest(kind=kind):
                status, _ = self.send(b"{}", kind)
                self.assertEqual(status, 415)
        # A body must arrive as it is, at either door.
        for encoding in ("gzip", "deflate", "br"):
            with self.subTest(encoding=encoding):
                status, _ = self.send(b"{}", headers={"Content-Encoding": encoding})
                self.assertEqual(status, 415)
                status, _ = post(self.proc.url, b"{}", "application/json",
                                 {"Content-Encoding": encoding})
                self.assertEqual(status, 415)
        self.assertEqual(self.stored(), ["token"])
        status, _ = self.send(b"{}", headers={"Content-Encoding": "identity"})
        self.assertEqual(status, 200)

    def test_no_length_is_411_and_past_the_cap_is_413_before_a_byte_is_read(self):
        opening = (f"POST /{self.token}/v1/logs HTTP/1.0\r\nHost: receiver\r\n"
                   f"Content-Type: {EVENTS}\r\n")
        answered = raw_request(self.proc.url, (opening + "\r\n").encode())
        self.assertTrue(answered.startswith(b"HTTP/1.0 411 "), answered)
        answered = raw_request(
            self.proc.url,
            (opening + "Content-Length: 1000000000000\r\n\r\n").encode())
        self.assertTrue(answered.startswith(b"HTTP/1.0 413 "), answered)
        self.assertEqual(self.stored(), ["token"])


class DepthTest(ReceiverFixture):
    """At either door a body nested past what the reader takes is 400,
    and so is one nested past what the writer takes (#474; the review
    of #482): the kept line wraps what was posted one level deeper, so
    the writer gives up one level before the reader does, and that one
    depth was a dropped connection with a traceback on the receiver's
    own output, which a holder of the URL could fill by a depth sweep.
    The depth is found here, not assumed: it moves with the interpreter."""

    def setUp(self):
        super().setUp()
        self.proc = self.start()
        self.said = []
        for stream in (self.proc.stdout, self.proc.stderr):
            threading.Thread(target=self.drain, args=(stream,),
                             daemon=True).start()

    def drain(self, stream):
        # Everything the receiver prints, so a sweep of a few hundred
        # requests never fills a pipe nobody reads, and a traceback shows.
        try:
            for line in stream:
                self.said.append(line)
        except (ValueError, OSError):
            pass  # the fixture closed the stream at cleanup

    @staticmethod
    def nested(depth):
        return b'{"a":' + b"[" * depth + b"]" * depth + b"}"

    def status_of(self, url, depth):
        try:
            return post(url, self.nested(depth), "application/json")[0]
        except (urllib.error.URLError, http.client.HTTPException,
                ConnectionError):
            return "dropped"

    def first_refused(self, url, seen):
        """The shallowest depth the door refuses: a coarse step up, then
        every depth of the last step. Every status goes into `seen`."""
        coarse = None
        for depth in range(100, 40001, 100):
            seen[depth] = self.status_of(url, depth)
            if seen[depth] == 400:
                coarse = depth
                break
        self.assertIsNotNone(coarse, "no depth up to 40000 was refused")
        for depth in range(coarse - 99, coarse):
            seen[depth] = self.status_of(url, depth)
            if seen[depth] == 400:
                break
        return min(depth for depth, status in seen.items() if status == 400)

    def test_every_depth_is_answered_200_or_400_at_either_door(self):
        for name, url in (("events", self.proc.url + "/v1/logs"),
                          ("head", self.proc.url)):
            with self.subTest(door=name):
                seen = {}
                first = self.first_refused(url, seen)
                self.assertGreater(first, 100)
                # The few depths below the first refusal land, the few
                # past it are refused, and each the same way every time.
                for depth in range(first - 6, first + 4):
                    for _ in range(3):
                        seen[depth] = self.status_of(url, depth)
                        self.assertEqual(seen[depth],
                                         200 if depth < first else 400, depth)
                self.assertEqual(sorted(set(seen.values())), [200, 400])
        said = "".join(self.said)
        self.assertEqual(said.count("Traceback"), 0,
                         "the receiver printed a traceback")
        self.assertNotIn(self.proc.url.rsplit("/", 1)[1], said)


class VerifyTest(ReceiverFixture):
    """The acceptance test is the recorder's (ADR-0031 ruling 4): the
    receiver's file is a receipt log, and `loxodonta verify --log`
    judges it with no new code."""

    def verify(self):
        return run_recorder("verify", "--log", self.data / CHAIN)

    def test_honest_batches_verify_valid_and_a_regenerated_chain_breaks(self):
        proc = self.start()
        log = self.root / CHAIN
        headers = {"X-Loxodonta-Chain": CHAIN}

        # The genesis batch, from the first entry; the sender's retry of
        # it; then the next batch, from the entry after the last one
        # acknowledged, the way the cursor sends it.
        genesis_batch = make_chain(log, ["step 1"], epoch=1700000000)
        self.assertEqual(post(proc.url, genesis_batch, NDJSON, headers)[0], 200)
        self.assertEqual(post(proc.url, genesis_batch, NDJSON, headers)[0], 200)
        for action in ("step 2", "step 3"):
            run_recorder("log", "--log", log, "--actor", "claude-code",
                         "--action", action, epoch=1700000000)
        next_batch = b"".join(log.read_bytes().splitlines(True)[2:])
        self.assertEqual(post(proc.url, next_batch, NDJSON, headers)[0], 200)

        judged = self.verify()
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertEqual(judged.stdout.strip(), "VALID")
        self.assertEqual((self.data / CHAIN).read_bytes(), log.read_bytes())

        # A regenerated chain, the writer's rewrite of history, sent after
        # the original: it lands beside the entries it replaced, and the
        # walk breaks at the first entry that differs.
        regenerated = make_chain(self.root / "again.jsonl", ["step 1", "step 2"],
                                 epoch=1700009999)
        self.assertEqual(post(proc.url, regenerated, NDJSON, headers)[0], 200)

        judged = self.verify()
        self.assertEqual(judged.returncode, 1, judged.stdout + judged.stderr)
        self.assertTrue(judged.stdout.startswith("BROKEN at entry 4"),
                        judged.stdout)
        self.assertNotIn("VALID", judged.stdout)


class AddressTest(ReceiverFixture):
    """Where it listens, and in what: all interfaces by default, since the
    sender is another machine; plain HTTP until given a pair, said out
    loud so command lines never cross a network in the clear unknowingly."""

    def test_without_a_pair_the_startup_line_names_plain_http(self):
        proc = self.start()
        self.assertIn("plain HTTP", proc.said)
        self.assertTrue(proc.url.startswith("http://127.0.0.1:"), proc.url)

    def test_the_default_is_all_interfaces_and_bind_narrows_it(self):
        everywhere = self.start(bind=None)
        self.assertIn("all interfaces", everywhere.said)
        # Whatever name it printed for this machine, the loopback address
        # is one of the interfaces it took.
        port = urllib.parse.urlsplit(everywhere.url).port
        token = everywhere.url.rsplit("/", 1)[1]
        status, _ = post(f"http://127.0.0.1:{port}/{token}", b"{}",
                         "application/json")
        self.assertEqual(status, 200)
        self.stop(everywhere)

        narrowed = self.start(bind="127.0.0.1")
        self.assertIn("127.0.0.1", narrowed.said)
        self.assertIn("this address only", narrowed.said)

    def test_cert_without_key_is_a_usage_error(self):
        for flags in (("--cert", "x.pem"), ("--key", "x.pem")):
            with self.subTest(flags=flags):
                done = subprocess.run(
                    [sys.executable, str(RECEIVER), "serve", "--data",
                     str(self.data), "--port", "0", *flags],
                    capture_output=True, encoding="utf-8", env=clean_env())
                self.assertEqual(done.returncode, 64, done.stderr)
                self.assertIn("--cert", done.stderr)
                self.assertIn("--key", done.stderr)


def drip(url, opening, byte, bound, stop=None):
    """Send `opening`, then `byte` every quarter second: the slow sender
    of #300. Returns (seconds until the receiver closed the connection,
    what it sent back), or (None, what it sent back) when it was still
    open after `bound` seconds or when `stop` was set."""
    parts = urllib.parse.urlsplit(url)
    answered = b""
    with socket.create_connection((parts.hostname, parts.port),
                                  timeout=10) as sock:
        sock.sendall(opening)
        started = time.monotonic()
        sock.settimeout(0.25)  # the wait for an answer is the pause
        while time.monotonic() - started < bound:
            if stop is not None and stop.is_set():
                break
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    return time.monotonic() - started, answered
                answered += chunk
            except socket.timeout:
                pass
            except ConnectionError:
                return time.monotonic() - started, answered
            try:
                sock.sendall(byte)
            except ConnectionError:
                return time.monotonic() - started, answered
    return None, answered


class DeadlineTest(ReceiverFixture):
    """A request is due whole, headers and body, within a deadline of its
    own, and a slow one holds only its own connection: one byte every
    1.5 seconds used to hold the door against every honest sender (#300)."""

    @staticmethod
    def openings(url):
        token = url.rsplit("/", 1)[1]
        return (
            # Stalled in the headers: a header line that never ends.
            ("headers", ("POST /%s HTTP/1.0\r\nX-Slow: " % token).encode(),
             b"a"),
            # Stalled in the body: every header sent, the body trickling.
            ("body", ("POST /%s HTTP/1.0\r\nHost: receiver\r\n"
                      "Content-Type: application/x-ndjson\r\n"
                      "X-Loxodonta-Chain: %s\r\n"
                      "Content-Length: 100000\r\n\r\n" % (token, CHAIN)
                      ).encode(),
             b"x"),
        )

    def test_a_request_that_misses_its_deadline_is_dropped(self):
        # Each byte arrives well inside the per-receive timeout, so only
        # a deadline on the whole request can end it. Two seconds, and
        # ten times that before the test calls the door held.
        proc = self.start(env={"RECEIVER_DEADLINE_SECONDS": "2"})
        for phase, opening, byte in self.openings(proc.url):
            with self.subTest(phase=phase):
                closed_after, answered = drip(proc.url, opening, byte, 20)
                self.assertIsNotNone(closed_after, "the connection was held")
                self.assertEqual(answered, b"")  # dropped, not answered
        self.assertEqual(self.stored(), ["token"])

    def test_a_slow_sender_does_not_hold_the_door_for_another(self):
        # The default deadline, far longer than this test: the slow
        # sender is still trickling when the honest head goes, and the
        # head must land anyway, well inside its ten seconds.
        proc = self.start()
        _, opening, byte = self.openings(proc.url)[1]
        stop = threading.Event()
        slow = threading.Thread(
            target=drip, args=(proc.url, opening, byte, 30, stop), daemon=True)
        slow.start()
        self.addCleanup(slow.join, 30)
        self.addCleanup(stop.set)
        time.sleep(0.5)  # the slow sender is in first

        head = json.dumps({"head": "e" * 64, "n": 5}).encode("utf-8")
        started = time.monotonic()
        try:
            status, _ = post(proc.url, head, "application/json", timeout=10)
        except (urllib.error.URLError, socket.timeout) as held:
            self.fail(f"the honest head waited behind the slow sender: {held}")
        self.assertEqual(status, 200)
        self.assertLess(time.monotonic() - started, 10)
        self.assertTrue(slow.is_alive(), "the slow sender stopped trickling")
        self.assertEqual(self.stored(), ["heads.jsonl", "token"])


def filler(first, count):
    """`count` lines shaped like entries from n=`first`, about 1.1 KB
    each: enough of them to reach a cap. Shape is all the receiver
    judges, so they need not be a chain."""
    return b"".join(
        json.dumps({"n": n, "entry_hash": "%064x" % n, "pad": "x" * 1000}
                   ).encode("utf-8") + b"\n"
        for n in range(first, first + count))


class CapTest(ReceiverFixture):
    """A cap on each file the receiver keeps and on all of them together,
    so a writer holding the URL cannot fill the disk under honest sends
    (#300). Past a cap is 507, and what is stored is never touched."""

    def send(self, proc, body, name=CHAIN):
        return post(proc.url, body, NDJSON, {"X-Loxodonta-Chain": name})

    def test_a_batch_past_the_file_cap_is_507_and_the_file_is_untouched(self):
        proc = self.start("--file-cap", "1")
        first = filler(0, 600)                        # about 0.63 MiB
        status, _ = self.send(proc, first)
        self.assertEqual(status, 200)
        self.logged(proc, 200)
        kept = (self.data / CHAIN).read_bytes()

        status, answer = self.send(proc, filler(600, 600))
        self.assertEqual(status, 507, answer)
        self.assertIn(b"file cap", answer)
        self.assertIn(b"1 MiB", answer)
        self.assertEqual(answer.count(b"\n"), 1)     # one line
        self.assertIn("file cap", self.logged(proc, 507))
        self.assertEqual((self.data / CHAIN).read_bytes(), kept)

        # A resend of what the file holds adds nothing, so it is never
        # refused: the sender's retry still gets its 2xx.
        status, answer = self.send(proc, first)
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(answer), {"appended": 0, "dropped": 600})

        # Another chain has a cap of its own.
        status, _ = self.send(proc, filler(600, 600), "receipts-other.jsonl")
        self.assertEqual(status, 200)
        self.assertEqual((self.data / CHAIN).read_bytes(), kept)

    def test_a_batch_past_the_total_cap_is_507_and_nothing_is_touched(self):
        proc = self.start("--file-cap", "1", "--total-cap", "2")
        for name in ("receipts-a.jsonl", "receipts-b.jsonl", "receipts-c.jsonl"):
            status, _ = self.send(proc, filler(0, 600), name)  # 1.9 MiB in all
            self.assertEqual(status, 200)
        before = {name: (self.data / name).read_bytes() for name in self.stored()}

        status, answer = self.send(proc, filler(0, 600), "receipts-d.jsonl")
        self.assertEqual(status, 507, answer)
        self.assertIn(b"total cap", answer)
        self.assertIn(b"2 MiB", answer)
        self.assertIn("total cap", self.logged(proc, 507))
        self.assertEqual(
            {name: (self.data / name).read_bytes() for name in self.stored()},
            before)

    def test_an_events_line_past_a_cap_is_507_and_nothing_is_touched(self):
        # The second door's lines live under the same caps as the chain
        # files (ADR-0041 ruling 2): the file cap on the day file, and
        # the total cap counted over chain files and events files alike.
        proc = self.start("--file-cap", "1", "--total-cap", "2")
        door = proc.url + "/v1/logs"
        body = json.dumps({"pad": "x" * (600 * 1024)}).encode()  # about 0.59 MiB
        status, _ = post(door, body, "application/json")
        self.assertEqual(status, 200)
        self.logged(proc, 200)
        kept = {name: (self.data / name).read_bytes() for name in self.stored()}

        status, answer = post(door, body, "application/json")
        self.assertEqual(status, 507, answer)
        self.assertIn(b"file cap", answer)
        self.assertIn("file cap", self.logged(proc, 507))
        self.assertEqual(
            {name: (self.data / name).read_bytes() for name in self.stored()},
            kept)

        for name in ("receipts-a.jsonl", "receipts-b.jsonl"):  # 1.85 MiB in all
            status, _ = self.send(proc, filler(0, 600), name)
            self.assertEqual(status, 200)
        kept = {name: (self.data / name).read_bytes() for name in self.stored()}
        small = json.dumps({"pad": "x" * (200 * 1024)}).encode()
        status, answer = post(door, small, "application/json")
        self.assertEqual(status, 507, answer)
        self.assertIn(b"total cap", answer)
        self.assertEqual(
            {name: (self.data / name).read_bytes() for name in self.stored()},
            kept)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not look into")
    def test_a_link_the_count_cannot_follow_refuses_the_write(self):
        # The kept size is what the receiver can read: a link into a
        # folder closed to it is a write refused by name, never bytes
        # left out of the count unsaid (#421). A link to nowhere keeps
        # nothing.
        proc = self.start()
        closed = self.root / "closed"
        closed.mkdir()
        (closed / "held.jsonl").write_bytes(b"x\n")
        try:
            os.symlink(str(self.root / "nowhere"), str(self.data / "gone"))
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlinks cannot be created here")
        status, answer = self.send(proc, filler(0, 1))
        self.assertEqual(status, 200, answer)

        os.symlink(str(closed / "held.jsonl"), str(self.data / "held"))
        os.chmod(closed, 0)
        self.addCleanup(os.chmod, closed, 0o755)
        status, answer = self.send(proc, filler(1, 1))

        self.assertEqual(status, 500, answer)
        self.assertIn(b"could not write: ", answer)

    def test_a_cap_that_is_not_a_whole_number_of_mebibytes_is_a_usage_error(self):
        for flag in ("--file-cap", "--total-cap"):
            for value in ("0", "-1", "1.5", "lots"):
                with self.subTest(flag=flag, value=value):
                    done = subprocess.run(
                        [sys.executable, str(RECEIVER), "serve", "--data",
                         str(self.data), "--port", "0", flag, value],
                        capture_output=True, encoding="utf-8", env=clean_env())
                    self.assertEqual(done.returncode, 64, done.stderr)
                    self.assertIn(flag, done.stderr)
                    self.assertIn("MiB", done.stderr)


@unittest.skipUnless(shutil.which("openssl"),
                     "openssl is not on PATH; the stdlib cannot mint a "
                     "certificate, so the TLS test has no pair to serve")
class TlsTest(ReceiverFixture):
    """`--cert` and `--key`: TLS through the stdlib's ssl module, from a
    pair the operator supplies. The test's pair is self-signed and
    minted by openssl, the one tool the suite already leans on."""

    def setUp(self):
        super().setUp()
        self.cert = self.root / "cert.pem"
        self.key = self.root / "key.pem"
        minted = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.key), "-out", str(self.cert),
             "-subj", "/CN=localhost", "-days", "2"],
            capture_output=True, encoding="utf-8")
        self.assertEqual(minted.returncode, 0, minted.stderr)

    def trusting_opener(self):
        """A client that trusts exactly the test's certificate. The
        hostname check is off because the pair names localhost and the
        test speaks to 127.0.0.1; the chain check stays on."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(self.cert))
        context.check_hostname = False
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context))

    def test_cert_and_key_serve_tls_and_plain_http_is_refused(self):
        proc = self.start("--cert", str(self.cert), "--key", str(self.key))
        self.assertIn("TLS", proc.said)
        self.assertNotIn("plain HTTP", proc.said)
        self.assertTrue(proc.url.startswith("https://127.0.0.1:"), proc.url)

        head = json.dumps({"head": "c" * 64, "n": 3}).encode("utf-8")
        request = urllib.request.Request(
            proc.url, data=head, method="POST",
            headers={"Content-Type": "application/json"})
        with self.trusting_opener().open(request, timeout=30) as response:
            self.assertEqual(response.status, 200)
        self.assertIn("heads.jsonl", self.stored())

        # The same port spoken to in the clear gets no answer worth having.
        with self.assertRaises((urllib.error.URLError, ConnectionError,
                                http.client.HTTPException)):
            post("http" + proc.url[len("https"):], head, "application/json")

    def test_an_idle_connection_does_not_hold_the_door(self):
        # A stranger that connects and sends nothing: the handshake it
        # never starts must be bounded by the door's timeout, or one idle
        # socket stops every honest sender behind it for as long as it
        # likes. The timeout is shortened through the suite's handle.
        proc = self.start("--cert", str(self.cert), "--key", str(self.key),
                          env={"RECEIVER_TIMEOUT_SECONDS": "5"})
        parts = urllib.parse.urlsplit(proc.url)
        idle = socket.create_connection((parts.hostname, parts.port))
        self.addCleanup(idle.close)

        head = json.dumps({"head": "d" * 64, "n": 4}).encode("utf-8")
        request = urllib.request.Request(
            proc.url, data=head, method="POST",
            headers={"Content-Type": "application/json"})
        started = time.monotonic()
        with self.trusting_opener().open(request, timeout=30) as response:
            self.assertEqual(response.status, 200)
        self.assertLess(time.monotonic() - started, 15)
        self.assertIn("heads.jsonl", self.stored())


if __name__ == "__main__":
    unittest.main()
