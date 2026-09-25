"""A sidecar row is read as strictly as an entry and a manifest (#365).

Python's JSON reader takes a line that a strict parser refuses: a key
given twice, which it reads as the last of the two, and `NaN`,
`Infinity` and `-Infinity`, which it reads as numbers. A row one reader
judges and another cannot read says two things, so each of these makes
the line unreadable, before its kind is read. The walk and the manifest
already refuse a key given twice (SPEC section 6 step 1, section 10.2).
And a proof is its timestamp tree and nothing after it: bytes past the
tree's end are ANCHOR-INVALID, named (SPEC section 9.5).

Every test drives the public CLI.
"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_sidecar_strictness`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import (FakeCalendar, FakeCalendarHandler,  # noqa: E402
                         clean_env)
from test_supervisor import (chains_by_session, home_outside,  # noqa: E402
                             isolated_env, make_chain, run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
NOT_A_RECORD = ("ANCHOR-INVALID: sidecar line is not a record — evidence "
                "that does not verify is not evidence")
NOT_A_STAMP = ("STAMP-INVALID: sidecar line is not a stamp record — "
               "evidence that does not verify is not evidence")
WORDS = ("NaN", "Infinity", "-Infinity")


def run_receipts(*args, cwd):
    return subprocess.run([sys.executable, str(LOXODONTA), *args], cwd=cwd,
                          capture_output=True, encoding="utf-8",
                          env=clean_env())


def start_calendar(case):
    """The fake calendar, answering pending, closed when `case` ends."""
    server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
    server.nonce = b"fake-nonce"
    server.prefix = b"left-branch"
    server.suffix = b"right-branch"
    server.height = 850000
    server.mode = "pending"
    server.submitted = []
    server.polled = []
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class PostTaker(FakeCalendarHandler):
    """A remote that takes every POST."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def serve_posts(case):
    """A remote that takes every POST, closed when `case` ends."""
    server = FakeCalendar(("127.0.0.1", 0), PostTaker)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


def completed_proof():
    """One sha256, then a Bitcoin attestation: a proof that replays
    offline to a claimed block (docs/ANCHORING.md section 4)."""
    return (b"\x08" + b"\x00" + TAG_BITCOIN + b"\x03" + b"\xd0\xf0\x33")


def row_line(**fields):
    """A row as the recorder writes one: keys sorted, compact."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def anchor_line(head, proof=None):
    proof = completed_proof() if proof is None else proof
    return row_line(kind="anchor", head=head, n=1,
                    ts="2026-09-25T10:00:00Z",
                    calendar="https://calendar.example.test",
                    proof=base64.b64encode(proof).decode("ascii"))


def with_member(line, member):
    """`line`, a JSON object, with `member` written in after its last
    member, as raw text: the spellings json.dumps will not write."""
    return line[:-1] + "," + member + "}"


class StrictRowTest(unittest.TestCase):
    """`verify --anchors` and `verify --stamps` on a row a strict JSON
    parser cannot read: exit 3, as any unreadable line is (SPEC 9.2)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        self.head = run_receipts("head", cwd=self.workdir).stdout.strip()
        self.anchors = self.workdir / "receipts.jsonl.anchors.jsonl"
        self.stamps = self.workdir / "receipts.jsonl.stamps.jsonl"

    def verify(self, flag, line):
        sidecar = self.anchors if flag == "--anchors" else self.stamps
        sidecar.write_text(line + "\n", encoding="utf-8")
        return run_receipts("verify", flag, cwd=self.workdir)

    def test_a_key_given_twice_makes_an_anchor_row_unreadable(self):
        # A first-wins reader sees a proof of another head (a mismatch),
        # a last-wins reader a proof of this one (ANCHORED): no reading
        # of the row is the row, so it is none.
        other = "ab" * 32
        good = anchor_line(self.head)
        for first, last in ((other, self.head), (self.head, other)):
            with self.subTest(first=first[:4]):
                line = good.replace(f'"head":"{self.head}"',
                                    f'"head":"{first}","head":"{last}"')

                result = self.verify("--anchors", line)

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip().splitlines(),
                                 [NOT_A_RECORD])

    def test_a_key_given_twice_is_unreadable_before_its_kind_is_read(self):
        line = row_line(kind="witness-note", ts="2026-09-25T10:00:00Z")
        line = line.replace('"kind":"witness-note"',
                            '"kind":"witness-note","kind":"anchor"')

        result = self.verify("--anchors", line)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip().splitlines(), [NOT_A_RECORD])

    def test_a_key_given_twice_makes_a_stamp_row_unreadable(self):
        line = row_line(kind="stamp", head=self.head, n=1,
                        ts="2026-09-25T10:00:00Z",
                        authority="https://authority.example/tsr",
                        response=base64.b64encode(b"token").decode("ascii"))
        line = line.replace('"n":1', '"n":1,"n":2')

        result = self.verify("--stamps", line)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip().splitlines(), [NOT_A_STAMP])

    def test_nan_and_infinity_make_a_row_unreadable(self):
        for word in WORDS:
            with self.subTest(word=word):
                line = with_member(anchor_line(self.head), f'"x":{word}')

                result = self.verify("--anchors", line)

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip().splitlines(),
                                 [NOT_A_RECORD])
                self.assertNotIn("ANCHORED", result.stdout)

    def test_nan_and_infinity_make_a_stamp_row_unreadable(self):
        for word in WORDS:
            with self.subTest(word=word):
                line = row_line(kind="stamp", head=self.head,
                                ts="2026-09-25T10:00:00Z",
                                authority="https://authority.example/tsr",
                                response=base64.b64encode(b"token")
                                .decode("ascii"))
                line = with_member(line, f'"n":{word}')

                result = self.verify("--stamps", line)

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip().splitlines(),
                                 [NOT_A_STAMP])

    def test_a_proof_with_bytes_after_its_tree_is_anchor_invalid(self):
        for tail in (b"\x00", b"\x08\x08\x08"):
            with self.subTest(tail=tail.hex()):
                line = anchor_line(self.head, completed_proof() + tail)

                result = self.verify("--anchors", line)

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip().splitlines(),
                                 ["ANCHOR-INVALID: proof holds bytes after "
                                  "its timestamp tree — evidence that does "
                                  "not verify is not evidence"])

    def test_the_same_proof_without_the_tail_is_anchored(self):
        # The control: the bytes after the tree are the whole difference.
        result = self.verify("--anchors", anchor_line(self.head))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("ANCHORED: entries 0..1"),
                        result.stdout)


class StrictReadersTest(unittest.TestCase):
    """The recorder's writing paths and the supervisor read rows by the
    same rule the judges do, so a row they could not read is never a
    head anchored or a batch sent."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

    def test_the_keeper_anchors_a_head_only_a_twice_keyed_row_names(self):
        calendar = start_calendar(self)
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        head = run_receipts("head", "--log", str(log),
                            cwd=self.root).stdout.strip()
        line = anchor_line(head).replace('"n":1', '"n":1,"n":2')
        Path(str(log) + ".anchors.jsonl").write_text(line + "\n",
                                                     encoding="utf-8")

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=self.env)

        self.assertNotIn("Traceback", result.stderr)
        (chain,) = chains_by_session(json.loads(result.stdout))[
            ("alpha", "sess-aaaa")]
        # The row is still judged, beside the pending proof the keeper
        # just added: invalid evidence, exit 3, and no anchor.
        self.assertIn(NOT_A_RECORD, chain["detail"])
        self.assertEqual(chain["exit"], 3)
        self.assertFalse(chain["anchored"])
        self.assertEqual(calendar.submitted, [bytes.fromhex(head)])

    def test_a_chain_row_the_reader_cannot_read_moves_no_cursor(self):
        remote = serve_posts(self)
        url = f"http://127.0.0.1:{remote.server_address[1]}/chain"
        workdir = self.root / "work"
        workdir.mkdir()
        run_receipts("init", cwd=workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=workdir)
        head = run_receipts("head", cwd=workdir).stdout.strip()
        remote_id = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        memo = workdir / "receipts.jsonl.published.jsonl"
        acknowledged = row_line(kind="chain", first=0, last=1, head=head,
                                ts="2026-09-25T10:00:00Z",
                                event="cadence", remote_id=remote_id)
        memo.write_text(acknowledged + "\n", encoding="utf-8")
        nothing = run_receipts("publish", "--chain", url, cwd=workdir)
        self.assertIn("nothing to send", nothing.stdout)
        for spoiled in (acknowledged.replace('"last":1', '"last":1,"last":1'),
                        with_member(acknowledged, '"x":NaN')):
            with self.subTest(line=spoiled[-12:]):
                memo.write_text(spoiled + "\n", encoding="utf-8")

                result = run_receipts("publish", "--chain", url, cwd=workdir)

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn("published chain entries 0-1", result.stdout)


if __name__ == "__main__":
    unittest.main()
