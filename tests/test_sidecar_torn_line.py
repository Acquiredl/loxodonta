"""A row appended after a sidecar's torn last line (#610).

A crash or a full disk can leave a sidecar (the anchors, the stamps, the
publish memo) ending in a partial line with no line end. The next row
starts on a line of its own, so only the torn line is unreadable: it
stays as it lies, the evidence of the tear, and every reader reads the
new row as it would beside any other line it cannot read. Before, the
row was glued onto the torn line and the two were one line nobody could
read.

Each test tears one sidecar, runs a verb that appends a row to it, and
reads the row back through the verb that reads that sidecar: `anchor`
and `stamp` find the head they hold, `publish --chain` finds its cursor,
and the supervisor's scan finds the head that left and the step that
failed. Every test drives the public CLI, against the fake calendar,
authority and remote the other suites use. No network, no internals.
"""

import json
import sys
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_sidecar_torn_line`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import (LOXODONTA, StoreCase, isolated_env, run,  # noqa: E402
                     temp_folder)

from test_anchor import start_calendar  # noqa: E402
from test_sidecar_strictness import serve_posts  # noqa: E402
from test_stamp import start_authority  # noqa: E402
from test_supervisor import (chains_by_session, make_chain,  # noqa: E402
                             run_scan)


# The first bytes of a row as the recorder writes one, cut off where a
# crash would cut it: no closing brace, no line end.
TORN = b'{"calendar":"https://calendar.example.test","head":"ab12'
# Nothing listens on the discard port, so a POST there is refused.
CLOSED = "http://127.0.0.1:9"


def tear(path):
    """`path` holding one torn line and nothing after it."""
    path.write_bytes(TORN)


def rows_after_the_tear(case, sidecar):
    """The kinds of the rows after `sidecar`'s first line, which must be
    the torn line, left as it lies, each row whole on a line of its
    own."""
    torn, *rows, end = sidecar.read_bytes().split(b"\n")
    case.assertEqual(torn, TORN, "the torn line is left as it lies")
    case.assertEqual(end, b"")
    return [json.loads(row)["kind"] for row in rows]


class TornSidecarTest(StoreCase):
    """`anchor`, `stamp` and `publish --chain` on a sidecar whose last
    line is torn: the row each writes starts on a line of its own, the
    torn line stays byte for byte, and the verb run again reads the row
    and has nothing to do."""

    def setUp(self):
        super().setUp()
        run(LOXODONTA, "log", "--actor", "agent", "--action", "step 1",
            cwd=self.workdir)
        self.head = run(LOXODONTA, "head", cwd=self.workdir).stdout.strip()

    def sidecar(self, suffix):
        return self.workdir / ("receipts.jsonl" + suffix)

    def test_an_anchor_row_after_a_torn_line_is_read_back(self):
        calendar = start_calendar(self, b"fake-nonce")
        sidecar = self.sidecar(".anchors.jsonl")
        tear(sidecar)

        first = run(LOXODONTA, "anchor", "--calendar", calendar.url,
                    cwd=self.workdir)
        again = run(LOXODONTA, "anchor", "--calendar", calendar.url,
                    cwd=self.workdir)

        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(rows_after_the_tear(self, sidecar), ["anchor"])
        self.assertEqual((again.returncode, again.stdout.strip()),
                         (0, f"already anchored head {self.head[:12]}… "
                             "(entry 1)"), again.stderr)
        self.assertEqual(len(calendar.submitted), 1)

    def test_verify_names_the_torn_line_and_judges_the_row_after_it(self):
        # The reader is unchanged: the torn line is one line it cannot
        # read, named by its number, and the row after it is judged.
        calendar = start_calendar(self, b"fake-nonce")
        tear(self.sidecar(".anchors.jsonl"))
        run(LOXODONTA, "anchor", "--calendar", calendar.url, cwd=self.workdir)

        result = run(LOXODONTA, "verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ANCHOR-INVALID: line 1 of receipts.jsonl.anchors.jsonl "
                      "is not a record", result.stdout)
        self.assertNotIn("line 2 of", result.stdout)
        self.assertIn("ANCHOR-PENDING", result.stdout)

    def test_a_stamp_row_after_a_torn_line_is_read_back(self):
        authority = start_authority(self)
        sidecar = self.sidecar(".stamps.jsonl")
        tear(sidecar)

        first = run(LOXODONTA, "stamp", "--authority", authority.url,
                    cwd=self.workdir)
        again = run(LOXODONTA, "stamp", "--authority", authority.url,
                    cwd=self.workdir)

        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("stamp", rows_after_the_tear(self, sidecar))
        self.assertEqual((again.returncode, again.stdout.strip()),
                         (0, f"already stamped head {self.head[:12]}… "
                             "(entry 1)"), again.stderr)
        self.assertEqual(len(authority.received), 1)

    def test_a_chain_row_after_a_torn_line_moves_the_cursor(self):
        remote = serve_posts(self)
        url = f"http://127.0.0.1:{remote.server_address[1]}/chain"
        sidecar = self.sidecar(".published.jsonl")
        tear(sidecar)

        first = run(LOXODONTA, "publish", "--chain", url, cwd=self.workdir)
        again = run(LOXODONTA, "publish", "--chain", url, cwd=self.workdir)

        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("published chain entries 0-1", first.stdout)
        self.assertIn("chain", rows_after_the_tear(self, sidecar))
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn("nothing to send", again.stdout)


class TornMemoScannedTest(unittest.TestCase):
    """`publish` on a memo whose last line is torn, read back by the
    supervisor's scan: the head row it writes for a head the remote
    took is the chain's departure, and the attempt row it writes for a
    head it could not send is the chain's last failed step."""

    def setUp(self):
        self.root = temp_folder(self)
        self.env = isolated_env(temp_folder(self))
        self.log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.memo = Path(str(self.log) + ".published.jsonl")
        tear(self.memo)

    def publish(self, url):
        return run(LOXODONTA, "publish", "--log", str(self.log), url,
                   cwd=self.root, env=self.env)

    def scanned(self):
        result = run_scan(self.root, env=self.env)
        self.assertNotIn("Traceback", result.stderr)
        (chain,) = chains_by_session(json.loads(result.stdout))[
            ("alpha", "sess-aaaa")]
        return chain

    def test_a_head_row_after_a_torn_line_is_the_departure(self):
        remote = serve_posts(self)

        sent = self.publish(f"http://127.0.0.1:{remote.server_address[1]}/hook")

        self.assertEqual(sent.returncode, 0, sent.stdout + sent.stderr)
        self.assertIn("head", rows_after_the_tear(self, self.memo))
        self.assertEqual(self.scanned()["left"]["via"], "published")

    def test_an_attempt_row_after_a_torn_line_is_the_last_failed_step(self):
        refused = self.publish(CLOSED)

        self.assertEqual(refused.returncode, 69,
                         refused.stdout + refused.stderr)
        self.assertEqual(rows_after_the_tear(self, self.memo), ["attempt"])
        self.assertEqual(self.scanned()["last_failed"]["step"],
                         "publish-head")


if __name__ == "__main__":
    unittest.main()
