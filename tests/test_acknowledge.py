"""Behavioral tests for a baseline that keeps what it remembered (#401),
a baseline the scan cannot read or keep (#409, its first half), and
`supervisor acknowledge`, the one act that moves the memory past either
(ADR-0039).

A remembered chain that reads `regressed`, `rewritten` or `vanished`
keeps the head and the number the baseline remembered, and says so on
every look, exit 5, until the chain holds that head again or the
operator accepts what is there by name. A baseline that cannot be read,
or one missing beside a day book that records a scan, is reported on
every look, exit 5, and left as it lies until `acknowledge --baseline`
starts the memory afresh. Everything is driven through the public CLI,
against chains the recorder wrote, and every process a test starts is
bounded, so a regression fails and never hangs.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_acknowledge`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar
from test_supervisor import (BASELINE_NAME, FakeCalendarHandler, ago,
                             home_outside, isolated_env, write_pending_anchor)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

BOUND = 180  # seconds any one process may take before the test fails
SESSION = "sess-aaaa"
LOG = f"alpha/receipts/receipts-{SESSION}.jsonl"
NO_VERDICT_MOVED = "moves no verdict"


class LegacyRoot(unittest.TestCase):
    """A legacy folder of repos (`--root`), one chain of five entries in
    it (genesis and four receipts, n 0 to 4), and a home of the test's
    own outside it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.env = {**isolated_env(home_outside(self)),
                    "PYTHONIOENCODING": "utf-8"}
        self.baseline = self.root / BASELINE_NAME
        self.log = self.root / LOG
        self.log.parent.mkdir(parents=True)
        self.recorder("init", "--log", str(self.log))
        self.logged(*(f"step {i}" for i in range(4)))

    # --- the recorder and the supervisor, bounded ---------------------------

    def recorder(self, *args):
        return subprocess.run(
            [sys.executable, str(LOXODONTA), *args], capture_output=True,
            encoding="utf-8", timeout=BOUND, env=self.env, check=True)

    def logged(self, *actions, log=None):
        for action in actions:
            self.recorder("log", "--log", str(log or self.log),
                          "--actor", "claude-code", "--action", action)

    def supervisor(self, *args):
        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), *args], capture_output=True,
            encoding="utf-8", timeout=BOUND, env=self.env)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def look(self, expect):
        """One `scan --root --json`, its exit held to `expect`."""
        result = self.supervisor("scan", "--root", str(self.root), "--json")
        self.assertEqual(result.returncode, expect,
                         result.stdout + result.stderr)
        return json.loads(result.stdout)

    def acknowledge(self, *args, expect=0):
        result = self.supervisor("acknowledge", *args,
                                 "--root", str(self.root))
        self.assertEqual(result.returncode, expect,
                         result.stdout + result.stderr)
        return result

    # --- what is on disk ----------------------------------------------------

    def head(self):
        """(n, head) of the chain as it stands."""
        last = json.loads(self.log.read_text(encoding="utf-8")
                          .splitlines()[-1])
        return last["n"], last["entry_hash"]

    def remembered(self):
        return json.loads(self.baseline.read_text(encoding="utf-8"))[
            "chains"].get(LOG)

    def cut(self):
        """The chain one entry shorter, still VALID; the line cut off."""
        lines = self.log.read_bytes().splitlines(keepends=True)
        self.log.write_bytes(b"".join(lines[:-1]))
        return lines[-1]

    def regenerate(self, entries):
        """A new history at the chain's name: `entries` entries, genesis
        included, none of them the old ones."""
        if self.log.exists():
            self.log.unlink()
        self.recorder("init", "--log", str(self.log))
        self.logged(*(f"other work {i}" for i in range(entries - 1)))

    def events(self, report):
        return [(event["log"], event["change"])
                for event in report["baseline"]["events"]]


class StandingAlarmTest(LegacyRoot):
    """The baseline keeps what it remembered (#401 ruling, parts 1 and
    2): the six cases the ruling's brief lays out, each from a chain of
    five entries remembered by a first look."""

    def test_a_chain_cut_short_regresses_on_every_look_from_one_since(self):
        self.look(0)
        n, head = self.head()
        self.cut()
        found = self.head()

        second = self.look(5)
        third = self.look(5)

        for report in (second, third):
            (event,) = report["baseline"]["events"]
            self.assertEqual((event["log"], event["change"]),
                             (LOG, "regressed"))
            self.assertEqual(event["remembered"], {"n": n, "head": head})
            self.assertEqual(event["found"],
                             {"n": found[0], "head": found[1]})
        since = second["baseline"]["events"][0]["since"]
        self.assertEqual(since, second["scanned"])
        self.assertEqual(third["baseline"]["events"][0]["since"], since,
                         "a later look keeps the time the alarm began")
        row = self.remembered()
        self.assertEqual((row["n"], row["head"]), (n, head),
                         "the baseline kept what it remembered")
        self.assertEqual(row["alarm"], {"change": "regressed",
                                        "since": since})

    def test_a_regenerated_chain_reads_rewritten_on_every_look(self):
        self.look(0)
        self.regenerate(6)

        for _ in range(2):
            report = self.look(5)
            self.assertEqual(self.events(report), [(LOG, "rewritten")])
        (chain,) = report["repos"][0]["sessions"][0]["chains"]
        self.assertEqual(chain["verdict"], "VALID",
                         "the verdict machinery sees nothing; the memory "
                         "is what notices")

    def test_a_deleted_chain_vanishes_on_every_look(self):
        self.look(0)
        n, head = self.head()
        self.log.unlink()

        for _ in range(2):
            report = self.look(5)
            (event,) = report["baseline"]["events"]
            self.assertEqual(event["change"], "vanished")
            self.assertEqual(event["remembered"], {"n": n, "head": head})
            self.assertIsNone(event["found"])
        self.assertEqual(self.remembered()["head"], head,
                         "a vanished chain is not forgotten")

    def test_a_shorter_chain_put_back_where_one_vanished_reads_regressed(self):
        # The hole the ruling closes: put back after one look at the gap,
        # a shorter chain used to read as a new one, exit 0.
        self.look(0)
        self.log.unlink()
        gone = self.look(5)
        self.regenerate(3)

        back = self.look(5)

        self.assertEqual(self.events(back), [(LOG, "regressed")])
        self.assertEqual(back["baseline"]["events"][0]["since"],
                         gone["baseline"]["events"][0]["since"],
                         "what is found changes; when the alarm began "
                         "does not")
        self.assertEqual(self.remembered()["alarm"]["change"], "regressed")

    def test_a_cut_chain_mended_and_grown_clears_and_the_row_follows(self):
        self.look(0)
        tail = self.cut()
        self.look(5)
        with open(self.log, "ab") as chain:
            chain.write(tail)
        self.logged("one more step")

        clean = self.look(0)

        self.assertEqual(clean["baseline"]["events"], [])
        n, head = self.head()
        row = self.remembered()
        self.assertEqual((row["n"], row["head"]), (n, head),
                         "once appends explain everything the row "
                         "follows the chain")
        self.assertNotIn("alarm", row)

    def test_a_longer_regenerated_chain_stays_rewritten_as_it_grows(self):
        # Growth never clears anything by length alone: the entry at the
        # remembered number must still hash to the remembered head.
        self.look(0)
        self.regenerate(9)
        self.look(5)
        self.logged("one more step")

        report = self.look(5)

        self.assertEqual(self.events(report), [(LOG, "rewritten")])

    def test_a_baseline_written_before_the_marker_raises_nothing_new(self):
        # The author's store was last written by the old code: rows with
        # no marker, no acknowledged list, and, older still, no
        # stillness clock. A first look by this code at that memory says
        # what the old code would have said.
        self.look(0)
        memory = json.loads(self.baseline.read_text(encoding="utf-8"))
        memory.pop("acknowledged", None)
        for row in memory["chains"].values():
            row.pop("last_grew", None)
        self.baseline.write_text(json.dumps(memory), encoding="utf-8")

        self.assertEqual(self.look(0)["baseline"]["events"], [])
        self.cut()
        self.assertEqual(self.events(self.look(5)), [(LOG, "regressed")])
        self.assertEqual(self.events(self.look(5)), [(LOG, "regressed")])

    def test_a_chain_under_an_alarm_never_reawakens_or_restarts_its_clock(self):
        self.look(0)
        grew = self.remembered()["last_grew"]
        self.regenerate(6)
        self.look(5)
        time.sleep(1.1)  # so a clock restarted here would read differently

        report = self.look(5)

        self.assertEqual(self.remembered()["last_grew"], grew,
                         "a rewritten chain is no growth")
        self.assertEqual(report["lifecycle"]["events"], [])


class StoreFixture(unittest.TestCase):
    """The store, the default universe (ADR-0011): one drawer, one chain
    of five entries, and a home of the test's own."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.home = base / "storehome"
        self.witness = base / "no-witness"
        self.witness.mkdir()
        drawer = self.home / "receipts" / "alpha-11111111"
        drawer.mkdir(parents=True)
        (drawer / "project.json").write_text(
            json.dumps({"path": "C:/work/alpha"}), encoding="utf-8")
        self.log = drawer / f"receipts-{SESSION}.jsonl"
        self.env = {**isolated_env(base / "home",
                                   LOXODONTA_HOME=str(self.home)),
                    "PYTHONIOENCODING": "utf-8"}
        steps = [["init"]] + [["log", "--actor", "claude-code",
                               "--action", f"step {i}"] for i in range(4)]
        for args in steps:
            subprocess.run([sys.executable, str(LOXODONTA), args[0],
                            "--log", str(self.log), *args[1:]],
                           capture_output=True, timeout=BOUND, check=True,
                           env=self.env)

    def run_supervisor(self, *args):
        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), *args], capture_output=True,
            encoding="utf-8", timeout=BOUND, env=self.env)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def look(self, expect):
        result = self.run_supervisor("scan", "--json",
                                     "--witness", str(self.witness))
        self.assertEqual(result.returncode, expect,
                         result.stdout + result.stderr)
        return json.loads(result.stdout)


class StoreStandingAlarmTest(StoreFixture):
    """The same rule in the store, and an acknowledgement given there
    with no --root."""

    def test_a_store_chain_cut_short_alarms_until_acknowledged(self):
        self.look(0)
        lines = self.log.read_bytes().splitlines(keepends=True)
        self.log.write_bytes(b"".join(lines[:-1]))

        first = self.look(5)
        second = self.look(5)

        for report in (first, second):
            (event,) = report["baseline"]["events"]
            self.assertEqual(event["change"], "regressed")
        relpath = event["log"]
        self.assertEqual(relpath, f"alpha-11111111/receipts-{SESSION}.jsonl")
        accepted = self.run_supervisor("acknowledge", relpath,
                                       event["found"]["head"])
        self.assertEqual(accepted.returncode, 0,
                         accepted.stdout + accepted.stderr)

        clean = self.look(0)

        (record,) = clean["baseline"]["acknowledged"]
        self.assertEqual((record["log"], record["change"]),
                         (relpath, "regressed"))


class AcknowledgeTest(LegacyRoot):
    """`supervisor acknowledge LOG STATE` (#401 ruling, part 3): it
    accepts only the state a scan reported, refuses everything else
    with what it found and changes nothing, and leaves a record every
    later report shows."""

    def refused(self, *args, expect=64):
        before = self.baseline.read_bytes()
        result = self.acknowledge(*args, expect=expect)
        self.assertEqual(self.baseline.read_bytes(), before,
                         "a refusal wrote the baseline")
        self.assertEqual(result.stdout, "")
        return result.stderr

    def cut_and_looked(self):
        """A chain remembered whole, then cut short and looked at: the
        remembered (n, head) and the event the look reported. The line
        cut off is kept in self.tail."""
        self.look(0)
        remembered = self.head()
        self.tail = self.cut()
        (event,) = self.look(5)["baseline"]["events"]
        return remembered, event

    # --- what it accepts ----------------------------------------------------

    def test_an_accepted_regression_reads_clean_and_is_on_record(self):
        (n, head), event = self.cut_and_looked()
        found = event["found"]

        said = self.acknowledge(LOG, found["head"]).stdout

        self.assertEqual(len(said.splitlines()), 1, said)
        for words in (LOG, "regressed", head[:12], found["head"][:12],
                      NO_VERDICT_MOVED):
            self.assertIn(words, said)
        row = self.remembered()
        self.assertEqual((row["n"], row["head"]), (found["n"], found["head"]))
        self.assertNotIn("alarm", row)
        clean = self.look(0)
        self.assertEqual(clean["baseline"]["events"], [])
        (record,) = clean["baseline"]["acknowledged"]
        self.assertEqual(record["log"], LOG)
        self.assertEqual(record["change"], "regressed")
        self.assertEqual(record["remembered"], {"n": n, "head": head})
        self.assertEqual(record["accepted"], found)
        self.assertTrue(record["ts"])

    def test_an_accepted_rewrite_by_its_first_twelve_characters_reads_clean(self):
        self.look(0)
        self.regenerate(6)
        (event,) = self.look(5)["baseline"]["events"]

        self.acknowledge(LOG, event["found"]["head"][:12].upper())

        clean = self.look(0)
        self.assertEqual(clean["baseline"]["events"], [])
        self.assertEqual(clean["baseline"]["acknowledged"][0]["change"],
                         "rewritten")

    def test_an_accepted_gone_forgets_the_chain_and_reads_clean(self):
        self.look(0)
        n, head = self.head()
        self.log.unlink()
        self.look(5)

        said = self.acknowledge(LOG, "gone").stdout

        self.assertIn("vanished", said)
        self.assertIn(NO_VERDICT_MOVED, said)
        self.assertIsNone(self.remembered())
        clean = self.look(0)
        (record,) = clean["baseline"]["acknowledged"]
        self.assertEqual((record["change"], record["remembered"],
                          record["accepted"]),
                         ("vanished", {"n": n, "head": head}, None))

    def test_an_accepted_head_then_one_more_receipt_reads_clean(self):
        _, event = self.cut_and_looked()
        self.acknowledge(LOG, event["found"]["head"])
        self.logged("one more step")

        self.assertEqual(self.look(0)["baseline"]["events"], [])

    def test_an_acknowledged_chain_rewritten_again_alarms_again(self):
        _, event = self.cut_and_looked()
        self.acknowledge(LOG, event["found"]["head"])
        self.look(0)
        self.regenerate(4)

        report = self.look(5)

        self.assertEqual(self.events(report), [(LOG, "rewritten")])
        self.assertEqual(len(report["baseline"]["acknowledged"]), 1,
                         "the list is kept whole")

    def test_the_acknowledgement_moves_no_verdict(self):
        # The chain was regenerated: verify calls it VALID before the
        # acknowledgement and after it, and nothing else judges it.
        self.look(0)
        self.regenerate(6)
        (event,) = self.look(5)["baseline"]["events"]
        verdict = self.recorder("verify", "--log", str(self.log)).stdout

        self.acknowledge(LOG, event["found"]["head"])

        self.assertEqual(self.recorder("verify", "--log",
                                       str(self.log)).stdout, verdict)

    # --- what it refuses ----------------------------------------------------

    def test_a_chain_with_no_standing_alarm_is_refused(self):
        self.look(0)
        _, head = self.head()

        self.assertIn("no alarm stands", self.refused(LOG, head))
        self.assertIn("no alarm stands",
                      self.refused("beta/receipts/receipts-x.jsonl", head))

    def test_a_chain_that_holds_its_remembered_head_again_is_refused(self):
        _, event = self.cut_and_looked()
        with open(self.log, "ab") as chain:
            chain.write(self.tail)

        said = self.refused(LOG, event["found"]["head"])

        self.assertIn("holds the remembered head again", said)
        self.assertIn("next look", said)

    def test_gone_is_refused_while_something_stands_at_the_name(self):
        _, event = self.cut_and_looked()
        self.assertIsNotNone(event["found"])

        self.assertIn("something stands at", self.refused(LOG, "gone"))

    def test_a_head_that_is_no_longer_the_chains_is_refused_with_what_is(self):
        # The rule from the prior art: an acknowledgement accepts only
        # the state that was reported, never whatever is there by now.
        _, event = self.cut_and_looked()
        self.logged("written after the look")
        now = self.head()

        said = self.refused(LOG, event["found"]["head"])

        self.assertIn(now[1], said, "the refusal says what it found")
        self.assertIn(f"n {now[0]}", said)

    def test_a_head_named_for_a_chain_that_is_not_there_is_refused(self):
        self.look(0)
        _, head = self.head()
        self.log.unlink()
        self.look(5)

        self.assertIn("nothing stands at", self.refused(LOG, head))

    def test_a_short_or_unreadable_state_is_refused(self):
        _, event = self.cut_and_looked()
        found = event["found"]["head"]

        for state in (found[:11], "not-a-head-at-all", "g" * 64, ""):
            with self.subTest(state=state):
                self.assertIn("12", self.refused(LOG, state))

    def test_a_chain_that_reads_as_no_entries_is_refused_a_head(self):
        self.look(0)
        _, head = self.head()
        self.log.write_bytes(b"")
        (event,) = self.look(5)["baseline"]["events"]
        self.assertEqual(event["found"], {"n": None, "head": None})

        self.assertIn("holds no entries", self.refused(LOG, head))

    def test_the_command_spoken_wrong_is_a_usage_error(self):
        self.look(0)
        for args in ((), (LOG,), ("--baseline", LOG),
                     ("--baseline", LOG, "gone")):
            with self.subTest(args=args):
                self.refused(*args)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not look into")
    def test_gone_is_refused_where_the_folder_cannot_be_looked_into(self):
        # A chain in a folder closed to the scan reads as vanished; whether
        # it is gone is unknown, so `gone` is no state to accept.
        self.look(0)
        closed = self.log.parent
        os.chmod(closed, 0)
        self.addCleanup(os.chmod, closed, 0o755)
        self.assertEqual(self.events(self.look(5)), [(LOG, "vanished")])

        self.assertIn("cannot be looked into", self.refused(LOG, "gone"))


class BlindBaselineTest(LegacyRoot):
    """A baseline the scan cannot read or keep (#409, first half; #401
    ruling, part 4): exit 5 on every look, nothing remembered or
    compared, the file left as it lies, until `acknowledge --baseline`."""

    def assert_blind(self, why, looks=2):
        before = (self.baseline.read_bytes() if self.baseline.is_file()
                  else None)
        for _ in range(looks):
            report = self.look(5)
            self.assertEqual(report["baseline"]["blind"], why)
            self.assertEqual(report["baseline"]["events"], [])
            self.assertIn("acknowledge --baseline",
                          report["baseline"]["note"])
            if before is not None:
                self.assertEqual(self.baseline.read_bytes(), before,
                                 "the file is evidence and left as it lies")
            elif not self.baseline.is_dir():
                self.assertFalse(os.path.lexists(self.baseline),
                                 "the scan started a memory on its own")
        return report

    def test_a_corrupt_baseline_is_blind_on_every_look(self):
        self.look(0)
        self.baseline.write_text("{not json at all", encoding="utf-8")

        report = self.assert_blind("unreadable")

        self.assertIn("could not be read", report["baseline"]["note"])

    def test_a_row_of_the_wrong_shape_is_an_unreadable_baseline(self):
        # #403: one planted row used to end every scan in a traceback,
        # exit 1, the BROKEN rung; it is the baseline that is unreadable.
        self.look(0)
        whole = json.loads(self.baseline.read_text(encoding="utf-8"))
        _, head = self.head()
        planted = {"a list for n": {"n": [], "head": head},
                   "a string for n": {"n": "4", "head": "f" * 64},
                   "null for n": {"n": None, "head": "f" * 64},
                   "a boolean for n": {"n": True, "head": head},
                   "a number for head": {"n": 4, "head": 4},
                   "no head": {"n": 4},
                   "a row that is a list": [4, head]}
        for name, row in planted.items():
            with self.subTest(row=name):
                memory = json.loads(json.dumps(whole))
                memory["chains"][LOG] = row
                self.baseline.write_text(json.dumps(memory),
                                         encoding="utf-8")
                self.assert_blind("unreadable")

    def assert_keys_unreadable(self, *keys):
        """#422 item 7: a key that leaves the root ended every look in a
        traceback from the vanished check; it is a row of the wrong shape."""
        self.look(0)
        memory = json.loads(self.baseline.read_text(encoding="utf-8"))
        row = memory["chains"][LOG]
        for key in keys:
            with self.subTest(key=key):
                memory["chains"] = {key: row}
                self.baseline.write_text(json.dumps(memory),
                                         encoding="utf-8")
                self.assert_blind("unreadable")

    def test_an_absolute_key_is_an_unreadable_baseline(self):
        self.assert_keys_unreadable(
            (self.root / "elsewhere" / "receipts-x.jsonl").as_posix(),
            "/etc/receipts.jsonl", "C:/work/receipts.jsonl")

    def test_a_key_climbing_out_of_the_root_is_an_unreadable_baseline(self):
        self.assert_keys_unreadable("../outside.jsonl",
                                    "alpha/../../outside.jsonl",
                                    "alpha\\..\\..\\outside.jsonl")

    def test_an_acknowledged_list_of_the_wrong_shape_is_unreadable(self):
        self.look(0)
        memory = json.loads(self.baseline.read_text(encoding="utf-8"))
        memory["acknowledged"] = {"not": "a list"}
        self.baseline.write_text(json.dumps(memory), encoding="utf-8")

        self.assert_blind("unreadable", looks=1)

    def test_a_baseline_deleted_beside_a_day_book_is_blind(self):
        self.look(0)
        self.baseline.unlink()

        report = self.assert_blind("missing")

        self.assertIn("missing", report["baseline"]["note"])

    def test_neither_file_is_a_first_look_seeded_quietly(self):
        report = self.look(0)

        self.assertNotIn("blind", report["baseline"])
        self.assertNotIn("note", report["baseline"])
        self.assertEqual(report["baseline"]["acknowledged"], [])
        self.assertEqual(self.remembered()["head"], self.head()[1])

    def test_a_blind_look_never_runs_the_keepers(self):
        # Their throttle lives in the unreadable file: run on every look,
        # they would ask the calendars every minute under `serve`.
        side = self.root / "beta" / "receipts" / "receipts-sess-pend.jsonl"
        side.parent.mkdir(parents=True)
        self.recorder("init", "--log", str(side))
        self.logged("step 0", "step 1", log=side)
        last = json.loads(side.read_text(encoding="utf-8").splitlines()[-1])
        calendar = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
        calendar.mode = "pending"
        calendar.submitted, calendar.polled = [], []
        calendar.url = f"http://127.0.0.1:{calendar.server_address[1]}"
        threading.Thread(target=calendar.serve_forever, daemon=True).start()
        self.addCleanup(calendar.server_close)
        self.addCleanup(calendar.shutdown)
        write_pending_anchor(side, last["entry_hash"],
                             submitted=ago(100000), calendar=calendar.url)
        self.env["SUPERVISOR_UPGRADE_EVERY_SECONDS"] = "0"
        self.look(0)
        asked = len(calendar.polled)
        self.assertGreater(asked, 0, "the keeper never asked at all")
        self.baseline.write_text("{not json", encoding="utf-8")

        report = self.look(5)

        self.assertEqual(len(calendar.polled), asked,
                         "a keeper ran on a blind look")
        self.assertIn("keepers wait", report["baseline"]["note"])
        self.acknowledge("--baseline")
        self.look(0)
        self.assertGreater(len(calendar.polled), asked,
                           "the keepers came back with the memory")

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not write in")
    def test_a_baseline_that_cannot_be_kept_is_exit_5_not_a_traceback(self):
        self.look(0)
        os.chmod(self.root, 0o555)
        self.addCleanup(os.chmod, self.root, 0o755)
        self.cut()

        report = self.look(5)

        self.assertTrue(report["baseline"]["unkept"])
        self.assertIn("could not be written", report["baseline"]["note"])
        self.assertEqual(self.events(report), [(LOG, "regressed")])

    # --- acknowledge --baseline ---------------------------------------------

    def test_acknowledging_a_corrupt_baseline_starts_the_memory_afresh(self):
        self.look(0)
        self.baseline.write_text("{not json at all", encoding="utf-8")
        self.look(5)

        said = self.acknowledge("--baseline").stdout

        self.assertEqual(len(said.splitlines()), 1, said)
        self.assertIn("unreadable", said)
        self.assertIn("calibration", said)
        self.assertIn(NO_VERDICT_MOVED, said)
        self.assertEqual(self.remembered()["head"], self.head()[1],
                         "every chain's current head is remembered")
        clean = self.look(0)
        (record,) = clean["baseline"]["acknowledged"]
        self.assertEqual(record["change"], "unreadable")
        self.assertIn("not JSON", record["stood"])
        self.assertNotIn("blind", clean["baseline"])

    def test_acknowledging_a_baseline_missing_beside_a_day_book(self):
        self.look(0)
        self.baseline.unlink()
        self.look(5)

        self.acknowledge("--baseline")

        clean = self.look(0)
        self.assertEqual(clean["baseline"]["acknowledged"][0]["change"],
                         "missing")

    def test_a_baseline_that_reads_fine_has_nothing_to_acknowledge(self):
        self.look(0)
        before = self.baseline.read_bytes()

        said = self.acknowledge("--baseline", expect=64).stderr

        self.assertIn("reads fine", said)
        self.assertEqual(self.baseline.read_bytes(), before)

    def test_a_first_look_has_nothing_to_acknowledge(self):
        said = self.acknowledge("--baseline", expect=64).stderr

        self.assertIn("next scan", said)
        self.assertFalse(os.path.lexists(self.baseline))

    def test_a_folder_at_the_baselines_name_is_for_the_operator_to_remove(self):
        self.look(0)
        self.baseline.unlink()
        self.baseline.mkdir()
        self.assert_blind("unreadable")

        said = self.acknowledge("--baseline", expect=64).stderr

        self.assertIn("remove it by hand", said)
        self.assertTrue(self.baseline.is_dir())
        self.assertIn("acknowledge --baseline",
                      self.acknowledge(LOG, "gone", expect=64).stderr)

    def test_a_chain_cannot_be_acknowledged_past_a_blind_baseline(self):
        self.look(0)
        self.baseline.write_text("[]", encoding="utf-8")
        before = self.baseline.read_bytes()

        said = self.acknowledge(LOG, "gone", expect=64).stderr

        self.assertIn("acknowledge --baseline", said)
        self.assertEqual(self.baseline.read_bytes(), before)


class RewritingHandler(BaseHTTPRequestHandler):
    """A remote that, while the scan waits on it, has another writer
    put its own baseline in place: what an acknowledgement typed while
    `serve` scans looks like to the scan."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        memory = json.loads(self.server.baseline.read_text(encoding="utf-8"))
        memory["written_by"] = "the other writer"
        self.server.baseline.write_text(json.dumps(memory), encoding="utf-8")
        self.server.posts += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class TwoWritersTest(LegacyRoot):
    """A scan does not write over a baseline that changed since it read
    it (#401 ruling, part 3): `serve` writes at the end of a scan what it
    read at the start, and would undo an acknowledgement made between.
    The window is held open by the publish keeper's POST, which the scan
    waits on, so the other writer always lands inside it."""

    def test_a_baseline_written_during_the_look_is_left_standing(self):
        self.look(0)
        remote = FakeCalendar(("127.0.0.1", 0), RewritingHandler)
        remote.baseline, remote.posts = self.baseline, 0
        threading.Thread(target=remote.serve_forever, daemon=True).start()
        self.addCleanup(remote.server_close)
        self.addCleanup(remote.shutdown)

        result = self.supervisor(
            "scan", "--root", str(self.root), "--json",
            "--publish-every", "0s", "--publish-url",
            f"http://127.0.0.1:{remote.server_address[1]}/hook")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(remote.posts, 1, "the keeper never posted")
        memory = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(memory.get("written_by"), "the other writer",
                         "the scan wrote over the other writer's baseline")
        self.assertIn("changed while this look ran",
                      json.loads(result.stdout)["baseline"]["note"])


class OtherReadersTest(LegacyRoot):
    """The digest over a standing alarm and a blind baseline: exit 0,
    as always, and never a quiet line."""

    def last_scan(self):
        result = self.supervisor("digest", "--repo", str(self.root / "alpha"))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.split("last scan:")[1].splitlines()[0]

    def test_the_digest_counts_a_standing_alarm(self):
        self.look(0)
        self.cut()
        self.look(5)

        self.assertIn("1 baseline alarm standing", self.last_scan())

    def test_the_digest_says_the_baseline_cannot_be_read(self):
        self.look(0)
        for text in ("{not json", "[]"):
            with self.subTest(baseline=text):
                self.baseline.write_text(text, encoding="utf-8")
                self.assertIn("cannot be read", self.last_scan())

    def test_the_digest_says_the_baseline_is_missing_beside_a_day_book(self):
        self.look(0)
        self.baseline.unlink()

        self.assertIn("missing beside a day book", self.last_scan())


class StoreKeysTest(StoreFixture):
    """#422 item 7 in the store universe: a key in the store's baseline
    that is absolute or climbs out of the receipts folder is a baseline
    of the wrong shape, exit 5 on every look, the file left as it lies."""

    def test_a_key_leaving_the_store_is_an_unreadable_baseline(self):
        self.look(0)
        path = self.home / "baseline.json"
        memory = json.loads(path.read_text(encoding="utf-8"))
        (row,) = memory["chains"].values()
        for key in (self.log.as_posix(), "../outside/receipts-x.jsonl",
                    "alpha-11111111/../../receipts-x.jsonl"):
            with self.subTest(key=key):
                memory["chains"] = {key: row}
                path.write_text(json.dumps(memory), encoding="utf-8")
                before = path.read_bytes()
                for _ in range(2):
                    report = self.look(5)
                    self.assertEqual(report["baseline"]["blind"],
                                     "unreadable")
                self.assertEqual(path.read_bytes(), before)


class StoreReadersTest(StoreFixture):
    """`export` and `package` take a scan of the store underneath; over
    a blind baseline each keeps its own exit and says so."""

    def blind(self):
        self.look(0)
        (self.home / "baseline.json").write_text("{not json",
                                                 encoding="utf-8")

    def test_export_over_a_blind_baseline_says_so_and_ships_exit_5(self):
        self.blind()
        out = Path(self._tmp.name) / "export.json"

        result = self.run_supervisor("export", "--witness", str(self.witness),
                                     "--out", str(out))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("could not be read", result.stderr)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))
                         ["machine"]["scan_exit"], 5)

    def test_package_over_a_blind_baseline_says_so(self):
        self.blind()
        out = Path(self._tmp.name) / "package"

        result = self.run_supervisor("package", SESSION, "--folder",
                                     "--out", str(out),
                                     "--witness", str(self.witness))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("could not be read", result.stderr)
        witness = json.loads((out / "witness.json").read_text(
            encoding="utf-8"))
        self.assertEqual(witness["scan"]["exit"], 5)


if __name__ == "__main__":
    unittest.main()
