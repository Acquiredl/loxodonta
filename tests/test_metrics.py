"""Behavioral tests for the metrics route (`supervisor.py serve`, `/metrics`;
ADR-0033, issue #252).

The route renders the scan's counts in the Prometheus text format for
whatever the operator already runs, and it is one pure function over the
report the status endpoint already serves. So the contract these tests
hold is arithmetic: every number in the body equals the corresponding
field of `scan --json` taken in the same fixture, every help line ends
with the grade of evidence behind it, and the route inherits the face's
posture, loopback bind and Host check alike. Tests drive a real `serve`
subprocess and a real `scan` subprocess and parse the text with a small
parser of their own; nothing is imported from the tool.
"""

import json
import os
import re
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_metrics`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env
from test_publish import FakeReceiver, FakeReceiverHandler
from test_serve import OPENER, ServerFixture, log_entry
from test_supervisor import (ago, chain_head, install_witness_hook,
                             make_chain, prime_memory, run_scan,
                             write_attempt_row, write_completed_anchor,
                             write_transcript)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"

GRADES = ("(verdict)", "(witness verdict)", "(testimony)")

# The text format, read strictly: a sample is a metric name, an optional
# label set, and one value; a name is what Prometheus accepts as one.
SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)$")
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


class Exposition:
    """A parsed scrape: help lines, types, and samples keyed by name and
    label set. `value(name, **labels)` reads one sample and fails loudly
    on a missing one, since a missing series is exactly what a panel
    must never meet."""

    def __init__(self, text):
        self.help = {}
        self.types = {}
        self.samples = {}
        for line in text.splitlines():
            if line.startswith("# HELP "):
                name, _, words = line[len("# HELP "):].partition(" ")
                self.help[name] = words
            elif line.startswith("# TYPE "):
                name, _, kind = line[len("# TYPE "):].partition(" ")
                self.types[name] = kind
            elif line.startswith("#") or not line.strip():
                continue
            else:
                match = SAMPLE.match(line)
                if match is None:
                    raise AssertionError(f"not a sample line: {line!r}")
                name, labels, value = match.groups()
                pairs = (tuple(sorted(LABEL.findall(labels[1:-1])))
                         if labels else ())
                self.samples[(name, pairs)] = float(value)

    def names(self):
        return sorted({name for name, _ in self.samples})

    def value(self, name, **labels):
        key = (name, tuple(sorted(labels.items())))
        if key not in self.samples:
            raise AssertionError(f"no sample {name}{labels or ''}; have "
                                 f"{sorted(self.samples)}")
        return self.samples[key]

    def label_values(self, name, label):
        return sorted(dict(pairs)[label] for metric, pairs in self.samples
                      if metric == name)


def tamper(log):
    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["action"] = "something else entirely"
    lines[1] = json.dumps(entry)
    log.write_text("".join(l + "\n" for l in lines), encoding="utf-8")


def tear(log):
    with open(log, "a", encoding="utf-8", newline="\n") as f:
        f.write('{"n":3,"half-written')


def regenerate(log_dir, session):
    """The adversary's best move: anchor the head, then rewrite the
    chain wholesale with one entry fewer. Only the anchor remembers."""
    log = make_chain(log_dir, session)
    write_completed_anchor(log, chain_head(log))
    log.unlink()
    return make_chain(log_dir, session, entries=1)


def chains_of(report):
    return [chain for repo in report["repos"]
            for session in repo["sessions"] for chain in session["chains"]]


class MetricsFixture(ServerFixture):
    """The serve fixture with a witness of its own, a calibration memory
    older than every session it will meet, and a home of its own, so
    the machine's real marker (#242) and real store never leak in."""

    def setUp(self):
        super().setUp()
        top = self.root
        self.root = top / "repos"
        self.root.mkdir()
        self.witness = top / "witness"
        install_witness_hook(self.witness)
        prime_memory(self.root)
        self.home = top / "home"
        self.knobs = {"LOXODONTA_HOME": str(self.home)}

    def serve(self, extra_env=None, extra_args=()):
        super().serve(extra_env={**self.knobs, **(extra_env or {})},
                      extra_args=("--witness", str(self.witness),
                                  *extra_args))

    def scrape(self):
        status, ctype, body = self.get("/metrics")
        self.assertEqual(status, 200)
        return ctype, body, Exposition(body)

    def scan(self, **knobs):
        """`scan --json` over the same root and witness: the numbers the
        route must agree with."""
        result = run_scan(self.root, "--witness", str(self.witness),
                          env={**os.environ, **self.knobs, **knobs})
        self.assertIn(result.returncode, range(0, 8),
                      result.stdout + result.stderr)
        return json.loads(result.stdout)


class ExpositionFormatTest(MetricsFixture):
    """The route speaks the text format, and every family on it is a
    gauge named by the tool and graded by its help line."""

    def test_the_route_speaks_the_text_format_with_a_grade_on_every_help_line(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        ctype, body, scrape = self.scrape()

        self.assertEqual(ctype, "text/plain; version=0.0.4; charset=utf-8")
        self.assertTrue(body.endswith("\n"))
        self.assertTrue(scrape.samples, "an empty scrape says nothing")
        for name in scrape.names():
            self.assertTrue(name.startswith("loxodonta_"), name)
            self.assertIn(name, scrape.help, f"{name} has no HELP line")
            self.assertEqual(scrape.types.get(name), "gauge", name)
            self.assertTrue(scrape.help[name].endswith(GRADES),
                            f"{name}: {scrape.help[name]!r}")
        for name in scrape.help:
            self.assertIn(name, scrape.names(), f"HELP for {name}, no sample")
        # A metric is named by its mechanism, never by a conclusion.
        lowered = body.lower()
        for anti_term in ("blockchain", "immutable", "audit", "tamper"):
            self.assertNotIn(anti_term, lowered)


class ChainsByVerdictTest(MetricsFixture):
    """`loxodonta_chains{verdict}`: one sample per verdict the scan
    knows, zero included, the value the scan's own string."""

    def test_chains_count_by_the_scans_own_verdict(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        anchored = make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        write_completed_anchor(anchored, chain_head(anchored))
        tamper(make_chain(self.root / "gamma" / "receipts", "sess-cccc"))
        regenerate(self.root / "delta" / "receipts", "sess-dddd")
        torn = make_chain(self.root / "epsilon" / "receipts", "sess-eeee")
        tear(torn)
        make_chain(self.root / "epsilon" / "receipts", "sess-eeee-002")
        hollow = self.root / "zeta" / "receipts" / "receipts-sess-ffff.jsonl"
        hollow.parent.mkdir(parents=True)
        hollow.write_text("", encoding="utf-8")
        self.serve()

        _, _, scrape = self.scrape()
        report = self.scan()

        chains = chains_of(report)
        judged = [c for c in chains if not c["superseded"]]
        for verdict in ("VALID", "BROKEN", "ANCHOR-MISMATCH", "NO-VERDICT"):
            self.assertEqual(
                scrape.value("loxodonta_chains", verdict=verdict),
                sum(1 for c in judged if c["verdict"] == verdict), verdict)
        # The fixture holds one of each (and the torn tail's sibling is
        # a third VALID chain): the count is not vacuous.
        self.assertEqual(scrape.value("loxodonta_chains", verdict="VALID"), 3)
        self.assertEqual(scrape.value("loxodonta_chains", verdict="BROKEN"), 1)
        self.assertEqual(
            scrape.value("loxodonta_chains", verdict="ANCHOR-MISMATCH"), 1)
        self.assertEqual(
            scrape.value("loxodonta_chains", verdict="NO-VERDICT"), 1)
        # Verdicts nothing here earned are still on the scrape, at zero.
        for verdict in ("ANCHOR-INVALID", "TRANSCRIPT-DIVERGED",
                        "UNSUPPORTED-VERSION"):
            self.assertEqual(scrape.value("loxodonta_chains", verdict=verdict),
                             0, verdict)
        # A torn tail a sibling continued is BROKEN by verify's word and
        # stood down by the scan: its own gauge, never the broken count.
        self.assertEqual(scrape.value("loxodonta_chains_superseded"),
                         sum(1 for c in chains if c["superseded"]))
        self.assertEqual(scrape.value("loxodonta_chains_superseded"), 1)
        self.assertEqual(
            sum(scrape.samples[key] for key in scrape.samples
                if key[0] == "loxodonta_chains")
            + scrape.value("loxodonta_chains_superseded"),
            len(chains), "every chain is in exactly one bucket")


class ScanAndTallyTest(MetricsFixture):
    """The scan's exit code and its age, and the tally: the store's own
    scale, counted the way the page's tally counts it."""

    def test_the_tally_and_the_scans_exit_and_age_equal_the_report(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        make_chain(self.root / "alpha" / "receipts", "sess-bbbb")
        make_chain(self.root / "alpha" / "receipts", "sess-bbbb-002")
        tamper(make_chain(self.root / "beta" / "receipts", "sess-cccc"))
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "300"})

        _, _, scrape = self.scrape()
        report = self.scan()

        self.assertEqual(scrape.value("loxodonta_scan_exit_code"),
                         report["exit"])
        self.assertEqual(report["exit"], 1, "one tampered chain: exit 1")
        age = scrape.value("loxodonta_scan_age_seconds")
        self.assertGreaterEqual(age, 0)
        self.assertLess(age, 60)
        chains = chains_of(report)
        self.assertEqual(scrape.value("loxodonta_store_drawers"),
                         len(report["repos"]))
        self.assertEqual(scrape.value("loxodonta_store_sessions"),
                         sum(len(r["sessions"]) for r in report["repos"]))
        self.assertEqual(scrape.value("loxodonta_store_chains"), len(chains))
        self.assertEqual(scrape.value("loxodonta_store_receipts"),
                         sum(c["entries"] for c in chains))
        self.assertEqual(scrape.value("loxodonta_store_drawers"), 2)
        self.assertEqual(scrape.value("loxodonta_store_sessions"), 3)
        self.assertEqual(scrape.value("loxodonta_store_chains"), 4)


class SessionsByStateTest(MetricsFixture):
    """Sessions by completeness state and by lifecycle tier, and the
    consumption watch's hot sessions: labelled gauges, one sample per
    state the scan knows, zero included. A later state is a new label
    value and never a renamed metric."""

    def test_completeness_and_lifecycle_states_are_label_values(self):
        make_chain(self.root / "alpha" / "receipts", "sess-ok", entries=3)
        write_transcript(self.witness, self.root / "alpha", "sess-ok",
                         event_times=[ago(300), ago(290), ago(280)])
        make_chain(self.root / "beta" / "receipts", "sess-ended")
        write_transcript(self.witness, self.root / "beta", "sess-ended",
                         event_times=[ago(4000), ago(3990)])
        write_transcript(self.witness, self.root / "gamma", "sess-ghost",
                         event_times=[ago(120), ago(110), ago(100)])
        make_chain(self.root / "delta" / "receipts", "sess-unwitnessed")
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "0"})

        _, _, first = self.scrape()
        report = self.scan()

        rows = report["completeness"]["sessions"]
        for state in ("OK", "ENDED-CLEAN", "ALARM-SILENT", "UNWITNESSED",
                      "ENDED-DEFICIT", "LAGGING", "IDLE-CLEAN", "ELSEWHERE"):
            self.assertEqual(
                first.value("loxodonta_completeness_sessions", state=state),
                sum(1 for row in rows if row["state"] == state), state)
        by_state = {row["session"]: row["state"] for row in rows}
        self.assertEqual(by_state, {"sess-ok": "OK",
                                    "sess-ended": "ENDED-CLEAN",
                                    "sess-ghost": "ALARM-SILENT",
                                    "sess-unwitnessed": "UNWITNESSED"})
        self.assertEqual(first.value("loxodonta_scan_exit_code"), 6)
        for tier in ("awake", "waning", "dormant"):
            self.assertEqual(
                first.value("loxodonta_lifecycle_sessions", state=tier),
                sum(1 for row in rows
                    if (row.get("dormancy") or {}).get("tier") == tier), tier)
        self.assertEqual(
            first.value("loxodonta_lifecycle_sessions", state="awake"), 2,
            "the two witnessed, chained sessions were just seen to grow")

        # A session in a state nothing above was in: its label value
        # moves off zero and no metric name changes.
        make_chain(self.root / "epsilon" / "receipts", "sess-short",
                   entries=1)
        write_transcript(self.witness, self.root / "epsilon", "sess-short",
                         event_times=[ago(4000), ago(3990), ago(3980)])
        _, _, second = self.scrape()

        self.assertEqual(second.names(), first.names())
        self.assertEqual(
            first.value("loxodonta_completeness_sessions",
                        state="ENDED-DEFICIT"), 0)
        self.assertEqual(
            second.value("loxodonta_completeness_sessions",
                         state="ENDED-DEFICIT"), 1)

    def test_sessions_before_the_memory_are_the_blocks_count(self):
        # ADR-0029: a session older than the supervisor's first look is
        # counted in one block and never takes a row; the label carries
        # the block's count, so the scrape says how much predates the
        # memory instead of reading a clean bill.
        (self.root / ".supervisor-baseline.json").unlink()
        make_chain(self.root / "alpha" / "receipts", "sess-old")
        write_transcript(self.witness, self.root / "alpha", "sess-old",
                         event_times=[ago(6000), ago(5990)])
        self.serve()

        _, _, scrape = self.scrape()
        report = self.scan()

        block = report["completeness"]["before_memory"]
        self.assertEqual(block["count"], 1)
        self.assertEqual(
            scrape.value("loxodonta_completeness_sessions",
                         state="BEFORE-MEMORY"), block["count"])
        self.assertEqual(report["completeness"]["sessions"], [])

    def test_sessions_running_hot_are_counted_by_the_consumption_watch(self):
        for name in ("aaaa", "bbbb", "cccc"):
            make_chain(self.root / name / "receipts", "sess-" + name,
                       entries=3)
        make_chain(self.root / "delta" / "receipts", "sess-hot", entries=12)
        knobs = {"SUPERVISOR_HOT_TIMES": "3", "SUPERVISOR_HOT_FLOOR": "10"}
        self.serve(extra_env=knobs)

        _, _, scrape = self.scrape()
        report = self.scan(**knobs)

        hot = report["consumption"]["sessions"]
        for state in ("RUNNING-HOT", "ENDED-HOT"):
            self.assertEqual(
                scrape.value("loxodonta_consumption_sessions", state=state),
                sum(1 for row in hot if row["state"] == state), state)
        self.assertEqual(
            scrape.value("loxodonta_consumption_sessions",
                         state="RUNNING-HOT"), 1)
        self.assertEqual(
            scrape.value("loxodonta_consumption_sessions", state="ENDED-HOT"),
            0)


class HeadsTest(MetricsFixture):
    """Heads not yet anchored and not yet out of reach: the anchor
    panel's own readings, counted. Whether an anchor covers a head is
    verify's word; whether a head has left the machine is what the
    sidecars beside the chain say, and those the writer can reach."""

    def setUp(self):
        super().setUp()
        self.receiver = FakeReceiver(("127.0.0.1", 0), FakeReceiverHandler)
        self.receiver.received = []
        self.receiver.delay = 0
        self.receiver.url = (
            "http://127.0.0.1:%d/hook" % self.receiver.server_address[1])
        threading.Thread(target=self.receiver.serve_forever,
                         daemon=True).start()
        self.addCleanup(self.receiver.server_close)
        self.addCleanup(self.receiver.shutdown)

    def publish_by_hand(self, log):
        """One head through the public `publish`, to the fake receiver:
        a real memo row, written the way the recorder writes it."""
        subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", "--log", str(log),
             self.receiver.url],
            capture_output=True, check=True, env=clean_env())

    def test_unanchored_and_unpublished_heads_are_the_panels_counts(self):
        make_chain(self.root / "alpha" / "receipts", "sess-bare")
        anchored = make_chain(self.root / "beta" / "receipts", "sess-anch")
        write_completed_anchor(anchored, chain_head(anchored))
        published = make_chain(self.root / "gamma" / "receipts", "sess-pub")
        self.publish_by_hand(published)
        # A chain with nothing in it has no head, so it is neither
        # anchored nor unanchored and neither published nor unpublished.
        hollow = self.root / "zeta" / "receipts" / "receipts-sess-ffff.jsonl"
        hollow.parent.mkdir(parents=True)
        hollow.write_text("", encoding="utf-8")
        self.serve()

        _, _, scrape = self.scrape()
        report = self.scan()

        chains = chains_of(report)
        self.assertEqual(
            scrape.value("loxodonta_heads_unanchored"),
            sum(1 for c in chains if c["anchors"]["head"]
                and not c["anchors"]["head"]["anchored"]))
        self.assertEqual(scrape.value("loxodonta_heads_unanchored"), 2,
                         "the bare chain and the published one")
        self.assertEqual(
            scrape.value("loxodonta_heads_unpublished"),
            sum(1 for c in chains if c["head_published"] is False))
        self.assertEqual(scrape.value("loxodonta_heads_unpublished"), 2,
                         "the bare chain and the anchored one; a head that "
                         "left by the anchor door was not published")
        # The headless chain is in the store and in neither gauge, which
        # is why the three do not add up.
        self.assertEqual(scrape.value("loxodonta_store_chains"), 4)
        self.assertEqual([c["head_published"] for c in chains
                          if not c["entries"]], [None])
        # Publishing is not wired on this witness, so the sentence the
        # scan would print is not the case and the gauge says so.
        self.assertFalse(report["published"]["wired"])
        self.assertIsNone(report["published"]["note"])
        self.assertEqual(
            scrape.value("loxodonta_publishing_wired_nothing_sent"), 0)

    def test_a_published_head_stops_counting_once_the_memo_holds_it(self):
        # The reading is the keeper's own already-sent test with the
        # cadence taken out, so it moves exactly when the memo gains the
        # row and never when an attempt row lands beside it.
        log = make_chain(self.root / "alpha" / "receipts", "sess-pub")
        write_attempt_row(log, "publish-head", "the remote answered 404",
                          when=ago(600), budget=3.0)
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "0"})

        _, _, before = self.scrape()
        self.assertEqual(before.value("loxodonta_heads_unpublished"), 1,
                         "a refused POST is not a publication")

        self.publish_by_hand(log)
        _, _, after = self.scrape()
        report = self.scan()

        self.assertEqual(after.value("loxodonta_heads_unpublished"), 0)
        self.assertEqual([c["head_published"] for c in chains_of(report)],
                         [True])

    def test_publishing_wired_with_nothing_sent_is_the_scans_sentence(self):
        # #240 part 3: the posture wired in name only. The scan says it
        # in one sentence; the same condition is one gauge.
        install_witness_hook(
            self.witness, sessionend=True,
            command="python loxodonta.py hook --publish "
                    "https://receipts.example.test/hook")
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        _, _, scrape = self.scrape()
        report = self.scan()

        self.assertTrue(report["published"]["wired"])
        self.assertFalse(report["published"]["sent"])
        self.assertIsNotNone(report["published"]["note"])
        self.assertEqual(
            scrape.value("loxodonta_publishing_wired_nothing_sent"), 1)


class LastAttemptFailedTest(MetricsFixture):
    """`loxodonta_last_attempt_failed{step}`: one gauge per session-end
    step, 1 when some chain's newest failed attempt is that step. Read
    from the rows the recorder writes after each step (#240), which are
    testimony about network luck and never a verdict."""

    def test_the_last_failed_attempt_is_one_gauge_per_step(self):
        refused = make_chain(self.root / "alpha" / "receipts",
                             "sess-refused")
        write_attempt_row(refused, "publish-head",
                          "the remote answered 404", when=ago(600),
                          budget=3.0)
        quiet = make_chain(self.root / "beta" / "receipts", "sess-quiet")
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "0"})

        _, _, first = self.scrape()
        report = self.scan()

        failed = [c["last_failed"] for c in chains_of(report)
                  if c["last_failed"]]
        self.assertEqual([f["step"] for f in failed], ["publish-head"])
        for step in ("anchor", "publish-head"):
            self.assertEqual(
                first.value("loxodonta_last_attempt_failed", step=step),
                1 if any(f["step"] == step for f in failed) else 0, step)
        self.assertEqual(
            first.value("loxodonta_last_attempt_failed",
                        step="publish-head"), 1)
        self.assertEqual(
            first.value("loxodonta_last_attempt_failed", step="anchor"), 0)

        # No calendar answered for the other chain: the anchor step's own
        # gauge moves off zero and no metric name changes.
        write_attempt_row(quiet, "anchor",
                          "no calendar answered within 12 seconds",
                          when=ago(60))
        _, _, second = self.scrape()

        self.assertEqual(second.names(), first.names())
        self.assertEqual(
            second.value("loxodonta_last_attempt_failed", step="anchor"), 1)
        self.assertEqual(
            second.value("loxodonta_last_attempt_failed",
                         step="publish-head"), 1)


    def test_the_chain_send_and_the_stamp_have_gauges_of_their_own(self):
        # The two steps later slices added (#248, #250) are label values
        # like the first two: served at zero before they ever fail, and at
        # one when some chain's newest failed attempt is theirs.
        sent = make_chain(self.root / "alpha" / "receipts", "sess-chain")
        write_attempt_row(sent, "publish-chain",
                          "no answer within 3 seconds", when=ago(300),
                          budget=3.0)
        stamped = make_chain(self.root / "beta" / "receipts", "sess-stamp")
        row = {"kind": "attempt", "step": "stamp", "ts": ago(120),
               "budget": 3.0, "outcome": "the remote answered 503"}
        with open(str(stamped) + ".stamps.jsonl", "a",
                  encoding="utf-8") as out:
            out.write(json.dumps(row) + "\n")
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "0"})

        _, _, scraped = self.scrape()
        report = self.scan()

        failed = sorted(c["last_failed"]["step"] for c in chains_of(report)
                        if c["last_failed"])
        self.assertEqual(failed, ["publish-chain", "stamp"])
        for step in ("anchor", "publish-head", "publish-chain", "stamp"):
            self.assertEqual(
                scraped.value("loxodonta_last_attempt_failed", step=step),
                1 if step in failed else 0, step)

class OffMachineMetricsTest(MetricsFixture):
    """The route inherits the face's posture (ADR-0033 ruling 3): a
    browser lied to by DNS reads as same-origin, so the Host header is
    the only witness left, and the scrape is refused on it exactly as
    the page is."""

    def test_a_rebound_host_header_is_refused_on_the_metrics_route(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        request = urllib.request.Request(
            self.url + "/metrics", headers={"Host": "attacker.example"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            OPENER.open(request, timeout=30)

        self.assertEqual(caught.exception.code, 403)
        # The same refusal the page gets, not a softer one of its own.
        page = urllib.request.Request(
            self.url + "/", headers={"Host": "attacker.example"})
        with self.assertRaises(urllib.error.HTTPError) as also:
            OPENER.open(page, timeout=30)
        self.assertEqual(also.exception.code, caught.exception.code)

    def test_the_machine_itself_is_still_scraped(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        status, ctype, _ = self.get("/metrics")

        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/plain; version=0.0.4; charset=utf-8")


class NoExtraWalkTest(MetricsFixture):
    """A scrape is not a tick. The route renders the scan the server
    already holds, so the day book's count of the supervisor's own looks
    is unchanged by a scrape and a chain that lands after the tick is
    not on it (ADR-0033: the route adds no reading)."""

    def ticks(self):
        """The supervisor's own count of its walks, from the day book it
        keeps beside the store."""
        book = json.loads((self.root / ".supervisor-daybook.json")
                          .read_text(encoding="utf-8"))
        return sum(row.get("scans", 0) for row in book["days"].values())

    def test_a_scrape_reads_the_held_scan_and_walks_nothing(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "300"})

        _, _, first = self.scrape()
        walked = self.ticks()
        # A chain that arrives after the tick: a scrape must not see it,
        # because a scrape must not walk the store to find it.
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        _, _, second = self.scrape()

        self.assertEqual(self.ticks(), walked, "a scrape ticked the scan")
        self.assertEqual(first.value("loxodonta_store_chains"), 1)
        self.assertEqual(second.value("loxodonta_store_chains"),
                         first.value("loxodonta_store_chains"))
        self.assertEqual(second.value("loxodonta_store_drawers"),
                         first.value("loxodonta_store_drawers"))
        self.assertGreaterEqual(second.value("loxodonta_scan_age_seconds"),
                                first.value("loxodonta_scan_age_seconds"))


class DocumentedNamesTest(MetricsFixture):
    """ADR-0033 ruling 4: the list lives in one place in the code beside
    its help text, and `docs/METRICS.md` restates it for the operator.
    The two must agree, name for name and help line for help line, or
    the page an operator freezes a dashboard against is already wrong."""

    def page(self):
        return (REPO_ROOT / "docs" / "METRICS.md").read_text(encoding="utf-8")

    def documented_values(self):
        """The page's label-values table, as {(name, label): {values}}.
        Three cells wide, which is what tells it from the table above."""
        rows = {}
        for line in self.page().splitlines():
            cells = [cell.strip()
                     for cell in line.strip().strip("|").split("|")]
            if len(cells) != 3 or not cells[0].startswith("`loxodonta_"):
                continue
            rows[(cells[0].strip("`"), cells[1].strip("`"))] = {
                cell.strip().strip("`") for cell in cells[2].split(",")
                if cell.strip()}
        return rows

    def documented(self):
        """The page's table, as {name: (labels, grade, help words)}."""
        rows = {}
        for line in self.page().splitlines():
            cells = [cell.strip()
                     for cell in line.strip().strip("|").split("|")]
            if len(cells) != 4 or not cells[0].startswith("`loxodonta_"):
                continue
            name = cells[0].strip("`")
            labels = tuple(sorted(cell.strip().strip("`")
                                  for cell in cells[1].split(",")
                                  if cell.strip() and cell.strip() != "none"))
            rows[name] = (labels, cells[2], cells[3])
        return rows

    def test_the_page_lists_every_name_with_its_help_line_and_grade(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        _, body, scrape = self.scrape()

        listed = self.documented()
        self.assertEqual(sorted(listed), scrape.names())
        for name, (labels, grade, words) in listed.items():
            self.assertEqual(scrape.help[name],
                             words + " (" + grade + ")", name)
            self.assertEqual(
                labels,
                tuple(sorted({key for metric, pairs in scrape.samples
                              if metric == name for key, _ in pairs})), name)

        # The label values are frozen exactly as the names are, so the
        # page names every value the route serves and the route serves
        # every value the page names. Without this, a state quietly
        # dropped from the code would pass the suite: no sample and no
        # test asks for one.
        values = self.documented_values()
        self.assertEqual(
            sorted(values),
            sorted({(metric, key) for metric, pairs in scrape.samples
                    for key, _ in pairs}))
        for (name, label), listed in values.items():
            self.assertEqual(
                listed,
                {value for metric, pairs in scrape.samples if metric == name
                 for key, value in pairs if key == label},
                name + "{" + label + "}")
            for value in listed:
                scrape.value(name, **{label: value})
        # What the operator needs beside the list: the loopback scrape
        # config, the one line about reaching it from another box, and
        # the freeze rule the names are worth nothing without.
        self.assertIn("scrape_configs", self.page())
        self.assertIn("127.0.0.1", self.page())
        self.assertIn("tunnel", self.page())
        self.assertIn("frozen", self.page())
        self.assertNotIn("push", body)


if __name__ == "__main__":
    unittest.main()
