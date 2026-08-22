"""Behavioral tests for the supervisor's one-shot scan (`supervisor.py scan`).

The supervisor is an operator that never sleeps (ADR-0005): it drives
receipts through the public CLI and judges nothing itself. These tests
drive only the supervisor's own public surface — `scan` with its JSON
output and exit code — against real chains built through the receipts
CLI in temp directories. No mocks, no internals.
"""

import base64
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECEIPTS = REPO_ROOT / "receipts.py"

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")


def ots_varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | 0x80 if n else byte)
        if not n:
            return bytes(out)


def chain_head(log):
    return subprocess.run(
        [sys.executable, str(RECEIPTS), "head", "--log", str(log)],
        capture_output=True, text=True, check=True).stdout.strip()


def write_completed_anchor(log, head, height=850000):
    """A minimal but genuine OTS timestamp: one sha256 op, then a Bitcoin
    attestation — enough for `verify --anchors` to replay offline and
    report ANCHORED, with no network and no calendar (ANCHORING.md §4)."""
    payload = ots_varint(height)
    proof = (b"\x08"
             + b"\x00" + TAG_BITCOIN + ots_varint(len(payload)) + payload)
    record = {"head": head, "n": 2, "ts": "2026-08-22T09:00:00Z",
              "calendar": "https://calendar.example.test",
              "proof": base64.b64encode(proof).decode()}
    Path(str(log) + ".anchors.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8")


def run_scan(root, *extra, env=None):
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "scan", "--root", str(root),
         "--json", *extra],
        capture_output=True, text=True, env=env)


def make_chain(log_dir, session, entries=2):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the supervisor is tested against what the tool writes."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"receipts-{session}.jsonl"
    subprocess.run([sys.executable, str(RECEIPTS), "init", "--log", str(log)],
                   capture_output=True, check=True)
    for i in range(entries):
        subprocess.run(
            [sys.executable, str(RECEIPTS), "log", "--log", str(log),
             "--actor", "claude-code", "--action", f"step {i}"],
            capture_output=True, check=True)
    return log


def chains_by_session(report):
    """{(repo, session): [chain, ...]} — flattens the grouping for
    assertions while leaving the grouping itself observable."""
    return {(repo["repo"], sess["session"]): sess["chains"]
            for repo in report["repos"] for sess in repo["sessions"]}


class ScanCensusTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_scan_reports_a_chain_with_its_verdict_as_json(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        sessions = chains_by_session(report)
        self.assertIn(("alpha", "sess-aaaa"), sessions)
        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "VALID")
        self.assertEqual(chain["entries"], 4)  # genesis + 3

    def test_scan_finds_chains_across_repos_and_in_the_root_itself(self):
        # History has shapes: sibling repos each with a receipts/, and the
        # root itself being a repo with its own.
        make_chain(self.root / "receipts", "sess-root")
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertIn(("alpha", "sess-aaaa"), sessions)
        self.assertIn(("beta", "sess-bbbb"), sessions)
        self.assertIn((self.root.name, "sess-root"), sessions)

    def test_sibling_chains_group_under_one_session(self):
        # A sibling is continuation by naming (ADR-0004): one session, one
        # story, even after tail damage moved the recording to -002.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002")

        result = run_scan(self.root)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertNotIn(("alpha", "sess-aaaa-002"), sessions,
                         "a sibling is not its own session")
        chains = sessions[("alpha", "sess-aaaa")]
        self.assertEqual([Path(c["log"]).name for c in chains],
                         ["receipts-sess-aaaa.jsonl",
                          "receipts-sess-aaaa-002.jsonl"])

    def test_anchor_sidecars_are_not_chains(self):
        # A sidecar is a proof *about* a chain, not a chain: it gets no
        # row of its own. (A real record, because the scan now judges
        # sidecar contents — malformed evidence would rightly shout.)
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stdout)
        sessions = chains_by_session(json.loads(result.stdout))
        self.assertEqual(len(sessions), 1)
        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertNotIn(".anchors", chain["log"])

    def test_a_chain_recorded_from_a_worktree_appears_under_its_main_repo(self):
        # Sessions that ran before the hook learned to log to the main repo
        # left chains inside .claude/worktrees/<name>/receipts/. Still real
        # history; worktree hygiene must never orphan it in the views.
        make_chain(
            self.root / "alpha" / ".claude" / "worktrees" / "wt" / "receipts",
            "sess-stranded")

        result = run_scan(self.root)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertIn(("alpha", "sess-stranded"), sessions)
        (chain,) = sessions[("alpha", "sess-stranded")]
        self.assertTrue(chain["worktree"],
                        "strandedness is evidence — say so")

    def test_an_empty_root_is_a_clean_scan(self):
        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["repos"], [])
        self.assertEqual(report["exit"], 0)

    def test_scan_without_json_flag_is_still_parseable(self):
        # One shape, two dressings: --json is compact for machines, the
        # default pretty-prints for eyes — both parse identically.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        machine = run_scan(self.root)
        human = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--root", str(self.root)],
            capture_output=True, text=True)

        self.assertEqual(human.returncode, 0, human.stderr)
        self.assertEqual(json.loads(human.stdout), json.loads(machine.stdout))


class ScanVerdictTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def tamper(self, log):
        lines = log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["action"] = "something else entirely"
        lines[1] = json.dumps(entry)
        log.write_text("".join(l + "\n" for l in lines), encoding="utf-8")

    def tear(self, log):
        with open(log, "a", encoding="utf-8", newline="\n") as f:
            f.write('{"n":3,"half-written')

    def test_a_tampered_chain_shouts_and_never_blanks_the_rest(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.tamper(log)
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root)

        self.assertNotEqual(result.returncode, 0)
        sessions = chains_by_session(json.loads(result.stdout))
        (bad,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(bad["verdict"], "BROKEN")
        (good,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(good["verdict"], "VALID",
                         "one bad chain never blanks the scan")

    def test_a_superseded_torn_tail_stays_visible_but_stands_down(self):
        # ADR-0004 working as designed: the tear ended a chain, not the
        # recording. Failing the exit code forever over handled history is
        # an alarm that never stops sounding — the dogfood's lesson.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.tear(log)
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002")

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stdout)
        sessions = chains_by_session(json.loads(result.stdout))
        torn, healthy = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(torn["verdict"], "BROKEN",
                         "the tear stays visible as evidence")
        self.assertTrue(torn["superseded"])
        self.assertIn("torn tail", " ".join(torn["detail"]))
        self.assertFalse(healthy["superseded"])

    def test_a_torn_tail_with_no_sibling_still_fails_the_exit_code(self):
        # No sibling means recording did NOT continue — a live fault, not
        # handled history.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.tear(log)

        result = run_scan(self.root)

        self.assertNotEqual(result.returncode, 0)

    def test_a_tampered_chain_shouts_even_with_a_sibling_beside_it(self):
        # Only the honest damage pattern stands down. A rewritten past
        # entry is tampering wherever the recording moved afterwards.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.tamper(log)
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002")

        result = run_scan(self.root)

        self.assertNotEqual(result.returncode, 0)

    def test_a_foreign_versioned_chain_is_reported_as_a_refusal(self):
        # UNSUPPORTED-VERSION is a refusal to judge, not a verdict — but a
        # chain nobody can judge still demands the operator's attention.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        lines = log.read_text(encoding="utf-8").splitlines()
        genesis = json.loads(lines[0])
        genesis["v"] = "receipts/v99"
        lines[0] = json.dumps(genesis)
        log.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root)

        self.assertNotEqual(result.returncode, 0)
        sessions = chains_by_session(json.loads(result.stdout))
        (foreign,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(foreign["verdict"], "UNSUPPORTED-VERSION")
        (good,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(good["verdict"], "VALID")

    def test_a_chain_verify_cannot_judge_at_all_is_still_reported(self):
        # An empty file draws an error, not a verdict line. The scan says
        # so — NO-VERDICT, verify's own words as detail — and shouts,
        # because a chain nobody can judge is not a chain in good standing.
        empty = self.root / "alpha" / "receipts" / "receipts-sess-hollow.jsonl"
        empty.parent.mkdir(parents=True)
        empty.write_text("", encoding="utf-8")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root)

        self.assertNotEqual(result.returncode, 0)
        sessions = chains_by_session(json.loads(result.stdout))
        (hollow,) = sessions[("alpha", "sess-hollow")]
        self.assertEqual(hollow["verdict"], "NO-VERDICT")
        self.assertTrue(hollow["detail"], "verify's refusal is the evidence")
        (good,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(good["verdict"], "VALID")


class ScanAnchorTest(unittest.TestCase):
    """The scan judges anchors too: VALID and ANCHORED are different
    claims (ADR-0002), and an anchor that contradicts the log is the
    exit-3 tier — "this is not the recorded history"."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_an_anchored_chain_is_a_distinct_claim_not_just_valid(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (anchored,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(anchored["verdict"], "VALID")
        self.assertTrue(anchored["anchored"])
        self.assertTrue(any(l.startswith("ANCHORED") for l in
                            anchored["detail"]),
                        "the anchor's own words are the evidence")
        (plain,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(plain["verdict"], "VALID")
        self.assertFalse(plain["anchored"],
                         "unanchored VALID must never borrow the claim")

    def test_a_regenerated_chain_fails_the_scan_at_the_gravest_tier(self):
        # The adversary's best move: rewrite history wholesale. The fresh
        # chain is internally valid; only the anchor remembers.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))
        log.unlink()
        # One entry fewer: rewritten history must actually differ, or a
        # same-second rebuild reproduces the old head and the anchor
        # rightly (and confusingly) still matches.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=1)

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (regenerated,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(regenerated["verdict"], "ANCHOR-MISMATCH")
        self.assertEqual(regenerated["exit"], 3)
        self.assertFalse(regenerated["anchored"])


class BaselineTest(unittest.TestCase):
    """The tripwire's memory (GLOSSARY: Baseline): heads remembered
    between looks, diffed each tick. Growth an append can explain is
    normal; anything else is a change event — a reason to investigate,
    never a verdict about which side is true."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.baseline = self.root / ".supervisor-baseline.json"

    def events(self, result):
        return json.loads(result.stdout)["baseline"]["events"]

    def test_appends_between_ticks_raise_no_alarm(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        first = run_scan(self.root)  # cold start seeds silently
        subprocess.run(
            [sys.executable, str(RECEIPTS), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "one more step"],
            capture_output=True, check=True)

        second = run_scan(self.root)

        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(self.events(first), [], "cold start is silent")
        self.assertEqual(second.returncode, 0,
                         second.stdout + second.stderr)
        self.assertEqual(self.events(second), [],
                         "growth an append can explain is normal")

    def test_a_regenerated_chain_between_ticks_trips_the_wire(self):
        # The tripwire's whole reason to exist: a regenerated chain with
        # no anchor still verifies VALID — only the memory of the last
        # look notices.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root)
        log.unlink()
        subprocess.run([sys.executable, str(RECEIPTS), "init",
                        "--log", str(log)], capture_output=True, check=True)
        subprocess.run(
            [sys.executable, str(RECEIPTS), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "innocent-looking work"],
            capture_output=True, check=True)
        subprocess.run(
            [sys.executable, str(RECEIPTS), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "nothing to see here"],
            capture_output=True, check=True)

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        (event,) = report["baseline"]["events"]
        self.assertEqual(event["change"], "rewritten")
        self.assertEqual(event["repo"], "alpha")
        self.assertEqual(event["session"], "sess-aaaa")
        sessions = chains_by_session(report)
        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "VALID",
                         "the verdict machinery sees nothing — that is "
                         "why the tripwire exists")

    def test_a_shortened_chain_regresses_and_a_deleted_chain_vanishes(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        gone = make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        run_scan(self.root)
        lines = log.read_text(encoding="utf-8").splitlines()
        log.write_text("".join(l + "\n" for l in lines[:-1]),
                       encoding="utf-8")  # still a VALID, shorter chain
        gone.unlink()

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        changes = {e["session"]: e["change"] for e in self.events(result)}
        self.assertEqual(changes, {"sess-aaaa": "regressed",
                                   "sess-bbbb": "vanished"})

    def test_alarm_language_investigates_and_never_claims_a_verdict(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root)
        lines = log.read_text(encoding="utf-8").splitlines()
        log.write_text("".join(l + "\n" for l in lines[:-1]),
                       encoding="utf-8")

        result = run_scan(self.root)

        baseline_words = json.dumps(
            json.loads(result.stdout)["baseline"]).lower()
        self.assertIn("investigate", baseline_words)
        self.assertNotIn("head record", baseline_words,
                         "the baseline is never called a head record")

    def test_the_baseline_updates_each_tick_so_one_change_shouts_once(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root)
        lines = log.read_text(encoding="utf-8").splitlines()
        log.write_text("".join(l + "\n" for l in lines[:-1]),
                       encoding="utf-8")
        caught = run_scan(self.root)

        settled = run_scan(self.root)

        self.assertEqual(caught.returncode, 5)
        self.assertEqual(settled.returncode, 0,
                         settled.stdout + settled.stderr)
        self.assertEqual(self.events(settled), [],
                         "remembered anew after diffing — the alarm "
                         "belongs to the tick that caught it")

    def test_a_corrupt_baseline_is_reported_never_trusted(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root)
        self.baseline.write_text("{not json at all", encoding="utf-8")

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("could not be read",
                      report["baseline"].get("note", ""))
        self.assertEqual(report["baseline"]["events"], [])
        after = run_scan(self.root)
        self.assertNotIn("note", json.loads(after.stdout)["baseline"],
                         "remembering resumes from the fresh look")


def munge(path):
    """A project path the way the harness names its transcript folder:
    every character that isn't a letter, digit, or dash becomes a dash."""
    return re.sub(r"[^A-Za-z0-9-]", "-", str(path))


def ago(seconds):
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=seconds)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_transcript(witness, project, session, event_times=(),
                     error_times=(), chatter=0, idle=0):
    """A synthetic harness transcript: tool-result lines (the witness
    signal), failed tool results (excluded — the hook never fires for
    them), and plain chatter lines (never counted)."""
    folder = witness / munge(project)
    folder.mkdir(parents=True, exist_ok=True)
    lines = []
    for ts in event_times:
        lines.append({"type": "user", "timestamp": ts,
                      "toolUseResult": {"stdout": "ok"}})
    for ts in error_times:
        lines.append({"type": "user", "timestamp": ts,
                      "toolUseResult": {"is_error": True}})
    for _ in range(chatter):
        lines.append({"type": "assistant", "timestamp": ago(10),
                      "message": "just talk"})
    transcript = folder / f"{session}.jsonl"
    transcript.write_text(
        "".join(json.dumps(line) + "\n" for line in lines),
        encoding="utf-8")
    if idle:
        quiet_since = time.time() - idle
        os.utime(transcript, (quiet_since, quiet_since))
    return transcript


class CompletenessTest(unittest.TestCase):
    """The flagship (issue #22): the ratified alarm state machine over
    the liveness witness — shouting when a session is demonstrably
    active but its chain is silent, and staying honest about what that
    claim is (accident detection and latency, nothing more)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name) / "witness"

    def scan(self, *extra, env=None):
        return run_scan(self.root, "--witness", str(self.witness),
                        *extra, env=env)

    def states(self, result):
        report = json.loads(result.stdout)
        return {s["session"]: s
                for s in report["completeness"]["sessions"]}

    def test_the_silent_fork_alarms_while_the_chain_verifies_valid(self):
        # The flagship case, from the field (2026-08-14): witness saw 8
        # tools, the chain holds 6 receipts and verifies VALID — entries
        # are missing and no verdict can say so. Only the pairing can.
        make_chain(self.root / "alpha" / "receipts", "sess-fork", entries=6)
        write_transcript(self.witness, self.root / "alpha", "sess-fork",
                         event_times=[ago(180 - 10 * i) for i in range(8)])

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        watched = self.states(result)["sess-fork"]
        self.assertEqual(watched["state"], "ALARM-DEFICIT")
        self.assertEqual(watched["tools"], 8)
        self.assertEqual(watched["receipts"], 6)
        self.assertEqual(watched["deficit"], 2)
        sessions = chains_by_session(report)
        (chain,) = sessions[("alpha", "sess-fork")]
        self.assertEqual(chain["verdict"], "VALID",
                         "the hole is invisible to every verdict")

    def test_a_hook_disabled_from_the_start_leaves_no_chain_yet_alarms(self):
        # No chain exists at all — the census alone would never notice.
        write_transcript(self.witness, self.root / "beta", "sess-ghost",
                         event_times=[ago(120), ago(110), ago(100)])

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        ghost = self.states(result)["sess-ghost"]
        self.assertEqual(ghost["state"], "ALARM-SILENT")
        self.assertEqual(ghost["receipts"], 0)

    def test_a_wedged_lock_mid_session_reads_silent_not_deficit(self):
        # Receipts flowed, then stopped while tools kept running: no
        # receipt since the deficit began. (Grace pinned to zero via the
        # env knob — the test suite's clock handle.)
        make_chain(self.root / "alpha" / "receipts", "sess-wedge",
                   entries=2)
        time.sleep(1.2)
        write_transcript(self.witness, self.root / "alpha", "sess-wedge",
                         event_times=[ago(300), ago(290),
                                      ago(0), ago(0), ago(0)])

        result = self.scan(env={**os.environ,
                                "SUPERVISOR_GRACE_SECONDS": "0"})

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        wedged = self.states(result)["sess-wedge"]
        self.assertEqual(wedged["state"], "ALARM-SILENT")

    def test_sibling_continuation_is_ok_and_sibling_genesis_not_counted(self):
        make_chain(self.root / "alpha" / "receipts", "sess-sib", entries=2)
        make_chain(self.root / "alpha" / "receipts", "sess-sib-002",
                   entries=1)
        write_transcript(self.witness, self.root / "alpha", "sess-sib",
                         event_times=[ago(300), ago(290), ago(280)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        story = self.states(result)["sess-sib"]
        self.assertEqual(story["state"], "OK")
        self.assertEqual(story["receipts"], 3,
                         "family counted, administrative geneses not")

    def test_chat_only_and_failed_tools_never_alarm(self):
        # A chat-only session expects nothing; a failed tool call fires
        # no hook (the field's suppression finding), so it is owed no
        # receipt and must not create a deficit.
        write_transcript(self.witness, self.root / "alpha", "sess-chat",
                         error_times=[ago(60), ago(50)], chatter=5)

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chat = self.states(result)["sess-chat"]
        self.assertEqual(chat["state"], "QUIET")
        self.assertEqual(chat["tools"], 0)

    def test_a_clean_end_clears_cleanly(self):
        make_chain(self.root / "alpha" / "receipts", "sess-done", entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-done",
                         event_times=[ago(7200), ago(7100)], idle=7000)

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.states(result)["sess-done"]["state"],
                         "ENDED-CLEAN")

    def test_an_ended_deficit_is_evidence_not_a_live_alarm(self):
        # Missing forever: reported so the operator sees it, but never a
        # siren that sounds for the rest of time (the dogfood's lesson).
        make_chain(self.root / "alpha" / "receipts", "sess-lost", entries=1)
        write_transcript(self.witness, self.root / "alpha", "sess-lost",
                         event_times=[ago(7200), ago(7100), ago(7000)],
                         idle=6900)

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lost = self.states(result)["sess-lost"]
        self.assertEqual(lost["state"], "ENDED-DEFICIT")
        self.assertIn("evidence", lost["words"])

    def test_a_deficit_inside_the_grace_window_only_lags(self):
        # An honest lock wait must never alarm: 30 seconds of grace.
        make_chain(self.root / "alpha" / "receipts", "sess-lag", entries=1)
        write_transcript(self.witness, self.root / "alpha", "sess-lag",
                         event_times=[ago(300), ago(2)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.states(result)["sess-lag"]["state"],
                         "LAGGING")

    def test_surplus_is_an_investigate_flag_never_a_verdict(self):
        make_chain(self.root / "alpha" / "receipts", "sess-plus", entries=3)
        write_transcript(self.witness, self.root / "alpha", "sess-plus",
                         event_times=[ago(60)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        plus = self.states(result)["sess-plus"]
        self.assertEqual(plus["state"], "SURPLUS")
        self.assertIn("investigate", plus["words"])

    def test_an_absent_witness_is_reported_never_guessed_at(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = self.scan()  # self.witness was never created

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("witness absent", report["completeness"]["note"])
        self.assertEqual(self.states(result)["sess-aaaa"]["state"],
                         "UNWITNESSED")

    def test_alarm_language_claims_detection_never_more(self):
        write_transcript(self.witness, self.root / "alpha", "sess-ghost",
                         event_times=[ago(120), ago(110)])

        result = self.scan()

        words = json.dumps(
            json.loads(result.stdout)["completeness"]).lower()
        self.assertIn("accident", words)
        for overclaim in ("prevent", "guarantee", "complete record"):
            self.assertNotIn(overclaim, words)


if __name__ == "__main__":
    unittest.main()
