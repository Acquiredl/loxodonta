"""Behavioral tests for the supervisor's one-shot scan (`supervisor.py scan`).

The supervisor is an operator that never sleeps (ADR-0005): it drives
receipts through the public CLI and judges nothing itself. These tests
drive only the supervisor's own public surface — `scan` with its JSON
output and exit code — against real chains built through the receipts
CLI in temp directories. No mocks, no internals.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECEIPTS = REPO_ROOT / "receipts.py"


def run_scan(root, *extra):
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "scan", "--root", str(root),
         "--json", *extra],
        capture_output=True, text=True)


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
        # A sidecar is a proof *about* a chain, not a chain: it gets no row.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        Path(str(log) + ".anchors.jsonl").write_text("{}\n", encoding="utf-8")

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


if __name__ == "__main__":
    unittest.main()
