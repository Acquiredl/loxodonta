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
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
LOXODONTA = REPO_ROOT / "loxodonta.py"

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")


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
        [sys.executable, str(LOXODONTA), "head", "--log", str(log)],
        capture_output=True, encoding="utf-8", check=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}).stdout.strip()


def ots_varbytes(b):
    return ots_varint(len(b)) + b


def write_pending_anchor(log, head, submitted,
                         calendar="http://127.0.0.1:1"):
    """A genuine pending OTS record whose calendar (by default) refuses
    connections instantly — the keeper's attempt fails fast, offline."""
    proof = (b"\x00" + TAG_PENDING
             + ots_varbytes(ots_varbytes(calendar.encode())))
    record = {"head": head, "n": 2, "ts": submitted, "calendar": calendar,
              "proof": base64.b64encode(proof).decode()}
    Path(str(log) + ".anchors.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8")


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
    # Pin both ends of the pipe to UTF-8 (PYTHONIOENCODING for the child,
    # encoding= for this parent): `text=True` alone decodes with the locale
    # codec — cp1252 on Windows — and crashes on a UTF-8-emitting child.
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "scan", "--root", str(root),
         "--json", *extra],
        capture_output=True, encoding="utf-8",
        env={**(os.environ if env is None else env),
             "PYTHONIOENCODING": "utf-8"})


def make_chain(log_dir, session, entries=2, action="step {i}"):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the supervisor is tested against what the tool writes."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"receipts-{session}.jsonl"
    subprocess.run([sys.executable, str(LOXODONTA), "init", "--log", str(log)],
                   capture_output=True, check=True)
    for i in range(entries):
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", action.format(i=i)],
            capture_output=True, check=True)
    return log


def chains_by_session(report):
    """{(repo, session): [chain, ...]} — flattens the grouping for
    assertions while leaving the grouping itself observable."""
    return {(repo["repo"], sess["session"]): sess["chains"]
            for repo in report["repos"] for sess in repo["sessions"]}


def run_store_scan(store_home, witness, *extra, env=None):
    """`scan` with no --root: the store is the default universe
    (ADR-0011), reached through LOXODONTA_HOME. The witness is always
    pinned — store mode watches every transcript on the machine, so an
    unpinned test would read the developer's real sessions."""
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "scan", "--json",
         "--witness", str(witness), *extra],
        capture_output=True, encoding="utf-8",
        env={**(os.environ if env is None else env),
             "PYTHONIOENCODING": "utf-8",
             "LOXODONTA_HOME": str(store_home)})


class StoreScanTest(unittest.TestCase):
    """The census over the central store. Drawers are laid out by hand —
    the scan never recomputes slugs, it reads what the store holds, so
    these tests own the layout the same way the writer does."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name) / "storehome"
        self.witness = Path(self._tmp.name) / "no-witness"
        self.witness.mkdir()

    def drawer(self, slug, project_path):
        d = self.home / "receipts" / slug
        d.mkdir(parents=True, exist_ok=True)
        (d / "project.json").write_text(
            json.dumps({"path": str(project_path)}), encoding="utf-8")
        return d

    def test_scan_with_no_root_sweeps_the_store(self):
        alpha = self.drawer("alpha-11111111", r"C:\work\alpha")
        beta = self.drawer("beta-22222222", r"C:\work\beta")
        make_chain(alpha, "sess-aaaa", entries=3)
        make_chain(beta, "sess-bbbb")

        result = run_store_scan(self.home, self.witness)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        sessions = chains_by_session(report)
        self.assertIn(("alpha", "sess-aaaa"), sessions)
        self.assertIn(("beta", "sess-bbbb"), sessions)
        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "VALID")
        self.assertEqual(chain["entries"], 4)

    def test_store_scan_keeps_its_baseline_beside_the_store(self):
        drawer = self.drawer("alpha-11111111", r"C:\work\alpha")
        make_chain(drawer, "sess-aaaa")

        run_store_scan(self.home, self.witness)

        self.assertTrue((self.home / "baseline.json").exists(),
                        "one baseline per machine, beside the store — "
                        "not inside it (ADR-0011)")

    def test_empty_store_scan_is_a_note_not_an_error(self):
        result = run_store_scan(self.home, self.witness)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["repos"], [])
        self.assertIn("install-hook", json.dumps(report),
                      "an empty store tells the newcomer what wires it")

    def test_drawer_without_record_still_scans_under_its_slug(self):
        # A hand-made or damaged drawer (no project.json) is still
        # someone's history: censused under the drawer's own name.
        drawer = self.home / "receipts" / "mystery-33333333"
        drawer.mkdir(parents=True)
        make_chain(drawer, "sess-cccc")

        result = run_store_scan(self.home, self.witness)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertIn(("mystery-33333333", "sess-cccc"), sessions)


def run_adopt(store_home, root, *extra):
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "adopt", "--root", str(root),
         *extra],
        capture_output=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8",
             "LOXODONTA_HOME": str(store_home)})


class AdoptTest(unittest.TestCase):
    """`supervisor adopt` (ADR-0011): the one-time move of legacy chains
    into the store. Move not copy, sidecars and .unlisted travel,
    nothing is ever overwritten, running it twice is a no-op."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repos"
        self.root.mkdir()
        self.home = Path(self._tmp.name) / "storehome"

    def drawers(self):
        receipts = self.home / "receipts"
        return sorted(p.name for p in receipts.iterdir()) \
            if receipts.is_dir() else []

    def test_adopt_moves_chains_sidecars_and_unlisted_into_drawers(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))
        (self.root / "alpha" / "receipts" / ".unlisted").write_text(
            "", encoding="utf-8")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_adopt(self.home, self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = self.drawers()
        self.assertEqual(len(names), 2, names)
        alpha = next(self.home / "receipts" / n for n in names
                     if n.startswith("alpha-"))
        self.assertTrue((alpha / "receipts-sess-aaaa.jsonl").exists())
        self.assertTrue(
            (alpha / "receipts-sess-aaaa.jsonl.anchors.jsonl").exists(),
            "the proof travels with its chain")
        self.assertTrue((alpha / ".unlisted").exists())
        record = json.loads((alpha / "project.json").read_text(
            encoding="utf-8"))
        self.assertEqual(Path(record["path"]).resolve(),
                         (self.root / "alpha").resolve())
        self.assertFalse(
            list((self.root / "alpha" / "receipts").glob("*.jsonl")),
            "moved, not copied — two copies of evidence is worse than one")

    def test_adopt_resolves_stranded_worktree_chains_to_the_main_repo(self):
        make_chain(self.root / "alpha" / ".claude" / "worktrees" / "wt"
                   / "receipts", "sess-stranded")

        result = run_adopt(self.home, self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (name,) = self.drawers()
        self.assertTrue(name.startswith("alpha-"), name)

    def test_adopt_never_overwrites_and_reports_the_refusal(self):
        # The same session name already in the drawer: evidence is never
        # clobbered by housekeeping.
        legacy = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        before = legacy.read_bytes()
        first = run_adopt(self.home, self.root)
        self.assertEqual(first.returncode, 0, first.stderr)
        # Forge a *different* chain under the same name back in the
        # legacy spot.
        clash = make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                           entries=5)

        result = run_adopt(self.home, self.root)

        self.assertNotEqual(before, clash.read_bytes())
        self.assertIn("refus", result.stdout.lower())
        self.assertTrue(clash.exists(), "the refused chain stays put")
        (name,) = self.drawers()
        adopted = (self.home / "receipts" / name
                   / "receipts-sess-aaaa.jsonl")
        self.assertEqual(adopted.read_bytes(), before,
                         "the adopted copy is untouched by the clash")

    def test_adopt_reports_a_sidecar_it_must_leave_behind(self):
        # A sidecar whose name is already taken in the drawer cannot
        # travel. Leaving proofs behind must be said, not silent —
        # everything else adopt refuses gets a printed word.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_adopt(self.home, self.root)
        (name,) = self.drawers()
        stranded = make_chain(self.root / "alpha" / "receipts",
                              "sess-cccc")
        write_completed_anchor(stranded, chain_head(stranded))
        squatter = (self.home / "receipts" / name
                    / "receipts-sess-cccc.jsonl.anchors.jsonl")
        squatter.write_text("{}\n", encoding="utf-8")

        result = run_adopt(self.home, self.root)

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        legacy_sidecar = (self.root / "alpha" / "receipts"
                         / "receipts-sess-cccc.jsonl.anchors.jsonl")
        self.assertTrue(legacy_sidecar.exists(),
                        "the refused sidecar stays put")
        self.assertIn("sidecar", result.stdout.lower())
        self.assertEqual(squatter.read_text(encoding="utf-8"), "{}\n",
                         "the store copy is untouched")

    def test_adopt_twice_is_a_quiet_no_op(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_adopt(self.home, self.root)

        again = run_adopt(self.home, self.root)

        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn("nothing to adopt", again.stdout.lower())

    def test_dry_run_plans_and_moves_nothing(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_adopt(self.home, self.root, "--dry-run")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("sess-aaaa", result.stdout)
        self.assertTrue(log.exists(), "dry-run moves nothing")
        self.assertEqual(self.drawers(), [])

    def test_adopted_chains_are_scanned_and_recalled(self):
        # The move is an end-to-end success only if the store's readers
        # pick the history up where it landed.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                   entries=3)
        run_adopt(self.home, self.root)
        witness = Path(self._tmp.name) / "no-witness"
        witness.mkdir()

        result = run_store_scan(self.home, witness)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertIn(("alpha", "sess-aaaa"), sessions)
        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "VALID")


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
            capture_output=True, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})

        def shape(text):
            # Two runs are two moments, and the scan stamps itself: the
            # claim under test is that the dressing changes and nothing
            # else does.
            report = json.loads(text)
            report.pop("scanned")
            return report

        self.assertEqual(human.returncode, 0, human.stderr)
        self.assertEqual(shape(human.stdout), shape(machine.stdout))


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
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
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
        subprocess.run([sys.executable, str(LOXODONTA), "init",
                        "--log", str(log)], capture_output=True, check=True)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "innocent-looking work"],
            capture_output=True, check=True)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
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


def install_witness_hook(witness, matcher="Edit|Write|NotebookEdit|Bash",
                         command="python loxodonta.py hook"):
    """The harness settings beside the witness layout, wiring a receipts
    PostToolUse hook for the given tools — what tells the watch which
    tool events owe a receipt. `command` is the wired command line, the
    seam the recorder-drift notice reads to find the executed file."""
    witness.mkdir(parents=True, exist_ok=True)
    (witness.parent / "settings.json").write_text(json.dumps({
        "hooks": {"PostToolUse": [{"matcher": matcher, "hooks": [
            {"type": "command", "command": command},
        ]}]},
    }), encoding="utf-8")


def write_transcript(witness, project, session, event_times=(),
                     error_times=(), chatter=0, idle=0, tool="Bash"):
    """A synthetic harness transcript shaped like the real one: each
    tool event is a tool_use block (carrying the tool's name) paired by
    id with a tool-result line (the witness signal). Failed results are
    excluded by the watch — the hook never fires for them — and plain
    chatter lines are never counted."""
    folder = witness / munge(project)
    folder.mkdir(parents=True, exist_ok=True)
    lines = []

    def event(i, ts, name, failed):
        use_id = f"tu_{session}_{i}"
        lines.append({"type": "assistant", "timestamp": ts, "message": {
            "content": [{"type": "tool_use", "id": use_id, "name": name}],
        }})
        # Failure as the harness really writes it (field capture,
        # 2026-08-29): toolUseResult collapses to a plain string and
        # the error flag sits on the tool_result block, not the result.
        result = "Error: Exit code 1\nboom" if failed else {"stdout": "ok"}
        block = {"type": "tool_result", "tool_use_id": use_id}
        if failed:
            block["is_error"] = True
        lines.append({"type": "user", "timestamp": ts,
                      "toolUseResult": result, "message": {
                          "content": [block]}})

    for i, ts in enumerate(event_times):
        event(i, ts, tool if isinstance(tool, str) else tool[i], False)
    for i, ts in enumerate(error_times):
        event(1000 + i, ts, tool if isinstance(tool, str) else "Bash",
              True)
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


class DaybookTest(unittest.TestCase):
    """The day book (GLOSSARY: Day book): one row per UTC day, so the
    page can answer the third question a monitoring surface owes its
    operator — is this a trend or a one-off? Testimony like the
    baseline beside it: writer-reachable, trusted for nothing."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.daybook = self.root / ".supervisor-daybook.json"

    def rows(self, result):
        return json.loads(result.stdout)["history"]

    def today(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d")

    def test_a_scan_writes_the_day_it_looked(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertTrue(self.daybook.is_file(), "the day book is written")
        book = json.loads(self.daybook.read_text(encoding="utf-8"))
        self.assertIn("trusted for nothing", book["purpose"],
                      "the day book claims no more than the baseline does")
        row = book["days"][self.today()]
        self.assertEqual(row["worst"], 0)
        self.assertEqual(row["chains"], 1)
        self.assertEqual(row["scans"], 1)

    def test_the_window_is_fourteen_days_oldest_first(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        rows = self.rows(run_scan(self.root))

        self.assertEqual(len(rows), 14)
        self.assertEqual([r["day"] for r in rows],
                         sorted(r["day"] for r in rows),
                         "the band reads left to right, oldest first")
        self.assertEqual(rows[-1]["day"], self.today(), "today lands last")
        self.assertTrue(rows[-1]["watched"])

    def test_a_day_nobody_watched_is_a_gap_not_a_quiet_day(self):
        # The dead-end failure mode: detection latency is a function of
        # how often the operator looks, so an unwatched day must never
        # paint like a clean one.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root)

        rows = self.rows(run_scan(self.root))

        unwatched = [r for r in rows[:-1] if not r["watched"]]
        self.assertEqual(len(unwatched), 13,
                         "every day before today went unwatched")
        for row in unwatched:
            self.assertNotIn("worst", row,
                             "an unwatched day carries no claim at all")

    def test_a_days_worst_outlives_a_later_clean_scan(self):
        # "Was today clean?" is not "is it clean right now" — a tripwire
        # that fired this morning still colours the day this evening.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root)
        log.unlink()
        subprocess.run([sys.executable, str(LOXODONTA), "init",
                        "--log", str(log)], capture_output=True, check=True)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "step 0"],
            capture_output=True, check=True)
        tripped = run_scan(self.root)

        settled = run_scan(self.root)

        self.assertEqual(tripped.returncode, 5, tripped.stdout)
        self.assertEqual(settled.returncode, 0,
                         "the wire is quiet again on the next look")
        self.assertEqual(self.rows(settled)[-1]["worst"], 5,
                         "the day still remembers what fired in it")
        self.assertEqual(self.rows(settled)[-1]["events"], 1)

    def test_the_book_keeps_a_season_not_forever(self):
        stale = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=200)).strftime("%Y-%m-%d")
        recent = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(days=3)).strftime("%Y-%m-%d")
        self.daybook.write_text(json.dumps({
            "purpose": "seeded", "days": {
                stale: {"worst": 3, "scans": 1},
                recent: {"worst": 0, "scans": 1}}}), encoding="utf-8")
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        rows = self.rows(run_scan(self.root))

        kept = json.loads(self.daybook.read_text(encoding="utf-8"))["days"]
        self.assertNotIn(stale, kept, "the book forgets past its season")
        self.assertIn(recent, kept)
        watched = [r["day"] for r in rows if r["watched"]]
        self.assertIn(recent, watched, "a remembered day still paints")


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
        install_witness_hook(self.witness)

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

    def test_a_session_split_across_drawers_is_watched_once(self):
        # From the field (2026-08-30): a worktree session logs to the
        # main repo's drawer (ADR-0011) while the harness still names
        # the transcript after the worktree. Pairing each drawer with
        # the transcript separately charged the whole witness count to
        # one drawer and left the other UNWITNESSED — a 6-receipt hole
        # the operator never owed. The witness counts sessions, not
        # drawers.
        make_chain(self.root / "alpha" / "receipts", "sess-split",
                   entries=6)
        make_chain(self.root / "alpha-wt" / "receipts", "sess-split",
                   entries=2)
        write_transcript(self.witness, self.root / "alpha-wt", "sess-split",
                         event_times=[ago(300 - 10 * i) for i in range(8)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [s for s in json.loads(result.stdout)["completeness"]["sessions"]
                if s["session"] == "sess-split"]
        self.assertEqual(len(rows), 1, "one session, one watch")
        (split,) = rows
        self.assertEqual(split["receipts"], 8, "both drawers counted")
        self.assertEqual(split["tools"], 8)
        self.assertEqual(split["deficit"], 0)
        self.assertEqual(split["state"], "OK")
        self.assertEqual(split["repo"], "alpha",
                         "home is the drawer holding most of it — the "
                         "worktree gets pruned, the repo's drawer stays")
        self.assertEqual(split["drawers"], ["alpha", "alpha-wt"],
                         "the span stays visible, never silently merged")

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

    def test_a_failed_call_among_successes_owes_no_receipt(self):
        # The calibration finding, live (2026-08-29): three commands
        # succeeded and were receipted, one failed and fired no hook.
        # The failure is witnessed in the transcript but owes nothing —
        # counting it manufactures a phantom deficit that never clears.
        make_chain(self.root / "alpha" / "receipts", "sess-mixed",
                   entries=3)
        write_transcript(self.witness, self.root / "alpha", "sess-mixed",
                         event_times=[ago(180), ago(170), ago(160)],
                         error_times=[ago(165)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        mixed = self.states(result)["sess-mixed"]
        self.assertEqual(mixed["tools"], 3)
        self.assertEqual(mixed["deficit"], 0)

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

    def test_a_surplus_at_session_end_is_remembered_not_forgiven(self):
        # Live, a surplus is an investigate flag; ending the session must
        # not quietly turn it into ENDED-CLEAN. Receipts nobody witnessed
        # are evidence too (walk finding, 2026-08-31).
        make_chain(self.root / "alpha" / "receipts", "sess-eplus",
                   entries=3)
        write_transcript(self.witness, self.root / "alpha", "sess-eplus",
                         event_times=[ago(7200)], idle=7000)

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        plus = self.states(result)["sess-eplus"]
        self.assertEqual(plus["state"], "ENDED-SURPLUS")
        self.assertIn("evidence", plus["words"])

    def test_bookkeeping_entries_never_count_as_receipts(self):
        # ADR-0017: a transcript commitment is the recorder's own voice
        # (actor "receipts", like genesis) — an entry no tool event owes.
        # Counting it would manufacture SURPLUS on every committed
        # session: a machine-wide self-inflicted false scar.
        log = make_chain(self.root / "alpha" / "receipts", "sess-mark",
                         entries=2)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "receipts", "--action",
             "transcript-commitment: bytes=9 sha256=" + "0" * 64],
            capture_output=True, check=True)
        write_transcript(self.witness, self.root / "alpha", "sess-mark",
                         event_times=[ago(120), ago(60)])

        result = self.scan()

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        watched = self.states(result)["sess-mark"]
        self.assertEqual(watched["state"], "OK")
        self.assertEqual(watched["receipts"], 2)

    def test_an_absent_witness_is_reported_never_guessed_at(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        nowhere = Path(self._tmp.name) / "no-such-layout" / "projects"

        result = run_scan(self.root, "--witness", str(nowhere))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("witness absent", report["completeness"]["note"])
        self.assertEqual(self.states(result)["sess-aaaa"]["state"],
                         "UNWITNESSED")

    def test_tools_the_hook_never_records_owe_no_receipts(self):
        # The calibration finding: an all-tools witness over an
        # Edit|Write|Bash hook manufactures deficits. Reads and browser
        # tools were witnessed, but the recorder was never asked to
        # record them — only matched tools count.
        make_chain(self.root / "alpha" / "receipts", "sess-mixed",
                   entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-mixed",
                         event_times=[ago(300), ago(290), ago(280),
                                      ago(270), ago(260)],
                         tool=["Read", "Grep", "Bash", "Edit",
                               "mcp__browser__computer"])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        watched = self.states(result)["sess-mixed"]
        self.assertEqual(watched["tools"], 2,
                         "only Bash and Edit owed a receipt")
        self.assertEqual(watched["state"], "OK")

    def test_no_wired_hook_means_nothing_owes_a_receipt(self):
        # A machine without the receipts hook has sessions that owe
        # nothing — expecting receipts there would alarm forever.
        (self.witness.parent / "settings.json").unlink()
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_transcript(self.witness, self.root / "alpha", "sess-aaaa",
                         event_times=[ago(300), ago(290)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("no recorder hook", report["completeness"]["note"])
        self.assertEqual(self.states(result)["sess-aaaa"]["state"],
                         "UNWATCHED")

    def test_alarm_language_claims_detection_never_more(self):
        write_transcript(self.witness, self.root / "alpha", "sess-ghost",
                         event_times=[ago(120), ago(110)])

        result = self.scan()

        words = json.dumps(
            json.loads(result.stdout)["completeness"]).lower()
        self.assertIn("accident", words)
        for overclaim in ("prevent", "guarantee", "complete record"):
            self.assertNotIn(overclaim, words)


class CalibrationTest(unittest.TestCase):
    """Effective-dated coverage (ADR-0016): each session is judged by
    the matchers in force at its time, so a matcher change never
    manufactures deficits over history the old rules recorded
    honestly — and never excuses silence after the change."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name) / "witness"
        self.baseline = self.root / ".supervisor-baseline.json"

    def scan(self, *extra, env=None):
        return run_scan(self.root, "--witness", str(self.witness),
                        *extra, env=env)

    def states(self, result):
        report = json.loads(result.stdout)
        return {s["session"]: s
                for s in report["completeness"]["sessions"]}

    def rewire(self, matcher, age):
        """(Re)wire the harness settings and pin their mtime `age`
        seconds into the past — the effective date the calibration
        reads for a changed matcher."""
        install_witness_hook(self.witness, matcher=matcher)
        stamp = time.time() - age
        os.utime(self.witness.parent / "settings.json", (stamp, stamp))

    def test_widening_does_not_rejudge_ended_sessions(self):
        # A session recorded honestly under the narrow matcher: three
        # Bash events with three receipts, five Reads nothing owed.
        # Widening to * afterwards must not turn those Reads into a
        # five-receipt scar (the wave ADR-0016 exists to prevent).
        self.rewire("Edit|Write|NotebookEdit|Bash", age=600)
        first = self.scan()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        make_chain(self.root / "alpha" / "receipts", "sess-old", entries=3)
        write_transcript(
            self.witness, self.root / "alpha", "sess-old",
            event_times=[ago(500), ago(490), ago(480), ago(470),
                         ago(460), ago(450), ago(440), ago(430)],
            tool=["Bash", "Read", "Bash", "Read", "Read", "Bash",
                  "Read", "Read"],
            idle=3600)
        self.rewire("*", age=100)

        result = self.scan()

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        judged = self.states(result)["sess-old"]
        self.assertEqual(judged["state"], "ENDED-CLEAN")
        self.assertEqual(judged["tools"], 3,
                         "Reads before the widening owe nothing")

    def test_events_after_widening_owe_receipts(self):
        # The flip side: once * is in force, a Read owes a receipt,
        # and a session of unreceipted Reads after the change alarms.
        self.rewire("Edit|Write|NotebookEdit|Bash", age=600)
        self.scan()
        self.rewire("*", age=300)
        write_transcript(self.witness, self.root / "alpha", "sess-new",
                         event_times=[ago(120), ago(110), ago(100)],
                         tool="Read")

        result = self.scan()

        self.assertEqual(result.returncode, 6,
                         result.stdout + result.stderr)
        judged = self.states(result)["sess-new"]
        self.assertEqual(judged["state"], "ALARM-SILENT")
        self.assertEqual(judged["tools"], 3)

    def test_calibration_is_remembered_and_spoken(self):
        # The observations live in the baseline (writer-reachable,
        # trusted for nothing beyond calibration), the change is named
        # in words on the watch, and an unchanged matcher adds nothing.
        self.rewire("Edit|Write|NotebookEdit|Bash", age=600)
        self.scan()
        self.rewire("*", age=100)

        result = self.scan()
        again = self.scan()

        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))
        epochs = baseline["calibration"]
        self.assertEqual(len(epochs), 2)
        self.assertIsNone(epochs[0]["since"],
                          "the first observation covers all history")
        self.assertEqual(epochs[1]["matchers"], ["*"])
        report = json.loads(result.stdout)
        words = report["completeness"]["calibration"]["words"]
        self.assertIn("in force at its time", words)
        rewritten = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(len(rewritten["calibration"]), 2,
                         "an unchanged matcher records no new epoch")
        self.assertEqual(again.returncode, 0,
                         again.stdout + again.stderr)


class FakeCalendarHandler(BaseHTTPRequestHandler):
    """The minimal calendar from the anchor suite: submits get a pending
    proof; polls get 404 while "pending", a Bitcoin continuation once
    "complete". Network isolation the same way test_anchor does it."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        digest = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.submitted.append(digest)
        body = (b"\xf0" + ots_varbytes(b"fake-nonce") + b"\x08"
                + b"\x00" + TAG_PENDING
                + ots_varbytes(ots_varbytes(self.server.url.encode())))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.polled.append(self.path)
        if self.server.mode == "pending":
            self.send_error(404, "Pending confirmation")
            return
        payload = ots_varint(850000)
        body = (b"\x08"
                + b"\x00" + TAG_BITCOIN + ots_varbytes(payload))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def keeper_env(**knobs):
    """Proxy-free env (urllib must reach 127.0.0.1 directly) with any
    supervisor knobs applied."""
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("http_proxy", "https_proxy", "all_proxy",
                                "no_proxy")}
    env.update(knobs)
    return env


class AnchorKeeperTest(unittest.TestCase):
    """The anchor keeper (issue #19): freshness assessed every tick,
    pending proofs completed with no operator action — the ritual the
    dogfood proved nobody remembers, absorbed by the operator that
    never sleeps."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def start_calendar(self):
        server = HTTPServer(("127.0.0.1", 0), FakeCalendarHandler)
        server.mode = "pending"
        server.submitted = []
        server.polled = []
        server.url = f"http://127.0.0.1:{server.server_address[1]}"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def chain_report(self, result, repo, session):
        (chain,) = chains_by_session(json.loads(result.stdout))[
            (repo, session)]
        return chain

    def test_the_panel_data_lists_heights_pending_and_fresh_heads(self):
        anchored_log = make_chain(self.root / "alpha" / "receipts",
                                  "sess-anch")
        write_completed_anchor(anchored_log, chain_head(anchored_log))
        pending_log = make_chain(self.root / "alpha" / "receipts",
                                 "sess-pend")
        # Submitted long ago, calendar unreachable: stale, quiet, and
        # never a broken scan.
        write_pending_anchor(pending_log, chain_head(pending_log),
                             submitted=ago(100000))
        make_chain(self.root / "beta" / "receipts", "sess-bare")

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        anch = self.chain_report(result, "alpha", "sess-anch")["anchors"]
        self.assertEqual(anch["anchored"], [{"upto": 2, "height": 850000}])
        self.assertTrue(anch["head"]["anchored"])
        pend = self.chain_report(result, "alpha", "sess-pend")["anchors"]
        (proof,) = pend["pending"]
        self.assertEqual(proof["submitted"], json.loads(
            (Path(str(pending_log) + ".anchors.jsonl"))
            .read_text(encoding="utf-8"))["ts"])
        self.assertIn("calendar", proof)
        self.assertFalse(pend["head"]["anchored"])
        bare = self.chain_report(result, "beta", "sess-bare")["anchors"]
        self.assertEqual(bare["anchored"], [])
        self.assertEqual(bare["pending"], [])
        self.assertFalse(bare["head"]["anchored"])
        self.assertTrue(bare["head"]["ts"], "age is the reader's to judge "
                        "from the surfaced timestamp")

    def test_a_completed_calendar_upgrades_on_tick_with_no_operator(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        subprocess.run(
            [sys.executable, str(LOXODONTA), "anchor", "--log", str(log),
             "--calendar", calendar.url],
            capture_output=True, check=True, env=keeper_env())
        calendar.mode = "complete"

        result = run_scan(self.root, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chain = self.chain_report(result, "alpha", "sess-aaaa")
        self.assertEqual(chain["anchors"]["anchored"],
                         [{"upto": 2, "height": 850000}])
        self.assertEqual(chain["anchors"]["pending"], [],
                         "the panel reflects the upgrade the same tick")
        self.assertTrue(chain["anchored"])
        self.assertEqual(len(calendar.polled), 1)

    def test_upgrade_attempts_are_polite_between_ticks(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        subprocess.run(
            [sys.executable, str(LOXODONTA), "anchor", "--log", str(log),
             "--calendar", calendar.url],
            capture_output=True, check=True, env=keeper_env())

        first = run_scan(self.root, env=keeper_env())   # polls: pending
        calendar.mode = "complete"
        throttled = run_scan(self.root, env=keeper_env())
        eager = run_scan(self.root, env=keeper_env(
            SUPERVISOR_UPGRADE_EVERY_SECONDS="0"))

        self.assertEqual(len(calendar.polled), 2,
                         "one poll on the first tick, none while "
                         "throttled, one when due again")
        still = self.chain_report(throttled, "alpha", "sess-aaaa")
        self.assertEqual(len(still["anchors"]["pending"]), 1)
        done = self.chain_report(eager, "alpha", "sess-aaaa")
        self.assertEqual(done["anchors"]["anchored"],
                         [{"upto": 2, "height": 850000}])
        self.assertEqual(first.returncode, 0, first.stderr)

    def test_a_fresh_head_older_than_the_cadence_is_anchored_on_tick(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        head = chain_head(log)

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [bytes.fromhex(head)],
                         "the head itself went to the calendar")
        chain = self.chain_report(result, "alpha", "sess-aaaa")
        self.assertEqual(len(chain["anchors"]["pending"]), 1,
                         "the panel reflects the submission this tick")

        again = run_scan(self.root, "--anchor-every", "0s",
                         "--calendar", calendar.url,
                         env=keeper_env(SUPERVISOR_UPGRADE_EVERY_SECONDS="0"))

        self.assertEqual(len(calendar.submitted), 1,
                         "a head already submitted is not resubmitted")
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_default_is_off_and_nothing_is_submitted_without_opt_in(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root, "--calendar", calendar.url,
                          env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [])
        self.assertFalse(Path(str(log) + ".anchors.jsonl").exists())

    def test_a_young_head_waits_for_its_cadence(self):
        calendar = self.start_calendar()
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root, "--anchor-every", "1d",
                          "--calendar", calendar.url, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [])

    def test_sibling_chains_are_anchored_individually(self):
        calendar = self.start_calendar()
        base = make_chain(self.root / "alpha" / "receipts", "sess-sib")
        sibling = make_chain(self.root / "alpha" / "receipts",
                             "sess-sib-002", entries=1)

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=keeper_env())

        self.assertEqual(sorted(calendar.submitted),
                         sorted([bytes.fromhex(chain_head(base)),
                                 bytes.fromhex(chain_head(sibling))]),
                         "no chain skipped because its session already "
                         "anchored another")
        sessions = chains_by_session(json.loads(result.stdout))
        for chain in sessions[("alpha", "sess-sib")]:
            self.assertEqual(len(chain["anchors"]["pending"]), 1)

    def test_all_calendars_failing_is_loud_never_silent(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", "http://127.0.0.1:1",
                          env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        chain = self.chain_report(result, "alpha", "sess-aaaa")
        self.assertTrue(chain["anchors"]["failed"])
        self.assertIn("anchoring failed", chain["anchors"]["note"])
        self.assertFalse(chain["anchors"]["head"]["anchored"])

    def test_one_turn_failing_twice_keeps_both_notes(self):
        # A single turn can fail twice — a refused upgrade AND a refused
        # fresh-head anchor. Both failures belong in the note: evidence
        # is not a scratchpad where the last writer wins.
        log = make_chain(self.root / "alpha" / "receipts", "sess-2xfl")
        first = json.loads(
            log.read_text(encoding="utf-8").splitlines()[0])["entry_hash"]
        write_pending_anchor(log, first, "2026-08-22T09:00:00Z")

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", "http://127.0.0.1:1",
                          env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chain = self.chain_report(result, "alpha", "sess-2xfl")
        self.assertIn("did not answer", chain["anchors"]["note"])
        self.assertIn("anchoring failed", chain["anchors"]["note"])

    def test_an_already_anchored_head_is_left_alone(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=keeper_env())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [])

    def test_every_sibling_chain_is_assessed_separately(self):
        base = make_chain(self.root / "alpha" / "receipts", "sess-sib")
        sibling = make_chain(self.root / "alpha" / "receipts",
                             "sess-sib-002", entries=1)
        write_completed_anchor(sibling, chain_head(sibling), height=900000)

        result = run_scan(self.root, env=keeper_env())

        sessions = chains_by_session(json.loads(result.stdout))
        bare, anchored = sessions[("alpha", "sess-sib")]
        self.assertFalse(bare["anchors"]["head"]["anchored"])
        self.assertEqual(anchored["anchors"]["anchored"],
                         [{"upto": 1, "height": 900000}])
        self.assertTrue(anchored["anchors"]["head"]["anchored"])


class DrillTest(unittest.TestCase):
    """The fire drill (issue #24): the tamper playground graduated into
    its honest job — rehearse detection on sandbox copies so the
    operator can trust the alarms before ever needing them."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def drill(self, log):
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "drill", "--root",
             str(self.root), "--log", str(log), "--json"],
            capture_output=True, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})

    def test_the_four_way_battery_fires_every_expected_alarm(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                         entries=3)

        result = self.drill("alpha/receipts/receipts-sess-aaaa.jsonl")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        outcomes = {d["tamper"]: d for d in report["drills"]}
        self.assertEqual(set(outcomes), {"edit", "delete", "reorder",
                                         "regenerate"})
        for tamper in ("edit", "delete", "reorder"):
            self.assertEqual(outcomes[tamper]["expected"], "BROKEN")
            self.assertEqual(outcomes[tamper]["verdict"], "BROKEN", tamper)
            self.assertTrue(outcomes[tamper]["fired"], tamper)
        regen = outcomes["regenerate"]
        self.assertEqual(regen["expected"], "HEAD-MISMATCH")
        self.assertEqual(regen["verdict"], "HEAD-MISMATCH")
        self.assertTrue(regen["fired"])
        self.assertTrue(report["all_fired"])
        self.assertIn("sandbox", report["rehearsal"],
                      "results present as rehearsal, never verdicts")

    def test_the_real_chain_is_byte_for_byte_untouched(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                         entries=3)
        before = log.read_bytes()

        result = self.drill("alpha/receipts/receipts-sess-aaaa.jsonl")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_bytes(), before)

    def test_the_sandbox_is_invisible_to_the_census(self):
        # Broken-on-purpose copies must never show up as alarms.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                   entries=3)
        self.drill("alpha/receipts/receipts-sess-aaaa.jsonl")

        result = run_scan(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        self.assertEqual(set(sessions), {("alpha", "sess-aaaa")})

    def test_a_chain_too_short_to_play_with_is_refused(self):
        make_chain(self.root / "alpha" / "receipts", "sess-tiny",
                   entries=1)

        result = self.drill("alpha/receipts/receipts-sess-tiny.jsonl")

        self.assertEqual(result.returncode, 1)
        self.assertIn("too short", result.stdout + result.stderr)
        self.assertFalse((self.root / ".supervisor-drill").exists(),
                         "a refused drill writes nothing")

    def test_a_chain_outside_the_root_is_refused(self):
        elsewhere = Path(self._tmp.name).parent

        result = self.drill(elsewhere / "receipts-nope.jsonl")

        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()


class WalkFindingsTest(unittest.TestCase):
    """Findings from the 2026-08-25 supervisor walk (issue #25 prep)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repos"
        self.root.mkdir()

    def test_scan_counts_entries_not_raw_lines(self):
        # GLOSSARY: an entry is a parsed record; a torn line is damage,
        # not an entry — the count must not launder damage into entries.
        log = make_chain(self.root / "alpha" / "receipts", "sess-torn",
                         entries=2)
        with open(log, "a", encoding="utf-8") as f:
            f.write('{"n": 3, "torn')
        finished = run_scan(self.root)
        report = json.loads(finished.stdout)
        chain = chains_by_session(report)[("alpha", "sess-torn")][0]
        self.assertEqual(chain["entries"], 3)   # genesis + 2, damage aside
        self.assertEqual(chain["verdict"], "BROKEN")

    def test_scan_survives_a_directory_shaped_transcript(self):
        # A transcript path that cannot be read (here: a directory whose
        # name matches the layout) must cost one session's watch, never
        # the whole scan.
        make_chain(self.root / "alpha" / "receipts", "sess-dirx")
        witness = Path(self._tmp.name) / "witness"
        install_witness_hook(witness)
        (witness / "anyproj").mkdir(parents=True)
        (witness / "anyproj" / "sess-dirx.jsonl").mkdir()
        finished = run_scan(self.root, "--witness", str(witness))
        self.assertNotIn("Traceback", finished.stderr)
        report = json.loads(finished.stdout)
        states = {s["session"]: s["state"]
                  for s in report["completeness"]["sessions"]}
        self.assertEqual(states["sess-dirx"], "UNWITNESSED")

    def test_keeper_treats_a_memory_from_the_future_as_no_memory(self):
        # The keeper's throttle memory is writer-reachable. A timestamp
        # from the future must read as "no memory" — otherwise one edit
        # stands the keeper down forever, silently.
        log = make_chain(self.root / "alpha" / "receipts", "sess-futr")
        write_pending_anchor(log, chain_head(log), "2026-08-22T09:00:00Z")
        relpath = log.relative_to(self.root).as_posix()
        (self.root / ".supervisor-baseline.json").write_text(json.dumps({
            "chains": {},
            "keeper": {relpath: "2099-01-01T00:00:00Z"}}), encoding="utf-8")
        finished = run_scan(self.root)
        report = json.loads(finished.stdout)
        chain = chains_by_session(report)[("alpha", "sess-futr")][0]
        # the upgrade was attempted (and failed fast, offline): the note
        # is the observable
        self.assertIn("note", chain["anchors"])
        baseline = json.loads(
            (self.root / ".supervisor-baseline.json").read_text("utf-8"))
        self.assertLess(baseline["keeper"][relpath], "2099")


class RecorderDriftTest(unittest.TestCase):
    """The harness executes the recorder from a working tree, so the
    code that records you is whatever is checked out at that path right
    now — no pin, no copy. The scan says which, and never fetches: a
    recorder that reaches the network to update itself would hand the
    writer a second road to the one file that must stay trustworthy
    (ADR-0002). Reporting drift is the honest half of that trade."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name) / "witness"

    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=str(cwd),
                              capture_output=True, encoding="utf-8")

    def make_checkout(self, branch="main"):
        """A git checkout holding a stand-in recorder, wired as the hook."""
        home = Path(self._tmp.name) / "recorder"
        home.mkdir()
        script = home / "loxodonta.py"
        script.write_text("# stand-in recorder\n", encoding="utf-8")
        self.git("init", "-b", branch, cwd=home)
        self.git("config", "user.email", "t@example.com", cwd=home)
        self.git("config", "user.name", "test", cwd=home)
        self.git("add", "-A", cwd=home)
        self.git("commit", "-m", "recorder", cwd=home)
        install_witness_hook(
            self.witness,
            command=f'python "{script.as_posix()}" hook')
        return home, script

    def notice(self):
        result = run_scan(self.root, "--witness", str(self.witness), "--json")
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        return json.loads(result.stdout)["recorder"]

    def test_it_names_the_branch_the_recorder_is_executed_from(self):
        self.make_checkout(branch="dev")

        recorder = self.notice()

        self.assertEqual(recorder["branch"], "dev")
        self.assertFalse(recorder["dirty"])
        self.assertTrue(recorder["path"].endswith("loxodonta.py"))

    def test_an_uncommitted_edit_to_the_recorder_is_drift(self):
        # The sharpest case: the file that runs is not the file that was
        # reviewed, and nothing else on the machine would say so.
        _, script = self.make_checkout()
        script.write_text("# edited, uncommitted\n", encoding="utf-8")

        recorder = self.notice()

        self.assertTrue(recorder["dirty"])
        self.assertIn("uncommitted", recorder["note"].lower())

    def test_a_recorder_outside_git_is_unknown_never_an_error(self):
        # No repo, no git, no upstream: say so plainly rather than
        # guessing or failing the scan over it.
        home = Path(self._tmp.name) / "loose"
        home.mkdir()
        script = home / "loxodonta.py"
        script.write_text("# loose recorder\n", encoding="utf-8")
        install_witness_hook(self.witness,
                             command=f'python "{script.as_posix()}" hook')

        recorder = self.notice()

        self.assertEqual(recorder["state"], "unknown")
        self.assertIsNone(recorder["branch"])

    def test_no_wired_hook_means_no_recorder_to_report_on(self):
        self.witness.mkdir(parents=True, exist_ok=True)
        (self.witness.parent / "settings.json").write_text(
            json.dumps({"hooks": {}}), encoding="utf-8")

        recorder = self.notice()

        self.assertEqual(recorder["state"], "unwired")

class ConsumptionTest(unittest.TestCase):
    """The consumption watch (issue #67; OWASP GenAI LLM06 mitigation
    #8): tool tempo per session against the store's own norm, read
    entirely from what the chains already hold. Evidence for someone
    else's circuit breaker — it never raises the exit and never is
    one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repos"
        self.root.mkdir()
        # Pinned to an empty layout: consumption reads only chains, and
        # the completeness watch must not read the developer's machine.
        self.witness = Path(self._tmp.name) / "witness" / "projects"

    def scan(self, env=None):
        return run_scan(self.root, "--witness", str(self.witness), env=env)

    def hot_env(self, **extra):
        """The suite's threshold handle: hot means a busiest hour of at
        least max(10, 3 x the store's median active hour)."""
        return {**os.environ, "SUPERVISOR_HOT_TIMES": "3",
                "SUPERVISOR_HOT_FLOOR": "10", **extra}

    def watched(self, result):
        report = json.loads(result.stdout)
        return report, {s["session"]: s
                       for s in report["consumption"]["sessions"]}

    def test_a_session_burning_above_the_store_norm_runs_hot(self):
        # Three ordinary sessions set the norm; one burns well past it,
        # driven by a single tool — the runaway-loop shape.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        make_chain(self.root / "beta" / "receipts", "sess-bbbb", entries=3)
        make_chain(self.root / "gamma" / "receipts", "sess-cccc", entries=3)
        make_chain(self.root / "delta" / "receipts", "sess-hot",
                   entries=12, action="Bash: loop {i}")

        result = self.scan(env=self.hot_env())

        report, hot = self.watched(result)
        self.assertIn("sess-hot", hot)
        burning = hot["sess-hot"]
        self.assertEqual(burning["state"], "RUNNING-HOT")
        self.assertEqual(burning["repo"], "delta")
        self.assertEqual(burning["busiest_hour"], 12)
        self.assertEqual(burning["top_tool"], "Bash")
        self.assertEqual(burning["top_tool_count"], 12)
        self.assertNotIn("sess-aaaa", hot,
                         "an ordinary session is never surfaced")

    def test_the_watch_is_evidence_and_never_raises_the_exit(self):
        # The boundary of issue #67, held: this tool evidences someone
        # else's circuit breaker; it never is one. A hot session leaves
        # the scan exit exactly where the verdicts put it.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        make_chain(self.root / "delta" / "receipts", "sess-hot",
                   entries=12, action="Bash: loop {i}")

        result = self.scan(env=self.hot_env())

        report, hot = self.watched(result)
        self.assertIn("sess-hot", hot)
        self.assertEqual(result.returncode, 0,
                         "a hot session is a reason to look, never an alarm "
                         "exit")
        self.assertEqual(report["exit"], 0)
        words = hot["sess-hot"]["words"]
        self.assertIn("never a brake", words)

    def test_a_quiet_store_flags_nothing_but_still_states_its_norm(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        make_chain(self.root / "beta" / "receipts", "sess-bbbb", entries=2)

        result = self.scan()

        report, hot = self.watched(result)
        self.assertEqual(hot, {})
        norm = report["consumption"]["norm"]
        self.assertGreater(norm["sessions_counted"], 0)
        self.assertIn("never a verdict", norm["words"])

    def test_a_hot_session_gone_quiet_is_evidence_not_a_siren(self):
        # Idle window pinned to zero: the burn is over, so it reads as
        # kept evidence, exactly like an ended deficit.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        make_chain(self.root / "delta" / "receipts", "sess-hot",
                   entries=12, action="Bash: loop {i}")

        result = self.scan(env=self.hot_env(
            SUPERVISOR_IDLE_END_SECONDS="0"))

        _, hot = self.watched(result)
        self.assertEqual(hot["sess-hot"]["state"], "ENDED-HOT")
        self.assertIn("evidence", hot["sess-hot"]["words"])

    def test_an_empty_store_has_no_norm_to_deviate_from(self):
        result = self.scan()

        report = json.loads(result.stdout)
        self.assertEqual(report["consumption"]["sessions"], [])
        self.assertEqual(report["consumption"]["norm"]["sessions_counted"], 0)
