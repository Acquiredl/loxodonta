"""Behavioral tests for the supervisor's one-shot scan (`supervisor.py scan`).

The supervisor is an operator that never sleeps (ADR-0005): it drives
receipts through the public CLI and judges nothing itself. These tests
drive only the supervisor's own public surface — `scan` with its JSON
output and exit code — against real chains built through the receipts
CLI in temp directories. No mocks, no internals.
"""

import base64
import datetime
import hashlib
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

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_supervisor`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import home_guard  # noqa: E402

# Every suite that starts scan, serve, calibrate, drill, export or
# package takes isolated_env from this module, so arming the home guard
# here arms it wherever those suites run, alone or under discovery
# (#242).
home_guard.arm()

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
BASELINE_NAME = ".supervisor-baseline.json"
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


def write_completed_anchor(log, head, height=850000, append=False):
    """A minimal but genuine OTS timestamp: one sha256 op, then a Bitcoin
    attestation — enough for `verify --anchors` to replay offline and
    report ANCHORED, with no network and no calendar (ANCHORING.md §4).
    `append=True` adds it behind whatever the sidecar already holds,
    the way an upgrade lands beside the pending record it completes."""
    payload = ots_varint(height)
    proof = (b"\x08"
             + b"\x00" + TAG_BITCOIN + ots_varint(len(payload)) + payload)
    record = {"head": head, "n": 2, "ts": "2026-08-22T09:00:00Z",
              "calendar": "https://calendar.example.test",
              "proof": base64.b64encode(proof).decode()}
    sidecar = Path(str(log) + ".anchors.jsonl")
    line = json.dumps(record) + "\n"
    if append and sidecar.exists():
        with sidecar.open("a", encoding="utf-8") as out:
            out.write(line)
    else:
        sidecar.write_text(line, encoding="utf-8")


def write_attempt_row(log, step, outcome, when, budget=12.0):
    """An attempt row (#240) in the sidecar the step owns, as the hook
    writes it after a session-end step: the anchors sidecar for the
    anchor, the publish memo for the head. Appended, so a proof or a
    head row already there stays where it was."""
    suffix = ".anchors.jsonl" if step == "anchor" else ".published.jsonl"
    row = {"kind": "attempt", "step": step, "ts": when, "budget": budget,
           "outcome": outcome}
    with open(str(log) + suffix, "a", encoding="utf-8") as out:
        out.write(json.dumps(row) + "\n")


def write_chain_row(log, first, last, head, when):
    """A chain row (ADR-0031 ruling 2) in the publish memo, as the
    recorder writes it once a remote has acknowledged a batch of the
    entries. Appended, like the attempt row above."""
    row = {"kind": "chain", "first": first, "last": last, "head": head,
           "ts": when, "event": "session-end"}
    with open(str(log) + ".published.jsonl", "a", encoding="utf-8") as out:
        out.write(json.dumps(row) + "\n")


def run_scan(root, *extra, env):
    # Pin both ends of the pipe to UTF-8 (PYTHONIOENCODING for the child,
    # encoding= for this parent): `text=True` alone decodes with the locale
    # codec — cp1252 on Windows — and crashes on a UTF-8-emitting child.
    # `env` has no default: the one it had was the machine's own, and the
    # scan reads the coverage marker from there whatever --root says
    # (#242). Build it with isolated_env.
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "scan", "--root", str(root),
         "--json", *extra],
        capture_output=True, encoding="utf-8",
        env={**env, "PYTHONIOENCODING": "utf-8"})


def make_chain(log_dir, session, entries=2, action="step {i}", actions=None):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the supervisor is tested against what the tool writes.
    `actions`, when given, are the action lines themselves, one entry
    each, spelled as the hook spells them ("Bash: pytest -q")."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"receipts-{session}.jsonl"
    subprocess.run([sys.executable, str(LOXODONTA), "init", "--log", str(log)],
                   capture_output=True, check=True)
    if actions is None:
        actions = [action.format(i=i) for i in range(entries)]
    for line in actions:
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", line],
            capture_output=True, check=True)
    return log


def chains_by_session(report):
    """{(repo, session): [chain, ...]} — flattens the grouping for
    assertions while leaving the grouping itself observable."""
    return {(repo["repo"], sess["session"]): sess["chains"]
            for repo in report["repos"] for sess in repo["sessions"]}


def run_store_scan(store_home, witness, *extra):
    """`scan` with no --root: the store is the default universe
    (ADR-0011), reached through LOXODONTA_HOME. The witness is always
    pinned — store mode watches every transcript on the machine, so an
    unpinned test would read the developer's real sessions — and the
    rest of the home sits beside the store, in the same temporary
    folder (#242)."""
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "scan", "--json",
         "--witness", str(witness), *extra],
        capture_output=True, encoding="utf-8",
        env={**isolated_env(Path(store_home).parent / "home",
                            LOXODONTA_HOME=str(store_home)),
             "PYTHONIOENCODING": "utf-8"})


class StoreScanTest(unittest.TestCase):
    """The census over the central store. Drawers are laid out by hand —
    the scan never recomputes slugs, it reads what the store holds, so
    these tests own the layout the same way the writer does."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name).resolve() / "storehome"
        self.witness = Path(self._tmp.name).resolve() / "no-witness"
        self.witness.mkdir()

    def drawer(self, slug, project_path):
        d = self.home / "receipts" / slug
        d.mkdir(parents=True, exist_ok=True)
        (d / "project.json").write_text(
            json.dumps({"path": str(project_path)}), encoding="utf-8")
        return d

    def test_scan_with_no_root_sweeps_the_store(self):
        alpha = self.drawer("alpha-11111111", "C:/work/alpha")
        beta = self.drawer("beta-22222222", "C:/work/beta")
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
        drawer = self.drawer("alpha-11111111", "C:/work/alpha")
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
    # adopt writes into the store alone, but no home is the machine's
    # (#274).
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), "adopt", "--root", str(root),
         *extra],
        capture_output=True, encoding="utf-8",
        env=isolated_env(Path(store_home).parent / "home",
                         LOXODONTA_HOME=str(store_home),
                         PYTHONIOENCODING="utf-8"))


class AdoptTest(unittest.TestCase):
    """`supervisor adopt` (ADR-0011): the one-time move of legacy chains
    into the store. Move not copy, sidecars and .unlisted travel,
    nothing is ever overwritten, running it twice is a no-op."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.home = Path(self._tmp.name).resolve() / "storehome"

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
        witness = Path(self._tmp.name).resolve() / "no-witness"
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
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

    def test_scan_reports_a_chain_with_its_verdict_as_json(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)

        result = run_scan(self.root, env=self.env)

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

        result = run_scan(self.root, env=self.env)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertIn(("alpha", "sess-aaaa"), sessions)
        self.assertIn(("beta", "sess-bbbb"), sessions)
        self.assertIn((self.root.name, "sess-root"), sessions)

    def test_sibling_chains_group_under_one_session(self):
        # A sibling is continuation by naming (ADR-0004): one session, one
        # story, even after tail damage moved the recording to -002.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002")

        result = run_scan(self.root, env=self.env)

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

        result = run_scan(self.root, env=self.env)

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

        result = run_scan(self.root, env=self.env)

        sessions = chains_by_session(json.loads(result.stdout))
        self.assertIn(("alpha", "sess-stranded"), sessions)
        (chain,) = sessions[("alpha", "sess-stranded")]
        self.assertTrue(chain["worktree"],
                        "strandedness is evidence — say so")

    def test_an_empty_root_is_a_clean_scan(self):
        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["repos"], [])
        self.assertEqual(report["exit"], 0)

    def test_scan_without_json_flag_is_still_parseable(self):
        # One shape, two dressings: --json is compact for machines, the
        # default pretty-prints for eyes — both parse identically.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        machine = run_scan(self.root, env=self.env)
        human = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--root", str(self.root)],
            capture_output=True, encoding="utf-8",
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

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
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

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

        result = run_scan(self.root, env=self.env)

        self.assertNotEqual(result.returncode, 0)
        sessions = chains_by_session(json.loads(result.stdout))
        (bad,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(bad["verdict"], "BROKEN")
        (good,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(good["verdict"], "VALID",
                         "one bad chain never blanks the scan")

    def test_contradicting_commitments_raise_scan_exit_seven(self):
        # ADR-0017: verify says TRANSCRIPT-DIVERGED with exit 5, but
        # scan's 5 already means the baseline tripwire — the fold
        # renames it to 7 so one number never tells two stories.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        for count in (18, 9):
            subprocess.run(
                [sys.executable, str(LOXODONTA), "log", "--log", str(log),
                 "--actor", "receipts", "--action",
                 f"transcript-commitment: bytes={count} sha256=" + "0" * 64],
                capture_output=True, check=True)

        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 7,
                         result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "TRANSCRIPT-DIVERGED")
        self.assertEqual(chain["exit"], 5,
                         "the chain keeps verify's own exit; only the "
                         "scan's fold renames")

    def test_a_superseded_torn_tail_stays_visible_but_stands_down(self):
        # ADR-0004 working as designed: the tear ended a chain, not the
        # recording. Failing the exit code forever over handled history is
        # an alarm that never stops sounding — the dogfood's lesson.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.tear(log)
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002")

        result = run_scan(self.root, env=self.env)

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

        result = run_scan(self.root, env=self.env)

        self.assertNotEqual(result.returncode, 0)

    def test_a_tampered_chain_shouts_even_with_a_sibling_beside_it(self):
        # Only the honest damage pattern stands down. A rewritten past
        # entry is tampering wherever the recording moved afterwards.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.tamper(log)
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002")

        result = run_scan(self.root, env=self.env)

        self.assertNotEqual(result.returncode, 0)

    def foreign_chain(self, edit=False):
        """A chain whose genesis claims another format, every hash
        recomputed so the chain holds as a hash chain (ADR-0036); with
        `edit`, entry 1 is then changed and its hash left as it was."""
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        entries = [json.loads(line) for line in
                   log.read_text(encoding="utf-8").splitlines()]
        entries[0]["v"] = "receipts/v99"
        prev = None
        for entry in entries:
            entry.pop("entry_hash")
            entry["prev"] = prev
            entry["entry_hash"] = prev = hashlib.sha256(json.dumps(
                entry, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8")).hexdigest()
        if edit:
            entries[1]["action"] = "rewritten after the fact"
        log.write_text("".join(json.dumps(e) + "\n" for e in entries),
                       encoding="utf-8")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

    def test_a_foreign_versioned_chain_is_reported_as_a_refusal(self):
        # UNSUPPORTED-VERSION is a refusal to judge, not a verdict — but a
        # chain nobody can judge still demands the operator's attention.
        self.foreign_chain()

        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 4, result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (foreign,) = sessions[("alpha", "sess-aaaa")]
        self.assertEqual(foreign["verdict"], "UNSUPPORTED-VERSION")
        (good,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(good["verdict"], "VALID")

    def test_an_edited_foreign_versioned_chain_is_broken_not_a_refusal(self):
        # The hashing is frozen across versions (ADR-0036): an edit is
        # BROKEN whatever the genesis claims, and the scan counts it so.
        self.foreign_chain(edit=True)

        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        (foreign,) = chains_by_session(report)[("alpha", "sess-aaaa")]
        self.assertEqual(foreign["verdict"], "BROKEN")
        self.assertEqual(foreign["exit"], 1)

    def test_a_chain_verify_cannot_judge_at_all_is_still_reported(self):
        # An empty file draws an error, not a verdict line. The scan says
        # so — NO-VERDICT, verify's own words as detail — and shouts,
        # because a chain nobody can judge is not a chain in good standing.
        empty = self.root / "alpha" / "receipts" / "receipts-sess-hollow.jsonl"
        empty.parent.mkdir(parents=True)
        empty.write_text("", encoding="utf-8")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root, env=self.env)

        # verify says 66, no input (ADR-0037); the scan counts a chain
        # nobody could judge on the refused rung, 4, and never as broken.
        self.assertEqual(result.returncode, 4, result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (hollow,) = sessions[("alpha", "sess-hollow")]
        self.assertEqual(hollow["verdict"], "NO-VERDICT")
        self.assertEqual(hollow["exit"], 4)
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
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

    def test_an_anchored_chain_is_a_distinct_claim_not_just_valid(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_scan(self.root, env=self.env)

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

        result = run_scan(self.root, env=self.env)

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
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))
        self.baseline = self.root / ".supervisor-baseline.json"

    def events(self, result):
        return json.loads(result.stdout)["baseline"]["events"]

    def test_appends_between_ticks_raise_no_alarm(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        first = run_scan(self.root, env=self.env)  # cold start seeds silently
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "one more step"],
            capture_output=True, check=True)

        second = run_scan(self.root, env=self.env)

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
        run_scan(self.root, env=self.env)
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

        result = run_scan(self.root, env=self.env)

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
        run_scan(self.root, env=self.env)
        lines = log.read_text(encoding="utf-8").splitlines()
        log.write_text("".join(l + "\n" for l in lines[:-1]),
                       encoding="utf-8")  # still a VALID, shorter chain
        gone.unlink()

        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        changes = {e["session"]: e["change"] for e in self.events(result)}
        self.assertEqual(changes, {"sess-aaaa": "regressed",
                                   "sess-bbbb": "vanished"})

    def test_alarm_language_investigates_and_never_claims_a_verdict(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root, env=self.env)
        lines = log.read_text(encoding="utf-8").splitlines()
        log.write_text("".join(l + "\n" for l in lines[:-1]),
                       encoding="utf-8")

        result = run_scan(self.root, env=self.env)

        baseline_words = json.dumps(
            json.loads(result.stdout)["baseline"]).lower()
        self.assertIn("investigate", baseline_words)
        self.assertNotIn("head record", baseline_words,
                         "the baseline is never called a head record")

    def test_the_baseline_updates_each_tick_so_one_change_shouts_once(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root, env=self.env)
        lines = log.read_text(encoding="utf-8").splitlines()
        log.write_text("".join(l + "\n" for l in lines[:-1]),
                       encoding="utf-8")
        caught = run_scan(self.root, env=self.env)

        settled = run_scan(self.root, env=self.env)

        self.assertEqual(caught.returncode, 5)
        self.assertEqual(settled.returncode, 0,
                         settled.stdout + settled.stderr)
        self.assertEqual(self.events(settled), [],
                         "remembered anew after diffing — the alarm "
                         "belongs to the tick that caught it")

    def test_a_corrupt_baseline_is_reported_never_trusted(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        run_scan(self.root, env=self.env)
        self.baseline.write_text("{not json at all", encoding="utf-8")

        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("could not be read",
                      report["baseline"].get("note", ""))
        self.assertEqual(report["baseline"]["events"], [])
        after = run_scan(self.root, env=self.env)
        self.assertNotIn("note", json.loads(after.stdout)["baseline"],
                         "remembering resumes from the fresh look")


def hold(test, path):
    """A second name for the file at `path` right now: what a reader that
    opened it before the next write is holding, and what a crash
    mid-write would leave behind if that write went into this file
    rather than beside it (#300). A hard link, in a folder of the test's
    own on the same volume, so it sits in no census. Skips where the
    filesystem has no hard links."""
    held = Path(test._tmp.name).resolve() / "held" / path.name
    held.parent.mkdir(exist_ok=True)
    try:
        os.link(path, held)
    except (OSError, NotImplementedError) as refused:
        test.skipTest(f"no hard links here: {refused}")
    return held


def assert_replaced_whole(test, held, before, live):
    """The file a reader held is untouched and still whole, and the name
    now points at a different, whole file: the state was swapped in,
    never truncated and rewritten where it stood."""
    test.assertEqual(held.read_text(encoding="utf-8"), before,
                     f"{live.name} was rewritten in place — a crash "
                     "mid-write would leave it torn")
    json.loads(held.read_text(encoding="utf-8"))
    json.loads(live.read_text(encoding="utf-8"))
    test.assertNotEqual(live.read_text(encoding="utf-8"), before,
                        f"{live.name} should hold this tick's state")


class StateSwapTest(unittest.TestCase):
    """The supervisor's state files (the baseline, the day book, the
    views) are written whole or not at all (#300): a new file beside the
    old, then swapped onto its name. The fault this closes was a crash
    or a full disk between truncating the baseline and finishing the
    write, which left a file the next look could not read and so reset
    the memory the tripwire diffs against. A crash cannot be staged
    through the CLI, so these watch the property that rules it out: the
    old file is never written into, and nothing temporary is left."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name).resolve() / "storehome"
        self.witness = Path(self._tmp.name).resolve() / "no-witness"
        self.witness.mkdir()
        drawer = self.home / "receipts" / "alpha-11111111"
        drawer.mkdir(parents=True)
        (drawer / "project.json").write_text(
            json.dumps({"path": "C:/work/alpha"}), encoding="utf-8")
        self.log = make_chain(drawer, "sess-aaaa")

    def test_a_scan_swaps_its_baseline_and_day_book_in_whole(self):
        first = run_store_scan(self.home, self.witness)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        state = [self.home / "baseline.json", self.home / "daybook.json"]
        before = [path.read_text(encoding="utf-8") for path in state]
        held = [hold(self, path) for path in state]
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(self.log),
             "--actor", "claude-code", "--action", "one more step"],
            capture_output=True, check=True)

        second = run_store_scan(self.home, self.witness)

        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        for kept, was, live in zip(held, before, state):
            assert_replaced_whole(self, kept, was, live)
        self.assertEqual(sorted(p.name for p in self.home.glob("*.tmp")), [],
                         "a finished write leaves nothing temporary behind")
        report = json.loads(second.stdout)
        self.assertEqual(report["baseline"]["events"], [])
        self.assertNotIn("note", report["baseline"],
                         "the memory survived the swap and was read back")


def munge(path):
    """A project path the way the harness names its transcript folder:
    every character that isn't a letter, digit, or dash becomes a dash."""
    return re.sub(r"[^A-Za-z0-9-]", "-", str(path))


def ago(seconds):
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=seconds)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def prime_memory(root, matcher="Edit|Write|NotebookEdit|Bash", age=864000,
                 failures=None):
    """Give a supervisor a calibration memory older than the fixtures.

    ADR-0029: a session whose first witnessed event predates the
    supervisor's first observation is BEFORE-MEMORY and is judged not
    at all. Every transcript in these suites is written into the past,
    while a scan started here stamps its first observation *now* — so
    without this, every fixture would be older than the memory watching
    it. A real machine's supervisor has been looking for weeks by the
    time these sessions run; this is that machine. `failures` is the
    matcher wired for failed calls (#239), when the memory saw one.
    """
    epoch = {"since": ago(age), "matchers": [matcher]}
    if failures:
        epoch["failures"] = [failures]
    (root / BASELINE_NAME).write_text(json.dumps({
        "chains": {},
        "calibration": [epoch],
    }), encoding="utf-8")


def install_witness_hook(witness, matcher="Edit|Write|NotebookEdit|Bash",
                         command="python loxodonta.py hook",
                         sessionend=False, failures=None):
    """The harness settings beside the witness layout, wiring a receipts
    PostToolUse hook for the given tools — what tells the watch which
    tool events owe a receipt. `command` is the wired command line, the
    seam the recorder-drift notice reads to find the executed file.
    `sessionend` wires the exit-commitment hook too (ADR-0018), and
    `failures` the failed-call event on that matcher (#239)."""
    witness.mkdir(parents=True, exist_ok=True)
    hooks = {"PostToolUse": [{"matcher": matcher, "hooks": [
        {"type": "command", "command": command},
    ]}]}
    if failures:
        hooks["PostToolUseFailure"] = [{"matcher": failures, "hooks": [
            {"type": "command", "command": command},
        ]}]
    if sessionend:
        hooks["SessionEnd"] = [{"hooks": [
            {"type": "command", "command": command},
        ]}]
    (witness.parent / "settings.json").write_text(
        json.dumps({"hooks": hooks}), encoding="utf-8")


def write_transcript(witness, project, session, event_times=(),
                     error_times=(), chatter=0, idle=0, tool="Bash",
                     metadata=0, failure="Exit code 1\nboom",
                     failed_tool=None, denial=None):
    """A synthetic harness transcript shaped like the real one: each
    tool event is a tool_use block (carrying the tool's name) paired by
    id with a tool-result line (the witness signal). A failed result
    owes a receipt only where the failed-call event is wired and the
    result says the call ran (ADR-0034), and plain chatter lines are
    never counted. `failure` is the failed result's text, by default a
    command that ran and exited, as the harness words one; `failed_tool`
    names the tool that failed, by default `tool`; `denial` is the
    `toolDenialKind` the harness writes on a permission denial."""
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
        result = "Error: " + failure if failed else {"stdout": "ok"}
        block = {"type": "tool_result", "tool_use_id": use_id}
        record = {"type": "user", "timestamp": ts, "toolUseResult": result,
                  "message": {"content": [block]}}
        if failed:
            block["is_error"] = True
            block["content"] = failure
            if denial:
                record["toolDenialKind"] = denial
        lines.append(record)

    if failed_tool is None:
        failed_tool = tool if isinstance(tool, str) else "Bash"
    for i, ts in enumerate(event_times):
        event(i, ts, tool if isinstance(tool, str) else tool[i], False)
    for i, ts in enumerate(error_times):
        event(1000 + i, ts, failed_tool, True)
    for _ in range(chatter):
        lines.append({"type": "assistant", "timestamp": ago(10),
                      "message": "just talk"})
    # Harness metadata records carry no timestamp (field capture,
    # 2026-09-01: last-prompt / custom-title / bridge-session appended
    # to ended sessions' transcripts by restart and resume).
    for i in range(metadata):
        lines.append({"type": "bridge-session", "note": f"meta {i}"})
    transcript = folder / f"{session}.jsonl"
    transcript.write_text(
        "".join(json.dumps(line) + "\n" for line in lines),
        encoding="utf-8")
    if idle:
        quiet_since = time.time() - idle
        os.utime(transcript, (quiet_since, quiet_since))
    return transcript


def write_subagent_transcript(witness, project, session, agent,
                              event_times=(), error_times=(), tool="Bash",
                              failure="Exit code 1\nboom"):
    """A subagent transcript as the harness really writes one (#211):
    `<slug>/<session>/subagents/agent-*.jsonl`, one file per subagent.
    The shape differs from the parent's in the way that matters — the
    result is a `tool_result` block carrying `is_error`, and the
    `toolUseResult` field the parent's records carry is absent. The
    harness fires PostToolUse for these calls under the *parent*
    session id, so their receipts land in the parent's chain. `failure`
    is a failed result's text, a command that ran by default."""
    folder = witness / munge(project) / session / "subagents"
    folder.mkdir(parents=True, exist_ok=True)
    lines = []

    def event(i, ts, name, failed):
        use_id = f"tu_{agent}_{i}"
        lines.append({"type": "assistant", "timestamp": ts, "message": {
            "content": [{"type": "tool_use", "id": use_id, "name": name}],
        }})
        block = {"type": "tool_result", "tool_use_id": use_id,
                 "is_error": failed}
        if failed:
            block["content"] = failure
        lines.append({"type": "user", "timestamp": ts, "message": {
            "content": [block]}})

    for i, ts in enumerate(event_times):
        event(i, ts, tool if isinstance(tool, str) else tool[i], False)
    for i, ts in enumerate(error_times):
        event(1000 + i, ts, "Bash", True)
    path = folder / f"agent-{agent}.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines),
                    encoding="utf-8")
    return path


class SubagentWitnessTest(unittest.TestCase):
    """#211: the harness fires PostToolUse for a subagent's tool calls
    under the *parent* session id, so their receipts land in the
    parent's chain — while the record of them sits in a separate file
    the witness never opened. A session that delegated read as
    ENDED-SURPLUS for work it did honestly, and the ingest leg ADR-0016
    widened coverage to capture went missing from the completeness
    picture entirely, because a delegating parent spawns and writes
    while its subagents read and search."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        install_witness_hook(self.witness, matcher="*")
        prime_memory(self.root, matcher="*")
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def scan(self, *extra):
        return run_scan(self.root, "--witness", str(self.witness), *extra,
                        env=self.env)

    def states(self, result):
        return {s["session"]: s
                for s in json.loads(result.stdout)["completeness"]["sessions"]}

    def test_a_delegated_call_owes_a_receipt_like_any_other(self):
        # Two calls in the parent, three in a subagent, five receipts.
        # The witness saw two before this and called the session
        # surplus for the three it could not see.
        make_chain(self.root / "alpha" / "receipts", "sess-deep", entries=5)
        write_transcript(self.witness, self.root / "alpha", "sess-deep",
                         event_times=[ago(6000), ago(5990)], tool="Agent")
        write_subagent_transcript(
            self.witness, self.root / "alpha", "sess-deep", "aaa",
            event_times=[ago(5980), ago(5970), ago(5960)], tool="Read")

        judged = self.states(self.scan())["sess-deep"]

        self.assertEqual(judged["tools"], 5,
                         "a subagent's calls owe receipts too")
        self.assertEqual(judged["state"], "ENDED-CLEAN")

    def test_several_subagents_are_all_read(self):
        make_chain(self.root / "alpha" / "receipts", "sess-fanout", entries=7)
        write_transcript(self.witness, self.root / "alpha", "sess-fanout",
                         event_times=[ago(6000)], tool="Agent")
        for n, agent in enumerate(("aaa", "bbb", "ccc")):
            write_subagent_transcript(
                self.witness, self.root / "alpha", "sess-fanout", agent,
                event_times=[ago(5900 - n * 10), ago(5890 - n * 10)],
                tool="Grep")

        judged = self.states(self.scan())["sess-fanout"]

        self.assertEqual(judged["tools"], 7)
        self.assertEqual(judged["state"], "ENDED-CLEAN")

    def test_a_failed_delegated_call_owes_nothing(self):
        # Under an install that never wired the failed-call event, a
        # failed call fired no hook, and the witness counts by that same
        # rule (ADR-0034). In a subagent file the flag sits on the
        # tool_result block, which is the only place it ever sits.
        make_chain(self.root / "alpha" / "receipts", "sess-fail", entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-fail",
                         event_times=[ago(6000)], tool="Agent")
        write_subagent_transcript(
            self.witness, self.root / "alpha", "sess-fail", "aaa",
            event_times=[ago(5900)], error_times=[ago(5890), ago(5880)],
            tool="Bash")

        judged = self.states(self.scan())["sess-fail"]

        self.assertEqual(judged["tools"], 2)
        self.assertEqual(judged["state"], "ENDED-CLEAN")

    def test_a_failed_delegated_command_is_owed_once_the_event_is_wired(self):
        # #239 in the #211 shape: the failed-call event fires for a
        # subagent's command under the parent session id too, and the
        # sidechain's block carries the same `Exit code N` line. A
        # receipt lost there is a deficit like any other.
        install_witness_hook(self.witness, matcher="*", failures="*")
        prime_memory(self.root, matcher="*", failures="*")
        make_chain(self.root / "alpha" / "receipts", "sess-sub-fail",
                   actions=["Agent: delegate", "Bash: pytest -q"])
        write_transcript(self.witness, self.root / "alpha", "sess-sub-fail",
                         event_times=[ago(6000)], tool="Agent")
        write_subagent_transcript(
            self.witness, self.root / "alpha", "sess-sub-fail", "aaa",
            event_times=[ago(5900)], error_times=[ago(5890)], tool="Bash")

        judged = self.states(self.scan())["sess-sub-fail"]

        self.assertEqual(judged["tools"], 3, "the failed command is owed")
        self.assertEqual(judged["state"], "ENDED-DEFICIT")
        self.assertEqual(judged["deficit"], 1)

    def test_a_subagents_calls_are_judged_by_their_own_coverage(self):
        # ADR-0016 reaches the sidechain too: a Read from before the
        # widening owes nothing, whoever ran it.
        prime_memory(self.root, matcher="Edit|Write|NotebookEdit|Bash")
        make_chain(self.root / "alpha" / "receipts", "sess-narrow", entries=1)
        write_transcript(self.witness, self.root / "alpha", "sess-narrow",
                         event_times=[ago(6000)], tool="Bash")
        write_subagent_transcript(
            self.witness, self.root / "alpha", "sess-narrow", "aaa",
            event_times=[ago(5900), ago(5890)], tool="Read")

        judged = self.states(self.scan())["sess-narrow"]

        self.assertEqual(judged["tools"], 1,
                         "uncovered reads owe nothing in a sidechain either")
        self.assertEqual(judged["state"], "ENDED-CLEAN")


class DaybookTest(unittest.TestCase):
    """The day book (GLOSSARY: Day book): one row per UTC day, so the
    page can answer the third question a monitoring surface owes its
    operator — is this a trend or a one-off? Testimony like the
    baseline beside it: writer-reachable, trusted for nothing."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))
        self.daybook = self.root / ".supervisor-daybook.json"

    def rows(self, result):
        return json.loads(result.stdout)["history"]

    def today(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d")

    def test_a_scan_writes_the_day_it_looked(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root, env=self.env)

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

        rows = self.rows(run_scan(self.root, env=self.env))

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
        run_scan(self.root, env=self.env)

        rows = self.rows(run_scan(self.root, env=self.env))

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
        run_scan(self.root, env=self.env)
        log.unlink()
        subprocess.run([sys.executable, str(LOXODONTA), "init",
                        "--log", str(log)], capture_output=True, check=True)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "step 0"],
            capture_output=True, check=True)
        tripped = run_scan(self.root, env=self.env)

        settled = run_scan(self.root, env=self.env)

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

        rows = self.rows(run_scan(self.root, env=self.env))

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
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        install_witness_hook(self.witness)
        prime_memory(self.root)
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def scan(self, *extra, env=None):
        return run_scan(self.root, "--witness", str(self.witness),
                        *extra, env=self.env if env is None else env)

    def states(self, result):
        report = json.loads(result.stdout)
        return {s["session"]: s
                for s in report["completeness"]["sessions"]}

    def store_holding(self, *sessions):
        """A store (ADR-0011) with a drawer holding these sessions'
        chains, and the env that points the supervisor at it."""
        home = Path(self._tmp.name).resolve() / "store"
        for session in sessions:
            make_chain(home / "receipts" / "alpha-deadbeef", session)
        return {**self.env, "LOXODONTA_HOME": str(home)}

    def test_a_session_recorded_into_the_store_is_named_not_charged(self):
        # #117, from the field (2026-09-03): --root scans a legacy folder
        # of repos for receipts/ folders, and a machine migrated to the
        # store has none left. Legacy pairing then charged every
        # transcript under the root its whole witnessed count: 111
        # ENDED-DEFICIT rows, the live session reading ALARM-SILENT, and
        # exit 6, from a wrong invocation rather than from anything
        # wrong. The alarm is the flagship claim and must not be faked.
        # Past the grace window, inside the idle one: live and silent.
        write_transcript(self.witness, self.root / "alpha", "sess-live",
                         event_times=[ago(600), ago(400), ago(120)])
        env = self.store_holding("sess-live")

        result = self.scan(env=env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["exit"], 0,
                         "receipts that exist elsewhere are not a deficit")
        row = self.states(result)["sess-live"]
        self.assertEqual(row["state"], "ELSEWHERE")
        self.assertEqual(row["deficit"], 0)
        self.assertIn("store", report["completeness"]["note"])
        self.assertIn("no chains", report["note"])

    def test_a_session_that_never_recorded_anywhere_still_alarms(self):
        # The other half, and the one the guard must not swallow: no
        # chain under the root and none in the store either is the
        # disabled hook, which is exactly what the watch exists to
        # catch.
        write_transcript(self.witness, self.root / "beta", "sess-nowhere",
                         event_times=[ago(600), ago(400), ago(120)])
        env = self.store_holding("sess-someone-else")

        result = self.scan(env=env)

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        self.assertEqual(self.states(result)["sess-nowhere"]["state"],
                         "ALARM-SILENT")

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

        result = self.scan(env={**self.env,
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

    def test_metadata_appends_never_keep_a_dead_session_alive(self):
        # Issue #85, found live on the dashboard: the harness appends
        # timestamp-less metadata (bridge-session, custom-title) to an
        # ended session's transcript on restart/resume. An mtime-based
        # idle clock resets on every touch, so an old deficit presents
        # as an immortal live alarm. Liveness must read the newest
        # timestamped record instead: this session went quiet hours
        # ago, so its deficit is kept evidence, never a live siren.
        make_chain(self.root / "alpha" / "receipts", "sess-meta",
                   entries=1)
        write_transcript(self.witness, self.root / "alpha", "sess-meta",
                         event_times=[ago(7200), ago(7100)], metadata=3)
        # No idle= here: the file was just written, so its mtime is
        # fresh — exactly the bug's shape.

        result = self.scan()

        watched = self.states(result)["sess-meta"]
        self.assertEqual(watched["state"], "ENDED-DEFICIT")

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

    def test_a_committed_session_carries_the_judge_command(self):
        # ADR-0017: the supervisor locates, verify judges — scan prints
        # the exact operator command for a session whose chain holds
        # transcript commitments and whose transcript still exists.
        log = make_chain(self.root / "alpha" / "receipts", "sess-judge",
                         entries=2)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "receipts", "--action",
             "transcript-commitment: bytes=9 sha256=" + "0" * 64],
            capture_output=True, check=True)
        transcript = write_transcript(self.witness, self.root / "alpha",
                                      "sess-judge",
                                      event_times=[ago(120), ago(60)])

        result = self.scan()

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        judged = self.states(result)["sess-judge"]
        self.assertIn("judge", judged)
        self.assertIn("verify", judged["judge"])
        self.assertIn("--transcript", judged["judge"])
        self.assertIn(transcript.as_posix(), judged["judge"])
        # An uncommitted session owes no ritual line.
        plain = make_chain(self.root / "alpha" / "receipts", "sess-plain",
                           entries=1)
        write_transcript(self.witness, self.root / "alpha", "sess-plain",
                         event_times=[ago(30)])
        rerun = self.states(self.scan())["sess-plain"]
        self.assertNotIn("judge", rerun)

    def baseline(self):
        return self.root / ".supervisor-baseline.json"

    def edit_baseline(self, mutate):
        data = json.loads(self.baseline().read_text(encoding="utf-8"))
        mutate(data)
        self.baseline().write_text(json.dumps(data), encoding="utf-8")

    def test_dormancy_reads_the_supervisors_own_clock(self):
        # ADR-0018: the tier comes from observation epochs — the
        # baseline's diary of when a look last saw the head move —
        # never from writer timestamps. First observation seeds "now",
        # so no session is dormant until stillness has been watched.
        make_chain(self.root / "alpha" / "receipts", "sess-still",
                   entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-still",
                         event_times=[ago(7200), ago(7100)], idle=7000)

        first = self.states(self.scan())["sess-still"]
        self.assertEqual(first["dormancy"]["tier"], "awake",
                         "stillness starts at the first observation")

        def age(data):
            for known in data["chains"].values():
                known["last_grew"] = "2026-08-25T00:00:00Z"
        self.edit_baseline(age)
        second = self.states(self.scan())["sess-still"]
        self.assertEqual(second["dormancy"]["tier"], "dormant")
        self.assertGreater(second["dormancy"]["still_seconds"],
                           2 * 86400)

    def test_uncommitted_tail_is_annotated_only_after_the_epoch(self):
        # ADR-0018 ruling 5: the annotation is effective-dated on the
        # SessionEnd wiring epoch — sessions before it are uncommitted
        # by history, not by misbehavior, and carry no field at all.
        install_witness_hook(self.witness, sessionend=True)
        make_chain(self.root / "alpha" / "receipts", "sess-tail",
                   entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-tail",
                         event_times=[ago(7200), ago(7100)], idle=7000)

        first = self.states(self.scan())["sess-tail"]
        self.assertNotIn("uncommitted_tail", first,
                         "the epoch starts at first observation; older "
                         "sessions are never judged")

        self.edit_baseline(lambda data: data.update(
            {"sessionend": {"wired": True,
                            "since": "2026-01-01T00:00:00Z"}}))
        second = self.states(self.scan())["sess-tail"]
        self.assertTrue(second["uncommitted_tail"])
        self.assertIn("tail uncommitted", second["tail_note"])

    def test_a_committed_tail_is_never_annotated(self):
        install_witness_hook(self.witness, sessionend=True)
        log = make_chain(self.root / "alpha" / "receipts", "sess-sealed",
                         entries=2)
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "receipts", "--action",
             "transcript-commitment: bytes=9 sha256=" + "0" * 64],
            capture_output=True, check=True)
        write_transcript(self.witness, self.root / "alpha", "sess-sealed",
                         event_times=[ago(7200), ago(7100)], idle=7000)
        self.scan()
        self.edit_baseline(lambda data: data.update(
            {"sessionend": {"wired": True,
                            "since": "2026-01-01T00:00:00Z"}}))

        row = self.states(self.scan())["sess-sealed"]

        self.assertNotIn("uncommitted_tail", row)

    def test_no_wired_sessionend_never_annotates(self):
        # Default witness settings carry no SessionEnd hook: the exit
        # commitment was never possible, so nothing is judged for it —
        # even with an epoch seeded into the baseline.
        make_chain(self.root / "alpha" / "receipts", "sess-nowire",
                   entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-nowire",
                         event_times=[ago(7200), ago(7100)], idle=7000)
        self.scan()
        self.edit_baseline(lambda data: data.update(
            {"sessionend": {"wired": True,
                            "since": "2026-01-01T00:00:00Z"}}))

        row = self.states(self.scan())["sess-nowire"]

        self.assertNotIn("uncommitted_tail", row)

    def test_a_dormant_chain_growing_again_reawakens(self):
        # ADR-0018: clean growth after dormant-tier observed stillness
        # is the one lifecycle event — investigate voice, never the
        # exit code, counted by the day book.
        log = make_chain(self.root / "alpha" / "receipts", "sess-wake",
                         entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-wake",
                         event_times=[ago(120), ago(60)])
        self.scan()
        self.edit_baseline(lambda data: [
            known.update({"last_grew": "2026-08-25T00:00:00Z"})
            for known in data["chains"].values()])
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "Bash: it stirs"],
            capture_output=True, check=True)

        result = self.scan()

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        report = json.loads(result.stdout)
        events = report["lifecycle"]["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["session"], "sess-wake")
        self.assertIn("observed stillness", events[0]["words"])
        today = [r for r in report["history"] if r.get("watched")][-1]
        self.assertGreaterEqual(today.get("reawakenings", 0), 1)

    def test_bookkeeping_growth_never_reawakens(self):
        # The cadence — or the tail keeper — writing commitments is the
        # recorder speaking, not the session acting.
        log = make_chain(self.root / "alpha" / "receipts", "sess-book",
                         entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-book",
                         event_times=[ago(120), ago(60)])
        self.scan()
        self.edit_baseline(lambda data: [
            known.update({"last_grew": "2026-08-25T00:00:00Z"})
            for known in data["chains"].values()])
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "receipts", "--action",
             "transcript-commitment: bytes=9 sha256=" + "0" * 64],
            capture_output=True, check=True)

        report = json.loads(self.scan().stdout)

        self.assertEqual(report["lifecycle"]["events"], [])

    def test_growth_from_awake_stillness_never_reawakens(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-busy",
                         entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-busy",
                         event_times=[ago(120), ago(60)])
        self.scan()
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
             "--actor", "claude-code", "--action", "Bash: still working"],
            capture_output=True, check=True)

        report = json.loads(self.scan().stdout)

        self.assertEqual(report["lifecycle"]["events"], [])

    def tail_entries(self, session):
        log = (self.root / "alpha" / "receipts"
               / f"receipts-{session}.jsonl")
        return [json.loads(l) for l in
                log.read_text(encoding="utf-8").splitlines()]

    def seed_epoch(self):
        self.edit_baseline(lambda data: data.update(
            {"sessionend": {"wired": True,
                            "since": "2026-01-01T00:00:00Z"}}))

    def test_the_tail_keeper_writes_the_missing_exit_commitment(self):
        # ADR-0018 ruling 6: the scan closes what the annotation
        # reports — the missing exit commitment lands through the
        # recorder's own machinery, and the annotation clears on the
        # next look.
        make_chain(self.root / "alpha" / "receipts", "sess-keep",
                   entries=2)
        transcript = write_transcript(
            self.witness, self.root / "alpha", "sess-keep",
            event_times=[ago(7200), ago(7100)], idle=7000)
        install_witness_hook(self.witness, sessionend=True)
        self.scan()
        self.seed_epoch()

        swept = self.states(self.scan())["sess-keep"]
        self.assertTrue(swept["uncommitted_tail"],
                        "the sweeping scan still tells the truth it saw")

        entries = self.tail_entries("sess-keep")
        last = entries[-1]
        self.assertEqual(last["actor"], "receipts")
        self.assertIn("transcript-commitment: bytes="
                      + str(transcript.stat().st_size), last["action"])
        after = self.states(self.scan())["sess-keep"]
        self.assertNotIn("uncommitted_tail", after,
                         "the next look sees the tail committed")

    def test_the_keeper_is_disableable_and_leaves_the_annotation(self):
        make_chain(self.root / "alpha" / "receipts", "sess-off",
                   entries=2)
        write_transcript(self.witness, self.root / "alpha", "sess-off",
                         event_times=[ago(7200), ago(7100)], idle=7000)
        install_witness_hook(self.witness, sessionend=True)
        quiet = {**self.env, "SUPERVISOR_TAIL_KEEPER": "0"}
        self.scan(env=quiet)
        self.seed_epoch()

        row = self.states(self.scan(env=quiet))["sess-off"]

        self.assertTrue(row["uncommitted_tail"])
        self.assertEqual(self.tail_entries("sess-off")[-1]["actor"],
                         "claude-code", "nothing was appended")

    def test_the_keeper_skips_a_damaged_tail(self):
        # ADR-0004's rule holds for the keeper too: a torn tail cannot
        # anchor a commitment, and the skip is silent.
        log = make_chain(self.root / "alpha" / "receipts", "sess-torn",
                         entries=2)
        with open(log, "a", encoding="utf-8", newline="\n") as f:
            f.write('{"n":3,"half-written')
        write_transcript(self.witness, self.root / "alpha", "sess-torn",
                         event_times=[ago(7200), ago(7100)], idle=7000)
        install_witness_hook(self.witness, sessionend=True)
        self.scan()
        self.seed_epoch()
        before = log.read_text(encoding="utf-8")

        result = self.scan()

        self.assertEqual(log.read_text(encoding="utf-8"), before,
                         "the damaged chain was not extended")

    def test_an_absent_witness_is_reported_never_guessed_at(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        nowhere = Path(self._tmp.name).resolve() / "no-such-layout" / "projects"

        result = run_scan(self.root, "--witness", str(nowhere),
                          env=self.env)

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
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        self.baseline = self.root / ".supervisor-baseline.json"
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def scan(self, *extra, env=None):
        return run_scan(self.root, "--witness", str(self.witness),
                        *extra, env=self.env if env is None else env)

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

    def seed(self, since, matcher):
        """The operator's word for coverage this supervisor never
        watched (ADR-0029 ruling 6). A test's first scan stamps the
        memory at *now*, so any session whose events predate the test
        run is BEFORE-MEMORY unless someone states what was wired then
        — which is the same thing the operator of a real machine does
        after installing the supervisor onto months of history."""
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "calibrate",
             "--root", str(self.root), "--since", since,
             "--matchers", matcher],
            capture_output=True, encoding="utf-8",
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

    def test_widening_does_not_rejudge_ended_sessions(self):
        # A session recorded honestly under the narrow matcher: three
        # Bash events with three receipts, five Reads nothing owed.
        # Widening to * afterwards must not turn those Reads into a
        # five-receipt scar (the wave ADR-0016 exists to prevent).
        self.rewire("Edit|Write|NotebookEdit|Bash", age=7000)
        first = self.scan()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        # The memory starts at this scan (ADR-0029), and the session
        # below ran before it; the operator states what was wired then.
        self.seed(ago(7000), "Edit|Write|NotebookEdit|Bash")
        make_chain(self.root / "alpha" / "receipts", "sess-old", entries=3)
        # Event stamps are the liveness clock (issue #85), so "ended"
        # means genuinely old timestamps, not a back-dated mtime.
        write_transcript(
            self.witness, self.root / "alpha", "sess-old",
            event_times=[ago(6500), ago(6490), ago(6480), ago(6470),
                         ago(6460), ago(6450), ago(6440), ago(6430)],
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
        self.seed(ago(700), "Edit|Write|NotebookEdit|Bash")
        self.seed(ago(300), "*")
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
        self.assertRegex(epochs[0]["since"] or "",
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                         "the first observation stamps when it was made "
                         "and claims nothing earlier (ADR-0029)")
        self.assertEqual(epochs[1]["matchers"], ["*"])
        report = json.loads(result.stdout)
        words = report["completeness"]["calibration"]["words"]
        self.assertIn("in force at its time", words)
        rewritten = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(len(rewritten["calibration"]), 2,
                         "an unchanged matcher records no new epoch")
        self.assertEqual(again.returncode, 0,
                         again.stdout + again.stderr)


class UsersOwnHookTest(unittest.TestCase):
    """The settings file is shared with the user's own hooks (#303): the
    supervisor reads an entry as the recorder's only by the rule the
    installer claims it by (#293), an interpreter, a script with one of
    the recorder's names, and the verb `hook`. A user's
    `upload_receipts.py` left after uninstall-hook is not a recorder,
    wired at session end or anywhere else."""

    USERS = "python ~/bin/upload_receipts.py --to s3"
    # The recorder's old name with another verb: the user's, not ours.
    SYNC = "python ~/bin/receipts.py sync"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        self.witness.mkdir()
        self.baseline = self.root / ".supervisor-baseline.json"
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def wire(self, hooks):
        (self.witness.parent / "settings.json").write_text(
            json.dumps({"hooks": hooks}), encoding="utf-8")

    def users_blocks(self):
        return {
            "PostToolUse": [{"matcher": "Read", "hooks": [
                {"type": "command", "command": self.USERS},
                {"type": "command", "command": self.SYNC}]}],
            "PostToolUseFailure": [{"matcher": "Read", "hooks": [
                {"type": "command", "command": self.USERS}]}],
            "SessionEnd": [{"hooks": [
                {"type": "command", "command": self.USERS}]}],
        }

    def scan(self):
        result = run_scan(self.root, "--witness", str(self.witness),
                          "--json", env=self.env)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))
        return json.loads(result.stdout), baseline

    def test_a_users_own_hooks_wire_no_recorder(self):
        # After uninstall-hook: only the user's hooks are left.
        self.wire(self.users_blocks())

        report, baseline = self.scan()

        self.assertFalse(baseline["sessionend"]["wired"],
                         "a user's upload_receipts.py is not the "
                         "recorder's SessionEnd")
        self.assertEqual(baseline["calibration"][-1]["matchers"], [])
        self.assertNotIn("failures", baseline["calibration"][-1])
        self.assertEqual(report["recorder"]["state"], "unwired")

    def test_the_recorder_beside_a_users_hooks_reads_as_before(self):
        hooks = self.users_blocks()
        recorder = "python loxodonta.py hook"
        hooks["PostToolUse"].append({
            "matcher": "Edit|Write|NotebookEdit|Bash",
            "hooks": [{"type": "command", "command": recorder}]})
        hooks["SessionEnd"].append({"hooks": [
            {"type": "command", "command": recorder}]})
        self.wire(hooks)

        report, baseline = self.scan()

        self.assertTrue(baseline["sessionend"]["wired"])
        self.assertEqual(baseline["calibration"][-1]["matchers"],
                         ["Edit|Write|NotebookEdit|Bash"])
        self.assertEqual(report["recorder"]["path"], "loxodonta.py")


class FailedCallWitnessTest(unittest.TestCase):
    """#239, ruled in ADR-0034: the harness fires `PostToolUseFailure`,
    not `PostToolUse`, for a tool call that started and failed, and
    nothing at all for one it denied, blocked or rejected before it ran.
    Once install-hook wires the event, the witness moves with it. A
    failed call whose result begins `Exit code N` is owed like a
    completed one, from the epoch that wired the event and never before.
    A rejected input, a marked denial, and a shell failure without that
    line owe nothing. Any other tool's failure may owe (`may_owe`), and
    receipts are reconciled tool by tool, going to a tool's `may_owe`
    calls first, so a receipt a failed call may have left never pays for
    one an owed call lost."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        install_witness_hook(self.witness, matcher="*", failures="*")
        prime_memory(self.root, matcher="*", failures="*")
        # Every home the tools read, pinned inside the test: the scan
        # reads neither this machine's marker nor its settings.
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def scan(self):
        return run_scan(self.root, "--witness", str(self.witness),
                        env=self.env)

    def states(self, result):
        return {s["session"]: s
                for s in json.loads(result.stdout)["completeness"]["sessions"]}

    def words(self, result):
        watch = json.loads(result.stdout)["completeness"]
        return watch.get("calibration", {}).get("words", "")

    def session(self, name, actions, completed, failed, **transcript):
        """A chain holding `actions`, spelled as the hook spells them,
        and a transcript with `completed` calls and `failed` ones."""
        make_chain(self.root / "alpha" / "receipts", name, actions=actions)
        write_transcript(self.witness, self.root / "alpha", name,
                         event_times=completed, error_times=failed,
                         **transcript)

    def test_a_failed_command_owes_a_receipt_and_is_paid_by_it(self):
        self.session("sess-paid", ["Bash: a", "Bash: b", "Bash: c"],
                     [ago(6000), ago(5990)], [ago(5980)])

        result = self.scan()

        judged = self.states(result)["sess-paid"]
        self.assertEqual(judged["tools"], 3, "the failed command is owed")
        self.assertEqual(judged["state"], "ENDED-CLEAN")
        self.assertNotIn("Exit code N", self.words(result),
                         "the canary is quiet while failures read as owed")

    def test_a_failed_command_with_no_receipt_alarms_while_live(self):
        # The hook that fires on success and not on failure is exactly
        # the gap #239 found; once the event is wired, a missing
        # failure receipt is a deficit like any other.
        self.session("sess-short", ["Bash: a", "Bash: b"],
                     [ago(600), ago(500)], [ago(400)])

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        judged = self.states(result)["sess-short"]
        self.assertEqual(judged["state"], "ALARM-DEFICIT")
        self.assertEqual(judged["deficit"], 1)

    def test_a_may_owe_receipt_never_pays_another_calls_deficit(self):
        # The writer as adversary (ADR-0002): starve one command's hook,
        # then make a fetch fail against a server it controls, so the
        # failed-call event writes a receipt the witness can only count
        # as may_owe. Counted as one total, that receipt paid for the
        # lost one and the session read OK with exit 0.
        self.session("sess-masked", ["Bash: a", "WebFetch: example.com"],
                     [ago(600), ago(500)], [ago(400)], failed_tool="WebFetch",
                     failure="Claude Code is unable to fetch from "
                             "example.com")

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        judged = self.states(result)["sess-masked"]
        self.assertEqual(judged["state"], "ALARM-DEFICIT")
        self.assertEqual(judged["deficit"], 1)
        self.assertEqual(judged["may_owe"], 1)

    def test_a_may_owe_receipt_never_pays_its_own_tools_deficit(self):
        # The same move inside one tool: starve the fetch that carried
        # something out, then fetch an address that errors on a server
        # the writer controls. Paired owed-first, the failed fetch's
        # receipt paid for the starved one and the session read OK with
        # exit 0; the tool's receipts now go to its may_owe calls first.
        self.session("sess-same-tool", ["WebFetch: example.com"],
                     [ago(600)], [ago(500)], tool="WebFetch",
                     failure="Claude Code is unable to fetch from "
                             "example.com")

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        judged = self.states(result)["sess-same-tool"]
        self.assertEqual((judged["state"], judged["deficit"],
                          judged["may_owe"]), ("ALARM-DEFICIT", 1, 1))

    def test_a_may_owe_receipt_still_on_its_way_gets_the_grace(self):
        # Receipts go to a tool's may_owe calls first, so while a failed
        # fetch's receipt is still on its way, the fetch that stands
        # unpaid is the earlier, receipted one. Dated by that earlier
        # call, the deficit skipped the grace window every receipt gets
        # and alarmed on a scan that read the chain a moment too soon;
        # dated no earlier than the failed call, it lags, as a command's
        # would.
        self.session("sess-lag-fetch", ["WebFetch: example.com"],
                     [ago(600)], [ago(3)], tool="WebFetch",
                     failure="Claude Code is unable to fetch from "
                             "example.com")
        self.session("sess-lag-bash", ["Bash: a"], [ago(600)], [ago(3)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = self.states(result)
        self.assertEqual(rows["sess-lag-fetch"]["state"], "LAGGING")
        self.assertEqual(rows["sess-lag-bash"]["state"], "LAGGING")

    def test_a_stream_of_failures_never_quiets_a_session_that_stopped(self):
        # The grace the failed call's receipt gets is held to what could
        # be on its way: a tool with no receipt at all has nothing
        # coming, so a fetch failing every few seconds cannot date an
        # old unpaid call forward and hold the alarm open. Recording
        # stopped here, which is the case the witness exists for.
        self.session("sess-silent", [], [ago(900), ago(800)], [ago(15)],
                     tool="WebFetch",
                     failure="Claude Code is unable to fetch from "
                             "example.com")

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        judged = self.states(result)["sess-silent"]
        self.assertEqual((judged["state"], judged["deficit"]),
                         ("ALARM-SILENT", 2))

    def test_a_stream_of_failures_never_quiets_a_starved_receipt(self):
        # The same floor, with receipts still arriving for another tool:
        # a starved fetch receipt stays a deficit however recently the
        # next fetch failed, since the fetch itself has no receipt that
        # could be on its way.
        failed = "Claude Code is unable to fetch from example.com"
        for name, when in (("sess-starved", ago(20)),
                           ("sess-starved-stale", ago(90))):
            self.session(name, ["Bash: a"], [ago(700), ago(600)], [when],
                         tool=["Bash", "WebFetch"], failed_tool="WebFetch",
                         failure=failed)
        # And where the tool does have a receipt, the floor reaches one
        # unpaid call per failed call that may owe, not the whole tool:
        # three starved fetches behind one failure stay an alarm.
        self.session("sess-starved-many", ["WebFetch: a"],
                     [ago(700), ago(690), ago(680)], [ago(20)],
                     tool="WebFetch", failure=failed)

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        rows = self.states(result)
        for name in ("sess-starved", "sess-starved-stale"):
            self.assertEqual((rows[name]["state"], rows[name]["deficit"]),
                             ("ALARM-DEFICIT", 1), name)
        many = rows["sess-starved-many"]
        self.assertEqual((many["state"], many["deficit"]),
                         ("ALARM-DEFICIT", 3))

    def test_fewer_receipts_than_may_owe_calls_leave_every_owed_call_unpaid(self):
        # The floor: two failed fetches that may owe and one receipt of
        # the tool. The receipt goes to them, none is left over, and all
        # three completed fetches stand unpaid, not one of them.
        failed = "Claude Code is unable to fetch from example.com"
        self.session("sess-floor", ["WebFetch: a"],
                     [ago(6000), ago(5990), ago(5980)],
                     [ago(5970), ago(5960)], tool="WebFetch", failure=failed)

        judged = self.states(self.scan())["sess-floor"]

        self.assertEqual((judged["state"], judged["tools"], judged["deficit"],
                          judged["may_owe"]), ("ENDED-DEFICIT", 3, 3, 2))

    def test_one_tool_short_and_another_over_reads_as_the_deficit(self):
        # ADR-0034 ruling 4. Tool by tool, a session can be short in one
        # tool and over in another while the totals match; a surplus in
        # one never stands a missing receipt in another down, live or
        # ended, and the words say what is true when the totals match.
        actions = ["Bash: a", "WebFetch: u", "WebFetch: v"]
        tools = ["Bash", "Bash", "WebFetch"]
        self.session("sess-mixed-live", actions,
                     [ago(600), ago(500), ago(400)], [], tool=tools)
        self.session("sess-mixed-ended", actions,
                     [ago(6000), ago(5990), ago(5980)], [], tool=tools)

        result = self.scan()

        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        rows = self.states(result)
        for name, state in (("sess-mixed-live", "ALARM-DEFICIT"),
                            ("sess-mixed-ended", "ENDED-DEFICIT")):
            row = rows[name]
            self.assertEqual((row["state"], row["tools"], row["receipts"],
                              row["deficit"]), (state, 3, 3, 1), name)
            self.assertIn("receipts fall short of the calls"
                          if state == "ALARM-DEFICIT"
                          else "receipts short of the calls", row["words"],
                          name)

    def test_a_call_that_never_ran_owes_nothing_and_excuses_nothing(self):
        # A rejected input, a marked denial, and a shell call with no
        # `Exit code N` line (blocked, or denied unmarked) fire no hook,
        # so they owe nothing and may owe nothing either: a receipt
        # planted under the tool's name reads as the surplus it is,
        # rather than as a slot the failure opened.
        self.session("sess-denied", ["Bash: a", "Bash: b"],
                     [ago(6000), ago(5990)], [ago(5980)],
                     failure="Permission to use Bash has been denied.",
                     denial="user-rejected")
        self.session("sess-rejected", ["Edit: a", "Edit: b", "Edit: planted"],
                     [ago(5000), ago(4990)], [ago(4980)], tool="Edit",
                     failure="<tool_use_error>String to replace not found "
                             "in file.</tool_use_error>")
        self.session("sess-blocked", ["Bash: a", "Bash: b", "Bash: planted"],
                     [ago(4000), ago(3990)], [ago(3980)],
                     failure="PreToolUse:Bash hook error: blocked by policy")

        rows = self.states(self.scan())

        denied, rejected = rows["sess-denied"], rows["sess-rejected"]
        blocked = rows["sess-blocked"]
        self.assertEqual((denied["tools"], denied["state"]),
                         (2, "ENDED-CLEAN"))
        self.assertEqual((rejected["tools"], rejected["state"]),
                         (2, "ENDED-SURPLUS"))
        self.assertEqual((blocked["tools"], blocked["state"]),
                         (2, "ENDED-SURPLUS"))
        for row in (denied, rejected, blocked):
            self.assertNotIn("may_owe", row)

    def test_a_failed_call_that_may_have_run_is_paid_first(self):
        # A fetch that started and failed fired the event; one a
        # PreToolUse hook blocked reads the same in the transcript and
        # fired nothing. Its tool's receipts go to it first: when it
        # fired, its receipt is excused from surplus; when it did not,
        # beside another fetch, the tool reads one short, the false
        # deficit ADR-0034 ruling 2 takes over a mask. Alone in its
        # tool, a failure that fired nothing costs nothing.
        failed = "Claude Code is unable to fetch from example.com"
        self.session("sess-fetched",
                     ["WebFetch: a", "WebFetch: b", "WebFetch: c"],
                     [ago(6000), ago(5990)], [ago(5980)], tool="WebFetch",
                     failure=failed)
        self.session("sess-unfired", ["WebFetch: a", "WebFetch: b"],
                     [ago(5000), ago(4990)], [ago(4980)], tool="WebFetch",
                     failure=failed)
        self.session("sess-lone", ["Bash: a", "Bash: b"],
                     [ago(4000), ago(3990)], [ago(3980)],
                     failed_tool="WebFetch", failure=failed)

        rows = self.states(self.scan())

        fetched, unfired = rows["sess-fetched"], rows["sess-unfired"]
        self.assertEqual(fetched["state"], "ENDED-CLEAN")
        self.assertEqual((fetched["tools"], fetched["receipts"]), (2, 3))
        self.assertEqual(fetched["may_owe"], 1,
                         "the row says why receipts outnumber the owed")
        self.assertEqual((unfired["state"], unfired["deficit"]),
                         ("ENDED-DEFICIT", 1))
        self.assertEqual(rows["sess-lone"]["state"], "ENDED-CLEAN")

    def test_an_install_from_before_the_event_is_judged_as_before(self):
        # Nothing wires the event, in the settings or in the memory. A
        # failed call owes nothing and may owe nothing, so a receipt for
        # one reads as the surplus it read before #239.
        install_witness_hook(self.witness, matcher="*")
        prime_memory(self.root, matcher="*")
        self.session("sess-old", ["Bash: a", "Bash: b", "Bash: c"],
                     [ago(9600), ago(9500)], [ago(9400)],
                     failure="Claude Code is unable to fetch from "
                             "example.com")

        judged = self.states(self.scan())["sess-old"]

        self.assertEqual((judged["tools"], judged["state"]),
                         (2, "ENDED-SURPLUS"))
        self.assertNotIn("may_owe", judged)

    def test_a_failed_command_owes_nothing_before_the_event_was_wired(self):
        # Both sides of one upgrade. The memory began with completed
        # calls wired alone; re-running install-hook added the event,
        # dated by the settings file's mtime like any matcher change
        # (ADR-0016). Before it, a failed command owes nothing; after
        # it, a failed command with no receipt is owed.
        prime_memory(self.root, matcher="*")
        stamp = time.time() - 3000
        os.utime(self.witness.parent / "settings.json", (stamp, stamp))
        self.session("sess-before", ["Bash: a", "Bash: b"],
                     [ago(6000), ago(5990)], [ago(5980)])
        self.session("sess-after", ["Bash: a", "Bash: b"],
                     [ago(2600), ago(2590)], [ago(2580)])

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = self.states(result)
        self.assertEqual((rows["sess-before"]["tools"],
                          rows["sess-before"]["state"]), (2, "ENDED-CLEAN"))
        self.assertNotIn("may_owe", rows["sess-before"])
        self.assertEqual((rows["sess-after"]["tools"],
                          rows["sess-after"]["state"]), (3, "ENDED-DEFICIT"))
        self.assertIn("in force at its time", self.words(result))

    def test_a_harness_that_rewords_its_failures_is_named(self):
        # The canary (ADR-0034): the witness leans on one wording, and
        # a harness that stopped opening a failed command with
        # `Exit code N` would turn every owed failure into one that owes
        # nothing. One sentence says so, and the exit stays where it was.
        self.session("sess-reworded", ["Bash: a"], [ago(6000)],
                     [ago(5990)], failure="Command failed with status 3")

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        judged = self.states(result)["sess-reworded"]
        self.assertEqual((judged["tools"], judged["state"]),
                         (1, "ENDED-CLEAN"))
        self.assertNotIn("may_owe", judged)
        self.assertIn("Exit code N", self.words(result))


class BeforeMemoryTest(unittest.TestCase):
    """ADR-0029, from issue #114: the supervisor judges nothing older
    than its own memory. This is the one case ADR-0016's effective
    dating could not see — a matcher change that predates the
    calibration memory itself, which left every session recorded under
    the old rules judged by today's wide matcher and scarred for tools
    it never owed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        install_witness_hook(self.witness)
        self.baseline = self.root / BASELINE_NAME
        # The coverage marker is machine-wide whatever --root says
        # (ADR-0030), so the memory these tests date is this home's, not
        # the machine's (#242).
        self.home = Path(self._tmp.name).resolve() / "home"
        self.env = isolated_env(self.home)

    def scan(self, *extra):
        return run_scan(self.root, "--witness", str(self.witness), *extra,
                        env=self.env)

    def calibrate(self, *args):
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "calibrate",
             "--root", str(self.root), *args],
            capture_output=True, encoding="utf-8",
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

    def watch(self, result):
        return json.loads(result.stdout)["completeness"]

    def test_the_first_observation_stamps_when_it_was_made(self):
        # The null that was the whole bug: `matchers_at` read it as
        # "this epoch covers all time before it", so a memory born
        # after the widening judged the narrow era by `*`.
        self.scan()

        epochs = json.loads(
            self.baseline.read_text(encoding="utf-8"))["calibration"]

        self.assertEqual(len(epochs), 1)
        self.assertRegex(epochs[0]["since"] or "",
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_a_session_older_than_the_memory_takes_no_row(self):
        # Install day, ended sessions: tool calls, no chain, because
        # there was no hook when they ran. Charged in full before this.
        self.scan()
        write_transcript(self.witness, self.root / "alpha", "sess-old",
                         event_times=[ago(6000), ago(5900), ago(5800)])

        result = self.scan()

        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        watch = self.watch(result)
        self.assertEqual(watch["sessions"], [],
                         "a session from before the memory takes no row")
        self.assertEqual(watch["before_memory"]["count"], 1)
        self.assertIn("unknown", watch["before_memory"]["words"])

    def test_a_live_session_older_than_the_memory_never_alarms(self):
        # The stranger's first five minutes (ADR-0029 ruling 3, and the
        # reason the *first* event decides and not the last): a session
        # that has been running since before install owes nothing it
        # could have paid, and judging it by today's matchers fires the
        # flagship alarm on the tool's own arrival.
        self.scan()
        write_transcript(self.witness, self.root / "alpha", "sess-live",
                         event_times=[ago(600), ago(400), ago(120)])

        result = self.scan()

        self.assertEqual(result.returncode, 0,
                         "no siren for history the supervisor never saw")
        self.assertEqual(self.watch(result)["before_memory"]["count"], 1)

    def test_the_rows_are_there_for_anyone_who_asks(self):
        self.scan()
        write_transcript(self.witness, self.root / "alpha", "sess-old",
                         event_times=[ago(6000), ago(5900)])

        result = self.scan("--before-memory")

        rows = self.watch(result)["before_memory"]["sessions"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "BEFORE-MEMORY")
        self.assertNotIn("deficit", rows[0],
                         "an unknown owed is not a deficit")

    def test_a_marker_in_the_home_the_scan_reads_moves_the_memory(self):
        # The coupling, tested rather than avoided (#242): the scan reads
        # the coverage marker from the machine-wide home whatever --root
        # says (ADR-0030). A marker older than the session, in this
        # test's own home, judges the session the tests above leave
        # unjudged. The same marker in the machine's home is what failed
        # them wherever install-hook had run.
        self.scan()
        write_transcript(self.witness, self.root / "alpha", "sess-old",
                         event_times=[ago(6000), ago(5900), ago(5800)])
        self.assertEqual(self.watch(self.scan())["before_memory"]["count"], 1)
        store = Path(self.env["LOXODONTA_HOME"])
        store.mkdir(parents=True)
        (store / "coverage.json").write_text(json.dumps({
            "purpose": "test fixture",
            "epochs": [{"since": ago(9000), "matchers": ["*"],
                        "harness": "claude-code"}]}), encoding="utf-8")

        watch = self.watch(self.scan())

        self.assertNotIn("before_memory", watch)
        self.assertEqual([s["session"] for s in watch["sessions"]],
                         ["sess-old"])
        self.assertIn("install-hook", watch["calibration"]["words"])

    def test_seeding_restores_judgment_and_forgetting_takes_it_back(self):
        # Ruling 6 end to end: the operator states what was wired before
        # the supervisor looked, the session is judged on that word and
        # said to be, and the statement can be withdrawn again.
        self.scan()
        make_chain(self.root / "alpha" / "receipts", "sess-old", entries=3)
        write_transcript(self.witness, self.root / "alpha", "sess-old",
                         event_times=[ago(6000), ago(5900), ago(5800)])
        self.assertEqual(self.watch(self.scan())["before_memory"]["count"], 1)
        since = ago(9000)

        seeded = self.calibrate("--since", since, "--matchers",
                                "Edit|Write|NotebookEdit|Bash")

        self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
        watch = self.watch(self.scan())
        judged = {s["session"]: s for s in watch["sessions"]}["sess-old"]
        self.assertEqual(judged["state"], "ENDED-CLEAN")
        self.assertNotIn("before_memory", watch)
        self.assertIn("stated by the operator",
                      watch["calibration"]["words"])

        forgot = self.calibrate("--forget", since)

        self.assertEqual(forgot.returncode, 0, forgot.stdout + forgot.stderr)
        self.assertEqual(self.watch(self.scan())["before_memory"]["count"], 1)

    def test_a_seed_swaps_the_baseline_in_whole(self):
        # calibrate rewrites the same file every scan diffs against, so
        # it takes the same swap (#300): a crash while seeding must not
        # cost the store its memory of heads.
        self.scan()
        before = self.baseline.read_text(encoding="utf-8")
        held = hold(self, self.baseline)

        seeded = self.calibrate("--since", ago(9000), "--matchers", "Bash")

        self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
        assert_replaced_whole(self, held, before, self.baseline)
        self.assertEqual(sorted(p.name for p in self.root.glob("*.tmp")), [])

    def test_a_seed_may_not_restate_what_the_supervisor_watched(self):
        # The hard refusal, with no --force behind it: observed time is
        # the one part of the calibration memory that is not testimony.
        self.scan()

        refused = self.calibrate("--since", ago(0), "--matchers", "*")

        self.assertEqual(refused.returncode, 64)
        self.assertIn("not yours to restate", refused.stderr)

    def test_forgetting_an_observed_epoch_is_refused(self):
        self.scan()
        observed = json.loads(
            self.baseline.read_text(encoding="utf-8"))["calibration"][0]

        refused = self.calibrate("--forget", observed["since"])

        self.assertEqual(refused.returncode, 64)
        self.assertIn("Only a seeded epoch", refused.stderr)


class CoverageMarkerTest(unittest.TestCase):
    """ADR-0030, from walking docs/START.md as a stranger: install the
    hook, work for a week, then scan. The supervisor's first look is the
    scan, so under ADR-0029 alone every session in that week falls
    before its memory and is judged not at all — zero judged sessions
    for a new installer, and an export that says nothing about the
    flagship claim. The recorder knows when coverage began, because it
    is the thing that wired it, and now it writes that down."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        self.store = Path(self._tmp.name).resolve() / "store"
        self.store.mkdir()
        install_witness_hook(self.witness, matcher="*")
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home",
                                LOXODONTA_HOME=str(self.store))

    def scan(self, *extra):
        return run_scan(self.root, "--witness", str(self.witness),
                        *extra, env=self.env)

    def states(self, result):
        return {s["session"]: s
                for s in json.loads(result.stdout)["completeness"]["sessions"]}

    def watch(self, result):
        return json.loads(result.stdout)["completeness"]

    def mark(self, since, matchers=("*",), harness="claude-code",
             failures=()):
        """The marker as `install-hook` writes it (its own CLI is tested
        in tests/test_hook.py); this exercises the reader."""
        epoch = {"since": since, "matchers": list(matchers),
                 "harness": harness}
        if failures:
            epoch["failures"] = list(failures)
        (self.store / "coverage.json").write_text(json.dumps({
            "purpose": "test fixture",
            "epochs": [epoch]}), encoding="utf-8")

    def a_session(self, name, when):
        make_chain(self.root / "alpha" / "receipts", name, entries=3)
        write_transcript(self.witness, self.root / "alpha", name,
                         event_times=[when, when, when], tool="Bash")

    def test_work_between_install_and_the_first_scan_is_judged(self):
        # The walk, exactly: coverage wired two hours ago, work an hour
        # ago, first scan now.
        self.mark(ago(7200))
        self.a_session("sess-week", ago(3600))

        judged = self.states(self.scan())["sess-week"]

        self.assertEqual(judged["state"], "ENDED-CLEAN")
        self.assertEqual(judged["tools"], 3)

    def test_a_marker_that_wired_failed_calls_is_read_for_them(self):
        # #239: the install that wired the failure event says so, and a
        # failed command in the week before the first scan is owed.
        self.mark(ago(7200), failures=("*",))
        install_witness_hook(self.witness, matcher="*", failures="*")
        make_chain(self.root / "alpha" / "receipts", "sess-week",
                   actions=["Bash: a", "Bash: b", "Bash: c"])
        write_transcript(self.witness, self.root / "alpha", "sess-week",
                         event_times=[ago(3600), ago(3600)],
                         error_times=[ago(3600)])
        judged = self.states(self.scan())["sess-week"]

        self.assertEqual(judged["tools"], 3)
        self.assertEqual(judged["state"], "ENDED-CLEAN")

    def test_without_the_marker_that_same_work_is_unjudged(self):
        # The control, and the bug this ADR closes.
        self.a_session("sess-week", ago(3600))

        watch = self.watch(self.scan())

        self.assertEqual(watch["sessions"], [])
        self.assertEqual(watch["before_memory"]["count"], 1)

    def test_the_marker_says_it_was_told_not_observed(self):
        self.mark(ago(7200))
        self.a_session("sess-week", ago(3600))

        words = self.watch(self.scan())["calibration"]["words"]

        self.assertIn("install-hook", words)
        self.assertIn("judged on that word", words)

    def test_a_marker_may_not_reach_time_the_supervisor_watched(self):
        # Ruling 4. The first scan stamps the memory; a marker written
        # afterwards cannot reopen what the supervisor has since been
        # watching for itself.
        self.scan()
        self.a_session("sess-old", ago(3600))
        self.mark(ago(60))

        watch = self.watch(self.scan())

        self.assertEqual(watch["before_memory"]["count"], 1,
                         "a late marker never re-dates observed time")

    def test_a_changed_profile_is_a_recorder_epoch_like_a_changed_matcher(self):
        # ADR-0031 ruling 1: the profile is written beside the matchers
        # so a change to it is as visible here as a matcher change. The
        # real installer writes both epochs, into the past, and the scan
        # reads them as ADR-0030 already reads a matcher epoch: told by
        # install-hook, never observed.
        home = Path(self._tmp.name).resolve() / "home"
        (home / ".claude").mkdir(parents=True)
        for age, profile in ((7200, "local"), (5400, "timestamped")):
            stamp = str(int(datetime.datetime.now(
                datetime.timezone.utc).timestamp()) - age)
            subprocess.run(
                [sys.executable, str(LOXODONTA), "install-hook",
                 "--profile", profile],
                capture_output=True, check=True,
                env={**self.env, "HOME": str(home), "USERPROFILE": str(home),
                     "SOURCE_DATE_EPOCH": stamp})
        self.a_session("sess-week", ago(3600))

        watch = self.watch(self.scan())

        told = [(epoch["profile"], epoch["matchers"])
                for epoch in watch["calibration"]["epochs"]
                if epoch.get("source") == "recorder"]
        self.assertEqual(told, [("local", ["*"]), ("timestamped", ["*"])])
        self.assertEqual(self.states(self.scan())["sess-week"]["state"],
                         "ENDED-CLEAN", "the profile changed no coverage")

    def test_a_codex_marker_never_speaks_for_the_claude_code_witness(self):
        self.mark(ago(7200), matchers=(".*",), harness="codex")
        self.a_session("sess-week", ago(3600))

        watch = self.watch(self.scan())

        self.assertEqual(watch["before_memory"]["count"], 1)

    def test_an_empty_store_tells_the_two_causes_apart(self):
        # Found walking the five steps: a reader who finishes step 2 and
        # scans out of curiosity was told to run install-hook, the step
        # they had just finished. An empty store means "nothing has run
        # yet" when the hook is wired and "nothing is recording" when it
        # is not, and those want opposite things from the reader.
        store = Path(self._tmp.name).resolve() / "freshstore"
        env = {**self.env, "LOXODONTA_HOME": str(store),
               "PYTHONIOENCODING": "utf-8"}
        # Its own parent: hook_matchers reads `<witness>/../settings.json`,
        # so a bare path beside the wired witness would read the wired
        # one's settings.
        bare = Path(self._tmp.name).resolve() / "nohook" / "projects"
        bare.mkdir(parents=True)

        def scan_store(witness):
            # No --root: the empty-store note belongs to store mode,
            # which is the universe a new install lands in (ADR-0011).
            return subprocess.run(
                [sys.executable, str(SUPERVISOR), "scan", "--json",
                 "--witness", str(witness)],
                capture_output=True, encoding="utf-8", env=env)

        unwired = scan_store(bare)
        wired = scan_store(self.witness)

        self.assertIn("install-hook", json.loads(unwired.stdout)["note"])
        told = json.loads(wired.stdout)["note"]
        self.assertIn("the hook is wired", told)
        self.assertNotIn("install-hook", told,
                         "never tell a reader to redo the step they just did")

    def test_one_epoch_from_each_side_is_not_a_matcher_change(self):
        # A marker and this supervisor's first look describe the same
        # wiring from two sides. Calling that a change would report a
        # widening nobody performed.
        self.mark(ago(7200))
        self.a_session("sess-week", ago(3600))

        words = self.watch(self.scan())["calibration"]["words"]

        self.assertNotIn("matchers changed", words)


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


def isolated_env(home, **knobs):
    """`keeper_env` with every home the tools read pointed inside `home`:
    the store, the user's settings and Codex's hooks, so a scan reads
    neither this machine's own wiring nor its coverage marker. Pair it
    with a `--witness` under a temporary folder. The knobs land last, so
    a test that keeps its store or its project somewhere of its own
    names it here (`LOXODONTA_HOME=...`, `CLAUDE_PROJECT_DIR=...`). Every
    start of scan, serve, calibrate, drill, export or package (#242), and
    of adopt, hook, install-hook or uninstall-hook (#274), goes through
    this or sets all four homes itself; the home guard
    (tests/home_guard.py) refuses one that does neither."""
    env = keeper_env(LOXODONTA_HOME=str(Path(home) / ".loxodonta"),
                     HOME=str(home), USERPROFILE=str(home),
                     CODEX_HOME=str(Path(home) / ".codex"))
    env.pop("CLAUDE_PROJECT_DIR", None)
    env.update(knobs)
    return env


def home_outside(test):
    """A temporary home for `test`, removed when it ends, for a test whose
    scanned root is its whole temporary folder: a home inside the root
    would sit in the census it is meant to stay out of."""
    away = tempfile.TemporaryDirectory()
    test.addCleanup(away.cleanup)
    return Path(away.name).resolve()


class AnchorKeeperTest(unittest.TestCase):
    """The anchor keeper (issue #19): freshness assessed every tick,
    pending proofs completed with no operator action — the ritual the
    dogfood proved nobody remembers, absorbed by the operator that
    never sleeps."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

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

        result = run_scan(self.root, env=self.env)

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

    def test_a_head_settled_by_one_calendar_leaves_no_pending_proof(self):
        # #199: a pending record from a calendar that never came back,
        # beside the upgrade another calendar delivered for the same
        # head. The panel reads verify's own words (ADR-0005), so the
        # dashboard stops painting anchor staleness on an anchored head.
        log = make_chain(self.root / "alpha" / "receipts", "sess-split")
        head = chain_head(log)
        write_pending_anchor(log, head, submitted=ago(2400000))
        write_completed_anchor(log, head, append=True)

        result = run_scan(self.root, env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chain = self.chain_report(result, "alpha", "sess-split")
        self.assertEqual(chain["anchors"]["anchored"],
                         [{"upto": 2, "height": 850000}])
        self.assertEqual(chain["anchors"]["pending"], [],
                         "a settled head owes no pending proof")
        self.assertTrue(chain["anchors"]["head"]["anchored"])
        self.assertTrue(chain["anchored"])

    def test_a_completed_calendar_upgrades_on_tick_with_no_operator(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        subprocess.run(
            [sys.executable, str(LOXODONTA), "anchor", "--log", str(log),
             "--calendar", calendar.url],
            capture_output=True, check=True, env=self.env)
        calendar.mode = "complete"

        result = run_scan(self.root, env=self.env)

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
            capture_output=True, check=True, env=self.env)

        first = run_scan(self.root, env=self.env)   # polls: pending
        calendar.mode = "complete"
        throttled = run_scan(self.root, env=self.env)
        eager = run_scan(self.root, env={
            **self.env, "SUPERVISOR_UPGRADE_EVERY_SECONDS": "0"})

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
                          "--calendar", calendar.url, env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [bytes.fromhex(head)],
                         "the head itself went to the calendar")
        chain = self.chain_report(result, "alpha", "sess-aaaa")
        self.assertEqual(len(chain["anchors"]["pending"]), 1,
                         "the panel reflects the submission this tick")

        again = run_scan(self.root, "--anchor-every", "0s",
                         "--calendar", calendar.url,
                         env={**self.env,
                              "SUPERVISOR_UPGRADE_EVERY_SECONDS": "0"})

        self.assertEqual(len(calendar.submitted), 1,
                         "a head already submitted is not resubmitted")
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_an_attempt_row_is_not_a_proof_so_the_keeper_still_anchors(self):
        # #240: a session end that no calendar answered leaves a note
        # in the sidecar and no proof. The keeper reads the note as a
        # note: the head is still unanchored, so it is anchored on the
        # tick, and the sidecar holding only notes owes no upgrade.
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-noted")
        head = chain_head(log)
        write_attempt_row(log, "anchor",
                          "no calendar answered within 12 seconds",
                          when=ago(600))

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [bytes.fromhex(head)])
        chain = self.chain_report(result, "alpha", "sess-noted")
        self.assertEqual(len(chain["anchors"]["pending"]), 1)
        self.assertNotIn("note", chain["anchors"],
                         "a sidecar of notes alone owes no upgrade")

    def test_default_is_off_and_nothing_is_submitted_without_opt_in(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root, "--calendar", calendar.url,
                          env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [])
        self.assertFalse(Path(str(log) + ".anchors.jsonl").exists())

    def test_a_young_head_waits_for_its_cadence(self):
        calendar = self.start_calendar()
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_scan(self.root, "--anchor-every", "1d",
                          "--calendar", calendar.url, env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [])

    def test_sibling_chains_are_anchored_individually(self):
        calendar = self.start_calendar()
        base = make_chain(self.root / "alpha" / "receipts", "sess-sib")
        sibling = make_chain(self.root / "alpha" / "receipts",
                             "sess-sib-002", entries=1)

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=self.env)

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
                          env=self.env)

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
                          env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chain = self.chain_report(result, "alpha", "sess-2xfl")
        self.assertIn("did not answer", chain["anchors"]["note"])
        self.assertIn("anchoring failed", chain["anchors"]["note"])

    def test_an_already_anchored_head_is_left_alone(self):
        calendar = self.start_calendar()
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        write_completed_anchor(log, chain_head(log))

        result = run_scan(self.root, "--anchor-every", "0s",
                          "--calendar", calendar.url, env=self.env)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calendar.submitted, [])

    def test_every_sibling_chain_is_assessed_separately(self):
        base = make_chain(self.root / "alpha" / "receipts", "sess-sib")
        sibling = make_chain(self.root / "alpha" / "receipts",
                             "sess-sib-002", entries=1)
        write_completed_anchor(sibling, chain_head(sibling), height=900000)

        result = run_scan(self.root, env=self.env)

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
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

    def drill(self, log):
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "drill", "--root",
             str(self.root), "--log", str(log), "--json"],
            capture_output=True, encoding="utf-8",
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

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

        result = run_scan(self.root, env=self.env)

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
        elsewhere = Path(self._tmp.name).resolve().parent

        result = self.drill(elsewhere / "receipts-nope.jsonl")

        self.assertEqual(result.returncode, 1)

    def drill_from(self, cwd, root, log):
        """`drill` started in `cwd` with `--root` and `--log` spelled as
        a reader types them, relative to that folder (#297)."""
        return subprocess.run(
            [sys.executable, str(SUPERVISOR), "drill", "--root", root,
             "--log", log, "--json"],
            capture_output=True, encoding="utf-8", cwd=str(cwd),
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

    def test_a_log_relative_to_the_current_folder_is_drilled(self):
        # The README's line, `drill --root docs/demo --log
        # docs/demo/bad-day-session.jsonl`, run from a clone: both paths
        # are read from the folder the command runs in.
        make_chain(self.root / "docs" / "demo", "sess-aaaa", entries=3)

        result = self.drill_from(self.root, "docs/demo",
                                 "docs/demo/receipts-sess-aaaa.jsonl")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["all_fired"])
        self.assertEqual(report["log"], "receipts-sess-aaaa.jsonl")
        self.assertTrue((self.root / "docs" / "demo" / ".supervisor-drill")
                        .is_dir(), "the sandbox sits under the root")

    def test_a_log_relative_to_the_root_is_still_drilled(self):
        make_chain(self.root / "docs" / "demo", "sess-aaaa", entries=3)

        result = self.drill_from(self.root, "docs/demo",
                                 "receipts-sess-aaaa.jsonl")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["all_fired"])

    def test_a_current_folder_log_outside_the_root_is_refused(self):
        # Read from the current folder, the path must still land on a
        # chain under the root: a real chain beside it is refused, and
        # nothing is written.
        make_chain(self.root / "docs" / "demo", "sess-aaaa", entries=3)
        make_chain(self.root / "elsewhere", "sess-bbbb", entries=3)

        result = self.drill_from(self.root, "docs/demo",
                                 "elsewhere/receipts-sess-bbbb.jsonl")

        self.assertEqual(result.returncode, 1)
        self.assertIn("is not a chain under", result.stderr)
        self.assertFalse(
            (self.root / "docs" / "demo" / ".supervisor-drill").exists(),
            "a refused drill writes nothing")


if __name__ == "__main__":
    unittest.main()


class WalkFindingsTest(unittest.TestCase):
    """Findings from the 2026-08-25 supervisor walk (issue #25 prep)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def test_scan_counts_entries_not_raw_lines(self):
        # GLOSSARY: an entry is a parsed record; a torn line is damage,
        # not an entry — the count must not launder damage into entries.
        log = make_chain(self.root / "alpha" / "receipts", "sess-torn",
                         entries=2)
        with open(log, "a", encoding="utf-8") as f:
            f.write('{"n": 3, "torn')
        finished = run_scan(self.root, env=self.env)
        report = json.loads(finished.stdout)
        chain = chains_by_session(report)[("alpha", "sess-torn")][0]
        self.assertEqual(chain["entries"], 3)   # genesis + 2, damage aside
        self.assertEqual(chain["verdict"], "BROKEN")

    def test_scan_survives_a_directory_shaped_transcript(self):
        # A transcript path that cannot be read (here: a directory whose
        # name matches the layout) must cost one session's watch, never
        # the whole scan.
        make_chain(self.root / "alpha" / "receipts", "sess-dirx")
        witness = Path(self._tmp.name).resolve() / "witness"
        install_witness_hook(witness)
        (witness / "anyproj").mkdir(parents=True)
        (witness / "anyproj" / "sess-dirx.jsonl").mkdir()
        finished = run_scan(self.root, "--witness", str(witness),
                            env=self.env)
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
        finished = run_scan(self.root, env=self.env)
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
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        self.witness = Path(self._tmp.name).resolve() / "witness"
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=str(cwd),
                              capture_output=True, encoding="utf-8")

    def make_checkout(self, branch="main"):
        """A git checkout holding a stand-in recorder, wired as the hook."""
        home = Path(self._tmp.name).resolve() / "recorder"
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
        result = run_scan(self.root, "--witness", str(self.witness), "--json",
                          env=self.env)
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
        home = Path(self._tmp.name).resolve() / "loose"
        home.mkdir()
        script = home / "loxodonta.py"
        script.write_text("# loose recorder\n", encoding="utf-8")
        install_witness_hook(self.witness,
                             command=f'python "{script.as_posix()}" hook')

        recorder = self.notice()

        self.assertEqual(recorder["state"], "unknown")
        self.assertIsNone(recorder["branch"])

    def test_a_recorder_wired_under_the_home_is_found_there(self):
        # The shell running the hook expands `~`, so the notice does
        # too (#303): a recorder wired as ~/x/loxodonta.py is the file
        # under the home, not a path that is "not on disk".
        home = Path(self.env["HOME"])
        script = home / "x" / "loxodonta.py"
        script.parent.mkdir(parents=True)
        script.write_text("# recorder under the home\n", encoding="utf-8")
        install_witness_hook(self.witness,
                             command="python ~/x/loxodonta.py hook")

        recorder = self.notice()

        self.assertEqual(recorder["path"], script.as_posix())
        self.assertNotIn("not on disk", recorder["note"])

    def test_an_install_from_before_the_failure_event_says_so(self):
        # #239: an install from before it wired completed calls alone,
        # and a failed call leaves no receipt until install-hook runs
        # again. One clause on the line that already reads the wired
        # command, never an alarm of its own.
        home = Path(self._tmp.name).resolve() / "loose"
        home.mkdir()
        script = home / "loxodonta.py"
        script.write_text("# loose recorder\n", encoding="utf-8")
        command = f'python "{script.as_posix()}" hook'
        install_witness_hook(self.witness, matcher="*", command=command)

        older = self.notice()
        install_witness_hook(self.witness, matcher="*", command=command,
                             failures="*")
        rewired = self.notice()

        self.assertIn("failed tool calls", older["note"])
        self.assertIn("install-hook", older["note"])
        self.assertNotIn("failed tool calls", rewired["note"])

    def test_no_wired_hook_means_no_recorder_to_report_on(self):
        self.witness.mkdir(parents=True, exist_ok=True)
        (self.witness.parent / "settings.json").write_text(
            json.dumps({"hooks": {}}), encoding="utf-8")

        recorder = self.notice()

        self.assertEqual(recorder["state"], "unwired")


class TranscriptRetentionTest(unittest.TestCase):
    """The harness deletes its own transcripts (#260): Claude Code
    sweeps a session transcript once it is older than
    `cleanupPeriodDays`, 30 when the setting is absent, and the chain's
    commitments outlast it with nothing left to judge. The scan reads
    the number from the settings beside the witness and says it, in one
    field; it never copies a transcript and never moves the exit. Every
    home is inside the test's own folder, so no scan here reads this
    machine's settings."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name).resolve() / "home"
        self.witness = self.home / ".claude" / "projects"
        self.witness.mkdir(parents=True)

    def settings(self, **keys):
        """The harness settings beside the witness: a wired recorder,
        plus whatever keys the test sets."""
        install_witness_hook(self.witness)
        path = self.witness.parent / "settings.json"
        settings = json.loads(path.read_text(encoding="utf-8"))
        settings.update(keys)
        path.write_text(json.dumps(settings), encoding="utf-8")
        return path

    def scan(self, *extra):
        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--witness",
             str(self.witness), *extra],
            capture_output=True, encoding="utf-8",
            env={**isolated_env(self.home), "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(result.returncode, 0,
                         "the harness's retention never moves the exit:\n"
                         + result.stdout + result.stderr)
        return result

    def report(self):
        """`scan --json` read as JSON and nothing looser. Python's own
        reader also takes `Infinity` and `NaN`, which no browser's does,
        so a report holding one would pass a plain `json.loads` here and
        still take the dashboard down."""
        def refuse(word):
            raise ValueError(f"{word} in the scan's output is not JSON")
        return json.loads(self.scan("--json").stdout, parse_constant=refuse)

    def retention(self):
        return self.report()["completeness"].get("transcript_retention")

    def assert_caveat(self, words):
        # Every line says what it did not read (#260 review).
        self.assertIn("Only this file is read", words)
        self.assertIn("claude --settings", words)
        self.assertIn("desktopSessionCleanupPeriodDays", words)

    def test_an_unset_period_reads_as_the_harness_default_of_30(self):
        path = self.settings()

        retention = self.retention()

        self.assertEqual(retention["days"], 30)
        self.assertFalse(retention["set"])
        self.assertNotIn("value", retention)
        self.assertEqual(retention["file"], path.as_posix())
        self.assertIn("cleanupPeriodDays", retention["words"])
        self.assertIn("not set", retention["words"])
        self.assertIn("the harness default of 30", retention["words"])
        self.assert_caveat(retention["words"])

    def test_a_set_period_is_reported_as_the_number_it_is(self):
        for value, days in ((90, 90), (1, 1), (45.0, 45)):
            with self.subTest(value=value):
                self.settings(cleanupPeriodDays=value)

                retention = self.retention()

                self.assertEqual(retention["days"], days)
                self.assertTrue(retention["set"])
                self.assertEqual(retention["value"], value)
                self.assertIn(f"older than {days} days", retention["words"])
                self.assertIn("cleanupPeriodDays", retention["words"])
                self.assertNotIn("not set", retention["words"])
                self.assert_caveat(retention["words"])

    def test_a_value_that_is_no_number_of_days_is_repeated_not_guessed(self):
        # The harness documents a whole number, 1 or more. Anything else
        # is said as it stands in the file, and no number of days is
        # read from it: not the default, not a rounding. What the
        # harness does then is its own documented rule, and the line
        # says it: the sweep pauses, unless managed settings set one.
        for value in ("forever", -5, 0, 2.5, None):
            with self.subTest(value=value):
                self.settings(cleanupPeriodDays=value)

                retention = self.retention()

                self.assertIsNone(retention["days"])
                self.assertTrue(retention["set"])
                self.assertEqual(retention["value"], value)
                self.assertIn(json.dumps(value), retention["words"])
                self.assertNotIn("older than", retention["words"])
                self.assertNotIn("default of 30", retention["words"])
                self.assertIn("pauses", retention["words"])
                self.assertIn("managed", retention["words"])
                self.assert_caveat(retention["words"])

    def test_infinity_or_nan_makes_the_file_unreadable_to_every_reader(self):
        # Python's reader takes three words JSON does not have (#260
        # review). The harness cannot read a settings file holding one,
        # so no hook in it is wired and no retention in it is set; and a
        # report that copied one would stop being JSON, and the
        # dashboard with it. json.dumps writes these as the bare words.
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                self.settings(cleanupPeriodDays=value)

                completeness = self.report()["completeness"]

                self.assertNotIn("transcript_retention", completeness)
                self.assertIn("no recorder hook is wired",
                              completeness.get("note", ""))

    def test_a_number_past_a_float_is_said_in_words_and_left_out_of_value(self):
        # 1e999 is JSON, and the harness reads it as Infinity, which is
        # no whole number of days. The file stays readable, its hook
        # stays wired, and the one value a JSON report cannot carry is
        # said in the words and left out of `value`.
        path = self.settings()
        path.write_text(path.read_text(encoding="utf-8")[:-1]
                        + ', "cleanupPeriodDays": 1e999}', encoding="utf-8")

        completeness = self.report()["completeness"]

        retention = completeness["transcript_retention"]
        self.assertIsNone(retention["days"])
        self.assertTrue(retention["set"])
        self.assertNotIn("value", retention)
        self.assertIn("cleanupPeriodDays is Infinity", retention["words"])
        self.assertNotIn("no recorder hook is wired",
                         completeness.get("note", ""))

    def test_no_settings_file_adds_nothing_new(self):
        # No file to read is not a new state: the scan already says what
        # it says about the witness, and says nothing about retention.
        self.assertIsNone(self.retention())

    def test_a_settings_file_that_is_not_json_adds_nothing_new(self):
        (self.witness.parent / "settings.json").write_text(
            "{not json", encoding="utf-8")

        self.assertIsNone(self.retention())


class ConsumptionTest(unittest.TestCase):
    """The consumption watch (issue #67; OWASP GenAI LLM06 mitigation
    #8): tool tempo per session against the store's own norm, read
    entirely from what the chains already hold. Evidence for someone
    else's circuit breaker — it never raises the exit and never is
    one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "repos"
        self.root.mkdir()
        # Pinned to an empty layout: consumption reads only chains, and
        # the completeness watch must not read the developer's machine.
        self.witness = Path(self._tmp.name).resolve() / "witness" / "projects"
        self.env = isolated_env(Path(self._tmp.name).resolve() / "home")

    def scan(self, env=None):
        return run_scan(self.root, "--witness", str(self.witness),
                        env=self.env if env is None else env)

    def hot_env(self, **extra):
        """The suite's threshold handle: hot means a busiest hour of at
        least max(10, 3 x the store's median active hour)."""
        return {**self.env, "SUPERVISOR_HOT_TIMES": "3",
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


class DashLeadingStoreTest(unittest.TestCase):
    """Every path the supervisor hands the recorder travels as one
    `--flag=value` token, so a store path that begins with a dash (a
    relative LOXODONTA_HOME such as `-home`, run from its parent folder)
    never reads as a flag to the recorder's parser, and scan's exit stays
    inside its own ladder instead of carrying the recorder's usage exit."""

    def test_a_dash_leading_store_path_scans_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            drawer = root / "-dashhome" / "receipts" / "alpha-11111111"
            drawer.mkdir(parents=True)
            (drawer / "project.json").write_text(
                json.dumps({"path": str(root)}), encoding="utf-8")
            make_chain(drawer, "sess-aaaa", entries=2)
            witness = root / "no-witness"
            witness.mkdir()

            result = subprocess.run(
                [sys.executable, str(SUPERVISOR), "scan", "--json",
                 "--witness", str(witness)],
                cwd=str(root), capture_output=True, encoding="utf-8",
                env={**isolated_env(root / "home"),
                     "PYTHONIOENCODING": "utf-8",
                     "LOXODONTA_HOME": "-dashhome"})

            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["exit"], 0)
            (chain,) = chains_by_session(report)[(root.name, "sess-aaaa")]
            self.assertEqual(chain["verdict"], "VALID")


def run_supervisor(home, *args):
    """Invoke the supervisor as an operator would, with nothing prepared
    in `home`: a usage error is decided before any store is read."""
    return subprocess.run(
        [sys.executable, str(SUPERVISOR), *args],
        capture_output=True, encoding="utf-8",
        env={**isolated_env(home), "PYTHONIOENCODING": "utf-8"})


class UsageExitTest(unittest.TestCase):
    """Usage errors exit 64 (sysexits EX_USAGE) here as in the recorder, so
    scan's 5/6/7 and verify's 0..5 are never an argparse error (ADR-0026
    ruling 7). Argparse's message stays on stderr; stdout stays empty."""

    def setUp(self):
        self.home = home_outside(self)

    def test_unknown_flag_exits_64_with_argparse_message(self):
        result = run_supervisor(self.home, "scan", "--no-such-flag")

        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertIn("usage:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_malformed_cadence_exits_64_not_a_verdict_number(self):
        # parse_cadence raises ArgumentTypeError inside the scan subparser;
        # the subparser must speak 64 too, or scan's own exits collide.
        result = run_supervisor(self.home, "scan", "--anchor-every", "soon")

        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("anchor-every", result.stderr)
        self.assertIn("not a cadence", result.stderr)
        self.assertEqual(result.stdout, "")
