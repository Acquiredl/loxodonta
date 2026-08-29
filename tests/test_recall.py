"""Behavioral tests for the Stage E recall surface (ADR-0009).

Recall lives in the supervisor: `digest` (the session-start injection),
`show` (one full entry by entry address), `search` and `timeline` (the
escalation ladder past the digest window). These tests drive only the
public CLI against real chains in temp directories — chains are forged
with spec-exact hashes (the drill's technique) so timestamps and spans
are deterministic, plus one parity test over a CLI-built chain. Recall
owns no verdicts, and these tests hold it to that: every surface must
label itself testimony and never print a verdict word of its own.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECEIPTS = REPO_ROOT / "receipts.py"
DOGFOOD = REPO_ROOT / "dogfood.py"


def run_py(script, *args, env_extra=None, cwd=None):
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True, encoding="utf-8", cwd=cwd,
        env={**os.environ, "PYTHONIOENCODING": "utf-8",
             **(env_extra or {})})


def spec_hash(entry_without_hash):
    canonical = json.dumps(entry_without_hash, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def forge_chain(repo_dir, session, steps, actor="forge"):
    """A spec-exact chain with chosen timestamps: [(ts, action), ...].
    Returns the list of entry hashes (genesis first)."""
    log = repo_dir / "receipts" / f"receipts-{session}.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    genesis = {"action": "genesis", "actor": "receipts", "files": [],
               "n": 0, "prev": None, "ts": steps[0][0], "v": "0.1"}
    genesis["entry_hash"] = spec_hash(genesis)
    entries = [genesis]
    for i, (ts, action) in enumerate(steps, start=1):
        entry = {"n": i, "ts": ts, "actor": actor, "action": action,
                 "files": [], "prev": entries[-1]["entry_hash"]}
        entry["entry_hash"] = spec_hash(entry)
        entries.append(entry)
    log.write_text("".join(
        json.dumps(e, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False) + "\n" for e in entries),
        encoding="utf-8")
    return log, [e["entry_hash"] for e in entries]


class RecallBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def repo(self, name):
        path = self.root / name
        path.mkdir(exist_ok=True)
        return path


class DigestTest(RecallBase):
    def test_rows_grouping_and_last_action_tags(self):
        repo = self.repo("alpha")
        _, h1 = forge_chain(repo, "aaaa1111-1111-1111-1111-111111111111", [
            ("2026-08-20T10:00:00Z", "Edit: one.py"),
            ("2026-08-20T10:05:00Z", "Bash: pytest -q"),
        ])
        _, h2 = forge_chain(repo, "bbbb2222-2222-2222-2222-222222222222", [
            ("2026-08-21T09:00:00Z", "Edit: two.py"),
            ("2026-08-21T09:10:00Z", "Bash: git commit -m done"),
        ])
        result = run_py(SUPERVISOR, "digest", "--repo", str(repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn("recall digest", out)
        self.assertIn("alpha", out)
        # Two session groups, newest last, spans shown.
        self.assertIn("session aaaa1111", out)
        self.assertIn("session bbbb2222", out)
        self.assertLess(out.index("session aaaa1111"),
                        out.index("session bbbb2222"))
        # Rows are addressed by 8-hex entry-hash prefixes, genesis excluded.
        self.assertIn(h1[1][:8], out)
        self.assertIn(h2[2][:8], out)
        self.assertNotIn(h1[0][:8], out)
        self.assertNotIn("genesis", out)
        # Each session's final entry carries the tag — a fact, not a guess.
        for line in out.splitlines():
            if h1[2][:8] in line or h2[2][:8] in line:
                self.assertIn("last recorded action", line)
            if h1[1][:8] in line or h2[1][:8] in line:
                self.assertNotIn("last recorded action", line)
        # Testimony label and the teaching footer.
        self.assertIn("testimony", out)
        self.assertIn("show", out)
        self.assertIn("search", out)

    def test_budget_cap_keeps_newest_and_says_so(self):
        repo = self.repo("alpha")
        steps = [(f"2026-08-20T10:{m:02d}:00Z", f"step {m}")
                 for m in range(10)]
        _, hashes = forge_chain(
            repo, "cccc3333-3333-3333-3333-333333333333", steps)
        result = run_py(SUPERVISOR, "digest", "--repo", str(repo),
                        "--limit", "4")
        out = result.stdout
        self.assertIn("showing last 4", out)
        self.assertIn("10 entries", out)
        for h in hashes[7:]:          # newest four survive
            self.assertIn(h[:8], out)
        for h in hashes[1:7]:         # oldest six evicted
            self.assertNotIn(h[:8], out)

    def test_since_filters_old_sessions(self):
        repo = self.repo("alpha")
        forge_chain(repo, "dddd4444-4444-4444-4444-444444444444",
                    [("2026-07-01T10:00:00Z", "ancient work")])
        _, fresh = forge_chain(repo, "eeee5555-5555-5555-5555-555555555555",
                               [("2026-08-25T10:00:00Z", "fresh work")])
        out = run_py(SUPERVISOR, "digest", "--repo", str(repo),
                     "--since", "2026-08-01").stdout
        self.assertIn(fresh[1][:8], out)
        self.assertNotIn("ancient work", out)

    def test_chainless_repo_is_silent_exit_zero(self):
        repo = self.repo("bare")
        result = run_py(SUPERVISOR, "digest", "--repo", str(repo))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")

    def test_digest_owns_no_verdicts_without_a_scan(self):
        repo = self.repo("alpha")
        forge_chain(repo, "ffff6666-6666-6666-6666-666666666666",
                    [("2026-08-25T10:00:00Z", "some work")])
        out = run_py(SUPERVISOR, "digest", "--repo", str(repo)).stdout
        # No scan has run: the digest must not invent an integrity line.
        self.assertIn("last scan: none recorded", out)
        self.assertNotIn("VALID", out)

    def test_digest_cites_scan_verdicts_as_testimony(self):
        repo = self.repo("alpha")
        forge_chain(repo, "abab7777-7777-7777-7777-777777777777",
                    [("2026-08-25T10:00:00Z", "some work")])
        witness = self.root / "no-witness"
        witness.mkdir()
        scan = run_py(SUPERVISOR, "scan", "--root", str(self.root),
                      "--witness", str(witness), "--json")
        self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
        out = run_py(SUPERVISOR, "digest", "--repo", str(repo)).stdout
        self.assertIn("last scan:", out)
        self.assertIn("VALID", out)
        self.assertIn("testimony", out.split("last scan:")[1].splitlines()[0])

    def test_parity_with_cli_built_chain(self):
        repo = self.repo("alpha")
        log = repo / "receipts" / ("receipts-"
                                   "cdcd8888-8888-8888-8888-888888888888"
                                   ".jsonl")
        log.parent.mkdir(parents=True)
        run_py(RECEIPTS, "init", "--log", str(log))
        run_py(RECEIPTS, "log", "--log", str(log), "--actor", "tester",
               "--action", "cli-built entry")
        out = run_py(SUPERVISOR, "digest", "--repo", str(repo)).stdout
        self.assertIn("cli-built entry", out)


class ShowTest(RecallBase):
    def test_full_entry_self_verified(self):
        repo = self.repo("alpha")
        _, hashes = forge_chain(repo, "1212aaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", [
            ("2026-08-20T10:00:00Z", "Edit: one.py"),
            ("2026-08-20T10:05:00Z", "Bash: pytest -q"),
        ])
        result = run_py(SUPERVISOR, "show", hashes[2][:8],
                        "--repo", str(repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn("Bash: pytest -q", out)
        self.assertIn(hashes[2], out)          # full hash printed
        self.assertIn("self-verified", out)
        self.assertIn("timeline", out)         # points at the next rung

    def test_ambiguous_prefix_lists_candidates(self):
        repo = self.repo("alpha")
        # Two chains with byte-identical content produce identical entry
        # hashes — the deterministic way to make a prefix ambiguous.
        steps = [("2026-08-20T10:00:00Z", "the twin step")]
        _, h_one = forge_chain(
            repo, "3434bbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", steps)
        _, h_two = forge_chain(
            repo, "5656eeee-eeee-eeee-eeee-eeeeeeeeeeee", steps)
        self.assertEqual(h_one[1], h_two[1])
        result = run_py(SUPERVISOR, "show", h_one[1][:8],
                        "--repo", str(repo))
        self.assertNotEqual(result.returncode, 0)
        message = result.stdout + result.stderr
        self.assertIn("ambiguous", message.lower())
        self.assertIn("3434bbbb", message)
        self.assertIn("5656eeee", message)

    def test_unknown_and_malformed_addresses_error(self):
        repo = self.repo("alpha")
        forge_chain(repo, "5656cccc-cccc-cccc-cccc-cccccccccccc",
                    [("2026-08-20T10:00:00Z", "only entry")])
        for bad in ("zzzz9999", "abc"):   # non-hex; shorter than 4 chars
            result = run_py(SUPERVISOR, "show", bad, "--repo", str(repo))
            self.assertNotEqual(result.returncode, 0, bad)

    def test_tampered_entry_warns_instead_of_verifying(self):
        repo = self.repo("alpha")
        log, hashes = forge_chain(repo, "7878dddd-dddd-dddd-dddd-dddddddddddd", [
            ("2026-08-20T10:00:00Z", "the honest step"),
        ])
        lines = log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["action"] = "the rewritten step"   # hash left stale
        lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        log.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
        result = run_py(SUPERVISOR, "show", hashes[1][:8],
                        "--repo", str(repo))
        self.assertNotEqual(result.returncode, 0)
        out = result.stdout + result.stderr
        self.assertIn("does not verify", out)
        self.assertIn("receipts verify", out)


class SearchTest(RecallBase):
    def make_two_repos(self):
        alpha = self.repo("alpha")
        beta = self.repo("beta")
        _, ha = forge_chain(alpha, "9090eeee-eeee-eeee-eeee-eeeeeeeeeeee",
                            [("2026-08-20T10:00:00Z", "alpha-needle work")])
        _, hb = forge_chain(beta, "b0b0ffff-ffff-ffff-ffff-ffffffffffff",
                            [("2026-08-21T10:00:00Z", "beta-needle work")])
        return alpha, beta, ha, hb

    def test_local_search_stays_in_repo(self):
        alpha, beta, ha, hb = self.make_two_repos()
        hit = run_py(SUPERVISOR, "search", "alpha-needle",
                     "--repo", str(alpha))
        self.assertIn(ha[1][:8], hit.stdout)
        miss = run_py(SUPERVISOR, "search", "beta-needle",
                      "--repo", str(alpha))
        self.assertIn("matched 0", miss.stdout)

    def test_all_reaches_other_repos(self):
        alpha, beta, ha, hb = self.make_two_repos()
        out = run_py(SUPERVISOR, "search", "beta-needle", "--all",
                     "--repo", str(alpha), "--root", str(self.root)).stdout
        self.assertIn(hb[1][:8], out)
        self.assertIn("beta", out)
        self.assertIn("testimony", out)

    def test_all_respects_unlisted_but_home_repo_still_sees_itself(self):
        alpha, beta, ha, hb = self.make_two_repos()
        (beta / "receipts" / ".unlisted").write_text("", encoding="utf-8")
        from_alpha = run_py(SUPERVISOR, "search", "beta-needle", "--all",
                            "--repo", str(alpha), "--root", str(self.root))
        self.assertIn("matched 0", from_alpha.stdout)
        from_beta = run_py(SUPERVISOR, "search", "beta-needle", "--all",
                           "--repo", str(beta), "--root", str(self.root))
        self.assertIn(hb[1][:8], from_beta.stdout)

    def test_limit_reports_full_match_count(self):
        alpha = self.repo("alpha")
        steps = [(f"2026-08-20T10:{m:02d}:00Z", f"needle {m}")
                 for m in range(6)]
        forge_chain(alpha, "d0d01111-2222-3333-4444-555566667777", steps)
        out = run_py(SUPERVISOR, "search", "needle", "--repo", str(alpha),
                     "--limit", "2").stdout
        self.assertIn("matched 6", out)
        self.assertIn("showing 2", out)


class TimelineTest(RecallBase):
    def test_context_rows_around_anchor(self):
        repo = self.repo("alpha")
        steps = [(f"2026-08-20T10:{m:02d}:00Z", f"step {m}")
                 for m in range(7)]
        _, hashes = forge_chain(
            repo, "e0e01111-2222-3333-4444-555566667777", steps)
        result = run_py(SUPERVISOR, "timeline", hashes[4][:8],
                        "--repo", str(repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        for h in hashes[1:8]:
            self.assertIn(h[:8], out)
        anchor_line = next(l for l in out.splitlines()
                           if l.startswith(hashes[4][:8]))
        self.assertIn("here", anchor_line)
        self.assertIn("testimony", out)


class ScanSummaryTest(RecallBase):
    def test_scan_persists_verdict_summary_in_baseline(self):
        repo = self.repo("alpha")
        forge_chain(repo, "f0f01111-2222-3333-4444-555566667777",
                    [("2026-08-25T10:00:00Z", "some work")])
        witness = self.root / "no-witness"
        witness.mkdir()
        run_py(SUPERVISOR, "scan", "--root", str(self.root),
               "--witness", str(witness), "--json")
        baseline = json.loads(
            (self.root / ".supervisor-baseline.json").read_text(
                encoding="utf-8"))
        self.assertIn("scanned", baseline)
        rows = baseline["chains"]
        self.assertTrue(rows)
        for row in rows.values():
            self.assertEqual(row.get("verdict"), "VALID")


class InstallerTest(RecallBase):
    def run_dogfood(self, *args):
        home = self.root / "home"
        home.mkdir(exist_ok=True)
        return run_py(DOGFOOD, *args, env_extra={
            "HOME": str(home), "USERPROFILE": str(home)}), home

    def settings(self, home):
        return json.loads((home / ".claude" / "settings.json").read_text(
            encoding="utf-8"))

    def test_install_wires_recording_and_digest_hooks(self):
        result, home = self.run_dogfood("install-global")
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = self.settings(home)
        post = json.dumps(settings["hooks"]["PostToolUse"])
        start = json.dumps(settings["hooks"]["SessionStart"])
        self.assertIn("receipts.py", post)
        # Every shell the harness offers is matched — omitting one
        # (PowerShell, on Windows desktop) silently loses sessions.
        self.assertIn("PowerShell", post)
        self.assertIn("supervisor.py", start)
        self.assertIn("digest", start)
        self.assertIn("startup|clear|compact",
                      json.dumps(settings["hooks"]["SessionStart"]))

    def test_install_is_idempotent(self):
        _, home = self.run_dogfood("install-global")
        again, _ = self.run_dogfood("install-global")
        self.assertEqual(again.returncode, 0)
        settings = self.settings(home)
        self.assertEqual(len(settings["hooks"]["PostToolUse"]), 1)
        self.assertEqual(len(settings["hooks"]["SessionStart"]), 1)

    def test_uninstall_removes_both_and_leaves_others(self):
        _, home = self.run_dogfood("install-global")
        path = home / ".claude" / "settings.json"
        settings = self.settings(home)
        settings["hooks"]["PostToolUse"].append(
            {"matcher": "*", "hooks": [{"type": "command",
                                        "command": "somebody-else"}]})
        path.write_text(json.dumps(settings), encoding="utf-8")
        result, _ = self.run_dogfood("uninstall-global")
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = self.settings(home)
        text = json.dumps(settings)
        self.assertNotIn("receipts.py", text)
        self.assertNotIn("supervisor.py", text)
        self.assertIn("somebody-else", text)


if __name__ == "__main__":
    unittest.main()
