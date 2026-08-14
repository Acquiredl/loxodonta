"""Behavioral tests for the dogfood dashboard (`python dogfood.py`).

The dogfood is machine-wide: the hook writes a chain into whichever repo
each Claude Code session ran in. A status command that only reads this
repo's own receipts/ is blind to the experiment it is supposed to
measure — it reports "no session chains yet" while chains accumulate
next door. These tests drive the command surface, never internals.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOGFOOD = REPO_ROOT / "dogfood.py"
RECEIPTS = REPO_ROOT / "receipts.py"


def run_dogfood(*args, root):
    env = dict(os.environ)
    env["RECEIPTS_DOGFOOD_ROOT"] = str(root)
    return subprocess.run(
        [sys.executable, str(DOGFOOD), *args],
        capture_output=True, text=True, env=env,
    )


def make_chain(log_dir, session, entries=2):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the dashboard is tested against what the tool writes."""
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


class DogfoodStatusTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_status_finds_chains_across_sibling_repos(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        result = run_dogfood("status", root=self.root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sess-aaaa", result.stdout)
        self.assertIn("sess-bbbb", result.stdout)

    def test_status_names_the_repo_each_chain_came_from(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")

        result = run_dogfood("status", root=self.root)

        self.assertIn("alpha", result.stdout)

    def test_status_reports_each_chains_verdict_and_entry_count(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)

        result = run_dogfood("status", root=self.root)

        self.assertIn("VALID", result.stdout)
        self.assertIn("4", result.stdout)  # genesis + 3

    def test_status_finds_chains_left_in_worktrees(self):
        # Sessions logged before the main-repo fix put their chains inside
        # .claude/worktrees/<name>/receipts/. Those are still real history.
        make_chain(
            self.root / "alpha" / ".claude" / "worktrees" / "wt" / "receipts",
            "sess-legacy")

        result = run_dogfood("status", root=self.root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sess-legacy", result.stdout)

    def test_status_ignores_anchor_sidecars(self):
        # A sidecar is a proof *about* a chain, not a chain: it gets no row.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        Path(str(log) + ".anchors.jsonl").write_text("{}\n", encoding="utf-8")

        result = run_dogfood("status", root=self.root)

        rows = [line for line in result.stdout.splitlines()
                if "entries" in line]
        self.assertEqual(len(rows), 1, result.stdout)
        self.assertNotIn(".anchors", rows[0])

    def test_status_flags_a_tampered_chain(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        lines = log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["action"] = "something else entirely"
        lines[1] = json.dumps(entry)
        log.write_text("".join(l + "\n" for l in lines), encoding="utf-8")

        result = run_dogfood("status", root=self.root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BROKEN", result.stdout)

    def test_status_says_so_when_there_is_nothing_to_report(self):
        result = run_dogfood("status", root=self.root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no session chains", result.stdout)


class DogfoodDefaultRootTest(unittest.TestCase):
    """With no RECEIPTS_DOGFOOD_ROOT set, the search root is the folder the
    repos live in — and it has to be found from wherever dogfood.py is run.

    Run from inside a git worktree, the naive answer (the parent directory)
    is `.claude/worktrees/`, which contains no repos at all: the dashboard
    then reports on itself and nothing else. The root is resolved through
    the same main-repo logic the hook uses.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repos = Path(self._tmp.name) / "repos"
        self.repos.mkdir()

    def install(self, target):
        target.mkdir(parents=True, exist_ok=True)
        for script in (DOGFOOD, RECEIPTS):
            (target / script.name).write_text(
                script.read_text(encoding="utf-8"), encoding="utf-8")
        return target / DOGFOOD.name

    def test_default_root_is_the_repos_folder_when_run_from_a_worktree(self):
        main = self.repos / "mainrepo"
        (main / ".git").mkdir(parents=True)
        worktree = main / ".claude" / "worktrees" / "wt"
        gitdir = main / ".git" / "worktrees" / "wt"
        gitdir.mkdir(parents=True)
        (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
        script = self.install(worktree)
        (worktree / ".git").write_text(f"gitdir: {gitdir.as_posix()}\n",
                                       encoding="utf-8")
        make_chain(self.repos / "neighbour" / "receipts", "sess-next-door")

        env = dict(os.environ)
        env.pop("RECEIPTS_DOGFOOD_ROOT", None)
        result = subprocess.run([sys.executable, str(script), "status"],
                                capture_output=True, text=True, env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sess-next-door", result.stdout)
        self.assertIn("neighbour", result.stdout)

    def test_default_root_is_the_repos_folder_when_run_from_a_plain_repo(self):
        main = self.repos / "mainrepo"
        (main / ".git").mkdir(parents=True)
        script = self.install(main)
        make_chain(self.repos / "neighbour" / "receipts", "sess-next-door")

        env = dict(os.environ)
        env.pop("RECEIPTS_DOGFOOD_ROOT", None)
        result = subprocess.run([sys.executable, str(script), "status"],
                                capture_output=True, text=True, env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sess-next-door", result.stdout)


if __name__ == "__main__":
    unittest.main()
