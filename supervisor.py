#!/usr/bin/env python3
"""supervisor.py — the operator that never sleeps (ADR-0005).

A reader-side companion to receipts.py: it watches every receipt log
under a root full of repos and shouts on change — a tripwire with a
memory, never a wall. It drives receipts exclusively through the public
CLI and judges nothing itself: verdicts come from `receipts verify`,
and everything the supervisor holds is writer-reachable, so nothing
here is a head record (GLOSSARY: Supervisor, Baseline).

  python supervisor.py scan --root DIR --json

`scan` is one tick without timers: a census of every chain under the
root, a verdict for each, machine-readable JSON on stdout, and an exit
code cron can shout about — 0 when nothing demands attention, else the
worst verify exit found.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECEIPTS = HERE / "receipts.py"


# --- Census -------------------------------------------------------------------

def find_chains(root):
    """Every receipt log under the root. Three shapes, because history has
    three shapes: the root itself being a repo, each sibling repo's
    receipts/, and chains stranded in worktrees by sessions that ran
    before the hook learned to log to the main repo."""
    patterns = ("receipts/*.jsonl",
                "*/receipts/*.jsonl",
                "*/.claude/worktrees/*/receipts/*.jsonl")
    return sorted(p for pattern in patterns for p in root.glob(pattern))


def chain_identity(root, log):
    """(repo, session, seq) — which repo a chain belongs to, which session
    wrote it, and where it sits in the session's run of sibling chains,
    all read from where the log lies and what it is named.

    A sibling chain (`-002`, `-003`) is continuation by naming alone
    (ADR-0004): it belongs to the session named before the suffix, in
    suffix order. The unsuffixed chain is seq 1."""
    parts = log.relative_to(root).parts
    repo = root.name if parts[0] == "receipts" else parts[0]
    session = log.stem
    if session.startswith("receipts-"):
        session = session[len("receipts-"):]
    prefix, dash, tail = session.rpartition("-")
    seq = 1
    if dash and len(tail) == 3 and tail.isdigit():
        session, seq = prefix, int(tail)
    return repo, session, seq


# --- Verdict runner -----------------------------------------------------------

def verify(log):
    """The single seam to receipts (ADR-0005): one subprocess per chain,
    verdict read from the exit code and the documented verdict lines."""
    result = subprocess.run(
        [sys.executable, str(RECEIPTS), "verify", "--log", str(log)],
        capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()
    verdict = lines[-1].split(":")[0].split(" at ")[0] if lines else "NO-VERDICT"
    return verdict, result.returncode, lines


def sibling_of(log):
    """Where recording moved when this chain's tail tore (ADR-0004):
    receipts-<session>.jsonl continues in receipts-<session>-002.jsonl,
    and -002 continues in -003."""
    stem = log.name[:-len(".jsonl")]
    prefix, dash, tail = stem.rpartition("-")
    if dash and len(tail) == 3 and tail.isdigit():
        stem = f"{prefix}-{int(tail) + 1:03d}"
    else:
        stem += "-002"
    return log.with_name(stem + ".jsonl")


def superseded(log, detail):
    """True when this chain's only damage is the honest crash pattern — a
    torn final line — and a sibling exists beside it: ADR-0004 already
    handled this tear, and recording continued. The tear stays in the
    report as evidence; only the exit code stands down, or the scan
    becomes an alarm that never stops sounding. Any other damage is
    tampering to shout about, sibling or not."""
    broken = [l for l in detail if l.startswith("BROKEN")]
    return (len(broken) == 1 and "torn tail" in broken[0]
            and sibling_of(log).exists())


# --- Scan ---------------------------------------------------------------------

def cmd_scan(args):
    root = Path(args.root).resolve()
    repos = {}
    worst = 0
    for log in find_chains(root):
        repo, session, seq = chain_identity(root, log)
        verdict, exit_code, detail = verify(log)
        stood_down = exit_code != 0 and superseded(log, detail)
        entries = sum(1 for _ in open(log, encoding="utf-8"))
        chain = {
            "log": log.as_posix(),
            # Stranded in a worktree: still this repo's history, but pruning
            # the worktree deletes it — worth saying, not worth hiding.
            "worktree": ".claude" in log.relative_to(root).parts,
            "entries": entries,
            "verdict": verdict,
            "exit": exit_code,
            "superseded": stood_down,
            "detail": detail,
        }
        repos.setdefault(repo, {}).setdefault(session, []).append((seq, chain))
        if not stood_down:
            worst = max(worst, exit_code)

    report = {
        "root": root.as_posix(),
        "exit": worst,
        "repos": [
            {"repo": repo,
             "sessions": [{"session": session,
                           "chains": [c for _, c in sorted(chains,
                                                           key=lambda s: s[0])]}
                          for session, chains in sorted(sessions.items())]}
            for repo, sessions in sorted(repos.items())
        ],
    }
    print(json.dumps(report, indent=None if args.json else 2))
    return worst


def main(argv):
    parser = argparse.ArgumentParser(prog="supervisor",
                                     description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="one tick: census + verdicts, JSON out, exit code")
    scan.add_argument("--root", required=True,
                      help="the folder your repos live in")
    scan.add_argument("--json", action="store_true",
                      help="compact machine output (default pretty-prints)")
    scan.set_defaults(func=cmd_scan)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
