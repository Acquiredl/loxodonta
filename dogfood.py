#!/usr/bin/env python3
"""dogfood.py — daily-driver commands for the receipts dogfood.

Stdlib only, runs anywhere Python does (Windows PowerShell included).
The experiment itself — the bet, the decision date, the journal — is
DOGFOOD.md (a local, operator-side journal; gitignored).

  python dogfood.py                 status: verdict for every session chain
                                    found across every repo (see below)
  python dogfood.py report [LOG]    timeline of the newest (or named) chain
  python dogfood.py anchor          anchor every chain head to Bitcoin
  python dogfood.py upgrade         complete pending anchor proofs
  python dogfood.py drill           tamper fire drill on a scratch chain
  python dogfood.py note "..."      append a line to the local DOGFOOD.md journal
  python dogfood.py install-global  wire the hooks into ~/.claude/settings.json:
                                    every Claude Code session on this machine
                                    logs to <project>/receipts/ and starts
                                    with a recall digest of that repo
  python dogfood.py uninstall-global  remove exactly those hooks again

Chains are searched for under the directory holding this repo — the folder
your repos live in. Point the search somewhere else with the environment
variable RECEIPTS_DOGFOOD_ROOT.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECEIPTS = HERE / "receipts.py"

sys.path.insert(0, str(HERE))
from receipts import main_repo_root  # noqa: E402  (needs HERE on the path)

# The dogfood is machine-wide: the hook writes a chain into whichever repo
# each session ran in, so the dashboard has to look across all of them. The
# default search root is the folder holding this repo — i.e. where your
# repos live — and never a path hardcoded into a public repo.
#
# Resolve this repo's root the same way the hook does. Run from a worktree,
# the naive parent directory is `.claude/worktrees/`, which holds no repos:
# the dashboard would find only itself and report an empty experiment.
DOGFOOD_ROOT = Path(
    os.environ.get("RECEIPTS_DOGFOOD_ROOT")
    or Path(main_repo_root(str(HERE))).parent
).resolve()


def receipts(*args, **kwargs):
    # The child is pinned to UTF-8 output so it always agrees with the
    # encoding="utf-8" the text-mode call sites pass — the invoking shell's
    # locale (cp1252 on Windows) never gets to sit between the two.
    env = dict(kwargs.pop("env", os.environ))
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(RECEIPTS), *args],
                          env=env, **kwargs)


def chains():
    """Every session chain under DOGFOOD_ROOT, newest first.

    Three shapes, because history has three shapes: the root itself being a
    repo, each sibling repo's receipts/, and chains stranded in worktrees by
    sessions that ran before the hook learned to log to the main repo.
    Anchor sidecars are proofs about a chain, not chains.
    """
    patterns = ("receipts/*.jsonl",
                "*/receipts/*.jsonl",
                "*/.claude/worktrees/*/receipts/*.jsonl")
    logs = {p.resolve() for pattern in patterns
            for p in DOGFOOD_ROOT.glob(pattern)
            if not p.name.endswith(".anchors.jsonl")}
    return sorted(logs, key=lambda p: p.stat().st_mtime, reverse=True)


def describe(log):
    """(repo, session) — which project a chain came from, and which session
    wrote it. The filename alone is a bare UUID; the repo is the part a
    human actually recognises."""
    session = log.stem
    if session.startswith("receipts-"):
        session = session[len("receipts-"):]
    try:
        parts = log.relative_to(DOGFOOD_ROOT).parts
        repo = DOGFOOD_ROOT.name if parts[0] == "receipts" else parts[0]
    except ValueError:
        repo = log.parent.parent.name
    if ".claude" in log.parts:
        repo += " (worktree)"  # stranded: pruning the worktree deletes it
    return repo, session


def fold(lines):
    """[(line, count)] with adjacent duplicates merged, order preserved.

    One anchor submission produces one line per calendar, differing only in
    the calendar URL and a second or two of timestamp. Collapsing them on
    their leading clause keeps four near-identical lines from burying the
    verdict they belong to."""
    folded = []
    for line in lines:
        key = line.split(" via ")[0].split(" submitted ")[0]
        if folded and folded[-1][0] == key:
            folded[-1][1] += 1
        else:
            folded.append([key, 1])
    return [(key, count) for key, count in folded]


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


def superseded(log, verdict_lines):
    """True when this chain's only damage is the honest crash pattern — a
    torn final line — and a sibling exists beside it: ADR-0004 already
    handled this tear, and recording continued. The tear stays printed as
    evidence; only the exit code stands down, or the dashboard becomes an
    alarm that never stops sounding. Any other damage is tampering to
    shout about, sibling or not."""
    broken = [l for l in verdict_lines if l.startswith("BROKEN")]
    return (len(broken) == 1 and "torn tail" in broken[0]
            and sibling_of(log).exists())


def cmd_status(args):
    logs = chains()
    if not logs:
        print(f"no session chains under {DOGFOOD_ROOT} yet — work a Claude "
              "Code session first (any repo, once the hook is installed)")
        return 0
    worst = 0
    for log in logs:
        repo, session = describe(log)
        entries = sum(1 for _ in open(log, encoding="utf-8"))
        result = receipts("verify", "--log", str(log), "--anchors",
                          capture_output=True, encoding="utf-8",
                          errors="replace")
        lines = (result.stdout.strip() or "?").splitlines()
        # verify prints its verdict last, with anchor and warning lines
        # above it. Showing only the verdict hides exactly the half the
        # operator is supposed to read — whether the chain is anchored, and
        # to which block (ANCHORING.md §5). Anchor lines repeat once per
        # calendar, so identical ones are folded into a count.
        print(f"{repo:30} {session:38} {entries:5} entries  {lines[-1]}")
        for note, count in fold(l for l in lines[:-1] if l.startswith("ANCHOR")):
            print(f"     {count}x  {note}" if count > 1 else f"     {note}")
        if result.returncode != 0:
            if superseded(log, lines):
                print(f"     ended here — recording continued in "
                      f"{sibling_of(log).name} (ADR-0004)")
                continue
            # A failing chain is the whole point of the tool — surface it in
            # the exit code too, so a scheduled run can shout.
            worst = max(worst, result.returncode)
            print(f"  !! exit {result.returncode} — full detail: "
                  f"python receipts.py verify --log {log} --anchors")
    return worst


def cmd_report(args):
    log = Path(args[0]) if args else (chains()[0] if chains() else None)
    if log is None:
        print("no session chains in receipts/ yet", file=sys.stderr)
        return 1
    receipts("report", "--log", str(log))
    print()
    receipts("verify", "--log", str(log), "--anchors")
    return 0


def cmd_anchor(args):
    for log in chains():
        receipts("anchor", "--log", str(log))
    return 0


def cmd_upgrade(args):
    for log in chains():
        if Path(str(log) + ".anchors.jsonl").exists():
            receipts("anchor", "--upgrade", "--log", str(log))
    return 0


def spec_hash(entry_without_hash):
    canonical = json.dumps(entry_without_hash, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def cmd_drill(args):
    """The fire drill: attack a scratch chain the way the writer would, and
    confirm the alarm sounds. A tamper-evidence tool that has never caught
    tampering in the field is untested in the way that matters."""
    results = []

    def check(name, expected, actual):
        ok = expected == actual
        print(f"{'PASS' if ok else 'FAIL'}  {name}"
              + ("" if ok else f" (expected exit {expected}, got {actual})"))
        results.append(ok)

    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "drill.jsonl"
        receipts("init", "--log", str(log), capture_output=True)
        for action in ("step one", "the incriminating step", "step three"):
            receipts("log", "--log", str(log), "--actor", "drill",
                     "--action", action, capture_output=True)
        head = receipts("head", "--log", str(log), capture_output=True,
                        encoding="utf-8").stdout.strip()
        pristine = log.read_text(encoding="utf-8")

        def verify(path, *extra):
            return receipts("verify", "--log", str(path), *extra,
                            capture_output=True).returncode

        # Attack 1: edit a past entry in place.
        edited = Path(tmp) / "edited.jsonl"
        lines = pristine.splitlines()
        entry = json.loads(lines[2])
        entry["action"] = "the incriminating step (rewritten)"
        lines[2] = json.dumps(entry)
        edited.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
        check("edited entry is caught (BROKEN)", 1, verify(edited))

        # Attack 2: delete an entry.
        deleted = Path(tmp) / "deleted.jsonl"
        lines = pristine.splitlines()
        del lines[2]
        deleted.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
        check("deleted entry is caught (BROKEN)", 1, verify(deleted))

        # Attack 3: the adversary's best move — drop an entry and recompute
        # every hash so the chain is internally consistent again (ADR-0002).
        regen = Path(tmp) / "regen.jsonl"
        entries = [json.loads(l) for l in pristine.splitlines()]
        del entries[2]
        prev = entries[0]["entry_hash"]
        for i, entry in enumerate(entries[1:], start=1):
            entry.pop("entry_hash")
            entry["n"] = i
            entry["prev"] = prev
            prev = entry["entry_hash"] = spec_hash(entry)
        regen.write_text(
            "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n"
                    for e in entries), encoding="utf-8")
        check("regenerated chain fools plain verify (the known gap)",
              0, verify(regen))
        check("regeneration caught against the head record (HEAD-MISMATCH)",
              3, verify(regen, "--expect-head", head))

    print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
    return 0 if all(results) else 1


def cmd_note(args):
    if not args:
        print('usage: python dogfood.py note "what happened"', file=sys.stderr)
        return 1
    line = f"- {date.today().isoformat()}: {' '.join(args)}\n"
    with open(HERE / "DOGFOOD.md", "a", encoding="utf-8", newline="\n") as f:
        f.write(line)
    print(line, end="")
    return 0


def load_settings(path):
    """The user-level settings, or None with the complaint printed —
    shared by install and uninstall so both refuse broken JSON the
    same way instead of clobbering it."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"refusing to touch {path}: it is not valid JSON ({e}) — "
              "fix it by hand first", file=sys.stderr)
        return None


def cmd_install_global(args):
    """Merge both hooks into the user-level Claude Code settings,
    idempotently and without clobbering anything already there: the
    PostToolUse recorder (every tool call leaves a receipt) and the
    SessionStart digest (Stage E, ADR-0009 — the session starts
    oriented). Each is checked separately, so an install that predates
    the digest gains it on re-run. The commands carry no shell
    expansion — both tools read CLAUDE_PROJECT_DIR themselves — and the
    digest is fail-open: a short timeout, and a chainless repo renders
    nothing. Restart open sessions afterward: hooks load at start."""
    python = Path(sys.executable).as_posix()
    supervisor = HERE / "supervisor.py"
    record = f'"{python}" "{RECEIPTS.as_posix()}" hook'
    digest = f'"{python}" "{supervisor.as_posix()}" digest'
    path = Path.home() / ".claude" / "settings.json"

    settings = load_settings(path)
    if settings is None:
        return 1
    if path.exists():
        shutil.copy2(path, str(path) + ".bak")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)

    hooks = settings.setdefault("hooks", {})
    installed = []

    post = hooks.setdefault("PostToolUse", [])
    if not any("receipts.py" in h.get("command", "")
               for b in post for h in b.get("hooks", [])):
        post.append({
            # State-changing tools only — and every shell the harness
            # offers: the desktop app on Windows runs most commands
            # through a PowerShell tool, and a matcher without it
            # sleeps through exactly the sessions it should record
            # (found in the field: this repo's own launch left almost
            # no receipts).
            "matcher": "Edit|Write|NotebookEdit|Bash|PowerShell",
            "hooks": [{"type": "command", "command": record}],
        })
        installed.append(f"PostToolUse: {record}")

    start = hooks.setdefault("SessionStart", [])
    if not any("supervisor.py" in h.get("command", "")
               for b in start for h in b.get("hooks", [])):
        start.append({
            "matcher": "startup|clear|compact",
            "hooks": [{"type": "command", "command": digest,
                       "timeout": 5}],
        })
        installed.append(f"SessionStart: {digest}")

    if not installed:
        print(f"already installed in {path} (recorder and digest both)")
        return 0

    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"installed in {path}"
          + (" (previous version saved as settings.json.bak)"
             if Path(str(path) + ".bak").exists() else ""))
    for line in installed:
        print(f"  {line}")
    print("every NEW Claude Code session on this machine now leaves a chain")
    print("in <project>/receipts/ and starts with a recall digest of that")
    print("repo's recent history. Restart open sessions.")
    return 0


def cmd_uninstall_global(args):
    """Remove exactly our hooks — recorder and digest — from the
    user-level settings, leaving everything else untouched. The
    symmetric half of install-global."""
    path = Path.home() / ".claude" / "settings.json"
    settings = load_settings(path)
    if settings is None:
        return 1
    if not settings:
        print("nothing installed: no user-level settings file")
        return 0

    ours = ("receipts.py", "supervisor.py")
    removed = []
    hooks = settings.get("hooks", {})
    for event in ("PostToolUse", "SessionStart"):
        kept_blocks = []
        for block in hooks.get(event, []):
            entries = [h for h in block.get("hooks", [])
                       if not any(marker in h.get("command", "")
                                  for marker in ours)]
            if len(entries) != len(block.get("hooks", [])):
                removed.append(event)
            if entries or "hooks" not in block:
                block["hooks"] = entries
                kept_blocks.append(block)
        if kept_blocks:
            hooks[event] = kept_blocks
        elif event in hooks:
            del hooks[event]

    if not removed:
        print(f"nothing of ours found in {path}")
        return 0

    shutil.copy2(path, str(path) + ".bak")
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"removed from {path}: {', '.join(sorted(set(removed)))}"
          " (previous version saved as settings.json.bak)")
    return 0


COMMANDS = {
    "status": cmd_status,
    "report": cmd_report,
    "anchor": cmd_anchor,
    "upgrade": cmd_upgrade,
    "drill": cmd_drill,
    "note": cmd_note,
    "install-global": cmd_install_global,
    "uninstall-global": cmd_uninstall_global,
}


def main(argv):
    command = argv[0] if argv else "status"
    if command not in COMMANDS:
        print(__doc__.strip(), file=sys.stderr)
        return 1
    return COMMANDS[command](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
