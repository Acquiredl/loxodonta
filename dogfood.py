#!/usr/bin/env python3
"""dogfood.py — daily-driver commands for the receipts dogfood.

Stdlib only, runs anywhere Python does (Windows PowerShell included).
The experiment itself — the bet, the decision date, the journal — is
DOGFOOD.md.

  python dogfood.py                 status: verdict for every session chain
  python dogfood.py report [LOG]    timeline of the newest (or named) chain
  python dogfood.py anchor          anchor every chain head to Bitcoin
  python dogfood.py upgrade         complete pending anchor proofs
  python dogfood.py drill           tamper fire drill on a scratch chain
  python dogfood.py note "..."      append a line to the DOGFOOD.md journal
  python dogfood.py install-global  wire the hook into ~/.claude/settings.json
                                    so every Claude Code session on this
                                    machine logs to <project>/receipts/
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
CHAIN_DIR = HERE / "receipts"


def receipts(*args, **kwargs):
    return subprocess.run([sys.executable, str(RECEIPTS), *args], **kwargs)


def chains():
    """Session chains in this repo, newest first (anchor sidecars excluded)."""
    logs = [p for p in CHAIN_DIR.glob("*.jsonl")
            if not p.name.endswith(".anchors.jsonl")]
    return sorted(logs, key=lambda p: p.stat().st_mtime, reverse=True)


def cmd_status(args):
    logs = chains()
    if not logs:
        print("no session chains in receipts/ yet — work a Claude Code "
              "session first (any repo, once the hook is installed)")
        return 0
    for log in logs:
        entries = sum(1 for _ in open(log, encoding="utf-8"))
        result = receipts("verify", "--log", str(log), "--anchors",
                          capture_output=True, text=True)
        lines = (result.stdout.strip() or "?").splitlines()
        print(f"{log.name:44} {entries:4} entries  {lines[-1]}")
        if result.returncode != 0:
            print(f"  !! exit {result.returncode} — full detail: "
                  f"python receipts.py verify --log {log} --anchors")
    return 0


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
                        text=True).stdout.strip()
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


def cmd_install_global(args):
    """Merge the hook into the user-level Claude Code settings, idempotently
    and without clobbering anything already there. The command carries no
    shell expansion — receipts.py reads CLAUDE_PROJECT_DIR itself — so the
    same line works whatever shell the harness runs hooks with. Restart open
    sessions afterward: hooks load at session start."""
    python = Path(sys.executable).as_posix()
    command = f'"{python}" "{RECEIPTS.as_posix()}" hook'
    path = Path.home() / ".claude" / "settings.json"

    settings = {}
    if path.exists():
        try:
            settings = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"refusing to touch {path}: it is not valid JSON ({e}) — "
                  "fix it by hand first", file=sys.stderr)
            return 1
        shutil.copy2(path, str(path) + ".bak")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)

    blocks = settings.setdefault("hooks", {}).setdefault("PostToolUse", [])
    already = [h.get("command", "") for b in blocks for h in b.get("hooks", [])
               if "receipts.py" in h.get("command", "")]
    if already:
        print(f"already installed in {path}:")
        for c in already:
            print(f"  {c}")
        return 0

    blocks.append({
        "matcher": "Edit|Write|NotebookEdit|Bash",
        "hooks": [{"type": "command", "command": command}],
    })
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")

    print(f"installed in {path}"
          + (" (previous version saved as settings.json.bak)"
             if Path(str(path) + ".bak").exists() else ""))
    print(f"  hook: {command}")
    print("every NEW Claude Code session on this machine now leaves a chain")
    print("in <project>/receipts/ — the hook creates the directory and a")
    print("protective .gitignore on first use. Restart open sessions.")
    return 0


COMMANDS = {
    "status": cmd_status,
    "report": cmd_report,
    "anchor": cmd_anchor,
    "upgrade": cmd_upgrade,
    "drill": cmd_drill,
    "note": cmd_note,
    "install-global": cmd_install_global,
}


def main(argv):
    command = argv[0] if argv else "status"
    if command not in COMMANDS:
        print(__doc__.strip(), file=sys.stderr)
        return 1
    return COMMANDS[command](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
