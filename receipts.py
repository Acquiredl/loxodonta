#!/usr/bin/env python3
"""receipts — a tamper-evident, hash-chained receipt log for AI agent pipelines.

Stdlib only. Format spec: docs/SPEC.md (v0.1, frozen).
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

FORMAT_VERSION = "0.1"
DEFAULT_LOG = "receipts.jsonl"

ENTRY_FIELDS = {"n", "ts", "actor", "action", "files", "prev", "entry_hash"}
GENESIS_FIELDS = ENTRY_FIELDS | {"v"}


# --- Canonical form (SPEC §4) -------------------------------------------------
#
# The entry_hash is SHA256 over the canonical JSON of the entry minus its
# entry_hash field: keys sorted, compact separators, UTF-8, no trailing
# newline. These bytes are the format's ground truth — an independent
# implementation must reproduce them exactly.

def canonical_bytes(entry_without_hash):
    return json.dumps(
        entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def entry_hash(entry_without_hash):
    return hashlib.sha256(canonical_bytes(entry_without_hash)).hexdigest()


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_line(entry):
    """One complete log line for a finished entry (hash included)."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"


def read_log(path):
    """All lines of the receipt log; FileNotFoundError if it doesn't exist."""
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def missing_log(path):
    print(f"error: {path} not found — run `receipts init` first", file=sys.stderr)
    return 1


# --- Commands -----------------------------------------------------------------

def cmd_init(args):
    genesis = {
        "v": FORMAT_VERSION,
        "n": 0,
        "ts": now_ts(),
        "actor": "receipts",
        "action": "genesis",
        "files": [],
        "prev": None,
    }
    genesis["entry_hash"] = entry_hash(genesis)
    try:
        with open(args.log, "x", encoding="utf-8", newline="\n") as f:
            f.write(entry_line(genesis))
    except FileExistsError:
        print(f"error: {args.log} already exists; refusing to overwrite", file=sys.stderr)
        return 1
    print(f"initialized {args.log}")
    return 0


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def file_reference(log_dir, raw_path):
    """Build a {path, sha256} reference per SPEC §3. Paths are stored and
    hashed relative to the log's directory."""
    path = raw_path.replace("\\", "/")
    # SPEC §3: absolute and `..` paths are rejected, never silently rewritten —
    # a file outside the log's directory usually means the log is misplaced.
    if os.path.isabs(path) or (len(path) > 1 and path[1] == ":"):
        raise ValueError(f"absolute path not allowed: {raw_path}")
    if ".." in path.split("/"):
        raise ValueError(f"path may not contain '..': {raw_path}")
    try:
        sha256 = sha256_file(os.path.join(log_dir, path))
    except FileNotFoundError:
        raise ValueError(f"file not found: {raw_path}")
    return {"path": path, "sha256": sha256}


def append_entry(log, actor, action, file_paths):
    """Append one chained entry. Shared by `log` and `run` — run introduces
    no new schema fields (SPEC §7)."""
    log_dir = os.path.dirname(os.path.abspath(log))
    try:
        files = [file_reference(log_dir, p) for p in file_paths]
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    files.sort(key=lambda ref: ref["path"])  # by path bytes (SPEC §3)
    try:
        lines = read_log(log)
    except FileNotFoundError:
        return missing_log(log)
    if not lines:
        print(f"error: {log} is empty — run `receipts init` first", file=sys.stderr)
        return 1
    # A new entry chains to the tail; a damaged tail cannot anchor one.
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError:
        last = None
    if not isinstance(last, dict) or "entry_hash" not in last or "n" not in last:
        print(f"error: {log} has a damaged final line — run `receipts verify` "
              "(appending would bury the damage)", file=sys.stderr)
        return 1

    # SPEC §3: case-insensitivity belongs to filesystems, not the format.
    # Catch a case-only respelling here, on the machine that knows.
    known_paths = {ref["path"] for line in lines for ref in json.loads(line)["files"]}
    for ref in files:
        for known in known_paths:
            if ref["path"] != known and ref["path"].lower() == known.lower():
                print(f"warning: {ref['path']} differs only by case from "
                      f"already-referenced {known}", file=sys.stderr)

    entry = {
        "n": last["n"] + 1,
        "ts": now_ts(),
        "actor": actor,
        "action": action,
        "files": files,
        "prev": last["entry_hash"],
    }
    entry["entry_hash"] = entry_hash(entry)
    # Single write of one complete line (SPEC §1): a crash can at worst
    # truncate this line, never damage earlier entries.
    with open(log, "a", encoding="utf-8", newline="\n") as f:
        f.write(entry_line(entry))
    print(f"logged entry {entry['n']}")
    return 0


def cmd_log(args):
    if not args.actor or not args.action:
        print("error: --actor and --action must be non-empty", file=sys.stderr)
        return 1
    return append_entry(args.log, args.actor, args.action, args.file)


def cmd_run(args):
    # No log means no receipt could be written — refuse before the command
    # runs, or the wrapper would execute work it cannot record.
    if not os.path.exists(args.log):
        return missing_log(args.log)
    # Run first, hash after: the receipt records what the command actually
    # did, and the invoked process cannot prevent or shape it (SPEC §7).
    completed = subprocess.run(args.command_argv)
    action = f"run: {' '.join(args.command_argv)} (exit {completed.returncode})"
    if append_entry(args.log, args.actor, action, args.file) != 0:
        # A lost receipt must never hide behind the command's success code.
        print(f"error: receipt not written for: {action}", file=sys.stderr)
        return 1
    return completed.returncode


def cmd_head(args):
    try:
        lines = read_log(args.log)
    except FileNotFoundError:
        return missing_log(args.log)
    if not lines:
        print(f"error: {args.log} is empty — no chain head to print", file=sys.stderr)
        return 1
    print(json.loads(lines[-1])["entry_hash"])
    return 0


def walk(lines):
    """The mechanical walk of SPEC §6, shared by verify (which judges) and
    report (which narrates). Returns (entries, breaks, warns): entries[n] is
    the parsed entry or None where the line is unparseable; breaks and warns
    are (n, message) lists in walk order."""
    entries = []
    breaks = []
    warns = []
    prev_hash = None
    prev_ts = None
    for n, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            if n == len(lines) - 1:
                # The one honest damage signature: a crash mid-append can
                # truncate the final line and nothing else (SPEC §6).
                breaks.append((n, f"BROKEN: torn tail at line {n} (crash-"
                                  f"truncated append; entries 0..{n - 1} intact)"))
            else:
                breaks.append((n, f"BROKEN at entry {n}: line is not valid JSON"))
            entries.append(None)
            prev_hash = None
            continue
        if not isinstance(entry, dict):
            breaks.append((n, f"BROKEN at entry {n}: line is not a JSON object"))
            entries.append(None)
            prev_hash = None
            continue
        entries.append(entry)
        expected_fields = GENESIS_FIELDS if n == 0 else ENTRY_FIELDS
        if set(entry) != expected_fields:
            odd = set(entry) ^ expected_fields
            breaks.append((n, f"BROKEN at entry {n}: schema mismatch: "
                              f"{', '.join(sorted(odd))}"))
        if entry.get("n") != n:
            breaks.append((n, f"BROKEN at entry {n}: sequence number is "
                              f"{entry.get('n')}, expected {n}"))
        if entry.get("prev") != prev_hash:
            breaks.append((n, f"BROKEN at entry {n}: prev does not match "
                              "predecessor's entry_hash"))
        stored_hash = entry.get("entry_hash")
        hashed_form = {k: v for k, v in entry.items() if k != "entry_hash"}
        if entry_hash(hashed_form) != stored_hash:
            breaks.append((n, f"BROKEN at entry {n}: entry_hash does not "
                              "match canonical form"))
        # ts is writer-supplied testimony, not a mechanical fact: a backward
        # jump warns but never changes the verdict (SPEC §6, ADR-0002).
        ts = entry.get("ts")
        if prev_ts is not None and ts is not None and ts < prev_ts:
            warns.append((n, f"WARN: ts decreases at entry {n} — clock skew "
                             "at write time?"))
        prev_ts = ts
        prev_hash = stored_hash
    return entries, breaks, warns


def cmd_verify(args):
    try:
        lines = read_log(args.log)
    except FileNotFoundError:
        return missing_log(args.log)
    if not lines:
        print(f"error: {args.log} is empty — not a receipt log", file=sys.stderr)
        return 1

    # SPEC §2.1: read the genesis version before applying any other rule.
    # The refusal is only for a *claimed* version we don't speak. A genesis
    # with no version claim at all (damaged, non-object, or v stripped) is
    # the walk's business — that's tampering to judge, not a dialect to
    # politely decline.
    try:
        genesis = json.loads(lines[0])
    except json.JSONDecodeError:
        genesis = None
    log_version = genesis.get("v", FORMAT_VERSION) if isinstance(genesis, dict) \
        else FORMAT_VERSION
    if log_version != FORMAT_VERSION:
        print(
            f'UNSUPPORTED-VERSION: log is format "{log_version}"; '
            f'this verifier speaks "{FORMAT_VERSION}"'
        )
        return 4

    entries, breaks, warns = walk(lines)
    for _, message in warns:
        print(message, file=sys.stderr)
    if breaks:
        for _, message in breaks:
            print(message)
        return 1

    diverged = 0
    if args.files:
        # Latest reference per path is authoritative (GLOSSARY: file reference).
        latest = {}
        for entry in entries:
            for ref in entry["files"]:
                latest[ref["path"]] = ref["sha256"]
        log_dir = os.path.dirname(os.path.abspath(args.log))
        for path in sorted(latest):
            try:
                on_disk = sha256_file(os.path.join(log_dir, path))
            except FileNotFoundError:
                print(f"MISSING (not on disk): {path}")
                continue
            if on_disk == latest[path]:
                print(f"CURRENT: {path}")
            else:
                print(f"MODIFIED-SINCE-LOGGED: {path}")
                diverged += 1
        if diverged:
            print(f"FILES-DIVERGED: chain intact, {diverged} file(s) "
                  "differ from their logged fingerprints")

    chain_head = entries[-1]["entry_hash"] if entries else None
    if args.expect_head is not None and chain_head != args.expect_head:
        # Internally consistent, but not the chain the operator recorded —
        # the signature of whole-chain regeneration. When files diverged
        # too, both are reported but this graver verdict sets the exit
        # code — a regenerated chain must never hide behind "some files
        # changed" (SPEC §6).
        print(f"HEAD-MISMATCH: chain head is {chain_head}, expected "
              f"{args.expect_head} — this is not the recorded history")
        return 3
    if diverged:
        return 2

    print("VALID")
    return 0


def cmd_report(args):
    try:
        lines = read_log(args.log)
    except FileNotFoundError:
        return missing_log(args.log)

    entries, breaks, warns = walk(lines)
    flags = {}
    for n, message in breaks + warns:
        flags.setdefault(n, []).append(message)

    print(f"receipt log: {args.log} ({len(lines)} entries)")
    print()
    for n, entry in enumerate(entries):
        if entry is not None:
            print(f"  {n:>4}  {entry.get('ts')}  "
                  f"{entry.get('actor')}: {entry.get('action')}")
            for ref in entry.get("files", []):
                print(f"        - {ref['path']} ({ref['sha256'][:12]}…)")
        for message in flags.get(n, []):
            print(f"        !! {message}")
    if breaks:
        print()
        print("chain integrity: BROKEN — this timeline is testimony only "
              "(run `receipts verify` for the verdict)")
    return 0


def head_record(value):
    """argparse validator: a head record is 64 lowercase hex characters."""
    v = value.lower()
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a chain head (need 64 hex characters)"
        )
    return v


def main(argv=None):
    parser = argparse.ArgumentParser(prog="receipts", description=__doc__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log", default=DEFAULT_LOG, help="receipt log path")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", parents=[common],
                   help="create a new receipt log with its genesis entry"
                   ).set_defaults(func=cmd_init)
    actor_files = argparse.ArgumentParser(add_help=False)
    actor_files.add_argument("--actor", required=True, help="who acted")
    actor_files.add_argument("--file", action="append", default=[], metavar="PATH",
                             help="file to fingerprint (repeatable)")
    log_parser = sub.add_parser("log", parents=[common, actor_files],
                                help="append one chained entry")
    log_parser.add_argument("--action", required=True, help="what happened, one line")
    log_parser.set_defaults(func=cmd_log)
    sub.add_parser(
        "run", parents=[common, actor_files],
        help="run a command, then append its receipt -- <command> [args...]"
        ).set_defaults(func=cmd_run)
    sub.add_parser("report", parents=[common],
                   help="render the log as a human-readable timeline"
                   ).set_defaults(func=cmd_report)
    sub.add_parser("head", parents=[common],
                   help="print the chain head (record it out of the writer's reach)"
                   ).set_defaults(func=cmd_head)
    verify_parser = sub.add_parser("verify", parents=[common],
                                   help="walk the chain and report a verdict")
    verify_parser.add_argument("--files", action="store_true",
                               help="also compare referenced files against disk")
    verify_parser.add_argument("--expect-head", metavar="HEX", type=head_record,
                               help="operator-held head record to compare against")
    verify_parser.set_defaults(func=cmd_verify)

    if argv is None:
        argv = sys.argv[1:]
    # `run` owns everything after `--`: split it off before argparse so the
    # wrapped command's own flags are never parsed as ours.
    command_argv = None
    if argv[:1] == ["run"] and "--" in argv:
        split = argv.index("--")
        command_argv = argv[split + 1:]
        argv = argv[:split]

    args = parser.parse_args(argv)
    if args.command == "run":
        if not command_argv:
            parser.error("run requires `-- <command> [args...]` after its flags")
        args.command_argv = command_argv
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
