#!/usr/bin/env python3
"""receipts — a tamper-evident, hash-chained receipt log for AI agent pipelines.

Stdlib only. Format spec: docs/SPEC.md (v0.1, frozen).
"""

import argparse
import hashlib
import json
import os
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


def cmd_log(args):
    if not args.actor or not args.action:
        print("error: --actor and --action must be non-empty", file=sys.stderr)
        return 1
    log_dir = os.path.dirname(os.path.abspath(args.log))
    try:
        files = [file_reference(log_dir, p) for p in args.file]
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    files.sort(key=lambda ref: ref["path"])  # by path bytes (SPEC §3)
    try:
        with open(args.log, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        print(f"error: {args.log} not found — run `receipts init` first", file=sys.stderr)
        return 1
    last = json.loads(lines[-1])

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
        "actor": args.actor,
        "action": args.action,
        "files": files,
        "prev": last["entry_hash"],
    }
    entry["entry_hash"] = entry_hash(entry)
    # Single write of one complete line (SPEC §1): a crash can at worst
    # truncate this line, never damage earlier entries.
    with open(args.log, "a", encoding="utf-8", newline="\n") as f:
        f.write(entry_line(entry))
    print(f"logged entry {entry['n']}")
    return 0


def cmd_verify(args):
    with open(args.log, encoding="utf-8") as f:
        lines = f.read().splitlines()

    # SPEC §2.1: read the genesis version before applying any other rule.
    log_version = json.loads(lines[0]).get("v")
    if log_version != FORMAT_VERSION:
        print(
            f'UNSUPPORTED-VERSION: log is format "{log_version}"; '
            f'this verifier speaks "{FORMAT_VERSION}"'
        )
        return 4

    breaks = []
    prev_hash = None
    for n, line in enumerate(lines):
        entry = json.loads(line)
        expected_fields = GENESIS_FIELDS if n == 0 else ENTRY_FIELDS
        if set(entry) != expected_fields:
            odd = set(entry) ^ expected_fields
            breaks.append((n, f"schema mismatch: {', '.join(sorted(odd))}"))
        if entry.get("n") != n:
            breaks.append((n, f"sequence number is {entry.get('n')}, expected {n}"))
        if entry.get("prev") != prev_hash:
            breaks.append((n, "prev does not match predecessor's entry_hash"))
        stored_hash = entry.pop("entry_hash", None)
        if entry_hash(entry) != stored_hash:
            breaks.append((n, "entry_hash does not match canonical form"))
        prev_hash = stored_hash

    if breaks:
        for n, reason in breaks:
            print(f"BROKEN at entry {n}: {reason}")
        return 1

    if args.files:
        # Latest reference per path is authoritative (GLOSSARY: file reference).
        latest = {}
        for line in lines:
            for ref in json.loads(line)["files"]:
                latest[ref["path"]] = ref["sha256"]
        log_dir = os.path.dirname(os.path.abspath(args.log))
        diverged = 0
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
            return 2

    print("VALID")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="receipts", description=__doc__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log", default=DEFAULT_LOG, help="receipt log path")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", parents=[common],
                   help="create a new receipt log with its genesis entry"
                   ).set_defaults(func=cmd_init)
    log_parser = sub.add_parser("log", parents=[common],
                                help="append one chained entry")
    log_parser.add_argument("--actor", required=True, help="who acted")
    log_parser.add_argument("--action", required=True, help="what happened, one line")
    log_parser.add_argument("--file", action="append", default=[], metavar="PATH",
                            help="file to fingerprint (repeatable)")
    log_parser.set_defaults(func=cmd_log)
    verify_parser = sub.add_parser("verify", parents=[common],
                                   help="walk the chain and report a verdict")
    verify_parser.add_argument("--files", action="store_true",
                               help="also compare referenced files against disk")
    verify_parser.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
