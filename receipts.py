#!/usr/bin/env python3
"""receipts — a tamper-evident, hash-chained receipt log for AI agent pipelines.

Stdlib only. Format spec: docs/SPEC.md (v0.1, frozen).
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

FORMAT_VERSION = "0.1"
DEFAULT_LOG = "receipts.jsonl"


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


# --- Commands -----------------------------------------------------------------

def cmd_init(args):
    genesis = {
        "v": FORMAT_VERSION,
        "n": 0,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actor": "receipts",
        "action": "genesis",
        "files": [],
        "prev": None,
    }
    genesis["entry_hash"] = entry_hash(genesis)
    with open(args.log, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(genesis, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"initialized {args.log}")
    return 0


def cmd_verify(args):
    with open(args.log, encoding="utf-8") as f:
        lines = f.read().splitlines()

    breaks = []
    for n, line in enumerate(lines):
        entry = json.loads(line)
        stored_hash = entry.pop("entry_hash", None)
        if entry_hash(entry) != stored_hash:
            breaks.append((n, "entry_hash does not match canonical form"))

    if breaks:
        for n, reason in breaks:
            print(f"BROKEN at entry {n}: {reason}")
        return 1
    print("VALID")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="receipts", description=__doc__)
    parser.add_argument("--log", default=DEFAULT_LOG, help="receipt log path")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a new receipt log with its genesis entry")
    sub.add_parser("verify", help="walk the chain and report a verdict")

    args = parser.parse_args(argv)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "verify":
        return cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
