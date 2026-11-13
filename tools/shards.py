#!/usr/bin/env python3
"""Which test modules one CI shard runs (#453).

    python tools/shards.py SHARD SHARDS              one module per line
    python tools/shards.py SHARD SHARDS --by-count   ignoring the table

Heaviest module first, each to the lightest shard so far, so the shards
finish together. A module weighs its measured seconds from the table
below, or, for one the table does not name (a new module, or every
module under --by-count), its test count: a module is never left out of
every shard for want of a row. Every machine computes the same split
from the same tree. A line on stderr says the shard's modules and
weight, for the job's log.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Seconds per module on ubuntu / py3.9, from the push run on dev of
# 2026-11-12 (run 43321535890): the time between one test's `-v` line and
# the next in the job's log, summed by module. A row gone stale costs
# balance, never coverage; measure again when the spread grows.
SECONDS = {
    "test_acknowledge": 89, "test_adapters": 6, "test_anchor": 85,
    "test_as_written": 37, "test_cleanroom": 1, "test_cli": 64,
    "test_concurrency": 6, "test_console_utf8": 3, "test_demo_store": 13,
    "test_explain": 5, "test_export": 15, "test_hook": 38,
    "test_house_check": 5, "test_managed_command": 6,
    "test_managed_install": 27, "test_mcp": 4, "test_metrics": 28,
    "test_package": 62, "test_package_anchor": 43, "test_package_sign": 14,
    "test_package_stamp": 46, "test_publish": 24, "test_publish_chain": 100,
    "test_publish_echo": 1, "test_publish_keeper": 85, "test_readme_pins": 3,
    "test_recall": 19, "test_receiver": 23, "test_serve": 66,
    "test_sidecar_not_a_file": 63, "test_sidecar_strictness": 7,
    "test_sidecar_torn_line": 5, "test_stamp": 105, "test_suite_shape": 27,
    "test_supervisor": 300, "test_too_deep": 4, "test_unparseable_record": 6,
    "test_vectors": 25, "test_verdict_lines": 4, "test_verifier": 327,
    "test_version": 1,
}


def weight(name, table):
    if name in table:
        return table[name]
    return unittest.defaultTestLoader.loadTestsFromName(
        "tests." + name).countTestCases()


def split(names, shards, table):
    shelves, totals = [[] for _ in range(shards)], [0] * shards
    weights = {name: weight(name, table) for name in names}
    for name in sorted(names, key=lambda n: (-weights[n], n)):
        lightest = totals.index(min(totals))
        shelves[lightest].append(name)
        totals[lightest] += weights[name]
    return shelves, totals


def main(argv):
    by_count = "--by-count" in argv
    args = [arg for arg in argv if arg != "--by-count"]
    if len(args) != 2 or not all(arg.isdigit() for arg in args):
        print(__doc__, file=sys.stderr)
        return 64
    shard, shards = int(args[0]), int(args[1])
    if not 1 <= shard <= shards:
        print(f"error: shard {shard} is not one of 1 to {shards}",
              file=sys.stderr)
        return 64
    sys.path.insert(0, str(ROOT))
    names = sorted(p.stem for p in (ROOT / "tests").glob("test_*.py"))
    shelves, totals = split(names, shards, {} if by_count else SECONDS)
    mine = sorted(shelves[shard - 1])
    print(f"shard {shard} of {shards}, weight {totals[shard - 1]}:",
          ", ".join(mine), file=sys.stderr, flush=True)
    print("\n".join(mine))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
