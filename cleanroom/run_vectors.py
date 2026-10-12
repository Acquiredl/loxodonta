#!/usr/bin/env python3
"""Run verify.py against the chain rows of vectors/vectors.json.

The slice is the `verify` and `head` rows that give neither --anchors nor
--stamps. Every other row is printed as `skipped`, never as a pass.

A row passes when the exit code matches and, per vectors/README.md "For
another implementation", the verdict word that starts the last line of stdout
matches. A `head` row's last line must match whole, since it is the head itself.

Rows that carry a `canonical` form are also checked byte for byte against
verify.py's canonical form of that entry, and reported on their own line. That
check does not change the score.

Usage: python -I run_vectors.py
"""

import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors")
VERIFY = os.path.join(HERE, "verify.py")


def load_verify():
    """verify.py's own functions, for the canonical-form check."""
    sys.dont_write_bytecode = True  # leave no __pycache__ in the clean room
    spec = importlib.util.spec_from_file_location("cleanroom_verify", VERIFY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_rows():
    with open(os.path.join(VECTORS, "vectors.json"), encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):  # the README does not say whether the rows are wrapped
        for value in data.values():
            if isinstance(value, list):
                return value
    return data


def row_args(row):
    args = row["args"]
    return shlex.split(args) if isinstance(args, str) else list(args)


def in_slice(args):
    return bool(args) and args[0] in ("verify", "head") and "--anchors" not in args and "--stamps" not in args


def verdict_word(line):
    match = re.match(r"[A-Za-z][A-Za-z-]*", line or "")
    return match.group(0) if match else ""


def run_row(row):
    """Returns (passed, explanation)."""
    args = row_args(row)
    result = subprocess.run([sys.executable, "-I", VERIFY] + args, cwd=VECTORS,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = result.stdout.decode("utf-8", "replace")
    lines = stdout.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    got_last = lines[-1] if lines else ""

    if "last_line" in row:
        expected_last, exact = row["last_line"], args[0] == "head" or row["last_line"] == ""
    else:
        expected_last, exact = row.get("last_line_prefix", ""), args[0] == "head"

    problems = []
    if result.returncode != row["exit"]:
        problems.append("exit %s, expected %s" % (result.returncode, row["exit"]))
    if exact:
        if got_last != expected_last:
            problems.append("last line %r, expected %r" % (got_last, expected_last))
    elif verdict_word(got_last) != verdict_word(expected_last):
        problems.append("verdict %r, expected %r (expected line %r; got %r)"
                        % (verdict_word(got_last), verdict_word(expected_last), expected_last, got_last))
    if problems and result.stderr:
        problems.append("stderr %r" % result.stderr.decode("utf-8", "replace").strip()[-300:])
    return not problems, "; ".join(problems)


def check_canonical(verify, row):
    """Entry N's canonical form, as verify.py writes it, against the row's text."""
    args = row_args(row)
    log = args[args.index("--log") + 1]
    with open(os.path.join(VECTORS, log), "rb") as handle:
        lines = verify.split_lines(handle.read())
    entry = verify.parse_line(lines[row["canonical"]["entry"]])
    entry.pop("entry_hash", None)
    mine = verify.canonical_json(entry)
    return mine == row["canonical"]["text"], mine


def main():
    verify = load_verify()
    rows = load_rows()
    passed = failed = skipped = 0
    canonical_results = []
    for row in rows:
        args = row_args(row)
        if not in_slice(args):
            skipped += 1
            print("skipped  %s" % row["name"])
            continue
        ok, why = run_row(row)
        if ok:
            passed += 1
            print("pass     %s" % row["name"])
        else:
            failed += 1
            print("FAIL     %s: %s" % (row["name"], why))
        if "canonical" in row:
            canonical_results.append((row["name"],) + check_canonical(verify, row))

    print()
    for name, same, mine in canonical_results:
        print("canonical %s  %s" % ("match   " if same else "MISMATCH", name) + ("" if same else ": mine %r" % mine))
    print()
    print("slice: %d / %d pass, %d fail; %d rows skipped (sidecar or package)"
          % (passed, passed + failed, failed, skipped))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
