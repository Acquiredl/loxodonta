"""The clean-room verifier (#493): cleanroom/verify.py, on the chain vectors.

cleanroom/verify.py was written from docs/SPEC.md and tests/vectors/
alone, by a session that never read loxodonta.py, so it is the one
reading of the spec here that does not share the recorder's. It is
frozen: its bytes are pinned below, and a change to it is a new
clean-room round, never an edit (cleanroom/README.md).

Each chain row of tests/vectors/vectors.json (the `verify` and `head`
rows that judge no sidecar) runs against it, judged by the contract
tests/vectors/README.md gives another implementation: the exit code,
the verdict word that starts the last line, and for `head` the whole
line. A chain vector added later runs here too, so a spec change the
clean room's reading does not survive fails here first.
"""

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "tests" / "vectors"
CLEANROOM = REPO_ROOT / "cleanroom" / "verify.py"

# The bytes the clean-room build left, 2026-10-08. `.gitattributes`
# keeps cleanroom/ as committed, so this holds on every system.
FROZEN_SHA256 = "7b49e72b66b914f076172aa96f998d14db980d57f64c81fd0c57fe795c7901cc"


def chain_rows():
    rows = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))["vectors"]
    return [row for row in rows
            if row["args"][0] in ("verify", "head")
            and "--anchors" not in row["args"] and "--stamps" not in row["args"]]


def last_line(stdout):
    lines = stdout.rstrip("\n").split("\n")
    return lines[-1] if stdout.strip("\n") else ""


def verdict(row, line):
    """What the contract compares: a `head` row's whole line, any other
    row's first word, without the colon a verifier may add after it."""
    if row["args"][0] == "head":
        return line
    return line.split(" ")[0].rstrip(":")


class CleanroomTest(unittest.TestCase):

    def test_the_clean_room_verifier_is_unedited(self):
        self.assertEqual(hashlib.sha256(CLEANROOM.read_bytes()).hexdigest(), FROZEN_SHA256,
                         "cleanroom/verify.py changed: a change to it is a new "
                         "clean-room round, not an edit (cleanroom/README.md)")

    def test_every_chain_row_gives_its_verdict(self):
        rows = chain_rows()
        # The slice the build was judged on; a filter that matched nothing
        # would pass this test by saying nothing.
        self.assertGreaterEqual(len(rows), 35)
        for row in rows:
            with self.subTest(row=row["name"]):
                done = subprocess.run(
                    [sys.executable, "-I", str(CLEANROOM), *row["args"]], cwd=VECTORS,
                    capture_output=True, encoding="utf-8", timeout=60,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"})
                self.assertEqual(done.returncode, row["exit"], done.stdout + done.stderr)
                got = last_line(done.stdout)
                if "last_line" in row:
                    self.assertEqual(verdict(row, got), verdict(row, row["last_line"]))
                else:
                    self.assertEqual(verdict(row, got), verdict(row, row["last_line_prefix"]))


if __name__ == "__main__":
    unittest.main()
