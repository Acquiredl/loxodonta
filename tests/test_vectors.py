"""The conformance vectors (ADR-0035): tests/vectors/, on both files.

Each vector is a small chain file and one row of tests/vectors/vectors.json:
the arguments to run, the exit expected, and the last line of stdout
expected (or how it starts). The same rows are what a second
implementation checks itself against (tests/vectors/README.md). Here each
row runs against loxodonta.py and against verifier.py, as a recipient
would run them, and the two files must also agree with each other, exit
and output alike.

A row may also give an entry's canonical form in full (SPEC section 4).
Its SHA256 must be that entry's stored `entry_hash`, so the bytes a
verifier must reproduce are written down, not only their hash.

The vectors are written by tools/build_vectors.py, and a rebuild must
give the committed bytes, so a vector edited by hand, or a generator
changed without its vectors, fails here.
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
MANIFEST = VECTORS / "vectors.json"
BUILD = REPO_ROOT / "tools" / "build_vectors.py"
TOOLS = {"loxodonta.py": REPO_ROOT / "loxodonta.py",
         "verifier.py": REPO_ROOT / "verifier.py"}


def rows():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["vectors"]


def run_row(tool, row):
    """One row, run the way the README says: from inside tests/vectors/,
    so every path a row names is relative to that folder."""
    return subprocess.run(
        [sys.executable, str(TOOLS[tool]), *row["args"]], cwd=VECTORS,
        capture_output=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})


def last_line(stdout):
    """The final line of stdout, or "" when nothing was printed. Split on
    `\\n` alone: a verdict never holds another line break, and a line
    that did must not be split where the tool did not split it."""
    lines = stdout.rstrip("\n").split("\n")
    return lines[-1] if stdout.strip("\n") else ""


class VectorsTest(unittest.TestCase):

    def test_every_row_gives_its_verdict_on_both_files(self):
        for row in rows():
            for tool in TOOLS:
                with self.subTest(vector=row["name"], tool=tool):
                    done = run_row(tool, row)
                    said = done.stdout + done.stderr
                    self.assertNotIn("Traceback", said)
                    self.assertEqual(done.returncode, row["exit"], said)
                    line = last_line(done.stdout)
                    if "last_line" in row:
                        self.assertEqual(line, row["last_line"], said)
                    else:
                        self.assertTrue(
                            line.startswith(row["last_line_prefix"]), said)

    def test_the_two_files_agree_on_every_row(self):
        for row in rows():
            with self.subTest(vector=row["name"]):
                recorder = run_row("loxodonta.py", row)
                verifier = run_row("verifier.py", row)
                self.assertEqual(
                    (recorder.returncode, recorder.stdout, recorder.stderr),
                    (verifier.returncode, verifier.stdout, verifier.stderr))

    def test_every_row_names_one_expectation_and_a_file_that_exists(self):
        names = [row["name"] for row in rows()]
        self.assertEqual(len(names), len(set(names)), "a name given twice")
        for row in rows():
            with self.subTest(vector=row["name"]):
                self.assertEqual(
                    ("last_line" in row) + ("last_line_prefix" in row), 1)
                log = row["args"][row["args"].index("--log") + 1]
                self.assertTrue((VECTORS / log).is_file(), log)

    def test_every_chain_file_is_run_by_some_row(self):
        run = {row["args"][row["args"].index("--log") + 1] for row in rows()}
        chains = {path.name for path in VECTORS.glob("*.jsonl")}
        self.assertEqual(chains - run, set(), "a chain no row runs")

    def test_each_canonical_form_written_down_hashes_to_its_entry(self):
        stated = [row for row in rows() if "canonical" in row]
        self.assertTrue(stated, "no row writes a canonical form down")
        for row in stated:
            with self.subTest(vector=row["name"]):
                log = row["args"][row["args"].index("--log") + 1]
                lines = (VECTORS / log).read_text(encoding="utf-8").split("\n")
                canonical = row["canonical"]
                entry = json.loads(lines[canonical["entry"]])
                digest = hashlib.sha256(
                    canonical["text"].encode("utf-8")).hexdigest()
                self.assertEqual(digest, entry["entry_hash"])

    def test_a_rebuild_gives_the_committed_vectors(self):
        checked = subprocess.run(
            [sys.executable, str(BUILD), "--check"], capture_output=True,
            encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(checked.returncode, 0,
                         checked.stdout + checked.stderr)


if __name__ == "__main__":
    unittest.main()
