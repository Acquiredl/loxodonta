"""Behavioral tests for `--version` (ADR-0022).

The tool carries a version decoupled from the frozen receipt format:
`--version` prints the tool version, the format version, and the commit
of the checkout the file sits in — the same fact the recorder notice
reports (ADR-0015), read from local git only, never fetched. Both files
are tagged together and must agree.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

# `<prog> <semver> (format <format>, commit <short-hash|unknown>)`
VERSION_LINE = re.compile(
    r"^(?P<prog>\S+) (?P<tool>\d+\.\d+\.\d+) "
    r"\(format (?P<format>\d+\.\d+), commit (?P<commit>[0-9a-f]{7,40}|unknown)\)$")


def run_version(script, env=None):
    return subprocess.run(
        [sys.executable, str(script), "--version"],
        capture_output=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})})


def checkout_commit():
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
        capture_output=True, encoding="utf-8", check=True).stdout.strip()


class VersionTest(unittest.TestCase):
    def test_recorder_prints_tool_format_and_commit_on_one_line(self):
        result = run_version(LOXODONTA)

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        said = VERSION_LINE.match(lines[0])
        self.assertIsNotNone(said, lines[0])
        self.assertEqual(said["prog"], "loxodonta")
        self.assertEqual(said["format"], "0.1")  # SPEC §2.1: frozen
        self.assertEqual(said["commit"], checkout_commit())

    def test_a_file_outside_any_checkout_says_unknown_never_fails(self):
        # A release asset, dropped anywhere: no git history to read, so
        # the commit is "unknown" — the flag still reports, exit 0.
        loose = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, loose, ignore_errors=True)
        script = loose / "loxodonta.py"
        shutil.copy(LOXODONTA, script)

        result = run_version(
            script,
            # Stop git from walking up into some checkout above the temp dir.
            env={"GIT_CEILING_DIRECTORIES": str(loose.parent)})

        self.assertEqual(result.returncode, 0, result.stderr)
        said = VERSION_LINE.match(result.stdout.strip())
        self.assertIsNotNone(said, result.stdout)
        self.assertEqual(said["commit"], "unknown")
        self.assertEqual(said["format"], "0.1")

    def test_supervisor_prints_the_same_three_identities(self):
        result = run_version(SUPERVISOR)

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        said = VERSION_LINE.match(lines[0])
        self.assertIsNotNone(said, lines[0])
        self.assertEqual(said["prog"], "supervisor")
        self.assertEqual(said["format"], "0.1")
        self.assertEqual(said["commit"], checkout_commit())

    def test_the_two_files_carry_one_tool_version_and_agree(self):
        # ADR-0022: tagged together, so a bump to one is a bump to both.
        recorder = VERSION_LINE.match(run_version(LOXODONTA).stdout.strip())
        supervisor = VERSION_LINE.match(run_version(SUPERVISOR).stdout.strip())
        self.assertEqual(recorder["tool"], supervisor["tool"])
        self.assertEqual(recorder["format"], supervisor["format"])

        # And each version lives in exactly one constant per file — the
        # place a release bump edits, and the only place.
        one_constant = re.compile(r'^TOOL_VERSION = "(\d+\.\d+\.\d+)"$', re.M)
        for script, said in ((LOXODONTA, recorder), (SUPERVISOR, supervisor)):
            declared = one_constant.findall(script.read_text(encoding="utf-8"))
            self.assertEqual(declared, [said["tool"]], script.name)


if __name__ == "__main__":
    unittest.main()
