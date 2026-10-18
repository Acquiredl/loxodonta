"""Behavioral tests for `--version` (ADR-0022).

The tool carries a version decoupled from the frozen receipt format:
`--version` prints the tool version, the format version, and the commit
of the checkout the file sits in — the same fact the recorder notice
reports (ADR-0015), read from local git only, never fetched. Both files
are tagged together and must agree.
"""

import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_version`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import (LOXODONTA, REPO_ROOT, RECEIVER, SUPERVISOR,  # noqa: E402
                     VERIFIER, clean_env, run, temp_folder)


# `<prog> <semver> (format <format>, commit <short-hash|unknown>)`
VERSION_LINE = re.compile(
    r"^(?P<prog>\S+) (?P<tool>\d+\.\d+\.\d+) "
    r"\(format (?P<format>\d+\.\d+), commit (?P<commit>[0-9a-f]{7,40}|unknown)\)$")


def checkout_commit():
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
        capture_output=True, encoding="utf-8", check=True,
        timeout=120).stdout.strip()


class VersionTest(unittest.TestCase):
    def test_recorder_prints_tool_format_and_commit_on_one_line(self):
        result = run(LOXODONTA, "--version")

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
        loose = temp_folder(self)
        script = loose / "loxodonta.py"
        shutil.copy(LOXODONTA, script)

        result = run(
            script, "--version",
            # Stop git from walking up into some checkout above the temp dir.
            env=clean_env(GIT_CEILING_DIRECTORIES=str(loose.parent)))

        self.assertEqual(result.returncode, 0, result.stderr)
        said = VERSION_LINE.match(result.stdout.strip())
        self.assertIsNotNone(said, result.stdout)
        self.assertEqual(said["commit"], "unknown")
        self.assertEqual(said["format"], "0.1")

    def test_supervisor_prints_the_same_three_identities(self):
        result = run(SUPERVISOR, "--version")

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        said = VERSION_LINE.match(lines[0])
        self.assertIsNotNone(said, lines[0])
        self.assertEqual(said["prog"], "supervisor")
        self.assertEqual(said["format"], "0.1")
        self.assertEqual(said["commit"], checkout_commit())

    def test_receiver_prints_the_same_three_identities(self):
        result = run(RECEIVER, "--version")

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        said = VERSION_LINE.match(lines[0])
        self.assertIsNotNone(said, lines[0])
        self.assertEqual(said["prog"], "receiver")
        self.assertEqual(said["format"], "0.1")
        self.assertEqual(said["commit"], checkout_commit())

    def test_verifier_prints_the_same_three_identities(self):
        # The copy answers for itself (ADR-0035): its own name, and the
        # commit of the checkout it sits in.
        result = run(VERIFIER, "--version")

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        said = VERSION_LINE.match(lines[0])
        self.assertIsNotNone(said, lines[0])
        self.assertEqual(said["prog"], "verifier")
        self.assertEqual(said["format"], "0.1")
        self.assertEqual(said["commit"], checkout_commit())

    def test_the_four_files_carry_one_tool_version_and_agree(self):
        # ADR-0022: tagged together, so a bump to one is a bump to all
        # of them (the receiver joined with ADR-0031, the verifier with
        # ADR-0035, which cuts it from the recorder at the same commit).
        said = {script: VERSION_LINE.match(run(script, "--version").stdout.strip())
                for script in (LOXODONTA, SUPERVISOR, RECEIVER, VERIFIER)}
        for script in (SUPERVISOR, RECEIVER, VERIFIER):
            self.assertEqual(said[script]["tool"], said[LOXODONTA]["tool"],
                             script.name)
            self.assertEqual(said[script]["format"], said[LOXODONTA]["format"],
                             script.name)

        # And each version lives in exactly one constant per file — the
        # place a release bump edits, and the only place.
        one_constant = re.compile(r'^TOOL_VERSION = "(\d+\.\d+\.\d+)"$', re.M)
        for script, line in said.items():
            declared = one_constant.findall(script.read_text(encoding="utf-8"))
            self.assertEqual(declared, [line["tool"]], script.name)

if __name__ == "__main__":
    unittest.main()
