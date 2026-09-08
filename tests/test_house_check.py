"""Behavioral tests for `tools/house_check.py`, the house checker (issue
#123, presentation arc): the repo's own vocabulary enforced by a stdlib
script that runs in the suite and in CI.

Every test writes a small Markdown fixture, runs the command a maintainer
would run, and reads the exit code and the findings it printed. The rule
lists live in the script next to the vocabulary they enforce; the tests
pin the behavior of each rule, each allowlisted form, and the file set
each rule applies to.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER = REPO_ROOT / "tools" / "house_check.py"


def run_checker(*paths, cwd=None):
    return subprocess.run(
        [sys.executable, str(CHECKER), *map(str, paths)], cwd=cwd,
        capture_output=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


class AntiTermsTest(Fixture):
    def test_an_anti_term_anywhere_fails_and_names_file_line_rule_excerpt(self):
        doc = self.write("docs/NOTES.md", "# Notes\n\nThe log is an immutable record.\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        finding = [line for line in result.stdout.splitlines() if "NOTES.md" in line]
        self.assertEqual(len(finding), 1, result.stdout)
        self.assertIn(":3:", finding[0])
        self.assertIn("anti-term", finding[0])
        self.assertIn("immutable record", finding[0])

    def test_the_refutation_form_is_allowed_everywhere(self):
        # The forms the GLOSSARY, README, CONTRIBUTING, and CLAUDE.md use
        # to say what this tool is not, and to name Bitcoin's chain.
        doc = self.write("docs/NOTES.md", "\n".join([
            "This is tamper-evident, not immutable.",
            "It is not a blockchain, nothing here is immutable, and it is not an audit log.",
            'Note the anti-terms: no "blockchain", no "immutable", no "audit log".',
            "- ~~blockchain~~ implies consensus.",
            "- ~~audit log / audit trail~~ promises a complete record.",
            'Deliberately weaker than "immutable".',
            "The head is committed onto the Bitcoin blockchain.",
            "The verb audit is not banned; it is never an audit trail.",
            "Prior art: ai-audit-trail, which signs each line.",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("anti-term", result.stdout)


class EmDashTest(Fixture):
    def test_an_em_dash_fails_on_a_front_door_file(self):
        readme = self.write("README.md", "# x\n\nOne command — one verdict.\n")

        result = run_checker(readme)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("README.md:3: em-dash:", result.stdout)

    def test_the_glossary_and_docs_keep_their_em_dashes(self):
        glossary = self.write("GLOSSARY.md", "- **Receipt** — one entry.\n")
        doc = self.write("docs/SPEC.md", "Canonical JSON — sorted keys.\n")

        result = run_checker(glossary, doc)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class OverclaimTest(Fixture):
    def test_an_overclaim_word_fails_on_the_front_door_and_warns_elsewhere(self):
        readme = self.write("README.md", "The chain proves nobody rewrote it.\n")
        adr = self.write("adrs/0001-x.md", "The chain proves internal consistency.\n")

        front = run_checker(readme)
        elsewhere = run_checker(adr)

        self.assertEqual(front.returncode, 1, front.stdout + front.stderr)
        self.assertIn("README.md:1: overclaim: ", front.stdout)
        self.assertEqual(elsewhere.returncode, 0, elsewhere.stdout + elsewhere.stderr)
        self.assertIn("0001-x.md:1: overclaim (warning): ", elsewhere.stdout)

    def test_refuting_an_overclaim_is_allowed(self):
        readme = self.write("README.md", "\n".join([
            "A plain log proves nothing.",
            "The format offers no guarantee, and it does **not** guarantee completeness.",
            "This tool cannot prove an entry was never written.",
        ]) + "\n")

        result = run_checker(readme)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class CommandTest(Fixture):
    def test_no_arguments_means_every_tracked_markdown_file(self):
        # A checkout with one tracked and one untracked Markdown file:
        # the tracked one is judged, the stray one is not (a scratch file
        # in the working tree is nobody's front door yet).
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        tracked = self.write("README.md", "Tracked — with a dash.\n")
        self.write("docs/scratch.md", "An immutable draft.\n")
        subprocess.run(["git", "-C", str(self.root), "add", "README.md"], check=True)

        result = run_checker(cwd=self.root)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("README.md:1: em-dash:", result.stdout)
        self.assertNotIn("scratch.md", result.stdout)

    def test_a_finding_prints_on_a_narrow_console_without_crashing(self):
        # Windows consoles default to cp1252; an excerpt carrying an arrow
        # or a curly quote must still print, not raise.
        readme = self.write("README.md", "A → B, and it proves it.\n")

        result = subprocess.run(
            [sys.executable, str(CHECKER), str(readme)],
            capture_output=True, encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "cp1252"})

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("README.md:1: overclaim:", result.stdout)

    def test_the_repo_itself_passes(self):
        # The claim CI makes, made here too: every tracked Markdown file in
        # this checkout satisfies the house rules.
        result = run_checker(cwd=REPO_ROOT)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
