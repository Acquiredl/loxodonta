"""Behavioral tests for `tools/house_check.py`, the house checker (issue
#123, presentation arc): the repo's own vocabulary enforced by a stdlib
script that runs in the suite and in CI.

Every test writes a small Markdown or tool-file fixture (issue #241 added
the old name, the synonym table and the code pass), runs the command a
maintainer would run, and reads the exit code and the findings it
printed. The rule
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

    def test_the_start_page_is_front_door_even_though_it_lives_in_docs(self):
        # docs/START.md is what a stranger is handed before they have
        # decided to trust anything, so it is judged like the README.
        start = self.write("docs/START.md",
                           "# Start here\n\nFive steps — no service.\n")

        result = run_checker(start)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("START.md:3: em-dash:", result.stdout)

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


class OldNameTest(Fixture):
    # ADR-0010: the command is `loxodonta`; only the artifact keeps the
    # name `receipts` (issue #241).

    def test_the_old_command_fails_in_a_page_that_is_not_about_the_past(self):
        doc = self.write("docs/NOTES.md", "\n".join([
            "# Notes",
            "",
            "Ask deliberately, with `receipts verify --files`.",
            "receipts run --actor ci -- make test",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NOTES.md:3: old-name: ", result.stdout)
        self.assertIn("NOTES.md:4: old-name: ", result.stdout)
        self.assertIn("say loxodonta", result.stdout)

    def test_the_old_name_as_the_tool_fails_as_subject_possessive_or_cli(self):
        doc = self.write("docs/NOTES.md", "\n".join([
            "Purpose B is the product: receipts exists so that a writer is caught.",
            "The part receipts actually needs is small.",
            "receipts' hook does not record tool outcomes.",
            "Each copy is verified through the public receipts CLI.",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for number in (1, 2, 3, 4):
            self.assertIn(f"NOTES.md:{number}: old-name: ", result.stdout)

    def test_the_artifact_keeps_its_name(self):
        # The noun survives on purpose (ADR-0010): the file, the folder,
        # the sibling chains, the genesis actor, and receipts in prose,
        # including a plural subject and a noun at the end of a phrase.
        doc = self.write("docs/NOTES.md", "\n".join([
            "The log is `receipts.jsonl`, under `~/.loxodonta/receipts/<slug>/`.",
            "A sibling chain is `receipts-<session>-002.jsonl`.",
            'Genesis is pinned: `actor: "receipts"`, `action: "genesis"`.',
            "Receipts are written by a hook the harness fires.",
            "Two receipts, a verdict, one word of history rewritten.",
            "A session of 3,721 receipts has a shape no waterfall can hold.",
            "A session with tool calls and no receipts is `ENDED-DEFICIT`.",
            "A receipts log plus its file references is one artifact.",
            "Every N receipts inside the hook is rejected.",
            "`loxodonta verify` reads the receipts; receipts must never hold secrets.",
            "The recorder began life as `receipts.py`.",
            # The tool's name is written in lower case even opening a
            # sentence; the capitalized word is the noun.
            "Receipts' timestamps are testimony.",
            "Receipts run from genesis to the head.",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_the_pages_that_quote_the_past_keep_the_old_command(self):
        # The history, the changelog, the two tours, and the ADRs written
        # before the rename, which ADR-0010 says are not rewritten.
        line = "The operator runs `receipts verify` by hand.\n"
        pages = [self.write(name, line) for name in (
            "docs/HISTORY.md", "CHANGELOG.md", "docs/TOUR.md",
            "docs/TOUR-SUPERVISOR.md", "adrs/0005-x.md")]

        result = run_checker(*pages)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("old-name", result.stdout)

    def test_an_adr_from_the_rename_on_is_judged(self):
        adr = self.write("adrs/0011-x.md", "The operator runs `receipts verify`.\n")

        result = run_checker(adr)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("0011-x.md:1: old-name: ", result.stdout)


class SynonymTest(Fixture):
    # The synonym table (issue #241): each GLOSSARY term and the words
    # that must not stand in for it. One failing and one passing fixture
    # per row; the passing one carries the everyday uses of the same
    # words, which this repo is full of and which must never fire.

    def assert_fails_on_the_front_door(self, sentence, term):
        readme = self.write("README.md", sentence + "\n")

        result = run_checker(readme)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("README.md:1: synonym: ", result.stdout)
        self.assertIn(f"say {term}:", result.stdout)

    def assert_passes_on_the_front_door(self, *sentences):
        readme = self.write("README.md", "\n".join(sentences) + "\n")

        result = run_checker(readme)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_profile_fails_as_a_security_level(self):
        self.assert_fails_on_the_front_door(
            "Pick a security level at install.", "profile")

    def test_profile_passes_the_everyday_mode_and_level(self):
        self.assert_passes_on_the_front_door(
            "`--root` remains the explicit legacy mode.",
            "Hooks go into your user-level settings, at the top level.",
            "A run of unread days is the one failure mode the chains cannot report.",
            "Set the log level to debug.",
            "Not a *posture*, not a *mode*, and never a *protection level*.")

    def test_published_chain_fails_as_a_backup_of_the_chain(self):
        self.assert_fails_on_the_front_door(
            "At full, a backup of the chain lands on a second machine.",
            "published chain")

    def test_published_chain_passes_the_everyday_backup_and_mirror(self):
        self.assert_passes_on_the_front_door(
            "The installer backs up the settings file before it writes.",
            "Keep it out of backups that leave the machine.",
            "`--codex` mirrors the Claude Code flags.",
            'The copy survives a wipe, never "your receipts are backed up".')

    def test_receiver_fails_as_a_chain_server(self):
        self.assert_fails_on_the_front_door(
            "Run the chain server on a machine the writer cannot reach.",
            "receiver")

    def test_receiver_passes_the_everyday_server_and_collector(self):
        self.assert_passes_on_the_front_door(
            "The dashboard's server binds 127.0.0.1.",
            "The same five readings are an MCP server.",
            "Public calendar servers aggregate digests; `http.server` serves the page.",
            "The OpenTelemetry Collector settles where vendor code lives.")

    def test_package_fails_as_a_bundle(self):
        self.assert_fails_on_the_front_door(
            "`supervisor package` ships the session as a bundle.", "package")

    def test_package_passes_the_refused_and_the_everyday_bundle(self):
        self.assert_passes_on_the_front_door(
            "It is not called a bundle, so the concept keeps one name.",
            "Not called a *bundle*: the everyday word for the same thing.",
            "Prior art: **Sigstore bundles**, and bundled navigation.",
            "The flag bundles nothing new.")

    def test_authority_timestamp_fails_as_an_anchor(self):
        self.assert_fails_on_the_front_door(
            "The TSA anchor arrives in one round trip.", "authority timestamp")

    def test_authority_timestamp_passes_beside_the_anchor(self):
        self.assert_passes_on_the_front_door(
            "The authority timestamp is made beside the anchor, never instead of it.",
            "An authority with no anchor cadence sends nothing.",
            "The anchor keeper's turn also stamps the head.",
            "So it is not an anchor and is never called one.")

    def test_a_synonym_warns_off_the_front_door(self):
        doc = self.write("docs/NOTES.md", "Pick a protection level at install.\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NOTES.md:1: synonym (warning): ", result.stdout)

    def test_an_adr_may_name_the_word_it_rejected(self):
        # The refutation form is the escape, and in an ADR the rejected
        # alternative is written as a bold heading followed by Rejected.
        adr = self.write("adrs/0026-x.md", "\n".join([
            "- **Call it a bundle.** Rejected: two words for one concept.",
            '- "Bundle", the everyday word, is avoided.',
        ]) + "\n")

        result = run_checker(adr)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_the_tours_keep_their_analogies(self):
        # The tour's envelope analogy quotes the past on purpose, as the
        # old-name rule lets it.
        tour = self.write("docs/TOUR.md",
                          "The counter staples thousands of fingerprints into one bundle.\n")

        result = run_checker(tour)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class CodePassTest(Fixture):
    # The code pass (issue #241): the anti-terms and the synonym table
    # read the tool files too, identifiers, docstrings and comments, with
    # an underscore read as a space. A synonym fails there as it does on
    # the front door.

    def test_a_function_named_for_a_synonym_fails(self):
        code = self.write("loxodonta.py", "\n".join([
            "def backup_chain(log):",
            '    """Send the entries off the machine."""',
        ]) + "\n")

        result = run_checker(code)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("loxodonta.py:1: synonym: def backup_chain(log):", result.stdout)
        self.assertIn("say published chain:", result.stdout)

    def test_an_anti_term_in_a_docstring_or_identifier_fails(self):
        code = self.write("supervisor.py", "\n".join([
            "def read(log):",
            '    """The immutable record, read back."""',
            "AUDIT_LOG = None",
        ]) + "\n")

        result = run_checker(code)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("supervisor.py:2: anti-term: ", result.stdout)
        self.assertIn("supervisor.py:3: anti-term: AUDIT_LOG = None", result.stdout)

    def test_the_everyday_words_and_the_prose_rules_pass_in_code(self):
        # backup_settings backs up the settings file, which is exactly
        # what it says; the overclaim, em-dash and old-name rules are
        # about prose and do not read code.
        code = self.write("receiver.py", "\n".join([
            "def backup_settings(path):",
            '    """Back up the settings file — always, before a write."""',
            "    had_backup = True  # the server object from http.server",
            '    actor = "receipts"  # receipts verify reads this',
            "    return had_backup",
        ]) + "\n")

        result = run_checker(code)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_no_arguments_reads_the_tool_files_and_not_the_rest(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("loxodonta.py", "def backup_chain(log):\n    pass\n")
        self.write("adapters/harness.py", "MIRROR_OF_THE_CHAIN = None\n")
        self.write("tools/helper.py", "def backup_chain(log):\n    pass\n")
        self.write("tests/test_x.py", 'FIXTURE = "an immutable record"\n')
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)

        result = run_checker(cwd=self.root)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("loxodonta.py:1: synonym: ", result.stdout)
        self.assertIn("harness.py:1: synonym: ", result.stdout)
        self.assertNotIn("helper.py", result.stdout)
        self.assertNotIn("test_x.py", result.stdout)


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
