"""Behavioral tests for `tools/house_check.py`, the house checker (issue
#123, presentation arc): the repo's own vocabulary enforced by a stdlib
script that runs in the suite and in CI.

Every test writes a small Markdown or tool-file fixture, runs the command
a maintainer would run, and reads the exit code and the findings it
printed. The rule lists live in the script next to the vocabulary they
enforce; the tests pin the behavior of each rule, each allowlisted form,
and the file set each rule applies to. Issue #241 added the old name, the
synonym table and the code pass, each with a failing and a passing
fixture.
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


class RefutationTest(Fixture):
    # The escapes every rule shares, tightened in the #241 review.

    def test_rejected_escapes_only_the_words_inside_its_bold_heading(self):
        # An ADR names what it rejected as a bold heading followed by
        # Rejected; a word outside that bold span is not refused by it.
        adr = self.write("adrs/0031-x.md", "\n".join([
            "- **Call it a bundle.** Rejected: two words for one concept.",
            "- **Call the bundle a posture, a mode, or a level.** Rejected: "
            "the other two say nothing.",
        ]) + "\n")
        readme = self.write(
            "README.md",
            "The log is immutable and proves it, see **Rejected alternatives** below.\n")

        inside = run_checker(adr)
        outside = run_checker(readme)

        self.assertEqual(inside.returncode, 0, inside.stdout + inside.stderr)
        self.assertEqual(inside.stdout.strip(), "")
        self.assertEqual(outside.returncode, 1, outside.stdout + outside.stderr)
        self.assertIn("README.md:1: anti-term: ", outside.stdout)
        self.assertIn("README.md:1: overclaim: ", outside.stdout)

    def test_a_refusal_never_reaches_across_the_end_of_a_sentence(self):
        for sentence in ("Is it a package? No. A bundle ships the session.",
                         "It is not. The chain server appends.",
                         "Was it changed? No! It is immutable."):
            with self.subTest(sentence=sentence):
                readme = self.write("README.md", sentence + "\n")

                result = run_checker(readme)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("README.md:1: ", result.stdout)


class OldNameTest(Fixture):
    # ADR-0010: the command is `loxodonta`; only the artifact keeps the
    # name `receipts` (issue #241). Only the forms that cannot be the
    # plural noun are judged.

    def test_the_old_command_fails_where_it_is_written_as_code(self):
        doc = self.write("docs/NOTES.md", "\n".join([
            "# Notes",
            "",
            "Ask deliberately, with `receipts verify --files`.",
            "Or at a prompt: `$ receipts init`.",
            "",
            "```",
            "receipts run --actor ci -- make test",
            "python receipts head --log chain.jsonl",
            "```",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for number in (3, 4, 7, 8):
            self.assertIn(f"NOTES.md:{number}: old-name: ", result.stdout)
        self.assertIn("say loxodonta", result.stdout)

    def test_the_old_script_and_the_tool_by_name_fail_anywhere(self):
        doc = self.write("docs/NOTES.md", "\n".join([
            "Then run python receipts.py verify on the copy.",
            "Install the receipts tool first.",
            "The Receipts CLI prints the verdict.",
            "The receipts recorder writes one line per call.",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for number in (1, 2, 3, 4):
            self.assertIn(f"NOTES.md:{number}: old-name: ", result.stdout)
        self.assertEqual(result.stdout.count("old-name"), 4, result.stdout)

    def test_the_artifact_keeps_its_name(self):
        # The noun survives on purpose (ADR-0010): the file, the folder,
        # the sibling chains, the genesis actor, and receipts in prose.
        doc = self.write("docs/NOTES.md", "\n".join([
            "The log is `receipts.jsonl`, under `~/.loxodonta/receipts/<slug>/`.",
            "A sibling chain is `receipts-<session>-002.jsonl`.",
            'Genesis is pinned: `actor: "receipts"`, `action: "genesis"`.',
            "Receipts are written by a hook the harness fires.",
            "A session of 3,721 receipts has a shape no waterfall can hold.",
            "The recorder began life as `receipts.py`; hook detection knows `receipts.py` too.",
            "No receipts tool calls are owed for a failed call.",
        ]) + "\n")

        result = run_checker(doc)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_bare_prose_is_not_judged_because_it_is_ambiguous(self):
        # Before a verb, `receipts` is the plural noun as often as the old
        # tool, so prose is left alone either way: the first seven are the
        # noun, the last two the tool, and none of them is judged.
        doc = self.write("docs/NOTES.md", "\n".join([
            "The session's receipts log grows by one line.",
            "Hook receipts run from genesis to the head.",
            "Per-project receipts drawers sit under the store.",
            "Hook receipts' timestamps are testimony.",
            "Each session's receipts verify clean.",
            "Compare receipts vs heads.",
            "The name receipts stays with the artifact.",
            "Ask with receipts verify.",
            "Then receipts will verify the chain.",
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
    # that must not stand in for it. Each row has failing sentences and
    # passing ones; the passing ones carry the everyday uses of the same
    # words, which this repo is full of and which must never fire.

    def assert_each_fails_on_the_front_door(self, term, *sentences):
        for sentence in sentences:
            with self.subTest(sentence=sentence):
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

    def test_profile_fails_as_a_protection_level_full_security_or_a_flag(self):
        self.assert_each_fails_on_the_front_door(
            "profile",
            "Pick a protection level at install.",
            "The full security tier sends the entries.",
            "Wire it with `--level full`.",
            'Or pass "--posture timestamped".')

    def test_profile_passes_the_everyday_mode_and_level(self):
        self.assert_passes_on_the_front_door(
            "`--root` remains the explicit legacy mode.",
            "Hooks go into your user-level settings, at the top level.",
            "A run of unread days is the one failure mode the chains cannot report.",
            "Set the log level to debug; OpenSSL's security level 2 refuses the key.",
            "**Tor Browser's Security Level** is prior art for the ladder.",
            "Make the folder with `mkdir --mode=700`.",
            "Not a *posture*, not a *mode*, and never a *protection level*.")

    def test_published_chain_fails_as_a_backup_mirror_or_replica_of_the_chain(self):
        self.assert_each_fails_on_the_front_door(
            "published chain",
            "At full, a backup of the chain lands on a second machine.",
            "The chain's mirror sits on a second box.",
            "The hook calls `backup_chain` at session end.",
            "Mirror the receipts to the far machine.",
            "Your receipts are backed up at the remote.")

    def test_published_chain_passes_the_everyday_backup_and_mirror(self):
        self.assert_passes_on_the_front_door(
            "The installer backs up the settings file before it writes.",
            "Keep it out of backups that leave the machine.",
            "`--codex` mirrors the Claude Code flags, and the report mirrors the log.",
            "Back up the receipts folder with your usual tools.",
            "It restores a backup of the log; keep a mirror of your work.",
            "The dashboard mirrors the chain's verdict.",
            'The copy survives a wipe, never "your receipts are backed up".')

    def test_receiver_fails_as_a_chain_server_or_a_collector_for_the_chain(self):
        self.assert_each_fails_on_the_front_door(
            "receiver",
            "Run the chain server on a machine the writer cannot reach.",
            "Point the hook at a collector for the published chain.")

    def test_receiver_passes_the_everyday_server_and_collector(self):
        self.assert_passes_on_the_front_door(
            "The dashboard's server binds 127.0.0.1; start the server.",
            "The same five readings are an MCP server.",
            "Public calendar servers aggregate digests; `http.server` serves the page.",
            "The OpenTelemetry Collector settles where vendor code lives.",
            "Your collector can scrape the route.")

    def test_package_fails_as_a_bundle(self):
        self.assert_each_fails_on_the_front_door(
            "package", "`supervisor package` ships the session as a bundle.")

    def test_package_passes_the_refused_and_the_everyday_bundle(self):
        self.assert_passes_on_the_front_door(
            "It is not called a bundle, so the concept keeps one name.",
            "Not called a *bundle*: the everyday word for the same thing.",
            "Prior art: **Sigstore bundles**, and bundled navigation.",
            "The flag bundles nothing new.")

    def test_the_raw_export_is_a_raw_archive_not_a_package(self):
        readme = self.write("README.md", "The raw bundle carries command lines.\n")

        result = run_checker(readme)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("say raw archive:", result.stdout)
        self.assertNotIn("say package:", result.stdout)

    def test_authority_timestamp_fails_as_an_anchor(self):
        self.assert_each_fails_on_the_front_door(
            "authority timestamp",
            "The TSA anchor arrives in one round trip.",
            "The stamp anchors the head at the authority.")

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
    # read the tool files too, with an underscore read as a space. Only a
    # comment or a docstring can refuse a word there, and a synonym fails
    # as it does on the front door.

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

    def test_python_syntax_is_never_read_as_a_refusal(self):
        # A quote that opens a string, `not` as an operator, and `no_` as
        # an identifier's prefix refuse nothing: each of these fails alone.
        for source in (
                '"""Mirror the receipts to the far machine."""',
                '"""Immutable once written."""',
                'HELP = "immutable record of the session"',
                'print(f"chain backup sent to {url}")',
                "if not backup_chain(entries):\n    pass",
                'p.add_argument("--level", ...)',
                "sent = True  # no_backup_chain any more"):
            with self.subTest(source=source):
                code = self.write("loxodonta.py", source + "\n")

                result = run_checker(code)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_a_comment_or_docstring_still_refuses_in_words(self):
        code = self.write("loxodonta.py", "\n".join([
            '"""Tamper-evident, not immutable."""',
            "",
            "",
            "def send(entries):",
            '    """Never a chain backup: the entries only go outward."""',
            "    return entries  # not an audit log, and no chain backup either",
        ]) + "\n")

        result = run_checker(code)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_the_everyday_words_and_the_prose_rules_pass_in_code(self):
        # backup_settings backs up the settings file, which is exactly
        # what it says; the overclaim, em-dash and old-name rules are
        # about prose and do not read code.
        code = self.write("receiver.py", "\n".join([
            "def backup_settings(path):",
            '    """Back up the settings file — always, before a write."""',
            "    had_backup = True  # the server object from http.server",
            '    actor = "receipts"  # `receipts verify` reads this',
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
