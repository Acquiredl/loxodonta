#!/usr/bin/env python3
"""house_check.py, the house checker: the repo's vocabulary, enforced.

The GLOSSARY names words this project refuses (the anti-terms), and the
presentation arc added two more house rules for the files a stranger
reads first. This script is where those rules live as code, next to the
vocabulary they enforce, so the rules cannot drift from the documents
that state them (issue #123, PRD #120). Stdlib only, like everything here.

    python tools/house_check.py            # every tracked Markdown file,
                                           # and the tool files (below)
    python tools/house_check.py README.md  # just these paths

With no paths it judges the checkout it is run from: run it from the root
of any checkout, not only this one, and it reads that checkout's tracked
files. A path ending in `.py` is read as code (the code pass, below).

Findings print one per line as `file:line: rule: excerpt`, warnings as
`file:line: rule (warning): excerpt`. The exit code is 1 when any finding
is a failure, 0 otherwise. CI runs the same command.
"""

import re
import subprocess
import sys
from pathlib import Path

# --- the rules -------------------------------------------------------------

# GLOSSARY, "Anti-terms": words that overclaim what a hash chain is. They
# fail wherever they appear, in any Markdown file or tool file, except in
# the refutation form (below), which is how the GLOSSARY itself and the
# README say what this tool is not.
ANTI_TERMS = [
    r"blockchain",
    r"immutable",
    r"audit[ -]log",
    r"audit[ -]trail",
]

# Overclaim words: claims about the chain that the threat model does not
# support (ADR-0002: detection, never prevention; ADR-0001: consistency,
# not proof). They fail on the front door and warn everywhere else, where
# an ADR may need the word to say what was rejected.
OVERCLAIMS = [
    r"prove",
    r"proves",
    r"guarantee",
    r"always",
    r"cannot be tampered",
    # "immutable" belongs here too, but the anti-term rule above already
    # fails it everywhere, which is the stricter reading; listing it twice
    # would report it twice.
]

# The synonym table (issue #241): each GLOSSARY term, the reason the
# GLOSSARY gives, and the words that must not stand in for it. Those
# words are everyday words used correctly all over this repo ("backs up
# the settings file", "the legacy mode", "an MCP server"), and a rule
# that fired on every "server" would be worse than none, so each pattern
# matches the concept use, never the bare word. A synonym warns
# everywhere and fails on the front door and in the code; the refutation
# form escapes it, so an ADR may still name the word it rejected.
_THE = r"(?:(?:the|a|an|your|its|their|our|this|that) )?"   # an optional article
_CHAIN = r"(?:chains?|receipts?|entries|entry|logs?)"           # what gets sent
SYNONYMS = [
    ("profile",
     "posture is this repo's word for trust standing, and the tool detects "
     "and does not prevent, so a tier is named by what is remembered where",
     [r"(?:security|protection|safety) (?:level|mode)s?",           # "a security level"
      r"(?:local|timestamped|full|custom) (?:mode|level|posture)s?",  # "full mode"
      r"(?:profile|tier) (?:mode|level)s?",                         # "profile mode"
      r"--(?:mode|level|posture)"]),                                # a flag: "--level full"
    ("published chain",
     "a backup, a mirror or a replica is kept in step with the original, "
     "and this copy only ever adds",
     [_CHAIN + r" (?:backup|mirror|replica)s?",                     # "chain backup"
      r"(?:backups?|mirror\w*|replica\w*) (?:of )?"                 # "a mirror of the chain",
      + _THE + r"(?:[\w-]+ )?" + _CHAIN,                            # `backup_chain`
      r"(?:back|backs|backed|backing) up "                          # "backs up the entries",
      + _THE + r"(?:[\w-]+ )?" + _CHAIN,                            # not "the settings file"
      _THE + _CHAIN + r" (?:(?:are|is|were|was|get|gets|got|being) )?"
      r"(?:backed up|mirrored|replicated)",                         # "your receipts are backed up"
      r"(?:remote|off-box|off-site|offsite|off-machine) "
      r"(?:backup|mirror|replica)s?"]),                             # "an off-box backup"
    ("receiver",
     "a collector transforms and forwards, and the receiver appends what "
     "arrives and has no read endpoint",
     [r"(?:receipts?|chains?|entries|heads?|publish|published|append-only"
      r"|loxodonta) (?:server|collector)s?",                        # "the chain server"
      r"(?:server|collector)s? (?:for|of) " + _THE
      + r"(?:published )?(?:chains?|entries|heads?|receipts)",      # "a collector for the entries"
      r"collector\.py"]),                                           # a file named for it
    ("package",
     "bundle is the everyday word for the same thing, avoided so the "
     "concept has one name",
     [r"(?:a|an|the|one|this|that|each|every|named|raw) bundles?",  # "ships as a bundle"
      r"bundles? of",                                               # "a bundle of the flags"
      r"bundle (?:readme|manifest|verdict)s?"]),                    # "the bundle readme"
    ("authority timestamp",
     "a token is somebody's signed word and an anchor's proof is nobody's "
     "product, so it is never called an anchor (ADR-0032)",
     [r"(?:authority|authority's|TSA|TSA's|RFC ?3161|timestamp authority)"
      r"[ -]anchor(?:s|ed)?",                                       # "the TSA anchor"
      r"anchor(?:ed|ing) (?:by|with|through|via|at|from) " + _THE
      + r"(?:qualified |public |internal )?(?:authority|TSA|RFC ?3161)",  # "anchored by the authority"
      r"anchor tokens?"]),                                          # a token is the stamp's
]

# The old name (ADR-0010): the command is `loxodonta`, and only the
# artifact keeps the name `receipts`: `receipts.jsonl`, `receipts/`,
# `receipts-<session>`, `actor: "receipts"`, and the noun in prose all
# pass, because none of them is followed by what the tool is followed by.
# Matched in lower case only: the tool's name is written that way even
# opening a sentence, where the noun is capitalized ("Receipts run from
# genesis").
OLD_NAME = [
    # the command: `receipts verify --files`
    r"(?<![.-])receipts (?:init|log|run|head|verify|anchor|publish|stamp"
    r"|hook|report|explain|install-hook|uninstall-hook)",
    # the tool as the subject of a singular verb, a word ending in one s
    # ("receipts exists", "receipts actually needs"); the plural noun
    # takes "are", "stay", "arrive"
    r"(?<![.-])receipts (?:(?:ever|actually|also|still|only|never|now"
    r"|already|itself|just|then) )?(?!(?:as|this|thus|plus|always|perhaps"
    r"|whereas|besides|towards|sometimes)\b)\w*[^\Ws]s",
    # the tool's possessive: "receipts' hook"
    r"(?<![.-])receipts'(?= \w)",
]
# Any of those just after a word that closes a noun phrase is the plural
# noun after all, and passes: "a receipts log", "no receipts is",
# "a session of 3,721 receipts has".
NOUN_PHRASE = (r"\b(?:a|an|the|no|of|to|for|with|from|in|into|on|by|at|its"
               r"|their|your|our|these|those|this|each|every|any|some|all"
               r"|many|more|most|few|both|owed|missing|leaving|\d[\d,]*)\s+$")
# And this one names the tool whatever comes before it.
OLD_NAME_CLI = [r"receipts CLI"]
OLD_NAME_NOTE = (" -> say loxodonta: the command is loxodonta; only the "
                 "artifact keeps the name receipts (ADR-0010)")

# The refutation form: saying the word in order to refuse it. A match is
# allowed when the text just before it is one of these (each anchored at
# the end, so it sits directly against the word) or when the text just
# after it is a REFUTATIONS_AFTER form.
REFUTATIONS = [
    r"\bnot\b(?: called)?\W*(?:(?:a|an|the)\W+)?$",    # "not immutable", "not called a bundle"
    r"\bnever\b(?: called)?\W*(?:(?:a|an|the)\W+)?$",  # "never an audit trail", "never a *protection level*"
    r"\bcannot\b\W*$",                   # "cannot prove"
    r"\bno\b\W*$",                       # 'no "immutable"', "no guarantee"
    r"\bnothing here is\W*$",            # CONTRIBUTING's line
    r"[\"\u201c`]$",                     # a quoted mention: "immutable"
    r"~~(?:[^~]*/ )?$",                  # GLOSSARY strikethrough: ~~audit log / audit trail~~
    r"\bBitcoin\W*$",                    # the other chain, named as such
    r"\w-$",                             # part of another project's name: ai-audit-trail
]
REFUTATIONS_AFTER = [
    r"^\W*nothing\b",                    # "proves nothing"
    r"^[^*]*\*\*\W*Rejected\b",          # an ADR's alternative: **Call it a bundle.** Rejected
]

# The front door: the files a stranger reads before deciding to trust the
# tool. They are written without em dashes (a ruling from the presentation
# arc: a dash reads as the author thinking aloud; the front door states).
# The GLOSSARY and the rest of docs/ keep theirs. Matched by file name,
# wherever the file sits, so a fixture in a temporary directory is judged
# like the root, and docs/START.md is judged as the front door it is: the
# page a stranger is handed before they have decided to trust anything.
FRONT_DOOR = {"README.md", "SECURITY.md", "CONTRIBUTING.md",
              "CHANGELOG.md", "CODE_OF_CONDUCT.md", "START.md"}
EM_DASH = "\u2014"

# The pages that quote the past on purpose: the history and the two tours,
# which walk the code as it was and keep their analogies. The old-name and
# synonym rules skip them. The old-name rule also skips the changelog and
# the ADRs written before the rename, which ADR-0010 says are records of
# decisions made under the old name and are not rewritten.
QUOTES_THE_PAST = {"HISTORY.md", "TOUR.md", "TOUR-SUPERVISOR.md"}

# The code pass: the tool files are read for the vocabulary too, every
# line of them, so identifiers, docstrings and comments are judged as
# prose is. An underscore reads as a space, so `backup_chain` is the words
# "backup chain". Only the anti-terms and the synonym table apply there:
# the overclaim and em-dash rules are about prose a stranger reads, and
# the code's `actor: "receipts"` is the artifact's name. A synonym in
# code fails as it does on the front door, not warns as it does in the
# ADRs: a word that reaches a function name spreads to every call site
# and into the tours, and a warning among the standing overclaim warnings
# would not stop it merging.
CODE_FILES = ["loxodonta.py", "supervisor.py", "receiver.py", "adapters/*.py"]

FAIL, WARN = "fail", "warning"


def findings_for(path):
    """Every finding in one file: (line number, rule, severity, excerpt)."""
    found = []
    text = path.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), 1):
        for rule, severity, match, note in line_findings(path, line):
            found.append((number, rule, severity, excerpt(line, match) + note))
    return found


def line_findings(path, line):
    """(rule, severity, match, note) for each finding on one line."""
    code = path.suffix == ".py"
    front_door = path.name in FRONT_DOOR
    # In code an underscore reads as a space. The swap keeps every offset,
    # so the excerpt still quotes the line as written.
    words = line.replace("_", " ") if code else line
    for match in each_word(ANTI_TERMS, words):
        if not refuted(words, match):
            yield "anti-term", FAIL, match, ""
    if path.name not in QUOTES_THE_PAST:
        for term, reason, patterns in SYNONYMS:
            # One row is one alternation, so two of its patterns meeting
            # on the same words ("named bundle", "bundle of") report once.
            for match in each_word(["(?:" + "|".join(patterns) + ")"], words):
                if not refuted(words, match):
                    severity = FAIL if front_door or code else WARN
                    yield "synonym", severity, match, f" -> say {term}: {reason}"
    if code:
        return
    for match in each_word(OVERCLAIMS, line):
        if not refuted(line, match):
            yield "overclaim", FAIL if front_door else WARN, match, ""
    if front_door:
        for match in re.finditer(EM_DASH, line):
            yield "em-dash", FAIL, match, ""
    if judged_for_old_name(path):
        for match in each_word(OLD_NAME, line, case=True):
            if not re.search(NOUN_PHRASE, line[:match.start()], re.IGNORECASE):
                yield "old-name", FAIL, match, OLD_NAME_NOTE
        for match in each_word(OLD_NAME_CLI, line, case=True):
            yield "old-name", FAIL, match, OLD_NAME_NOTE


def judged_for_old_name(path):
    """False for the pages that keep the old name on purpose: the ones
    that quote the past, the changelog, and ADR-0001 to ADR-0009."""
    if path.name in QUOTES_THE_PAST or path.name == "CHANGELOG.md":
        return False
    return not (path.parent.name == "adrs" and re.match(r"000\d-", path.name))


def each_word(words, line, case=False):
    flags = 0 if case else re.IGNORECASE
    for word in words:
        yield from re.finditer(r"(?<!\w)" + word + r"(?!\w)", line, flags)


def refuted(line, match):
    """True when the word is being refused, quoted, or struck through."""
    before, after = line[:match.start()], line[match.end():]
    return (any(re.search(f, before, re.IGNORECASE) for f in REFUTATIONS)
            or any(re.search(f, after, re.IGNORECASE) for f in REFUTATIONS_AFTER))


def excerpt(line, match):
    """The matched word with a little of its sentence on each side."""
    start = max(0, match.start() - 30)
    end = min(len(line), match.end() + 30)
    return line[start:end].strip()


# --- the command -----------------------------------------------------------

def tracked_files():
    """Every Markdown file git tracks under the working directory, and the
    tool files the code pass reads. Tracked, not present: a scratch file
    in the tree is nobody's front door yet, and the operator-side journals
    the .gitignore lists are not the repo's."""
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md", *CODE_FILES],
        capture_output=True, encoding="utf-8", check=True).stdout
    return [Path(name) for name in listing.split("\0") if name]


def main(argv):
    # Findings quote the documents, which carry arrows and curly quotes; a
    # console that cannot show them must still show the finding.
    sys.stdout.reconfigure(errors="backslashreplace")
    paths = [Path(p) for p in argv] or tracked_files()
    failures = 0
    for path in paths:
        for number, rule, severity, text in findings_for(path):
            label = rule if severity == FAIL else f"{rule} ({severity})"
            print(f"{path}:{number}: {label}: {text}")
            failures += severity == FAIL
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
