#!/usr/bin/env python3
"""house_check.py, the house checker: the repo's vocabulary, enforced.

The GLOSSARY names words this project refuses (the anti-terms), and the
presentation arc added two more house rules for the files a stranger
reads first. This script is where those rules live as code, next to the
vocabulary they enforce, so the rules cannot drift from the documents
that state them (issue #123, PRD #120). Issue #241 added three more: the
tool's old name, the synonym table, and the code pass (each below).
Stdlib only, like everything here.

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

import io
import re
import subprocess
import sys
import tokenize
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
# the settings file", "the legacy mode", "an MCP server", "OpenSSL's
# security level"), so each pattern names the concept, the word tied to
# what it would stand for. A bare everyday noun ("a mirror of your work",
# "the server", "your collector") is ambiguous and is not judged. A
# synonym warns everywhere and fails on the front door and in the code;
# the refutation form escapes it, so an ADR may still name the word it
# rejected.
_THE = r"(?:(?:the|a|an|your|its|their|our|this|that) )?"   # an optional article
# What gets sent, never the place an operator keeps it: "back up the
# receipts folder" is the operator's own backup, and passes.
_CHAIN = (r"(?:chains?|receipts?|entries|entry)"
          r"(?! (?:folder|drawer|store|director|file|home|path)\w*)")
SYNONYMS = [
    ("profile",
     "posture is this repo's word for trust standing, and the tool detects "
     "and does not prevent, so a tier is named by what is remembered where",
     [r"protection (?:level|mode)s?",                               # "a protection level"
      r"full security",                                             # the tier's rejected name
      r"(?:local|timestamped|full|custom) (?:mode|level|posture)s?",  # "full mode"
      r"(?:profile|tier) (?:mode|level)s?",                         # "profile mode"
      r"--(?:level|posture)"]),                                     # a flag: `--level full`
    ("published chain",
     "the entries only go outward, to a remote chosen because it only "
     "adds, and nothing is restored from it or synced back",
     [_CHAIN + r"(?:'s|')? (?:backup|mirror|replica)s?",            # "chain backup", "the chain's mirror"
      r"(?:backups?|mirror\w*|replica\w*) (?:of )?"                 # "a mirror of the chain",
      + _THE + r"(?:[\w-]+ )?" + _CHAIN + r"(?!')",                 # `backup_chain`, "mirror the receipts"
      r"(?:back|backs|backed|backing) up "                          # "backs up the entries",
      + _THE + r"(?:[\w-]+ )?" + _CHAIN,                            # never "the settings file"
      _THE + _CHAIN + r" (?:(?:are|is|were|was|get|gets|got|being) )?"
      r"(?:backed up|mirrored|replicated)",                         # "your receipts are backed up"
      r"(?:remote|off-box|off-site|offsite|off-machine) "
      r"(?:backup|mirror|replica)s?"]),                             # "an off-box backup"
    ("receiver",
     "it keeps what arrives, forwards nothing, and has no route to read, "
     "list or delete; its name is the receiver",
     [r"(?:receipts?|chains?|entries|heads?|publish|published|append-only"
      r"|loxodonta) (?:server|collector)s?",                        # "the chain server"
      r"(?:server|collector)s? (?:for|of) " + _THE
      + r"(?:published )?(?:chains?|entries|heads?|receipts)",      # "a collector for the entries"
      r"collector\.py"]),                                           # a file named for it
    ("package",
     "bundle is the everyday word for the same thing, avoided so the "
     "concept has one name",
     [r"(?:a|an|the|one|this|that|each|every|named) bundles?",      # "ships as a bundle"
      r"bundles? of",                                               # "a bundle of the flags"
      r"bundle (?:readme|manifest|verdict)s?"]),                    # "the bundle readme"
    ("raw archive",
     "the --raw export's zip has no manifest and is not a package "
     "(ADR-0026 ruling 9)",
     [r"raw bundles?"]),                                            # "raw bundles carry command lines"
    ("authority timestamp",
     "a token is somebody's signed word and an anchor's proof is nobody's "
     "product, so it is never called an anchor (ADR-0032)",
     [r"(?:authority|authority's|TSA|TSA's|RFC ?3161|timestamp authority)"
      r"[ -]anchor(?:s|ed)?",                                       # "the TSA anchor"
      r"anchor(?:s|ed|ing) (?:(?:the|a|its|each) (?:head|chain|manifest|digest)s? )?"
      r"(?:by|with|through|via|at|from|to) " + _THE
      + r"(?:qualified |public |internal )?(?:authority|TSA|RFC ?3161)",  # "anchors the head at the authority"
      r"anchor tokens?"]),                                          # a token is the stamp's
]

# The old name (ADR-0010): the command is `loxodonta`, and only the
# artifact keeps the name `receipts`. In prose, `receipts` before a verb is
# the plural noun as often as the old tool ("receipts run from genesis to
# the head", "each session's receipts verify clean"), so bare prose is not
# judged. Three forms are not ambiguous, and those fail. The artifact's
# own spellings (`receipts.jsonl`, `receipts/`, `receipts-<session>`,
# `actor: "receipts"`) match none of them.
_VERBS = (r"(?:init|log|run|head|verify|anchor|publish|stamp|hook|report"
          r"|explain|install-hook|uninstall-hook)")
# 1. The old command written as code: inside an inline code span, or on a
#    line of a fenced block, `$ receipts verify` and `python receipts run`
#    included. Judged only there (below).
OLD_COMMAND = r"(?<![\w.-])receipts " + _VERBS + r"(?!\w)"
OLD_NAME = [
    # 2. The old script run as a command: `python receipts.py verify`,
    #    or the script and a verb. Its name alone is only a file name.
    r"(?:\bpython3? (?:\S*[/\\])?receipts\.py(?: " + _VERBS + r")?"
    r"|(?<![\w.-])receipts\.py " + _VERBS + r")(?!\w)",
    # 3. The tool named as a tool, in any case: "the receipts CLI", "Install
    #    the Receipts tool". Not "receipts tool calls" or "command lines".
    r"(?<![\w.-])(?i:receipts (?:tool|CLI|command|recorder)s?(?! (?:call|line)s?\b))",
]
OLD_NAME_NOTE = (" -> say loxodonta: the command is loxodonta; only the "
                 "artifact keeps the name receipts (ADR-0010)")

# The refutation form: saying the word in order to refuse it. A match is
# allowed when the text just before it is one of these (each anchored at
# the end, so it sits directly against the word), when the text just after
# it is a REFUTATIONS_AFTER form, or when it sits inside an ADR's rejected
# alternative (below). The gap a refusing word may leave before the word
# it refuses never crosses the end of a sentence: in "It is not. The chain
# server appends." the "not" refuses nothing that follows.
_GAP = r"[^\w.?!]"                       # a space or a mark, never . ? !
QUOTED = r"[\"\u201c`]$"                 # a quoted mention: "immutable"
REFUTATIONS = [
    r"\bnot\b(?: called)?" + _GAP + r"*(?:(?:a|an|the)" + _GAP + r"+)?$",    # "not a blockchain", "not called a bundle"
    r"\bnever\b(?: called)?" + _GAP + r"*(?:(?:a|an|the)" + _GAP + r"+)?$",  # "never a *protection level*"
    r"\bcannot\b" + _GAP + r"*$",       # "cannot prove"
    r"\bno\b" + _GAP + r"*$",           # 'no "immutable"', "no guarantee"
    r"\bnothing here is" + _GAP + r"*$",  # CONTRIBUTING's line
    QUOTED,
    r"~~(?:[^~]*/ )?$",                  # GLOSSARY strikethrough: ~~audit log / audit trail~~
    r"\bBitcoin\W*$",                    # the other chain, named as such
    r"\w-$",                             # part of another project's name: ai-audit-trail
]
REFUTATIONS_AFTER = [
    r"^\W*nothing\b",                    # "proves nothing"
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

# A fenced code block opens and closes on a line of backticks or tildes.
FENCE = r"\s*(?:```|~~~)"

# The code pass: the tool files are read for the vocabulary too, every
# line of them, identifiers, strings, comments and docstrings. Only the
# anti-terms and the synonym table apply there: the overclaim and em-dash
# rules are about prose a stranger reads, and the code's own
# `actor: "receipts"` is the artifact's name. Only a comment or a
# docstring can refuse a word in code, and only by the word forms: a quote
# there opens a string, and `not` elsewhere is an operator. A synonym in
# code fails as it does on the front door, not warns as it does in the
# ADRs: a word that reaches a function name spreads to every call site and
# into the tours, and a warning among the standing overclaim warnings
# would not stop it merging.
CODE_FILES = ["loxodonta.py", "supervisor.py", "receiver.py", "adapters/*.py"]

FAIL, WARN = "fail", "warning"


# --- reading a file --------------------------------------------------------

def findings_for(path):
    """Every finding in one file: (line number, rule, severity, excerpt)."""
    text = path.read_text(encoding="utf-8")
    code = path.suffix == ".py"
    prose = prose_in_code(text) if code else {}
    fenced = False
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if code:
            results = code_findings(line, prose.get(number, []))
        else:
            if re.match(FENCE, line):
                fenced = not fenced
            results = markdown_findings(path, line, fenced)
        for rule, severity, match, note in results:
            found.append((number, rule, severity, excerpt(line, match) + note))
    return found


def markdown_findings(path, line, fenced):
    """(rule, severity, match, note) for each finding on one Markdown line."""
    front_door = path.name in FRONT_DOOR
    for match in each_word(ANTI_TERMS, as_words(line)):
        if not refuted(line, match, quotes=not written_as_code(line, match)):
            yield "anti-term", FAIL, match, ""
    if path.name not in QUOTES_THE_PAST:
        for term, reason, match in synonyms(line):
            if not refuted(line, match, quotes=not written_as_code(line, match)):
                severity = FAIL if front_door else WARN
                yield "synonym", severity, match, f" -> say {term}: {reason}"
    for match in each_word(OVERCLAIMS, line):
        if not refuted(line, match):
            yield "overclaim", FAIL if front_door else WARN, match, ""
    if front_door:
        for match in re.finditer(EM_DASH, line):
            yield "em-dash", FAIL, match, ""
    if judged_for_old_name(path):
        spans = code_spans(line, fenced)
        for match in re.finditer(OLD_COMMAND, line):
            if any(start <= match.start() < end for start, end in spans):
                yield "old-name", FAIL, match, OLD_NAME_NOTE
        for pattern in OLD_NAME:
            for match in re.finditer(pattern, line):
                yield "old-name", FAIL, match, OLD_NAME_NOTE


def code_findings(line, prose):
    """(rule, severity, match, note) for each finding on one line of code.
    `prose` is where this line is a comment or a docstring, the only place
    a word in code can be refused."""
    for match in each_word(ANTI_TERMS, as_words(line)):
        if not refuted_in_code(line, match, prose):
            yield "anti-term", FAIL, match, ""
    for term, reason, match in synonyms(line):
        if not refuted_in_code(line, match, prose):
            yield "synonym", FAIL, match, f" -> say {term}: {reason}"


def synonyms(line):
    """(term, reason, match) for each synonym on a line. One row is one
    alternation, so two of its patterns meeting on the same words ("named
    bundle", "bundle of") report once."""
    for term, reason, patterns in SYNONYMS:
        for match in each_word(["(?:" + "|".join(patterns) + ")"], as_words(line)):
            yield term, reason, match


def as_words(line):
    """The line with each underscore read as a space, so an identifier such
    as `backup_chain` is the words "backup chain". The length is the same,
    so every offset still points into the line as written."""
    return line.replace("_", " ")


def written_as_code(line, match):
    """True for an identifier (`backup_chain`) or a flag (`--level`): in
    quotes because it is code, never because it is being mentioned."""
    text = line[match.start():match.end()]
    return "_" in text or text.startswith("-")


def code_spans(line, fenced):
    """Where a Markdown line is code, as (start, end) offsets: the whole
    line inside a fenced block, otherwise each inline `code span`."""
    if fenced:
        return [(0, len(line))]
    return [m.span() for m in re.finditer(r"`[^`]+`", line)]


def prose_in_code(text):
    """Where a Python file speaks prose, as {line number: [(start, end)]}:
    each comment after its `#`, and each string that is a statement by
    itself (a docstring) inside its quotes. A file that does not tokenize
    has no prose, so nothing in it is refused."""
    spans = {}
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError):
        return spans
    for i, token in enumerate(tokens):
        if token.type == tokenize.COMMENT:
            row, column = token.start
            spans.setdefault(row, []).append((column + 1, token.end[1]))
        elif token.type == tokenize.STRING and stands_alone(tokens, i):
            body = token.string.lstrip("rRbBuU")
            prefix = len(token.string) - len(body)
            quote = 3 if body[:3] in ('"""', "'''") else 1
            (first, opened), (last, closed) = token.start, token.end
            for row in range(first, last + 1):
                start = opened + prefix + quote if row == first else 0
                end = closed - quote if row == last else sys.maxsize
                spans.setdefault(row, []).append((start, end))
    return spans


# Tokens that sit between statements without being one.
_BETWEEN = {tokenize.NL, tokenize.COMMENT}
_STATEMENT_EDGE = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                   tokenize.ENCODING, tokenize.ENDMARKER}


def stands_alone(tokens, i):
    """True when the string at tokens[i] is a statement by itself, as a
    docstring is: a statement edge on each side of it."""
    before, after = i - 1, i + 1
    while before >= 0 and tokens[before].type in _BETWEEN:
        before -= 1
    while after < len(tokens) and tokens[after].type in _BETWEEN:
        after += 1
    return ((before < 0 or tokens[before].type in _STATEMENT_EDGE)
            and after < len(tokens) and tokens[after].type in _STATEMENT_EDGE)


def judged_for_old_name(path):
    """False for the pages that keep the old name on purpose: the ones
    that quote the past, the changelog, and ADR-0001 to ADR-0009."""
    if path.name in QUOTES_THE_PAST or path.name == "CHANGELOG.md":
        return False
    return not (path.parent.name == "adrs" and re.match(r"000\d-", path.name))


def each_word(words, line):
    for word in words:
        yield from re.finditer(r"(?<!\w)" + word + r"(?!\w)", line, re.IGNORECASE)


def refuted(line, match, start=0, end=None, quotes=True):
    """True when the word is being refused, quoted, struck through, or
    named as an ADR's rejected alternative. Only the line from `start` to
    `end` counts, and with `quotes` false a quote beside the word is not
    a mention."""
    before, after = line[start:match.start()], line[match.end():end]
    forms = REFUTATIONS if quotes else [f for f in REFUTATIONS if f != QUOTED]
    return (any(re.search(f, before, re.IGNORECASE) for f in forms)
            or any(re.search(f, after, re.IGNORECASE) for f in REFUTATIONS_AFTER)
            or rejected_alternative(before, after))


def refuted_in_code(line, match, prose):
    """True when the word sits in a comment or docstring on this line and
    that comment or docstring refuses it, by the word forms alone."""
    for start, end in prose:
        if start <= match.start() and match.end() <= end:
            return refuted(line, match, start, end, quotes=False)
    return False


def rejected_alternative(before, after):
    """An ADR names what it rejected as a bold heading followed by the word
    Rejected: `**Call it a bundle.** Rejected: ...`. The word is refused
    only inside that bold span, never merely somewhere before one."""
    return (before.count("**") % 2 == 1
            and re.match(r"[^*]*\*\*\W*Rejected\b", after) is not None)


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
