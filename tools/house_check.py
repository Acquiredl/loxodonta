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
    python tools/house_check.py --front-door   # the presentation rules

With no paths it judges the checkout it is run from: run it from the root
of any checkout, not only this one, and it reads that checkout's tracked
files. A path ending in `.py` is read as code (the code pass, below).

Findings print one per line as `file:line: rule: excerpt`, warnings as
`file:line: rule (warning): excerpt`. The exit code is 1 when any finding
is a failure, 0 otherwise. CI runs the same command.

`--front-door` runs a separate set of rules instead, about the shape a
stranger meets rather than the words (issue #298, the section of that
name below). It takes no paths, judges the whole checkout, and exits 1 on
any finding. CI does not run it yet.
"""

import io
import posixpath
import re
import subprocess
import sys
import tokenize
from pathlib import Path
from urllib.parse import unquote

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
# "the server", "your collector") is ambiguous and is not judged, and
# neither is a verb ("the report mirrors the chain", "back up your
# receipts"): an operator copying their own files is everyday. A
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
      r"(?:backup|mirror|replica)s? (?:of " + _THE                  # "a mirror of the chain",
      + r"(?:[\w-]+ )?)?" + _CHAIN + r"(?!')",                     # `backup_chain`
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
      r"(?:anchored by|anchors (?:the|a|its|each) (?:head|chain|manifest|digest)s?"
      r" (?:at|by|with|through)) " + _THE
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
    # 3. The tool named as a tool, after "the" or "a" and in any case:
    #    "the receipts CLI", "Install the Receipts tool". Never "hook
    #    receipts tool names", "the receipts tooling" or "command lines".
    r"(?i:\b(?:the|a) receipts (?:tool|CLI|command|recorder)s?)(?![\w-])"
    r"(?! (?:call|line)s?\b)",
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
    # "not a blockchain", "not called a bundle"; "whether or not" refuses nothing
    r"(?<!whether or )\bnot\b(?: called)?" + _GAP + r"*(?:(?:a|an|the)" + _GAP + r"+)?$",
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


# --- the front door, measured (--front-door) -------------------------------
#
# The rules above judge words. These judge the shape a stranger meets
# before reading a word closely: the README's first screen, the pictures,
# the indexes, what sits at the root, the changelog, the ADR file names
# (issue #298; an outside review of v0.8.0 scored the presentation below
# the engineering, and a fix held by memory drifts back). They report and
# gate: `--front-door` exits 1 on any finding, and CI runs it as its own
# step after the default pass.
#
# Every number and list the rules use is in this one table, so an argument
# with a threshold is an edit to one line. Paths are relative to the root
# of the checkout, with forward slashes, as `git ls-files` prints them.

# 1. The README's first screen.
FIRST_PARAGRAPH_WORDS = 60       # the first prose paragraph, at most
FIRST_IMAGE_WITHIN = 15          # a picture within the README's first lines,
WORDMARK = "docs/images/wordmark.svg"  # and the wordmark is not that picture
WHY_NOT = "Why not"              # a README heading starts with these words
# 2. Pictures: every file here is shown by some tracked Markdown file,
#    except the sources a picture is made from (a VHS `.tape` script).
IMAGES = "docs/images/"
IMAGE_SOURCES = {".tape"}
# ...and the pictures shown somewhere no Markdown file reaches, with where.
IMAGES_SHOWN_ELSEWHERE = {
    "docs/images/social-preview.png":
        "the GitHub social preview, uploaded by hand in the repository settings",
}
# 3. Indexes: (the index page, the pages it must link, said in words).
#    An index does not have to link itself.
INDEXES = [
    ("docs/README.md", r"docs/[^/]+\.md", "every page in docs/"),
    ("adrs/README.md", r"adrs/\d{4}-[^/]+\.md", "every ADR"),
]
# 4. The root: the only files tracked there, besides any dotfile.
ROOT_ALLOWED = {
    "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "AGENTS.md", "CLAUDE.md",
    "loxodonta.py", "supervisor.py", "receiver.py",   # the three tools
}
# ...and, for anything else, where it could live instead (first match).
WHERE_IT_COULD_LIVE = [
    (r"\.md$", "docs/"),
    (r"\.py$", "tools/"),
    (r"\.(?:toml|ya?ml|json|ini|cfg)$",
     ".github/ (a tool that reads a config file can be told its path)"),
    (r".", "docs/, tools/ or .github/, by what reads it"),
]
# 5. The changelog: each bullet under a version newer than this one, and
#    under [Unreleased], which is newer than every version, at most so
#    many words. The versions already released keep their bullets.
CHANGELOG_JUDGED_AFTER = (0, 8, 0)
CHANGELOG_BULLET_WORDS = 40
# 6. ADR file names: from this number on, a slug of at most so many
#    characters. The ADRs already written keep their names.
ADR_SLUG_FROM = 36
ADR_SLUG_CHARS = 60

# A link or image target in Markdown: `[text](target)`, `![alt](target)`,
# `<a href="target">`, `<img src="target">`, and a reference definition
# `[name]: target`. A reference-style use (`![alt][name]`) is found through
# its definition.
LINK_TARGETS = [
    r"\]\(\s*<?([^)\s>]+)>?(?:\s+[\"'(][^)]*)?\)",
    r"\b(?:src|href)\s*=\s*[\"']([^\"']+)[\"']",
    r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)",
]
IMAGE_TARGETS = [
    r"!\[[^\]]*\]\(\s*<?([^)\s>]+)",
    r"<img\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']",
]
# An image by itself, or an image inside a link (a badge), the link
# inline `[![t](image)](url)` or by reference `[![t](image)][ci]`.
_IMAGE = r"!\[[^\]]*\]\([^)]*\)"
IMAGES_ONLY = (r"(?:\s*(?:\[" + _IMAGE + r"\](?:\([^)]*\)|\[[^\]]*\])|"
               + _IMAGE + r"))+\s*")
# The tagline: a line wholly in italics or bold, with asterisks or
# underscores: `*this*`, `**this**`, `_this_`, `__this__`.
TAGLINE = r"\*{1,2}[^*].*\*{1,2}|_{1,2}[^_].*_{1,2}"
# A list item: `- `, `* `, `+ `, `1. ` or `1) `.
LIST_ITEM = r"\s*(?:[-*+]|\d+[.)])\s"


def front_door_main():
    """Run the front-door rules on the checkout the command is run in and
    print each finding. Exit 1 when there is any, 0 otherwise."""
    top = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, encoding="utf-8", check=True).stdout.strip())
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=top,
        capture_output=True, encoding="utf-8", check=True).stdout
    tracked = sorted(name for name in listing.split("\0") if name)
    found = front_door_findings(top, tracked)
    for where, rule, text in found:
        print(f"{where}: {rule}: {text}")
    return 1 if found else 0


def front_door_findings(top, tracked):
    """Every front-door finding, as (where, rule, text). `where` is
    `file:line` when the finding has a line, and the file alone when it
    is about the whole file (a picture nothing shows, a file at the root).
    Every file set is the tracked one, read from the working tree: a
    scratch file is nobody's front door yet, as for the default pass."""
    def read(name):
        return (top / name).read_text(encoding="utf-8")

    pages = [name for name in tracked if name.endswith(".md")]
    targets = {name: list(link_targets(name, read(name))) for name in pages}
    found = []
    if "README.md" in tracked:
        found += readme_findings(read("README.md"))
    else:
        found.append(("README.md", "first-screen", "there is no README.md"))
    found += orphan_images(tracked, targets)
    found += index_findings(tracked, targets)
    found += root_findings(tracked)
    if "CHANGELOG.md" in tracked:
        found += changelog_findings(read("CHANGELOG.md"))
    found += adr_slug_findings(tracked)
    return found


def readme_findings(text):
    """Rule 1: the README's first paragraph, first picture and Why-not
    heading."""
    lines = text.splitlines()
    found = []
    number, paragraph = first_paragraph(lines)
    if paragraph is not None:
        words = count_words(paragraph)
        if words > FIRST_PARAGRAPH_WORDS:
            found.append((f"README.md:{number}", "first-paragraph",
                          f"{words} words, at most {FIRST_PARAGRAPH_WORDS}: "
                          f"{paragraph[:60]}..."))
    pictures = [target for line in lines[:FIRST_IMAGE_WITHIN]
                for pattern in IMAGE_TARGETS
                for target in re.findall(pattern, line)
                if resolve("README.md", target) not in (None, WORDMARK)]
    if not pictures:
        found.append(("README.md", "first-image",
                      f"no image but the wordmark in the first "
                      f"{FIRST_IMAGE_WITHIN} lines (a badge is served from "
                      f"elsewhere and does not count)"))
    headings = [line for line, fenced in unfenced(lines)
                if not fenced and re.match(r"#{1,6}\s+" + re.escape(WHY_NOT) + r"\b",
                                           line, re.IGNORECASE)]
    if not headings:
        found.append(("README.md", "why-not",
                      f'no heading starts "{WHY_NOT}"'))
    return found


def first_paragraph(lines):
    """(line number, text) of the README's first paragraph of ordinary
    prose, or (None, None) when it has none. On the way down, every line
    that is not ordinary prose is passed over:

    - blank lines, and HTML comments (a `<!-- -->` on one line or several),
    - a line of images and nothing else: the wordmark, and a line of badges
      (each an image inside a link),
    - the tagline: a line wholly in italics or bold (TAGLINE),
    - headings, HTML lines (`<p align=...>`), fenced code, list items,
      table rows and quotations, none of which is a paragraph.

    The first line left starts the paragraph, and it runs to the next blank
    line. Its words are counted as they read (see count_words)."""
    in_comment = fenced = False
    start, paragraph = None, []
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if start is None:
            if in_comment:
                in_comment = "-->" not in stripped
                continue
            if stripped.startswith("<!--"):
                in_comment = "-->" not in stripped
                continue
            if re.match(FENCE, line):
                fenced = not fenced
                continue
            if (fenced or not stripped
                    or re.fullmatch(IMAGES_ONLY, stripped)
                    or re.fullmatch(TAGLINE, stripped)
                    or re.match(r"(?:#|<|\||>|[-*+]\s|\d+[.)]\s)", stripped)):
                continue
            start = number
        if not stripped:
            break
        paragraph.append(stripped)
    return (start, " ".join(paragraph)) if start else (None, None)


def count_words(text):
    """Words as a reader meets them: a link is its text, an image is
    nothing, and a token with no letter or digit in it (a lone dash or
    colon) is not a word."""
    text = re.sub(_IMAGE, " ", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return len(re.findall(r"\S*\w\S*", text))


def unfenced(lines):
    """(line, fenced) for each line: whether it sits in a fenced block."""
    fenced = False
    for line in lines:
        if re.match(FENCE, line):
            fenced = not fenced
            yield line, True
        else:
            yield line, fenced


def link_targets(page, text):
    """Every link or image target in a Markdown page, outside fenced code."""
    for line, fenced in unfenced(text.splitlines()):
        if fenced:
            continue
        for pattern in LINK_TARGETS:
            yield from re.findall(pattern, line)


def resolve(page, target):
    """The tracked-file path a link on `page` points at, or None for a
    link to a URL or to a place in the same page. `/x` is from the root
    of the checkout, anything else from the page's own folder; a `#part`
    or `?query` is dropped."""
    target = unquote(re.split(r"[#?]", target, maxsplit=1)[0])
    if not target or re.match(r"[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
        return None
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    return posixpath.normpath(posixpath.join(posixpath.dirname(page), target))


def links_to(targets, name):
    """True when some page's link reaches `name`: by its path, or by a
    URL whose path ends in it (a raw.githubusercontent.com address)."""
    return any(resolve(page, target) == name
               or (resolve(page, target) is None
                   and re.split(r"[#?]", target, maxsplit=1)[0].endswith("/" + name))
               for page, page_targets in targets.items()
               for target in page_targets)


def orphan_images(tracked, targets):
    """Rule 2: a picture under docs/images/ that no tracked page shows."""
    return [(name, "orphan-image", "no tracked Markdown file links it")
            for name in tracked
            if name.startswith(IMAGES)
            and posixpath.splitext(name)[1] not in IMAGE_SOURCES
            and name not in IMAGES_SHOWN_ELSEWHERE
            and not links_to(targets, name)]


def index_findings(tracked, targets):
    """Rule 3: an index page that is missing (one finding, however many
    pages it would list), or that does not link one of its pages."""
    found = []
    for index, pattern, pages in INDEXES:
        listed = [name for name in tracked
                  if re.fullmatch(pattern, name) and name != index]
        if not listed:
            continue
        if index not in tracked:
            found.append((index, "index",
                          f"missing; it would link {pages}, "
                          f"{len(listed)} pages"))
            continue
        own = {index: targets.get(index, [])}
        found += [(index, "index", f"does not link {name}")
                  for name in listed if not links_to(own, name)]
    return found


def root_findings(tracked):
    """Rule 4: a file at the root that is neither allowed nor a dotfile,
    and where it could live instead."""
    found = []
    for name in tracked:
        if "/" in name or name.startswith(".") or name in ROOT_ALLOWED:
            continue
        home = next(where for pattern, where in WHERE_IT_COULD_LIVE
                    if re.search(pattern, name))
        found.append((name, "root-file",
                      f"not on the root allowlist; it could live in {home}"))
    return found


def changelog_findings(text):
    """Rule 5: a changelog bullet too long, under [Unreleased] or a version
    newer than CHANGELOG_JUDGED_AFTER. A bullet runs from its marker to
    the next blank line, heading or bullet, so a wrapped bullet is counted
    whole and reported at its first line."""
    found = []
    judged = False
    bullets = []                     # [line number, text] of each judged bullet
    current = None
    for number, (line, fenced) in enumerate(unfenced(text.splitlines()), 1):
        # `## [0.9.0] - date`, `## 0.10.0`, `## [Unreleased]`, `## Unreleased`
        heading = re.match(r"##\s+\[?([^\]\s]+)", line)
        if not fenced and re.match(r"#{1,2}\s", line):
            judged = bool(heading) and newer_than_judged(heading.group(1))
            current = None
        elif fenced or not line.strip() or line.startswith("#"):
            current = None
        elif re.match(LIST_ITEM, line):
            body = re.sub(r"^" + LIST_ITEM, "", line)
            current = [number, body] if judged else None
            if current:
                bullets.append(current)
        elif current:
            current[1] += " " + line.strip()
    for number, bullet in bullets:
        words = count_words(bullet)
        if words > CHANGELOG_BULLET_WORDS:
            found.append((f"CHANGELOG.md:{number}", "changelog-bullet",
                          f"{words} words, at most {CHANGELOG_BULLET_WORDS}: "
                          f"{bullet.strip()[:60]}..."))
    return found


def newer_than_judged(version):
    """True for [Unreleased] and for a version newer than the last one
    whose bullets are left alone. A heading that names no version is not
    judged."""
    if version.strip().lower() == "unreleased":
        return True
    numbers = re.match(r"v?(\d+)\.(\d+)\.(\d+)", version.strip())
    return bool(numbers) and tuple(map(int, numbers.groups())) > CHANGELOG_JUDGED_AFTER


def adr_slug_findings(tracked):
    """Rule 6: an ADR numbered ADR_SLUG_FROM or later whose file name,
    past its number, is longer than ADR_SLUG_CHARS characters."""
    found = []
    for name in tracked:
        adr = re.fullmatch(r"adrs/(\d{4})-(.+)\.md", name)
        if adr and int(adr.group(1)) >= ADR_SLUG_FROM \
                and len(adr.group(2)) > ADR_SLUG_CHARS:
            found.append((name, "adr-slug",
                          f"slug of {len(adr.group(2))} characters, at most "
                          f"{ADR_SLUG_CHARS}"))
    return found


# --- the command -----------------------------------------------------------

def tracked_files():
    """Every Markdown file git tracks under the working directory, and the
    tool files the code pass reads. Tracked, not present: a scratch file
    in the tree is nobody's front door yet, and an untracked local file
    is not the repo's."""
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md", *CODE_FILES],
        capture_output=True, encoding="utf-8", check=True).stdout
    return [Path(name) for name in listing.split("\0") if name]


USAGE = ("usage: house_check.py [PATH ...]\n"
         "       house_check.py --front-door   (takes no paths: it judges "
         "the whole checkout)")


def main(argv):
    # Findings quote the documents, which carry arrows and curly quotes; a
    # console that cannot show them must still show the finding.
    sys.stdout.reconfigure(errors="backslashreplace")
    if "--front-door" in argv:
        if len(argv) != 1:
            # Exit 2, as argparse does in the three tools, for a command
            # line that asks for something the checker does not do.
            print(USAGE, file=sys.stderr)
            return 2
        return front_door_main()
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
