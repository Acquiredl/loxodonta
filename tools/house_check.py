#!/usr/bin/env python3
"""house_check.py, the house checker: the repo's vocabulary, enforced.

The GLOSSARY names words this project refuses (the anti-terms), and the
presentation arc added two more house rules for the files a stranger
reads first. This script is where those rules live as code, next to the
vocabulary they enforce, so the rules cannot drift from the documents
that state them (issue #123, PRD #120). Stdlib only, like everything here.

    python tools/house_check.py            # every tracked Markdown file
    python tools/house_check.py README.md  # just these paths

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
# fail wherever they appear, in any Markdown file, except in the
# refutation form (below), which is how the GLOSSARY itself and the README
# say what this tool is not.
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

# The refutation form: saying the word in order to refuse it. A match is
# allowed when the text just before it is one of these (each anchored at
# the end, so it sits directly against the word) or when the text just
# after it is a REFUTATION_AFTER form.
REFUTATIONS = [
    r"\bnot\b\W*(?:a |an |the )?$",      # "not immutable", "not a blockchain"
    r"\bnever\b\W*(?:a |an |the )?$",    # "never an audit trail"
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
]

# The front door: the files a stranger reads before deciding to trust the
# tool. They are written without em dashes (a ruling from the presentation
# arc: a dash reads as the author thinking aloud; the front door states).
# The GLOSSARY and docs/ keep theirs. Matched by file name, wherever the
# file sits, so a fixture in a temporary directory is judged like the root.
FRONT_DOOR = {"README.md", "SECURITY.md", "CONTRIBUTING.md",
              "CHANGELOG.md", "CODE_OF_CONDUCT.md"}
EM_DASH = "\u2014"

FAIL, WARN = "fail", "warning"


def findings_for(path):
    """Every finding in one file: (line number, rule, severity, excerpt)."""
    found = []
    front_door = path.name in FRONT_DOOR
    text = path.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), 1):
        for match in each_word(ANTI_TERMS, line):
            if not refuted(line, match):
                found.append((number, "anti-term", FAIL, excerpt(line, match)))
        for match in each_word(OVERCLAIMS, line):
            if not refuted(line, match):
                severity = FAIL if front_door else WARN
                found.append((number, "overclaim", severity, excerpt(line, match)))
        if front_door:
            for match in re.finditer(EM_DASH, line):
                found.append((number, "em-dash", FAIL, excerpt(line, match)))
    return sorted(found, key=lambda f: f[0])


def each_word(words, line):
    for word in words:
        yield from re.finditer(r"\b" + word + r"\b", line, re.IGNORECASE)


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

def tracked_markdown():
    """Every Markdown file git tracks under the working directory. Tracked,
    not present: a scratch file in the tree is nobody's front door yet, and
    the operator-side journals the .gitignore lists are not the repo's."""
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        capture_output=True, encoding="utf-8", check=True).stdout
    return [Path(name) for name in listing.split("\0") if name]


def main(argv):
    # Findings quote the documents, which carry arrows and curly quotes; a
    # console that cannot show them must still show the finding.
    sys.stdout.reconfigure(errors="backslashreplace")
    paths = [Path(p) for p in argv] or tracked_markdown()
    failures = 0
    for path in paths:
        for number, rule, severity, text in findings_for(path):
            label = rule if severity == FAIL else f"{rule} ({severity})"
            print(f"{path}:{number}: {label}: {text}")
            failures += severity == FAIL
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
