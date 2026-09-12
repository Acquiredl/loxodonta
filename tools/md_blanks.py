#!/usr/bin/env python3
"""md_blanks.py: markdownlint MD012 (no multiple consecutive blank
lines), locally, before CI says it.

Nothing in the repo runs markdownlint, so this rule is only ever caught
in the pull request, twice now on the same file. The naive shell version
of this check misses it on a Windows checkout, where git's line-ending
conversion leaves a carriage return on every line and a "blank" line is
"\r" rather than "". Strip the line ending, then test.

    python tools/md_blanks.py              # every tracked Markdown file
    python tools/md_blanks.py README.md    # just these

Prints `file:line: two blank lines` per finding; exit 1 when any.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tracked():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.md"],
                         capture_output=True, encoding="utf-8", check=True)
    return [ROOT / name for name in out.stdout.split("\n") if name.strip()]


def findings(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    blank = 0
    for number, line in enumerate(text.split("\n"), start=1):
        if line.strip("\r").strip() == "":
            blank += 1
            if blank > 1:
                yield number
        else:
            blank = 0


def main(argv):
    files = [Path(name).resolve() for name in argv[1:]] or tracked()
    found = 0
    for path in files:
        for number in findings(path):
            rel = path.relative_to(ROOT).as_posix()
            print(f"{rel}:{number}: two blank lines (MD012)")
            found += 1
    if found:
        print(f"{found} finding(s); markdownlint would fail the build")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
