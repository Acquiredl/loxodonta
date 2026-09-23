#!/usr/bin/env python3
"""Cut verifier.py out of loxodonta.py (ADR-0035).

The recorder holds the verify side as one region between two fence
lines. This script copies the recorder's imports and constants, then that
region, under a header of its own, and adds the two lines that run it.
It understands nothing it copies: a rule lives in loxodonta.py and only
there, and verifier.py is never edited by hand.

    python tools/build_verifier.py           write verifier.py
    python tools/build_verifier.py --check   exit 1 if verifier.py is stale

CI runs the check, so a change to the region that did not rebuild the
copy fails the build.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDER = ROOT / "loxodonta.py"
VERIFIER = ROOT / "verifier.py"

OPEN = "# === The verifier (ADR-0035) "
CLOSE = "# === End of the verifier (ADR-0035) "

HEADER = '''\
#!/usr/bin/env python3
"""verifier — the verify side of loxodonta, for whoever is handed a chain.

Judges a receipt chain or a package with nothing running: `head`,
`verify` and `verify-package`, the same verbs and the same verdicts as
loxodonta.py, and nothing that writes, sends, stamps or installs. Stdlib
only. Format spec: docs/SPEC.md (v0.1, frozen).

Generated from loxodonta.py by tools/build_verifier.py (ADR-0035): every
line below is the recorder's own, copied, never edited here. Check this
file against the release's SHA256SUMS, not against a copy beside it.
"""

'''

FOOTER = '''

if __name__ == "__main__":
    run_main(verifier_main)
'''


def build():
    """verifier.py's text: the header, then the recorder from its first
    import to the closing fence, then the entry point."""
    lines = RECORDER.read_text(encoding="utf-8").split("\n")
    first_import = next(i for i, line in enumerate(lines)
                        if line.startswith("import "))
    opens = [i for i, line in enumerate(lines) if line.startswith(OPEN)]
    closes = [i for i, line in enumerate(lines) if line.startswith(CLOSE)]
    if len(opens) != 1 or len(closes) != 1 or not opens[0] < closes[0]:
        sys.exit("error: loxodonta.py needs exactly one verifier region, "
                 "opened and then closed by its two fence lines")
    body = "\n".join(lines[first_import:closes[0]]).rstrip("\n")
    return HEADER + body + "\n" + FOOTER


def main(argv):
    text = build()
    if argv == ["--check"]:
        # Text mode on both sides, so a checkout's line endings are not
        # a difference.
        current = (VERIFIER.read_text(encoding="utf-8")
                   if VERIFIER.exists() else None)
        if current != text:
            print("verifier.py is stale: run python tools/build_verifier.py "
                  "and commit the result", file=sys.stderr)
            return 1
        print("verifier.py is current")
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 64
    VERIFIER.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {VERIFIER.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
