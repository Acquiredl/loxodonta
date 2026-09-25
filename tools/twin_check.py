#!/usr/bin/env python3
"""Hold the rules written in more than one file to one text (ADR-0035).

loxodonta.py, supervisor.py and receiver.py never import each other, so
a rule two of them need is written in each: a twin. The list below is
every twin, the names it covers, the files it lives in and why it is
written twice, and every name the files share that is not a twin. The
recorder holds the original of every twin; a copy is its text again,
docstring included.

    python tools/twin_check.py --page    write docs/TWINS.md from the list
    python tools/twin_check.py --check   exit 1 on drift, naming each problem
    ... --root DIR                       judge the files under DIR instead

`--check` fails on a copy whose top-level source differs from its
original, on a name the list declares that a file no longer defines, on
a stale docs/TWINS.md, and on a top-level name defined in two of the
files that the list does not declare. The files are read as text,
never imported. The suite runs the check.
"""

import ast
import sys
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ("loxodonta.py", "supervisor.py", "receiver.py")
ORIGINAL = "loxodonta.py"
PAGE = Path("docs") / "TWINS.md"

EX_USAGE = 64

# A twin: its rule, the top-level names it covers, the file holding the
# original, the files holding a copy, and why it is written twice.
Twin = namedtuple("Twin", "rule names original copies why")
# A name the files share that is not a twin: each file means its own.
Different = namedtuple("Different", "name files why")

SUPERVISOR = ("supervisor.py",)
RECEIVER = ("receiver.py",)
BOTH = ("supervisor.py", "receiver.py")

TWINS = (
    Twin("The line rule", ("split_lines",), ORIGINAL, BOTH,
         "Where a line of a chain ends (SPEC section 1, #299): the recorder "
         "verifies by it, the supervisor lists and shows chains by it, and "
         "the receiver counts the lines of a batch and of the file it keeps "
         "by it."),
    Twin("Escaping receipt text",
         ("NAMED_ESCAPES", "STEERING_CATEGORIES", "visible"),
         ORIGINAL, SUPERVISOR,
         "The recorder shows receipt text in report, explain and verify's "
         "messages, the supervisor on every recall surface, and both must "
         "make the same hidden characters visible (#295)."),
    Twin("Which hook entries are the recorder's",
         ("RECORDER_NAMES", "DIGEST_NAMES", "WIRED_VERB", "command_words",
          "file_name", "is_interpreter", "owned_script",
          "beside_a_recorder"),
         ORIGINAL, SUPERVISOR,
         "install-hook and uninstall-hook claim entries by it; the "
         "supervisor's scan reads the wired matchers, the SessionEnd "
         "wiring and the recorder's path by it (#293, #303)."),
    Twin("The store's address", ("store_home", "project_slug"),
         ORIGINAL, SUPERVISOR,
         "A hook files each chain in its project's drawer, and the "
         "supervisor finds the drawer by the same two answers, so one "
         "project names one folder (ADR-0011)."),
    Twin("Versions", ("TOOL_VERSION", "FORMAT_VERSION"), ORIGINAL, BOTH,
         "The files ship in one release, whose tag must match the tool "
         "version in every file, and each prints both on `--version` "
         "(ADR-0022)."),
    Twin("The checkout's commit", ("checkout_commit",), ORIGINAL, RECEIVER,
         "The recorder and the receiver print the commit they sit in on "
         "`--version` the same way: local git only, never fetched "
         "(ADR-0015)."),
    Twin("A usage error", ("EX_USAGE", "UsageParser"), ORIGINAL, BOTH,
         "A wrong flag exits 64 from every file, never a number a script "
         "could read as an answer (ADR-0026 ruling 7)."),
    Twin("No chain to judge", ("EX_NOINPUT",), ORIGINAL, SUPERVISOR,
         "`verify` exits 66 when there is no chain to judge, in the "
         "recorder and in the supervisor alike (ADR-0037)."),
    Twin("Writing to the console", ("speak_utf8",), ORIGINAL, BOTH,
         "Every file can print text a Windows console's code page cannot "
         "hold, and none of them may die on it (#294)."),
    Twin("The package",
         ("PACKAGE_FORMAT", "PACKAGE_MAX_BYTES", "SIGNATURE_NAMESPACE",
          "SIGNATURE_PRINCIPAL", "key_fingerprint"),
         ORIGINAL, SUPERVISOR,
         "The supervisor writes a package and the recorder, and the "
         "verifier cut from it, judge one: the format it names, the size "
         "it may unpack to, the namespace and principal its signature is "
         "made and checked under, and the key fingerprint both print "
         "(ADR-0026)."),
    Twin("Attempt rows", ("ATTEMPT_KIND", "is_attempt"),
         ORIGINAL, SUPERVISOR,
         "The recorder notes how a session-end step went in a row of kind "
         "`attempt`, and every reader that judges or schedules skips it, "
         "the recorder's and the supervisor's alike (#240)."),
    Twin("Naming a remote", ("remote_id",), ORIGINAL, SUPERVISOR,
         "The recorder writes a fingerprint of the receiver's URL into the "
         "publish memo, and the supervisor's keeper compares against it "
         "to find where the chain route left off (#263)."),
    Twin("A URL the tools send to",
         ("PUBLISH_SCHEMES", "SHELL_HAZARDS", "publish_url"),
         ORIGINAL, SUPERVISOR,
         "The supervisor's keeper hands its URLs to the recorder's "
         "`publish`, so its flags refuse the URLs `publish` refuses, as a "
         "usage error when the flag is given (ADR-0025)."),
    Twin("Written-down coverage", ("COVERAGE_NAME",), ORIGINAL, SUPERVISOR,
         "The recorder writes down the coverage it wired under this name, "
         "and the supervisor's scan reads it there (ADR-0030)."),
    Twin("A chain batch's content type", ("CHAIN_TYPE",), ORIGINAL, RECEIVER,
         "The recorder sends a batch of the chain under this content type, "
         "and the receiver takes a batch only under it (ADR-0031)."),
)

DIFFERENT = (
    Different("main", FILES,
              "Each file's own command line."),
    Different("cmd_verify", ("loxodonta.py", "supervisor.py"),
              "The recorder's `verify` judges the chain at a path; the "
              "supervisor's finds the chain holding an entry address, "
              "then prints the recorder's verdict on it."),
    Different("cmd_serve", ("supervisor.py", "receiver.py"),
              "The supervisor serves its dashboard and recall; the "
              "receiver serves the URL published chains are sent to."),
    Different("chain_cursor", ("loxodonta.py", "supervisor.py"),
              "Both find where the chain route left off, in different "
              "shapes; a twin once #344 gives the supervisor the "
              "recorder's."),
    Different("VersionAction", FILES,
              "Each file's `--version`, the same line in all three, built "
              "from each file's own helpers: not a twin, since the "
              "supervisor and the receiver hold no `version_line`."),
)


# --- reading the files ----------------------------------------------------

def segment(lines, node):
    """The source text of top-level `node`, as ast.get_source_segment
    gives it, cut from lines split once: that function splits the whole
    file again on every call. A top-level node starts at column 0, and
    its end column counts UTF-8 bytes."""
    last = lines[node.end_lineno - 1].encode("utf-8")
    return "\n".join(lines[node.lineno - 1:node.end_lineno - 1]
                     + [last[:node.end_col_offset].decode("utf-8")])


def top_level(path):
    """{name: source} for every top-level function, class and assignment
    in `path`, read as text. A name defined twice in one file keeps
    both definitions, one after the other."""
    text = path.read_text(encoding="utf-8")
    # Read in text mode, so every line ends in a lone newline.
    lines = text.split("\n")
    found = {}
    for node in ast.parse(text, filename=str(path)).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [name.id for target in node.targets
                     for name in ast.walk(target)
                     if isinstance(name, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target,
                                                            ast.Name):
            names = [node.target.id]
        else:
            continue
        source = segment(lines, node)
        for name in names:
            found[name] = (found[name] + "\n" + source if name in found
                           else source)
    return found


# --- the page -------------------------------------------------------------

INTRO = """\
# Rules written twice

`loxodonta.py`, `supervisor.py` and `receiver.py` never import each other (ADR-0035): each is one file a reader can check alone, run from its own source. So a rule two of them need is written in each. This page lists every such rule, a twin: the names it covers, the files it lives in, and why it is written more than once.

The original of every twin is the recorder, `loxodonta.py`. To change a twin, change the recorder's text, then make each copy the same text, docstring included, since the check compares source. `python tools/twin_check.py --check` fails when a copy differs from its original, when a file no longer defines a name listed here, when this page is stale, and when a top-level name is defined in two of the files without being listed here. The suite runs it.

This page is written from the list in `tools/twin_check.py` by `python tools/twin_check.py --page`: change the list, then rewrite the page.
"""


def code(names):
    return ", ".join(f"`{name}`" for name in names)


def page():
    """docs/TWINS.md's text, from the two lists."""
    parts = [INTRO, "## Twins\n"]
    for twin in TWINS:
        parts.append(f"### {twin.rule}\n\n"
                     f"Names: {code(twin.names)}.\n\n"
                     f"Original: `{twin.original}`. "
                     f"Copies: {code(twin.copies)}.\n\n"
                     f"{twin.why}\n")
    parts.append("## Same name, not a twin\n\n"
                 "These names are defined in more than one file, and each "
                 "file means its own thing by it. The check leaves them "
                 "unjudged.\n\n"
                 "| Name | Files | Why they differ |\n"
                 "| --- | --- | --- |\n"
                 + "".join(f"| `{d.name}` | {code(d.files)} | {d.why} |\n"
                           for d in DIFFERENT))
    return "\n".join(parts)


# --- the check ------------------------------------------------------------

def problems(root):
    """Every way the files under `root` and the page there disagree with
    the lists, one sentence each."""
    found = []
    defined = {name: top_level(root / name) for name in FILES}

    declared = {}   # name: the files the lists say define it
    for twin in TWINS:
        for name in twin.names:
            if name in declared:
                found.append(f"{name} is declared twice in the lists")
            declared[name] = (twin.original, *twin.copies)
    for different in DIFFERENT:
        if different.name in declared:
            found.append(f"{different.name} is declared twice in the lists")
        declared[different.name] = different.files

    for twin in TWINS:
        for name in twin.names:
            original = defined[twin.original].get(name)
            if original is None:
                found.append(f"{twin.rule}: {twin.original} no longer "
                             f"defines {name}, the original")
                continue
            for copy in twin.copies:
                text = defined[copy].get(name)
                if text is None:
                    found.append(f"{twin.rule}: {copy} no longer defines "
                                 f"{name}")
                elif text != original:
                    found.append(f"{twin.rule}: {name} in {copy} differs "
                                 f"from {twin.original}, its original")
    for different in DIFFERENT:
        for file in different.files:
            if different.name not in defined[file]:
                found.append(f"{different.name}: {file} no longer defines "
                             f"it, and the lists say it does")

    for name in sorted(set().union(*defined.values())):
        holders = [file for file in FILES if name in defined[file]]
        if len(holders) < 2:
            continue
        if name not in declared:
            found.append(f"{name} is defined in {' and '.join(holders)} "
                         "and declared neither a twin nor a same name "
                         "that differs: add it to TWINS or DIFFERENT in "
                         "tools/twin_check.py")
            continue
        unlisted = [file for file in holders if file not in declared[name]]
        if unlisted:
            found.append(f"{name} is defined in {' and '.join(unlisted)} "
                         "too, which the lists do not name")

    written = root / PAGE
    current = written.read_text(encoding="utf-8") if written.exists() else None
    if current != page():
        found.append(f"{PAGE.as_posix()} is stale: run python "
                     "tools/twin_check.py --page and commit the result")
    return found


def main(argv):
    args = list(argv)
    root = ROOT
    if "--root" in args:
        at = args.index("--root")
        if at + 1 == len(args):
            print(__doc__, file=sys.stderr)
            return EX_USAGE
        root = Path(args[at + 1])
        del args[at:at + 2]
    if args == ["--page"]:
        written = root / PAGE
        # LF on every checkout, so the check reads the same text back.
        written.write_text(page(), encoding="utf-8", newline="\n")
        print(f"wrote {PAGE.as_posix()}")
        return 0
    if args == ["--check"]:
        found = problems(root)
        for problem in found:
            print(problem, file=sys.stderr)
        if found:
            print(f"{len(found)} problem(s); the twins are listed in "
                  f"{PAGE.as_posix()}", file=sys.stderr)
            return 1
        names = sum(len(twin.names) for twin in TWINS)
        print(f"the twins are current: {len(TWINS)} rules, {names} names, "
              f"{len(DIFFERENT)} same names that are not twins")
        return 0
    print(__doc__, file=sys.stderr)
    return EX_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
