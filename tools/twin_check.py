#!/usr/bin/env python3
"""Hold the rules written in more than one file to one text (ADR-0035).

loxodonta.py, supervisor.py and receiver.py never import each other, so
a rule two of them need is written in each: a twin. The list below is
every twin, the names it covers, the files it lives in and why it is
written twice, and every name the files share that is not a twin. The
recorder holds the original of every twin; a copy is its text again,
docstring included, under one comment line naming its original.

    python tools/twin_check.py --page    write docs/TWINS.md from the list
    python tools/twin_check.py --write   copy each original over its copies
    python tools/twin_check.py --check   exit 1 on drift, naming each problem
    ... --root DIR                       work on the files under DIR instead

`--check` fails on a copy whose top-level source differs from its
original, on a copy without its pointer line, on a name the list
declares that a file no longer defines, on a stale docs/TWINS.md, on a
top-level name defined in two of the files that the list does not
declare, and on an import that binds a name one of the files defines or
the list declares. The files are read as text, never imported. The
suite runs the check.

`--write` replaces each copy's top-level definition with its original's
text and adds a missing pointer, leaving every other byte of the file as
it was, line endings included. It never writes the original, and never
adds a copy a file lacks: it names it and exits 1, since that is the
list's problem, for a person. It also refuses, and leaves that file as
it was, any copy whose text in place would take other code with it: a
definition sharing its first line with other code, in the copy or the
original; two copies on one line; one statement binding other names
than its original's; an indent that differs from the original's.

The pointer is the line directly above a copy, below any comment there.
A run of adjacent copies with nothing else in its block (between blank
lines, comments aside) shares one, over its first; any other copy has
its own, so a statement without one is never a copy.

What counts as a top-level definition: a function or
class, from its first decorator; an assignment, an annotated one or an
augmented one, to a name or to an item or attribute of one; each found
at the top of the file or inside a top-level if, try, with, for, while
or match block. Its text is compared, never the condition or loop
around it, and a name bound as a loop variable, a `with ... as` or an
`except ... as`, or by `global` inside a function, is not seen.
"""

import ast
import io
import re
import sys
import tokenize
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
    Twin("The version line",
         ("checkout_commit", "version_line", "VersionAction"),
         ORIGINAL, BOTH,
         "Every file answers `--version` with the same line, tool, format "
         "and the commit it sits in, read by local git only and never "
         "fetched (ADR-0015, ADR-0022)."),
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
          "SIGNATURE_PRINCIPAL", "key_fingerprint", "bare_name",
          "WINDOWS_REFUSED_CHARACTERS", "WINDOWS_UNZIP_UNDERSCORES",
          "landing_name", "one_file_twice"),
         ORIGINAL, SUPERVISOR,
         "The supervisor writes a package and the recorder, and the "
         "verifier cut from it, judge one: the format it names, the size "
         "it may unpack to, the namespace and principal its issuer "
         "signature is made and checked under, the key fingerprint "
         "both print, the bare names its manifest may list, and which "
         "two names some system opens as one file (ADR-0026, #358)."),
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
)


# --- reading the files ----------------------------------------------------

# The blocks whose statements count as top level: a name defined under
# `if` or `try` at the top of a file is still the file's. ast.TryStar
# (3.11) and ast.Match (3.10) are looked up, since CI runs 3.9 too.
BLOCKS = tuple(getattr(ast, kind) for kind in
               ("If", "Try", "TryStar", "With", "AsyncWith", "For",
                "AsyncFor", "While", "Match") if hasattr(ast, kind))
DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def statements(body):
    """Each statement of `body`, and of every block it opens, never
    descending into a function or a class."""
    for node in body:
        yield node
        if isinstance(node, BLOCKS):
            inner = [getattr(node, field, []) for field in
                     ("body", "orelse", "finalbody")]
            inner += [part.body for part in getattr(node, "handlers", [])]
            inner += [case.body for case in getattr(node, "cases", [])]
            for block in inner:
                yield from statements(block)


def target_names(target):
    """The module names an assignment to `target` binds or changes:
    `A = ...` and `A, B = ...` bind them, `A[k] = ...` and `A.x = ...`
    change A."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for part in target.elts for name in target_names(part)]
    if isinstance(target, ast.Starred):
        return target_names(target.value)
    if isinstance(target, (ast.Subscript, ast.Attribute)):
        return target_names(target.value)
    return []


# A top-level definition: its first and last line (counted from 1), the
# UTF-8 byte its text ends at on the last line, its text, whether its
# first line holds nothing before it but its indent, and the names the
# statement binds or changes.
Definition = namedtuple("Definition", "first last end source alone names")


class Unreadable(Exception):
    """A file the tool cannot read as Python source; the message says
    which and why."""


def definition(lines, node, names):
    """`node`'s Definition: its text from the start of its first line
    (its first decorator's, for a decorated function or class) to its
    end, cut from lines split once, since ast.get_source_segment splits
    the whole file again on every call."""
    first = min([node.lineno] + [d.lineno for d in
                                 getattr(node, "decorator_list", [])])
    last = lines[node.end_lineno - 1].encode("utf-8")
    source = "\n".join(lines[first - 1:node.end_lineno - 1]
                       + [last[:node.end_col_offset].decode("utf-8")])
    # `X = 1; Y = 2` or `if c: Y = 2` puts code before Y on its line. A
    # decorator always opens its line, so only an undecorated node can.
    before = lines[first - 1].encode("utf-8")[:node.col_offset]
    alone = first != node.lineno or not before.strip()
    return Definition(first, node.end_lineno, node.end_col_offset, source,
                      alone, tuple(names))


def read_lines(path):
    """`path`'s text split into lines, as text mode reads it, and the
    line ending each line had on disk ("" after the last)."""
    if not path.is_file():
        raise Unreadable(f"{path.name} is missing")
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        raise Unreadable(f"{path.name} starts with a byte order mark, and "
                         "the scripts are plain UTF-8: take it off")
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Unreadable(f"{path.name} is not UTF-8 ({error.reason} at "
                         f"byte {error.start})")
    # Text mode ends a line at \r\n, \r or \n; split where it does.
    pieces = re.split(r"(\r\n|\r|\n)", raw)
    return pieces[0::2], pieces[1::2] + [""]


def top_level(lines, filename):
    """({name: [Definition]}, {name bound by an import}) for a file's
    `lines`: every top-level definition by the names it binds or
    changes, in file order, and the names its imports bind."""
    text = "\n".join(lines)
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as error:
        raise Unreadable(f"{filename} is not readable as Python "
                         f"({error.msg}, line {error.lineno})")
    found, imported = {}, set()
    for node in statements(tree.body):
        if isinstance(node, DEFS):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [n for target in node.targets for n in target_names(target)]
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            names = target_names(node.target)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # `import a.b` binds a; `as` binds the alias.
            imported.update(alias.asname or alias.name.split(".")[0]
                            for alias in node.names)
            continue
        else:
            continue
        found_here = definition(lines, node, names)
        for name in names:
            found.setdefault(name, []).append(found_here)
    return found, imported


def source(definitions):
    """The text compared for a name: each of its definitions in one
    file, one after the other."""
    return "\n".join(d.source for d in definitions)


# --- the pointer ----------------------------------------------------------

def pointer(twin):
    """The comment line above each copy, naming where to edit it."""
    return (f"# Copy of {twin.original}'s; edit there, then run "
            "tools/twin_check.py --write.")


def copies_in(file):
    """{name: twin} for every name `file` holds a copy of."""
    return {name: twin for twin in TWINS if file in twin.copies
            for name in twin.names}


def comment_lines(lines):
    """The numbers (from 1) of the lines holding only a comment. The
    tokenizer finds them, so a line of a string that starts with `#` is
    not one."""
    tokens = tokenize.generate_tokens(io.StringIO("\n".join(lines)).readline)
    return {token.start[0] for token in tokens
            if token.type == tokenize.COMMENT
            and not token.line[:token.start[1]].strip()}


def runs(defined, file):
    """The copies in `file` as [[(Definition, name)]], in file order,
    one list per run: copies of one original, each starting on the line
    after the one before it ends (or bound by the same statement)."""
    copies = copies_in(file)
    found = sorted((defined[name][0], name) for name in copies
                   if name in defined)
    grouped = []
    for here, name in found:
        if grouped:
            before, before_name = grouped[-1][-1]
            if ((before.last == here.first - 1 or before == here)
                    and copies[before_name].original
                    == copies[name].original):
                grouped[-1].append((here, name))
                continue
        grouped.append([(here, name)])
    return grouped


def alone_in_its_block(run, lines, comments):
    """Whether nothing but comment lines stands between `run` and the
    blank lines (or file edges) around it, so one pointer over its first
    copy can only be read as covering the run."""
    above = run[0][0].first - 1
    while above in comments:
        above -= 1
    below = run[-1][0].last + 1
    while below in comments:
        below += 1
    return all(n < 1 or n > len(lines) or not lines[n - 1].strip()
               for n in (above, below))


def unpointed(lines, defined, file):
    """[(twin, name, Definition)] for each copy in `file` whose line
    directly above is not its pointer. A run of copies alone in its
    block needs one pointer, over its first; any other copy its own."""
    copies = copies_in(file)
    comments = comment_lines(lines)
    missing = []
    for run in runs(defined, file):
        needing = (run[:1] if alone_in_its_block(run, lines, comments)
                   else run)
        seen = set()
        for found, name in needing:
            if found in seen:            # one statement binding two
                continue
            seen.add(found)
            above = lines[found.first - 2] if found.first > 1 else ""
            if above.strip() != pointer(copies[name]):
                missing.append((copies[name], name, found))
    return missing


# --- the page -------------------------------------------------------------

INTRO = """\
# Rules written twice

`loxodonta.py`, `supervisor.py` and `receiver.py` never import each other (ADR-0035): each is one file a reader can check alone, run from its own source. So a rule two of them need is written in each. This page lists every such rule, a twin: the names it covers, the files it lives in, and why it is written more than once.

The original of every twin is the recorder, `loxodonta.py`, and each copy carries one comment line directly above it that says so. A run of adjacent copies with nothing else in its block shares one line, over its first; any other copy has its own, so a statement without one is not a copy. To change a twin, edit the original in `loxodonta.py`, run `python tools/twin_check.py --write`, which copies it over each copy in place, then `python tools/twin_check.py --check`. When the original lies inside the verifier region, `--write` says so, and `python tools/build_verifier.py` carries it into `verifier.py`. `--write` never adds a copy a file lacks, and never rewrites a copy whose place holds other code (a second statement on its first line, say): it names each and exits 1, leaving that file as it was.

`python tools/twin_check.py --check` fails when a copy differs from its original, when a copy has no line naming its original, when a file no longer defines a name listed here, when this page is stale, when a top-level name is defined in two of the files without being listed here, and when an import binds a name one of the files defines. The suite runs it.

A top-level definition is a function or class, from its first decorator, or an assignment to a name (plain, annotated or augmented, or to an item or attribute of it), at the top of a file or inside a top-level `if`, `try`, `with`, `for`, `while` or `match` block. The check compares the definition's text, not the condition or loop around it, and does not see a name bound as a loop variable, by `with ... as` or `except ... as`, or by `global` inside a function.

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
    try:
        lines = {name: read_lines(root / name)[0] for name in FILES}
        read = {name: top_level(lines[name], name) for name in FILES}
    except Unreadable as error:
        return [str(error)]
    defined = {name: read[name][0] for name in FILES}
    imported = {name: read[name][1] for name in FILES}

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
                elif source(text) != source(original):
                    found.append(f"{twin.rule}: {name} in {copy} differs "
                                 f"from {twin.original}, its original: "
                                 f"run python tools/twin_check.py --write")
    for copy in FILES:
        for twin, name, _ in unpointed(lines[copy], defined[copy], copy):
            found.append(f"{twin.rule}: {name} in {copy} has no pointer "
                         f"to {twin.original} above it: run python "
                         "tools/twin_check.py --write")
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

    # Two files importing the same module is no twin; an import that
    # binds a name a file defines, or one the lists declare, shadows it.
    every_definition = set().union(*defined.values()) | set(declared)
    for file in FILES:
        for name in sorted(imported[file] & every_definition):
            holders = [f for f in FILES if name in defined[f]] or ["the lists"]
            found.append(f"{name} is bound by an import in {file}, and is "
                         f"defined in {' and '.join(holders)}")

    written = root / PAGE
    current = written.read_text(encoding="utf-8") if written.exists() else None
    if current != page():
        found.append(f"{PAGE.as_posix()} is stale: run python "
                     "tools/twin_check.py --page and commit the result")
    return found


# --- the copier -----------------------------------------------------------

def fence():
    """The two fence lines of tools/build_verifier.py, read from its
    source, never imported: an original between them is also copied
    into verifier.py, by that tool and not by this one."""
    tool = Path(__file__).resolve().parent / "build_verifier.py"
    values = {}
    for node in ast.parse(tool.read_text(encoding="utf-8")).body:
        if (isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)):
            values.update((target.id, node.value.value)
                          for target in node.targets
                          if isinstance(target, ast.Name))
    return values["OPEN"], values["CLOSE"]


def in_the_fence(lines, found, opening, closing):
    """Whether the Definition `found`, in the recorder's `lines`, lies
    between the fence lines `opening` and `closing`."""
    opens = [n for n, line in enumerate(lines, 1) if line.startswith(opening)]
    closes = [n for n, line in enumerate(lines, 1)
              if line.startswith(closing)]
    return any(o < found.first and found.last < c
               for o in opens for c in closes)


def indent(found):
    first = found.source.split("\n")[0]
    return first[:len(first) - len(first.lstrip())]


def ending(endings, at):
    """The line ending for new lines written at line `at`: the one that
    line has, else the file's first, else LF."""
    return endings[at - 1] or next((e for e in endings if e), "\n")


def replace(lines, endings, found, text):
    """Put `text` where the Definition `found` stands. Whatever followed
    it on its last line stays, as does that line's ending."""
    tail = lines[found.last - 1].encode("utf-8")[found.end:].decode("utf-8")
    new = text.split("\n")
    new[-1] += tail
    new_endings = ([ending(endings, found.first)] * (len(new) - 1)
                   + [endings[found.last - 1]])
    lines[found.first - 1:found.last] = new
    endings[found.first - 1:found.last] = new_endings


def add_pointer(lines, endings, twin, found):
    """Put `twin`'s pointer on the line directly above the Definition
    `found`, below any comment already there, at its indent."""
    lines.insert(found.first - 1, indent(found) + pointer(twin))
    endings.insert(found.first - 1, ending(endings, found.first))


def refusal(twin, name, copy, text, original):
    """Why --write will not copy `original` over `text`, the copy of
    `name` in `copy`, or None when it will. Each is a layout where text
    replaced in place would take other code with it."""
    if len(text) != 1 or len(original) != 1:
        return (f"{twin.rule}: {name} is defined {len(original)} time(s) "
                f"in {twin.original} and {len(text)} in {copy}, and "
                "--write copies one definition over one")
    text, original = text[0], original[0]
    for where, found in ((copy, text), (twin.original, original)):
        if not found.alone:
            return (f"{twin.rule}: {name} in {where} shares its first line "
                    "with other code, which --write would lose or copy: "
                    "give it a line of its own")
    if set(text.names) != set(original.names):
        return (f"{twin.rule}: {name} in {copy} is bound by a statement "
                f"binding {', '.join(text.names)}, and in {twin.original} "
                f"by one binding {', '.join(original.names)}")
    if indent(text) != indent(original):
        return (f"{twin.rule}: {name} is indented differently in {copy} "
                f"and in {twin.original}")
    return None


def plan(copy, here, defined):
    """({Definition in `copy`: the original's text}, [the names to
    write], [the refusals]) for one copy file."""
    edits, names, refused = {}, [], []
    for name, twin in copies_in(copy).items():
        original = defined[twin.original].get(name)
        text = here.get(name)
        if original is None:
            refused.append(f"{twin.rule}: {twin.original} no longer "
                           f"defines {name}, the original")
        elif text is None:
            refused.append(f"{twin.rule}: {copy} no longer defines {name}, "
                           "and --write never adds a copy: add it by hand, "
                           "or take it off the list")
        elif source(text) != source(original):
            why = refusal(twin, name, copy, text, original)
            if why:
                refused.append(why)
            else:
                edits[text[0]] = original[0].source
                names.append(name)
    ordered = sorted(edits, key=lambda found: found.first)
    for above, below in zip(ordered, ordered[1:]):
        if below.first <= above.last:
            refused.append(f"{copy}: two copies share line {below.first}, "
                           "and --write rewrites whole lines: give each a "
                           "line of its own")
    return edits, names, refused


def write_copies(root):
    """Copy each original's text over its copies under `root`, and add
    each missing pointer. A copy file with any refusal is left exactly
    as it was. Returns (what was done, the problems left, the names
    whose original lies inside the verifier region)."""
    done, found, fenced = [], [], []
    walls = fence()
    try:
        read = {name: read_lines(root / name) for name in FILES}
        defined = {name: top_level(read[name][0], name)[0] for name in FILES}
    except Unreadable as error:
        return [], [f"{error}; --write wrote nothing"], []
    for copy in FILES:
        if not copies_in(copy):
            continue
        lines, endings = list(read[copy][0]), list(read[copy][1])
        edits, names, refused = plan(copy, defined[copy], defined)
        # From the bottom up, so each edit leaves the lines above in place.
        for at in sorted(edits, key=lambda d: d.first, reverse=True):
            replace(lines, endings, at, edits[at])
        if not refused:
            try:
                here = top_level(lines, copy)[0]
            except Unreadable as error:
                refused.append(f"{error} after --write")
        if refused:
            found += refused + [f"{copy} is left as it was"]
            continue
        missing = unpointed(lines, here, copy)
        for twin, name, at in reversed(missing):
            add_pointer(lines, endings, twin, at)
        done += [f"wrote {name} in {copy}" for name in names]
        done += [f"added the pointer above {name} in {copy}"
                 for _, name, _ in missing]
        for name in names:
            twin = copies_in(copy)[name]
            if twin.original == ORIGINAL and in_the_fence(
                    read[ORIGINAL][0], defined[ORIGINAL][name][0], *walls):
                fenced.append(name)
        written = "".join(line + end for line, end in zip(lines, endings))
        path = root / copy
        if written.encode("utf-8") != path.read_bytes():
            path.write_bytes(written.encode("utf-8"))
    return done, found, fenced


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
        # Bytes, since write_text takes no newline before Python 3.10.
        written.write_bytes(page().encode("utf-8"))
        print(f"wrote {PAGE.as_posix()}")
        return 0
    if args == ["--write"]:
        done, found, fenced = write_copies(root)
        for line in done:
            print(line)
        if fenced:
            print(f"{', '.join(sorted(set(fenced)))}: the original lies "
                  "inside the verifier region, so run python "
                  "tools/build_verifier.py too")
        for problem in found:
            print(problem, file=sys.stderr)
        if found:
            print(f"{len(found)} problem(s) --write leaves for a person",
                  file=sys.stderr)
            return 1
        if not done:
            print("every copy already holds its original's text and "
                  "its pointer")
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
