#!/usr/bin/env python3
"""A second verifier for the loxodonta receipt chain, written from SPEC.md alone.

It covers the chain format, SPEC sections 1 to 6: the `verify` and `head`
commands. The sidecars (SPEC 9) and the package (SPEC 10) are not here.

Usage:
    python -I verify.py verify --log FILE [--files] [--expect-head HEX] [--transcript FILE]
    python -I verify.py head --log FILE

The file reads top to bottom in the order the spec's verification runs.
Every rule names the SPEC section it comes from. Where the spec was silent or
could be read two ways, the comment says "choice" and GAPS.md gives the reason.
"""

import hashlib
import json
import os
import re
import stat
import sys
import traceback

# SPEC 2.1: the one format version this verifier speaks.
THIS_VERSION = "0.1"

# SPEC 1: the default name of a receipt log.
DEFAULT_LOG = "receipts.jsonl"

# SPEC 6 "Verdicts", and SPEC 2.1 for exit 4. Exit 1 is BROKEN and nothing else.
EXIT_VALID = 0
EXIT_BROKEN = 1
EXIT_FILES_DIVERGED = 2
EXIT_HEAD_MISMATCH = 3
EXIT_UNSUPPORTED_VERSION = 4
EXIT_TRANSCRIPT_DIVERGED = 5
# SPEC 6: when no verdict can be reached, a sysexits(3) code, never a verdict's.
EX_USAGE = 64
EX_NOINPUT = 66
EX_SOFTWARE = 70
# SPEC 6: a reader that closes the output early ends it with 141, never 0.
EXIT_OUTPUT_CLOSED = 141


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

def say(line):
    """Print one line of the report on stdout."""
    sys.stdout.write(line + "\n")


def shown(text):
    """Write text from the log with every character that could steer a
    terminal written as its escape (the courtesy SPEC 9.2 asks for kinds)."""
    out = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or 0x7F <= code <= 0x9F or 0xD800 <= code <= 0xDFFF:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    return "".join(out)


class NoInput(Exception):
    """SPEC 6: the log is missing, empty, or cannot be read as a file (exit 66)."""


class UsageError(Exception):
    """SPEC 6: the verifier was invoked wrong (exit 64)."""


# ---------------------------------------------------------------------------
# SPEC 6 (and 9.1): opening a name the writer controls
# ---------------------------------------------------------------------------

def read_regular_file(path):
    """SPEC 6: open the name without waiting, and ask what was opened before
    reading a byte. A folder, a pipe or a device cannot be read as a file.

    Returns the file's bytes, or raises NoInput with the reason."""
    try:
        before = os.stat(path)  # follows links, as SPEC 3 says links are followed
    except FileNotFoundError:
        raise NoInput("%s: no such file" % path)
    except OSError as error:
        raise NoInput("%s: %s" % (path, error.strerror or error))
    if stat.S_ISDIR(before.st_mode):
        raise NoInput("%s: it is a folder, not a file" % path)
    if not stat.S_ISREG(before.st_mode):
        raise NoInput("%s: it is not a regular file" % path)

    # O_NONBLOCK: an ordinary open of a pipe waits for the other end (SPEC 9.1).
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise NoInput("%s: %s" % (path, error.strerror or error))
    try:
        # Ask again what was opened: the name may have changed since the stat.
        opened = os.fstat(fd)
        if stat.S_ISDIR(opened.st_mode):
            raise NoInput("%s: it is a folder, not a file" % path)
        if not stat.S_ISREG(opened.st_mode):
            raise NoInput("%s: it is not a regular file" % path)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as error:
        raise NoInput("%s: %s" % (path, error.strerror or error))
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# SPEC 1: the receipt log is lines
# ---------------------------------------------------------------------------

def split_lines(data):
    """SPEC 1: a line is the bytes before each \\n, and nothing else ends one.
    A \\r just before the \\n is part of the line ending. The bytes after the
    final \\n, when there are any, are a line too (the torn tail of SPEC 6)."""
    pieces = data.split(b"\n")
    last = pieces.pop()  # the bytes after the final \n; empty when the file ends in \n
    lines = []
    for piece in pieces:
        if piece.endswith(b"\r"):  # SPEC 1: \r\n reads as the same line ending
            piece = piece[:-1]
        lines.append(piece)
    if last:
        lines.append(last)  # SPEC 1: a final piece with no \n is still a line
    return lines


# ---------------------------------------------------------------------------
# SPEC 6 step 1: the line parses as one JSON object, each key given once
# ---------------------------------------------------------------------------

class NotJson(Exception):
    """The line fails to parse as JSON at all. On the final line this is the
    torn tail of SPEC 6; anywhere else it is an ordinary break."""


class DuplicateKey(Exception):
    """SPEC 6 step 1: a key given twice, at any depth."""

    def __init__(self, key):
        Exception.__init__(self, key)
        self.key = key


def _each_key_once(pairs):
    # SPEC 6 step 1: one parser keeps the first of two keys and another the
    # last, so a line that gives a key twice has no single reading.
    seen = set()
    for key, _value in pairs:
        if key in seen:
            raise DuplicateKey(key)
        seen.add(key)
    return dict(pairs)


def _refuse_constant(name):
    # NaN, Infinity and -Infinity are not JSON (SPEC 9.1 names them; a strict
    # parser refuses them, and Python's reader would otherwise take them).
    raise ValueError("%s is not JSON" % name)


def parse_line(raw):
    """SPEC 6 step 1 (and SPEC 1: the file is UTF-8): parse one line.
    Raises NotJson or DuplicateKey."""
    try:
        text = raw.decode("utf-8")  # strict: a byte that is not UTF-8 is refused
    except UnicodeDecodeError:
        raise NotJson("holds a byte that is not UTF-8")
    try:
        return json.loads(text, object_pairs_hook=_each_key_once,
                          parse_constant=_refuse_constant)
    except DuplicateKey:
        raise
    except RecursionError:
        raise NotJson("nests deeper than this reader can take apart")
    except ValueError:  # JSONDecodeError, NaN, an integer past Python's digit limit
        raise NotJson("is not JSON")


def json_type(value):
    """The JSON type of a parsed value, for naming a wrong field by its type."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int):
        return "an integer"
    if isinstance(value, float):
        return "a number with a fraction"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


# ---------------------------------------------------------------------------
# SPEC 4: canonical form and entry_hash
# ---------------------------------------------------------------------------

class NoCanonicalForm(Exception):
    """SPEC 4: the entry has no canonical form, so it is refused, not hashed."""


# SPEC 4 rule 3: the short escapes RFC 8785 uses. Everything else from U+0000
# to U+001F is \u with four lowercase hex digits; every other character stands.
SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def canonical_string(text):
    """SPEC 4 rule 3: a string, escaped exactly as RFC 8785 3.2.2.2 escapes it."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch in SHORT_ESCAPES:
            out.append(SHORT_ESCAPES[ch])
        elif code < 0x20:
            out.append("\\u%04x" % code)  # SPEC 4 rule 3: hex is never uppercase
        elif 0xD800 <= code <= 0xDFFF:
            # SPEC 4 rule 3: a lone surrogate has no UTF-8 form.
            raise NoCanonicalForm("a string holds a lone surrogate (U+%04X)" % code)
        else:
            out.append(ch)  # SPEC 4 rule 3: /, DEL, C1, U+2028, U+2029, non-ASCII as they stand
    out.append('"')
    return "".join(out)


def canonical_json(value):
    """SPEC 4 rules 1, 2, 4 and 5: the canonical JSON text of a value."""
    if value is None:
        return "null"  # SPEC 4 rule 5
    if isinstance(value, bool):
        # SPEC 4 rule 5: booleans do not occur in v0.1, and the 0.1 field rules
        # refuse them first. Choice (GAPS.md): a later version's boolean is
        # written as JSON writes it.
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)  # SPEC 4 rule 4: integers only
    if isinstance(value, float):
        # SPEC 4 rule 4: no floats anywhere. Choice (GAPS.md): a number with a
        # fraction or an exponent has no canonical form.
        raise NoCanonicalForm("it holds a number that is not an integer")
    if isinstance(value, str):
        return canonical_string(value)
    if isinstance(value, list):
        # SPEC 4 rule 2: compact separators. Choice (GAPS.md): array order is
        # kept as stored; SPEC 4's six rules sort keys, never arrays.
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    # SPEC 4 rule 1: keys sorted by byte order at every level. For text that
    # has a UTF-8 form, code point order is UTF-8 byte order.
    parts = []
    for key in sorted(value):
        parts.append(canonical_string(key) + ":" + canonical_json(value[key]))
    return "{" + ",".join(parts) + "}"


def compute_entry_hash(entry):
    """SPEC 4: entry_hash = SHA256(canonical_json(entry minus entry_hash)),
    lowercase hex. SPEC 4 rule 6: the bytes are UTF-8, no trailing newline."""
    without_hash = {key: value for key, value in entry.items() if key != "entry_hash"}
    text = canonical_json(without_hash)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SPEC 3: the spelling rule for a file reference's path
# ---------------------------------------------------------------------------

def path_leaves_base(path):
    """SPEC 3: a path is refused when it begins with / or \\, when its second
    character is :, or when a segment is .. with either slash as separator.
    Returns why, or None for a path that passes."""
    if path.startswith("/") or path.startswith("\\"):
        return "an absolute path"
    if len(path) >= 2 and path[1] == ":":
        return "a drive"
    if ".." in re.split(r"[/\\]", path):
        return "a '..' segment"
    return None


# ---------------------------------------------------------------------------
# SPEC 2 and SPEC 6 step 1: the fields of an entry and their types
# ---------------------------------------------------------------------------

# SPEC 2: every entry has exactly these fields; genesis also carries v (SPEC 2.1).
FIELDS = ("n", "ts", "actor", "action", "files", "prev", "entry_hash")


def schema_problem(obj, is_genesis):
    """SPEC 6 step 1: exactly the schema fields, each of its SPEC 2 type, and
    each reference's path passes SPEC 3's spelling rule. Type only: whether a
    string is hex or a timestamp well-formed is not judged here.
    Returns the reason the line is refused, or None."""
    if not isinstance(obj, dict):
        return "line is %s, not a JSON object" % json_type(obj)

    expected = FIELDS + (("v",) if is_genesis else ())
    for key in expected:
        if key not in obj:
            return "key '%s' is missing" % key
    for key in sorted(obj):
        if key not in expected:
            if key == "v":
                return "key 'v' is on an entry that is not genesis"  # SPEC 2.1: only genesis
            return "key '%s' is not a field of format %s" % (shown(key), THIS_VERSION)

    # SPEC 6 step 1: n an integer, never a boolean or a float.
    if isinstance(obj["n"], bool) or not isinstance(obj["n"], int):
        return "n is %s, not an integer" % json_type(obj["n"])
    # SPEC 6 step 1: ts, actor and action non-empty strings.
    for key in ("ts", "actor", "action"):
        if not isinstance(obj[key], str):
            return "%s is %s, not a string" % (key, json_type(obj[key]))
        if obj[key] == "":
            return "%s is an empty string" % key
    # SPEC 6 step 1: files an array of {path, sha256} objects, string values, no other keys.
    files = obj["files"]
    if not isinstance(files, list):
        return "files is not an array"
    for ref in files:
        if not isinstance(ref, dict):
            return "files holds %s, not a {path, sha256} object" % json_type(ref)
        for key in ("path", "sha256"):
            if key not in ref:
                return "files holds a reference with no %s" % key
        for key in sorted(ref):
            if key not in ("path", "sha256"):
                return "files holds a reference with the key '%s'" % shown(key)
        for key in ("path", "sha256"):
            if not isinstance(ref[key], str):
                return "files holds a reference whose %s is %s, not a string" % (key, json_type(ref[key]))
        # SPEC 3 and SPEC 6 step 1: the path's spelling.
        why = path_leaves_base(ref["path"])
        if why:
            return "files names a path that leaves the project (%s): %s" % (why, shown(ref["path"]))
    # SPEC 6 step 1: prev a string or null; entry_hash a string.
    if obj["prev"] is not None and not isinstance(obj["prev"], str):
        return "prev is %s, not a string or null" % json_type(obj["prev"])
    if not isinstance(obj["entry_hash"], str):
        return "entry_hash is %s, not a string" % json_type(obj["entry_hash"])
    # SPEC 2.1: v is a string.
    if is_genesis and not isinstance(obj["v"], str):
        return "v is %s, not a string" % json_type(obj["v"])
    return None


# ---------------------------------------------------------------------------
# SPEC 2.1: read the genesis entry's v before anything else
# ---------------------------------------------------------------------------

def read_version(lines):
    """SPEC 2.1 and SPEC 6: the format version the genesis entry claims.
    Returns the version string, or None when genesis cannot be read for one;
    choice (GAPS.md): such a chain is judged under this verifier's own rules,
    which then refuse its genesis by name."""
    if not lines:
        return None
    try:
        genesis = parse_line(lines[0])
    except (NotJson, DuplicateKey):
        return None
    if isinstance(genesis, dict) and isinstance(genesis.get("v"), str):
        return genesis["v"]
    return None


# ---------------------------------------------------------------------------
# SPEC 2.2: the transcript commitment
# ---------------------------------------------------------------------------

# SPEC 2.2: one space between fields, no trailing content. Choice (GAPS.md):
# a decimal count is written without leading zeros.
COMMITMENT_GRAMMAR = re.compile(r"transcript-commitment: bytes=(0|[1-9][0-9]*) sha256=([0-9a-f]{64})")
COMMITMENT_NAME = "transcript-commitment:"


def read_commitment(entry):
    """SPEC 2.2: a bookkeeping entry (actor "receipts") whose action follows
    the commitment grammar. Returns (bytes, sha256), "malformed" for a line
    that names the grammar and fails it, or None for an ordinary entry."""
    if entry["actor"] != "receipts" or not entry["action"].startswith(COMMITMENT_NAME):
        return None
    match = COMMITMENT_GRAMMAR.fullmatch(entry["action"])
    if match is None or entry["files"] != []:  # SPEC 2.2: files is []
        return "malformed"
    return int(match.group(1)), match.group(2)


# ---------------------------------------------------------------------------
# SPEC 6: the walk
# ---------------------------------------------------------------------------

class Walk:
    """What one walk of the chain found."""

    def __init__(self):
        self.breaks = []        # SPEC 6: every break, the first one is the verdict
        self.warnings = []      # SPEC 6 step 5: testimony gets reporting
        self.entries = []       # (line number, entry) for every line that is an entry
        self.commitments = []   # SPEC 2.2: (line number, bytes, sha256)


def torn_tail_message(index):
    # SPEC 6 "Torn tail": the distinct report for a final line that is not JSON.
    if index == 0:
        intact = "no entry intact"
    elif index == 1:
        intact = "entry 0 intact"
    else:
        intact = "entries 0–%d intact" % (index - 1)
    return "BROKEN: torn tail at line %d (crash-truncated append; %s)" % (index, intact)


def parse_or_break(walk, lines, index):
    """SPEC 6 step 1, the parse half, shared by both walks. Returns the parsed
    value, or None after recording the break."""
    try:
        return parse_line(lines[index])
    except NotJson as error:
        if index == len(lines) - 1:
            walk.breaks.append(torn_tail_message(index))  # SPEC 6 "Torn tail"
        else:
            # SPEC 6 "Torn tail": garbage mid-file is ordinary BROKEN.
            walk.breaks.append("BROKEN at entry %d: line %s" % (index, error))
    except DuplicateKey as error:
        walk.breaks.append("BROKEN at entry %d: key '%s' given twice" % (index, shown(error.key)))
    return None


def walk_own_version(lines):
    """SPEC 6 steps 1 to 5, for a chain of format 0.1."""
    walk = Walk()
    previous = None  # the previous entry, or None when the line before was not one
    for index in range(len(lines)):
        entry = parse_or_break(walk, lines, index)
        if entry is None:
            previous = None
            continue

        # Step 1: exactly the schema fields, each of its type. A line that
        # fails is refused by name and is not an entry: nothing downstream reads it.
        problem = schema_problem(entry, is_genesis=(index == 0))
        if problem:
            walk.breaks.append("BROKEN at entry %d: %s" % (index, problem))
            previous = None
            continue

        # Step 2: n equals the line number (0-based). Catches deletion and reordering.
        if entry["n"] != index:
            walk.breaks.append("BROKEN at entry %d: n is %d, expected %d (an entry deleted or moved?)"
                               % (index, entry["n"], index))

        # Step 3: the recomputed canonical hash equals the stored entry_hash. Catches edits.
        try:
            recomputed = compute_entry_hash(entry)
        except NoCanonicalForm as error:
            # SPEC 4 rule 3: refused, not hashed. Choice (GAPS.md): not an entry.
            walk.breaks.append("BROKEN at entry %d: the entry has no canonical form: %s" % (index, error))
            previous = None
            continue
        if recomputed != entry["entry_hash"]:
            walk.breaks.append("BROKEN at entry %d: entry_hash does not match the entry's canonical form "
                               "(the entry was edited?)" % index)

        # Step 4: prev equals the previous entry's entry_hash; genesis: prev is null.
        if index == 0:
            if entry["prev"] is not None:
                walk.breaks.append("BROKEN at entry 0: genesis prev is not null")
        elif previous is not None and entry["prev"] != previous["entry_hash"]:
            walk.breaks.append("BROKEN at entry %d: prev does not match entry %d's entry_hash "
                               "(an entry spliced in or out?)" % (index, index - 1))
        # Choice (GAPS.md): after a line that is not an entry, the link is not judged.

        # Step 5: ts non-decreasing, a warning and never a verdict.
        # Choice (GAPS.md): timestamps compared as strings, character by character.
        if previous is not None and entry["ts"] < previous["ts"]:
            walk.warnings.append("WARN: ts decreases at entry %d — clock skew at write time?" % index)

        # SPEC 2.2: note each transcript commitment for the checks after the walk.
        commitment = read_commitment(entry)
        if commitment == "malformed":
            # SPEC 6: warned about and judged as nothing.
            walk.warnings.append("WARN: entry %d names the transcript-commitment grammar and fails it; "
                                 "judged as nothing" % index)
        elif commitment is not None:
            walk.commitments.append((index, commitment[0], commitment[1]))

        walk.entries.append((index, entry))
        previous = entry
    return walk


def walk_hashes_only(lines):
    """SPEC 2.1: for a version this verifier does not speak, walk the hash
    chain alone (SPEC 4 and SPEC 5 are the same in every version): each line
    one JSON object with each key given once, its entry_hash the hash of its
    canonical form, its prev the entry_hash before it."""
    walk = Walk()
    previous_hash = None  # None when the line before has no entry_hash to link to
    for index in range(len(lines)):
        entry = parse_or_break(walk, lines, index)
        if entry is None:
            previous_hash = None
            continue
        if not isinstance(entry, dict):
            walk.breaks.append("BROKEN at entry %d: line is %s, not a JSON object" % (index, json_type(entry)))
            previous_hash = None
            continue
        stored = entry.get("entry_hash")
        if not isinstance(stored, str):
            walk.breaks.append("BROKEN at entry %d: the line has no entry_hash string" % index)
            previous_hash = None
            continue
        # SPEC 4: frozen across versions.
        try:
            recomputed = compute_entry_hash(entry)
        except NoCanonicalForm as error:
            walk.breaks.append("BROKEN at entry %d: the entry has no canonical form: %s" % (index, error))
            previous_hash = None
            continue
        if recomputed != stored:
            walk.breaks.append("BROKEN at entry %d: entry_hash does not match the entry's canonical form "
                               "(the entry was edited?)" % index)
        # SPEC 5: for every entry after genesis, prev is the entry_hash before it.
        # Choice (GAPS.md): genesis's own prev is a field rule, not judged here.
        if index > 0 and previous_hash is not None and entry.get("prev") != previous_hash:
            walk.breaks.append("BROKEN at entry %d: prev does not match entry %d's entry_hash "
                               "(an entry spliced in or out?)" % (index, index - 1))
        walk.entries.append((index, entry))
        previous_hash = stored
    return walk


# ---------------------------------------------------------------------------
# SPEC 5 and SPEC 10.3: the chain head
# ---------------------------------------------------------------------------

def chain_head(lines):
    """SPEC 5: the chain head is the entry_hash of the last entry, the final
    line, read as SPEC 2.1 reads a line under any version: one JSON object,
    each key once. A final line that cannot be read so, a torn tail among
    them, leaves the chain with no head (vector tail-torn-head; GAPS.md G1).
    Returns the head, or None."""
    if not lines:
        return None
    try:
        last = parse_line(lines[-1])
    except (NotJson, DuplicateKey):
        return None
    if isinstance(last, dict) and isinstance(last.get("entry_hash"), str):
        return last["entry_hash"]
    return None


# ---------------------------------------------------------------------------
# SPEC 6 step 6 (--files) and SPEC 3: the working tree against the chain
# ---------------------------------------------------------------------------

def reference_base(log_path):
    """SPEC 3: the reference base. For a chain beside a project record
    (project.json) it is the recorded project path; for any other chain, the
    log's own directory. Returns (base, None) or (None, why it cannot be followed)."""
    log_dir = os.path.dirname(os.path.abspath(log_path))
    record = os.path.join(log_dir, "project.json")
    if os.path.lexists(record):
        # Choice (GAPS.md): SPEC 3 does not say which member of project.json
        # holds the project path, so this verifier cannot follow any record.
        return None, ("%s cannot be read as a project record: the spec does not say which "
                      "member names the project" % record)
    return log_dir, None


def check_files(walk, log_path):
    """SPEC 6 step 6: every referenced path that still exists is hashed, and
    the latest reference per path is CURRENT or MODIFIED-SINCE-LOGGED.
    Prints one line per path; returns True when any file diverged."""
    latest = {}    # path -> (line number, sha256) of its latest reference
    recorded = {}  # path -> every sha256 the chain recorded for it
    for index, entry in walk.entries:
        for ref in entry["files"]:
            latest[ref["path"]] = (index, ref["sha256"])
            recorded.setdefault(ref["path"], set()).add(ref["sha256"])

    base, why = reference_base(log_path)
    if why:
        # SPEC 3: unresolvable is a different sentence from "file diverged".
        for path in sorted(latest, key=lambda p: p.encode("utf-8", "surrogatepass")):
            say("UNRESOLVABLE: %s (%s)" % (shown(path), why))
        return False

    diverged = False
    # SPEC 3: paths compare byte-exact, no case folding; listed in byte order.
    for path in sorted(latest, key=lambda p: p.encode("utf-8", "surrogatepass")):
        index, logged = latest[path]
        try:
            data = read_regular_file(os.path.join(base, path))
        except NoInput:
            # SPEC 3: a path that is not a readable regular file is reported and
            # the walk goes on to its verdict. Choice (GAPS.md): a note, not a divergence.
            say("MISSING (not a readable file here): %s" % shown(path))
            continue
        now = hashlib.sha256(data).hexdigest()
        if now == logged:
            say("CURRENT: %s (as logged at entry %d)" % (shown(path), index))
        else:
            # Choice (GAPS.md): divergence is judged on the latest reference.
            older = " (matches an earlier entry's record)" if now in recorded[path] else ""
            say("MODIFIED-SINCE-LOGGED: %s (latest logged at entry %d)%s" % (shown(path), index, older))
            diverged = True
    return diverged


# ---------------------------------------------------------------------------
# SPEC 2.2 and SPEC 6 "Transcript commitments"
# ---------------------------------------------------------------------------

def commitments_shrink(walk):
    """SPEC 2.2 and SPEC 6: every walk judges, from the chain alone, that the
    committed byte counts never decrease. Prints a line for each decrease and
    returns True when there is one."""
    found = False
    for (before_index, before_bytes, _), (index, count, _) in zip(walk.commitments, walk.commitments[1:]):
        if count < before_bytes:
            say("TRANSCRIPT-DIVERGED: the commitment at entry %d covers %d bytes, fewer than the %d "
                "bytes entry %d covered (a growing file never shrinks)"
                % (index, count, before_bytes, before_index))
            found = True
    return found


def check_transcript(walk, transcript_path):
    """SPEC 6, under --transcript: re-hash each committed prefix, oldest
    boundary first, report each commitment as holding or diverged, then state
    the tail the chain never vouched for. Returns True when one diverged."""
    if not os.path.lexists(transcript_path):
        # SPEC 6: a missing transcript is a note, never a verdict.
        say("note: transcript %s is not there; its commitments are not checked" % shown(transcript_path))
        return False
    try:
        data = read_regular_file(transcript_path)
    except NoInput as error:
        # SPEC 6: read like a missing transcript, and say why.
        reason = str(error).split(": ", 1)[-1]
        say("TRANSCRIPT-UNRESOLVED: %s cannot be read as a transcript: %s" % (shown(transcript_path), reason))
        return False

    diverged = False
    for index, count, digest in walk.commitments:
        if len(data) < count:
            say("transcript commitment at entry %d: DIVERGED (it covers %d bytes; the transcript holds %d)"
                % (index, count, len(data)))
            diverged = True
        elif hashlib.sha256(data[:count]).hexdigest() == digest:
            say("transcript commitment at entry %d: holds (first %d bytes)" % (index, count))
        else:
            say("transcript commitment at entry %d: DIVERGED (the first %d bytes hash otherwise)" % (index, count))
            diverged = True
    furthest = max([count for _, count, _ in walk.commitments] or [0])
    tail = max(len(data) - furthest, 0)
    say("transcript tail: %d bytes after the furthest commitment, which the chain never vouched for" % tail)
    return diverged


# ---------------------------------------------------------------------------
# SPEC 6: the verify command, its verdict and exit
# ---------------------------------------------------------------------------

def command_verify(log_path, files=False, expect_head=None, transcript=None):
    """SPEC 6: walk the log and give the verdict. The verdict is the last line."""
    data = read_regular_file(log_path)
    if not data:
        raise NoInput("%s: the log is empty" % log_path)  # SPEC 6: empty is no input
    lines = split_lines(data)

    # SPEC 2.1 and SPEC 6: read the genesis entry's v before anything else.
    version = read_version(lines)
    own_version = version is None or version == THIS_VERSION

    walk = walk_own_version(lines) if own_version else walk_hashes_only(lines)

    # SPEC 6: the first break is the verdict; the walk lists every break.
    for line in walk.breaks[1:]:
        say(line)
    for line in walk.warnings:
        say(line)

    files_diverged = False
    transcript_diverged = False
    if own_version:
        # SPEC 2.1: field rules (and the vocabulary built on them) are the
        # version's own, so these run only for format 0.1.
        if files:
            files_diverged = check_files(walk, log_path)
        transcript_diverged = commitments_shrink(walk)
        if transcript is not None:
            transcript_diverged = check_transcript(walk, transcript) or transcript_diverged

    # SPEC 6 step 7: after the walk, compare the chain head, under any version (SPEC 2.1).
    head = chain_head(lines)
    head_mismatch = False
    if expect_head is not None and head != expect_head:
        head_mismatch = True
        head_line = "HEAD-MISMATCH: the chain head is %s, the recorded head is %s" % (
            head or "absent (no line holds an entry_hash)", shown(expect_head))

    # SPEC 6 precedence: the gravest sets the exit, 1 > 3 > 5 > 2; everything found is reported.
    if walk.breaks:
        if head_mismatch:
            say(head_line)
        say(walk.breaks[0])
        return EXIT_BROKEN
    if head_mismatch:
        if transcript_diverged:
            say("TRANSCRIPT-DIVERGED: see above")
        if files_diverged:
            say("FILES-DIVERGED: see above")
        say(head_line)
        return EXIT_HEAD_MISMATCH
    if not own_version:
        # SPEC 2.1: only when every hash and link holds.
        say('UNSUPPORTED-VERSION: log is format "%s"; this verifier speaks "%s"'
            % (shown(version), THIS_VERSION))
        return EXIT_UNSUPPORTED_VERSION
    if transcript_diverged:
        if files_diverged:
            say("FILES-DIVERGED: see above")
        say("TRANSCRIPT-DIVERGED: a transcript commitment does not hold")
        return EXIT_TRANSCRIPT_DIVERGED
    if files_diverged:
        say("FILES-DIVERGED: a referenced file changed since it was logged; the chain itself is intact")
        return EXIT_FILES_DIVERGED
    say("VALID: %d entries, head %s" % (len(lines), head))
    return EXIT_VALID


# ---------------------------------------------------------------------------
# SPEC 6: the head command
# ---------------------------------------------------------------------------

def command_head(log_path):
    """SPEC 6: `head` prints the current chain head, so the operator can keep
    it where the writer cannot reach. It prints the head without judging the
    rest of the chain; verify is the judge (GAPS.md P2)."""
    data = read_regular_file(log_path)
    if not data:
        raise NoInput("%s: the log is empty" % log_path)
    head = chain_head(split_lines(data))
    if head is None:
        # A torn tail has no head: nothing on stdout, the reason on stderr,
        # exit 1 since it is BROKEN (vector tail-torn-head; GAPS.md G1).
        sys.stderr.write("BROKEN: the final line holds no entry_hash (a torn tail?), "
                         "so the chain has no head\n")
        return EXIT_BROKEN
    say(head)
    return EXIT_VALID


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------

# Flags of the sidecars (SPEC 9), outside this verifier's slice.
OUT_OF_SLICE = ("--anchors", "--stamps", "--block-header", "--authority-chain")


def parse_arguments(argv):
    """The verbs and flags SPEC 6 names. `--log` comes from vectors/README.md.
    Flags may come before or after the verb, as `--flag VALUE` or `--flag=VALUE`."""
    verb = None
    options = {"log": DEFAULT_LOG, "files": False, "expect_head": None, "transcript": None}
    takes_value = {"--log": "log", "--expect-head": "expect_head", "--transcript": "transcript"}
    i = 0
    while i < len(argv):
        arg = argv[i]
        name, _, inline = arg.partition("=")
        if name in takes_value:
            if inline or "=" in arg:
                value = inline
            else:
                i += 1
                if i >= len(argv):
                    raise UsageError("%s needs a value" % name)
                value = argv[i]
            options[takes_value[name]] = value
        elif arg == "--files":
            options["files"] = True
        elif name in OUT_OF_SLICE:
            raise UsageError("%s is a sidecar flag (SPEC 9); this verifier covers the chain only" % name)
        elif arg.startswith("-"):
            raise UsageError("unknown option %s" % arg)
        elif verb is None and arg in ("verify", "head"):
            verb = arg
        else:
            raise UsageError("unexpected argument %s" % arg)
        i += 1
    if verb is None:
        raise UsageError("give a verb: verify or head")
    if verb == "head" and (options["files"] or options["expect_head"] is not None
                           or options["transcript"] is not None):
        raise UsageError("head takes only --log")
    return verb, options


def main(argv):
    try:
        verb, options = parse_arguments(argv)
    except UsageError as error:
        sys.stderr.write("usage error: %s\n%s" % (error, __doc__.split("Usage:")[1].split("\n\n")[0] + "\n"))
        return EX_USAGE
    try:
        if verb == "head":
            return command_head(options["log"])
        return command_verify(options["log"], options["files"], options["expect_head"], options["transcript"])
    except NoInput as error:
        # SPEC 6: the reason on stderr and nothing on stdout.
        sys.stderr.write("no input: %s\n" % error)
        return EX_NOINPUT


if __name__ == "__main__":
    # Lines end in \n alone, and text from the log prints as UTF-8 on any console.
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace", newline="\n")
    try:
        code = main(sys.argv[1:])
        sys.stdout.flush()
    except BrokenPipeError:
        # SPEC 6: a reader that closed the output early gets 141, never 0.
        code = EXIT_OUTPUT_CLOSED
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
    except Exception:  # SPEC 6: the verifier itself failed
        traceback.print_exc()
        code = EX_SOFTWARE
    sys.exit(code)
