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

import argparse
import base64
import errno
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import traceback
import unicodedata
from datetime import datetime, timezone

# Two versions, moving independently (ADR-0022): TOOL_VERSION says which
# recorder is running; FORMAT_VERSION says which chains it can read. The
# format is frozen (SPEC §2.1); the tool is tagged at every promotion,
# together with supervisor.py — the two constants must agree.
TOOL_VERSION = "0.9.0"
FORMAT_VERSION = "0.1"
DEFAULT_LOG = "receipts.jsonl"

ENTRY_FIELDS = {"n", "ts", "actor", "action", "files", "prev", "entry_hash"}
GENESIS_FIELDS = ENTRY_FIELDS | {"v"}


# === The verifier (ADR-0035) ==================================================
#
# The verify side, in reading order: the format, reading a chain, the
# walk, the judges and the verdicts, then the command line that speaks
# them. Nothing in it appends to a chain, sends, stamps or installs. In
# loxodonta.py a closing line ends it, and nothing in it calls a
# definition past that line; tools/build_verifier.py copies it, with the
# imports and constants above it, into verifier.py, the file a recipient
# runs (ADR-0035).


# --- What an exit code says (ADR-0037) ----------------------------------------
#
# Exit 1 is BROKEN and nothing else: the chain does not walk clean, or a
# writer found its tail damaged and will not build on it. The verdicts
# hold 0 to 5 (SPEC §6), and every failure that is not a verdict takes
# its number from sysexits(3), so a script that reads the code is never
# told a chain is broken when the log was only missing or the tool fell
# over. The numbers only the writers give sit beside them, below the
# verifier.
EX_USAGE = 64     # the command was spoken wrong
EX_NOINPUT = 66   # no log to judge: missing, empty, or not readable as a file
EX_SOFTWARE = 70  # the tool itself failed; the traceback is on stderr
# Not a sysexits number: a shell reports a writer that its pipe's reader
# left as 128 + SIGPIPE, and this is that number, given on purpose.
EXIT_READER_GONE = 141


# --- Canonical form (SPEC §4) -------------------------------------------------
#
# The entry_hash is SHA256 over the canonical JSON of the entry minus its
# entry_hash field: keys sorted, compact separators, UTF-8, no trailing
# newline. These bytes are the format's ground truth — an independent
# implementation must reproduce them exactly. json.dumps escapes a string
# exactly as RFC 8785 section 3.2.2.2 does, which is what SPEC §4 pins:
# `\n` and the other short forms, lowercase `\u001b` for the rest of the
# controls, everything else as it stands. tests/vectors/ holds it there.

def canonical_bytes(entry_without_hash):
    return json.dumps(
        entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def entry_hash(entry_without_hash):
    return hashlib.sha256(canonical_bytes(entry_without_hash)).hexdigest()


def receipt_text(text):
    """`text` as a receipt can hold it: each lone surrogate written as
    its six ASCII characters of escape text (`\\ud800`), everything
    else exactly as it stands (#292). A lone surrogate has no UTF-8
    form, so the canonical form cannot hold it, yet JSON and POSIX argv
    both hand Python one; escaped, the receipt still says what was sent
    and the format does not change. Every string an entry takes from
    outside passes through here: actor, action, file paths."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


# --- Reading a chain ----------------------------------------------------------
# The log's lines, the tail, and the files an entry names, read and
# never written.

def split_lines(data):
    """The lines of a chain's or a sidecar's bytes, by the one rule every
    reader keeps (SPEC §1, #299): a line is the bytes before each `\\n`,
    and nothing else ends one. U+2028, U+2029 and NEL are characters a
    JSON string holds raw, and a `\\r` alone is whitespace between two
    JSON tokens; a reader that ended a line at any of them would read
    one entry of another conforming writer as two broken ones. A `\\r`
    just before the `\\n` belongs to the ending, so a file whose endings
    a Windows tool rewrote to `\\r\\n` reads as the same lines. The bytes
    after the last `\\n`, when there are any, are a line too: the torn
    tail a crash leaves, which the walk names. Written the same way in
    loxodonta.py, supervisor.py and receiver.py, which never import one
    another; tools/twin_check.py holds the copies equal."""
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return [line[:-1] if line.endswith(b"\r") else line for line in lines]


def read_log(path):
    """All lines of the receipt log, split by `split_lines`, for every
    reader and writer here; FileNotFoundError if it doesn't exist. A
    byte that is not UTF-8 arrives as a lone surrogate (surrogateescape)
    instead of ending the whole read in a traceback: the walk refuses
    the one line it sits on by name (SPEC §6), and `tail_entry` calls a
    tail holding one damaged. The recorder only ever writes ASCII lines,
    so no line it wrote is read any differently."""
    with open(path, "rb") as f:
        return [line.decode("utf-8", "surrogateescape")
                for line in split_lines(f.read())]


def missing_log(path):
    print(f"error: {path} not found — run `loxodonta init` first", file=sys.stderr)
    return EX_NOINPUT


def unreadable_log(path, error):
    """A log that is there and cannot be read as a file: a folder, or a
    file this user may not open. No input, like a missing one (ADR-0037);
    a line that cannot be read is another matter, and the walk names it."""
    print(f"error: {path} cannot be read as a receipt log: "
          f"{error.strerror or error}", file=sys.stderr)
    return EX_NOINPUT


def tail_entry(lines):
    """The chain's final entry, or None if the tail is damaged: torn (a
    line left partial by a crash or an overlapping append, or holding a
    byte that is not UTF-8) or forked (a well-formed entry whose `n` is
    not its line number, left by a lock taken from a paused holder).
    Neither can be built on: a new entry laid over a fork would bury an
    innocent race under later receipts until it read as tampering in
    the middle of the file, so damage stays at the tail (SPEC §6, §8)."""
    if not lines:
        return None
    try:
        # A byte that is not UTF-8 arrives from `read_log` as a lone
        # surrogate, which has no UTF-8 form. Every refusal of the reader
        # is a ValueError, the too-long integer's among them; nesting too
        # deep is a RecursionError.
        lines[-1].encode("utf-8")
        last = json.loads(lines[-1])
    except (ValueError, RecursionError):
        return None
    if not isinstance(last, dict) or "entry_hash" not in last or "n" not in last:
        return None
    if last["n"] != len(lines) - 1:
        return None
    return last


def sha256_file(path):
    """sha256 of a file's bytes, read in chunks: a packaged transcript can
    run to hundreds of MB, and nothing here needs it in memory at once."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def files_base(log):
    """The directory file references resolve against (SPEC §3 as
    amended v0.1.1, ADR-0012): the project named by a project record
    beside the log (a store chain), else the log's own directory (a
    local log at the project root — the two rules agree there).
    Returns (base, problem): problem is the honest sentence when a
    record exists but cannot lead anywhere."""
    log_dir = os.path.dirname(os.path.abspath(log))
    record = os.path.join(log_dir, "project.json")
    if not os.path.exists(record):
        return log_dir, None
    try:
        with open(record, encoding="utf-8") as f:
            path = json.load(f).get("path")
    except (OSError, ValueError):
        return None, f"project record unreadable: {record}"
    if isinstance(path, str) and os.path.isdir(path):
        return path, None
    return None, (f"project record points at a missing project ({path}) — "
                  "references cannot be resolved")


# --- The walk (SPEC §6) -------------------------------------------------------
# Every line judged against the format and the one before it.

class KeyGivenTwice(ValueError):
    """A JSON object that names one key twice. A last-wins reader (this
    one) and a first-wins reader see two different lines, and a hash that
    holds under one reading says nothing under the other; no reading of
    such a line is an entry (SPEC §6 step 1)."""

    def __init__(self, key):
        super().__init__(key)
        self.key = key


def object_with_each_key_once(pairs):
    """The dict of a JSON object's pairs, refusing a key given twice at
    any depth (json's object_pairs_hook is called for every object)."""
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise KeyGivenTwice(key)
        seen[key] = value
    return seen


def path_leaving_base(path):
    """How a reference path's spelling could lead outside the reference
    base, named; None when it cannot (SPEC §3). A leading slash of
    either kind is absolute (`\\\\server\\share` too), a letter and a
    colon is a drive (`C:\\x`, and `C:x`, which Windows reads from that
    drive's current folder), and a `..` segment steps up, with either
    slash as the separator since Windows reads both.
    The rule is spelling, the same on every platform, so a chain's
    verdict never depends on the machine that judges it. The recorder
    applies it to what a receipt stores and the walk to what a chain
    holds, so a chain the recorder wrote never fails it (#299). It is
    not containment: a symbolic link under the base is followed where
    it leads, by `log` and by `verify --files` alike (SPEC §3)."""
    if path[:1] in ("/", "\\"):
        return "absolute"
    if path[1:2] == ":":
        return "a drive"
    if ".." in path.replace("\\", "/").split("/"):
        return "a '..' segment"
    return None


def shape_problem(entry):
    """The first way `entry`'s values fail SPEC §2's types, named; None
    when each is of its type. Type only, with one exception: whether a
    string is hex, or a timestamp well-formed, is the hash comparison's
    and the reader's business, and a mistyped value is what makes a
    reader crash. The exception is a reference path that could leave the
    project: `verify --files` would open it on the recipient's machine,
    and no chain the recorder wrote holds one, so it was written past
    the recorder's refusal or forged (SPEC §3, §6 step 1; #299)."""
    n = entry.get("n")
    if isinstance(n, bool) or not isinstance(n, int):
        return "n is not an integer"
    for field in ("ts", "actor", "action"):
        value = entry.get(field)
        if not isinstance(value, str) or not value:
            return f"{field} is not a non-empty string"
    if not isinstance(entry.get("entry_hash"), str):
        return "entry_hash is not a string"
    prev = entry.get("prev")
    if prev is not None and not isinstance(prev, str):
        return "prev is not a string or null"
    files = entry.get("files")
    if not isinstance(files, list):
        return "files is not an array"
    for ref in files:
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}                 or not all(isinstance(value, str) for value in ref.values()):
            return "files holds something that is not a reference"
    for ref in files:
        how = path_leaving_base(ref["path"])
        if how is not None:
            # Escaped for display (`visible`, below): the path is the
            # writer's text.
            return (f"files names a path that leaves the project ({how}): "
                    f"{visible(ref['path'])}")
    return None


# Receipt text is written by the agent under observation, and report
# prints it to a terminal, explain hands it to a model, and verify's
# messages quote a writer's odd field names to whoever reads the verdict.
# A newline could forge a row or a verdict line, an ANSI sequence can
# repaint the screen, a bidi override reorders what the eye sees. So
# every character whose Unicode category steers rather than reads (Cc
# controls, Cf format characters, Cs lone surrogates, Zl and Zp
# separators) is printed as its escape; an emoji joined with a zero-width
# joiner prints as its parts, the price of naming categories.
# Display only: verify hashes the raw entry, and a backslash stays as it
# is, so the chain file is where the exact bytes are read. Twin of
# supervisor.py's `visible`; the files never import each other
# (ADR-0035), and tools/twin_check.py holds the two copies equal.
NAMED_ESCAPES = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}
STEERING_CATEGORIES = ("Cc", "Cf", "Cs", "Zl", "Zp")


def visible(text):
    """`text` with every steering character written as its escape: `\\n`,
    `\\x1b`, `\\u202e`, `\\U000e0041`. One line in, one line out,
    whatever the writer put in it."""
    shown = []
    for char in str(text):
        code = ord(char)
        if char in NAMED_ESCAPES:
            shown.append(NAMED_ESCAPES[char])
        elif unicodedata.category(char) not in STEERING_CATEGORIES:
            shown.append(char)
        elif code <= 0xff:
            shown.append(f"\\x{code:02x}")
        elif code <= 0xffff:
            shown.append(f"\\u{code:04x}")
        else:
            shown.append(f"\\U{code:08x}")
    return "".join(shown)


def walk(lines, field_rules=True):
    """The mechanical walk of SPEC §6, shared by verify (which judges) and
    report (which narrates). Returns (entries, breaks, warns): entries[n] is
    the parsed entry or None where the line is unparseable or is not the
    shape of an entry; breaks and warns are (n, message) lists in walk
    order. With `field_rules` False only the hash chain is walked (each
    line one JSON object, each key once, each hash and `prev` link) and
    not v0.1's field rules: that is how a chain whose genesis claims a
    version this verifier does not speak is judged, since the hashing is
    the same in every version and its fields are not ours to judge."""
    entries = []
    breaks = []
    warns = []
    prev_hash = None
    prev_ts = None
    for n, line in enumerate(lines):
        # A line the reader cannot take apart is refused by name like any
        # other line that is not an entry, never a traceback that leaves
        # the reader with no verdict at all (SPEC §6, #292).
        try:
            # A byte that is not UTF-8 arrives from `read_log` as a
            # lone surrogate, the one thing UTF-8 cannot encode.
            line.encode("utf-8")
            entry = json.loads(line, object_pairs_hook=object_with_each_key_once)
        except UnicodeEncodeError:
            breaks.append((n, f"BROKEN at entry {n}: line is not valid UTF-8"))
            entries.append(None)
            prev_hash = None
            continue
        except KeyGivenTwice as twice:
            breaks.append((n, f"BROKEN at entry {n}: key {twice.key!r} "
                              "given twice"))
            entries.append(None)
            prev_hash = None
            continue
        except json.JSONDecodeError:
            if n == len(lines) - 1:
                # The one honest damage signature: a crash mid-append can
                # truncate the final line and nothing else (SPEC §6).
                breaks.append((n, f"BROKEN: torn tail at line {n} (crash-"
                                  f"truncated append; entries 0..{n - 1} intact)"))
            else:
                breaks.append((n, f"BROKEN at entry {n}: line is not valid JSON"))
            entries.append(None)
            prev_hash = None
            continue
        except ValueError:
            # Python 3.11 and later refuse to read an integer of more
            # than 4,300 digits; the JSON is well formed, but no reader
            # here can hold it.
            breaks.append((n, f"BROKEN at entry {n}: an integer is too "
                              "long to read"))
            entries.append(None)
            prev_hash = None
            continue
        except RecursionError:
            breaks.append((n, f"BROKEN at entry {n}: nesting too deep to read"))
            entries.append(None)
            prev_hash = None
            continue
        if not isinstance(entry, dict):
            breaks.append((n, f"BROKEN at entry {n}: line is not a JSON object"))
            entries.append(None)
            prev_hash = None
            continue
        expected_fields = GENESIS_FIELDS if n == 0 else ENTRY_FIELDS
        if field_rules and set(entry) != expected_fields:
            odd = set(entry) ^ expected_fields
            # The odd names are the writer's, and this message reaches
            # agents through recall's verify tool: escaped like any other
            # receipt text (`visible`, #295), a lone surrogate among the
            # characters it escapes (#292).
            breaks.append((n, f"BROKEN at entry {n}: schema mismatch: "
                              f"{', '.join(visible(k) for k in sorted(odd))}"))
        # The right field names and the right hash do not make an entry
        # when a value is the wrong type (SPEC §6 step 1): a `files` that
        # is a string would crash every reader that resolves references.
        # The line is refused by name and carried as None, so nothing
        # downstream touches it; the chain rule carries on from its
        # stored hash where that is a string, so the next line is judged
        # on its own account.
        wrong = shape_problem(entry) if field_rules else None
        if wrong is not None:
            breaks.append((n, f"BROKEN at entry {n}: {wrong}"))
            entries.append(None)
            stored = entry.get("entry_hash")
            prev_hash = stored if isinstance(stored, str) else None
            continue
        # A string holding a lone surrogate (a JSON escape reads as one)
        # has no UTF-8 form, so the entry has no canonical form to hash
        # (SPEC §4): not an entry, refused the way a wrong type is. The
        # recorder never writes one; it writes the escape text instead.
        stored_hash = entry.get("entry_hash")
        hashed_form = {k: v for k, v in entry.items() if k != "entry_hash"}
        try:
            recomputed = entry_hash(hashed_form)
        except (UnicodeEncodeError, RecursionError) as unhashable:
            reason = ("nesting too deep to read"
                      if isinstance(unhashable, RecursionError) else
                      "a string holds a lone surrogate, which has no "
                      "canonical form")
            breaks.append((n, f"BROKEN at entry {n}: {reason}"))
            entries.append(None)
            prev_hash = stored_hash
            continue
        entries.append(entry)
        if field_rules and entry.get("n") != n:
            breaks.append((n, f"BROKEN at entry {n}: sequence number is "
                              f"{entry.get('n')}, expected {n}"))
        if entry.get("prev") != prev_hash:
            breaks.append((n, f"BROKEN at entry {n}: prev does not match "
                              "predecessor's entry_hash"))
        if recomputed != stored_hash:
            breaks.append((n, f"BROKEN at entry {n}: entry_hash does not "
                              "match canonical form"))
        # ts is writer-supplied testimony, not a mechanical fact: a backward
        # jump warns but never changes the verdict (SPEC §6, ADR-0002).
        ts = entry.get("ts") if field_rules else None
        if prev_ts is not None and ts is not None and ts < prev_ts:
            warns.append((n, f"WARN: ts decreases at entry {n} — clock skew "
                             "at write time?"))
        prev_ts = ts
        prev_hash = stored_hash
    return entries, breaks, warns


# --- Transcript commitments (SPEC §2.2, ADR-0017) -----------------------------
# Judged on every walk; the prefix hashes only under --transcript.

def parse_commitment(action):
    """(bytes, sha256) when the action line speaks SPEC §2.2's pinned
    grammar exactly; None otherwise."""
    prefix = "transcript-commitment: bytes="
    if not action.startswith(prefix):
        return None
    count, sep, digest = action[len(prefix):].partition(" sha256=")
    if not sep or not count.isdigit() or len(digest) != 64 \
            or any(c not in "0123456789abcdef" for c in digest):
        return None
    return int(count), digest


def transcript_commitments(entries):
    """(commitments, malformed): each commitment is (n, bytes, sha256)
    in chain order. An entry that names the grammar but fails it is
    malformed — entries are hash-protected, so it was *written* that
    way, and pretending to judge it would judge nothing."""
    marks, malformed = [], []
    for entry in entries:
        if entry is None or entry.get("actor") != "receipts":
            continue
        action = str(entry.get("action", ""))
        if not action.startswith("transcript-commitment:"):
            continue
        parsed = parse_commitment(action)
        if parsed is None:
            malformed.append(entry["n"])
        else:
            marks.append((entry["n"], parsed[0], parsed[1]))
    return marks, malformed


def judge_prefixes(marks, transcript_path):
    """One pass over the transcript, oldest boundary first: hash up to
    each committed byte count and photograph the digest there
    (hashlib.copy) — which localizes a rewrite to the span between two
    commitments. Returns True when any commitment failed to hold."""
    if not marks:
        print("no transcript commitments in this chain — nothing to judge")
        return False
    try:
        handle = open(transcript_path, "rb")
    except OSError:
        # Absence is a note, never a verdict: the harness cleans
        # transcripts on a retention cycle (ADR-0017).
        print(f"TRANSCRIPT-UNRESOLVED: no transcript at {transcript_path} "
              "— commitments unjudgeable; chain verdict unaffected")
        return False
    diverged = False
    with handle:
        running = hashlib.sha256()
        pos = 0
        for n, count, expected in sorted(marks, key=lambda m: m[1]):
            if count > pos:
                chunk = handle.read(count - pos)
                running.update(chunk)
                pos += len(chunk)
            if pos < count:
                print(f"COMMITMENT DIVERGED (entry {n}): transcript holds "
                      f"{pos} bytes, {count} committed — truncated")
                diverged = True
            elif running.copy().hexdigest() == expected:
                print(f"COMMITMENT HOLDS (entry {n}: first {count} bytes)")
            else:
                print(f"COMMITMENT DIVERGED (entry {n}): the first "
                      f"{count} bytes no longer match the committed hash")
                diverged = True
        if pos >= count:
            # The bytes past the last commitment are the honest window:
            # committed by nothing in this chain, stated so the reader
            # knows how much of the transcript the chain never vouched
            # for (a package's manifest commits them as of packaging).
            rest = handle.seek(0, os.SEEK_END) - pos
            print(f"transcript tail: {rest} bytes after the last commitment "
                  f"(entry {n}), uncommitted by the chain")
    return diverged


def check_transcript(entries, transcript_path):
    """The --transcript half of verify, plus the chain-only monotonicity
    rule (SPEC §2.2/§6 as amended v0.1.2, ADR-0017). Judges every
    commitment in one pass, oldest boundary first, photographing the
    running hash at each committed byte count — which localizes a
    rewrite to the span between two commitments. `transcript_path` may
    be None: monotonicity needs no transcript. Returns True when any
    commitment failed to hold."""
    marks, malformed = transcript_commitments(entries)
    for n in malformed:
        print(f"warning: entry {n} names transcript-commitment but not "
              "its grammar — skipped, judged as nothing", file=sys.stderr)
    diverged = False

    # A growing file never shrinks: contradicting byte counts are their
    # own evidence, judged from the chain alone.
    high = None
    for n, count, _ in marks:
        if high is not None and count < high:
            print(f"COMMITMENT-SHRANK (entry {n}): commits {count} bytes "
                  f"after an earlier commitment of {high} — a growing "
                  "transcript never shrinks")
            diverged = True
        high = count if high is None else max(high, count)

    if transcript_path is not None:
        diverged = judge_prefixes(marks, transcript_path) or diverged
    # The TRANSCRIPT-DIVERGED verdict line itself is printed by the
    # caller's exit ladder, last — the supervisor reads the final line
    # as the verdict (its own tripwire comment), so detail lines here
    # must never dangle after the conclusion.
    return diverged


# --- Anchoring (Stage B, ADR-0003 / docs/ANCHORING.md) ------------------------
#
# An anchor commits a chain head to Bitcoin via OpenTimestamps: free public
# calendar servers fold the head digest into a Merkle tree whose root lands
# in a Bitcoin transaction. The proof is a list of byte operations that
# replays the digest up to a Bitcoin block's merkle root. This section
# implements the small subset of the OTS format that calendar proofs use —
# anything outside it is refused by name, never guessed.


OP_SHA256, OP_APPEND, OP_PREPEND = 0x08, 0xF0, 0xF1
ATTESTATION_MARKER = 0x00
BRANCH_MARKER = 0xFF
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
MAX_PROOF_BYTES = 8192  # generous; real calendar proofs are a few hundred
MAX_PROOF_DEPTH = 512   # ops nest one level each; real proofs stay under ~100


class ProofError(ValueError):
    """A proof this verifier cannot judge — malformed or outside the subset."""


class ProofReader:
    """Cursor over proof bytes; every read is bounds-checked."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def byte(self):
        return self.bytes(1)[0]

    def bytes(self, count):
        if self.pos + count > len(self.data):
            raise ProofError("truncated proof")
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def varint(self):
        # Unsigned, little-endian base 128; high bit means "more".
        value = shift = 0
        while True:
            byte = self.byte()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise ProofError("varint too large")

    def varbytes(self):
        length = self.varint()
        if length > MAX_PROOF_BYTES:
            raise ProofError("proof field too large")
        return self.bytes(length)


def parse_timestamp(reader, depth=0):
    """One node of the proof tree: attestations that hold at the current
    digest, plus operations that each transform it and continue into a
    child node. Wire format: every element but the last is 0xff-prefixed.

    Depth is capped: each chained op nests one level, so without a cap a
    crafted proof a few KB long could exhaust the interpreter's recursion
    limit — a crash where a verdict belongs. Malformed evidence is judged
    (ANCHOR-INVALID), never guessed at and never crashed on."""
    if depth > MAX_PROOF_DEPTH:
        raise ProofError(f"proof nests deeper than {MAX_PROOF_DEPTH} operations")
    node = {"attestations": [], "ops": []}
    while True:
        tag = reader.byte()
        last = tag != BRANCH_MARKER
        if not last:
            tag = reader.byte()
        if tag == ATTESTATION_MARKER:
            node["attestations"].append(
                (bytes(reader.bytes(8)), bytes(reader.varbytes()))
            )
        elif tag in (OP_APPEND, OP_PREPEND):
            arg = bytes(reader.varbytes())
            node["ops"].append((tag, arg, parse_timestamp(reader, depth + 1)))
        elif tag == OP_SHA256:
            node["ops"].append((tag, None, parse_timestamp(reader, depth + 1)))
        else:
            raise ProofError(
                f"proof uses operation 0x{tag:02x}, "
                "which this verifier does not implement"
            )
        if last:
            return node


def replay_proof(digest, node, results=None):
    """Walk the proof applying each operation to the digest; collect every
    attestation together with the digest it attests to and the node holding
    it (the node reference is what upgrade splices into)."""
    if results is None:
        results = []
    for tag, payload in node["attestations"]:
        results.append(
            {"tag": tag, "payload": payload, "digest": digest, "node": node}
        )
    for op, arg, child in node["ops"]:
        if op == OP_SHA256:
            next_digest = hashlib.sha256(digest).digest()
        elif op == OP_APPEND:
            next_digest = digest + arg
        else:  # OP_PREPEND
            next_digest = arg + digest
        replay_proof(next_digest, child, results)
    return results


def bitcoin_height(payload):
    reader = ProofReader(payload)
    height = reader.varint()
    if reader.pos != len(payload):
        raise ProofError("malformed Bitcoin attestation payload")
    return height


def judge_proof(head_hex, proof_bytes):
    """Replay a proof from a chain head. Returns ("bitcoin", height, root),
    ("pending", digest_hex), or raises ProofError."""
    node = parse_timestamp(ProofReader(proof_bytes))
    results = replay_proof(bytes.fromhex(head_hex), node)
    for r in results:
        if r["tag"] == TAG_BITCOIN:
            return ("bitcoin", bitcoin_height(r["payload"]), r["digest"])
    for r in results:
        if r["tag"] == TAG_PENDING:
            return ("pending", r["digest"].hex())
    raise ProofError("proof contains no attestation this verifier can judge")


# --- Checking the block (ruling 3 on #299) ------------------------------------
# A Bitcoin attestation is eight bytes of tag and a height, and replaying
# the proof ends at a 32-byte merkle root. Nothing in either says a block
# with that root was ever mined: a regenerated chain can carry an
# attestation made up whole, with any height it likes. What closes that is
# the block's header, which the recipient fetches from a source they trust
# (`--block-header`): 80 bytes, the merkle root at bytes 36 to 68, stored
# in the order the proof's final double sha256 leaves it, so the two are
# compared byte for byte. A header carries no height, so it is matched to
# an attestation by that root, never by the height either one names, and
# a matched block is named by its hash, the value a second source can
# confirm. Explorers print a hash, and a merkle root, byte-reversed.

BLOCK_HEADER_BYTES = 80


def header_root(header):
    """The merkle root field of an 80-byte block header, as stored."""
    return header[36:68]


def header_hash(header):
    """The block's hash as explorers print it: double sha256, reversed."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def headers_by_root(headers):
    """The headers the recipient gave, keyed by the merkle root each holds."""
    return {header_root(header): header for header in headers or ()}


def attestation_words(subject, height, root, headers, used):
    """What a completed proof shows about `subject`, said no further than
    it was checked. Without a header holding its root, the attestation's
    height is its own claim; with one, the entries existed by the block
    that header is, named by its hash. `used` collects the roots a header
    matched, so the headers that matched nothing can be named after."""
    shown = root[::-1].hex()
    header = headers.get(root)
    if header is None:
        return (f"{subject}: the attestation claims Bitcoin block {height}, "
                "and the block was not checked; that block's merkle root "
                f"must read {shown}, which --block-header with its header "
                "checks")
    used.add(root)
    return (f"{subject} existed by the block whose header hashes to "
            f"{header_hash(header)}, whose merkle root {shown} is the one "
            "the proof replays to; the attestation calls it Bitcoin block "
            f"{height}, which is your header source's word, and the hash is "
            "what a second source can confirm")


def note_unmatched_headers(headers, used):
    """A header that matched no attestation checked nothing: a note, never
    a verdict, since without a height nobody can say which attestation it
    was fetched for. The note says what the recipient can: if they fetched
    it for a height an attestation claims, that attestation does not
    replay to their block."""
    for root, header in headers.items():
        if root not in used:
            print(f"HEADER-UNMATCHED: the block header with hash "
                  f"{header_hash(header)} holds merkle root "
                  f"{root[::-1].hex()}, which no Bitcoin attestation judged "
                  "here replays to; it checked nothing, and an attestation "
                  "claiming the height you fetched it for does not replay "
                  "to that block")


def sidecar_path(log, suffix):
    """A file beside a chain that is not a chain: the anchor sidecar,
    the publish memo. Named after the chain so the two travel together."""
    return log + suffix


def anchors_path(log):
    return sidecar_path(log, ".anchors.jsonl")


def read_sidecar_records(path):
    """The records of one sidecar, or None when the file does not exist
    (every sidecar is optional). A line that is not a JSON object reads
    as None, so a judge can name it rather than skip it, and so does a
    line the reader cannot take apart: a byte that is not UTF-8 (a lone
    surrogate from `read_log`), an integer too long to read, nesting too
    deep (#299)."""
    try:
        lines = read_log(path)
    except FileNotFoundError:
        return None
    records = []
    for line in lines:
        try:
            line.encode("utf-8")
            record = json.loads(line)
            if not isinstance(record, dict):
                record = None
        except (ValueError, RecursionError):
            record = None
        records.append(record)
    return records


def read_anchor_records(log):
    """The anchor sidecar's records, or None when there is no sidecar."""
    return read_sidecar_records(anchors_path(log))


def record_label(head, n):
    """How an anchor record is named in messages: a chain head by its
    entry number; a manifest digest, which has no entry, as the
    manifest's."""
    if n is None:
        return f"manifest {head[:12]}…"
    return f"head {head[:12]}… (entry {n})"


# --- Attempt records (#240, PRD #244) ----------------------------------------
# Session-end steps that reach off the machine fail quietly (ADR-0024
# ruling 3, ADR-0025), but not silently: after each one the recorder
# writes a row of kind `attempt` into the sidecar the step already owns
# (the anchors sidecar, the publish memo), with the step, the time, its
# budget and the outcome. Never the URL: a webhook URL is a credential.
# The row is testimony, never proof: every reader that judges skips it
# by its kind, and the supervisor reads it to say when a head last left
# the machine. The chain's schema is untouched.

ATTEMPT_KIND = "attempt"
# The publish memo's other note: a batch of entries sent to a receiver
# (ADR-0031). Named here because the row reader below knows it.
CHAIN_KIND = "chain"


def is_attempt(record):
    """True for a row of kind `attempt`: a note on how a session-end
    step went, never a proof and never a sent head. Readers that judge
    skip these rows; readers that report use them."""
    return isinstance(record, dict) and record.get("kind") == ATTEMPT_KIND


# --- What a sidecar row is (ADR-0038) -----------------------------------------
# Every sidecar row names its kind. The first rows of each sidecar were
# written before rows named one, so a row with no `kind` reads as its
# sidecar's evidence row: a proof, a token, a sent head. That holds
# whenever the row was written, since a sidecar is not chained and
# nothing in it dates a row. A kind this verifier does not know, or one
# that belongs in another sidecar, is named and never judged, so a row a
# newer recorder writes is never evidence against an honest log. The
# rule is written here and nowhere else: every reader asks `row_kind`.

ANCHOR_KIND = "anchor"
STAMP_KIND = "stamp"
HEAD_KIND = "head"

# The kinds each sidecar holds, its evidence kind first: the anchors
# sidecar, the stamps sidecar, and the publish memo.
SIDECAR_KINDS = {
    "anchors": (ANCHOR_KIND, ATTEMPT_KIND),
    "stamps": (STAMP_KIND, ATTEMPT_KIND),
    "memo": (HEAD_KIND, CHAIN_KIND, ATTEMPT_KIND),
}
# What `row_kind` answers when a row has no kind of its sidecar's. No
# sidecar holds either word as a kind, so a writer who writes one is
# read as unknown, never as these.
UNREADABLE_ROW = "unreadable"
UNKNOWN_ROW = "unknown"


def row_kind(sidecar, record):
    """What one row of `sidecar` ("anchors", "stamps" or "memo") is, for
    a row as `read_sidecar_records` gives it: the row's kind; the
    sidecar's evidence kind for a row with no `kind`; UNREADABLE_ROW for
    a line that is not a JSON object; UNKNOWN_ROW for a kind this
    sidecar does not hold, a kind that is not a string among them."""
    if record is None:
        return UNREADABLE_ROW
    kinds = SIDECAR_KINDS[sidecar]
    if "kind" not in record:
        return kinds[0]
    kind = record["kind"]
    if isinstance(kind, str) and kind in kinds:
        return kind
    return UNKNOWN_ROW


JSON_TYPE_WORDS = ((bool, "true or false"), (int, "a number"),
                   (float, "a number"), (list, "an array"),
                   (dict, "an object"), (type(None), "null"))


def rows_to_judge(sidecar, records, prefix, name):
    """The rows of `records` a judge of `sidecar` weighs, in file order:
    each evidence row, and None for each unreadable line, which the
    judge names. Attempt rows and the memo's chain rows are left out
    silently. A row of a kind unknown here is left out after one line
    that names it, headed `prefix`, with its line number in the sidecar
    file `name`: a bare file name, never a path of this machine. The kind is the writer's text, so it is printed escaped, and
    a kind that is not a string is named by its JSON type, never its
    value."""
    judged = []
    evidence = SIDECAR_KINDS[sidecar][0]
    for number, record in enumerate(records, 1):
        kind = row_kind(sidecar, record)
        if kind in (evidence, UNREADABLE_ROW):
            judged.append(record)
            continue
        if kind != UNKNOWN_ROW:
            continue
        written = record["kind"]
        if isinstance(written, str):
            shown = f'of kind "{visible(written)}"'
        else:
            words = next((words for types, words in JSON_TYPE_WORDS
                          if isinstance(written, types)), "a value")
            shown = f"of a kind that is {words}, not a string"
        print(f"{prefix}: line {number} of {visible(name)} is {shown} — this "
              "verifier does not know the kind in this sidecar, and does "
              "not judge it")
    return judged


# --- Judging anchors (docs/ANCHORING.md §3) -----------------------------------

def check_anchors(log, entries, headers, used):
    """The --anchors half of verify (docs/ANCHORING.md §3): judge every
    sidecar record against the chain, offline. `headers` are the block
    headers the recipient gave, by root, and `used` collects the roots
    that checked a block here. Returns True if any record is evidence
    against this log (mismatch or invalid — exit-3 tier); a block left
    unchecked is said so, and is never that."""
    records = read_anchor_records(log)
    if records is None:
        print(f"NO-ANCHORS: {anchors_path(log)} not found — anchoring is "
              "optional; run `loxodonta anchor` to add one")
        return False
    hash_to_n = {e["entry_hash"]: e["n"] for e in entries}

    # A row of an unknown kind is named here, before any verdict line, so
    # the last line printed is the one it would be without the row.
    judged = []
    for record in rows_to_judge("anchors", records, "ANCHOR-UNKNOWN-KIND",
                                os.path.basename(anchors_path(log))):
        if record is None:
            judged.append((record, "invalid", "sidecar line is not a record"))
            continue
        head = record.get("head")
        if head is None:
            # No head at all is malformed evidence, not a mismatch
            # against a head called "None".
            judged.append((record, "invalid", "record has no head"))
            continue
        if head not in hash_to_n:
            judged.append((record, "mismatch", None))
            continue
        try:
            verdict = judge_proof(head, base64.b64decode(record["proof"]))
        except (ProofError, KeyError, ValueError) as e:
            judged.append((record, "invalid", str(e)))
            continue
        judged.append((record, *verdict))

    completed = {(r["head"], r.get("calendar"))
                 for r, kind, *_ in judged if r and kind == "bitcoin"}
    # The anchor's claim is about the head, not about any one calendar
    # (#199). Four calendars is the default and they disagree routinely,
    # so once any of them settles a head the stragglers are evidence of
    # where the submission went, not work still owed.
    settled_heads = {head for head, _ in completed}
    bad = False
    for record, kind, *detail in judged:
        if kind == "bitcoin":
            height, root = detail
            subject = f"ANCHORED: entries 0..{hash_to_n[record['head']]}"
            print(attestation_words(subject, height, root, headers, used))
        elif kind == "pending":
            if (record["head"], record.get("calendar")) in completed:
                continue  # this submission's own upgraded record supersedes it
            if record["head"] in settled_heads:
                print(f"ANCHOR-UNANSWERED: head {record['head'][:12]}… "
                      f"submitted {record.get('ts')} via "
                      f"{record.get('calendar')} never came back, and "
                      "another calendar settled this head — no upgrade is "
                      "owed")
                continue
            print(f"ANCHOR-PENDING: head {record['head'][:12]}… submitted "
                  f"{record.get('ts')} via {record.get('calendar')} — run "
                  "`loxodonta anchor --upgrade`")
        elif kind == "mismatch":
            bad = True
            print(f"ANCHOR-MISMATCH: anchored head {record.get('head')} "
                  "appears nowhere in this log — this log is not the "
                  "anchored history")
        else:
            bad = True
            reason = detail[0]
            print(f"ANCHOR-INVALID: {reason} — evidence that does not "
                  "verify is not evidence")
    return bad


# --- Judging authority timestamps (ADR-0032) ----------------------------------
# What a stamp is, and how it is made, is with the stamp command below.

def stamps_path(log):
    return sidecar_path(log, ".stamps.jsonl")


def read_stamp_records(log):
    """The stamps sidecar's records, or None when there is no sidecar."""
    return read_sidecar_records(stamps_path(log))


def openssl_reason(stderr):
    """Why openssl refused, in its own words and on one line. Its error
    lines are colon-separated fields (an id, `error`, a code, a library,
    a function, the reason, the source file and line, then any words
    the check added), innermost first, so the last one is the summary
    and its reason field is what a reader needs. Anything else it said
    is kept whole, except the line naming the configuration file it
    loaded, which says nothing about the token."""
    said = [line.strip() for line in stderr.splitlines()
            if line.strip() and not line.startswith("Using configuration")]
    errors = [line for line in said if line.split(":")[1:2] == ["error"]]
    if errors:
        fields = errors[-1].split(":")
        if len(fields) > 8:
            tail = ": ".join(f.strip() for f in fields[8:] if f.strip())
            return fields[5] + (f": {tail}" if tail else "")
        return errors[-1]
    return "; ".join(said) or "openssl gave no reason"


# openssl's words when a certificate in the chain it checks is past its
# end date, as of the moment it verifies (X509_V_ERR_CERT_HAS_EXPIRED).
CERT_EXPIRED = "certificate has expired"
# The notes a token leaves when that is why openssl refused it (#264):
# the same check as of the time the token states passed, or this openssl
# cannot be asked about any moment but now.
STAMP_OUTLIVED = ("the authority's certificate expired after the token "
                  "was issued")
STAMP_NO_ATTIME = ("the authority's certificate has expired, and this "
                   "openssl cannot judge a token as of the time it states")


def openssl_verify(head, token, chain_file, *more):
    """`openssl ts -verify` on one token file: `-in` reads the whole
    TimeStampResp the sidecar keeps; `-digest` is the head, the sha256
    imprint the token must carry; `-CAfile` is the authority's chain the
    operator saved. `more` is `-attime` and a moment, when the question
    is about some other moment than now."""
    return subprocess.run(
        ["openssl", "ts", "-verify", "-digest", head, "-sha256",
         "-in", token, "-CAfile", chain_file, *more],
        capture_output=True, encoding="utf-8", errors="replace")


def token_time(token):
    """The moment a token states, in epoch seconds, from the one `Time
    stamp:` line `openssl ts -reply -token_out -text` prints; None when
    there is not exactly one such line this can read. openssl reads the
    token, never this file (ADR-0032 ruling 4). `-token_out` is the
    trap: without it openssl first prints the reply's status text, which
    nobody signed and the writer can edit, so a line break in it could
    set a `Time stamp:` line of the writer's own ahead of the
    authority's (#264). With it, a second such line is signed or breaks
    the signature, so two of them is a time nobody can read."""
    shown = subprocess.run(["openssl", "ts", "-reply", "-in", token,
                            "-token_out", "-text"],
                           capture_output=True, encoding="utf-8",
                           errors="replace")
    stated = [line.partition(":")[2] for line in shown.stdout.splitlines()
              if line.partition(":")[0] == "Time stamp"]
    if len(stated) != 1:
        return None
    # "Sep 18 22:55:50 2026 GMT", with a fraction on the seconds when the
    # authority's clock gives one, which -attime has no room for. The
    # month is English whatever the machine's language: openssl prints
    # it so, and Python reads %b in the C locale unless a program changes
    # that, which this one never does.
    words = stated[0].split()
    if len(words) != 5 or words[4] != "GMT":
        return None
    words[2] = words[2].split(".")[0]
    try:
        stated_at = datetime.strptime(" ".join(words[:4]), "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return int(stated_at.replace(tzinfo=timezone.utc).timestamp())


def takes_attime():
    """Whether this openssl can judge a token as of a given moment: its
    `ts -help` lists `-attime` when `ts -verify` takes it."""
    shown = subprocess.run(["openssl", "ts", "-help"], capture_output=True,
                           encoding="utf-8", errors="replace")
    return "-attime" in shown.stdout + shown.stderr


def judge_outlived(head, token, chain_file, refused):
    """A token openssl refused because a certificate in the authority's
    chain has expired (#264), judged again as of the time the token
    states. openssl checks the certificate before the signature, so past
    that date a tampered token fails exactly as a genuine one does; only
    the second check tells them apart. Passing, it is a note, never a
    verdict and never STAMPED: a key whose certificate has run out is
    vouched for by nobody now, and could sign any past time (long-term
    validation is not built). Failing, that reason is the verdict. An
    openssl that cannot be asked about a past moment judges nothing, and
    says why; a token whose time cannot be read (missing, twice, or `Bad
    time value`) keeps openssl's first refusal, as the token's fault."""
    if not takes_attime():
        return "not judged", STAMP_NO_ATTIME
    stated = token_time(token)
    if stated is None:
        return "invalid", (f"{openssl_reason(refused.stderr)}; the time the "
                           "token states could not be read, so nothing shows "
                           "the certificate was in date then")
    then = openssl_verify(head, token, chain_file, "-attime", str(stated))
    if then.returncode == 0:
        return "not judged", STAMP_OUTLIVED
    return "invalid", (f"{openssl_reason(then.stderr)} (judged as of the "
                       "time the token states)")


def judge_stamp(head, reply, chain_file):
    """One token against the head it claims, through `openssl ts -verify`
    and never this file (ADR-0032 ruling 5, in ADR-0026's posture), with
    the arguments openssl_verify names. Nothing is fetched. Returns
    (verdict, detail): ("stamped", None) when openssl accepted it,
    ("invalid", openssl's reason) when it refused, or ("not judged",
    why) when nobody judged it, which is a note and never a verdict: no
    tool, no chain file, or a certificate that has expired since the
    token was issued (judge_outlived)."""
    if chain_file is None:
        return "not judged", "no --authority-chain FILE given"
    if not os.path.isfile(chain_file):
        return "not judged", f"--authority-chain {chain_file} not found"
    try:
        with tempfile.TemporaryDirectory() as scratch:
            token = os.path.join(scratch, "stamp.tsr")
            with open(token, "wb") as f:
                f.write(reply)
            judged = openssl_verify(head, token, chain_file)
            if judged.returncode != 0 and CERT_EXPIRED in judged.stderr:
                return judge_outlived(head, token, chain_file, judged)
    except FileNotFoundError:
        return "not judged", "openssl is not on PATH"
    except PermissionError:
        return "not judged", "openssl cannot run here (permission denied)"
    if judged.returncode == 0:
        return "stamped", None
    return "invalid", openssl_reason(judged.stderr)


def check_stamps(log, entries, chain_file):
    """The --stamps half of verify (ADR-0032 ruling 5): every row of the
    stamps sidecar against the chain, offline, and its token through
    openssl when this machine has it and the operator gave the
    authority's chain file. Returns True if any row is evidence against
    this log (STAMP-INVALID, the exit-3 tier beside ANCHOR-INVALID). A
    token nobody judged is a note, never a verdict: the exit stays the
    chain's."""
    records = read_stamp_records(log)
    if records is None:
        print(f"NO-STAMPS: {stamps_path(log)} not found — the authority "
              "timestamp is optional; run `loxodonta stamp --authority URL` "
              "to add one")
        return False
    hash_to_n = {e["entry_hash"]: e["n"] for e in entries}
    bad = False
    # A row of an unknown kind is named here, before any verdict line, so
    # the last line printed is the one it would be without the row.
    for record in rows_to_judge("stamps", records, "STAMP-UNKNOWN-KIND",
                                os.path.basename(stamps_path(log))):
        head = record.get("head") if record else None
        if not isinstance(head, str) or \
                not isinstance(record.get("response"), str):
            bad = True
            print("STAMP-INVALID: sidecar line is not a stamp record — "
                  "evidence that does not verify is not evidence")
            continue
        if head not in hash_to_n:
            bad = True
            print(f"STAMP-INVALID: stamped head {head} appears nowhere in "
                  "this log — this log is not the stamped history")
            continue
        n = hash_to_n[head]
        label = record_label(head, n)
        try:
            reply = base64.b64decode(record["response"], validate=True)
        except ValueError:
            bad = True
            print(f"STAMP-INVALID: {label}: the response is not base64 — "
                  "evidence that does not verify is not evidence")
            continue
        verdict, detail = judge_stamp(head, reply, chain_file)
        if verdict == "stamped":
            # What openssl checked, and nothing it did not: that a key
            # the chain file certifies signed this head under its own
            # clock. The record's `authority` is the writer's note of
            # whom it asked, in a file the writer can edit, so it is
            # named as testimony and never as the signer (the trap
            # ADR-0008 ruling 4 closes for the signature).
            print(f"STAMPED: entries 0..{n} existed when a key certified "
                  f"by {chain_file} signed this head under its own clock "
                  f"(the record names {record.get('authority')}, "
                  "testimony) — the time inside the token is that key's "
                  "word, not this machine's (`openssl ts -reply -text` "
                  "prints it)")
        elif verdict == "invalid":
            bad = True
            print(f"STAMP-INVALID: {label}: {detail} — evidence that does "
                  "not verify is not evidence")
        else:
            print(f"stamp not judged: {detail} — {label} holds a token, "
                  "present and not judged here (ADR-0032)")
    return bad


# --- The verdicts: verify and head --------------------------------------------

def verify_log(log, files=False, expect_head=None, transcript=None,
               anchors=False, stamps=False, authority_chain=None,
               block_headers=None, headers_used=None, mechanisms=None):
    """The walk of one chain, then whatever the checks add, then the
    verdict as the exit code: `verify PATH` and the package judge both
    call this, each with the checks it asked for. `block_headers` are
    `--block-header`'s, by root. `headers_used` and `mechanisms` are the
    package judge's out-parameters: the roots a header matched (so a
    header matching nothing is noted once, across every chain; without
    it this walk notes its own), and the exit-3 findings' words (so the
    package verdict names the mechanism: "anchor" is never the word for
    an authority timestamp)."""
    try:
        lines = read_log(log)
    except FileNotFoundError:
        return missing_log(log)
    except OSError as e:
        return unreadable_log(log, e)
    if not lines:
        print(f"error: {log} is empty — not a receipt log", file=sys.stderr)
        return EX_NOINPUT

    # SPEC §2.1: read the genesis version first, to know which field rules
    # apply. A version we don't speak is judged by its hashes alone
    # (ADR-0036). A genesis with no version claim at all (damaged,
    # non-object, or v stripped) is the walk's business — that's
    # tampering to judge, not a dialect to politely decline.
    try:
        # A line that is not UTF-8, or that the reader cannot take apart
        # at all, claims no version: the walk names it (#292).
        lines[0].encode("utf-8")
        genesis = json.loads(lines[0])
    except (ValueError, RecursionError):
        genesis = None
    log_version = genesis.get("v", FORMAT_VERSION) if isinstance(genesis, dict) \
        else FORMAT_VERSION
    if log_version != FORMAT_VERSION:
        return verify_unknown_version(lines, log_version, expect_head)

    entries, breaks, warns = walk(lines)
    for _, message in warns:
        print(message, file=sys.stderr)
    if breaks:
        for _, message in breaks:
            print(message)
        return 1

    diverged = 0
    if files:
        # Every path below comes from the chain being judged, and every
        # one stays under the base by its spelling: an entry naming a
        # path that could leave it is refused by the walk above, BROKEN,
        # so this is never reached for it and nothing here opens it
        # (`path_leaving_base`, #299). A symbolic link is followed, as the
        # recorder followed it when it logged the file (SPEC §3).
        # Latest reference per path is authoritative (GLOSSARY: file reference).
        latest = {}
        for entry in entries:
            for ref in entry["files"]:
                latest[ref["path"]] = ref["sha256"]
        base, problem = files_base(log)
        if problem:
            # Honest unresolvability, a different sentence from "file
            # diverged" (ADR-0012): the check could not run, and
            # nothing is claimed about the files either way.
            print(f"FILES-UNRESOLVED: {problem} — file checks skipped")
            latest = {}
        for path in sorted(latest):
            try:
                on_disk = sha256_file(os.path.join(base, path))
            except FileNotFoundError:
                print(f"MISSING (not on disk): {path}")
                continue
            except (OSError, ValueError):
                # A path this machine cannot open as a file: a directory,
                # a name the platform refuses, a NUL (#292). Nothing to
                # fingerprint, so it is missing in the same sense, and
                # the verdict stays the chain's.
                print(f"MISSING (not a readable file here): {path}")
                continue
            if on_disk == latest[path]:
                print(f"CURRENT: {path}")
            else:
                print(f"MODIFIED-SINCE-LOGGED: {path}")
                diverged += 1
        if diverged:
            print(f"FILES-DIVERGED: chain intact, {diverged} file(s) "
                  "differ from their logged fingerprints")

    # Transcript commitments (SPEC §2.2, ADR-0017): monotonicity is
    # judged on every walk; the prefix hashes only under --transcript.
    transcript_diverged = check_transcript(entries, transcript)

    # Anchor, stamp and head-record findings share the exit-3 tier: all
    # mean "this is not the recorded history", the graver verdict, never
    # masked by a files divergence (SPEC §6, docs/ANCHORING.md §3 and §6).
    headers = block_headers or {}
    used = set() if headers_used is None else headers_used
    anchors_bad = anchors and check_anchors(log, entries, headers, used)
    if anchors and headers_used is None:
        note_unmatched_headers(headers, used)
    stamps_bad = stamps and check_stamps(log, entries, authority_chain)
    if mechanisms is not None:
        mechanisms += (["ANCHOR-MISMATCH"] if anchors_bad else []) \
            + (["STAMP-INVALID"] if stamps_bad else [])

    if transcript_diverged:
        # Printed after the anchor chatter so that when this verdict
        # governs, it is the last line — the supervisor reads the final
        # line as the verdict. A graver finding below still prints
        # later and wins the exit (all reported, gravest sets the code).
        print("TRANSCRIPT-DIVERGED: chain intact, but a committed "
              "transcript prefix no longer holds")

    chain_head = entries[-1]["entry_hash"] if entries else None
    if head_mismatch(chain_head, expect_head):
        return 3
    if anchors_bad or stamps_bad:
        return 3
    if transcript_diverged:
        # Graver than a files divergence (working-tree drift is usually
        # innocent; a rewritten transcript never is), milder than a
        # regenerated chain (SPEC §6 as amended v0.1.2).
        return 5
    if diverged:
        return 2

    print("VALID")
    return 0


def head_mismatch(chain_head, expect_head):
    """True, with the verdict line printed, when a head record was given
    and the chain's head is not it: internally consistent, but not the
    chain the operator recorded, the signature of whole-chain
    regeneration."""
    if expect_head is None or chain_head == expect_head:
        return False
    print(f"HEAD-MISMATCH: chain head is {chain_head}, expected "
          f"{expect_head} — this is not the recorded history")
    return True


def verify_unknown_version(lines, log_version, expect_head):
    """A chain whose genesis claims a format this verifier does not speak
    (ADR-0036). The hashing is frozen across versions, so its hash chain
    is walked all the same, and a break is BROKEN, exit 1, exactly as for
    a chain of our own. Only when every hash and link holds is it the
    refusal, exit 4: the field rules are a later version's, and not ours
    to judge. The head is the last entry's hash under any version, so a
    head record is still compared, and a mismatch is still exit 3. The
    other checks read fields (files, the transcript, the sidecars'
    entry numbers) and do not run."""
    entries, breaks, _ = walk(lines, field_rules=False)
    if breaks:
        for _, message in breaks:
            print(message)
        return 1
    # Escape text, so a claim holding a lone surrogate prints (#292).
    claimed = receipt_text(str(log_version))
    print(f'UNSUPPORTED-VERSION: log is format "{claimed}"; '
          f'this verifier speaks "{FORMAT_VERSION}"')
    if head_mismatch(entries[-1]["entry_hash"], expect_head):
        return 3
    return 4


def cmd_verify(args):
    """`verify PATH`: the flags, handed to the one walk."""
    return verify_log(args.log, files=args.files,
                      expect_head=args.expect_head,
                      transcript=args.transcript, anchors=args.anchors,
                      stamps=args.stamps,
                      authority_chain=args.authority_chain,
                      block_headers=headers_by_root(args.block_header))


def cmd_head(args):
    try:
        lines = read_log(args.log)
    except FileNotFoundError:
        return missing_log(args.log)
    except OSError as e:
        return unreadable_log(args.log, e)
    if not lines:
        print(f"error: {args.log} is empty — no chain head to print", file=sys.stderr)
        return EX_NOINPUT
    last = tail_entry(lines)
    if last is None:
        print(f"error: {args.log} has a damaged tail — run "
              "`loxodonta verify` (a torn tail has no head to record)",
              file=sys.stderr)
        return 1
    print(last["entry_hash"])
    return 0


# --- Package verification (ADR-0026, applying ADR-0007) -----------------------
#
# A package is a session's chains with their anchor sidecars, the project
# record, a witness snapshot, and a README, listed by a manifest written
# last (`supervisor package` builds it). The recorder judges it here,
# layer by layer: its own verify output per chain, verbatim; each artifact
# against the manifest; then the package verdict in ADR-0007's words. The
# manifest's hash is the only sealing surface, and this package format
# declares no seals yet, so the ceiling is SELF-CONSISTENT.

PACKAGE_FORMAT = "loxodonta-package/1"   # the receipt format stays 0.1
PACKAGE_MAX_BYTES = 1 << 30   # a zip declaring more unpacked is refused unopened

# The package ladder (ADR-0026 ruling 7), mapped onto verify's own exits so
# a script that reads those learns nothing new. Gravest wins, in this
# order: a refusal, a broken chain, a seal or an anchor that is not this
# history, a transcript that no longer holds, an artifact off its manifest.
# Every finding names its mechanism, and the verdict line is the gravest
# finding's word (ADR-0007 ruling 5); the seal rungs (`+ ANCHORED`, then
# `+ SIGNED (key: ...)`) join the ceiling by adding words, and never by
# hiding a finding.
PACKAGE_GRAVITY = (4, 1, 3, 5, 2)
PACKAGE_WORDS = {
    "UNSUPPORTED-FORMAT": "a chain in this package is a format this verifier "
                          "does not speak (its lines above say which)",
    "CHAIN-BROKEN": "a chain in this package does not walk clean (its lines "
                    "above say where)",
    "ANCHOR-MISMATCH": "an anchor packaged with a chain is not evidence for "
                       "that chain (its lines above say which)",
    "STAMP-INVALID": "an authority timestamp packaged with a chain is not "
                     "evidence for that chain (its lines above say which)",
    "SEAL-INVALID": "a seal this package carries does not hold for its "
                    "manifest (the seal line above says why)",
    "SEAL-MISSING": "a seal the manifest declares is not in this package "
                    "(the seal line above says which)",
    "TRANSCRIPT-DIVERGED": "a chain's transcript commitments do not hold: they "
                           "contradict each other, or the packaged transcript "
                           "differs from what they committed (its lines above "
                           "say which)",
    "ARTIFACT-DIVERGED": "something in this package is not what the manifest "
                         "lists (the lines above say what)",
    "SELF-CONSISTENT": "every chain walks clean and every artifact matches "
                       "the manifest",
}
# The exit-3 tier holds two mechanisms, the anchor's and the authority
# timestamp's; `verify_log` hands back which fired through `mechanisms`,
# and this table is the fallback for an exit with no word beside it. An
# empty packaged chain exits 66 (ADR-0037), but the manifest lists it,
# so inside a package it is a finding: CHAIN-BROKEN.
CHAIN_WORDS = {1: "CHAIN-BROKEN", 3: "ANCHOR-MISMATCH",
               4: "UNSUPPORTED-FORMAT", 5: "TRANSCRIPT-DIVERGED",
               EX_NOINPUT: "CHAIN-BROKEN"}
# The issuer signature (ADR-0008, ADR-0026 ruling 4) is made and judged
# by ssh-keygen, never by this file: the stdlib has no Ed25519, and the
# tool is on every machine since OpenSSH 8.0. The namespace is the
# supervisor's too, so a signature made for anything else never verifies
# here; the principal labels the one-line allowed-signers file the
# verifier writes for ssh-keygen and is never printed, since the verifier
# names a key by its fingerprint and nothing else (ADR-0008 ruling 4).
SIGNATURE_NAMESPACE = "loxodonta-package"
SIGNATURE_PRINCIPAL = "issuer"


def bare_name(value):
    """A manifest path is accepted only as a bare file name: the layout is
    flat, and a name that could leave the package, or that one system
    opens as another file than the rest do, is refused, never followed.
    Judged by its characters alone, the same on every system, so one
    package gets one verdict wherever it is read: not empty, not `.` or
    `..`; no `/`, `\\` or `:` (a folder, a drive such as `C:x`, a
    Windows stream) and no control character, below U+0020; no trailing
    dot or space, which Windows strips, so `project.json.` would open
    `project.json` there and nothing elsewhere; and not a Windows device
    name, in any case and whatever follows its first dot (`NUL`,
    `con.txt`, `COM1` to `COM9`, `LPT1` to `LPT9`)."""
    if not isinstance(value, str) or value in ("", ".", ".."):
        return False
    if any(c in "/\\:" or c < " " for c in value) or value[-1] in ". ":
        return False
    device = value.split(".")[0].upper()
    return not (device in ("CON", "PRN", "AUX", "NUL")
                or (len(device) == 4 and device[:3] in ("COM", "LPT")
                    and device[3] in "123456789¹²³"))


def manifest_refusal(manifest):
    """The sentence that refuses a manifest whose shape this verifier
    cannot judge, or None when every field is what the format says. A
    refusal is never a verdict (ADR-0007 ruling 5): the recipient learns
    the package is not one this verifier reads, and nothing else."""
    if not isinstance(manifest, dict):
        return "manifest.json is not an object"
    tag = manifest.get("format")
    if tag != PACKAGE_FORMAT:
        return f'package is format "{tag}"; this verifier speaks "{PACKAGE_FORMAT}"'
    if not isinstance(manifest.get("unit"), dict):
        return "manifest.json has no unit"
    chains = manifest.get("chains")
    if not isinstance(chains, list) or not chains:
        return "manifest.json lists no chain; a package without one is not a package"
    for listing in chains:
        if not (isinstance(listing, dict) and bare_name(listing.get("path"))
                and isinstance(listing.get("head"), str)
                and isinstance(listing.get("entries"), int)):
            return ("manifest.json lists a chain without a bare file name, "
                    "a head, and an entry count")
        # A transcript named on a chain (--transcript, ADR-0026 ruling 2)
        # is a file of this package like any other: a bare name only.
        if listing.get("transcript") is not None \
                and not bare_name(listing["transcript"]):
            return ("manifest.json names a transcript on a chain that is "
                    "not a bare file name")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return "manifest.json has no artifacts list"
    for listing in artifacts:
        if not (isinstance(listing, dict) and bare_name(listing.get("path"))
                and isinstance(listing.get("sha256"), str)
                and isinstance(listing.get("bytes"), int)):
            return ("manifest.json lists an artifact without a bare file "
                    "name, a sha256, and a byte count")
    # The transcript's bytes are committed by the artifacts list and
    # nowhere else (one commitment home per fact), so a chain naming a
    # transcript the artifacts do not list names a file nothing vouches for.
    listed = {listing["path"] for listing in artifacts}
    for listing in chains:
        named = listing.get("transcript")
        if named is not None and named not in listed:
            return (f"manifest.json names transcript {named} on a chain, "
                    "and its artifacts do not list it")
    seals = manifest.get("seals")
    if not isinstance(seals, list) or not all(isinstance(k, str) for k in seals):
        return ("manifest.json declares no seal set; a stripped seal is "
                "judged against the declared set (ADR-0007)")
    return None


def read_manifest(folder):
    """(manifest, None), or (None, the refusal line). The manifest sits
    at the top of the folder; a missing or unreadable one, an unknown
    format tag, and a shape this verifier cannot judge are refusals, the
    way UNSUPPORTED-VERSION is."""
    try:
        # Read with the walk's guard (SPEC §6 step 1): a manifest giving
        # one key twice says two things, one to a reader keeping the
        # first and another to one keeping the last, and whatever this
        # verifier judged, the recipient's own tools may read the other
        # (#299).
        with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f, object_pairs_hook=object_with_each_key_once)
    except KeyGivenTwice as twice:
        return None, (f"UNSUPPORTED-FORMAT: manifest.json has key "
                      f"{visible(repr(twice.key))} given twice; no reading "
                      "of it is the manifest")
    except (OSError, ValueError, RecursionError):
        return None, ("UNSUPPORTED-FORMAT: no readable manifest.json at the "
                      "top of this package; not a loxodonta package")
    refusal = manifest_refusal(manifest)
    if refusal:
        return None, f"UNSUPPORTED-FORMAT: {refusal}"
    return manifest, None


def print_manifest_summary(path, manifest):
    """The manifest's displayed fields, testimony like every convenience
    copy (ADR-0007 ruling 3); the committed facts are judged below. The
    unit prints whatever it holds, so a later kind needs no new line."""
    unit = manifest["unit"]
    seals = manifest["seals"]
    print(f"package: {path}")
    print(f"format: {manifest['format']}")
    print(f"packed: {manifest.get('packed')} by {manifest.get('tool')} "
          "(testimony)")
    print("unit: " + ", ".join(f"{k} {v}" for k, v in unit.items()))
    print(f"contents: {len(manifest['chains'])} chain(s), "
          f"{len(manifest['artifacts'])} artifact(s), seals: "
          f"{', '.join(seals) if seals else 'none declared'}")


def walked_listing(log):
    """What the walk says about a packaged chain: its head, its line
    count, how many file references its entries carry, and how many
    transcript commitments it holds. The same walk verify uses; a chain
    is judged by walking, never by file hash (ADR-0026 ruling 3)."""
    lines = read_log(log)
    entries, _, _ = walk(lines)
    head = None
    references = 0
    for entry in entries:
        if entry is None:
            continue
        if isinstance(entry.get("entry_hash"), str):
            head = entry["entry_hash"]
        references += len(entry.get("files") or [])
    commitments = len(transcript_commitments(entries)[0])
    return head, len(lines), references, commitments


def judge_chain(folder, listing, chain_file=None, headers=None, used=None):
    """One chain of the package: the recorder's own verify, anchors and
    authority timestamps included, verbatim; then its walked head and
    length against the manifest's. `chain_file` is the authority's
    certificate chain the recipient saved, which `--authority-chain`
    gives and without which a packaged token is present and not judged.
    `headers` are `--block-header`'s, by root, and `used` the package's
    record of the roots they matched. Returns (findings, file references
    counted); a finding is (exit code, verdict word)."""
    name, head = listing["path"], listing["head"]
    print(f"chain: {name} (manifest: head {head[:12]}…, "
          f"{listing['entries']} entries)")
    log = os.path.join(folder, name)
    if not os.path.isfile(log):
        print(f"{name}: MISSING (listed in the manifest, not in the package)")
        return [(2, "ARTIFACT-DIVERGED")], 0
    # The packaged transcript the listing names, judged the way `verify
    # --transcript PATH` judges one: every commitment against its prefix,
    # the recorder's lines verbatim (ADR-0026 ruling 5, ADR-0017).
    named = listing.get("transcript")
    transcript = os.path.join(folder, named) if named else None
    if transcript is not None and not os.path.isfile(transcript):
        # The artifact judge reports the missing file; here only its
        # bare name, never a path of this machine.
        print(f"{named}: MISSING (named on this chain, not in the package); "
              "its commitments go unjudged")
        transcript = None
    # verify_log runs without the files check (a package carries no
    # working tree) and without a head the recipient was not given.
    # Stamps are judged as `verify --stamps` judges them (ADR-0032
    # ruling 5), but only when the manifest lists the sidecar: one it
    # does not vouch for is `unlisted` and judged by nobody, like every
    # unlisted file, so an older package without stamps verifies as it
    # always did. `mechanisms` carries back which exit-3 finding fired.
    mechanisms = []
    code = verify_log(log, transcript=transcript, anchors=True,
                      stamps=bool(listing.get("stamps")),
                      authority_chain=chain_file, block_headers=headers,
                      headers_used=set() if used is None else used,
                      mechanisms=mechanisms)
    if mechanisms:
        findings = [(3, word) for word in mechanisms]
    else:
        findings = [(code, CHAIN_WORDS[code])] if code in CHAIN_WORDS else []
    walked, count, references, commitments = walked_listing(log)
    if transcript is None and commitments and code != 5:
        # The chain committed a transcript this package does not carry:
        # the recorder's note for an absent transcript, and no verdict
        # from it (ADR-0017: absence is a note, never a verdict).
        print(f"TRANSCRIPT-UNRESOLVED: {commitments} transcript "
              "commitment(s) in this chain, no transcript in this package "
              "— commitments unjudgeable; chain verdict unaffected")
    if walked != head or count != listing["entries"]:
        print(f"{name}: off the manifest: walks to head "
              f"{(walked or 'none')[:12]}… with {count} lines, listed as "
              f"{head[:12]}… with {listing['entries']}")
        findings.append((2, "ARTIFACT-DIVERGED"))
    return findings, references


def judge_artifact(folder, listing):
    """One post-close artifact against the manifest: sha256 and byte
    count of the bytes as they are now, read in chunks. Returns True when
    it diverged. The witness snapshot is testimony, and the line says so
    where the file is judged: its bytes are checked, its words never are."""
    name = listing["path"]
    path = os.path.join(folder, name)
    try:
        digest = sha256_file(path)
        size = os.path.getsize(path)
    except OSError:
        print(f"{name}: MISSING (listed in the manifest, not in the package)")
        return True
    listed = listing["sha256"]
    if digest != listed or size != listing["bytes"]:
        print(f"{name}: DIVERGED from the manifest (sha256 {digest[:12]}…, "
              f"{size} bytes; listed {listed[:12]}…, "
              f"{listing['bytes']} bytes)")
        return True
    note = ""
    if name == "witness.json":
        note = (" (testimony: the packing machine's reading, unaltered; no "
                "verdict is drawn from it)")
    print(f"{name}: matches the manifest (sha256 {digest[:12]}…, "
          f"{size} bytes){note}")
    return False


def judge_manifest_anchor(folder, headers, used):
    """The anchor seal (ADR-0026 rulings 4 and 6), judged offline the way
    check_anchors judges a chain's: every record of
    manifest.json.anchors.jsonl must name this manifest's sha256 and
    replay, and a header the recipient gave checks its block. Returns
    (findings, height, block): the lowest height a completed proof
    names, or None while the rung is unearned, and the hash of the
    header that checked it, or None when that block was not checked.
    A checked block outranks a lower claimed one, since a claim nobody
    checked is not a lower bound on anything. Only the manifest's own
    anchor can earn the package rung; the chains' anchors printed above
    are detail, since they seal a different object."""
    manifest = os.path.join(folder, "manifest.json")
    digest = sha256_file(manifest)
    records = read_anchor_records(manifest)
    if records:
        # Only proofs and unreadable lines are judged (ADR-0038): a
        # sidecar holding only notes, or rows of kinds this verifier
        # does not know, holds no record, the same as an empty one.
        records = rows_to_judge("anchors", records,
                                "seal anchor: ANCHOR-UNKNOWN-KIND",
                                anchors_path("manifest.json"))
    if not records:
        what = "is not in this package" if records is None else "holds no record"
        print(f"seal anchor: SEAL-MISSING: {anchors_path('manifest.json')} "
              f"{what} — the manifest declares an anchor it does not carry")
        return [(3, "SEAL-MISSING")], None, None
    findings = []
    claimed = []   # (height, header hash or None), one per completed proof
    completed = set()
    pending = []
    for record in records:
        head = record.get("head") if record else None
        if not isinstance(head, str) or not isinstance(record.get("proof"), str):
            reason = "sidecar line is not an anchor record"
        elif head != digest:
            reason = (f"the proof is for digest {head[:12]}…, and this "
                      f"manifest's sha256 is {digest[:12]}…")
        else:
            try:
                verdict = judge_proof(head, base64.b64decode(record["proof"]))
            except (ProofError, KeyError, ValueError) as e:
                reason = str(e)
            else:
                if verdict[0] == "pending":
                    pending.append(record)
                    continue
                _, block, root = verdict
                print(attestation_words("seal anchor: ANCHORED: the manifest",
                                        block, root, headers, used))
                header = headers.get(root)
                claimed.append((block, header_hash(header) if header else None))
                completed.add(record.get("calendar"))
                continue
        print(f"seal anchor: SEAL-INVALID: {reason} — evidence that does "
              "not verify is not evidence")
        findings.append((3, "SEAL-INVALID"))
    for record in pending:
        if record.get("calendar") in completed:
            continue  # superseded by the upgraded record from that calendar
        if completed:
            # Some calendar settled this manifest, so the stragglers are
            # not work the recipient owes either (#199).
            print(f"seal anchor: ANCHOR-UNANSWERED: the manifest was "
                  f"submitted {record.get('ts')} via "
                  f"{record.get('calendar')}, which never came back; "
                  "another calendar settled it, so no upgrade is owed")
            continue
        print(f"seal anchor: ANCHOR-PENDING: the manifest was submitted "
              f"{record.get('ts')} via {record.get('calendar')} — unpack the "
              "package and run `loxodonta anchor --upgrade --manifest=<its "
              "manifest.json>` after a few hours; the rung is not earned "
              "until the proof completes")
    checked = [c for c in claimed if c[1] is not None]
    height, block = min(checked or claimed, key=lambda c: c[0],
                        default=(None, None))
    return findings, height, block


def judge_manifest_stamp(folder, chain_file):
    """The stamp seal (ADR-0032 rulings 4 and 5): every record of
    manifest.json.stamps.jsonl must be a token over this manifest's
    sha256 that openssl accepts against the certificate chain the
    recipient saved. Returns (findings, stamped, why): whether the rung
    is earned, and why nobody judged the seal when nobody did. A token
    this machine cannot judge, or whose certificate expired after it was
    issued (#264), is a note and never a verdict: the rung is neither
    earned nor failed. Only the manifest's own token can earn the
    package rung; the chains' tokens stamp a different object."""
    manifest = os.path.join(folder, "manifest.json")
    digest = sha256_file(manifest)
    records = read_stamp_records(manifest)
    if records:
        # Only tokens and unreadable lines are judged (ADR-0038): a
        # sidecar holding only notes, or rows of kinds this verifier
        # does not know, holds no record, the same as an empty one.
        records = rows_to_judge("stamps", records,
                                "seal stamp: STAMP-UNKNOWN-KIND",
                                stamps_path("manifest.json"))
    if not records:
        what = "is not in this package" if records is None else "holds no record"
        print(f"seal stamp: SEAL-MISSING: {stamps_path('manifest.json')} "
              f"{what} — the manifest declares an authority timestamp it "
              "does not carry")
        return [(3, "SEAL-MISSING")], False, None
    findings = []
    stamped = False
    why = None
    for record in records:
        head = record.get("head") if record else None
        if not isinstance(head, str) or \
                not isinstance(record.get("response"), str):
            reason = "sidecar line is not a stamp record"
        elif head != digest:
            reason = (f"the token is over digest {head[:12]}…, and this "
                      f"manifest's sha256 is {digest[:12]}…")
        else:
            try:
                reply = base64.b64decode(record["response"], validate=True)
            except ValueError:
                reason = "the response is not base64"
            else:
                verdict, detail = judge_stamp(head, reply, chain_file)
                if verdict == "stamped":
                    # The signer is the key the recipient's chain file
                    # certifies; the name in the record sits in a file
                    # the manifest does not list, so it is testimony.
                    print(f"seal stamp: STAMPED: a key certified by "
                          f"{chain_file} signed this manifest's sha256 under "
                          "its own clock (the record names "
                          f"{record.get('authority')}, testimony) — the time "
                          "inside the token is that key's word, not this "
                          "machine's (`openssl ts -reply -text` prints it)")
                    stamped = True
                    continue
                if verdict == "not judged":
                    why = detail
                    # A recipient whose certificate has expired holds
                    # openssl and the chain file already, so the usual
                    # pointer would send them after what they hold (#264).
                    if detail == STAMP_OUTLIVED:
                        after = ("no chain file earns it now: judging a "
                                 "token once its certificate has expired is "
                                 "long-term validation, which is not built "
                                 "(ADR-0032)")
                    elif detail == STAMP_NO_ATTIME:
                        after = ("an openssl whose `ts -verify` takes "
                                 "`-attime` tells a certificate that "
                                 "outlived the token from a token that "
                                 "fails on its own, and this command asks "
                                 "it once it can run it")
                    else:
                        after = ("openssl and the certificate chain you "
                                 "saved from that authority judge this "
                                 "seal, and `verify-package "
                                 "--authority-chain FILE` judges it once it "
                                 "has both")
                    print(f"seal stamp: not judged: {detail} — the rung is "
                          f"neither earned nor failed; {after}")
                    continue
                reason = detail
        print(f"seal stamp: SEAL-INVALID: {reason} — evidence that does "
              "not verify is not evidence")
        findings.append((3, "SEAL-INVALID"))
    # A token that holds earns the rung beside one nobody judged (one
    # that failed is a finding, and the gravest finding is the verdict).
    # The one nobody judged keeps its note on its own seal line above,
    # and the verdict does not carry it too, or it would say in one
    # sentence that the timestamp was judged and that it was not.
    return findings, stamped, None if stamped else why


def key_fingerprint(public_key):
    """The SHA256 fingerprint of a public key file, as ssh-keygen prints
    it (`ssh-keygen -lf`), or None when the file is not a key it reads.
    The fingerprint is the key's identity (ADR-0008 ruling 6); the
    comment ssh-keygen prints beside it is a name, and stays unread."""
    listed = subprocess.run(["ssh-keygen", "-lf", public_key],
                            capture_output=True, encoding="utf-8",
                            errors="replace")
    words = listed.stdout.split()
    if listed.returncode != 0 or len(words) < 2:
        return None
    return words[1]


def judge_manifest_signature(folder):
    """The issuer signature (ADR-0008; ADR-0026 rulings 4 and 6), judged
    by ssh-keygen and never by this file: the shipped public key becomes
    a one-line allowed-signers file under a fixed principal, and
    `ssh-keygen -Y verify` says whether manifest.json.sig is that key's
    signature over this manifest's exact bytes. Returns (findings, the
    key's fingerprint when the signature holds, else None, and why the
    seal was not judged, None when it was): a recipient whose ssh-keygen
    is missing, cannot run, or predates `-Y verify` is told so, and the
    rung is neither earned nor failed."""
    manifest = os.path.join(folder, "manifest.json")
    signature, public_key = manifest + ".sig", manifest + ".pub"
    absent = [os.path.basename(p) for p in (signature, public_key)
              if not os.path.isfile(p)]
    if absent:
        print(f"seal signature: SEAL-MISSING: {' and '.join(absent)} not in "
              "this package — the manifest declares a signature it does not "
              "carry")
        return [(3, "SEAL-MISSING")], None, None
    why = None
    try:
        fingerprint = key_fingerprint(public_key)
        if fingerprint is None:
            print("seal signature: SEAL-INVALID: manifest.json.pub is not a "
                  "public key ssh-keygen reads — a signature under no key "
                  "verifies nothing")
            return [(3, "SEAL-INVALID")], None, None
        with tempfile.TemporaryDirectory() as scratch:
            # The allowed-signers line ssh-keygen wants: a principal, then
            # the key's two tokens, type and key. The shipped file's own
            # tokens and nothing else, so what verifies is what shipped.
            allowed = os.path.join(scratch, "allowed_signers")
            with open(public_key, encoding="utf-8", errors="replace") as f:
                key = " ".join(f.readline().split()[:2])
            with open(allowed, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"{SIGNATURE_PRINCIPAL} {key}\n")
            with open(manifest, "rb") as shipped:
                verified = subprocess.run(
                    ["ssh-keygen", "-Y", "verify", "-f", allowed,
                     "-I", SIGNATURE_PRINCIPAL, "-n", SIGNATURE_NAMESPACE,
                     "-s", signature],
                    stdin=shipped, capture_output=True, encoding="utf-8",
                    errors="replace")
    except FileNotFoundError:
        why = "ssh-keygen is not on PATH"
    except PermissionError:
        why = "ssh-keygen cannot run here (permission denied)"
    else:
        if verified.returncode != 0 and "usage: ssh-keygen" in verified.stderr:
            # An option ssh-keygen does not know draws its usage text:
            # OpenSSH before 8.0 has no -Y, and a tool that is present is
            # not the same as a seal that was judged.
            why = "this ssh-keygen predates `-Y verify` (OpenSSH 8.0)"
    if why:
        print(f"seal signature: not judged: {why} — the rung is neither "
              "earned nor failed; OpenSSH 8.0 or later carries the tool, "
              "and this command judges the seal once it can run it")
        return [], None, why
    if verified.returncode != 0:
        reason = "; ".join(verified.stderr.strip().splitlines()) \
            or "ssh-keygen gave no reason"
        print(f"seal signature: SEAL-INVALID: {reason} — the signature is "
              "not the shipped key's over this manifest's bytes")
        return [(3, "SEAL-INVALID")], None, None
    print(f"seal signature: SIGNED (key: {fingerprint}): the manifest, and "
          "transitively every artifact it lists, was issued by the holder "
          "of that key and has not changed since signing — compare the "
          "fingerprint against a channel this package cannot rewrite")
    return [], fingerprint, None


def judge_seals(folder, manifest, chain_file=None, headers=None, used=None):
    """Each declared seal against what the package carries, in the
    declared order: the anchor, the authority timestamp and the
    signature are judged; a kind this verifier does not know is named as
    such and adds nothing to the verdict, so the recipient is never told
    a seal was checked when it was not. `headers` and `used` are the
    block headers and the roots they matched, as judge_chain has them.
    Returns (findings, earned): what the seals earned toward the rungs,
    as ceiling_lines reads it."""
    findings = []
    earned = {"height": None, "block": None, "key": None, "stamped": False,
              "unjudged": []}
    for kind in manifest["seals"]:
        found = []
        if kind == "anchor":
            found, earned["height"], earned["block"] = judge_manifest_anchor(
                folder, headers or {}, set() if used is None else used)
        elif kind == "stamp":
            found, earned["stamped"], why = judge_manifest_stamp(folder,
                                                                 chain_file)
            if why:
                earned["unjudged"].append(
                    f"its authority timestamp was not judged, since {why}")
        elif kind == "signature":
            found, earned["key"], why = judge_manifest_signature(folder)
            if why:
                earned["unjudged"].append(
                    f"its signature was not judged, since {why}")
        else:
            print(f"seal {kind}: declared; this verifier does not know the "
                  "kind, and does not judge it")
        findings += found
    return findings, earned


def seal_files(manifest):
    """The files the declared seals put beside the manifest, which the
    manifest cannot list because they are written after it."""
    files = set()
    if "anchor" in manifest["seals"]:
        files.add(anchors_path("manifest.json"))
    if "stamp" in manifest["seals"]:
        files.add(stamps_path("manifest.json"))
    if "signature" in manifest["seals"]:
        files.update(("manifest.json.sig", "manifest.json.pub"))
    return files


def print_unlisted(folder, manifest):
    """Files in the package the manifest does not list: named, not
    judged, so a reader is never misled by a file nothing vouches for.
    A declared seal's own file is judged above, not here."""
    listed = {"manifest.json"} | seal_files(manifest)
    listed.update(c["path"] for c in manifest["chains"])
    listed.update(a["path"] for a in manifest["artifacts"])
    for name in sorted(os.listdir(folder)):
        if name not in listed:
            print(f"unlisted: {name} (not in the manifest, not judged)")


def gravest(findings):
    """The gravest finding's (code, word) in the ladder's order; a package
    with no finding is SELF-CONSISTENT."""
    for code in PACKAGE_GRAVITY:
        for found, word in findings:
            if found == code:
                return code, word
    return 0, "SELF-CONSISTENT"


def series(items):
    """"A", "A, and B", "A, B, and C": one sentence's list."""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + ", and " + items[-1]


def ceiling_lines(manifest, earned):
    """The two closing lines of a package with no finding, the residual
    trust and then the verdict, from what the declared seals earned:
    `height` and `block` (the anchor's block, and its header hash when a
    header checked it), `stamped`, `key` (the signature's fingerprint)
    and `unjudged`. Rungs add their words in a fixed order: the anchor,
    then the authority timestamp (a proof is nobody's product, a token
    somebody's signed word), then the signature, whose words are
    ADR-0008's caged sentence and no other. What no seal earned rests on
    the issuer's word; the verdict names what a regeneration would also
    produce, and why the rung is unearned."""
    height, key, seals = earned["height"], earned["key"], manifest["seals"]
    block = earned["block"]
    stamped = earned["stamped"]
    rungs, given, trusted = "", "", ""
    unsaid = ["the record inside is true and complete"]
    if height is not None and block is not None:
        # A header the recipient gave holds the root the proof replays
        # to: the block is theirs, named by its hash, and its height is
        # the word of the attestation and of their header's source.
        rungs += " + ANCHORED"
        given += (", and the manifest existed by the block whose header "
                  f"hashes to {block}, which its anchor calls Bitcoin block "
                  f"{height}")
        trusted += (f", and it existed by Bitcoin block {height} if the "
                    "header given for it is that block's, which its hash "
                    f"{block} lets you check against a second source")
    elif height is not None:
        # The proof completes to an attestation, and nothing checked the
        # block it names (ruling 3 on #299): a claim, said as one.
        rungs += " + ANCHORED"
        given += (f", and the manifest's anchor claims Bitcoin block "
                  f"{height}, a block not checked here")
        trusted += (f", and it existed by Bitcoin block {height} if the "
                    "merkle root printed beside that block is the block's, "
                    "which --block-header checks")
    elif not stamped:
        unsaid.append("that it existed before today")
    if stamped:
        # With a token and no anchor, the time rests on the word of
        # whoever holds the signing key, and the residual trust states
        # that as a condition. The authority's name in the stamps record
        # is testimony, so the verdict names only what openssl checked
        # (as ADR-0008 ruling 4 does for the signature).
        rungs += " + STAMPED"
        given += (", and a key certified by the --authority-chain file "
                  "signed the manifest's sha256 under its own clock")
        trusted += (", and it existed by the time inside that token if the "
                    "holder of that key keeps an honest clock and sole "
                    "custody of the key; whose key it is rests on where you "
                    "got the chain file, never on the name the stamps "
                    "record gives")
    if key is not None:
        rungs += f" + SIGNED (key: {key})"
        given += (", and the manifest, and transitively every artifact it "
                  f"lists, was issued by the holder of key {key} and has not "
                  "changed since signing")
        trusted += (f", and it was issued by the holder of key {key} and has "
                    "not changed since signing, if that fingerprint matches "
                    "one the issuer published through a channel this "
                    "package cannot rewrite")
    else:
        unsaid.append("which key packed it")
    why = limit = ""
    if height is None:
        if not seals:
            why = ", since no seal is declared"
        elif "anchor" in seals:
            why = " until its manifest anchor completes"
        else:
            why = ", since no anchor is declared"
        alike = ("a regeneration re-signed with that key" if key
                 else "a wholesale regeneration")
        limit = f"; indistinguishable from {alike}{why}"
    for note in earned["unjudged"]:
        limit += f"; {note}"
    unjudged = "".join(f" {n[0].upper()}{n[1:]}." for n in earned["unjudged"])
    pause = "," if len(unsaid) > 1 else ""   # "That A, and B, rests"
    trust = ("residual trust: this package is unaltered since it was packed"
             f"{trusted}. That {series(unsaid)}{pause} rests on the issuer's "
             f"word alone{why}.{unjudged}")
    verdict = (f"SELF-CONSISTENT{rungs}: {PACKAGE_WORDS['SELF-CONSISTENT']}"
               f"{given}{limit}")
    return trust, verdict


def judge_package(shown, folder, chain_file=None, block_headers=None):
    """The ladder, in ADR-0026 ruling 5's order: the manifest's summary,
    each chain, the file references, each artifact, each declared seal,
    the unlisted files, one line of residual trust when the ladder allows
    it, and the package verdict last, so the last line is the verdict as
    it is for `verify`. `chain_file` is `--authority-chain`: the
    certificate chain the recipient saved from the authority, which every
    token in this package is judged against and without which each is a
    note (ADR-0032 ruling 5). `block_headers` are `--block-header`'s, by
    root, checked against every anchor the package carries; one that
    matched none of them is noted once, after the seals."""
    manifest, refusal = read_manifest(folder)
    if refusal:
        print(refusal)
        return 4
    print_manifest_summary(shown, manifest)
    findings = []
    references = 0
    headers, used = block_headers or {}, set()
    for listing in manifest["chains"]:
        found, counted = judge_chain(folder, listing, chain_file, headers,
                                     used)
        findings += found
        references += counted
    # Off the machine the project record points nowhere and FILES-
    # UNRESOLVED would be the honest line (ADR-0012); the package says
    # the same thing once, in plain words, instead of per chain.
    print(f"file references: {references} recorded, not checkable off the "
          "machine")
    if any([judge_artifact(folder, a) for a in manifest["artifacts"]]):
        findings.append((2, "ARTIFACT-DIVERGED"))
    found, earned = judge_seals(folder, manifest, chain_file, headers, used)
    findings += found
    note_unmatched_headers(headers, used)
    print_unlisted(folder, manifest)
    code, word = gravest(findings)
    if code != 0:
        print(f"{word}: {PACKAGE_WORDS[word]}")
        return code
    # The ceiling, with its limit and the residual trust, by what the
    # seals earned: `+ ANCHORED` is the manifest's anchor and no other's
    # (ADR-0026 ruling 6), `+ SIGNED` names a fingerprint and never a
    # name (ADR-0008 ruling 4).
    trust, verdict = ceiling_lines(manifest, earned)
    print(trust)
    print(verdict)
    return 0


# The characters a Windows unzip turns into `_` in a member's name.
WINDOWS_UNZIP_UNDERSCORES = str.maketrans(':<>|"?*', "_" * 7)


def landing_name(name):
    """The file a zip member's name unpacks to, folded so that two names
    landing on one file on any system compare equal: a drive or a
    `\\\\server\\share` prefix dropped and either slash a separator
    (Windows), empty, `.` and `..` segments dropped (every unzip), a
    segment's trailing dots and spaces dropped and `:<>|"?*` read as `_`
    (Windows), one Unicode normal form (macOS), and case folded (Windows
    and macOS). The fold is the union of those systems' rules, applied on
    every system, so a package's verdict never depends on where the
    recipient unpacks it; it folds a little more than any one system
    does, and a package the supervisor wrote, flat and plainly named,
    never comes near it (#299)."""
    import ntpath  # Windows's own path rules, the same on every system
    _, rest = ntpath.splitdrive(name.replace("/", "\\"))
    segments = (segment.rstrip(". ") for segment in rest.split("\\"))
    landed = "/".join(segment for segment in segments if segment)
    landed = landed.translate(WINDOWS_UNZIP_UNDERSCORES)
    return unicodedata.normalize("NFC", landed).casefold()


def one_file_twice(names):
    """The first two of a zip's member names that unpack to one file, or
    None. Unpacking writes both and keeps the last, while `unzip -p` and
    a zip reader that stops at the first show the first: a tampered
    chain ahead of the original verified SELF-CONSISTENT (#299)."""
    seen = {}
    for name in names:
        landed = landing_name(name)
        if landed in seen:
            return seen[landed], name
        seen[landed] = name
    return None


def cmd_verify_package(args):
    """`verify-package PATH`: a zip or an unpacked folder, the manifest at
    its top. A zip is unpacked into a temporary folder and judged there,
    so a Windows unzip and this command see the same bytes the same way;
    one that declares more than PACKAGE_MAX_BYTES unpacked, that holds
    two members unpacking to one file, or that is damaged past what its
    end record shows, is refused unopened."""
    import zipfile  # only this command reads zips; the hook never pays for it
    path = args.path
    headers = headers_by_root(args.block_header)
    if os.path.isdir(path):
        return judge_package(path, path, args.authority_chain, headers)
    if not os.path.isfile(path):
        print(f"error: {path} not found", file=sys.stderr)
        return EX_NOINPUT
    if not zipfile.is_zipfile(path):
        print(f"UNSUPPORTED-FORMAT: {path} is neither a folder nor a zip; "
              "not a loxodonta package")
        return 4
    with tempfile.TemporaryDirectory() as unpacked:
        try:
            with zipfile.ZipFile(path) as package:
                declared = sum(info.file_size for info in package.infolist())
                if declared > PACKAGE_MAX_BYTES:
                    print(f"UNSUPPORTED-FORMAT: {path} declares {declared} "
                          "bytes unpacked, more than this verifier will "
                          f"unpack ({PACKAGE_MAX_BYTES})")
                    return 4
                twice = one_file_twice(package.namelist())
                if twice is not None:
                    first, second = (visible(repr(name)) for name in twice)
                    which = (f"{first} twice" if twice[0] == twice[1]
                             else f"{first} and {second}")
                    print(f"UNSUPPORTED-FORMAT: {path} holds two members "
                          f"that unpack to one file, {which}; which one is "
                          "read depends on the tool that unpacks it, so "
                          "this verifier refuses it unopened")
                    return 4
                package.extractall(unpacked)
        # ValueError: a member whose name leaves nothing to unpack to,
        # such as `..`, which extractall refuses by raising.
        except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError,
                ValueError) as e:
            print(f"UNSUPPORTED-FORMAT: {path} could not be unpacked ({e}); "
                  "not a loxodonta package")
            return 4
        return judge_package(path, unpacked, args.authority_chain, headers)


# --- The verifier's command line ----------------------------------------------
# The three verbs a recipient needs, and the parsing both files share:
# the recorder's `main` adds them beside its writers, and `verifier_main`
# is the whole of verifier.py's command line.

def head_record(value):
    """argparse validator: a head record is 64 lowercase hex characters."""
    v = value.lower()
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a chain head (need 64 hex characters)"
        )
    return v


def block_header(value):
    """argparse validator: a block header is 80 bytes, given as 160 hex
    characters (`bitcoin-cli getblockheader HASH false` prints one)."""
    v = value.strip().lower()
    if len(v) != 2 * BLOCK_HEADER_BYTES \
            or any(c not in "0123456789abcdef" for c in v):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a block header (need 160 hex characters, "
            f"the {BLOCK_HEADER_BYTES} bytes of one)"
        )
    return bytes.fromhex(v)


def checkout_commit(home):
    """The short commit of the git checkout `home` sits in, or "unknown"
    when git cannot say: no git on this machine, no checkout around the
    file, or a question that failed. Local git only: a version is a
    label on the file, never a channel to fetch a newer one."""
    try:
        asked = subprocess.run(
            ["git", "-C", home, "rev-parse", "--short", "HEAD"],
            capture_output=True, encoding="utf-8")
    except (OSError, ValueError):
        return "unknown"
    return asked.stdout.strip() if asked.returncode == 0 else "unknown"


def version_line(prog, home):
    """Three identities on one line: tool, format, commit (ADR-0022)."""
    return (f"{prog} {TOOL_VERSION} (format {FORMAT_VERSION}, "
            f"commit {checkout_commit(home)})")


class VersionAction(argparse.Action):
    """`--version`, answered only when asked: the commit is one git
    question, and no other command pays for it."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        home = os.path.dirname(os.path.abspath(__file__))
        print(version_line(parser.prog, home))
        parser.exit()


def speak_utf8():
    """Write stdout and stderr in UTF-8, whatever the console dealt
    (#294): Windows hands a pipe cp1252, where one CJK character or
    emoji in a receipt killed the verb mid-output. Only the bytes change,
    never the text; a lone surrogate prints as its backslash escape. A
    stream without `reconfigure` (None under pythonw, or one an embedder
    swapped in) is left as it is."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


class UsageParser(argparse.ArgumentParser):
    """argparse, with usage errors on an exit of their own. A wrong flag, a
    missing argument, or a malformed value exits 64 instead of argparse's
    stock 2, so no exit a script reads as an answer is ever an argparse
    error (ADR-0026 ruling 7). The message is argparse's, unchanged, on
    stderr. Subparsers inherit this class, so every command speaks the
    same number."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, f"{self.prog}: error: {message}\n")


BLOCK_HEADER_HELP = (
    "a Bitcoin block header (80 bytes as 160 hex characters) from a "
    "source you trust, for the anchors (repeatable, one per anchored "
    "block): an anchor whose proof replays to the merkle root it holds "
    "existed by that block, named by its hash; without one, a block an "
    "attestation claims is reported as not checked")


def add_verify_commands(sub, common):
    """`head`, `verify` and `verify-package`, added to a command line. The
    recorder and the verifier both build their parsers from this one
    definition, so their flags cannot differ. Returns the verify parser,
    for the usage rule argparse cannot state (`verify_usage`)."""
    sub.add_parser("head", parents=[common],
                   help="print the chain head (record it out of the writer's reach)"
                   ).set_defaults(func=cmd_head)
    verify_parser = sub.add_parser("verify", parents=[common],
                                   help="walk the chain and report a verdict")
    verify_parser.add_argument("--files", action="store_true",
                               help="also compare referenced files against disk")
    verify_parser.add_argument("--expect-head", metavar="HEX", type=head_record,
                               help="operator-held head record to compare against")
    verify_parser.add_argument("--transcript", metavar="PATH", default=None,
                               help="judge transcript commitments against "
                                    "this harness transcript (ADR-0017); a "
                                    "missing file is noted, never a verdict")
    verify_parser.add_argument("--anchors", action="store_true",
                               help="also judge anchor proofs, offline")
    verify_parser.add_argument("--block-header", metavar="HEX",
                               type=block_header, action="append",
                               default=[], help=BLOCK_HEADER_HELP)
    verify_parser.add_argument("--stamps", action="store_true",
                               help="also judge authority timestamps, "
                                    "offline, through openssl (ADR-0032); "
                                    "without --authority-chain, or without "
                                    "openssl, each is noted as not judged")
    verify_parser.add_argument("--authority-chain", metavar="FILE",
                               default=None,
                               help="the authority's certificate chain "
                                    "(PEM) you saved, for --stamps. Every "
                                    "token is judged against this one "
                                    "file, so when the sidecar holds "
                                    "tokens from more than one authority, "
                                    "give one chain file holding every "
                                    "authority's certificates "
                                    "(concatenated PEM)")
    verify_parser.set_defaults(func=cmd_verify)
    package_parser = sub.add_parser(
        "verify-package",
        help="judge a package written by `supervisor package`, a zip or a "
             "folder, layer by layer: each chain verbatim, each artifact "
             "against the manifest, each declared seal (the anchor here, "
             "the signature through ssh-keygen), the package verdict last "
             "(ADR-0026)")
    package_parser.add_argument("path", metavar="PATH",
                                help="the package: a zip, or its unpacked "
                                     "folder")
    package_parser.add_argument("--authority-chain", metavar="FILE",
                                default=None,
                                help="the certificate chain (PEM) you saved "
                                     "from the authority, for the tokens "
                                     "this package carries (ADR-0032); "
                                     "without it a token is present and not "
                                     "judged, and the seal earns no rung. "
                                     "Every token in the package, the "
                                     "manifest's and each chain's, is "
                                     "judged against this one file, so when "
                                     "the records name more than one "
                                     "authority, give one chain file "
                                     "holding every authority's "
                                     "certificates (concatenated PEM)")
    package_parser.add_argument("--block-header", metavar="HEX",
                                type=block_header, action="append",
                                default=[], help=BLOCK_HEADER_HELP)
    package_parser.set_defaults(func=cmd_verify_package)
    return verify_parser


def verify_usage(args, verify_parser):
    """The usage rule for the verify verbs that argparse cannot state."""
    if args.command == "verify" and args.authority_chain and not args.stamps:
        # The operator who names a chain file named it in order to have
        # the tokens judged against it. Ignoring the flag would print
        # `VALID` with nothing judged, which is the one outcome ADR-0032
        # ruling 5 exists to prevent: a verdict that sounds like the
        # tokens passed. A command spoken wrong is told so, exit 64, as
        # a raw flag beside a named profile is.
        verify_parser.error("--authority-chain is the file --stamps judges "
                            "tokens against; add --stamps, or drop it")
    if args.command == "verify" and args.block_header and not args.anchors:
        # The same rule, for the same reason: a header was given to check
        # an anchor, and `VALID` with no anchor judged would sound like
        # it did.
        verify_parser.error("--block-header checks the blocks --anchors "
                            "judges; add --anchors, or drop it")


def verifier_main(argv=None):
    """verifier.py's command line (ADR-0035): the three verbs that judge,
    and nothing that writes, sends, stamps or installs."""
    # The docstring's first two paragraphs: what it is, what it judges.
    parser = UsageParser(prog="verifier",
                         description="\n\n".join(__doc__.split("\n\n")[:2]))
    parser.add_argument("--version", action=VersionAction,
                        help="print tool version, format version, and "
                             "the checkout's commit, then exit")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log", default=DEFAULT_LOG, help="receipt log path")
    sub = parser.add_subparsers(dest="command", required=True)
    verify_parser = add_verify_commands(sub, common)
    args = parser.parse_args(argv)
    verify_usage(args, verify_parser)
    return args.func(args)


def reader_gone(error):
    """True when `error` is the reader hanging up on stdout (`loxodonta
    report | head`). POSIX raises BrokenPipeError (EPIPE); Windows
    reports a plain EINVAL from the closed handle instead, so match on
    both or the quiet death is a traceback on half the platforms. EINVAL
    means nothing about pipes off Windows."""
    return isinstance(error, BrokenPipeError) or (
        os.name == "nt" and isinstance(error, OSError)
        and error.errno == errno.EINVAL)


def run_main(main):
    """Run a command line to its exit code, as both files' entry point.
    Two endings are not the command's own (ADR-0037). A reader that hung
    up gets a quiet 141, what a shell reports for that: never 0 (VALID)
    or 1 (BROKEN), since the unread lines were never judged. A crash
    prints its traceback to stderr and exits 70, sysexits' internal
    error, so it is never read as a verdict. SystemExit (argparse's 64,
    `--version`'s 0) and Ctrl-C pass through as Python ends them."""
    try:
        speak_utf8()  # before anything prints
        code = main()
    except Exception as e:  # noqa: BLE001 - every failure gets its exit
        if not reader_gone(e):
            traceback.print_exc()
            sys.exit(EX_SOFTWARE)
        # Give the interpreter a sink to flush into, or shutdown re-raises.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(EXIT_READER_GONE)
    sys.exit(code)


if __name__ == "__main__":
    run_main(verifier_main)
