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
import unicodedata
from datetime import datetime, timezone

# Two versions, moving independently (ADR-0022): TOOL_VERSION says which
# recorder is running; FORMAT_VERSION says which chains it can read. The
# format is frozen (SPEC §2.1); the tool is tagged at every promotion,
# together with supervisor.py — the two constants must agree.
TOOL_VERSION = "0.8.1"
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
    else exactly as it stands (#292).

    A lone surrogate is half of a UTF-16 pair with no other half. JSON
    lets a model type one into any tool argument, and POSIX hands Python
    one for every byte of argv or a file name that is not UTF-8. It has
    no UTF-8 form, so the canonical form above cannot hold it: the
    append used to die in a traceback, leaving no receipt while the
    chain went on verifying VALID. Written as escape text, the receipt
    says what was sent and the format does not change. The codec's
    backslashreplace is exactly that rule, since a lone surrogate is the
    only thing UTF-8 cannot encode. Every string an entry takes from
    outside passes through here: actor, action, file paths."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


# --- Reading a chain ----------------------------------------------------------
# The log's lines, the tail, and the files an entry names, read and
# never written.

def read_log(path):
    """All lines of the receipt log; FileNotFoundError if it doesn't exist."""
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def read_log_to_judge(path):
    """`read_log` for the readers that walk the chain (verify, report,
    explain, the package's walk). A byte that is not UTF-8 arrives as a
    lone surrogate (surrogateescape) instead of ending the whole read in
    a traceback, so the walk can refuse the one line it sits on by name
    (SPEC §6). The recorder only ever writes ASCII lines, so no line it
    wrote is read any differently."""
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return f.read().splitlines()


def missing_log(path):
    print(f"error: {path} not found — run `loxodonta init` first", file=sys.stderr)
    return 1


def tail_entry(lines):
    """The chain's final entry, or None if the tail is damaged. Two shapes
    of damage, both innocent (ADR-0004): a torn tail, the line left
    partial by a crash or an overlapping append; and a forked tail, a
    well-formed entry whose `n` is not its line number, which is what a
    lock taken from a paused holder leaves behind: two entries claiming
    one `n`. Neither can be built on. A new entry laid over a fork would
    bury an innocent race under later receipts until it read as
    tampering in the middle of the file, so the fork ends the chain the
    way a tear does, and damage stays at the tail, where the readers
    that name it honestly expect it (SPEC §6, §8)."""
    if not lines:
        return None
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError:
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


def shape_problem(entry):
    """The first way `entry`'s values fail SPEC §2's types, named; None
    when each is of its type. Type only: whether a string is hex, or a
    timestamp well-formed, is the hash comparison's and the reader's
    business, and a mistyped value is what makes a reader crash."""
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
    return None


# Receipt text is written by the agent under observation, and report
# prints it to a terminal, explain hands it to a model, and verify's
# messages name a writer's odd field names to whoever reads the verdict,
# recall's agents among them (#295). A newline could forge a timeline
# row, a verdict line or a line that reads as an order, an ANSI sequence
# can clear or recolour the screen, and a bidi override reorders what
# the eye sees. So every such character is printed as its escape.
# Which characters: every one whose Unicode category says it steers
# rather than reads. Cc is the controls (C0 with tab, newline and
# carriage return among them, DEL, C1 with NEL among them); Cf the format
# characters (the bidi marks, embeddings, overrides and isolates, the
# Arabic letter mark, zero-width spaces and joiners, the byte-order mark,
# and the tag characters a model reads and a person does not see); Cs a
# lone surrogate, which JSON allows as `\ud800` and no encoder accepts;
# Zl and Zp the line and paragraph separators. An emoji built with a
# zero-width joiner prints as its parts and a `\u200d`: the price of
# naming the category rather than listing characters.
# Display only: verify hashes the raw entry. A backslash stays as it is,
# so the chain file is where the exact bytes are read. The twin of
# supervisor.py's `visible`, which every recall surface uses; the files
# never import each other (ADR-0035), and tests/test_suite_shape.py
# holds the two copies equal. It sits above `walk`, which calls it.
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


def walk(lines):
    """The mechanical walk of SPEC §6, shared by verify (which judges) and
    report (which narrates). Returns (entries, breaks, warns): entries[n] is
    the parsed entry or None where the line is unparseable or is not the
    shape of an entry; breaks and warns are (n, message) lists in walk
    order."""
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
            # A byte that is not UTF-8 arrives from `read_log_to_judge`
            # as a lone surrogate, the one thing UTF-8 cannot encode.
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
        if set(entry) != expected_fields:
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
        wrong = shape_problem(entry)
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
        if entry.get("n") != n:
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
        ts = entry.get("ts")
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


def sidecar_path(log, suffix):
    """A file beside a chain that is not a chain: the anchor sidecar,
    the publish memo. Named after the chain so the two travel together."""
    return log + suffix


def anchors_path(log):
    return sidecar_path(log, ".anchors.jsonl")


def read_sidecar_records(path):
    """The records of one sidecar, or None when the file does not exist
    (every sidecar is optional). A line that is not a JSON object reads
    as None, so a judge can name it rather than skip it."""
    try:
        lines = read_log(path)
    except FileNotFoundError:
        return None
    records = []
    for line in lines:
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                record = None
        except json.JSONDecodeError:
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
# Every session-end step that reaches off the machine is quiet on failure
# (ADR-0024 ruling 3, ADR-0025): an exit hook that complains is noise
# nobody can act on. Quiet at the moment and silent in the record are
# different choices, so after each step the recorder writes down how it
# went, in the sidecar the step already owns: the anchors sidecar for the
# anchor, the publish memo for the head. One row of kind `attempt`,
# carrying the step, the time, the budget it had, and the outcome, which
# is `submitted` or `sent`, or the one line the bounded call produced.
# Never the URL: a webhook URL is a credential. The row is testimony and
# never a proof: every reader that judges (`verify --anchors`, the
# keeper, `verify-package`) skips it by its kind, and the supervisor
# reads it to say when a head last left the machine and when the last
# attempt failed. The chain's schema is untouched.

ATTEMPT_KIND = "attempt"


def is_attempt(record):
    """True for a row of kind `attempt`: a note on how a session-end
    step went, never a proof and never a sent head. Readers that judge
    skip these rows; readers that report use them."""
    return isinstance(record, dict) and record.get("kind") == ATTEMPT_KIND


# --- Judging anchors (docs/ANCHORING.md §3) -----------------------------------

def check_anchors(log, entries):
    """The --anchors half of verify (docs/ANCHORING.md §3): judge every
    sidecar record against the chain, offline. Returns True if any record
    is evidence against this log (mismatch or invalid — exit-3 tier)."""
    records = read_anchor_records(log)
    if records is None:
        print(f"NO-ANCHORS: {anchors_path(log)} not found — anchoring is "
              "optional; run `loxodonta anchor` to add one")
        return False
    hash_to_n = {e["entry_hash"]: e["n"] for e in entries}

    judged = []
    for record in records:
        if is_attempt(record):
            continue  # a note on how a step went, not evidence (#240)
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
            print(f"ANCHORED: entries 0..{hash_to_n[record['head']]} existed "
                  f"by Bitcoin block {height} — confirm merkle root "
                  f"{root[::-1].hex()} against a block source you trust")
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
    token and this reads one line of what openssl printed, the way
    openssl_reason reads its errors, so the recorder still never parses
    a token (ADR-0032 ruling 4).

    `-token_out` is what keeps the writer from choosing the moment. The
    reply around the token carries a status text nobody signed, kept in
    a sidecar the writer can edit, and without the flag openssl prints
    it first and verbatim, so a line break in it could set a `Time
    stamp:` line of the writer's own ahead of the authority's (#264).
    With it openssl prints the signed token alone, and a second such
    line can only be one the authority signed or one that breaks the
    signature, so two of them is a time nobody can read."""
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
    chain has expired (#264). openssl checks the chain as of the moment
    it verifies, so a genuine token fails this way on the calendar alone;
    and it checks the certificate before the signature, so a token
    tampered with fails this way too. The same check as of the time the
    token states tells them apart. Passing, the certificate was in date
    when the token was issued and the calendar is the only reason: that
    is a note and never a verdict, and never STAMPED either, since a key
    whose certificate has run out is vouched for by nobody now, and
    whoever holds it could sign any past time they liked (long-term
    validation is not built, ADR-0032). Failing, the token has a reason
    of its own, and that is the verdict.

    An openssl that can be asked about no moment but now gets ADR-0026's
    posture for an ssh-keygen that predates `-Y verify`, before anything
    else is read: nothing could be judged, so it is not judged, and why.
    A token whose time cannot be read keeps openssl's first refusal:
    openssl decoded it to check its chain, and every token carries
    exactly one time, so a time printed as `Bad time value`, or missing,
    or twice over, is the token's fault and not this machine's."""
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
    for record in records:
        if is_attempt(record):
            continue  # a note on how a step went, not evidence (#240)
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
               mechanisms=None):
    """The walk of one chain, then whatever the checks add, then the
    verdict as the exit code: `verify PATH` and the package judge both
    call this, each with the checks it asked for. `mechanisms` is the
    package judge's out-parameter and nobody else's: it collects the
    exit-3 findings' words, because a package names the mechanism in its
    own verdict line and "anchor" is never the word for an authority
    timestamp (ADR-0032 ruling 1)."""
    try:
        lines = read_log_to_judge(log)
    except FileNotFoundError:
        return missing_log(log)
    if not lines:
        print(f"error: {log} is empty — not a receipt log", file=sys.stderr)
        return 1

    # SPEC §2.1: read the genesis version before applying any other rule.
    # The refusal is only for a *claimed* version we don't speak. A genesis
    # with no version claim at all (damaged, non-object, or v stripped) is
    # the walk's business — that's tampering to judge, not a dialect to
    # politely decline.
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
        # Escape text, so a claim holding a lone surrogate prints (#292).
        claimed = receipt_text(str(log_version))
        print(
            f'UNSUPPORTED-VERSION: log is format "{claimed}"; '
            f'this verifier speaks "{FORMAT_VERSION}"'
        )
        return 4

    entries, breaks, warns = walk(lines)
    for _, message in warns:
        print(message, file=sys.stderr)
    if breaks:
        for _, message in breaks:
            print(message)
        return 1

    diverged = 0
    if files:
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
    anchors_bad = anchors and check_anchors(log, entries)
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
    if expect_head is not None and chain_head != expect_head:
        # Internally consistent, but not the chain the operator recorded —
        # the signature of whole-chain regeneration.
        print(f"HEAD-MISMATCH: chain head is {chain_head}, expected "
              f"{expect_head} — this is not the recorded history")
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


def cmd_verify(args):
    """`verify PATH`: the flags, handed to the one walk."""
    return verify_log(args.log, files=args.files,
                      expect_head=args.expect_head,
                      transcript=args.transcript, anchors=args.anchors,
                      stamps=args.stamps,
                      authority_chain=args.authority_chain)


def cmd_head(args):
    try:
        lines = read_log(args.log)
    except FileNotFoundError:
        return missing_log(args.log)
    if not lines:
        print(f"error: {args.log} is empty — no chain head to print", file=sys.stderr)
        return 1
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
# The exit-3 tier holds two mechanisms now, the anchor's and the
# authority timestamp's, and a chain's verify exit alone cannot say which
# fired; `verify_log` hands the word back through `mechanisms`, and this
# table is the fallback for an exit with no word beside it.
CHAIN_WORDS = {1: "CHAIN-BROKEN", 3: "ANCHOR-MISMATCH",
               4: "UNSUPPORTED-FORMAT", 5: "TRANSCRIPT-DIVERGED"}
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
    flat, and a path that could leave the package (a folder, `..`, an
    absolute path, a backslash) is refused, never followed."""
    return (isinstance(value, str) and value not in ("", ".", "..")
            and "/" not in value and "\\" not in value
            and value == os.path.basename(value))


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
        with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
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
    lines = read_log_to_judge(log)
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


def judge_chain(folder, listing, chain_file=None):
    """One chain of the package: the recorder's own verify, anchors and
    authority timestamps included, verbatim; then its walked head and
    length against the manifest's. `chain_file` is the authority's
    certificate chain the recipient saved, which `--authority-chain`
    gives and without which a packaged token is present and not judged.
    Returns (findings, file references counted); a finding is (exit code,
    verdict word)."""
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
    # The checks `verify_log` runs are named here: never the files, since
    # a package carries no working tree, and never a head the recipient
    # was not given. The packaged stamps sidecar is judged exactly as
    # `verify --stamps` judges one (ADR-0032 ruling 5): through openssl
    # against the chain file the recipient named, or as an honest note
    # when they named none. Only when the manifest lists it, though: a
    # sidecar the manifest does not vouch for is named `unlisted` and
    # judged by nobody, which is the rule every other unlisted file
    # follows, and a package from before stamps travelled verifies as it
    # always did, with no NO-STAMPS line pointing a recipient at a
    # temporary copy.
    # `mechanisms` carries back which of the two exit-3 findings fired,
    # since the package names it.
    mechanisms = []
    code = verify_log(log, transcript=transcript, anchors=True,
                      stamps=bool(listing.get("stamps")),
                      authority_chain=chain_file, mechanisms=mechanisms)
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


def judge_manifest_anchor(folder):
    """The anchor seal (ADR-0026 rulings 4 and 6), judged offline the way
    check_anchors judges a chain's: every record of
    manifest.json.anchors.jsonl must name this manifest's sha256 and
    replay. Returns (findings, height): the lowest block a completed
    proof reached, or None while the rung is unearned. Only the
    manifest's own anchor can earn the package rung; the chains' anchors
    printed above are detail, since they seal a different object."""
    manifest = os.path.join(folder, "manifest.json")
    digest = sha256_file(manifest)
    records = read_anchor_records(manifest)
    if records:
        # Attempt rows are notes, never proofs (#240): a sidecar holding
        # only notes holds no record, the same as an empty one.
        records = [r for r in records if not is_attempt(r)]
    if not records:
        what = "is not in this package" if records is None else "holds no record"
        print(f"seal anchor: SEAL-MISSING: {anchors_path('manifest.json')} "
              f"{what} — the manifest declares an anchor it does not carry")
        return [(3, "SEAL-MISSING")], None
    findings = []
    height = None
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
                print(f"seal anchor: ANCHORED: the manifest existed by "
                      f"Bitcoin block {block} — confirm merkle root "
                      f"{root[::-1].hex()} against a block source you trust")
                height = block if height is None else min(height, block)
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
    return findings, height


def judge_manifest_stamp(folder, chain_file):
    """The stamp seal (ADR-0032 rulings 4 and 5, in ADR-0026 ruling 6's
    shape): every record of manifest.json.stamps.jsonl must be a token
    over this manifest's sha256, and openssl must accept it against the
    certificate chain the recipient saved. Returns (findings, stamped,
    why): whether the rung is earned, and why nobody judged the seal
    when nobody did. A token this machine cannot judge, or one whose
    certificate has expired since it was issued (#264), is a note and
    never a verdict, the issuer signature's exact posture — the rung is
    neither earned nor failed. Only the manifest's own token can earn
    the package rung; the chains' tokens printed above are detail, since
    they stamp a different object."""
    manifest = os.path.join(folder, "manifest.json")
    digest = sha256_file(manifest)
    records = read_stamp_records(manifest)
    if records:
        # Attempt rows are notes, never tokens (#240).
        records = [r for r in records if not is_attempt(r)]
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


def judge_seals(folder, manifest, chain_file=None):
    """Each declared seal against what the package carries, in the
    declared order: the anchor, the authority timestamp and the
    signature are judged; a kind this verifier does not know is named as
    such and adds nothing to the verdict, so the recipient is never told
    a seal was checked when it was not. Returns (findings, earned): what
    the seals earned toward the rungs, as ceiling_lines reads it."""
    findings = []
    earned = {"height": None, "key": None, "stamped": False, "unjudged": []}
    for kind in manifest["seals"]:
        found = []
        if kind == "anchor":
            found, earned["height"] = judge_manifest_anchor(folder)
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
    trust and then the verdict, built from what the declared seals
    earned: `height`, the block the manifest anchor reached; `stamped`,
    whether openssl accepted the authority's token over the manifest;
    `key`, the fingerprint the signature verified under; `unjudged`, the
    seals this machine could not judge. Each rung adds its words in
    ADR-0007's order, the two *when* seals before the signature (which
    key), and the anchor before the authority timestamp, because an
    anchor's proof is nobody's product where a token is somebody's
    signed word (ADR-0032 ruling 1); the signature's words are
    ADR-0008's caged sentence and no other. What no seal earned is named
    as resting on the issuer's word (ADR-0026 ruling 6). The ceiling
    verdict carries its limit: what a regeneration would also produce,
    and why the rung is unearned."""
    height, key, seals = earned["height"], earned["key"], manifest["seals"]
    stamped = earned["stamped"]
    rungs, given, trusted = "", "", ""
    unsaid = ["the record inside is true and complete"]
    if height is not None:
        rungs += " + ANCHORED"
        given += f", and the manifest existed by Bitcoin block {height}"
        trusted += (f", and it existed by Bitcoin block {height} if the "
                    "merkle root printed beside that block is the block's")
    elif not stamped:
        unsaid.append("that it existed before today")
    if stamped:
        # With a token and no anchor, when is not unsaid: it is said by
        # whoever holds the key that signed it, and what it rests on is
        # that holder's word, which the residual trust states as the
        # condition it is rather than letting the rung sound like the
        # anchor's. The manifest names no authority, and the name in the
        # stamps record is testimony, so the verdict says what openssl
        # checked and no name at all, as ADR-0008 ruling 4 has it for
        # the signature.
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


def judge_package(shown, folder, chain_file=None):
    """The ladder, in ADR-0026 ruling 5's order: the manifest's summary,
    each chain, the file references, each artifact, each declared seal,
    the unlisted files, one line of residual trust when the ladder allows
    it, and the package verdict last, so the last line is the verdict as
    it is for `verify`. `chain_file` is `--authority-chain`: the
    certificate chain the recipient saved from the authority, which every
    token in this package is judged against and without which each is a
    note (ADR-0032 ruling 5)."""
    manifest, refusal = read_manifest(folder)
    if refusal:
        print(refusal)
        return 4
    print_manifest_summary(shown, manifest)
    findings = []
    references = 0
    for listing in manifest["chains"]:
        found, counted = judge_chain(folder, listing, chain_file)
        findings += found
        references += counted
    # Off the machine the project record points nowhere and FILES-
    # UNRESOLVED would be the honest line (ADR-0012); the package says
    # the same thing once, in plain words, instead of per chain.
    print(f"file references: {references} recorded, not checkable off the "
          "machine")
    if any([judge_artifact(folder, a) for a in manifest["artifacts"]]):
        findings.append((2, "ARTIFACT-DIVERGED"))
    found, earned = judge_seals(folder, manifest, chain_file)
    findings += found
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


def cmd_verify_package(args):
    """`verify-package PATH`: a zip or an unpacked folder, the manifest at
    its top. A zip is unpacked into a temporary folder and judged there,
    so a Windows unzip and this command see the same bytes the same way;
    one that declares more than PACKAGE_MAX_BYTES unpacked, or that is
    damaged past what its end record shows, is refused unopened."""
    import zipfile  # only this command reads zips; the hook never pays for it
    path = args.path
    if os.path.isdir(path):
        return judge_package(path, path, args.authority_chain)
    if not os.path.isfile(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 1
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
                package.extractall(unpacked)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as e:
            print(f"UNSUPPORTED-FORMAT: {path} could not be unpacked ({e}); "
                  "not a loxodonta package")
            return 4
        return judge_package(path, unpacked, args.authority_chain)


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


def checkout_commit(home):
    """The short commit of the checkout `home` sits in, or "unknown" —
    the same fact the recorder notice reports (ADR-0015). Local git only:
    a version is a label on the file, never a channel to fetch a newer
    one."""
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
    question, and the hook path must not pay for it on every call."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        home = os.path.dirname(os.path.abspath(__file__))
        print(version_line(parser.prog, home))
        parser.exit()


EX_USAGE = 64  # sysexits(3) EX_USAGE: the command was spoken wrong


def speak_utf8():
    """Write stdout and stderr in UTF-8, whatever encoding the console
    dealt (#294). Windows hands a piped stdout its ANSI code page, cp1252,
    which has no CJK and no emoji: one such character in a receipt killed
    the verb mid-output with UnicodeEncodeError, and a hook reading
    through a pipe got nothing. The text printed is unchanged; only its
    bytes are. UTF-8 carries every character but a lone surrogate (a file
    name that did not decode), which backslashreplace prints as its
    escape rather than crash on. A stream without `reconfigure` (None
    under pythonw, or one an embedder swapped in) is left as it is."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


class UsageParser(argparse.ArgumentParser):
    """argparse, with usage errors on an exit of their own. A wrong flag, a
    missing argument, or a malformed value exits 64 instead of argparse's
    stock 2, so no verdict exit is ever an argparse error (ADR-0026
    ruling 7). The message is argparse's, unchanged, on stderr. Subparsers
    inherit this class, so every command speaks the same number."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, f"{self.prog}: error: {message}\n")


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


def run_main(main):
    """Run a command line to its exit code, as both files' entry point."""
    try:
        speak_utf8()  # before anything prints
        sys.exit(main())
    except OSError as e:
        # The reader hung up (`loxodonta report | head`) — no verdict was
        # asked of the lines that went unread; die quietly, not loudly.
        # (This exit 1 reuses a verdict number, the only one left now that
        # usage errors exit 64 on their own, so scripts should trust the
        # stdout verdict line, never the exit code alone.)
        # POSIX raises BrokenPipeError (EPIPE); Windows reports a plain
        # EINVAL from the closed handle instead, so match on both or the
        # quiet death is a traceback on half the platforms.
        if not isinstance(e, BrokenPipeError) and not (
                os.name == "nt" and e.errno == errno.EINVAL):
            raise  # EINVAL means nothing about pipes off Windows: let it fly
        # Give the interpreter a sink to flush into, or shutdown re-raises.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)


if __name__ == "__main__":
    run_main(verifier_main)
