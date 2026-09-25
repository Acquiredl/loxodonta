#!/usr/bin/env python3
"""Write the conformance vectors (ADR-0035) into tests/vectors/.

    python tools/build_vectors.py           write the vectors and vectors.json
    python tools/build_vectors.py --check   exit 1 if a committed vector differs

A vector is a small chain file, or a package (SPEC section 10), and one
row of tests/vectors/vectors.json saying what running a verb on it must
give: the exit code and the last line of stdout. tests/test_vectors.py
runs every row against loxodonta.py and against verifier.py, and a second
implementation checks itself against the same rows
(tests/vectors/README.md).

The honest chains are written by the recorder itself, through its public
command line, with SOURCE_DATE_EPOCH pinning every timestamp, so two runs
give the same bytes. The lines no recorder writes (a key given twice, a
wrong type, a lone surrogate, another spelling of the same entry) are
built here, and hashed here by SPEC section 4's rules written out again,
never imported: every line the recorder wrote is hashed that way too, and
the build stops if the two disagree. The packages are assembled here as
`supervisor package` lays one out, from those chains, with every date
pinned; the anchored one carries a proof and a block header made up here,
as tests/test_anchor.py makes them, so no calendar is asked. The expected
verdicts are written out below, one row at a time, and never read back
from a run.
"""

import base64
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDER = ROOT / "loxodonta.py"
VECTORS = ROOT / "tests" / "vectors"
KEPT = {"README.md"}   # written by hand, never by this script

EPOCH = 1790164800   # 2026-09-23T12:00:00Z; each entry a minute later
NOTES = b"the notes, as they stood when they were logged\n"
TRANSCRIPT = (b'{"role":"user","text":"list the files"}\n'
              b'{"role":"assistant","text":"notes.txt"}\n'
              b'{"role":"user","text":"thanks"}\n')

# The action that needs every kind of escape SPEC section 4 pins: the
# quote and the backslash, the five controls JSON names (\b \t \n \f \r),
# the other controls (NUL, U+0001, U+001F), and then the characters that
# are emitted as they stand though another encoder might escape them:
# the solidus, DEL, NEL (U+0085), and the line and paragraph separators
# (U+2028, U+2029).
ESCAPES = ('say "hi" \\ then\nnext\ttab\rcr\bbs\fff \x00\x01\x1f'
           ' / \x7f \x85     end')
# The six ASCII characters the recorder writes for a lone surrogate
# (#292), which a verifier reads as plain text.
SURROGATE_TEXT = "read the file name caf\\udce9.txt"

# The packages (SPEC section 10). Every field the verifier does not judge
# is pinned too, so the manifest's bytes, and so its sha256, never move.
PACKAGE_FORMAT = "loxodonta-package/1"
PACKAGE_CHAIN = "receipts-vector.jsonl"
PACKED = "2026-09-23T12:10:00Z"
PACKER = "loxodonta supervisor 0.9.0"
PROJECT_RECORD = b'{"path": "/home/operator/vector-project"}\n'
PACKAGE_UNIT = {"kind": "session", "session": "vector", "project":
                "vector-project"}
ZIP_TIME = (2026, 9, 23, 12, 10, 0)

# The anchored package's made-up proof: the ops of a completed
# OpenTimestamps proof (docs/ANCHORING.md section 4), append a nonce,
# sha256, prepend and append, then the double sha256 that ends at a
# Bitcoin attestation. Its root goes into a made-up block header.
OTS_APPEND, OTS_PREPEND, OTS_SHA256 = b"\xf0", b"\xf1", b"\x08"
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")
PROOF_NONCE, PROOF_PREFIX, PROOF_SUFFIX = (b"vector-nonce", b"vector-prefix",
                                           b"vector-suffix")
PROOF_HEIGHT = 850123


# --- SPEC section 4, written out again ----------------------------------------

def canonical(entry):
    """The canonical form: keys sorted, compact, UTF-8, non-ASCII as it
    stands, only JSON's mandatory escapes (RFC 8785 section 3.2.2.2)."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sealed(entry):
    """`entry` with its entry_hash, computed over the rest."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return {**body, "entry_hash": hashlib.sha256(canonical(body)).hexdigest()}


def rechained(entries):
    """Each entry's prev set to the one before it and every hash
    recomputed: a chain regenerated whole, consistent inside."""
    out, prev = [], None
    for entry in entries:
        entry = sealed({**entry, "prev": prev})
        out.append(entry)
        prev = entry["entry_hash"]
    return out


def stored(entry):
    """The line as the recorder writes it: sorted keys, compact, and
    everything past ASCII as a JSON escape."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def raw(entry):
    """The same entry written with non-ASCII as UTF-8, as it stands."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def json_string(text, escape):
    """`text` as a JSON string literal, each character spelled by
    `escape` (a function returning its spelling, or None for as it is)."""
    return '"' + "".join(escape(c) or c for c in text) + '"'


def every_char_as_upper_hex(char):
    """Another spelling a JSON parser reads as the same string: every
    character a \\u escape, in uppercase hex, pairs for the astral ones."""
    data = char.encode("utf-16-be")
    return "".join("\\u%04X" % int.from_bytes(data[i:i + 2], "big")
                   for i in range(0, len(data), 2))


def other_hashing_spelling(char):
    """A canonical form a careless implementation might hash: every
    control as uppercase \\u hex (no short forms), and the separators
    and DEL escaped as well."""
    if char in '"\\':
        return "\\" + char
    if ord(char) < 0x20 or char in "\x7f\x85  ":
        return "\\u%04X" % ord(char)
    return None


def with_action_spelled(entry, spelling):
    """`entry`'s stored line with its action written as `spelling`."""
    marker = "ACTION-GOES-HERE"
    line = stored({**entry, "action": marker})
    return line.replace(json.dumps(marker), spelling)


# --- The recorder, driven through its command line ----------------------------

def recorded(workdir, steps):
    """A chain the recorder writes: `init`, then one `log` per step of
    (actor, action, files), each a minute after the last. Returns its
    lines, each checked against the hash written out above."""
    log = workdir / "chain.jsonl"
    if log.exists():
        log.unlink()

    def recorder(minute, *args):
        done = subprocess.run(
            [sys.executable, str(RECORDER), *args, "--log", str(log)],
            cwd=workdir, capture_output=True, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8",
                 "SOURCE_DATE_EPOCH": str(EPOCH + 60 * minute)})
        if done.returncode != 0:
            sys.exit(f"error: the recorder refused {args}: {done.stderr}")

    recorder(0, "init")
    for minute, (actor, action, files) in enumerate(steps, start=1):
        recorder(minute, "log", "--actor", actor, "--action", action,
                 *[arg for path in files for arg in ("--file", path)])
    data = log.read_bytes()
    lines = data.decode("utf-8").split("\n")
    if lines[-1] != "" or "\r" in data.decode("utf-8"):
        sys.exit("error: the recorder wrote a line this script cannot read")
    lines = lines[:-1]
    for line in lines:
        if sealed(json.loads(line)) != json.loads(line):
            sys.exit("error: the recorder and SPEC section 4 as written "
                     "here hash an entry differently:\n" + line)
    return lines


def entries_of(lines):
    return [json.loads(line) for line in lines]


# --- Packages (SPEC section 10), assembled as the supervisor lays one out ------

def package_files(chain_lines, seals=(), format_tag=PACKAGE_FORMAT):
    """A package of one chain and the project record, as {name: bytes},
    with the manifest written last listing them: the chain by its head
    and line count, the record by its sha256 and byte count."""
    chain = "".join(line + "\n" for line in chain_lines).encode("utf-8")
    manifest = {
        "format": format_tag,
        "packed": PACKED,
        "tool": PACKER,
        "unit": PACKAGE_UNIT,
        "chains": [{"path": PACKAGE_CHAIN,
                    "head": json.loads(chain_lines[-1])["entry_hash"],
                    "entries": len(chain_lines),
                    "anchors": None, "stamps": None}],
        "artifacts": [{"path": "project.json",
                       "sha256": hashlib.sha256(PROJECT_RECORD).hexdigest(),
                       "bytes": len(PROJECT_RECORD)}],
        "seals": list(seals),
    }
    return {PACKAGE_CHAIN: chain, "project.json": PROJECT_RECORD,
            "manifest.json": (json.dumps(manifest, indent=2) + "\n").encode()}


def ots_varint(n):
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | 0x80 if n else byte)
        if not n:
            return bytes(out)


def ots_varbytes(data):
    return ots_varint(len(data)) + data


def completed_proof():
    """A completed proof from any digest: each op is followed by the node
    it leads to, and the last node is the Bitcoin attestation."""
    return (OTS_APPEND + ots_varbytes(PROOF_NONCE) + OTS_SHA256
            + OTS_PREPEND + ots_varbytes(PROOF_PREFIX)
            + OTS_APPEND + ots_varbytes(PROOF_SUFFIX) + OTS_SHA256 + OTS_SHA256
            + b"\x00" + OTS_BITCOIN + ots_varbytes(ots_varint(PROOF_HEIGHT)))


def replayed_root(digest_hex):
    """completed_proof replayed by hand from `digest_hex`: the merkle root
    its attestation claims, in the order a block header stores it."""
    step = hashlib.sha256(bytes.fromhex(digest_hex) + PROOF_NONCE).digest()
    return hashlib.sha256(hashlib.sha256(
        PROOF_PREFIX + step + PROOF_SUFFIX).digest()).digest()


def block_header(root):
    """An 80-byte header in Bitcoin's layout holding `root` at bytes 36
    to 68. Made up: nothing checks that it was ever mined, and the
    verifier does not claim to."""
    return (struct.pack("<I", 0x20000000) + b"\x11" * 32 + root
            + struct.pack("<III", 1790165400, 0x17034219, 7))


def header_hash(header):
    """A header's hash as explorers print it: double sha256, reversed."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def zipped(members):
    """A zip of (name, bytes) members in the order given, stored, with
    every date and attribute pinned, so it is the same bytes on every
    system. A name given twice is written twice: that is a vector."""
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # zipfile warns on a name twice
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as package:
            for name, data in members:
                info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
                info.create_system = 3            # the same on every system
                info.external_attr = 0o644 << 16
                package.writestr(info, data)
    return out.getvalue()


# --- The vectors ----------------------------------------------------------------

def build(workdir):
    """Every vector file, as {path from tests/vectors/: bytes}, the
    manifest of rows among them."""
    (workdir / "notes.txt").write_bytes(NOTES)
    files = {"notes.txt": NOTES, "transcript.txt": TRANSCRIPT}
    rows = []

    def chain(name, lines, torn=None):
        text = "".join(line + "\n" for line in lines)
        files[name + ".jsonl"] = (text + (torn or "")).encode("utf-8")

    def row(name, verb, about, exit, line=None, prefix=None, more=(),
            log=None, **extra):
        entry = {"name": name, "about": about,
                 "args": [verb, *more, "--log", (log or name) + ".jsonl"],
                 "exit": exit}
        if prefix is None:
            entry["last_line"] = line
        else:
            entry["last_line_prefix"] = prefix
        rows.append({**entry, **extra})

    # The honest chain every tamper below starts from.
    base = recorded(workdir, [
        ("agent", "wrote the notes", ["notes.txt"]),
        ("human", "reviewed the notes", []),
        ("agent", "run: python -m unittest (exit 0)", []),
    ])
    e = entries_of(base)
    head = e[3]["entry_hash"]

    chain("genesis-only", base[:1])
    row("genesis-only", "verify", "A chain of its genesis alone.", 0, "VALID")
    row("genesis-only-head", "head", "The head of a genesis-only chain is "
        "the genesis entry's hash.", 0, e[0]["entry_hash"],
        log="genesis-only")

    chain("valid-chain", base)
    row("valid-chain", "verify", "Genesis and three entries, one with a "
        "file reference, as the recorder wrote them.", 0, "VALID")
    row("valid-chain-files", "verify", "The file reference checked against "
        "notes.txt beside the chain: CURRENT, then VALID.", 0, "VALID",
        more=["--files"], log="valid-chain")
    row("valid-chain-head", "head", "head prints the last entry's "
        "entry_hash.", 0, head, log="valid-chain")
    row("expect-head-match", "verify", "The head record matches the chain "
        "head.", 0, "VALID", more=["--expect-head", head], log="valid-chain")
    mismatch = e[2]["entry_hash"]
    row("expect-head-mismatch", "verify", "A head record from another "
        "chain: internally valid, but not the recorded history.", 3,
        f"HEAD-MISMATCH: chain head is {head}, expected {mismatch} — "
        "this is not the recorded history",
        more=["--expect-head", mismatch], log="valid-chain")

    edited = {**e[2], "action": "reviewed the notes and approved them"}
    chain("entry-edited", base[:2] + [stored(edited)] + base[3:])
    row("entry-edited", "verify", "Entry 2's action edited, its hash left "
        "as it was.", 1,
        "BROKEN at entry 2: entry_hash does not match canonical form")

    chain("entry-deleted", base[:2] + base[3:])
    row("entry-deleted", "verify", "Entry 2 removed: the next entry's n "
        "and prev no longer fit.", 1,
        "BROKEN at entry 2: prev does not match predecessor's entry_hash")

    chain("entries-swapped", [base[0], base[2], base[1], base[3]])
    row("entries-swapped", "verify", "Entries 1 and 2 swapped.", 1,
        "BROKEN at entry 3: prev does not match predecessor's entry_hash")

    chain("tail-truncated", base[:3])
    row("tail-truncated", "verify", "The last entry cut away cleanly: the "
        "rest walks clean, which is why a head record is kept.", 0, "VALID")
    row("tail-truncated-expect-head", "verify", "The same cut, against "
        "the head recorded before it.", 3,
        f"HEAD-MISMATCH: chain head is {e[2]['entry_hash']}, expected "
        f"{head} — this is not the recorded history",
        more=["--expect-head", head], log="tail-truncated")

    chain("tail-torn", base[:3], torn=base[3][:40])
    row("tail-torn", "verify", "The last line cut off mid-write, with no "
        "line ending: the signature of a crash, named as such.", 1,
        "BROKEN: torn tail at line 3 (crash-truncated append; entries "
        "0..2 intact)")
    row("tail-torn-head", "head", "A torn tail has no head: nothing on "
        "stdout, the reason on stderr.", 1, "", log="tail-torn")

    # The last-wins reading of this line is entry 3 exactly, hash and
    # all; a first-wins reader sees an action that says the tests failed.
    twice = '{"action":"run: python -m unittest (exit 1)",' + base[3][1:]
    chain("key-given-twice", base[:3] + [twice])
    row("key-given-twice", "verify", "Entry 3 names action twice; its hash "
        "holds for the last of the two.", 1,
        "BROKEN at entry 3: key 'action' given twice")

    chain("wrong-type-files", base[:3] + [stored(sealed(
        {**e[3], "files": "notes.txt"}))])
    row("wrong-type-files", "verify", "Entry 3's files is a string, with a "
        "hash that holds for it.", 1,
        "BROKEN at entry 3: files is not an array")

    chain("wrong-type-n", base[:3] + [stored(sealed({**e[3], "n": True}))])
    row("wrong-type-n", "verify", "Entry 3's n is true, a boolean, with a "
        "hash that holds for it.", 1, "BROKEN at entry 3: n is not an integer")

    wide = recorded(workdir, [("エージェント", "記録を書いた 🐘 象", [])])
    wide_entry = entries_of(wide)[1]
    chain("non-ascii", wide)
    row("non-ascii", "verify", "CJK and an emoji, stored as the recorder "
        "writes them: \\u escapes, the emoji as a surrogate pair. The "
        "canonical form holds them as UTF-8.", 0, "VALID",
        canonical={"entry": 1, "text": canonical(
            {k: v for k, v in wide_entry.items() if k != "entry_hash"}
        ).decode("utf-8")})
    chain("non-ascii-raw", [raw(entry) for entry in entries_of(wide)])
    row("non-ascii-raw", "verify", "The same entries stored as raw UTF-8: "
        "another spelling of the line, the same hashes.", 0, "VALID")
    row("non-ascii-raw-head", "head", "Its head is the non-ascii chain's "
        "head.", 0, wide_entry["entry_hash"], log="non-ascii-raw")

    genesis = entries_of(base[:1])[0]
    escaped = sealed({"n": 1, "ts": "2026-09-23T12:01:00Z", "actor": "agent",
                      "action": ESCAPES, "files": [],
                      "prev": genesis["entry_hash"]})
    escaped_body = {k: v for k, v in escaped.items() if k != "entry_hash"}
    chain("escapes", base[:1] + [stored(escaped)])
    row("escapes", "verify", "An action needing every escape SPEC section "
        "4 pins, exactly as RFC 8785 section 3.2.2.2 spells them: \\\" and "
        "\\\\, the short forms \\b \\t \\n \\f \\r, lowercase \\u00xx for the "
        "other controls, and DEL, NEL, U+2028 and U+2029 as they stand.",
        0, "VALID", canonical={"entry": 1, "text":
                               canonical(escaped_body).decode("utf-8")})

    upper = json_string(ESCAPES, every_char_as_upper_hex)
    chain("escapes-other-spelling",
          base[:1] + [with_action_spelled(escaped, upper)])
    row("escapes-other-spelling", "verify", "The same entry, its action "
        "stored as uppercase \\u escapes throughout: the line is spelled "
        "differently, the canonical form is not, and the hash holds.",
        0, "VALID")

    careless = canonical(escaped_body).decode("utf-8").replace(
        json.dumps(ESCAPES, ensure_ascii=False),
        json_string(ESCAPES, other_hashing_spelling))
    misspelled = {**escaped,
                  "entry_hash": hashlib.sha256(careless.encode()).hexdigest()}
    chain("escapes-hashed-wrong", base[:1] + [stored(misspelled)])
    row("escapes-hashed-wrong", "verify", "The same entry hashed over a "
        "canonical form that spells its controls as uppercase \\u hex and "
        "escapes DEL, NEL and the separators: what a verifier with other "
        "escaping would compute. It does not hold.", 1,
        "BROKEN at entry 1: entry_hash does not match canonical form")

    surrogate = sealed({"n": 1, "ts": "2026-09-23T12:01:00Z",
                        "actor": "agent", "action": SURROGATE_TEXT,
                        "files": [], "prev": genesis["entry_hash"]})
    chain("lone-surrogate-text", base[:1] + [stored(surrogate)])
    row("lone-surrogate-text", "verify", "The escape text the recorder "
        "writes for a lone surrogate (#292): six ASCII characters, "
        "canonical like any text.", 0, "VALID",
        canonical={"entry": 1, "text": canonical(
            {k: v for k, v in surrogate.items() if k != "entry_hash"}
        ).decode("utf-8")})
    lone = stored(surrogate).replace("\\\\udce9", "\\udce9")
    chain("lone-surrogate-json", base[:1] + [lone])
    row("lone-surrogate-json", "verify", "The same entry with the escape "
        "read as JSON: a lone surrogate, which has no UTF-8 form and so no "
        "canonical form.", 1, "BROKEN at entry 1: a string holds a lone "
        "surrogate, which has no canonical form")

    first = TRANSCRIPT.split(b"\n")[0] + b"\n"
    second = first + TRANSCRIPT.split(b"\n")[1] + b"\n"

    def commitment(prefix):
        return ("receipts", "transcript-commitment: bytes=%d sha256=%s"
                % (len(prefix), hashlib.sha256(prefix).hexdigest()), [])

    chain("transcript-commitment", recorded(workdir, [
        commitment(first), ("agent", "listed the files", []),
        commitment(second)]))
    row("transcript-commitment", "verify", "Two transcript commitments "
        "(SPEC section 2.2), byte counts growing: judged from the chain "
        "alone.", 0, "VALID")
    row("transcript-commitment-transcript", "verify", "The same chain "
        "against transcript.txt: both commitments hold, and the tail "
        "after them is stated.", 0, "VALID",
        more=["--transcript", "transcript.txt"], log="transcript-commitment")
    chain("transcript-commitment-shrank", recorded(workdir, [
        commitment(second), ("agent", "listed the files", []),
        commitment(first)]))
    row("transcript-commitment-shrank", "verify", "A later commitment of "
        "fewer bytes than an earlier one: a growing transcript never "
        "shrinks.", 5, "TRANSCRIPT-DIVERGED: chain intact, but a committed "
        "transcript prefix no longer holds")

    # The hashing is frozen across format versions (ADR-0036): a chain
    # whose genesis claims a version this verifier does not speak has its
    # hash chain walked all the same, and only its field rules go unjudged.
    refusal = ('UNSUPPORTED-VERSION: log is format "0.2"; this verifier '
               'speaks "0.1"')
    later = rechained([{**e[0], "v": "0.2"}] + e[1:])
    chain("unsupported-version", [stored(entry) for entry in later])
    row("unsupported-version", "verify", "Genesis claims format 0.2, every "
        "hash holding: the field rules are a later version's, so this "
        "verifier refuses to judge them.", 4, refusal)
    later_head = later[3]["entry_hash"]
    row("unsupported-version-expect-head", "verify", "The same chain "
        "against a head record from elsewhere: the head is the last "
        "entry's hash under any version, so it is still compared.", 3,
        f"HEAD-MISMATCH: chain head is {later_head}, expected {head} — "
        "this is not the recorded history", more=["--expect-head", head],
        log="unsupported-version")
    fields = rechained([{**e[0], "v": "0.2"},
                        {**e[1], "model": "a field 0.1 does not have"},
                        {**e[2], "files": "a shape 0.1 does not allow"},
                        e[3]])
    chain("unsupported-version-new-fields", [stored(entry) for entry in fields])
    row("unsupported-version-new-fields", "verify", "Genesis claims format "
        "0.2; entry 1 carries a field 0.1 lacks and entry 2 a files that is "
        "a string, every hash holding. BROKEN under 0.1's field rules, which "
        "do not apply: a refusal.", 4, refusal)
    later[2] = {**later[2], "action": "reviewed the notes and approved them"}
    chain("unsupported-version-edited", [stored(entry) for entry in later])
    row("unsupported-version-edited", "verify", "Genesis claims format "
        "0.2 and entry 2 is edited: the hashes are walked whatever the "
        "version says, and a hash that fails is BROKEN.", 1,
        "BROKEN at entry 2: entry_hash does not match canonical form")

    # No input (ADR-0037): nothing to judge is not a verdict. Exit 66,
    # nothing on stdout, the reason on stderr.
    row("log-missing", "verify", "The file --log names is not there, and "
        "is deliberately absent from this folder.", 66, "", log_absent=True)
    chain("log-empty", [])
    row("log-empty", "verify", "An empty file: no genesis, so not a "
        "receipt log.", 66, "")
    row("log-empty-head", "head", "An empty file has no head.", 66, "",
        log="log-empty")

    # The packages (SPEC section 10). A package row names a folder or a
    # zip in this folder, after the verb, and no --log.
    def package(name, members):
        for member, data in members.items():
            files[f"{name}/{member}"] = data

    def package_row(name, about, exit, line, target=None, more=()):
        rows.append({"name": name, "about": about,
                     "args": ["verify-package", target or name, *more],
                     "exit": exit, "last_line": line})

    unsealed = package_files(base)
    package("package-unsealed", unsealed)
    package_row("package-unsealed", "One chain and the project record, "
                "listed by a manifest declaring no seal: the ceiling, with "
                "its limit.", 0, "SELF-CONSISTENT: every chain walks clean "
                "and every artifact matches the manifest; indistinguishable "
                "from a wholesale regeneration, since no seal is declared")

    package("package-artifact-altered", {
        **unsealed,
        "project.json": b'{"path": "/home/operator/another-project"}\n'})
    package_row("package-artifact-altered", "The same package with "
                "project.json rewritten after the manifest listed it: its "
                "sha256 is not the listed one.", 2, "ARTIFACT-DIVERGED: "
                "something in this package is not what the manifest lists "
                "(the lines above say what)")

    # The tampered chain goes first: unpacking keeps the last member of a
    # name, while a reader that stops at the first sees this one (#299).
    tampered = "".join(line + "\n" for line in
                       base[:2] + [stored(edited)] + base[3:]).encode()
    files["package-named-twice.zip"] = zipped(
        [(PACKAGE_CHAIN, tampered)] + list(unsealed.items()))
    package_row("package-named-twice", "A zip of the unsealed package with "
                "a second member of the chain's name ahead of it, entry 2 "
                "edited: which one is read depends on the unzip, so it is "
                "refused unopened.", 4, "UNSUPPORTED-FORMAT: "
                f"package-named-twice.zip holds two members that unpack to "
                f"one file, '{PACKAGE_CHAIN}' twice; which one is read "
                "depends on the tool that unpacks it, so this verifier "
                "refuses it unopened", target="package-named-twice.zip")

    package("package-seal-missing", package_files(base, seals=["anchor"]))
    package_row("package-seal-missing", "The manifest declares an anchor "
                "and no manifest.json.anchors.jsonl is in the package: a "
                "stripped seal fails, never reads as unsealed.", 3,
                "SEAL-MISSING: a seal the manifest declares is not in this "
                "package (the seal line above says which)")

    package("package-unknown-format",
            package_files(base, format_tag="loxodonta-package/2"))
    package_row("package-unknown-format", "The manifest's format is a tag "
                "this verifier does not speak: a refusal, and nothing is "
                "judged.", 4, 'UNSUPPORTED-FORMAT: package is format '
                '"loxodonta-package/2"; this verifier speaks '
                '"loxodonta-package/1"')

    anchored = package_files(base, seals=["anchor"])
    digest = hashlib.sha256(anchored["manifest.json"]).hexdigest()
    proof = {"calendar": "https://calendar.example/", "head": digest,
             "kind": "anchor", "proof":
             base64.b64encode(completed_proof()).decode("ascii"),
             "ts": "2026-09-23T12:11:00Z"}
    anchored["manifest.json.anchors.jsonl"] = (
        stored(proof) + "\n").encode()
    package("package-anchored", anchored)
    header = block_header(replayed_root(digest))
    package_row("package-anchored", "The manifest's sha256 anchored by a "
                "completed proof, and the header of the block its "
                "attestation claims given: the rung, the block named by the "
                "header's hash.", 0, "SELF-CONSISTENT + ANCHORED: every chain "
                "walks clean and every artifact matches the manifest, and "
                "the manifest existed by the block whose header hashes to "
                f"{header_hash(header)}, which its anchor calls Bitcoin block "
                f"{PROOF_HEIGHT}", more=["--block-header", header.hex()])
    package_row("package-anchored-unchecked", "The same package with no "
                "header given: the rung is earned, and the block is the "
                "attestation's claim.", 0, "SELF-CONSISTENT + ANCHORED: every "
                "chain walks clean and every artifact matches the manifest, "
                "and the manifest's anchor claims Bitcoin block "
                f"{PROOF_HEIGHT}, a block not checked here",
                target="package-anchored")

    manifest = {
        "format": "0.1",
        "about": "Conformance vectors for the receipt format and the "
                 "package (docs/SPEC.md). Run each row's args from inside "
                 "this folder; the exit and the last line of stdout must be "
                 "as given. See README.md.",
        "vectors": rows,
    }
    files["vectors.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return files


def main(argv):
    if argv not in ([], ["--check"]):
        print(__doc__, file=sys.stderr)
        return 64
    with tempfile.TemporaryDirectory() as scratch:
        files = build(Path(scratch))
    if argv == ["--check"]:
        # A package is a folder of files, so every file below is counted,
        # named by its path from here with forward slashes.
        on_disk = {p.relative_to(VECTORS).as_posix()
                   for p in VECTORS.rglob("*") if p.is_file()} - KEPT
        stale = sorted(name for name in set(files) | on_disk
                       if not (VECTORS / name).is_file()
                       or name not in files
                       or (VECTORS / name).read_bytes() != files[name])
        if stale:
            print("stale vectors: " + ", ".join(stale) + " (run python "
                  "tools/build_vectors.py and commit the result)",
                  file=sys.stderr)
            return 1
        print(f"the vectors are current ({len(files)} files)")
        return 0
    VECTORS.mkdir(exist_ok=True)
    for name, data in files.items():
        (VECTORS / name).parent.mkdir(exist_ok=True)
        (VECTORS / name).write_bytes(data)
    print(f"wrote {len(files)} files to {VECTORS}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
