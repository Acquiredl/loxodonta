#!/usr/bin/env python3
"""receiver.py — the far end of the published chain (ADR-0031).

The third single file. The recorder sends a chain's entries and its
head off the machine that wrote them (GLOSSARY: Published chain,
Published head); this is the machine they go to. It mints one URL,
appends what arrives at that URL to its own disk, and refuses
everything else: no read, no list, no delete. That is what makes the
URL pass the head-record test (GLOSSARY: Head record): a credential
that can add and cannot take away, so a wiped machine no longer takes
the evidence with it, as of the last send.

  python receiver.py serve                       # ~/.loxodonta/receiver, all interfaces, port 8790
  python receiver.py serve --data DIR --port N   # elsewhere, another port
  python receiver.py serve --bind 127.0.0.1      # this address only
  python receiver.py serve --cert C --key K      # TLS from your own pair
  python receiver.py serve --new-token           # rotate the URL; the old one answers 404
  python receiver.py serve --file-cap MIB --total-cap MIB   # what it may keep
  python receiver.py --version                   # tool, format, and commit

What it keeps, in its data directory: `token`, the secret half of the
URL; `heads.jsonl`, one line per published head; one
`receipts-<session>.jsonl` per chain, named by the sender and holding
chain bytes from genesis on, so `loxodonta verify --log` judges it as
it is; and `events-<day>.jsonl`, one line per request of a harness's
own events, up to a cap on each file and one on them all. The operator
on this box reads those files with the recorder;
nothing here serves them back over the wire. The wire contract, header
names included, is docs/RECEIVER.md. Stdlib only, like everything here.

A chain batch is kept only when every line is an entry, its hash
recomputed here, and is refused with 409 when it would leave a hole;
every answer says the highest n held and whether the batch's first
entry connects, every entry down to its genesis held (ADR-0045),
answered from memory and not from the file. A chain's anchors and
stamps rows are kept beside its copy, a row already there dropped.

The second door, `POST /<token>/v1/logs`, takes a harness's events about
its tool calls as one JSON object, drops every `user.*` and
`organization.*` attribute at every level, and keeps each request as one
line in the file of its UTC day of arrival, understanding nothing else
about it (ADR-0041 rulings 2 and 3).
"""

import argparse
import collections
import errno
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import threading
import time
import unicodedata
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# Two versions, moving independently (ADR-0022): TOOL_VERSION says which
# receiver is running and is tagged together with loxodonta.py and
# supervisor.py — the three constants must agree (the suite says so).
# FORMAT_VERSION is the frozen receipt format of the chain files it
# keeps (SPEC §2.1).
# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
TOOL_VERSION = "0.19.0"
FORMAT_VERSION = "0.1"

DEFAULT_PORT = 8790
TOKEN_FILE = "token"
HEADS_FILE = "heads.jsonl"

# The wire contract (docs/RECEIVER.md). One POST is either a published
# head, one JSON object, or a batch of a published chain, newline-
# delimited entries exactly as they sit in the chain file; the content
# type says which. A chain batch names its file in one header.
HEAD_TYPE = "application/json"
# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
CHAIN_TYPE = "application/x-ndjson"
CHAIN_HEADER = "X-Loxodonta-Chain"

# The rows of a chain's anchors or stamps sidecar (ADR-0045 ruling 5),
# newline-delimited as they sit beside the chain, under the chain header
# and one more naming the sidecar. Kept beside this receiver's copy of
# the chain, as `<chain file>.anchors.jsonl` or `.stamps.jsonl`, so the
# recorder's `verify --anchors` and `--stamps` read them where they read
# its own. Only a sidecar's evidence rows travel, never its attempt rows.
# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
SIDECAR_TYPE = "application/x-loxodonta-sidecar"
SIDECAR_HEADER = "X-Loxodonta-Sidecar"
# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
ANCHOR_KIND = "anchor"
# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
STAMP_KIND = "stamp"
# The sidecars a batch may name, each with the one kind of row it takes
# (ADR-0038: a row with no kind is its sidecar's evidence row).
SIDECAR_ROWS = {"anchors": ANCHOR_KIND, "stamps": STAMP_KIND}

# The second door (ADR-0041 rulings 2 and 3): a harness's own events
# about its tool calls, posted at the token's path plus the logs suffix
# of the OpenTelemetry protocol, which an exporter given the receiver's
# URL as its base address appends itself. The body is one JSON object,
# kept one request per line in a file per UTC day of arrival. Nothing
# here reads the object: which lines are tool calls, and what a harness
# calls them, is the supervisor's business, so the receiver knows no
# vendor (ADR-0031 ruling 5).
EVENTS_SUFFIX = "/v1/logs"
EVENTS_TYPE = "application/json"
EVENTS_PREFIX = "events-"

# The identity namespaces of the OpenTelemetry conventions, dropped
# before a line is kept from every list the standard keeps attributes
# in, at every level: an `attributes` list, and the `values` of a
# `kvlistValue`, its nested-attributes shape. Matched exactly, case
# included, whoever the sender is: the operator's email and ids serve
# nothing the session id does not, and belong on no file of the
# receiver's (ADR-0041 ruling 3).
IDENTITY_KEYS = ("user.", "organization.")
NESTED_ATTRIBUTES = "kvlistValue"

# The only file names a header can reach: the recorder's own chain
# names, `receipts-<session>.jsonl` and the sibling
# `receipts-<session>-002.jsonl` (GLOSSARY: sibling chain). A session id
# is letters, digits, hyphens and underscores, and the sibling suffix is
# made of the same, so one class covers both; the length keeps the name
# inside what every filesystem takes. Nothing else in a header ever
# becomes a path: no separator, no dot, no other extension.
CHAIN_NAME = re.compile(r"receipts-[A-Za-z0-9_-]{1,200}\.jsonl")

# The most one POST may carry. A session's chain runs to a few hundred
# bytes per entry, so this holds many thousands of entries in one batch;
# a body declared larger is refused before a byte of it is read.
BODY_CAP = 8 * 1024 * 1024

# The most of a body read and thrown away after a refusal judged on the
# headers alone (#450). A socket closed before a body it never read has
# arrived is reset when the body lands, and the reset destroys the
# answer before the sender reads it, so the sender would see a dropped
# connection where the refusal was. A body declared larger is not read:
# past this, the reset is the price of not reading it.
DRAIN_CAP = 64 * 1024

# What the receiver may keep, so a writer holding the URL cannot fill the
# disk under the honest sends (#300): a cap on each file and one on the
# data directory as a whole, in MiB, which --file-cap and --total-cap
# change. A chain runs to a few hundred bytes per entry, so a file cap of
# 1 GiB holds millions of entries, and the total holds thousands of
# ordinary sessions. A request that would pass either cap is refused
# whole; nothing already kept is ever trimmed to make room.
MIB = 1024 * 1024
FILE_CAP_MIB = 1024
TOTAL_CAP_MIB = 10 * 1024

# The whole of one request, headers and body, is due this many seconds
# after its connection is taken, or the connection is dropped (#300). A
# timeout per receive alone let a sender trickle one byte every 1.5
# seconds and hold its request open for as long as it liked. Sixty
# seconds carries a full 8 MiB batch at a little over one megabit a
# second, and the recorder's own sends give up sooner. The env knob is
# the test suite's handle, like the timeout's on the door below.
DEADLINE_SECONDS = float(os.environ.get("RECEIVER_DEADLINE_SECONDS", 60))

# The shape of a token this file mints (secrets.token_urlsafe), so a
# hand-edited token file that would not make a clean URL is replaced.
TOKEN_SHAPE = re.compile(r"[A-Za-z0-9_-]+")

# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
EX_USAGE = 64  # sysexits(3) EX_USAGE: the command was spoken wrong


# --- The data directory and the token ------------------------------------------

def data_home():
    """Where the receiver keeps its files when `--data` is not given:
    the store home's `receiver` folder, the same home the recorder uses
    (`~/.loxodonta`, or wherever LOXODONTA_HOME points)."""
    home = (os.environ.get("LOXODONTA_HOME")
            or os.path.join(os.path.expanduser("~"), ".loxodonta"))
    return os.path.join(home, "receiver")


def token_path(data):
    return os.path.join(data, TOKEN_FILE)


def mint_token(data):
    """A fresh token, written to the data directory readable by this
    user alone where the filesystem has the notion, and returned."""
    token = secrets.token_urlsafe(32)
    fd = os.open(token_path(data), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(token + "\n")
    return token


def current_token(data, rotate=False):
    """The token on disk, or a new one when there is none yet, when the
    stored one is not the shape this file writes, or when the operator
    asked to rotate. Rotation is how a leaked URL is retired: the old
    path answers 404 from the next start on."""
    if not rotate:
        try:
            with open(token_path(data), encoding="utf-8") as f:
                stored = f.read().strip()
        except OSError:
            stored = ""
        if TOKEN_SHAPE.fullmatch(stored):
            return stored
    return mint_token(data)


# --- Appending, durably --------------------------------------------------------

def ends_mid_line(path):
    """True when the file is there, not empty, and its last byte is not
    a newline: a torn tail, the honest damage a crash mid-append leaves
    (GLOSSARY: torn tail)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                return False
            f.seek(-1, os.SEEK_END)
            return f.read(1) != b"\n"
    except FileNotFoundError:
        return False


def append_durably(path, lines):
    """Append each line, then flush and fsync before returning: the 2xx
    that follows means the bytes are on the disk, not in a buffer a
    power cut would lose. A torn tail gets its newline first, so the
    torn line stands alone as the one bad entry verify reports and the
    sender's retry lands whole after it, never glued onto it."""
    torn = ends_mid_line(path)
    with open(path, "ab") as f:
        if torn:
            f.write(b"\n")
        for line in lines:
            f.write(line + b"\n")
        f.flush()
        os.fsync(f.fileno())


def size_of(path):
    """The file's size in bytes, 0 for one that is not there yet."""
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def kept_size(data):
    """Every byte the receiver keeps: the sizes of the files in its data
    directory, read afresh each time, so a file the operator moves off
    the box frees its room at once. A link to nowhere keeps nothing; a
    link into a folder this user may not look into raises, and the
    write is refused, where os.path.isfile would leave its bytes out of
    the count unsaid (#421)."""
    kept = 0
    with os.scandir(data) as entries:
        for entry in entries:
            try:
                found = entry.stat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(found.st_mode):
                kept += found.st_size
    return kept


def head_line(body):
    """The one line a published head becomes: the JSON object that was
    posted, compact and key-sorted so the heads file reads one head per
    line whatever whitespace the sender used. None when the body is not
    one JSON object, is nested past what the reader or the writer takes,
    or carries a number JSON cannot (#474). The writer sits under the
    same guard as the reader: it gives up at a depth the reader still
    takes, and that depth must be a refusal too, never a traceback.
    `allow_nan=False`, because Python's reader takes NaN and Infinity
    and a line holding one is a line most readers refuse."""
    try:
        head = json.loads(body.decode("utf-8"))
        if not isinstance(head, dict):
            return None
        return json.dumps(head, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def identity_attribute(attribute):
    """True for an attribute whose key begins with an identity
    namespace. Anything that is not an attribute, or whose key is not
    text, is not one, and stays."""
    return (isinstance(attribute, dict)
            and isinstance(attribute.get("key"), str)
            and attribute["key"].startswith(IDENTITY_KEYS))


def drop_identity(logs):
    """Remove each identity attribute from every `attributes` list, and
    from the `values` of every nested attribute list, at any depth of
    the posted object, in place, and return how many went. Walked with
    a list of what is left to visit, not by recursion: the object passed
    the JSON reader's depth limit, and the walk must not be what runs
    out of stack a few frames further down. Nothing else in the object
    is touched, list order included."""
    dropped = 0
    pending = [logs]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            for holder, name in ((node, "attributes"),
                                 (node.get(NESTED_ATTRIBUTES), "values")):
                if isinstance(holder, dict) and isinstance(holder.get(name), list):
                    kept = [a for a in holder[name] if not identity_attribute(a)]
                    dropped += len(holder[name]) - len(kept)
                    holder[name] = kept
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return dropped


def events_line(body, sender, received):
    """The one line a received request becomes: the client address, the
    posted object after the identity rule, and the arrival time, compact
    and key-sorted, with how many attributes were dropped. (None, 0)
    when the body is not one JSON object, which is all the receiver asks
    of it, is nested past what the reader or the writer takes, or
    carries a number JSON cannot (#474). The kept line wraps the object
    one level deeper than it was read, so the writer gives up at a depth
    the reader still takes: the writer sits under the same guard, and
    that depth is a refusal too, never a traceback. `allow_nan=False`,
    as for a head."""
    try:
        logs = json.loads(body.decode("utf-8"))
        if not isinstance(logs, dict):
            return None, 0
        dropped = drop_identity(logs)
        line = {"from": sender, "logs": logs, "received": received}
        return (json.dumps(line, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("utf-8"), dropped)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, 0


# --- What an entry is (ADR-0045 ruling 1) --------------------------------------
# A chain file here holds entries and nothing else, so a line is kept
# only when it is one: SPEC section 2's fields of their types, read by a
# strict parser, an n of 0 or more, and an entry_hash that recomputes
# from the line by SPEC section 4. The rule is the recorder's own, copied
# below, since nothing here imports anything (ADR-0035): the recorder
# asks it of its own lines before it sends them.

# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
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


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
class KeyGivenTwice(ValueError):
    """A JSON object that names one key twice. A last-wins reader (this
    one) and a first-wins reader see two different lines, and a hash that
    holds under one reading says nothing under the other; no reading of
    such a line is an entry (SPEC §6 step 1)."""

    def __init__(self, key):
        super().__init__(key)
        self.key = key


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def object_with_each_key_once(pairs):
    """The dict of a JSON object's pairs, refusing a key given twice at
    any depth (json's object_pairs_hook is called for every object)."""
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise KeyGivenTwice(key)
        seen[key] = value
    return seen


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
class NotStrictJson(ValueError):
    """A spelling Python's JSON reader takes and a strict parser refuses,
    so a line or a manifest holding one says something to this reader
    and nothing to another (#365)."""


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def not_json(word):
    """Refuse `NaN`, `Infinity` or `-Infinity` (json's parse_constant
    hook): words Python's JSON reader takes as numbers and JSON does not
    have."""
    raise NotStrictJson(f"{word}, which is not JSON")


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def finite_float(text):
    """The number `text` spells (json's parse_float hook), refused when
    it is not finite: Python reads `1e999` as infinity, where a strict
    parser refuses it as it refuses `Infinity`."""
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise NotStrictJson(f"{text}, a number past what JSON holds")
    return value


# The reason a line is refused quotes what the sender wrote, and the
# receiver prints that reason on its own log: every character that
# steers a terminal is written as its escape.
# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
NAMED_ESCAPES = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}
STEERING_CATEGORIES = ("Cc", "Cf", "Cs", "Zl", "Zp")


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
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


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
ENTRY_FIELDS = {"n", "ts", "actor", "action", "files", "prev", "entry_hash"}
GENESIS_FIELDS = ENTRY_FIELDS | {"v"}


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def canonical_bytes(entry_without_hash):
    return json.dumps(
        entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def entry_hash(entry_without_hash):
    return hashlib.sha256(canonical_bytes(entry_without_hash)).hexdigest()


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
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


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
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
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} \
                or not all(isinstance(value, str) for value in ref.values()):
            return "files holds something that is not a reference"
    for ref in files:
        how = path_leaving_base(ref["path"])
        if how is not None:
            # Escaped for display (`visible`, below): the path is the
            # writer's text.
            return (f"files names a path that leaves the project ({how}): "
                    f"{visible(ref['path'])}")
    return None


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def entry_of(line):
    """(entry, None) when `line`, one line's bytes as `split_lines` gives
    them, is an entry the receiver keeps (ADR-0045 ruling 1), else
    (None, why). It is one when it is one JSON object a strict parser
    takes, each key given once and no NaN, Infinity or 1e999 (#365);
    holds SPEC section 2's fields, `v` on the genesis and only there,
    each of its type (`shape_problem`); has an `n` of 0 or more and a
    `prev` that is null on the genesis and only there; and has an
    `entry_hash` that recomputes from the line's own content by SPEC
    section 4, the rule frozen across format versions (ADR-0036). The
    recorder asks it of a line of its own chain before sending the line,
    and the receiver of every line it is sent, by the same text."""
    try:
        entry = json.loads(line.decode("utf-8"),
                           object_pairs_hook=object_with_each_key_once,
                           parse_constant=not_json, parse_float=finite_float)
    except KeyGivenTwice as twice:
        return None, f"key '{visible(twice.key)}' given twice"
    except UnicodeDecodeError:
        return None, "it is not UTF-8"
    except (ValueError, RecursionError):
        return None, "it is not JSON"
    if not isinstance(entry, dict):
        return None, "it is not a JSON object"
    wrong = shape_problem(entry)
    if wrong is not None:
        return None, wrong
    if entry["n"] < 0:
        return None, "n is below 0"
    fields = GENESIS_FIELDS if entry["n"] == 0 else ENTRY_FIELDS
    if set(entry) != fields:
        odd = ", ".join(visible(key) for key in sorted(set(entry) ^ fields))
        return None, f"its fields are not an entry's: {odd}"
    if (entry["n"] == 0) != (entry["prev"] is None):
        return None, ("the genesis names a prev" if entry["n"] == 0
                      else "prev is null past the genesis")
    try:
        recomputed = entry_hash({key: value for key, value in entry.items()
                                 if key != "entry_hash"})
    except (UnicodeEncodeError, RecursionError):
        return None, "it has no canonical form"
    if recomputed != entry["entry_hash"]:
        return None, "entry_hash does not recompute from the line"
    return entry, None


# --- A chain batch, and what is held of the chain (ADR-0045 ruling 2) ---------

def chain_lines(body):
    """A chain batch as [(line, n, prev, entry_hash)], each line as
    `split_lines` reads it: without its newline, and without a carriage
    return before it, so a proxy that rewrote the line endings changes
    nothing on disk. The sender's trailing newline is not an empty last
    line. A batch with no lines, or with any line that is not an entry
    (`entry_of`), raises ValueError naming the line and why: the whole
    batch is refused, nothing of it written."""
    lines = split_lines(body)
    if not lines:
        raise ValueError("the batch holds no lines")
    batch = []
    for number, line in enumerate(lines, 1):
        entry, why = entry_of(line)
        if entry is None:
            raise ValueError(f"line {number} is not an entry: {why}")
        batch.append((line, entry["n"], entry["prev"], entry["entry_hash"]))
    return batch


# What the receiver remembers of each chain file while it runs (ADR-0045
# ruling 2). An entry connects when it is the genesis, or when its prev
# is the hash of an entry held at the n before it that itself connects:
# so an entry connects only when every entry down to its genesis is
# held, and a gap anywhere below shows in the answer about every entry
# above it. Kept per chain, keyed by entry hash (32 bytes, not the 64
# characters of its hex): which held entries connect and which do not
# yet, with the n of each, and for each entry that does not, the hash
# its prev names. The memory is a cache: the file is the record, and a
# chain forgotten is read again on its next touch.

HASH_HEX = re.compile(r"[0-9a-f]{64}")

# The most entries remembered across every chain: about 130 bytes an
# entry that connects and 320 one that does not (docs/RECEIVER.md, *What
# an answer costs the receiver*), so some 65 MB for chains that connect.
# Past it, the chains touched longest ago are forgotten first; the chain
# being answered is always kept, however long it is.
REMEMBERED_ENTRIES = 500_000


def hash_key(text):
    """The 32 bytes a hex entry hash names, or None for a prev that is
    null or is no entry hash at all, which no held entry can match."""
    if isinstance(text, str) and HASH_HEX.fullmatch(text):
        return bytes.fromhex(text)
    return None


class Held:
    """One chain file as the receiver remembers it: `top` the highest n
    held (-1 for none), `joined` and `loose` the entries held that
    connect and that do not yet (hash to n), `waiting` for each hash a
    loose entry's prev names, the loose entries naming it, and `size`
    the file's size once the receiver last read or wrote it. The
    receiver is the only writer of its files, so a size that is not the
    one remembered (a file the operator moved off the box, say) means
    the file is read and remembered again."""

    def __init__(self, size=0):
        self.top = -1
        self.joined, self.loose, self.waiting = {}, {}, {}
        self.size = size

    def __len__(self):
        return len(self.joined) + len(self.loose)

    def holds(self, n, digest):
        """Whether the entry with this n and hash is held."""
        key = hash_key(digest)
        return n in (self.joined.get(key), self.loose.get(key))

    def connects(self, n, prev):
        """Whether an entry at `n` naming `prev` connects: the genesis,
        or a prev that is an entry held at n - 1 that connects."""
        if n == 0 and prev is None:
            return True
        return self.joined.get(hash_key(prev), -2) == n - 1

    def add(self, n, prev, digest):
        """Remember an entry the file now holds. One that connects may
        make entries already held above it connect, each in turn: an
        entry that fills a gap joins every entry above it whose prev
        names it, up to the next gap. Each entry joins at most once, so
        the work over a chain's life is one step an entry."""
        key = hash_key(digest)
        if key in self.joined or key in self.loose:
            return
        self.top = max(self.top, n)
        if not self.connects(n, prev):
            self.loose[key] = n
            below = hash_key(prev)
            if below is not None:
                self.waiting.setdefault(below, []).append(key)
            return
        self.joined[key] = n
        rising = [key]
        while rising:
            below = rising.pop()
            for above in self.waiting.pop(below, ()):
                if self.loose.get(above) == self.joined[below] + 1:
                    self.joined[above] = self.loose.pop(above)
                    rising.append(above)


def held_in(path):
    """A chain file read whole into its memory (`Held`), a line that is
    not an entry counting for nothing, read a line at a time since a
    file may run to its cap: a file opened for bytes ends a line at
    `\\n` and nowhere else, the rule of `split_lines`. Empty for a file
    that is not there yet. The slow path, taken once a chain."""
    held = Held()
    try:
        with open(path, "rb") as f:
            for raw in f:
                for line in split_lines(raw):
                    entry, _ = entry_of(line)
                    if entry is not None:
                        held.add(entry["n"], entry["prev"],
                                 entry["entry_hash"])
    except FileNotFoundError:
        pass
    held.size = size_of(path)
    return held


def hole_in(batch, top):
    """The n of the first entry in `batch` that is more than one past
    the highest n the file would hold once the entries before it were
    in, `top` being the highest it holds now (-1 for none); None when
    there is no such entry (ADR-0045 ruling 2). Appended, such an entry
    would leave a hole the file could never verify across."""
    for _, n, _, _ in batch:
        if n > top + 1:
            return n
        top = max(top, n)
    return None


def new_lines(batch, held):
    """The append rule that keeps the file a receipt log (ADR-0031
    ruling 4). A line whose n and entry_hash the file already holds is
    an exact duplicate, the sender's retry after a lost acknowledgement,
    and is dropped. A line whose n the file holds with a different hash
    is a regenerated chain arriving after the original, or an entry the
    URL's holder made, and is appended: that collision is what the copy
    exists to show, and verify reports it. Everything else is appended
    in the order received. Returns the batch's entries that are to
    land, each as `chain_lines` gives it."""
    keep, seen = [], set()
    for line, n, prev, digest in batch:
        if held.holds(n, digest) or (n, digest) in seen:
            continue
        seen.add((n, digest))  # the same line twice in one batch lands once
        keep.append((line, n, prev, digest))
    return keep


# --- A chain's proofs (ADR-0045 ruling 5) ----------------------------------------


def sidecar_lines(body, sidecar):
    """A sidecar batch as its lines, each as `split_lines` reads it. Every
    line must be one JSON object a strict parser takes (a key given
    once, no NaN, Infinity or 1e999, the recorder's own sidecar reader)
    whose kind is the sidecar's evidence kind or absent (ADR-0038). A
    batch with no lines, or with any other line, an attempt row among
    them, raises ValueError naming the line: refused whole, nothing of
    it written. Nothing else about a row is judged here; that is
    `verify --anchors` and `--stamps`."""
    lines = split_lines(body)
    if not lines:
        raise ValueError("the batch holds no lines")
    kind = SIDECAR_ROWS[sidecar]
    for number, line in enumerate(lines, 1):
        try:
            row = json.loads(line.decode("utf-8"),
                             object_pairs_hook=object_with_each_key_once,
                             parse_constant=not_json,
                             parse_float=finite_float)
        except (ValueError, RecursionError):
            row = None
        if not isinstance(row, dict) or row.get("kind", kind) != kind:
            raise ValueError(f"line {number} is not a row of kind {kind}")
    return lines


def known_lines(path):
    """Every line the sidecar copy already holds, byte for byte, as
    `split_lines` reads it, so a resent row is dropped: read a line at a
    time, as `held_in` reads a chain, its `\\n` and a `\\r` before it
    taken off. Nothing when the file is not there yet."""
    known = set()
    try:
        with open(path, "rb") as f:
            for line in f:
                line = line[:-1] if line.endswith(b"\n") else line
                known.add(line[:-1] if line.endswith(b"\r") else line)
    except FileNotFoundError:
        pass
    return known


# --- The door ------------------------------------------------------------------

class Receiver(ThreadingHTTPServer):
    """A thread for each request, so a slow sender holds its own
    connection and no one else's (#300); daemon threads, so stopping the
    receiver never waits on a stalled one. The appends still go one at a
    time. `appending` is held from reading what a file already knows to
    the fsync of the last line written, so two batches for one chain
    never interleave, and two requests never both fit under a cap that
    has room for one. One lock for every file, because the total cap is
    a question about every file at once. `held` is what it remembers of
    each chain file it has touched (`Held`), the one touched longest ago
    first, read and written under the same lock."""

    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.appending = threading.Lock()
        self.held = collections.OrderedDict()

    def chain_held(self, name, path):
        """What is remembered of the chain file `name`, read from `path`
        when it is not remembered or its size is not the one remembered.
        Called holding `appending`."""
        held = self.held.pop(name, None)
        if held is None or held.size != size_of(path):
            held = held_in(path)
        self.held[name] = held
        return held

    def forget_past_bound(self):
        """Forget the chains touched longest ago while more than
        REMEMBERED_ENTRIES entries are remembered in all, never the one
        touched last. Called holding `appending`."""
        remembered = sum(len(held) for held in self.held.values())
        while remembered > REMEMBERED_ENTRIES and len(self.held) > 1:
            _, gone = self.held.popitem(last=False)
            remembered -= len(gone)

    def server_bind(self):
        # The stdlib's server_bind looks up the bound host's fully
        # qualified name, a reverse DNS query nothing here ever reads
        # and a long stall on some machines. Bind, name it ourselves.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address):
        # A sender that stalled past the timeout or the deadline, or
        # spoke plain HTTP to a TLS door, is dropped silently: a stalling
        # stranger must not be able to fill the operator's log. Anything
        # that is not a socket or TLS error is a bug in this file, and
        # those still print the stdlib's traceback.
        if not isinstance(sys.exc_info()[1], OSError):
            super().handle_error(request, client_address)


class Arrival(io.RawIOBase):
    """A connection's incoming bytes, under one deadline for the whole
    request. Before every receive the socket's timeout is set to what is
    left of the deadline, or to one receive's own timeout when that is
    shorter, so a sender that trickles runs out of time as surely as one
    that stops. Past the deadline a read fails the way a timeout does,
    and the stdlib drops the connection unanswered."""

    def __init__(self, sock, deadline, per_receive):
        self.sock = sock
        self.due = time.monotonic() + deadline
        self.per_receive = per_receive

    def limit_wait(self):
        left = self.due - time.monotonic()
        if left <= 0:
            raise socket.timeout("the request missed its deadline")
        self.sock.settimeout(min(left, self.per_receive))

    def readable(self):
        return True

    def readinto(self, buffer):
        self.limit_wait()
        return self.sock.recv_into(buffer)


class Door(BaseHTTPRequestHandler):
    """Two doors: POST at the token's path, for a head or a chain batch,
    and POST at the events path under it, for a harness's events.
    Everything else is turned away with a status and one short line, and
    the request path is never written anywhere, because the path is the
    credential."""

    # A sender that goes quiet this long, mid-body or before a TLS
    # handshake it never starts, is dropped, not waited on, even with
    # time left before the deadline. The env knob is the test suite's
    # handle.
    timeout = float(os.environ.get("RECEIVER_TIMEOUT_SECONDS", 30))

    def setup(self):
        # The stdlib sets the timeout and opens the reading side here.
        # The reading side is swapped for one under the request's
        # deadline, which starts now, before the TLS handshake, so a
        # handshake that trickles is bounded too. The handshake runs
        # here rather than inside accept(), where do_handshake_on_connect
        # would run it on a socket with no timeout at all.
        super().setup()
        self.rfile.close()
        arrival = Arrival(self.connection, DEADLINE_SECONDS, self.timeout)
        self.rfile = io.BufferedReader(arrival)
        if isinstance(self.connection, ssl.SSLSocket):
            arrival.limit_wait()
            self.connection.do_handshake()

    def door(self):
        """Which door the path is at: "token" for the token's own,
        "events" for the events path under it, None for anything else.
        A token is ASCII, so a path that is not is at neither; asked
        first, because compare_digest refuses non-ASCII text. Each
        comparison is of the whole path, so the token is never judged a
        character at a time."""
        path = urlsplit(self.path).path
        if not path.isascii():
            return None
        token = "/" + self.server.token
        if hmac.compare_digest(path, token):
            return "token"
        if hmac.compare_digest(path, token + EVENTS_SUFFIX):
            return "events"
        return None

    def refuse_method(self):
        """Every verb but POST: 405 at either door, so an operator with
        the right URL learns it is the verb that is wrong, and 404
        anywhere else. There is no verb that reads, lists or deletes."""
        if self.door():
            self.refuse_unread(405, "the receiver takes POST only",
                               allow="POST")
        else:
            self.refuse_unread(404, "not the receiver's path")

    do_GET = do_HEAD = do_PUT = do_DELETE = refuse_method
    do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = refuse_method

    def refuse_unread(self, status, text, allow=None):
        """A refusal judged before the body is read, then the body read
        and thrown away when it is declared no larger than DRAIN_CAP, so
        the connection closes cleanly and the answer reaches the sender
        (#450). The answer goes first, so a body that never comes delays
        nothing but the close, under the door's timeout and deadline."""
        self.answer(status, text, allow=allow)
        try:
            declared = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        if 0 < declared <= DRAIN_CAP:
            try:
                self.rfile.read(declared)
            except OSError:
                pass  # a sender that stalls or goes is dropped, as anywhere

    def declared_length(self):
        """The body length the sender declared, judged before any of it
        is read: None with the refusal already sent when it is missing,
        malformed, or past the cap."""
        declared = self.headers.get("Content-Length")
        if declared is None:
            self.answer(411, "Content-Length is required")
            return None
        try:
            length = int(declared)
        except ValueError:
            length = -1
        if length < 0:
            self.answer(400, "Content-Length is not a length")
            return None
        if length > BODY_CAP:
            self.answer(413, f"the body cap is {BODY_CAP} bytes")
            return None
        return length

    def content_type(self):
        return (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    def content_encoding(self):
        return (self.headers.get("Content-Encoding") or "identity").strip().lower()

    def do_POST(self):
        door = self.door()
        if door is None:
            self.refuse_unread(404, "not the receiver's path")
            return
        kind = self.content_type()
        if door == "events":
            if kind != EVENTS_TYPE:
                self.refuse_unread(415, f"events are {EVENTS_TYPE}")
                return
        elif kind not in (HEAD_TYPE, CHAIN_TYPE, SIDECAR_TYPE):
            self.refuse_unread(415, f"a head is {HEAD_TYPE}, a chain batch "
                                    f"is {CHAIN_TYPE}, a sidecar's rows are "
                                    f"{SIDECAR_TYPE}")
            return
        # A body is taken as it is, at either door: nothing here
        # decompresses, so an encoded body would be kept as garbage or
        # refused as one. Judged before the body is read, like the type.
        if self.content_encoding() != "identity":
            self.refuse_unread(415, "the body must be sent as it is, with "
                                    "no Content-Encoding")
            return
        # The chain's name is judged before the body is read: a batch
        # for a file this receiver would not write is only drained
        # (`refuse_unread`), never parsed or kept.
        name = sidecar = None
        if kind in (CHAIN_TYPE, SIDECAR_TYPE):
            name = self.headers.get(CHAIN_HEADER) or ""
            if not CHAIN_NAME.fullmatch(name):
                self.refuse_unread(400, f"{CHAIN_HEADER} must be a receipt "
                                        "file name, receipts-<session>.jsonl")
                return
        if kind == SIDECAR_TYPE:
            sidecar = self.headers.get(SIDECAR_HEADER) or ""
            if sidecar not in SIDECAR_ROWS:
                self.refuse_unread(400, f"{SIDECAR_HEADER} must be "
                                        "anchors or stamps")
                return
        length = self.declared_length()
        if length is None:
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.answer(400, "the body ended before its declared length")
            return
        if door == "events":
            self.keep_events(body)
        elif kind == HEAD_TYPE:
            self.keep_head(body)
        elif kind == SIDECAR_TYPE:
            self.keep_sidecar(body, name, sidecar)
        else:
            self.keep_batch(body, name)

    def keep_events(self, body):
        """The second door's keep: one line per received request, in the
        file of the UTC day it arrived, under the same lock and caps as
        a chain. The day and the line's `received` come from one reading
        of the clock, so the file a line sits in and the time it carries
        never disagree. The log line says how many identity attributes
        went and nothing of the path."""
        now = datetime.now(timezone.utc)
        line, dropped = events_line(body, self.client_address[0],
                                    now.isoformat())
        if line is None:
            self.answer(400, "events are one JSON object, within what JSON carries")
            return
        path = os.path.join(self.server.data,
                            EVENTS_PREFIX + now.strftime("%Y-%m-%d") + ".jsonl")
        with self.server.appending:
            refused = self.append(path, [line])
        if refused:
            self.answer(*refused)
        else:
            self.ok({}, said=f"events: {dropped} identity attribute(s) dropped")

    def keep_head(self, body):
        line = head_line(body)
        if line is None:
            self.answer(400, "a head is one JSON object, within what JSON carries")
            return
        path = os.path.join(self.server.data, HEADS_FILE)
        with self.server.appending:
            refused = self.append(path, [line])
        if refused:
            self.answer(*refused)
        else:
            self.ok({"appended": 1})

    def keep_batch(self, body, name):
        """A chain batch: every line an entry or the whole batch refused,
        400 (ADR-0045 ruling 1); then a hole refused, 409 (ruling 2), or
        the new lines appended by the append rule. Every answer says the
        highest n held once it is through and whether the batch's first
        entry connects. Judged from what is remembered of the chain
        (`Held`); the file is read only on a chain's first touch since
        the receiver started, or when its size is not the one
        remembered."""
        try:
            batch = chain_lines(body)
        except ValueError as why:
            self.answer(400, str(why))
            return
        path = os.path.join(self.server.data, name)
        _, first_n, first_prev, _ = batch[0]
        with self.server.appending:
            held = self.server.chain_held(name, path)
            hole = hole_in(batch, held.top)
            refused = None
            if hole is None:
                landing = new_lines(batch, held)
                refused = self.append(path, [line for line, _, _, _ in landing])
                if refused:
                    self.server.held.pop(name)   # read the file again next time
                else:
                    for _, n, prev, digest in landing:
                        held.add(n, prev, digest)
                    held.size = size_of(path)
            connected = held.connects(first_n, first_prev)
            top = None if held.top < 0 else held.top
            self.server.forget_past_bound()
        if hole is not None:
            # Nothing appended (ADR-0045 ruling 2).
            why = (f"entry {hole} is more than one past entry {top}, the "
                   "highest this receiver holds of the chain"
                   if top is not None else
                   f"entry {hole} is not the genesis, and this receiver "
                   "holds none of the chain")
            self.answer(409, json.dumps({"refused": why, "held_n": top,
                                         "connects": connected}),
                        kind="application/json", said=why)
        elif refused:
            self.answer(*refused)
        else:
            self.ok({"appended": len(landing),
                     "dropped": len(batch) - len(landing),
                     "held_n": top, "connects": connected})

    def keep_sidecar(self, body, name, sidecar):
        """A chain's anchors or stamps rows, kept beside this receiver's
        copy of the chain, dropping a row the file already holds byte for
        byte: the sender sends every evidence row each time, and the file
        only adds (ADR-0045 ruling 5). The same lock, caps and fsync as
        a batch."""
        try:
            lines = sidecar_lines(body, sidecar)
        except ValueError as why:
            self.answer(400, str(why))
            return
        path = os.path.join(self.server.data, f"{name}.{sidecar}.jsonl")
        with self.server.appending:
            known = known_lines(path)
            kept = []
            for line in lines:
                if line not in known:
                    known.add(line)
                    kept.append(line)
            refused = self.append(path, kept)
        if refused:
            self.answer(*refused)
        else:
            self.ok({"appended": len(kept), "dropped": len(lines) - len(kept)})

    def append(self, path, lines):
        """Put the lines on disk: None once they are there (nothing to
        write counts), else the (status, reason) refusing them. Called
        holding `appending`, and answering nothing itself, so a sender
        slow to read its answer never holds the lock. Past a cap is 507
        Insufficient Storage (RFC 4918), not 413, which stays the answer
        for a body too large to take at all, so the sender's failure
        line tells the two apart; a disk that refuses is a 500. A
        refusal writes nothing and trims nothing, so the sender's memo
        never advances over bytes that did not land."""
        if not lines:
            return None
        server = self.server
        adding = sum(len(line) + 1 for line in lines)
        if ends_mid_line(path):
            adding += 1  # the torn tail's newline
        try:
            if size_of(path) + adding > server.file_cap:
                return 507, (f"the file cap is {server.file_cap // MIB} MiB "
                             "(--file-cap), and this would pass it")
            if kept_size(server.data) + adding > server.total_cap:
                return 507, (f"the total cap is {server.total_cap // MIB} MiB "
                             "(--total-cap), and this would pass it")
            append_durably(path, lines)
        except OSError as e:
            return 500, f"could not write: {e.strerror or e}"
        return None

    def ok(self, counts, said=None):
        """The 200: what landed, as JSON, and said to be JSON. `said` is
        the log line's words when the body is not them."""
        self.answer(200, json.dumps(counts), kind="application/json", said=said)

    def answer(self, status, text, allow=None, kind="text/plain; charset=utf-8",
               said=None):
        body = (text + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"{stamp} {self.client_address[0]} {self.command} {status} "
              f"{said or text}", flush=True)

    def log_request(self, *_):
        pass  # `answer` prints the line, without the path

    def log_message(self, *_):
        pass


def tls_context(cert, key):
    """The server side of TLS from the operator's own pair, through the
    stdlib alone. The receiver mints no certificate: a pair from a CA the
    sending machine trusts, or a self-signed one the operator installs
    there, is the operator's choice (docs/RECEIVER.md)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def cmd_serve(args):
    if bool(args.cert) != bool(args.key):
        print("receiver serve: error: --cert and --key go together",
              file=sys.stderr)
        return EX_USAGE
    data = os.path.abspath(args.data or data_home())
    try:
        os.makedirs(data, exist_ok=True)
        token = current_token(data, rotate=args.new_token)
    except OSError as e:
        print(f"error: cannot write to {data}: {e.strerror or e}",
              file=sys.stderr)
        return 1
    try:
        server = Receiver((args.bind, args.port), Door)
    except OSError as e:
        print(f"error: cannot listen on {args.bind}:{args.port}: "
              f"{e.strerror or e}", file=sys.stderr)
        return 1
    server.data = data
    server.token = token
    server.file_cap = args.file_cap * MIB
    server.total_cap = args.total_cap * MIB
    scheme = "http"
    if args.cert:
        try:
            # No handshake in accept(): the door does it once its
            # timeout is set (Door.setup), so an idle stranger is bounded.
            server.socket = tls_context(args.cert, args.key).wrap_socket(
                server.socket, server_side=True, do_handshake_on_connect=False)
        except (OSError, ssl.SSLError) as e:
            print(f"error: cannot serve TLS from {args.cert} and {args.key}: "
                  f"{e}", file=sys.stderr)
            server.server_close()
            return 1
        scheme = "https"
    port = server.server_address[1]
    everywhere = args.bind in ("", "0.0.0.0")
    host = socket.gethostname() if everywhere else args.bind
    print(f"receiver {TOOL_VERSION} keeping {data}, at most "
          f"{args.file_cap} MiB a file and {args.total_cap} MiB in all")
    print(f"listening on {args.bind}:{port} "
          f"({'all interfaces' if everywhere else 'this address only'}), "
          + (f"speaking TLS from {args.cert}" if args.cert else
             "speaking plain HTTP (give --cert and --key for TLS)"))
    print(f"publish to {scheme}://{host}:{port}/{token}")
    if everywhere:
        print(f"  ({host} is this machine's name; use the address the "
              "sending machine reaches this one by)")
    print("the URL is the credential: it can add and cannot read, list or "
          "delete; --new-token retires it", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


# --- The command line ----------------------------------------------------------

# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
GIT_TIMEOUT = 10


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def helper_path(name):
    """The full path of the helper program `name` (openssl, ssh-keygen,
    git, gh, claude), found by walking PATH: only entries that are
    absolute paths, never an empty one, a relative one or one that is
    the working directory under any spelling, so a file of that name in
    the folder a check is run from is never the program that runs. On
    Windows, where a bare name is looked for in the working directory
    before PATH, an entry with no drive letter or server is read against
    the working directory's drive, so it counts as relative there; the
    names tried are `name.exe` and `name.com`, never a batch file, which
    would run through cmd.exe. Raises FileNotFoundError when none is
    found, as running an absent program does, so a missing helper is
    said as it always was."""
    windows = sys.platform == "win32"
    endings = (".exe", ".com") if windows else ("",)
    for folder in os.get_exec_path():
        absolute = os.path.isabs(folder) and (
            not windows or os.path.splitdrive(folder)[0] != "")
        if not absolute:
            continue
        try:
            if os.path.samefile(folder, os.getcwd()):
                continue
        except OSError:
            continue  # an entry that cannot be compared is not trusted
        for ending in endings:
            found = os.path.join(folder, name + ending)
            if os.path.isfile(found) and os.access(found, os.X_OK):
                return found
    raise FileNotFoundError(errno.ENOENT, "not found on PATH", name)


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def checkout_commit(home):
    """The short commit of the git checkout `home` sits in, or "unknown"
    when git cannot say: no git on this machine, no checkout around the
    file, a question that failed, or no answer within GIT_TIMEOUT.
    Local git only: a version is a label on the file, never a channel
    to fetch a newer one."""
    try:
        asked = subprocess.run(
            [helper_path("git"), "-C", home, "rev-parse", "--short", "HEAD"],
            # Never a pipe on stderr: a program git starts inherits it,
            # and on Windows the timeout then waits for that program.
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            encoding="utf-8", timeout=GIT_TIMEOUT)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "unknown"
    return asked.stdout.strip() if asked.returncode == 0 else "unknown"


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
def version_line(prog, home):
    """Three identities on one line: tool, format, commit (ADR-0022)."""
    return (f"{prog} {TOOL_VERSION} (format {FORMAT_VERSION}, "
            f"commit {checkout_commit(home)})")


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
class VersionAction(argparse.Action):
    """`--version`, answered only when asked: the commit is one git
    question, and no other command pays for it."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        home = os.path.dirname(os.path.abspath(__file__))
        print(version_line(parser.prog, home))
        parser.exit()


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
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


def mebibytes(text):
    """A cap as typed at the command line: a whole number of MiB, one or
    more. Anything else is a usage error naming the flag."""
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("a cap is a whole number of MiB, "
                                         "1 or more")
    return value


# Copy of loxodonta.py's; edit there, then run tools/twin_check.py --write.
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


def main(argv):
    parser = UsageParser(prog="receiver",
                         description=__doc__.splitlines()[0])
    parser.add_argument("--version", action=VersionAction,
                        help="print tool version, format version, and "
                             "the checkout's commit, then exit")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="listen for published chains, "
                                         "heads and a harness's events, "
                                         "and keep them")
    serve.add_argument("--data", metavar="DIR",
                       help="where the token and the files live "
                            "(default: ~/.loxodonta/receiver)")
    serve.add_argument("--bind", default="0.0.0.0", metavar="ADDRESS",
                       help="the address to listen on (default: all "
                            "interfaces, since the sender is another "
                            "machine); 127.0.0.1 narrows it to this one")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT,
                       help=f"the port to listen on (default: {DEFAULT_PORT}; "
                            "0 picks a free one and prints it)")
    serve.add_argument("--cert", metavar="FILE",
                       help="a PEM certificate (with --key): speak TLS")
    serve.add_argument("--key", metavar="FILE",
                       help="the certificate's PEM private key (with --cert)")
    serve.add_argument("--new-token", action="store_true",
                       help="mint a new token; the old URL answers 404 "
                            "from now on")
    serve.add_argument("--file-cap", type=mebibytes, default=FILE_CAP_MIB,
                       metavar="MIB",
                       help="the most any one file may hold; past it a "
                            f"request is refused with 507 (default: "
                            f"{FILE_CAP_MIB} MiB)")
    serve.add_argument("--total-cap", type=mebibytes, default=TOTAL_CAP_MIB,
                       metavar="MIB",
                       help="the most the data directory may hold in all; "
                            f"past it a request is refused with 507 "
                            f"(default: {TOTAL_CAP_MIB} MiB)")
    serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    speak_utf8()  # before anything prints
    sys.exit(main(sys.argv[1:]))
