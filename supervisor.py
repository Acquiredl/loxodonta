#!/usr/bin/env python3
"""supervisor.py — the operator that never sleeps (ADR-0005).

A reader-side companion to loxodonta.py: it watches every receipt log
under a root full of repos and shouts on change — a tripwire with a
memory, never a wall. It drives receipts exclusively through the public
CLI and judges nothing itself: verdicts come from `loxodonta verify`,
and everything the supervisor holds is writer-reachable, so nothing
here is a head record (GLOSSARY: Supervisor, Baseline).

  python supervisor.py scan --json              # one tick over the store
  python supervisor.py serve                    # the face
  python supervisor.py digest [--repo DIR]      # the session-start injection
  python supervisor.py show ADDRESS             # one entry, self-verifying
  python supervisor.py search TEXT [--all]      # the ladder past the digest
  python supervisor.py timeline ADDRESS         # context around one entry
  python supervisor.py mcp [--repo DIR]         # the same recall, as an MCP server
  python supervisor.py package SESSION|ADDRESS  # one session, sealed by a manifest
  python supervisor.py scan --root DIR --json   # legacy: a folder of repos
  python supervisor.py --version                # tool, format, and commit

`scan` is one tick without timers: a census of every chain in the
store (ADR-0011; --root walks a legacy folder of repos instead), a
verdict for each, a baseline diff against the last look,
machine-readable JSON on stdout, and an exit code cron can shout about —
0 when nothing demands attention, 1–4 for the worst verify exit found,
5 when the baseline saw a change appends cannot explain (a reason to
investigate, never a verdict), 6 when a session is demonstrably active
but its chain is behind the witness (the completeness alarm), 7 when a
chain's transcript commitments contradict each other (verify's exit 5,
ADR-0017 — renumbered in this fold because scan's 5 already means the
tripwire).

`serve` is the face: a localhost-only stdlib HTTP server serving one
inline HTML page — no framework, no build step. The page opens on
**recall**, the memory view (GLOSSARY: Recall): a cross-repo timeline of
sessions, filterable by repo, date range, and file path, labeled as
testimony because it renders what the writer said happened. Around it
sits the alarm layer — the status band: every chain on the machine, its
verdict drawn by tier, answered from the newest scan no older than the
tick (one verify per chain per tick, never per request — ADR-0005).
Nothing is ever offered off-machine.
"""

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socketserver
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
LOXODONTA = HERE / "loxodonta.py"

# Two versions, moving independently (ADR-0022): TOOL_VERSION says which
# supervisor is running and is tagged together with loxodonta.py — the
# two files' constants must agree (the suite says so); FORMAT_VERSION
# is the frozen receipt format the recorder it drives speaks (SPEC §2.1).
TOOL_VERSION = "0.3.0"
FORMAT_VERSION = "0.1"

# Who wrote an entry, read off the actor field. The harness actors are
# the ones whose entries are tool calls (ADR-0020): their action lines
# start with the tool's name. The recorder's own name marks bookkeeping
# it writes about itself — transcript commitments and the like — which
# is housekeeping rather than work the agent did, so every reader that
# counts tool calls sets it aside. Both live up here because two
# sections read them: the export's allowlist and the histogram.
HOOK_ACTORS = ("claude-code", "codex", "openai-agents")
BOOKKEEPING_ACTOR = "receipts"


# --- Census -------------------------------------------------------------------

# What sits beside a chain and is not one: the anchor sidecar (proofs
# about the chain) and the publish memo (which heads left, ADR-0025).
# Both end in .jsonl and share the chain's name, so every census that
# globs for chains must set them aside by suffix.
SIDECAR_SUFFIXES = (".anchors.jsonl", ".published.jsonl")


def find_chains(root):
    """Every receipt log under a legacy --root. Three shapes, because
    pre-store history has three shapes: the root itself being a repo,
    each sibling repo's receipts/, and chains stranded in worktrees by
    sessions that ran before the hook learned to log to the main repo.
    The default census is not this one: it is a single glob over the
    store's drawers, inline in scan_root (ADR-0011). Sidecars are files
    about a chain, not chains."""
    patterns = ("receipts/*.jsonl",
                "*/receipts/*.jsonl",
                "*/.claude/worktrees/*/receipts/*.jsonl")
    return sorted(p for pattern in patterns for p in root.glob(pattern)
                  if not p.name.endswith(SIDECAR_SUFFIXES))


def split_seq(stem):
    """(base, seq) — a trailing three-digit sibling suffix split off.

    A sibling chain (`-002`, `-003`) is continuation by naming alone
    (ADR-0004): it belongs to whatever the name says before the suffix,
    in suffix order. An unsuffixed name is seq 1."""
    prefix, dash, tail = stem.rpartition("-")
    if dash and len(tail) == 3 and tail.isdigit():
        return prefix, int(tail)
    return stem, 1


def chain_identity(root, log):
    """(repo, session, seq) — which repo a chain belongs to, which session
    wrote it, and where it sits in the session's run of sibling chains,
    all read from where the log lies and what it is named."""
    parts = log.relative_to(root).parts
    repo = root.name if parts[0] == "receipts" else parts[0]
    session = log.stem
    if session.startswith("receipts-"):
        session = session[len("receipts-"):]
    session, seq = split_seq(session)
    return repo, session, seq


def read_entries(log):
    """Every line of a chain that still reads as an entry — the census's
    parsing half, display and diffing only (ADR-0005). Damage is not
    judged here: a torn or garbled line is simply not remembered; the
    verify walk is where damage gets its name."""
    entries = []
    with open(log, encoding="utf-8", errors="replace") as lines:
        for line in lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    return entries


def parse_when(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


# --- Verdict runner -----------------------------------------------------------

def verify(log):
    """The single seam to receipts (ADR-0005): one subprocess per chain,
    verdict read from the exit code and the documented verdict lines.
    --anchors judges sidecar proofs offline too, because VALID and
    ANCHORED are different claims (ADR-0002) and an anchor contradicting
    the log is the gravest finding there is."""
    # Both ends of the pipe pinned to UTF-8: verdict lines land in the
    # frontend, and a shell's codepage must never garble evidence —
    # errors="replace" because a verdict lost to a decode error is a
    # supervisor that missed its one job.
    result = subprocess.run(
        [sys.executable, str(LOXODONTA), "verify", "--anchors",
         f"--log={log}"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    lines = result.stdout.strip().splitlines()
    if lines:
        # Last line is the verdict — true for every combination this
        # command can produce. Tripwire: if the tick ever gains --files
        # (.out-of-scope/002's reopening), FILES-DIVERGED prints before
        # the anchor lines and this parse breaks; fix the parse and the
        # print ordering in the same PR that adds the flag.
        verdict = lines[-1].split(":")[0].split(" at ")[0]
    else:
        # verify refused without a verdict line (an empty or unopenable
        # log). Its own words on stderr are the evidence; the supervisor
        # invents no verdict of its own.
        verdict = "NO-VERDICT"
        lines = result.stderr.strip().splitlines()
    return verdict, result.returncode, lines


def sibling_of(log):
    """Where recording moved when this chain's tail tore (ADR-0004):
    receipts-<session>.jsonl continues in receipts-<session>-002.jsonl,
    and -002 continues in -003."""
    base, seq = split_seq(log.name[:-len(".jsonl")])
    return log.with_name(f"{base}-{seq + 1:03d}.jsonl")


def superseded(log, detail):
    """True when this chain's only damage is the honest crash pattern — a
    torn final line — and a sibling exists beside it: ADR-0004 already
    handled this tear, and recording continued. The tear stays in the
    report as evidence; only the exit code stands down, or the scan
    becomes an alarm that never stops sounding. Any other damage is
    tampering to shout about, sibling or not."""
    broken = [l for l in detail if l.startswith("BROKEN")]
    return (len(broken) == 1 and "torn tail" in broken[0]
            and sibling_of(log).exists())


# --- Baseline -----------------------------------------------------------------
# The tripwire's memory (GLOSSARY: Baseline): every chain's last-seen
# head, kept beside what it watches — the store's home in store mode
# (ADR-0011), the legacy root folder otherwise. Writer-reachable by definition,
# therefore trusted for nothing — a disagreement is a reason to
# investigate, never a verdict about which side is true. Verdicts come
# from verify; the out-of-reach copy, if you keep one, is the anchor.

BASELINE_NAME = ".supervisor-baseline.json"

INVESTIGATE = ("investigate — this memory is writer-reachable and decides "
               "nothing; run loxodonta verify and check your anchors")

CHANGE_WORDS = {
    "rewritten": "the head seen last look is no longer in this chain's "
                 "history — change appends cannot explain; " + INVESTIGATE,
    "regressed": "this chain is shorter than it was last look — receipts "
                 "do not un-happen; " + INVESTIGATE,
    "vanished": "this chain was here last look and is gone; " + INVESTIGATE,
}


def read_baseline(path):
    """The remembered heads and the keeper's attempt times, plus a note
    when the file could not be read. An unreadable memory is reported
    and replaced, never repaired and never trusted — this look simply
    remembers afresh."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        chains = data["chains"]
        if not all(isinstance(known, dict) and "head" in known
                   and "n" in known for known in chains.values()):
            raise ValueError("baseline rows must remember a head and an n")
        keeper = data.get("keeper")
        calibration = [epoch for epoch in data.get("calibration", [])
                       if isinstance(epoch, dict)
                       and isinstance(epoch.get("matchers"), list)]
        sessionend = data.get("sessionend")
        return (chains, keeper if isinstance(keeper, dict) else {},
                calibration,
                sessionend if isinstance(sessionend, dict) else {}, None)
    except FileNotFoundError:
        return {}, {}, [], {}, None  # cold start: seed silently
    except (ValueError, KeyError, TypeError, AttributeError,
            json.JSONDecodeError, OSError):
        return {}, {}, [], {}, ("the baseline could not be read — "
                                "remembering afresh from this look; it "
                                "was trusted for nothing either way")


def diff_baseline(remembered, relpath, entries):
    """One chain against the memory of it: None when appends explain
    everything (or the chain is new), else the change kind."""
    known = remembered.get(relpath)
    if known is None:
        return None
    at_n = {entry.get("n"): entry.get("entry_hash") for entry in entries}
    if at_n.get(known["n"]) == known["head"]:
        return None  # still there, possibly grown past — appends explain it
    if entries and max((n for n in at_n if isinstance(n, int)),
                       default=-1) < known["n"]:
        return "regressed"
    if not entries:
        return "regressed"
    return "rewritten"


# --- The day book -------------------------------------------------------------
# The baseline above remembers heads; this remembers days. One row per
# UTC day, so the page can answer the third question a monitoring
# surface owes its operator — "is this a trend or a one-off?" — before
# anyone drills into anything.
#
# It also counts its own looks, and that is the point. Our claim is
# detection latency, and detection latency is a function of how often
# the operator actually looks. A front page designed to read quiet every
# morning teaches the operator its answer and then goes unread; the
# chain stays silent about that, because the thing that stopped working
# is the reading of it. A run of unwatched days is the only shape that
# failure has, so the surface keeps it where the alarm lives.
#
# Testimony like everything else here: writer-reachable, trusted for
# nothing, and it decides no verdicts (ADR-0014).

DAYBOOK_NAME = ".supervisor-daybook.json"
DAYBOOK_SEASON = 90  # how many days the book keeps
FORTNIGHT = 14  # how many the band shows

DAYBOOK_PURPOSE = ("the supervisor's day-by-day memory of its own looks — "
                   "writer-reachable, trusted for nothing")


def read_daybook(path):
    """The remembered days. An unreadable book is replaced, never
    repaired — the same posture the baseline takes."""
    try:
        days = json.loads(path.read_text(encoding="utf-8"))["days"]
        return days if isinstance(days, dict) else {}
    except (OSError, ValueError, KeyError, TypeError,
            json.JSONDecodeError):
        return {}


def write_daybook(path, days, now):
    """Keep a season, forget the rest, and never let a write failure
    take the tick down with it — the book is a convenience, and the
    verdicts do not live here.

    Pruned by date, not by row count: a book that went unwritten for a
    year should forget that year, not keep it because it is short."""
    oldest = (now - timedelta(days=DAYBOOK_SEASON)).strftime("%Y-%m-%d")
    kept = {day: row for day, row in sorted(days.items()) if day >= oldest}
    try:
        path.write_text(
            json.dumps({"purpose": DAYBOOK_PURPOSE, "days": kept},
                       indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    return kept


def remember_day(path, now, tally):
    """Fold one tick into today's row.

    The day's worst is sticky: a tripwire that fired at 09:00 still
    colours the day at 17:00, because "was today clean?" is a different
    question from "is it clean right now?" — and the strip above
    already answers the second one."""
    days = read_daybook(path)
    today = now.strftime("%Y-%m-%d")
    row = dict(days.get(today) or {})
    for claim, seen in tally.items():
        if claim != "chains":
            row[claim] = max(row.get(claim, 0), seen)
    row["chains"] = tally["chains"]  # a count of now, not a high-water mark
    row["scans"] = row.get("scans", 0) + 1
    row["looks"] = row.get("looks", 0)
    row["last"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    days[today] = row
    return write_daybook(path, days, now)


def remember_look(path, now):
    """Someone opened the front page. Counted separately from scans,
    which the poll drives on its own."""
    days = read_daybook(path)
    today = now.strftime("%Y-%m-%d")
    row = dict(days.get(today) or {})
    row["looks"] = row.get("looks", 0) + 1
    days[today] = row
    write_daybook(path, days, now)


# What a day contributes to the band, as against what the book keeps
# for itself. The scan tally and the last-scan stamp stay on disk: they
# move on every tick, and a report that changes when nothing changed
# would break the one invariant worth having here — two looks at an
# unchanged store say the same thing, whether printed or served.
PAINTED = ("worst", "chains", "broken", "events", "alarms",
           "reawakenings")


def fortnight(days, now):
    """The last FORTNIGHT days, oldest first, gaps included.

    A day nobody watched carries no claim at all — no worst, no counts.
    It must never paint like a quiet day, because it isn't one: it is a
    day this machine's history went unread."""
    band = []
    for back in range(FORTNIGHT - 1, -1, -1):
        day = (now - timedelta(days=back)).strftime("%Y-%m-%d")
        row = days.get(day) if isinstance(days.get(day), dict) else None
        seen = {"day": day, "looks": (row or {}).get("looks", 0)}
        if row is not None and "worst" in row:
            band.append({**seen, "watched": True,
                         **{claim: row.get(claim, 0) for claim in PAINTED}})
        else:
            band.append({**seen, "watched": False})
    return band


# --- Anchor keeper ------------------------------------------------------------
# Freshness assessed every tick; pending proofs completed by driving the
# public CLI's upgrade path — the ritual the dogfood proved nobody
# remembers, absorbed. Staleness is quiet evidence, never an exit shout:
# an aging head is not news the operator can act on every tick, and a
# siren that never stops sounding trains them to ignore the band.

# How often the keeper may ask a calendar about the same log. The env
# knob is the test suite's clock handle.
UPGRADE_EVERY_SECONDS = int(
    os.environ.get("SUPERVISOR_UPGRADE_EVERY_SECONDS", 3600))

ANCHORED_LINE = re.compile(
    r"^ANCHORED: entries 0\.\.(\d+) existed by Bitcoin block (\d+)")
PENDING_LINE = re.compile(
    r"^ANCHOR-PENDING: head (\S+) submitted (\S+) via (\S+)")


def parse_cadence(text):
    """A duration the operator can say out loud: 30s, 15m, 6h, 1d, or
    bare seconds. Used by --anchor-every and --publish-every."""
    match = re.fullmatch(r"(\d+)([smhd]?)", text.strip())
    if not match:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a cadence (try 6h, 1d, or seconds)")
    return int(match.group(1)) * {"": 1, "s": 1, "m": 60,
                                  "h": 3600, "d": 86400}[match.group(2)]


def upgrade_due(last_attempt, now):
    attempted = parse_when(last_attempt)
    # A memory from the future is nonsense and reads as no memory: the
    # throttle lives in a writer-reachable file, and a nonsense value
    # must never stand the keeper down — it would do so silently and
    # forever, which is exactly what an adversary would want from it.
    if attempted is None or attempted > now:
        return True
    return (now - attempted).total_seconds() >= UPGRADE_EVERY_SECONDS


def sidecar_records(sidecar):
    """The records of a file beside a chain (the anchor sidecar, the
    publish memo), read tolerantly and for scheduling or display only —
    judging the proofs stays with verify. A missing file, a torn line,
    or a line that is not an object yields nothing."""
    try:
        with open(sidecar, encoding="utf-8", errors="replace") as lines:
            for line in lines:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    yield record
    except FileNotFoundError:
        return


def sidecar_heads(sidecar):
    """Heads that already have a record, for scheduling only."""
    return {record["head"] for record in sidecar_records(sidecar)
            if isinstance(record.get("head"), str)}


def ripe_head(entries, now, cadence):
    """The chain head once it has aged past the cadence, else None: the
    ripeness test both keepers share. No cadence means no opt-in, and a
    head with no readable birth time never ripens — the keeper sends
    nothing it cannot date."""
    if cadence is None or not entries:
        return None
    born = parse_when(entries[-1].get("ts"))
    if born is None or (now - born).total_seconds() < cadence:
        return None
    return entries[-1].get("entry_hash") or None


def keep_anchors(log, last_attempt, now, entries, cadence, calendars):
    """One chain's turn with the keeper, at most once per throttle
    window: pending proofs are driven through `loxodonta anchor
    --upgrade` (the record's own calendar; judgment stays with verify),
    and — only when the operator opted in with a cadence — a fresh head
    that has aged past it is anchored. Off by default: nothing leaves
    the machine without the say-so. Returns (attempted, note, failed)."""
    sidecar = Path(str(log) + ".anchors.jsonl")
    if not upgrade_due(last_attempt, now):
        return False, None, False
    attempted = False
    notes = []  # one turn can fail twice; every failure stays said
    failed = False
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    if sidecar.exists():
        finished = subprocess.run(
            [sys.executable, str(LOXODONTA), "anchor", "--upgrade",
             f"--log={log}"],
            capture_output=True, encoding="utf-8", env=env)
        attempted = True
        if finished.returncode != 0:
            notes.append("upgrade attempted; a calendar did not answer — "
                         "proofs stay pending and the keeper will try again")
    if cadence is not None and entries:
        head = ripe_head(entries, now, cadence)
        if head and head not in sidecar_heads(sidecar):
            command = [sys.executable, str(LOXODONTA), "anchor",
                       f"--log={log}"]
            for calendar in calendars:
                command += ["--calendar", calendar]
            finished = subprocess.run(command, capture_output=True,
                                      encoding="utf-8", env=env)
            attempted = True
            if finished.returncode != 0:
                failed = True
                notes.append("anchoring failed — no calendar accepted "
                             "this head; it stays unanchored and the "
                             "keeper will try again")
    return attempted, "; ".join(notes) or None, failed


# --- Publish keeper -----------------------------------------------------------
# The keeper's half of the published head (ADR-0025 ruling 3), for
# always-on machines and for sessions that never reached their end: the
# bad day is a stripped hook, so no session end ever fired and nothing
# was published or anchored. Same throttle, same ripeness test, same
# posture as the anchor keeper: off by default, staleness quiet.

def publish_url(value):
    """argparse validator for --publish-url: the recorder's rule, twice
    over, since the two files never import each other. A plain http or
    https URL with nothing a shell could act on (a quote, a backtick, a
    dollar sign, a backslash, whitespace): the recorder's `publish`
    refuses anything else, so refusing here too makes a bad URL a usage
    error (exit 64) before the first tick, never a failure note on
    every tick."""
    parts = urlparse(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not an http or https URL")
    if any(c in "\"'`$\\" or c.isspace() for c in value):
        raise argparse.ArgumentTypeError(
            f"{value!r} holds a character a shell could act on (a quote, "
            "a backtick, a dollar sign, a backslash, or whitespace)")
    return value


PUBLISH_BACKSTOP = 60   # seconds; well past the recorder's own bound


def keep_published(log, last_attempt, now, entries, cadence, url):
    """One chain's turn with the publish keeper, on the anchor keeper's
    throttle: only when the operator opted in with a cadence and a URL,
    a head that has aged past the cadence and is not yet in the chain's
    publish memo is posted once, through `loxodonta publish`. The memo
    is the recorder's (`<log>.published.jsonl`), writer-reachable and
    therefore testimony: it stops a repeat and proves nothing; the
    remote's copy is the head record. Off by default: nothing leaves
    the machine without the say-so. Returns (attempted, note, failed)."""
    if not url or not upgrade_due(last_attempt, now):
        return False, None, False
    memo = Path(str(log) + ".published.jsonl")
    head = ripe_head(entries, now, cadence)
    if not head or head in sidecar_heads(memo):
        return False, None, False
    try:
        finished = subprocess.run(
            [sys.executable, str(LOXODONTA), "publish", f"--log={log}", url],
            capture_output=True, encoding="utf-8", timeout=PUBLISH_BACKSTOP,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    except subprocess.TimeoutExpired:
        # The recorder bounds its own POST; this is the backstop above
        # it, so one stuck publish can never hold a tick.
        return True, ("publishing did not finish in time; the head stays "
                      "unpublished and the keeper will try again"), True
    if finished.returncode == 64:
        # A usage exit is the URL refused, not the remote: retrying
        # would never help, and the note must say so.
        return True, ("publishing refused: the recorder would not take "
                      "--publish-url as given; fix the URL (see "
                      "`loxodonta publish --help`)"), True
    if finished.returncode != 0:
        # The recorder's stderr names the failure and never the URL, but
        # it is not repeated here: the note is the panel's, and one
        # sentence the operator can act on beats a transport error.
        return True, ("publishing failed — the remote did not take this "
                      "head; it stays unpublished and the keeper will try "
                      "again"), True
    return True, None, False


def last_departure(log):
    """When a head of this chain last left the machine, and by which
    door: the newest `ts` across the publish memo and the anchor
    sidecar, or {"ts": None, "via": None} when nothing has left. The
    reading is the panel's staleness evidence, in the anchor keeper's
    voice: a timestamp the reader ages, never an alarm, never the exit.
    Both files are writer-reachable, so a fresh reading here proves
    nothing; a stale one is the reason to look."""
    departures = []   # (when, ts, via)
    for record in sidecar_records(Path(str(log) + ".published.jsonl")):
        when = parse_when(record.get("ts"))
        if when is not None:
            departures.append((when, record["ts"], "published"))
    # An upgrade appends a second record for the same head, stamped
    # when the proof completed, so a head's departure is its first
    # record: the newest record would make an idle chain read fresh
    # every time a calendar answered a poll.
    first = {}
    for record in sidecar_records(Path(str(log) + ".anchors.jsonl")):
        when = parse_when(record.get("ts"))
        head = record.get("head")
        if when is not None and head is not None \
                and (head not in first or when < first[head][0]):
            first[head] = (when, record["ts"])
    departures += [(when, ts, "anchored") for when, ts in first.values()]
    if not departures:
        return {"ts": None, "via": None}
    _, ts, via = max(departures, key=lambda d: d[0])
    return {"ts": ts, "via": via}


def assess_anchors(detail, entries):
    """The panel's data, read from verify's own words (the documented
    verdict lines are the seam, ADR-0005): anchored spans with their
    block heights, pending proofs with their submission times, and the
    chain head with whether any anchor covers it. Ages are the reader's
    to compute — the report carries timestamps, not clocks."""
    anchored = []
    pending = []
    for line in detail:
        span = ANCHORED_LINE.match(line)
        if span:
            anchored.append({"upto": int(span.group(1)),
                             "height": int(span.group(2))})
        wait = PENDING_LINE.match(line)
        if wait:
            pending.append({"head": wait.group(1),
                            "submitted": wait.group(2),
                            "calendar": wait.group(3)})
    head = None
    if entries:
        n = entries[-1].get("n")
        head = {"n": n, "ts": entries[-1].get("ts"),
                "anchored": isinstance(n, int)
                and any(span["upto"] >= n for span in anchored)}
    return {"anchored": anchored, "pending": pending, "head": head}


# --- Completeness -------------------------------------------------------------
# The flagship (issue #22): pair what the harness transcript witnessed
# with what the chain received, per session, and shout while the session
# is still live. Honest scope, carried from the grill: this catches
# accidents — the disabled hook, the wedged lock, the silent fork — and
# shortens the window between loss and discovery. The transcript is
# testimony too; a writer shaping both is beyond this alarm.
# Completeness itself stays the integration's job.

# Ratified thresholds; the env knobs are the test suite's clock handle.
GRACE_SECONDS = int(os.environ.get("SUPERVISOR_GRACE_SECONDS", 30))
IDLE_END_SECONDS = int(os.environ.get("SUPERVISOR_IDLE_END_SECONDS", 1800))
# The lifecycle tiers (ADR-0018): flat and legible on purpose, decided
# by observation epochs — how long the supervisor's own looks have seen
# a session's chains not move. Defaults survived the real-store gap
# measurement (docs/EXPERIMENTS.md §5): honest week-later resumes exist
# and are meant to surface — reasons to look, never alarms.
WANING_SECONDS = int(os.environ.get("SUPERVISOR_WANING_SECONDS", 86400))
DORMANT_SECONDS = int(os.environ.get("SUPERVISOR_DORMANT_SECONDS",
                                     172800))
# The tail keeper (ADR-0018 ruling 6): on by default — protective
# recording does not ask permission (ADR-0017's reasoning) — and
# disableable for stores where the operator wants annotations only.
TAIL_KEEPER = os.environ.get("SUPERVISOR_TAIL_KEEPER", "1") != "0"

WITNESS_ROOT = Path.home() / ".claude" / "projects"

WATCH_WORDS = {
    "ALARM-SILENT": "the witness saw tools run but no receipt has arrived "
                    "since the deficit began — recording stopped (disabled "
                    "hook? wedged lock?). An accident detector: investigate "
                    "while the session is live.",
    "ALARM-DEFICIT": "receipts still arrive but fewer than the witness saw "
                     "— the fork-shaped hole, where a chain reads intact "
                     "with entries missing. An accident detector: "
                     "investigate while the session is live.",
    "ENDED-DEFICIT": "the session ended short of the witness's count — "
                     "those receipts are missing forever; kept as "
                     "evidence, not as a siren.",
    "ENDED-SURPLUS": "the session ended with more receipts than witnessed "
                     "tools — witness lag frozen at end, or receipts that "
                     "arrived unwitnessed; kept as evidence, not as a "
                     "siren.",
    "SURPLUS": "more receipts than witnessed tools — witness lag, or "
               "receipts arriving unwitnessed; investigate. A flag, "
               "never a verdict.",
    "LAGGING": "behind the witness inside the grace window — an honest "
               "lock wait looks like this; no shout yet.",
    "UNWITNESSED": "no transcript pairs with this session — completeness "
                   "cannot be watched for it; nothing is assumed "
                   "either way.",
    "UNWATCHED": "no recorder hook is wired into the harness settings — "
                 "nothing owes a receipt, so there is nothing to be "
                 "behind.",
}


def munge(path):
    """A project path the way the harness names its transcript folder:
    every character that isn't a letter, digit, or dash becomes a dash."""
    return re.sub(r"[^A-Za-z0-9-]", "-", str(path))


def hook_matchers(witness):
    """Which tools owe a receipt: the PostToolUse matchers wired to
    receipts, read from the harness settings beside the witness layout.
    No wired hook means nothing owes a receipt — a session can never be
    behind a recorder that was never asked to record."""
    try:
        settings = json.loads((witness.parent / "settings.json")
                              .read_text(encoding="utf-8"))
        rules = settings["hooks"]["PostToolUse"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    matchers = []
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        commands = rule.get("hooks")
        wired = isinstance(commands, list) and any(
            isinstance(hook, dict)
            # Either era's name (ADR-0010): an install that predates the
            # rename still owes receipts, and is still watched.
            and any(marker in str(hook.get("command", ""))
                    for marker in ("receipts", "loxodonta"))
            for hook in commands)
        if wired:
            matchers.append(str(rule.get("matcher", "*")))
    return matchers


def sessionend_wired(witness):
    """True when a recorder SessionEnd hook is observably wired beside
    the witness layout — the exit commitment's precondition, and the
    uncommitted-tail annotation's gate (ADR-0018)."""
    try:
        settings = json.loads((witness.parent / "settings.json")
                              .read_text(encoding="utf-8"))
        rules = settings["hooks"]["SessionEnd"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return any(
        isinstance(rule, dict)
        and any(isinstance(hook, dict)
                and any(marker in str(hook.get("command", ""))
                        for marker in ("receipts", "loxodonta"))
                for hook in rule.get("hooks", [])
                if isinstance(rule.get("hooks"), list))
        for rule in (rules if isinstance(rules, list) else []))


def sessionend_epoch(remembered, witness, now):
    """Since when the exit commitment has been possible (ADR-0018): the
    calibration pattern's third use. First observation of a wired
    SessionEnd hook stamps now — the supervisor claims no knowledge
    older than its own memory — and only sessions active after that
    epoch are ever judged for an uncommitted tail: everything earlier
    is uncommitted by history, not by misbehavior."""
    wired = sessionend_wired(witness)
    since = remembered.get("since") if isinstance(remembered, dict) else None
    if wired and not since:
        since = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"wired": wired, "since": since}


def calibrate(remembered, witness, now):
    """Effective-dated coverage (ADR-0016): the supervisor's memory of
    which matchers were wired when, so a matcher change never re-judges
    history the old rules recorded honestly. The first observation
    covers all time before it; a change is dated by the settings file's
    mtime, clamped between the last observation and now — the best
    estimate available, since the harness does not log its own config
    changes. Lives in the baseline: writer-reachable, trusted for
    nothing beyond calibration."""
    current = hook_matchers(witness)
    if remembered and remembered[-1]["matchers"] == current:
        return remembered
    if not remembered:
        return [{"since": None, "matchers": current}]
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        changed = datetime.fromtimestamp(
            (witness.parent / "settings.json").stat().st_mtime,
            timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        changed = stamp
    floor = remembered[-1]["since"] or ""
    return remembered + [{"since": min(max(changed, floor), stamp),
                          "matchers": current}]


def matchers_at(calibration, ts):
    """The matchers in force at one moment: the newest observation not
    after `ts` (ISO timestamps compare as strings). A time before the
    first observation gets the first — the supervisor claims no
    knowledge older than its own memory — and a missing timestamp gets
    the present."""
    if not calibration:
        return []
    if not isinstance(ts, str):
        return calibration[-1]["matchers"]
    chosen = calibration[0]["matchers"]
    for epoch in calibration[1:]:
        if epoch["since"] <= ts:
            chosen = epoch["matchers"]
    return chosen


# --- The recorder notice ------------------------------------------------------
# The harness executes a *path*, not a version, so the recorder running
# on this machine is whatever is checked out there at the moment a tool
# fires. Nothing pins it and nothing copies it. This reports that state
# and corrects none of it: reading local git only, never the network,
# because a recorder that updated itself from a remote would hand the
# writer a second road to the one file that has to stay honest
# (ADR-0002). Drift is the operator's to resolve, deliberately.

RECORDER_NAMES = ("loxodonta.py", "receipts.py")


def recorder_path(witness):
    """The file the harness actually runs for PostToolUse, read out of
    the wired command line — the only place that truth lives. Either
    era's name (ADR-0010)."""
    try:
        settings = json.loads((witness.parent / "settings.json")
                              .read_text(encoding="utf-8"))
        rules = settings["hooks"]["PostToolUse"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        for hook in rule.get("hooks") or []:
            if not isinstance(hook, dict):
                continue
            # Quoted first: a path with spaces is one token, not several.
            for quoted, bare in re.findall(r'"([^"]+?\.py)"|(\S+\.py)',
                                           str(hook.get("command", ""))):
                candidate = Path(quoted or bare)
                if candidate.name in RECORDER_NAMES:
                    return candidate
    return None


def git_say(home, *question):
    """One read-only git question, or None when git cannot answer —
    absent, or the path is not a checkout. Never fetches, never writes."""
    try:
        answered = subprocess.run(["git", "-C", str(home), *question],
                                  capture_output=True, encoding="utf-8")
    except (OSError, ValueError):
        return None
    return answered.stdout.strip() if answered.returncode == 0 else None


def recorder_drift(witness):
    """Which recorder is running, and whether it is the one the operator
    thinks. Testimony like everything else local: it says what the
    checkout looks like, never that the code is trustworthy."""
    script = recorder_path(witness)
    if script is None:
        return {"state": "unwired", "path": None, "branch": None,
                "note": "no recorder hook is wired into the harness "
                        "settings — nothing is recording, so there is no "
                        "recorder to drift"}
    notice = {"state": "unknown", "path": script.as_posix(), "branch": None,
              "head": None, "dirty": False, "upstream": None,
              "ahead": None, "behind": None, "fetched": None, "note": None}
    if not script.exists():
        notice["note"] = ("the wired recorder is not on disk — the hook "
                          "runs nothing, and a session that records "
                          "nothing looks exactly like a quiet one")
        return notice
    home = script.parent
    branch = git_say(home, "rev-parse", "--abbrev-ref", "HEAD")
    if branch is None:
        notice["note"] = ("the recorder is not in a git checkout, or git "
                          "is unavailable — only its path can be read "
                          "from here, not its version")
        return notice
    notice.update({
        "state": "tracked",
        "branch": branch,
        "head": git_say(home, "rev-parse", "--short", "HEAD"),
        # Only the executed file matters: an unrelated dirty file in the
        # same checkout is not drift in the recorder.
        "dirty": bool(git_say(home, "status", "--porcelain", "--",
                              script.name)),
        "upstream": git_say(home, "rev-parse", "--abbrev-ref",
                            "--symbolic-full-name", "@{u}"),
    })
    if notice["upstream"]:
        counts = git_say(home, "rev-list", "--left-right", "--count",
                         "@{u}...HEAD")
        if counts and len(counts.split()) == 2:
            behind, ahead = counts.split()
            notice["behind"], notice["ahead"] = int(behind), int(ahead)
        git_dir = git_say(home, "rev-parse", "--git-dir")
        if git_dir:
            stamp = (home / git_dir) / "FETCH_HEAD"
            try:
                notice["fetched"] = datetime.fromtimestamp(
                    stamp.stat().st_mtime, timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            except OSError:
                pass  # never fetched here; the counts say so themselves
    notice["note"] = recorder_words(notice)
    return notice


def recorder_words(notice):
    """The notice in one sentence, worst thing first. Behind-counts are
    only as fresh as the last fetch and say so, because a stale count
    that reads as reassurance is worse than no count."""
    said = []
    if notice["dirty"]:
        said.append("the recorder has uncommitted changes — the file "
                    "being executed is not the file that was reviewed")
    if notice["behind"]:
        said.append(f"the checkout is {notice['behind']} commit(s) behind "
                    f"{notice['upstream']} as of the last fetch"
                    + (f" ({notice['fetched']})" if notice["fetched"]
                       else ", which has never run here")
                    + " — pull deliberately; nothing updates it for you")
    if notice["ahead"]:
        said.append(f"the checkout is {notice['ahead']} commit(s) ahead of "
                    f"{notice['upstream']} — you are recording with code "
                    "that has not been pushed")
    if not said:
        said.append(f"recording from {notice['branch']} at "
                    f"{notice['head']}, clean")
    return "; ".join(said)


def owes_receipt(name, matchers):
    for matcher in matchers:
        if matcher in ("", "*"):
            return True
        try:
            if re.fullmatch(matcher, name or ""):
                return True
        except re.error:
            continue
    return False


def read_witness(transcript, calibration):
    """The witness signal: timestamps of tool events that owe a receipt.
    A tool event is a tool_use block paired by id with its result line;
    only completed results count (failed calls fire no hook — the
    field's suppression finding) and only tools covered at the event's
    own time (the calibration finding, effective-dated by ADR-0016: an
    all-tools witness over an Edit|Write|Bash hook manufactures
    deficits, and so does today's wide matcher over yesterday's narrow
    sessions). Chatter is never counted: a chat-only session can never
    alarm. Returns (events, latest): latest is the newest timestamped
    record of any conversational kind — the session's liveness clock.
    Chatter moves it (a chat-only session is alive); the harness's
    timestamp-less metadata records (bridge-session, custom-title,
    appended to ended transcripts by restart and resume) never do,
    because an idle clock that resets on metadata re-presents an old
    deficit as an immortal live alarm (issue #85)."""
    names = {}
    events = []
    latest = None
    with open(transcript, encoding="utf-8", errors="replace") as lines:
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            stamped = parse_when(record.get("timestamp"))
            if stamped is not None:
                if stamped.tzinfo is None:
                    stamped = stamped.replace(tzinfo=timezone.utc)
                if latest is None or stamped > latest:
                    latest = stamped
            message = record.get("message")
            blocks = (message.get("content")
                      if isinstance(message, dict) else None)
            if not isinstance(blocks, list):
                blocks = []
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    names[block.get("id")] = block.get("name")
            result = record.get("toolUseResult")
            if result is None:
                continue
            if isinstance(result, dict) and result.get("is_error"):
                continue
            found = next((block for block in blocks
                          if isinstance(block, dict)
                          and block.get("type") == "tool_result"), None)
            if found is not None and found.get("is_error"):
                # A failed call, as the harness really writes it: the
                # result collapses to an error string and the flag sits
                # on the tool_result block (field capture, 2026-08-29).
                continue
            name = names.get(found.get("tool_use_id")) if found else None
            when = record.get("timestamp")
            if owes_receipt(name, matchers_at(calibration, when)):
                events.append(when)
    return events, latest


def classify(tools, receipts, ended, idle, deficit_age, silent):
    """The ratified alarm state machine (issue #22, from the #15
    prototype) — a pure reading of the evidence. Deficit is sticky:
    lost receipts never arrive later, so a session keeps its scar until
    end-of-session reconciliation reports it as evidence."""
    deficit = max(0, tools - receipts)
    if ended:
        if receipts > tools:
            return "ENDED-SURPLUS"
        return "ENDED-CLEAN" if deficit == 0 else "ENDED-DEFICIT"
    if idle:
        return "IDLE-CLEAN" if deficit == 0 else "IDLE-DEFICIT"
    if receipts > tools:
        return "SURPLUS"
    if tools == 0:
        return "QUIET"
    if deficit == 0:
        return "OK"
    if deficit_age is not None and deficit_age < GRACE_SECONDS:
        return "LAGGING"
    return "ALARM-SILENT" if silent else "ALARM-DEFICIT"


def watch_session(transcript, receipts, last_receipt, now, calibration):
    """One session against its witness. deficit_since needs no stored
    state: receipts pair with tool events in order, so the first
    unpaired event's timestamp is when the deficit began."""
    events, latest = read_witness(transcript, calibration)
    tools = len(events)
    # The idle clock reads the newest timestamped record, not file
    # mtime: the harness touches ended transcripts with timestamp-less
    # metadata, and an mtime clock resets on every touch (issue #85).
    # mtime remains the fallback for a transcript holding no
    # timestamped record at all.
    if latest is not None:
        quiet_for = (now - latest).total_seconds()
    else:
        quiet_for = now.timestamp() - transcript.stat().st_mtime
    # Today both flags read from the idle window ("witness quiet this
    # long ⇒ session treated as ended"); they separate if the harness
    # ever writes an explicit end marker.
    ended = idle = quiet_for >= IDLE_END_SECONDS
    deficit_since = (parse_when(events[receipts])
                     if tools > receipts else None)
    deficit_age = ((now - deficit_since).total_seconds()
                   if deficit_since else None)
    arrived = parse_when(last_receipt)
    silent = arrived is None or (deficit_since is not None
                                 and arrived < deficit_since)
    state = classify(tools, receipts, ended, idle, deficit_age, silent)
    return state, tools


def keep_tails(sessions):
    """The tail keeper (ADR-0018 ruling 6): for every ended session the
    watch annotated tail-uncommitted, write the missing exit commitment
    through the recorder itself — the public seam, ADR-0005 discipline —
    by handing `loxodonta hook` a SessionEnd payload. A commitment is
    honest whenever it is taken; it commits the transcript's bytes as
    they are now. Every failure is a silent skip: the recorder's ending
    branch already refuses damaged tails, missing transcripts, and lost
    locks on its own, and an exit-keeper that complained would be noise
    nobody can act on. Returns how many commitments actually landed."""
    kept = 0
    for row in sessions:
        if not row.get("uncommitted_tail") or not row.get("home"):
            continue
        payload = json.dumps({
            "session_id": row["session"],
            "hook_event_name": "SessionEnd",
            "reason": "tail-keeper",
            "transcript_path": row.get("transcript", ""),
        }).encode("utf-8")
        try:
            done = subprocess.run(
                [sys.executable, str(LOXODONTA), "hook",
                 f"--log-dir={row['home']}"],
                input=payload, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        # The recorder exits 0 for skips too; an appended entry is the
        # only proof a commitment landed.
        if done.returncode == 0 and b"logged entry" in done.stdout:
            kept += 1
    return kept


def lifecycle_tier(last_grew, now):
    """The dormancy tier (ADR-0018), from observed stillness alone:
    how long the supervisor's own looks have seen no movement. Returns
    (tier, seconds) or None when nothing has been observed yet."""
    when = parse_when(last_grew)
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    still = (now - when).total_seconds()
    tier = ("dormant" if still >= DORMANT_SECONDS
            else "waning" if still >= WANING_SECONDS else "awake")
    return tier, int(still)


def watch_completeness(root, witness, families, everywhere=False,
                       calibration=None, sessionend=None):
    """The completeness half of a tick: every census session paired with
    its transcript, plus witnessed sessions that never grew a chain at
    all — the disabled-hook case the census alone can never see.
    `everywhere` is store mode (ADR-0011): the store covers the whole
    machine, so every witnessed project is this scan's business, not
    just folders under one root. `calibration` is the effective-dated
    coverage memory (ADR-0016); without one, this look's wired matchers
    are taken to have always been in force."""
    now = datetime.now(timezone.utc)
    watch = {"witness": witness.as_posix(), "sessions": []}
    ours = munge(root)
    if calibration is None:
        calibration = [{"since": None, "matchers": hook_matchers(witness)}]
    matchers = calibration[-1]["matchers"]
    if len(calibration) > 1:
        watch["calibration"] = {
            "epochs": calibration,
            "words": ("the wired matchers changed on "
                      f"{calibration[-1]['since']} — each session is "
                      "judged by the coverage in force at its time "
                      "(ADR-0016)"),
        }
    transcripts = {}
    if witness.is_dir():
        transcripts = {t.stem: t for t in sorted(witness.glob("*/*.jsonl"))}
    else:
        watch["note"] = (f"witness absent — no transcript layout at "
                         f"{witness.as_posix()}; completeness cannot be "
                         "watched this look")
    if witness.is_dir() and not matchers:
        watch["note"] = ("no recorder hook is wired into the harness "
                         "settings beside this witness — nothing owes a "
                         "receipt, so completeness has nothing to watch")

    def add(repo, session, state, tools, receipts, drawers=(), judge=None,
            transcript=None):
        entry = {"repo": repo, "session": session, "state": state,
                 "tools": tools, "receipts": receipts,
                 "deficit": max(0, tools - receipts)}
        if len(drawers) > 1:
            entry["drawers"] = list(drawers)
        if state in WATCH_WORDS:
            entry["words"] = WATCH_WORDS[state]
        if judge:
            entry["judge"] = judge
        if transcript is not None:
            # The pairing itself, on the row: the tail keeper and
            # `package --transcript` read it here rather than pairing
            # again. Local by nature; WITNESS_FIELDS keeps it out of a
            # package.
            entry["transcript"] = transcript.as_posix()
        watch["sessions"].append(entry)
        return entry

    # One session, one watch. A single session's receipts can span
    # drawers: a worktree session logs to the main repo's drawer
    # (ADR-0011, because worktrees get pruned) while the harness still
    # names the transcript after the worktree it ran in. Pairing each
    # (repo, session) family with the transcript separately charged the
    # whole witness count to whichever drawer sorted first and left the
    # rest UNWITNESSED, manufacturing a deficit nobody owed. The witness
    # counts sessions, not drawers — so sum the family across drawers
    # and judge the session once.
    sessions = {}
    for (repo, session), family in sorted(families.items()):
        group = sessions.setdefault(session, {"drawers": [], "last": None})
        group["drawers"].append((family["receipts"], repo))
        if family["last"]:
            was_newest = group["last"] is None or family["last"] > group["last"]
            group["last"] = max(group["last"] or "", family["last"])
            # The tail that matters is the one still being written to —
            # the family whose receipts are newest (ADR-0018).
            if was_newest and "tail_committed" in family:
                group["tail_committed"] = family["tail_committed"]
                group["home"] = family.get("home")
        if family.get("last_grew", "") > (group.get("last_grew") or ""):
            group["last_grew"] = family["last_grew"]
        if "committed_log" in family and "judge_log" not in group:
            group["judge_log"] = family["committed_log"]
    for group in sessions.values():
        group["receipts"] = sum(n for n, _ in group["drawers"])
        # The session's home is the drawer holding most of it: the
        # worktree is pruned, the repo's drawer is what survives. Ties
        # go to the first name, so the label never wobbles between looks.
        group["repo"] = min(group["drawers"], key=lambda d: (-d[0], d[1]))[1]
        group["spans"] = sorted(name for _, name in group["drawers"])

    for session, group in sorted(sessions.items(),
                                 key=lambda kv: (kv[1]["repo"], kv[0])):
        repo, receipts = group["repo"], group["receipts"]
        spans = group["spans"]
        transcript = transcripts.pop(session, None)
        if transcript is None:
            add(repo, session, "UNWITNESSED", 0, receipts, spans)
            continue
        if not matchers:
            add(repo, session, "UNWATCHED", 0, receipts, spans,
                transcript=transcript)
            continue
        try:
            state, tools = watch_session(transcript, receipts,
                                         group["last"], now, calibration)
        except OSError:
            # A transcript that cannot be read (vanished mid-scan, or a
            # path that is not a readable file) costs this one session
            # its watch, never the whole scan. UNWITNESSED says it
            # honestly: completeness cannot be watched, nothing assumed.
            add(repo, session, "UNWITNESSED", 0, receipts, spans)
            continue
        # The supervisor locates, verify judges (ADR-0017): a committed
        # session with a living transcript gets the exact ritual command.
        judge = None
        if group.get("judge_log"):
            judge = (f'python "{LOXODONTA.as_posix()}" verify '
                     f'--log "{group["judge_log"]}" '
                     f'--transcript "{transcript.as_posix()}"')
        row = add(repo, session, state, tools, receipts, spans, judge=judge,
                  transcript=transcript)
        # The lifecycle facts (ADR-0018), quiet fields on the row.
        tier = lifecycle_tier(group.get("last_grew"), now)
        if tier:
            row["dormancy"] = {"tier": tier[0], "still_seconds": tier[1],
                               "since": group["last_grew"]}
        # The uncommitted tail: annotated only where the exit commitment
        # was possible (effective-dated on the wiring epoch) and the
        # session has ended with a tool receipt as its final word.
        # Neutral fact, never alarm-shaped: on clients with no clean
        # exit this is the common case, and the tail keeper closes it.
        if (sessionend and sessionend.get("wired") and sessionend.get("since")
                and state.startswith("ENDED")
                and group.get("tail_committed") is False
                and (group.get("last") or "") > sessionend["since"]):
            row["uncommitted_tail"] = True
            row["tail_note"] = ("tail uncommitted — no exit commitment "
                                "recorded")
            if group.get("home"):
                row["home"] = group["home"]

    # Chainless sessions: only transcript folders under this root are
    # this scan's business; a folder's name past the root prefix is the
    # best name the witness has for the project.
    for stem, transcript in transcripts.items():
        folder = transcript.parent.name
        if not matchers or (not everywhere and not folder.startswith(ours)):
            continue
        try:
            state, tools = watch_session(transcript, 0, None, now,
                                         calibration)
        except OSError:
            continue  # unreadable and chainless: nothing to say about it
        name = (folder if everywhere
                else folder[len(ours):].strip("-") or root.name)
        add(name, stem, state, tools, 0, transcript=transcript)

    return watch


# --- Consumption --------------------------------------------------------------
# The consumption watch (issue #67; OWASP GenAI LLM06 mitigation #8):
# wide coverage (ADR-0016) makes the chains a record of tool tempo —
# entries per session per hour — so a runaway loop or recursion without
# a clear end state shows up as a session burning far above this
# store's own norm. Everything read here is testimony (writer-stamped
# timestamps and action lines), so the watch never raises the scan exit
# and owns no verdicts. The boundary of the issue, held on purpose:
# this tool evidences someone else's circuit breaker; it never is one
# (.out-of-scope/001 — the hook stays outcome-blind).

# A session runs hot when its busiest sliding hour reaches HOT_TIMES x
# the median busiest hour of every *other* session, and at least
# HOT_FLOOR — below one entry a minute nothing is runaway, however
# small the norm. Peak against peaks, deliberately: an ordinary busy
# hour towers over the median *hour* of a store full of quiet ones
# (the first cut flagged a fifth of this machine's honest history);
# against other sessions' peaks, that same history sat inside 3x while
# a runaway loop still stands clear of it. The env knobs are the test
# suite's threshold handle.
HOT_TIMES = int(os.environ.get("SUPERVISOR_HOT_TIMES", 3))
HOT_FLOOR = int(os.environ.get("SUPERVISOR_HOT_FLOOR", 60))

CONSUMPTION_WORDS = {
    "RUNNING-HOT": "receipts arriving far above this store's norm and "
                   "still coming — a runaway loop or recursion without a "
                   "clear end state looks like this. Evidence for your "
                   "hand on the brake, never a brake itself.",
    "ENDED-HOT": "a session that burned far above the store's norm and "
                 "has gone quiet — kept as evidence, not a siren.",
}


def tool_of(action):
    """The tool inside an action line, the way the hook writes one —
    "Tool: summary" or a bare tool name. A line from any other writer
    is its own label, whole: testimony rendered, never interpreted."""
    head, sep, _ = str(action).partition(": ")
    return head if sep else str(action)


def busiest_hour(moments):
    """One session's peak tempo: the sliding hour holding the most
    entries, as (count, window start, dominant tool, its count). Two
    pointers over the sorted timestamps; ties keep the earliest
    window, so the figure never wobbles between looks."""
    stamped = sorted(m for m in moments if m[0] is not None)
    best, start = (0, None, None, 0), 0
    for end in range(len(stamped)):
        while (stamped[end][0] - stamped[start][0]).total_seconds() >= 3600:
            start += 1
        if end - start + 1 > best[0]:
            window = [tool for _, tool in stamped[start:end + 1]]
            top = max(set(window), key=window.count)
            best = (len(window), stamped[start][0], top, window.count(top))
    return best


def median_of(counts):
    ordered = sorted(counts)
    mid = len(ordered) // 2
    return (ordered[mid] if len(ordered) % 2
            else (ordered[mid - 1] + ordered[mid]) / 2)


def watch_consumption(families, now):
    """The consumption half of a tick: every census session's tempo
    against the store's norm, the hot ones surfaced. A session's
    drawers merge exactly as the completeness watch merges them — the
    tempo belongs to the session, not the drawer — and its home is the
    drawer holding most of it, ties to the first name."""
    sessions = {}
    for (repo, session), family in sorted(families.items()):
        group = sessions.setdefault(session, {"moments": [], "homes": []})
        moments = family.get("moments", ())
        group["moments"].extend(moments)
        group["homes"].append((len(moments), repo))
    peaks = {name: busiest_hour(group["moments"])
             for name, group in sessions.items()}
    # A session with no timestamped entries has no peak — it neither
    # sets the norm nor gets judged against one.
    samples = {name: peak[0] for name, peak in peaks.items() if peak[0]}
    if not samples:
        return {"norm": {"sessions_counted": 0,
                         "words": "no timestamped entries yet — there is "
                                  "no norm to deviate from"},
                "sessions": []}
    watch = {
        "norm": {
            "median_busiest_hour": median_of(samples.values()),
            "sessions_counted": len(samples),
            # The rule, and where the bar is set. Nobody discovers an
            # environment variable by looking at a dashboard, so the
            # panel names them rather than growing a control: `scan`
            # runs from the CLI and in CI too, and the environment is
            # the one place all three already agree (ADR-0027).
            "words": (f"hot means a busiest hour of at least "
                      f"max({HOT_FLOOR}, {HOT_TIMES} x the median busiest "
                      "hour of every other session) — a session never "
                      "sets its own norm. The norm is context for a "
                      "flag, never a verdict; timestamps are testimony. "
                      f"The bar moves with SUPERVISOR_HOT_FLOOR (now "
                      f"{HOT_FLOOR}) and SUPERVISOR_HOT_TIMES (now "
                      f"{HOT_TIMES}), read by the page, the CLI and CI "
                      "alike"),
        },
        "sessions": [],
    }
    for session, group in sorted(sessions.items()):
        # Deviation needs a norm the session did not write: the other
        # sessions' peaks. A store holding only this session has no
        # norm to deviate from, and says nothing rather than guessing.
        others = [peak for name, peak in samples.items() if name != session]
        if not others:
            continue
        threshold = max(HOT_FLOOR, HOT_TIMES * median_of(others))
        count, began, top, top_count = peaks[session]
        if count < threshold:
            continue
        last = max((when for when, _ in group["moments"]
                    if when is not None), default=None)
        live = (last is not None
                and (now - last).total_seconds() < IDLE_END_SECONDS)
        state = "RUNNING-HOT" if live else "ENDED-HOT"
        home = min(group["homes"], key=lambda h: (-h[0], h[1]))[1]
        watch["sessions"].append({
            "repo": home, "session": session, "state": state,
            "busiest_hour": count, "threshold": threshold,
            "window_start": began.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "top_tool": top, "top_tool_count": top_count,
            "words": CONSUMPTION_WORDS[state],
        })
    return watch


# --- Scan ---------------------------------------------------------------------

def scan_root(root, witness=WITNESS_ROOT, anchor_every=None, calendars=(),
              publish_every=None, publish_url=None, store=False, tick=True):
    """One tick without timers: census + verdicts + baseline diff +
    completeness watch as a report dict — what `scan` prints and what
    the status endpoint serves. The baseline is remembered anew after
    diffing, so an alarm belongs to the tick that caught it.

    Two universes, one walk: the store (ADR-0011 — root is the store's
    receipts folder, drawers name their repos, the baseline lives
    beside the store) or a legacy folder of repos under an explicit
    --root."""
    now = datetime.now(timezone.utc)
    if store:
        os.makedirs(root.parent, exist_ok=True)
        baseline_path = root.parent / "baseline.json"
        daybook = root.parent / "daybook.json"
    else:
        baseline_path = root / BASELINE_NAME
        daybook = root / DAYBOOK_NAME
    (remembered, keeper, calibration, sessionend,
     note) = read_baseline(baseline_path)
    # Observe the wired matchers before anything is judged, so this
    # tick's own judgments use a memory that includes this tick's look.
    calibration = calibrate(calibration, witness, now)
    sessionend = sessionend_epoch(sessionend, witness, now)
    events = []
    awakened = {}
    heads = {}
    families = {}
    # Walk in display order — repo, then session, then sibling sequence —
    # so the grouping below is plain insertion, no re-sorting.
    if store:
        found = (sorted(p for p in root.glob("*/receipts-*.jsonl")
                        if not p.name.endswith(SIDECAR_SUFFIXES))
                 if root.is_dir() else [])
        census = sorted((store_identity(log), log) for log in found)
    else:
        census = sorted((chain_identity(root, log), log)
                        for log in find_chains(root))
    repos = {}
    worst = 0
    damaged = 0
    for (repo, session, _), log in census:
        relpath = log.relative_to(root).as_posix()
        entries = read_entries(log)
        # `tick=False` is a reading: both keepers stay quiet, so a reader
        # that copies a chain (package) appends nothing to it and sends
        # nothing off the machine.
        attempted, keeper_note, anchor_failed = (
            keep_anchors(log, keeper.get(relpath), now, entries,
                         anchor_every, calendars)
            if tick else (False, None, False))
        posted, publish_note, publish_failed = (
            keep_published(log, keeper.get("publish:" + relpath), now, entries,
                           publish_every, publish_url)
            if tick else (False, None, False))
        # One throttle per keeper: an anchor attempt never delays the
        # publish keeper's turn, nor the other way round.
        if attempted:
            keeper[relpath] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        if posted:
            keeper["publish:" + relpath] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        verdict, exit_code, detail = verify(log)
        stood_down = exit_code != 0 and superseded(log, detail)
        chain = {
            "log": log.as_posix(),
            # Stranded in a worktree: still this repo's history, but pruning
            # the worktree deletes it — worth saying, not worth hiding.
            "worktree": ".claude" in log.relative_to(root).parts,
            # Parsed entries, not raw lines: a torn line is damage, not an
            # entry (GLOSSARY), and verify names the damage.
            "entries": len(entries),
            "verdict": verdict,
            "exit": exit_code,
            # VALID says the chain agrees with itself; ANCHORED says it
            # agrees with a Bitcoin block. Different claims, kept apart.
            "anchored": any(line.startswith("ANCHORED") for line in detail),
            "superseded": stood_down,
            "detail": detail,
            "anchors": assess_anchors(detail, entries),
            # When a head last left the machine, published or anchored
            # (ADR-0025): staleness evidence beside the anchor panel,
            # aged by the reader, never raising the exit.
            "left": last_departure(log),
        }
        if keeper_note:
            chain["anchors"]["note"] = keeper_note
        if anchor_failed:
            chain["anchors"]["failed"] = True
        if publish_note:
            chain["left"]["note"] = publish_note
        if publish_failed:
            chain["left"]["failed"] = True
        repos.setdefault(repo, {}).setdefault(session, []).append(chain)
        if not stood_down:
            # verify's TRANSCRIPT-DIVERGED is exit 5 in its own contract
            # (SPEC §6 v0.1.2); scan's 5 already means the baseline
            # tripwire, so the fold renames it rather than letting one
            # number tell two stories.
            worst = max(worst, 7 if exit_code == 5 else exit_code)
            if verdict == "BROKEN":
                damaged += 1

        change = diff_baseline(remembered, relpath, entries)
        if change:
            events.append({"repo": repo, "session": session, "log": relpath,
                           "change": change,
                           "investigate": CHANGE_WORDS[change]})
        if entries:
            # The lifecycle's clock (ADR-0018): the reader's own diary
            # of when it last saw this head move. An unchanged head
            # carries its stamp forward; a new or moved head — or a
            # baseline that predates the field — stamps this look, so
            # stillness only exists once it has actually been observed.
            known = remembered.get(relpath) or {}
            last_grew = (known.get("last_grew")
                         if known.get("head") == entries[-1].get("entry_hash")
                         and known.get("last_grew")
                         else now.strftime("%Y-%m-%dT%H:%M:%SZ"))
            heads[relpath] = {"n": entries[-1].get("n"),
                              "head": entries[-1].get("entry_hash"),
                              # For the digest's last-scan line (Stage E):
                              # a remembered verdict is testimony like the
                              # rest of this file, never the verdict itself.
                              "verdict": verdict,
                              # A torn tail that recording already moved
                              # past (ADR-0004) stood the exit down above;
                              # remembered so the digest can cite it as
                              # the quiet evidence it is, not fresh damage.
                              "superseded": stood_down,
                              "last_grew": last_grew}
            # The reawakening (ADR-0018): clean growth after dormant-tier
            # observed stillness — one-shot, spoken in the investigate
            # voice, never the exit. Rewrites belong to the tripwire, and
            # bookkeeping-only growth (the cadence or the tail keeper
            # writing commitments) is the recorder speaking, not the
            # session acting — it never wakes anything.
            woke = lifecycle_tier(known.get("last_grew"), now)
            if (change is None and known.get("head")
                    and entries[-1].get("entry_hash") != known.get("head")
                    and woke and woke[0] == "dormant"
                    and any(isinstance(e, dict)
                            and isinstance(e.get("n"), int)
                            and e["n"] > (known.get("n") or 0)
                            and e.get("actor") != "receipts"
                            for e in entries)):
                awakened[(repo, session)] = {
                    "repo": repo, "session": session, "log": relpath,
                    "still_seconds": woke[1],
                    "words": (f"grew after {woke[1] // 86400}d of "
                              "observed stillness — several quiet days, "
                              "or someone riding an old session; yours "
                              "to tell apart"),
                }

        # The session's receipt tally for the completeness watch: the
        # whole sibling family counts, minus the recorder's own voice —
        # genesis and transcript commitments carry actor "receipts" and
        # are owed by no tool event, so counting them would manufacture
        # SURPLUS on every committed session (ADR-0017).
        family = families.setdefault((repo, session),
                                     {"receipts": 0, "last": None,
                                      "moments": []})
        logged = [e for e in entries if e.get("actor") != "receipts"]
        family["receipts"] += len(logged)
        stamps = [e["ts"] for e in logged if isinstance(e.get("ts"), str)]
        if stamps:
            family["last"] = max(family["last"] or "", max(stamps))
        # And the same entries as (when, tool) moments for the
        # consumption watch — a stamp without a zone is read as UTC, so
        # one odd writer can never make two timestamps incomparable.
        for e in logged:
            when = parse_when(e.get("ts"))
            if when is not None and when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            family["moments"].append((when, tool_of(e.get("action"))))
        # ADR-0017: a chain holding transcript commitments earns the
        # operator's judge command once the watch pairs its transcript.
        if "committed_log" not in family and any(
                isinstance(e, dict) and e.get("actor") == "receipts"
                and str(e.get("action", "")).startswith(
                    "transcript-commitment:")
                for e in entries):
            family["committed_log"] = (root / relpath).as_posix()
        # The lifecycle facts (ADR-0018): the family's newest observed
        # movement, and whether the family's last chain ends in a
        # commitment (siblings sort after their parent, so the chain
        # seen last is the one still being written to).
        if entries:
            grew = heads[relpath]["last_grew"]
            if grew > (family.get("last_grew") or ""):
                family["last_grew"] = grew
            family["tail_committed"] = (
                entries[-1].get("actor") == "receipts"
                and str(entries[-1].get("action", "")).startswith(
                    "transcript-commitment:"))
            family["home"] = (root / relpath).parent.as_posix()

    for relpath in remembered:
        if relpath not in heads and not (root / relpath).exists():
            repo_name, session, _ = (store_identity(root / relpath) if store
                                     else chain_identity(root, root / relpath))
            events.append({"repo": repo_name, "session": session,
                           "log": relpath, "change": "vanished",
                           "investigate": CHANGE_WORDS["vanished"]})

    baseline_path.write_text(json.dumps({
        "purpose": "the supervisor's memory between looks — "
                   "writer-reachable, trusted for nothing",
        "scanned": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "chains": heads,
        "keeper": keeper,
        "calibration": calibration,
        "sessionend": sessionend,
    }, indent=2) + "\n", encoding="utf-8")
    if events:
        worst = max(worst, 5)

    completeness = watch_completeness(root, witness, families,
                                      everywhere=store,
                                      calibration=calibration,
                                      sessionend=sessionend)
    # The keeper closes what the annotation reports — after the rows
    # are judged, so this scan says the truth it saw and the next scan
    # sees the tails committed.
    kept = keep_tails(completeness["sessions"]) if tick and TAIL_KEEPER else 0
    # The consumption watch never touches `worst`: a hot session is a
    # reason to look, and the brake is the operator's (issue #67).
    consumption = watch_consumption(families, now)
    # Only a live alarm raises the exit: an ended deficit is evidence,
    # and a siren that never stops sounding trains the operator to
    # ignore the band (the dogfood's lesson).
    if any(s["state"] in ("ALARM-SILENT", "ALARM-DEFICIT")
           for s in completeness["sessions"]):
        worst = max(worst, 6)

    # The day book last, so the row this tick writes is the finished one
    # — worst already raised by the tripwire and the completeness watch.
    alarms = len([s for s in completeness["sessions"]
                  if s["state"] in ("ALARM-SILENT", "ALARM-DEFICIT")])
    days = remember_day(daybook, now, {
        "worst": worst, "chains": len(census), "broken": damaged,
        "events": len(events), "alarms": alarms,
        "reawakenings": len(awakened),
    })

    baseline = {"file": baseline_path.as_posix(), "events": events}
    if note:
        baseline["note"] = note
    report_note = None
    if store and not repos:
        report_note = (f"store empty at {root.as_posix()} — run "
                       "`loxodonta install-hook` to wire recording, or "
                       "scan a legacy layout with --root")
    return {
        **({"note": report_note} if report_note else {}),
        "root": root.as_posix(),
        "scanned": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exit": worst,
        "history": fortnight(days, now),
        "baseline": baseline,
        "completeness": completeness,
        "consumption": consumption,
        # The lifecycle events (ADR-0018): reasons to look, never
        # verdicts — deliberately not in baseline.events, whose words
        # mean "appends cannot explain this"; a reawakening is exactly
        # appends explaining everything.
        "lifecycle": {"events": list(awakened.values()), "kept": kept},
        # Which recorder is actually running. Never raises the exit:
        # drift is a reason to look, and the operator's to resolve.
        "recorder": recorder_drift(witness),
        "repos": [
            {"repo": repo,
             "sessions": [{"session": session, "chains": chains}
                          for session, chains in sessions.items()]}
            for repo, sessions in repos.items()
        ],
    }


def adoption_project(root, log):
    """Which project owns a legacy chain: the folder holding its
    receipts/; a stranded worktree chain belongs to the repo the
    worktree served; a receipts/ at the root's own top level means the
    root itself is the project."""
    parts = log.relative_to(root).parts
    if ".claude" in parts:
        idx = parts.index(".claude")
        return root.joinpath(*parts[:idx]) if idx else root
    if parts[0] == "receipts":
        return root
    return root / parts[0]


def cmd_adopt(args):
    """The one-time move of legacy chains into the store (ADR-0011).
    Move, not copy — two copies of evidence is worse than one; the
    chain, its anchor sidecars, and the folder's .unlisted marker
    travel together; a name collision is refused and reported, never
    overwritten; running it twice is a quiet no-op; --dry-run prints
    the plan. Empty legacy folders are left for the operator to
    prune."""
    root = Path(args.root).resolve()
    moves, refused = [], []
    for log in find_chains(root):
        project = adoption_project(root, log)
        drawer = store_receipts() / project_slug(project)
        (refused if (drawer / log.name).exists() else moves).append(
            (log, drawer, project))
    if not moves and not refused:
        print(f"nothing to adopt under {root.as_posix()}")
        return 0
    for log, drawer, project in moves:
        line = f"{log.relative_to(root).as_posix()} -> {drawer.name}/"
        if args.dry_run:
            print(f"would adopt {line}")
            continue
        os.makedirs(drawer, exist_ok=True)
        record = drawer / "project.json"
        if not record.exists():
            record.write_text(json.dumps(
                {"path": str(project.resolve()).replace(os.sep, "/")})
                + "\n", encoding="utf-8")
        marker = log.parent / UNLISTED_NAME
        shutil.move(str(log), str(drawer / log.name))
        for suffix in SIDECAR_SUFFIXES:
            sidecar = log.parent / (log.name + suffix)
            if not sidecar.exists():
                continue
            if (drawer / sidecar.name).exists():
                # Proofs left behind are still proofs; say so — silence
                # here would read as "everything travelled".
                print(f"left sidecar "
                      f"{sidecar.relative_to(root).as_posix()}: "
                      f"{drawer.name}/{sidecar.name} already exists in "
                      "the store — evidence is never overwritten; "
                      "reconcile by hand")
            else:
                shutil.move(str(sidecar), str(drawer / sidecar.name))
        if marker.exists() and not (drawer / UNLISTED_NAME).exists():
            shutil.copy2(str(marker), str(drawer / UNLISTED_NAME))
        print(f"adopted {line}")
    for log, drawer, _ in refused:
        print(f"refused {log.relative_to(root).as_posix()}: "
              f"{drawer.name}/{log.name} already exists in the store — "
              "evidence is never overwritten; reconcile by hand")
    if not args.dry_run and moves:
        print(f"{len(moves)} chain(s) adopted into "
              f"{store_receipts().as_posix()}")
    return 0


def cmd_scan(args):
    store = args.root is None
    root = store_receipts() if store else Path(args.root).resolve()
    report = scan_root(root,
                       witness=Path(args.witness),
                       anchor_every=args.anchor_every,
                       calendars=args.calendar or (),
                       publish_every=args.publish_every,
                       publish_url=args.publish_url,
                       store=store)
    print(json.dumps(report, indent=None if args.json else 2))
    return report["exit"]


# --- Recall -------------------------------------------------------------------
# The memory view: chains read as *what happened*, not as evidence.
# Reading the JSONL directly is display-only and allowed (ADR-0005) — the
# format is a public interface — but recall owns no verdicts: it renders
# writer-supplied testimony and says so, exactly as `report` does.

TESTIMONY = ("testimony, not a verdict — what was attempted, as the writer "
             "told it; run loxodonta verify for the verdict")


def mentions(entries, needle):
    """True when any receipt touches the path: a fingerprinted file
    reference, or the path surviving only in the action line — the
    field's common case, where the hook leaves files[] empty."""
    needle = needle.lower()
    for entry in entries:
        if needle in str(entry.get("action", "")).lower():
            return True
        refs = entry.get("files")
        if isinstance(refs, list) and any(
                isinstance(ref, dict)
                and needle in str(ref.get("path", "")).lower()
                for ref in refs):
            return True
    return False


def universe(root, store):
    """(repo, session, seq, log) for every chain in the serving
    universe: the store's drawers, or a legacy folder of repos under an
    explicit --root (ADR-0011/0013)."""
    if store:
        found = (sorted(p for p in root.glob("*/receipts-*.jsonl")
                        if not p.name.endswith(SIDECAR_SUFFIXES))
                 if root.is_dir() else [])
        return [(*store_identity(log), log) for log in found]
    return [(*chain_identity(root, log), log) for log in find_chains(root)]


def recall_root(root, repo=None, since=None, until=None, path=None,
                store=False):
    """The timeline: one story per session, sibling chains folded in
    (ADR-0004 — one session, one story), newest first. Dates compare as
    ISO prefixes; a session is in range when its span overlaps."""
    stories = {}
    for repo_name, session, _, log in universe(root, store):
        if repo and repo_name != repo:
            continue
        entries = read_entries(log)
        story = stories.setdefault((repo_name, session), {
            "repo": repo_name, "session": session, "chains": [],
            "paths": [], "entries": 0, "started": None, "ended": None,
            "worktree": False, "_touched": False})
        story["chains"].append(log.name)
        story["paths"].append(log.relative_to(root).as_posix())
        story["entries"] += len(entries)
        story["worktree"] = (story["worktree"]
                             or ".claude" in log.relative_to(root).parts)
        stamps = sorted(e["ts"] for e in entries
                        if isinstance(e.get("ts"), str))
        if stamps:
            story["started"] = min(filter(None, (story["started"],
                                                 stamps[0])))
            story["ended"] = max(story["ended"] or "", stamps[-1])
        if path and not story["_touched"]:
            story["_touched"] = mentions(entries, path)

    sessions = []
    for story in stories.values():
        if path and not story.pop("_touched", False):
            continue
        story.pop("_touched", None)
        if (since or until) and story["ended"] is None:
            continue  # a span nobody can place is outside every range
        if since and story["ended"][:10] < since:
            continue
        if until and story["started"][:10] > until:
            continue
        sessions.append(story)
    # Newest first; name order breaks same-second ties deterministically.
    sessions.sort(key=lambda s: (s["repo"], s["session"]))
    sessions.sort(key=lambda s: s["ended"] or "", reverse=True)
    return {"root": root.as_posix(), "testimony": TESTIMONY,
            "sessions": sessions}


# How far back the activity walk reads. Matches the day book's season:
# the heat map wants more than a fortnight to have a shape, and neither
# wants to grow without bound.
ACTIVITY_DAYS = 90


def panel_tool_key(entry):
    """What one entry reached for, named for the operator's own eyes.

    Deliberately not `histogram_key`, which folds hard because its
    answers leave the machine (ADR-0021): there, a name off the
    allowlist becomes `other` and every MCP call collapses into one
    `mcp` bucket. Nothing leaves the machine here — serve binds
    localhost and offers this to nobody — so a tool is named as the
    harness named it, and an MCP call is named by the server it
    reached (`mcp:reddit`), which on your own machine is information
    rather than exposure. The two must stay apart rather than become
    one function with a switch: the export's whole value is that it
    has no switch anybody can get wrong (ADR-0027).

    Bookkeeping is not a tool call and returns None; so does the
    genesis, which records that a chain opened, not that work
    happened. An entry from anything but a harness actor was
    hand-logged — `loxodonta log`, `loxodonta run` — and is counted
    as that rather than guessed at."""
    if entry.get("n") == 0:
        return None
    actor = entry.get("actor")
    if actor == BOOKKEEPING_ACTOR:
        return None
    if actor not in HOOK_ACTORS:
        return "hand-logged"
    head = str(entry.get("action", "")).split(":", 1)[0].strip()
    if not head:
        return "unnamed"
    if head.startswith("mcp__"):
        parts = head.split("__")
        return "mcp:" + parts[1] if len(parts) > 1 and parts[1] else "mcp"
    return head


# The ladder of bucket widths for the density strip, in seconds, and
# the most bars it may draw. A real store holds sessions eighteen
# seconds long and sessions a week long, five orders of magnitude
# apart, so no single width serves both: the strip takes the first rung
# that fits the span into SHAPE_BARS bars or fewer. The panel then says
# which rung won, because a bar chart whose scale the reader has to
# guess is worse than no bar chart.
SHAPE_RUNGS = (1, 5, 15, 30, 60, 300, 900, 1800, 3600, 7200,
               10800, 21600, 43200, 86400)
SHAPE_BARS = 60


def session_shape(root, repo, session, store=False):
    """One session's receipts bucketed across its own span.

    The axis is the session as it happened, first receipt to last, gaps
    and all. A session that went quiet for a day and woke up draws as
    mostly empty, and that emptiness is the finding rather than a
    rendering problem — it is ADR-0018's reawakening, seen (ADR-0027).
    Sibling chains fold in: one session is one story (ADR-0004).

    Testimony, like the rest of recall — writer-stamped timestamps,
    counted — and it owns no verdicts. The owed tail the page draws
    over this belongs to the completeness watch, not to here."""
    stamps = []
    for repo_name, name, _, log in universe(root, store):
        if repo_name != repo or name != session:
            continue
        for entry in read_entries(log):
            # The genesis records that a chain opened, not that work
            # happened, and it would stretch the span backwards.
            if entry.get("n") == 0:
                continue
            when = parse_when(entry.get("ts"))
            if when is not None:
                stamps.append(when)
    if not stamps:
        return None
    stamps.sort()
    first, last = stamps[0], stamps[-1]
    span = int((last - first).total_seconds())
    width = next((rung for rung in SHAPE_RUNGS
                  if span <= rung * SHAPE_BARS), SHAPE_RUNGS[-1])
    buckets = [0] * (span // width + 1)
    for when in stamps:
        buckets[int((when - first).total_seconds()) // width] += 1
    peak = max(range(len(buckets)), key=lambda i: buckets[i])
    return {"repo": repo, "session": session, "testimony": TESTIMONY,
            "from": first.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "to": last.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "seconds": span, "bucket_seconds": width, "buckets": buckets,
            "receipts": len(stamps),
            "peak": {"index": peak, "count": buckets[peak]}}


# Where a subagent's checkout lives inside the project it serves. File
# references are already project-relative (ADR-0012), so this prefix is
# the only thing that splits one file into several — and it splits it
# badly, because the worktree is pruned when its branch merges and the
# directory in the receipt stops existing.
WORKTREE_PREFIX = ".claude/worktrees/"


def panel_file_key(path):
    """One file reference, folded to the file it actually names.

    A subagent working in `.claude/worktrees/<name>/` records its edits
    under that prefix, so the same file arrives as several paths and
    ranks as several files — none of them right, and most of them
    naming a directory that was deleted when the branch merged. The
    prefix folds away and nothing else does: a path this rule does not
    recognise is shown exactly as the writer wrote it, because quietly
    rewriting a path is how a reader starts lying about what happened
    (ADR-0027)."""
    if not isinstance(path, str) or not path:
        return None
    if path.startswith(WORKTREE_PREFIX):
        rest = path[len(WORKTREE_PREFIX):]
        cut = rest.find("/")
        if cut > 0:
            return rest[cut + 1:]
    return path


def activity_root(root, store=False, days=ACTIVITY_DAYS):
    """Receipts counted into UTC hour buckets, per repo, plus what the
    writer reached for and what it touched.

    Four surfaces read this: the working-hours heat map, the per-drawer
    sparklines, the histogram, and files touched. The first two are
    questions about the operator's local calendar, and only the browser
    knows their zone — so the buckets stay hourly and stay UTC, and the
    client folds them into local days and weekdays. Aggregating to days
    here would bake a UTC midnight into an answer about somebody's
    evenings. The other two ride the same walk rather than paying for a
    second one, and therefore share its window.

    Testimony like the rest of recall: this counts what the writer said
    it attempted, and owns no verdicts."""
    floor = (datetime.now(timezone.utc)
             - timedelta(days=days)).strftime("%Y-%m-%dT%H")
    counts = {}
    tools = {}
    files = {}
    for repo_name, _, _, log in universe(root, store):
        drawer = counts.setdefault(repo_name, {})
        for entry in read_entries(log):
            # The genesis is administrative — it records that a chain
            # was opened, not that any work happened.
            if entry.get("n") == 0:
                continue
            stamp = entry.get("ts")
            if not isinstance(stamp, str) or len(stamp) < 13:
                continue
            hour = stamp[:13]
            if hour < floor:
                continue
            drawer[hour] = drawer.get(hour, 0) + 1
            reached = panel_tool_key(entry)
            if reached:
                tools[reached] = tools.get(reached, 0) + 1
            # One receipt counts once per file it named, however many
            # times it named it: the question is how often a file was
            # in the work, not how long a `files` array ran.
            touched = set()
            for ref in entry.get("files") or ():
                if isinstance(ref, dict):
                    folded = panel_file_key(ref.get("path"))
                    if folded:
                        touched.add(folded)
            for path in touched:
                where = (repo_name, path)
                files[where] = files.get(where, 0) + 1
    return {"root": root.as_posix(), "testimony": TESTIMONY,
            "since": floor, "activity": counts, "tools": tools,
            "files": [{"repo": repo, "path": path, "receipts": count}
                      for (repo, path), count in
                      sorted(files.items(), key=lambda kv: (-kv[1], kv[0]))]}


def resolve_chain(root, asked):
    """A chain path under the root, or None — the shared gate for the
    walker and the drill. Sidecars and anything that escapes the root
    are refused."""
    path = Path(asked)
    if not path.is_absolute():
        path = root / path
    try:
        path = path.resolve()
        path.relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    if (not path.name.endswith(".jsonl")
            or path.name.endswith(SIDECAR_SUFFIXES)
            or not path.is_file()):
        return None
    return path


def walk_chain(root, asked):
    """One chain, line by line, for the walker: parsed entries where
    lines parse, raw damage kept where it sits — a broken chain is
    still a readable log. Display only (ADR-0005): the browser
    recomputes hashes itself, and verify owns the verdict. Only chains
    under the root are served; anything else is None (404)."""
    path = resolve_chain(root, asked)
    if path is None:
        return None
    relpath = path.relative_to(root.resolve()).as_posix()
    lines = []
    with open(path, encoding="utf-8", errors="replace") as chain:
        for raw in chain:
            raw = raw.rstrip("\n")
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                lines.append({"damage": raw})
                continue
            if isinstance(entry, dict):
                lines.append({"entry": entry})
            else:
                lines.append({"damage": raw})
    return {"log": relpath, "testimony": TESTIMONY, "lines": lines}


SEARCH_CAP = 500  # hits returned; `matched` still counts every one


def search_root(root, query, store=False):
    """Free-text search over action lines, machine-wide. Finds what was
    *written* — the writer's word, testimony like all of recall — and
    hands back the context the timeline links on. Newest first; an empty
    query matches nothing rather than everything."""
    needle = (query or "").lower()
    hits = []
    if needle:
        for repo_name, session, _, log in universe(root, store):
            for entry in read_entries(log):
                action = str(entry.get("action", ""))
                if needle in action.lower():
                    hits.append({
                        "repo": repo_name, "session": session,
                        "chain": log.name, "n": entry.get("n"),
                        "ts": entry.get("ts"), "actor": entry.get("actor"),
                        "action": action,
                    })
    hits.sort(key=lambda hit: str(hit["ts"] or ""), reverse=True)
    return {"root": root.as_posix(), "testimony": TESTIMONY,
            "query": query or "", "matched": len(hits),
            "hits": hits[:SEARCH_CAP]}


# --- Recall CLI (Stage E, ADR-0009) -------------------------------------------
# The agent-facing mouths on the recall organ: `digest` renders the
# session-start injection, `show` fetches one entry by entry address,
# `search` and `timeline` are the ladder past the digest window. All of
# it is recall — testimony rendered from chains, verdicts owned by
# nobody here (GLOSSARY: Digest, Entry address, Unlisted). Output is
# plain ASCII on purpose: it lands in hook-injected context and in
# whatever console encoding the operator's shell dealt.

UNLISTED_NAME = ".unlisted"

ADDRESS_RE = re.compile(r"^[0-9a-f]{4,64}$")

DIGEST_LIMIT = 30    # rows, not entries: the budget is the honesty cap
ACTION_WIDTH = 110


def repo_chains(repo):
    """Every chain belonging to one repo: its receipts/ plus chains
    stranded in its own worktrees — still this repo's history."""
    patterns = ("receipts/*.jsonl", ".claude/worktrees/*/receipts/*.jsonl")
    return sorted(p.resolve() for pattern in patterns
                  for p in repo.glob(pattern)
                  if not p.name.endswith(SIDECAR_SUFFIXES))


def session_of(log):
    stem = log.stem
    if stem.startswith("receipts-"):
        stem = stem[len("receipts-"):]
    session, _ = split_seq(stem)
    return session


def main_repo_of(project):
    """A git worktree holds no chains: the hook writes them to the
    repository the worktree belongs to (receipts.main_repo_root — this
    is its reader-side twin, same file walk). A worktree's `.git` is a
    file reading `gitdir: <main>/.git/worktrees/<name>`, and that
    directory's `commondir` points back at `<main>/.git`. Anything
    unexpected returns `project` unchanged — recall never fails over
    path layout."""
    dot_git = project / ".git"
    if not dot_git.is_file():
        return project  # a normal checkout (.git/ dir), or not a repo
    try:
        line = dot_git.read_text(encoding="utf-8").strip()
        if not line.startswith("gitdir:"):
            return project
        gitdir = Path(line[len("gitdir:"):].strip())
        if not gitdir.is_absolute():
            gitdir = project / gitdir
        try:
            common = (gitdir / "commondir").read_text(
                encoding="utf-8").strip()
            root = Path(os.path.normpath(gitdir / common)).parent
        except OSError:
            # A deregistered worktree (ADR-0023): the gitdir is gone, but
            # its path still spells <main>/.git/worktrees/<name>.
            spelled = gitdir.as_posix()
            at = spelled.find("/.git/worktrees/")
            if at <= 0:
                return project
            root = Path(spelled[:at])
        return root if root.is_dir() else project
    except OSError:
        return project


def invoking_repo(args):
    """The repository a recall or package command speaks of: --repo, else
    CLAUDE_PROJECT_DIR, else the current directory, spelled the way the
    recorder spells it when it slugs a drawer (an absolute path with any
    link left as typed, ADR-0011), then a worktree resolved to its
    repository. Resolving links here and not there would hash two names
    for one drawer."""
    spoken = args.repo or os.environ.get("CLAUDE_PROJECT_DIR") or Path.cwd()
    return main_repo_of(Path(os.path.abspath(str(spoken))))


def store_home():
    """The machine-wide home of hook-written chains (ADR-0011):
    ~/.loxodonta, or wherever LOXODONTA_HOME points. Duplicated from
    loxodonta.py — like project_slug below, the two copies must agree,
    and the recall tests hold them together behaviorally (hook in,
    digest out)."""
    return (os.environ.get("LOXODONTA_HOME")
            or os.path.join(os.path.expanduser("~"), ".loxodonta"))


def project_slug(project):
    """The store drawer name for a project: basename plus 8 hex of the
    normalized full path's SHA256 (ADR-0011)."""
    p = os.path.abspath(str(project))
    key = os.path.normcase(p).replace(os.sep, "/")
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
    base = os.path.basename(p.rstrip("/\\")) or "root"
    safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in base)
    return f"{safe}-{digest}"


def store_receipts():
    return Path(store_home()) / "receipts"


def drawer_chains(drawer):
    return sorted(p for p in drawer.glob("receipts-*.jsonl")
                  if not p.name.endswith(SIDECAR_SUFFIXES))


def drawer_name(drawer):
    """A drawer's display name: the project record's basename, else the
    drawer's own slug — a damaged or missing record degrades the label,
    never the census."""
    try:
        record = json.loads((Path(drawer) / "project.json").read_text(
            encoding="utf-8"))
        base = os.path.basename(str(record.get("path", "")).rstrip("/\\"))
        return base or Path(drawer).name
    except (OSError, ValueError):
        return Path(drawer).name


def store_identity(log):
    """(repo, session, seq) for a chain in the store: the repo is the
    drawer's display name; session and sibling sequence come from the
    filename exactly as in the legacy layout."""
    stem = log.stem
    if stem.startswith("receipts-"):
        stem = stem[len("receipts-"):]
    session, seq = split_seq(stem)
    return drawer_name(log.parent), session, seq


def repo_label(log):
    """The repo name a recall row prints for a chain, wherever it
    lives: a store drawer labels itself; a legacy path is named by the
    folder that holds its receipts/."""
    parent = log.parent
    if (parent / "project.json").exists() or parent.parent == store_receipts():
        return drawer_name(parent)
    return parent.parent.name


def worktree_drawers(repo):
    """The store drawers of a repository's own harness worktrees: those
    whose recorded project path lies under <repo>/.claude/worktrees/
    (ADR-0023). A session that fell back to a worktree's own path, on
    this machine before the one-session-one-drawer rule or on any
    machine that ran v0.1.0, is still this repository's history. Narrow
    on purpose: a sub-project elsewhere in the tree is its own memory."""
    prefix = os.path.normcase(str(repo)).replace(os.sep, "/").rstrip("/") \
        + "/.claude/worktrees/"
    found = []
    try:
        drawers = sorted(p for p in store_receipts().iterdir() if p.is_dir())
    except OSError:
        return found
    for drawer in drawers:
        try:
            recorded = json.loads((drawer / "project.json").read_text(
                encoding="utf-8")).get("path", "")
        except (OSError, ValueError, AttributeError):
            continue
        spelled = os.path.normcase(str(recorded)).replace(os.sep, "/")
        if spelled.startswith(prefix) and not own_repository(recorded):
            found.append(drawer)
    return found


def own_repository(path):
    """True when `path` still exists and is a repository of its own: a
    `.git` folder, where a harness worktree has a `.git` file. Checked
    out under another repository's .claude/worktrees/, such a folder is
    not that repository's worktree and its history is not that
    repository's. A pruned worktree's folder is gone, so it keeps the
    prefix rule above."""
    return os.path.isdir(os.path.join(str(path), ".git"))


def repo_drawers(repo):
    """A repository's drawers in the store, in recall's order: its own
    drawer when it exists, then the drawers of its harness worktrees
    (ADR-0023). The one resolution `digest --repo`, `search --repo`,
    `timeline`, and `package --repo` all read a repository through."""
    drawer = store_receipts() / project_slug(repo)
    found = [drawer] if drawer.is_dir() else []
    found += [extra for extra in worktree_drawers(repo) if extra != drawer]
    return found


def store_chains(repo):
    """A repository's chains in the store: its own drawer, then the
    drawers of its harness worktrees (ADR-0023), in that order."""
    return [log for drawer in repo_drawers(repo)
            for log in drawer_chains(drawer)]


def project_chains(repo):
    """One project's chains, wherever they live: its store drawer and
    its harness worktrees' drawers (ADR-0011, ADR-0023) — or, when the
    store holds nothing yet (pre-adopt), the legacy repo layout, so the
    transition never blanks anyone's memory. The store outranks a stale
    legacy folder once it holds anything."""
    return store_chains(repo) or repo_chains(repo)


def recall_scope(args):
    """The chains a recall command may read: the invoking project's
    drawer in the store (ADR-0011) — or, when the drawer holds nothing
    yet (pre-adopt), the legacy repo layout, so the transition never
    blanks anyone's memory. Under --all, every drawer in the store (or
    every repo under the legacy root), minus unlisted ones other than
    our own. Unlisted is an output courtesy, never a security
    boundary: the chains stay plain files."""
    repo = invoking_repo(args)
    drawer = store_receipts() / project_slug(repo)
    logs = store_chains(repo)
    if logs:
        if getattr(args, "all", False):
            known = set(logs)
            for log in sorted(store_receipts().glob("*/receipts-*.jsonl")):
                if log.name.endswith(SIDECAR_SUFFIXES) or log in known:
                    continue
                if (log.parent / UNLISTED_NAME).exists() \
                        and log.parent != drawer:
                    continue
                logs.append(log)
        return repo, logs
    return legacy_recall_scope(args, repo)


def legacy_recall_scope(args, repo):
    """The pre-store reading (kept for un-adopted layouts): the repo's
    own receipts/, plus — under --all — every repo under the root."""
    logs = repo_chains(repo)
    if getattr(args, "all", False):
        root = Path(args.root or repo.parent).resolve()
        known = set(logs)
        for log in find_chains(root):
            log = log.resolve()
            if log in known:
                continue
            if (log.parent / UNLISTED_NAME).exists():
                try:
                    repo.relative_to(log.parent.parent)
                except ValueError:
                    continue  # unlisted, and we are outside it
            logs.append(log)
    return repo, logs


def address_of(entry):
    h = entry.get("entry_hash")
    return h[:8] if isinstance(h, str) and len(h) >= 8 else "????????"


def clip(text, width=ACTION_WIDTH):
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[:width - 3] + "..."


def hhmm(ts):
    return ts[11:16] + "Z" if isinstance(ts, str) and len(ts) >= 16 else str(ts)


def day_span(ts):
    return f"{ts[:10]} {hhmm(ts)}" if isinstance(ts, str) and len(ts) >= 16 \
        else str(ts)


def gather(logs):
    """(families, rows): sibling chains folded per session (ADR-0004),
    bookkeeping excluded — genesis and transcript commitments are the
    chain talking about itself, not memory of the work (ADR-0017);
    search and `show` still reach them by address. Rows arrive sorted
    oldest-first; ties break on chain name then n, deterministically."""
    families = {}
    rows = []
    for log in logs:
        session = session_of(log)
        family = families.setdefault(
            session, {"count": 0, "first": None, "last": None,
                      "final": None, "bookkeeping": 0, "last_n": 0})
        for entry in read_entries(log):
            n = entry.get("n")
            if isinstance(n, int) and n > family["last_n"]:
                family["last_n"] = n
            if entry.get("actor") == "receipts":
                # Genesis is n 0; anything else the chain says about
                # itself (a transcript commitment) is bookkeeping the
                # header must own up to, or its count reads as a gap
                # against the rows' own n (#154).
                if isinstance(n, int) and n > 0:
                    family["bookkeeping"] += 1
                continue
            ts = entry.get("ts") if isinstance(entry.get("ts"), str) else ""
            rows.append({"session": session, "log": log, "ts": ts,
                         "entry": entry})
            family["count"] += 1
            if family["first"] is None or ts < family["first"]:
                family["first"] = ts
            if family["last"] is None or ts > family["last"]:
                family["last"] = ts
    rows.sort(key=lambda r: (r["ts"], r["log"].name,
                             r["entry"].get("n") or 0))
    for row in rows:
        families[row["session"]]["final"] = row["entry"].get("entry_hash")
    return families, rows


def tool_of(action):
    """The collapse key for a digest row: the tool label the hook
    writes before the first colon (`Read: ...` -> `Read`), or the
    whole action when there is none. A prefix rule is tool-agnostic
    on purpose — it cannot rot the way a tool taxonomy would (#66)."""
    return str(action).partition(":")[0].strip()


def collapse_runs(rows):
    """Consecutive same-actor, same-tool rows folded into rendered
    units (#66) — the recorder never filters, readers collapse
    (ADR-0016 ruling 3). A unit's line stands on the run's last
    entry: its address resolves like any other, and `timeline`
    around it unrolls the rest of the run."""
    units = []
    for row in rows:
        entry = row["entry"]
        key = (entry.get("actor"), tool_of(entry.get("action", "")))
        if units and units[-1]["key"] == key:
            units[-1]["rows"].append(row)
        else:
            units.append({"key": key, "rows": [row]})
    return units


def run_action(unit):
    """The action text a unit renders: a lone row speaks for itself;
    a run says how long it was, the shared tool, and where it ended —
    `14x Read, last: supervisor.py`. The newest detail is shown
    because it is what the session did most recently; the rest is one
    `timeline` away."""
    rows = unit["rows"]
    action = str(rows[-1]["entry"].get("action", ""))
    if len(rows) == 1:
        return action
    label, _, rest = action.partition(":")
    prefix = f"{len(rows)}x {label.strip()}"
    return f"{prefix}, last: {rest.strip()}" if rest.strip() else prefix


def scan_testimony(repo):
    """The last scan's verdicts for this repo's chains, read from
    whichever baseline covers it: the store's, where the default scan
    remembers (ADR-0011), else the legacy spots (the repo itself, or
    the folder of repos above it). The baseline is trusted for nothing
    — which is exactly why recall may cite it: testimony citing
    testimony."""
    slugs = [project_slug(repo) + "/"] + [
        drawer.name + "/" for drawer in worktree_drawers(repo)]

    def in_drawer(relpath, base_dir):
        # Store baseline rows are keyed <drawer-slug>/<chain>; a repo's
        # harness worktree drawers are its history too (ADR-0023).
        return any(relpath.startswith(slug) for slug in slugs)

    def under_repo(relpath, base_dir):
        try:
            (base_dir / relpath).resolve().relative_to(repo)
            return True
        except (ValueError, OSError):
            return False

    sources = [(Path(store_home()) / "baseline.json", in_drawer),
               (repo / BASELINE_NAME, under_repo),
               (repo.parent / BASELINE_NAME, under_repo)]
    for path, covers in sources:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        scanned = data.get("scanned")
        chains = data.get("chains")
        if not isinstance(scanned, str) or not isinstance(chains, dict):
            continue
        verdicts = [str(row["verdict"])
                    + (" (superseded)" if row.get("superseded") else "")
                    for relpath, row in chains.items()
                    if isinstance(row, dict) and "verdict" in row
                    and covers(relpath, path.parent)]
        if verdicts:
            return scanned, verdicts
    return None, []


def payload_cwd():
    """The `cwd` a harness hook payload names on stdin, or None. Read
    only when `digest --payload` asks (ADR-0020): a harness that sets
    no CLAUDE_PROJECT_DIR — Codex — says which repo a session is in
    here and nowhere else. Never read implicitly: under `mcp`, stdin
    is the wire."""
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    cwd = payload.get("cwd") if isinstance(payload, dict) else None
    return cwd if isinstance(cwd, str) and os.path.isdir(cwd) else None


def cmd_digest(args):
    """The session-start injection: local by design ("all memory" means
    all reachable, never all injected), budget-capped, zero subprocess
    spawns — recall owns no verdicts, so nothing here runs verify."""
    if getattr(args, "payload", False) and not args.repo             and not os.environ.get("CLAUDE_PROJECT_DIR"):
        args.repo = payload_cwd()  # the environment wins when present
    repo = invoking_repo(args)
    families, rows = gather(project_chains(repo))
    if args.since:
        rows = [r for r in rows if r["ts"][:10] >= args.since]
    total = len(rows)
    if not total:
        return 0  # nothing to recall; the hook must stay silent, not nag
    # Collapse before capping (#66): the budget counts rendered rows,
    # so a Read flood folds to one line instead of scrolling the story
    # out of the window. Runs never cross sessions.
    by_session = {}
    for row in rows:
        by_session.setdefault(row["session"], []).append(row)
    units = [unit for session_rows in by_session.values()
             for unit in collapse_runs(session_rows)]
    units.sort(key=lambda u: (u["rows"][-1]["ts"],
                              u["rows"][-1]["log"].name,
                              u["rows"][-1]["entry"].get("n") or 0))
    shown = units[-max(args.limit, 1):]
    reached = sum(len(unit["rows"]) for unit in shown)

    lines = [f"== recall digest -- {repo.name} ({repo.as_posix()}) =="]
    memory = f"memory: {len(families)} sessions, {total} entries"
    kept_out = sum(f["bookkeeping"] for f in families.values())
    if kept_out:
        # Say what the count leaves out, and how far the chain's own n
        # runs, so a reader who meets n 63 under a header saying 61 does
        # not go looking for two missing receipts (#154).
        last_n = max(f["last_n"] for f in families.values())
        memory += (f", plus {kept_out} bookkeeping entries not rendered "
                   f"(last n {last_n})")
    if reached < total:
        memory += f"; showing last {reached} (search reaches the rest)"
    lines.append(memory)
    scanned, verdicts = scan_testimony(repo)
    if scanned:
        counts = {}
        for verdict in verdicts:
            counts[verdict] = counts.get(verdict, 0) + 1
        if set(counts) == {"VALID"}:
            summary = f"all {len(verdicts)} chains VALID"
        else:
            summary = ", ".join(f"{n} {v}"
                                for v, n in sorted(counts.items()))
        lines.append(f"last scan: {scanned} - {summary} "
                     "(testimony; the verify line below judges a chain)")
    else:
        lines.append("last scan: none recorded - "
                     "the verify line below judges a chain")

    groups = {}
    for unit in shown:
        groups.setdefault(unit["rows"][-1]["session"], []).append(unit)
    for session in sorted(groups,
                          key=lambda s: groups[s][-1]["rows"][-1]["ts"]):
        family = families[session]
        lines.append("")
        lines.append(f"-- session {session[:8]} "
                     f"({day_span(family['first'])} .. "
                     f"{day_span(family['last'])}, "
                     f"{family['count']} entries) --")
        for unit in groups[session]:
            row = unit["rows"][-1]
            entry = row["entry"]
            line = (f"{address_of(entry)}  {hhmm(row['ts'])}  "
                    f"{clip(entry.get('actor', '?'), 16)}  "
                    f"{clip(run_action(unit))}")
            if entry.get("entry_hash") == family["final"]:
                line += "   <- last recorded action"
            lines.append(line)

    me = Path(__file__).resolve().as_posix()
    lines.append("")
    lines.append("this digest is testimony rendered from receipt chains; "
                 "it owns no verdicts.")
    lines.append(f'detail: python "{me}" show <address> '
                 f'--repo "{repo.as_posix()}"')
    lines.append(f'search: python "{me}" search "text" '
                 f'--repo "{repo.as_posix()}" [--all]')
    # The one line that leads to a verdict, and it is the recorder's:
    # an agent holding an address must never have to hunt for the
    # chain file to judge it (#155).
    lines.append(f'verify: python "{me}" verify <address> '
                 f'--repo "{repo.as_posix()}"')
    print("\n".join(lines))
    return 0


def cmd_verify(args):
    """The recorder's verdict on the chain holding one entry address:
    the CLI twin of the MCP tool (ADR-0019, one-to-one), and the
    answer to #155, where agents holding an address could not find the
    chain to judge. Recall owns no verdict here either: it names the
    chain, then prints `loxodonta verify --log` verbatim and returns
    its exit code. `scan` is the supervisor's own tick over every chain;
    this is one chain, by the handle the digest hands out."""
    match, code = resolve_address(args)
    if match is None:
        return code
    log = match[0]
    judged = subprocess.run(
        [sys.executable, str(LOXODONTA), "verify", f"--log={log}"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    print(f"chain: {log.as_posix()}")
    sys.stdout.write(judged.stdout)
    sys.stderr.write(judged.stderr)
    return judged.returncode


def resolve_address(args):
    """Entry-address resolution, git's rules (GLOSSARY: Entry address):
    lowercase hex, 4 to 64 chars; any unambiguous prefix resolves; an
    ambiguous one is refused with the candidates named. Returns
    (match, exit_code) — exactly one of the two is meaningful."""
    prefix = args.address.lower()
    if not ADDRESS_RE.match(prefix):
        print(f"error: {args.address!r} is not an entry address - "
              "4 to 64 lowercase hex characters of an entry hash",
              file=sys.stderr)
        return None, 1
    repo, logs = recall_scope(args)
    where = "the root" if getattr(args, "all", False) else repo.as_posix()
    return match_address(prefix, logs, where)


def match_address(prefix, logs, where,
                  hint="widen with --all, or search instead"):
    """The one entry among `logs` whose hash starts with `prefix`, or
    the refusal: none (named by `where`), or ambiguous with the
    candidates listed. Shared by the recall commands and by `package`,
    which searches the whole store (ADR-0026 ruling 1)."""
    matches = [(log, entry) for log in logs
               for entry in read_entries(log)
               if isinstance(entry.get("entry_hash"), str)
               and entry["entry_hash"].startswith(prefix)]
    if not matches:
        print(f"no entry under {where} matches {prefix} - {hint}",
              file=sys.stderr)
        return None, 1
    if len(matches) > 1:
        print(f"ambiguous: {prefix} names {len(matches)} entries - "
              "lengthen the prefix:", file=sys.stderr)
        for log, entry in matches[:20]:
            print(f"  {address_of(entry)}  {entry.get('ts', '')}  "
                  f"session {session_of(log)[:8]}  "
                  f"{clip(entry.get('action', ''), 60)}", file=sys.stderr)
        return None, 1
    return matches[0], 0


def cmd_show(args):
    """One full entry by address. The address is the fingerprint: the
    fetched entry is re-hashed against it, so recall's pointers are
    self-verifying — the one place recall touches a hash, and still not
    a verdict: a mismatch is a warning that names the real judge."""
    match, code = resolve_address(args)
    if match is None:
        return code
    log, entry = match
    stored = entry["entry_hash"]
    unhashed = {k: v for k, v in entry.items() if k != "entry_hash"}
    recomputed = hashlib.sha256(json.dumps(
        unhashed, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    verified = recomputed == stored

    print(f"entry {stored}" + (" (self-verified)" if verified else ""))
    # The chain's full path, not its file name: an agent that has this
    # entry's address must be able to reach the file that holds it (#155).
    print(f"chain: {log.as_posix()}  session: {session_of(log)[:8]}  "
          f"n: {entry.get('n')}")
    print(f"ts: {entry.get('ts', '')}  actor: {entry.get('actor', '')}")
    print(f"action: {entry.get('action', '')}")
    refs = entry.get("files") or []
    if refs:
        print("files:")
        for ref in refs:
            if isinstance(ref, dict):
                print(f"  {ref.get('path', '?')}  {ref.get('sha256', '')}")
    else:
        print("files: (none)")
    me = Path(__file__).resolve().as_posix()
    print(f'context: python "{me}" timeline {stored[:8]} '
          f'--repo "{invoking_repo(args).as_posix()}"')
    print(f'verify: python "{me}" verify {stored[:8]} '
          f'--repo "{invoking_repo(args).as_posix()}"')
    if not verified:
        print("WARNING: this entry does not verify against its own hash - "
              "the chain is damaged or edited here; run "
              f"loxodonta verify --log {log.as_posix()}", file=sys.stderr)
        return 1
    return 0


def cmd_search_cli(args):
    """Free-text search over action lines — the whole repo's memory,
    or the whole root's with --all. Finds what was written, the
    writer's word; matched counts everything, the limit only caps
    what is shown (no silent caps)."""
    repo, logs = recall_scope(args)
    needle = args.text.lower()
    hits = []
    for log in logs:
        session = session_of(log)
        repo_name = repo_label(log)
        for entry in read_entries(log):
            if entry.get("n") == 0:
                continue
            action = str(entry.get("action", ""))
            if needle and needle in action.lower():
                hits.append((str(entry.get("ts") or ""), repo_name,
                             session, entry))
    hits.sort(key=lambda hit: hit[0], reverse=True)
    shown = hits[:max(args.limit, 1)]
    print(f'search: "{args.text}" - matched {len(hits)}, '
          f"showing {len(shown)} ({TESTIMONY})")
    for ts, repo_name, session, entry in shown:
        print(f"{address_of(entry)}  {ts[:10]} {hhmm(ts)}  "
              f"{repo_name}/{session[:8]}  "
              f"{clip(entry.get('actor', ''), 16)}  "
              f"{clip(entry.get('action', ''))}")
    return 0


def cmd_timeline(args):
    """Context rows around one address: how the moment unfolded, from
    the same chain, testimony like all of recall."""
    match, code = resolve_address(args)
    if match is None:
        return code
    log, entry = match
    entries = read_entries(log)
    idx = next(i for i, e in enumerate(entries)
               if e.get("entry_hash") == entry.get("entry_hash")
               and e.get("n") == entry.get("n"))
    lo = max(0, idx - max(args.before, 0))
    hi = min(len(entries), idx + max(args.after, 0) + 1)
    print(f"timeline around {address_of(entry)} - "
          f"session {session_of(log)[:8]}, chain {log.name} "
          f"({TESTIMONY})")
    for e in entries[lo:hi]:
        mark = "   <- here" if e is entries[idx] else ""
        print(f"{address_of(e)}  {hhmm(str(e.get('ts', '')))}  "
              f"{clip(e.get('actor', ''), 16)}  "
              f"{clip(e.get('action', ''))}{mark}")
    return 0


# --- MCP: recall on the wire (ADR-0019) ---------------------------------------
# `supervisor mcp` speaks the Model Context Protocol over stdin/stdout so
# any harness that speaks MCP — not only the one that runs our hooks —
# can read this machine's agent memory. Five tools, one-to-one with the
# recall commands above, in the CLI's own words: the model reads exactly
# what a shell user reads. There is no write path on this surface. The
# recorder stays in the harness hook, outside the writer's volition
# (ADR-0002); an agent may read its history here but never append to it
# through a tool it controls.
#
# Two protocol eras are served, decided per request and never from
# session state: a request whose `_meta` carries `io.modelcontextprotocol/`
# keys is modern (revision 2026-07-28, stateless, `resultType` on every
# result); anything else is the legacy `initialize` handshake (2025-11-25
# and earlier). One wire rule above all: nothing but MCP messages ever
# reaches stdout, so every tool call runs under a redirect.

MCP_MODERN_VERSIONS = ("2026-07-28",)
MCP_LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26",
                       "2024-11-05")
MCP_META = "io.modelcontextprotocol/"
MCP_SERVER_INFO = {"name": "loxodonta-recall", "version": "1"}
MCP_INSTRUCTIONS = (
    "loxodonta recall: the receipt chains this machine's agents left "
    "behind, read as memory. Every tool renders testimony (what the "
    "writer said happened) except verify, which runs the chain's judge "
    "and returns its verdict as-is. This surface never writes: receipts "
    "come from the harness hook, not from the agent. Start with digest "
    "for the current repo; search reaches further; show and timeline "
    "pull detail by entry address; verify judges one chain.")
MCP_READ_ONLY = {"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False}


def mcp_prop(kind, text):
    return {"type": kind, "description": text}


MCP_SCOPE_PROPS = {
    "repo": mcp_prop("string", "repo directory (default: the server's "
                               "--repo, else the working directory)"),
    "all": mcp_prop("boolean", "reach every repo in the store (unlisted "
                               "repos stay invisible from outside "
                               "themselves)"),
}
MCP_ADDRESS_PROP = mcp_prop(
    "string", "entry address: 4 to 64 lowercase hex chars of an entry "
              "hash; any unambiguous prefix resolves")


def mcp_tool(name, description, properties, required=()):
    schema = {"type": "object", "properties": properties,
              "additionalProperties": False}
    if required:
        schema["required"] = list(required)
    return {"name": name, "description": description,
            "inputSchema": schema, "annotations": dict(MCP_READ_ONLY)}


# Fixed order: clients cache the list and prompt caches key on it.
MCP_TOOLS = [
    mcp_tool("digest",
             "This repo's recent history as one-line rows, each with an "
             "entry address, grouped by session, runs of one tool "
             "collapsed, budget-capped. Testimony rendered from receipt "
             "chains; owns no verdicts. Start here.",
             {"repo": MCP_SCOPE_PROPS["repo"],
              "limit": mcp_prop("integer",
                                f"most rows shown (default {DIGEST_LIMIT})"),
              "since": mcp_prop("string",
                                "only entries on or after YYYY-MM-DD")}),
    mcp_tool("show",
             "One full receipt by entry address. Re-hashed on fetch, so "
             "the pointer is self-verifying.",
             {"address": MCP_ADDRESS_PROP, **MCP_SCOPE_PROPS},
             required=("address",)),
    mcp_tool("search",
             "Free-text search over action lines: this repo's chains, or "
             "every repo in the store with all=true. Matched counts "
             "everything; limit only caps what is shown.",
             {"text": mcp_prop("string", "text to find in action lines"),
              "limit": mcp_prop("integer", "most hits shown (default 20)"),
              **MCP_SCOPE_PROPS},
             required=("text",)),
    mcp_tool("timeline",
             "The rows around one entry address in its own chain: how "
             "that moment unfolded.",
             {"address": MCP_ADDRESS_PROP,
              "before": mcp_prop("integer", "rows before (default 3)"),
              "after": mcp_prop("integer", "rows after (default 3)"),
              **MCP_SCOPE_PROPS},
             required=("address",)),
    mcp_tool("verify",
             "Run the judge on the chain holding this entry address "
             "(loxodonta verify --log) and return its verdict and exit "
             "code as-is: VALID, BROKEN, and the rest. The one tool here "
             "that is not testimony.",
             {"address": MCP_ADDRESS_PROP, **MCP_SCOPE_PROPS},
             required=("address",)),
]
MCP_TYPES = {"string": str, "integer": int, "boolean": bool}


def mcp_check(tool, arguments):
    """Argument problems, in words the model can act on — validated
    before any command runs, so a typo never reaches the chains."""
    schema = tool["inputSchema"]
    problems = [f"missing required argument: {name}"
                for name in schema.get("required", ()) if name not in arguments]
    for name, value in arguments.items():
        prop = schema["properties"].get(name)
        if prop is None:
            problems.append(f"unknown argument: {name}")
            continue
        want = MCP_TYPES[prop["type"]]
        if not isinstance(value, want) or (want is int
                                           and isinstance(value, bool)):
            problems.append(f"{name} must be {prop['type']}")
    return problems


def mcp_namespace(name, arguments, default_repo):
    """The argparse namespace the CLI command would have built — the
    same defaults the parser declares, so the two surfaces cannot
    drift apart."""
    ns = argparse.Namespace(repo=arguments.get("repo") or default_repo,
                            all=bool(arguments.get("all", False)), root=None)
    if name == "digest":
        ns.limit = arguments.get("limit", DIGEST_LIMIT)
        ns.since = arguments.get("since")
    elif name == "search":
        ns.text = arguments["text"]
        ns.limit = arguments.get("limit", 20)
    else:
        ns.address = arguments["address"]
        if name == "timeline":
            ns.before = arguments.get("before", 3)
            ns.after = arguments.get("after", 3)
    return ns


def mcp_call(name, arguments, default_repo):
    """Run one tool. Returns (text, is_error): the CLI's stdout and
    stderr, and whether its exit code said something went wrong."""
    tool = next(t for t in MCP_TOOLS if t["name"] == name)
    problems = mcp_check(tool, arguments)
    if problems:
        return "\n".join(problems) + "\n", True
    ns = mcp_namespace(name, arguments, default_repo)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            command = {"digest": cmd_digest, "show": cmd_show,
                       "search": cmd_search_cli, "timeline": cmd_timeline,
                       "verify": cmd_verify}
            code = command[name](ns)
        except SystemExit as stop:  # argparse-style exits inside a command
            code = stop.code if isinstance(stop.code, int) else 1
        except Exception as failure:  # never take the server down
            err.write(f"error: {failure}\n")
            code = 1
    text = out.getvalue()
    if name == "digest" and code == 0 and not text.strip():
        # The hook needs silence for a chainless repo; a tool that
        # returns nothing teaches the model the tool is broken.
        text = (f"no receipts recorded under "
                f"{invoking_repo(ns).as_posix()}\n")
    return text + err.getvalue(), code != 0


def mcp_error(id_, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": error}


def mcp_result(id_, result, modern):
    if modern:
        result = dict(result)
        result.setdefault("resultType", "complete")
        meta = dict(result.get("_meta") or {})
        meta[MCP_META + "serverInfo"] = MCP_SERVER_INFO
        result["_meta"] = meta
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def mcp_dispatch(message, default_repo):
    """One reply for one request; None for a notification (never
    answered) or a response (clients do not send them; nothing to say)."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        id_ = message.get("id") if isinstance(message, dict) else None
        return mcp_error(id_, -32600, "Invalid Request")
    method = message.get("method")
    id_ = message.get("id")
    if not isinstance(method, str) or id_ is None:
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        params = {}
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) \
        else {}
    modern = any(isinstance(k, str) and k.startswith(MCP_META) for k in meta)
    if modern:
        version = meta.get(MCP_META + "protocolVersion")
        if not isinstance(version, str) \
                or MCP_META + "clientCapabilities" not in meta:
            return mcp_error(id_, -32602,
                             "Invalid params: _meta must carry "
                             f"{MCP_META}protocolVersion and "
                             f"{MCP_META}clientCapabilities")
        if version not in MCP_MODERN_VERSIONS:
            return mcp_error(id_, -32022, "Unsupported protocol version",
                             {"supported": list(MCP_MODERN_VERSIONS),
                              "requested": version})

    if method == "ping":
        return mcp_result(id_, {}, modern)
    if method == "initialize":
        asked = params.get("protocolVersion")
        version = asked if asked in MCP_LEGACY_VERSIONS \
            else MCP_LEGACY_VERSIONS[0]
        return mcp_result(id_, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": MCP_SERVER_INFO,
            "instructions": MCP_INSTRUCTIONS}, modern)
    if method == "server/discover":
        return mcp_result(id_, {
            "supportedVersions": list(MCP_MODERN_VERSIONS),
            "capabilities": {"tools": {}},
            "instructions": MCP_INSTRUCTIONS}, modern)
    if method == "tools/list":
        return mcp_result(id_, {"tools": MCP_TOOLS}, modern)
    if method == "tools/call":
        name = params.get("name")
        if not any(t["name"] == name for t in MCP_TOOLS):
            return mcp_error(id_, -32602, f"Unknown tool: {name}")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return mcp_error(id_, -32602, "arguments must be an object")
        text, is_error = mcp_call(name, arguments, default_repo)
        return mcp_result(id_, {"content": [{"type": "text", "text": text}],
                                "isError": is_error}, modern)
    return mcp_error(id_, -32601, f"Method not found: {method}")


def cmd_mcp(args):
    """Serve recall over stdio until the client closes stdin. Bytes in,
    bytes out: the console codepage never touches the wire."""
    wire = sys.stdout.buffer
    for raw in sys.stdin.buffer:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            reply = mcp_error(None, -32700, "Parse error")
        else:
            reply = mcp_dispatch(message, args.repo)
        if reply is None:
            continue
        try:
            wire.write((json.dumps(reply, ensure_ascii=False) + "\n")
                       .encode("utf-8"))
            wire.flush()
        except OSError:
            return 0  # the client hung up; there is nobody to answer
    return 0


# --- Export: field data (ADR-0021) -------------------------------------------
# `supervisor export` is how a stranger sends back what the recorder saw
# on their machine without publishing their username, their project
# names, or their shell history. Everything in the file is named below,
# by allowlist: nothing from the scan passes through unnamed, so a new
# scan field can never leak by default. The sender reads the file
# before it goes (it is printed), and it goes under their own GitHub
# login (`--send` runs `gh`: a secret gist, then a field-data issue on
# this repo from the template). Raw chains are a separate opt-in that
# shows a sample line and asks first, because chains carry command
# lines and that is the sender's call.

EXPORT_VERSION = 1
FIELD_DATA_REPO = "Acquiredl/loxodonta"
# The tool names the histogram may carry: the harnesses' own built-ins,
# written down here. A name is the harness's word rather than the
# sender's only when it is on this list. MCP tool names say which
# servers a sender runs (a custom one can be named after an employer)
# and an Agents SDK function is named by the sender; both fold by kind,
# and anything else unknown folds into `other`. A new built-in shows up
# as `other` until it is added here: the allowlist fails closed.
EXPORT_TOOLS = (
    # Claude Code
    "Agent", "Task", "AskUserQuestion", "Bash", "PowerShell", "BashOutput",
    "KillShell", "Edit", "MultiEdit", "Write", "Read", "Glob", "Grep", "LS",
    "NotebookEdit", "NotebookRead", "WebFetch", "WebSearch", "TodoWrite",
    "TodoRead", "Skill", "ToolSearch", "TaskOutput", "TaskStop", "Monitor",
    "SendUserFile", "ScheduleWakeup", "ListAgents", "SendMessage",
    "EnterPlanMode", "ExitPlanMode", "EnterWorktree", "ExitWorktree",
    "Artifact", "Workflow", "ReportFindings", "SuggestSkills", "ListSkills",
    "CronCreate", "CronDelete", "CronList",
    # Codex CLI
    "shell", "shell_command", "exec_command", "write_stdin", "apply_patch",
    "update_plan", "view_image", "web_search",
    # OpenAI Agents SDK adapter (function tools fold to `function` below)
    "handoff",
)
EXPORT_REMOVED = [
    "every path (the store, the witness, the recorder, your home directory)",
    "every command line and action line",
    "every file reference and fingerprint",
    "every repo name (repos become repo-1, repo-2, ... in first-seen order)",
    "every tool name that is not a harness built-in on the written list "
    "(MCP calls fold into one 'mcp' bucket, Agents SDK function tools into "
    "'function', anything else into 'other')",
    "every anchor calendar URL and proof",
    "every word the scan wrote for a human (the 'words' fields)",
]
EXPORT_KEPT = [
    "session ids (random UUIDs the harness assigned)",
    "counts: entries, chains, bytes, tools per session, owed and received",
    "verdicts and states: VALID/BROKEN, completeness, dormancy, consumption",
    "timestamps: when sessions started and ended, and the day book",
    "the recorder's commit, your Python version, and your OS family",
    "which harnesses recorded (claude-code, codex, openai-agents), by actor",
]
EXPORT_WORDS = (
    "This file was built by an allowlist: the fields below are the only "
    "fields it can contain, named in supervisor.py, and nothing else from "
    "the scan passes through. Read it before you send it. It carries no "
    "paths, no command lines, no repo names, and no file references. If "
    "you sent a raw archive as well, that is different: raw chains carry "
    "every command line, and you were shown one and asked first.")


def write_lf(path, text):
    """Write text with LF line endings on every platform. (Path.write_text
    grew its newline= argument in 3.10; the README promises 3.9.)"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def histogram_key(entry):
    """The histogram key for one entry: the tool name a hook actor's
    action line starts with, kept only when it is on EXPORT_TOOLS;
    `mcp` for any MCP tool; `function` for an Agents SDK function tool
    (the adapter's actor, any name but `handoff`); `other` for anything
    else, hand-logged lines included. A line wearing a hook actor still
    cannot smuggle text in: nothing off the list passes."""
    actor = entry.get("actor")
    if actor not in HOOK_ACTORS:
        return "other"
    head = str(entry.get("action", "")).split(":", 1)[0].strip()
    if head.startswith("mcp__"):
        return "mcp"
    if actor == "openai-agents" and head != "handoff":
        return "function"
    return head if head in EXPORT_TOOLS else "other"


def export_sessions(report):
    """One row per (drawer, session) in the scan, joined to the
    completeness and consumption sections by session id alone. The
    completeness section names repos by the witness's folder slug — a
    path in disguise — so it is never read for its name."""
    completeness = {s.get("session"): s
                    for s in report.get("completeness", {}).get("sessions", [])
                    if isinstance(s, dict)}
    consumption = {s.get("session"): s
                   for s in report.get("consumption", {}).get("sessions", [])
                   if isinstance(s, dict)}
    ordinal = {}
    rows = []
    store = {"chains": 0, "entries": 0, "bytes": 0}
    actors = set()  # which harnesses recorded: HOOK_ACTORS only
    newest = None  # the sample line a raw archive shows first
    for repo in report.get("repos", []):
        label = ordinal.setdefault(repo.get("repo"),
                                   f"repo-{len(ordinal) + 1}")
        for sess in repo.get("sessions", []):
            entries = []
            for chain in sess.get("chains", []):
                log = Path(chain["log"])
                entries.extend(read_entries(log))
                store["chains"] += 1
                try:
                    store["bytes"] += log.stat().st_size
                except OSError:
                    pass
            store["entries"] += len(entries)
            stamps = sorted(e["ts"] for e in entries
                            if isinstance(e.get("ts"), str))
            tools = {}
            bookkeeping = commitments = 0
            for entry in entries:
                if not entry.get("n"):
                    continue  # genesis is neither an action nor bookkeeping
                if entry.get("actor") == BOOKKEEPING_ACTOR:
                    bookkeeping += 1
                    if str(entry.get("action", "")).startswith(
                            "transcript-commitment"):
                        commitments += 1
                    continue
                key = histogram_key(entry)
                tools[key] = tools.get(key, 0) + 1
                if entry.get("actor") in HOOK_ACTORS:
                    actors.add(entry["actor"])
                # Newest by timestamp, then by position in its chain:
                # receipts stamp whole seconds, so a burst of calls
                # shares one stamp and the later entry must still win.
                if entry.get("actor") in HOOK_ACTORS and isinstance(
                        entry.get("ts"), str):
                    rank = (entry["ts"], int(entry.get("n") or 0))
                    if newest is None or rank > newest[0]:
                        newest = (rank, str(entry.get("action", "")))
            watched = completeness.get(sess.get("session"), {})
            hot = consumption.get(sess.get("session"), {})
            dormancy = watched.get("dormancy") or {}
            chains = sess.get("chains", [])
            rows.append({
                "session": sess.get("session"),
                "repo": label,
                "entries": len(entries),
                "span": {"first": stamps[0] if stamps else None,
                         "last": stamps[-1] if stamps else None},
                # The worst sibling speaks for the session: a session
                # whose first chain broke and whose recording moved to
                # -002 is the finding field data exists to surface, and
                # the last sibling alone would have called it VALID.
                "verdict": (max(chains, key=lambda c: c.get("exit", 0))
                            .get("verdict") if chains else None),
                "commitments": commitments,
                "completeness": {"state": watched.get("state", "UNWITNESSED"),
                                 "owed": watched.get("tools"),
                                 "received": watched.get("receipts")},
                "dormancy": dormancy.get("tier"),
                "consumption": hot.get("state"),
                "siblings": len(chains),
                "bookkeeping": bookkeeping,
                "tools": dict(sorted(tools.items())),
            })
    return rows, store, ordinal, sorted(actors), newest


def build_export(report):
    """The allowlisted file. `redaction` is the first key on purpose:
    the sender reads the rule before the data, and the issue template
    quotes it."""
    import platform
    sessions, store, ordinal, actors, newest = export_sessions(report)
    day_book = [{k: day.get(k) for k in ("day", "looks", "watched", "worst",
                                         "chains", "broken", "events",
                                         "alarms", "reawakenings")}
                for day in report.get("history", []) if isinstance(day, dict)]
    # The scan underneath just rewrote the store's baseline, calibration
    # included; read it back the way the scan does (a tuple, not a
    # dict — the first dry run shipped `matchers: null` for that).
    _, _, calibration, _, _ = read_baseline(
        Path(store_home()) / "baseline.json")
    matchers = matchers_at(calibration, report.get("scanned")) \
        if calibration else None
    lifecycle = report.get("lifecycle") or {}
    recorder = report.get("recorder") or {}
    data = {
        "redaction": {"words": EXPORT_WORDS, "removed": EXPORT_REMOVED,
                      "kept": EXPORT_KEPT},
        "export": {"version": EXPORT_VERSION,
                   "written": report.get("scanned"),
                   "tool": "loxodonta supervisor export"},
        "machine": {
            "recorder_commit": recorder.get("head"),
            "python": "%d.%d" % sys.version_info[:2],
            "os": platform.system(),
            "matchers": matchers,
            "actors": actors,
            "store": store,
            "day_book": day_book,
            "lifecycle": {"events": len(lifecycle.get("events") or []),
                          "kept": lifecycle.get("kept", 0)},
            "scan_exit": report.get("exit"),
        },
        "sessions": sessions,
    }
    return data, ordinal, newest


def write_raw_archive(report, ordinal, path):
    """Chain bytes and anchor sidecars, drawers renamed to their
    ordinals, no project.json: the one export that carries command
    lines, written only after the sender said yes. A raw archive, not a
    package: no manifest, no witness, nothing a recipient verifies as a
    set (ADR-0026 ruling 9 keeps the two names apart)."""
    import zipfile
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for repo in report.get("repos", []):
            label = ordinal.get(repo.get("repo"), "repo-0")
            for sess in repo.get("sessions", []):
                for chain in sess.get("chains", []):
                    log = Path(chain["log"])
                    archive.write(log, f"{label}/{log.name}")
                    sidecar = log.with_name(log.name + ".anchors.jsonl")
                    if sidecar.exists():
                        archive.write(sidecar, f"{label}/{sidecar.name}")


def issue_body(data, gist_url, raw):
    """The field-data issue, from the template's shape: the gist link,
    the redaction block verbatim, the consent lines."""
    redaction = json.dumps(data["redaction"], indent=2, ensure_ascii=False)
    machine = data["machine"]
    seen = sorted({tool for s in data["sessions"] for tool in s["tools"]})
    return "\n".join([
        f"**Export:** {gist_url or '<gist link>'}",
        "",
        "**What the export says it removed:**",
        "",
        "```",
        redaction,
        "```",
        "",
        f"**Machine:** {machine['os']}, Python {machine['python']}, "
        f"recorder {machine['recorder_commit'] or 'unknown'}, "
        f"{machine['store']['chains']} chains, "
        f"{machine['store']['entries']} entries, "
        f"{len(data['sessions'])} sessions.",
        "",
        f"**Harness(es) recorded:** {', '.join(machine['actors']) or 'none'}",
        "",
        f"**Tools seen:** {', '.join(seen) or 'none'}",
        "",
        "**Anything that surprised you:** ",
        "",
        "---",
        "",
        "- [x] The export was built by the tool's allowlist; I did not "
        "edit it by hand.",
        "- [x] I read the export before sending it and I am fine with it "
        "being public in this issue and in `docs/FIELD-DATA.md`.",
        f"- [{'x' if raw else ' '}] *(raw archives only)* I ran "
        "`export --raw`, read the sample action line it showed me, and "
        "answered yes.",
        "",
    ])


def cmd_export(args):
    """Write the allowlisted export (and, on --raw, the raw archive),
    print it, and on --send hand it to `gh`. The scan underneath is one
    ordinary tick: it remembers its baseline like any other."""
    root = store_receipts()
    report = scan_root(root, witness=Path(args.witness), store=True)
    data, ordinal, newest = build_export(report)
    stamp = str(report.get("scanned") or "")[:10] or "undated"
    out = (Path(args.out) if args.out
           else Path.cwd() / f"loxodonta-export-{stamp}.json")

    archive = None
    if args.raw:
        if newest is None:
            print("nothing to archive: no hook receipts in the store",
                  file=sys.stderr)
            return 1
        print("A raw archive carries every chain byte-for-byte, which means "
              "every command line your agents ran. One of yours, the "
              "newest, reads:", file=sys.stderr)
        print(f"    {newest[1]}", file=sys.stderr)
        print("Everything in the archive looks like that. Type yes to write "
              "it, anything else to stop: ", end="", file=sys.stderr,
              flush=True)
        answer = sys.stdin.readline().strip().lower()
        if answer != "yes":
            print("stopped; nothing written", file=sys.stderr)
            return 1
        archive = out.with_name(out.stem + "-raw.zip")

    body = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    write_lf(out, body)
    print(body, end="")
    print(f"written: {out.name}", file=sys.stderr)
    if archive is not None:
        write_raw_archive(report, ordinal, archive)
        print(f"written: {archive.name} (raw chains)", file=sys.stderr)

    if not args.send:
        return 0
    return send_export(data, out, archive)


def send_export(data, out, archive):
    """`gh` twice, under the sender's login: a secret gist of the files,
    then the issue. The issue body is written beside the export first,
    so a missing `gh` leaves everything needed to file by hand."""
    issue = out.with_name(out.stem + ".issue.md")
    gh = shutil.which("gh")
    if gh is None:
        write_lf(issue, issue_body(data, None, archive is not None))
        print("gh is not on PATH, so nothing was sent. The export and an "
              f"issue body ({issue.name}) are beside you: upload the export "
              "as a secret gist and open a field-data issue on "
              f"{FIELD_DATA_REPO} with that body.", file=sys.stderr)
        return 1
    machine = data["machine"]
    stamp = str(data["export"]["written"] or "")[:10]
    files = [str(out)] + ([str(archive)] if archive else [])
    # `gh gist create` is secret unless told --public; there is no
    # --secret flag to say it twice, so the test pins the absence.
    gist = subprocess.run([gh, "gist", "create", "--desc",
                           f"loxodonta field data {stamp}", *files],
                          capture_output=True, encoding="utf-8",
                          errors="replace")
    if gist.returncode != 0:
        print(f"gh gist create failed: {gist.stderr.strip()}",
              file=sys.stderr)
        return 1
    lines = gist.stdout.strip().splitlines()
    gist_url = lines[-1] if lines else "<gist link>"
    write_lf(issue, issue_body(data, gist_url, archive is not None))
    title = (f"field-data: {machine['os']} / {len(data['sessions'])} "
             f"sessions / {stamp}")
    filed = subprocess.run([gh, "issue", "create", "--repo", FIELD_DATA_REPO,
                            "--label", "field-data", "--title", title,
                            "--body-file", str(issue)],
                           capture_output=True, encoding="utf-8",
                           errors="replace")
    if filed.returncode != 0:
        print(f"gist is up at {gist_url}, but gh issue create failed: "
              f"{filed.stderr.strip()}. The issue body is in {issue.name}; "
              f"file it by hand on {FIELD_DATA_REPO}.", file=sys.stderr)
        return 1
    print(f"sent: {gist_url}", file=sys.stderr)
    print(f"filed: {filed.stdout.strip()}", file=sys.stderr)
    return 0


# --- Package (ADR-0026, applying ADR-0007) ------------------------------------
# One session's chains with their anchor sidecars, the project record, a
# witness snapshot labelled testimony, and a plain-words README, listed by
# a manifest written last: the package a stranger can verify on a clean
# machine with `loxodonta verify-package` and nothing else. The supervisor
# builds and the recorder judges (ADR-0005, ADR-0009), so the recipient
# downloads the one file that already verifies a bare chain.

PACKAGE_FORMAT = "loxodonta-package/1"   # the receipt format stays 0.1
# The seals a package can declare (ADR-0007's declared seal set), in the
# order they are declared and applied: the anchor (--anchor) says when,
# the issuer signature (--sign) says which key (ADR-0026 ruling 4).
SEAL_ANCHOR = "anchor"
SEAL_SIGNATURE = "signature"
MANIFEST_SIDECAR = "manifest.json.anchors.jsonl"   # the anchor's proof
MANIFEST_SIGNATURE = "manifest.json.sig"   # ssh-keygen's detached signature
MANIFEST_PUBLIC_KEY = "manifest.json.pub"  # the key that made it: testimony
# The ssh-keygen signature namespace, the verifier's and the signer's
# both, so a signature made for anything else never verifies here.
SIGNATURE_NAMESPACE = "loxodonta-package"
# The verifier's allowed-signers principal, twice over: the packer runs
# the recipient's check on what it ships before anything is written.
SIGNATURE_PRINCIPAL = "issuer"
# The completeness row travels with these fields only: no judge command,
# no transcript path, no home. Paths the recipient cannot follow are
# noise, and the project record already carries the one that matters.
WITNESS_FIELDS = ("repo", "session", "state", "tools", "receipts",
                  "deficit", "words")
WITNESS_WORDS = (
    "testimony: the supervisor's completeness reading of each session "
    "packaged and the scan's verdicts at packaging, as the packing "
    "machine reported them. `loxodonta verify-package` checks that these "
    "bytes are unchanged since packaging and draws no verdict from them "
    "(ADR-0026).")


def sessions_of(chains):
    """{session: [chains]} in the census's order: session, then sibling
    sequence (ADR-0004: -002 continues the unsuffixed chain, whatever the
    two names sort like as strings)."""
    sessions = {}
    for log in sorted(chains, key=store_identity):
        sessions.setdefault(session_of(log), []).append(log)
    return sessions


def store_sessions():
    """{session: [chains]} over every drawer in the store, siblings
    included, drawer by drawer in the census's order."""
    return sessions_of(log for log in store_receipts().glob("*/receipts-*.jsonl")
                       if not log.name.endswith(SIDECAR_SUFFIXES))


def drawer_sessions(repo):
    """{session: [chains]} over a repository's drawers, as recall reads
    them (its own drawer, then its harness worktree drawers, ADR-0023),
    each drawer in the census's order: session, then sibling sequence."""
    sessions = {}
    for drawer in repo_drawers(repo):
        for session, logs in sessions_of(drawer_chains(drawer)).items():
            sessions.setdefault(session, []).extend(logs)
    return sessions


def chain_listing(log):
    """How the manifest lists a chain (ADR-0026 ruling 3): by head and
    entry count, never by file hash. The head is the commitment, and
    the verifier recomputes it by walking, so a Windows unzip that
    changes line endings changes nothing the manifest says."""
    lines = log.read_text(encoding="utf-8").splitlines()
    head = None
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
            head = entry["entry_hash"]
    sidecar = log.with_name(log.name + ".anchors.jsonl")
    return {"path": log.name, "head": head, "entries": len(lines),
            "anchors": sidecar.name if sidecar.exists() else None}


def artifact_listing(path):
    """How the manifest lists a post-close artifact: sha256 of its bytes
    and their count, because nothing else commits it (ADR-0026 ruling 3).
    Read in chunks: a transcript can run to hundreds of MB."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": path.name, "sha256": digest.hexdigest(), "bytes": size}


PACKAGE_MAX_BYTES = 1 << 30   # the verifier's cap, twice over


def bare_file_name(value):
    """The verifier's rule for a packaged name, twice over: a bare file
    name, nothing a path could be, since the layout is flat."""
    return (isinstance(value, str) and value not in ("", ".", "..")
            and "/" not in value and "\\" not in value
            and value == os.path.basename(value))


def package_too_large(stage, written):
    """True, the error printed, when the files would exceed the cap the
    verifier applies before unpacking a zip: writing such a package would
    ship one nothing can judge."""
    total = sum((stage / name).stat().st_size for name in written)
    if total <= PACKAGE_MAX_BYTES:
        return False
    print(f"error: the package would be {total} bytes unpacked, more than a "
          f"verifier will unpack ({PACKAGE_MAX_BYTES}); leave the transcript "
          "out, or package one session", file=sys.stderr)
    return True


def witness_snapshot(report, unit, sessions):
    """The witness's word on what is packaged, labelled testimony in the
    file itself: one completeness row per session, in the package's
    order, and the scan's verdict for each chain, as this scan reported
    them (ADR-0026 ruling 2). A session the scan gave no row is named
    with nothing else said of it."""
    rows = {row.get("session"): row
            for row in report.get("completeness", {}).get("sessions", [])}
    names = {log.name for chains in sessions.values() for log in chains}
    verdicts = [{"log": Path(chain["log"]).name, "verdict": chain["verdict"],
                 "entries": chain["entries"], "anchored": chain["anchored"]}
                for repo in report.get("repos", [])
                for sess in repo.get("sessions", [])
                for chain in sess.get("chains", [])
                if Path(chain["log"]).name in names]
    return {
        "testimony": WITNESS_WORDS,
        "scanned": report.get("scanned"),
        "unit": unit,
        "completeness": [
            {k: rows[session][k] for k in WITNESS_FIELDS if k in rows[session]}
            if session in rows else {"session": session}
            for session in sessions],
        "scan": {"exit": report.get("exit"), "chains": verdicts},
    }


def transcript_words(session, transcripts):
    """The README's sentence on one session's transcript: present, or
    why not. ADR-0026 ruling 2: the transcript ships only on request,
    and the README says whether it is here."""
    if transcripts is None:
        return ("no transcript: not requested (`supervisor package "
                "--transcript` carries it).")
    name = transcripts.get(session)
    if name is None:
        return ("no transcript: requested, but none for this session was "
                "paired on the packing machine: the harness keeps a "
                "transcript for a retention cycle, so an old session's may "
                "be gone, and a session the witness never covered has none "
                "to pair. The chain's commitments bind a transcript only "
                "while it exists.")
    if name is False:
        return ("no transcript: requested, and the scan named one, but it "
                "could not be read at packaging (moved, held open, or gone "
                "between the scan and the copy).")
    return (f"`{name}`: the harness transcript of this session, as it stood "
            "at packaging. The chain's transcript commitments bind its "
            "committed prefixes; the manifest commits the whole file, tail "
            "included, as of packaging. What it says is the harness's "
            "record, testimony like the action lines.")


def package_readme(unit, packed, sessions, witness, record, notes,
                   transcripts=None):
    """The plain-words page a recipient reads first: what is inside, how
    to verify it, what each layer shows and does not. `sessions` is
    {session: [chain listings]} in the package's order; `notes` says, per
    session that needs it, where it was recorded; `transcripts` is None
    when none was requested, else {session: the packaged transcript's
    name, or None when it was gone}. The page may print the chain heads,
    which exist before it is written; it never prints the manifest's
    hash, which does not exist yet (ADR-0007 ruling 2)."""
    project = unit["project"]
    count = sum(len(listings) for listings in sessions.values())
    if unit["kind"] == "session":
        title = f"session {unit['session']}"
        what = ("This is the receipt log of one AI agent session: one line "
                "per completed tool call, hash-chained, as the recorder "
                "wrote it on the machine where the session ran "
                "(docs/SPEC.md).")
        state = witness["completeness"][0].get("state", "none")
        reading = ("the supervisor's completeness reading of this session "
                   f"at packaging (state: {state})")
    else:
        title = f"drawer {project}"
        what = ("These are the receipt logs of one project's drawer, every "
                f"session recorded for it: {len(sessions)} session"
                f"{'' if len(sessions) == 1 else 's'} in {count} chain"
                f"{'' if count == 1 else 's'}, one line per completed tool "
                "call, hash-chained, as the recorder wrote them on the "
                "machine where the sessions ran (docs/SPEC.md).")
        reading = ("the supervisor's completeness reading of each session "
                   "at packaging, one row per session")
    lines = [
        f"# loxodonta package: {title}",
        "",
        f"Project `{project}`, packed {packed} by loxodonta supervisor "
        f"{TOOL_VERSION}, format `{PACKAGE_FORMAT}`. {what}",
        "",
        "## What is inside",
        "",
    ]
    for session, listings in sessions.items():
        indent = ""
        if unit["kind"] == "drawer":
            note = f" ({notes[session]})" if session in notes else ""
            lines.append(f"- session `{session}`{note}:")
            indent = "  "
        for chain in listings:
            lines.append(f"{indent}- `{chain['path']}`: a chain of "
                         f"{chain['entries']} entries, head `{chain['head']}`.")
            if chain["anchors"]:
                lines.append(f"{indent}- `{chain['anchors']}`: its anchor "
                             "sidecar, the OpenTimestamps proofs the recorder "
                             "collected for this chain's heads.")
        lines.append(f"{indent}- {transcript_words(session, transcripts)}")
    if record:
        lines.append(
            "- `project.json`: the project record, the absolute path of the "
            "project on the machine that recorded it. Off that machine it "
            "points nowhere, which the verifier says in so many words.")
    lines += [
        f"- `witness.json`: {reading}, and the verdict its scan gave each "
        "chain. Labelled testimony in the file: the verifier confirms "
        "these bytes are unchanged and draws no verdict from them.",
        "- `manifest.json`: the list of everything above, written last. "
        "Chains are listed by head and entry count, the other files by "
        "sha256 and byte count. Its hash is the only surface a seal "
        "applies to, and this package declares no seals.",
        "",
        "The transcript ships only on request (ADR-0026 ruling 2). The "
        "chain holds `Read: .env` with a fingerprint; the transcript holds "
        "the contents of `.env`. Packaging it can hand the recipient the "
        "very secret a session exfiltrated, so it is the operator's "
        "explicit call, and this page says, per session, whether it is "
        "here.",
        "",
        "## How to verify",
        "",
        "Get `loxodonta.py` from a release you trust "
        "(https://github.com/Acquiredl/loxodonta/releases; check it "
        "against the release's `SHA256SUMS`). Python 3.9 or newer, no "
        "dependencies. Then, on the zip or on the unpacked folder:",
        "",
        "    python loxodonta.py verify-package <this package>",
        "",
        "It prints the manifest's summary, the recorder's own verdict for "
        "each chain, the file references it cannot check off the machine, "
        "each artifact against the manifest, then the package verdict and "
        "one line of residual trust. Exit 0 is `SELF-CONSISTENT`; 1 is "
        "`CHAIN-BROKEN`; 2 is `ARTIFACT-DIVERGED`; 3 is `ANCHOR-MISMATCH`; 4 is "
        "`UNSUPPORTED-FORMAT`, a refusal; 5 is `TRANSCRIPT-DIVERGED` "
        "(docs/PACKAGE.md).",
        "",
        "## What each layer shows, and what it does not",
        "",
        "- The chain walk shows that no entry was edited, removed, or "
        "reordered since the chain was written. It does not show that "
        "the recorder was told the truth: the agent's harness supplied "
        "every action line, and the timestamps are its word.",
        "- An anchor line under a chain shows that chain's head existed "
        "by the Bitcoin block it names; the printed merkle root is yours "
        "to confirm against a block source you trust. An anchor speaks "
        "for its chain, never for this package as a set.",
    ]
    if transcripts and any(transcripts.values()):
        lines.append(
            "- A transcript here is judged against its chain's transcript "
            "commitments: `COMMITMENT HOLDS` under the chain means the "
            "committed prefix is the bytes the recorder hashed at the "
            "time. The bytes after the last commitment are held by the "
            "manifest alone, as of packaging; and before its first "
            "commitment a transcript was the harness's to write "
            "(ADR-0017).")
    lines += [
        "- The witness snapshot is testimony: the reader's reading on the "
        "packing machine, carried along unaltered, never checked against "
        "anything here.",
        "- The manifest shows that every file here is the one that was "
        "packed. With no seal declared, the whole package could have "
        "been regenerated wholesale and then packed, and nothing inside "
        "it could tell you: `SELF-CONSISTENT` states that limit.",
        "- File contents are not here. Each entry carries the path and "
        "the sha256 of the file the agent touched, as it stood then; the "
        "files themselves travel separately or not at all.",
        "",
    ]
    return "\n".join(lines)


def write_package(unit, sessions, drawer, report, stage, packed, seals,
                  transcripts=None):
    """Assemble one package in `stage`, in ADR-0007's write order: chain
    snapshot and sidecars, each session's transcript beside its chains,
    then the artifacts, then the README, then the manifest last,
    declaring `seals` before any of them exists so a stripped seal is
    caught (seal_package applies them). `sessions` is {session:
    [chains]} in the package's order; `drawer` is the one whose project
    record ships; `transcripts` is None when none was requested, else
    {session: transcript path} for the sessions the scan paired with a
    transcript still on disk (ADR-0026 ruling 2). Returns the file names
    in the order they were written, which is the order the zip keeps."""
    record = drawer / "project.json"   # travels only when it exists
    written = []
    listings = {}
    artifacts = []
    notes = {}
    shipped = None if transcripts is None else {}
    for session, chains in sessions.items():
        listings[session] = []
        for log in chains:
            # Listed from the chain in its drawer, whose sidecar sits
            # beside it; the snapshot has the same head and lines, byte
            # for byte.
            listing = chain_listing(log)
            listings[session].append(listing)
            shutil.copyfile(log, stage / log.name)
            written.append(log.name)
            if listing["anchors"]:
                shutil.copyfile(log.with_name(listing["anchors"]),
                                stage / listing["anchors"])
                written.append(listing["anchors"])
                artifacts.append(artifact_listing(stage / listing["anchors"]))
        if transcripts is not None:
            # The transcript travels under a bare name that names the
            # session (the layout is flat), listed by sha256 like any
            # post-close artifact, and every chain of the session names
            # it, so the verifier knows which transcript is whose. Gone
            # between the scan and this copy is gone: the README says so.
            shipped[session] = None
            name = f"transcript-{session}.jsonl"
            if session in transcripts:
                try:
                    shutil.copyfile(transcripts[session], stage / name)
                except OSError:
                    # Named by the scan, unreadable now; nothing partial
                    # stays behind, and the README says which it was.
                    (stage / name).unlink(missing_ok=True)
                    shipped[session] = False
                else:
                    written.append(name)
                    artifacts.append(artifact_listing(stage / name))
                    for listing in listings[session]:
                        listing["transcript"] = name
                    shipped[session] = name
        if chains[0].parent != drawer:
            # A worktree drawer's session (ADR-0023 part 3): its own
            # project record does not travel, so the README says whose
            # path its file references are relative to.
            notes[session] = (
                "recorded in the drawer of the harness worktree "
                f"`{drawer_name(chains[0].parent)}`, read as this "
                "repository's history (ADR-0023); its file references are "
                "relative to that worktree"
                + (", not to the path in `project.json`"
                   if record.exists() else ""))
    if record.exists():
        shutil.copyfile(record, stage / "project.json")
        written.append("project.json")
        artifacts.append(artifact_listing(stage / "project.json"))
    witness = witness_snapshot(report, unit, sessions)
    write_lf(stage / "witness.json",
             json.dumps(witness, indent=2, ensure_ascii=False) + "\n")
    written.append("witness.json")
    artifacts.append(artifact_listing(stage / "witness.json"))
    write_lf(stage / "README.md",
             package_readme(unit, packed, listings, witness, record.exists(),
                            notes, shipped))
    written.append("README.md")
    artifacts.append(artifact_listing(stage / "README.md"))
    manifest = {
        "format": PACKAGE_FORMAT,
        "packed": packed,
        "tool": f"loxodonta supervisor {TOOL_VERSION}",
        "unit": unit,
        "chains": [listing for per_session in listings.values()
                   for listing in per_session],
        "artifacts": artifacts,
        "seals": list(seals),
    }
    write_lf(stage / "manifest.json",
             json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    written.append("manifest.json")
    return written


def key_fingerprint(public_key):
    """The SHA256 fingerprint of a public key file, as ssh-keygen prints
    it (`ssh-keygen -lf`), or None when the file is not a key it reads:
    the recorder's, twice over, so the fingerprint printed at packaging
    is the one the verifier prints. The fingerprint is the key's
    identity (ADR-0008 ruling 6); the comment ssh-keygen prints beside
    it is a name, and stays unread."""
    listed = subprocess.run(["ssh-keygen", "-lf", str(public_key)],
                            capture_output=True, encoding="utf-8",
                            errors="replace")
    words = listed.stdout.split()
    if listed.returncode != 0 or len(words) < 2:
        return None
    return words[1]


def sign_manifest(stage, keyfile):
    """The issuer signature (ADR-0026 ruling 4, ADR-0008): ssh-keygen
    signs the manifest's shipped bytes with KEYFILE and writes
    manifest.json.sig beside it. This file never opens the private key;
    only ssh-keygen does, and its own prompts, a passphrase or a
    hardware touch, reach the terminal because its output is not
    captured. The public key ships as manifest.json.pub, testimony
    (ADR-0008 ruling 4): KEYFILE.pub when it exists, else what
    `ssh-keygen -y` derives from the key, which asks for an encrypted
    key's passphrase a second time; its two tokens only, type and key,
    since the comment is a name and the package carries none. Then the
    recipient's check, twice over: the signature must verify under the
    key that ships, or a stale KEYFILE.pub beside a regenerated key
    would send a package that could only ever read SEAL-INVALID.
    Returns (the shipped key's fingerprint, None), or (None, the
    problem sentence)."""
    manifest = stage / "manifest.json"
    signed = subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-n", SIGNATURE_NAMESPACE,
         "-f", str(keyfile), str(manifest)])
    if signed.returncode != 0:
        return None, (f"the manifest was not signed (ssh-keygen exited "
                      f"{signed.returncode}; its words are above)")
    beside = keyfile.with_name(keyfile.name + ".pub")
    if beside.is_file():
        line = beside.read_text("utf-8", errors="replace")
    else:
        derived = subprocess.run(["ssh-keygen", "-y", "-f", str(keyfile)],
                                 stdout=subprocess.PIPE, encoding="utf-8",
                                 errors="replace")
        if derived.returncode != 0:
            return None, (f"the public key was not derived from {keyfile} "
                          f"(ssh-keygen exited {derived.returncode}; its "
                          "words are above)")
        line = derived.stdout
    key = " ".join(line.split()[:2])
    write_lf(stage / MANIFEST_PUBLIC_KEY, key + "\n")
    with tempfile.TemporaryDirectory() as scratch:
        allowed = Path(scratch) / "allowed_signers"
        write_lf(allowed, f"{SIGNATURE_PRINCIPAL} {key}\n")
        with open(manifest, "rb") as shipped:
            verified = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", str(allowed),
                 "-I", SIGNATURE_PRINCIPAL, "-n", SIGNATURE_NAMESPACE,
                 "-s", str(stage / MANIFEST_SIGNATURE)],
                stdin=shipped, capture_output=True, encoding="utf-8",
                errors="replace")
    if verified.returncode != 0:
        reason = "; ".join(verified.stderr.strip().splitlines()) \
            or "ssh-keygen gave no reason"
        source = beside if beside.is_file() else keyfile
        return None, (f"the signature does not verify under the public key "
                      f"{source} gave ({reason}); a stale .pub beside a "
                      "regenerated key looks like this: move it aside and "
                      "the key derives its own")
    return key_fingerprint(stage / MANIFEST_PUBLIC_KEY), None


def seal_package(stage, seals, calendars, keyfile):
    """Apply the declared seals to the manifest, the last step of
    ADR-0007's write order: the signature first, then the anchor, since
    signing can fail on a passphrase or a touch and the anchor is the
    one step that leaves the machine, so a signing that fails costs no
    calendar submission. The signature: sign_manifest. The anchor
    (ADR-0026 ruling 4): the recorder posts the manifest's sha256 to the
    calendars once and writes the proof beside it as
    manifest.json.anchors.jsonl; the supervisor never speaks OTS itself.
    Returns (the seal files written, in order; the signing key's
    fingerprint, or None; and the problem when a seal could not be
    applied, the tool's own words already on stderr)."""
    written, fingerprint = [], None
    if SEAL_SIGNATURE in seals:
        try:
            fingerprint, problem = sign_manifest(stage, keyfile)
        except (FileNotFoundError, PermissionError):
            problem = ("the manifest was not signed: ssh-keygen is not on "
                       "PATH or cannot run here (OpenSSH 8.0 or later "
                       "carries it)")
        if problem:
            return [], None, problem
        written += [MANIFEST_SIGNATURE, MANIFEST_PUBLIC_KEY]
    if SEAL_ANCHOR in seals:
        command = [sys.executable, str(LOXODONTA), "anchor",
                   f"--manifest={stage / 'manifest.json'}"]
        for calendar in calendars:
            command += ["--calendar", calendar]
        finished = subprocess.run(
            command, capture_output=True, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        if finished.returncode != 0:
            print(finished.stderr.strip() or "the recorder gave no reason",
                  file=sys.stderr)
            return [], None, "the manifest was not anchored"
        written.append(MANIFEST_SIDECAR)
    return written, fingerprint, None


def zip_package(stage, written, out):
    """The default shape: one zip, members in write order, so the
    manifest is the last member too."""
    import zipfile
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as package:
        for name in written:
            package.write(stage / name, name)


def select_session(selector, sessions):
    """The session a selector names, with its chains: a session id, or
    an entry address inside it, resolved over the whole store with the
    recall commands' rules. (None, None) after the refusal is printed."""
    if selector in sessions:
        return selector, sessions[selector]
    if ADDRESS_RE.match(selector.lower()):
        logs = [log for chains in sessions.values() for log in chains]
        match, _ = match_address(selector.lower(), logs, "the store",
                                 hint="check the session id, or lengthen "
                                      "the address")
        if match is None:
            return None, None
        session = session_of(match[0])
        return session, sessions[session]
    print(f"error: {selector!r} is neither a session in the store nor an "
          "entry address (4 to 64 hex characters)", file=sys.stderr)
    return None, None


def split_refusal(session, chains):
    """True, the error printed, when a session's chains sit in more than
    one drawer (possible before ADR-0023). The layout is flat, one
    project record beside the chains; two drawers under one chain name
    would mean one silently overwriting the other. Refused whether the
    unit is the session or a drawer holding part of it: a drawer package
    that looked complete and was not would be worse than the refusal."""
    drawers = sorted({log.parent for log in chains})
    if len(drawers) < 2:
        return False
    print(f"error: session {session} spans {len(drawers)} drawers "
          f"({', '.join(d.name for d in drawers)}); packaging a split "
          "session is not built", file=sys.stderr)
    return True


def cmd_package(args):
    """Build one package (ADR-0026 ruling 1): of a session, selected by
    id or by an entry address inside it, siblings included; or, with
    --repo or no selector at all, of the repository's whole drawer,
    resolved as `digest --repo` resolves it (CLAUDE_PROJECT_DIR, else the
    current directory), its harness worktree drawers included
    (ADR-0023). The scan underneath is one ordinary tick, as export's
    is: its completeness rows and verdicts are the witness snapshot."""
    everywhere = store_sessions()
    if args.selector is not None:
        session, chains = select_session(args.selector, everywhere)
        if session is None:
            return 1
        drawer = chains[0].parent
        sessions = {session: chains}
        unit = {"kind": "session", "session": session,
                "project": drawer_name(drawer)}
        stem, label = session, f"session {session}"
    else:
        repo = invoking_repo(args)
        drawer = store_receipts() / project_slug(repo)
        sessions = drawer_sessions(repo)
        if not sessions:
            if repo_drawers(repo):
                print(f"error: the drawer for {repo} holds no chain; nothing "
                      "to package", file=sys.stderr)
            else:
                print(f"error: the store holds no drawer for {repo}; nothing "
                      "to package (a legacy receipts/ layout moves into the "
                      "store with `supervisor adopt`)", file=sys.stderr)
            return 1
        project = drawer_name(drawer) if drawer.is_dir() else repo.name
        unit = {"kind": "drawer", "project": project,
                "sessions": len(sessions)}
        # The file is named for the drawer folder, the slug: safe on every
        # filesystem and hash-suffixed, so two projects of one name never
        # collide (ADR-0011). The README keeps the display name.
        slug = drawer.name if drawer.is_dir() else project_slug(repo)
        stem, label = slug, f"drawer {slug}, {len(sessions)} session(s)"
    for session in sessions:
        # Checked against the whole store, not the selection: half of a
        # split session may sit in a drawer no selector reaches.
        if split_refusal(session, everywhere.get(session, sessions[session])):
            return 1
    packed = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    default = Path.cwd() / f"loxodonta-package-{stem}"
    out = Path(args.out) if args.out else (
        default if args.folder else default.with_name(default.name + ".zip"))
    if out.exists():
        print(f"error: {out} already exists; choose another --out",
              file=sys.stderr)
        return 1
    # A reading, not a tick (tick=False): the keepers stay quiet, so
    # packaging appends nothing to the chain it copies and sends nothing
    # off the machine; the baseline still remembers the look. Only the
    # seal step sends anything, and only with --anchor.
    report = scan_root(store_receipts(), witness=Path(args.witness),
                       store=True, tick=False)
    # Declared in ADR-0007's ladder order, the anchor before the
    # signature, which is the order the verifier judges and prints
    # them; applied the other way round (seal_package), since neither
    # depends on the other and only the anchor leaves the machine.
    seals = ([SEAL_ANCHOR] if args.anchor else []) + (
        [SEAL_SIGNATURE] if args.sign else [])
    # `~` reaches argv unexpanded from PowerShell and cmd, and
    # ssh-keygen does not expand it either; the docs' own example
    # starts with it, so it means home on every shell here.
    keyfile = Path(args.sign).expanduser() if args.sign else None
    calendars = args.calendar or ()
    transcripts = None
    if args.transcript:
        # The completeness watch's own pairing, session to transcript,
        # read off the scan's rows rather than paired a second time. A
        # session the watch found no readable transcript for is packaged
        # without one, and the README says why.
        transcripts = {
            row["session"]: Path(row["transcript"])
            for row in report.get("completeness", {}).get("sessions", [])
            if row.get("session") in sessions and row.get("transcript")}
    if transcripts is not None:
        for session in sessions:
            if not bare_file_name(f"transcript-{session}.jsonl"):
                # The verifier refuses a manifest naming anything but a
                # bare file name, so such a package would never verify.
                print(f"error: session {session!r} cannot carry a transcript: "
                      "its name is not a bare file name, and the package "
                      "layout is flat", file=sys.stderr)
                return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.folder:
        out.mkdir()
        written = write_package(unit, sessions, drawer, report, out, packed,
                                seals, transcripts)
        if package_too_large(out, written):
            shutil.rmtree(out)
            return 1
        sealed, fingerprint, problem = seal_package(out, seals, calendars,
                                                    keyfile)
        if problem:
            # A package declaring a seal it does not carry would verify
            # SEAL-MISSING; better nothing than that.
            shutil.rmtree(out)
    else:
        with tempfile.TemporaryDirectory() as staging:
            written = write_package(unit, sessions, drawer, report,
                                    Path(staging), packed, seals, transcripts)
            if package_too_large(Path(staging), written):
                return 1
            sealed, fingerprint, problem = seal_package(
                Path(staging), seals, calendars, keyfile)
            if not problem:
                zip_package(Path(staging), written + sealed, out)
    if problem:
        print(f"error: {problem}; nothing written", file=sys.stderr)
        return 1
    written += sealed
    chains = sum(len(logs) for logs in sessions.values())
    print(f"written: {out.name} ({label}, {chains} chain(s), "
          f"{len(written)} files)")
    print(f'verify: python "{LOXODONTA.as_posix()}" verify-package '
          f'"{out.as_posix()}"')
    if args.anchor:
        # The proof is pending until Bitcoin has it; the upgrade rewrites
        # only the sidecar, so the manifest and its seal stand.
        where = out if args.folder else Path("<the unpacked zip>")
        print("anchored: the manifest's sha256 went to the calendars; the "
              "proof is pending until Bitcoin has it, a few hours")
        print(f'upgrade: python "{LOXODONTA.as_posix()}" anchor --upgrade '
              f'--manifest="{(where / "manifest.json").as_posix()}"')
    if fingerprint:
        # The issuer's one job past signing (ADR-0008 ruling 4): the
        # fingerprint is what the recipient compares, so it is printed
        # here for publishing through a channel the package cannot
        # rewrite. Never the key's comment: that is a name.
        print(f"signed: key {fingerprint}; publish this fingerprint through "
              "a channel the package cannot rewrite, since the recipient "
              "compares it against one (ADR-0008)")
    return 0


# --- Fire drill ---------------------------------------------------------------
# The tamper playground graduated into its honest job: copy one chain
# into a sandbox, run the four-way battery, and show every expected
# alarm firing — detection rehearsed before it is ever needed. Real
# chains are never touched; the sandbox sits under the root (so the
# walker can inspect the copies) but outside every census pattern (so
# broken-on-purpose copies never alarm).

DRILL_DIR = ".supervisor-drill"

DRILL_EXPECTED = {"edit": ("BROKEN", 1), "delete": ("BROKEN", 1),
                  "reorder": ("BROKEN", 1),
                  "regenerate": ("HEAD-MISMATCH", 3)}

REHEARSAL = ("rehearsal on sandbox copies — nothing here is a verdict "
             "about the real chain; the checklist (including the "
             "walker's in-browser check) is at /checklist")


def receipts_cli(*args):
    return subprocess.run(
        [sys.executable, str(LOXODONTA), *args],
        capture_output=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(line + "\n" for line in lines))


def run_drill(root, asked):
    """The battery. Returns (report, exit) — exit 0 only when every
    alarm fired; a refusal reports why and writes nothing."""
    log = resolve_chain(root, asked)
    if log is None:
        return None, 1
    lines = log.read_text(encoding="utf-8").splitlines()
    if len(lines) < 3:
        return {"log": asked, "refused": "too short to drill — the "
                "battery plays with middle entries; give it at least "
                "two receipts past genesis"}, 1

    sandbox = root / DRILL_DIR
    if sandbox.exists():
        shutil.rmtree(sandbox)
    sandbox.mkdir()
    write_lines(sandbox / "pristine.jsonl", lines)
    known_head = receipts_cli(
        "head", "--log", str(sandbox / "pristine.jsonl")).stdout.strip()

    edited = json.loads(lines[1])
    edited["action"] = "REHEARSAL: this text was rewritten after the fact"
    write_lines(sandbox / "edit.jsonl",
                [lines[0], json.dumps(edited, sort_keys=True,
                                      separators=(",", ":")), *lines[2:]])
    write_lines(sandbox / "delete.jsonl", [lines[0], *lines[2:]])
    write_lines(sandbox / "reorder.jsonl",
                [lines[0], lines[2], lines[1], *lines[3:]])
    regenerated = sandbox / "regenerate.jsonl"
    receipts_cli("init", "--log", str(regenerated))
    for i in range(len(lines) - 1):
        receipts_cli("log", "--log", str(regenerated), "--actor",
                     "claude-code",
                     "--action", f"REHEARSAL: innocent-looking work {i}")

    drills = []
    for tamper, (expected, expected_exit) in DRILL_EXPECTED.items():
        command = ["verify", "--log", str(sandbox / f"{tamper}.jsonl")]
        if tamper == "regenerate":
            command += ["--expect-head", known_head]
        judged = receipts_cli(*command)
        spoken = judged.stdout.strip().splitlines()
        verdict = (spoken[-1].split(":")[0].split(" at ")[0]
                   if spoken else "NO-VERDICT")
        drills.append({
            "tamper": tamper,
            "expected": expected,
            "verdict": verdict,
            "fired": verdict == expected
            and judged.returncode == expected_exit,
            "copy": (sandbox / f"{tamper}.jsonl")
            .relative_to(root).as_posix(),
        })

    all_fired = all(d["fired"] for d in drills)
    report = {
        "log": log.relative_to(root.resolve()).as_posix(),
        "sandbox": sandbox.relative_to(root).as_posix(),
        "known_head": known_head,
        "rehearsal": REHEARSAL,
        "drills": drills,
        "all_fired": all_fired,
    }
    return report, 0 if all_fired else 1


def cmd_drill(args):
    root = Path(args.root).resolve()
    report, code = run_drill(root, args.log)
    if report is None:
        print(f"error: {args.log} is not a chain under {root}",
              file=sys.stderr)
        return 1
    print(json.dumps(report, indent=None if args.json else 2))
    return code


# --- Serve --------------------------------------------------------------------
# The face. Serialization only, zero decisions (ADR-0005): requests are
# answered from the newest scan no older than the tick, and the page
# below renders what the scan said — verdicts still come from
# `loxodonta verify`, nowhere else.

# How long one scan's answer stays the answer. The batching clause of
# ADR-0005 — one verify per chain per tick, never per HTTP request —
# and the reason two requests must never race: a scan diffs the
# baseline and then rewrites it, so concurrent scans could swallow a
# tripwire event between them. The env knob is the test suite's handle.
SCAN_TTL_SECONDS = float(os.environ.get("SUPERVISOR_SCAN_TTL_SECONDS", 3))


class Watchtower(ThreadingHTTPServer):
    """The threading server, with its one scan serialized: requests
    share the current tick's report instead of each spawning their own
    census of verify subprocesses."""

    def server_bind(self):
        # The stdlib's server_bind looks up the bound host's fully
        # qualified name, a reverse DNS query nothing here ever reads.
        # On a macOS runner that query hangs ~35 s per process, which
        # every `serve` test paid at startup. Bind, name it ourselves.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def remember_look(self):
        """One opening of the front page, under the scan lock — the day
        book is one file and the tick rewrites it wholesale."""
        book = (self.root.parent / "daybook.json" if self.store
                else self.root / DAYBOOK_NAME)
        with self.scan_lock:
            remember_look(book, datetime.now(timezone.utc))

    def fresh_status(self):
        with self.scan_lock:
            if (self.scan_body is None
                    or time.monotonic() - self.scan_at >= SCAN_TTL_SECONDS):
                report = scan_root(self.root, witness=self.witness,
                                   anchor_every=self.anchor_every,
                                   calendars=self.calendars,
                                   publish_every=self.publish_every,
                                   publish_url=self.publish_url,
                                   store=self.store)
                self.scan_body = json.dumps(report).encode("utf-8")
                self.scan_at = time.monotonic()
            return self.scan_body


class Face(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # the scan is the story; per-request chatter is noise

    def refused_off_machine(self):
        """The 127.0.0.1 bind keeps other machines out, but not a
        browser lied to by DNS: a page at attacker.example whose name
        rebinds to 127.0.0.1 reads as same-origin to the browser, and
        CORS never enters it — the Host header is the only witness
        left. A foreign Origin on a POST is the same stranger poking
        the drill from a page this server never wrote. Both get 403:
        nothing about this machine's activity is ever offered
        off-machine, and that includes off-machine by trickery."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        stranger = host not in ("127.0.0.1", "localhost")
        if not stranger and self.command == "POST":
            origin = self.headers.get("Origin")
            if origin:
                spoke = (urlparse(origin).hostname or "").lower()
                stranger = spoke not in ("127.0.0.1", "localhost")
        if stranger:
            self.send_error(403)
        return stranger

    def do_GET(self):
        if self.refused_off_machine():
            return
        url = urlparse(self.path)
        if url.path == "/api/status":
            self.reply(self.server.fresh_status(), "application/json")
        elif url.path == "/api/recall":
            asked = {key: values[0]
                     for key, values in parse_qs(url.query).items()}
            report = recall_root(self.server.root,
                                 repo=asked.get("repo") or None,
                                 since=asked.get("from") or None,
                                 until=asked.get("to") or None,
                                 path=asked.get("path") or None,
                                 store=self.server.store)
            self.reply(json.dumps(report).encode("utf-8"),
                       "application/json")
        elif url.path == "/api/activity":
            report = activity_root(self.server.root,
                                   store=self.server.store)
            self.reply(json.dumps(report).encode("utf-8"),
                       "application/json")
        elif url.path == "/api/shape":
            asked = {key: values[0]
                     for key, values in parse_qs(url.query).items()}
            report = session_shape(self.server.root, asked.get("repo", ""),
                                   asked.get("session", ""),
                                   store=self.server.store)
            if report is None:
                self.send_error(404)
                return
            self.reply(json.dumps(report).encode("utf-8"),
                       "application/json")
        elif url.path == "/api/chain":
            asked = {key: values[0]
                     for key, values in parse_qs(url.query).items()}
            report = walk_chain(self.server.root, asked.get("log", ""))
            if report is None:
                self.send_error(404)
                return
            self.reply(json.dumps(report).encode("utf-8"),
                       "application/json")
        elif url.path == "/api/search":
            asked = {key: values[0]
                     for key, values in parse_qs(url.query).items()}
            report = search_root(self.server.root, asked.get("q"),
                                 store=self.server.store)
            self.reply(json.dumps(report).encode("utf-8"),
                       "application/json")
        elif url.path == "/checklist":
            doc = HERE / "docs" / "FIRE-DRILL.md"
            if not doc.is_file():
                self.send_error(404)
                return
            self.reply(doc.read_bytes(), "text/plain; charset=utf-8")
        elif url.path == "/":
            self.server.remember_look()
            self.reply(PAGE.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.refused_off_machine():
            return
        url = urlparse(self.path)
        if url.path != "/api/drill":
            self.send_error(404)
            return
        asked = {key: values[0]
                 for key, values in parse_qs(url.query).items()}
        report, _ = run_drill(self.server.root, asked.get("log", ""))
        if report is None:
            self.send_error(404)
            return
        self.reply(json.dumps(report).encode("utf-8"), "application/json")

    def reply(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def cmd_serve(args):
    store = args.root is None
    root = store_receipts() if store else Path(args.root).resolve()
    # 127.0.0.1 is the whole posture: nothing about this machine's
    # activity is ever offered to another one.
    server = Watchtower(("127.0.0.1", args.port), Face)
    server.root = root
    server.store = store
    server.witness = Path(args.witness)
    server.anchor_every = args.anchor_every
    server.calendars = args.calendar or ()
    server.publish_every = args.publish_every
    server.publish_url = args.publish_url
    server.scan_lock = threading.Lock()
    server.scan_body = None
    server.scan_at = 0.0
    print(f"watching {root.as_posix()} on "
          f"http://127.0.0.1:{server.server_address[1]}/ "
          "(localhost only)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


# One inline page, two surfaces. The front is recall — the memory view,
# testimony-labeled, the selfish reason the operator visits daily. Around
# it sits the alarm layer: the status band, where tier styling is the
# point — the exit-3 tier ("this is not the recorded history") reads
# gravest and is never outranked by housekeeping; VALID and ANCHORED are
# visibly different claims; superseded tears stay as quiet evidence while
# new damage shouts. Data goes into the DOM through textContent only.
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>loxodonta — supervisor</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🐘</text></svg>">
<style>
  :root {
    /* One committed look (issue #48, ratified 2026-09-01): the cockpit
       is dark. OLED slate surfaces, one green accent for life signs,
       and the verdict palette below for claims. System fonts only —
       this page renders offline and asks nothing of any other host. */
    color-scheme: dark;
    --bg: #0b1120; --surface: #111a2e; --surface2: #18233b;
    --border: #24304c; --line: #1b2740;
    --fg: #f1f5f9; --dim: #8fa3bf; --faint: #5b6b85;
    --accent: #22c55e;
    --mono: 'JetBrains Mono', ui-monospace, Consolas, monospace;
    --sans: 'Inter', system-ui, sans-serif;
    /* The verdict palette. Roughly 8% of men cannot separate red from
       green, and the stoplight triple is the worst case of it: strong
       colour vision deficiency renders both as brown. So the quiet
       state carries blue (teal survives the collapse), and the three
       states part by lightness as well as hue — steps re-picked for
       the dark surface, same rule. Colour is never the only encoding
       here — every state is also named in words and marked with a
       shape, which is what makes the hue safe to keep. */
    --quiet: #2dd4bf;
    --damage: #f59e0b;
    --grave: #f87171;
    --quiet-wash: color-mix(in srgb, var(--quiet) 13%, transparent);
    --damage-wash: color-mix(in srgb, var(--damage) 13%, transparent);
    /* Deliberately much heavier than the other two. Amber and red are
       adjacent hues and collapse onto the same olive under deuteranopia,
       so the gravest state is separated by weight as well — which is
       what it should look like anyway. */
    --grave-wash: color-mix(in srgb, var(--grave) 26%, transparent);
    /* The investigate voice (tripwire, hot sessions): deliberately
       unlike any verdict tier. */
    --look: #a78bfa;
  }
  * { box-sizing: border-box; }
  /* The browser's own [hidden] rule loses to any author `display`, so
     an element the script hides would keep painting the moment someone
     gives it a grid. Say it once, here, and `hidden` means hidden. */
  [hidden] { display: none !important; }
  body { font-family: var(--sans); background: var(--bg); color: var(--fg);
         margin: 0; line-height: 1.5; }
  a { color: inherit; }
  code { font-family: var(--mono); }
  @media (prefers-reduced-motion: no-preference) {
    button, .tile, .chain, .story, .hit { transition: border-color 0.18s
      ease, background 0.18s ease, color 0.18s ease; }
  }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

  /* The shell: a sticky rail (what wants your eyes) beside the work
     area (what you chose to look at). Stacks on narrow viewports. */
  #shell { display: grid; grid-template-columns: 20rem minmax(0, 1fr);
           min-height: 100vh; }
  #rail { border-right: 1px solid var(--border); background: var(--surface);
          padding: 1.1rem 1rem 1rem; display: flex; flex-direction: column;
          gap: 1.1rem; position: sticky; top: 0; max-height: 100vh;
          overflow: auto; }
  #work { padding: 1.4rem 1.8rem 3rem; min-width: 0; max-width: 72rem; }
  @media (max-width: 60rem) {
    #shell { grid-template-columns: 1fr; }
    #rail { position: static; max-height: none;
            border-right: 0; border-bottom: 1px solid var(--border); }
  }
  header h1 { margin: 0; font-size: 1.05rem; letter-spacing: 0.04em; }
  header .stance { color: var(--dim); margin: 0.15rem 0 0;
                   font-size: 0.8rem; }
  /* The wordmark and the elephant are decoration, never information:
     aria-hidden in the markup, and every state must read without them. */
  .wordmark { font-family: var(--mono); font-size: 5px; line-height: 1.15;
              margin: 0 0 0.3rem; opacity: 0.8; overflow: hidden;
              user-select: none; color: var(--accent); }

  /* The status block: one condition, stated big, at the top of the
     rail. Grave is "not the recorded history" or receipts stopping
     mid-session; damage is a broken chain or a tripwire event; quiet
     is the state the operator sees most mornings — designed, not
     empty. Three encodings carry the same one condition: the shape,
     the words, and the colour. Drop any one and it still reads. */
  #strip { padding: 0.9rem 1rem; border-radius: 0.7rem;
           display: grid; grid-template-columns: auto 1fr;
           gap: 0 0.7rem; align-items: start; background: var(--surface2);
           border: 2px solid var(--border); }
  #strip .state { font-size: 1.15rem; font-weight: 800; margin: 0;
                  letter-spacing: 0.01em; }
  #strip .why { margin: 0.25rem 0 0; color: var(--dim);
                font-size: 0.85rem; }
  /* The recorder line sits under the verdict as context, quieter than
     it: smaller, dimmer, monospaced for the path. Drift underlines
     rather than recolours — it is a reason to look, never a verdict,
     and must not read as a fourth alarm state. */
  #recorder { font-size: 0.72rem; color: var(--faint);
              font-family: var(--mono); overflow-wrap: anywhere; }
  #recorder.drifted { color: var(--dim);
                      text-decoration: underline dotted var(--damage);
                      text-underline-offset: 0.25rem; }
  #statemark { font-size: 1.3rem; line-height: 1.2; grid-row: 1 / span 4; }
  #strip > :not(#statemark) { grid-column: 2; }
  #strip.quiet { background: color-mix(in srgb, var(--quiet) 9%, var(--surface));
                 border-color: color-mix(in srgb, var(--quiet) 55%, transparent); }
  #strip.quiet #statemark { color: var(--quiet); }
  #strip.damage { background: color-mix(in srgb, var(--damage) 10%, var(--surface));
                  border-color: var(--damage); }
  #strip.damage #statemark { color: var(--damage); }
  #strip.grave { background: color-mix(in srgb, var(--grave) 14%, var(--surface));
                 border-color: var(--grave); border-width: 3px; }
  #strip.grave #statemark { color: var(--grave); }

  /* The attention queue: the only loud list on the page. Severity
     sorted — live alarms, then damaged history, then reasons to look.
     Empty is designed, not blank: the elephant's other appearance. */
  #attention { display: flex; flex-direction: column; gap: 0.45rem; }
  .alert { display: flex; flex-direction: column; gap: 0.2rem;
           padding: 0.55rem 0.7rem; border-radius: 0.55rem;
           background: var(--surface2); border: 1px solid var(--border);
           font-size: 0.8rem; }
  .alert .head { display: flex; gap: 0.5rem; align-items: baseline; }
  .alert .what { color: var(--dim); overflow-wrap: anywhere; }
  .alert.grave { border-color: var(--grave);
                 background: color-mix(in srgb, var(--grave) 12%, var(--surface2)); }
  .alert.damage { border-color: var(--damage);
                  background: color-mix(in srgb, var(--damage) 9%, var(--surface2)); }
  .alert.look { border-color: var(--look);
                background: color-mix(in srgb, var(--look) 9%, var(--surface2)); }
  .alert button { align-self: flex-start; }
  #rail h2 { border: 0; margin: 0 0 0.4rem; padding: 0;
             font-size: 0.72rem; letter-spacing: 0.1em;
             text-transform: uppercase; color: var(--dim); }
  #railfoot { margin-top: auto; font-family: var(--mono);
              font-size: 0.7rem; color: var(--faint); line-height: 1.8; }

  /* Fourteen days, one cell each: the question the status block cannot
     answer on its own is whether today is a trend or a one-off. A day
     nobody watched is drawn as absence — hatched, not coloured —
     because an unread day is not a quiet one. */
  #fortnight { display: grid; grid-template-columns: repeat(14, 1fr);
               gap: 0.25rem; margin: 0.6rem 0 0.3rem; }
  .day { border-radius: 0.25rem; padding: 0.15rem 0; min-height: 2rem;
         display: flex; flex-direction: column; justify-content: flex-end;
         align-items: center; gap: 0.15rem; font-size: 0.65rem;
         border: 1px solid color-mix(in srgb, currentColor 22%, transparent);
         font-variant-numeric: tabular-nums; }
  .day .mark { font-size: 0.8rem; line-height: 1; }
  .day .num { opacity: 0.6; }
  .day.quiet { background: var(--quiet-wash); border-color: var(--quiet); }
  .day.quiet .mark { color: var(--quiet); }
  .day.damage { background: var(--damage-wash);
                border-color: var(--damage); }
  .day.damage .mark { color: var(--damage); }
  .day.grave { background: var(--grave-wash); border-color: var(--grave); }
  .day.grave .mark { color: var(--grave); }
  .day.unwatched {
    background: repeating-linear-gradient(45deg,
      transparent, transparent 3px,
      color-mix(in srgb, currentColor 14%, transparent) 3px,
      color-mix(in srgb, currentColor 14%, transparent) 6px);
    border-style: dashed; }
  .day.unwatched .mark { opacity: 0.45; }
  /* Ch. 9's move: mark where "now" is, so the eye lands on today
     rather than on the worst day in the window. */
  .day.today { outline: 2px solid currentColor; outline-offset: 1px; }
  /* The chart vocabulary borrowed from the scenarios (Ch. 18, 9, 31).
     No SVG and no library: bars are positioned divs, so the whole page
     stays readable top to bottom by someone who does not write CSS for
     a living. */

  /* Sequential ramps are a different job from alerting ramps, and must
     never be confused with one: counting receipts is not a claim that
     anything is wrong. Its own hue, deliberately outside the verdict
     palette. */
  :root { --busy: #4f6bed; }

  /* The session Gantt: one row per session on a shared fourteen-day
     axis. Ch. 18's move is the label riding the bar — when a row wants
     attention its name is already where the eye lands. */
  /* The gantt draws one lane per session, so its height is set by how
     much the operator worked and grows every month. It gets a box of
     its own and scrolls inside it (ADR-0027). That box is the cap's
     cheapest give: the panel scrolls either way, so its height is a
     display choice and not an information one, and it shrank when the
     histogram arrived. The axis rides the bottom of the same box so it
     stays put and stays aligned — sharing the scroller's width is what
     keeps the lanes and the dates on one scale. */
  #gantt-scroll { max-height: 24rem; overflow-y: auto; }
  #gantt { margin: 0.6rem 0; }
  .lane { position: relative; height: 1.55rem; margin: 0.2rem 0;
          border-radius: 0.3rem;
          background: color-mix(in srgb, currentColor 5%, transparent); }
  .bar { position: absolute; top: 0; bottom: 0; min-width: 3px;
         border-radius: 0.3rem; cursor: pointer; overflow: hidden;
         border: 1px solid color-mix(in srgb, currentColor 35%, transparent);
         background: color-mix(in srgb, currentColor 14%, transparent);
         display: flex; align-items: center; }
  .bar:hover, .bar:focus-visible {
         border-color: color-mix(in srgb, currentColor 75%, transparent); }
  /* Ch. 18 puts the label on the mark so a row's name is already where
     the eye lands. Its bars span one day and have room for text; ours
     span a fortnight, so a fifteen-minute session is a sliver and an
     inside label clips to "loxo". Same intent, adjusted: the label sits
     immediately beside its bar, and flips to the other side near the
     right edge so it never runs off. */
  .bar-label { position: absolute; top: 0; bottom: 0; font-size: 0.72rem;
               white-space: nowrap; padding: 0 0.35rem; opacity: 0.85;
               display: flex; align-items: center; pointer-events: none; }
  .bar-label.before { transform: translateX(-100%); }
  .bar.damage { background: var(--damage-wash); border-color: var(--damage); }
  .bar.grave { background: var(--grave-wash); border-color: var(--grave); }
  /* The deficit, drawn as absence: the tail a session owed and never
     wrote. Hatched, like an unwatched day, because it is the same
     kind of hole. */
  /* The density strip: one session's receipts across its own span,
     gaps and all (ADR-0027). An hour nobody worked is a floor line
     rather than a missing bar, because a gap and a blank must not look
     the same. The owed tail reuses the gantt's hatch on purpose —
     receipts a session owed and never wrote mean the same thing here,
     and one idiom is cheaper to learn than two. */
  .shape { display: flex; align-items: flex-end; gap: 1px; height: 38px;
           margin: 0.5rem 0 0.1rem;
           border-bottom: 1px solid var(--border); }
  .shape > div { flex: 1; min-width: 1px; background: var(--quiet);
                 border-radius: 1px 1px 0 0; }
  .shape .gap { height: 1px; background: var(--line); }
  .shape .peak { background: var(--look); }
  /* A fixed cap, never a proportion. This axis is time, and receipts
     a session owed and never wrote are a count with no hour attached —
     sizing the hatch by the deficit would put a number on the time
     axis that is not a time, and squeeze the real bars to make room.
     The count lives in the caption, where it can be read. */
  .shape .owed { position: static; flex: none; width: 0.75rem;
                 margin-left: 0.25rem; align-self: stretch;
                 border-radius: 0.2rem; }
  #inspect-shape .testimony { font-size: 0.7rem; padding: 0; margin: 0; }
  .owed { position: absolute; top: 0; bottom: 0; border-radius: 0.3rem;
          border: 1px dashed var(--damage);
          background: repeating-linear-gradient(45deg,
            transparent, transparent 3px,
            color-mix(in srgb, var(--damage) 45%, transparent) 3px,
            color-mix(in srgb, var(--damage) 45%, transparent) 6px); }
  #axis { display: flex; justify-content: space-between; font-size: 0.7rem;
          opacity: 0.6; font-variant-numeric: tabular-nums;
          margin-top: 0.15rem; position: sticky; bottom: 0;
          background: var(--surface); padding-top: 0.15rem; }

  /* The working-hours heat map: local weekday against local hour. */
  #clock { display: grid; grid-template-columns: auto repeat(24, 1fr);
           gap: 1px; margin: 0.6rem 0; font-size: 0.62rem; }
  /* Wider than tall on purpose. The cells were square when the
     clock lived in half a pane; at the activity tab's full width
     square makes every row 40px and the panel twice the height
     it needs for the same 24 columns (ADR-0027's cap). */
  .cell { aspect-ratio: 2 / 1; border-radius: 0.15rem;
          background: color-mix(in srgb, currentColor 6%, transparent); }
  .cell.on { background: color-mix(in srgb, var(--busy)
             calc(var(--heat) * 1%), transparent); }
  .clock-head, .clock-day { opacity: 0.6; display: flex;
          align-items: center; justify-content: center;
          font-variant-numeric: tabular-nums; }
  .clock-day { justify-content: flex-end; padding-right: 0.3rem; }

  /* The sparkline: fourteen days of one drawer, inside its own tile. */
  .spark { display: flex; align-items: flex-end; gap: 1px; height: 1.6rem;
           margin-top: 0.15rem; }
  .spark i { flex: 1; min-height: 1px; border-radius: 1px;
             background: color-mix(in srgb, var(--busy) 55%, transparent); }
  /* Ch. 9: mark where now is, so the eye lands on today rather than on
     the tallest bar in the window. */
  .spark i.now { background: var(--busy); }

  #lapse { margin: 0.2rem 0 0; font-size: 0.85rem; }
  #lapse.warn { color: var(--damage); font-weight: 700; }
  #freshness { display: block; margin-top: 0.35rem; font-size: 0.8rem;
               opacity: 0.7; font-variant-numeric: tabular-nums; }
  #elephant { font-family: ui-monospace, Consolas, monospace;
              font-size: 0.85rem; line-height: 1.1; margin: 0.5rem 0 0;
              opacity: 0.75; user-select: none; }

  /* The worktable (#48): tabs over a two-pane split. Pane one is
     always "what am I looking at"; pane two is always "the thing under
     inspection". Stacks on narrow viewports. */
  #tabs { display: flex; gap: 0.2rem; border-bottom: 1px solid var(--border);
          margin-bottom: 0; }
  .tab { font: inherit; font-size: 0.85rem; color: var(--dim);
         background: none; border: 0; border-bottom: 2px solid transparent;
         padding: 0.5rem 1rem; cursor: pointer; }
  .tab:hover { color: var(--fg); }
  .tab.on { color: var(--fg); border-bottom-color: var(--accent); }
  /* The split is the operator's to shape: the divider drags (or takes
     arrow keys) to trade width between the panes, and each pane body
     drags its own bottom-right corner to grow taller — the browser's
     native resize, no library. */
  #split { display: grid;
           grid-template-columns: minmax(0, var(--p1, 1fr)) 6px
                                  minmax(0, var(--p2, 1fr));
           border: 1px solid var(--border); border-top: 0;
           border-radius: 0 0 0.6rem 0.6rem; overflow: hidden;
           min-height: 24rem; }
  .pane { min-width: 0; display: flex; flex-direction: column; }
  #divider { cursor: col-resize; background: var(--border);
             border: 0; padding: 0; }
  #divider:hover, #divider:focus-visible { background: var(--accent); }
  .phead { font-family: var(--mono); font-size: 0.7rem; color: var(--faint);
           letter-spacing: 0.06em; padding: 0.45rem 0.8rem;
           border-bottom: 1px solid var(--border); background: var(--surface);
           display: flex; gap: 0.5rem; align-items: baseline; }
  .phead .no { color: var(--accent); }
  .pbody { overflow: auto; flex: 1; height: 32rem;
           resize: vertical; min-height: 10rem; }
  @media (max-width: 72rem) {
    #split { grid-template-columns: 1fr; }
    #divider { display: none; }
    .pane + .pane { border-top: 1px solid var(--border); }
  }
  #sessions-table { width: 100%; border-collapse: collapse;
                    font-size: 0.82rem; }
  #sessions-table th { font-size: 0.68rem; text-transform: uppercase;
                       letter-spacing: 0.07em; color: var(--faint);
                       text-align: left; padding: 0.5rem 0.7rem;
                       border-bottom: 1px solid var(--border);
                       position: sticky; top: 0; background: var(--surface); }
  #sessions-table td { padding: 0.5rem 0.7rem;
                       border-bottom: 1px solid var(--line); }
  #sessions-table tr { cursor: pointer; }
  #sessions-table tr:hover td { background: var(--surface2); }
  #sessions-table tr.dormant td { opacity: 0.55; }
  #sessions-table tr.sel td { background:
      color-mix(in srgb, var(--accent) 8%, transparent);
    border-left: 2px solid var(--accent); }
  #sessions-table .addr { font-family: var(--mono); color: #7dd3fc; }
  #sessions-table .num { font-variant-numeric: tabular-nums;
                         color: var(--dim); }
  #sessions-table .when { font-family: var(--mono); font-size: 0.72rem;
                          color: var(--faint); }
  #inspect-meta { padding: 0.7rem 0.9rem 0; color: var(--dim);
                  font-size: 0.82rem; }
  #inspect-chains { padding: 0.2rem 0.9rem 0.9rem; }
  #inspect-judge { margin: 0.4rem 0.9rem; padding: 0.55rem 0.7rem;
                   border-radius: 0.5rem; border: 1px dashed var(--border);
                   font-family: var(--mono); font-size: 0.72rem;
                   color: var(--dim); overflow-wrap: anywhere; }
  #inspect-judge strong { color: var(--fg); }
  .pane-empty { color: var(--faint); padding: 1.2rem;
                font-size: 0.85rem; }
  .tabpane { padding: 0; }
  /* The activity tab (ADR-0027): the store counted, at the full width
     of the work area rather than inside half of a split. The cap is
     physical — everything here fits one 1440x900 screen without
     scrolling, and the next panel displaces one of these rather than
     lengthening the page. Paired panels sit two across; the clock and
     the gantt want the whole row and take it. */
  #activity-view { display: grid; gap: 0.5rem;
                   grid-template-columns: repeat(2, minmax(0, 1fr));
                   padding: 0.6rem 0; }
  #activity-view .chartbox { border: 1px solid var(--line);
                             border-radius: 0.4rem;
                             background: var(--surface); min-width: 0; }
  #activity-view .wide { grid-column: 1 / -1; }
  /* The tally: how much is in here, stated once, in one row. Scale
     only — no verdict counts. How many chains are broken is the
     rail's sentence, and a cockpit whose two surfaces can disagree
     about what is alarming is the failure ADR-0013 named by name. */
  #tally { display: flex; flex-wrap: wrap; gap: 1.7rem;
           padding: 0.25rem 0 0.35rem; }
  #tally .count { display: flex; flex-direction: column; gap: 0.05rem; }
  #tally .num { font-family: var(--mono); font-size: 1.45rem;
                line-height: 1.15; color: var(--fg);
                font-variant-numeric: tabular-nums; }
  #tally .what { font-size: 0.68rem; letter-spacing: 0.09em;
                 text-transform: uppercase; color: var(--faint); }
  @media (max-width: 60rem) {
    #activity-view { grid-template-columns: 1fr; }
  }
  .chartbox { padding: 0.7rem 0.9rem 0.4rem; }
  .chartbox h3 { margin: 0 0 0.3rem; font-size: 0.72rem;
                 letter-spacing: 0.08em; text-transform: uppercase;
                 color: var(--dim); }
  .chartbox .testimony { font-size: 0.72rem; padding: 0; }
  .clab { font-family: var(--mono); font-size: 10px; fill: var(--dim); }
  .cval { font-family: var(--mono); font-size: 10px; fill: var(--fg); }
  .cbar { fill: var(--accent); opacity: 0.85; }
  .cbar.hot { fill: var(--grave); }
  .cnorm { stroke: var(--dim); stroke-width: 1.5;
           stroke-dasharray: 4 4; }
  .tabpane > .testimony { padding: 0.6rem 0.8rem 0; margin: 0; }
  #pane-projects #tiles { margin: 0.8rem; }
  #pane-search #ask-search { width: calc(100% - 1.6rem);
                             margin: 0.6rem 0.8rem; }
  #pane-search #found { padding: 0 0.8rem 0.8rem; }
  #pane-evidence > div { padding: 0.3rem 0.8rem; }
  #pane-sessions #filters { margin: 0.6rem 0.8rem; }

  /* The drawers: one tile per project, worst claim first, click for
     that project's timeline. */
  #tiles { display: grid; gap: 0.7rem; margin: 0.8rem 0;
           grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr)); }
  .tile { text-align: left; font: inherit; color: inherit; cursor: pointer;
          display: flex; flex-direction: column; gap: 0.35rem;
          padding: 0.7rem 0.9rem; border-radius: 0.6rem;
          border: 1px solid color-mix(in srgb, currentColor 25%, transparent);
          background: color-mix(in srgb, currentColor 5%, transparent); }
  .tile:hover, .tile:focus-visible {
          border-color: color-mix(in srgb, currentColor 60%, transparent); }
  .tile .name { font-weight: 700; font-size: 1.05rem;
                overflow-wrap: anywhere; }
  .tile .meta { font-size: 0.82rem; opacity: 0.8;
                font-variant-numeric: tabular-nums; }
  .tile .row { display: flex; flex-wrap: wrap; gap: 0.5rem;
               align-items: baseline; }
  h2 { border-bottom: 1px solid color-mix(in srgb, currentColor 25%, transparent);
       padding-bottom: 0.2rem; margin-top: 2rem; }
  .testimony { font-style: italic; margin-top: -0.4rem;
               color: color-mix(in srgb, currentColor 65%, transparent); }
  #filters { display: flex; flex-wrap: wrap; gap: 1rem; margin: 1rem 0;
             align-items: end; }
  #filters label { display: flex; flex-direction: column;
                   font-size: 0.8rem; opacity: 0.85; gap: 0.15rem; }
  #filters input, #filters select {
    font: inherit; padding: 0.25rem 0.4rem; border-radius: 0.4rem;
    border: 1px solid color-mix(in srgb, currentColor 35%, transparent);
    background: transparent; color: inherit; }
  .story { display: flex; flex-wrap: wrap; gap: 0.7rem;
           align-items: baseline; padding: 0.55rem 0.8rem; margin: 0.4rem 0;
           border-left: 3px solid color-mix(in srgb, currentColor 30%, transparent);
           background: color-mix(in srgb, currentColor 5%, transparent);
           border-radius: 0 0.5rem 0.5rem 0; }
  .story .repo { font-weight: 700; }
  .story .id { font-family: monospace; opacity: 0.8; }
  .story .span { font-variant-numeric: tabular-nums; }
  .story .count { opacity: 0.85; }
  .story .sibling { flex-basis: 100%; margin: 0; font-size: 0.85rem;
                    opacity: 0.7; }
  .story.found-you { border-left-color: var(--quiet);
                     background: var(--quiet-wash); }
  #ask-search { width: 100%; box-sizing: border-box; font: inherit;
                padding: 0.45rem 0.7rem; border-radius: 0.5rem;
                border: 1px solid color-mix(in srgb, currentColor 35%, transparent);
                background: transparent; color: inherit; margin: 0.6rem 0; }
  #found .tally { font-size: 0.85rem; opacity: 0.7; margin: 0.2rem 0; }
  .hit { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: baseline;
         width: 100%; text-align: left; font: inherit; color: inherit;
         background: color-mix(in srgb, currentColor 7%, transparent);
         border: 1px solid color-mix(in srgb, currentColor 20%, transparent);
         border-radius: 0.5rem; padding: 0.4rem 0.7rem; margin: 0.3rem 0;
         cursor: pointer; }
  .hit .where { font-weight: 700; }
  .hit .entry { font-family: monospace; font-size: 0.8rem; opacity: 0.7; }
  .hit .said { flex-basis: 100%; margin: 0; font-family: monospace;
               font-size: 0.85rem; overflow-wrap: anywhere; }
  .session { margin: 0.8rem 0 0.8rem 0.5rem; }
  .session > .name { font-family: monospace; opacity: 0.8; }
  .chain { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: baseline;
           padding: 0.5rem 0.8rem; margin: 0.4rem 0; border-radius: 0.5rem;
           border: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  .chain .file { font-family: monospace; font-size: 0.85rem; opacity: 0.75; }
  .chain .claim { flex-basis: 100%; margin: 0; font-size: 0.9rem;
                  opacity: 0.85; }
  .chain details { flex-basis: 100%; font-size: 0.85rem; }
  .chain pre { overflow-x: auto; opacity: 0.8; }
  .chip { font-family: monospace; font-weight: 700; font-size: 0.85rem;
          padding: 0.15rem 0.6rem; border-radius: 0.4rem;
          border: 2px solid transparent; }
  .badge { font-size: 0.75rem; padding: 0.1rem 0.5rem; border-radius: 0.4rem;
           background: color-mix(in srgb, currentColor 12%, transparent); }

  /* The tier ladder. Visual weight goes down as you read down — and the
     top rung belongs to "not the recorded history", always. */
  .tier-regenerated { border: 3px solid #7a0c0c;
                      background: #7a0c0c1a; }
  .tier-regenerated .chip { background: #7a0c0c; color: #fff; }
  .tier-broken { border-color: var(--grave); background: var(--grave-wash); }
  .tier-broken .chip { color: var(--grave); border-color: var(--grave); }
  .tier-refused .chip { color: #8a6d00; border-color: #8a6d00; }
  .tier-anchored .chip { background: var(--quiet); color: #fff; }
  .tier-valid .chip { color: var(--quiet); border-color: var(--quiet); }
  .tier-superseded { opacity: 0.55; }
  .tier-superseded .chip { color: inherit;
                           border-color: color-mix(in srgb, currentColor 40%, transparent); }

  /* The tripwire speaks in its own color: a change event is a reason to
     investigate, deliberately unlike any verdict tier. */
  .trip { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: baseline;
          padding: 0.5rem 0.8rem; margin: 0.4rem 0; border-radius: 0.5rem;
          border: 3px solid #6d28a8; background: #6d28a81a; }
  .trip .chip { background: #6d28a8; color: #fff; }
  .trip .claim { flex-basis: 100%; margin: 0; font-size: 0.9rem;
                 opacity: 0.9; }

  /* The completeness watch: live alarms in their own amber voice;
     ended deficits and flags kept quiet, as evidence. */
  .watch-row { display: flex; flex-wrap: wrap; gap: 0.6rem;
               align-items: baseline; padding: 0.5rem 0.8rem;
               margin: 0.4rem 0; border-radius: 0.5rem;
               border: 1px solid color-mix(in srgb, currentColor 25%, transparent); }
  .watch-row.live { border: 3px solid var(--damage); background: var(--damage-wash); }
  .watch-row.live .chip { background: var(--damage); color: #fff; }
  .watch-row.quiet { opacity: 0.6; }
  .watch-row.quiet .chip { color: inherit;
                           border-color: color-mix(in srgb, currentColor 40%, transparent); }
  /* The consumption watch borrows the tripwire's investigate voice:
     a hot session is a reason to look, deliberately unlike any
     verdict tier and never as loud as a live completeness alarm. */
  .watch-row.hot { border: 3px solid #6d28a8; background: #6d28a81a; }
  .watch-row.hot .chip { background: #6d28a8; color: #fff; }

  /* The anchor panel: the block height is the operator's half of the
     regeneration defense, so it is the biggest thing in each row. */
  .berth { display: flex; flex-wrap: wrap; gap: 0.7rem;
           align-items: baseline; padding: 0.5rem 0.8rem; margin: 0.4rem 0;
           border-left: 3px solid color-mix(in srgb, currentColor 30%, transparent);
           background: color-mix(in srgb, currentColor 5%, transparent);
           border-radius: 0 0.5rem 0.5rem 0; }
  .berth .height { font-size: 1.35rem; font-weight: 800; color: var(--quiet); }
  .berth .pending-proof { color: #8a6d00; }
  .berth .bare { opacity: 0.75; }
  .berth .stale { color: var(--damage); font-weight: 700; }
  .berth .shout { color: var(--grave); font-weight: 700; }

  /* The walker: entry by entry, with the browser's own recomputation
     beside each hash — a second check in the reader's hands. */
  .walk-entry { padding: 0.5rem 0.8rem; margin: 0.4rem 0;
                border-radius: 0.5rem; font-size: 0.9rem;
                border: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  .walk-entry .hashes { font-family: monospace; font-size: 0.8rem;
                        opacity: 0.75; }
  .walk-entry .said { font-family: monospace; overflow-wrap: anywhere; }
  .walk-entry .who { opacity: 0.75; font-size: 0.85rem; }
  .walk-damage { padding: 0.5rem 0.8rem; margin: 0.4rem 0;
                 border: 3px solid var(--grave); background: var(--grave-wash);
                 border-radius: 0.5rem; font-family: monospace;
                 overflow-wrap: anywhere; }
  .recheck { font-size: 0.8rem; padding: 0.1rem 0.5rem;
             border-radius: 0.4rem; }
  .recheck.match { color: var(--quiet); border: 1px solid var(--quiet); }
  .recheck.mismatch { background: var(--grave); color: #fff; font-weight: 700; }
  .broken-link { color: var(--grave); font-weight: 700; font-size: 0.85rem; }
  button.walk { font: inherit; font-size: 0.8rem; cursor: pointer;
                border-radius: 0.4rem; padding: 0.1rem 0.6rem;
                border: 1px solid color-mix(in srgb, currentColor 35%, transparent);
                background: transparent; color: inherit; }

  /* The fire drill: rehearsal results, never verdicts. */
  .drill-row { display: flex; flex-wrap: wrap; gap: 0.7rem;
               align-items: baseline; padding: 0.4rem 0.8rem;
               margin: 0.3rem 0; border-radius: 0.5rem;
               border: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  .drill-row .fired { color: var(--quiet); font-weight: 700; }
  .drill-row .misfired { background: var(--grave); color: #fff;
                         font-weight: 700; padding: 0.1rem 0.5rem;
                         border-radius: 0.4rem; }
  #drill-banner.quiet, #drill-banner.shouting { padding: 0.5rem 1rem;
               border-radius: 0.5rem; font-weight: 600; margin: 0.5rem 0; }
  #drill-banner.quiet { background: var(--quiet)22; border: 1px solid var(--quiet); }
  #drill-banner.shouting { background: var(--grave-wash);
                           border: 1px solid var(--grave); }
</style>
</head>
<body>
<div id="shell">
<aside id="rail">
<header>
  <pre class="wordmark" aria-hidden="true">
db       .d88b.  db    db  .d88b.  d8888b.  .d88b.  d8b   db d888888b  .d8b.
88      .8P  Y8. `8b  d8' .8P  Y8. 88  `8D .8P  Y8. 888o  88 `~~88~~' d8' `8b
88      88    88  `8bd8'  88    88 88   88 88    88 88V8o 88    88    88ooo88
88      88    88  .dPYb.  88    88 88   88 88    88 88 V8o88    88    88~~~88
88booo. `8b  d8' .8P  Y8. `8b  d8' 88  .8D `8b  d8' 88  V888    88    88   88
Y88888P  `Y88P'  YP    YP  `Y88P'  Y8888D'  `Y88P'  VP   V8P    YP    YP   YP</pre>
  <h1>supervisor</h1>
  <p class="stance">a tripwire with a memory — verdicts come from
  <code>receipts verify</code>; this page draws them and decides nothing</p>
</header>
<div id="strip">
  <span id="statemark" aria-hidden="true"></span>
  <p class="state" id="stateline">reading the scan…</p>
  <p class="why" id="statewhy"></p>
  <p class="why" id="recorder"></p>
  <span id="freshness"></span>
  <pre id="elephant" aria-hidden="true" hidden>
       __ ___
   .--'  `   `''--..   ,-.
  /   ()            `-'  /
 |      ___.....____,--'`
  \\    /       |    |
  |    |       |    |
  J    L       J    L
 (__,__)      (__,__)</pre>
</div>

<section id="attention-box">
  <h2>attention</h2>
  <div id="attention"></div>
</section>

<section id="trend">
  <h2>fourteen days</h2>
  <p class="testimony">one cell per day, worst claim of that day — is
  this a trend or a one-off? A day nobody watched is drawn as a gap,
  because an unread day is not a quiet one</p>
  <div id="fortnight"></div>
  <p id="lapse"></p>
</section>

<footer id="railfoot">verdicts come from <code>receipts verify</code> —
this page draws them and decides nothing</footer>
</aside>
<main id="work">
<section id="worktable">
  <div id="tabs" role="tablist">
    <button type="button" class="tab on" data-tab="sessions">sessions</button>
    <button type="button" class="tab" data-tab="projects">projects</button>
    <button type="button" class="tab" data-tab="search">search</button>
    <button type="button" class="tab" data-tab="evidence">evidence</button>
    <button type="button" class="tab" data-tab="activity">activity</button>
  </div>
  <div id="split">
    <div class="pane">
      <div class="phead"><span class="no">[1]</span> testimony, not a
      verdict — what was attempted, as the writer told it;
      click a row to inspect</div>
      <div class="pbody" id="pane1">
        <div class="tabpane" id="pane-sessions">
          <div id="filters">
            <label>repo
              <select id="ask-repo"><option value="">every repo</option></select>
            </label>
            <label>from <input type="date" id="ask-from"></label>
            <label>to <input type="date" id="ask-to"></label>
            <label>file path
              <input type="text" id="ask-path" placeholder="anywhere it appears">
            </label>
          </div>
          <table id="sessions-table">
            <thead><tr><th>session</th><th>repo</th><th>receipts</th>
            <th>span</th></tr></thead>
            <tbody id="sessions-body"></tbody>
          </table>
        </div>
        <div class="tabpane" id="pane-projects" hidden>
          <p class="testimony">one per project — the worst claim leads;
          click a drawer to focus its sessions</p>
          <div id="tiles">remembering…</div>
        </div>
        <div class="tabpane" id="pane-search" hidden>
          <p class="testimony">the writer's word, findable — run
          <code>receipts verify</code> for the verdict</p>
          <input type="search" id="ask-search"
                 placeholder="search every action line on this machine">
          <div id="found"></div>
        </div>
        <div class="tabpane" id="pane-evidence" hidden>
          <p class="testimony">what changed since the last look, which
          sessions ended behind their witness, and which burned far
          above the store's norm — kept as evidence; reasons to look,
          never verdicts</p>
          <div id="tripwire"></div>
          <div id="watch"></div>
          <div id="consumption"></div>
          <div id="lifecycle"></div>
          <div id="anchors">
            <p class="testimony">the block height is your half of the
            regeneration defense — confirm it against a Bitcoin block
            source you trust; when a head last left this machine,
            published or anchored, is staleness to read, not a
            verdict</p>
            <div id="panel"></div>
          </div>
        </div>
      </div>
    </div>
    <button type="button" id="divider" role="separator"
            aria-orientation="vertical"
            aria-label="drag or use arrow keys to resize the panes"
            title="drag to resize"></button>
    <div class="pane">
      <div class="phead"><span class="no">[2]</span> inspect — the chain
        as <code>receipts verify</code> sees it</div>
      <div class="pbody">
        <div id="p2-inspect">
          <div id="inspect-meta" class="pane-empty">click a session on
          the left — its chains, claims, and actions land here</div>
          <div id="inspect-shape" hidden></div>
          <div id="inspect-judge" hidden></div>
          <div id="inspect-chains"></div>
        </div>
      </div>
    </div>
  </div>

  <div id="activity-view" hidden>
    <div class="chartbox wide">
      <h3>the tally — the whole store</h3>
      <div id="tally">remembering…</div>
    </div>
    <div class="chartbox">
      <h3>busiest hour vs the store's norm — every session</h3>
      <div id="chart-tempo"></div>
    </div>
    <div class="chartbox">
      <h3>looks per day — fourteen days</h3>
      <p class="testimony">red marks a day that carried an alarm; an
      unread day is a gap, not a quiet day</p>
      <div id="chart-looks"></div>
    </div>
    <div class="chartbox">
      <h3>the histogram — ninety days</h3>
      <p class="testimony">the tool each receipt names, counted; an MCP
      call by the server it reached. Bookkeeping is not a tool call and
      is left out</p>
      <div id="chart-tools"></div>
      <p class="testimony" id="tools-tail"></p>
    </div>
    <div class="chartbox">
      <h3>files touched — ninety days</h3>
      <p class="testimony">receipts that named the file. A subagent's
      worktree copy folds into the file it copied; any other path is
      shown as the writer wrote it</p>
      <div id="chart-files"></div>
      <p class="testimony" id="files-tail"></p>
    </div>
    <div class="chartbox wide">
      <h3>working hours — ninety days, your own timezone</h3>
      <p class="testimony">when receipts actually arrive: what your
      weeks really look like</p>
      <div id="clock">remembering…</div>
    </div>
    <div class="chartbox wide">
      <h3>sessions on one axis — fourteen days</h3>
      <p class="testimony">drawn from the completeness watch; a hatched
      tail is receipts the session owed and never wrote. Reasons to
      look, never verdicts</p>
      <div id="gantt-scroll">
        <div id="gantt">remembering…</div>
        <div id="axis"></div>
      </div>
    </div>
  </div>
</section>

<section id="firedrill" hidden>
  <h2>fire drill</h2>
  <p class="testimony">rehearsal on sandbox copies — nothing here is a
  verdict about a real chain. The manual checklist, including the
  walker's in-browser WebCrypto check, lives at
  <a href="/checklist">/checklist</a></p>
  <div id="drill-banner"></div>
  <div id="drill-results"></div>
</section>

<section id="walker" hidden>
  <h2>walker</h2>
  <p class="testimony">entry by entry, each hash recomputed in your
  browser via WebCrypto — a second, independent check in your hands.
  The walker reports its recomputation; the verdict comes from
  <code>receipts verify</code></p>
  <div id="walking"></div>
  <div id="entries"></div>
</section>
</main>
</div>
<script>
"use strict";

// Which rung of the ladder a chain stands on. Order matters: standing
// down (superseded) is checked first, then the gravest claim, downward.
function tier(chain) {
  if (chain.superseded) return "superseded";
  if (chain.exit === 3) return "regenerated";
  if (chain.verdict === "BROKEN") return "broken";
  // No diverged tier: the tick never passes --files
  // (.out-of-scope/002), so the files-diverged verdict cannot reach
  // this page — anything unexpected falls to "refused", failing loud.
  if (chain.verdict === "VALID") {
    return chain.anchored ? "anchored" : "valid";
  }
  return "refused";  // UNSUPPORTED-VERSION, NO-VERDICT
}

// What each rung is allowed to claim — VALID and ANCHORED deliberately
// say different things, because they are different things.
const CLAIM = {
  regenerated: "not the recorded history — an anchor or head record " +
               "contradicts this chain",
  broken: "chain integrity failed — history was altered after the fact",
  refused: "no verdict — a chain nobody can judge still demands attention",
  valid: "intact against itself — tamper-evident, not yet anchored",
  anchored: "intact and anchored — this history existed by the named " +
            "Bitcoin block",
  superseded: "torn tail, already handled — recording continued in a " +
              "sibling chain; kept as quiet evidence",
};

// The shape half of the strip's redundant encoding. Colour, words and
// shape all carry the same one condition, so the state still reads for
// someone who cannot separate the hues — and still reads in a
// screenshot printed in black and white.
const MARK = { quiet: "●", damage: "▲", grave: "✕",
               unwatched: "·" };

const CHIP = {
  regenerated: c => c.verdict, broken: () => "BROKEN",
  refused: c => c.verdict,
  valid: () => "VALID", anchored: () => "ANCHORED",
  superseded: () => "BROKEN · superseded",
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function chainRow(chain) {
  const rung = tier(chain);
  const row = el("div", "chain tier-" + rung);
  row.appendChild(el("span", "chip", CHIP[rung](chain)));
  const file = chain.log.split("/").pop();
  row.appendChild(el("span", "file",
                     file + " · " + chain.entries + " entries"));
  if (chain.worktree) {
    row.appendChild(el("span", "badge", "stranded in a worktree"));
  }
  const walk = el("button", "walk", "walk this chain");
  walk.type = "button";
  walk.addEventListener("click", () => openWalker(chain.log));
  row.appendChild(walk);
  const drill = el("button", "walk", "drill (sandbox)");
  drill.type = "button";
  drill.addEventListener("click", () => runDrill(chain.log));
  row.appendChild(drill);
  const anchoredLine =
    chain.detail.find(line => line.startsWith("ANCHORED"));
  row.appendChild(el("p", "claim",
    rung === "anchored" && anchoredLine ? anchoredLine : CLAIM[rung]));
  if (chain.detail.length) {
    const details = el("details");
    details.appendChild(el("summary", "", "what verify said"));
    details.appendChild(el("pre", "", chain.detail.join("\\n")));
    row.appendChild(details);
  }
  return row;
}

// The verdict strip: one condition, stated huge, ordered by the tier
// language — "not the recorded history" and a mid-session silence read
// red; damage and tripwire events read amber; everything else is the
// designed quiet state (the elephant's one appearance).
function renderStrip(report) {
  const strip = document.getElementById("strip");
  const state = document.getElementById("stateline");
  const why = document.getElementById("statewhy");
  // Which recorder is running. Quiet by design — it is context for
  // every verdict above it, not a verdict of its own, and it never
  // colours the strip.
  const rec = report.recorder;
  const recLine = document.getElementById("recorder");
  if (rec && recLine) {
    recLine.textContent = "recorder: " + rec.note +
      (rec.path ? " · " + rec.path : "");
    recLine.classList.toggle("drifted",
      !!(rec.dirty || rec.behind || rec.state === "unwired" ||
         rec.state === "unknown"));
  }
  const chains = report.repos.flatMap(r =>
    r.sessions.flatMap(s => s.chains));
  const live = report.completeness.sessions.filter(s =>
    ["ALARM-SILENT", "ALARM-DEFICIT"].includes(s.state));
  const regenerated = chains.filter(c => !c.superseded && c.exit === 3);
  const broken = chains.filter(c => !c.superseded &&
                                    c.verdict === "BROKEN");
  const changes = report.baseline.events.length;
  const quietEvidence = chains.filter(c => c.superseded).length;
  let colour;
  if (regenerated.length) {
    colour = "grave";
    state.textContent = "NOT THE RECORDED HISTORY";
    why.textContent = regenerated.length + " chain(s) contradict an " +
      "anchor or head record — the gravest claim this page can carry";
  } else if (live.length) {
    colour = "grave";
    state.textContent = "RECEIPTS STOPPED ARRIVING";
    why.textContent = live.length + " session(s) visibly active while " +
      "the chain goes quiet — investigate while it is live";
  } else if (broken.length || changes || report.exit !== 0) {
    colour = "damage";
    state.textContent = broken.length ? "HISTORY WAS ALTERED"
                                      : "CHANGED SINCE LAST LOOK";
    why.textContent = (broken.length
      ? broken.length + " chain(s) fail verification — "
      : "") + (changes
      ? changes + " change(s) the baseline cannot explain as appends"
      : "details in the band below") +
      " (scan exit " + report.exit + ")";
  } else {
    colour = "quiet";
    state.textContent = "all quiet";
    why.textContent = chains.length + " chain(s), every receipt " +
      "accounted for" +
      (quietEvidence ? " — " + quietEvidence + " superseded tear(s) " +
                       "kept as quiet evidence" : "");
  }
  strip.className = colour;
  document.getElementById("statemark").textContent = MARK[colour];
  document.getElementById("elephant").hidden = colour !== "quiet";
  const freshness = document.getElementById("freshness");
  freshness.textContent = "last scan " +
    (report.scanned ? since(report.scanned) + " ago" : "just now") +
    " · this page refreshes every 30s";
}

// The attention queue: everything that wants eyes, in one list,
// severity sorted — the rail's ordering contract. Live completeness
// alarms outrank damaged history, which outranks reasons to look
// (tripwire events, hot sessions). Everything else on the page is
// deliberately quiet.
// How far past its own bar a session actually burned. The bar is what
// made it hot, so the multiple against the bar is the honest reading:
// a busiest hour of 713 against a bar of 153 is a different event from
// 155 against 153, and both wore the identical word until now
// (ADR-0027). One helper, so the number reads the same in all three
// places the flag appears.
function pastTheBar(session) {
  const bar = session.threshold;
  if (!bar || !session.busiest_hour) return "";
  const times = session.busiest_hour / bar;
  return (times >= 10 ? Math.round(times)
                      : Math.round(times * 10) / 10) + "× the bar";
}

const SEVERITY = ["alarm", "regenerated", "broken", "tripwire", "hot",
                  "reawakened"];

function attentionItems(report) {
  const items = [];
  for (const s of report.completeness.sessions) {
    if (["ALARM-SILENT", "ALARM-DEFICIT"].includes(s.state)) {
      items.push({rank: "alarm", tone: "grave", chip: s.state,
        text: s.repo + " · " + s.session.slice(0, 8) + " — " +
              (s.words || "receipts behind the witness"),
        repo: s.repo, session: s.session});
    }
  }
  for (const repo of report.repos) {
    for (const session of repo.sessions) {
      for (const chain of session.chains) {
        if (chain.superseded) continue;
        if (chain.exit === 3) {
          items.push({rank: "regenerated", tone: "grave",
            chip: chain.verdict,
            text: repo.repo + " · " + session.session.slice(0, 8) +
                  " — not the recorded history",
            repo: repo.repo, session: session.session});
        } else if (chain.verdict === "BROKEN") {
          items.push({rank: "broken", tone: "damage", chip: "BROKEN",
            text: repo.repo + " · " + session.session.slice(0, 8) +
                  " — history was altered after the fact",
            repo: repo.repo, session: session.session});
        }
      }
    }
  }
  for (const event of report.baseline.events) {
    items.push({rank: "tripwire", tone: "damage",
      chip: "CHANGED SINCE LAST LOOK",
      text: event.repo + " · " + event.session + " — " + event.change,
      tab: "evidence"});
  }
  for (const s of (report.consumption || {sessions: []}).sessions) {
    if (s.state === "RUNNING-HOT") {
      const past = pastTheBar(s);
      items.push({rank: "hot", tone: "look", chip: "RUNNING-HOT",
        text: s.repo + " · " + s.session.slice(0, 8) +
              " — busiest hour " + s.busiest_hour +
              (past ? ", " + past : ""), tab: "evidence"});
    }
  }
  for (const w of ((report.lifecycle || {}).events || [])) {
    items.push({rank: "reawakened", tone: "look", chip: "REAWAKENED",
      text: w.repo + " · " + w.session.slice(0, 8) + " — " + w.words,
      repo: w.repo, session: w.session});
  }
  items.sort((a, b) =>
    SEVERITY.indexOf(a.rank) - SEVERITY.indexOf(b.rank));
  return items;
}

function renderAttention(report) {
  const box = document.getElementById("attention");
  box.replaceChildren();
  const items = attentionItems(report);
  if (!items.length) {
    const kept = report.completeness.sessions.filter(s =>
      ["ENDED-DEFICIT", "ENDED-SURPLUS", "SURPLUS", "IDLE-DEFICIT"]
        .includes(s.state)).length;
    const row = el("div", "alert");
    const head = el("div", "head");
    head.appendChild(el("strong", "", "nothing wants your eyes"));
    row.appendChild(head);
    row.appendChild(el("span", "what", kept
      ? kept + " quieter finding(s) kept as evidence, folded below"
      : "the elephant is watching"));
    box.appendChild(row);
    return;
  }
  for (const item of items) {
    const row = el("div", "alert " + item.tone);
    const head = el("div", "head");
    head.appendChild(el("strong", "", item.chip));
    row.appendChild(head);
    row.appendChild(el("span", "what", item.text));
    const go = el("button", "walk", "look");
    go.type = "button";
    go.addEventListener("click", () => {
      // A named session opens under inspection; anything else opens
      // the evidence view — either way, the loud row is one click
      // from its own detail.
      const story = item.session && (shownRecall
        ? shownRecall.sessions : []).find(s =>
          s.repo === item.repo && s.session === item.session);
      if (story) { showTab("sessions"); selectSession(story); }
      else showTab(item.tab || "evidence");
      document.getElementById("worktable")
        .scrollIntoView({behavior: "smooth"});
    });
    row.appendChild(go);
    box.appendChild(row);
  }
}

// Fourteen days under the strip. The strip says what is true now; the
// band says whether now is unusual — "is this a trend or a one-off?",
// the third question a monitoring surface owes its operator, answered
// before anyone drills into anything.
//
// The gaps matter more than the colours. Our claim is detection
// latency, and latency is a function of how often the operator looks;
// a stretch of unread days is the one failure mode the chain itself
// can never report, so it is drawn here, next to the alarm.
function dayTier(row) {
  if (!row.watched) return "unwatched";
  if (row.worst === 3 || row.worst === 6) return "grave";
  if (row.worst !== 0) return "damage";
  return "quiet";
}

const DAY_WORDS = {
  quiet: "all quiet", damage: "damage or a tripwire event",
  grave: "the gravest claim this page can carry",
  unwatched: "nobody looked",
};

function renderFortnight(report) {
  const band = document.getElementById("fortnight");
  const history = report.history || [];
  band.replaceChildren();
  history.forEach((row, i) => {
    const rung = dayTier(row);
    const cell = el("div", "day " + rung +
                    (i === history.length - 1 ? " today" : ""));
    cell.appendChild(el("span", "mark", MARK[rung]));
    cell.appendChild(el("span", "num", row.day.slice(8)));
    cell.title = row.day + " — " + DAY_WORDS[rung] +
      (row.looks ? " · opened " + row.looks + " time(s)" : "");
    band.appendChild(cell);
  });

  // Only count gaps after the first day this machine was ever watched:
  // days before the recorder existed are not days anyone missed.
  const began = history.findIndex(row => row.watched);
  const missed = began < 0 ? []
    : history.slice(began, -1).filter(row => !row.watched);
  const lapse = document.getElementById("lapse");
  if (missed.length >= 3) {
    lapse.className = "warn";
    lapse.textContent = MARK.damage + " " + missed.length +
      " of the last " + (history.length - 1 - began) +
      " days went unread — detection latency is a function of how " +
      "often you look, and a run of unread days is the one failure " +
      "this page cannot alarm on";
  } else {
    lapse.className = "";
    lapse.textContent = history.filter(row => row.watched).length +
      " of the last " + history.length + " days watched" +
      (began < 0 ? " — the day book starts with this look" : "");
  }
}

// The drawers: one tile per project, built from the scan (verdicts,
// anchors) and the timeline (spans, session counts) together.
let lastStatus = null;
let lastRecall = null;

function worstTier(chains) {
  const ladder = ["regenerated", "broken", "refused", "valid",
                  "anchored", "superseded"];
  const rungs = chains.map(tier);
  for (const rung of ladder) {
    if (rungs.includes(rung)) return rung;
  }
  return "valid";
}

// The worktable's tab row: pane one shows exactly one of the four
// views; pane two stays the inspection surface throughout.
// Four tabs share the split: a list on the left, whatever you clicked
// on the right. Activity is neither — it is the store counted, with no
// detail to open — so it takes the whole worktable, which is the width
// its grid needs (ADR-0027).
function showTab(name) {
  const drawn = name === "activity";
  for (const b of document.querySelectorAll("#tabs .tab")) {
    b.classList.toggle("on", b.dataset.tab === name);
  }
  document.getElementById("split").hidden = drawn;
  document.getElementById("activity-view").hidden = !drawn;
  if (drawn) {
    renderCharts();
    return;
  }
  for (const pane of document.querySelectorAll("#pane1 > .tabpane")) {
    pane.hidden = pane.id !== "pane-" + name;
  }
}
for (const b of document.querySelectorAll("#tabs .tab")) {
  b.addEventListener("click", () => showTab(b.dataset.tab));
}

// The divider: pointer-drag or arrow keys trade width between the
// panes. Fractions live in CSS custom properties; nothing persists —
// the split is a working posture, not configuration.
const splitBox = document.getElementById("split");
function setSplit(fraction) {
  const share = Math.min(0.8, Math.max(0.2, fraction));
  splitBox.style.setProperty("--p1", share + "fr");
  splitBox.style.setProperty("--p2", (1 - share) + "fr");
}
const divider = document.getElementById("divider");
divider.addEventListener("pointerdown", down => {
  down.preventDefault();
  divider.setPointerCapture(down.pointerId);
  const move = drag => {
    const box = splitBox.getBoundingClientRect();
    setSplit((drag.clientX - box.left) / box.width);
  };
  divider.addEventListener("pointermove", move);
  divider.addEventListener("pointerup", () => {
    divider.removeEventListener("pointermove", move);
  }, {once: true});
});
divider.addEventListener("keydown", key => {
  const current = parseFloat(
    splitBox.style.getPropertyValue("--p1")) || 0.5;
  if (key.key === "ArrowLeft") setSplit(current - 0.05);
  if (key.key === "ArrowRight") setSplit(current + 0.05);
});

function openDrawer(repo) {
  document.getElementById("ask-repo").value = repo;
  loadRecall();
  showTab("sessions");
  document.getElementById("worktable")
    .scrollIntoView({behavior: "smooth"});
}

function renderTiles() {
  if (!lastStatus) return;
  const tiles = document.getElementById("tiles");
  tiles.replaceChildren();
  const spans = {};
  for (const story of (lastRecall ? lastRecall.sessions : [])) {
    const span = spans[story.repo] = spans[story.repo] ||
      {sessions: 0, ended: null};
    span.sessions += 1;
    if (story.ended && (!span.ended || story.ended > span.ended)) {
      span.ended = story.ended;
    }
  }
  for (const repo of lastStatus.repos) {
    const chains = repo.sessions.flatMap(s => s.chains);
    const rung = worstTier(chains);
    const tile = el("button", "tile tier-" + rung);
    tile.type = "button";
    tile.appendChild(el("span", "name", repo.repo));
    const row = el("span", "row");
    const face = chains.find(c => tier(c) === rung) || {};
    row.appendChild(el("span", "chip", CHIP[rung](face)));
    if (chains.some(c => c.anchored)) {
      row.appendChild(el("span", "badge", "anchored"));
    } else if (chains.some(c =>
        (c.anchors && c.anchors.pending || []).length)) {
      row.appendChild(el("span", "badge", "anchor pending"));
    }
    tile.appendChild(row);
    const span = spans[repo.repo];
    tile.appendChild(el("span", "meta",
      (span ? span.sessions : repo.sessions.length) + " session(s) · " +
      chains.length + " chain(s)" +
      (span && span.ended ? " · last activity " + since(span.ended) +
                            " ago" : "")));
    tile.appendChild(renderSpark(repo.repo));
    tile.addEventListener("click", () => openDrawer(repo.repo));
    tiles.appendChild(tile);
  }
  if (!lastStatus.repos.length) {
    tiles.appendChild(el("p", "",
      "no drawers yet — wire recording with loxodonta install-hook " +
      "and receipts will appear here."));
  }
}

// --- the chart vocabulary (Ch. 18, 9, 31) ---------------------------

let lastActivity = null;

function startOfDay(when) {
  return new Date(when.getFullYear(), when.getMonth(), when.getDate())
    .getTime();
}

// Fourteen days of one drawer, inside its own tile (Ch. 9). The last
// bar is marked because "now" is what the eye should land on, not the
// tallest bar in the window.
function renderSpark(repo) {
  const drawer = (lastActivity && lastActivity.activity[repo]) || {};
  const days = new Array(14).fill(0);
  const today = startOfDay(new Date());
  for (const [hour, n] of Object.entries(drawer)) {
    // The bucket key is UTC; the Date turns it into the reader's own
    // day, which is the only day they think in.
    const back = Math.round(
      (today - startOfDay(new Date(hour + ":00:00Z"))) / 86400000);
    if (back >= 0 && back < 14) days[13 - back] += n;
  }
  const peak = Math.max(1, ...days);
  const spark = el("div", "spark");
  days.forEach((n, i) => {
    const bar = el("i", i === 13 ? "now" : "");
    bar.style.height = Math.max(2, Math.round(100 * n / peak)) + "%";
    bar.title = n + " receipt(s)";
    spark.appendChild(bar);
  });
  spark.title = "fourteen days of receipts in this drawer";
  return spark;
}

// When receipts actually arrive, local weekday against local hour
// (Ch. 31's seasonality table). A sequential ramp in its own hue:
// counting receipts is not alerting about them.
const WEEK = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function renderClock() {
  const grid = document.getElementById("clock");
  if (!lastActivity) return;
  const counts = Array.from({length: 7}, () => new Array(24).fill(0));
  for (const drawer of Object.values(lastActivity.activity || {})) {
    for (const [hour, n] of Object.entries(drawer)) {
      const when = new Date(hour + ":00:00Z");
      counts[when.getDay()][when.getHours()] += n;
    }
  }
  const peak = Math.max(1, ...counts.flat());
  grid.replaceChildren();
  grid.appendChild(el("span", "clock-head", ""));
  for (let h = 0; h < 24; h++) {
    grid.appendChild(el("span", "clock-head", h % 3 === 0 ? String(h) : ""));
  }
  for (let d = 0; d < 7; d++) {
    grid.appendChild(el("span", "clock-day", WEEK[d]));
    for (let h = 0; h < 24; h++) {
      const n = counts[d][h];
      const cell = el("div", "cell" + (n ? " on" : ""));
      cell.style.setProperty("--heat", Math.round(14 + 86 * n / peak));
      cell.title = WEEK[d] + " " + h + ":00 - " + n + " receipt(s)";
      grid.appendChild(cell);
    }
  }
}

// The session Gantt (Ch. 18): every session of the fortnight on one
// shared axis. Spans come from recall, states from the completeness
// watch - the watch's own language, never verify's verdicts, because
// this is a reason to look and not a claim about a chain.
//
// A bar covers the session's real span. The hatched tail inside it is
// the share of that session's tool calls that never left a receipt,
// split by count and not by time, because a missing receipt has no
// duration. The label says the number out loud.
function renderGantt() {
  const host = document.getElementById("gantt");
  const axis = document.getElementById("axis");
  if (!lastStatus || !lastRecall) return;
  const watch = new Map(lastStatus.completeness.sessions.map(
    seen => [seen.repo + "/" + seen.session, seen]));
  const now = Date.now();
  const start = startOfDay(new Date(now - 13 * 86400000));
  const width = now - start;
  // Newest first, except that a reason to look outranks recency: the
  // panel scrolls inside its own box now (ADR-0027), and a hatched
  // tail or an alarm must never be the thing below the fold.
  const lanes = lastRecall.sessions
    .filter(story => story.started && story.ended)
    .map(story => {
      const seen = watch.get(story.repo + "/" + story.session);
      const state = seen ? seen.state : "";
      const flagged = state.startsWith("ALARM") ||
        state.endsWith("DEFICIT") || (seen && seen.deficit > 0);
      return {story, seen, state, flagged: flagged ? 0 : 1,
              from: Date.parse(story.started),
              to: Date.parse(story.ended)};
    })
    .filter(row => row.to >= start)
    .sort((a, b) => a.flagged - b.flagged || b.to - a.to);

  host.replaceChildren();
  if (!lanes.length) {
    host.appendChild(el("p", "testimony",
      "no sessions in the last fourteen days"));
  }
  for (const lane of lanes) {
    const story = lane.story;
    const row = el("div", "lane");
    const seen = lane.seen;
    const state = lane.state;
    const rung = state.startsWith("ALARM") ? " grave"
      : state.endsWith("DEFICIT") ? " damage" : "";
    const left = Math.max(0, (lane.from - start) / width) * 100;
    const right = Math.min(1, (lane.to - start) / width) * 100;
    const bar = el("button", "bar" + rung);
    bar.type = "button";
    bar.style.left = left + "%";
    bar.style.width = Math.max(right - left, 0.4) + "%";
    const owed = seen && seen.deficit > 0 ? seen.deficit : 0;
    const near = left + Math.max(right - left, 0.4) > 62;
    const label = el("span", "bar-label" + (near ? " before" : ""),
      story.repo + " \u00b7 " + story.entries + " receipt(s)" +
      (owed ? " \u00b7 " + owed + " owed" : ""));
    label.style.left = (near ? left : Math.min(right, 100)) + "%";
    if (owed && seen.tools) {
      const tail = el("div", "owed");
      tail.style.right = "0";
      tail.style.width =
        Math.min(100, Math.max(12, 100 * owed / seen.tools)) + "%";
      bar.appendChild(tail);
    }
    bar.title = story.repo + " " + story.session
      + "\\n" + story.started + " to " + story.ended
      + "\\n" + story.entries + " receipt(s)"
      + (state ? " - watch says " + state : "");
    bar.addEventListener("click", () => openWalker(story.paths[0]));
    row.appendChild(bar);
    row.appendChild(label);
    host.appendChild(row);
  }

  axis.replaceChildren();
  for (let back = 13; back >= 0; back -= 2) {
    const day = new Date(start + (13 - back) * 86400000);
    axis.appendChild(el("span", "", String(day.getDate())));
  }
}

function render(report) {
  lastStatus = report;
  renderStrip(report);
  renderAttention(report);
  renderFortnight(report);
  if (!document.getElementById("activity-view").hidden) renderCharts();
  renderTiles();
  renderGantt();

  const tripwire = document.getElementById("tripwire");
  tripwire.replaceChildren();
  for (const event of report.baseline.events) {
    const row = el("div", "trip");
    row.appendChild(el("span", "chip",
                       "CHANGED SINCE LAST LOOK · " + event.change));
    row.appendChild(el("span", "file",
                       event.repo + " · " + event.session +
                       " · " + event.log));
    row.appendChild(el("p", "claim", event.investigate));
    tripwire.appendChild(row);
  }
  if (report.baseline.note) {
    tripwire.appendChild(el("p", "claim", report.baseline.note));
  }

  // The completeness watch: only sessions worth a second look get a
  // row — the alarm layer must never bury its own signal in OK rows.
  const watch = document.getElementById("watch");
  watch.replaceChildren();
  const LIVE = ["ALARM-SILENT", "ALARM-DEFICIT"];
  const NOTEWORTHY = LIVE.concat(["ENDED-DEFICIT", "ENDED-SURPLUS",
                                  "SURPLUS", "LAGGING", "IDLE-DEFICIT"]);
  const watchRow = s => {
    const live = LIVE.includes(s.state);
    const row = el("div", "watch-row " + (live ? "live" : "quiet"));
    row.appendChild(el("span", "chip", s.state));
    row.appendChild(el("span", "file", s.repo + " · " + s.session +
      " · witnessed " + s.tools + ", received " + s.receipts));
    if (s.words) row.appendChild(el("p", "claim", s.words));
    // A session whose receipts landed in more than one drawer is
    // counted once, against the whole family — say so, so the tally
    // never looks larger than the drawer it is filed under.
    if (s.drawers) row.appendChild(el("p", "claim",
      "receipts span " + s.drawers.length + " drawers (" +
      s.drawers.join(", ") + "), counted together as one session"));
    return row;
  };
  // Live alarms are the signal; ended deficits are evidence, and a
  // machine's worth of history must never bury the one live row —
  // the quiet ones fold away, present but not shouting.
  const noteworthy = report.completeness.sessions.filter(
    s => NOTEWORTHY.includes(s.state));
  for (const s of noteworthy.filter(s => LIVE.includes(s.state))) {
    watch.appendChild(watchRow(s));
  }
  const quiet = noteworthy.filter(s => !LIVE.includes(s.state));
  if (quiet.length) {
    const fold = el("details");
    fold.appendChild(el("summary", "", quiet.length +
      " quieter finding(s) — deficits ended and flags, kept as evidence"));
    for (const s of quiet) fold.appendChild(watchRow(s));
    watch.appendChild(fold);
  }
  if (report.completeness.note) {
    watch.appendChild(el("p", "claim", report.completeness.note));
  }
  // A matcher change is context the deficits above need: sessions are
  // judged by the coverage in force at their time (ADR-0016).
  if (report.completeness.calibration) {
    watch.appendChild(el("p", "claim",
      report.completeness.calibration.words));
  }

  // The consumption watch (issue #67, OWASP LLM06 #8): sessions
  // burning far above the store's own norm — evidence for the
  // operator's circuit breaker, never a breaker. Nothing here raises
  // the exit or colours the strip; a quiet store draws nothing.
  const burn = document.getElementById("consumption");
  burn.replaceChildren();
  const consumption = report.consumption || {sessions: []};
  const hotRow = s => {
    const row = el("div", "watch-row " +
                   (s.state === "RUNNING-HOT" ? "hot" : "quiet"));
    row.appendChild(el("span", "chip", s.state));
    row.appendChild(el("span", "file", s.repo + " · " + s.session +
      " · busiest hour " + s.busiest_hour + " entries against a bar of " +
      s.threshold + " — " + pastTheBar(s) + ". " +
      s.top_tool + " ran " + s.top_tool_count + " of them"));
    if (s.words) row.appendChild(el("p", "claim", s.words));
    return row;
  };
  for (const s of consumption.sessions.filter(
      s => s.state === "RUNNING-HOT")) {
    burn.appendChild(hotRow(s));
  }
  const cooled = consumption.sessions.filter(
    s => s.state !== "RUNNING-HOT");
  if (cooled.length) {
    const fold = el("details");
    fold.appendChild(el("summary", "", cooled.length +
      " session(s) that ran hot and ended — kept as evidence"));
    for (const s of cooled) fold.appendChild(hotRow(s));
    burn.appendChild(fold);
  }
  if (consumption.sessions.length && consumption.norm) {
    burn.appendChild(el("p", "claim", consumption.norm.words));
  }

  // The lifecycle events (ADR-0018): a dormant chain grew again — the
  // investigate voice, beside the other reasons to look.
  const woke = document.getElementById("lifecycle");
  woke.replaceChildren();
  for (const w of ((report.lifecycle || {}).events || [])) {
    const row = el("div", "watch-row hot");
    row.appendChild(el("span", "chip", "REAWAKENED"));
    row.appendChild(el("span", "file", w.repo + " · " + w.session));
    row.appendChild(el("p", "claim", w.words));
    woke.appendChild(row);
  }

  renderAnchors(report);

  const ask = document.getElementById("ask-repo");
  const known = new Set(Array.from(ask.options, o => o.value));
  for (const repo of report.repos) {
    if (!known.has(repo.repo)) {
      const option = document.createElement("option");
      option.value = option.textContent = repo.repo;
      ask.appendChild(option);
    }
  }
}

// --- the fire drill -------------------------------------------------

async function runDrill(logPath) {
  const section = document.getElementById("firedrill");
  const banner = document.getElementById("drill-banner");
  const results = document.getElementById("drill-results");
  section.hidden = false;
  banner.className = "";
  banner.textContent = "drilling a sandbox copy of " + logPath + "…";
  results.replaceChildren();
  section.scrollIntoView({behavior: "smooth"});
  let report;
  try {
    const response = await fetch(
      "/api/drill?log=" + encodeURIComponent(logPath),
      {method: "POST"});
    if (!response.ok) throw new Error("HTTP " + response.status);
    report = await response.json();
  } catch (error) {
    banner.className = "shouting";
    banner.textContent = "the drill could not run: " + error;
    return;
  }
  if (report.refused) {
    banner.className = "shouting";
    banner.textContent = "refused: " + report.refused;
    return;
  }
  if (report.all_fired) {
    banner.className = "quiet";
    banner.textContent = "every alarm fired — rehearsal passed. Now the "
      + "manual half: walk the edit copy and watch your browser catch it.";
  } else {
    banner.className = "shouting";
    banner.textContent = "AN ALARM DID NOT FIRE — detection is broken; "
      + "do not trust the band until you know why.";
  }
  for (const d of report.drills) {
    const row = el("div", "drill-row");
    row.appendChild(el("strong", "", d.tamper));
    row.appendChild(el("span", "", "expected " + d.expected +
                       " · saw " + d.verdict));
    row.appendChild(el("span", d.fired ? "fired" : "misfired",
                       d.fired ? "alarm fired" : "ALARM DID NOT FIRE"));
    const walk = el("button", "walk", "walk this copy");
    walk.type = "button";
    walk.addEventListener("click", () => openWalker(d.copy));
    row.appendChild(walk);
    results.appendChild(row);
  }
}

// --- the walker: recomputed in your browser -------------------------

// SPEC §4 in JavaScript: keys sorted at every depth, compact
// separators, entry_hash stripped, UTF-8 — the exact bytes the CLI
// hashes, rebuilt independently here.
function canonicalJSON(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJSON).join(",") + "]";
  }
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(key =>
      JSON.stringify(key) + ":" + canonicalJSON(value[key])
    ).join(",") + "}";
  }
  return JSON.stringify(value);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest),
    b => b.toString(16).padStart(2, "0")).join("");
}

async function recheck(entry, badge) {
  const hashed = {};
  for (const key of Object.keys(entry)) {
    if (key !== "entry_hash") hashed[key] = entry[key];
  }
  try {
    const recomputed = await sha256Hex(canonicalJSON(hashed));
    const agrees = recomputed === entry.entry_hash;
    badge.textContent = "recomputed in your browser: " +
      (agrees ? "matches" : "does NOT match the stored entry_hash");
    badge.className = "recheck " + (agrees ? "match" : "mismatch");
  } catch (error) {
    badge.textContent = "recomputation unavailable: " + error;
  }
}

function walkEntry(entry, prevHash) {
  const row = el("div", "walk-entry");
  const head = el("div");
  head.appendChild(el("strong", "", "#" + entry.n + " "));
  head.appendChild(el("span", "who",
    (entry.ts || "no ts") + " · " + entry.actor + " "));
  const badge = el("span", "recheck", "recomputing…");
  head.appendChild(badge);
  row.appendChild(head);
  row.appendChild(el("p", "said", entry.action));
  for (const ref of entry.files || []) {
    row.appendChild(el("div", "hashes",
      "file " + ref.path + " · " + String(ref.sha256).slice(0, 12)));
  }
  row.appendChild(el("div", "hashes",
    "prev " + String(entry.prev).slice(0, 12) + " → entry_hash " +
    String(entry.entry_hash).slice(0, 12)));
  if (entry.prev !== prevHash) {
    row.appendChild(el("div", "broken-link",
      "chain link does not match the previous entry — damage sits here"));
  }
  recheck(entry, badge);
  return row;
}

async function openWalker(logPath) {
  const section = document.getElementById("walker");
  const entries = document.getElementById("entries");
  section.hidden = false;
  entries.replaceChildren();
  document.getElementById("walking").textContent = "walking " + logPath;
  let report;
  try {
    const response =
      await fetch("/api/chain?log=" + encodeURIComponent(logPath));
    if (!response.ok) throw new Error("HTTP " + response.status);
    report = await response.json();
  } catch (error) {
    entries.textContent = "the walker could not read this chain: " + error;
    return;
  }
  let prevHash = null;
  for (const line of report.lines) {
    if (line.damage !== undefined) {
      entries.appendChild(el("div", "walk-damage",
        "unreadable line — damage sits here: " + line.damage));
      prevHash = null;
      continue;
    }
    entries.appendChild(walkEntry(line.entry, prevHash));
    prevHash = line.entry.entry_hash;
  }
  section.scrollIntoView({behavior: "smooth"});
}

// --- the anchor panel -----------------------------------------------

// Ages are computed here, from the report's timestamps — the report
// itself carries no clock.
function since(ts) {
  const seconds = (Date.now() - Date.parse(ts)) / 1000;
  if (!isFinite(seconds)) return "";
  if (seconds < 5400) return Math.max(0, Math.round(seconds / 60)) + "m";
  if (seconds < 129600) return Math.round(seconds / 3600) + "h";
  return Math.round(seconds / 86400) + "d";
}

const PENDING_STALE = 24 * 3600 * 1000;
const BARE_STALE = 7 * 24 * 3600 * 1000;

function renderAnchors(report) {
  const panel = document.getElementById("panel");
  panel.replaceChildren();
  for (const repo of report.repos) {
    for (const session of repo.sessions) {
      for (const chain of session.chains) {
        const a = chain.anchors;
        if (!a) continue;
        const row = el("div", "berth");
        row.appendChild(el("span", "file",
          repo.repo + " · " + session.session + " · " +
          chain.log.split("/").pop()));
        for (const span of a.anchored) {
          row.appendChild(el("span", "height", "block " + span.height));
          row.appendChild(el("span", "bare",
                             "covers entries 0.." + span.upto));
        }
        for (const proof of a.pending) {
          const old = Date.now() - Date.parse(proof.submitted)
                      > PENDING_STALE;
          row.appendChild(el("span",
            "pending-proof" + (old ? " stale" : ""),
            "pending " + since(proof.submitted) + " via " +
            proof.calendar));
        }
        if (a.head && !a.head.anchored) {
          const old = a.head.ts &&
            Date.now() - Date.parse(a.head.ts) > BARE_STALE;
          row.appendChild(el("span", "bare" + (old ? " stale" : ""),
            "head (entry " + a.head.n + ") unanchored" +
            (a.head.ts ? " for " + since(a.head.ts) : "")));
        }
        // When a head last left the machine, published or anchored
        // (ADR-0025): the same staleness voice as the unanchored head,
        // never an alarm. A fresh reading proves nothing (both files
        // are writer-reachable); a stale one is the reason to look.
        const left = chain.left;
        if (left) {
          if (left.ts) {
            const old = Date.now() - Date.parse(left.ts) > BARE_STALE;
            row.appendChild(el("span", "bare" + (old ? " stale" : ""),
              "a head last left " + since(left.ts) + " ago (" +
              left.via + ")"));
          } else {
            row.appendChild(el("span", "bare",
                               "no head has left this machine"));
          }
          if (left.note) {
            row.appendChild(el("p", "claim" + (left.failed ? " shout" : ""),
                               left.note));
          }
        }
        if (a.note) {
          row.appendChild(el("p", "claim" + (a.failed ? " shout" : ""),
                             a.note));
        }
        panel.appendChild(row);
      }
    }
  }
  if (!panel.children.length) {
    panel.appendChild(el("p", "", "no chains to keep anchors for yet."));
  }
}

// --- recall: the memory surface -------------------------------------

function spanText(story) {
  if (!story.started) return "no timestamps to place";
  const trim = ts => ts.slice(0, 16).replace("T", " ");
  return trim(story.started) + " → " + trim(story.ended) + " UTC";
}

// --- the worktable: sessions in pane one, inspection in pane two ----

let shownRecall = null;
let selectedWhere = null;

function sessionRow(story) {
  const row = document.createElement("tr");
  row.dataset.where = story.repo + "/" + story.session;
  if (row.dataset.where === selectedWhere) row.className = "sel";
  const addr = el("td", "addr", story.session.slice(0, 8));
  addr.title = story.session;
  // Dormancy is scaffolding, shown dimly (ADR-0018): the state never
  // shouts — only the reawakening does.
  const seen = lastStatus && lastStatus.completeness.sessions.find(
    s => s.repo === story.repo && s.session === story.session);
  if (seen && seen.dormancy && seen.dormancy.tier === "dormant") {
    row.classList.add("dormant");
    addr.title += " · dormant — no observed movement for " +
      Math.round(seen.dormancy.still_seconds / 86400) + "d";
  }
  row.appendChild(el("td", "", story.repo));
  row.appendChild(el("td", "num", String(story.entries)));
  row.appendChild(el("td", "when", spanText(story)));
  row.addEventListener("click", () => selectSession(story));
  return row;
}

function renderRecall(report) {
  shownRecall = report;
  const body = document.getElementById("sessions-body");
  body.replaceChildren();
  for (const story of report.sessions) {
    body.appendChild(sessionRow(story));
  }
  if (!report.sessions.length) {
    const row = document.createElement("tr");
    const cell = el("td", "pane-empty", "nothing remembered here — " +
      "no session matches these filters.");
    cell.colSpan = 4;
    row.appendChild(cell);
    body.appendChild(row);
  }
}

// Pane two: the selected session's chains, claims, and actions — the
// chain rows are the same tier ladder the whole page speaks, and the
// walk buttons still open the WebCrypto walker.
// The density strip: one session's receipts across its own span, gaps
// and all (ADR-0027). The axis is the session as it happened, so a
// week of dormancy draws as a week of empty — which is the finding,
// not a rendering problem. Bucket width comes off a ladder because
// sessions here run from eighteen seconds to a week, and the caption
// names the rung: a bar chart whose scale you have to guess is worse
// than none. The owed tail is the completeness watch's, which the page
// already holds — the strip itself owns no verdicts.
function shapeWords(seconds) {
  if (seconds < 60) return seconds + "s";
  if (seconds < 3600) return Math.round(seconds / 60) + " min";
  if (seconds < 86400) return Math.round(seconds / 3600) + "h";
  return Math.round(seconds / 86400) + "d";
}

async function renderShape(story) {
  const host = document.getElementById("inspect-shape");
  const where = story.repo + "/" + story.session;
  host.hidden = true;
  host.replaceChildren();
  let shape;
  try {
    const response = await fetch("/api/shape?repo=" +
      encodeURIComponent(story.repo) + "&session=" +
      encodeURIComponent(story.session));
    if (!response.ok) return;
    shape = await response.json();
  } catch (error) {
    return;
  }
  // A second click can land while the first fetch is still in flight;
  // the answer to a question nobody is asking any more is dropped.
  if (where !== selectedWhere) return;

  const strip = el("div", "shape");
  const top = Math.max(...shape.buckets, 1);
  shape.buckets.forEach((count, i) => {
    const bar = el("div", count
      ? (i === shape.peak.index ? "peak" : "") : "gap");
    if (count) {
      bar.style.height =
        Math.max(2, Math.round(count / top * 34)) + "px";
    }
    bar.title = count + " receipt(s)";
    strip.appendChild(bar);
  });
  const watch = lastStatus && lastStatus.completeness.sessions.find(
    s => s.repo === story.repo && s.session === story.session);
  const owed = watch && watch.deficit > 0 ? watch.deficit : 0;
  if (owed) {
    const tail = el("div", "owed");
    tail.title = owed + " receipt(s) owed and never written";
    strip.appendChild(tail);
  }
  host.appendChild(strip);
  host.appendChild(el("p", "testimony",
    "one bar = " + shapeWords(shape.bucket_seconds) + " · " +
    shape.buckets.length + " bars · busiest " + shape.peak.count +
    (owed ? " · hatched: " + owed + " owed, never written" : "") +
    " — testimony, not a verdict"));
  host.hidden = false;
}

function selectSession(story) {
  selectedWhere = story.repo + "/" + story.session;
  for (const row of document.querySelectorAll("#sessions-body tr")) {
    row.classList.toggle("sel", row.dataset.where === selectedWhere);
  }
  const meta = document.getElementById("inspect-meta");
  meta.className = "";
  meta.replaceChildren();
  meta.appendChild(el("strong", "", story.repo + " · " +
                      story.session.slice(0, 8)));
  meta.appendChild(el("span", "", " — " + story.entries +
    " receipt(s) · " + spanText(story) +
    (story.worktree ? " · stranded in a worktree" : "")));
  if (story.chains.length > 1) {
    meta.appendChild(el("p", "sibling", story.chains.length +
      " chains — recording continued in a sibling"));
  }
  renderShape(story);
  // The last rung of the ladder: the walker, hashes rechecked in the
  // reader's own browser.
  for (const path of story.paths || []) {
    const walk = el("button", "walk",
      story.paths.length > 1 ? "walk " + path.split("/").pop()
                             : "walk this session");
    walk.type = "button";
    walk.style.marginLeft = "0.5rem";
    walk.addEventListener("click", () => openWalker(path));
    meta.appendChild(walk);
  }
  // The chains as verify saw them, worst first — reusing the page's
  // one tier vocabulary.
  const chainsBox = document.getElementById("inspect-chains");
  chainsBox.replaceChildren();
  const scan = findScanSession(story);
  for (const chain of scan ? scan.chains : []) {
    chainsBox.appendChild(chainRow(chain));
  }
  if (!scan) {
    chainsBox.appendChild(el("p", "pane-empty",
      "the scan has not judged this session yet — refresh in a tick"));
  }
  // The ADR-0017 judge command, where the watch paired a transcript:
  // the supervisor locates, verify judges — copy it, run it, read the
  // verdict in your own terminal.
  const judgeBox = document.getElementById("inspect-judge");
  const seen = (lastStatus ? lastStatus.completeness.sessions : [])
    .find(s => s.repo === story.repo && s.session === story.session);
  if (seen && seen.judge) {
    judgeBox.hidden = false;
    judgeBox.replaceChildren();
    judgeBox.appendChild(el("strong", "", "judge transcript "));
    judgeBox.appendChild(el("span", "", "— commitments re-hashed " +
      "against the harness transcript (run it yourself): "));
    judgeBox.appendChild(el("code", "", seen.judge));
    const copy = el("button", "walk", "copy");
    copy.type = "button";
    copy.style.marginLeft = "0.5rem";
    copy.addEventListener("click", () =>
      navigator.clipboard.writeText(seen.judge));
    judgeBox.appendChild(copy);
  } else {
    judgeBox.hidden = true;
  }
}

// The charts speak the house rules — one hue per chart, values
// reachable as text, red only for status and never alone (a HOT word
// rides it).

const SVGNS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs) {
  const node = document.createElementNS(SVGNS, tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    node.setAttribute(key, value);
  }
  return node;
}

// Thin horizontal bars, rounded data ends, direct value labels, ink
// for text and one hue for marks; an optional dashed norm line.
// `left` widens the label gutter for charts whose labels are long by
// nature — a file path is not a tool name — and trades bar length for
// it. Everything else keeps the default.
function hbars(host, items, unit, norm, left) {
  host.replaceChildren();
  if (!items.length) return;
  const peak = Math.max(norm || 0, ...items.map(i => i.v), 1);
  const W = 420, LEFT = left || 100, BARS = W - LEFT - 58, ROW = 24;
  const svg = svgEl("svg",
    {viewBox: "0 0 " + W + " " + (items.length * ROW + 6),
     role: "img", style: "width:100%;height:auto"});
  items.forEach((item, i) => {
    const y = i * ROW;
    const w = Math.max(3, Math.round(item.v / peak * BARS));
    const label = svgEl("text", {x: LEFT - 8, y: y + 14,
      "text-anchor": "end", "class": "clab"});
    label.textContent = item.label;
    svg.appendChild(label);
    const bar = svgEl("rect", {x: LEFT, y: y + 4, width: w, height: 13,
      rx: 4, "class": "cbar" + (item.hot ? " hot" : "")});
    const tip = svgEl("title", {});
    tip.textContent = (item.full || item.label) + ": " + item.v + " " +
      unit;
    bar.appendChild(tip);
    svg.appendChild(bar);
    const value = svgEl("text", {x: LEFT + w + 7, y: y + 15,
      "class": "cval"});
    value.textContent = item.v + (item.hot ? " · HOT" : "");
    svg.appendChild(value);
  });
  if (norm) {
    const x = LEFT + Math.round(norm / peak * BARS);
    svg.appendChild(svgEl("line", {x1: x, x2: x, y1: 0,
      y2: items.length * ROW, "class": "cnorm"}));
    const cap = svgEl("text", {x: x + 5, y: 10, "class": "clab"});
    cap.textContent = "norm " + norm;
    svg.appendChild(cap);
  }
  host.appendChild(svg);
}

// The tally: the store's own scale, which nothing else on this page
// says out loud. Counts only — never how many chains are broken or how
// many sessions ran hot. Those are the rail's sentences, and two
// surfaces that can disagree about what is alarming is the one thing
// ADR-0013 says a cockpit must never be. Derived from payloads the
// page already holds, so it costs no endpoint and no second walk.
function renderTally() {
  if (!lastStatus || !lastRecall) return;
  const host = document.getElementById("tally");
  let receipts = 0;
  let since = null;
  for (const story of lastRecall.sessions) {
    receipts += story.entries;
    if (story.started && (!since || story.started < since)) {
      since = story.started;
    }
  }
  let chains = 0;
  for (const repo of lastStatus.repos) {
    for (const seen of repo.sessions) chains += seen.chains.length;
  }
  host.replaceChildren();
  const counts = [["drawers", lastStatus.repos.length],
                  ["sessions", lastRecall.sessions.length],
                  ["chains", chains],
                  ["receipts", receipts]];
  for (const [what, value] of counts) {
    const cell = el("div", "count");
    cell.appendChild(el("span", "num", value.toLocaleString()));
    cell.appendChild(el("span", "what", what));
    host.appendChild(cell);
  }
  const first = el("div", "count");
  first.appendChild(el("span", "num", since ? since.slice(0, 10) : "—"));
  first.appendChild(el("span", "what", "recording since"));
  host.appendChild(first);
}

// The histogram: what the writer reached for, counted. Admitted as a
// recording-health panel (ADR-0027) — on a settled machine its shape
// barely moves, and the shape *moving* is what a switched harness or a
// broken adapter looks like from here. Read it for movement, not for
// news. Only the top few get bars: the tail is long, the panel is not,
// and a bar per name would say less than the count of what is missing.
function renderHistogram() {
  const host = document.getElementById("chart-tools");
  const tail = document.getElementById("tools-tail");
  const ranked = Object.entries((lastActivity && lastActivity.tools) || {})
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  tail.textContent = "";
  if (!ranked.length) {
    host.replaceChildren();
    host.appendChild(el("p", "testimony",
      "nothing recorded in the window"));
    return;
  }
  // hbars anchors a label at its right edge, so an over-long name is
  // clipped from the left and loses the part that identifies it. Trim
  // from the right instead, and hand hbars the whole name for the
  // tooltip: an MCP server can be called anything.
  const fit = name =>
    name.length > 15 ? name.slice(0, 14) + "…" : name;
  const TOP = 6;
  hbars(host, ranked.slice(0, TOP).map(
    ([name, count]) => ({label: fit(name), full: name, v: count})),
    "receipt(s)");
  const rest = ranked.slice(TOP);
  if (rest.length) {
    tail.textContent = "and " + rest.length + " more, " +
      rest.reduce((sum, row) => sum + row[1], 0) +
      " receipt(s) between them";
  }
}

// Files touched: which files the work actually kept returning to.
// Ranked per drawer, because two projects both holding a README hold
// two different files. Labels trim from the *left*, the opposite of
// the histogram's: a path is identified by its tail.
function renderFiles() {
  const host = document.getElementById("chart-files");
  const tail = document.getElementById("files-tail");
  const ranked = (lastActivity && lastActivity.files) || [];
  tail.textContent = "";
  if (!ranked.length) {
    host.replaceChildren();
    host.appendChild(el("p", "testimony",
      "no files fingerprinted in the window"));
    return;
  }
  const fit = path =>
    path.length > 23 ? "…" + path.slice(-22) : path;
  const TOP = 6;
  hbars(host, ranked.slice(0, TOP).map(row => ({
    label: fit(row.path), full: row.repo + " · " + row.path,
    v: row.receipts})), "receipt(s)", 0, 150);
  const rest = ranked.slice(TOP);
  if (rest.length) {
    tail.textContent = "and " + rest.length + " more, " +
      rest.reduce((sum, row) => sum + row.receipts, 0) +
      " receipt(s) between them";
  }
}

function renderCharts() {
  renderTally();
  renderHistogram();
  renderFiles();
  // No receipts-per-session bar here: the sessions table already
  // carries that column, in the same order, and a bar with no norm
  // beside it only redraws what is already on screen (ADR-0027).
  const tempoHost = document.getElementById("chart-tempo");
  const consumption = (lastStatus && lastStatus.consumption) ||
    {sessions: [], norm: null};
  if (consumption.sessions.length) {
    // No multiple on this chart: the value column has 58 units and the
    // words would clip. It grades already — bar length against the
    // norm line is the distance, drawn (ADR-0027).
    hbars(tempoHost, consumption.sessions.map(s => ({
      label: s.session.slice(0, 8), v: s.busiest_hour, hot: true})),
      "calls in the busiest hour",
      consumption.norm ? consumption.norm.median_busiest_hour : 0);
  } else {
    tempoHost.replaceChildren();
    tempoHost.appendChild(el("p", "testimony", consumption.norm
      ? "no session ran hot — the norm holds at " +
        consumption.norm.median_busiest_hour + " calls in a busiest " +
        "hour (" + consumption.norm.sessions_counted + " sessions " +
        "counted). Testimony, never a verdict."
      : "no tempo to draw yet"));
  }

  const days = ((lastStatus && lastStatus.history) || []).map(row => ({
    label: row.day.slice(5), v: row.looks || 0,
    hot: row.watched && (row.alarms || 0) > 0}));
  hbars(document.getElementById("chart-looks"), days, "look(s)");
}

function findScanSession(story) {
  if (!lastStatus) return null;
  const repo = lastStatus.repos.find(r => r.repo === story.repo);
  return repo ? repo.sessions.find(s => s.session === story.session)
              : null;
}

function asked() {
  const query = new URLSearchParams();
  const value = id => document.getElementById(id).value.trim();
  if (value("ask-repo")) query.set("repo", value("ask-repo"));
  if (value("ask-from")) query.set("from", value("ask-from"));
  if (value("ask-to")) query.set("to", value("ask-to"));
  if (value("ask-path")) query.set("path", value("ask-path"));
  const text = query.toString();
  return text ? "?" + text : "";
}

async function loadRecall() {
  try {
    const response = await fetch("/api/recall" + asked());
    const report = await response.json();
    // The tiles want the unfiltered picture; only a filter-free answer
    // updates their memory of it.
    if (!asked()) lastRecall = report;
    renderRecall(report);
    renderTiles();
    renderGantt();
    renderTally();
  } catch (error) {
    document.getElementById("inspect-meta").textContent =
      "recall did not answer: " + error;
  }
}

// --- search: the writer's word, findable ----------------------------

// A hit links into the worktable: focus the session's repo, then
// select its row once the sessions pane has re-answered.
async function visit(hit) {
  document.getElementById("ask-repo").value = hit.repo;
  await loadRecall();
  const where = hit.repo + "/" + hit.session;
  const story = (shownRecall ? shownRecall.sessions : [])
    .find(s => s.repo + "/" + s.session === where);
  if (story) { showTab("sessions"); selectSession(story); }
  for (const row of document.querySelectorAll("#sessions-body tr")) {
    if (row.dataset.where === where) {
      row.scrollIntoView({behavior: "smooth", block: "center"});
    }
  }
}

function hitRow(hit) {
  const row = el("button", "hit");
  row.type = "button";
  row.appendChild(el("span", "where", hit.repo + " · " + hit.session));
  row.appendChild(el("span", "entry",
    "entry " + hit.n + (hit.ts ? " · " + hit.ts : "")));
  row.appendChild(el("p", "said", hit.action));
  row.addEventListener("click", () => visit(hit));
  return row;
}

async function runSearch() {
  const found = document.getElementById("found");
  const query = document.getElementById("ask-search").value.trim();
  if (!query) {
    found.replaceChildren();
    return;
  }
  try {
    const response =
      await fetch("/api/search?q=" + encodeURIComponent(query));
    const report = await response.json();
    found.replaceChildren();
    found.appendChild(el("p", "tally", report.matched
      ? "found in " + report.matched + " action line(s)" +
        (report.matched > report.hits.length
          ? " — showing the newest " + report.hits.length : "")
      : "nothing written matches — the writer never said it"));
    for (const hit of report.hits) {
      found.appendChild(hitRow(hit));
    }
  } catch (error) {
    found.textContent = "search did not answer: " + error;
  }
}

let searchPause;
document.getElementById("ask-search").addEventListener("input", () => {
  clearTimeout(searchPause);
  searchPause = setTimeout(runSearch, 300);
});

async function loadActivity() {
  try {
    const response = await fetch("/api/activity");
    lastActivity = await response.json();
    renderClock();
    renderTiles();
    renderHistogram();
    renderFiles();
  } catch (error) {
    document.getElementById("clock").textContent =
      "activity did not answer: " + error;
  }
}

async function loadStatus() {
  try {
    const response = await fetch("/api/status");
    render(await response.json());
  } catch (error) {
    const strip = document.getElementById("strip");
    strip.className = "grave";
    document.getElementById("statemark").textContent = MARK.grave;
    document.getElementById("stateline").textContent =
      "the scan did not answer";
    document.getElementById("statewhy").textContent = String(error);
    document.getElementById("elephant").hidden = true;
  }
}

for (const id of ["ask-repo", "ask-from", "ask-to"]) {
  document.getElementById(id).addEventListener("change", loadRecall);
}
let pathPause;
document.getElementById("ask-path").addEventListener("input", () => {
  clearTimeout(pathPause);
  pathPause = setTimeout(loadRecall, 300);
});

loadRecall();
loadStatus();
loadActivity();
setInterval(loadRecall, 30000);
setInterval(loadStatus, 30000);
setInterval(loadActivity, 30000);
</script>
</body>
</html>
"""


class VersionAction(argparse.Action):
    """`--version`: tool, format, and the commit of the checkout this
    file sits in — the recorder notice's fact, read the recorder notice's
    way (local git only, never fetched: ADR-0015, ADR-0022). Answered
    only when asked, so no other command pays for the git question."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        commit = git_say(HERE, "rev-parse", "--short", "HEAD") or "unknown"
        print(f"{parser.prog} {TOOL_VERSION} (format {FORMAT_VERSION}, "
              f"commit {commit})")
        parser.exit()


EX_USAGE = 64  # sysexits(3) EX_USAGE: the command was spoken wrong


class UsageParser(argparse.ArgumentParser):
    """argparse, with usage errors on an exit of their own, the recorder's
    class twice over. A wrong flag, a missing argument, or a malformed
    value exits 64 instead of argparse's stock 2, so scan's 5, 6, 7 and
    verify's 0..5 are never an argparse error (ADR-0026 ruling 7). The
    message is argparse's, unchanged, on stderr. Subparsers inherit this
    class, so every command speaks the same number."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, f"{self.prog}: error: {message}\n")


def main(argv):
    parser = UsageParser(prog="supervisor",
                         description=__doc__.splitlines()[0])
    parser.add_argument("--version", action=VersionAction,
                        help="print tool version, format version, and "
                             "the checkout's commit, then exit")
    sub = parser.add_subparsers(dest="command", required=True)
    # Parents only donate arguments; the parser that errors is the
    # subparser's, and add_subparsers gives every subparser `parser`'s
    # class, so the helpers below stay plain.
    watching = argparse.ArgumentParser(add_help=False)
    watching.add_argument("--witness", default=str(WITNESS_ROOT),
                          help="the harness transcript layout (the "
                               "liveness witness for completeness)")
    watching.add_argument("--anchor-every", type=parse_cadence,
                          default=None, metavar="AGE",
                          help="opt in: anchor a fresh head once it is "
                               "this old (e.g. 6h, 1d). Off by default — "
                               "nothing leaves the machine without it")
    watching.add_argument("--calendar", action="append", default=None,
                          metavar="URL",
                          help="calendar for auto-anchoring (repeatable; "
                               "default: receipts' public pools)")
    watching.add_argument("--publish-every", type=parse_cadence,
                          default=None, metavar="AGE",
                          help="opt in: publish a head once it is this old "
                               "and has not left yet (e.g. 6h, 1d), to "
                               "--publish-url, through `loxodonta publish` "
                               "(ADR-0025). Off by default — nothing leaves "
                               "the machine without it")
    watching.add_argument("--publish-url", type=publish_url, default=None,
                          metavar="URL",
                          help="where --publish-every posts: a plain http "
                               "or https URL the credentials on this "
                               "machine cannot delete from, such as a chat "
                               "incoming webhook")
    scan = sub.add_parser(
        "scan", parents=[watching],
        help="one tick: census + verdicts, JSON out, exit code")
    scan.add_argument("--root", default=None,
                      help="legacy/explicit mode: scan this folder of "
                           "repos instead of the store (default: the "
                           "store, ADR-0011)")
    scan.add_argument("--json", action="store_true",
                      help="compact machine output (default pretty-prints)")
    scan.set_defaults(func=cmd_scan)
    serve = sub.add_parser(
        "serve", parents=[watching],
        help="the face: status band on a localhost-only server")
    serve.add_argument("--root", default=None,
                       help="legacy/explicit mode: serve this folder of "
                            "repos instead of the store (default: the "
                            "store, ADR-0011)")
    serve.add_argument("--port", type=int, default=7717,
                       help="localhost port (0 picks a free one; "
                            "default 7717)")
    serve.set_defaults(func=cmd_serve)
    adopt = sub.add_parser(
        "adopt", help="one-time move of legacy chains into the store "
                      "(ADR-0011): sidecars and .unlisted travel, "
                      "nothing is ever overwritten")
    adopt.add_argument("--root", required=True,
                       help="the legacy folder of repos to adopt from")
    adopt.add_argument("--dry-run", action="store_true",
                       help="print the plan, move nothing")
    adopt.set_defaults(func=cmd_adopt)
    drill = sub.add_parser(
        "drill", help="rehearse detection: four-way tamper battery on a "
                      "sandbox copy — real chains untouched")
    drill.add_argument("--root", required=True,
                       help="the folder your repos live in")
    drill.add_argument("--log", required=True,
                       help="the chain to copy and drill")
    drill.add_argument("--json", action="store_true",
                       help="compact machine output (default "
                            "pretty-prints)")
    drill.set_defaults(func=cmd_drill)

    # The recall surface (Stage E, ADR-0009): digest is local by design;
    # show / search / timeline take --all to reach the whole root.
    recall_common = argparse.ArgumentParser(add_help=False)
    recall_common.add_argument(
        "--repo", default=None,
        help="repo directory (default: CLAUDE_PROJECT_DIR, else the "
             "current directory)")
    recall_common.add_argument(
        "--all", action="store_true",
        help="reach every repo under the root (unlisted repos stay "
             "invisible from outside themselves)")
    recall_common.add_argument(
        "--root", default=None,
        help="folder of repos for --all (default: the repo's parent)")
    digest = sub.add_parser(
        "digest",
        help="the session-start injection: this repo's recent history, "
             "budget-capped, testimony-labeled")
    digest.add_argument("--repo", default=None,
                        help="repo directory (default: CLAUDE_PROJECT_DIR, "
                             "else the current directory)")
    digest.add_argument("--limit", type=int, default=DIGEST_LIMIT,
                        help=f"most rows shown (default {DIGEST_LIMIT})")
    digest.add_argument("--payload", action="store_true",
                        help="read the harness's SessionStart payload on "
                             "stdin and take the repo from its cwd when "
                             "neither --repo nor CLAUDE_PROJECT_DIR names "
                             "one (Codex wiring, ADR-0020)")
    digest.add_argument("--since", default=None, metavar="YYYY-MM-DD",
                        help="only entries on or after this date")
    digest.set_defaults(func=cmd_digest)
    show = sub.add_parser(
        "show", parents=[recall_common],
        help="one full entry by entry address (self-verifying)")
    show.add_argument("address", help="entry-hash prefix, 4+ hex chars")
    show.set_defaults(func=cmd_show)
    verify = sub.add_parser(
        "verify", parents=[recall_common],
        help="the recorder's verdict on the chain holding one entry "
             "address (loxodonta verify --log, verbatim; exit code is "
             "the recorder's)")
    verify.add_argument("address", help="entry-hash prefix, 4+ hex chars")
    verify.set_defaults(func=cmd_verify)
    search = sub.add_parser(
        "search", parents=[recall_common],
        help="free-text search over action lines, this repo or --all")
    search.add_argument("text", help="text to find in action lines")
    search.add_argument("--limit", type=int, default=20,
                        help="most hits shown (default 20; matched "
                             "always counts all)")
    search.set_defaults(func=cmd_search_cli)
    timeline = sub.add_parser(
        "timeline", parents=[recall_common],
        help="context rows around one entry address")
    timeline.add_argument("address", help="entry-hash prefix, 4+ hex chars")
    timeline.add_argument("--before", type=int, default=3)
    timeline.add_argument("--after", type=int, default=3)
    timeline.set_defaults(func=cmd_timeline)
    mcp = sub.add_parser(
        "mcp",
        help="the recall surface as an MCP server on stdio — digest, "
             "show, search, timeline, verify; read-only (ADR-0019)")
    mcp.add_argument("--repo", default=None,
                     help="default repo for tool calls that name none "
                          "(default: CLAUDE_PROJECT_DIR, else the "
                          "working directory)")
    mcp.set_defaults(func=cmd_mcp)
    export = sub.add_parser(
        "export",
        help="field data for the project: an allowlisted, redacted "
             "summary of this machine's store, printed before it goes "
             "anywhere (ADR-0021)")
    export.add_argument("--witness", default=str(WITNESS_ROOT),
                        help="the harness transcript layout the scan "
                             "underneath reads (same as scan)")
    export.add_argument("--out", default=None,
                        help="file to write (default: "
                             "loxodonta-export-<date>.json here)")
    export.add_argument("--raw", action="store_true",
                        help="also write a raw archive of the chains "
                             "themselves, "
                             "byte-for-byte; shows a sample line and asks "
                             "first, because chains carry command lines")
    export.add_argument("--send", action="store_true",
                        help="upload as a secret gist under your gh login "
                             "and open a field-data issue on "
                             f"{FIELD_DATA_REPO}")
    export.set_defaults(func=cmd_export)
    package = sub.add_parser(
        "package",
        help="a session or a drawer as a package: its chains and anchor "
             "sidecars, the project record, a witness snapshot labelled "
             "testimony, a README, and a manifest written last; verified "
             "by `loxodonta verify-package` alone (ADR-0026)")
    # One unit or the other: argparse refuses both with a usage error.
    unit = package.add_mutually_exclusive_group()
    unit.add_argument("selector", nargs="?", default=None,
                      metavar="SESSION|ADDRESS",
                      help="a session id, or any entry address inside the "
                           "session (siblings included either way)")
    unit.add_argument("--repo", default=None, metavar="PATH",
                      help="the whole drawer of this repository instead, "
                           "every session and sibling, its harness worktree "
                           "drawers included, as `digest --repo` reads it "
                           "(default when no selector is given: "
                           "CLAUDE_PROJECT_DIR, else the current directory)")
    package.add_argument("--out", default=None,
                         help="file (or, with --folder, folder) to write "
                              "(default: loxodonta-package-<session>.zip "
                              "here)")
    package.add_argument("--folder", action="store_true",
                         help="write an unpacked folder instead of a zip")
    package.add_argument("--witness", default=str(WITNESS_ROOT),
                         help="the harness transcript layout the scan "
                              "underneath reads (same as scan)")
    package.add_argument("--transcript", action="store_true",
                         help="also carry each session's harness transcript "
                              "while it is still on disk; it can hold what "
                              "the session read, a secret included, so it "
                              "ships only on request (ADR-0026)")
    package.add_argument("--anchor", action="store_true",
                         help="seal the package: post the manifest's sha256 "
                              "to the OpenTimestamps calendars once and "
                              "ship the proof beside it, so verify-package "
                              "can earn + ANCHORED (ADR-0026 ruling 4). "
                              "Nothing leaves the machine without this")
    package.add_argument("--calendar", action="append", default=None,
                         metavar="URL",
                         help="calendar for --anchor (repeatable; default: "
                              "the public pools)")
    package.add_argument("--sign", default=None, metavar="KEYFILE",
                         help="seal the package with the issuer signature: "
                              "ssh-keygen signs the manifest with this SSH "
                              "private key (it alone reads the key, and "
                              "asks for a passphrase or a touch itself) and "
                              "the signature and public key ship beside it, "
                              "so verify-package can earn + SIGNED with the "
                              "key's fingerprint (ADR-0026 ruling 4, "
                              "ADR-0008). A key any process of this user "
                              "could use without you is writer-reachable, "
                              "and its signature is testimony")
    package.set_defaults(func=cmd_package)

    args = parser.parse_args(argv)
    # The cadence says when and the URL says where; one without the
    # other is a command spoken wrong, refused before any tick runs.
    if ((getattr(args, "publish_every", None) is None)
            != (getattr(args, "publish_url", None) is None)):
        parser.error("--publish-every and --publish-url go together")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
