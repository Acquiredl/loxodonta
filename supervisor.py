#!/usr/bin/env python3
"""supervisor.py — the operator that never sleeps (ADR-0005).

A reader-side companion to receipts.py: it watches every receipt log
under a root full of repos and shouts on change — a tripwire with a
memory, never a wall. It drives receipts exclusively through the public
CLI and judges nothing itself: verdicts come from `receipts verify`,
and everything the supervisor holds is writer-reachable, so nothing
here is a head record (GLOSSARY: Supervisor, Baseline).

  python supervisor.py scan --root DIR --json
  python supervisor.py serve --root DIR

`scan` is one tick without timers: a census of every chain under the
root, a verdict for each, a baseline diff against the last look,
machine-readable JSON on stdout, and an exit code cron can shout about —
0 when nothing demands attention, 1–4 for the worst verify exit found,
5 when the baseline saw a change appends cannot explain (a reason to
investigate, never a verdict), 6 when a session is demonstrably active
but its chain is behind the witness (the completeness alarm).

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
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
RECEIPTS = HERE / "receipts.py"


# --- Census -------------------------------------------------------------------

def find_chains(root):
    """Every receipt log under the root. Three shapes, because history has
    three shapes: the root itself being a repo, each sibling repo's
    receipts/, and chains stranded in worktrees by sessions that ran
    before the hook learned to log to the main repo. Anchor sidecars are
    proofs about a chain, not chains."""
    patterns = ("receipts/*.jsonl",
                "*/receipts/*.jsonl",
                "*/.claude/worktrees/*/receipts/*.jsonl")
    return sorted(p for pattern in patterns for p in root.glob(pattern)
                  if not p.name.endswith(".anchors.jsonl"))


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
        [sys.executable, str(RECEIPTS), "verify", "--anchors",
         "--log", str(log)],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    lines = result.stdout.strip().splitlines()
    if lines:
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
# head, kept in a file beside the repos. Writer-reachable by definition,
# therefore trusted for nothing — a disagreement is a reason to
# investigate, never a verdict about which side is true. Verdicts come
# from verify; the out-of-reach copy, if you keep one, is the anchor.

BASELINE_NAME = ".supervisor-baseline.json"

INVESTIGATE = ("investigate — this memory is writer-reachable and decides "
               "nothing; run receipts verify and check your anchors")

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
        return chains, keeper if isinstance(keeper, dict) else {}, None
    except FileNotFoundError:
        return {}, {}, None  # cold start: seed silently
    except (ValueError, KeyError, TypeError, AttributeError,
            json.JSONDecodeError, OSError):
        return {}, {}, ("the baseline could not be read — remembering "
                        "afresh from this look; it was trusted for "
                        "nothing either way")


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
    bare seconds. Used by --anchor-every."""
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


def sidecar_heads(sidecar):
    """Heads that already have a record, read tolerantly and for
    scheduling only — judging the proofs stays with verify."""
    heads = set()
    try:
        with open(sidecar, encoding="utf-8", errors="replace") as lines:
            for line in lines:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (isinstance(record, dict)
                        and isinstance(record.get("head"), str)):
                    heads.add(record["head"])
    except FileNotFoundError:
        pass
    return heads


def keep_anchors(log, last_attempt, now, entries, cadence, calendars):
    """One chain's turn with the keeper, at most once per throttle
    window: pending proofs are driven through `receipts anchor
    --upgrade` (the record's own calendar; judgment stays with verify),
    and — only when the operator opted in with a cadence — a fresh head
    that has aged past it is anchored. Off by default: nothing leaves
    the machine without the say-so. Returns (attempted, note, failed)."""
    sidecar = Path(str(log) + ".anchors.jsonl")
    if not upgrade_due(last_attempt, now):
        return False, None, False
    attempted = False
    note = None
    failed = False
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    if sidecar.exists():
        finished = subprocess.run(
            [sys.executable, str(RECEIPTS), "anchor", "--upgrade",
             "--log", str(log)],
            capture_output=True, encoding="utf-8", env=env)
        attempted = True
        if finished.returncode != 0:
            note = ("upgrade attempted; a calendar did not answer — "
                    "proofs stay pending and the keeper will try again")
    if cadence is not None and entries:
        head = entries[-1].get("entry_hash")
        born = parse_when(entries[-1].get("ts"))
        ripe = born is not None and (now - born).total_seconds() >= cadence
        if head and ripe and head not in sidecar_heads(sidecar):
            command = [sys.executable, str(RECEIPTS), "anchor",
                       "--log", str(log)]
            for calendar in calendars:
                command += ["--calendar", calendar]
            finished = subprocess.run(command, capture_output=True,
                                      encoding="utf-8", env=env)
            attempted = True
            if finished.returncode != 0:
                failed = True
                note = ("anchoring failed — no calendar accepted this "
                        "head; it stays unanchored and the keeper will "
                        "try again")
    return attempted, note, failed


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
    "SURPLUS": "more receipts than witnessed tools — witness lag, or "
               "receipts arriving unwitnessed; investigate. A flag, "
               "never a verdict.",
    "LAGGING": "behind the witness inside the grace window — an honest "
               "lock wait looks like this; no shout yet.",
    "UNWITNESSED": "no transcript pairs with this session — completeness "
                   "cannot be watched for it; nothing is assumed "
                   "either way.",
    "UNWATCHED": "no receipts hook is wired into the harness settings — "
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
            and "receipts" in str(hook.get("command", ""))
            for hook in commands)
        if wired:
            matchers.append(str(rule.get("matcher", "*")))
    return matchers


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


def read_witness(transcript, matchers):
    """The witness signal: timestamps of tool events that owe a receipt.
    A tool event is a tool_use block paired by id with its result line;
    only completed results count (failed calls fire no hook — the
    field's suppression finding) and only tools the wired matchers
    cover (the calibration finding: an all-tools witness over an
    Edit|Write|Bash hook manufactures deficits). Chatter is never
    counted: a chat-only session can never alarm."""
    names = {}
    events = []
    with open(transcript, encoding="utf-8", errors="replace") as lines:
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
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
            name = next((names.get(block.get("tool_use_id"))
                         for block in blocks
                         if isinstance(block, dict)
                         and block.get("type") == "tool_result"), None)
            if owes_receipt(name, matchers):
                events.append(record.get("timestamp"))
    return events


def classify(tools, receipts, ended, idle, deficit_age, silent):
    """The ratified alarm state machine (issue #22, from the #15
    prototype) — a pure reading of the evidence. Deficit is sticky:
    lost receipts never arrive later, so a session keeps its scar until
    end-of-session reconciliation reports it as evidence."""
    deficit = max(0, tools - receipts)
    if ended:
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


def watch_session(transcript, receipts, last_receipt, now, matchers):
    """One session against its witness. deficit_since needs no stored
    state: receipts pair with tool events in order, so the first
    unpaired event's timestamp is when the deficit began."""
    events = read_witness(transcript, matchers)
    tools = len(events)
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


def watch_completeness(root, witness, families):
    """The completeness half of a tick: every census session paired with
    its transcript, plus witnessed sessions that never grew a chain at
    all — the disabled-hook case the census alone can never see."""
    now = datetime.now(timezone.utc)
    watch = {"witness": witness.as_posix(), "sessions": []}
    ours = munge(root)
    matchers = hook_matchers(witness)
    transcripts = {}
    if witness.is_dir():
        transcripts = {t.stem: t for t in sorted(witness.glob("*/*.jsonl"))}
    else:
        watch["note"] = (f"witness absent — no transcript layout at "
                         f"{witness.as_posix()}; completeness cannot be "
                         "watched this look")
    if witness.is_dir() and not matchers:
        watch["note"] = ("no receipts hook is wired into the harness "
                         "settings beside this witness — nothing owes a "
                         "receipt, so completeness has nothing to watch")

    def add(repo, session, state, tools, receipts):
        entry = {"repo": repo, "session": session, "state": state,
                 "tools": tools, "receipts": receipts,
                 "deficit": max(0, tools - receipts)}
        if state in WATCH_WORDS:
            entry["words"] = WATCH_WORDS[state]
        watch["sessions"].append(entry)

    for (repo, session), family in sorted(families.items()):
        transcript = transcripts.pop(session, None)
        if transcript is None:
            add(repo, session, "UNWITNESSED", 0, family["receipts"])
            continue
        if not matchers:
            add(repo, session, "UNWATCHED", 0, family["receipts"])
            continue
        try:
            state, tools = watch_session(transcript, family["receipts"],
                                         family["last"], now, matchers)
        except OSError:
            # A transcript that cannot be read (vanished mid-scan, or a
            # path that is not a readable file) costs this one session
            # its watch, never the whole scan. UNWITNESSED says it
            # honestly: completeness cannot be watched, nothing assumed.
            add(repo, session, "UNWITNESSED", 0, family["receipts"])
            continue
        add(repo, session, state, tools, family["receipts"])

    # Chainless sessions: only transcript folders under this root are
    # this scan's business; a folder's name past the root prefix is the
    # best name the witness has for the project.
    for stem, transcript in transcripts.items():
        folder = transcript.parent.name
        if not matchers or not folder.startswith(ours):
            continue
        try:
            state, tools = watch_session(transcript, 0, None, now, matchers)
        except OSError:
            continue  # unreadable and chainless: nothing to say about it
        add(folder[len(ours):].strip("-") or root.name, stem, state,
            tools, 0)

    return watch


# --- Scan ---------------------------------------------------------------------

def scan_root(root, witness=WITNESS_ROOT, anchor_every=None, calendars=()):
    """One tick without timers: census + verdicts + baseline diff +
    completeness watch as a report dict — what `scan` prints and what
    the status endpoint serves. The baseline is remembered anew after
    diffing, so an alarm belongs to the tick that caught it."""
    now = datetime.now(timezone.utc)
    baseline_path = root / BASELINE_NAME
    remembered, keeper, note = read_baseline(baseline_path)
    events = []
    heads = {}
    families = {}
    # Walk in display order — repo, then session, then sibling sequence —
    # so the grouping below is plain insertion, no re-sorting.
    census = sorted((chain_identity(root, log), log)
                    for log in find_chains(root))
    repos = {}
    worst = 0
    for (repo, session, _), log in census:
        relpath = log.relative_to(root).as_posix()
        entries = read_entries(log)
        attempted, keeper_note, anchor_failed = keep_anchors(
            log, keeper.get(relpath), now, entries,
            anchor_every, calendars)
        if attempted:
            keeper[relpath] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
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
        }
        if keeper_note:
            chain["anchors"]["note"] = keeper_note
        if anchor_failed:
            chain["anchors"]["failed"] = True
        repos.setdefault(repo, {}).setdefault(session, []).append(chain)
        if not stood_down:
            worst = max(worst, exit_code)

        change = diff_baseline(remembered, relpath, entries)
        if change:
            events.append({"repo": repo, "session": session, "log": relpath,
                           "change": change,
                           "investigate": CHANGE_WORDS[change]})
        if entries:
            heads[relpath] = {"n": entries[-1].get("n"),
                              "head": entries[-1].get("entry_hash")}

        # The session's receipt tally for the completeness watch: the
        # whole sibling family counts; each genesis is administrative.
        family = families.setdefault((repo, session),
                                     {"receipts": 0, "last": None})
        logged = [e for e in entries if e.get("n") != 0]
        family["receipts"] += len(logged)
        stamps = [e["ts"] for e in logged if isinstance(e.get("ts"), str)]
        if stamps:
            family["last"] = max(family["last"] or "", max(stamps))

    for relpath in remembered:
        if relpath not in heads and not (root / relpath).exists():
            repo_name, session, _ = chain_identity(root, root / relpath)
            events.append({"repo": repo_name, "session": session,
                           "log": relpath, "change": "vanished",
                           "investigate": CHANGE_WORDS["vanished"]})

    baseline_path.write_text(json.dumps({
        "purpose": "the supervisor's memory between looks — "
                   "writer-reachable, trusted for nothing",
        "chains": heads,
        "keeper": keeper,
    }, indent=2) + "\n", encoding="utf-8")
    if events:
        worst = max(worst, 5)

    completeness = watch_completeness(root, witness, families)
    # Only a live alarm raises the exit: an ended deficit is evidence,
    # and a siren that never stops sounding trains the operator to
    # ignore the band (the dogfood's lesson).
    if any(s["state"] in ("ALARM-SILENT", "ALARM-DEFICIT")
           for s in completeness["sessions"]):
        worst = max(worst, 6)

    baseline = {"file": baseline_path.as_posix(), "events": events}
    if note:
        baseline["note"] = note
    return {
        "root": root.as_posix(),
        "exit": worst,
        "baseline": baseline,
        "completeness": completeness,
        "repos": [
            {"repo": repo,
             "sessions": [{"session": session, "chains": chains}
                          for session, chains in sessions.items()]}
            for repo, sessions in repos.items()
        ],
    }


def cmd_scan(args):
    report = scan_root(Path(args.root).resolve(),
                       witness=Path(args.witness),
                       anchor_every=args.anchor_every,
                       calendars=args.calendar or ())
    print(json.dumps(report, indent=None if args.json else 2))
    return report["exit"]


# --- Recall -------------------------------------------------------------------
# The memory view: chains read as *what happened*, not as evidence.
# Reading the JSONL directly is display-only and allowed (ADR-0005) — the
# format is a public interface — but recall owns no verdicts: it renders
# writer-supplied testimony and says so, exactly as `report` does.

TESTIMONY = ("testimony, not a verdict — what was attempted, as the writer "
             "told it; run receipts verify for the verdict")


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


def recall_root(root, repo=None, since=None, until=None, path=None):
    """The timeline: one story per session, sibling chains folded in
    (ADR-0004 — one session, one story), newest first. Dates compare as
    ISO prefixes; a session is in range when its span overlaps."""
    stories = {}
    for log in find_chains(root):
        repo_name, session, _ = chain_identity(root, log)
        if repo and repo_name != repo:
            continue
        entries = read_entries(log)
        story = stories.setdefault((repo_name, session), {
            "repo": repo_name, "session": session, "chains": [],
            "entries": 0, "started": None, "ended": None,
            "worktree": False, "_touched": False})
        story["chains"].append(log.name)
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
            or path.name.endswith(".anchors.jsonl")
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


def search_root(root, query):
    """Free-text search over action lines, machine-wide. Finds what was
    *written* — the writer's word, testimony like all of recall — and
    hands back the context the timeline links on. Newest first; an empty
    query matches nothing rather than everything."""
    needle = (query or "").lower()
    hits = []
    if needle:
        for log in find_chains(root):
            repo_name, session, _ = chain_identity(root, log)
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
        [sys.executable, str(RECEIPTS), *args],
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
# `receipts verify`, nowhere else.

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

    def fresh_status(self):
        with self.scan_lock:
            if (self.scan_body is None
                    or time.monotonic() - self.scan_at >= SCAN_TTL_SECONDS):
                report = scan_root(self.root, witness=self.witness,
                                   anchor_every=self.anchor_every,
                                   calendars=self.calendars)
                self.scan_body = json.dumps(report).encode("utf-8")
                self.scan_at = time.monotonic()
            return self.scan_body


class Face(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # the scan is the story; per-request chatter is noise

    def do_GET(self):
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
                                 path=asked.get("path") or None)
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
            report = search_root(self.server.root, asked.get("q"))
            self.reply(json.dumps(report).encode("utf-8"),
                       "application/json")
        elif url.path == "/checklist":
            doc = HERE / "docs" / "FIRE-DRILL.md"
            if not doc.is_file():
                self.send_error(404)
                return
            self.reply(doc.read_bytes(), "text/plain; charset=utf-8")
        elif url.path == "/":
            self.reply(PAGE.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def do_POST(self):
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
    root = Path(args.root).resolve()
    # 127.0.0.1 is the whole posture: nothing about this machine's
    # activity is ever offered to another one.
    server = Watchtower(("127.0.0.1", args.port), Face)
    server.root = root
    server.witness = Path(args.witness)
    server.anchor_every = args.anchor_every
    server.calendars = args.calendar or ()
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
<title>supervisor — recall</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 64rem;
         margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  header h1 { margin-bottom: 0.2rem; }
  header .stance { color: color-mix(in srgb, currentColor 60%, transparent);
                   margin-top: 0; }
  #summary { padding: 0.6rem 1rem; border-radius: 0.5rem; margin: 1rem 0;
             font-weight: 600; border: 1px solid transparent; }
  #summary.quiet { background: #1d7a3e22; border-color: #1d7a3e; }
  #summary.shouting { background: #b3261e22; border-color: #b3261e; }
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
  .story.found-you { border-left-color: #1d7a3e;
                     background: #1d7a3e1f; }
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
  .tier-broken { border-color: #b3261e; background: #b3261e14; }
  .tier-broken .chip { color: #b3261e; border-color: #b3261e; }
  .tier-refused .chip { color: #8a6d00; border-color: #8a6d00; }
  .tier-diverged .chip { color: #8a6d00; border-color: #8a6d0055; }
  .tier-anchored .chip { background: #1d7a3e; color: #fff; }
  .tier-valid .chip { color: #1d7a3e; border-color: #1d7a3e; }
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
  .watch-row.live { border: 3px solid #b45309; background: #b453091a; }
  .watch-row.live .chip { background: #b45309; color: #fff; }
  .watch-row.quiet { opacity: 0.6; }
  .watch-row.quiet .chip { color: inherit;
                           border-color: color-mix(in srgb, currentColor 40%, transparent); }

  /* The anchor panel: the block height is the operator's half of the
     regeneration defense, so it is the biggest thing in each row. */
  .berth { display: flex; flex-wrap: wrap; gap: 0.7rem;
           align-items: baseline; padding: 0.5rem 0.8rem; margin: 0.4rem 0;
           border-left: 3px solid color-mix(in srgb, currentColor 30%, transparent);
           background: color-mix(in srgb, currentColor 5%, transparent);
           border-radius: 0 0.5rem 0.5rem 0; }
  .berth .height { font-size: 1.35rem; font-weight: 800; color: #1d7a3e; }
  .berth .pending-proof { color: #8a6d00; }
  .berth .bare { opacity: 0.75; }
  .berth .stale { color: #b45309; font-weight: 700; }
  .berth .shout { color: #b3261e; font-weight: 700; }

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
                 border: 3px solid #b3261e; background: #b3261e14;
                 border-radius: 0.5rem; font-family: monospace;
                 overflow-wrap: anywhere; }
  .recheck { font-size: 0.8rem; padding: 0.1rem 0.5rem;
             border-radius: 0.4rem; }
  .recheck.match { color: #1d7a3e; border: 1px solid #1d7a3e; }
  .recheck.mismatch { background: #b3261e; color: #fff; font-weight: 700; }
  .broken-link { color: #b3261e; font-weight: 700; font-size: 0.85rem; }
  button.walk { font: inherit; font-size: 0.8rem; cursor: pointer;
                border-radius: 0.4rem; padding: 0.1rem 0.6rem;
                border: 1px solid color-mix(in srgb, currentColor 35%, transparent);
                background: transparent; color: inherit; }

  /* The fire drill: rehearsal results, never verdicts. */
  .drill-row { display: flex; flex-wrap: wrap; gap: 0.7rem;
               align-items: baseline; padding: 0.4rem 0.8rem;
               margin: 0.3rem 0; border-radius: 0.5rem;
               border: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  .drill-row .fired { color: #1d7a3e; font-weight: 700; }
  .drill-row .misfired { background: #b3261e; color: #fff;
                         font-weight: 700; padding: 0.1rem 0.5rem;
                         border-radius: 0.4rem; }
  #drill-banner.quiet, #drill-banner.shouting { padding: 0.5rem 1rem;
               border-radius: 0.5rem; font-weight: 600; margin: 0.5rem 0; }
  #drill-banner.quiet { background: #1d7a3e22; border: 1px solid #1d7a3e; }
  #drill-banner.shouting { background: #b3261e22;
                           border: 1px solid #b3261e; }
</style>
</head>
<body>
<header>
  <h1>supervisor</h1>
  <p class="stance">a tripwire with a memory — verdicts come from
  <code>receipts verify</code>; this page draws them and decides nothing</p>
</header>
<div id="summary">reading the scan…</div>

<section id="recall">
  <h2>recall</h2>
  <p class="testimony">testimony, not a verdict — what was attempted, as
  the writer told it; run <code>receipts verify</code> for the verdict</p>
  <input type="search" id="ask-search"
         placeholder="search every action line on this machine">
  <div id="found"></div>
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
  <div id="timeline">remembering…</div>
</section>

<section id="anchors">
  <h2>anchors</h2>
  <p class="testimony">the block height is your half of the regeneration
  defense — confirm it against a Bitcoin block source you trust</p>
  <div id="panel"></div>
</section>

<section id="alarms">
  <h2>status band</h2>
  <div id="tripwire"></div>
  <div id="watch"></div>
  <div id="band"></div>
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
<script>
"use strict";

// Which rung of the ladder a chain stands on. Order matters: standing
// down (superseded) is checked first, then the gravest claim, downward.
function tier(chain) {
  if (chain.superseded) return "superseded";
  if (chain.exit === 3) return "regenerated";
  if (chain.verdict === "BROKEN") return "broken";
  if (chain.verdict === "FILES-DIVERGED") return "diverged";
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
  diverged: "chain intact, but files differ from their logged fingerprints",
  valid: "intact against itself — tamper-evident, not yet anchored",
  anchored: "intact and anchored — this history existed by the named " +
            "Bitcoin block",
  superseded: "torn tail, already handled — recording continued in a " +
              "sibling chain; kept as quiet evidence",
};

const CHIP = {
  regenerated: c => c.verdict, broken: () => "BROKEN",
  refused: c => c.verdict, diverged: () => "FILES-DIVERGED",
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

function render(report) {
  const summary = document.getElementById("summary");
  const chains = report.repos.flatMap(r =>
    r.sessions.flatMap(s => s.chains));
  const quietEvidence = chains.filter(c => c.superseded).length;
  const changes = report.baseline.events.length;
  if (report.exit === 0) {
    summary.className = "quiet";
    summary.textContent = "all quiet — " + chains.length + " chain(s) " +
      "under " + report.root +
      (quietEvidence ? " (" + quietEvidence + " superseded tear(s) kept " +
                       "as evidence)" : "");
  } else {
    summary.className = "shouting";
    summary.textContent = "attention — something under " + report.root +
      " demands it" +
      (changes ? " — " + changes + " change(s) since the last look" : "") +
      " (scan exit: " + report.exit + ")";
  }

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
  const NOTEWORTHY = LIVE.concat(["ENDED-DEFICIT", "SURPLUS", "LAGGING",
                                  "IDLE-DEFICIT"]);
  for (const s of report.completeness.sessions) {
    if (!NOTEWORTHY.includes(s.state)) continue;
    const live = LIVE.includes(s.state);
    const row = el("div", "watch-row " + (live ? "live" : "quiet"));
    row.appendChild(el("span", "chip", s.state));
    row.appendChild(el("span", "file", s.repo + " · " + s.session +
      " · witnessed " + s.tools + ", received " + s.receipts));
    if (s.words) row.appendChild(el("p", "claim", s.words));
    watch.appendChild(row);
  }
  if (report.completeness.note) {
    watch.appendChild(el("p", "claim", report.completeness.note));
  }

  renderAnchors(report);

  const band = document.getElementById("band");
  band.replaceChildren();
  for (const repo of report.repos) {
    band.appendChild(el("h2", "", repo.repo));
    for (const session of repo.sessions) {
      const box = el("div", "session");
      box.appendChild(el("div", "name", "session " + session.session));
      for (const chain of session.chains) {
        box.appendChild(chainRow(chain));
      }
      band.appendChild(box);
    }
  }
  if (!report.repos.length) {
    band.appendChild(el("p", "", "no chains under this root yet — work " +
      "a session with the hook installed and receipts will appear here."));
  }

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

function storyRow(story) {
  const row = el("div", "story");
  row.dataset.where = story.repo + "/" + story.session;
  row.appendChild(el("span", "repo", story.repo));
  row.appendChild(el("span", "id", story.session));
  row.appendChild(el("span", "span", spanText(story)));
  row.appendChild(el("span", "count", story.entries + " receipt(s)"));
  if (story.worktree) {
    row.appendChild(el("span", "badge", "stranded in a worktree"));
  }
  if (story.chains.length > 1) {
    row.appendChild(el("p", "sibling", story.chains.length +
      " chains — recording continued in a sibling"));
  }
  return row;
}

function renderRecall(report) {
  const timeline = document.getElementById("timeline");
  timeline.replaceChildren();
  for (const story of report.sessions) {
    timeline.appendChild(storyRow(story));
  }
  if (!report.sessions.length) {
    timeline.appendChild(el("p", "", "nothing remembered here — " +
      "no session matches these filters."));
  }
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
    renderRecall(await response.json());
  } catch (error) {
    document.getElementById("timeline").textContent =
      "recall did not answer: " + error;
  }
}

// --- search: the writer's word, findable ----------------------------

// A hit links into the timeline: focus the session's repo, then scroll
// to its story once the timeline has re-answered.
async function visit(hit) {
  document.getElementById("ask-repo").value = hit.repo;
  await loadRecall();
  const where = hit.repo + "/" + hit.session;
  for (const row of document.querySelectorAll("#timeline .story")) {
    if (row.dataset.where === where) {
      row.classList.add("found-you");
      row.scrollIntoView({behavior: "smooth", block: "center"});
      setTimeout(() => row.classList.remove("found-you"), 2500);
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

async function loadStatus() {
  try {
    const response = await fetch("/api/status");
    render(await response.json());
  } catch (error) {
    const summary = document.getElementById("summary");
    summary.className = "shouting";
    summary.textContent = "the scan did not answer: " + error;
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
setInterval(loadRecall, 30000);
setInterval(loadStatus, 30000);
</script>
</body>
</html>
"""


def main(argv):
    parser = argparse.ArgumentParser(prog="supervisor",
                                     description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    watching = argparse.ArgumentParser(add_help=False)
    watching.add_argument("--root", required=True,
                          help="the folder your repos live in")
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
    scan = sub.add_parser(
        "scan", parents=[watching],
        help="one tick: census + verdicts, JSON out, exit code")
    scan.add_argument("--json", action="store_true",
                      help="compact machine output (default pretty-prints)")
    scan.set_defaults(func=cmd_scan)
    serve = sub.add_parser(
        "serve", parents=[watching],
        help="the face: status band on a localhost-only server")
    serve.add_argument("--port", type=int, default=7717,
                       help="localhost port (0 picks a free one; "
                            "default 7717)")
    serve.set_defaults(func=cmd_serve)
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
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
