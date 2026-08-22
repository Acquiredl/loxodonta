"""PROTOTYPE - THROWAWAY (issue #15). Delete or absorb; never ship.

The question: what are the right semantics for the supervisor's completeness
alarm - the state machine that pairs liveness-witness activity (tool events
seen in the harness transcript) with receipt arrival in a session's chain
family, and shouts when a session is demonstrably active but its chain is
silent or short?

The model under test:
- The witness signal is TOOL EVENTS, not transcript growth. A chat-only
  session grows its transcript and innocently writes zero receipts.
- Pairing is by session id (transcript filename == chain filename stem).
- Receipts are counted across the whole chain family (siblings included);
  a sibling's genesis is administrative and not counted.
- deficit = tools_witnessed - receipts_arrived. Deficit is STICKY: a lost
  receipt never arrives later, so a session that recovers keeps its scar.
- Two alarm shapes after a grace window:
    ALARM-SILENT  - no receipt at all since the deficit began
                    (hook disabled, wedged lock: recording stopped)
    ALARM-DEFICIT - receipts still arriving, but fewer than tool calls
                    (the silent fork: chain VALID, entries missing)
- A session with zero tool events never alarms. An ended session gets a
  final reconciliation verdict instead of a live alarm.

Pure module: no I/O, no clock reads - `now` always comes in from outside.
"""

GRACE_SECONDS = 30       # lock timeout is 10s; stay well above any honest lag
IDLE_END_SECONDS = 1800  # witness quiet this long => treat session as ended


def new_world():
    return {"now": 0, "sessions": {}, "order": []}


def new_session(world, sid):
    w = _copy(world)
    w["sessions"][sid] = {
        "id": sid,
        "tools": 0,          # cumulative tool events witnessed
        "receipts": 0,       # cumulative receipts arrived (family-wide, minus genesis)
        "chains": 1,         # chains in the family (1 = no siblings yet)
        "last_tool": None,
        "last_receipt": None,
        "deficit_since": None,  # when deficit last went 0 -> positive
        "ended": False,
        "ended_at": None,
    }
    w["order"].append(sid)
    return w


def apply_event(world, sid, kind):
    """kind: 'tool' | 'receipt' | 'sibling_receipt' | 'end' | ('tick', seconds)"""
    w = _copy(world)
    if isinstance(kind, tuple) and kind[0] == "tick":
        w["now"] += kind[1]
        return w
    s = dict(w["sessions"][sid])
    now = w["now"]
    if kind == "tool":
        s["tools"] += 1
        s["last_tool"] = now
        if s["tools"] - s["receipts"] == 1 and s["deficit_since"] is None:
            s["deficit_since"] = now
    elif kind in ("receipt", "sibling_receipt"):
        if kind == "sibling_receipt":
            s["chains"] += 1  # genesis of the new sibling is not counted
        s["receipts"] += 1
        s["last_receipt"] = now
        if s["receipts"] >= s["tools"]:
            s["deficit_since"] = None
    elif kind == "end":
        s["ended"] = True
        s["ended_at"] = now
    w["sessions"][sid] = s
    return w


def classify(s, now):
    """Derived status for one session: (STATE, detail). Pure."""
    deficit = max(0, s["tools"] - s["receipts"])
    surplus = max(0, s["receipts"] - s["tools"])
    if s["ended"]:
        if deficit == 0:
            return "ENDED-CLEAN", "reconciled: every tool call has its receipt"
        return "ENDED-DEFICIT", f"{deficit} receipt(s) missing forever - report as evidence"
    last_activity = max(x for x in (s["last_tool"], s["last_receipt"], 0) if x is not None)
    if s["tools"] > 0 and now - last_activity >= IDLE_END_SECONDS:
        tag = "IDLE-CLEAN" if deficit == 0 else "IDLE-DEFICIT"
        return tag, "witness quiet past idle window - treated as ended"
    if surplus:
        return "SURPLUS?", f"{surplus} more receipt(s) than witnessed tools - witness lag or fabrication; investigate, not a verdict"
    if s["tools"] == 0:
        return "QUIET", "no tool events witnessed - nothing expected, never alarms"
    if deficit == 0:
        return "OK", "tools and receipts in step"
    age = now - s["deficit_since"]
    if age < GRACE_SECONDS:
        return "LAGGING", f"deficit {deficit}, in grace ({age}s/{GRACE_SECONDS}s)"
    silent = s["last_receipt"] is None or s["last_receipt"] < s["deficit_since"]
    if silent:
        return "ALARM-SILENT", f"recording stopped: {deficit} unmatched for {age}s (hook off / wedged lock?)"
    return "ALARM-DEFICIT", f"receipts arriving but {deficit} short for {age}s (fork-shaped hole)"


def _copy(world):
    return {"now": world["now"],
            "sessions": dict(world["sessions"]),
            "order": list(world["order"])}
