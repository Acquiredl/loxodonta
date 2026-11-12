# ADR-0046: A disagreement is a finding until it is accepted out of the writer's reach

**Status:** accepted 2026-11-12, built (#601). Ruled by the author on that date after a design review of the whole tool, as one answer to the proposal with its four choices and a one-hour settle window.
**Deciders:** Acquiredl

## Context

Two readers ask whether a session's receipts are all there.

**The witness on the agent's machine** reads the harness's transcripts
and counts the tool calls that owe a receipt (ADR-0016, ADR-0034).
Every file it reads is in the account the writer runs as: the
transcripts, the coverage marker that says which tools were wired,
the baseline and the day book that hold what the supervisor
remembered. A transcript of the writer's making stands in for the
real one, a narrowed matcher lowers what is owed, and a baseline
edited by hand raises nothing. None of that is a fault in the
witness. It is what the same account means.

**The reading at the receiver** (ADR-0041 ruling 4) reconciles the
harness's events with the receipts that arrived, on a machine the
writer cannot reach, and keeps its own memory there. Three things in
it are weaker than its place deserves:

- A settled disagreement, `ENDED-DEFICIT`, `SECOND-RECORD-ABSENT` or
  `SECOND-RECORD-GAP`, is printed and moves no exit code. Forty
  `Bash` calls reported and thirty-seven receipts held is exit 0, and
  whatever watches the exit sees nothing.
- Calls and receipts are paired by count, tool by tool. Three
  receipts missing and three of the same tool too many read as
  clean.
- A session is judged seven hours after it goes quiet, because
  receipts reached the receiver only at session end or on the
  keeper's six hours. ADR-0045 sends each entry as it is written.

The README and `docs/CLAIMS.md` have disagreed about which of the two
readers the completeness promise rests on.

### Prior art, read on 2026-11-10

| System | What it does | What is taken from it |
|---|---|---|
| Tripwire (Kim and Spafford, 1993) | the baseline, the configuration and the acceptance of a change are kept off the host they describe, and a change is reported at every run until accepted | where the memory and the acceptance live, and that a finding repeats |
| PeerReview (Haeberlen, Kouznetsov, Druschel, 2007) | a node is trusted, suspected or exposed, and exposed does not clear by itself | a finding stands until someone ends it |
| Elastic EQL, `sequence by` with `maxspan` and missing events | events are joined on a shared id inside a span, and the half that never came is the match | pairing by the call's id, inside a window |

## Decision

1. **The witness on the agent's machine catches faults, and is said
   to.** A hook that crashed, a setting that was stripped, an install
   that broke: it shows those, live, and it stays as it is. It is not
   a defence against a writer in the same account, and no document
   says or implies that it is. The promise that a call without a
   receipt shows is made for the vantage setup, where the reading is
   the receiver's.

2. **At the receiver, a settled disagreement raises the exit until it
   is acknowledged there.** `ENDED-DEFICIT`, `SECOND-RECORD-ABSENT`
   and `SECOND-RECORD-GAP` in a scan of a receiver's folder exit as a
   live deficit does, at every scan. `acknowledge --receiver DIR`
   takes a session and the state the scan reported, writes one record
   to the memory in that folder, and from then on the session is
   listed with its acknowledgement and no longer raises the exit. It
   is refused when the session is not in that state. A session whose
   counts change after it was acknowledged is a finding again. On the
   agent's machine an ended deficit moves no exit, as before
   (ruling 1).

3. **A call and its receipt are paired by the call's id where both
   records carry it.** Where the harness's event names the call and
   the receipt names the same call (ADR-0047 gives the receipt the
   place to say it), the two are joined on that id, and a call with
   no receipt is named by its id. Where either side carries none, the
   count by tool stands, and the report says which rule judged the
   session.

4. **A session at the receiver settles after one hour.** The window
   is one hour of nothing arriving, where it was seven. The knob that
   moves it stays. One hour clears a closed lid or a dropped network
   without a false deficit, and a real one shows the same day.

5. **The docs say it:** `docs/CLAIMS.md` and the README (which
   reader the promise rests on), `docs/RECEIVER.md` section 7 (the
   exit, the acknowledgement, the pairing, the window),
   `docs/TOPOLOGY.md`, the glossary, and an addendum on ADR-0041.

6. **A call is judged by its own age, whatever arrives after it.**
   Ruled on 2026-11-12, after the review of the build (#601) showed
   that one event an hour, posted by whoever holds the URL, kept a
   session `PENDING` and so never judged. The window of ruling 4
   still decides when a session as a whole has settled. Beside it, in
   a session that is still `PENDING`, a call the harness reported
   more than the window ago is overdue: its age is the receiver's own
   `received` of the arrival that carried it, never a time the event
   states. An overdue call with no receipt, paired as ruling 3 says,
   makes the session `PENDING-OVERDUE`, and so does a hole in the
   events' counter below an event that arrived more than the window
   ago. `PENDING-OVERDUE` raises the exit as the three findings of
   ruling 2 do. It cannot be acknowledged: it ends when the receipts
   arrive, or when the session settles and reads as one of the three,
   which can. Where the count by tool stands, the overdue calls are
   counted against every receipt held, so a receipt of a newer call
   can pay for an older one until the session settles; that reading
   is never louder than the settled one will be.

### What it claims, and what it does not

It claims that in the vantage setup, a session the receiver heard of
from the harness whose receipts fall short raises the exit of the
receiver's scan within the settle window, and keeps raising it until
a person with access to the receiver accepts it.

It does not claim:

- **Anything of the kind on one machine.** There the witness reads
  what the writer can write.
- **A session the receiver never heard of.** A harness whose events
  were cut tells the receiver nothing, and such a session's receipts
  read `SECOND-RECORD-ABSENT`, which is a finding here too.
- **That an acknowledgement is right.** It records that someone
  accepted the state, and when.
- **Pairing by id where the harness's events name no call.**
- **An absent second record in a session that is kept arriving.** A
  writer that cuts the harness's events and keeps posting entries
  holds its session `PENDING` with no call to be overdue. Ruling 6
  judges calls the receiver heard of.

## Consequences

**What gets easier:**

- One sentence says where completeness is judged, and the README and
  `docs/CLAIMS.md` say the same one.
- A monitor on the receiver's scan needs only its exit.
- The findings against the on-machine witness (a transcript standing
  in for another, a narrowed matcher, an edited baseline) are named
  limits and not a list of holes to close one at a time.

**What gets harder or more constrained:**

- A receiver's scan that exited 0 over old ended deficits exits
  non-zero until each is acknowledged, the first time it runs after
  the change.
- An operator with one machine is told plainly that the completeness
  promise is not theirs.
- A session that sends nothing for an hour and then resumes is
  judged, then judged again.

**What we'll have to revisit if:**

- The harness's events turn out to name no call: ruling 3 then
  builds nothing, and the count stands.
- One hour raises false deficits in practice: the knob is there.
- The surplus that #476 causes makes acknowledged sessions change
  their counts often.

## Alternatives considered

- **Harden the on-machine witness, hole by hole.** Rejected: each fix
  would guard a file with another file in the same reach.
- **Leave ended deficits at exit 0, as evidence.** Rejected: on the
  receiver the evidence is what the setup was built to produce, and
  nothing reads it unprompted.
- **A window of five minutes, or of seven hours.** Five raises a
  deficit over a closed lid; seven was the keeper's cadence, which no
  longer decides when receipts arrive.
- **Acknowledge from the agent's machine.** Rejected: Tripwire's
  lesson. The acceptance lives where the baseline does.
- **Name the limit and keep the session-wide window alone.** The
  build as first reviewed. Rejected: the finding of ruling 2 could be
  put to sleep by the party it is kept against.
- **A session that has raised keeps raising while it is pending.**
  Rejected: a writer that posts from the first hour is never judged,
  so never raises once.
- **Let `PENDING-OVERDUE` be acknowledged.** Rejected for now: its
  counts move with every call of a live session, so an acceptance
  would hold for seconds.

## References

- ADR-0002 (the writer is the adversary), ADR-0016 and ADR-0034
  (what owes a receipt), ADR-0018 (a session's lifecycle), ADR-0039
  (the baseline keeps what it remembered until acknowledged),
  ADR-0041 (the second record, narrowed here), ADR-0045 (entries
  leave as written), ADR-0047 (the receipt names its call)
- #476 (the surplus), `docs/RECEIVER.md` section 7,
  `docs/CLAIMS.md`

## Addendum, 2026-11-12: what pays a call, and when

*Drafted for the author to confirm (#620).* The author ruled five
points on a decision sheet the same day; this records them as built.

1. **A receipt pays a call only under the tool the event names.**
   Joined on the id (ruling 3), a receipt pays the call only when the
   tool its action line names is the one the harness's event names for
   that id. One naming another tool pays nothing, the call stays
   unpaid, and the row names the id and both tools. An event naming no
   tool pairs on the id alone. The build found one place the two names
   differ for an honest call: the harness's events name every call to
   a server the user configured `mcp_tool`, where the hook writes
   `mcp__<server>__<tool>`, so an event naming `mcp_tool` is met by any
   receipt of an MCP tool.
2. **At most one receipt per call id pays** (#476, the reader's half).
   A further receipt of an id already paid is neither surplus nor
   deficit; the row counts it, and the chain keeps it. Under the count
   by tool, a receipt repeating an id pays no second call. A refused
   call's receipt is read as before, a surplus, until the harness is
   measured.
3. **A receipt first seen too late after its call was named missing
   pays nothing.** The memory at the receiver keeps, per session, each
   call id a settled look named missing and when, and when a receipt
   paying it was first seen, by the reader's own looks and never the
   chain's timestamps. One first seen more than
   `SUPERVISOR_LATE_RECEIPT_SECONDS` after the naming look (one hour;
   0, 1 hour and 6 hours the panel) pays nothing, and the session keeps
   its finding until acknowledged. Inside it, an honest tail re-sent
   after a failed send still clears. A memory that cannot be read
   reads as before and says so.
4. **A copy carrying the `second-record-cut:` note is never before
   memory** (#486 item 11). Its dates are the writer's, and the note
   exists only since the pin did.
5. **Events naming no completed call are no second record.** One
   event posted through the URL for a session with receipts and no
   events read every receipt as surplus. A settled session whose events
   hold no `tool_result` while its copy holds receipts reads
   `SECOND-RECORD-ABSENT`.

What it still does not claim: a receipt posted through the URL inside
the grace period pays the call it names, and a receipt naming any MCP
tool pays a call the events name `mcp_tool`.
