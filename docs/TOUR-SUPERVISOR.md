# A guided reading of supervisor.py

This document walks `supervisor.py` top to bottom, in file order, the way
a first reader meets it. It grew out of the 2026-08-31 readability walk
(issue #25) and is kept as reference documentation, the sibling of
[TOUR.md](TOUR.md): each section explains what the code does, what
controls what, and *why it was built that way*, with pointers to the
ADRs that hold the decisions.

It extends TOUR.md's restaurant. The recorder is the cook's ticket
spike; the supervisor is **the night watchman the manager hired** — he
patrols a warehouse of sealed boxes he is forbidden to open or repair.
He can only look, remember what he saw, and shout. Everything in this
file answers one question — how does a watchman stay useful when the
adversary can reach everything the watchman writes down? (ADR-0002,
ADR-0005: verdicts come only from `loxodonta verify`; everything the
supervisor holds is writer-reachable and decides nothing.)

The file reads in five walking clusters:

| # | Cluster | What it is |
|---|---|---|
| 1 | The patrol | Census, verdict runner, baseline, day book |
| 2 | The specialists | Anchor keeper; the completeness witness and recorder notice |
| 3 | The tick | `scan_root` assembly, `adopt`, exit codes |
| 4 | Memory | Recall core and the Stage E CLI (ADR-0009, ADR-0011) |
| 5 | The face & the drill | Fire drill; `serve` and the in-browser walker |

## 1. The patrol — census, verdicts, baseline, day book

One pass of the watchman's round, for one chain:

**Roll call.** The default census is a single glob over the store's
drawers (`~/.loxodonta/receipts/<slug>/receipts-*.jsonl`, ADR-0011),
inline in `scan_root`. `find_chains` is the *legacy* roll call — three
glob shapes over a `--root` folder of repos, kept because old layouts
still exist in the field. Identity is read from where a log lies and
what it is named: `split_seq` peels a `-002`/`-003` suffix into a
sibling sequence, because continuation is **by naming alone**
(ADR-0004) — nothing inside a sibling chain declares its parent.

**The inspector.** `verify()` is the single seam to the recorder
(ADR-0005): one subprocess per chain, `loxodonta verify --anchors`,
verdict read from the last stdout line. The supervisor never judges
bytes itself. Both ends of the pipe are pinned to UTF-8 because a
verdict lost to a codepage is a watchman who missed his one job. When
verify refuses without a verdict line, the supervisor reports
`NO-VERDICT` and quotes stderr — it invents nothing.

**The stand-down.** `superseded()` recognises exactly one damage shape:
a single torn *final* line with a sibling chain beside it. That is the
honest crash pattern ADR-0004 already handled — recording continued in
`-002` — so the **exit code** stands down while the BROKEN verdict
stays in the report as evidence. Any other shape (a mid-file tear, two
BROKEN lines, no sibling) shouts, sibling or not. Without this, the
scan becomes an alarm that never stops sounding, and an alarm that
never stops sounding is one that gets ignored.

**The baseline.** The tripwire's memory: every chain's last-seen head
(entry `n` + `entry_hash`), diffed each look. Three change words, a
closed vocabulary: **rewritten** (your old head is no longer in the
chain's history — change appends cannot explain), **regressed** (the
chain got shorter; receipts do not un-happen), **vanished** (was here,
gone). Every word carries the same suffix: *investigate — this memory
is writer-reachable and decides nothing*. That is ADR-0002's posture in
one sentence. The baseline detects; `verify` judges what exists; only
an **anchor** proves what existed — a regenerated chain verifies VALID,
and a vanished chain cannot be verified at all. An unreadable baseline
is replaced, never repaired: the supervisor builds no repair paths,
even for its own files.

**The day book (ADR-0014).** One row per UTC day, a 90-day season, a
14-day band on the front page. The day's `worst` is sticky — a tripwire
at 09:00 still colours the day at 17:00, because "was today clean?" is
a different question from "is it clean right now?". And the book counts
its own reads: the security claim is detection *latency*, latency is a
function of whether anyone looks, and a run of unwatched days is the
only shape that failure has. A day nobody watched paints as "history
went unread", never as a quiet day.

## 2. The specialists — anchor keeper, completeness witness, recorder notice

**The anchor keeper** absorbed the ritual the dogfood proved nobody
remembers: completing pending OpenTimestamps proofs. Each tick, at most
once per throttle window per chain, it drives `loxodonta anchor
--upgrade` for pending proofs, and — only when the operator opted in
with `--anchor-every` — submits a fresh head that has aged past the
cadence. Off by default: nothing leaves the machine without the say-so.
Two adversary details worth noticing. The throttle memory lives in the
writer-reachable baseline, so a timestamp *from the future* reads as no
memory at all — otherwise one edit stands the keeper down silently and
forever, which is exactly what an adversary would want from it. And a
turn can fail twice (a refused upgrade and a refused submission); every
failure stays said in the note, because evidence is not a scratchpad
where the last writer wins. Staleness is quiet evidence, never an exit
shout — a siren that never stops sounding trains the operator to ignore
the band.

**The completeness witness** is the flagship claim (issue #22): pair
what the harness transcript saw with what the chain received, per
session, and shout while the session is still live. Honest scope,
carried from the grill: this catches *accidents* — the disabled hook,
the wedged lock, the silent fork — and shortens the window between loss
and discovery. A writer shaping both the transcript and the chain is
beyond this alarm, and the code says so out loud.

Two field findings calibrate the count (2026-08-29): the witness counts
only tools the *wired matchers* cover (`hook_matchers` reads the
harness settings — an all-tools witness over an `Edit|Write|Bash` hook
manufactures deficits), and failed tool calls are skipped, because the
harness fires no hook for them and marks them with `is_error` on the
`tool_result` block, not on `toolUseResult`. So witnessed count equals
receipts owed, and a chat-only session can never alarm.

`classify` is the ratified state machine — a pure reading of the
evidence: OK / QUIET / LAGGING (a 30-second grace, because an honest
lock wait must never alarm) / ALARM-SILENT (recording stopped) /
ALARM-DEFICIT (the fork-shaped hole: receipts arrive, fewer than owed)
/ SURPLUS (an investigate flag, never a verdict) / ENDED-CLEAN /
ENDED-DEFICIT (missing forever; kept as evidence, not a siren) /
ENDED-SURPLUS (a surplus does not become clean by the session ending) /
UNWITNESSED / UNWATCHED. Deficit is sticky — lost receipts never
arrive later. One session is judged *once* even when its receipts span
drawers (a worktree session logs to the main repo's drawer, ADR-0011,
while the transcript is named after the worktree): the witness counts
sessions, not drawers.

**The recorder notice.** The harness executes a *path*, not a version —
the recorder running on this machine is whatever is checked out there
when a tool fires. The notice reports that state (branch, head, dirty,
ahead/behind as of the last fetch) and corrects none of it, reading
local git only: a recorder that updated itself from a remote would hand
the writer a second road to the one file that has to stay honest
(ADR-0002). Behind-counts name their fetch date, because a stale count
that reads as reassurance is worse than no count.
