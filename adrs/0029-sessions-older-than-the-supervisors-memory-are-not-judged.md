# ADR-0029: Sessions older than the supervisor's memory are not judged (ADR-0016 ruling 2 completed)

**Status:** accepted 2026-09-11 (restate-to-ratify passed)

**Deciders:** Acquiredl

## Context

ADR-0016 ruling 2 promised that a matcher change manufactures no scars:
"the witness judges each session against the matchers in force at that
session's time, as best the supervisor observed them." The mechanism is
`calibrate()`, which remembers each observation of the wired matchers,
and `matchers_at()`, which picks the newest observation not after a
session's timestamp.

There is one era the mechanism cannot see, and it is the era before the
mechanism existed. `calibrate()` writes its first observation as
`{"since": null, "matchers": [...]}`, and `matchers_at()` hands that
epoch to every earlier timestamp on the rule that "the first observation
covers all time before it." The calibration memory on the author's
machine was born *after* `install-hook` had already widened the matcher
to `*`, so it never observed the narrow era at all. Every session
recorded under `Edit|Write|NotebookEdit|Bash|PowerShell` is therefore
judged by `*`, and the deficits that produces are the ones ADR-0016
promised would not appear.

The store says so plainly. The baseline holds exactly one calibration
epoch, `{"since": null, "matchers": ["*"]}`. The witness holds 171
transcripts — 62 from July, 59 from August, 50 from September — against
66 chains. Issue #114 walked two of the deficit sessions against their
transcripts: every large gap was a tool the narrow matcher never covered
(`Read`, `Grep`, `PowerShell`, MCP calls), while the tools it did cover
agreed to within a handful. Sessions recorded after coverage went wide
on 2026-08-31 show no deficit on covered tools at all.

The rule reaches further than the narrow era. Roughly 95 witnessed
transcripts on this machine have no chain whatsoever — July sessions
from before the hook existed, and sessions from clients that fire no
hooks. Each reads `ENDED-DEFICIT` with nothing received. A stranger who
installs today and exports tomorrow sends the same picture: their entire
pre-install history rendered as loss. That is what blocks issue #135,
because it is the first question any reader of a field-data export asks.

`sessionend_epoch()` already states the principle its sibling breaks:
"the supervisor claims no knowledge older than its own memory ...
everything earlier is uncommitted by history, not by misbehavior." The
calibration epoch says the same sentence in its docstring and then does
the opposite.

Two dates settle what an honest floor can be. The day book's first day
is 2026-08-30; coverage went wide on 2026-08-31. So the day book bounds
when the supervisor began *looking*, not when the matchers became what
they are now, and using it as the first epoch would assert that `*` was
in force on a day it was not. The settings file's mtime is worse: it
reads 2026-09-10 here, nine days late, because unrelated edits touched
it. Neither is evidence. There is no date on this machine that says when
the calibration memory began, because nothing ever wrote one down.

Prior art consulted. **OCSP** answers good, revoked, or *unknown*, where
unknown means the responder holds no record for that certificate — a
third answer that is explicitly not a bad verdict, which is this
situation's shape exactly. **Nagios** and its descendants keep `UNKNOWN`
beside OK, WARNING and CRITICAL for a check that could not determine an
answer, rather than folding it into a failure. **Prometheus** renders no
data instead of zero, and the alerting convention built on it declines
to fire on an incomplete first window — the same instinct ADR-0014
already cites from the Big Book of Dashboards, where charting an absent
series as zero is the classic dashboard lie. **Git** permits asserted
history through replace objects and grafts, and makes the assertion
visible to anyone who looks. **DFIR practice** keeps analyst annotation
in a separate layer from collected artifact, permanently. The first
three converge on separating "I looked and it is bad" from "I cannot
say"; the last two on letting an operator assert what the instrument
missed, so long as the assertion is marked as one.

## Decision

Ratified restatement, in the author's words: *sessions older than the
supervisor's memory aren't judged.*

1. **The first calibration observation is stamped with the moment it is
   made.** No more `null`. A store whose first epoch is already `null`
   has it stamped on the next scan, which is the whole migration. This
   matches `sessionend_epoch()`, the pattern's other use, and it invents
   no dates: not the day book's first day, not the settings file's
   mtime, neither of which is evidence of when coverage became what it
   is.

2. **A session whose first witnessed event precedes that epoch is
   `BEFORE-MEMORY`** — a completeness state of its own, not an
   annotation on `ENDED-DEFICIT`. Evidence, not deficit. `ENDED-DEFICIT`
   says in its own words that "those receipts are missing forever", and
   for a session from before the memory that is a claim the supervisor
   cannot support.

3. **The state applies to the whole session, live or ended, and the
   session is never truncated at the boundary.** The first event decides,
   not the last. A session already running when the memory begins is
   unjudged for its whole life, however long it runs.

4. **`BEFORE-MEMORY` never renders as a row.** One counted block states
   it instead — the count, the epoch, and the words — on the scan's
   watch, in the dashboard beside the calibration note, and in both the
   field-data export and a package's `witness.json`. A flag on `scan`
   lists the sessions anyway, for the operator who wants to look.

5. **The boundary is the epoch and nothing else.** A session recorded
   *after* the epoch with tool calls and no receipts keeps
   `ENDED-DEFICIT`. That picture is the completeness alarm working:
   a harness that fires no hooks and a hook an attacker killed produce
   identical evidence (ADR-0002), and a tool that learns to shrug at one
   has disarmed itself against the other.

6. **`supervisor calibrate --since <ts> --matchers <m>` seeds what the
   operator knows and the supervisor could not see.** It inserts an
   epoch before the first observed one. It may not touch observed time —
   a hard refusal, no `--force` — because observed time is the one part
   of the calibration memory that is not testimony. The inserted epoch
   is marked as operator-stated in the baseline, permanently, and any
   surface that judged a session by a seeded epoch says so.

7. **Calibration becomes a glossary term.** ADR-0016 has owned the word
   since it was written while `GLOSSARY.md` only pointed at it, and a
   state named for the edge of the calibration memory cannot be the
   thing that finally defines it.

## Consequences

**What gets easier:**

- A field-data export stops reporting a stranger's pre-install history
  as loss, which is what issue #135 needed before outside readers see
  one. The export now says the store predates its own supervisor — true,
  and the first thing a reader needs to know.
- The completeness alarm keeps its meaning. ADR-0014's dashboard rule is
  that a surface showing false scars teaches its operator to distrust
  scars; the wall of pre-memory deficits was exactly that surface, and
  it sat on the flagship claim.
- The `null` first epoch is gone, so the calibration memory now states
  its own inception rather than implying an infinite one.

**What gets harder or more constrained:**

- The author's store stamps its first epoch on the next scan, so the
  August judgments go quiet until they are seeded back. That is the cost
  of inventing no dates, and ruling 6 is the way to pay it.
- A session already running when the supervisor's memory begins is
  unjudged for its whole life, including a live one. On a fresh install
  that is one session, and it resolves when the session ends. The
  alternative — judging it by today's matchers — fires the flagship
  alarm on a session that never owed a receipt, minutes after install.
- The dashboard carries two hard-coded state lists in its JavaScript and
  a package carries `WITNESS_FIELDS`; `BEFORE-MEMORY` has to stay out of
  all three and live only in the new block.

**What we'll have to revisit if:**

- A harness arrives whose sessions are legitimately unrecordable and
  recent. Ruling 5 holds the line at the epoch on purpose, and the
  answer for such a harness is an adapter (ADR-0020), never a quieter
  alarm. Antigravity's hooks are the live example: a different payload
  shape, reachable by a spoon.
- Seeding turns out to be something operators get wrong often enough
  that the hard refusal costs more than hand-editing a writer-reachable
  baseline would. Nothing suggests that yet, and the seam it protects is
  the reason.

## Alternatives considered

- **An annotation on `ENDED-DEFICIT`, like the uncommitted tail.** Keeps
  the state machine at its current size. Rejected: the state's own words
  contradict the annotation, and `state` is the field every reader of an
  export or a `witness.json` sorts on, so the annotation would be the
  half nobody reads.
- **The day book's first day as the first epoch.** Convenient, and it
  would have kept September's judgments intact with no seeding. Rejected
  on the merits above: it asserts `*` was in force on 2026-08-30, which
  is false by one day, and a rule with an invented date in it is worse
  than a rule that admits ignorance.
- **The settings file's mtime.** Already used to date a *change*, so the
  symmetry is tempting. Rejected: it reads 2026-09-10 on this machine
  because unrelated edits touched the file, making it a worse floor than
  the day book and a far worse one than now.
- **Suppressing pre-epoch events inside `read_witness`, judging the
  straddling session on the part the supervisor can see.** Fits the
  existing per-event `matchers_at` design. Rejected: receipts pair with
  witness events positionally, so dropping early events while keeping
  every receipt turns the session into a false `SURPLUS`, and filtering
  the receipts too would mean deciding which entries count by reading
  the writer's own timestamps — the thing ADR-0002 exists to refuse.
- **The name `UNCALIBRATED`.** Names the mechanism and fits the `UN-`
  family beside `UNWITNESSED` and `UNWATCHED`. Rejected on how it reads
  to the stranger it was designed for: ninety-five sessions marked
  uncalibrated reads as a defect in their setup, which is the distrust
  ADR-0014 warns about. `BEFORE-MEMORY` reads as a fact about time.
- **An inline addendum to ADR-0016.** The repo does this for corrections
  of fact (ADR-0017, ADR-0020, ADR-0025). Rejected here because this is
  seven rulings including a state and a command, and when a ruling
  changed the repo has written a new ADR that names what it amends
  (ADR-0025, ADR-0028).

## References

- ADR-0016 (coverage goes wide; ruling 2 completed here, rulings 1, 3
  and 4 unchanged)
- ADR-0002 (the writer as adversary; why ruling 5 holds the boundary and
  why ruling 6 refuses)
- ADR-0018 (`sessionend_epoch`, the calibration pattern's other use and
  the sentence this ADR makes true of both)
- ADR-0014 (the day book, and the dashboard rule about false scars)
- ADR-0021 (the field-data export's allowlist, which the count joins)
- ADR-0026 (`witness.json` in a package)
- Issue #114 (the report, with the two walked sessions)
- Issue #135 (outside readers and the first field data; unblocked by
  ruling 4)
