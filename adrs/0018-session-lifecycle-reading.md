# ADR-0018: The session lifecycle reading — dormancy, reawakening, and the tail keeper

**Status:** accepted 2026-09-01

## Context

Two ideas arrived within hours of each other, both from the first
consumer test case (the todo build, 2026-09-01). Issue #96: the build
session ended without its exit commitment — and the investigation
found why: Claude Desktop's Code mode offers no reliable clean exit
(no `/exit`; SessionEnd behavior undocumented and known-buggy
upstream), so ADR-0017's tail commitment fires dependably only under
the terminal CLI, and "ended without goodbye" is the *common* case on
a whole client population. Issue #97: the operator proposed dormancy
tiers over sessions and a flag when a dormant session starts recording
again — several quiet days, or someone riding an old hanging session
under its accumulated context (ADR-0002's adversary, resuming).

Both are readings of a session's temporal state. Both need the same
disciplines: the false-scar avoidance ADR-0016 taught, the
effective-dating its calibration invented, and the which-clock honesty
issue #85 settled for liveness (file mtime lies; harness metadata
appends re-present ended sessions as live).

Prior art consulted: **systemd** (unit state `active`/`inactive`, with
the *exit reason* — clean vs killed — carried as a sub-annotation of
inactive, not a state of its own; the sharpest fit); **Nagios/Icinga**
(one host-state axis plus a separate flapping detector layered over
state *history*; freshness checks deliberately use the **server's**
clock because a compromised agent lies about its own liveness);
**Prometheus** (`up` as the state gauge, alerts as expressions over
its history). All three converge: one lifecycle state, with
change-events read as expressions over the watcher's own record of it.

## Decision

Ratified restatement: *we designed a system that detects the missing
tail — and, in the same ruling, the thing that fixes the gap it
detects.*

**1. One reading, not two features.** The *session lifecycle* unifies
both issues: **dormancy** is the state axis, **reawakening** is the
one event read over it, and the **uncommitted tail** is a terminal
annotation — systemd's shape (state + exit-reason), not two bolted-on
watches.

**2. Two clocks, split by job.** Displayed ages render from writer
timestamps and wear recall's testimony label. The lifecycle *state*
and the reawakening *event* are decided by **observation epochs**: the
baseline remembers, per chain, the scan-time at which the supervisor
last saw the head advance (`last_grew` — the reader's own diary of its
looks, the day book's trick applied per chain). The adversary can
forge every `ts` it writes; it cannot redate the watcher's memory of
when the watcher looked. Stated cost: resolution is scan cadence, and
a week nobody scanned is indistinguishable from a week of stillness —
the day book already draws that honesty as unwatched gaps.

**3. Hybrid tiers.** The state is flat and legible: **awake** (0–24h
of observed stillness) → **waning** (24–48h) → **dormant** (48h+),
env-tunable, defaults *not frozen until measured* — the build's first
step measures the real store's intra-session gap distribution into
EXPERIMENTS.md (the consumption watch's lesson: its first cut flagged
6 of 29 honest sessions because nobody measured first). The *event* is
gated at the dormant tier only, never the waning band. Session-level
only; repo-level quietness stays the project tiles' "last activity".

**4. Reawakening.** Fires when a scan's baseline diff shows the head
*advanced by clean appends* after dormant-tier observed stillness.
`rewritten`/`regressed` diffs never fire it — the tripwire owns those
screams, and double-firing would dilute both. One-shot, reported by
the scan that saw it, counted by the day book, spoken in the
investigate voice ("grew after N days of observed stillness — several
quiet days, or someone riding an old session; yours to tell apart"),
and it never touches the exit code.

**5. The uncommitted tail.** An annotation on ended sessions whose
chain's last entry is a tool receipt rather than a commitment — not a
state, not an event. A session ending exactly on a cadence commitment
counts as covered (the ambiguity is accepted: functionally the tail
is committed, and the check stays one honest line). Effective-dated,
the calibration pattern's third use: the witness remembers since when
SessionEnd was wired, and only sessions after that epoch carry the
annotation — everything earlier is uncommitted by history, not by
misbehavior. Wording is neutral fact ("tail uncommitted — no exit
commitment recorded"), never alarm-styled: on Claude Desktop this is
the common case, and a wall of scars teaches operators to stop
reading.

**6. The tail keeper — the fix beside the detector.** On its scan
tick, for any session that is idle-ended with an uncommitted tail and
a still-present transcript, the supervisor writes the exit commitment
itself, through the recorder's own machinery — same pinned grammar,
same `receipts` voice, chain lock held, silent skip when the harness
has already cleaned the transcript. A commitment is honest whenever
it is taken: it commits the bytes as they are now, and monotonicity
holds. This shrinks the forever-open desktop tail to one scan
cadence, and demotes the annotation from common to rare — marking
only what the keeper couldn't reach. Default on, env knob to disable
(ADR-0017's reasoning: protective recording does not ask permission).
Named boundary extension: ADR-0005's supervisor has taken protective
action before (the anchor keeper), but this is the first time its
tick **appends to a chain**. The trust story survives because a
transcript commitment was always writer-grade bookkeeping — testimony
protected by the chain, judged only by `verify` — and the keeper adds
nothing the recorder itself wouldn't have written on a clean exit.

**7. Surfacing.** Completeness session rows gain `dormancy` (tier +
observed-still-since) and the `uncommitted tail` annotation (absent
for pre-epoch sessions — silence, not judgment). Reawakenings get
their own top-level `lifecycle` key — never folded into
`baseline.events`, whose words mean "appends cannot explain this"
while a reawakening is precisely appends explaining everything. The
dashboard ranks reawakenings in the attention queue below `hot`
(a loop burning now outranks a session that stirred), details them in
the evidence tab, and shows dormancy as at most a dimmed tag. The day
book counts reawakenings in its own field. The digest is untouched —
recall is memory, not monitoring. The scan exit code never moves.

**8. Names.** *Session lifecycle*, *awake/waning/dormant*,
*reawakening*, *uncommitted tail*. "Unsealed" is rejected — *seal* is
ADR-0007's word for outer commitments, the glossary already anti-uses
it for transcript commitments, and #79's own docs drifted ("the tail
is sealed on clean exits"); the build cleans HOOK.md's wording to
*tail commitment* and adds the client-dependence honesty (reliable
under the terminal CLI; undocumented on Claude Desktop). "Active" and
"idle" were rejected as tier names: both already belong to the
completeness watch's vocabulary.

## Why not the alternatives

- **Two separate features** — same inputs, same disciplines, same
  surface; two bolt-ons would disagree eventually.
- **Writer timestamps as the deciding clock** — hands the adversary
  the mute button for the exact signal meant to catch them (#85's
  lesson generalized; Nagios/CT unanimity).
- **Rhythm-relative tiers** — statistically elegant, but the state
  becomes unstable (other sessions' behavior re-tiers this one) and
  unexplainable in a sentence; rhythm stays available for tuning the
  thresholds the flat tiers use.
- **A flat 48h event with no measurement gate** — the consumption
  watch already paid for this lesson.
- **Folding reawakenings into baseline events** — dilutes the
  tripwire's meaning ("appends cannot explain") with its exact
  opposite.
- **Recorder-side fix only (shrink the cadence)** — a smaller N
  shrinks the tail but never closes it, doubles chain bloat well
  before it helps, and does nothing for a session that dies between
  boundaries. The keeper closes it from the side that outlives the
  session.

## Consequences

- The baseline schema grows (`last_grew` per chain; a SessionEnd
  wiring epoch beside the matcher calibration). First scan after
  upgrade seeds `last_grew` from current observation — no session can
  reawaken until stillness has actually been *observed*, so the
  upgrade manufactures no events.
- `scan --json` gains additive fields (`dormancy`, the annotation,
  the `lifecycle` key) — contract growth, mirrored in the dashboard.
- The keeper's commitments may include post-exit harness metadata
  bytes in the committed prefix — honest: it commits what is there.
- Residue, stated: a session hard-killed and never scanned before its
  transcript is cleaned keeps its tail uncommitted forever; the
  annotation is exactly the record of that.
- Build slices: (1) observation-epoch memory + tiers + annotation +
  the measurement gate; (2) reawakening event + surfaces + HOOK.md
  wording cleanup; (3) the tail keeper.

## References

- Related ADRs: 0002 (the adversary who would ride an old session),
  0005 (the supervisor boundary this consciously extends), 0014 (the
  day book — the reader's diary of its own looks, generalized here),
  0016 (false scars; effective-dating), 0017 (the tail this closes).
- Issues: #96, #97 (both carry the field findings that forced this);
  #85 (the which-clock lesson); the todo test-case audit, 2026-09-01.
- Prior art: systemd unit states + exit reason; Nagios/Icinga
  freshness and flap detection; Prometheus `up` + alert expressions.
- Glossary terms added: *Session lifecycle* (with awake / waning /
  dormant, *reawakening*, *uncommitted tail*).
