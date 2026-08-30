# ADR-0014: The day book — per-day history beside the baseline, and it counts looks

**Status:** accepted 2026-08-30 (built first in PR #56, ratified here)

## Context

ADR-0013 deferred this by name: *"Kuma's signature strip needs per-scan
history the baseline does not retain; growing the baseline into a time
series is its own decision for its own day."* This is that day.

Two pressures arrived together while redesigning the front page against
*The Big Book of Dashboards* (Wexler, Shaffer & Cotgreave).

**The third question.** The book's server-monitoring scenario (Ch. 18)
is close to a specification for this surface: an audience of one,
read each morning, answering *what failed, which ones, and is this a
trend or a one-off*. The strip answered the first two. The third was
unanswerable — the baseline remembers heads, not days, and nothing on
the machine remembered what yesterday looked like.

**The sharper one.** Ch. 32 warns that a dashboard which always says
the same thing teaches its answer and then goes unread. A tripwire is
*designed* to read quiet. That is a direct threat to the only claim we
make: detection latency is a function of how often the operator
actually looks, and a page that reads "all quiet" every morning for a
year will stop being opened. The chains cannot report that failure,
because the thing that stopped working is the reading of them. It is
the one hole with no alarm behind it.

Both wants are the same want: the supervisor needs to remember its own
days, including the days nobody asked it anything.

## Decision

> **The supervisor keeps a day book: one row per UTC day in
> `.supervisor-daybook.json`, beside the baseline and never inside it,
> recording that day's worst claim, its counts, and how often the front
> page was opened. It shares the baseline's posture exactly —
> writer-reachable, trusted for nothing, owning no verdicts — and it
> never raises an exit code.**

The ratified shape, recorded because the trade-offs were argued:

- **The day's worst is sticky.** A tripwire that fired at 09:00 still
  colours the day at 17:00. "Was today clean?" is a different question
  from "is it clean right now?", and the strip above already answers
  the second. A day cell that forgets what fired in it answers neither.
- **Looks are recorded, not just scans.** Opening `/` increments the
  day's `looks`. This is the Ch. 32 defence and the reason the artifact
  exists at all rather than being a counter bolted onto the baseline.
- **An unwatched day is drawn as absence, never as quiet.** A day with
  no scan carries no claim in the report — no worst, no counts — and
  the band hatches it. A day nobody read is not a day that was fine.
- **Gaps only count after the first watched day.** A fresh install is
  not scolded for the fortnight before it existed.
- **Bounded by date, not by row count.** A season (90 days). A book
  that went unwritten for a year should forget that year, not keep it
  because it happens to be short.
- **Bookkeeping stays out of the report.** The scan tally and
  last-scan stamp live on disk and are never projected. They move every
  tick, and a report that changes when nothing changed would break the
  one invariant worth having here: two looks at an unchanged store say
  the same thing, printed or served.

## Consequences

- The front page can answer Ch. 18's third question, and the fortnight
  band has something true to draw.
- **The supervisor now observes the operator, not only the writer.**
  That is a new kind of thing for this tool to record and deserves
  saying plainly: it is local-only, never leaves the machine (the
  localhost posture is unchanged), and it is testimony about somebody's
  reading habits, not about any chain. It earns its place because the
  operator's attention is load-bearing for our one claim.
- One more writer-reachable file. An adversary can forge a tidy run of
  watched, quiet days. This changes nothing — the day book decides no
  verdicts, exactly like the baseline, and anchors remain the only hard
  boundary (ADR-0002 stands unamended).
- **A day is a UTC day.** An operator working late in a western
  timezone sees that work land in the next cell. The working-hours heat
  map, which exists to answer a local-calendar question, converts in
  the browser instead — so the page holds two notions of "day" at once.
  Accepted for now because the band's job is coarse (was this day
  clean, was it read) and UTC keys are stable across DST. Revisit if
  the band ever reads wrong to the operator looking at it.
- Store growth is bounded and trivial: ~90 small rows per machine.

## Alternatives considered

- **Grow the baseline into a time series** — rejected: the baseline has
  one job, remembering heads so the next look can diff them. Bolting an
  unrelated series onto it couples two lifetimes and two retention
  policies into one file, and the baseline's "unreadable means remember
  afresh" recovery would silently discard the history too.
- **Derive the history from the chains** — rejected, and this is the
  load-bearing rejection: chains record what the writer did, not what
  the supervisor saw. From the chains alone, a day with no scan and a
  day with a clean scan are identical. That distinction is the entire
  point of the artifact.
- **Record counts but not looks** — rejected: that answers Ch. 18 and
  leaves Ch. 32 invisible, which is the more dangerous of the two
  because it has no alarm behind it.
- **Append every scan instead of folding into days** — rejected on
  arithmetic: `serve` scans on a 30s poll, so a scan log grows by
  roughly 2,900 rows a day to feed a band that renders fourteen cells.
- **An ADR before building** — not taken. The operator chose to build
  first and ratify after; recorded here so the order is on the record
  rather than implied.
