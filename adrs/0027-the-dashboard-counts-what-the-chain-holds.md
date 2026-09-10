# ADR-0027: The dashboard counts what the chain already holds; the hook still records nothing new

**Status:** accepted 2026-09-10 (grilled against SigNoz; restated by the author)
**Deciders:** Acquiredl

## Context

The operator asked to borrow from SigNoz's dashboard and metrics — an
OpenTelemetry-native observability platform, seven panel types, a query
builder over a columnar store. SigNoz is the archetype of the territory
`.out-of-scope/001` named as not ours: *"'this session is erroring' is
health monitoring — observability-product territory, not flight-recorder
territory."*

Read precisely, that ruling binds **the hook**. Its subject is what the
writer is made to record on every tool call forever, and its argument is
that changing the writer to prettify the reader inverts the dependency.
It says nothing about what the *reader* counts from fields the chain
already carries. The distinction is the whole of this decision, and it
was not obvious enough to leave implicit — a future reader who finds a
tool histogram on the front page and that document in the same repo is
owed the seam between them.

The counting also arrived long before it was named. The consumption
watch (ADR-0016, GLOSSARY: *Consumption watch*) already counts entries
per session per hour against the store's own median. The day book
(ADR-0014) already counts looks per day. `activity_root` already buckets
ninety days of receipts per repo per hour to draw the working-hours map
and the drawer sparklines. Every one of those is an aggregate over
fields already on the chain, and none of them asked the hook for
anything. What this ADR adds is the rule they were built under.

**Prior art, both sides of the line.** Sigstore's Rekor is the closest
structural cousin — a hash-linked log whose operators need to know it
has not been rewritten. Its public surface is entry search and inclusion
proof, with no metrics panels; aggregate analytics arrived years later
as a separate BigQuery research dataset, deliberately *not* the operator
surface. Git is the other: `git log` and `gitk` render provenance and
nobody has ever shipped a throughput chart beside them. SigNoz sits on
the far side because its data has magnitudes worth aggregating —
latency, tokens, error rates — while a provenance log's data mostly has
identity. Mostly, but not only: *when* and *how many* are magnitudes,
and they are already on our chain.

ADR-0014's own argument cuts toward counting rather than away from it.
Detection latency is a function of how often the operator actually
looks, and a page that always says the same thing teaches its answer and
then goes unread. A tripwire is designed to read quiet. Content on quiet
days is not a distraction from the alarm — it is what keeps a human in
front of it.

Grounding, on the author's real store at the time of the grill: ten
drawers, sixty chains, 9,286 receipts, and a norm of fifty-two receipts
in a busiest hour across fifty sessions.

## Decision

> **The dashboard can count anything the chain already holds. Counting
> is not recording: the hook records nothing new, and
> `.out-of-scope/001` stands unamended. What is counted is testimony
> like everything else recall renders, and owns no verdicts.**

The ratified shape, recorded here because the trade-offs were argued
(rendering details live on the issue):

- **Activity becomes a tab.** It moves out of the second pane's
  inspect/activity toggle to a fifth tab beside sessions, projects,
  search and evidence — honest about the weight it now carries, and
  twice the width, which is what makes a grid possible at all.
- **One screen, no scroll, at 1440x900.** A physical cap rather than a
  numeric one, because a tab that scrolls is a tab that gets skimmed,
  and because numbers get argued up by half a panel. The cap binds the
  incumbents too: the receipts-per-session chart is cut, being a bar
  drawing of the receipts column already on screen beside it, with no
  norm to compare against.
- **Seven panels, and no headroom.** The tally, tempo against the norm,
  looks per day, the histogram, files touched, working hours, and
  sessions on one axis. The next panel displaces one of these.
- **Every panel names its own window; no global range picker.** The
  fortnight band and the ninety-day buckets are chosen shapes, not
  defaults someone forgot to expose, and the sessions tab already
  carries repo, from, to and path filters for exploration. A picker
  that some panels quietly ignored would be the page lying about what
  it is showing, which is the one thing ADR-0013 says a cockpit must
  never do.
- **The histogram gets its own key function.** `histogram_key` stays
  unparameterised and fails closed on the export path, where names
  leave the machine (ADR-0021). Three lines of duplication cost less
  than a switch on the code path whose value is that it has none.
- **Files touched folds the worktree prefix, and nothing else.** File
  references are already project-relative (ADR-0012), so the only
  splitting is subagent worktrees writing
  `.claude/worktrees/<name>/<path>`. Folding that prefix moves
  `supervisor.py` from seven scattered rows to one, and from 79
  receipts to roughly 350. A path the rule does not recognise is shown
  as itself, never quietly rewritten.
- **The density strip, not a waterfall.** SigNoz's waterfall works
  because a trace holds tens of spans; session `80f00b1e` holds 3,721
  receipts. What survives translation is the question — what shape did
  this run have, and where was the burn — answered as a band in the
  inspect pane: receipts bucketed across the session's span, the peak
  marked, the owed tail hatched as the gantt already hatches it.
- **The hot flag gains gradation before settability.** A session at 713
  against a bar of 153 and one at 155 against 153 currently wear the
  same word. Distance past the bar is shown. `SUPERVISOR_HOT_TIMES` and
  `SUPERVISOR_HOT_FLOOR` remain the only place a threshold is set, and
  are surfaced on the panel — an environment variable is the one place
  the page, the CLI and CI all already read, and a value set in the
  browser would fork them.
- **Named views live in a sibling dotfile** in the day book's posture
  exactly: writer-reachable, trusted for nothing, owning no verdicts,
  never raising an exit.

## What none of this survives

- **A count is never a verdict.** No panel here raises the scan exit,
  and none may. Verdicts come from `loxodonta verify`, as they always
  have.
- **No view may touch the alarm.** A named view filters the worktable
  and nothing else — never the rail, the status strip, or the attention
  list. A saved view that *could* hide an alarm is one that eventually
  will.
- **Counting is not inference.** No scoring, no derived quality metric,
  no panel that says a session went badly. Every number here is a count
  of something the writer already stamped, and inherits the writer's
  semi-trust.
- **The hook stays blind to `tool_response`.** No outcomes, no exit
  codes, no success flags. `.out-of-scope/001` keeps its own reopening
  clause: field evidence, and a full ADR of its own. This is not that
  ADR.
- **The export's allowlist is untouched.** Nothing here changes what
  leaves the machine.

## Consequences

**What gets easier:**

- The page gains a reason to be opened on a quiet morning, which is the
  mechanism ADR-0014 identified as the only defence against the one
  hole with no alarm behind it.
- The rule the existing aggregates were already built under is written
  down, so the next panel argument is about the panel rather than about
  whether counting is allowed at all.
- Files touched, once folded, reports something true and slightly
  uncomfortable about the operator's own workflow that no other surface
  shows.

**What gets harder or more constrained:**

- **Positioning.** A page that looks like a small observability product
  invites the comparison on that product's axes, where this tool loses
  every one. The defence has to stay visible in the panels themselves:
  they count *the recording*, not the system being recorded. If that
  stops being legible, the panels are wrong, not the framing.
- **The histogram is a near-constant.** On the author's store, Bash,
  Edit and Read are 83% of 9,286 receipts, and that shape will not move
  for months. It is admitted as a recording-health panel — watched for
  when its shape *changes*, which is what a broken adapter or a
  switched harness looks like — not read for what it says. If it never
  earns a second look, it is the first candidate for displacement.
- `supervisor.py` grows again under ADR-0009's readability constraint.
  The file is past six thousand lines; the split question is closer
  than it was.
- A third operator-side file to explain, after the baseline and the day
  book.

## Alternatives considered

- **Tighten instead, following Rekor and git** — rule the surface
  search-and-verify only and shrink the existing activity view.
  Rejected: it is the strongest claim available about what the tool is,
  and it throws away ADR-0014's answer to the unread-page problem,
  which is the only failure mode the chains cannot report.
- **A fifth admission question ("is the recording healthy?")** —
  rejected as a hedge. It would have admitted the same panels while
  pretending to a narrower rule, and a rule that admits everything it
  was written to exclude is worse than the honest wider one.
- **A full global time range picker** — rejected: it duplicates filters
  that already exist and puts a control over bands that were chosen.
  The half-measure, a picker some panels ignore, was rejected harder.
- **Page-editable thresholds** — rejected for now: the value is read by
  `scan` from the CLI and in CI, and an environment variable is the one
  place all three surfaces already agree. Revisit if gradation turns
  out not to be the actual fix.
- **Leave activity in the second pane** — rejected: it is a fine home
  for five charts and a poor one for seven, and the half-width column
  is what forced the vertical stack that made the cap unreachable.

## References

- `.out-of-scope/001-outcome-capture-in-hook.md` — the ruling this one
  confines rather than amends.
- ADR-0009 (recall lives in the supervisor), ADR-0012 (file references
  rebase to project root), ADR-0013 (the dashboard grows in serve),
  ADR-0014 (the day book), ADR-0016 (coverage goes wide), ADR-0021 (the
  export is allowlisted).
- *The Big Book of Dashboards*, Wexler, Shaffer & Cotgreave — Ch. 18
  (the server-monitoring scenario) and Ch. 32 (the dashboard that
  teaches its own answer), already load-bearing in ADR-0014.
- SigNoz — seven panel types, a query builder, RED metrics over a
  columnar store; the borrow's source and the boundary's test case.
- Sigstore Rekor — search and inclusion proof as the operator surface;
  aggregate analytics kept deliberately separate.
