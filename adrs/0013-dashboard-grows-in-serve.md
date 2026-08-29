# ADR-0013: The dashboard grows inside `serve`; no separate viewer

**Status:** accepted 2026-08-29 (grilled; issue #48)

## Context

The operator wants a dashboard that flags what needs attention so
nobody digs through chains by hand — and wants it "as practical and
pleasing to the eyes as possible." The tempting shape is a separate
viewer: its own code over the `scan --json` contract, free of the
stdlib constraint. The seam is real — a viewer that renders scan's
JSON inherits the trust story without touching it, since verdicts come
from `verify` and the WebCrypto walker stays the independent check.

Prior art settled the capability question: Healthchecks ships its
dashboard as a single page of plain HTML/CSS/JS with no build step,
and Uptime Kuma — the aesthetic bar for this category — earns its
looks from design decisions (status tiles, one accent, a designed
dark theme), not framework weight. The ceiling on a stdlib page is
aesthetic effort, not capability.

## Decision

> **The dashboard is `serve`'s front page, grown in place —
> stdlib http.server, vanilla HTML/CSS/JS, inside supervisor.py. A
> separate viewer is deferred behind an explicit necessity test: it
> gets built when serve's plainness demonstrably falls short, not
> before.** (The same boundary discipline as ADR-0005 and ADR-0009,
> and the same rule the planned section applies to query features.)

The ratified shape, recorded here because the trade-offs were argued
(rendering details live on issue #48):

- **Alarm-first hierarchy.** A full-width verdict strip states one
  condition: red for the exit-3 tier ("not the recorded history") or a
  live completeness alarm; amber for unsuperseded BROKEN or a fresh
  tripwire event; green for all-quiet. The quiet state is *designed*,
  not empty — scan freshness always visible — because an alarm page
  that is ugly when calm trains the operator to stop opening it.
  Below: one tile per project (verdict chip, last recorded action,
  anchor state), then the recent-events ledger from the baseline.
- **Bundled navigation, per-project only.** A tile opens that
  project's timeline (sessions → entries → `show` with the walker,
  search within the project). Cross-project aggregation stays in the
  CLI (`search --all`) under the necessity test.
- **Freshness by polling.** The page refetches on a ~30s interval and
  displays the last-scan age; no push, no sockets — a flight
  recorder's cockpit can be thirty seconds behind, but never
  dishonest about it.
- **Terminal identity.** ASCII wordmark in the header, an ASCII
  elephant on the quiet state and (SVG-wrapped) as favicon. Two hard
  rules: decoration never carries information (art is aria-hidden;
  alarm states survive any font and any copy-paste), and no art in
  agent-facing output — the digest is injected into context windows,
  where every byte is somebody's token budget.
- **No heartbeat-history bars in v1.** Kuma's signature strip needs
  per-scan history the baseline does not retain; growing the baseline
  into a time series is its own decision for its own day.

## Consequences

- No second codebase, no packaging, no divergence risk between two
  surfaces disagreeing about what is alarming.
- "Auditable in an afternoon" keeps covering the surface operators
  look at most; supervisor.py grows, and the growth is HTML/CSS
  strings — bulk, not logic.
- The `scan --json` contract remains the boundary a future viewer
  would consume, so the deferral costs nothing structural.

## Alternatives considered

- **Separate viewer now** — rejected: a second codebase to keep
  honest, the walker's independent-check story to port, and it
  un-ships the single-file claim for the most-viewed surface — all for
  looks the stdlib page can reach with effort.
- **Both (serve as default, viewer as showcase)** — rejected on
  sight: two dashboards disagreeing about what's alarming is the one
  thing a cockpit must never do.
- **Live push (websockets/SSE)** — rejected: freshness displayed
  honestly beats freshness promised; stdlib SSE is possible but buys
  seconds on a page about minutes.
