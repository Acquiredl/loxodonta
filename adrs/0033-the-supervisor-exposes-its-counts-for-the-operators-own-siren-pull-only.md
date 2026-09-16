# ADR-0033: The supervisor exposes its counts for the operator's own siren, pull only; the dashboard is held

**Status:** accepted 2026-09-16 (grilled; restated by the author: *metrics route pull only, hold the dashboard*)
**Deciders:** Acquiredl

## Context

The operator asked for one of two things: a stronger local dashboard, or
compatibility with the monitoring stacks people already run, Grafana and
Elastic by name. The dashboard has been grown twice under a necessity
test (ADR-0013: it gets more when its plainness demonstrably falls
short; ADR-0027: it may count anything the chain already holds), and the
ask named no gap it fails. The other half sits against a written
boundary: `.out-of-scope/001` calls health monitoring "observability-
product territory, not flight-recorder territory", and ADR-0027 drew the
seam through it precisely. The hook records nothing new, ever; the
reader may count what the chain holds. A monitoring seam is on the
allowed side exactly as long as it renders those counts and nothing
else.

What `serve` already exposes settles the shape. Its `/api/status` route
returns the scan's JSON (baseline, completeness, consumption, lifecycle,
recorder, repos), and a JSON datasource can read it today. But every
panel built on it would encode our JSON's shape, which was never
promised stable, and a JSON blob cannot be alerted on by the tools that
page people.

Prior art. **Prometheus exposition** (OpenMetrics) is the vendor-neutral
pull format: Grafana reads it through Prometheus, Elastic through
Metricbeat's prometheus module, Datadog through its agent, and none of
them is named in the exporter's code. **Healthchecks.io**, the product
ADR-0013 modelled the dashboard on, exposes a Prometheus endpoint per
project rather than growing alerting of its own. **Tripwire** and
**AIDE**, the supervisor's namesakes, integrate with SIEMs by emitting
to syslog rather than by building consoles. **Go's `expvar`** is the
stdlib-served-diagnostics precedent ADR-0005 already leans on. Prometheus
`up` is the reading ADR-0018 borrowed for session lifecycle; here it
comes back as itself.

## Decision

> **`serve` answers `/metrics` in the Prometheus text format with the
> counts the scan already produces, as gauges, named by mechanism, each
> labelled verdict or testimony. Pull only: nothing is pushed to any
> vendor. The dashboard is held under ADR-0013's necessity test.**

1. **What is exposed: the scan, and only the scan.** Chains by verdict
   (`VALID`, `BROKEN`, `HEAD-MISMATCH`, `TRANSCRIPT-DIVERGED`), sessions
   by completeness state and by lifecycle state, sessions running hot,
   heads not yet anchored and not yet published, the age of the last
   scan, and the tally (drawers, sessions, chains, receipts). Every one
   is a number the scan or the dashboard already computes; the route
   adds no reading and asks the hook for nothing (`.out-of-scope/001`
   stands unamended, as ADR-0027 left it).
2. **Names say the mechanism; help lines say the grade.**
   `loxodonta_chains_broken`, never `loxodonta_tampering_detected`. Each
   `# HELP` line ends with `(verdict)`, `(witness verdict)` or
   `(testimony)`, the same honesty labels recall carries, so an operator
   reading the scrape knows which numbers came from `verify` and which
   from writer-stamped lines. Gauges only: the counts are the reading;
   the trend is the operator's time-series database's job.
3. **Pull only, on the loopback.** Nothing is pushed to Loki, Elastic,
   or anyone: a push needs a credential on the writer's machine and a
   vendor's wire in the supervisor, and this repo puts neither there.
   The route inherits `serve`'s posture, `127.0.0.1` and the `Host`
   check; reaching it from another box is the operator's tunnel or
   reverse proxy, as with the dashboard. A scrape that stops is itself
   the loudest signal, which is what `up` is for.
4. **Names are a public interface from the first release.** A metric,
   once scraped into someone's dashboard, is renamed by nobody. New
   metrics may be added; existing names and label sets do not change,
   and a metric that stops being meaningful is left in place and
   documented rather than removed. The list lives in one place in the
   code beside its help text, and `docs/` gets one page listing them.
5. **The dashboard is held.** No dashboard work in this arc. ADR-0013's
   test stands: it grows when its plainness demonstrably falls short,
   and no such shortfall was named. ADR-0013 also declined to grow the
   baseline into a time series; with a scrape, the operator's monitoring
   keeps the series, which is where it belongs, and the baseline stays
   what it is.
6. **What stands.** The scan owns the verdicts (`verify` behind it);
   the route owns none. The dashboard's alarm band and the `scan --json`
   contract are unchanged. MCP stays the agent-facing surface
   (ADR-0019); this route is for machines that page people.

## What none of this survives

- **The machine it runs on.** The supervisor is writer-reachable, and so
  is its scrape. A metric is the supervisor's reading rendered for a
  pager; a writer that can kill the supervisor can silence the route,
  which the scrape's absence shows and the numbers cannot. Verdicts
  still come from `verify` and its inputs, not from a gauge.
- **The reading between scans.** A gauge is as fresh as the last tick;
  `loxodonta_scan_age_seconds` says how fresh, and the operator's alert
  on it is the honest guard.
- **Anything the chain does not hold.** The route counts receipts, not
  outcomes, not health, not errors. "This session is erroring" remains
  somebody else's product.

## Consequences

**What gets easier:**

- "Works with Grafana and Elastic" becomes a true README sentence
  without either name in the code, and the operator's existing pager
  becomes the siren for a tripwire that only ever shouted on a page
  nobody was looking at (ADR-0014's failure mode, answered from
  outside).
- A killed supervisor is finally visible to something that pages.
- The trend question the day book approximates is answered properly by
  the operator's time-series store.

**What gets harder or more constrained:**

- Metric names are frozen on first release; a naming mistake is kept
  and documented, not fixed.
- One more route to keep honest as the scan's vocabulary moves: a new
  completeness or lifecycle state means a new label value and a doc
  line.
- A test through the public surface, the way `tests/test_serve.py`
  already starts the server: fetch `/metrics`, parse it, assert the
  labelled help lines and that every number matches `scan --json`.

## Alternatives considered

- **A stronger dashboard.** Held, not rejected: no gap was named, and
  ADR-0013's test is the standing rule.
- **Push to Loki or Elastic.** Rejected: a vendor's wire in the
  supervisor and a credential on the writer's machine, for a stack the
  operator can point at a pull route instead.
- **OTLP over HTTP.** Rejected: a heavier contract for the same numbers,
  and the OpenTelemetry Collector the operator would run can scrape
  Prometheus text already.
- **Document `/api/status` as stable and add nothing.** Rejected as the
  whole answer: it works for panels and not for alerts, and it would
  freeze the scan's JSON shape, which serves the dashboard first.
- **Histograms or summaries.** Rejected: the counts are the reading; the
  distribution over time is what the operator's store computes from
  gauges it already keeps.
- **Metrics from the recorder.** Rejected without discussion: the
  recorder is the writer's process and exposes nothing (ADR-0005).

## References

- Related ADRs: `0005-supervisor-as-sibling-tool.md` (stdlib-served
  diagnostics as precedent; the recorder exposes nothing),
  `0013-dashboard-grows-in-serve.md` (the necessity test; the time
  series declined), `0014-the-day-book.md` (the unwatched-page failure
  mode), `0018-session-lifecycle-reading.md` (`up` borrowed),
  `0019-recall-speaks-mcp-read-only.md` (the agent-facing surface, left
  alone), `0027-the-dashboard-counts-what-the-chain-holds.md` (the seam
  this route sits on).
- Out of scope, upheld: `.out-of-scope/001-outcome-capture-in-hook.md`.
- Glossary terms **added**: *Metrics route*.
- Prior art: Prometheus exposition and OpenMetrics; Healthchecks.io's
  per-project endpoint; Tripwire and AIDE's syslog integration; Go's
  `expvar`.
- Raised: the author, 2026-09-15 ("compatible with popular monitoring
  solutions like elastic or grafana"); grilled 2026-09-16.
