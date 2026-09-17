# The metrics route: the supervisor's counts, for the siren you already run

**Status:** accepted 2026-09-16 (ADR-0033). This page is the list of every metric `supervisor serve` puts on `/metrics`, with its help line, its labels and the grade of evidence behind it, plus the rule that keeps the names still. Nothing here is a new reading: every number is one the scan already produces, which is why `scan --json` and the scrape can never disagree.

## 1. What the route is

The supervisor's alarm band lives on a page, and a page has one failure mode that the chains themselves can never report: nobody is looking at it (ADR-0014). Most operators already run something that pages people. So `serve` renders the scan's counts in the Prometheus text exposition format at `/metrics`, and Prometheus, Grafana, Elastic through its Prometheus module, an agent, or a bare `curl` in a cron job does the rest. None of those is named anywhere in the code, and none of them needs to be: the format is the seam.

Three things it is not.

- **It is not a push.** Nothing leaves the machine on the route's account. A push would want a vendor's wire in the supervisor and a credential for a monitoring service sitting on the writer's machine, and this repo puts neither there (ADR-0033 ruling 3). The route answers when something on this machine asks.
- **It is not a second reading.** The body is one pure function over the scan report the status endpoint already holds. A scrape starts no walk of the store, so scraping every fifteen seconds costs what the poll already costs and no more. The hook still records nothing new (`.out-of-scope/001`); the reader still counts only what the chain holds (ADR-0027).
- **It is not the verdict.** `verify` owns those, as it did before. A gauge is the supervisor's reading of `verify`'s output, rendered for a pager.

## 2. Turning it on

There is nothing to turn on. Any `serve` answers it:

```
python supervisor.py serve
```

```
curl http://127.0.0.1:8787/metrics
```

The response is `text/plain; version=0.0.4; charset=utf-8`, and every family on it is a gauge: the counts are the reading, and the trend over time is your time-series store's job, which is exactly where ADR-0013 declined to grow one.

## 3. What is on the scrape

Every name begins with `loxodonta_` and says the mechanism it counts, never the conclusion you might draw: `loxodonta_chains{verdict="BROKEN"}`, and no metric anywhere called "tampering detected". Every `# HELP` line ends with the grade of evidence behind the number, the same honesty labels [recall](../GLOSSARY.md#recall) carries:

- **(verdict)** — the number came from `loxodonta verify` and its inputs: recomputed hashes, the chain rule, an anchor replayed against a Bitcoin block.
- **(witness verdict)** — the supervisor decided it from its own watching: the harness transcript paired with the chain it witnessed, or its own diary of when it last saw a head move (ADR-0018).
- **(testimony)** — the number counts writer-stamped lines and writer-reachable files. Recorded faithfully, trusted for nothing.

The help line in the table is exactly the one the route prints, with its grade in the next column over. A gauge with labels carries one sample per value the scan knows, zero included, so a panel never meets a missing series.

| Metric | Labels | Grade | Help line |
|---|---|---|---|
| `loxodonta_scan_exit_code` | none | verdict | The last scan's exit code: 0 nothing demanding attention, 1 to 4 the worst verify exit among the chains, 5 the baseline saw a change appends cannot explain, 6 a live session is behind its witness, 7 a chain's transcript commitments contradict each other |
| `loxodonta_scan_age_seconds` | none | testimony | Seconds since the scan these numbers come from; a gauge is as fresh as the last tick |
| `loxodonta_chains` | `verdict` | verdict | Chains by the verdict verify handed them on the last scan, torn tails a sibling continued excluded |
| `loxodonta_chains_superseded` | none | verdict | Chains verify called BROKEN for a torn tail alone, stood down because a sibling chain continued the recording |
| `loxodonta_completeness_sessions` | `state` | witness verdict | Sessions by completeness state, the chain paired with the harness transcript that witnessed it |
| `loxodonta_lifecycle_sessions` | `state` | witness verdict | Sessions by dormancy tier, decided by when the supervisor's own scans last saw the chain's head move |
| `loxodonta_consumption_sessions` | `state` | testimony | Sessions whose busiest hour ran past the store's own norm, still receiving or gone quiet |
| `loxodonta_heads_unanchored` | none | verdict | Chains whose head no anchor covers yet, from the spans verify replayed on the last scan |
| `loxodonta_heads_unsent` | none | testimony | Chains no head of which has left this machine yet, by the publish door or the anchor door, as the writer-reachable sidecars beside them say |
| `loxodonta_publishing_wired_nothing_sent` | none | testimony | 1 when publishing is wired on the session-end command and no chain in the store holds a sent head, else 0 |
| `loxodonta_last_attempt_failed` | `step` | testimony | 1 when some chain's newest failed session-end attempt is this step, else 0 |
| `loxodonta_store_drawers` | none | testimony | Drawers in the store, one per project |
| `loxodonta_store_sessions` | none | testimony | Sessions in the store, counted per drawer, sibling chains folded into one |
| `loxodonta_store_chains` | none | testimony | Chains in the store, sidecars excluded |
| `loxodonta_store_receipts` | none | testimony | Entries across every chain, genesis and bookkeeping included |

### The label values

Each is the scan's own string, unchanged. The sets below are what a scrape carries today; a value that joins later joins as a new sample under the same name (section 4).

- `loxodonta_chains{verdict}` — `VALID`, `BROKEN`, `ANCHOR-MISMATCH`, `ANCHOR-INVALID`, `TRANSCRIPT-DIVERGED`, `UNSUPPORTED-VERSION`, `NO-VERDICT`. The vocabulary is the GLOSSARY's *States and transitions*, as the scan emits it. Note that a chain verify called `BROKEN` only because its tail is torn, where a sibling chain carried the recording on, is not in this count: it has its own gauge, so the broken count says what the dashboard's strip and the day book say (ADR-0004).
- `loxodonta_completeness_sessions{state}` — `OK`, `LAGGING`, `SURPLUS`, `QUIET`, `ALARM-SILENT`, `ALARM-DEFICIT`, `IDLE-CLEAN`, `IDLE-DEFICIT`, `ENDED-CLEAN`, `ENDED-DEFICIT`, `ENDED-SURPLUS`, `UNWITNESSED`, `UNWATCHED`, `ELSEWHERE`, `BEFORE-MEMORY`. The last one is the counted block of sessions older than the supervisor's own memory (ADR-0029): they take no row anywhere, and the block's count is that label's value, so a store full of them reads as unjudged rather than as a clean bill.
- `loxodonta_lifecycle_sessions{state}` — `awake`, `waning`, `dormant`. A session the completeness watch never paired with a transcript has no tier and is in none of the three.
- `loxodonta_consumption_sessions{state}` — `RUNNING-HOT`, `ENDED-HOT`.
- `loxodonta_last_attempt_failed{step}` — `anchor`, `publish-head`. The steps the recorder writes an attempt row for at session end (`docs/HOOK.md`).

### Two readings that are deliberately absent

**There is no per-chain "unpublished" gauge.** The scan's per-chain departure reading names the newest door a head went out of, not every door it ever used, so a chain that published a head in the morning and anchored a later one in the afternoon reads as *anchored* and nothing in the report contradicts that. A metric that can be wrong about which door is worse than one that is narrower, so the route offers the narrower pair instead: `loxodonta_heads_unsent`, which counts chains that have sent nothing anywhere, and `loxodonta_publishing_wired_nothing_sent`, the store-wide condition the scan already says in one sentence when publishing is wired in name only (#240 part 3).

**There is no metric for whether the supervisor is alive.** That one is `up`, which your Prometheus writes for you on every scrape, and a scrape that stops is the loudest signal on this page. A writer that can kill the supervisor can silence the route; no gauge served by the thing being killed can report that.

## 4. The names are frozen

**A metric scraped into somebody's dashboard is renamed by nobody.** From the release that first carries a name, that name and its label set are a public interface (ADR-0033 ruling 4). What that rule allows and forbids:

- New metrics may be added at any time.
- A new completeness state, lifecycle tier, verdict or session-end step is a **new label value** and a new line in this page. It is never a renamed metric and never a new metric name.
- A metric that stops meaning anything is left in place, reading zero, with a line here saying so. It is not removed.
- A naming mistake is kept and documented. That is the price of the freeze, and it was chosen with open eyes.

The list lives in one place in the code, `metrics_text` in `supervisor.py`, beside the help text it prints. This page restates it for you, and the suite holds the two together: `tests/test_metrics.py` reads the table above and refuses a name, a label or a help line that the route and this page disagree about.

## 5. Scraping it

The route inherits `serve`'s posture exactly: it binds `127.0.0.1` and it refuses a request whose `Host` header names another machine, with the same 403 the dashboard gives, because a browser lied to by DNS reads a rebound name as same-origin and the `Host` header is the only witness left. So the scraper goes on the same machine:

```yaml
scrape_configs:
  - job_name: loxodonta
    scrape_interval: 30s
    static_configs:
      - targets: ['127.0.0.1:8787']
```

Reaching it from another box is your tunnel or your reverse proxy, the same as the dashboard: an SSH forward, or a proxy that presents the route under a name this machine answers to. The supervisor offers no way to do that for you, deliberately.

Two alerts worth having on day one, in words rather than in anyone's query language: page when `loxodonta_scan_age_seconds` climbs past a few multiples of your tick, because the numbers are then stale and saying so; and page when the scrape itself disappears, because that is the case the numbers cannot cover.

## 6. What a gauge does not survive

- **The machine it runs on.** The supervisor is writer-reachable, and so is its scrape. Verdicts still come from `verify` and its inputs, never from a number on this route.
- **The gap between scans.** A gauge is as fresh as the last tick. `loxodonta_scan_age_seconds` says how fresh, and an alert on it is the honest guard.
- **Anything the chain does not hold.** The route counts receipts, not outcomes, not health, not errors. "This session is erroring" is somebody else's product, and `.out-of-scope/001` still says so.

## 7. See also

- `adrs/0033-the-supervisor-exposes-its-counts-for-the-operators-own-siren-pull-only.md` — the decision, the alternatives, and why the dashboard was held.
- `adrs/0027-the-dashboard-counts-what-the-chain-holds.md` — the seam this route sits on.
- `GLOSSARY.md` — *Metrics route*, *Completeness*, *Session lifecycle*, *Consumption watch*, *Tally*, *Before memory*, *Testimony*.
- `docs/HOOK.md` — the attempt rows behind `loxodonta_last_attempt_failed`.
