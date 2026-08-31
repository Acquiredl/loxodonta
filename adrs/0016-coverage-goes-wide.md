# ADR-0016: Coverage goes wide — record every completed tool call, judge history by the rules in force at its time

**Status:** accepted 2026-08-31

## Context

The installed `PostToolUse` matcher recorded state-changing tools only:
`Edit|Write|NotebookEdit|Bash|PowerShell`, with a comment explaining the
choice. Two things broke that position.

**The field already voted against curated lists.** The desktop app on
Windows runs commands through a `PowerShell` tool the original matcher
didn't name, and this repo's own launch left almost no receipts until it
was added. A curated list is a list somebody forgot to update, and MCP
tools make the problem structural rather than occasional: their names are
generated per server (`mcp__<server>__<tool>`), so no finite list covers
them even in principle.

**The threat model demands the missing tools most.** The OWASP Top 10
for LLM Applications (2026) prescribes this tool's job in LLM03
mitigation #8, verbatim: *"Log and monitor the activity of LLM tools and
downstream systems to identify where undesirable actions are taking
place."* And LLM01's lethal-trifecta analysis (private data + untrusted
content + external communication) shows what the narrow matcher missed:
it recorded only the state-change leg. The ingest leg (`Read`,
`WebFetch` — where injection enters) and the communication leg (network
and MCP tools — where exfiltration leaves) were exactly the uncovered
tools. A forensic record that misses two of the three legs cannot
reconstruct the attacks that matter.

Widening surfaced a second problem. The witness judges every transcript
against the *currently wired* matchers — its own docstring names the
inverse failure ("an all-tools witness over an Edit|Write|Bash hook
manufactures deficits"), and widening replays it forward: every ended
session in the transcript window gets re-judged with `*`, manufacturing
a wall of `ENDED-DEFICIT` scars, and every session still running at
upgrade fires hooks under its old loaded matcher while the witness
expects `*` — a live false alarm until restart. Nor is this a one-time
migration cost: *any* matcher change, in either direction, replays it.
ADR-0014 already cites the dashboard failure this causes (Big Book of
Dashboards, Ch. 32): a surface that shows false scars teaches its
operator to distrust scars, and this tool's one claim is detection
latency through an operator who still looks.

Prior art consulted: **Linux auditd** (record broadly at the syscall
layer, filter at analysis time; rule changes apply forward only, and the
kernel logs rule changes so the boundary is knowable); **Sysmon**
(curated event configs, famous for rot — every working config is a fork
of someone's maintained ruleset); **EDR sensors** (hook everything at
the sensor, triage in the pipeline — the sensor is deliberately dumb
because the sensor is the part you cannot retrofit after an incident).
All three converge: nobody re-judges history with today's rules, and
nobody puts the allowlist in the sensor.

## Decision

Four rulings, one family — ratified restatement: *we widen coverage to
every completed tool call, and judge each session's completeness by the
coverage in force at its time.*

**1. The default matcher is `*`. The sensor has no allowlist.** Every
completed tool call owes a receipt — reads, searches, fetches, spawns,
MCP tools included. A sensor with an allowlist has blind spots an
attacker can enumerate by reading this public repo. "Completed" is
load-bearing: the harness fires no hook for failed or denied calls, so
they sit outside coverage by harness design — the same boundary the
witness already counts by.

**2. Calibration is effective-dated.** The witness judges each session
against the matchers in force at that session's time, as best the
supervisor observed them — the supervisor already reads the settings
every scan and already remembers its own observations (day book,
ADR-0014; recorder notice, ADR-0015). A matcher change manufactures no
scars: sessions recorded under the old rules are judged by the old
rules. Observation granularity is scan granularity, and the dashboard
says so in words where the boundary matters ("matcher widened on this
date; older sessions judged by the rules then in force").

**3. The recorder never filters; readers do.** Volume concerns
(a digest drowned in `Read` lines, a noisy report) are answered at the
reading surfaces — weighting, collapsing runs, search — never by the
hook declining to record. This is ADR-0002 applied to volume: the writer
is the adversary, so the writer does not get to decide what history is
interesting.

**4. No recorder-side redaction.** Wider coverage records more sensitive
material — URLs, queries, prompt heads — and OWASP LLM02 names exactly
this logging pattern as a disclosure surface. The control is custody of
the log, not amnesia in it: in the prompt-injection forensic, the
injected URL *is* the evidence, and a chain that scrubs it faithfully
proves nothing. The existing guards stand and become documented posture:
action lines are 160-character summaries, never transcripts (SPEC §2);
no secrets in receipts (SPEC §8); the store is local-only with a
protective `.gitignore`, and operators treat the drawer with log-store
handling. One consequence sharpens §8: the recall digest is injected
into every session start, so chain content is *discoverable context*
(OWASP LLM08) — nothing sensitive may ever enter an action line, because
everything in the chain must survive being read by the next attacker.

**Migration** follows the `heal()` philosophy — touch only what is
provably ours and provably stale: `install-hook` replaces a matcher that
is byte-for-byte the old shipped default with `*`; any other string is
operator customization, left alone with a printed notice. The README's
claim tightens from "every tool call" to "every **completed** tool
call" — the claim and the alarm then describe the same set.

## Why not the alternatives

- **A wider curated list** (`…|WebFetch|Task|mcp__.*`) — rots like the
  old one, and structurally cannot cover MCP names. Rejected at the
  sensor; curation is fine at reading surfaces, where rot degrades to
  "unweighted", not "unrecorded".
- **Recorder-side redaction** — destroys the evidence the forensic
  purpose exists to keep, and puts a content transform inside the
  component the threat model trusts least.
- **Suppressing fingerprints on read tools** — would take more code (a
  tool allowlist inside the hook) to deliver less evidence. Read
  fingerprints are safe by construction (`--files` is
  latest-reference-wins) and record what the agent last *saw* — for the
  ingest leg, exactly the forensic question.
- **Accepting the retroactive scar wave** — free of code, but it lands
  on the flagship claim: the completeness alarm would lie for a month
  after every config change, and a scar the operator learns to shrug at
  is a disarmed tripwire.

## Consequences

- The hook now spawns for every tool call, machine-wide. Accepted with a
  measurement gate: the build slice times the wired hook end-to-end and
  publishes an operating envelope in docs (measured latency, burst
  behavior, where `LockTimeout` rollovers begin) instead of an
  unstated limit. Chains are per-session and locks per-chain, so
  concurrent agents mostly do not contend; the envelope says what was
  actually measured.
- Exploration-heavy sessions grow several-fold. Digest ergonomics are
  deferred to their own slice (collapse-runs is the front-runner);
  the recorder-never-filters ruling governs the shape of any fix.
- Coverage makes tool-use *baselines* possible: entries per session per
  hour is a consumption signal, and OWASP LLM06 #8 ("detect
  resource-intensive tool interactions… establish baselines of normal
  tool behavior") becomes a natural future supervisor surface. The hook
  stays outcome-blind (`.out-of-scope/001`) — this tool evidences
  someone else's circuit breaker; it never is one.
- The chain is the tamper-evident *spine* of a forensic rebuild, not the
  flesh: receipts hold chronology and content-hashes, while the rich
  record (tool outputs, full commands, diffs) lives in the harness
  transcript, which is writer-reachable. Extending tamper-evidence to
  the transcript by reference — receipts periodically committing the
  transcript's hash — is named future work, not this slice.
- GLOSSARY gains **Coverage**, with the anti-claim spelled out: coverage
  is not completeness; coverage says which calls owe, the witness judges
  whether the owed receipts arrived.
