# ADR-0020: Recorder adapters speak the hook contract — Codex hooks and the Agents SDK trace processor

**Status:** accepted 2026-09-02 (restate-to-ratify passed)

## Context

The README has promised "adapters for other agent frameworks, so
recording isn't tied to my stack" since launch, and named the reason
only one existed: Claude Code is what the operator uses daily. Two
facts changed the priority. First, the market read behind ADR-0019: a
buyer keeps their own agent, and a flight recorder that records one
harness is, for every other harness, no recorder at all. Second, the
field caught up — Codex CLI's hooks reached general availability in
May 2026 with a `PostToolUse` event whose stdin payload deliberately
mirrors Claude Code's (`session_id`, `transcript_path`, `cwd`,
`hook_event_name`, `tool_name`, `tool_input`, `tool_response`), and the
OpenAI Agents SDK exposes every tool call and handoff as a tracing span
to any registered processor. The two most-used harnesses beside ours
now both offer an observation point outside the model's control.

Where the observation point sits differs, and the difference is the
substance of this decision. A Codex hook is a process the harness
spawns after the call — the same trust position as our Claude Code
hook. An Agents SDK processor runs *inside* the agent program's
process: the model cannot skip it (the SDK fires it, not the model),
but the program's author can, and a tool the model runs could edit the
program. That is one ring closer to the writer than a harness hook,
and the docs must say so rather than let "recorded" mean the same
thing in both places.

Prior art consulted: **OpenTelemetry** (one span contract, many
exporters; in-process instrumentation is the norm and the collector
sits outside — the accepted split between "the program reports" and
"something else keeps the record"); **syslog(3)** (every program logs
through one small call to a daemon it does not own — the adapter's
job is translation into that one call, never a second log format);
**Codex's own hook design** (a payload shaped to match Claude Code's is
an emerging de-facto standard for harness hooks, and this repo's hook
contract is already that shape). Confidence high on the Codex payload
(official docs, verified 2026-09-02) and on the SDK processor
interface (source, `openai-agents` 0.22.0); medium on Codex's
`tool_response` shapes, which the recorder never reads anyway
(`.out-of-scope/001`).

## Decision

> **Every adapter translates its harness's event into the hook payload
> and hands it to `loxodonta hook`. None writes the chain format
> itself.** Codex is wired by `install-hook --codex`, which writes
> `~/.codex/hooks.json` (PostToolUse on `.*`, SessionEnd for the tail
> commitment). The Agents SDK is served by `adapters/openai_agents.py`,
> a stdlib-only `TracingProcessor` that records function-tool and
> handoff spans. The recorder learns two small things to make this
> possible: a payload's `cwd` names the project when the harness sets
> no `CLAUDE_PROJECT_DIR`, and `summary` joins the end of the
> action-line preference list as a last resort.

Ratified restatement: *whatever the harness, the elephant is fed
through one mouth — the hook — and every adapter is a spoon.*

The shape, as built:

- **The hook payload is the adapter contract.** It was Claude Code's
  shape; it is now the shape any integration produces. The recorder
  gains no harness-specific branches beyond the two fields above, and
  the chain format (SPEC v0.1, frozen) gains nothing. `actor` names the
  harness (`claude-code`, `codex`, `openai-agents`) so recall rows read
  honestly across a machine that runs several.
- **Codex: same event, same file, one more home.** The installer writes
  the same PostToolUse and SessionEnd blocks it writes for Claude Code
  into `$CODEX_HOME/hooks.json` (default `~/.codex`), idempotently,
  preserving foreign hooks, refusing broken JSON, backing up first.
  Codex requires the user to trust new hooks once (`/hooks`); the
  installer says so instead of pretending the install is complete.
  Codex's transcript is its rollout JSONL; transcript commitments and
  the SessionEnd seal work unchanged because they hash bytes, not
  shapes. Its SessionEnd budget is capped at three seconds, which the
  installer honors. *(Addendum 2026-09-03: this ADR first said Codex
  injects hook context only through a JSON envelope and shipped no
  SessionStart digest. Codex's current hooks documentation says the
  opposite — plain-text stdout "is added as extra developer context" —
  so the digest ships for Codex too, as a third block: `supervisor.py
  digest --payload`, the flag telling the digest to take its repo from
  the SessionStart payload's `cwd`, since Codex sets no
  CLAUDE_PROJECT_DIR and the hook process's working directory is
  nobody's promise. The flag is explicit rather than implied because
  under `supervisor mcp` stdin is the wire; the digest must never read
  it unasked.)*
- **Agents SDK: the span is the event.** `on_span_end` for spans of
  type `function` (which covers MCP tools, wrapped by the SDK as
  function tools) and `handoff`. Chosen over the lifecycle hooks
  (`on_tool_end`) because the span fires even when the tool raised and
  the SDK's hooks do not, and a receipt records the attempt regardless
  of outcome. The trace id is the session: one chain per run, sibling
  chains for concurrent runs, the drawer is the program's working
  directory. Synchronous by design — one recorder process per tool
  call, in span order, nothing lost if the program dies; a background
  queue was rejected as cleverness that trades ordering and crash
  safety for milliseconds beside a model turn.
- **Outcome-blind holds.** Codex sends exit codes and the SDK sends
  span errors; both adapters drop them. `.out-of-scope/001` was
  decided for one harness and is reaffirmed for all: a receipt says
  what was attempted on what.
- **Coverage is per harness, and the witness is not.** Codex fires
  PostToolUse for a non-zero exit where Claude Code fires nothing; the
  SDK fires for a raised tool. So "every completed tool call owes a
  receipt" reads slightly differently per harness, and the
  completeness witness (ADR-0016) — which counts owed receipts by
  reading Claude Code's transcript layout — judges Claude Code sessions
  only. Codex and SDK chains get integrity, recall, anchoring, and the
  baseline tripwire; they do not get the completeness alarm until a
  witness is written for their transcript layout. This is stated in
  `docs/HOOK.md`, not left to be discovered.

## Consequences

**What gets easier:**

- A machine running Claude Code, Codex, and an Agents SDK program
  leaves one store, one digest, one search, one MCP server — the
  harness-neutral product the README promised.
- New adapters are small and shaped: produce the payload, call the
  hook. LangGraph or a shell-based harness is an afternoon, not a
  design.
- The hook's own tests are the adapters' tests: any payload that
  reaches `loxodonta hook` is judged by the same suite.

**What gets harder or more constrained:**

- The hook payload is now a public contract with three producers, not
  an internal detail of one harness. Renaming a field is a breaking
  change for adapters.
- `adapters/` is a third code location in a repo built on "single file
  per tool" (ADR-0005). It is not a third *tool* — the adapter is a
  spoon, not a mouth — but the constraint's wording should be read as
  *one file per tool, plus adapters that speak to the recorder only
  through its CLI*.
- Two coverage semantics and one witness. Until Codex has a witness,
  a Codex session whose hook dies silently is caught only by the
  baseline tripwire's cadence, not by the alarm.
- The SDK adapter's trust position is weaker than a harness hook's,
  and every place it is described must carry that sentence.

**What we'll have to revisit if:**

- A Codex witness is wanted — the rollout layout is documented as
  unstable, so a witness there is a maintenance commitment, not a
  slice.
- A harness offers no post-call event at all and only a stream (e.g.
  `codex exec --json`) — a stream tailer would be a resident process,
  and residency belongs to the supervisor, not the recorder.
- ~~Codex's SessionStart gains a plain-text context path, or the digest
  gains a JSON envelope — then the digest injection can ship for Codex
  too.~~ *Fired 2026-09-03: it already had one; see the addendum above.*

## Alternatives considered

- **Adapters that write the chain directly** — rejected: a second
  writer of the frozen format, with its own lock and genesis logic to
  get wrong, when the hook already does all of it behind one command.
- **SDK lifecycle hooks (`RunHooks.on_tool_end`) instead of a trace
  processor** — rejected: not fired when a tool raises without a
  failure handler, nor on a rejected guardrail; a recorder that misses
  the failing calls misses the interesting ones.
- **An async recorder thread in the SDK adapter** — rejected: ordering
  and crash safety over ~135 ms per call; readability outranks
  cleverness (repo constraint).
- **Codex `notify` or rollout-file tailing** — rejected: `notify` is
  per turn, not per tool call; tailing an unstable format is a resident
  process's job and a maintenance burden the hook path avoids.
- **Recording Codex outcomes since they are right there** — rejected:
  `.out-of-scope/001`; the field evidence it asks for has not arrived.

## References

- Related ADRs: `0002-writer-as-adversary.md` (the trust-position
  tiers this ADR names); `0011-central-receipts-store.md` (the `cwd`
  path→slug resolution reuses the store's rule); `0016-coverage-goes-
  wide.md` (coverage semantics differ per harness; the witness stays
  Claude Code's); `0017-transcript-commitments.md` (Codex rollouts are
  committed unchanged); `0019-recall-speaks-mcp-read-only.md` (the
  read side of the same move).
- Out of scope: `.out-of-scope/001-outcome-capture-in-hook.md`
  (reaffirmed for every harness).
- Glossary terms **added**: *Adapter*. *Writer* gains the
  harness-name actor convention.
- Prior art: OpenTelemetry (instrumentation/collector split),
  syslog(3) (one call, one daemon), Codex hooks documentation
  (developers.openai.com/codex/hooks), `openai-agents` 0.22.0 tracing
  source.
- Discussion: agent-first surface planning, 2026-09-02.
