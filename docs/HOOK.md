# The harness hook — Stage C wiring, and the adapters that speak it

`loxodonta hook` turns a `PostToolUse` payload (JSON on stdin) into one chained entry. Claude Code was the first harness to send one and is the reference throughout this page; Codex CLI sends the same shape natively, and the OpenAI Agents SDK adapter produces it from tracing spans — see [Other harnesses](#other-harnesses) below (ADR-0020). This is the completeness mechanism promised in SPEC §8 and ADR-0002: the harness fires the hook after every **completed** tool call, so the log call sits outside the writer's volition — the agent cannot skip its own receipt, and a session becomes a verifiable flight recording with no cooperation from the agent at all. (A failed or denied call fires no hook — the harness's rule, not ours — and the supervisor's witness counts by exactly the same rule, so nothing is owed for it.)

## Wiring

In the project's `.claude/settings.json` (or your user settings):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /absolute/path/to/loxodonta.py hook"
          }
        ]
      }
    ]
  }
}
```

- With no `--log-dir`, the adapter reads the `CLAUDE_PROJECT_DIR` environment variable the harness sets for hooks and logs to that project's **drawer in the store** (ADR-0011): `~/.loxodonta/receipts/<project-slug>/` (override the home with `LOXODONTA_HOME`), writing a `project.json` project record on the first receipt so file references stay resolvable wherever the chain lives. Resolved in Python, not by the shell, so the same settings command works on every platform (Windows included). For machine-wide recording, run `python loxodonta.py install-hook` — it writes exactly the block above into your user-level `~/.claude/settings.json`. Don't wire the same hook at both user and project level: both fire, and every tool call is logged twice.
- Without `CLAUDE_PROJECT_DIR`, a payload that names a `cwd` (Codex does; the Agents SDK adapter does) logs to the store drawer for that directory instead — the environment wins when both are present (ADR-0020). With neither (running the hook by hand), logs land in the working directory; `--log-dir receipts/` keeps them in one place — the hook creates the directory on first use and seeds it with a protective `.gitignore` (command history must not ride into a commit by accident). An explicit `--log-dir` outranks everything, the store included. One more variable the recorder reads: `SOURCE_DATE_EPOCH` (integer Unix seconds, UTC, the reproducible-builds convention) replaces the wall clock in every timestamp it writes, which is how `tools/demo_store.py` produces the same demo store on every run; timestamps are testimony either way, since the writer is the adversary (ADR-0002).
- **Worktrees log to the repository they belong to.** When the project directory is a git worktree, the drawer is keyed by the main repository's path, not the worktree's. Worktrees are disposable — pruned once their branch merges — so history keyed to one would be deleted by routine hygiene, losing exactly the sessions worth keeping. Every worktree's history therefore collects in one drawer. The linkage is read from the files git writes (`.git` → `commondir`), never by spawning `git`: this runs on every tool call. Anything unreadable falls back to the project directory's own drawer rather than failing the session.
- **Parallel tool calls share one chain, so the hook serializes itself.** A harness fires one hook process per tool call and runs tool calls concurrently; each append therefore takes an exclusive `<log>.lock` across read-tail-then-append (ADR-0004). Without it, racing writers tear a line or — more often — silently drop a receipt from a chain that still verifies `VALID`. Waiting writers retry for `RECEIPTS_LOCK_TIMEOUT` seconds (default 10) and then **fail loudly**: a missing receipt is the one thing this tool exists to prevent, so contention is never a quiet skip. A lock left untouched for 60s is treated as abandoned and broken, so a crashed writer cannot wedge a chain forever.
- **A damaged chain is retired, not repaired.** If the chain the hook would extend has a torn tail, it starts a sibling — `receipts-<session>-002.jsonl` — and records there. The damaged chain is left byte-for-byte as evidence (there is no repair command, by design: ADR-0002). Each sibling is a complete chain with its own genesis and head, and **anchors separately** — worth knowing before you rely on one head record per session. The `log` and `run` commands still refuse to extend a damaged tail; siblings are the hook's answer, because a harness cannot stop and ask.
- The shipped `matcher` is `"*"` — every completed tool call, reads and fetches included (ADR-0016): the forensic record must cover where an attack *enters* (reads of untrusted content) and *leaves* (network and MCP tools), not just where it changes state, and MCP tool names can't be enumerated in advance. You can narrow it (e.g. `"Edit|Write|NotebookEdit|Bash|PowerShell"`, the old default) to receipt only state-changing tools — but every uncovered tool call is a blind spot, and if you narrow, include every shell tool your harness actually runs: the desktop app on Windows issues most commands through a `PowerShell` tool, and a matcher that omits it silently misses those sessions' work. `install-hook` widens the old shipped default in place when it finds it, leaves any other matcher alone, and prints a notice; the supervisor observes matcher changes and judges each session by the coverage in force at its time, so changing your matcher never manufactures deficits over old sessions.
- The adapter reads `session_id`, `tool_name`, and `tool_input` from the payload, plus `cwd` (only when `CLAUDE_PROJECT_DIR` is unset) and `transcript_path` (for the commitments below); nothing else. `tool_response` is never read: tool output is deliberately not recorded (`.out-of-scope/001`) — receipts are not transcripts, and `action`/`path` values are plaintext forever (SPEC §8: no secrets).

## What gets written

- **One chain per session**: `receipts-<session_id>.jsonl`, auto-initialized on first use — plus a `-002` sibling if that chain is ever damaged (above). Separate sessions get separate chains; interleaving them is `report`'s display concern, not an integrity concern. Note the two senses of *sibling*: parallel **sessions** each get their own chain because they are separate histories, while a damaged chain gets a sibling because history must continue somewhere. Within one session, parallel tool calls share a chain and are serialized (SPEC §8, ADR-0004).
- **actor** — `claude-code` by default; the installers name the harness (`codex`), the SDK adapter names itself (`openai-agents`), and `--actor` overrides. On a machine running several harnesses, recall rows say which one acted.
- **action** — the tool name plus its most descriptive argument, collapsed to one line: `Bash: pytest -q`, `Write: src/main.py`. The argument is chosen by key, in preference order (`file_path`, `notebook_path`, `command`, `path`, `pattern`, `url`, `query`, `prompt`), with `summary` last as the adapters' fallback for tools whose arguments carry none of the named keys; a tool with no usable argument records its name alone.
- **files** — a `{path, sha256}` fingerprint for `file_path` / `notebook_path` arguments that sit under the **project** and still exist after the call, recorded relative to the project root (SPEC §3 as amended v0.1.1, ADR-0012). Files outside the project (or already gone) are skipped, never fatal: a hook that fails the session over path layout teaches the operator to turn the hook off — the receipt still records the action itself. With the `"*"` matcher this includes **read** tools: a `Read` receipt fingerprints the file as it was when the agent saw it — for a forensic rebuild, "what content did the agent ingest" is exactly the question — and `verify --files` judges by a file's *latest* reference, so a read fingerprint never manufactures divergence noise. One caveat: the hash covers the whole file on disk, not the slice a ranged read returned; it identifies the artifact, not the excerpt.

## Coverage and cost

Wide coverage is one fresh hook process per tool call, machine-wide. Measured on the author's machine (Windows 11, CPython 3.13, NVMe): **~135 ms median per call, p95 ~158 ms**, end-to-end — cold interpreter spawn, payload on stdin, locked append. Chain length doesn't move it: appends to a ~380-entry chain measure the same 134 ms median, so a session never slows down as its history grows. Interpreter startup dominates everything.

Where the real limits sit:

- **Across sessions there is no contention.** Chains are per-session and locks per-chain, so any number of simultaneous agents record independently — the store's limit is your disk, not a shared lock.
- **Within one session**, parallel tool calls serialize on the chain's lock (ADR-0004, above). At ~135 ms per append, a burst of dozens of concurrent calls in a single session can stack toward the 10-second lock timeout — and the hook then **fails loudly** rather than skipping. If your harness fans out very wide inside one session, that is the edge to watch; nothing in the field has reached it.
- **The store is a log store — treat it like one.** Action lines are one-line, 160-character summaries, never transcripts, and never tool output (SPEC §2, §8) — but with `"*"` they include URLs fetched, queries searched, and prompt heads, because in a forensic reconstruction those *are* the evidence (a receipt that scrubbed the exfiltration URL would faithfully prove nothing). The chain deliberately holds evidence, so give `~/.loxodonta/` the handling you give logs: local ACLs, keep it out of backups that leave the machine, and never commit it (the drawer's `.gitignore` guards the accident, not the policy). Remember the recall digest is injected into session context — everything in a chain is discoverable by whatever reads that context, which is one more reason receipts must never contain secrets.

Failure semantics: on an unusable payload or an unappendable log the adapter prints one error line and exits 1 — visible in the harness, non-blocking for the session (the tool already ran; PostToolUse cannot roll it back, and receipts wouldn't want to).

## The transcript commitment (ADR-0017)

The chain is the *spine* of a forensic rebuild; the flesh — full commands, tool output, the conversation — lives in the harness transcript, a plain file the writer can reach. Every 25 entries, the hook staples the two together: it hashes the transcript **from byte zero** and appends a bookkeeping entry in the recorder's own voice —

```
{"actor": "receipts", "action": "transcript-commitment: bytes=1679210 sha256=c01237…", "files": [], …}
```

A committed prefix can never be rewritten undetected again: `verify --transcript` re-hashes each committed boundary and says which commitments hold (SPEC §2.2, §6). Because each commitment covers the whole prefix, a diverging one localizes the rewrite to the span since the previous commitment. `supervisor scan` hands each committed session its exact judge command.

The honest limits, stated plainly:

- **The window before the next commitment is open.** Bytes newer than the latest commitment — including the whole transcript during the first 25 calls — are rewritable until a commitment covers them, and the commitment will faithfully fingerprint whatever is there by then. At most ~25 calls of history are exposed at any moment.
- **The tail commitment depends on the client.** A SessionEnd hook writes one final commitment over the whole transcript, whatever the cadence position (issue #79) — but only where the client actually fires SessionEnd. The terminal CLI does, reliably, on `/exit` and Ctrl-D. Claude Desktop's Code mode offers no `/exit` and its SessionEnd behavior is undocumented, so sessions there commonly end with an **uncommitted tail** — the final <25 calls' bytes never locked in. The supervisor says so honestly ("tail uncommitted", ADR-0018) and its **tail keeper** closes the gap from the reading side: the scan writes the missing exit commitment itself, shrinking the open window to one scan cadence. A hard kill anywhere fires nothing, and the docs keep saying so.
- The commitment is **writer-authored**, like everything the recorder writes: it extends tamper-evidence to the transcript *by reference, forward from each commitment* — detection latency, not protection. Anchors remain the only hard boundary.

Cost: a commitment is one extra append (~4% more entries) and one transcript read+hash at the boundary — measured at ~1 ms per MB, inside a ~155 ms hook call that interpreter startup dominates either way (EXPERIMENTS §4). Bookkeeping entries never count against the completeness witness and never spend digest rows.

## Other harnesses

The hook payload is the adapter contract (ADR-0020): whatever the harness, an integration produces this payload and hands it to `loxodonta hook`. Nothing else writes the chain. Two adapters ship.

### Codex CLI

Codex's hooks (GA since 2026-05) send a `PostToolUse` payload with the same fields Claude Code sends — `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`, `tool_response` — plus `turn_id`, `model`, `permission_mode`, `tool_use_id`, which the recorder ignores. The one difference that matters: Codex sets no `CLAUDE_PROJECT_DIR`, so the recorder takes the project from the payload's `cwd` (above). Wire it machine-wide:

```
python loxodonta.py install-hook --codex
```

That writes three blocks into `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`), idempotently, keeping any hooks already there and backing the file up first: a `PostToolUse` block on matcher `.*` (Codex matchers are regexes; this is its every-tool-call) running `loxodonta.py hook --actor codex`, a `SessionEnd` block for the tail commitment with a 3-second timeout, which is Codex's cap for that event, and a `SessionStart` block running `supervisor.py digest --payload` so a Codex session opens with the same recall digest a Claude Code session does. The `--payload` flag is the one Codex-specific wrinkle: Codex sets no `CLAUDE_PROJECT_DIR`, so the digest reads the SessionStart payload on stdin and takes the repo from its `cwd` (the environment still wins when a harness sets it). The digest never reads stdin unasked, because under `supervisor mcp` stdin is the wire. **Codex asks you to review new hooks once** — open Codex and run `/hooks` to trust them; until you do, nothing records, and the installer says so. `uninstall-hook --codex` removes exactly those two entries.

Honest differences from the Claude Code wiring:

- **Coverage reads slightly differently.** Codex fires `PostToolUse` after a shell command with a non-zero exit, where Claude Code fires nothing for a failed call. Both are recorded outcome-blind, so a Codex chain has receipts for attempts that failed and a Claude Code chain does not. Neither is wrong; they are what each harness owes.
- **No completeness witness yet.** The supervisor's completeness alarm (exit 6) counts owed receipts by reading Claude Code's transcript layout. Codex's rollout transcript (`$CODEX_HOME/sessions/…/rollout-*.jsonl`) is a different layout that Codex documents as unstable, so Codex sessions get integrity, recall, anchoring, and the baseline tripwire — everything except the alarm that says "this session is live and its receipts stopped". Transcript commitments do work: they hash bytes, not shapes, so the rollout file is committed every 25 entries and sealed at SessionEnd exactly as a Claude Code transcript is.
- **The digest arrives as developer context.** Codex adds a SessionStart hook's plain-text stdout to the model's context, so the digest lands the same way it does in Claude Code. The same memory is also reachable over MCP for anything Codex runs that wants to ask for more — [docs/MCP.md](MCP.md).

### OpenAI Agents SDK

`adapters/openai_agents.py` is a `TracingProcessor` that turns the SDK's spans into hook payloads. Three lines in your program:

```python
from agents import add_trace_processor
from adapters.openai_agents import ReceiptRecorder
add_trace_processor(ReceiptRecorder())
```

Each run's trace becomes one chain — `receipts-<trace_id>.jsonl` in the drawer for the program's working directory (pass `project=` to name another) — and `supervisor digest`, `search`, and the MCP server read it exactly as they read a Claude Code session. Recorded: `function` spans (every function tool, and MCP tools, which the SDK wraps as function tools) and `handoff` spans (`handoff: coder -> reviewer`). Not recorded: model turns, guardrails, and hosted server-side tools, which are not actions on this machine. A tool that raised still leaves its receipt — the span fires either way, which is why the adapter listens to spans rather than the SDK's `on_tool_end` hook, which does not fire for a raised tool. Tool arguments are summarized by the same key rules as above; with `trace_include_sensitive_data=False` the arguments are absent and the line carries the tool name alone.

The adapter is stdlib only and imports the SDK only if present, so it reads and tests as plain Python. It is synchronous on purpose: one recorder process per tool call (~135 ms, below), in span order, nothing lost if the program dies. A recorder failure is printed to stderr and never raised — the run must not die over its flight recorder, but a silent recorder is worse than a loud one. Register it with `set_trace_processors([ReceiptRecorder()])` instead of `add_trace_processor` if you also want to stop the SDK's default export to OpenAI; do not use `set_tracing_disabled(True)`, which silences every processor including this one.

**The trust position is one ring closer to the writer than a harness hook, and this page will keep saying so.** A Codex or Claude Code hook is a process the harness spawns after the call: outside the agent program entirely. The SDK processor runs inside the agent program's own process. The model still cannot skip a receipt — the SDK fires the processor, not anything the model controls — but the program's author can (by not installing it), and a tool the model runs could edit the program's source. Completeness is the integration's job (GLOSSARY: *Completeness*); this is the integration, and this is its boundary. As with Codex, there is no completeness witness for SDK runs.

### Writing another adapter

Produce the payload, call the hook. The minimum is `session_id` (one chain per value), `hook_event_name: "PostToolUse"`, `tool_name`, `tool_input` (a dict; use a named key or `summary`), and `cwd` (the project). Add `transcript_path` if the harness keeps one and you want commitments. Send `hook_event_name: "SessionEnd"` with the same `session_id` and `transcript_path` to seal the tail. Pipe it as UTF-8 JSON to `python loxodonta.py hook --actor <harness>`; exit 0 means the receipt is on the chain, anything else comes with one line on stderr. That is the whole contract, and the hook's own test suite is your test suite.

## Verifying a session

```
receipts verify --log receipts-<session>.jsonl            # chain integrity
receipts verify --log ... --transcript <transcript.jsonl> # + judge transcript commitments
receipts report --log receipts-<session>.jsonl            # human timeline
receipts anchor --log receipts-<session>.jsonl            # pin it to Bitcoin (Stage B)
```

The operator ritual from ANCHORING.md §5 applies unchanged; session chains are ordinary receipt logs.
