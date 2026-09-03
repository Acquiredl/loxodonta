# ADR-0019: The recall surface speaks MCP, read-only, from the supervisor

**Status:** proposed 2026-09-02 (awaiting restate-to-ratify)

## Context

ADR-0009 built the recall surface as four shell commands and named the
one thing that would reopen the question: "richer queries (aggregation,
a query language, MCP) — deferred deliberately; shelling out must be
shown insufficient first." Shelling out has not proved insufficient for
queries. It has proved insufficient for *reach*.

The recall surface today assumes the Claude Code harness: a
`SessionStart` hook injects the digest, and the agent runs
`supervisor.py show|search|timeline` through its shell tool. Every
other harness the operator now meets — Codex CLI, programs on the
OpenAI Agents SDK, editor agents — cannot run our hook and may have no
shell tool at all. What they all speak is the Model Context Protocol.
The market read that prompted this (Spittel, 2026-08-21: "i want to use
my agent to use your thing", 666K views) says the same in one line:
the buyer keeps their agent and wants the product reachable from it.
A product whose memory can only be read from one harness is, for every
other harness, a product with no memory.

Prior art consulted: **observability vendors' MCP servers** (Langfuse,
Sentry, Honeycomb each shipped a read-side MCP server ahead of any
richer dashboard, and each exposes queries, never ingestion — the
write path stays in the SDK or agent instrumentation; confidence
medium, from release notes rather than a fresh survey); **journalctl**
(the reader is a separate mouth on the same log; it has no network
face and this repo already made that cut in ADR-0009); **the MCP
specification itself** (revision 2026-07-28 made the protocol stateless
with per-request `_meta`, and its own compatibility matrix expects
servers to answer the legacy `initialize` handshake for a long tail of
clients — a dual-era server is the spec's recommendation, not a
hedge).

## Decision

> **The supervisor gains `mcp`: a stdio MCP server that exposes the
> recall surface — `digest`, `show`, `search`, `timeline`, `verify` —
> as five read-only tools, one-to-one with the CLI, in the CLI's own
> words. No write path exists on this surface. The server is stdlib
> only and dual-era (the 2025-11-25 `initialize` handshake and the
> 2026-07-28 per-request form).**

Ratified restatement: *the elephant's memory gets a second mouth, and
it only speaks; nobody feeds it through this one.*

The shape, as built:

- **One-to-one with the CLI.** Each tool builds the same argument set
  the CLI parses and calls the same function; the text the model reads
  is byte-identical to what a shell user reads (the parity tests hold
  this). The digest's shell footer stays as-is — a model on MCP can
  still act on it, and one rendering is one honesty. The lone
  deviation: a digest of an empty repo *says so* instead of the silence
  the hook needs, because a tool that returns nothing teaches the model
  the tool is broken.
- **Read-only, by omission and by test.** No `log`, `run`, `hook`,
  `anchor`, `init`, `adopt`, or `scan` tool. ADR-0002's adversary is
  the writer; a tool that lets the agent append receipts through a
  surface it controls is the agent writing its own history, and `scan`
  writes the baseline. The recorder stays in the harness hook, outside
  the agent's volition (SPEC §8). The tests assert the tool list never
  names a writer and that every chain is byte-identical after a full
  session of every tool.
- **`verify` is the judge's word, not recall's.** It resolves the chain
  by entry address (GLOSSARY: *Entry address*, recall's one identifier)
  and runs `loxodonta verify --log` as a subprocess, returning stdout
  and exit code as-is (ADR-0005: the supervisor speaks only the public
  CLI). Recall still owns no verdicts; it hands the model the phone.
- **Stdlib wire.** Newline-delimited JSON-RPC 2.0 over stdin/stdout,
  about two hundred readable lines. Every tool call runs under a
  stdout redirect so the CLI's `print` never touches the wire; stderr
  carries the CLI's error text back as a tool error (`isError`), so the
  model reads "no entry under <repo> matches deadbeef" instead of a
  protocol failure it cannot act on.
- **Dual-era.** A request whose `_meta` carries
  `io.modelcontextprotocol/*` keys is served statelessly under
  2026-07-28 (`resultType`, `serverInfo` in `_meta`,
  `server/discover`, `-32022` on an unsupported version). Anything
  else is served under the legacy handshake, echoing the client's
  version when we support it and offering 2025-11-25 otherwise.
  Tool annotations declare `readOnlyHint` so clients that gate on them
  need not prompt.

Client wiring is a one-liner per harness and lives in `docs/MCP.md`:
Claude Code (`claude mcp add`), Codex (`~/.codex/config.toml`
`[mcp_servers.loxodonta]`), and the Agents SDK (`MCPServerStdio`).

## Consequences

**What gets easier:**

- Every harness that speaks MCP can read the machine's agent memory,
  and the same text a human reads at the shell. Adapters for recording
  (ADR-0020) and this surface for reading together make loxodonta
  harness-neutral end to end.
- The read-only claim is now defended by tests, not by prose.
- The freeze on `loxodonta.py` survives another surface: the server
  imports nothing from the recorder and spawns it only for `verify`.

**What gets harder or more constrained:**

- `supervisor.py` grows past 4,900 lines. ADR-0009's revisit trigger —
  "outgrows one-sitting readability" — is now live, not hypothetical.
  This ADR does not split the file (stability during the public
  phase outranks tidiness), but the next reader-side slice should open
  with the cleave question, and recall is the natural line.
- The CLI's stdout is now a wire contract for a third audience
  (shell user, hook, MCP client). Changing a digest or show line
  changes what models read across every harness at once.
- Two protocol eras means two result shapes to keep straight. The
  era decision is made per request from `_meta` and nowhere else, so
  the server holds no session state to get wrong.

**What we'll have to revisit if:**

- A client needs MCP resources or prompts (e.g. the digest as a
  resource the client refreshes) — tools were chosen because every
  client supports them; resources are a second surface.
- The 2025-11-25 handshake stops appearing in the wild — the legacy
  branch then comes out.
- Anyone asks for a write tool with a good reason — the answer is
  still ADR-0002, but the ask should be recorded.

## Alternatives considered

- **A third file `recall_mcp.py` shelling out to `supervisor.py`** —
  rejected: ADR-0009 resolved "no third reader file," and a shell-out
  server would spawn a process per tool call for text the same file
  could render in-process.
- **The official `mcp` Python SDK** — rejected: the first dependency in
  a repo whose product claim is "no dependencies, ever," for a wire
  that fits in two hundred lines of stdlib.
- **Exposing `log` so agents can leave notes in their own chain** —
  rejected: ADR-0002. The chain's value is that the writer did not
  choose what went in it.
- **Exposing `scan`** — rejected: `scan` writes the baseline (a writer
  on a read-only surface) and its verdicts cover the whole store; a
  model asking about one chain gets `verify`, one chain, on request.
- **A richer query language while we are here** — rejected: nothing
  has shown the five plain commands insufficient for *queries*; this
  ADR reopens ADR-0009 on reach alone and leaves the query deferral
  standing.

## References

- Related ADRs: `0009-recall-surface-lives-in-the-supervisor.md`
  (extended: its MCP deferral is lifted on reach, not on query power);
  `0002-writer-as-adversary.md` (why no write tool); `0005-supervisor-
  as-sibling-tool.md` (`verify` runs through the public CLI);
  `0020-recorder-adapters-for-other-harnesses.md` (the write side of
  harness neutrality).
- Glossary terms: *Recall*, *Entry address*, *Testimony* (unchanged,
  load-bearing); *Supervisor* (role statement gains "and an MCP
  server").
- Prior art: observability MCP servers (read-side pattern), journalctl
  (carried from ADR-0009), MCP specification 2026-07-28 and 2025-11-25.
- Discussion: agent-first surface planning, 2026-09-02, prompted by the
  r/SaaS repost of Spittel's line.
