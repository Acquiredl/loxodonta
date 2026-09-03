# The recall surface over MCP — `supervisor mcp`

`python supervisor.py mcp` serves the recall surface (Stage E,
ADR-0009) as a Model Context Protocol server on stdio, so any agent
that speaks MCP can read this machine's receipt chains as memory — not
only the harness that runs our hooks. It is the same five commands, in
the same words: what the model reads is byte-for-byte what a shell
user reads (the tests hold this). It is read-only, and that is a
decision, not an omission (ADR-0019).

## What the model gets

| Tool | The CLI command it is | What it answers |
|---|---|---|
| `digest` | `supervisor digest` | this repo's recent history, one row per action or run of actions, budget-capped, testimony-labeled |
| `show` | `supervisor show ADDRESS` | one full receipt by entry address, re-hashed on fetch (self-verifying) |
| `search` | `supervisor search TEXT [--all]` | free-text over action lines, this repo or the whole store |
| `timeline` | `supervisor timeline ADDRESS` | the rows around one entry in its own chain |
| `verify` | `loxodonta verify --log <chain>` | the judge's verdict for the chain holding that address, exit code and all |

Every tool except `verify` renders testimony and says so (GLOSSARY:
*Recall*). `verify` is the one tool that is not testimony: it spawns the
recorder's own judge and returns its words unchanged — `VALID`,
`BROKEN`, `FILES-DIVERGED`, whatever it said.

Arguments are validated before anything runs, and a bad one comes back
as a tool error in plain words (`missing required argument: address`),
the same for a CLI error (`no entry under <repo> matches deadbeef`), so
the model can act on it instead of seeing a protocol failure. A digest
of a repo with no chains says `no receipts recorded under <repo>` — the
one place the tool differs from the CLI, which stays silent there
because the SessionStart hook must.

**There is no write tool.** No `log`, `run`, `hook`, `init`, `anchor`,
`adopt`, `scan`. The recorder is fed by the harness hook, outside the
agent's volition (SPEC §8, ADR-0002); an agent that could append
receipts through a tool it controls would be the writer choosing its
own history, which is the one thing this repo exists to prevent. The
tests assert the tool list never names a writer and that every chain is
byte-identical after a session that exercised every tool.

## Wiring it

The server takes one optional argument, `--repo DIR`: the repo whose
memory tools read when a call names none (default: `CLAUDE_PROJECT_DIR`,
else the working directory). Any tool call can override it with `repo`,
and `all: true` reaches every repo in the store (unlisted repos stay
invisible from outside themselves, as everywhere in recall).

**Claude Code** — one command, then restart the session:

```
claude mcp add loxodonta -- python /absolute/path/to/supervisor.py mcp
```

**Codex CLI** — in `~/.codex/config.toml`:

```toml
[mcp_servers.loxodonta]
command = "python"
args = ["/absolute/path/to/supervisor.py", "mcp"]
```

**OpenAI Agents SDK** — the SDK's stdio MCP client, attached to an
agent:

```python
from agents import Agent
from agents.mcp import MCPServerStdio

recall = MCPServerStdio(params={
    "command": "python",
    "args": ["/absolute/path/to/supervisor.py", "mcp"]})
async with recall:
    agent = Agent(name="assistant", instructions="...", mcp_servers=[recall])
```

Any other MCP client: launch `python supervisor.py mcp` as a stdio
server. Use the absolute path on every platform; the server has no
dependencies beyond Python 3.9+.

## Protocol notes

The server is dual-era. A request whose `_meta` carries
`io.modelcontextprotocol/*` keys is served under the 2026-07-28
revision (stateless: `resultType` on every result, `serverInfo` in the
result's `_meta`, `server/discover`, error `-32022` with the supported
list on an unknown version). Anything else is served under the legacy
`initialize` handshake (2025-11-25 and earlier): the client's version
is echoed when supported, 2025-11-25 offered otherwise. The era is
decided per request from `_meta` alone — the server holds no session
state to get wrong.

Wire hygiene: newline-delimited JSON-RPC 2.0, UTF-8, one message per
line. Nothing but MCP messages ever reaches stdout; every tool call
runs under a redirect so the CLI's own `print` cannot corrupt the
stream. Malformed JSON is answered with `-32700`, an unknown method
with `-32601`, an unknown tool with `-32602`. Notifications are never
answered. The process exits when stdin closes.

Tool annotations declare `readOnlyHint: true`, `destructiveHint:
false`, `idempotentHint: true`, `openWorldHint: false`, so clients that
gate on annotations need not prompt for every call. Clients are told
to treat annotations as untrusted; the test suite is the trust.

## What this is not

Not a richer query surface. ADR-0009 deferred filters, aggregation, and
a query language until the plain commands prove insufficient, and
nothing has shown that. This ADR reopened MCP on *reach* — harnesses
that cannot run our hook — and left the query deferral standing. Not a
resource or prompt provider either: tools were chosen because every
client supports them; a `digest` resource the client refreshes is a
second surface, listed under ADR-0019's revisit triggers.
