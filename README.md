# loxodonta

*An elephant never forgets.*

**receipts** — a tamper-evident flight recorder for AI agent pipelines. A small, stdlib-only CLI that gives any automation pipeline a hash-chained activity log: every action an agent takes leaves a receipt, every receipt is chained to the one before it, and a single command proves whether the history has been edited, deleted from, or reordered.

> **Status: Stages A–D built.** Format spec v0.1 is frozen (`docs/SPEC.md`); the decision records are `accepted`. The core CLI, Bitcoin anchoring, and the Claude Code hook adapter are built and tested; a local dogfood (`DOGFOOD.md`) closed 2026-08-21 with the verdict *push forward*, and recording has run machine-wide since. Stage D added the reader side: `supervisor.py`, an operator that never sleeps. The suite stands at 201 behavioral tests, all through the public CLI. Remaining before going public: a human readability walk of the supervisor plus an adversary pass (issue #25).

## the problem

AI agents are being wired into real workflows — writing files, calling tools, publishing content. When something goes wrong (or someone asks), the first question is *"what exactly did the agent do?"* Most pipelines answer with a plain log file. A plain log file proves nothing: anyone — including the agent itself, or the operator after the fact — can edit it, delete the embarrassing line, or backdate an entry, and no one can tell.

## the idea

Make every log entry contain the SHA256 hash of the previous entry. That single change turns a log into a **hash chain**: modify, remove, or reorder any entry and every later entry's recorded hash stops matching — the break is mechanically detectable, always, by anyone holding the file. Appending is the only operation that survives verification.

Each receipt also records the SHA256 of every file it touched, so "the report that passed review" and "the report on disk today" can be compared at any time.

## quickstart

One file, no dependencies — copy `receipts.py` anywhere Python 3.9+ runs (`alias receipts='python3 /path/to/receipts.py'`):

```
receipts init                                                   # start a chain (writes the genesis entry)
receipts log --actor agent --action "wrote draft" --file report.md
receipts run --actor agent --file report.md -- python make_draft.py
                                 # run a command; it cannot skip its own receipt
receipts verify                  # walk the chain; exit 1 on any break
receipts head                    # print the chain head — record it out of the agent's reach
receipts verify --expect-head <hex>   # catch a wholesale rewrite, against your recorded head
receipts report                  # human-readable timeline of the run
```

Then, the outer layers:

```
receipts anchor                  # commit the head to Bitcoin via OpenTimestamps (free, no wallet)
receipts anchor --upgrade        # complete the proof once Bitcoin has it (a few hours later)
receipts verify --anchors        # judge anchor proofs, offline — see docs/ANCHORING.md
receipts explain                 # LLM narration of the log (testimony, not a verdict)
```

And for Claude Code sessions, a `PostToolUse` hook turns every tool call into a receipt automatically — the agent cannot skip its own receipt. Wiring in [docs/HOOK.md](docs/HOOK.md).

## the supervisor

Chains only earn their keep if someone reads them, and nobody reads logs daily. `supervisor.py` is the operator that never sleeps: a sibling single file under the same constraints (stdlib only, readable top-to-bottom — the repo rule is *single file per tool*, ADR-0005) that drives receipts exclusively through the public CLI:

```
python supervisor.py scan      # one tick: census of every chain on the machine, verdicts, exit code
python supervisor.py serve     # localhost-only status page: recall front page with search, verdict tiers
python supervisor.py drill     # rehearse detection: tamper battery on a sandbox copy — real chains untouched
```

It remembers chain heads between looks (a baseline tripwire), alarms when a session is active but no receipts arrive (the completeness alarm — the failure mode nothing else watches), keeps anchors fresh (`--anchor-every`), and re-verifies chains in the browser via WebCrypto so the page's verdicts don't ask you to trust the server that rendered them. The claim is deliberately modest: **a tripwire with a memory** — it shortens the window between tampering and discovery, and it is never a wall. Everything it stores is reachable by the writer, so nothing it holds is a head record; anchors remain the only hard boundary (ADR-0002 stands unamended). Rehearsal script and honest limits: [docs/FIRE-DRILL.md](docs/FIRE-DRILL.md).

## why no keys

The nearest tools in this niche sign each entry with Ed25519. receipts deliberately doesn't: whoever holds the signing key can rewrite history and re-sign it, so on a single machine a key adds ceremony without adding proof — and key management is the entire UX cost of such a tool. Instead, the chain proves internal consistency, and **anchoring** binds the history to something nobody holds: the chain head is committed to Bitcoin via OpenTimestamps, so entries provably existed before the block that anchors them. No wallet, no tokens, no service to operate. (ADR-0001; the threat model that drives everything is ADR-0002 — the writer of the log, in practice an AI agent, is the primary adversary.)

## what this defends against — and what it doesn't

Honest threat model, in both directions:

| Threat | Covered? | How |
|---|---|---|
| Editing a past entry | ✔ | chain break at that entry, detected by `verify` |
| Deleting an entry | ✔ | successor's `prev` no longer matches |
| Reordering entries | ✔ | every moved entry breaks its neighbor's link |
| Silently modifying a logged file after the fact | ✔ | file's current hash ≠ hash in its receipt |
| A compromised writer lying *at write time* | ✘ | garbage in, faithfully chained garbage out |
| The writer omitting an entry entirely | ✘ for the chain itself | a never-written entry leaves no break to detect — completeness comes from moving the `log` call outside the writer's volition (`receipts run`, gate scripts, the hook adapter) |
| The writer (or anyone with write access) regenerating the whole chain from scratch | tiered | `receipts head` + `verify --expect-head` catch a full rewrite against an operator-held head record; **anchoring** removes the operator's memory burden — a regenerated chain can only carry *young* anchors, and `verify --anchors` puts every anchor's Bitcoin block height in front of the operator |

"Tamper-evident" is the precise claim: tampering is not prevented, it is *always detectable*. See [docs/SPEC.md](docs/SPEC.md) for the format, [docs/ANCHORING.md](docs/ANCHORING.md) for the anchor tiers, and [adrs/](adrs/) for the reasoning.

## prior art

The mechanism is decades old (Certificate Transparency's linear ancestor; rsyslog + KSI is the closest chain-plus-anchor analog) and a niche of agent-focused tools formed in 2026 — the closest being [halo-record](https://github.com/bkuan001/halo-record), which is worth a look. This project's position: the smallest honest implementation — one readable file per tool, six core commands plus three outer-layer ones (`anchor` / `hook` / `explain`), a written threat model, and anchoring that needs no infrastructure. See `docs/PRIOR-ART.md` for the survey.

## roadmap

- **Stage A — core** *(done)*: frozen format spec → stdlib-only CLI (`init` / `log` / `run` / `head` / `verify` / `report`) → tamper-demo test battery (edit / delete / reorder / splice / regenerate / torn tail each caught) → golden fixture pinning canonicalization forever.
- **Stage B — anchoring** *(done)*: `receipts anchor` commits the chain head to Bitcoin via OpenTimestamps; `verify --anchors` judges proofs offline. ADR-0003.
- **Stage C — agent adapter** *(done)*: `receipts hook`, a Claude Code `PostToolUse` adapter — any agent session becomes a verifiable flight recording; plus `receipts explain`, an optional LLM layer that narrates a run and flags anomalies.
- **Stage D — supervisor** *(done)*: the reader side. A dogfood (2026-08-13 → 2026-08-21, journal in `DOGFOOD.md`) closed early with the verdict *push forward* and one persistent lesson — the everyday value of the chains is *recall*, reading them as memory, not only as evidence — so Stage D built the operator that never sleeps: `supervisor.py`, ADR-0005.
- **Beyond the tools**: this repo's decision records also serve as the canon for *derived trail designs* — systems that chain findings rather than tool calls. ADR-0006 (evidence grades), ADR-0007 (the package manifest as a single sealing surface), and ADR-0008 (issuer signatures, admitted for cross-party delivery and nowhere else) exist for those designs; `receipts.py` itself stays frozen at v0.1 and gains nothing from them.
- **Next**: the go-public gate — a human readability walk of the supervisor, an adversary pass, and a dogfood handover (issue #25). Positioning discipline per `docs/PRIOR-ART.md`.

## license

MIT
