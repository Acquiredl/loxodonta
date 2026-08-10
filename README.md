# loxodonta

*An elephant never forgets.*

**receipts** — a tamper-evident flight recorder for AI agent pipelines. A small, stdlib-only CLI that gives any automation pipeline a hash-chained activity log: every action an agent takes leaves a receipt, every receipt is chained to the one before it, and a single command proves whether the history has been edited, deleted from, or reordered.

> **Status: design phase.** The format spec and decision records below are the current deliverable; implementation follows after design review. Nothing here is running code yet.

## the problem

AI agents are being wired into real workflows — writing files, calling tools, publishing content. When something goes wrong (or an auditor asks), the first question is *"what exactly did the agent do?"* Most pipelines answer with a plain log file. A plain log file proves nothing: anyone — including the agent itself, or the operator after the fact — can edit it, delete the embarrassing line, or backdate an entry, and no one can tell.

## the idea

Make every log entry contain the SHA256 hash of the previous entry. That single change turns a log into a **hash chain**: modify, remove, or reorder any entry and every later entry's recorded hash stops matching — the break is mechanically detectable, always, by anyone holding the file. Appending is the only operation that survives verification.

Each receipt also records the SHA256 of every file it touched, so "the report that passed review" and "the report on disk today" can be compared at any time.

```
receipts init                    # start a chain (writes the genesis entry)
receipts log --actor agent --action "wrote draft" --file report.md
receipts verify                  # walk the chain; exit 1 on any break
receipts report                  # human-readable timeline of the run
```

## what this defends against — and what it doesn't

Honest threat model, in both directions:

| Threat | Covered? | How |
|---|---|---|
| Editing a past entry | ✔ | chain break at that entry, detected by `verify` |
| Deleting an entry | ✔ | successor's `prev` no longer matches |
| Reordering entries | ✔ | every moved entry breaks its neighbor's link |
| Silently modifying a logged file after the fact | ✔ | file's current hash ≠ hash in its receipt |
| A compromised writer lying *at write time* | ✘ | garbage in, faithfully chained garbage out |
| The log owner regenerating the whole chain from scratch | ✘ in v0.1 | this is exactly what **anchoring** (Stage B) closes: committing the chain head to an external system — OpenTimestamps onto the Bitcoin blockchain — makes even a full rewrite detectable against the anchored head |

"Tamper-evident" is the precise claim: tampering is not prevented, it is *always detectable*. See [docs/SPEC.md](docs/SPEC.md) for the format and [adrs/](adrs/) for why a hash chain and not signatures.

## roadmap

- **Stage A — core:** format spec (done, in review) → stdlib-only CLI (`init` / `log` / `verify` / `report`) → tamper-demo test suite (edit / delete / reorder each caught).
- **Stage B — anchoring:** `receipts anchor` commits the chain head to Bitcoin via OpenTimestamps (free calendar servers, no wallet, no tokens); `verify` learns to check anchor proofs.
- **Stage C — agent adapter:** a Claude Code `PostToolUse` hook that logs every tool call automatically — any agent session becomes a verifiable flight recording; plus `receipts explain`, an optional LLM layer that narrates a run and flags anomalies.

## license

MIT
