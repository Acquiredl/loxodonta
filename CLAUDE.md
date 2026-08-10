# loxodonta — repo map

**receipts**: a tamper-evident, hash-chained activity log ("flight recorder") for AI agent pipelines. Stdlib-only Python CLI. The elephant never forgets.

**Current phase: Stage A implementation.** SPEC v0.1 and ADR-0001/0002 are `accepted` (2026-08-10); the format is frozen. `receipts.py` gets written via `/tdd` against the frozen spec — behavior tested through the public CLI only.

## Read first

1. `GLOSSARY.md` — the vocabulary is settled; use it exactly (note the anti-terms: no "blockchain", no "immutable", no "audit log").
2. `docs/SPEC.md` — format spec v0.1-draft. The canonical-JSON rules in §4 are the load-bearing part.
3. `adrs/0001-hash-chain-not-signatures.md` — why no keys, and why anchoring (not signatures) closes the owner-rewrite gap.
4. `adrs/0002-writer-as-adversary.md` — the threat model: the agent writing the log is the adversary; drove head records, the `run` wrapper, and the completeness principle.
5. `docs/PRIOR-ART.md` — the 2026-08-09 landscape survey; read before making any public-positioning claim (halo-record is the competitor to diff against).

## Roadmap

- **Stage A** — spec review → stdlib-only CLI (`init` / `log` / `run` / `head` / `verify` / `report`) via `/tdd`, tamper-demo tests (edit / delete / reorder / splice / regenerate each caught).
- **Stage B** — `receipts anchor`: OpenTimestamps commitment of the chain head to Bitcoin; `verify` learns anchor proofs.
- **Stage C** — Claude Code `PostToolUse` hook adapter (auto-log every tool call) + `receipts explain` (LLM narration/anomaly layer).

## Constraints

- Python stdlib only for the core tool — no dependencies, ever, for Stage A. (Anchoring in Stage B may vendor an OpenTimestamps client; that gets its own ADR.)
- Single-file `receipts.py`, readable top-to-bottom by a non-expert. Readability outranks cleverness everywhere in this repo.
- Tests verify behavior through the public CLI surface, not internals.
- This repo will be public under the **Acquiredl** identity (repo-local git config is set; noreply email). Keep all personal identifiers out of this repo; Acquiredl identity only.

## Git autonomy

**Level:** commit — auto-commit at logical breakpoints; push/PR/merge always ask. Rationale: solo greenfield project, fast iteration wanted, but nothing leaves the machine without explicit say-so (public-portfolio repo; opsec review happens before any push).
