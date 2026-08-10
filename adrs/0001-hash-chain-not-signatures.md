# ADR-0001: Tamper evidence via hash chain, not digital signatures

**Status:** `proposed`
**Date:** 2026-08-09
**Deciders:** Acquiredl

## Context

receipts must let anyone holding a receipt log detect whether its history was edited, deleted from, or reordered. Two credible mechanisms exist: chain entries by hash (each entry commits to its predecessor), or sign each entry with a private key. The tool targets solo operators and small pipelines first — people who will not run key infrastructure — and "simple but solid, readable by a layman" is an explicit design goal of the project.

## Decision

> We chose a **hash chain with no keys** for the core format, and we close the chain's one structural weakness — the log owner regenerating the entire chain — with **external anchoring** (Stage B, OpenTimestamps onto Bitcoin) rather than with signatures.

## Consequences

**What gets easier:**
- Zero key management: nothing to generate, store, rotate, or lose. `receipts init` works in one second with no setup.
- Stdlib-only implementation (`hashlib`, `json`) — no crypto dependencies, auditable in an afternoon.
- Verification requires only the file itself; any third party can verify without any public-key distribution.
- The layman explanation stays one sentence: "every entry contains the fingerprint of the one before it."

**What gets harder or more constrained:**
- The chain proves *internal consistency*, not *authorship* — it cannot say **who** wrote an entry.
- The log owner can rewrite history wholesale by regenerating every hash. Until an anchor exists, the guarantee is only "not edited since the chain was built," not "not edited since the events happened."
- Multi-writer scenarios (several agents, one log) have no per-writer accountability.

**What we'll have to revisit if this changes:**
- If receipts ever targets adversarial multi-party settings (client + contractor both writing), per-entry signatures return to the table — likely as an optional layer on top of the same canonical form, since the canonical bytes are exactly what a signature would sign.

## Alternatives considered

- **Ed25519 signatures per entry** — rejected for v0.1: key management is the entire UX cost of the tool, and a lost key bricks verification; solves authorship, which is not the Stage A problem.
- **Merkle tree over entries** — rejected: buys efficient partial proofs (prove entry 5 without revealing entries 1–4), which no current use case needs; costs significant explainability. A linear chain *is* a degenerate Merkle structure; upgrading later doesn't break the entry format.
- **Signed git commits as the log** (one commit per receipt) — rejected: couples the audit trail to git presence and habits, drags the full working tree into every receipt, and makes "drop into any pipeline" false.

## References

- Related ADRs: `0002-writer-as-adversary.md` (names the adversary this mechanism serves).
- Prior-art landscape: `docs/PRIOR-ART.md` — the 2026-08-09 survey found the niche's closest competitors chose Ed25519 signatures; this ADR's reasoning (whoever holds the key can rewrite and re-sign; anchoring binds history to something nobody holds) must therefore surface in the README, not only here.
- Glossary terms **added or sharpened**: `GLOSSARY.md` — *hash chain*, *chain head*, *tamper-evident*, *anchor*, *canonical form*.
- Glossary terms **retired**, and topologies overruled: none — first ADR of the repo.
- Discussion: design conversation, Cowork session 2026-08-09 (career/portfolio thread).
