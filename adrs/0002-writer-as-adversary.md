# ADR-0002: The writer is the primary adversary

**Status:** `accepted` (2026-08-10)
**Date:** 2026-08-09
**Deciders:** Acquiredl

## Context

The original design docs framed the tool's one structural gap — whole-chain regeneration — as "the log owner rewriting history," an edge case deferred to Stage B anchoring. The design grill of 2026-08-09 surfaced the problem with that framing: in the target use case, the **writer is an AI agent with the same filesystem access as the operator**. An agent can be prompt-injected by content it reads; an injected agent's cleanest cover-up is editing its own log. The predecessor system (Acu) could dismiss log tampering as "self-sabotage" because writer and operator were the same person. The moment they aren't, the deferred gap becomes the primary adversary's easiest move.

Four candidate purposes were weighed: (A) operator forensics, (B) the agent as untrusted writer, (C) third-party proof, (D) compliance artifact. A plain log already serves A; C and D require anchoring (Stage B) to be honest.

## Decision

> **Purpose B is the product: receipts exists so that a writer — in practice, an AI agent — that edits, deletes, reorders, or wholesale-regenerates its own history is always caught.** Operator forensics falls out for free; third-party proof begins at Stage B.

## Consequences

This one reframing drove five v0.1 features, all decided in the same session:

- **`receipts head` + `verify --expect-head` (exit 3, `HEAD-MISMATCH`)** — the writer can regenerate an internally-`VALID` chain, so the operator holds a *head record* outside the writer's reach. The tool deliberately does **not** store heads locally: a state file the writer can also reach is false security.
- **The completeness principle** — a chain cannot prove an entry was never written. Integrity is the tool's job; completeness is the integration's job (`receipts run`, gate scripts, Stage C hook — the `log` call sits outside the writer's volition).
- **No repair command** — a sanctioned way to trim a log's tail is exactly the capability an adversary with a "crash" cover story wants. Torn tails get a distinct message; the operator repairs by hand.
- **Testimony vs. mechanical facts** — `ts`, `actor`, `action` are writer-supplied testimony and can at most raise warnings; verdicts come only from what verify can recompute (hashes, sequence, chain, head).
- **Tiered guarantee, stated honestly** — surgical tampering is caught unconditionally; regeneration is caught only against a head record (or, from Stage B, an anchor). The public claim must never blur the tiers.

**What gets harder:**

- The strongest Stage A guarantee requires an operator ritual (record the head out of reach). Drop-in users silently get the lower tier — docs must present the tiers explicitly.
- Positioning discipline: this is an accountability/forensic-integrity layer (flight recorder), **not** a detection or prevention feature. "Security audit" phrasing overclaims; write-time lies remain garbage in, faithfully chained garbage out.

## Alternatives considered

- **Third-party proof as primary purpose (C)** — rejected for Stage A: without anchoring, a verifier who isn't the operator cannot distinguish an honest chain from a regenerated one; claiming C before Stage B would be dishonest.
- **Auto-tracked head state file (e.g. `~/.receipts/heads`)** — rejected: anything the operator's machine stores, the agent on that machine can likely rewrite; false sense of security.
- **Signatures for writer accountability** — already rejected in ADR-0001; unchanged. Anchoring (Stage B) closes the regeneration gap without keys.

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (the mechanism; this ADR names the adversary).
- Prior-art landscape: the 2026-08-09 operator-side survey ( the agent-as-adversary framing is absent from the competitive niche).
- Glossary terms **added or sharpened**: *Operator*, *Writer*, *Head record*, *Completeness*, *Tamper-evident* (tier scoping), *Genesis* (pinned, versioned).
- Discussion: design grill session, 2026-08-09 (this repo, branch `claude/project-design-grill-8c20e2`).
