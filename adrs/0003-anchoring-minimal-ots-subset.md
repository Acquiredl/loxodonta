# ADR-0003: Anchoring via a minimal OpenTimestamps subset, implemented in-file

**Status:** `accepted` (2026-08-13)
**Date:** 2026-08-13
**Deciders:** Acquiredl

## Context

Stage B closes the whole-chain-regeneration gap named in ADR-0001: commit the chain head to something nobody holds. The chosen system is OpenTimestamps (OTS) — free public calendar servers aggregate digests into Bitcoin transactions; the resulting proof shows a digest existed by a given Bitcoin block, with no wallet, no tokens, and no standing service to operate.

The open question was **how the OTS client gets into this repo.** CLAUDE.md permits vendoring one for Stage B. The reference client (`opentimestamps-client` + `python-opentimestamps`) is several thousand lines across two packages — while the part receipts actually needs is small: submit a SHA256 digest to a calendar, parse the returned proof, later fetch the Bitcoin-attested completion, and replay a proof's operations offline. Real calendar proofs use a handful of operations: `sha256`, `append`, `prepend`, branch forks, and two attestation types (pending-calendar and Bitcoin-block-header).

## Decision

> **Implement a minimal OTS subset directly in `receipts.py`** — varint/varbytes wire codec, the `sha256`/`append`/`prepend` operations, fork handling, pending and Bitcoin attestations, and the two calendar HTTP calls — rather than vendoring the reference client. **Verification is offline and stops, honestly, at the Bitcoin block-header commitment:** `verify --anchors` replays the proof from a chain entry's hash to a claimed block height and merkle root, and tells the operator to confirm that root against a Bitcoin source they trust. The tool never fetches anything during `verify`.

## Consequences

**What gets easier:**
- The repo keeps its identity: one file, stdlib only, readable top-to-bottom. A vendored client would be the largest body of unread code in a project whose moat is that everything can be read.
- The proof format section becomes teachable — the OTS subset is ~150 commented lines, not a dependency boundary.
- `verify` stays a pure function of local files: no network, no nondeterminism, usable air-gapped.

**What gets harder or more constrained:**
- **Unknown operations are a refusal, not a guess.** A proof using an operation outside the subset (`sha1`, `ripemd160`, `keccak256`) fails with a clear "this verifier does not implement op X" — today's calendars don't emit these on the digest path, but the failure mode is honest if that changes.
- **The last hop is the operator's.** Offline replay proves "digest → merkle root R, claimed for block H." Whether R is really block H's root requires a block-header source (local node, explorer of choice). The tool prints exactly what to check and never pretends to have checked it.
- **What an anchor proves is existence-by-block-H, not authorship.** A writer that regenerates the chain can re-anchor — but only into a *recent* block. Detection is freshness reasoning: a log claiming months of history whose earliest anchor is from yesterday is regenerated. `verify --anchors` therefore reports block heights prominently; judging their plausibility stays with the operator (same division of labor as the head record, with the out-of-reach property outsourced to Bitcoin).
- Anchor proofs are **evidence beside the log** (SPEC §8 reserves no fields): sidecar `<log>.anchors.jsonl`. The sidecar is not chained — a forged proof fails replay, a deleted proof deletes evidence but forges nothing. Copying `.anchors.jsonl` out of the writer's reach is strictly stronger than a head record, since proofs are self-authenticating.

## Alternatives considered

- **Vendor `python-opentimestamps`** — rejected: thousands of unread lines against a ~150-line need; breaks single-file; the dependency-zero claim becomes an asterisk.
- **RFC 3161 timestamp authority (halo-record's route)** — rejected: requires trusting/operating a TSA; the prior-art survey names "anchoring without infrastructure" as this project's concrete edge.
- **Random nonce before submission (reference-client behavior)** — omitted: the nonce hides the submitted digest from calendar operators, but a chain head is already an opaque 32-byte value that reveals nothing. Fewer moving parts wins.
- **Online Bitcoin verification in `verify` (block explorer API)** — rejected: puts a trusted third party and a network dependency inside the one command whose whole job is local, mechanical judgment.

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (anchoring is that ADR's promised closure), `0002-writer-as-adversary.md` (the adversary anchoring finally beats).
- Format details and CLI: `docs/ANCHORING.md`.
- Prior-art landscape: the 2026-08-09 operator-side survey — rsyslog+KSI as the mechanistic analog (chain + commercial anchor); OpenTimestamps chosen precisely because its anchor is nobody's product.
- Glossary terms **added or sharpened**: *Anchor*, *Anchor proof*, *Calendar*.
