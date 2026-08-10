# Prior art — landscape survey

**Date:** 2026-08-09 (design phase, before implementation). Star counts and activity are as of this date; low-confidence items are flagged inline.

Surveyed before writing a line of code, in three sweeps: established systems-world tamper-evident logging, AI-agent-specific audit tooling, and small direct competitors. Verdict up front: **the mechanism is decades old, the niche is forming right now, and receipts' position is the smallest honest implementation with the best-argued threat model — not the first implementation.**

## The three rings

### 1. Mainstream AI observability — empty on integrity, and staying empty

LangSmith, Langfuse, AgentOps, Helicone, Braintrust, W&B Weave, and the OpenTelemetry GenAI semantic conventions all trace agent runs; **none makes any tamper-evidence claim.** They answer "what did the agent do?" with telemetry the operator (or the agent) can silently rewrite. OWASP's MCP Top 10 (2025) lists "Lack of Audit and Telemetry" (MCP08) as a named protocol gap.

### 2. Enterprise / systems world — right mechanism, wrong shape

The cryptography receipts uses is thoroughly established prior art, none of it packaged as a drop-in file-level tool:

| System | Mechanism | Why it isn't this tool |
|---|---|---|
| Certificate Transparency (RFC 6962/9162) | Merkle tree + signed tree heads | An internet-scale multi-party ecosystem (logs, monitors, auditors), not a CLI. A linear hash chain is its degenerate case. |
| Google Trillian / Sigstore Rekor | Merkle tree, gRPC + database | Server infrastructure; Trillian is in maintenance mode; Rekor is a hosted public log for software signing. |
| immudb | Merkle hash trees | A full database server with SDKs. |
| Amazon QLDB | Merkle "digests" | **Discontinued 2025.** AWS's recommended migration (Aurora) loses cryptographic verifiability — the managed-cloud answer to this problem evaporated. |
| systemd-journald FSS | Forward-secure sealing keys | Linux/systemd-only, binary format, key management; rarely enabled. Cryptanalysis exists (eprint 2023/867). |
| RFC 5848 signed syslog | Per-block signatures + PKI | Key-dependent; real-world adoption unverified/minimal. |
| rsyslog + GuardTime KSI | Local hash chain + commercial anchor | Closest mechanistic analog to receipts' chain+anchor two-tier design — but tied to rsyslog and a commercial anchoring service. |
| IETF SCITT | COSE receipts, transparency registries | Standards-track enterprise ledger infrastructure. |

### 3. The micro-niche — tamper-evident logs for AI agents, forming now

Eight-to-ten projects converged on "hash chain + verify command for agent activity" within roughly twelve months of this survey, most marketing against the EU AI Act's record-keeping article (Article 12, enforcement from 2026-08-02). Notable: Article 12 requires *automatic logging and retention*, **not** cryptographic tamper-evidence — competitors sell the chain as a compliance upsell.

Most of the niche reached for signatures (opposite of ADR-0001): **Obsigna/agent-receipts** (Ed25519 + key-holding daemon, 3-language protocol, Alloy-verified invariants, pre-1.0), **ai-audit-trail** (Ed25519 + Merkle batch sealing, compliance-suite framing), **Nobulex**, **AgentStamp**, **Pipelock** (signed receipts as a byproduct of a commercial agent firewall), **Microsoft Agent Governance Toolkit** (HMAC + Merkle, full governance platform). Keyless like us: **GoLogX** (Go, stdlib-only, honest about the truncation gap, ~5 stars) and the one that matters most:

## The closest competitor: halo-record

[github.com/bkuan001/halo-record](https://github.com/bkuan001/halo-record) — Python, stdlib-only, zero dependencies, SHA-256 hash chain over RFC 8785 canonical JSON, explicitly keyless, external anchoring (RFC 3161 timestamp authority + optional witness service), **and a shipped Claude Code `PostToolUse` hook**. Apache-2.0, ~4,800 LOC, 11+ subcommands, ~62 stars, created 2026-06, actively maintained. It is receipts' Stage A + B + C thesis, already on PyPI.

Read it before implementing; credit it in the README. Differentiation against it specifically:

- **Size and legibility.** ~4,800 lines and 11+ subcommands vs. a single file a non-expert reads in one sitting and six commands (`init` / `log` / `run` / `head` / `verify` / `report`). No surveyed tool claims "readable top-to-bottom by a layman" as a design constraint. That constraint is this repo's moat — see `CLAUDE.md`.
- **Anchoring without infrastructure.** halo-record's rewrite-gap answer needs a timestamp authority or a witness service someone must operate. OpenTimestamps (Stage B) is free, decentralized, and needs no standing service — pick-up-and-verify with nothing running.
- **Threat-model writing.** On Hacker News, halo-record was hit with the integrity-vs-completeness objection and answered it operationally ("publish checkpoints as a practice"). This repo's spec answers it structurally: *integrity is the tool's job; completeness is the integration's job* (`SPEC.md` §8, ADR-0002), with the `run` wrapper and hook as the completeness mechanisms. The agent-as-adversary framing (ADR-0002) appears nowhere in the niche except one academic paper ("Notarized Agents," arXiv 2606.04193, which goes further via receiver-side signing).

## Practical warnings

- **Naming:** `agent-receipts` is taken on PyPI (Obsigna); a package named `receipts` would collide in search and mindshare. Decide the distribution name (likely `loxodonta`) before anything is published.
- **Patent:** Attested Intelligence holds a filed US patent application (19/433,835, Dec 2025) on signed-evidence-bundle receipt architecture for MCP governance. receipts' keyless design likely stays clear; do not drift toward "signed evidence bundles" without checking claims scope.
- **Keyless must be argued where readers land.** Both nearest name-competitors use Ed25519; without the README stating *why* no keys (whoever holds the key can rewrite and re-sign; anchoring binds history to something nobody holds), "no signatures" reads as a missing feature instead of a decision.
- Low-confidence items from the survey, kept out of the tables above: OpenFang (marketing spread across near-identical repos; claims unverified), ChainProof and several SEO-style "AI audit" sites (templated content, unverified).

## What this changes about the roadmap

Nothing structural; two emphases. (1) Stage B (anchoring) is promoted in spirit from "stretch" to "the point" — it is both the honest closure of the regeneration gap and the concrete edge over halo-record. (2) The README's job is positioning discipline: *flight recorder, not intrusion detector; tamper-evident, not immutable; smallest honest implementation, with the reasoning shown.*

## Cross-references

- `adrs/0001-hash-chain-not-signatures.md` — the keyless decision this survey stress-tested; survives, but must surface in the README.
- `adrs/0002-writer-as-adversary.md` — the threat model that differentiates this project's writing from the niche.
- `docs/SPEC.md` §8 — the completeness principle the niche's closest competitor lacks.
