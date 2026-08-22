# ADR-0005: The supervisor is a sibling single file that speaks only the public CLI

**Status:** `accepted` (2026-08-22)
**Date:** 2026-08-22
**Deciders:** Acquiredl

## Context

The dogfood closed early on 2026-08-21 with the verdict *push forward*, and the chosen direction is the reader side: a **supervisor** — an operator-side process that continuously verifies chains, holds a baseline, keeps anchors fresh, and monitors completeness ("session active but no receipts arriving" — the fork-shaped hole the 2026-08-14 incident exposed, which nothing currently watches). The glossary now defines the supervisor as *a tripwire with a memory*: detection latency only, never a wall; its baseline is deliberately **not** a head record, so ADR-0002's rejection of writer-reachable head state stands unamended.

That settled *what it is*. This ADR settles *what shape it takes* — because the repo's founding constraint reads "single-file `receipts.py`, stdlib only, readable top-to-bottom by a non-expert," and a resident process with a web frontend strains every clause of that sentence.

Prior art consulted: **SQLite + Litestream** (a frozen, self-contained artifact format, with a separate resident process adding continuous replication that the format never learns about); **SQLite's own repo shape** (the one-file amalgamation plus a separate CLI shell — "single file" survived as *single file per tool*); **Go's stdlib-served diagnostics** (`net/http/pprof`, `expvar` — production precedent that a stdlib HTTP server serving inline HTML is a legitimate, dependency-free window onto a running process).

## Decision

> **`receipts.py` stays frozen as the pure recorder/verifier. The supervisor is `supervisor.py` — a sibling single file in the same repo, bound by the same constraints: stdlib only, readable top-to-bottom, with `http.server` for its frontend. It drives receipts exclusively through the public CLI.** The repo constraint is restated as *single file per tool, each independently readable in one sitting*.

Concretely:

- No web framework, no build step, no package manager. The frontend is inline HTML/JS served by `supervisor.py`.
- `supervisor.py` invokes `receipts verify`, `receipts anchor`, etc. as subprocesses — it is *an operator that never sleeps*, speaking exactly the interface a human operator speaks. The exit-code verdict vocabulary (SPEC §6) was designed for scripts; the supervisor is the script it was built for.
- `receipts.py` gains nothing from this ADR: no imports of its internals, no new commands, no format change. v0.1 stays frozen.

## Consequences

**What gets easier:**

- `receipts.py` remains auditable in an afternoon, and its freeze is real: internals never become an API, so refactors inside the file break nobody.
- The supervisor is testable the same way everything else here is — through its own public surface — and its coupling to receipts is exactly the documented CLI contract, nothing more.
- The moat claim ("readable by a non-expert") survives per file, with SQLite's repo shape as the precedent for saying so honestly.

**What gets harder or more constrained:**

- A process spawn per check. Acceptable by design: the watch loop ticks in seconds and is not the hook's hot path — but the supervisor must batch sensibly (one `verify` per chain per tick, not per HTTP request).
- The CLI's *output* becomes a compatibility surface. The supervisor should lean on exit codes, which are frozen vocabulary; any stdout parsing must stick to documented verdict lines. If richer machine-readable output is ever wanted (`--json`), that is a CLI surface change and gets its own decision.
- Two files now carry the readability constraint, and the frontend can only be what stdlib `http.server` can serve — no websockets; polling or SSE-style chunked responses.

**What we'll have to revisit if:**

- The watch loop ever needs reaction times where subprocess spawn dominates — that pressure reopens the import question, consciously.
- The frontend needs push semantics beyond what stdlib can express.
- A second sibling tool appears — three files is a pattern, and "single file per tool" would deserve a fresh look at whether this is still the smallest honest shape.

## Alternatives considered

- **Import `receipts.py` as a module** — rejected: it silently converts internal functions into an API, un-freezing the file this ADR declares frozen, and violates the tests-through-public-interfaces convention in spirit.
- **Grow `receipts.py` with a `supervise` command** — rejected: a resident HTTP server living inside the readable verifier bloats the one file whose smallness is the product's moat, and couples the tool's most stable code to its least stable.
- **A web framework (Flask et al.)** — rejected: breaks stdlib-only, adds the first dependency, and the frontend's needs (status JSON + static HTML) don't come close to earning it.
- **A separate repo** — rejected: the supervisor shares this repo's vocabulary, threat model, fixtures, and opsec posture; splitting doubles maintenance and invites drift between the tool and its watcher.

## References

- Related ADRs: `0002-writer-as-adversary.md` (the tripwire claim and the rejected writer-reachable head state — the supervisor's baseline is *not* a head record); `0004-serialize-hook-appends.md` (two of its three revisit triggers are what the supervisor watches); `0001-hash-chain-not-signatures.md` (anchors as the only hard boundary, which the supervisor automates but never replaces).
- Glossary terms **added**: *Supervisor*, *Baseline* (both 2026-08-21, during the grill that produced this ADR). Term **protected**: *Head record* keeps its out-of-reach definition.
- Prior art: SQLite/Litestream, the SQLite amalgamation + shell split, Go `net/http/pprof`.
- Discussion: supervisor/frontend design grill, 2026-08-21 → 2026-08-22 (this repo, branch `claude/handoff-document-review-8c86e1`).
