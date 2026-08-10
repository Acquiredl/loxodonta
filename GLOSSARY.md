# GLOSSARY — loxodonta

Ubiquitous language for this repo. The shared vocabulary between the codebase, its author, and the agent.

Every term in this file should be:
- Used in the code (variable names, file names, type names, function names).
- Used in your planning docs (PRDs, issues, ADRs).
- Used in conversations with the agent.

If a concept is in your head but not in this file, the agent will guess — and probably guess wrong. Add it.

---

## Roles

### Operator

The human who owns the machine and the receipt log, and who runs `verify`. The operator's job in the trust story is exactly one thing: keep a [head record](#head-record) somewhere the writer cannot reach.

### Writer

The process that appends entries to the log — in the target use case, an AI agent (directly in Stage A, via a harness hook in Stage C). The writer is **semi-trusted**: trusted to run, *not* trusted to leave history alone afterward. The writer is the tool's primary adversary — receipts exists so that a writer that edits, deletes, or reorders its own history is always caught. One writer per log.

The writer/operator split is the load-bearing idea of the project: in Acu (the predecessor), writer and operator were the same person, so log tampering was "self-sabotage" and a plain JSONL file sufficed. An AI agent with filesystem access is a semi-trusted third party operating inside your machine — that is what makes the chain earn its keep.

### Head record

An operator-held copy of the chain head, stored **outside the writer's reach** — another machine, a password-manager note, a message to self. Input to `verify --expect-head`. The tool never stores heads locally on the operator's behalf (a state file the writer can reach is false security). Stage B anchors are head records with the out-of-reach property outsourced to Bitcoin.

---

## Core domain

### Receipt log

The single append-only JSON Lines file holding a chain of entries. Default filename `receipts.jsonl`. One writer per log. Anchors in code: the `--log` CLI flag and the spec's §1.

### Entry

One line of the receipt log: a JSON object with exactly `n`, `ts`, `actor`, `action`, `files`, `prev`, `entry_hash`. An entry *is* a receipt — the two words are interchangeable; "entry" is the code-facing term, "receipt" the human-facing one.

### Genesis

The entry with `n == 0` and `prev == null` — the only entry allowed a null `prev`, and the only entry carrying `v`, the format version. Written by `receipts init` with pinned contents (`actor: "receipts"`, `action: "genesis"`, `files: []`); only its timestamp varies. The chain's title page: who started it, when, and under which rulebook — all hash-committed, so a chain can't be relabeled to a different version without breaking.

### Canonical form

The deterministic serialization of an entry (minus its `entry_hash` field) defined by the six rules in `docs/SPEC.md` §4: sorted keys, compact separators, UTF-8, integers only, no trailing newline. **The hash is always computed over canonical form**, regardless of how the line is written on disk.

### Entry hash

`SHA256(canonical form)` of the entry, lowercase hex, stored in the entry's `entry_hash` field. What the *next* entry's `prev` commits to.

### Chain rule

The invariant `entry[n].prev == entry[n-1].entry_hash` for all `n ≥ 1`. The property that makes the log a hash chain rather than a list of independent lines.

### Chain head

The `entry_hash` of the last entry. Commits to the entire history — this is the value an anchor pins externally.

### File reference

A `{path, sha256}` pair inside an entry's `files` array: the fingerprint of one file at log time. Paths are relative to the log's directory, forward slashes, sorted by path within the entry.

### Verify

The walk defined in `docs/SPEC.md` §6: schema → sequence → recomputed hash → chain rule → timestamps, optionally file checks, optionally head comparison (`--expect-head`). Produces a verdict, never repairs anything.

### Tamper-evident

The precise security claim of this tool: modifications to history are *always detectable*, never *prevented*. Deliberately weaker than "immutable" — see Anti-terms. Scope in v0.1: *surgical* tampering (edit / delete / reorder / file swap) is detectable unconditionally; *whole-chain regeneration* is detectable only against a head record (`--expect-head`) or, in Stage B, an anchor.

### Completeness

The property receipts deliberately does **not** guarantee: that every action produced an entry. The chain proves integrity of *what was logged*; a writer that never calls `log` leaves no break to detect. Completeness comes from the integration — placing the `log` call outside the writer's volition (`receipts run`, pipeline gate scripts, the Stage C harness hook). Slogan form: *integrity is the tool's job; completeness is the integration's job.*

### Anchor *(Stage B)*

An external commitment of the chain head to a system the log owner doesn't control — OpenTimestamps onto the Bitcoin blockchain. Closes the whole-chain-regeneration gap named in ADR-0001. Anchor proofs live beside the log, not inside the entry format.

---

## Relationships

- A receipt log has exactly one genesis and zero-or-more subsequent entries.
- A workflow with parallel writers uses one log **per writer** (sibling chains). Chains never share a file; merging happens only at display time in `report`.
- An entry references zero-or-more files; a file may be referenced by many entries (its latest reference is authoritative for `--files` checks).
- An anchor commits to exactly one chain head; a log may accumulate many anchors over time.

---

## States and transitions

- Verification verdict is one of: `VALID` (exit 0) | `BROKEN` (exit 1, chain integrity failed at ≥1 entries) | `FILES-DIVERGED` (exit 2, chain intact but a referenced file was modified since logging) | `HEAD-MISMATCH` (exit 3, chain internally valid but its head differs from the operator's head record — the whole-chain-regeneration case). `UNSUPPORTED-VERSION` (exit 4) is a refusal to judge, not a verdict: the log's genesis declares a format this verifier doesn't speak.
- A log never transitions backward: append is the only legal write; anything else moves the verdict to `BROKEN`.

---

## Sub-terms and orthogonal categories

- A *broken* chain is still a readable log — `report` works on it; only its integrity claim is gone. Broken ≠ unparseable.
- A *torn tail* is the one honest way a log gets damaged: the final line truncated by a crash mid-append. Verify reports it distinctly (entries before it are intact; operator trims the partial line by hand) but it is still `BROKEN`/exit 1. A malformed line anywhere *else* has no innocent explanation and reports as ordinary tampering.
- An *anchored* chain is still just a chain — anchoring adds an external proof, it does not change any entry.

---

## Anti-terms (deliberately not used)

- ~~blockchain~~ — implies consensus, multiple writers, and tokens. This is a single-writer hash chain; say *hash chain*.
- ~~immutable~~ — overclaims. Nothing prevents mutation; mutation is detected. Say *tamper-evident* (and *anchored* once Stage B applies).
- ~~audit log / audit trail~~ — Acu's term for its *non-chained* JSONL gate log, the system this project improves on. Using it here blurs exactly the distinction the project exists to make. Say *receipt log*.
- ~~signature~~ — no keys exist in v0.1 (ADR-0001). If signatures ever arrive they get their own ADR and glossary entry.

---

## Cross-references

- ADRs that touched this glossary: `adrs/0001-hash-chain-not-signatures.md`
- Related out-of-scope decisions: none yet.

---

*Last updated: 2026-08-09*
