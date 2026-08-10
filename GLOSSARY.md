# GLOSSARY — loxodonta

Ubiquitous language for this repo. The shared vocabulary between the codebase, its author, and the agent.

Every term in this file should be:
- Used in the code (variable names, file names, type names, function names).
- Used in your planning docs (PRDs, issues, ADRs).
- Used in conversations with the agent.

If a concept is in your head but not in this file, the agent will guess — and probably guess wrong. Add it.

---

## Core domain

### Receipt log

The single append-only JSON Lines file holding a chain of entries. Default filename `receipts.jsonl`. One writer per log. Anchors in code: the `--log` CLI flag and the spec's §1.

### Entry

One line of the receipt log: a JSON object with exactly `n`, `ts`, `actor`, `action`, `files`, `prev`, `entry_hash`. An entry *is* a receipt — the two words are interchangeable; "entry" is the code-facing term, "receipt" the human-facing one.

### Genesis

The entry with `n == 0` and `prev == null` — the only entry allowed a null `prev`. Written by `receipts init`. Marks the start of a chain; carries no file references.

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

The walk defined in `docs/SPEC.md` §6: schema → sequence → recomputed hash → chain rule → timestamps, optionally file checks. Produces a verdict, never repairs anything.

### Tamper-evident

The precise security claim of this tool: modifications to history are *always detectable*, never *prevented*. Deliberately weaker than "immutable" — see Anti-terms.

### Anchor *(Stage B)*

An external commitment of the chain head to a system the log owner doesn't control — OpenTimestamps onto the Bitcoin blockchain. Closes the whole-chain-regeneration gap named in ADR-0001. Anchor proofs live beside the log, not inside the entry format.

---

## Relationships

- A receipt log has exactly one genesis and zero-or-more subsequent entries.
- An entry references zero-or-more files; a file may be referenced by many entries (its latest reference is authoritative for `--files` checks).
- An anchor commits to exactly one chain head; a log may accumulate many anchors over time.

---

## States and transitions

- Verification verdict is one of: `VALID` (exit 0) | `BROKEN` (exit 1, chain integrity failed at ≥1 entries) | `FILES-DIVERGED` (exit 2, chain intact but a referenced file was modified since logging).
- A log never transitions backward: append is the only legal write; anything else moves the verdict to `BROKEN`.

---

## Sub-terms and orthogonal categories

- A *broken* chain is still a readable log — `report` works on it; only its integrity claim is gone. Broken ≠ unparseable.
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
