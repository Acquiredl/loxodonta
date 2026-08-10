# receipts format specification

**Version:** 0.1
**Status:** accepted 2026-08-10 (ADR-0001, ADR-0002 both `accepted`) — v0.1 is **frozen**; any format change requires a new version and a new chain (§2.1).

This document defines the receipt log format precisely enough that an independent implementation, in any language, produces byte-identical hashes. That reproducibility is the whole game: a hash chain is only as trustworthy as the serialization rules underneath it.

## 1. The receipt log

A receipt log is a single UTF-8 text file, JSON Lines format (one JSON object per line, `\n` line endings, no trailing whitespace). Default filename: `receipts.jsonl`.

- Line 0 is the **genesis entry**.
- Every subsequent line is an **entry** appended in strictly increasing sequence.
- The file is append-only. Any other mutation is tampering by definition.
- Writers SHOULD append each entry as a single write of one complete line (`{...}\n`) so a crash mid-append can at worst truncate the final line (see *torn tail*, §6) — never interleave or damage earlier entries.

## 2. Entry schema

Every entry is a JSON object with exactly these fields (no extras in v0.1). The genesis entry additionally carries `v` — see §2.1. These field names are **frozen**: canonical form hashes the field-name bytes, so renaming any of them after the first real chain exists would orphan every existing log. (Decided 2026-08-09; `null` is JSON's own keyword, not a name of ours.)

| Field | Type | Meaning |
|---|---|---|
| `n` | integer | Sequence number. Genesis is `0`; each entry increments by exactly 1. |
| `ts` | string | UTC timestamp, ISO 8601 with `Z` suffix, second precision: `2026-08-09T17:21:08Z`. |
| `actor` | string | Who acted: `"agent"`, `"human"`, a tool name — free text, non-empty. |
| `action` | string | What happened, one line, non-empty. Genesis uses `"genesis"`. |
| `files` | array | Zero or more **file references** (§3). Genesis uses `[]`. |
| `prev` | string \| null | The `entry_hash` of entry `n-1`. Genesis uses `null` — the only entry allowed to. |
| `entry_hash` | string | SHA256 of this entry's **canonical form** (§4), lowercase hex. |

### 2.1 The genesis entry, pinned

Genesis is fully determined except for its timestamp:

```json
{"action":"genesis","actor":"receipts","entry_hash":"<computed>","files":[],"n":0,"prev":null,"ts":"<init time>","v":"0.1"}
```

- `v` is the **format version** — a string, present on genesis and **only** genesis. A chain is born under one version and stays there; a format upgrade means starting a new chain.
- Because `v` sits inside the genesis entry, it is hash-committed like everything else: every later entry's chain transitively pins the version. A chain cannot be relabeled without breaking.
- Verifiers MUST read `v` before applying any other rule. An unrecognized version stops verification immediately with `UNSUPPORTED-VERSION: log is format "X"; this verifier speaks "0.1"` (exit 4) — a clean refusal, not a tamper verdict.

## 3. File references

A file reference snapshots one file at log time:

```json
{"path": "report.md", "sha256": "8019e97e17..."}
```

- `path` is relative to the receipt log's directory, forward slashes, no `..` segments.
- `sha256` is the lowercase-hex SHA256 of the file's bytes at the moment of logging.
- Within one entry, `files` is sorted by `path` (byte order) — part of canonicalization, not decoration.

**Path identity rules:**

- Writers normalize separators **on intake**: backslashes become forward slashes before the entry is built. The hashed bytes are always the forward-slash spelling — Windows and Unix writers produce identical hashes for the same relative path.
- Absolute paths and paths containing `..` are **rejected with an error**, never silently rewritten. A file outside the log's directory usually means the log is in the wrong place; the operator should feel that friction. (Absolute paths would also leak machine-specific directory layout into a log that may be shown to others.)
- Path identity is **byte-exact — no case folding**. Case-insensitivity is a property of some filesystems, not of the format; a verifier on another OS cannot know what the writer's filesystem considered equal. Instead, `log`/`run` SHOULD warn at write time when a new reference differs from an existing one only by case — the mistake is caught on the machine that knows, and the format stays dumb.

## 4. Canonical form and `entry_hash`

The `entry_hash` is computed as:

```
entry_hash = SHA256( canonical_json( entry minus the entry_hash field ) )
```

**Canonical JSON rules** (these six rules are the load-bearing part of the spec):

1. Object keys sorted lexicographically (byte order) at every nesting level.
2. Compact separators: `,` and `:` with no whitespace anywhere.
3. Strings serialized as UTF-8; non-ASCII characters emitted as-is (no `\uXXXX` escaping beyond JSON's mandatory escapes: `"`, `\`, control characters).
4. Integers only — no floats anywhere in the schema (timestamps are strings for exactly this reason; float serialization is not portable).
5. `null` is the literal `null`; booleans do not occur in v0.1.
6. The hashed bytes are the canonical JSON string encoded as UTF-8, with no trailing newline.

In Python this is `json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")` — but the *rules* above are normative, not the Python idiom.

The line as written to the file MAY be non-canonical (any key order); the hash is always computed over the canonical form. Verifiers MUST re-canonicalize before hashing.

## 5. The chain rule

For every entry `n ≥ 1`:

```
entry[n].prev == entry[n-1].entry_hash
```

The **chain head** is the `entry_hash` of the last entry. It commits to the entire history: any change to any earlier byte of any entry produces a different head.

## 6. Verification algorithm

`verify` walks the file top to bottom. Before anything else it reads the genesis entry's `v` (§2.1) and refuses cleanly if it doesn't speak that version. Then it checks, per entry:

1. The line parses as JSON with exactly the schema fields (genesis: plus `v`).
2. `n` equals the line number (0-based) — catches deletion and reordering.
3. Recomputed canonical hash equals the stored `entry_hash` — catches edits.
4. `prev` equals the previous entry's `entry_hash` (genesis: `prev` is `null`) — catches splice attacks.
5. `ts` is non-decreasing relative to the previous entry — violations produce a **warning** (`WARN: ts decreases at entry N — clock skew at write time?`), never a verdict change. Rationale: `ts` is writer-supplied testimony, like `actor` and `action`. No attack trips this check without also tripping a hash check (editing a past `ts` breaks that entry's hash; a full regeneration fakes timestamps consistently), so a hard failure here could only ever fire on honest clock wobble — NTP step-backs, VM resume — and false `BROKEN`s teach operators to ignore real ones. Mechanical facts get verdicts; testimony gets reporting.
6. *(optional, `--files`)* Every referenced path that still exists on disk hashes to some entry's recorded `sha256`; the **latest** reference per path is reported as `CURRENT` or `MODIFIED-SINCE-LOGGED`.
7. *(optional, `--expect-head <hex>`)* After the walk, the chain head (the last entry's `entry_hash`) is compared to the given value. A mismatch means the file is not the chain the operator last recorded — even if every internal check passed. This is the v0.1 defense against **whole-chain regeneration**: an internally consistent rewrite still produces a different head.

The companion command `receipts head` prints the current chain head, so the operator can record it somewhere the writer cannot reach (another machine, a password-manager note, a message to self). The tool deliberately does **not** store heads locally on the operator's behalf: a state file the writer can also reach would be false security. The out-of-reach storage is the operator's job; the tool only makes the comparison mechanical.

**Verdicts:** `VALID` (exit 0) or `BROKEN at entry N: <reason>` (exit 1, first break reported, walk continues to list all breaks). File mismatches under `--files` are reported but produce exit 2 — the chain itself is intact; the working tree diverged. A head mismatch under `--expect-head` produces `HEAD-MISMATCH` (exit 3) — the chain may be internally valid, but it is not the recorded history.

**Torn tail:** if the **final** line of the file fails to parse as JSON, verify reports it distinctly — `BROKEN: torn tail at line N (crash-truncated append; entries 0–N-1 intact)` — still exit 1. This is the signature of an honest interrupted append, and the message says so plus what survives; the operator repairs it by removing the partial line themselves. An unparseable line anywhere **other than** the final line is ordinary `BROKEN` — there is no innocent way for garbage to appear mid-file. Verify never repairs anything, and the tool deliberately ships no repair command: a sanctioned way to trim the end of a log is exactly the capability an adversary with a cover story wants.

## 7. `receipts run` — logging outside the writer's volition

```
receipts run --actor <name> [--file PATH]... -- <command> [args...]
```

Runs the command, waits for it to exit, then appends exactly one entry: `action` is the literal command line plus its exit code (e.g. `run: pytest -q (exit 0)`), and each `--file` is hashed **after** the command completes. The entry is appended whether the command succeeded or failed — the point of the wrapper is that the invoked process cannot prevent or shape its own receipt. `run` introduces no new schema fields; it is sugar over `log` with the invocation moved outside the writer's volition.

## 8. Explicit non-goals (v0.1)

- **No history completeness.** The chain proves nothing was removed *from what was logged*; it cannot prove that everything got logged — a writer that simply never calls `log` leaves no break to detect. Completeness comes from placing the `log` call outside the writer's volition: pipeline gate scripts, the `receipts run` wrapper (§7), or a harness hook that fires on every action (Stage C). **Integrity is the tool's job; completeness is the integration's job.**
- **No keys, no signatures.** The chain proves internal consistency, not authorship. (ADR-0001.)
- **No prevention of whole-chain regeneration by anyone with write access to the log** — which includes the writer itself (in the target use case, an AI agent has the same filesystem access as the operator). Partially mitigated in v0.1 by `receipts head` + `verify --expect-head` against an operator-held head record; fully closed by anchoring in Stage B. The spec reserves no fields for anchoring — anchor proofs live beside the log, not inside it.
- **No concurrency.** One writer per log. Two processes appending simultaneously is corruption, not a supported mode. Parallelism is handled by giving each writer its **own** log (sibling chains, e.g. `receipts-<session>.jsonl`), never by sharing one — each chain verifies independently; interleaving them by timestamp is a display concern for `report`, not an integrity concern.
- **No secrets in receipts.** `action` and `path` values are plaintext forever; the logger must not put credentials or sensitive content in them.
