# receipts format specification

**Version:** 0.1-draft
**Status:** in design review — nothing below is frozen until ADR-0001 is `accepted`.

This document defines the receipt log format precisely enough that an independent implementation, in any language, produces byte-identical hashes. That reproducibility is the whole game: a hash chain is only as trustworthy as the serialization rules underneath it.

## 1. The receipt log

A receipt log is a single UTF-8 text file, JSON Lines format (one JSON object per line, `\n` line endings, no trailing whitespace). Default filename: `receipts.jsonl`.

- Line 0 is the **genesis entry**.
- Every subsequent line is an **entry** appended in strictly increasing sequence.
- The file is append-only. Any other mutation is tampering by definition.

## 2. Entry schema

Every entry is a JSON object with exactly these fields (no extras in v0.1):

| Field | Type | Meaning |
|---|---|---|
| `n` | integer | Sequence number. Genesis is `0`; each entry increments by exactly 1. |
| `ts` | string | UTC timestamp, ISO 8601 with `Z` suffix, second precision: `2026-08-09T17:21:08Z`. |
| `actor` | string | Who acted: `"agent"`, `"human"`, a tool name — free text, non-empty. |
| `action` | string | What happened, one line, non-empty. Genesis uses `"genesis"`. |
| `files` | array | Zero or more **file references** (§3). Genesis uses `[]`. |
| `prev` | string \| null | The `entry_hash` of entry `n-1`. Genesis uses `null` — the only entry allowed to. |
| `entry_hash` | string | SHA256 of this entry's **canonical form** (§4), lowercase hex. |

## 3. File references

A file reference snapshots one file at log time:

```json
{"path": "report.md", "sha256": "8019e97e17..."}
```

- `path` is relative to the receipt log's directory, forward slashes, no `..` segments.
- `sha256` is the lowercase-hex SHA256 of the file's bytes at the moment of logging.
- Within one entry, `files` is sorted by `path` (byte order) — part of canonicalization, not decoration.

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

`verify` walks the file top to bottom and checks, per entry:

1. The line parses as JSON with exactly the schema fields.
2. `n` equals the line number (0-based) — catches deletion and reordering.
3. Recomputed canonical hash equals the stored `entry_hash` — catches edits.
4. `prev` equals the previous entry's `entry_hash` (genesis: `prev` is `null`) — catches splice attacks.
5. `ts` is non-decreasing relative to the previous entry.
6. *(optional, `--files`)* Every referenced path that still exists on disk hashes to some entry's recorded `sha256`; the **latest** reference per path is reported as `CURRENT` or `MODIFIED-SINCE-LOGGED`.

**Verdicts:** `VALID` (exit 0) or `BROKEN at entry N: <reason>` (exit 1, first break reported, walk continues to list all breaks). File mismatches under `--files` are reported but produce exit 2 — the chain itself is intact; the working tree diverged.

## 7. Explicit non-goals (v0.1)

- **No keys, no signatures.** The chain proves internal consistency, not authorship. (ADR-0001.)
- **No prevention of whole-chain regeneration by the log owner.** Closed by anchoring in Stage B; the spec reserves no fields for it — anchor proofs live beside the log, not inside it.
- **No concurrency.** One writer per log. Two processes appending simultaneously is corruption, not a supported mode.
- **No secrets in receipts.** `action` and `path` values are plaintext forever; the logger must not put credentials or sensitive content in them.
