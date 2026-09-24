# receipts format specification

**Version:** 0.1.3
**Status:** accepted 2026-08-10 (ADR-0001, ADR-0002 both `accepted`) — v0.1 is **frozen**; any format change requires a new version and a new chain (§2.1). Amendment 0.1.1 (2026-08-29, ADR-0012) changes only what a file-reference path resolves *against* (§3) — no byte of any entry, canonical form, or hash moves, so chains keep `v: "0.1"` and verify identically. Amendment 0.1.2 (2026-08-31, ADR-0017) names the bookkeeping-entry class and pins the transcript-commitment grammar (§2.2) — additive vocabulary over ordinary entries; again no byte moves and chains keep `v: "0.1"`. Amendment 0.1.3 (2026-09-23, ADR-0036, ADR-0037) freezes the hash chain across format versions (§4), so a verifier walks the hashes before it refuses a version (§2.1), and gives exit 1 to `BROKEN` alone (§6): verifier behavior, and a promise about later versions; no byte moves and chains keep `v: "0.1"`.

This document defines the receipt log format precisely enough that an independent implementation, in any language, produces byte-identical hashes. That reproducibility is the whole game: a hash chain is only as trustworthy as the serialization rules underneath it.

## 1. The receipt log

A receipt log is a single UTF-8 text file, JSON Lines format (one JSON object per line, `\n` line endings, no trailing whitespace). Default filename: `receipts.jsonl`.

- Line 0 is the **genesis entry**.
- Every subsequent line is an **entry** appended in strictly increasing sequence.
- The file is append-only. Any other mutation is tampering by definition.
- Writers SHOULD append each entry as a single write of one complete line (`{...}\n`) so a crash mid-append can at worst truncate the final line (see *torn tail*, §6), never damage earlier entries. This bounds the damage from a *crash*; it does not make concurrent appends safe. Two processes writing at once can still interleave, and — more quietly — can read the same tail and produce two entries claiming the same `n`. Serializing writers is the integration's job (§8). Writers SHOULD also push each written line through the operating system's cache to the disk before reporting it written (`fsync` or its equivalent), so that a report of a logged entry is true when it is made: a crash that loses a written entry looks, to a reader counting entries against a second record, exactly like a hook that was killed, and an innocent loss should not wear that face. What remains after the sync is the directory entry of a chain created a moment before the power went, which some filesystems commit separately from the file's bytes; the recorder does not sync the directory. *(Stated 2026-09-21; writer behavior, not a format change.)*
- Readers take a line to be the bytes before each `\n`, and nothing else ends one. U+2028 and U+2029, which a JSON string holds unescaped (§4 rule 3), are characters of the line they sit in, and so is a `\r` anywhere but just before the `\n` (between two JSON tokens it is whitespace). A `\r` just before the `\n` is read as part of the line ending, so a log whose endings a Windows tool rewrote to `\r\n` holds the same lines; writers write `\n` alone. The bytes after the final `\n`, when there are any, are a line too: the torn tail of §6. *(Stated 2026-09-23; reader behavior, not a format change: v0.1 hashes are unaffected.)*

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
- Verifiers MUST read `v` before applying the field rules (§2, and §6 steps 1, 2 and 5 past parsing), which are the version's own. The hash chain is not: §4 and §5 are the same in every version, so for a version it does not recognize a verifier still walks the hashes. Each line must parse as one JSON object with each key given once, its `entry_hash` must be the hash of its canonical form, and its `prev` the `entry_hash` before it; any that fails is `BROKEN` (exit 1), reported as for a chain of its own version. Only when every hash and link holds does it stop with `UNSUPPORTED-VERSION: log is format "X"; this verifier speaks "0.1"` (exit 4), a clean refusal to judge field rules it does not know, not a tamper verdict. The chain head is the last `entry_hash` under any version, so `--expect-head` is still compared, and a mismatch is `HEAD-MISMATCH` (exit 3). *(Amended v0.1.3, 2026-09-23, ADR-0036: before, the refusal came before the walk, so an edit behind a relabeled version read as a refusal. Verifier behavior, not a format change; v0.1 hashes are unaffected.)*

### 2.2 Bookkeeping entries and the transcript commitment *(amended v0.1.2, ADR-0017)*

An entry whose `actor` is `"receipts"` is a **bookkeeping entry**: the recorder speaking in its own voice rather than on behalf of a tool call. Genesis is the original bookkeeping entry; the transcript commitment is the second kind. Readers that count or render *work* — the completeness witness, the recall digest — exclude bookkeeping entries; no tool event owes them.

A **transcript commitment** records the hash of the harness transcript's byte-prefix at the moment of writing. Its action line is machine-parsed and its grammar is pinned, one space between fields, no trailing content:

```
transcript-commitment: bytes=<decimal byte count> sha256=<64 lowercase hex>
```

- The hash covers the transcript's **first `bytes` bytes, from byte zero**, so each commitment re-covers everything before it; across one chain the byte counts never decrease (a growing file never shrinks — a verifier may judge this from the chain alone).
- `files` is `[]`. The commitment is an ordinary entry in every other respect: chained, hashed, no new schema fields — a v0.1 verifier that predates this amendment walks it without noticing.
- The honest claim, stated once here: the commitment is **writer-authored**. It extends tamper-evidence to the transcript *by reference, forward from each commitment* — a prefix rewritten before it was first committed is committed as-is. Detection latency, not protection.

## 3. File references

A file reference snapshots one file at log time:

```json
{"path": "report.md", "sha256": "8019e97e17..."}
```

- `path` is relative to the **reference base**, forward slashes, no `..` segments. *(Amended v0.1.1, ADR-0012.)* The reference base is the **project root** the chain records: for a chain beside a project record (`project.json` — a store chain, ADR-0011), the recorded project path; for any other chain, the log's own directory, which for a log kept at the project root is the same base the original rule named — the two rules agree byte-for-byte there. A verifier that finds a project record it cannot follow reports the references as unresolvable, a different sentence from "file diverged".
- `sha256` is the lowercase-hex SHA256 of the file's bytes at the moment of logging.
- Within one entry, `files` is sorted by `path` (byte order) — part of canonicalization, not decoration.

**Path identity rules:**

- Writers normalize separators **on intake**: backslashes become forward slashes before the entry is built. The hashed bytes are always the forward-slash spelling — Windows and Unix writers produce identical hashes for the same relative path.
- Absolute paths and paths containing `..` are **rejected with an error**, never silently rewritten. A file outside the project usually means the log is recording the wrong place; the operator should feel that friction. (Absolute paths would also leak machine-specific directory layout into a log that may be shown to others.)
- The rule reads the spelling the receipt stores, the same way on every platform: a path is refused when it begins with `/` or `\` (absolute, a `\\server\share` path among them), when its second character is `:` (a drive, `C:x` included), or when a segment is `..` with either slash as the separator, since Windows reads both. A verifier applies the same rule to every reference it walks (§6 step 1), so `--files` never opens a path the chain chose outside the reference base. Two kinds of spelling a recorder once wrote now fail it, and the recorder refuses both at write time: a path rooted without a drive on Windows (`\Users\x`, which Python 3.13 there stopped calling absolute, recorded as `/Users/x`), and a name that begins with a byte that is not UTF-8, or with `..` followed by one (recorded as the escape text `\udcff...` or `..\udcff`, which Windows reads as rooted or as a step up). *(Sharpened 2026-09-23, #299; writer and verifier behavior, not a format change: v0.1 hashes are unaffected.)*
- That rule is about the path's spelling, not containment: nothing checks whether a path leads outside the reference base. A symbolic link under the reference base is followed like any other path, so the reference carries the link's `path`, and `sha256` is of the target's bytes at the moment of logging, wherever the target sits. `--files` (§6) follows the link the same way, on the verifying machine. `log`, `run` and `--files` read whatever the path opens, with no check that it is a regular file; the hook fingerprints regular files only (docs/HOOK.md). *(Stated 2026-09-18; behavior since v0.1, not a format change: v0.1 hashes are unaffected.)*
- Path identity is **byte-exact — no case folding**. Case-insensitivity is a property of some filesystems, not of the format; a verifier on another OS cannot know what the writer's filesystem considered equal. Instead, `log`/`run` SHOULD warn at write time when a new reference differs from an existing one only by case — the mistake is caught on the machine that knows, and the format stays dumb.

## 4. Canonical form and `entry_hash`

The `entry_hash` is computed as:

```
entry_hash = SHA256( canonical_json( entry minus the entry_hash field ) )
```

**Canonical JSON rules** (these six rules are the load-bearing part of the spec):

1. Object keys sorted lexicographically (byte order) at every nesting level.
2. Compact separators: `,` and `:` with no whitespace anywhere.
3. Strings serialized as UTF-8, each string escaped exactly as RFC 8785 section 3.2.2.2 escapes it (it MUST be): `"` as `\"` and `\` as `\\`; U+0008, U+0009, U+000A, U+000C and U+000D as `\b`, `\t`, `\n`, `\f` and `\r`; every other character from U+0000 to U+001F as `\u` and four lowercase hex digits (`\u001b`); and every other character as it stands, unescaped, non-ASCII included. So a newline is `\n` and never `\u000a`, hex is never uppercase, and the solidus `/`, DEL (U+007F), the C1 controls such as NEL (U+0085), and the separators U+2028 and U+2029 are emitted as they stand. A string holding a lone surrogate has no UTF-8 form, so the entry has no canonical form and is refused, not hashed (RFC 8785 likewise requires an error). The recorder never writes one: a lone surrogate it is handed is written as the six characters of its escape text (`\ud800`), which are ordinary text here. *(Pinned 2026-09-23, #299: the escaping every v0.1 chain was already hashed under, now stated; not a format change, and v0.1 hashes are unaffected.)*
4. Integers only — no floats anywhere in the schema (timestamps are strings for exactly this reason; float serialization is not portable).
5. `null` is the literal `null`; booleans do not occur in v0.1.
6. The hashed bytes are the canonical JSON string encoded as UTF-8, with no trailing newline.

In Python this is `json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")` — but the *rules* above are normative, not the Python idiom.

Only the string escaping is taken from RFC 8785. Key order is rule 1's byte order, which for the keys v0.1 allows (all ASCII) is the same order as RFC 8785's UTF-16 order, and numbers are rule 4's integers.

The line as written to the file MAY be non-canonical (any key order, and any escape spelling JSON allows: the recorder writes non-ASCII as `\u` escapes); the hash is always computed over the canonical form. Verifiers MUST re-canonicalize before hashing.

**Frozen across versions** *(amended v0.1.3, ADR-0036)*. The canonical form above, `entry_hash` computed over it, and the chain rule of §5 are the same in every format version. A later version MAY add field rules: fields, their types, their sequencing. It MUST NOT change how an entry is canonicalized or hashed, or what `prev` names. That is what lets a verifier judge the integrity of a chain whose field rules it does not know (§2.1), and it is why every head already recorded, anchored or published outside the machine keeps its meaning under any later version.

The conformance set is [`tests/vectors/`](../tests/vectors/README.md): small chains, each with the exit and verdict a verifier must reach on it, among them an entry needing every escape above, with its canonical form written out in full.

## 5. The chain rule

For every entry `n ≥ 1`:

```
entry[n].prev == entry[n-1].entry_hash
```

The **chain head** is the `entry_hash` of the last entry. It commits to the entire history: any change to any earlier byte of any entry produces a different head.

## 6. Verification algorithm

`verify` walks the file top to bottom. Before anything else it reads the genesis entry's `v` (§2.1); for a version it doesn't speak, it walks the hash chain alone and reports `BROKEN` or refuses, as §2.1 says. For its own version it checks, per entry:

1. The line parses as a JSON object with exactly the schema fields (genesis: plus `v`), each given once, each of its §2 type: `n` an integer (never a boolean or a float), `ts`, `actor` and `action` non-empty strings, `files` an array of `{path, sha256}` objects with string values and no other keys, `prev` a string or `null`, `entry_hash` a string; and each reference's `path` passes §3's spelling rule. A line that fails this is refused by name (`BROKEN at entry N: key 'action' given twice`, `BROKEN at entry N: files is not an array`, `BROKEN at entry N: files names a path that leaves the project (a '..' segment): ../x`) and is not an entry: nothing downstream reads it. The rule exists because a line can carry the right field names and a hash that recomputes and still say two things: a JSON parser that keeps the last of two `action` keys hashes it clean while a parser that keeps the first sees another action, and a `files` that is a string crashes a reader that expected a list. Type only, but for the path: whether a string is hex, or a timestamp well-formed, is the hash comparison's and the reader's business. *(Sharpened 2026-09-21; verifier behavior, not a format change: every entry the recorder has ever written passes, and v0.1 hashes are unaffected.)* The path is the exception because `--files` (step 6) opens it on the verifying machine, and a path that could leave the reference base would have the recipient's verifier hash a file the chain chose. No chain the recorder writes holds one, so an entry that does was written past the recorder's refusal or forged, and it is refused here, before anything opens it. *(Sharpened 2026-09-23, #299; verifier behavior, not a format change: v0.1 hashes are unaffected, and the only entries a recorder wrote that fail it are the two kinds of spelling §3 names.)*
2. `n` equals the line number (0-based) — catches deletion and reordering.
3. Recomputed canonical hash equals the stored `entry_hash` — catches edits.
4. `prev` equals the previous entry's `entry_hash` (genesis: `prev` is `null`) — catches splice attacks.
5. `ts` is non-decreasing relative to the previous entry — violations produce a **warning** (`WARN: ts decreases at entry N — clock skew at write time?`), never a verdict change. Rationale: `ts` is writer-supplied testimony, like `actor` and `action`. No attack trips this check without also tripping a hash check (editing a past `ts` breaks that entry's hash; a full regeneration fakes timestamps consistently), so a hard failure here could only ever fire on honest clock wobble — NTP step-backs, VM resume — and false `BROKEN`s teach operators to ignore real ones. Mechanical facts get verdicts; testimony gets reporting.
6. *(optional, `--files`)* Every referenced path that still exists on disk hashes to some entry's recorded `sha256`; the **latest** reference per path is reported as `CURRENT` or `MODIFIED-SINCE-LOGGED`.
7. *(optional, `--expect-head <hex>`)* After the walk, the chain head (the last entry's `entry_hash`) is compared to the given value. A mismatch means the file is not the chain the operator last recorded — even if every internal check passed. This is the v0.1 defense against **whole-chain regeneration**: an internally consistent rewrite still produces a different head.

The companion command `loxodonta head` prints the current chain head, so the operator can record it somewhere the writer cannot reach (another machine, a password-manager note, a message to self). The tool deliberately does **not** store heads locally on the operator's behalf: a state file the writer can also reach would be false security. The out-of-reach storage is the operator's job; the tool only makes the comparison mechanical.

**Verdicts:** `VALID` (exit 0) or `BROKEN at entry N: <reason>` (exit 1, first break reported, walk continues to list all breaks). File mismatches under `--files` are reported but produce exit 2 — the chain itself is intact; the working tree diverged. A head mismatch under `--expect-head` produces `HEAD-MISMATCH` (exit 3) — the chain may be internally valid, but it is not the recorded history. When both fire in one invocation, both are reported but the head mismatch sets the exit code (3): a regenerated chain is the graver finding and must never be masked by the milder one. *(Precedence decided 2026-08-13; verifier behavior, not a format change — v0.1 hashes are unaffected.)*

**Exit 1 is `BROKEN` and nothing else.** A verifier that cannot reach a verdict at all exits with a sysexits(3) code, never with a verdict's: 66 (`EX_NOINPUT`) when the log is missing, empty, or cannot be read as a file, with the reason on stderr and nothing on stdout (a *line* that cannot be read is `BROKEN`, as step 1 says); 70 (`EX_SOFTWARE`) when the verifier itself fails; 64 (`EX_USAGE`) when it is invoked wrong. A reader that closes the output early ends it with 141, never 0, which would read as `VALID` of lines nobody read. *(Amended v0.1.3, 2026-09-23, ADR-0037; verifier behavior, not a format change.)*

**Transcript commitments** *(amended v0.1.2, ADR-0017)*: every walk judges commitment monotonicity from the chain alone (§2.2 — byte counts never decrease); under `--transcript <path>`, the verifier additionally re-hashes the transcript's committed prefixes, oldest boundary first, and reports each commitment as holding or diverged — which localizes a rewrite to the span between two commitments — then states the tail, the bytes after the furthest commitment, which the chain never vouched for. Any failure produces `TRANSCRIPT-DIVERGED` (exit 5): graver than `FILES-DIVERGED` (working-tree drift is usually innocent; a rewritten transcript never is), milder than `HEAD-MISMATCH` and `BROKEN` — full precedence, gravest sets the exit: 1 > 3 > 5 > 2, everything found is reported. A *missing* transcript is a note, never a verdict: the harness cleans transcripts on a retention cycle, and absence-as-failure would scar every aged chain. A commitment line that names the grammar but fails it is warned about and judged as nothing — entries are hash-protected, so it was written that way.

**Torn tail:** if the **final** line of the file fails to parse as JSON, verify reports it distinctly — `BROKEN: torn tail at line N (crash-truncated append; entries 0–N-1 intact)` — still exit 1. This is the signature of an honest interrupted append, and the message says so plus what survives; the operator repairs it by removing the partial line themselves. An unparseable line anywhere **other than** the final line is ordinary `BROKEN` — there is no innocent way for garbage to appear mid-file. Verify never repairs anything, and the tool deliberately ships no repair command: a sanctioned way to trim the end of a log is exactly the capability an adversary with a cover story wants.

## 7. `loxodonta run` — logging outside the writer's volition

```
loxodonta run --actor <name> [--file PATH]... -- <command> [args...]
```

Runs the command, waits for it to exit, then appends exactly one entry: `action` is the literal command line plus its exit code (e.g. `run: pytest -q (exit 0)`), and each `--file` is hashed **after** the command completes. The command is receipted however it ends: when it succeeds or fails, when the wrapper is interrupted or signalled, and when it cannot start.

- **Interrupted or signalled.** The wrapper catches Ctrl-C, and where the platform has them SIGTERM, SIGHUP and Ctrl-Break, including a signal the command sends its own wrapper. SIGTERM and SIGHUP are passed on to the command; Ctrl-C and Ctrl-Break are not, because the console already sent them to it. The wrapper then waits as long as the command runs (a command that ignores SIGTERM keeps it waiting) and records the command's exit status beside what the wrapper was sent: `(interrupted, exit N)` for Ctrl-C, exiting 130, or `(terminated by signal S, exit N)` otherwise, exiting 128+S. `N` is the exit status as Python's `subprocess` reports it, negative on POSIX when the command died of a signal. A signal already set to be ignored when `run` starts (as under `nohup`) is left ignored, for the command too.
- **Could not start.** A command that is not found or not executable is recorded as `(could not start: <reason>)`, exiting 127, or 126 when it is not executable.

What is not receipted is the wrapper's own death by a signal it cannot catch: SIGKILL, or on Windows a TerminateProcess (which is what a SIGTERM sent there becomes). A command running with the operator's privileges can kill its wrapper that way, and then no receipt is written. `run` introduces no new schema fields; it is sugar over `log` with the invocation moved outside the writer's volition.

## 8. Explicit non-goals (v0.1)

- **No history completeness.** The chain proves nothing was removed *from what was logged*; it cannot prove that everything got logged — a writer that simply never calls `log` leaves no break to detect. Completeness comes from placing the `log` call outside the writer's volition: pipeline gate scripts, the `loxodonta run` wrapper (§7), or a harness hook that fires on every action (Stage C). **Integrity is the tool's job; completeness is the integration's job.**
- **No keys, no signatures.** The chain proves internal consistency, not authorship. (ADR-0001.)
- **No prevention of whole-chain regeneration by anyone with write access to the log** — which includes the writer itself (in the target use case, an AI agent has the same filesystem access as the operator). Partially mitigated in v0.1 by `loxodonta head` + `verify --expect-head` against an operator-held head record; fully closed by anchoring in Stage B. The spec reserves no fields for anchoring — anchor proofs live beside the log, not inside it.
- **No concurrency *in the format*.** One writer per log, where a writer is a **process**, not a session or a person. Two processes appending simultaneously is corruption — a torn line, or two entries claiming the same `n` — not a supported mode. Parallelism is handled by giving each writer its **own** log (sibling chains, e.g. `receipts-<session>.jsonl`), never by sharing one — each chain verifies independently; interleaving them by timestamp is a display concern for `report`, not an integrity concern.

  Where a shared chain is unavoidable, **the integration must serialize its writers** — the format offers no help. The Stage C hook is the case in point: a harness runs tool calls in parallel and fires one hook process per call, so a session-keyed chain has many writers by construction. The hook therefore takes an exclusive lock across read-tail-then-append (ADR-0004). A session may consequently span **sibling chains** (`receipts-<session>-002.jsonl`, …) — created when a chain's tail is already damaged, since recording must not stop and damage must not be repaired (ADR-0002). Each sibling is a complete, independent chain: it has its own genesis, its own head, and anchors separately. The lock judges staleness by age, so a writer paused past the window (a machine asleep mid-append) can have its lock taken; where the operating system lets the lock file go, the result is two well-formed entries claiming one `n`: a **forked tail**, the second shape of tail damage beside the torn one. A chain whose final entry's `n` is not its line number therefore cannot be extended either: the hook starts a sibling and the writing verbs refuse, so an innocent race stays at the tail rather than being buried under later entries until it reads as tampering mid-file. The bound is one damaged tail and one sibling. `verify` reports the fork as `BROKEN` at the second entry, as it always did. *(Stated 2026-09-21, ADR-0004 addendum; writer behavior, not a format change.)*
- **No secrets in receipts.** `action` and `path` values are plaintext forever; the logger must not put credentials or sensitive content in them.
