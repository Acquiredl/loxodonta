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

The **chain head** is the `entry_hash` of the last entry, and it commits to the canonical form of every entry before it: a change to what any entry says, or an entry added, removed or reordered, produces a different head. It commits to what the entries say, not to the file's bytes. A line re-spelled without changing its canonical form (its keys in another order, a character escaped another way, whitespace between tokens, a `\r\n` ending) hashes as it did, and a chain rewritten only that way verifies `VALID` with the same head. This is a property of the format, not a gap: two files with one head hold the same entries. It is why a package lists a chain by its head and never by the file's sha256 (ADR-0026 ruling 3). *(Corrected 2026-09-24: the sentence before said any changed byte moves the head, which §4 contradicts. Not a format change: v0.1 hashes are unaffected.)*

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

## 9. The sidecars

A chain has up to three **sidecars** beside it, files that are not chains and are found by the chain's name. Two hold evidence about the chain: the anchors sidecar, proofs that commit its heads to Bitcoin (ADR-0003), and the stamps sidecar, the tokens of an authority timestamp (ADR-0032). The third, the publish memo, is the recorder's bookkeeping of what left the machine (ADR-0025, ADR-0031). No entry carries a field for any of them, and nothing in a sidecar is hash-committed: a sidecar is in the writer's reach, so a row in it is evidence to be judged, or testimony, and never a verdict by being there. A forged proof fails its replay; a deleted one destroys evidence and forges nothing. This section states every rule `verify --anchors` and `verify --stamps` apply to a sidecar; the commands that write the rows, why each rule is there, and worked examples are in [ANCHORING.md](ANCHORING.md) and [HOOK.md](HOOK.md). *(Stated 2026-09-25, #343: the rules `verify` already applied, written down here; not a format change.)*

### 9.1 Files and lines

| Sidecar | File | Holds |
|---|---|---|
| anchors | `<log>.anchors.jsonl` | Proofs of the chain's heads (ADR-0003). |
| stamps | `<log>.stamps.jsonl` | Authority timestamps of its heads (ADR-0032). |
| memo | `<log>.published.jsonl` | What left the machine: sent heads and acknowledged batches of entries (ADR-0025, ADR-0031). |

`<log>` is the chain's file name, whole: the anchors sidecar of `receipts.jsonl` is `receipts.jsonl.anchors.jsonl`. A package manifest's two sidecar seals are named the same way beside `manifest.json`, `manifest.json.anchors.jsonl` and `manifest.json.stamps.jsonl`, and hold rows of the same kinds over the manifest's SHA256 (§10.6). Every sidecar is optional.

A sidecar holds one JSON object per line, its lines split as §1 splits a log's: the bytes before each `\n`, a `\r` just before it read as part of the ending, and the bytes after the final `\n`, when there are any, a line too. Lines are numbered from 1. A writer appends each row as one complete line, keys sorted and separators compact as §4 rules 1 and 2 have it, every character past ASCII written as a `\u` escape, and `\n` alone ending it. It never rewrites or removes a line: the sidecar is append-only by convention, and nothing but that convention keeps it so. A reader takes a row in any key order and any spelling JSON allows. A row is never hashed, so §4 rule 4 does not bind it: the attempt row's `budget` is a number with a fraction.

A line that is not a JSON object is **unreadable**: it is not JSON, or it is empty, or it is JSON and not an object (an array, a string, a number), or it holds a byte that is not UTF-8, or the reader cannot take it apart, as when it holds an integer longer than the reader keeps (Python from 3.11 keeps 4,300 digits) or nests deeper than its recursion allows. A sidecar has no torn tail: a final line cut short is unreadable like any other (§6 names the torn tail of a chain only). A key given twice in one row is not refused, as it is in an entry (§6 step 1) and in a manifest (§10.2): the reader keeps the last of the two.

### 9.2 What a row is (ADR-0038)

Every row names its **kind** in a string member `kind`, and a writer MUST write it on every row it writes. The kinds each sidecar holds, its evidence kind first:

| Sidecar | Evidence kind | Other kinds |
|---|---|---|
| anchors | `anchor` | `attempt` |
| stamps | `stamp` | `attempt` |
| memo | `head` | `chain`, `attempt` |

- **A row with no `kind` member** reads as its sidecar's evidence kind: a proof, a token, a sent head. This holds whenever the row was written. The first rows of each sidecar were written before rows named a kind, and a sidecar is not chained, so nothing in it dates a row: one written tomorrow by hand reads exactly as one written in 2026-09. The rule is permanent, and it never widens.
- **An unknown kind.** A row whose `kind` is a string its sidecar does not hold is of an unknown kind: a kind a later recorder writes, or a known kind in the wrong sidecar (the memo's `chain` in the anchors sidecar, an `anchor` in the stamps sidecar). So is a row whose `kind` member is present and not a string. `{"kind": null}` is unknown and not kind-less: the rule above is for a row with no `kind` member, and `null` is a value a writer chose. A row of an unknown kind is named, before any verdict line, and never judged: it earns nothing, is no finding, and moves no exit code, so it can never make a head read as anchored or stamped. Its line is `ANCHOR-UNKNOWN-KIND: line N of <sidecar> is of kind "<kind>"`, `STAMP-UNKNOWN-KIND` in the stamps sidecar, with `<sidecar>` the file's bare name, never a path of the verifying machine, and the kind printed with every character that could steer a terminal written as its escape. A kind that is not a string is named by its JSON type (`of a kind that is null, not a string`), never by its value. In a manifest's sidecar the line is headed `seal anchor:` or `seal stamp:` (§10.6).
- **An attempt row** is the recorder's note on how a step that reaches off the machine went (#240): testimony, never a proof, a token or a sent head. Every judge leaves it out silently, so a sidecar holding only attempt rows, or those and rows of unknown kinds, reads exactly as an empty one: nothing is printed for it, and in a manifest's sidecar it is `SEAL-MISSING` (§10.6).
- **An unreadable line** in the anchors or the stamps sidecar is judged, and is invalid evidence: `ANCHOR-INVALID` or `STAMP-INVALID`, and `SEAL-INVALID` in a manifest's sidecar. It is named and never skipped, so a recipient sees every line the file holds. The memo is judged by nobody (§9.8).

### 9.3 The rows

The fields of each kind, and their types as the recorder writes them. A field is read only where §9.4 to §9.8 say it is; the rest is testimony, printed or not read.

**`anchor`**, in the anchors sidecar:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `anchor`. Absent on the first rows (§9.2). |
| `head` | string | The head anchored, 64 lowercase hex: an entry's `entry_hash`, or a manifest's SHA256. |
| `n` | integer | That entry's `n`. Absent from a manifest's row, which has no entries (ADR-0026 ruling 4). Not read: the verifier takes `n` from the chain. |
| `ts` | string | When the head was submitted, in §2's form. Testimony. |
| `calendar` | string | The calendar the proof came from. Testimony, printed, and what pairs a pending proof with its completion (§9.4). |
| `proof` | string | The base64 of an OpenTimestamps timestamp starting at `head` (§9.5): pending, or completed to a Bitcoin attestation. Its bytes are what the calendar returned, spliced with the completion on upgrade, so `ots verify` on the same bytes reaches the same block. |

**`stamp`**, in the stamps sidecar:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `stamp`. Absent on the first rows (§9.2). |
| `head` | string | The head stamped, as an anchor row's. |
| `n` | integer | As an anchor row's, absent from a manifest's row, and not read. |
| `ts` | string | When the token was asked for. Testimony. |
| `authority` | string | The URL that was asked. Testimony: printed, and never presented as the signer (ADR-0032 ruling 4). |
| `response` | string | The base64 of the authority's whole `TimeStampResp`, verbatim. The recorder reads its status to decide whether to write the row, and nothing else in it. |

**`head`**, in the memo, written only for a head the remote took (ADR-0025):

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `head`. Absent on the first rows (§9.2). |
| `head` | string | The chain head sent. |
| `n` | integer | Its entry's `n`. |
| `ts` | string | When it was sent, the time the sent body carried. |
| `event` | string | `session-end` or `cadence`: which door sent it. |

**`chain`**, in the memo, written only when the remote acknowledged the batch (ADR-0031):

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `chain`. |
| `first`, `last` | integer | The `n` of the first and the last entry in the batch. |
| `head` | string | The `entry_hash` of entry `last`. |
| `ts` | string | When the batch was acknowledged. |
| `event` | string | `session-end` or `cadence`. |
| `remote_id` | string | The first 16 hex characters of the SHA-256 of the remote's URL (#263). Absent from rows written before it was, which count for no remote. |

**`attempt`**, in any sidecar (#240):

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `attempt`. |
| `step` | string | The step: `anchor`, `stamp`, `publish-head` or `publish-chain`. |
| `ts` | string | When the step ended. |
| `budget` | number | The seconds the step had, to one decimal; `0.0` for a step the session-end window closed on before it began. |
| `outcome` | string | `submitted`, `granted` or `sent`, or the one line the step produced instead. |

No memo row and no attempt row holds a URL: a webhook's or a receiver's URL is a credential (ADR-0025). The stamp row's `authority` is the one URL a sidecar holds, since it names whom the operator chose to trust and grants nothing (ADR-0032 ruling 4).

### 9.4 Judging an anchor row

`verify --anchors` judges the anchors sidecar offline, after the walk of §6 and against the entries it walked. A chain that is `BROKEN` has no sidecar judged, and neither does a chain whose format version the verifier does not speak (§2.1). With no sidecar the verifier prints `NO-ANCHORS`, and the exit is the chain's: anchoring is optional.

The rows of unknown kinds are named first (§9.2). Then each proof and each unreadable line is judged, in file order:

1. An unreadable line, or a row with no `head` (absent, or `null`), is `ANCHOR-INVALID`.
2. A `head` that is not the `entry_hash` of an entry of the chain is `ANCHOR-MISMATCH`: this log is not the anchored history, which is the signature of a regenerated chain.
3. A `proof` that is absent, or is not base64, or does not replay from `head` (§9.5) is `ANCHOR-INVALID`: evidence that does not verify is not evidence.
4. A proof that replays to a Bitcoin attestation is `ANCHORED` for entries `0..n`, where `n` is that of the entry whose `entry_hash` is `head`. The block it names is claimed, or checked when a header was given (§9.6). Each completed proof prints its own line.
5. A proof that replays to a pending attestation earns nothing and is no finding. When a completed proof in the sidecar has the same `head` and `calendar`, it is that submission's own completion, and the pending row is superseded and prints nothing. When another calendar completed that head, the pending row is `ANCHOR-UNANSWERED`, and no upgrade is owed: the anchor's claim is about the head, not about any one calendar (#199). Otherwise it is `ANCHOR-PENDING`.

`ANCHOR-MISMATCH` and `ANCHOR-INVALID` are exit 3, the tier of `HEAD-MISMATCH` in §6's precedence (1 > 3 > 5 > 2), and every finding is printed. `ANCHORED`, `ANCHOR-PENDING`, `ANCHOR-UNANSWERED`, `NO-ANCHORS`, a row of an unknown kind and `HEADER-UNMATCHED` (§9.6) move no exit code, and with no finding the last line is `VALID`.

A row of the wrong shape, as the recorder judges it on 2026-09-25: a `head` that is a number or a boolean is `ANCHOR-MISMATCH` by step 2, since it is no entry's hash; a `proof` string is decoded as base64 with the characters outside the base64 alphabet dropped; and a `head` or a `calendar` that is an array or an object, or a `proof` that is not a string, ends `verify` in a failure of the verifier itself (exit 70, §6) and not a verdict. #348 makes each of those `ANCHOR-INVALID`.

A package judges each chain's anchors sidecar by these rules, its words mapped as §10.5 says; the manifest's anchor is judged by §10.6.

### 9.5 The proof

A proof is replayed through the subset of the OpenTimestamps format that calendar proofs use, implemented in the file and nothing more (ADR-0003). Anything outside it is refused by name, never guessed, and the row is `ANCHOR-INVALID`.

- **varint**: unsigned, little-endian base 128, the high bit of each byte meaning another follows. One longer than ten bytes is refused.
- **varbytes**: a varint length, then that many bytes. A length over 8,192 is refused, and so is one that runs past the end of the proof.
- **Operations**, each applied to the current digest `msg`: `0x08` sha256, giving `SHA256(msg)`; `0xf0` append, giving `msg‖arg`; `0xf1` prepend, giving `arg‖msg`. Append and prepend carry `arg` as varbytes. Any other operation is refused.
- **The tree**: a node is a sequence of elements, every element but the last prefixed `0xff`. An element is an attestation (`0x00`, an 8-byte tag, then a varbytes payload) or an operation (its tag byte, its `arg` when it has one, then the node that continues from the new digest). A proof nesting deeper than 512 operations is refused. The bytes after the first node ends are not read.
- **Attestations**: the Bitcoin tag is `05 88 96 0d 73 d7 19 01`, and its payload MUST be exactly one varint, the height H: it says the current digest is the merkle root of block H, in the byte order a block header stores it (§9.6). The pending tag is `83 df e3 0d 2e f9 0c 8e`, and its payload, a varbytes calendar URI, is not read. A proof may hold attestations of other tags, and they are not judged.

The replay starts from the 32 bytes of `head` and collects every attestation with the digest it sits on, in the order of the walk: a node's attestations before the operations that continue from it, and the operations in the order written. The first Bitcoin attestation is the one judged, and when there is none, the first pending one. A proof that reaches neither is `ANCHOR-INVALID`.

### 9.6 Checking the block

An attestation names a height, and replaying the proof gives a merkle root; nothing in either shows that a block with that root was mined. The block's header shows it, and the recipient fetches it from a source they trust (ruling 3 on #299). Nothing is fetched by the verifier (ADR-0003).

`--block-header HEX` gives one Bitcoin block header, its 80 bytes as 160 hex characters, and it may be given once per anchored block. It needs `--anchors`, and without it is a usage error, exit 64, since a `VALID` with no anchor judged would read as though the header had checked one; a value that is not 160 hex characters is exit 64 too. A header's merkle root is its bytes 36 to 68, as stored, and it is compared byte for byte with the digest a Bitcoin attestation sits on. A header carries no height, so headers are matched to attestations by that root and never by a height.

- An attestation whose digest a given header holds is **checked**: the entries existed by that block, which is named by the header's hash, the double SHA256 of its 80 bytes, byte-reversed as explorers print it. The height the line repeats is the attestation's claim and the header source's word, never the verifier's.
- An attestation whose digest no given header holds is **claimed**: the line says the block was not checked, and prints the height and the root it must hold, byte-reversed as explorers print a root.
- A header that no attestation judged replays to is `HEADER-UNMATCHED`, printed after the anchor lines and before the verdict. It checked nothing, and it is a note.

None of these moves the exit code. `verify-package` checks each header against every anchor it carries, the chains' and the manifest's, and notes one that matched none of them once (§10.5 step 6).

### 9.7 Judging a stamp row

`verify --stamps` judges the stamps sidecar offline, after the walk of §6, as §9.4 judges the anchors sidecar: a `BROKEN` chain, or one of a version the verifier does not speak, has none judged, and with no sidecar the verifier prints `NO-STAMPS` and the exit is the chain's. `--authority-chain FILE` names the certificate chain tokens are judged against, and without `--stamps` it is a usage error, exit 64: the file was named in order to have tokens judged, and a `VALID` with none judged would read as though they had been.

The rows of unknown kinds are named first (§9.2). Then each token and each unreadable line is judged, in file order:

1. An unreadable line, or a row whose `head` or `response` is not a string, is `STAMP-INVALID`.
2. A `head` that is not the `entry_hash` of an entry of the chain is `STAMP-INVALID`: this log is not the stamped history. That much needs no tool.
3. A `response` that is not base64, read strictly, with nothing outside the alphabet and the padding whole, is `STAMP-INVALID`.
4. The token goes to `openssl` as §10.8 says, with `head` as the digest it must carry and FILE as the chain. Accepted, it is `STAMPED` for entries `0..n`, `n` taken from the chain as in §9.4: a key the chain file certifies signed that head under its own clock, the time inside the token is that key's word, and the row's `authority` is named as testimony. Refused, it is `STAMP-INVALID`, with `openssl`'s reason. When no tool or input could judge it, for a reason §10.8 lists, it is `stamp not judged: <reason>`: the token is present, and nobody judged it.

`STAMP-INVALID` is exit 3, the tier of `ANCHOR-MISMATCH`. `STAMPED`, `stamp not judged`, `NO-STAMPS` and a row of an unknown kind move no exit code. A package judges each chain's stamps sidecar by these rules when its row sets `stamps` (§10.2), and the manifest's token by §10.6.

### 9.8 The memo

The memo is bookkeeping, kept so that a head is posted once and a published chain resumes where its remote stopped, and for nothing else. No verifier judges it, no `verify` flag reads it, and a package never carries it (§10.1). Its rows are read by kind as §9.2 says, with `head` its evidence kind, so a kind-less row is a sent head. The recorder reads the `chain` rows as the cursor for one remote: the greatest integer `last` among the rows whose `remote_id` is that remote's, or none, and then the send starts at genesis (docs/RECEIVER.md). A line of the memo that is not JSON is read past, which costs at worst a batch sent again and dropped by the receiver as a duplicate; a line holding a byte that is not UTF-8 stops the send rather than be guessed at. The supervisor's keeper reads the head rows and the attempt rows, to say when a head last left the machine and which step last failed (docs/TOUR-SUPERVISOR.md).

The conformance vectors hold the anchors and stamps sidecars: [`tests/vectors/`](../tests/vectors/README.md) has a pending proof, a completed one with and without its block's header, a mismatch, a proof that does not replay, an unreadable line, an attempt row alone, a kind-less row, `{"kind": null}`, an unknown kind and a misplaced `chain` row; and, needing no `openssl`, a kind-less stamp row, an attempt row and an unknown kind, each with its exit and every line it prints.

## 10. The package

A **package** carries chains across a trust boundary with the files written after them, listed by a **manifest** written last, and sealed by what is applied to the manifest from outside it (ADR-0007, ADR-0026). Its format is `loxodonta-package/1`. The chains inside are chains of this document's format, judged by §6's walk and nothing else. This section states every rule `verify-package` applies itself; how a package is built, why each rule is there, and worked examples are in [PACKAGE.md](PACKAGE.md). *(Stated 2026-09-25, #341: the rules `verify-package` already applied, written down here; not a format change.)*

### 10.1 Layout

A package is a folder, or a zip of one. It is flat: `manifest.json` sits at the top, and so does every file the manifest lists. Beside a chain its sidecars are found by name, `<chain>.anchors.jsonl` and `<chain>.stamps.jsonl` (docs/ANCHORING.md). Beside the manifest its seals are found the same way: `manifest.json.anchors.jsonl` (the anchor), `manifest.json.stamps.jsonl` (the authority timestamp), `manifest.json.sig` and `manifest.json.pub` (the issuer signature and the public key it was made with).

A **bare name** is a string that is not empty, not `.` or `..`, and holds no `/` and no `\`. Every path in the manifest MUST be a bare name. A verifier opens only the files §10 names, each at the top of the package, and never follows a name out of it. A symbolic link inside a folder package is followed like any other file, wherever it points, as §3 says of file references: the rule is about the names, not about containment.

### 10.2 The manifest

`manifest.json` is one JSON object in UTF-8. It MUST be read with each key given once at every level of nesting, as §6 step 1 reads an entry: a manifest that gives a key twice anywhere says one thing to a parser that keeps the first and another to one that keeps the last, so no reading of it is the manifest. Its fields:

| Field | Type | Rule |
|---|---|---|
| `format` | string | MUST be `loxodonta-package/1`. |
| `packed`, `tool` | any | When and by what the package was made. Testimony: printed, never judged, and not required. |
| `unit` | object | What was packaged (ADR-0026 ruling 1). Printed as it stands, never judged. |
| `chains` | array | One row per chain, at least one. Each row MUST hold `path`, a bare name; `head`, a string, the chain head; and `entries`, an integer, the chain's line count. It MAY hold `anchors` and `stamps`, the chain's sidecar names or `null`, and `transcript`, only when a transcript travels with the chain's session. |
| `artifacts` | array | One row per file written after the chains close, possibly none. Each row MUST hold `path`, a bare name; `sha256`, a string, the lowercase hex SHA256 of the file's bytes; and `bytes`, an integer, its length. |
| `seals` | array of strings | The seals the package carries (§10.6); `[]` for none. |

A row's `transcript`, when present and not `null`, MUST be a bare name, and `artifacts` MUST list that name. The verifier does not read a chain row's `anchors`: a chain's anchor sidecar is judged whenever `<chain>.anchors.jsonl` is beside it. It reads a row's `stamps` only for whether it is set, which it is unless it is absent, `null`, `false`, `0`, an empty string, an empty array or an empty object: when it is set, `<chain>.stamps.jsonl` is judged with the chain, whatever name the field gives. Fields this section does not name are not read.

### 10.3 Two ways of listing

A chain is listed by its head and its line count, never by the hash of its file (ADR-0026 ruling 3). The head commits to the canonical form of every entry and not to the file's bytes (§5), so a chain re-spelled on its way to the recipient, its line endings turned to `\r\n` by an unzip, holds the same entries and walks to the same head. A verifier MUST walk each listed chain (§6) and compare the head it walks to, the `entry_hash` of the last line that has one, and its number of lines as §1 counts them, a torn tail included, with the row's `head` and `entries`.

An artifact has no chain to commit it, so the manifest's listing is its only commitment: a verifier MUST compare the SHA256 and the length of its bytes, exactly, with the row's. A transcript named on a chain row is an artifact like any other, the whole file as it stood at packaging, and it is also judged against that chain's transcript commitments (§2.2, §6), which commit its prefixes. Each fact is committed in one place (ADR-0007 ruling 3).

### 10.4 Refused before anything is judged

Each of the following is `UNSUPPORTED-FORMAT`, exit 4: a refusal, not a verdict. The one line printed says why, and nothing is judged.

- **The path.** It is neither a folder nor a zip. (A path that is not there is no input: exit 66, the reason on stderr and nothing on stdout, as §6 says of a missing log.)
- **The zip.** It declares more than 2^30 bytes unpacked; it is damaged, or cannot be unpacked; or two of its members unpack to one file. A verifier MUST NOT write outside the folder it unpacks into: a member's drive or root and its `.` and `..` segments are dropped, and a name that leaves nothing is refused. Two members unpack to one file when their names are equal once folded the way the most forgiving system lands them: either slash a separator, a drive or `\\server\share` prefix dropped, empty, `.` and `..` segments dropped, each segment's trailing dots and spaces dropped, each of `:<>|"?*` read as `_`, the name in Unicode normal form NFC, and case folded. The fold is the same on every system, so the verdict does not depend on where the zip is unpacked (#299). Unpacking keeps the last of two such members while a reader that stops at the first shows the first, so which file a recipient reads would depend on the tool.
- **The manifest.** There is no `manifest.json` at the top, or it is not UTF-8, or not JSON, or not an object; it gives a key twice; its `format` is not `loxodonta-package/1`; or it breaks §10.2: no `unit` object, no chain, a chain row without a bare-name `path`, a string `head` and an integer `entries`, no `artifacts` array, an artifact row without a bare-name `path`, a string `sha256` and an integer `bytes`, a `transcript` that is not a bare name or that `artifacts` does not list, or a `seals` that is not an array of strings.

### 10.5 The order of judging

Once the manifest is read, a verifier judges in this order and prints in it, so the verdict is the last line (ADR-0026 ruling 5):

1. **The manifest's summary**: the package, its format, the testimony of `packed` and `tool`, the unit, and the seals declared.
2. **Each chain**, in the manifest's order. A chain the package lacks is `ARTIFACT-DIVERGED`. Otherwise it is walked as §6 walks it, without `--files` and without `--expect-head`, with its anchor sidecar judged as `verify --anchors` judges one, its stamps sidecar as `verify --stamps` does when the row's `stamps` is set (§10.2), and the transcript the row names as `verify --transcript` does. A `--block-header` given to `verify-package` is checked against the chain's anchors too. The walk's verdict becomes the package's word: `BROKEN`, and an empty chain file, which inside a package is a finding and not a missing input, are `CHAIN-BROKEN`; an anchor that is not evidence for the chain (`ANCHOR-MISMATCH`, `ANCHOR-INVALID`) is `ANCHOR-MISMATCH`; a token that is not (`STAMP-INVALID`) is `STAMP-INVALID`; `TRANSCRIPT-DIVERGED` stays itself; and a chain whose genesis claims a format version the verifier does not speak (§2.1) is `UNSUPPORTED-FORMAT`, found here, after the manifest was read, so the rest of the package is still judged and printed. A chain that holds transcript commitments when no transcript travelled with it is a note, never a finding (§6). Then the walked head and line count are compared with the row (§10.3); a difference is `ARTIFACT-DIVERGED`.
3. **The file references**, counted across the chains. They are not checked: off the recording machine the project record points nowhere (ADR-0012).
4. **Each artifact**, by §10.3. One that is missing or differs is `ARTIFACT-DIVERGED`.
5. **Each declared seal**, in the order `seals` lists them (§10.6).
6. **The block headers**: a `--block-header` that matched no anchor in the package, a chain's or the manifest's, is noted once. It checked nothing; it is never a finding.
7. **The unlisted files**: every name at the top of the package that is not `manifest.json`, a listed chain, a listed artifact, or a file of a declared seal, one line each, sorted by name, `unlisted: <name> (not in the manifest, not judged)`. Nothing vouches for them and no verdict comes from them. A seal file whose seal is not declared is unlisted: the declared set is what a seal is judged against (ADR-0007).
8. **The verdict** (§10.7), after one line of residual trust when there is no finding.

### 10.6 The seals

The **sealing surface** is the manifest's exact bytes, and nothing else (ADR-0007 ruling 4): the anchor and the authority timestamp commit the lowercase hex SHA256 of those bytes, and the issuer signature is made over the bytes themselves. A seal is applied after the manifest is written, so the manifest cannot list a seal's file; it declares the seal instead, in `seals`, and a verifier judges each declared seal against the file it expects. The kinds are `anchor`, `stamp` and `signature`. A writer SHOULD declare them in that order: the two answers to *when* before the answer to *who*, and the anchor, which is nobody's product, before the token, which is an authority's word (ADR-0007, ADR-0032). A verifier judges them in the order declared, and a kind declared twice is judged twice, its lines printed twice; the verdict's rungs come in the fixed order of §10.7 whatever that order was.

**`SEAL-MISSING`**, exit 3, is a declared seal the package does not carry (ADR-0007's declared seal set): its sidecar absent, or holding no evidence row, with none but attempt rows and rows of kinds the verifier does not know, or no rows at all (ADR-0038); or `manifest.json.sig` or `manifest.json.pub` absent. A package stripped of a seal fails; it never reads as merely unsealed.

- **`anchor`.** The rows of `manifest.json.anchors.jsonl` are read as any anchor sidecar's are (ADR-0038): a row with no `kind`, or of kind `anchor`, is a proof; a line that is not a JSON object is judged, and is `SEAL-INVALID`; an attempt row is left out; a row of any other kind is named with its line number and its kind, and never judged. Each proof MUST have a string `head` equal to the manifest's SHA256 and a string `proof` that replays from it (§9.5); a proof that does not is `SEAL-INVALID`. A proof that replays to a Bitcoin attestation earns the rung. A `--block-header` whose merkle root, bytes 36 to 68 as stored, is the one the proof replays to checks the block it claims, which is then named by the header's hash; without one, the block is the attestation's claim and is said to be. With several completed proofs, the rung names the lowest checked block, or when none was checked the lowest claimed one. A pending proof earns nothing and is no finding: it is superseded by a completed proof from the same `calendar`, and after another calendar completed it is noted as unanswered, the rung standing, since the anchor's claim is about the digest and not about any one calendar (#199).
- **`stamp`.** The rows of `manifest.json.stamps.jsonl` are read as any stamps sidecar's are (ADR-0038): a row with no `kind`, or of kind `stamp`, is a token; a line that is not a JSON object is `SEAL-INVALID`; an attempt row is left out; a row of any other kind is named with its line number and its kind, and never judged. Each token MUST have a string `head` equal to the manifest's SHA256 and a string `response`, the authority's `TimeStampResp` in base64; one that does not is `SEAL-INVALID`. The token is judged by `openssl` (§10.8) against the certificate chain the recipient names with `--authority-chain`: accepted, it earns the rung; refused, it is `SEAL-INVALID`. The `authority` a row names is testimony, and a verifier never presents it as the signer. The rung is earned when at least one token is accepted and none is refused.
- **`signature`.** The first two whitespace-separated tokens of the first line of `manifest.json.pub`, the key's type and the key, become a one-line allowed-signers file under the principal `issuer`, and `manifest.json.sig` MUST verify over the manifest's bytes under the namespace `loxodonta-package` (§10.8). A `.pub` that is not a public key `ssh-keygen` reads, or a signature that does not verify, is `SEAL-INVALID`. A signature that verifies earns the rung, named by the key's SHA256 fingerprint as `ssh-keygen -lf` prints it and never by a name or the key's comment (ADR-0008 ruling 4).
- **Any other kind** is named as declared and not judged, on its own seal line: it earns nothing, is no finding, and appears in neither closing line (§10.7).

### 10.7 Verdicts and exit codes

The findings are ranked, and the gravest sets the verdict and the exit; within one rank the verdict is the first finding of that rank in the order of §10.5. Every finding is printed where it is found.

| Rank | Verdict | Exit | Meaning |
|---|---|---|---|
| 1 | `UNSUPPORTED-FORMAT` | 4 | A refusal (§10.4), or a chain in a format version this verifier does not speak (§10.5). |
| 2 | `CHAIN-BROKEN` | 1 | A chain does not walk clean, or is empty. |
| 3 | `SEAL-INVALID`, `SEAL-MISSING`, `ANCHOR-MISMATCH`, `STAMP-INVALID` | 3 | A seal, or evidence packaged with a chain, that does not hold for what it seals: not what was issued. |
| 4 | `TRANSCRIPT-DIVERGED` | 5 | A packaged transcript no longer matches a commitment, or the commitments contradict each other. |
| 5 | `ARTIFACT-DIVERGED` | 2 | A listed file is missing or differs from its listing, or a chain walks to another head or length. |
| — | `SELF-CONSISTENT` | 0 | No finding. |

`SELF-CONSISTENT` is the ceiling of a package with no seal, and it is printed with its limit: a wholesale regeneration, packed afresh, verifies the same. Each seal that holds adds its rung, in this order whatever the order declared: `+ ANCHORED` (the manifest's anchor completed), `+ STAMPED` (a token over the manifest was accepted), `+ SIGNED (key: <fingerprint>)` (the signature verified). The rungs are the manifest's seals alone: a chain's own anchor or token is printed under that chain and earns the package nothing, since it seals another object (ADR-0026 ruling 6). The verdict words name the mechanism, never a conclusion (ADR-0007 ruling 5). The line of residual trust before it states what rests on the issuer's word alone: that the record inside is true and complete, in every case, and whatever no seal earned. A seal of a known kind that no tool could judge (§10.8) is said so in both lines, and changes the exit in nothing; a seal of a kind the verifier does not know (§10.6) is named on its seal line only.

Outside the ladder, as for `verify` (ADR-0037): 64 for a usage error, 66 when the package path is not there, 70 when the verifier itself fails. Exit 1 is `CHAIN-BROKEN` and nothing else.

### 10.8 Checks handed to other tools

Two checks need public-key cryptography, which the standard library does not have, and a verifier hands them to a tool the recipient already holds rather than writing it (ADR-0026 ruling 4, ADR-0032 ruling 5). Everything else in §10, the manifest, the listings and the walk, is this document's rules, and so are the proof's replay and the block header (§9.5, §9.6); none of them needs a tool. Nothing is fetched (ADR-0003).

- **An authority timestamp's token**, the manifest's and each chain's, goes to `openssl ts -verify`, with the SHA256 it must carry and the certificate chain the recipient saved (ADR-0032). The verifier reads nothing in a token itself. When `openssl` refuses a token because a certificate in the chain has expired, the verifier asks again as of the time the token states, which `openssl ts -reply -token_out -text` prints (#264): accepted then, the token is not judged, since past its certificate nothing vouches for the key, and refused then, or with no time that can be read, it is `SEAL-INVALID` (for a chain's token, `STAMP-INVALID`).
- **The issuer signature** goes to `ssh-keygen -Y verify`, and its key's fingerprint to `ssh-keygen -lf` (ADR-0008, ADR-0026 ruling 4).

When the tool or its input is absent, the seal is **not judged**, and says why on its line: no `--authority-chain` given, the file it names not found, `openssl` not on the path or unable to run, a certificate that expired after the token was issued, as above, or, when a certificate has expired, an `openssl` whose `ts -verify` takes no `-attime`; `ssh-keygen` not on the path, unable to run, or older than `-Y verify` (OpenSSH 8.0). Not judged is a note and never a verdict: the rung is neither earned nor failed, and the exit is whatever the rest of the package gives. With no finding, the verdict line names the seal that was not judged and why, save a token not judged beside one that was accepted, whose note stays on its own line. A verifier never says a token or a signature holds when no tool checked it.

The conformance vectors hold the package too: [`tests/vectors/`](../tests/vectors/README.md) has an unsealed package, an altered artifact, a zip naming one file twice, a declared seal missing, an unknown format, and an anchored manifest, each with its exit and its verdict.
