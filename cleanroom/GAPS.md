# Gaps

Each place where `SPEC.md` was silent, could be read two ways, or contradicted itself, with what `verify.py` does about it.

There are two parts:

- **Part 1** was written in Phase 1, from the spec alone, before `vectors/vectors.json` or any vector file was opened. Each entry there is a choice made blind.
- **Part 2** was written in Phase 3. It has one entry per fix to a failing row, each sorted into exactly one kind: `spec-silent`, `spec-ambiguous`, `spec-wrong` or `my-bug`.

## Part 1: found while writing from the spec

**P1. The command line (interface).** SPEC 6 names the flags (`--files`, `--expect-head <hex>`, `--transcript <path>`) and the verb `head`, but never gives a whole command line. `--log` comes only from `vectors/README.md`. *Choice:* `verify` or `head` as the verb, `--log PATH` (default `receipts.jsonl`, SPEC 1's default name), and flags before or after the verb, as `--flag VALUE` or `--flag=VALUE`.

**P2. What `head` does with a broken chain** (silent). SPEC 6 says only that `head` "prints the current chain head". It does not say whether `head` judges the chain first, or what it prints for a chain with a torn tail. *Choice:* `head` does not judge; `verify` does that. It prints the head as SPEC 10.3 defines it, "the `entry_hash` of the last line that has one", so a torn tail still has a head. If no line holds an `entry_hash`, it prints a `BROKEN` line and exits 1.

**P3. The chain head when the last line is not an entry** (ambiguous). SPEC 5 and SPEC 6 step 7 say "the last entry's `entry_hash`". SPEC 10.3 says "the `entry_hash` of the last line that has one". The two differ when the final line is a torn tail or a refused line. *Choice:* SPEC 10.3's wording, for `--expect-head` and `head` alike, because it is the more precise of the two.

**P4. Is `files` sorted as part of canonical form?** (contradiction). SPEC 3 says "`files` is sorted by `path` (byte order) — part of canonicalization, not decoration". But SPEC 4's "six rules" sort object keys, never arrays, and the Python idiom SPEC 4 quotes (`json.dumps(..., sort_keys=True, ...)`) keeps array order. A line holding an unsorted `files` hashes differently under the two readings. *Choice:* SPEC 4. The array is hashed as stored, and an unsorted `files` is neither re-sorted nor refused. SPEC 4 calls its six rules "the load-bearing part", and SPEC 6 step 1 lists every shape check without naming order. Sorting is read as the writer's duty at intake.

**P5. Which final lines count as a torn tail** (ambiguous). SPEC 6 says a final line that "fails to parse as JSON" is a torn tail. *Choice:* that means the line is not JSON at all: a syntax error, a cut-off line, an empty line, a byte that is not UTF-8 (a cut can split a character), `NaN` or `Infinity`, or a number the reader cannot take apart. A final line that *is* JSON but gives a key twice, is not an object, or fails a field rule is refused by name as an ordinary `BROKEN`, since it parsed.

**P6. Numbering in `BROKEN at entry N` and `torn tail at line N`** (silent). *Choice:* N is the 0-based line number in both. It is not the entry's own `n`, which may be the thing that is wrong. The torn-tail sentence "entries 0–N-1 intact" only works 0-based. With N = 0 the sentence would read "entries 0–-1", so it says "no entry intact" there.

**P7. The link after a refused line** (silent). SPEC 6 step 1 says a refused line "is not an entry: nothing downstream reads it". It does not say what the next line's `prev` (step 4) is checked against. *Choice:* it is not checked. The line before is already a break, and checking against an older entry would report one tamper as two.

**P8. Which verdict is the last line when there are several breaks** (silent). SPEC 6: "first break reported, walk continues to list all breaks". *Choice:* every later break is printed first, and the first break is the last line, so the verdict names the first.

**P9. A lone surrogate: refused, or hashed and failed?** (silent on the mechanics). SPEC 4 rule 3: "the entry has no canonical form and is refused, not hashed". *Choice:* the walk reports `BROKEN at entry N: the entry has no canonical form`, and, as for a line refused at step 1, the next line's link is not judged.

**P10. Genesis with no `v`, or a `v` that is not a string** (silent). SPEC 2.1 says to read `v` first, but not what to do when it cannot be read. *Choice:* the chain is judged under this verifier's own field rules (0.1), which refuse such a genesis by name (`key 'v' is missing`, `v is an integer, not a string`). The same goes for a genesis line that does not parse.

**P11. The hash walk for an unknown version: genesis `prev`, `n`, floats, booleans** (silent). SPEC 2.1 lists what the version-free walk checks: one JSON object, each key once, `entry_hash` its canonical hash, `prev` the hash before it. *Choices:*
- genesis's own `prev` is not checked (it is a field rule, SPEC 2; SPEC 5's chain rule starts at `n ≥ 1`);
- `n` is not checked;
- a line with no string `entry_hash` is `BROKEN`;
- a number with a fraction has no canonical form (SPEC 4 rule 4), so its line is `BROKEN`;
- a boolean, which SPEC 4 rule 5 says "does not occur in v0.1", is written as `true` or `false`, since a later version may add one and the canonical form is frozen.

**P12. `--expect-head` against a version this verifier does not speak** (ambiguous). SPEC 2.1 says that when the hashes hold the verifier stops with `UNSUPPORTED-VERSION` (exit 4), and also that `--expect-head` "is still compared, and a mismatch is `HEAD-MISMATCH` (exit 3)". It never says which wins when both apply. *Choice:* `HEAD-MISMATCH`, exit 3. It is a finding about the history, and exit 4 is a refusal to judge field rules.

**P13. What makes `--files` exit 2** (ambiguous). SPEC 6 step 6 gives two tests. One: "every referenced path that still exists on disk hashes to some entry's recorded `sha256`". Two: "the latest reference per path is reported as `CURRENT` or `MODIFIED-SINCE-LOGGED`". A file put back to an older logged version passes the first test and is `MODIFIED-SINCE-LOGGED` under the second. *Choice:* exit 2 when any latest reference is `MODIFIED-SINCE-LOGGED`, and the line says when the content matches an earlier record. A path that is missing, or not a regular file, is `MISSING (not a readable file here)`, a note (SPEC 3: "goes on to its verdict"). The verdict word `FILES-DIVERGED` is taken from SPEC 6's transcript paragraph, the only place it appears.

**P14. The reference base for a chain beside `project.json`** (silent). SPEC 3: the base is "the recorded project path", but no section says which member of `project.json` records it. *Choice:* this verifier cannot follow any project record, so it reports such references as `UNRESOLVABLE` (SPEC 3: "a different sentence from 'file diverged'"). That is a note and moves no exit, since the spec gives unresolvable no exit code.

**P15. Commitments that shrink, without `--transcript`** (ambiguous). SPEC 6 says "every walk judges commitment monotonicity from the chain alone". But "Any failure produces `TRANSCRIPT-DIVERGED` (exit 5)" sits in the sentence about `--transcript`. *Choice:* a decrease is `TRANSCRIPT-DIVERGED`, exit 5, on every walk. SPEC 10.7 lists "the commitments contradict each other" under that verdict.

**P16. What a transcript commitment is, exactly** (silent). *Choices:*
- An entry is a commitment only when `actor` is `"receipts"`, since SPEC 2.2 calls it a kind of bookkeeping entry.
- Its action "names the grammar" when it starts with `transcript-commitment:`.
- `bytes` is a decimal with no leading zeros (`0` itself allowed), and `sha256` is 64 lowercase hex.
- A commitment whose `files` is not `[]` fails the grammar.
- A line that names the grammar and fails it is warned about and judged as nothing, as SPEC 6 says.

**P17. A missing transcript's wording** (silent). SPEC 6 makes it "a note, never a verdict" but gives no words. *Choice:* `note: transcript <path> is not there; its commitments are not checked`.

**P18. How `ts` is compared** (silent). SPEC 6 step 5 asks for non-decreasing `ts`, and step 1 says whether a timestamp is well-formed is not the walk's business. *Choice:* `ts` values are compared as strings, character by character. For SPEC 2's pinned form that is time order.

**P19. A log that is one blank line** (silent). SPEC 6: an *empty* log is no input, exit 66. *Choice:* only a 0-byte file is empty. A file holding `\n` has one line, which is not JSON, so it is a torn tail, exit 1.

**P20. `--expect-head` case** (silent). *Choice:* compared exactly, with no case folding. SPEC 2 says the hash is lowercase hex, and the comparison is meant to be mechanical.

**P21. Does `verify` check genesis's pinned values?** (silent, noted for completeness). SPEC 2.1 pins genesis as `action "genesis"`, `actor "receipts"`, `files []`. SPEC 6 step 1, though, is "type only", and no other step checks those values. *Choice:* not checked. Step 2 checks genesis's `n` = 0, and step 4 checks its `prev` = null.

## Part 2: closing the gaps (Phase 3)

One row failed at first contact, so there is one fix.

**G1. `head` on a chain with a torn tail: `spec-ambiguous`.** Row `tail-torn-head`.

- *What the spec says.* SPEC 5 and SPEC 6 say the head is "the `entry_hash` of the last entry". A torn final line is not an entry, so "the last entry" can be read as the last line that *is* one (here entry 2, head `6da33680…`). SPEC 10.3 supports that reading: it takes "the `entry_hash` of the last line that has one … a torn tail included". The other reading is "the final line", and a torn line has no hash. The spec says nothing about what `head` prints or exits when it has no head.
- *What I chose blind* (P2, P3): the first reading. I printed `6da33680…` and exited 0.
- *What the vector decided:* the second reading. "A torn tail has no head: nothing on stdout, the reason on stderr", exit 1.
- *Fix:* `chain_head` now reads the final line only, as SPEC 2.1 reads any line (one JSON object, each key once). When that line holds no `entry_hash`, `head` writes the reason to stderr and exits 1. `--expect-head` uses the same function. On a torn chain the verdict there is `BROKEN` either way, so only the wording of the head line changed.
- *Why this kind:* the spec's own words support both readings, and SPEC 10.3 states the one the vector rejects. The exit code and the empty stdout are unstated (silent), but they follow from that choice.

## Part 3: what the passing rows showed

These rows passed under the contract (exit code and verdict word), so none of them is a fix or counts in the tally above. Comparing whole last lines against the vectors turned up these points.

**O1. The last line under several breaks is the *last* break, not the first.** On `entries-swapped` the expected last line is `BROKEN at entry 3: prev does not match predecessor's entry_hash`. Mine is `BROKEN at entry 1: …`. On `entry-deleted` the expected line is the `prev` break at entry 2, which in step order comes after the `n` break at the same entry. So the reference lists every break in walk order and its last line is the last one. SPEC 6 says "first break reported, walk continues to list all breaks". I read that as "the verdict names the first break" (P8); the reference apparently reads it as "printing starts at the first break". This is `spec-ambiguous`, but outside the contract, so `verify.py` keeps its reading. A recipient comparing the two tools' full output would see them name different entries for the same chain.

**O2. The torn-tail sentence.** SPEC 6 quotes it as `entries 0–N-1 intact` (an en dash). The vector expects `entries 0..2 intact`. The spec's quoted wording is not the reference's. Only wording, and outside the contract.

**O3. Blind choices the vectors confirmed.**
- P1: the command-line form needed no adapting.
- P12: `--expect-head` beats `UNSUPPORTED-VERSION`; `unsupported-version-expect-head` is exit 3.
- P15: shrinking commitments are `TRANSCRIPT-DIVERGED` with no `--transcript`; `transcript-commitment-shrank` is exit 5.
- The SPEC 4 escaping: all three written-out canonical forms (`non-ascii`, `escapes`, `lone-surrogate-text`) matched byte for byte, and every head the rows name matched.

**O4. Blind choices no slice row tests.** P4 (is `files` sorted before hashing), P5's edge cases (a final line that is JSON but refused), P7 and P9 (the link after a refused line), P10 (genesis `v` unreadable), P11 (floats, booleans and genesis `prev` under an unknown version), P13 (a file put back to an older logged version), P14 (`project.json` beside the log), P16 (commitment grammar edges), P17 to P20. A second implementation could choose differently on any of these and still score 35 / 35. P4 is the one that moves hashes.
