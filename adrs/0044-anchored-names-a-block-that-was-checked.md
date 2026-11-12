# ADR-0044: ANCHORED names a block that was checked, and a block that was not is ANCHOR-CLAIMED

**Status:** accepted 2026-11-11, built (#597). Ruled by the author on that date after a design review of the whole tool, as one answer to the proposal with its three choices.
**Deciders:** Acquiredl

## Context

An OpenTimestamps proof replays from a chain head to a merkle root
and ends in an attestation: a few bytes that say which Bitcoin block
holds that root. Nobody signs them. `verify --anchors` replays the
proof offline, and only a recipient who passes `--block-header` has
the root compared with a block (ruling 3 on #299, SPEC section 9.6).

Both cases print a line that starts with the same word:

```
ANCHORED: entries 0..41: the attestation claims Bitcoin block 871204, and the block was not checked; ...
ANCHORED: entries 0..41 existed by the block whose header hashes to ...
```

A package says it more shortly still. Its verdict reads
`SELF-CONSISTENT + ANCHORED` in both cases, and the exit is 0 in
both. The supervisor reads either line and shows the chain as
`ANCHORED` on the dashboard and in its counts.

The sentence after the word is exact. The word is not. A writer who
regenerates a chain today can end a proof in an attestation that names
a block of two years ago, at no cost, and a recipient who gives no
header reads `+ ANCHORED`. The package's own rule is that its verdict
names what a regeneration would also produce and each rung is earned
(ADR-0026): a regeneration earns this rung for nothing. ADR-0007
ruling 5 already says a verdict word names the mechanism and never a
conclusion, and the stamps already keep to it: a token nobody judged
prints `stamp not judged` and never `STAMPED` (ADR-0032).

### Prior art, read on 2026-11-10

| System | What it prints for what it could not check | What is taken from it |
|---|---|---|
| The OpenTimestamps client | success only when it asked a node for the block; otherwise that it could not verify | the word for a checked block is kept for a checked block |
| Git, `%G?` | one letter each for a good signature, a good one of unknown validity, and one that cannot be checked | one word for each thing checked |
| debsig-verify | its own exit code for a signature it had no policy to judge | considered for the exit, and not taken: see ruling 3 |
| GnuPG, the counter-example | `Good signature`, then a warning that the key is not certified | the first word is what is read |

## Decision

1. **`ANCHORED` is printed only for a block that was checked.** A
   proof that replays to a Bitcoin attestation whose root a given
   header holds is `ANCHORED`, worded as today. A proof that replays
   to an attestation and met no header is `ANCHOR-CLAIMED`, with the
   rest of today's line: the block the attestation claims, that it
   was not checked, the root to check and the flag that checks it.
   The same on a manifest's seal line: `seal anchor: ANCHORED` or
   `seal anchor: ANCHOR-CLAIMED`.

2. **A package earns `+ ANCHORED` only with a checked block.** With
   an attestation and no header the verdict gains no rung. The line of
   residual trust keeps what it says today for that case, so the
   recipient still reads which block is claimed and how to check it.
   The verdict then carries the limit a package with no seal carries,
   and says what would lift it: a block header that checks the
   manifest anchor's block. A pending anchor's words name both steps,
   the proof completing and a header checking its block.

3. **No exit code moves.** `ANCHOR-CLAIMED` is a note, as `ANCHORED`
   is: exit codes here mean a finding against the log (ADR-0037), and
   nearly every honest `verify` runs with no header. A script that
   must know a block was checked reads for the word.

4. **The supervisor says what verify said.** It reads both lines and
   keeps them apart: a chain whose anchor was claimed is shown and
   counted as `ANCHOR-CLAIMED`, and `ANCHORED` is kept for a chain
   whose block the supervisor's own verify checked. The supervisor
   gives no header today, so the dashboard and the metrics read
   `ANCHOR-CLAIMED` where they read `ANCHORED`, until it is given a
   way to check a block. A count that was of anchored chains is a
   count of checked ones, and the claimed ones get a count of their
   own.

5. **The docs say it:** `docs/SPEC.md` sections 9 and 10,
   `docs/ANCHORING.md`, `docs/PACKAGE.md`, `docs/METRICS.md` and the
   glossary, each where a sentence would otherwise be false.

The chain format is untouched (ADR-0036). A verifier of an earlier
release prints the earlier word.

### What it claims, and what it does not

It claims that the word `ANCHORED`, on a line or in a package's
verdict, was printed by a verifier that compared the proof's root with
a block header its user gave.

It does not claim:

- **That the header is the block's.** That is the header source's
  word, and the hash printed beside it is what a second source
  confirms, as before.
- **That `ANCHOR-CLAIMED` is a fault.** It is what an honest anchor
  reads as until someone checks its block.
- **Anything about a pending proof.** `ANCHOR-PENDING` and
  `ANCHOR-UNANSWERED` are as they were.

## Consequences

**What gets easier:**

- One word, one meaning: a reader who sees `ANCHORED` need not read
  the rest of the line to know whether a block was looked at.
- The package's rungs are again what a regeneration cannot earn.
- Anchors and stamps follow the same rule.

**What gets harder or more constrained:**

- The operator's dashboard stops saying `ANCHORED` for chains it said
  it for yesterday, with nothing about those chains changed.
- A script that read `ANCHORED` to mean "a proof completed" reads two
  words.
- Three docs and the spec change their verdict words.

**What we'll have to revisit if:**

- The supervisor gains a way to fetch or be given block headers: the
  dashboard can then earn the word back.
- Recipients ask for an exit code after all: a flag that makes a
  claimed block a refusal is additive.

## Alternatives considered

- **Keep the word and rely on the sentence.** Rejected: GnuPG's
  lesson, and the package's verdict line has no sentence at the rung.
- **`ANCHOR-UNCHECKED`.** Rejected: it reads as a fault in the
  recipient. `ANCHOR-CLAIMED` reuses the verb the line already had.
- **A rung of its own, `+ ANCHOR-CLAIMED`.** Rejected by the author:
  a rung is earned, and this one costs a regeneration nothing.
- **A new exit code.** Rejected: ruling 3.
- **Keep `ANCHORED` on the dashboard.** Rejected: the supervisor would
  then say more than the verifier it ran.

## References

- #299 (ruling 3: the block not checked is said so), #349 (the
  supervisor reads verify's own line)
- ADR-0003 (the OpenTimestamps subset), ADR-0007 ruling 5 (verdict
  words name the mechanism), ADR-0026 (the package's rungs), ADR-0032
  (the stamp nobody judged), ADR-0036, ADR-0037
- `docs/SPEC.md` sections 9 and 10, `docs/ANCHORING.md`,
  `docs/PACKAGE.md`
