# ADR-0036: The hashing is frozen across format versions, so the hashes are walked before the version is refused

**Status:** accepted 2026-09-23 (ruled on #299)
**Deciders:** Acquiredl

## Context

SPEC section 2.1 told a verifier to read the genesis `v` before any
other rule, and to stop at a version it does not speak:
`UNSUPPORTED-VERSION`, exit 4, "a clean refusal, not a tamper verdict".
That order was chosen at v0.1 so that a later format could change
anything, the canonical form included, and an old verifier would not
misjudge it.

The order has a cost the conformance vectors made visible (#321). Set
the genesis `v` to `"0.2"`, recompute nothing, and edit any entry: the
verifier says `UNSUPPORTED-VERSION` before it walks a single hash, and
`--expect-head` is never compared. `supervisor scan` counts the chain
as refused, not broken. The genesis `v` is inside the genesis hash, so
the relabel itself breaks the chain, and the verifier never looks. Any
writer can turn a BROKEN verdict into a polite refusal by changing
three characters on line 0. ADR-0002 makes the writer the adversary,
and this is a downgrade the writer controls.

Two things a version could change are different in kind. The field
rules (which fields an entry has, of which types, and `n` counting up)
are what a new format would want to grow: a field for the model, a new
kind of reference. The hash chain (SPEC section 4's canonical form,
`entry_hash` over it, and `prev` naming the entry before) is what makes
the log tamper-evident at all, and every head record, anchor, published
head and package manifest already out in the world commits to hashes
computed under it.

## Decision

> **The hash chain never changes between format versions: SPEC
> section 4's canonical form, `entry_hash` over it, and the `prev` link.
> A later version may only add field rules. So a verifier walks the
> hashes first, whatever `v` claims. Any hash or link that fails is
> `BROKEN`, exit 1. Exit 4, `UNSUPPORTED-VERSION`, means only that every
> hash and link holds and the field rules are ones this verifier does not
> know. The cost is accepted: no future version can change the
> canonicalization.**

What the verifier does with a genesis whose `v` it does not speak:

- **The hash walk.** Each line must be one JSON object, each key given
  once, with an `entry_hash` equal to the SHA-256 of its canonical form
  and a `prev` equal to the entry before it's (`null` at genesis). A
  line that cannot be read, a torn tail, a key given twice and a string
  holding a lone surrogate are refused by name exactly as they are for a
  v0.1 chain, since each makes the hash unreadable or ambiguous. The
  field rules are not applied: an extra field, a `files` that is not an
  array, or an `n` out of step is a later format's business.
- **A break is reported as BROKEN is reported today:** the same lines,
  exit 1, and no `UNSUPPORTED-VERSION` line.
- **Clean hashes are the refusal:** `UNSUPPORTED-VERSION: log is format
  "X"; this verifier speaks "0.1"`, exit 4, as before.
- **`--expect-head` is still compared.** The head is the last entry's
  `entry_hash` under any version, so it is version-invariant. A
  mismatch prints the refusal line and then `HEAD-MISMATCH`, exit 3,
  the graver finding last, the way every other pair of findings is
  reported. A match leaves exit 4.
- **The other checks do not run** under an unknown version: `--files`,
  `--transcript`, `--anchors` and `--stamps` read fields (the file
  references, the commitment grammar, the entry numbers the sidecars
  name), and those are the field rules this verifier does not know.
- **`head` is unchanged.** It reads only the tail, and the tail's
  `entry_hash` is the head under any version.

The walk that judges v0.1 chains is unchanged. The code keeps the two
kinds of rule apart: `walk` takes `field_rules`, and the unknown
version walks with it off.

## Consequences

**What gets easier:**

- An edit is `BROKEN` whatever the genesis claims, so relabeling the
  version no longer hides tampering from `verify`, `verify-package`
  (`CHAIN-BROKEN`, not `UNSUPPORTED-FORMAT`) or the scan (exit 1, not
  exit 4).
- A second implementation of the format can judge a later chain's
  integrity without knowing its fields. The conformance vectors hold
  both sides of the line: `unsupported-version` and
  `unsupported-version-new-fields` exit 4, and
  `unsupported-version-edited` exits 1.
- Every hash already committed outside the machine stays meaningful
  under any later format.

**What gets harder or more constrained:**

- No format version can change the canonical form, the hash function,
  or what `prev` names. A change there is not a new version of this
  format; it is another format, with another way to tell a verifier so
  than a field inside a hash the verifier must first be able to check.
- A later format may still add a field to the genesis or to every
  entry. It may not add a field whose absence changes how the canonical
  form is computed.

**What we'll have to revisit if:**

- SHA-256 stops being fit for purpose. Moving the hash is then a new
  format in the sense above, and the way a verifier learns of it is
  that decision's to make.

## Alternatives considered

- **Keep the version check first.** The v0.1 order. Rejected: the
  refusal is a verdict the writer can choose, and the writer is the
  adversary (ADR-0002).
- **Walk the hashes first only when the claimed version is "close".**
  Rejected: "close" would be a rule about version strings, and whatever
  a verifier cannot parse it would still refuse unwalked, which is the
  same downgrade.
- **Treat an unknown version as BROKEN.** Rejected: a chain a later
  recorder wrote honestly would read as tampering to every older
  verifier, and a false `BROKEN` teaches operators to ignore real ones
  (SPEC section 6, on timestamps, for the same reason).

## References

- SPEC section 2.1 (the version, as amended), section 4 (the canonical
  form, now frozen across versions), section 6 (the verdicts).
- Related ADRs: `0001-hash-chain-not-signatures.md` (the chain is the
  whole mechanism); `0002-writer-as-adversary.md` (the writer chooses
  what the genesis says); `0035-the-recipients-verifier-is-copied-out-of-the-recorder-never-imported-by-it.md`
  (the conformance vectors that showed the gap).
- `0037-exit-1-means-broken-and-nothing-else.md`, ruled the same day.
- Discussion: the rulings on #299, 2026-09-23, item 1.
