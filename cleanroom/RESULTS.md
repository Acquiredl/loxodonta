# Results

## First contact (pre-registered, recorded before any fix)

`verify.py` was written from `SPEC.md` and `vectors/README.md` alone (Phase 1). `vectors/vectors.json` was then opened for the first time, by `run_vectors.py`, and this was the first run.

**first-contact score: 34 / 35**

Failing rows:

- `tail-torn-head`: exit 0, expected 1. My last line was the head `6da336801769a2bb75cc6a22c67c852069597548afd3d0fa20e822951169ec11`; the expected stdout was empty.

`run_vectors.py` also compared the three rows that write out a canonical form (`non-ascii`, `escapes`, `lone-surrogate-text`) byte for byte. All three matched.

There was nothing to adapt in the interface: the rows use `verify --log FILE` and `head --log FILE` with `--files`, `--expect-head HEX` and `--transcript FILE`, which is the form chosen blind in GAPS.md P1.

## Phase 3

One fix (GAPS.md G1): `head` reads the head from the final line only, and a torn tail has no head (exit 1, nothing on stdout).

Comparing whole last lines, not just verdict words, showed two wording differences that the contract allows (GAPS.md Part 3). Neither was changed:

- With several breaks, the reference's last line is the last break; mine is the first.
- SPEC 6 quotes the torn-tail sentence differently from what the reference prints.

## Final

1. **First-contact score: 34 / 35. Final score: 35 / 35.** The 37 sidecar and package rows were skipped, not passed.
2. **GAPS.md, by kind** (Part 2, one entry per fix):
   - `spec-silent`: 0
   - `spec-ambiguous`: 1
   - `spec-wrong`: 0
   - `my-bug`: 0

   Phase 1 also logged 21 blind choices (Part 1). The vectors confirmed 3 of them, refuted 1 (which became the one fix), and never tested the rest (Part 3, O4).
3. The spec carried the hashing on its own. The canonical-form rules and the RFC 8785 escaping were exact enough that every hash, head and written-out canonical form matched the reference on the first run, which is the claim SPEC.md makes about itself. Where it fell short was the commands rather than the format. It defines "the chain head" two ways (SPEC 5's "last entry" and SPEC 10.3's "last line that has one"), never says what `head` does with a torn tail, and its "first break reported" reads differently from what the reference prints. More quietly, about twenty of my choices are untested by any chain row. The sharpest is whether `files` is sorted before hashing: SPEC 3 says it is "part of canonicalization", while SPEC 4's six rules and its Python idiom never sort an array. Two careful implementers could split there and both still score 35 / 35.
