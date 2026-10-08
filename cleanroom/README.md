# The clean-room verifier

`verify.py` here is a second verifier for the receipt chain, written from [docs/SPEC.md](../docs/SPEC.md) and [tests/vectors/](../tests/vectors/) alone, by an agent session that never read `loxodonta.py`. It tests one claim the spec makes about itself: that an independent implementation produces byte-identical hashes. `verifier.py` cannot test that, since it is copied out of the recorder (ADR-0035) and shares its reading by construction.

It covers the chain only, SPEC sections 1 to 6: `verify` and `head`. Sidecars and packages are not in it.

## How it was built

On 2026-10-08 a fresh session got a folder holding the spec, the vectors and [BRIEF.md](BRIEF.md), and three phases in order: write from the spec without seeing the expected answers, run the vectors once and record that score before fixing anything, then fix one failure at a time and say whose fault each one was. Afterwards its own receipt chain and its harness transcript were read side by side, and neither shows a read outside that folder.

| | |
|---|---|
| First run, before any fix | 34 / 35 chain rows |
| After one fix | 35 / 35 |
| The one fix | the spec defines "the chain head" two ways (#490) |
| Real chains it never saw | 145 / 145 agree with `loxodonta.py` on verdict and head |

So the hashing claim held. The gaps it found are in how the verbs are described, not in the format: #490, #491, #492. The details are in [RESULTS.md](RESULTS.md) and [GAPS.md](GAPS.md), written by the build itself, and [PROVENANCE.txt](PROVENANCE.txt) lists the hash of every file it was given.

## Frozen

Nothing here is edited. `tests/test_cleanroom.py` pins the bytes of `verify.py` and runs it against every chain row of the vectors, including rows added later. If the spec moves and this reading falls behind, the fix is a new clean-room round, not an edit, because an edit made with the recorder open would end the independence that is the whole point.

`run_vectors.py` is the build's own runner and expects a copy of `tests/vectors/` beside it as `vectors/`. In this repo the suite test does that job.

```
cd tests/vectors
python -I ../../cleanroom/verify.py verify --log valid-chain.jsonl
```
