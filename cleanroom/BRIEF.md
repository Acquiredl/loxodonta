<!-- The brief the clean-room build was given, as its CLAUDE.md, 2026-10-08 (#493).
     Redacted for publication: the author's name and this machine's paths are
     replaced by words in [square brackets]. Nothing else differs. -->

# Clean-room build: a second verifier for the loxodonta chain format

This folder is a clean room. You are building a verifier for the loxodonta receipt-chain format **from the written spec alone**, to test one public claim: SPEC.md says it is "precise enough that an independent implementation, in any language, produces byte-identical hashes." Nobody has tested that claim yet. You are the test.

The person directing this is [the author]. They own the decisions; you own the code.

## The clean-room rule

You may read only:

- the files in this folder (`SPEC.md`, `vectors/`, `PROVENANCE.txt`, this file);
- Python's own standard-library documentation.

You may not read, search, list or run anything under [the loxodonta repository], [its stable checkout], or `~/.loxodonta`. You may not search or fetch the web for loxodonta, Acquiredl, or its GitHub repo. You may not import any module named `loxodonta`, `verifier` or `supervisor`.

This session is recorded by loxodonta itself. Afterwards [the author] will search this session's receipts for every file it opened, so the clean room is checked, not taken on trust. If you find yourself wanting to peek, that is a finding: write it in `GAPS.md` and make a choice instead.

[Two workspace instruction files] load here too, because this folder sits under them. Their maps name the loxodonta repo; that is not an invitation. Their "when you first arrive" steps (read the repo's glossary, skim its ADRs) do not apply: this folder is not a repo, and the spec is the only glossary you get. SPEC.md cites ADRs by number; you cannot read them, and a rule you can only understand through one is a gap.

Never edit `SPEC.md` or anything in `vectors/`. `PROVENANCE.txt` holds their hashes.

## The slice

Chain rows only: SPEC sections 1 to 6, and the `verify` and `head` rows of `vectors/vectors.json` that give neither `--anchors` nor `--stamps` (35 rows). Sidecar rows (section 9) and package rows (section 10) are out of this slice. The runner reports them as `skipped`, never as passes.

## How to work: three phases, in order

**Phase 1: write from the spec.** Read `SPEC.md` and `vectors/README.md`. Do **not** open `vectors/vectors.json` or the vector files yet. Write `verify.py`. Each time the spec is silent, ambiguous or contradicts itself, add an entry to `GAPS.md` saying what you chose and why.

**Phase 2: first contact. Pre-registered, so record it before you fix anything.** Write `run_vectors.py`, run it, and write the score into `RESULTS.md` as *first-contact score: N / 35*, with the list of failing rows. Adapting command-line flags to the `args` the rows use is allowed here; log it as `interface`, not as a gap.

**Phase 3: close the gaps.** Fix the failures one at a time. Each fix gets one `GAPS.md` entry, sorted into exactly one kind:

- `spec-silent`: the spec does not say, and the vector decided it;
- `spec-ambiguous`: the spec can be read two ways, and the vector picked one;
- `spec-wrong`: the spec says one thing and the vector expects another;
- `my-bug`: the spec was clear and I misread it or coded it wrong.

Be honest with `my-bug`. That count is as interesting as the others. A row you cannot pass without guessing stays failing and is written up; it is never forced green.

## The code

- `verify.py`: one file, Python 3.9+, standard library only, run as `python -I verify.py ...`.
- It must accept the `verify` and `head` forms the slice's rows use. The contract is the **exit code** and the **verdict word** at the start of the last line (`vectors/README.md`, "For another implementation"). Other wording may differ, and the runner compares only those two (and the whole line for `head` rows).
- Readable by someone who is not a programmer: plain functions, top to bottom, in the order the spec's verification algorithm runs. Every function and every rule carries a comment naming its SPEC section, for example `# SPEC 4: keys sorted by code point`. The finished file should work as a map of the spec.
- `run_vectors.py`: reads `vectors/vectors.json`, runs each row in the slice from inside `vectors/`, prints one line per row (`pass`, `FAIL` with expected vs got, or `skipped`), then the totals.

## Finishing

`RESULTS.md` ends with:

1. the first-contact score and the final score, out of 35;
2. the `GAPS.md` count by kind;
3. three to five sentences, in plain language, on what the spec carried on its own and where it fell short.

Then stop and tell [the author] it is done. Do not commit anything. There is no git here on purpose: the receipts are the history. Moving the result into the loxodonta repo happens in a separate session, through a pull request.

If something blocks you completely (a row that seems to need code you were told not to read, say), stop and ask [the author] rather than working around it.
