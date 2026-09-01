# Experiments — what was actually tested, and how it came out

Claims in the README about agents using the chain are backed by runs,
not intuition. This file is the record: protocol, numbers, and the
caveats that keep the conclusions honest. Everything here was measured
against this repo's real chains; the chains themselves are the ground
truth the answers were graded against.

## 1. Orientation test (2026-08, informal)

Fresh agents had to orient in a repo from the chain, the git log, or
both. The chain was the only source that caught work happening off
main: a local branch never pushed, operations that produce no commit,
the action in flight when the last session ended. Git log held its own
on committed work. This shaped the README's framing: the chain doesn't
replace git; it answers what git structurally can't.

## 2. The recall quiz (2026-08-29, pre-registered)

**Protocol.** Six questions about this repo's real history. Ground
truth was derived from the chains and written down, with a scoring
rubric (2 = correct and specific, 1 = partial or an honest "cannot
determine" where the source truly can't know, 0 = wrong), *before* any
agent launched. Four fresh agents, no session context, 15-tool-call
budget each:

- **Arm A** (×2): the session-start digest, the read-only recall
  commands (`digest` / `show` / `search` / `timeline`), plus git and
  the working tree.
- **Arm B** (×2): git and the working tree only — the world without
  the recorder. Told explicitly that an honest "cannot determine"
  beats a guess.

**Results.**

| Agent | Sources | Score | Tool calls | Confabulations |
|---|---|---|---|---|
| A1 | digest + recall + git | 12/12 | 7 | 0 |
| A2 | digest + recall + git | 12/12 | 8 | 0 |
| B1 | git only | 10/12 | 4 | 0 |
| B2 | git only | 10/12 | 2 | 0 |

Both git-only agents dropped exactly the same two points — the two
questions whose answers exist only in the chain: the sub-commit final
action of a session (the chain knows the exact edit and minute; git's
best answer is the nearest commit), and whether any recorded history
is damaged (the chain shows a crash-truncated tail; git cannot see it).
Both said "cannot determine" rather than guessing, so the measured
difference is coverage, not honesty.

The single best artifact: asked to name activity git cannot show, both
digest agents independently produced a receipt recording an edit to a
throwaway prototype in a since-pruned worktree — and showed that
`git log --all` has no trace of that file on any branch, ever. The
prototype's design survived into the supervisor; the record that it
happened survives only in the receipts.

**Caveats, stated plainly.** N = 2 per arm; one repo, and that repo
builds the tool; all agents share a model family; the git-only arms
were *faster* on git-visible facts (2–4 tool calls). The supported
claim is precisely the README's — the chain answers what git can't —
not "agents with the chain are faster". Productivity is a separate,
harder experiment, deliberately not claimed here.

## 3. The adversary battery (2026-08-29)

Run against the public `main` snapshot with a copy of a real 118-entry
chain, through the public CLI only:

| Attack | Result | Exit |
|---|---|---|
| edit one entry's action | `BROKEN at entry 60: entry_hash does not match canonical form` | 1 |
| delete a middle entry | `BROKEN at entry 60: sequence number is 61, expected 60` | 1 |
| reorder two entries | `BROKEN at entry 40: sequence number is 41, expected 40` | 1 |
| splice a forged entry | `BROKEN at entry 31: sequence number is 30, expected 31` | 1 |
| regenerate (internally valid) | `VALID` — the documented gap | 0 |
| regenerate vs recorded head | `HEAD-MISMATCH` | 3 |

The automated drill agreed (4/4 alarms, exit 0), the baseline tripwire
caught a chain regenerated between two scan ticks (exit 5), and `show`
on a tampered entry refused to bless it (warning, exit 1). A separate
fresh agent followed the README with no prior context; every recorder
claim held as written — including, unplanned, the flagship one: the
agent mistyped a `run` command, and the failure was receipted anyway.

## 4. The transcript-commitment envelope (2026-08-31, ADR-0017)

Measured on the author's machine (Windows 11, CPython 3.13, NVMe),
synthetic transcripts of random bytes, medians over repeated runs:

| What | 1 MB | 10 MB | 50 MB |
|---|---|---|---|
| open + read + sha256 of the whole prefix | 0.9 ms | 9.6 ms | 48.0 ms |

End-to-end through the real hook (10 MB transcript, 5 runs each): an
off-boundary call medians **153 ms**, the boundary call — tool receipt
*plus* transcript hash *plus* commitment append under the same lock —
medians **156 ms**. Interpreter startup dominates both; the commitment
itself is noise until transcripts reach tens of MB, and even a 50 MB
transcript adds ~50 ms to one call in 25 (~2 ms amortized). Lock
behavior is unchanged in shape: the boundary call holds the same
per-chain lock once, slightly longer — the ADR-0016 burst arithmetic
gains no new term.

**The append-only assumption, live:** the first real commitment landed
during the session that shipped the feature (entry 126, 1,679,210
bytes) and was judged minutes later, after the transcript had grown
past it: `COMMITMENT HOLDS`. In-session growth is append-only as
assumed. The **resume drill** ran the same day: the session was closed,
restarted, and resumed, worked a few more calls, and the judge command
re-run — `COMMITMENT HOLDS (entry 126)` again. Close-and-resume does
not rewrite committed bytes, so the README carries the claim. The one
behavior still unobserved is **compaction**: no commitment has yet been
judged across a context compaction, and the claim's fine print stays
honest about it until one is. (Indirect comfort, not proof: the
completeness witness has paired transcripts with chains across weeks of
long sessions without surplus scars, so compaction at least preserves
tool events — byte-stability across it is the remaining question.)
