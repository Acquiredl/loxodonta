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

## 5. The lifecycle gap measurement (2026-09-01, ADR-0018)

Before the dormancy thresholds froze, the real store's intra-session
gaps were measured: every pair of consecutive receipts within a
session, across all drawers (36 sessions, 3,560 gaps, bookkeeping
entries excluded).

| statistic | value |
|---|---|
| median gap | 10 s |
| p95 | ~7 min |
| p99 | ~68 min |
| gaps > 24h | 5 |
| gaps > 48h | 5 (50h, 95h, 173h ×3) |

The verdict: the 24h/48h defaults survive. Every observed 24h+ gap
was also 48h+ — the waning band captures nothing dishonest, and the
five dormant-tier resumes were all the operator genuinely reopening
sessions days later. Those *will* fire the reawakening signal, by
design: at roughly one or two a week it is a legible investigate
cadence, and "someone reopened an old session" is exactly the fact
the signal exists to surface — the words leave whose hands it was to
the operator. Thresholds stay env-tunable
(`SUPERVISOR_WANING_SECONDS`, `SUPERVISOR_DORMANT_SECONDS`) for
stores with different rhythms.

## 6. The orientation-cost measurement (pre-registered, second repo)

This section is written before any agent launches (#130, PRD #120). It
decides what the README's memory reason may say. It extends the recall
quiz (§2) in three ways: a second repo that does not build the tool, a
third arm that reads the raw harness transcript, and a cost measure, not
only a correctness one.

**The repo.** `todo`, a small command-line todo list built with the tool
recording it but not developing it. One dense session on 2026-09-01: 64
receipts in the project's drawer, plus a 12-receipt worktree drawer, and
the harness transcript still on disk. The session's history carries the
three shapes the measurement needs: work git can see, work only the chain
can see, and a volume of detail only the transcript holds.

**The question this settles.** Not "is the chain more correct than git" —
§2 answered that. The new question is the one a reader asks: if the
transcript already holds everything, does the chain add anything but a
copy? The three arms are built to separate correctness from cost, because
that is where the answer lives: the chain and the transcript hold the
same facts, but one is an index of a few KB and the other is most of a
megabyte to wade through.

**Arms.** Three, three fresh agents each (N = 3), no session context, a
fixed tool-call budget, same model family across all nine:

- **Arm A** — the session-start digest and the read-only recall commands
  (`digest` / `show` / `search` / `timeline`), plus git and the working
  tree. The tool as an operator runs it.
- **Arm B** — the raw harness transcript file on disk and ordinary file
  tools, no digest and no recall. The world where the transcript is the
  memory. Whether an agent can orient in a ~720 KB transcript at all, and
  at what cost, is part of what this measures.
- **Arm C** — git and the working tree only. The world without the
  recorder. Told plainly that an honest "cannot determine" beats a guess.

**Measures.** Per agent: **correctness** against the rubric; **tool calls
to orient** (the headline cost measure, as in §2); and a **token
estimate** read from each agent's own transcript usage records where the
harness wrote them (secondary, reported when available, never the claim's
sole support). Plus one mechanical measure, below.

**Rubric**, fixed here: `2` correct and specific; `1` partial, or an
honest "cannot determine" where the source genuinely cannot know; `0`
wrong. Twelve points per agent over the six questions.

**The questions and their ground truth** (derived from the store, the
transcript, and git before launch; the quiz agents do not read this
file):

1. *(git-visible)* What was the last change committed, and what did it
   do? — Commit `5c5339b`, "close code walk: glossary seeded, Gate 2
   review discharged in METACOG".
2. *(git-visible)* How does the `rm` command decide which item to remove,
   and how were out-of-range numbers handled? — 1-based lookup reusing
   the shared bounds check (`pick_item`); commits `af0d9e2` then
   `a945026` (rm reuses the `pick_item` result instead of discarding it).
3. *(chain-only)* Was any of this work done in a git worktree, and does
   that worktree still exist? — Yes: the session wrote `GLOSSARY.md` and
   `METACOG.md` under `.claude/worktrees/todo-cli-v1-eeb1aa/`; that
   worktree is gone from `git worktree list` now. Git shows no trace that
   the work happened in a worktree; the chain records every write there.
4. *(chain-only, sub-commit)* What was the exact final recorded action of
   the session? — Receipt 63: the `git add GLOSSARY.md METACOG.md; git
   commit` PowerShell call, immediately after a full test run (receipt
   62). Git's finest answer is the commit; the chain has the minute and
   the step before it.
5. *(chain-only, integrity)* Is any recorded history of this session
   damaged or truncated? — No; the chain verifies VALID end to end. Git
   and the transcript cannot answer this at all.
6. *(tempo)* Which tool did the session lean on most, and roughly how
   often? — PowerShell, by a wide margin: 24 of the 64 receipts in the
   main drawer. Git cannot know; the transcript can be made to count, at
   a cost.

**The mechanical size measure.** Chain bytes versus transcript bytes for
the same session, by file size. Method: the session's chain file against
its harness transcript file. Measured 2026-09-06 on the worktree
session: chain `3,955` bytes, transcript `738,079` bytes — a **187×**
ratio. This is the number behind "a few KB per session": the chain is the
index, the transcript is the volume it indexes.

**Results.** *(Filled after the run; the table below is the shape.)*

| Agent | Arm | Score | Tool calls | Token estimate | Confabulations |
|---|---|---|---|---|---|
| A1 | digest + recall | | | | |
| A2 | digest + recall | | | | |
| A3 | digest + recall | | | | |
| B1 | transcript only | | | | |
| B2 | transcript only | | | | |
| B3 | transcript only | | | | |
| C1 | git only | | | | |
| C2 | git only | | | | |
| C3 | git only | | | | |

**What the result may license.** If Arm A reaches the chain-only facts at
a fraction of Arm B's cost while Arm C misses them, the README's memory
reason may state the index-versus-volume claim with the size ratio as its
number. If Arm B orients as cheaply as Arm A, the reason keeps to "what
git cannot tell you" and drops any cost claim. A productivity claim is
out of scope either way (the PRD, §2's standing rule).

**Caveats.** *(Completed with the results, in §2's voice: N per arm, one
repo and one session, shared model family, and any arm that was faster on
facts it could see.)*
