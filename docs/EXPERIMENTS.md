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

## 6. The orientation-cost measurement (pre-registered and run 2026-09-06, second repo)

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

**Run.** Nine headless Claude Code sessions (`claude -p`, fresh, the arm
prompt as the first message), all one model. Each agent worked in its
own throwaway clone of `todo` at a neutral path with `origin` removed
and reflogs expired, so no run received a digest of another run and git
could not walk to the source repo. A `PreToolUse` hook denied every tool
call past the fifteenth and told the agent to answer with what it had.
Tool calls and tokens were read from each session's own transcript
(`in` is input plus cache tokens: the context the agent took in). An
unbounded run earlier the same day (the *pilot*, below) shaped that
protocol.

**Results.**

| Agent | Arm | Score | Tool calls | Token estimate (out / in) | Confabulations |
|---|---|---|---|---|---|
| A1 | digest + recall | 11/12 | 15 (3 denied) | 32K / 903K | 0 |
| A2 | digest + recall | 11/12 | 16 (4 denied)¹ | 32K / 1.06M | 1² |
| A3 | digest + recall | 11/12 | 15 (4 denied) | 34K / 954K | 0 |
| B1 | transcript only | 11/12 | 9 | 23K / 675K | 0 |
| B2 | transcript only | 11/12 | 15 (1 denied) | 43K / 1.17M | 0 |
| B3 | transcript only | 11/12 | 13 | 23K / 999K | 0 |
| C1 | git only | 8/12 | 9 | 18K / 553K | 0 |
| C2 | git only | 8/12 | 7 | 9K / 400K | 0 |
| C3 | git only | 8/12 | 8 | 14K / 484K | 0 |

¹ Two `Glob` calls issued in parallel raced the hook's counter file.
² Said the empty `.claude/worktrees/` folder was absent; it is present.

Per arm, means: **A** 15.3 calls, 33K out, 973K in, five of six
questions answered; **B** 12.3 calls, 30K out, 948K in, six of six;
**C** 8.0 calls, 14K out, 479K in, two of six.

**Where the points went.** Arm C answered the two git-visible questions
in full and said "cannot determine" on the other four, each time for the
right reason ("the reflog is absent; this checkout is a copy"). The
rubric scores an honest "cannot determine" at 1, as §2 did (its git-only
agents scored 10/12 for the same reason), so C's 8/12 is two questions
answered in full and four points for honesty: it answered two of six.
(The run's Arm C prompt said such an answer was "worth full marks"; the
pre-registered rubric governs, and the table above follows it.) Arm A answered Q1–Q4 and Q6 correct
and specific, Q4 to the second (receipt 63 at 22:06:25Z, the full test
run before it). On Q5 the digest labels its `VALID` line testimony and
points at `verify`, which recall does not expose; all three A agents
spent their remaining calls looking for it, hit the budget, and said
"cannot determine" (1 point). Arm B answered all six; on Q5 it verified
the transcript's own integrity (485 lines, every parent link resolves,
every call has a result), not the chain's (1 point).

**Ground truth, revised.** Two of the pre-registered answers did not
survive contact with the transcript arm.

- *Q4.* The key names receipt 63, the closing commit. Every transcript
  agent, and every pilot chain agent, places the last action later: a
  detached PowerShell loop set to delete the worktree folder, then the
  session renaming itself at 23:17:39Z; the transcript's final record is
  the operator's `/exit` at 23:20:35Z. Those receipts are in the store,
  in the 12-entry worktree drawer this section mentions above, which
  repo-scoped recall does not reach. The key was derived from the drawer
  recall shows. Arm B is right and scored 2; the budgeted A agents never
  reached that drawer and matched the key as written.
- *Q6.* The transcript counts 38 PowerShell calls of 79; the main
  drawer's receipts give 24 of 61 (31 of 71 with the worktree drawer).
  Both arms named PowerShell and scored 2. The gap between 71 receipts
  and 79 calls is exactly the eight calls the transcript marks
  `is_error` (seven PowerShell, one Read), which fire no hook: per tool,
  calls minus failures equals receipts without remainder, `ToolSearch`,
  `Skill`, and the MCP tool included (checked 2026-09-08, #158). That is
  "every completed tool call" as the README states it.

**Pilot** (same day, no budget, `origin` left in place). Means: A 26.3
calls, 62K out, 1.91M in; B 14.3, 42K, 925K; C 11.3, 22K, 619K. All
three A agents distrusted the digest's "last recorded action", left the
recall surface for the raw chain files, ran `scan` and `verify`, found
the worktree drawer and the two revisions above; none had written an
answer before its sixteenth call. All three C agents followed the
clone's `origin` to the source repo and answered Q3 from its reflog and
its empty `.claude/worktrees/` folder. Both are leaks in the protocol,
closed for the run; the pilot's numbers are reported, not scored.

**What the result licenses.** The pre-registration's second branch: Arm
B oriented as cheaply as Arm A (948K against 973K in, 30K against 33K
out), and A used more tool calls, reaching the budget in three sessions
of three to B's one. The 187× ratio is real and measures bytes on disk,
not cost to orient: no transcript agent loaded the file into context;
each parsed it with two or three Python one-liners, and input processed
tracked turn count in every arm (roughly 55–65K of resident context per
turn). So the README's memory reason keeps to what git cannot tell you
and makes no cost claim; the size ratio stays here as a mechanical fact.
What the run does support: with the digest and recall, three fresh
agents of three answered five of six within budget, including the
worktree that no longer exists and the exact final receipt, and said
"cannot determine" on the sixth rather than guess; git alone answered
two.

**Caveats, stated plainly.** N = 3 per arm; one repo and one session;
all nine agents one model; the git-only arm was fastest (7–9 calls) on
the facts it could see; Arm A's Q5 miss is a gap in the recall surface
(no `verify` offered) as much as in the arm; Arm B was handed the
transcript's path, which the harness keeps thirty days by default, in
one harness's layout; the key's Q4 was wrong as pre-registered and is
corrected above from the transcript. Productivity is not claimed.

**Findings for the tool, from the run.** Repo-scoped recall does not
reach a session's worktree-path drawer. The digest header's entry count
(61) against the last sequence number (63) read as a possible gap to two
agents. The digest hedges `VALID` as testimony and points at a command
recall cannot run. The fast-forward merge is in the reflog and in
neither chain. Action text is capped at 173 characters, twice cut
mid-character. 71 receipts against 79 transcript tool calls (resolved: the eight are the failed calls, #158).
