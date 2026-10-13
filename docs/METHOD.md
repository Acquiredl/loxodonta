# How it was built

This page is for someone who wants to build a thing with an AI coding
agent that other people might trust, and wonders what that is like in
practice. It says how this repository was built, what kept it honest, what
the agent could not supply, and what went wrong. It is one person's account
of one project. Whether any of it carries over to yours is for you to
judge, and the open door at the end is real.

The short version: one person directs, an agent writes, and neither of
them is trusted. The checks are.

## Who does what

The author decides what to build, in what order, and whether what came
back is right. The agent writes the code, the tests, the drafts of the
docs, and most of the pull request text. Nothing reaches the stable branch
without the author's word, every time, and that has not been automated
away on purpose: it is the one gate a person still holds.

The author owns the examples. Behaviour is specified as concrete cases,
this input gives this output, before the agent writes a line, and those
cases become the tests that judge what the agent wrote. When a test is
wrong the author wrote a wrong example, which is a different conversation
from the agent writing wrong code, and it is a conversation worth having
in the open. [CONTRIBUTING.md](../CONTRIBUTING.md) says this in one
paragraph; this page is the long form.

## Language first

The first thing settled was the vocabulary, not the code.
[GLOSSARY.md](GLOSSARY.md) names every term and, more usefully, the words
the project refuses: this is not a blockchain, nothing here is immutable,
and it is not an audit log. Each refusal has a reason written beside it,
and the reason is a design constraint in disguise. Once "immutable" is off
the table, the only honest claim left is that a change shows, and the
verifier's output has to name the mechanism rather than draw the
conclusion for you
([ADR-0007](../adrs/0007-sidecar-manifest-seals-the-package.md)).

An agent drifts back to the comfortable word within a week, so the
glossary is enforced by a script. `tools/house_check.py` fails on a
refused word anywhere in the tree, on an overclaim on the front door, and
on a synonym standing in for a settled term, and it runs in CI. That one
check has caught more design drift than any review, because a wrong word
is usually the first visible symptom of a wrong idea.

## Decisions written where the code cannot argue back

Every decision that is hard to reverse, surprising without context, or a
real trade-off is an architecture decision record. There are 41 at the
time of writing, indexed in [adrs/README.md](../adrs/README.md). Each one
says what was weighed and names the published work it stands on, collected
in [GROUNDING.md](GROUNDING.md); a design that leans on a 1991 paper says
so. A changed mind is an addendum under the original, dated, never a
rewrite, so the record shows what was believed when. What was deliberately
not built has its own folder, `.out-of-scope/`, so the same idea is not
proposed fresh every month. And [DIRECTION.md](DIRECTION.md) says where
all of it points, so a session that starts from the code and not from a
conversation can tell a step toward the destination from a step beside it.

One habit around the ADRs did more than the ADRs themselves. Before a
decision is written down, the author restates it in their own words, and
the agent writes that version. More than once the restatement came out
different from what the agent had proposed, and the difference was the
decision.

## Tests that run what a user runs

Every behaviour is tested by running the command a user would run and
reading what it printed or wrote. No internals are mocked, no function is
called around the command line. That rule costs speed and buys something
an agent-built project needs badly: the tests cannot pass because the code
and the test share a misunderstanding of the internals, since the test
never sees them.

A few tests go further. The README's own command blocks run in the suite,
on three operating systems, so a sentence like "verify says VALID" is
checked, not remembered. Every screenshot and excerpt in the docs is built
by [tools/demo_store.py](../tools/demo_store.py) from a fixed script under
a neutral home, so no real path or name leaks into a picture and two
builds produce the same bytes. The receipt format has 35 conformance
vectors that the recorder, the verifier copied out of it, and the
clean-room verifier below must all pass. And when a family of bugs
appeared, a file opened in a way that could wait forever on a pipe put in
its place, the fix after the fifth patch was not a sixth patch but a check
over the three scripts' syntax trees, which found 37 such calls, 13 of
them unlisted, 8 that no review had seen ([HISTORY.md](HISTORY.md)).

## Rounds: unattended work, ruled first

Most of the code after the first month was built in rounds. The author
rules each issue first, in writing: what to build, which option, what is
out. Then builders run unattended, one issue each in its own worktree,
three at most at once. Every pull request gets one read-only reviewer that
did not write it, and the reviewer's verdict is one of three: merge, fix
first, or wrong direction, and the last one stops the issue and asks.
After three review rounds on one issue without a merge, the round stops
that issue and puts one yes-or-no question to the author. Bugs the
builders notice outside their issue are filed, not fixed. CI, not any
agent, is the judge of the full suite.

[HISTORY.md](HISTORY.md) records these rounds as they happened, including
the one where ten slices from one brief became 18 merged pull requests
with a defect found on almost every one, and the one after it that
cleared its own findings before anything new began. A lesson a round had
to learn is written into the round's own brief, dated, so the next round
starts smarter than the last.

## What the agent cannot supply

Whether any of it is true. The same model writes the code and reviews it,
and an agent's review of an agent's code tends to find it fine. So the
scarce input in this way of working is a reading from outside, and the
project went looking for it:

- Three machine-written reviews of the public repository at v0.6.0, read
  against the tree rather than taken; most of what they saw was real.
- Two outside reviews after that, one of which tested the README's claims
  by experiment and scored the presentation below the engineering. Its
  findings became nine issues and a front-door checklist the house checker
  now enforces.
- A clean-room verifier: a fresh session was handed the format spec and
  the vectors, never the code, and asked to reproduce every hash. It
  scored 34 of 35 on its first run, and the one miss was an ambiguity in
  the spec, not in the hashing ([cleanroom/](../cleanroom/README.md)).
- Red-team rounds: a session that attacks what the docs promise and builds
  nothing. The first one, in October 2026, attacked 29 stated promises and
  found 5 things, 2 of which were not visible from reading the code; they
  became issues #473 and #474 and changed [CLAIMS.md](CLAIMS.md).
- Measurements, pre-registered where it mattered: fresh agents quizzed on
  real history with and without the chain, the cost of orienting a new
  session, the gap between a session's end and its last receipt
  ([EXPERIMENTS.md](EXPERIMENTS.md)).

The one still missing is the plainest: two people who had never heard the
tool explained, asked what it does and who it is for. That test was ruled
the stop condition for the presentation work in September 2026 and has
not run yet.

## Thinking traps, named out loud

The author keeps a log of the traps that fired, one line each with what
was done about it. Three recur. Solving a question that was not the one
asked, which is why a plan now starts by restating the question. Patching
the same area a second time instead of asking whether it needs an
overhaul, which is where the syntax-tree check above came from. And the
code outgrowing the author's model of it, which in an agent-built project
is the main risk, and whose fix is a code walk: a guided reading of the
code, in plain language, hunting for bugs and drift at the same time.
Every walk so far has found something real. One more entry, because it is
the kind that repeats: a subagent's report about a harness flag was relayed
as checked when it was not, and the correction became a rule, that a
load-bearing claim from a subagent is read at its source before it is
repeated.

## What went wrong

The README has been re-led four times in six weeks, because the author's
taste was the finish line and taste is not one. The outside-readers test
above would have been a finish line, and it is still ahead. The first
community post, in September 2026, drew zero comments on three forums,
which is about the median for a tool of this kind and was read as an
underpowered test rather than a verdict. The "file opened waiting" family
took five issues before it was named as a family. And the obvious
objection, that the vendor already logs all this, sat unanswered on the
front page for weeks before a line was written for it.

## What this is not

It is not a claim that the method makes code correct. The measurements and
the outside readings do that work, slowly, and the method's job is to make
them possible: a tool a stranger can run and judge in an afternoon, with
claims small enough to check. The author is not a cryptographer, and the
design leans on published work for exactly that reason
([GROUNDING.md](GROUNDING.md), section 1). The agent wrote most of the
lines, and the author can still walk every function ([TOUR.md](TOUR.md))
because staying walkable was a rule from the start: single files, the
standard library only, and comments that say why.

| At the time of writing (2026-10-13) | |
|---|---|
| Architecture decision records | 41 |
| Tests, all through the command line | 1,656 in 37 files |
| Pull requests merged | 421 |
| Releases | 21, the latest v0.15.0 |
| Lines in the recorder, the supervisor, the receiver | 7,496 / 11,904 / 906 |

If you work this way and it breaks somewhere this page does not mention,
an issue here is as welcome as a bug report. That is field data too.
