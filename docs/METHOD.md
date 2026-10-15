# How it was built

This page is for someone who wants to build a thing with an AI coding
agent that other people might trust, and wonders what that is like in
practice. It says how this repository was built, what kept it honest, what
the agent could not supply, and what went wrong. It is one person's account
of one project. Whether any of it carries over to yours is for you to
judge, and the open door at the end is real.

The short version: one person directs, an agent writes, and neither of
them is trusted. The checks are.

## Why I built it

I come from about 10 years in tech: tech support first, then networking,
cloud and security, physical work like cabling, wiring and PCs, and
enterprise migrations of databases, software versions and Windows. I had
done penetration testing, so I knew how some of today's security settings
get defeated, but I had never been the one putting them in place. So the
goal was practice: a security tool that defends rather than attacks. I knew
I could pick up the defensive side quickly once I had my hands on it, I
just did not have it yet.

The idea came out of a harness I built for myself. Along the way it grew
gates that check whether what goes through an agent is still what I asked
for, to catch drift. I took that one piece and went deep on it, and left
the rest of the harness alone. The first premise was a log that is
truthful and can show it is truthful, and from there it turned into
building a tool that could actually do that.

My blind spot was the engineering side, the programming. I understand the
main security threats and I can follow the model of what was built here,
because every decision was mine: I reviewed what the agent suggested,
asked for the pros and cons of each option, and over time we settled into
always testing. Thin slices, quick demos, try both and keep the better
one. The agent fills the coding gap with good enough code, and the checks
on this page are what make good enough hold.

Some choices came straight from it being a security tool. A receipt is
plain JSON text: nothing to decrypt, no proprietary format, no protocol to
learn first, so anyone can open a chain and read it. No dependencies, four
files you can read, easy to carry and easy to audit, because people need
to be able to test a tool like this and see inside it. Keeping the code
readable was a goal from the start too, and it got harder as the files
grew, so it became one goal among others.

At the start there was a lot of hand-holding from the agent; I knew I was
an amateur at the engineering questions. With time I came to understand
the reasoning behind most of the options, and now I keep adding to it to
make it as strong as I can. The first motivation was fun, then it became a
challenge, and a proof to myself that I could build something worth
reading. If someone uses it as a security tool, takes something from the
method, or just sees that you can build this way, that is a good outcome.

The rest of this page calls me the author.

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

## The layers, and what forced each

Each layer exists because something showed the one before it was not
enough. The short form, newest at the bottom, with the finding that forced
it; the ADRs hold the long form.

1. **The chain** (ADR-0001). A log an agent can edit is worth what the
   agent says it is. Each receipt carries the hash of the one before, so
   an edit, a deletion or a reorder shows and `verify` names the entry.
   Left open: a chain rebuilt from scratch is a valid chain.
2. **The head, kept off the machine** (ADR-0002, ADR-0025). The rebuilt
   chain. `head` prints the one line only the recorded history produces;
   kept out of the agent's reach, it makes a rebuild read `HEAD-MISMATCH`.
   Forced by the threat model itself, before any attacker existed.
3. **The anchor** (ADR-0003). A head still needs a witness with a clock
   nobody controls. A 32-byte digest goes to the OpenTimestamps calendars,
   which commit it to Bitcoin, so the chain's existence by a date rests on
   nobody's word. Left open: the hours until a proof matures.
4. **The hook** (ADR-0002, Stage C). Asking an agent to log itself is
   asking the adversary. The harness runs the recorder after each tool
   call, so the agent is what is recorded, not what decides. Left open: a
   call the harness fires no hook for.
5. **The witness** (ADR-0016). Integrity says nothing about omission. The
   supervisor counts a session's tool calls against the harness's
   transcript and names the deficit. Forced by the first weeks of real
   sessions, which the chain alone could not judge. Left open: the
   transcript sits on the agent's machine.
6. **The store, then the receiver** (ADR-0011, ADR-0031). Chains in each
   project's folder are the agent's to find, so one machine-wide store
   came first; then a remote that can only add, on a machine the agent
   cannot reach, after two outside reviews converged on the same gap,
   evidence that travels.
7. **The package and the verifier** (ADR-0026, ADR-0035). A recipient has
   to judge the record with nothing running and nobody to ask: one zip,
   one file, one verdict. The verifier is copied out of the recorder and
   never imported by it, after an experiment showed a module's bytecode
   cache can be swapped with its checksum unmoved.
8. **The managed install** (ADR-0040). One flag on the command line
   switched the hook off and the chain went quiet (#259). The hook now
   lives where only an administrator writes, measured against that flag
   and against `--bare`.
9. **The second record, out of reach** (ADR-0041). The red-team round
   showed completeness fell to a writer who edits one or two files on its
   own machine (#473). The harness's own tool-call events now go to the
   receiver by a second door, and the reading that counts runs there.
10. **The clean-room verifier** (#493). The spec claimed an independent
    implementation reproduces every hash, and nothing had tested the
    claim. A session that never saw the code wrote one from the spec: 34
    of 35 on the first run, the miss an ambiguity in the spec.

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
