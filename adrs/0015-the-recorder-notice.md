# ADR-0015: The recorder notice — report which recorder is running, never update it

**Status:** accepted 2026-08-31

## Context

The harness executes a *path*, not a version. `install-hook` writes an
absolute command into the user's settings:

```
"…/python.exe" "S:/Code/repos/loxodonta/loxodonta.py" hook
```

Nothing about that line pins a commit and nothing copies the file. The
recorder that runs when a tool fires is whatever is checked out at that
path at that moment. Three consequences fall out, and none of them were
visible from anywhere on the machine:

- **It tracks a branch.** The author's own checkout sat on `dev` for
  weeks. Every session on the machine was recorded by `dev`'s recorder
  while `main` and the README described a different one. Nothing said so.
- **It tracks a working tree.** An uncommitted edit, a feature branch, a
  half-finished rebase: the recorder's behaviour changes silently, and
  the file being executed is not the file that was reviewed.
- **Pushing changes nothing locally.** The question that surfaced this
  ("does my local setup get the update when I push?") has the answer
  *no, and it never will* — push sends code away. The checkout only moves
  when someone pulls it.

The obvious fix is to make the recorder update itself: a cron `git pull`,
or a fetch on scan. That is the fix this ADR refuses.

## Decision

**The supervisor reports the recorder's state and corrects none of it.**

`scan` grows a `recorder` block, read from the wired hook command (the
only place that truth lives) and answered from local git only: which
file is executed, which branch, which commit, whether the executed file
is dirty, and how far the checkout sits from its upstream *as of the
last fetch*. The dashboard prints it under the verdict strip, quieter
than the verdict, underlined when it drifts. It never raises the exit
code.

**The notice never reaches the network.** No fetch, no pull, no version
check against a remote. Behind-counts are as stale as the last fetch and
say so in their own wording, because a stale count that reads as
reassurance is worse than no count at all.

## Why not auto-update

ADR-0002 fixes the threat model: the writer of the log is the adversary,
and it is an agent with filesystem access. Auto-updating the recorder
hands that adversary a second road to the one file whose honesty the
entire tool depends on. Today, compromising the recorder means editing a
local file; with auto-pull it also means anything that can influence the
remote or the transport. That converts a local-only trust boundary into
a supply-chain one, on the component least able to afford it.

It also breaks the project's own readability bargain: a recorder you can
read in an afternoon is only meaningful if the copy you read is the copy
that runs. Silent updates make the audited version and the executing
version different objects.

The trade is accepted honestly: drift is now the operator's to resolve,
and the tool's job is to make sure they cannot fail to notice it. That
is the same posture as everywhere else here — detection, not prevention.

## Consequences

- A new `recorder` block in the scan report, and a line on the front
  page. Testimony, like everything else local: it says what the checkout
  looks like, never that the code is trustworthy.
- Reading it costs a `git` invocation. When git is absent, or the
  recorder is not inside a checkout, the state is `unknown` and the scan
  continues — a notice that could fail the scan would teach the operator
  to turn it off.
- Only the executed file's dirtiness counts. An unrelated dirty file in
  the same checkout is not drift in the recorder.
- The staleness of behind-counts is a real limit, accepted rather than
  papered over. A machine that never fetches will never learn it is
  behind, and the notice cannot fix that without becoming the thing this
  ADR refuses. `fetched` is reported so the operator can judge the
  count's age themselves.
- Not an alarm. Drift is a reason to look. Verdicts still come only from
  `verify`, and the exit code is untouched.
