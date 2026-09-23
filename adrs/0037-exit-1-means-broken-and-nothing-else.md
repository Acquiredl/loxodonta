# ADR-0037: Exit 1 means BROKEN and nothing else; every other failure takes a sysexits(3) code

**Status:** accepted 2026-09-23 (ruled on #299)
**Deciders:** Acquiredl

## Context

`verify` answers in exit codes as well as words: 0 `VALID`, 1
`BROKEN`, 2 files diverged, 3 head mismatch, 4 a format it does not
speak, 5 transcript diverged, and 64 a usage error (ADR-0026 ruling 7
gave usage its own number). A script, a CI step or the supervisor reads
the number first. Until now 1 said many things besides `BROKEN`:

- the log was not there, or was empty (`verify`, `head`, every writer);
- the lock was held past its timeout (`log`, `run`, `hook`);
- the tool crashed, since Python's own exit on an uncaught exception
  is 1;
- the reader hung up on the pipe (`verify | head`), which `run_main`
  turned into a quiet 1 on purpose, its comment saying 1 was "the only
  one left" and telling scripts to trust the verdict line and never the
  exit code alone;
- on the writers, a calendar or a remote that did not answer, an
  existing log under `init`, a hook payload that was not one.

So a `1` from `verify` meant "this chain may have been tampered with,
or the path was wrong, or the tool fell over", and the supervisor's
scan counted an empty chain file as exit 1 beside the broken ones. The
recipient is ruled first (docs/DIRECTION.md), and a recipient's script
that sees 1 must be able to say "the evidence was altered" without
reading English.

sysexits(3) is the BSD list of exit codes for exactly these failures,
and 64 is already its `EX_USAGE`.

## Decision

> **Exit 1 is `BROKEN` and nothing else: on the verbs that judge, the
> chain does not walk clean; on a writer, the chain's tail is damaged
> and it will not build on it, which is the same fact found at the
> tail. Every other failure takes its number from sysexits(3). The
> reader hanging up exits 141, quietly. 64 stays the usage error.**

The numbers, and what each says:

| exit | name | says |
|---|---|---|
| 1 | | `BROKEN`: a chain that does not walk clean, or a writer refusing a damaged tail |
| 64 | `EX_USAGE` | the command was spoken wrong |
| 65 | `EX_DATAERR` | an input is not what it must be: a hook payload, a settings file |
| 66 | `EX_NOINPUT` | no input to read: a log missing, empty, or not readable as a file; a `--file` or manifest that cannot be read |
| 69 | `EX_UNAVAILABLE` | a service did not do what was asked: a calendar, a publish URL, a timestamp authority, the narrating command |
| 70 | `EX_SOFTWARE` | the tool itself failed; Python's traceback is on stderr |
| 73 | `EX_CANTCREAT` | a file the verb must create cannot be: a log that already exists, a lock file, a token the authority granted |
| 75 | `EX_TEMPFAIL` | another writer holds the lock; try again |
| 141 | | the reader hung up (128 + SIGPIPE) |

Verb by verb, what moved off 1:

- **`verify`**: a log missing, empty or unreadable as a file, 66. A
  line that cannot be read stays `BROKEN`, since that is the walk's
  verdict on a line and not a failure to open the file.
- **`head`**: missing, empty or unreadable, 66. A damaged tail stays 1.
- **`verify-package`**: a path that is not there, 66.
  Inside a package, a chain file that is empty is a finding, not a
  missing input, since the manifest lists a chain there: it stays
  `CHAIN-BROKEN`, exit 1, as it was.
- **`init`**: a log that already exists, or a path it cannot create, 73.
- **`log`**: an empty `--actor` or `--action`, 64; a `--file` spelled
  absolute or with `..`, 64; a `--file` or project record that cannot be
  read, 66; a log missing, empty or unreadable, 66; the lock held past
  the timeout, 75, or a lock file the directory refuses, 73.
- **`run`**: a missing log, 66, before the command runs, as before.
  When the receipt cannot be written after the command ran, the exit is
  the reason the receipt was lost (66, 75, 73, 64, or 1 for a damaged
  tail) instead of 1. The receipt's record of the command's own exit
  status, and `run`'s exit with the command's code, 130 on Ctrl-C and
  128+S on another signal, are untouched.
- **`hook`**: a payload that is not JSON, or has no session or tool,
  65; the lock, 75 or 73. Claude Code reads exit 2 from a hook as
  "block", and every other non-zero code as a non-blocking error shown
  to the operator; no path here gives 2, so the hook contract
  (docs/HOOK.md) holds. Every session-end step still fails silently.
- **`anchor`**: no calendar accepted the digest, or an upgrade a
  calendar did not complete, 69; no anchors to upgrade, 66; a log or
  manifest that cannot be read, 66.
- **`publish`**, with or without `--chain`: the remote did not take it,
  69; an empty or unreadable log, 66.
- **`stamp`**: the authority refused, did not answer, or answered
  something else, 69; a granted token that could not be written, 73; an
  empty or unreadable log or manifest, 66.
- **`report`**, **`explain`**: an empty or unreadable log, 66;
  `explain` with an empty `--llm`, 64, and a narrating command that is
  missing or fails, 69.
- **`install-hook`**, **`uninstall-hook`**: a settings file that is not
  JSON, or not of a shape they can read, 65; `--codex
  --anchor-at-session-end`, refused as a command spoken wrong, 64.

Two endings belong to `run_main`, the entry point both files share:

- **An internal error exits 70.** An exception nobody caught prints
  Python's traceback to stderr, unchanged, and exits 70, so a crash is
  never read as a verdict. `SystemExit` (argparse's 64, `--version`'s
  0) passes through as it always did, and so does Ctrl-C, which Python
  ends as an interrupt; `run` catches its own Ctrl-C and exits 130, and
  that is unchanged.
- **The reader hanging up exits 141, quietly.** 141 is 128 + SIGPIPE,
  what a shell reports for a writer its pipe's reader left, and what
  `set -o pipefail` already treats as a failure. 0 was the other
  candidate and is wrong here: `verify | head -1` can hang up with a
  `BROKEN` line among the unread ones, and 0 is `VALID`. 1 is `BROKEN`.
  On Windows, where the closed handle is reported as EINVAL and there is
  no SIGPIPE, the number is the same.

The supervisor reads the recorder's codes, and follows:

- **`scan`** keeps its ladder (0, 1 to 4 the worst verify exit, 5, 6,
  7). A chain verify could not judge at all, 66 or 70 or anything else
  outside 0 to 5, counts as 4, the refused rung beside
  `UNSUPPORTED-VERSION`, which is where the dashboard already drew a
  chain with no verdict. It still raises the exit, and it is no longer
  counted as 1.
- **`supervisor verify ADDRESS`** returns the recorder's exit verbatim,
  so its 1 is `BROKEN` too; an address it cannot resolve said 1 and now
  says 64 when it is spelled wrong and 66 when it names no one chain.
  The MCP `verify` tool reports only whether the exit was non-zero, and
  is unchanged.
- The keepers and `package` read only zero against non-zero, and are
  unchanged.

**Scope.** The recorder's verbs, `verifier.py`'s three, and the
supervisor's readings of them. The supervisor's own exits (`scan`'s
ladder, `drill`, `package`, the recall commands), the receiver, and the
repo's tools in `tools/` keep their contracts; each is its own program
with its own readers.

## Consequences

**What gets easier:**

- A script can act on the number: 1 is a broken chain, 66 a wrong
  path, 75 a retry, 70 a bug to report, and nothing else is confused
  with `BROKEN`. docs/PACKAGE.md's "read the verdict line, not the
  code alone" becomes advice rather than a warning.
- The scan's exit 1 means a broken chain, and an empty chain file in the
  store stops reading as one.

**What gets harder or more constrained:**

- A script that tested `$? -eq 1` for "something went wrong" now misses
  the operational failures. Before 1.0, and the CHANGELOG says so under
  *Changed*.
- More numbers to document, and each verb's list in this ADR has to be
  kept true as verbs change.
- 70 has no test through the command line. No honest input makes the
  recorder fail, and the suite does not add a hook that exists only to
  make it crash; the code that gives 70 is short and read, not run.

**What we'll have to revisit if:**

- A harness gives a hook's exit code a meaning past 0 and 2. The hook's
  numbers would then have to be chosen against that harness's contract.

## Alternatives considered

- **Keep 1 for everything that is not a verdict, as Python does.**
  Rejected: that is the ambiguity the ruling removes.
- **One number, say 70, for every operational failure.** Rejected: a
  missing path, a held lock and a crash want three different responses
  from a script (fix the path, retry, report a bug), and sysexits
  already names them.
- **EPIPE exits 0.** Rejected: 0 is `VALID`, and the lines the reader
  never read may include a `BROKEN` one.

## References

- sysexits(3), FreeBSD manual: `EX_USAGE` 64, `EX_DATAERR` 65,
  `EX_NOINPUT` 66, `EX_UNAVAILABLE` 69, `EX_SOFTWARE` 70,
  `EX_CANTCREAT` 73, `EX_TEMPFAIL` 75.
- SPEC section 6 (the verdicts and their exits, as amended).
- Related ADRs: `0026-the-store-ships-as-a-package-verified-by-one-file.md`
  (ruling 7: usage errors exit 64, and the package verdicts map onto
  verify's exits); `0004-serialize-hook-appends.md` (the lock);
  `0036-the-hashing-is-frozen-across-format-versions.md`, ruled the
  same day.
- docs/HOOK.md (what a harness does with a hook's exit).
- Discussion: the rulings on #299, 2026-09-23, item 2.
