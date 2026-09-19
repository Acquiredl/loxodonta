# ADR-0034: A failed call owes a receipt when its words say it ran, and receipts pay tool by tool

**Status:** proposed 2026-09-18, a draft for the author's review (#239)
**Deciders:** Acquiredl

## Context

Claude Code fires `PostToolUse` only for a tool call that completed. A
call that started and failed fires `PostToolUseFailure`, which
`install-hook` never wired, so on the author's machine about one covered
call in thirty, the failing ones, left no receipt (#239). The ruling was
to wire it, and `install-hook` now does, beside `PostToolUse`, with the
same command on the same matcher. The receipt is the same receipt: the
action attempted, never its outcome (`.out-of-scope/001`, ADR-0027).

The completeness witness (ADR-0016) counted only completed calls, because
until then a failed call fired nothing. Once failures are wired, a
witness that does not move reads every failure's receipt as surplus, and
a witness that moves naively, owing every failed result, reads every
denial as a deficit, because a denial fires nothing and gets no receipt.

The harness's hooks page draws the line. The failed-call event fires for
a tool that started executing and failed: the tool threw, or an MCP tool
returned an error. It does not fire for an unknown tool, for input that
fails validation (returned as `tool_use_error`, before any hook runs,
firing neither `PreToolUse` nor the failed-call event), for a permission
denial (which fires `PreToolUse` only), for a call a `PreToolUse` hook
blocked, or for a running tool that is cancelled. For Bash and
PowerShell, the event's `error` opens with `Exit code N` when the
command ran and exited, and the page calls that string "generally the
same text" the model receives, which is what the transcript records.

The transcript sets the same `is_error` flag on every one of those, and
only their words tell them apart. Surveyed on the author's machine
(Claude Code 2.1.2xx, some 39,000 results, 1,041 of them failed, main
transcripts and subagent files both):

| what the failed result says | count | tools |
|---|---|---|
| opens `Exit code N` | 626 | Bash 279, PowerShell 347, nothing else |
| wrapped in `<tool_use_error>` | 135 | Edit, Write, Grep, Bash and a dozen more |
| the record carries `toolDenialKind` | 74 | 73 in main transcripts, 1 in a subagent file |
| none of those | 206 | 66 sidechain Bash denials from the desktop app's worktree guard, written without the marker; 140 non-shell errors from tools that started (a file not found, an MCP server's error, a refused fetch, a subagent that died) |

Every permission denial in a main transcript carried `toolDenialKind`;
in subagent files one of 67 did. No field in the transcript separates a
non-shell tool that started and failed from a call a `PreToolUse` hook
blocked: both are an error string on a flagged block.

The first cut of this change counted those last failures as `may_owe`
and let them loosen the surplus check. Review found the blocker: the
witness paired two totals, so a receipt it could not owe paid for a
receipt another call lost. The writer is the adversary (ADR-0002), and
the move is cheap: starve one command's hook (hold the chain lock past
its timeout), run the command, then make a fetch fail against a server
it controls. The failed-call event writes the fetch's receipt, owed
equals receipts, and the session reads clean. Totals had carried that
weakness for any receipt nothing owed; wiring failures would have handed
the writer a steady supply of them.

## Decision

1. **A failed call reads one of three ways, under the coverage in force
   at its time.**
   - **Owes nothing** where that epoch wired no failed-call event for its
     tool (no `failures` in the epoch, or a matcher that misses it),
     because nothing could have fired, so an install from before #239 is
     judged as before. Also owes nothing where the transcript says it
     never ran: a result wrapped in `<tool_use_error>`, or a record
     carrying `toolDenialKind`. A cancelled call leaves no result and was
     never counted.
   - **Owed** where the result opens `Exit code N`: a command that ran.
     The check is on the words, not the tool's name.
   - **`may_owe`**, every other failure: a tool that started and failed
     fired the event, a call that was blocked or denied without its
     marker fired nothing, and the transcript words them alike.
2. **Receipts pay tool by tool.** For each tool, count its owed calls,
   its `may_owe` calls and its receipts, a receipt's tool being the one
   its action line names. The deficit is the sum over tools of owed
   minus receipts where positive; the surplus is the sum of receipts
   minus owed minus `may_owe` where positive. A `may_owe` call excuses one
   receipt of its own tool from surplus and pays for nothing else. The
   deficit clock keys on the first owed call still unpaid, receipts
   paying each tool's calls earliest first.
3. **A receipt whose line names no tool the transcript shows keeps the
   pooled reading.** A line written by hand with `loxodonta log`, a
   `run` line, another writer's line: it pays the earliest unpaid call
   of any tool, and is surplus only when none is left. That is how every
   chain holding such lines was judged before, the suite's own included.
   A witnessed call whose tool the transcript cannot name, one result in
   39,000 on this machine, is paid only by those lines.
4. **The deficit wins.** The ratified machine (issue #22) could never
   see a deficit and a surplus at once, because it compared two totals.
   Tool by tool it can, and then the state is the deficit's: a surplus
   in one tool never stands a missing receipt in another down.
5. **The epoch carries the event.** The calibration observes
   `PostToolUseFailure` beside `PostToolUse`, and the coverage marker
   writes its matchers as `failures`, only when it was wired (ADR-0016,
   ADR-0030). The witness reads it per call time, as it reads matchers.
6. **The wording has a canary.** The rule leans on one line of the
   harness's words. When failed shell calls under the event were left
   `may_owe` and not one failure in the scan read as owed, the calibration
   words say so in one sentence. Context, never an alarm, because an
   unmarked denial reads the same way.

## Consequences

**What gets easier:**

- A command that ran and failed leaves a receipt, is owed one, and a
  starved hook on it is a deficit like any other.
- The receipt a failed fetch left can never cover the one a starved
  command lost: the reviewers' probe reads `ALARM-DEFICIT`, exit 6,
  where the first cut read `OK`, exit 0.
- An install that never wired the event is judged exactly as before:
  the reviewers' second probe reads `ENDED-SURPLUS` on dev and here.
- Judged over a copy of the author's store, tool-by-tool pairing read 94
  of 95 judged sessions exactly as the totals did. The 95th was already
  `ENDED-DEFICIT` and now counts 8 missing where the totals counted 7: a
  surplus receipt of one tool had been covering a loss in another.

**What gets harder or more constrained:**

- **Under-owing, chosen over false alarms.** A non-shell tool that
  started and failed, and whose hook was starved, is not caught: it may
  owe, so its absence is no deficit. That is 140 of the 1,041 failures
  here. Owing them instead would raise a live alarm for every call a
  `PreToolUse` hook blocks and every unmarked denial in a subagent (66
  here), and a siren that sounds for honest sessions trains the
  operator to ignore it (ADR-0014).
- **One wording carries the owed class.** `Exit code N` is documented
  for the event's `error` and only "generally the same text" in the
  transcript. If the harness rewords it, owed failures turn `may_owe`
  without a sound; the canary is what says so.
- **`toolDenialKind` is not documented.** It only moves a call from
  `may_owe` to owing nothing. If the harness stops writing it, a denial
  becomes `may_owe`, which never alarms.
- **The pool keeps its old weakness.** A hand-written line naming a tool
  the session never used still pays any deficit, as it could before; a
  writer that runs `loxodonta log` leaves that call in its own receipts,
  and a writer shaping both the transcript and the chain is beyond this
  alarm (ADR-0002).
- **A session that spans the re-install.** The calibration dates the
  change by the settings file's mtime, clamped between the last
  observation and now (ADR-0016). The harness normally picks up a hook
  edit in a running session (its hooks page: the file watcher), so
  failures after the install fire the event and are owed from then. If
  the settings file is edited again before the supervisor's next look,
  the epoch is dated late: a failed command in between owes nothing and
  its receipt reads as its tool's surplus, a flag and never an alarm. A
  harness that did not pick the edit up would leave failed commands
  after the install owed and missing in that session, the edge a matcher
  change already has.
- The completeness row gains `may_owe`, and a package's `witness.json`
  carries it. The field-data export's allowlist does not (ADR-0021);
  that is deferred to the author.
- Codex is untouched. It has no failed-call event, its `PostToolUse`
  already fires after a Bash command that exits non-zero, and it has no
  witness (ADR-0020).

**What we'll have to revisit if:**

- The harness marks a blocked or denied call in the transcript for every
  tool, in both files. Then `may_owe` can shrink to nothing.
- The canary speaks on a store where failures are known to have run:
  the harness has reworded `Exit code N`.

## Alternatives considered

- **Owe every failed call.** One rule and no `may_owe` at all. Rejected:
  every denial and every blocked call becomes a deficit, live ones
  alarms.
- **Owe no failed call** (#239's option 2). Rejected by the ruling: the
  failure receipts then read as surplus in every session that fails a
  command, and a stripped failure hook is invisible.
- **Totals with a `may_owe` allowance** (this change's first cut).
  Rejected in review: a receipt nothing owed pays for one that was lost.
- **Read the hook attachments the transcript carries** (`hook_success`
  keyed by tool-use id). Rejected: circular. A stripped hook leaves no
  attachment, so the witness would owe nothing exactly when it should
  shout.
- **Owe unmarked non-shell failures in main transcripts**, where
  permission denials are marked. Rejected: a `PreToolUse` hook's block is
  unmarked everywhere, and operators who run blocking hooks are the ones
  most likely to run this tool.

## References

- Issue #239 (the gap and the ruling); ADR-0002 (the writer as
  adversary); ADR-0014 (a siren nobody trusts); ADR-0016 (coverage and
  effective dating, amended here); ADR-0020 (Codex, amended here);
  ADR-0021 (the export allowlist); ADR-0027 and `.out-of-scope/001` (the
  receipt records the attempt); ADR-0029 (before memory); ADR-0030 (the
  coverage marker)
- `docs/HOOK.md`, the harness's hooks page (`PostToolUseFailure`), and
  the reviewers' probes of the first cut
