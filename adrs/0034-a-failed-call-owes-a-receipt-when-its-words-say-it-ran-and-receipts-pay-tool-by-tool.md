# ADR-0034: A failed call owes a receipt when its words say it ran, and receipts pay tool by tool (ADR-0016 ruling 1 amended)

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

ADR-0016 ruling 1 said "completed" was load-bearing because the harness
fired no hook for a failed call, and the completeness witness counted
by that boundary. Once failures are wired, a witness that does not move
reads every failure's receipt as surplus, and a witness that moves
naively, owing every failed result, reads every denial as a deficit,
because a denial fires nothing and gets no receipt.

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

| what the failed result says | count | what it is |
|---|---|---|
| opens `Exit code N` | 626 | Bash 279, PowerShell 347: a command that ran |
| wrapped in `<tool_use_error>` | 135 | input rejected before the tool ran |
| the record carries `toolDenialKind` | 74 | a permission denial: 73 in main transcripts, 1 in a subagent file |
| a shell failure with none of those | 66 | all in subagent files, one message from the desktop app's worktree guard: a denial written without the marker |
| any other tool's failure with none of those | 140 | mcp tools 66, Read 52, WebFetch 8, Agent 5, Glob 3, Grep 3, WebSearch 2, Write 1; by their words, tools that started (a file not found, an MCP server's error, a refused fetch, a subagent that died) |

Every permission denial in a main transcript carried `toolDenialKind`;
in subagent files one of 67 did. No field in the transcript separates a
non-shell tool that started and failed from a call a `PreToolUse` hook
blocked: both are an error string on a flagged block.

Two reviews shaped the rule. The first cut paired two totals and let a
failure that might have fired loosen the surplus check, so a receipt the
witness could not owe paid for a receipt another call lost. The writer
is the adversary (ADR-0002), and the move is cheap: starve one command's
hook (hold the chain lock past its timeout), run the command, then make
a fetch fail against a server it controls; the failed-call event writes
the fetch's receipt, and the session reads clean. Pairing tool by tool
closed that across tools and left it open inside one: a starved fetch
beside a failed fetch that fired read `OK`, exit 0, where dev reads
`ALARM-SILENT`, exit 6. That is every non-shell tool whose failures fire
the event, with the same attack kept inside one tool.

## Decision

1. **A failed call reads one of three ways, under the coverage in force
   at its time.**
   - **Owes nothing** where that epoch wired no failed-call event for its
     tool (no `failures` in the epoch, or a matcher that misses it),
     because nothing could have fired, so a failed call under an install
     from before #239 is judged as before. Owes nothing where the
     transcript says it never ran: a result wrapped in `<tool_use_error>`,
     or a record carrying `toolDenialKind`. Owes nothing where a Bash or
     PowerShell failure lacks the `Exit code N` line: the command did not
     run, because it was denied or blocked, or, rarely, the shell never
     started. A cancelled call leaves no result and was never counted.
   - **Owed** where the result opens `Exit code N`: a command that ran.
     The check is on the words, not the tool's name.
   - **`may_owe`**, any other tool's failure: one that started and
     failed fired the event, one that was blocked or denied without its
     marker fired nothing, and the transcript words them alike.
2. **Receipts pay tool by tool, and `may_owe` calls are paid first.** For
   each tool, count its owed calls, its `may_owe` calls and its receipts,
   a receipt's tool being the one its action line names. Receipts go
   first to the tool's `may_owe` calls, and only what is left pays its
   owed calls, earliest first: the deficit is the sum over tools of owed
   minus (receipts minus `may_owe`, not below zero), where positive, and
   the surplus is the sum of receipts minus `may_owe` minus owed, where
   positive. A receipt that may be the one a failed call left can then
   never cover the one an owed call lost, in its own tool or in another.
   The deficit clock keys on the first owed call still unpaid. What this
   costs is a false deficit when a `may_owe` call did not in fact fire,
   in a session with owed calls of the same tool, and the ruling takes
   it: an alarm on a blocked call over a mask on a starved one, the
   choice ADR-0029 ruling 5 made, because a harness that fired no hook
   and a hook an attacker killed leave the same evidence.
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
   in one tool never stands a missing receipt in another down. The
   deficit words say what is true when the totals match and one tool is
   short: a call the witness saw has no receipt of its tool.
5. **The epoch carries the event.** The calibration observes
   `PostToolUseFailure` beside `PostToolUse`, and the coverage marker
   writes its matchers as `failures`, only when it was wired (ADR-0016,
   ADR-0030). The witness reads it per call time, as it reads matchers.
6. **The wording has a canary.** The owed class leans on one line of the
   harness's words. When failed shell calls under the event carried no
   `Exit code N` line and not one failure in the scan read as owed, the
   calibration words say so in one sentence. Context, never an alarm,
   because an unmarked denial reads the same way.
7. **Held: the hook's own record.** The transcript records each hook run
   as an attachment keyed by the tool call's id (`hook_success`,
   `hook_non_blocking_error`; #239's measurement used them, and #212
   asks what they say). With those, a later witness could tell a failed
   call that fired from one that did not, and `may_owe` would shrink to
   nothing. That reads the harness's bookkeeping, which the witness does
   not read today, and whether it should is #212's to rule, so it is
   held for that ruling rather than taken here.

## What none of this survives

- **A line written by hand.** The pooled reading (ruling 3) lets a line
  naming a tool the session never used pay any deficit, and a line
  naming the starved tool pays that tool's deficit in any ruling that
  counts receipts. That was so before #239. A writer that runs
  `loxodonta log` leaves that call in its own receipts, and the chain
  says who wrote each line only in the writer's own words.
- **A shell that failed to start.** Rarely, the harness fires the event
  for a Bash call that never ran its command, with no `Exit code N`
  line. That call owes nothing (ruling 1), and the receipt it left is
  read as its tool's, where it can cover a lost receipt of another
  command.
- **A writer that shapes both the transcript and the chain.** The
  witness compares two writer-reachable files; a writer that rewrites
  both is beyond this alarm, as ADR-0002 says of every completeness
  reading.

## Consequences

**What gets easier:**

- A command that ran and failed leaves a receipt, is owed one, and a
  starved hook on it is a deficit like any other.
- A receipt a failed call left can never cover one a starved call lost,
  in its own tool or another: the tests
  `test_a_may_owe_receipt_never_pays_another_calls_deficit` and
  `test_a_may_owe_receipt_never_pays_its_own_tools_deficit` read
  `ALARM-DEFICIT`, exit 6, with the action lines the hook writes.
- A failed call under an install that never wired the event is judged
  as before (`test_an_install_from_before_the_event_is_judged_as_before`
  reads `ENDED-SURPLUS`, as dev does). Tool-by-tool pairing itself
  applies to every install.
- Measured over copies of the author's store against the real
  transcripts: 95 rows, of which 92 are ended sessions, 1 is the live
  session the measuring ran in, and 2 are unwitnessed. Tool-by-tool
  pairing left every state as the totals had it; one ended session,
  already `ENDED-DEFICIT`, counts 8 missing where the totals counted 7,
  a surplus receipt of one tool having covered a loss in another. With
  ruling 2's order and ruling 1's shell rule added, no state changed
  either, since no epoch there wires the event yet.

**What gets harder or more constrained:**

- **The false deficit ruling 2 accepts.** Measured by simulation on
  copies of the same store (every epoch wired, every `Exit code N`
  failure given its receipt, no other failure given one, so every
  `may_owe` call counted as one that never fired, the worst case): 6 of
  the 92 ended sessions turn from `ENDED-CLEAN` to `ENDED-DEFICIT`, and
  one already short grows by one. Each is an unmarked non-shell failure
  beside completed calls of its tool: Read in three sessions, Grep in
  two, a browser MCP tool, a fetch, a subagent. Their words say they
  started, so wired they would have fired and paid their own slot; the
  simulation is the bound, not the forecast. The live session's state
  is the same under both rules.
- **Under-owing where the words cannot tell.** A non-shell tool that
  started and failed, and whose own hook was starved, is `may_owe`, so
  its absence is no deficit: 140 of the 1,041 failures here. Owing them
  instead would raise a live alarm for every non-shell call a
  `PreToolUse` hook blocks, and a siren that sounds for honest sessions
  trains the operator to ignore it (ADR-0014).
- **One wording carries the owed class.** `Exit code N` is documented
  for the event's `error` and only "generally the same text" in the
  transcript. If the harness rewords it, owed failures owe nothing
  without a sound; the canary is what says so.
- **`toolDenialKind` is not documented.** It only moves a call from
  `may_owe` to owing nothing. If the harness stops writing it, a
  non-shell denial becomes `may_owe`, and ruling 2 can then read it as a
  false deficit in a session that used that tool.
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

- #212 rules that the witness may read the hook's attachments (ruling
  7): `may_owe`, and the false deficit ruling 2 accepts, can then go.
- The harness marks a blocked or denied call in the transcript for every
  tool, in both files.
- The canary speaks on a store where failures are known to have run:
  the harness has reworded `Exit code N`.

## Alternatives considered

- **Owe every failed call.** One rule and no `may_owe` at all. Rejected:
  every denial and every blocked call becomes a deficit, live ones
  alarms.
- **Owe no failed call** (#239's option 2). Rejected by the ruling: the
  failure receipts then read as surplus in every session that fails a
  command, and a stripped failure hook is invisible.
- **Totals with a `may_owe` allowance** (the first cut). Rejected in
  review: a receipt nothing owed pays for one that was lost, across
  tools.
- **Tool by tool, owed calls paid first** (the second cut). Rejected in
  review: inside one tool, the receipt a failed fetch left pays for the
  one a starved fetch lost.
- **Read the hook's attachments now.** Held, not rejected (ruling 7).
- **Owe unmarked non-shell failures in main transcripts**, where
  permission denials are marked. Rejected: a `PreToolUse` hook's block is
  unmarked everywhere, and operators who run blocking hooks are the ones
  most likely to run this tool.

## References

- Related ADRs: `0002-writer-as-adversary.md` (the writer as adversary,
  and the limit named above), `0014-the-day-book.md` (a siren nobody
  trusts), `0016-coverage-goes-wide.md` (ruling 1 amended: a failed call
  is covered where the event is wired; effective dating reused),
  `0020-recorder-adapters-speak-the-hook-contract.md` (Codex, no second
  event needed), `0021-field-data-export-is-allowlisted-and-sent-through-gh.md`
  (the allowlist left as is), `0027-the-dashboard-counts-what-the-chain-holds.md`
  (the receipt records the attempt), `0029-sessions-older-than-the-supervisors-memory-are-not-judged.md`
  (ruling 5's choice, taken again in ruling 2),
  `0030-the-recorder-writes-down-what-coverage-it-wired.md` (the marker
  carries `failures`).
- Out of scope, upheld: `.out-of-scope/001-outcome-capture-in-hook.md`.
- Glossary terms **sharpened**: *Coverage*, *Coverage marker*.
- Raised: issue #239 (the gap, and the ruling to wire the event); the
  spec and standards reviews of its first two cuts, 2026-09-18 and
  2026-09-19; #212 holds ruling 7.
