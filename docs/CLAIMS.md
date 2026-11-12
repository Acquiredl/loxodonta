# What loxodonta promises, and what it depends on

This page is for someone who wants to rely on a loxodonta record, or build a tool on top of one. It says what the record promises, the setup those promises depend on, and where they stop.

## Three questions a record can be asked

| Question | Answered by | The short answer |
|---|---|---|
| Was the record changed after it was written? | The chain, checked against a copy of its head kept off the machine | Promised, under the vantage setup below |
| Is anything missing from it? | The reading at the [receiver](GLOSSARY.md#receiver), counting against the harness's own events, under the vantage setup | Not promised yet. On the agent's machine the [witness](GLOSSARY.md#witness) catches faults; see what each adds, below |
| Is what was written true? | Nothing | Never promised. A receipt is what the hook was handed |

## The two promises

1. **A change shows.** An edit, a deletion or a reorder of any entry covered by a commitment held off the machine makes `verify` say so and name the entry. (SPEC sections 5, 6 and 8.1.)
2. **A date holds.** A chain with that head existed by the time of the commitment. (ANCHORING.md.)

## What the witness adds

It is not a promise, and on one machine it is not a defence against the writer: every file it reads is in the account the writer runs as (ADR-0046). A Claude Code session that ran tool calls owing a receipt and wrote fewer is reported by the supervisor. That catches faults: a hook that stopped firing, a wedged lock, a silent fork. It does not hold against a writer who can edit or delete the transcript: the second record it counts against is on the same machine, and a session whose transcript is garbled, emptied or gone reads as quiet or is not seen at all (#473). Its other limits are under *Where the promises stop*. (GLOSSARY, *Second record*; GROUNDING section 3.)

At the receiver the same count runs against the harness's own events. At `full`, a managed install pins those events to the receiver, and `supervisor scan --receiver DIR`, run on the receiver's machine, counts each session's receipts against them tool by tool, or call by call where both name the call, once nothing of the session has arrived for the settle window, one hour. It names a session short of receipts, one whose events never arrived, and one whose events' counter has holes, and each raises the scan's exit until someone with access to the receiver accepts it there, and again if its counts change after. One whose events never arrived is judged only once it has settled, so receipts that keep arriving keep it unjudged (RECEIVER.md section 7, ADR-0046). The agent cannot delete those events once they land. It holds the URL, though, so it can add events, and the reading cannot tell an event it posted from one the harness sent. And where calls are paired by their id, a receipt pays the call its id names whatever tool the receipt says it was: a receipt that names one tool and carries the id of another tool's call reads as that call's receipt.

That count is where the promise that a call without a receipt shows will rest, and it is not a promise yet: ADR-0041 names it for a session the receiver heard from, and it waits on a run end to end on two machines.

## The vantage setup

A vantage point is a place with a clear view that the watched party cannot get to. The vantage setup is a machine where these four conditions hold. The two promises are made for records written under it.

| # | Condition | How it is set | Standing |
|---|---|---|---|
| 1 | The hook cannot be switched off by the agent, nor the recorder or the interpreter it runs changed, nor what it is told set by a variable or by your own settings file, as far as the installer can see | `install-hook --managed`, run by an administrator with a Python installed for all users | ADR-0040 and ADR-0042. The switch measured on 2026-10-05 against a run with hooks switched off on its command line, and against a run under `--bare` (Claude Code 2.1.287, Windows; #259). The copy of the recorder not yet measured; the installer checks the interpreter's path and not each file of its library, and on Windows judges a path by its place, not its access list. What the hook is told (ADR-0043) not yet measured |
| 2 | The agent holds no administrator rights | The operator's own job. It is about the account the agent runs as, never about the harness's permission mode | Outside the tool |
| 3 | A copy leaves the machine | The `full` [profile](GLOSSARY.md#profile) with a [receiver](GLOSSARY.md#receiver) the writer cannot reach; `timestamped` gives the second promise only | Built |
| 4 | Somebody reads it | `supervisor serve` on its cadence, and a check of the chain against the copy off the machine; on the receiver's machine, `supervisor scan --receiver DIR` | Built |

**Checking condition 1.**

1. Run `install-hook --managed` again, with the profile you chose and no administrator rights: it answers "already installed in", names the managed file, and changes nothing.
2. In the harness, `/status` lists `Enterprise managed settings (drop-ins)` on its `Setting sources` line. On a machine whose organization delivers settings another way, the file may not be the one in use, and that line says which source is.
3. The proof: start a session with `{"disableAllHooks": true}` passed through `--settings`, run one tool call, and see that its drawer and its receipt are written.

**Condition 2 has no check on this page.** An elevated shell, or `sudo` that asks for no password, breaks it. The supervisor runs as the same account as the agent, so it is the one placed to say when that account can rewrite the managed file (#469).

**The pin on the harness's events is not a condition.** A managed install at `full` writes it as a second managed file of its own (ADR-0041). It holds against the settings files and the command line, and not against the environment a run is launched with. On Claude Code 2.1.294 the hook sees a run launched with its telemetry off and notes it in the chain; a run launched with its events sent elsewhere leaves no note, and reads at the receiver as one whose events never arrived (HOOK.md).

## Running less than the vantage setup

The full setup is what the two promises are made for, and it is the one to run when the record has to hold against the agent that writes it. Every condition can be left out. Each one left out opens something, and this is what.

| Left out | What it opens |
|---|---|
| 1, the managed install | One flag on a run's command line, or an edit to your own settings file, stops the record. The witness reports the silence only while the transcript survives, and a hook taken out of your settings file reads to it as coverage ended, a note and not an alarm. And the recorder and its interpreter sit at paths the operator owns: the hook fires after the call it records, so a session that edits either writes that edit's receipt with the edited code, and the chain stays `VALID`; what is then left is the count at the receiver, never the content of the receipts |
| 2, an agent without administrator rights | The managed file is as easy to rewrite as any other, and condition 1 is worth nothing |
| 3, a copy off the machine | At `local`, a chain regenerated whole or a store wiped does not show. At `timestamped`, a regeneration shows once the anchor matures, if a copy of its proof was kept off the machine, since nothing sends it there (#524); and a wiped store is gone |
| 4, somebody reading it | Nothing is detected until someone looks |

The full setup does not make the record complete. Whether anything is missing is the reading at the receiver's question, and the witness on the agent's machine catches faults; the limits of both are above.

## What each profile adds

| What happened to the chain | `local` | `timestamped` | `full` |
|---|---|---|---|
| One entry edited, deleted or moved | shows | shows | shows |
| Regenerated whole | only against a head you kept by hand | shows once the anchor matures, if its proof was kept off the machine | shows at once, at the remote |
| The store wiped | gone | gone, and a copy of the anchor's proof kept off the machine says a chain existed | survives at the remote as of the last send |
| The tail since the last send rewritten | does not show | does not show | does not show: the rewritten tail reaches the remote as the only version |

At `full` the hook sends each entry as it is written, so with the receiver reachable that tail is about a second long; a send that failed, or that the writer stopped by the network or the process, leaves its entries in the tail until the next call, the session end or the keeper sends them (ADR-0045). (GLOSSARY, *Profile*; TOPOLOGY.md; HOOK.md.)

## Where the promises stop

Stated here once, so that none of them is a discovery.

**Limits of the design** (SPEC section 8.1, each with its source in GROUNDING section 2):

- Entries after the last commitment held off the machine can be rewritten.
- A cut tail shows only against a published head made after it.
- The receipt is written after the call it records, and prevents nothing.
- No verdict says who wrote an entry.
- The chain alone never shows that everything was logged.
- Entries written after a compromise are chained as faithfully as honest ones.
- A chain regenerated past the last commitment verifies clean.

**Limits of the setup:**

- A writer with administrator rights rewrites the managed file like any other (ADR-0040).
- The harness's own program sits where its installer put it, under the operator's account on a per-user install. A harness changed there fires no hook, managed or not; what shows it is the count at the receiver, where events stop arriving or arrive for calls that left no receipt (ADR-0042).
- On a machine whose organization delivers settings from a server or through device management, the managed file may be skipped without a warning (ADR-0040).
- That a managed hook runs under `--bare` is measured on one version of the harness and not stated in its documentation, so a later version may differ (#259).
- A managed hook finds the home folder through the environment, as the harness does, so a changed home moves the store with everything else the account owns. It sends through no proxy, so where the network requires one, its publishes, stamps and anchors do not leave (ADR-0043).

**Limits of the witness on the agent's machine:**

- What a session owed is read from the harness's settings files and the coverage marker, files on the agent's machine, and a change of coverage is dated by the settings file's modification time (ADR-0016, ADR-0030).
- A session is counted against the transcript file named for its session id; whatever file holds that name is the second record it reads.
- Receipts are paired with calls by count within each tool, not call by call: a receipt for a call the transcript does not show covers a lost call of the same tool, and a hand-written entry naming no tool the transcript shows covers a lost call of any tool (ADR-0034).

**Limits of what the supervisor remembers:**

- The baseline, the day book and the coverage marker are files on the agent's machine. A baseline deleted alone is an alarm. The baseline and the day book deleted together read as a new install, and a session the scan had already reported as silent is then never judged again (ADR-0039, ADR-0029).
- An edit in place to the baseline or the day book is not detected either, and `acknowledge`, which stands an alarm down, can be run by the account the agent runs as.
- What holds against the writer is what is kept off the machine: the anchor, the published head and the published chain. Nothing the supervisor on the agent's machine remembers about sessions is kept there, so a machine that keeps its only memory beside the agent is at risk of losing it to the agent. The reading at the receiver keeps its own memory, and the acknowledgements that stand its findings down, on the receiver's machine (ADR-0046).

**Limits of what a receipt holds:**

- An action line holds the tool's name and one field of its input: the first that is a string and not empty, from a fixed list (a file path, a notebook's path, a command, a path, a pattern, a URL, a query, a prompt, a summary). Of that field it holds at most the first 160 characters, with runs of whitespace collapsed to one space. What came after is not in the record; a cut line ends with the count of characters dropped, and holds nothing more of them than a hash of the whole input (#470). A call whose input holds none of those fields is recorded by its tool's name and that hash alone. The input's other fields are not recorded; the hash commits to them, so a copy of the input reproduces it or does not, and holds none of their text (ADR-0047).
- No receipt exists for what is not a tool call: configuration that runs when the harness starts, what happens inside an MCP server, a call the harness denied.
- A listing shows an action line without the group a hook's receipt ends with, `[call=<id> input sha256=<hex> bytes=<n>]`. Any line that ends in a group of that shape is shown without it, a hand-written one included, so what a writer puts there is in the chain and not in the listing.
- A receipt holds the input as the hook was handed it. Where a `PreToolUse` hook rewrites a call's input, the hook that fires after the call is handed the input from before the rewrite, so the action line and the hash are of the call as the model sent it, and what ran is in neither the receipt nor the transcript. Measured on Claude Code 2.1.294, Windows (ADR-0047).
- A receipt never holds tool output or conversation. Those are in the transcript, which the chain commits by its hash, which the writer can reach, and which the harness deletes after its retention period (ADR-0017, HOOK.md).

**Limits of coverage** (DIRECTION section 3): Claude Code has all four parts of a vertical. Codex CLI and the OpenAI Agents SDK give a chain and no second record, so the witness adds nothing for them.

## Sorting a reported weakness

Any way of getting past the record lands in one of three places.

| It is | Which means | What happens |
|---|---|---|
| Loud | It works, and it leaves a mark the agent cannot erase: an alarm, a mismatch at the remote, a broken verdict | Nothing. That is the design working |
| A stated limit | It needs something this page already excludes | It is already on this page. If it is not, the page gains a line |
| Silent, and inside a promise | It works, leaves no mark, and needs nothing excluded | A vulnerability. Report it privately ([SECURITY.md](../SECURITY.md)) |

## If you build on top of it

- What your tool may repeat: the two promises, for records made under the vantage setup.
- What it may add: what the witness catches, with its limit said beside it.
- What it has to ask of its users: the vantage setup, by name.
- What it must not say: that the record is complete, that it shows the agent told the truth, or any of the words the [glossary](GLOSSARY.md#anti-terms-deliberately-not-used) refuses.

## Shown, not only said

Today [FIRE-DRILL.md](FIRE-DRILL.md) rehearses four alarms on sandbox copies: an edit, a deletion, a reorder and a regeneration. Condition 1 was measured by hand on 2026-10-05 (#259). The same day a red-team pass attacked 29 stated guarantees in temp folders, each attempt run and not reasoned: the two promises held against all of them, and what it did find is in the limits above (#473, #474). A list of each promise with the drill that shows it firing, and each limit above with the run that shows it holding as described, is not written yet.

## Standing of this page

This page describes v0.20.0, as of 2026-11-12. Condition 1 is measured on one machine and one version of the harness (Claude Code 2.1.287, Windows). What a managed hook does under `--bare` is measured there and not documented by the harness.
