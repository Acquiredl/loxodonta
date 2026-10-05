# What loxodonta promises, and what it depends on

This page is for someone who wants to rely on a loxodonta record, or build a tool on top of one. It says what the record promises, the setup those promises depend on, and where they stop.

## Three questions a record can be asked

| Question | Answered by | The short answer |
|---|---|---|
| Was the record changed after it was written? | The chain, checked against a copy of its head kept off the machine | Promised, under the vantage setup below |
| Is anything missing from it? | The [witness](GLOSSARY.md#witness), counting against a [second record](GLOSSARY.md#second-record) | Not promised. The witness catches faults; see what it adds, below |
| Is what was written true? | Nothing | Never promised. A receipt is what the hook was handed |

## The two promises

1. **A change shows.** An edit, a deletion or a reorder of any entry covered by a commitment held off the machine makes `verify` say so and name the entry. (SPEC sections 5, 6 and 8.1.)
2. **A date holds.** A chain with that head existed by the time of the commitment. (ANCHORING.md.)

## What the witness adds

It is not a promise. A Claude Code session that ran tool calls owing a receipt and wrote fewer is reported by the supervisor. That catches faults: a hook that stopped firing, a wedged lock, a silent fork. It does not hold against a writer shaping both records, because the second record it counts against is on the same machine. (GLOSSARY, *Second record*; GROUNDING section 3.)

It becomes a promise the day a second record exists that the agent cannot reach.

## The vantage setup

A vantage point is a place with a clear view that the watched party cannot get to. The vantage setup is a machine where these four conditions hold. The two promises are made for records written under it.

| # | Condition | How it is set | Standing |
|---|---|---|---|
| 1 | The hook cannot be switched off by the agent | `install-hook --managed`, run by an administrator | ADR-0040. Measured on 2026-10-05 against a run with hooks switched off on its command line, and against a run under `--bare` (Claude Code 2.1.287, Windows; #259) |
| 2 | The agent holds no administrator rights | The operator's own job. It is about the account the agent runs as, never about the harness's permission mode | Outside the tool |
| 3 | A copy leaves the machine | The `full` [profile](GLOSSARY.md#profile) with a [receiver](GLOSSARY.md#receiver) the writer cannot reach; `timestamped` gives the second promise only | Built |
| 4 | Somebody reads it | `supervisor serve` on its cadence, and a check of the chain against the copy off the machine | Built |

**Checking condition 1.**

1. Run `install-hook --managed` again, with the profile you chose and no administrator rights: it answers "already installed in", names the managed file, and changes nothing.
2. In the harness, `/status` lists `Enterprise managed settings (drop-ins)` on its `Setting sources` line. On a machine whose organization delivers settings another way, the file may not be the one in use, and that line says which source is.
3. The proof: start a session with `{"disableAllHooks": true}` passed through `--settings`, run one tool call, and see that its drawer and its receipt are written.

**Condition 2 has no check on this page.** An elevated shell, or `sudo` that asks for no password, breaks it. The supervisor runs as the same account as the agent, so it is the one placed to say when that account can rewrite the managed file (#469).

## What each profile adds

| What happened to the chain | `local` | `timestamped` | `full` |
|---|---|---|---|
| One entry edited, deleted or moved | shows | shows | shows |
| Regenerated whole | only against a head you kept by hand | shows once the anchor matures | shows at once, at the remote |
| The store wiped | gone | gone, and the anchor says a chain existed | survives at the remote as of the last send |
| The tail since the last send rewritten | does not show | does not show | does not show until the next send |

(GLOSSARY, *Profile*; TOPOLOGY.md.)

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
- The recorder file itself sits at a path the operator owns (#460).
- On a machine whose organization delivers settings from a server or through device management, the managed file may be skipped without a warning (ADR-0040).
- That a managed hook runs under `--bare` is measured on one version of the harness and not stated in its documentation, so a later version may differ (#259).

**Limits of what a receipt holds:**

- An action line holds the first 160 characters of what ran, with runs of whitespace collapsed to one space. What came after is not in the record, and today nothing in the receipt says how much was dropped (#470 adds the count).
- No receipt exists for what is not a tool call: configuration that runs when the harness starts, what happens inside an MCP server, a call the harness denied.
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

Today [FIRE-DRILL.md](FIRE-DRILL.md) rehearses four alarms on sandbox copies: an edit, a deletion, a reorder and a regeneration. Condition 1 was measured by hand on 2026-10-05 (#259). A list of each promise with the drill that shows it firing, and each limit above with the run that shows it holding as described, is not written yet.

## Standing of this page

This page describes v0.13.0, as of 2026-10-05. Condition 1 is measured on one machine and one version of the harness (Claude Code 2.1.287, Windows). What a managed hook does under `--bare` is measured there and not documented by the harness.
