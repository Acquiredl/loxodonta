# loxodonta

*A flight recorder for AI agents.*

[![tests](https://github.com/Acquiredl/loxodonta/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/Acquiredl/loxodonta/actions/workflows/tests.yml) [![python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/) [![no dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](#install) [![license MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

Every completed tool call your agent makes leaves a receipt, and one command tells you whether history was touched. The agent that writes the log is treated as the adversary: edits, deletions, and reorders break the chain, and an anchor puts the chain head somewhere no rewrite on the machine can reach.

- **Memory.** What git cannot tell you: what a session was doing before it ended, which files were hot, what was left mid-edit, and what never became a commit. A fresh session starts with that record in front of it.
- **The bad day.** A prompt-injected session keeps leaving receipts, because the hook fires outside the agent's control. Afterward you have the ordered record of what it did, whether that record was cleaned up, and a redacted export to study.
- **The anchor.** The chain head committed to Bitcoin through OpenTimestamps, free and without a wallet: the one piece of evidence a rewrite on the machine cannot forge.

Tamper-evident, not immutable: the tool detects, it does not prevent.

```
$ python loxodonta.py init
initialized receipts.jsonl
$ python loxodonta.py log --actor agent --action "drafted the Q3 report"
logged entry 1
$ python loxodonta.py log --actor agent --action "sent the draft to the client"
logged entry 2
$ python loxodonta.py verify
VALID
$ sed -i 's/Q3/Q2/' receipts.jsonl        # change one word of a past entry
$ python loxodonta.py verify
BROKEN at entry 1: entry_hash does not match canonical form
```

## Install

One file, Python 3.9 or newer, nothing to install. Download `loxodonta.py` from the [releases page](https://github.com/Acquiredl/loxodonta/releases) (put `supervisor.py` beside it for the watching layer), check its sum against the `SHA256SUMS` attached to the same release, and ask the file which version it is:

```
sha256sum loxodonta.py            # certutil -hashfile loxodonta.py SHA256 on Windows
python loxodonta.py --version     # loxodonta 0.1.0 (format 0.1, commit ...)
```

`main` is the stable branch: it is tested on Linux, macOS, and Windows, and every claim on this page is true of it. New work lands on `dev` and reaches `main` with a tag and a release.

## Quick start

1. **Record.** Start a chain, then wrap a command in `run`: the receipt is written after the command exits, whatever the command did, and `--file` fingerprints a file it touched. `log` writes a line by hand.

   ```
   python loxodonta.py init
   python loxodonta.py run --actor agent -- python --version
   python loxodonta.py log --actor agent --action "reviewed the output"
   ```

2. **Tamper.** Open `receipts.jsonl` and change one word of a past entry. Or delete a line, or swap two.

3. **Verify.** The verdict is one line and an exit code, so a script or a cron job can read it.

   ```
   python loxodonta.py verify     # VALID, or BROKEN at entry N; exit 1 on any break
   python loxodonta.py report     # the chain as a timeline
   python loxodonta.py head       # the chain head; keep it where the agent cannot reach
   ```

4. **Wire the hook.** One command, and every session on the machine leaves a chain in the store (`~/.loxodonta/receipts/`, one drawer per project) and starts with a recall digest.

   ```
   python loxodonta.py install-hook            # Claude Code
   python loxodonta.py install-hook --codex    # Codex CLI
   ```

## Where to go next

**Operator**, running agents and wanting to know what they did:

- [docs/HOOK.md](docs/HOOK.md): the hook wiring, what a receipt holds, coverage and cost.
- [docs/TOUR.md](docs/TOUR.md): the recorder, read top to bottom in a sitting.
- [The supervisor](#the-supervisor), then [docs/TOUR-SUPERVISOR.md](docs/TOUR-SUPERVISOR.md): the watching layer.

**Security**, validating the claims in the order any tool gets validated:

- [ADR-0002](adrs/0002-writer-as-adversary.md): the threat model, the writer of the log as the adversary.
- [What this defends against, and what it does not](#what-this-defends-against-and-what-it-does-not): the table.
- [docs/OWASP.md](docs/OWASP.md): the mapping to the OWASP Top 10 for LLM applications.
- [docs/SPEC.md](docs/SPEC.md): the receipt format, frozen at 0.1.
- [SECURITY.md](SECURITY.md): how to report, and what is in scope.

How the tool got here is [docs/HISTORY.md](docs/HISTORY.md); what changed since the first tag is [CHANGELOG.md](CHANGELOG.md).

## How it works

Every receipt carries the SHA256 hash of the one before it. That single change turns a log into a hash chain: edit, delete, or reorder any line and every later hash stops matching. `verify` walks the chain and prints a verdict. Not prevented, detected. That distinction matters and the docs never blur it.

The chain holds one-line summaries, not the full story. The full record, complete commands and tool output, lives in the harness transcript, a plain file anyone can rewrite. So every 25 receipts the chain also commits the transcript's hash as it grows: once a stretch of transcript is committed, rewriting it is detectable from then on, and `verify --transcript` says which stretch was touched. The claim is caged the same way as everything here: coverage runs forward from each commitment, the newest ~25 calls are still open, and it is detection, not protection. Anchors remain the only hard boundary.

The outer layers, when you want them:

```
python loxodonta.py anchor            # commit the head to Bitcoin via OpenTimestamps (free, no wallet)
python loxodonta.py anchor --upgrade  # complete the proof once Bitcoin has it (a few hours later)
python loxodonta.py verify --anchors  # judge anchor proofs, offline
python loxodonta.py verify --files    # also compare every logged file against disk
python loxodonta.py explain           # LLM narration of the log (testimony, not a verdict)
```

One honest note on timing: an anchor hardens history **up to the anchored head**; entries written since your last anchor are protected by detection only until the next one. So anchor at meaningful moments (end of a session, end of a pipeline run), and copy the sidecar proof file somewhere the agent can't reach. A proof in your hands is evidence no rewrite on the machine can touch.

**Exit codes**, since scripts and cron will read them: `0` valid, `1` chain broken, `2` a logged file changed since its receipt (`verify --files`), `3` this is not the recorded history (head or anchor mismatch, the gravest tier). Argparse usage errors also exit `2`, so scripts should trust the stdout verdict line, never the exit code alone.

It's one Python file, no dependencies, six core commands, and you can read the whole thing top to bottom in a sitting. That's a design constraint, not an accident: a tool whose job is auditing agents should itself be auditable in an afternoon.

## What a recorded task looks like

The hook writes a receipt for every completed tool call, so a chain ends up being a timeline of how a task evolved, without the agent getting a vote. Here is one session from the demo project, a small todo CLI: tests read and extended first, the code edited until they pass, then the commit. Every `Edit` carries the fingerprint of the file as it stood afterward. This is `report` over that session's chain in the store:

```
receipt log: ~/.loxodonta/receipts/todo-08a89dd2/receipts-7c1f3a2e-4b8d-4f0e-9a61-2d5e8c3b7f10.jsonl (10 entries)

     0  2026-08-18T13:42:07Z  receipts: genesis
     1  2026-08-18T13:42:07Z  claude-code: Read: todo.py
        - todo.py (6f3899efcaac…)
     2  2026-08-18T13:42:21Z  claude-code: Read: tests/test_todo.py
        - tests/test_todo.py (b13388f7cbea…)
     3  2026-08-18T13:43:57Z  claude-code: Edit: tests/test_todo.py
        - tests/test_todo.py (f610d630cc0b…)
     4  2026-08-18T13:44:18Z  claude-code: Bash: python -m unittest -q
     5  2026-08-18T13:46:41Z  claude-code: Edit: todo.py
        - todo.py (71ccd7f591cf…)
     6  2026-08-18T13:47:19Z  claude-code: Edit: todo.py
        - todo.py (8567c946da8a…)
     7  2026-08-18T13:47:38Z  claude-code: Bash: python -m unittest -q
     8  2026-08-18T13:48:05Z  claude-code: Bash: git add -A
     9  2026-08-18T13:48:14Z  claude-code: Bash: git commit -m "done: mark an item complete"
```

Months later I can answer "how did that fix actually happen" from the chain instead of from memory. And because it's chained, I can also show that nobody rewrote that story afterward. That second part is the point: git only remembers what got committed, and a summary written by the agent is the agent grading its own homework. The chain records every completed call, gets written outside the agent's control, and breaks visibly if anyone edits it after the fact.

## Agents reading their own history

The chain isn't only for humans checking up on agents. It feeds the agents themselves, a second memory layer for your agent work. A fresh session's first problem is figuring out what happened before it arrived: git only shows what got committed, and the raw transcripts are megabytes. The chain sits in the middle, a few KB per session, every action and every file touched, across every repo on the machine, and an agent can walk it to see exactly what changed and when.

That reading ships as a surface of its own. A `SessionStart` hook injects a **digest** at the top of every session: the repo's recent receipts as one-line rows, each session's final entry tagged as the last recorded action, capped at a fixed row budget so a long history can't flood the context. Runs of same-tool receipts collapse into one row before the cap is applied, so an exploration-heavy session spends rows on its story, not its searching. This is the demo project's second session as the digest renders it:

```
-- session d94b0e61 (2026-08-20 09:15Z .. 2026-08-20 09:22Z, 10 entries) --
4d3268d8  09:15Z  claude-code  2x Bash, last: python todo.py list
0bd89d11  09:16Z  claude-code  Grep: todo.py
e2646aab  09:16Z  claude-code  Read: todo.py
6184994f  09:18Z  claude-code  Edit: tests/test_todo.py
283b2543  09:19Z  claude-code  Bash: python -m unittest -q
30df5aae  09:21Z  claude-code  2x Edit, last: todo.py
09d87676  09:22Z  claude-code  2x Bash, last: git commit -am "list: count from 1, the way people do"   <- last recorded action
```

Every row carries an **entry address**, a short prefix of the entry's own hash, and three commands climb from there:

```
python supervisor.py digest                   # what the hook injects, by hand
python supervisor.py show 09d87676            # one full entry by address
python supervisor.py search "unittest"        # the whole repo's chains, not just the window
python supervisor.py search "unittest" --all  # every repo under your root
python supervisor.py timeline 09d87676        # what happened around that entry
```

The same five readings are also an MCP server (`python supervisor.py mcp`), so an agent that can't run the hook (Codex, an Agents SDK program, any MCP client) reads the same memory in the same words. It is read-only by decision: an agent may read its history here, never append to it ([docs/MCP.md](docs/MCP.md)).

Because the address is a hash prefix, `show` re-hashes what it fetched and confirms it matches: the pointers into your memory are self-verifying. And because recall is reading, not judging, none of this runs `verify` or prints a verdict: the digest cites the supervisor's last scan and labels it testimony, and the real verdict stays one command away. A repo can opt out of cross-repo results by dropping a `receipts/.unlisted` marker beside its chains, and its memory then renders only inside that repo.

What has been measured so far, rather than assumed: fresh agents were quizzed on this repo's real history, six questions, ground truth derived from the chains beforehand, scored blind ([docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) has the protocol and the caveats). With the chain, both agents answered everything, down to the exact final action of a session that ended mid-edit, and named work that exists in no commit on any branch. Git-only, both answered what git can see and said "cannot determine" on the rest. That is a small N on one repo, and it is a correctness result, not a productivity one; the larger pre-registered measurement is planned, and the memory reason at the top of this page states no more than that experiment supports.

## Hooking it into an agent

For Claude Code, a `PostToolUse` hook turns every completed tool call into a receipt automatically, which is how the timeline above got written: `install-hook` wires it, [docs/HOOK.md](docs/HOOK.md) explains it.

The same hook payload is the contract for every other harness, so recording isn't tied to my stack:

```
python loxodonta.py install-hook            # Claude Code: PostToolUse + SessionEnd + the session-start digest
python loxodonta.py install-hook --codex    # Codex CLI: the same three events into ~/.codex/hooks.json (trust them once with /hooks)
```

```python
from agents import add_trace_processor            # OpenAI Agents SDK: three lines in your program
from adapters.openai_agents import ReceiptRecorder
add_trace_processor(ReceiptRecorder())
```

All three write to the same store, one drawer per project, with the actor naming the harness (`claude-code`, `codex`, `openai-agents`), so a machine running several leaves one memory. The honest differences (Codex records failed commands where Claude Code fires no hook, the SDK adapter runs inside your program rather than one process out, and only Claude Code sessions get the completeness alarm today) are in [docs/HOOK.md](docs/HOOK.md#other-harnesses). The recorder itself doesn't care who writes to it: anything that can run a command can leave a receipt through `loxodonta run` or `loxodonta log`, and writing another adapter is producing that one payload.

## The supervisor

Tampering only gets caught if something actually looks at the chains, and nobody reads logs every day. So `supervisor.py` does the looking. Same rules as the recorder: one file, stdlib only, readable in a sitting. It drives the recorder through the public CLI and decides nothing itself:

```
python supervisor.py scan                     # one tick: every chain in the store, verdicts, exit code for cron
python supervisor.py serve                    # localhost-only dashboard: status rail, attention queue, sessions worktable
python supervisor.py drill --root ~/repos --log <chain>   # rehearse detection on a sandbox copy, real chains untouched
python supervisor.py adopt --root ~/repos     # one-time move of pre-store chains into the store (--dry-run to preview)
```

`scan` needs no arguments: the store is its universe. `--root <folder>` scans a legacy folder-of-repos layout instead (every `<repo>/receipts/` under it, plus chains stranded in old worktrees), the mode `adopt` migrates you out of. Scan adds two exit codes of its own: `5`, the baseline tripwire (a chain changed in a way appends can't explain since the last look) and `6`, the completeness alarm (a session is visibly active while receipts stop arriving, the failure nothing else watches for).

Under the verdict strip sits a fourteen-day band, one cell per day, carrying that day's worst claim. The strip says what is true now; the band says whether now is unusual. A day nobody looked at is drawn as a gap rather than a quiet day, and that is deliberate: detection latency is a function of how often you actually look, so a run of unread days is the one failure the chains cannot report about themselves.

The scan also reports which recorder is running. The hook wires an absolute path, not a version, so the file that records you is whatever is checked out there (a branch, an uncommitted edit, a half-finished rebase), and pushing changes nothing on your own machine. The front page prints that under the verdict strip and underlines it when it drifts. It never fetches: a recorder that updated itself from a remote would give the agent a second road to the one file that has to stay honest, so noticing is the tool's job and pulling stays yours (ADR-0015).

Between looks it remembers every chain's last position, and it shouts when the difference can't be explained by normal appends: a chain that shrank, a head that vanished from its own history, a silently dead hook. It also keeps anchor proofs fresh, and the page re-verifies every chain in your browser via WebCrypto, so the verdicts you see don't depend on trusting the server that drew them.

One honesty rule holds all of it together: everything the supervisor stores lives on the same machine as the agent, so the agent could edit that too, and the supervisor trusts none of it. Its memory is only a reason to shout, never proof. The one thing the agent can never touch is the anchor, because that lives in a Bitcoin block. Once a chain head is anchored, no rewrite on this machine can fake that record or its timestamp. That's the hard boundary: every other layer detects fast, the anchor is the one piece of evidence a rewrite can't forge.

## Why no keys

Signing every entry with a private key sounds like the obvious upgrade, and it's the first thing most people suggest. loxodonta doesn't do it, on purpose: on a single machine, whoever holds the signing key is the same party who could rewrite the log, so a key adds ceremony without adding proof, and now you're managing keys on top. The chain shows internal consistency, and anchoring binds history to something nobody holds: the head gets committed to Bitcoin via OpenTimestamps, so an entry can be shown to have existed before the block that anchors it. No wallet, no tokens, no service to run. The threat model this falls out of: the writer of the log, in practice an AI agent, is the adversary ([ADR-0001](adrs/0001-hash-chain-not-signatures.md), [ADR-0002](adrs/0002-writer-as-adversary.md)).

## Where it actually helps

A few places this has already earned its keep for me, beyond the daily timeline:

**Security.** If an agent gets compromised through a prompt injection, the hook keeps recording anyway, because it fires outside the agent's control. Afterward you have the full timeline of what the compromised session actually did: which files, which commands, in what order, and the chain breaks visibly if that record was cleaned up afterward. Unless an attack specifically disables the recorder, it keeps logging, and the action that disables it is itself a tool call, so the last receipt before the silence is the kill command. This repo's completeness alarm exists because a real incident showed a session silently losing receipts, and nothing else on the machine noticed.

**Production.** Every receipt fingerprints the files it touched, so "the report that passed review" and "the report on disk today" are one comparison apart. If a deliverable got modified after the run that produced it, `verify --files` says so.

**Automation.** `scan` is built for cron: one tick, machine-readable JSON, and an exit code that only goes loud when something demands attention. A dead hook, a wedged lock, a chain that shrank, you find out the same day instead of months later.

**Context.** The agents-reading-their-own-history section above, which is the use I lean on most.

## What this defends against, and what it does not

| Threat | Covered? | How |
|---|---|---|
| Editing a past entry | yes | chain break at that entry, caught by `verify` |
| Deleting an entry | yes | successor's `prev` no longer matches |
| Reordering entries | yes | every moved entry breaks its neighbor's link |
| Silently modifying a logged file later | yes | file's current hash differs from its receipt |
| A compromised writer lying at write time | no | garbage in, faithfully chained garbage out |
| The writer omitting an entry entirely | not by the chain | a never-written entry leaves no break; completeness comes from the integration (`run`, the hook), and the supervisor alarms on the gap |
| Regenerating the whole chain from scratch | tiered | `verify --expect-head` against your recorded head, or an anchor: a regenerated chain can only carry young anchors |

## Send me what your machine saw

Everything above has been tested on exactly one machine: mine. The thresholds, the witness, the numbers in the docs all came out of one store. The thing I need most now is not a feature, it is evidence that the recorder holds up somewhere else, and a look at what real workloads look like when they are not my workloads.

So there is a one-command way to send that back, and it is built so you can read every byte before it leaves:

```
python supervisor.py export           # writes a redacted summary and prints it
python supervisor.py export --send    # uploads it as a secret gist under your account, opens a field-data issue here
```

The export is built from a list of fields I wrote down, not from your scan output with things crossed out. No paths, no command lines, no repo names (they become `repo-1`, `repo-2`), no file references. It opens with a plain-words block saying what was removed. Raw chains are a separate opt-in that shows you a sample line and asks first, because chains carry command lines and that is your call, not mine. `--send` runs `gh` under your login, so the gist stays yours and you can delete it. The design is [ADR-0021](adrs/0021-field-data-export-is-allowlisted-and-sent-through-gh.md).

What comes back gets read into [docs/FIELD-DATA.md](docs/FIELD-DATA.md), one row per export with what it taught, so you can see whether sending it was worth anything. Bug reports with a chain attached are just as welcome; [CONTRIBUTING.md](CONTRIBUTING.md) has the short version of how this repo works.

## Planned

A better viewer for reviewing the logs, most likely growing the localhost page in `supervisor serve` into full memory navigation, so browsing history doesn't require the CLI (still open to change). More adapters as harnesses earn them, and a completeness witness for Codex sessions once its transcript layout settles. A richer query surface if shelling out ever turns out insufficient: filters and aggregation are deliberately not built until the plain commands above fall short. The larger memory measurement, on a second repo, before the memory reason on this page says more than it does today.

## License

MIT. If you have questions or you think I got something wrong, open an issue. All feedback is welcome.
