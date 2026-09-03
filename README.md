# loxodonta

*An elephant never forgets.*

> **Status: work in progress.** I chose to publish this early rather than polish it privately. The code is real and the test suite holds every claim below, but this README has not had its final editing pass — some sections will still be rewritten. Read it as an honest draft.

**loxodonta** is a flight recorder for AI agents. I run agents on my machine all day, and at some point the obvious question hit me: if anyone ever asks "what exactly did the agent do", all I have is a plain log file. And a plain log proves nothing. Anyone can edit it after the fact, delete the embarrassing line, backdate an entry. Including the agent itself, which has filesystem access and every reason to look good.

So this tool makes every action an agent takes leave a receipt, and every receipt contains the SHA256 hash of the one before it. That single change turns a log into a hash chain: edit, delete, or reorder any line and every later hash stops matching. One command tells you whether history was touched. Not prevented, detected. That distinction matters and the docs never blur it: this is tamper-evident, not immutable.

In practice that means you can review what your agents ran while you were away — every completed tool call joins the chain, and later you can see where, why order matters, and how a session actually spent its time. And because the hook fires outside the agent's control, the record survives the case that worried me into building this: a prompt-injected session. Unless an attack specifically disables the recorder, it keeps logging — and the action that disables it is itself a tool call, so the last receipt before the silence is the kill command. The watching layer below alarms on the silence that follows.

The chain holds one-line summaries, not the full story. The full record, complete commands and tool output, lives in the harness transcript, a plain file anyone can rewrite. So every 25 receipts the chain also commits the transcript's hash as it grows: once a stretch of transcript is committed, rewriting it is detectable forever, and `verify --transcript` says which stretch was touched. The claim is caged the same way as everything here: coverage runs forward from each commitment, the newest ~25 calls are always still open, and it is detection, not protection. Anchors remain the only hard boundary.

It's one Python file, no dependencies, six core commands, and you can read the whole thing top to bottom in a sitting. That's a design constraint, not an accident: a tool whose job is auditing agents should itself be auditable in an afternoon.

## what a recorded task actually looks like

A Claude Code hook writes a receipt for every completed tool call, so a chain ends up being a timeline of how a task evolved, without the agent getting a vote. Here's a short real excerpt from a session building this repo — tests written first, code edited until they pass, then the merge:

```
160  17:53:23Z  claude-code: Bash: cat >> tests/test_supervisor.py << 'EOF' class WalkFindingsTest...
161  17:53:31Z  claude-code: Edit: supervisor.py
176  17:55:21Z  claude-code: Bash: python -m unittest discover -s tests -q
179  17:58:31Z  claude-code: Bash: git checkout -b claude/supervisor-walk-fixes && git commit ...
181  18:17:16Z  claude-code: Bash: gh pr merge 37 --merge
```

*(A fuller worked example from a small demo project is pending — this repo recording its own construction is honest but dense.)*

Months later I can answer "how did that fix actually happen" from the chain instead of from memory. And because it's chained, I can also prove nobody rewrote that story afterward. That second part is the point: git only remembers what got committed, and a summary written by the agent is the agent grading its own homework. The chain records everything, gets written outside the agent's control, and breaks visibly if anyone edits it after the fact.

## agents reading their own history

The chain isn't only for humans checking up on agents. It feeds the agents themselves — a second memory layer for your agent work. A fresh session's first problem is figuring out what happened before it arrived: git only shows what got committed, and the raw transcripts are megabytes. The chain sits in the middle, a few KB per session, every action and every file touched, across every repo on the machine, and an agent can walk it to see exactly what changed and when.

Here are the test results, rather than the assumption. Fresh agents were quizzed on this repo's real history — six questions, ground truth derived from the chains beforehand, scored blind ([docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) has the full protocol and caveats):

- **With the chain: 12/12 and 12/12.** Both agents answered everything, down to the exact final action of a session that ended mid-edit, and named work that exists in *no* commit on *any* branch — a throwaway prototype the receipts alone remember.
- **Git-only: 10/10 on what git can see, and an honest "cannot determine" on the rest.** Both dropped exactly the two chain-only questions. Git log holds its own on committed work — the chain doesn't replace it. It answers what git structurally can't: what was going on here recently, which files were hot, what was left mid-flight, and what never became a commit at all.

That reading ships as a surface of its own. A `SessionStart` hook injects a **digest** at the top of every session: the repo's recent receipts as one-line rows, each session's final entry tagged as the last recorded action, capped at a fixed row budget so a long history can't flood the context. Runs of same-tool receipts collapse into one row (`14x Read, last: ...`) before the cap is applied, so an exploration-heavy session spends rows on its story, not its searching. Every row carries an **entry address** — a short prefix of the entry's own hash — and three commands climb from there:

```
python supervisor.py digest                   # what the hook injects, by hand
python supervisor.py show 413d5fdf            # one full entry by address
python supervisor.py search "torn tail"       # the whole repo's chains, not just the window
python supervisor.py search "lock" --all      # every repo under your root
python supervisor.py timeline 413d5fdf        # what happened around that entry
```

The same five readings are also an MCP server — `python supervisor.py mcp` — so an agent that can't run the hook (Codex, an Agents SDK program, any MCP client) reads the same memory in the same words. It is read-only by decision: an agent may read its history here, never append to it ([docs/MCP.md](docs/MCP.md)).

Because the address is a hash prefix, `show` re-hashes what it fetched and confirms it matches — the pointers into your memory are self-verifying. And because recall is reading, not judging, none of this runs `verify` or prints a verdict: the digest cites the supervisor's last scan and labels it testimony, and the real verdict stays one command away. A repo can opt out of cross-repo results by dropping a `receipts/.unlisted` marker beside its chains — its memory then renders only inside that repo.

## quickstart

Three motions. One file, stdlib only, Python 3.9+, nothing to install.

**1. Grab it.** Download `loxodonta.py` anywhere (for the watching layer later, put `supervisor.py` beside it). Give it a short name if you like:

```
alias loxodonta='python3 /path/to/loxodonta.py'            # bash/zsh
function loxodonta { python C:\path\to\loxodonta.py @args } # PowerShell
```

**2. Record something and try to catch yourself.**

```
loxodonta init                                        # start a chain (writes the genesis entry)
loxodonta run --actor agent --file report.md -- python make_draft.py
                                                      # run a command; it cannot skip its own receipt
loxodonta report                                      # the timeline
loxodonta verify                                      # walk the chain; exit 1 on any break
```

Now open `receipts.jsonl`, change one word in a past entry, and run `verify` again — that's the whole idea, demonstrated in under a minute. (`loxodonta log` appends an entry by hand; `loxodonta head` prints the chain head, which you record somewhere the agent can't reach and later check with `verify --expect-head <hex>`.)

**3. Wire it into your agent.** For Claude Code, one command sets up the whole machine — every session then leaves a chain in the store (`~/.loxodonta/receipts/`, one drawer per project, so history survives even when a repo gets deleted) and starts with a recall digest:

```
python loxodonta.py install-hook
```

(Manual wiring and the details live in [docs/HOOK.md](docs/HOOK.md) — or hand your agent this file and say "wire loxodonta into this project"; the hook is a receipt-per-tool-call, so it can wire the thing that will be auditing it.)

Then the outer layers, when you want them:

```
loxodonta anchor                  # commit the head to Bitcoin via OpenTimestamps (free, no wallet)
loxodonta anchor --upgrade        # complete the proof once Bitcoin has it (a few hours later)
loxodonta verify --anchors        # judge anchor proofs, offline
loxodonta explain                 # LLM narration of the log (testimony, not a verdict)
```

One honest note on timing: an anchor hardens history **up to the anchored head** — entries written since your last anchor are protected by detection only until the next one. So anchor at meaningful moments (end of a session, end of a pipeline run), and copy the sidecar proof file somewhere the agent can't reach; a proof in your hands is evidence no rewrite on the machine can touch.

**Exit codes**, since scripts and cron will read them: `0` valid · `1` chain broken · `2` a logged file changed since its receipt (`verify --files`) · `3` this is not the recorded history (head or anchor mismatch — the gravest tier). Argparse usage errors also exit `2`, so scripts should trust the stdout verdict line, never the exit code alone.

## hooking it into an agent

For Claude Code, a `PostToolUse` hook turns every completed tool call into a receipt automatically, which is how the timeline above got written — `install-hook` wires it, [docs/HOOK.md](docs/HOOK.md) explains it.

The same hook payload is the contract for every other harness, so recording isn't tied to my stack:

```
python loxodonta.py install-hook            # Claude Code: PostToolUse + SessionEnd + the session-start digest
python loxodonta.py install-hook --codex    # Codex CLI: the same two events into ~/.codex/hooks.json (trust them once with /hooks)
```

```python
from agents import add_trace_processor            # OpenAI Agents SDK: three lines in your program
from adapters.openai_agents import ReceiptRecorder
add_trace_processor(ReceiptRecorder())
```

All three write to the same store, one drawer per project, with the actor naming the harness (`claude-code`, `codex`, `openai-agents`), so a machine running several leaves one memory. The honest differences — Codex records failed commands where Claude Code fires no hook, the SDK adapter runs inside your program rather than one process out, and only Claude Code sessions get the completeness alarm today — are in [docs/HOOK.md](docs/HOOK.md#other-harnesses). The recorder itself doesn't care who writes to it: anything that can run a command can leave a receipt through `loxodonta run` or `loxodonta log`, and writing another adapter is producing that one payload.

## the supervisor

Tampering only gets caught if something actually looks at the chains, and nobody reads logs every day. So `supervisor.py` does the looking. Same rules as the recorder: one file, stdlib only, readable in a sitting. It drives the recorder through the public CLI and decides nothing itself:

```
python supervisor.py scan                     # one tick: every chain in the store, verdicts, exit code for cron
python supervisor.py serve                    # localhost-only dashboard: status rail, attention queue, sessions worktable
python supervisor.py drill --root ~/repos --log <chain>   # rehearse detection on a sandbox copy, real chains untouched
python supervisor.py adopt --root ~/repos     # one-time move of pre-store chains into the store (--dry-run to preview)
```

`scan` needs no arguments: the store is its universe. `--root <folder>` scans a legacy folder-of-repos layout instead (every `<repo>/receipts/` under it, plus chains stranded in old worktrees) — the mode `adopt` migrates you out of. Scan adds two exit codes of its own: `5`, the baseline tripwire (a chain changed in a way appends can't explain since the last look) and `6`, the completeness alarm (a session is visibly active while receipts stop arriving — the failure nothing else watches for).

Under the verdict strip sits a fourteen-day band, one cell per day, carrying that day's worst claim. The strip says what is true now; the band says whether now is unusual. A day nobody looked at is drawn as a gap rather than a quiet day, and that is deliberate: detection latency is a function of how often you actually look, so a run of unread days is the one failure the chains cannot report about themselves.

The scan also reports which recorder is running. The hook wires an absolute path, not a version, so the file that records you is whatever is checked out there — a branch, an uncommitted edit, a half-finished rebase — and pushing changes nothing on your own machine. The front page prints that under the verdict strip and underlines it when it drifts. It never fetches: a recorder that updated itself from a remote would give the agent a second road to the one file that has to stay honest, so noticing is the tool's job and pulling stays yours (ADR-0015).

Between looks it remembers every chain's last position, and it shouts when the difference can't be explained by normal appends: a chain that shrank, a head that vanished from its own history, a silently dead hook. It also keeps anchor proofs fresh, and the page re-verifies every chain in your browser via WebCrypto, so the verdicts you see don't depend on trusting the server that drew them.

One honesty rule holds all of it together: everything the supervisor stores lives on the same machine as the agent, so the agent could edit that too, and the supervisor trusts none of it. Its memory is only a reason to shout, never proof. The one thing the agent can never touch is the anchor, because that lives in a Bitcoin block. Once a chain head is anchored, no rewrite on this machine can fake that record or its timestamp. That's the hard boundary: every other layer detects fast, the anchor is the one piece of evidence a rewrite can't forge.

## why no keys

Signing every entry with a private key sounds like the obvious upgrade, and it's the first thing most people suggest. loxodonta doesn't do it, on purpose: on a single machine, whoever holds the signing key is the same party who could rewrite the log, so a key adds ceremony without adding proof, and now you're managing keys on top. The chain proves internal consistency, and anchoring binds history to something nobody holds: the head gets committed to Bitcoin via OpenTimestamps, so entries provably existed before the block that anchors them. No wallet, no tokens, no service to run. The threat model this falls out of: the writer of the log, in practice an AI agent, is the adversary.

## where it actually helps

A few places this has already earned its keep for me, beyond the daily timeline:

**Security.** If an agent gets compromised through a prompt injection, the hook keeps recording anyway, because it fires outside the agent's control. Afterward you have the full timeline of what the compromised session actually did: which files, which commands, in what order, and the chain proves that record wasn't cleaned up afterward. This repo's completeness alarm exists because a real incident showed a session silently losing receipts, and nothing else on the machine noticed.

**Production.** Every receipt fingerprints the files it touched, so "the report that passed review" and "the report on disk today" are one comparison apart. If a deliverable got modified after the run that produced it, `verify --files` says so.

**Automation.** `scan` is built for cron: one tick, machine-readable JSON, and an exit code that only goes loud when something demands attention. A dead hook, a wedged lock, a chain that shrank, you find out the same day instead of months later.

**Context.** The agents-reading-their-own-history section above, which is the use I lean on most.

## what this defends against, and what it doesn't

| Threat | Covered? | How |
|---|---|---|
| Editing a past entry | yes | chain break at that entry, caught by `verify` |
| Deleting an entry | yes | successor's `prev` no longer matches |
| Reordering entries | yes | every moved entry breaks its neighbor's link |
| Silently modifying a logged file later | yes | file's current hash differs from its receipt |
| A compromised writer lying at write time | no | garbage in, faithfully chained garbage out |
| The writer omitting an entry entirely | not by the chain | a never-written entry leaves no break; completeness comes from the integration (`run`, the hook), and the supervisor alarms on the gap |
| Regenerating the whole chain from scratch | tiered | `verify --expect-head` against your recorded head, or an anchor: a regenerated chain can only carry young anchors |

## planned

A better viewer for reviewing the logs — most likely growing the localhost page in `supervisor serve` into full memory navigation, so browsing history doesn't require the CLI (still open to change). More adapters as harnesses earn them, and a completeness witness for Codex sessions once its transcript layout settles. A richer query surface if shelling out ever proves insufficient — filters and aggregation are deliberately not built until the plain commands above fall short. New work happens on the `dev` branch; `main` stays stable and everything on it holds the claims above.

## license

MIT. If you have questions or you think I got something wrong, open an issue. All feedback is welcome.
