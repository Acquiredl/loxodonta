# loxodonta

*An elephant never forgets.*

> **Status: work in progress.** I chose to publish this early rather than polish it privately. The code is real and the test suite holds every claim below, but this README has not had its final editing pass — some sections will still be rewritten. Read it as an honest draft.

**loxodonta** is a flight recorder for AI agents. I run agents on my machine all day, and at some point the obvious question hit me: if anyone ever asks "what exactly did the agent do", all I have is a plain log file. And a plain log proves nothing. Anyone can edit it after the fact, delete the embarrassing line, backdate an entry. Including the agent itself, which has filesystem access and every reason to look good.

So this tool makes every action an agent takes leave a receipt, and every receipt contains the SHA256 hash of the one before it. That single change turns a log into a hash chain: edit, delete, or reorder any line and every later hash stops matching. One command tells you whether history was touched. Not prevented, detected. That distinction matters and the docs never blur it: this is tamper-evident, not immutable.

It's one Python file, no dependencies, six core commands, and you can read the whole thing top to bottom in a sitting. That's a design constraint, not an accident: a tool whose job is auditing agents should itself be auditable in an afternoon.

## what a recorded task actually looks like

Here's a real slice from one of my own sessions building this repo. A Claude Code hook writes a receipt for every tool call, so the chain ends up being a timeline of how the task evolved, without the agent getting a vote:

```
160  17:53:23Z  claude-code: Bash: cat >> tests/test_supervisor.py << 'EOF' class WalkFindingsTest...
161  17:53:31Z  claude-code: Edit: supervisor.py
164  17:53:43Z  claude-code: Edit: supervisor.py
165  17:53:53Z  claude-code: Bash: python -m unittest tests.test_supervisor.WalkFindingsTest
171  17:54:51Z  claude-code: Edit: supervisor.py
174  17:55:09Z  claude-code: Bash: python -m unittest tests.test_serve.ScanBatchingTest ...
176  17:55:21Z  claude-code: Bash: python -m unittest discover -s tests -q
179  17:58:31Z  claude-code: Bash: git checkout -b claude/supervisor-walk-fixes && git commit ...
181  18:17:16Z  claude-code: Bash: gh pr merge 37 --merge
```

You can read the whole story in there: failing tests written first, the code edited until they pass, the full suite run, then the branch, the commit, the merge. Months later I can answer "how did that fix actually happen" from the chain instead of from memory. And because it's chained, I can also prove nobody rewrote that story afterward.

That second part is the point. The timeline is useful every day, and honestly it's the reason I keep the thing running. But the integrity claim is what makes it worth publishing: git only remembers what got committed, and a summary written by the agent is the agent grading its own homework. The chain records everything, gets written outside the agent's control, and breaks visibly if anyone edits it after the fact.

## agents reading their own history

The chain isn't only for humans checking up on agents. It feeds the agents themselves. A fresh session's first problem is figuring out what happened before it arrived: git only shows what got committed, and the raw transcripts are megabytes. The chain sits in the middle, a few KB per session, every action and every file touched, across every repo on the machine.

I tested this instead of assuming it. Fresh agents had to orient in a repo from either the chain, the git log, or both, and the chain was the only source that caught the work happening off main: a local branch that was never pushed, operations that produce no commit at all, the exact action that was in flight when the last session ended. Git log held its own on committed work, so the honest summary is that the chain doesn't replace git or reading the code. It answers "what was going on here recently, which files were hot, and what was left mid-flight" before any code gets read, and it's the only record that survives when a session crashes or the work never got committed.

That reading now ships as a surface of its own. A `SessionStart` hook injects a **digest** at the top of every session: the repo's recent receipts as one-line rows, each session's final entry tagged as the last recorded action, capped at a fixed row budget so a long history can't flood the context. Every row carries an **entry address** — a short prefix of the entry's own hash — and three commands climb from there:

```
python supervisor.py digest                   # what the hook injects, by hand
python supervisor.py show 413d5fdf            # one full entry by address
python supervisor.py search "torn tail"       # the whole repo's chains, not just the window
python supervisor.py search "lock" --all      # every repo under your root
python supervisor.py timeline 413d5fdf        # what happened around that entry
```

Because the address is a hash prefix, `show` re-hashes what it fetched and confirms it matches — the pointers into your memory are self-verifying. And because recall is reading, not judging, none of this runs `verify` or prints a verdict: the digest cites the supervisor's last scan and labels it testimony, and the real verdict stays one command away. A repo can opt out of cross-repo results by dropping a `receipts/.unlisted` marker beside its chains — its memory then renders only inside that repo.

## quickstart

One file, stdlib only, Python 3.9+ (`alias loxodonta='python3 /path/to/loxodonta.py'`):

```
loxodonta init                                                   # start a chain (writes the genesis entry)
loxodonta log --actor agent --action "wrote draft" --file report.md
loxodonta run --actor agent --file report.md -- python make_draft.py
                                 # run a command; it cannot skip its own receipt
loxodonta verify                  # walk the chain; exit 1 on any break
loxodonta head                    # print the chain head — record it out of the agent's reach
loxodonta verify --expect-head <hex>   # catch a wholesale rewrite, against your recorded head
loxodonta report                  # the timeline you saw above
```

Then the outer layers:

```
loxodonta anchor                  # commit the head to Bitcoin via OpenTimestamps (free, no wallet)
loxodonta anchor --upgrade        # complete the proof once Bitcoin has it (a few hours later)
loxodonta verify --anchors        # judge anchor proofs, offline
loxodonta explain                 # LLM narration of the log (testimony, not a verdict)
```

## hooking it into an agent

For Claude Code, a `PostToolUse` hook turns every tool call into a receipt automatically, which is how the timeline above got written. Wiring in [docs/HOOK.md](docs/HOOK.md).

The recorder itself doesn't care who writes to it. Anything that can run a command can leave a receipt, so `loxodonta run` and `loxodonta log` work with any framework today, and wiring another stack in automatically means writing one small adapter against its tool-call events. Claude Code is the only shipped adapter right now because it's what I use daily. Adapters for other frameworks are on the planned list below.

## the supervisor

Tampering only gets caught if something actually looks at the chains, and nobody reads logs every day. So `supervisor.py` does the looking. Same rules as the recorder: one file, stdlib only, readable in a sitting. It drives receipts through the public CLI and decides nothing itself:

```
python supervisor.py scan      # one tick: every chain on the machine, verdicts, exit code for cron
python supervisor.py serve     # localhost-only page: the recall timeline with search, plus the alarm band
python supervisor.py drill     # rehearse detection on a sandbox copy, real chains untouched
```

Between looks it remembers every chain's last position, and it shouts when the difference can't be explained by normal appends: a chain that shrank, a head that vanished from its own history, a session that's visibly active while no receipts arrive (the failure nothing else watches for). It also keeps anchor proofs fresh, and the page re-verifies every chain in your browser via WebCrypto, so the verdicts you see don't depend on trusting the server that drew them.

One honesty rule holds all of it together: everything the supervisor stores lives on the same machine as the agent, so the agent could edit that too, and the supervisor trusts none of it. Its memory is only a reason to shout, never proof. The one thing the agent can never touch is the anchor, because that lives in a Bitcoin block. Once a chain head is anchored, no rewrite on this machine can fake that record or its timestamp. That's the hard boundary: every other layer detects fast, the anchor is the one piece of evidence a rewrite can't forge.

## why no keys

Signing every entry with a private key sounds like the obvious upgrade, and it's the first thing most people suggest. receipts doesn't do it, on purpose: on a single machine, whoever holds the signing key is the same party who could rewrite the log, so a key adds ceremony without adding proof, and now you're managing keys on top. The chain proves internal consistency, and anchoring binds history to something nobody holds: the head gets committed to Bitcoin via OpenTimestamps, so entries provably existed before the block that anchors them. No wallet, no tokens, no service to run. The reasoning lives in [adrs/](adrs/), starting with the threat model: the writer of the log, in practice an AI agent, is the adversary.

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

Adapters for other agent frameworks, so recording isn't tied to my stack. A richer query surface if shelling out ever proves insufficient — filters and aggregation are deliberately not built until the plain commands above fall short. Navigation for the recall page in `supervisor serve`, so browsing memory doesn't require the CLI. New work happens on the `dev` branch; `main` stays stable and everything on it holds the claims above.

## license

MIT. If you have questions or you think I got something wrong, open an issue. All feedback is welcome.
