# Dogfood log — the usefulness experiment

**Started:** 2026-08-13 · **Decision date:** 2026-09-10 (four weeks)

receipts records every Claude Code session on this machine: `python dogfood.py install-global` (run once) wires a `PostToolUse` hook into `~/.claude/settings.json`, and each session writes one chained entry per tool call into `<project>/receipts/` — the hook creates that directory and a protective `.gitignore` on first use, since action lines record every command run. The tool works; this experiment answers whether it is *useful* — decided by usage data, not argument.

## The bet, written down before the data

**Signals of value** (any one is enough to keep going):

- At least once, a receipts log was actually *consulted* to answer "what did the agent do?" — and answered it faster or more trustworthily than scrollback or git would have.
- `verify` or a fire drill surfaced something real that would otherwise have been missed.
- The head-record/anchor ritual got done unprompted at session ends — the habit formed.

**Signals of failure** (all three together means park it):

- Four weeks in, no log was ever read for a real reason.
- The hook got disabled, or its output was never once looked at.
- Every time a log *was* read, a plain log would have served identically (the chain added nothing).

**On the decision date, pick one from the evidence:** build the reader side (a supervisor that holds head records and verifies continuously — promoted from speculation only if the ritual failed to become a habit), or polish and go public, or park it as a finished portfolio piece. All three are legitimate outcomes.

## How to run it

Once: `python dogfood.py install-global` (then restart open Claude Code sessions — hooks load at session start), plus a shell shortcut for the CLI:

- PowerShell (`$PROFILE`): `function receipts { python S:\Code\repos\loxodonta\receipts.py @args }`
- bash/zsh rc: `alias receipts='python3 /path/to/loxodonta/receipts.py'`

From then on the hook runs itself — every session in every repo leaves a chain in that repo's `receipts/`. Sessions run in a git worktree log to the repo the worktree belongs to, so nothing is lost when the worktree is pruned after its branch merges.

Everything else is `python dogfood.py`, run from anywhere. It searches every repo in the folder holding this one, so one dashboard covers the whole experiment; point it elsewhere with `RECEIPTS_DOGFOOD_ROOT`. `status` exits non-zero if any chain fails to verify, so it can be scheduled and shout.

| When | Command | What it does |
|---|---|---|
| Whenever curious | `python dogfood.py` | verdict for every session chain |
| After a session | `python dogfood.py report` | timeline of the newest chain + anchor status |
| End of a meaningful session | `python dogfood.py anchor` | commit every chain head to Bitcoin |
| A few hours later (or cron) | `python dogfood.py upgrade` | complete pending proofs |
| Every week or two | `python dogfood.py drill` | tamper fire drill — edit / delete / regenerate, confirm each alarm |
| Whenever something happens | `python dogfood.py note "..."` | one journal line, below |

To automate the upgrade step, schedule `python dogfood.py upgrade` weekly — Task Scheduler on Windows (Action: `python`, arguments: `S:\Code\repos\loxodonta\dogfood.py upgrade`), or cron elsewhere (`0 9 * * 1 cd ~/loxodonta && python3 dogfood.py upgrade`). Or just run it by hand when you remember; pending proofs don't expire quickly.

Ritual reminders: a session can span **sibling chains** (`receipts-<session>-002.jsonl`) if a tail is ever damaged — each has its own head and anchors separately, so `anchor` and the head-record ritual cover every chain, not one per session; copy `receipts/*.anchors.jsonl` somewhere the writer can't reach (proofs are self-authenticating — an out-of-reach copy beats a head record, ANCHORING.md §5); and when `verify --anchors` says ANCHORED, actually read the block height — freshness judgment is the operator's half of the regeneration defense.

## What to journal

One line per event, via `python dogfood.py note "..."`: consulted a log (and whether the chain mattered), friction hit, warning seen, drill result, wished-for command, anything that surprised. The journal is the data the decision date runs on.

## Journal

- 2026-08-13: wired up — hook, driver script, this file. Experiment starts. First local `anchor` run doubles as live validation of the OTS wire subset (calendars were unreachable from the build sandbox).
- 2026-08-13: first friction finding, before the first chain: the driver shipped as bash and the operator's machine runs Windows. Ported to dogfood.py (stdlib, cross-platform); hook command made shell-free (receipts.py reads CLAUDE_PROJECT_DIR itself).
