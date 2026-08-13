# Dogfood log — the usefulness experiment

**Started:** 2026-08-13 · **Decision date:** 2026-09-10 (four weeks)

receipts now records its own development: a `PostToolUse` hook in `.claude/settings.json` writes one chained entry per tool call, one chain per Claude Code session, into `receipts/` (gitignored — action lines record every command run). The tool works; this experiment answers whether it is *useful* — decided by usage data, not argument.

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

Once: `alias receipts='python3 /path/to/loxodonta/receipts.py'` in your shell rc.

The hook runs itself — every Claude Code session in this repo leaves a chain. Everything else is `./dogfood.sh`:

| When | Command | What it does |
|---|---|---|
| Whenever curious | `./dogfood.sh` | verdict for every session chain |
| After a session | `./dogfood.sh report` | timeline of the newest chain + anchor status |
| End of a meaningful session | `./dogfood.sh anchor` | commit every chain head to Bitcoin |
| A few hours later (or cron) | `./dogfood.sh upgrade` | complete pending proofs |
| Every week or two | `./dogfood.sh drill` | tamper fire drill — edit / delete / regenerate, confirm each alarm |
| Whenever something happens | `./dogfood.sh note "..."` | one journal line, below |

Cron for the upgrade step (adjust the path):

```
0 9 * * 1  cd $HOME/path/to/loxodonta && ./dogfood.sh upgrade >> receipts/upgrade.out 2>&1
```

Ritual reminders: copy `receipts/*.anchors.jsonl` somewhere the writer can't reach (proofs are self-authenticating — an out-of-reach copy beats a head record, ANCHORING.md §5); and when `verify --anchors` says ANCHORED, actually read the block height — freshness judgment is the operator's half of the regeneration defense.

## What to journal

One line per event, via `./dogfood.sh note "..."`: consulted a log (and whether the chain mattered), friction hit, warning seen, drill result, wished-for command, anything that surprised. The journal is the data the decision date runs on.

## Journal

- 2026-08-13: wired up — hook, dogfood.sh, this file. Experiment starts. First local `anchor` run doubles as live validation of the OTS wire subset (calendars were unreachable from the build sandbox).
