# ADR-0010: The tool is named loxodonta; what it writes are receipts

**Status:** accepted 2026-08-29

## Context

The recorder began life as `receipts.py` inside a repo named loxodonta,
and the split identity survived into publication: the README introduced
"receipts", the repo answered to loxodonta, and a visitor had to hold
both names to talk about one tool. "receipts" is descriptive but
generic — ungoogleable, unbrandable, and colliding with half the
point-of-sale industry. The operator called it: the project is
loxodonta, everywhere, including the script. This is the last cheap
moment for the change — before any PyPI package or install base exists,
a rename is one mechanical change; after, it is a breaking one.

## Decision

> **The script is `loxodonta.py`; the command is `loxodonta`; what it
> writes are still receipts.** The noun survives on purpose: entries
> are receipts, chains live in `receipts/`, and the prose keeps saying
> so — the tool has one name, its artifact keeps its own.

The frozen format does not move (ADR-0005, ADR-0009): the genesis
actor string `"receipts"`, the `receipts-<session>.jsonl` filename
convention, the `receipts/` log directory, and every SPEC v0.1 byte
stay exactly as they were. A chain written before the rename verifies
identically after it. The env knob `RECEIPTS_LOCK_TIMEOUT` becomes
`LOXODONTA_LOCK_TIMEOUT` (an internal tuning knob with no install
base; not part of the format).

Two consequences travel with the rename:

1. **The hook installer moves into the public surface.** `dogfood.py
   install-global` becomes `loxodonta install-hook` (and
   `uninstall-hook`), because "wire your machine" belongs in the tool a
   stranger downloads, not in the operator's private experiment driver.
   dogfood.py retires from the repo: its status/drill duties were
   already superseded by `supervisor scan`/`drill`, and its journal is
   operator-side by definition.
2. **Either era's install is honored.** Hook detection — in the
   installer's idempotency check and in the supervisor's witness
   (`hook_matchers`) — recognizes both `receipts.py` and
   `loxodonta.py` in a wired command, so a pre-rename install is never
   doubled and never mistaken for "no recorder wired".

## Consequences

- One name to say, search, and package. The README introduces
  loxodonta and means the whole thing.
- Historical documents (ADRs 0001–0009, SPEC discussion) keep saying
  `receipts.py`; they are records of decisions made under that name and
  are not rewritten.
- Existing machine-wide installs keep working unmodified; re-running
  `loxodonta install-hook` after an update migrates the command path
  on its own schedule (`uninstall-hook` removes either era's wiring).

## Alternatives considered

- **Keep `receipts.py`, brand only the repo** — rejected: the split
  identity is the confusing part, and it deepens with every doc.
- **Rename the artifact too ("the chain leaves loxodons")** — rejected
  with prejudice: "receipt" is the clearest word in the whole design.
- **A compatibility shim `receipts.py` importing `loxodonta.py`** —
  rejected: there is no install base to shim for, and two files
  claiming to be the recorder violates the one-file readability rule.
