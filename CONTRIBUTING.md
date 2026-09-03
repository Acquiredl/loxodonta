# Contributing

Thanks for looking. This is a small repo with strong opinions, and most of
them are written down. Reading three files first saves everyone a round trip:

- `GLOSSARY.md` — the vocabulary, used exactly. Note the anti-terms: this is
  not a blockchain, nothing here is immutable, and it is not an audit log.
- `docs/SPEC.md` — the receipt format, frozen at v0.1. The canonical-JSON
  rules in §4 are the load-bearing part.
- `adrs/` — the decisions that are hard to reverse. If a change fights one of
  them, the ADR is what to argue with, not the code.

## The three rules that shape every change

1. **Stdlib only, no dependencies, ever.** Anything that needs the network or
   another program shells out to it (`explain` runs `claude -p`, anchoring
   speaks HTTP by hand, `export --send` runs `gh`).
2. **Readable top to bottom by a non-expert.** `loxodonta.py` and
   `supervisor.py` are single files on purpose. Readability outranks
   cleverness; a comment that says why beats a trick that saves a line.
3. **Tests first, through the public CLI.** Every behavior is tested by
   running the command a user would run and reading what it printed or wrote.
   No mocking of internals. Run the suite with:

   ```
   python -m unittest discover -s tests
   ```

## Branches

`main` is stable and every claim in the README is true of it. Work happens on
`dev`; open pull requests against `dev`. `dev` reaches `main` at milestones.

## What helps most right now

**Field data.** The recorder has been proven on one machine. If you run it on
yours, `python supervisor.py export` writes a redacted, scan-shaped summary
you can read before you send it, and `export --send` files it here through a
secret gist and the *Field data* issue template. What comes back gets read
into `docs/FIELD-DATA.md`, one row per export, with what it taught.

**Bug reports** that come with the chain (or the export) that shows them.

**Adapters** for harnesses not yet covered: produce the hook payload, call
`loxodonta hook`. `docs/HOOK.md` (*Writing another adapter*) is the whole
contract, and the hook's test suite is yours.

## Decisions

If a change is hard to reverse, surprising without context, or a real
trade-off, it gets an ADR in `adrs/` before it gets code. Small choices do
not. When unsure, open an issue and ask; the answer is usually short.
