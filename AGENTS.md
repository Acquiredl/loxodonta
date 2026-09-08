# loxodonta, for agents

You are in the repository of a tamper-evident receipt log for AI agents: two
single-file Python programs, standard library only. `loxodonta.py` records
and verifies; `supervisor.py` watches and recalls. What they write are
receipts. The vocabulary is settled; use it exactly.

Read, in this order:

1. `GLOSSARY.md`: the words, and the anti-terms. This is not a blockchain,
   nothing here is immutable, and it is not an audit log.
2. `docs/SPEC.md`: the receipt format, frozen at v0.1.
3. `adrs/`: the decisions that are hard to reverse. Argue with the ADR, not
   the code.
4. `CONTRIBUTING.md`: the rest, including how this repo is built.

Rules:

- Standard library only. No dependencies, nothing to install.
- Single files, readable top to bottom. A comment that says why beats a
  trick that saves a line.
- Tests first, through the public CLI: run the command a user would run and
  read what it printed or wrote. No mocking of internals.
- Never change the receipt format.
- Never work on `main`. Branch from `dev`; pull requests target `dev`.
- Front-door prose (README, SECURITY, CONTRIBUTING, CHANGELOG,
  CODE_OF_CONDUCT) is the author's. Draft it; do not expect it merged as
  written.

Before a pull request, both green:

```
python -m unittest discover -s tests
python tools/house_check.py
```

If you were asked to wire loxodonta into a project rather than change it,
that is a different task: read `docs/HOOK.md`.
