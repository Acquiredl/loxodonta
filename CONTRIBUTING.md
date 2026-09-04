# Contributing

Thanks for looking. This is a small repo with strong opinions, and most of
them are written down. Reading three files first saves everyone a round trip:

- `GLOSSARY.md`: the vocabulary, used exactly. Note the anti-terms: this is
  not a blockchain, nothing here is immutable, and it is not an audit log.
- `docs/SPEC.md`: the receipt format, frozen at v0.1. The canonical-JSON
  rules in §4 are the load-bearing part.
- `adrs/`: the decisions that are hard to reverse. If a change fights one of
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

## The one local check

The repo enforces its own vocabulary. `tools/house_check.py` fails on the
GLOSSARY anti-terms anywhere (the refutation form, "not immutable", is
allowed), on em dashes in the front-door files (README, SECURITY,
CONTRIBUTING, CHANGELOG, CODE_OF_CONDUCT), and on overclaim words there
("prove", "guarantee", "always"); elsewhere those words only warn. CI runs
exactly this command, so passing it locally is passing CI:

```
python tools/house_check.py
```

The Markdown has two more checks, and they run in CI only: markdownlint
(rules in `.markdownlint.yml`) and lychee, the link checker (exclusions and
their reasons in `lychee.toml`; it also runs weekly, so a link that dies
quietly still gets noticed). Neither needs anything installed here.

## The voice rule

Drafts may come from anywhere: a person, an agent, a template. Every sentence
on the front door (README, SECURITY, CONTRIBUTING, CHANGELOG, CODE_OF_CONDUCT)
is the author's, and README edits are reviewed on that basis. A pull request
that rewrites front-door prose is taken as a draft, not merged as written.

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

## Releases

Every promotion of `dev` to `main` gets a tag and a GitHub release carrying
`loxodonta.py`, `supervisor.py`, and a `SHA256SUMS` file over both, so a
person can check the file they downloaded against what was published
(ADR-0022). The tool version is semantic and decoupled from the receipt
format, which stays at `0.1`. The ritual, in order:

1. Branch a throwaway `promote/<date>` from `dev` and open a pull request
   from it into `main`.
2. In that pull request, move the entries under `## [Unreleased]` in
   `CHANGELOG.md` to a new `## [x.y.z] - YYYY-MM-DD` heading, add the
   version's compare link at the bottom, and bump `TOOL_VERSION` in both
   `loxodonta.py` and `supervisor.py` to `x.y.z`. Minor per promotion;
   patch for a hotfix cherry-picked to `main`. The two files carry one
   version and the suite checks that they agree.
3. Merge the pull request once the suite and the house checker are green.
4. On `main`, tag the merge commit `vx.y.z` and push the tag:

   ```
   git tag vx.y.z && git push origin vx.y.z
   ```

5. CI takes it from there (`.github/workflows/release.yml`): it checks the
   tag against `TOOL_VERSION` in both files, builds `SHA256SUMS`, takes the
   matching CHANGELOG section as the notes, and publishes the release with
   the three files attached. A mismatched tag or a missing section stops
   the release.
6. Check the sums once by hand. Download the three files from the release
   page into an empty folder and run:

   ```
   sha256sum -c SHA256SUMS
   ```

   On Windows, `certutil -hashfile loxodonta.py SHA256` (and the same for
   `supervisor.py`) prints each sum; compare it by eye with the line in
   `SHA256SUMS`. If a sum disagrees, the release is wrong, not the file:
   delete the release and the tag, find out why, and cut it again.

`1.0.0` waits for one export from another machine read into
`docs/FIELD-DATA.md` (ADR-0022). Until then, minor versions may change
behavior, and each CHANGELOG entry says so when they do.
