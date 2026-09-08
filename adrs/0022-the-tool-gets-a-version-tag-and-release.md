# ADR-0022: The tool gets a version, a tag, and a release; 1.0 waits for field data

**Status:** accepted 2026-09-03 (presentation-arc grill, issue #119; ratified by worked example: promotion, hotfix, outside export that holds, outside export that fails)

**Deciders:** Acquiredl

## Context

The receipt format has a version (`v: "0.1"`, frozen by SPEC §2.1), the
SPEC document has one (0.1.2), and the export has one (`EXPORT_VERSION`).
The tool itself has none. The recorder notice (ADR-0015) and the export
identify the recorder by its git commit, which is exact and useless to a
stranger: a bug report cannot say "which version", a changelog cannot
be read against a hash, and a release page has nothing to point at.

The presentation arc drops the README's "work in progress" banner and
lets a badge row, a tag, and one sentence carry status instead. That
sentence, "everything on `main` is walked and tested", needs a number a
reader can cite back. Every popular repo in the adjacent spaces surveyed
for the arc (gitleaks, trufflehog, cosign, the OpenTimestamps client)
carries semantic-version tags; none carries a commit as its version.

The `main` branch already has a milestone ritual: `dev` promotes to
`main` at stable points (eight times so far), through a throwaway
`promote/<date>` branch. A tag at each promotion costs nothing new.

## Decision

1. **The tool is versioned with semantic versioning, decoupled from the
   format.** The format stays `0.1` and frozen; a format change still
   requires a new format version and a new chain (SPEC §2.1). The tool
   version says which recorder and supervisor a person is running; the
   format version says which chains it can read. They move
   independently.
2. **The first tag is `v0.1.0`**, cut from the promotion that lands the
   presentation arc. The number does not try to encode the eight
   promotions before it; the ADRs and CLAUDE.md are that history.
3. **`--version` prints all three identities**: tool version, format
   version, and the recorder's git commit when the file sits in a
   checkout (the same fact the recorder notice reports). The version
   string lives in one constant in each file.
4. **Every promotion to `main` gets a tag and a GitHub release.** The
   release attaches `loxodonta.py`, `supervisor.py`, and a `SHA256SUMS`
   file; the README's Install heading tells the reader to check the
   sum. Minor version per promotion; patch for a hotfix cherry-picked
   to `main`.
5. **`CHANGELOG.md` starts at `v0.1.0`, in Keep a Changelog form, with
   no backfill.** One entry per release, written from the promotion
   PR.
6. **`1.0.0` is gated on one export from another machine read into
   `docs/FIELD-DATA.md`.** "Stable on `main`" means walked and tested
   here; 1.0 means the recorder held somewhere that is not the
   author's machine. The community order already waits for the same
   event.

The recorder notice's rule stands: the tool reports which version is
running and never updates itself (ADR-0015). A version number is a
label on the file, not a channel to fetch a newer one.

## Consequences

**What gets easier:**

- Bug reports and field-data exports can name a version. The export's
  `recorder_commit` field keeps the exact commit beside it.
- The README can say "stable" and point at the thing that proves it.
- Release assets give a stranger a download that is not "clone the
  repo and hope `main` is where I think it is".

**What gets harder or more constrained:**

- Two files, one version: `loxodonta.py` and `supervisor.py` are tagged
  together and must agree. A change to one bumps both.
- The `SHA256SUMS` file is a claim the release must keep true; a
  release edited after publication breaks its own sums, which is the
  point.
- Pre-1.0 semantics: minor bumps may change behavior. The changelog
  says so per entry.

**What we'll have to revisit if:**

- Field data arrives and the recorder does not hold: 1.0 waits, and
  the gate stays honest by having been stated in advance.
- The format ever leaves 0.1: the tool version and the format version
  then differ visibly, which is the reason they were decoupled.

## Alternatives considered

- **Calendar versioning** (`2026.09.0`): honest about "the version is
  the promotion date", but carries no compatibility signal, and the
  format version already owns compatibility. Rejected.
- **Commit as version** (status quo): exact, unreadable, no changelog.
  Kept as the third field of `--version`, rejected as the public
  version.
- **A starting number that reflects prior promotions** (`v0.8.0`):
  arbitrary to a reader who was not here. Rejected.
- **Tool version tied to the format version** (`0.1.x` forever until a
  format change): would make every tool release look like a patch and
  a format change look like a tool rewrite. Rejected.

## References

- ADR-0015 (the recorder notice; never self-update)
- SPEC §2.1 (format versioning and the new-chain rule)
- ADR-0021 (field-data export, the 1.0 gate's event)
- Issue #119 (presentation arc)
