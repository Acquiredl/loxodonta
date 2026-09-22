# ADR-0022: The tool gets a version, a tag, and a release; 1.0 waits for field data

**Status:** accepted 2026-09-03 (presentation-arc grill, issue #119; ratified by worked example: promotion, hotfix, outside export that holds, outside export that fails); ruling 6 amended 2026-09-21 (direction grill, restate-to-ratify passed; see the addendum)

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
   event. *(Amended 2026-09-21: this gate stands, as the third of
   four. See the addendum below.)*

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

## Addendum, 2026-09-21: 1.0 is four gates, and someone who is not the author passes two of them

Ruling 6 was written for an operator's tool, so its one gate is the
operator's: the recorder held on a machine that is not the author's. The
direction grill of 2026-09-20 and 2026-09-21 ruled that when the
project's goals pull apart the recipient wins, and everything it ruled
after that (a vertical that is complete or does not count, a contract
for the second record, a verifier copied out of the recorder by
ADR-0035) sits outside that gate. Semantic Versioning, which the
changelog follows, says what the number is for: "Version 1.0.0 defines
the public API." So 1.0 is a promise about contracts and not about
features, and the open question was which contracts, and promised to
whom.

> **1.0 is the point where every contract a recipient depends on is
> frozen, and each has been exercised by someone who is not the author.
> Four gates, all of them required:**
>
> 1. **The verifier.** `verifier.py` exists as ADR-0035 rules it, the
>    conformance vectors exist and pass on both files, the walk refuses
>    a duplicate key and a wrong-typed field by name, and the SPEC
>    states every property the verifier relies on, the sidecars and the
>    package included, beside the list of what this design cannot claim.
> 2. **The second-record contract at `/1`.** The format starts as
>    `loxodonta-second-record/0`, provisional, and freezes only with two
>    producers behind it: Claude Code's transcript and one more vertical
>    that is complete (capture, a second record the witness reads, a
>    commitment to the rich record, a package). The grill named that
>    vertical: LangGraph, carrying a real recurring workload.
> 3. **The recorder held elsewhere.** Ruling 6 as it stood: one export
>    from another machine read into `docs/FIELD-DATA.md`.
> 4. **One recipient, unaided.** Someone who is not the author and has
>    had nothing explained is handed a package, `verifier.py` and the
>    docs, and reaches the verdict the author reached.

Ratified restatement: *the four gates block 1.0. 1.0 promises the
recipient, and anyone who builds on loxodonta, that the contracts they
depend on will not break: the verifier's verdicts, the package format,
and the second-record format. Each one was exercised by someone other
than the author before it froze. Until all four gates hold the version
stays 0.9.x, however long that takes, and features and more
compatibility come after.*

What the promise covers: the verdict words and exit codes of `verify`
and `verify-package` (SPEC section 6; GLOSSARY, *States and
transitions*), the package format (`loxodonta-package/1`), and the
second-record format once it reads `/1`. The chain format has been
frozen at `0.1` since the first chain and is promised already. The hook
payload has been a public contract with more than one producer since
ADR-0020, and is no gate here.

Where each gate comes from. Gate 2 is the practice of never freezing an
interface on a single implementation, which the IETF writes down as two
independent, interoperable implementations before a specification
advances (RFC 2026 section 4.1.2, cited from general knowledge). Gate 4
is the ACPO Good Practice Guide's third principle used as an acceptance
test: an independent third party should be able to "examine those
processes and achieve the same result" (v5, section 2.1, verified in the
grill's research pass). It is the recipient's twin of the reader test
issue #135 already carries for the front door.

The order that follows: `0.8.0` ships what `dev` already holds. `0.9.x`
is the foundation (the verifier arc of ADR-0035, the SPEC's growth, the
witness split from its reader, the `/0` format) and then the second
vertical, for as long as that takes. Pre-1.0 semantics stand for all of
it: a minor bump may change behaviour and the changelog says so. After
1.0, or in another repository: more verticals, the dashboard, recall's
growth, the incident-review service, a second record for Claude Code
that is out of the writer's reach, a receipt written before the call
runs.

A lighter reading was weighed and declined: ship 1.0 with `/0` still
provisional and freeze `/1` in 1.1. The completeness reading is the one
thing in this project the published work names as missing and nobody
supplies, and a 1.0 whose flagship contract is still provisional would
undersell exactly that. If the second vertical stalls, that lighter
reading is the amendment to reach for, and it was named here first.

When `verifier.py` exists it joins the files ruling 4 attaches to a
release and the version test ruling 3 implies, and gate 4 gets its own
issue; issue #135 already carries gate 3.

## References

- ADR-0015 (the recorder notice; never self-update)
- SPEC §2.1 (format versioning and the new-chain rule)
- ADR-0021 (field-data export, the 1.0 gate's event)
- Issue #119 (presentation arc)
- ADR-0035 (the verifier the first gate names); ADR-0020 (the hook
  payload as a public contract); GLOSSARY, *Witness* and *Second
  record* (the second gate's terms)
- Semantic Versioning 2.0.0, item 5; RFC 2026 section 4.1.2; ACPO Good
  Practice Guide for Digital Evidence v5, section 2.1
- Discussion: the direction grill, 2026-09-20 and 2026-09-21
