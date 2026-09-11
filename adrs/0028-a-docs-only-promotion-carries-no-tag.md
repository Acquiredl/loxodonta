# ADR-0028: A promotion that does not move the tools carries no tag (ADR-0022 amendment)

**Status:** accepted 2026-09-11 (ruled by the author on the START.md promotion)

**Deciders:** Acquiredl

## Context

ADR-0022 ruling 4 reads: "Every promotion to `main` gets a tag and a
GitHub release. The release attaches `loxodonta.py`, `supervisor.py`,
and a `SHA256SUMS` file... Minor version per promotion; patch for a
hotfix cherry-picked to `main`." Four promotions have followed it, and
the release workflow enforces it from the other side: the tag has to
match `TOOL_VERSION` in both files, and the release notes have to be
the matching changelog section, or the release does not happen.

The ruling was written during the presentation arc, where every
promotion carried code. The case it did not consider arrived with
`docs/START.md`: a promotion whose whole content is a page, with both
tools byte-for-byte what `v0.4.0` already published.

Following ruling 4 literally there means cutting `v0.5.0`, bumping
`TOOL_VERSION` in two files that changed in no other way, and
publishing a release whose `SHA256SUMS` covers the same code under new
sums. A reader comparing `v0.4.0` and `v0.5.0` would find the version
string and nothing else. That is the version number saying something
untrue about the thing it names.

ADR-0022 ruling 3 says what the number is for: "The tool version says
which recorder and supervisor a person is running; the format version
says which chains it can read." A page is neither.

There is a second reason, and it is the operator's. `docs/START.md`
step 1 tells a stranger to check the two files against the `SHA256SUMS`
attached to the release. Every extra release for a code change that did
not happen is one more set of sums over identical bytes, and one more
chance for the page and the releases list to disagree about which
download is current.

## Decision

1. **A promotion to `main` that changes neither `loxodonta.py` nor
   `supervisor.py` carries no tag and no release.** It is an ordinary
   merge of `dev` into `main` through a `promote/<date>` branch, with
   the same pull request and the same required checks as any other.
2. **ADR-0022 ruling 4 is amended to say so**, and is otherwise
   unchanged: a promotion that moves either tool still gets a minor
   version, a tag, and a release, and a hotfix cherry-picked to `main`
   still gets a patch.
3. **The changelog still records the change, under `Unreleased`.** It
   ships with whatever version comes next, which is Keep a Changelog's
   own answer and needs no exception.
4. **`docs/HISTORY.md` is untouched by such a promotion.** It carries
   stages, and a page is not one. The stage that eventually names
   `START.md` will be written by the promotion that releases.

The test is mechanical, not editorial: `git diff` over the two files
between `main` and the promotion. Anything else in the tree, the
adapters and `tools/` included, is documentation or repo tooling for
this purpose, because neither is what `--version` names and neither
ships on a release.

## Consequences

**What gets easier:**

- The version number keeps meaning what ruling 3 says it means. A bump
  is a claim that the recorder changed, and it stays a true one.
- Documentation reaches `main` at the speed documentation should. The
  reason `START.md` needed promoting at all was to make a link work
  before it was handed to anyone, and a release ritual is a poor thing
  to stand between a typo and its fix.

**What gets harder or more constrained:**

- `main` now carries commits that no tag names, so "which release am I
  looking at" and "what is on `main`" can differ by a page. The README
  already says `main` is the stable branch and the releases page is
  where downloads come from, and those two sentences now do real work.
- Whoever writes the next release notes has to look at `Unreleased`
  rather than at the commits since the last tag, because the two are
  no longer the same set.

**What we'll have to revisit if:**

- A documentation change turns out to be the kind a stranger needs a
  download to act on. Nothing in the repo works that way today: the
  docs a release carries are the ones inside the two files, in their
  `--help` output.
- The adapters under `adapters/` ever ship on a release. They do not
  today, which is why they sit on the documentation side of the test
  above. If that changes, so does the test.

## Alternatives considered

- **`v0.4.1`, a patch.** Reads honestly on the releases page: nothing
  in the tool changed. But it still bumps `TOOL_VERSION` in two files
  to describe a page, and ADR-0022 reserves patch for the hotfix path,
  where it carries a real meaning. Rejected.
- **Hold the page until the next code promotion.** Costs nothing in
  ritual and the whole point of the page was a link that works now.
  Rejected.
- **Leave ruling 4 alone and cut `v0.5.0`.** The literal reading, and
  the reason this ADR exists rather than a quiet exception. A ratified
  ruling should be amended in the open or followed. Rejected on the
  merits above, amended here rather than ignored.

## References

- ADR-0022 (the tool gets a version, a tag, and a release; ruling 4
  amended, rulings 1, 2, 3, 5 and 6 unchanged)
- ADR-0015 (the recorder notice; the tool reports its version and never
  fetches a newer one)
- `.github/workflows/release.yml` (the tag-matches-`TOOL_VERSION` gate,
  unchanged: it runs on a tag, and this promotion pushes none)
- `docs/START.md` (the promotion that raised it)
