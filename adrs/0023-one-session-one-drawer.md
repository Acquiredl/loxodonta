# ADR-0023: Every receipt of a session goes to one drawer, the one its first receipt chose (ADR-0011 amendment)

**Status:** accepted 2026-09-08 (grilled, issue #153; restated by the author)
**Deciders:** Acquiredl

## Context

ADR-0011 routes each hook receipt by resolving the project directory to a
drawer at every call: `CLAUDE_PROJECT_DIR` (or the payload's `cwd`) →
`main_repo_root` → slug. A session running in a git worktree therefore
lands in the repository's drawer, because the worktree's `.git` file leads
to `<main>/.git/worktrees/<name>/commondir` and from there to the main
checkout.

The orientation-cost measurement (EXPERIMENTS §6) found a session split
in two. It ran in a worktree from the start; 64 receipts went to the
repository's drawer. Then the harness deregistered the worktree while the
session was still running in it: the folder stayed, held open by the
session, but `<main>/.git/worktrees/<name>` was gone. The next receipt's
lookup hit a missing `commondir`, took ADR-0011's documented fallback
("anything unreadable returns the project unchanged"), hashed the
worktree's own path, and opened a second drawer with a fresh genesis. Same
session id, two chains, two drawers. `digest --repo`, `search --repo`, and
`timeline` resolve the repository to one slug and never saw the session's
tail, which held its true last tool receipt and its exit commitment. Only
`search --all` reached it.

Two facts shaped the ruling. The reader's unit is the session: the digest
groups by session, the witness counts by session, the lifecycle reading is
per session. And the harness fixes a session's project directory for its
lifetime, so a mid-session change in where a receipt resolves is, by
construction, a resolution failure and not a real move.

Prior art: the harness's own transcript is one file per session id
whatever the session does; journald keys a session's records by session,
never by the directory a process happened to be in.

## Decision

> **Every receipt of a session goes to one drawer, the one the session's
> first receipt chose.**

Three parts, in the order they act:

1. **The writer keeps the invariant.** When the hook resolves a drawer for
   a receipt and that drawer holds no chain for the session yet, it looks
   for one elsewhere in the store before opening a new one; if a chain for
   this session id exists in another drawer, the receipt goes there. In
   the normal case the resolved drawer already holds the session's chain
   and nothing extra runs; the store-wide lookup happens once per session,
   or on every call only while a resolution is failing. Drawer, not chain:
   ADR-0004's damage siblings (`receipts-<session>-002.jsonl`) stay in the
   same drawer, as before.
2. **A deregistered worktree still names its repository.** Its `.git` file
   reads `gitdir: <main>/.git/worktrees/<name>` even after that directory
   is gone. `main_repo_root` derives `<main>` from that string when
   `commondir` cannot be read, so the observed failure cannot recur even
   for a session's first receipt. Still read from the files git writes,
   never by spawning `git`; a folder with no `.git` file at all falls back
   as before.
3. **Recall for a repository also reads its harness worktree drawers.**
   `digest --repo`, `search --repo`, and `timeline` include drawers whose
   recorded project path lies under `<repo>/.claude/worktrees/`, the
   store-era twin of the legacy `repo_chains` rule ("chains stranded in
   its own worktrees, still this repo's history"). Narrow on purpose: a
   subfolder someone runs as its own project (a monorepo package) is not
   swept into its parent's digest. This is what makes a split that already
   happened visible, on this machine and on any machine that ran v0.1.0,
   since two chains cannot be joined after the fact.

## Consequences

**What gets easier:**

- A session is one drawer, so a reader who asks for a repository's
  history gets every receipt of every session that ran there, including
  the tail after a worktree was cleaned up under it.
- The recall surface's answer to "what was the last recorded action" is
  the last recorded action. The pre-registered key in EXPERIMENTS §6 was
  wrong for exactly this reason.

**What gets harder or more constrained:**

- A session whose harness sends a different `cwd` per call (the Codex and
  Agents SDK adapters send `cwd` in the payload) now follows its first
  drawer instead of the repository each call touched. Under the reader's
  unit that is the intended behaviour; it is named here so the trade is on
  record.
- The store-wide lookup is a directory listing plus one stat per drawer,
  and it runs only when the resolved drawer has no chain for the session.
  A store with hundreds of drawers pays that once per session.
- ADR-0012 is unchanged: file references stay relative to the drawer's
  recorded project root, so a pruned worktree's references become
  unresolvable exactly as they do today.

## Alternatives considered

- **Fix only the resolution (part 2 alone).** Closes the observed case,
  leaves any other mid-session resolution flip free to split a session.
  Rejected: the invariant is what readers already assume.
- **Tag the fallback drawer with the repository it served.** The writer
  did not know the repository at the moment it fell back; that is why it
  fell back. Rejected as unable to fix the observed case.
- **Broad reader inclusion (any drawer under the repository's tree).**
  Complete, but sweeps a deliberately separate sub-project into its
  parent's digest. Rejected for the narrow rule with a precedent.
- **Merge the two existing chains.** A hash chain cannot be joined after
  the fact without rewriting it, which is the one thing this tool exists
  to make visible. The split stays as two chains; part 3 shows both.

## References

- Related ADRs: `0011-central-receipts-store.md` (amended: the write split
  now holds per session, not per call), `0004-serialize-hook-appends.md`
  (damage siblings share the drawer), `0012-file-references-rebase-to-project-root.md`
  (unchanged), `0018-session-lifecycle-reading.md` (the session as the
  reader's unit).
- Found by: `docs/EXPERIMENTS.md` §6; issue #153.
- Glossary terms **added or sharpened**: *Store* (one session, one drawer).
