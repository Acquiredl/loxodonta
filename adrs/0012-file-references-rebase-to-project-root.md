# ADR-0012: File references are relative to the project root (SPEC §3 amendment)

**Status:** accepted 2026-08-29 (grilled with ADR-0011; SPEC text change
lands with the implementing slice, so the spec never describes behavior
the tool does not yet have)

## Context

SPEC §3 v0.1 makes file references relative to **the log's directory**
and rejects paths that reach outside it — "a file outside the log's
directory usually means the log is in the wrong place." That rule was
written for the manual workflow, where `receipts.jsonl` sits at the
project root and every project file is beneath it.

The hook broke the rule's assumption silently: it writes logs into
`<repo>/receipts/`, so **every file an agent touches is outside the
log's directory, and the hook skips them all**. Verified in the field
during the grill (2026-08-29): a live session's chain held 21
Edit/Write receipts and zero file references. Hook-recorded sessions
have never fingerprinted a file — the README's "every receipt
fingerprints the files it touched" and the `verify --files` production
story were true only for hand-logged chains. ADR-0011's central store
would have made the gap permanent: a chain in `~/.loxodonta` can never
reach its project's files by log-relative paths.

## Decision

> **The reference base becomes the project root.** A file reference's
> path is the file's forward-slash path relative to the project the
> chain records, not to the log's location. Everything else in §3 —
> forward slashes normalized on intake, no absolute paths, no `..`,
> byte-exact identity, sorted within the entry — is unchanged, and the
> entry schema and hashing are untouched. SPEC becomes **v0.1.1** with
> the amendment stated.

Resolution at verify time:

- A store chain resolves references through its subfolder's
  **project record** (`project.json`, ADR-0011) — the recorded
  project path is the base. A missing or dangling record degrades
  honestly: `verify --files` reports that references cannot be
  resolved, distinct from "file diverged".
- A local chain (the quickstart's `receipts.jsonl` at the project
  root) resolves against its own directory — which *is* the project
  root, so the old rule and the new rule agree byte-for-byte there.

## Why this is compatible with the freeze

The freeze protects the entry schema, canonical form, and hashing —
none move; an amended chain hashes identically to a v0.1 chain. The
amendment changes only what the path *means* to `verify --files`. And
no existing chain changes meaning: manual logs sit at project roots
where both rules coincide, and hook chains carry empty `files` arrays
(the bug this ADR fixes), so there is nothing to misresolve. The
freeze was declined twice for convenience (ADR-0005, ADR-0009); it
bends here because a flagship claim was silently false for the primary
integration — necessity, not convenience.

## Consequences

- The hook starts fingerprinting: `file_path`/`notebook_path` inputs
  are recorded relative to the resolved project root. The Production
  claim ("the report that passed review vs the report on disk") becomes
  true for hook-recorded sessions for the first time.
- `verify --files` gains project-record resolution and the honest
  "cannot resolve" report.
- SPEC §3 text updates to v0.1.1 in the implementing slice; README
  claims stay as they are (they finally become accurate).
- Files outside the project (a hook edit to `~/.claude/settings.json`,
  say) remain unreferenced — the boundary moved from "the log's
  folder" to "the project", not to "the machine".

## Alternatives considered

- **Keep the rule, soften the claims** — rejected: it quietly guts the
  Production use case for the primary integration and demotes
  `verify --files` to a manual-workflow feature.
- **Move hook logs to the project root** so the old rule works —
  rejected: clutters every repo, breaks discovery, and dies again the
  moment chains centralize (ADR-0011).
- **Record absolute paths in entries** — rejected by §3's own
  reasoning, which stands: absolute paths leak machine layout into a
  log that may be shown to others, and the project record already
  carries the machine-specific part exactly once, as testimony.
