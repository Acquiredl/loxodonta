# ADR-0011: Chains live in one machine-wide store, not inside each repo

**Status:** accepted 2026-08-29 (grilled; issue #47)

## Context

The per-repo layout (`<repo>/receipts/`) produced a family of discovery
failures in the field: `scan --root` cannot see repos nested deeper than
its three glob shapes (#44); a session rooted at a non-repo folder
writes to an orphan `receipts/` no repo-rooted view ever finds; and
chains die with their folder — the worktree-pruning class, patched for
worktrees specifically, but the class survived. Chains are gitignored,
so "receipts belong beside the work" never actually gave collaborators
anything; it only scattered the evidence.

Prior art that shaped the ruling: the harness itself stores transcripts
centrally per munged project path (`~/.claude/projects/…`) — which is
exactly why the completeness witness works no matter where a session
ran. journald centralizes system logs away from the workloads that
produce them. The `~/.<tool>` + `TOOL_HOME` override convention is the
settled pattern for per-user tool state (cargo, docker).

## Decision

> **Every hook-written chain lives in one machine-wide store:
> `~/.loxodonta/receipts/<project-slug>/receipts-<session>.jsonl`,
> overridable via `LOXODONTA_HOME`. Repos no longer hold their own
> chains.**

The shape, as grilled:

- **Slug:** `<basename>-<8 hex of the SHA256 of the normalized full
  project path>` (e.g. `loxodonta-3f9a21c4`) — readable at a glance,
  collision-free by construction (two same-named projects can never
  share a drawer). Precedent: the harness's own worktree naming. The
  lossy harness path-munge was rejected: colliding projects would
  interleave chains in one subfolder, the one corruption a store must
  never allow.
- **Project record:** each subfolder carries `project.json`, written on
  first receipt, holding the project's real absolute path (and nothing
  load-bearing beyond it). Writer-reachable, therefore testimony —
  like everything else local. Not called a "manifest": that word is
  taken (ADR-0007).
- **Write split by workflow:** the hook resolves
  `CLAUDE_PROJECT_DIR` → `main_repo_root` → slug and writes to the
  store; worktree sessions therefore land in their main repo's drawer
  as before. The manual quickstart (`init`/`log`/`run`) keeps its
  cwd-local default — the sandbox stays touchable, which *is* the
  demo. `--log`/`--log-dir` override either.
- **Read side:** the store is the unnamed default universe.
  `supervisor scan` takes no arguments; `digest`/`--repo` resolve
  through the same path→slug chain as the hook, so writer and reader
  agree by construction; `search --all` means the whole store.
  `--root <folder>` survives as the explicit legacy mode, scanning the
  old three shapes for pre-migration machines, foreign folders, and
  drills. `.unlisted` moves with the chains into the subfolder; same
  courtesy-not-boundary semantics.
- **Migration:** `supervisor adopt --root <folder>` — the supervisor
  already owns multi-chain discovery, so it adopts legacy chains into
  the store. Manners: move, not copy (two copies of evidence is worse
  than one); chain, anchor sidecars, and `.unlisted` travel together;
  per-chain project resolution (repo folder; a stranded worktree's
  main repo; a root-is-project orphan as itself); never overwrite —
  collisions are refused and reported; idempotent; `--dry-run` prints
  the plan; empty legacy folders are left for the operator to prune.
- **Supervisor memory:** the baseline moves to
  `~/.loxodonta/baseline.json` — beside the store, not inside it, one
  per machine. In legacy `--root` mode it stays beside that root as
  today.

## Threat model delta (ADR-0002 unchanged)

Centralizing changes the adversary's *effort*, not its *capability*:
the writer could already delete every scattered `receipts/` folder.
Detection does not weaken, and the reasoning belongs on record:

- Wiping the store leaves the baseline alive beside it — the next scan
  shouts about every vanished chain.
- Wiping all of `~/.loxodonta` mutes the baseline — and the witness
  lives at a *different address* (`~/.claude`): transcripts still show
  sessions that ran tools, and the next scan reports them chainless
  (ALARM-SILENT). The adversary must reach two unrelated locations to
  delete quietly, and still cannot reach the third:
- Anchors stay the only hard boundary, exactly as before. The
  operator ritual improves: "copy the sidecar off-machine" gains a
  simpler companion — back up one folder.

## Consequences

- `scan`/`serve`/`drill` work verbatim with no arguments — the
  newcomer's first supervisor commands stop dying on `--root` (the
  walkthrough finding), and #44 dissolves rather than being patched.
- Chains outlive their repos. The sessions most worth keeping are
  exactly the ones whose folder got deleted.
- One folder to back up, one anchor sweep, one address for a
  dashboard (#48) to read.
- File references need a base that isn't the log's directory — split
  into ADR-0012, decided in the same grill.
- Implementation lands as vertical slices on `dev`; docs and README
  claims update with the code, not before.

## Alternatives considered

- **Keep per-repo layout, patch discovery deeper** — rejected: every
  fix so far (worktree logging, worktree recall, #44's report wording)
  patched a symptom of scattering; the class outlived each patch.
- **XDG platform paths** — rejected: two documented addresses and a
  lookup dance versus one memorable address for a tool whose pitch
  includes "you can find your evidence".
- **Central store for everything including the quickstart** — rejected:
  the newcomer's first chain must be where their hands are.
- **Store + legacy swept together on every scan** — rejected: every
  tick pays a filesystem walk over layouts that are empty on any
  migrated machine, and provenance in reports gets murkier.
