# loxodonta — repo map

**receipts**: a tamper-evident, hash-chained activity log ("flight recorder") for AI agent pipelines. Stdlib-only Python CLI. The elephant never forgets.

**Current phase: public.** The repo is live under the Acquiredl identity; `main` is the stable branch and every claim in the README must stay true of it; additions happen on `dev` (see *Branching model*). Issue #25 (the HITL readability walk + adversary pass + dogfood handover) continues in the open as the release ritual.

**Stage D history:** The dogfood closed early on 2026-08-21 (verdict: **push forward**). Stage D was grilled and ratified 2026-08-22 (ADR-0005) and **built the same day**: `supervisor.py` is a sibling stdlib-only single file driving receipts through the public CLI — slices 1–11 merged (PRs #27, #29, #30, #28; suite at 201). It scans and serves (localhost only): recall front page with free-text search (GLOSSARY: *Recall*, testimony-labeled), status band with verdict tiers, baseline tripwire (scan exit 5), the completeness alarm over the transcript witness (flagship claim, exit 6; ratified state machine from the #15 prototype), anchor keeper with opt-in `--anchor-every` cadence, WebCrypto chain walker, and the fire-drill surface (`docs/FIRE-DRILL.md`). Security claim unchanged: *a tripwire with a memory* — detection latency only; anchors stay the only hard boundary. The hook stays outcome-blind (`.out-of-scope/001`). Standing question: witness calibration (the transcript witness counts tool events the hook may never see).

Stages A–C are implemented and merged (2026-08-13); SPEC v0.1 and ADR-0001/0002/0003 are `accepted`; the format is frozen. Sessions are recorded machine-wide: `python dogfood.py install-global` wires the `PostToolUse` hook into `~/.claude/settings.json`, and every Claude Code session writes per-session chains into that project's `receipts/` (auto-created, auto-gitignored; sessions run in a worktree log to the main repo, since worktrees get pruned). `python dogfood.py status` reads every chain across every repo, not just this one. The experiment's journal lives operator-side (the driver is `dogfood.py`; `DOGFOOD.md` is a local, gitignored journal — recording continues even though the experiment has concluded). Code changes still go tests-first through the public CLI.

## Read first

1. `GLOSSARY.md` — the vocabulary is settled; use it exactly (note the anti-terms: no "blockchain", no "immutable", no "audit log").
2. `docs/SPEC.md` — format spec v0.1-draft. The canonical-JSON rules in §4 are the load-bearing part.
3. `adrs/0001-hash-chain-not-signatures.md` — why no keys, and why anchoring (not signatures) closes the owner-rewrite gap.
4. `adrs/0002-writer-as-adversary.md` — the threat model: the agent writing the log is the adversary; drove head records, the `run` wrapper, and the completeness principle.
5. Public-positioning claims are governed by the operator-side prior-art survey (not in this repo): show our claims, avoid naming others unless necessary, never overclaim.

## Roadmap

- **Stage A** *(done)* — spec review → stdlib-only CLI (`init` / `log` / `run` / `head` / `verify` / `report`), tamper-demo tests (edit / delete / reorder / splice / regenerate each caught), golden fixture pinning canonicalization.
- **Stage B** *(done)* — `receipts anchor`: OpenTimestamps commitment of the chain head to Bitcoin (minimal in-file OTS subset, ADR-0003, `docs/ANCHORING.md`); `verify --anchors` judges proofs offline.
- **Stage C** *(done)* — Claude Code `PostToolUse` hook adapter (`receipts hook`, `docs/HOOK.md`) + `receipts explain` (LLM narration via external command, default `claude -p`).
- **Stage D** *(built 2026-08-22, ADR-0005)* — reader-side supervisor + frontend: `supervisor.py`, stdlib-only sibling file; recall front page + search, verdict tiers, baseline tripwire, completeness alarm, anchor keeper + opt-in auto-anchor, WebCrypto walker, fire drill. Slices 1–11 merged; slice 12 (issue #25, HITL: readability walk + adversary pass + dogfood handover) is the remaining gate.
- **Public since 2026-08** — positioning discipline governs (operator-side survey); the go-public opsec review happened (author scrub + dev-doc purge, 2026-08-26).

## Constraints

- Python stdlib only for the core tool — no dependencies, ever, for Stage A. (Anchoring in Stage B may vendor an OpenTimestamps client; that gets its own ADR.)
- Single-file `receipts.py`, readable top-to-bottom by a non-expert. Readability outranks cleverness everywhere in this repo.
- Tests verify behavior through the public CLI surface, not internals.
- This repo will be public under the **Acquiredl** identity (repo-local git config is set; noreply email). Keep all personal identifiers out of this repo; Acquiredl identity only.

## Branching model

`main` is the stable branch: everything on it is walked, tested, and honest to the README's claims. Additions and experiments happen on `dev`; feature branches PR into `dev`; `dev` merges to `main` only at stable milestones (suite green, docs true, claims checked). Hotfixes to `main` are the exception and get cherry-picked back to `dev`. Default branch stays `main` so visitors land on stable.

## Git autonomy

**Level:** commit — auto-commit at logical breakpoints; push/PR/merge always ask. Rationale: solo greenfield project, fast iteration wanted, but nothing leaves the machine without explicit say-so (public-portfolio repo; opsec review happens before any push).
