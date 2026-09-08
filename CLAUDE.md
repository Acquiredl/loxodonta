# loxodonta — repo map

**loxodonta**: a tamper-evident, hash-chained receipt log ("flight recorder") for AI agent pipelines. `loxodonta.py` is the recorder, and what it writes are *receipts* (ADR-0010); `supervisor.py` is the reader that scans, serves, and recalls. Both are stdlib-only, single-file Python. The elephant never forgets.

**Phase: public**, under the Acquiredl identity. `main` is the stable branch and every claim in the README must stay true of it; work happens on `dev` (see *Branching model*). The stage history (stages, dates, PR numbers) lives in `docs/HISTORY.md`; the changelog starts at `v0.1.0`, no backfill (ADR-0022).

## Read first

1. `GLOSSARY.md` — the vocabulary is settled; use it exactly (note the anti-terms: no "blockchain", no "immutable", no "audit log").
2. `docs/SPEC.md` — format spec v0.1-draft. The canonical-JSON rules in §4 are the load-bearing part.
3. `adrs/0001-hash-chain-not-signatures.md` — why no keys, and why anchoring (not signatures) closes the owner-rewrite gap.
4. `adrs/0002-writer-as-adversary.md` — the threat model: the agent writing the log is the adversary; drove head records, the `run` wrapper, and the completeness principle.
5. Public-positioning claims are governed by the operator-side prior-art survey (not in this repo): show our claims, avoid naming others unless necessary, never overclaim.

## Where things live

- `loxodonta.py` — the recorder: `init` / `log` / `run` / `head` / `verify` / `report` / `anchor` / `hook` / `explain` / `install-hook` / `uninstall-hook`.
- `supervisor.py` — the reader: `scan` / `serve` / `adopt` / `drill` / `digest` / `show` / `search` / `timeline` / `mcp` / `export`.
- `adapters/` — per-harness recorder adapters (ADR-0020).
- `tools/` — repo tooling; `house_check.py` enforces the vocabulary.
- `tests/` — the suite, through the public CLI: `python -m unittest discover -s tests`.
- `docs/` — SPEC, HOOK, ANCHORING, MCP, OWASP, the tours, HISTORY.
- `adrs/` — decisions that are hard to reverse; `.out-of-scope/` — what was deliberately not built.
- The store: `~/.loxodonta/receipts/<project-slug>/`, one drawer per project (ADR-0011, `docs/HOOK.md`).

## Constraints

- Python stdlib only for the core tool — no dependencies, ever. (Anchoring vendors nothing: ADR-0003 chose a minimal in-file OpenTimestamps subset.)
- Single-file `loxodonta.py`, readable top-to-bottom by a non-expert. Readability outranks cleverness everywhere in this repo. `adapters/` holds per-harness spoons, not tools: each is stdlib-only, imports its SDK only if present, and speaks to the recorder solely through `loxodonta hook` (ADR-0020).
- Tests verify behavior through the public CLI surface, not internals.
- This repo is public under the **Acquiredl** identity (repo-local git config is set; noreply email). Keep all personal identifiers out of this repo; Acquiredl identity only.

## Branching model

`main` is the stable branch: everything on it is walked, tested, and honest to the README's claims. Additions and experiments happen on `dev`; feature branches PR into `dev`; `dev` merges to `main` only at stable milestones (suite green, docs true, claims checked). Hotfixes to `main` are the exception and get cherry-picked back to `dev`. Default branch stays `main` so visitors land on stable.

## Git autonomy

**Level:** commit — auto-commit at logical breakpoints; push/PR/merge always ask. Rationale: solo greenfield project, fast iteration wanted, but nothing leaves the machine without explicit say-so (public-portfolio repo; opsec review happens before any push).
