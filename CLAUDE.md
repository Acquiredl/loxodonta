# loxodonta — repo map

**loxodonta**: a tamper-evident, hash-chained receipt log ("flight recorder") for AI agent pipelines. `loxodonta.py` is the recorder, and what it writes are *receipts* (ADR-0010); `supervisor.py` is the reader that scans, serves, and recalls; `receiver.py` is the far end of the published chain and the published head, run on a machine the writer cannot reach (ADR-0031). All three are stdlib-only, single-file Python. The elephant never forgets.

**Phase: public**, under the Acquiredl identity. `main` is the stable branch and every claim in the README must stay true of it; work happens on `dev` (see *Branching model*). The stage history (stages, dates, PR numbers) lives in `docs/HISTORY.md`; the changelog starts at `v0.1.0`, no backfill (ADR-0022).

## Read first

0. `docs/DIRECTION.md` — where the project is going and what it declines: the recipient first, a vertical complete or not counted, the four gates to 1.0, the supervisor's ceiling. Check a plan against it before building. `docs/GROUNDING.md` holds the published work it stands on, and what the design can and cannot claim.
1. `docs/GLOSSARY.md` — the vocabulary is settled; use it exactly (note the anti-terms: no "blockchain", no "immutable", no "audit log").
2. `docs/SPEC.md` — format spec v0.1-draft. The canonical-JSON rules in §4 are the load-bearing part.
3. `adrs/0001-hash-chain-not-signatures.md` — why no keys, and why anchoring (not signatures) closes the owner-rewrite gap.
4. `adrs/0002-writer-as-adversary.md` — the threat model: the agent writing the log is the adversary; drove head records, the `run` wrapper, and the completeness principle.

## Where things live

- `loxodonta.py` — the recorder: `init` / `log` / `run` / `head` / `verify` / `verify-package` / `report` / `anchor` / `publish` / `stamp` / `hook` / `explain` / `install-hook` / `uninstall-hook`.
- `supervisor.py` — the reader: `scan` / `calibrate` / `serve` / `adopt` / `drill` / `digest` / `show` / `search` / `timeline` / `verify` / `mcp` / `export` / `package`.
- `receiver.py` — the receiver: `serve`, one verb; the URL that can only add, never delete (ADR-0031, `docs/RECEIVER.md`).
- `adapters/` — per-harness recorder adapters (ADR-0020).
- `tools/` — repo tooling; `house_check.py` enforces the vocabulary.
- `tests/` — the suite, through the public CLI: `python -m unittest discover -s tests`.
- `docs/` — GLOSSARY, DIRECTION, GROUNDING, START, TOPOLOGY, SPEC, HOOK, ANCHORING, PACKAGE, RECEIVER, METRICS, MCP, OWASP, FIRE-DRILL, EXPERIMENTS, FIELD-DATA, the tours, HISTORY.
- `adrs/` — decisions that are hard to reverse; `.out-of-scope/` — what was deliberately not built.
- The store: `~/.loxodonta/receipts/<project-slug>/`, one drawer per project (ADR-0011, `docs/HOOK.md`).

## Constraints

- Python stdlib only for the core tool — no dependencies, ever. (Anchoring vendors nothing: ADR-0003 chose a minimal in-file OpenTimestamps subset.)
- Single-file `loxodonta.py`, readable top-to-bottom by a non-expert. Readability outranks cleverness everywhere in this repo. `adapters/` holds per-harness spoons, not tools: each is stdlib-only, imports its SDK only if present, and speaks to the recorder solely through `loxodonta hook` (ADR-0020). Single-file is a security property as well as a readability one: a directly run script is compiled from source every time, while an imported sibling can be swapped through its bytecode cache with its checksum unmoved, so nothing here imports anything (ADR-0035, which also rules how the recipient's `verifier.py` is copied out of the recorder).
- Tests verify behavior through the public CLI surface, not internals.

## Branching model

`main` is the stable branch: everything on it is walked, tested, and honest to the README's claims. Additions and experiments happen on `dev`; feature branches PR into `dev`; `dev` merges to `main` only at stable milestones (suite green, docs true, claims checked). Hotfixes to `main` are the exception and get cherry-picked back to `dev`. Default branch stays `main` so visitors land on stable.
