# ADR-0009: The recall surface lives in the supervisor; receipts.py stays frozen

**Status:** `accepted` (2026-08-26)
**Date:** 2026-08-26
**Deciders:** Acquiredl

## Context

Stage E gives agents a recall surface: a budget-capped digest of recent history injected at session start, plus `show` / `search` / `timeline` commands for pulling detail on demand. The design was provoked by a code study of the category leader (claude-mem, ~92k stars), whose architecture validates the injection loop — memory that arrives without being asked for is the feature that makes an episodic-memory tool sticky — but implements it with a resident daemon, an observer LLM, and external storage. This repo's version is deterministic rendering over chains that are already structured, so none of that machinery is needed. The open question was where the code lives.

Three homes were possible: grow `receipts.py` (git's shape — one tool owns read and write), a third sibling `recall.py` (journald's shape — writer and reader as separate binaries), or grow `supervisor.py`. Two facts settled it:

1. **The reader already exists.** `supervisor.py` already carries `recall_root()` — a cross-repo recall reader with repo, date, and path filters — served at `/api/recall` and rendered as the testimony-labeled front page of `supervisor serve`. The operator also wants a fuller front end for navigating memory without the CLI; that grows from the same page, in the same file, under the inline-HTML pattern ADR-0005 already ratified. A third file would mean either a second HTTP server or cross-file imports, both worse.
2. **The necessity test against the freeze fails.** Nothing in Stage E needs the recorder: rendering chains is `json.loads` over the public JSONL format, and recall owns no verdicts (GLOSSARY: *Recall*), so verification stays behind `receipts verify` where it already lives. Unfreezing `receipts.py` was considered with eyes open — the operator was willing — and declined because nothing required it.

## Decision

> **Recall lives in `supervisor.py`. `receipts.py` stays frozen.** The supervisor gains an agent-facing CLI recall mode — `digest` (budget-capped, current-repo, called by the SessionStart hook), `search`, `show`, `timeline` — as new mouths on the existing `recall_root` organ. The web front end for navigating memory grows later inside `serve`, in the same file. Hook installation stays in `dogfood.py` beside the existing PostToolUse wiring.

The supervisor's role statement widens accordingly: it is the *reader* tool — one file serving two mornings, suspicion (`scan`, the alarm band) and memory (`recall`, the digest, the front page). Both readings were already in the file; this ADR names that as its shape rather than an accident.

## Consequences

**What gets easier:**

- The freeze on `receipts.py` survives a live temptation, which makes it real: the file's "done" status is now a defended claim, not an untested one.
- The future front end is an extension of an existing page, not a new tool — no new server, no new file, no new constraint-carrier.
- Digest stays fast by principle, not optimization: because recall owns no verdicts, session start spawns zero `verify` subprocesses; the digest cites the last scan's verdicts as testimony, labeled as such.

**What gets harder or more constrained:**

- `supervisor.py` (1,700 lines) absorbs Stage E and carries the readability constraint under more weight. If it stops being readable in a sitting, the split question reopens — consciously, as ADR-0005 prescribed.
- The supervisor now has two audiences (operator via HTTP, agent via stdout), and its CLI output becomes a compatibility surface for hooks and agents the way receipts' verdict lines are for the supervisor.

**What we'll have to revisit if:**

- `supervisor.py` outgrows one-sitting readability — that reopens single-file-per-tool with recall as the natural cleave line.
- The recall surface ever wants richer queries (aggregation, a query language, MCP) — deferred deliberately; shelling out must be shown insufficient first.

## Alternatives considered

- **Third sibling `recall.py` (journalctl precedent)** — rejected: the journald/journalctl split separates writer from reader, but this repo already made that cut (receipts writes, supervisor reads); a third file would cut the *reader* in half and duplicate its HTTP or its chain-walking.
- **Grow `receipts.py` (git precedent)** — rejected: adds three-plus commands and cross-chain selection to the file whose smallness and frozenness are the product's moat; ADR-0005's "no new commands" was the freeze's enforcement clause, and the necessity test that could have overridden it failed.
- **Unfreezing `receipts.py` generally for Stage E** — considered at the operator's explicit invitation, declined: convenience is not necessity.

## References

- Related ADRs: `0005-supervisor-as-sibling-tool.md` (extended: the supervisor's read-side role widens to include agent-facing recall; its revisit trigger — "a second sibling tool appears" — fired here and resolved to *no third file*); `0002-writer-as-adversary.md` (recall renders testimony and owns no verdicts); `0004-serialize-hook-appends.md` (the SessionStart hook is read-only and needs no lock).
- Glossary terms: *Recall* (unchanged, load-bearing here); *Supervisor* (role statement widened by this ADR).
- Prior art: claude-mem (injection loop and progressive disclosure validated; daemon/observer-LLM/external-storage shape rejected — see the Stage E grill), journald/journalctl (rejected shape), Go `net/http/pprof` (carried over from ADR-0005 for the inline front end).
- Discussion: Stage E recall-surface grill, 2026-08-26.
