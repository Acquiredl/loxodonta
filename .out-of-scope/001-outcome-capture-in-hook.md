# Out of Scope: Outcome capture in the hook

**Date:** 2026-08-22
**Decided by:** Acquiredl

## What we're not building

> receipts' hook does not record tool outcomes — no success flags, no exit codes, no `tool_response` content. A hook ticket records what was attempted on what, never how it went.

This covers the one-bit variant too ("just a success boolean"): the hook stays entirely blind to `tool_response`.

## Why

No supervisor duty needs outcomes — verify, baseline, anchoring, and completeness monitoring all work without them; outcomes would only decorate narration. Changing the writer to prettify the reader inverts the dependency, and the hook is the code path paid on every tool call forever. An outcome flag is harness testimony (ADR-0002) that could never inform a verdict, and deriving it means guessing at per-tool `tool_response` shapes — the kind of guessing the anchoring code refuses by name. Finally, "this session is erroring" is health monitoring — observability-product territory (`docs/PRIOR-ART.md` ring 1), not flight-recorder territory. Operators who need an outcome on a critical command already have one: `receipts run` records exit codes.

## What to do with issues that match

- Close with a comment linking here.
- Point to `receipts run` as the in-scope alternative for commands whose outcome must be on the record.
- Tag `wontfix`.

## Could this ever change?

> Only on field evidence: a journaled incident where outcome-blind narration demonstrably misled an operator — not a cosmetic wish. If that happens, the one-bit flag returns to the table and gets a full ADR, because it changes what every chain on the machine records.
