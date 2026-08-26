# Out of Scope: File checks in the supervisor's tick

**Date:** 2026-08-25
**Decided by:** Acquiredl

## What we're not building

> The supervisor's scan never passes `--files` to `receipts verify`. The tick judges chains; file divergence is a question the operator asks deliberately, per chain, with `receipts verify --files`.

This covers the frontend consequence too: the status band carries no FILES-DIVERGED tier, because the scan cannot produce that verdict and a tier nothing can earn is dead display code (an unexpected verdict falls to the "refused" tier, which fails loud).

## Why

Files changing after a session ends is the normal course of a working machine, not a signal: a chain from last week fingerprints a file as it was then, and every legitimate edit since would report MODIFIED-SINCE-LOGGED — a permanent exit-2 siren on essentially every chain that references anything under active development. A siren that never stops sounding trains the operator to ignore the band (the dogfood's ratified lesson; the same reasoning keeps anchor staleness quiet). Chains are append-only by contract, so any change to them is signal; files are mutable by design, so continuous file watching imports the noisy half of the Tripwire/AIDE domain — the tools the Baseline is named after, scarred by exactly this failure mode. And `receipts verify` itself makes `--files` opt-in: the supervisor speaking the CLI's own default is the canon-consistent posture.

## What to do with issues that match

- Close with a comment linking here.
- Point to `receipts verify --files --log <chain>` as the in-scope way to ask the file-divergence question about a specific chain.
- Tag `wontfix`.

## Could this ever change?

> On a pipeline-shaped use case: a root where chains fingerprint *deliverables* that must not drift after logging (the Acu-style "the report that passed review" case). That earns an **opt-in** `--files` flag on `scan` — never a default — and the PR that adds it must also fix the verdict parse in `supervisor.verify()` (the last-line read breaks when FILES-DIVERGED prints before the anchor lines; a tripwire comment sits at the parse site) and restore the frontend tier removed with this decision.
