# ADR-0004: Serialize the hook's appends, and never stop recording

**Status:** `proposed`
**Date:** 2026-08-14
**Deciders:** Acquiredl

## Context

SPEC §8 rules concurrency out: *one writer per log; two processes appending simultaneously is corruption, not a supported mode.* Parallelism is handled by giving each writer its own chain — `receipts-<session>.jsonl`.

Stage C keyed those chains by `session_id`. That is the wrong grain. The glossary defines a **writer** as *the process that appends entries* — and a Claude Code session issues tool calls in parallel, with the harness firing one hook process per call. A single session therefore has many writers appending to one log, routinely. The spec was satisfied on paper and violated in practice, because "session" was read as a synonym for "writer" and it is not.

The dogfood caught it on 2026-08-14, in this repo's own chain: entries 0–7 intact, line 8 a torn fragment carrying entry 7's timestamp — two hook processes writing in the same second. `verify` named the line and refused to extend it.

The refusal is correct (ADR-0002: no repair command). Its consequence is not: because `append_entry` will not append past a damaged tail, **the session stopped recording, silently, for the rest of its life.** For a tool whose entire value proposition is completeness, a fault that quietly ends the recording is worse than the tear that caused it.

`append_entry` reads the tail, computes `n` and `prev`, then appends, with no mutual exclusion. Two faults live in that gap: a **torn line** (observed) and a **forked chain** — two entries claiming the same `n` (not yet observed, equally reachable).

## Decision

> We serialize appends with an exclusive lock file per log, and — when a log's tail is already damaged — start a **new sibling chain** rather than refusing to record.

Two parts, one fault domain:

1. **Lock.** `append_entry` holds an `os.open(log + ".lock", O_CREAT | O_EXCL)` lock across read-tail-then-append. It retries with backoff; it breaks a lock whose recorded holder is provably gone; on timeout it **fails loudly** rather than dropping the entry.
2. **Sibling on damage.** Finding a damaged tail, the hook repairs nothing, trims nothing, appends nothing. It starts `receipts-<session>-002.jsonl` and records there. The damaged chain is preserved byte-for-byte as evidence.

Part 2 is what keeps part 1 honest: a lock reduces the odds of damage but cannot reach damage that already exists, and "stop recording" is not an acceptable response to either.

No format change. No new fields. v0.1 stays frozen.

## Consequences

**What gets easier:**

- Parallel tool calls stop corrupting chains — the common case is correct with no operator ritual.
- A session's history survives its own faults: damage ends a chain, not the recording.
- Stays stdlib-only and single-code-path across platforms; `O_EXCL` behaves on Windows, which the `fcntl`/`msvcrt` split does not.

**What gets harder or more constrained:**

- Every tool call now contends for a lock. The hook sits in the harness's hot path; latency here is paid on every action, forever.
- A stale lock is a new class of bug — and the crash that strands one is exactly the crash that tears a line.
- Loud failure on timeout means the hook can fail a tool call. Deliberate: a silently missing receipt is precisely what this tool exists to prevent, so the noisy failure is the correct one (ADR-0002, completeness).
- A session may now span several chains. `report`, `anchor`, `verify --expect-head`, and `dogfood status` must treat `-002` as continuation, and **each chain anchors separately** — the operator's head-record ritual now has more than one head per session to hold.
- The lock is writer-reachable, so it is **not** a security boundary. It prevents accidents, not adversaries — and an adversarial writer was never going to be stopped by a lock file (ADR-0002).

**What we'll have to revisit if:**

- The harness ever guarantees serialized hook execution — the lock becomes dead weight.
- Chains move off a shared filesystem — a lock file assumes one.
- Sibling-on-damage proves common rather than rare, which would mean the lock is not doing its job and the grain is still wrong.

## Alternatives considered

- **One chain per hook process** — follows SPEC §8 to the letter, and is absurd in practice: a hook process is a single tool call, so this yields two-entry chains and destroys the session as the unit of history.
- **`fcntl.flock` / `msvcrt.locking`** — rejected: a platform fork inside a deliberately single-file, readable-top-to-bottom tool. Windows portability has already cost this repo three bugs in one day; `O_EXCL` is one path everywhere.
- **A resident writer daemon serializing appends** — rejected: a background process contradicts the stdlib-only, nothing-to-install premise.
- **Optimistic retry without a lock** (re-read the tail, re-append on conflict) — rejected: it can resolve a fork but not a tear. By the time the conflict is visible, the torn bytes are already on disk.
- **Let `verify` tolerate torn tails and heal them** — rejected outright. ADR-0002 refuses a repair command because a sanctioned way to trim a tail is exactly the capability an adversary with a "crash" cover story wants. That reasoning is unchanged; this ADR routes *around* damage instead of erasing it.

## References

- Related ADRs: `0002-writer-as-adversary.md` — supplies the no-repair constraint and the completeness principle this decision is bounded by; `0001-hash-chain-not-signatures.md`.
- **Spec amendment required:** `docs/SPEC.md` §8 "No concurrency" currently says sharing a log is unsupported and stops there. It must state that the Stage C hook *enforces* one-writer-at-a-time on a shared session chain, and that a session may span sibling chains. The entry format is untouched.
- Glossary terms **sharpened**: *Writer* — "one writer per log" reads as satisfied by one chain per session; it must say the writer is a **process**, and that one session has many.
- Glossary terms **retired**: none. No topology is overruled — the session-keyed chain survives; only its concurrency assumption is corrected.
- Discussion: the dogfood, 2026-08-14 — the first fault this tool caught in the field rather than in a drill.
