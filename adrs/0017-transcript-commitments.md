# ADR-0017: Transcript commitments — the chain commits the transcript by prefix, in-band

**Status:** accepted 2026-08-31

## Context

The chain is the tamper-evident *spine* of a forensic rebuild, not the
flesh: receipts hold chronology and content-hashes, while the rich
record — tool outputs, full commands, diffs, the conversation — lives in
the harness transcript, which is writer-reachable and unprotected
(ADR-0016, consequences; issue #69). An agent that just ran a command
can open its own transcript and quietly rewrite what the output said,
and today nothing catches it. The hook payload already carries
`transcript_path`; the recorder ignores it.

Two existing mechanisms were candidates and both fail for reasons worth
recording. The anchor-sidecar pattern (ADR-0003) does not transfer:
anchor records live outside the chain safely only because they are
*self-proving* — the OTS proof replays against the head, and forging one
requires rewriting Bitcoin. A transcript-hash sidecar has no such
self-proof; it is writer-reachable and chain-unprotected, so it proves
nothing against ADR-0002's adversary. And the `files` array cannot carry
it: SPEC §3 rejects absolute paths, references resolve against the
project root (the transcript lives in the harness's own folder), and a
growing file diverges from a whole-file sha256 before anyone verifies.

Prior art consulted: **RFC 5848 syslog-sign** (signature blocks embedded
in the syslog stream itself, each committing hashes of prior messages —
the record rides the same channel it protects; direct precedent for an
in-band commitment record); **Certificate Transparency** (a growing log
is committed as `(tree_size, root_hash)`, and any two commitments at
different sizes must be consistent — our flat-file degenerate form is
`(byte_count, sha256_of_prefix)`, with monotonicity as the
consistency-lite check); **in-toto/SLSA** via ADR-0007 (a statement
about an artifact by digest works only under an outer seal, which a
per-session sidecar does not have).

## Decision

Ratified restatement: *every 25 ledger entries the elephant sniffs the
whole diary from page one — pages older than the last sniff are locked
forever; newer pages stay re-inkable only until the next sniff.*

**1. The commitment lives in the chain, as an ordinary receipt.**
`actor: "receipts"` (the recorder's own bookkeeping voice, matching
genesis), `action: "transcript-commitment: bytes=N sha256=<hex>"`,
`files: []`. No schema change — the v0.1 freeze holds, and an old
verifier reads a commitment entry as an ordinary receipt, so this is
forward-compatible by construction. The action-line grammar becomes a
small frozen surface, pinned by a golden fixture like canonicalization.

**2. The payload is a byte-prefix commitment, and nothing else.** The
hash covers the transcript from byte zero to its current end; `bytes=N`
records how far. Not lines — deciding what a line is reimports exactly
the canonical-form ambiguity SPEC §4 exists to kill. No transcript path —
the chain filename *is* the session id, which is already the pairing key
the witness uses; a recorded path is machine-specific testimony that
goes stale when the harness relocates its folder.

**3. Cadence: every 25 entries, inside the existing PostToolUse hook,
default on.** When the just-appended entry's `n` is a multiple of 25,
the hook hashes the transcript and appends one commitment entry.
Default on is ADR-0016's spirit: the recorder does not ask permission to
protect evidence; readers manage the volume. The two honesty windows are
stated wherever the feature is documented: a region of the transcript is
rewritable for at most ~25 calls, until the next commitment locks it;
and the tail after the last commitment is uncommitted until the
SessionEnd slice lands (deferred, tracked as its own issue — bounded
value, since SessionEnd fires only on clean exits, against a third
machine-wide hook event's install surface).

**4. `verify --transcript <path>` judges; the supervisor locates.**
Opt-in like `--anchors` and `--files`; verify stays layout-ignorant and
judges the file it is handed, while `supervisor scan` supplies the path
per session and prints the exact command for the operator ritual. One
pass over the transcript, `hashlib.copy()` at each committed boundary,
every commitment judged — "commitments 1–3 hold, 4 diverged" localizes
the rewrite to a byte range. Monotonicity (byte counts never decrease in
chain order) is judged from the chain alone, transcript or no
transcript. A missing transcript is a **note, never a failure** — the
harness cleans transcripts on a retention cycle, and absence-as-verdict
would scar every chain older than a month (ADR-0016's false-scar
lesson). Present-but-short or hash-mismatched is the real thing:
**`TRANSCRIPT-DIVERGED`, exit 5.** Gravity when verdicts compete:
`BROKEN` (1) > `HEAD-MISMATCH` (3) > `TRANSCRIPT-DIVERGED` (5) >
`FILES-DIVERGED` (2) — transcript divergence is never innocent, while
working-tree drift usually is.

**5. Readers absorb bookkeeping entries; the witness must, in the same
slice.** Commitment entries are receipts no tool event owes, so the
witness excludes actor-`receipts` bookkeeping from the receipts count —
otherwise every session drifts into `SURPLUS`/`ENDED-SURPLUS`, a
machine-wide self-inflicted false-scar wave. This exclusion ships in the
same slice as the recorder change, never skewed. The digest skips
bookkeeping rows (ADR-0016 ruling 3: the recorder never filters, readers
do; search and `show` still reach them by address). Scan/serve surfacing
of commitment status is deferred to the dashboard's territory
(ADR-0013, issue #48).

**6. The name is *transcript commitment*.** "Seal" is refused here: a
[seal](../GLOSSARY.md#seal) (ADR-0007) is an *outer* commitment applied
from beyond the package; this is writer-authored, inner, and protected
only by the chain. Calling it a seal would launder recorder bookkeeping
into the vocabulary of outer trust — the same overclaim family as
"immutable".

**7. Paperwork.** SPEC gains an additive v0.1.2 amendment (the
bookkeeping-entry class, the commitment grammar, monotonicity, the
verdict and exit 5); the wire `v` stays `"0.1"`, the v0.1.1 precedent —
spec-text version, not wire version. `docs/EXPERIMENTS.md` gains the
measured envelope (hash cost vs. transcript size, amortized per-call
overhead at N=25) per ADR-0016's measurement-gate pattern. The README
claim is worded with discipline: the transcript is covered *by
reference, forward from each commitment, detection latency only* — never
a flat "the transcript is tamper-evident".

## Why not the alternatives

- **Sidecar file beside the chain** — cryptographically inert: no
  self-proof, writer-reachable, proves nothing. The anchor sidecar works
  for reasons this record does not share.
- **New schema field** — unfreezes v0.1 for a payload the action line
  carries; `run` set the no-new-fields precedent (SPEC §7).
- **Per-receipt cadence** — doubles chain length and digest noise, and
  puts an O(transcript-size) read+hash in the hot path on every call.
- **Session-end only** — the whole session stays a rewrite window until
  it ends; SessionEnd never fires on a crash; and "ended" is
  idle-defined everywhere else in this system.
- **Line-count commitment** — reimports canonical-form ambiguity (CRLF,
  torn tails, trailing newline) for no gain over bytes.

## Consequences

- **The first-move problem stays open, honestly.** An adversary whose
  first action attacks the apparatus is ADR-0002's founding case, and
  nothing recorder-side can close it — the recorder runs inside the
  adversary. This commitment adds one wire to a lattice where each
  disabling move already trips another: disabling the hook leaves its
  own receipt (config loaded at session start) and then chainless
  sessions the witness flags; editing the recorder leaves a fingerprinted
  receipt and the recorder notice (ADR-0015); deleting chains trips the
  baseline. Rewriting the transcript inside the pre-commitment window is
  the priced residual — and the forged flesh must still stay consistent
  with the spine's summaries, fingerprints, and timestamps. The anchor
  remains the only hard boundary.
- **One assumption must be falsified before the claim ships:** that the
  harness treats the transcript as append-only across resume and
  compaction. The build slice dogfoods it (commit early, resume/compact,
  re-verify). If it fails, prefix commitments cry wolf and the fallback
  is committing only where the file has stopped moving — the README
  claim waits on this check.
- Chain bloat ≈ 4% at N=25; the measured envelope goes in
  `docs/EXPERIMENTS.md`.
- Deferred, tracked: the SessionEnd tail commitment (own slice); scan
  and dashboard surfacing of commitment status (#48).
- GLOSSARY gains **Transcript commitment** and **Bookkeeping entry**;
  the verdict ladder gains `TRANSCRIPT-DIVERGED` (exit 5).
