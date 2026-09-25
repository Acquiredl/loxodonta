# ADR-0038: Every sidecar row names its kind; a row with none reads as its sidecar's evidence, and a kind the reader does not know is named, never judged

**Status:** accepted 2026-09-24 (foundation grill)
**Deciders:** Acquiredl

## Context

A chain has up to three sidecars beside it, one JSON object per line:

| sidecar | the evidence row | the other rows |
|---|---|---|
| `<log>.anchors.jsonl` | an OpenTimestamps proof, pending or complete | `attempt` (#240) |
| `<log>.stamps.jsonl` | an RFC 3161 reply (ADR-0032) | `attempt` |
| `<log>.published.jsonl`, the memo | a note that a head was sent (ADR-0025) | `chain` (ADR-0031), `attempt` |

The rows that came later carry a `kind`. The first rows in each sidecar
never did, so every reader found them by elimination: a row that is not
`attempt` (and, in the memo, not `chain`) is the sidecar's evidence.
That test was written eight times in the recorder and five in the
supervisor, and it is the only definition of a proof there is. The
author's own store holds 170 anchor rows, 165 of them kind-less proofs;
shipped packages hold more, and neither can be rewritten.

It also answered the wrong way for a kind nobody had written yet. A
newer recorder's row `{"kind": "witness-note", ...}` in an anchors
sidecar reads, to today's verifier, as a proof with no head:
`ANCHOR-INVALID`, exit 3, evidence against an honest package.

The SPEC is about to state the sidecars as normative text (the 0.9.x
foundation, docs/DIRECTION.md section 4), and 1.0 freezes what it
states. Whatever a row is, the SPEC will say it for good.

Two precedents shaped the ruling. Certificate Transparency (RFC 6962
section 3.4) gives every leaf an explicit `LogEntryType`, and a client
"MUST NOT construe an unrecognized" type as an error. The package's own
`seals` list names each seal's kind, and `verify-package` prints
`declared; this verifier does not know the kind, and does not judge it`
for one it does not know.

## Decision

> **New rows name their kind. A row with no kind reads as its
> sidecar's evidence row, whenever it was written. A kind the reader
> does not know, or a known kind in the wrong sidecar, is named and
> never judged.**

The kinds:

| sidecar | `kind` |
|---|---|
| anchors | `anchor`, `attempt` |
| stamps | `stamp`, `attempt` |
| memo | `head`, `chain`, `attempt` |

- **Written.** `append_anchor_record`, the stamp writer and the memo's
  head writer add `kind`. Nothing else in a row changes.
- **Read, in one place.** One function inside the verifier region
  (ADR-0035) takes a sidecar and a row and returns what the row is: its
  kind, `unreadable` for a line that is not a JSON object, or unknown.
  The kind-less rule lives there and nowhere else. Every judge and
  every note in the recorder asks it; the supervisor's copy is a twin,
  held equal by the check the foundation adds (docs/DIRECTION.md
  section 4).
- **No date.** A sidecar is not chained, and its `ts` is whatever the
  writer wrote, so a kind-less row cannot be dated to before this
  change. One written tomorrow by hand reads exactly as one written in
  2026-09.
- **Unknown.** Printed with the row's number and kind, earning nothing
  and moving no exit code. It can never make a head read as anchored or
  stamped.

## Consequences

**What gets easier:**

- The SPEC defines each row by what it is, not by what it lacks.
- A later kind is not a breaking change for any verifier already handed
  to a recipient.
- The thirteen elimination tests become one question asked of one
  function.

**What gets harder or more constrained:**

- The kind-less rule is permanent. It stops growing; it never goes
  away.
- A writer can relabel a forged proof with an unknown kind and turn
  `ANCHOR-INVALID` into a printed note. It gains nothing it lacked: the
  sidecar is in its reach, and it could delete the row instead.

**Compatibility:**

- The v0.9.0 `verifier.py` skips only `attempt`, so it judges an
  `anchor` or `stamp` row as it judged a kind-less one. A package made
  after this change verifies the same under it.
- The memo never travels in a package; its readers are the recorder's
  keeper and the supervisor, both updated with the reader.

## Alternatives considered

- **Keep absence as the type.** No write changes, and the SPEC would
  freeze "a proof is a row with no `kind`". Rejected: a type defined by
  a missing field, and the elimination test stays the definition.
- **An unknown kind is invalid evidence** (today's accident). Rejected:
  every new kind would break every verifier a recipient already holds.
- **Skip an unknown kind silently.** Rejected: a judge names a line
  rather than skipping it, and a recipient should see every row.
- **`proof`, `timestamp`, `published-head`.** `anchor` and `stamp` are
  the glossary's and the verbs' words; `head` pairs with the memo's
  `chain` as *published head* pairs with *published chain*.

## References

- RFC 6962, section 3.4
- ADR-0025, ADR-0031, ADR-0032, ADR-0035; #240
- docs/DIRECTION.md section 4
