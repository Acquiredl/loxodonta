# ADR-0006: Evidence grades generalize testimony vs. mechanical facts

**Status:** `accepted` (2026-08-25)
**Date:** 2026-08-25
**Deciders:** Acquiredl

## Context

ADR-0002 drew a binary line: writer-supplied fields (`ts`, `actor`, `action`) are testimony and can at most raise warnings; verdicts come only from mechanical facts the verifier can recompute (hashes, sequence, chain rule, head). The slogan was "write-time lies remain garbage in, faithfully chained garbage out."

This repo is also the canon for derived trail designs: systems that record *findings* rather than tool calls, of which the first exists (an assessment trail in a sibling project). An external review of that system (2026-08-25) surfaced the failure mode the binary cannot express: a subject's self-declared "yes, we have that process" renders with the same visual and rhetorical weight as a fact the system observed itself. Between pure testimony and recomputable fact there is a spectrum (a document was received; the artifact itself was examined), and every derived design will re-invent that spectrum ad hoc unless the canon names it once.

## Decision

> We chose to generalize the testimony/mechanical-facts binary into an ordered **evidence grade** attached per claim, canonical for any trail design derived from this repo, instead of adding new status values or a boolean "verified" flag.

The scale, from weakest to strongest:

| Grade | Name | Meaning |
|---|---|---|
| 0 | `self_reported` | Subject testimony, unexamined. The claim is recorded, not checked. |
| 1 | `document_evidenced` | A document supporting the claim exists and was received. |
| 2 | `artifact_inspected` | The artifact itself was examined by the assessor or by code. |
| 3 | `independently_observed` | Reproducibly observed or recomputable by the verifier without trusting the writer or the subject. |

Rules that hold everywhere:

- A grade **qualifies** a claim's status; it never changes it. Status answers "what did we conclude"; grade answers "on what kind of evidence." The two are recorded side by side, additively.
- Grade measures **independence of the evidence, not correctness of the conclusion**. A grade-3 observation can still be misinterpreted; a grade-0 answer can still be true.
- Chain-integrity verdicts remain grade-3-only. ADR-0002 stands unamended: `verify` trusts nothing below the top rung.
- Loxodonta's own v0.1 format is frozen and untouched. Its entries remain the two-endpoint case of this scale: `ts`/`actor`/`action` sit at grade 0, the hash chain at grade 3. The scale exists for derived designs whose records carry richer payloads.

**Corollary (producer provenance):** genesis is the chain's hash-committed rulebook. A derived trail whose output depends on an interpreting engine must commit, in its genesis payload, every ingredient whose change alters output: format version, engine identity, prompt version or hash, check-catalog version, evaluation-suite version. Otherwise "why did this assessment change" has no recorded answer. This extends the existing Genesis concept; it is stated here so derived designs treat it as required, not optional.

## Consequences

**What gets easier:**

- Derived designs share one vocabulary for "what was verified vs. what we were told," instead of each re-deriving it.
- Reports can show the gap honestly: a reader sees at a glance which findings rest on the subject's word.
- The "not present vs. not observable" ambiguity in assessment statuses resolves without mutating any frozen status taxonomy: a low grade on an `unknown` finding says "we could not look," a high grade says "we looked and it is not there."

**What gets harder or more constrained:**

- Grade assignment is itself a judgment at the boundaries (is a screenshot of a register grade 1 or grade 2?). Every derived design must publish its own grading table with concrete examples; the scale without the table invites drift.
- The temptation to read high grades as truth must be resisted in client-facing copy. The grade is about evidence provenance; marketing language that blurs this repeats the overclaim ADR-0002 warned about for the chain itself.

**What we'll have to revisit if conditions change:**

- If a format v2 ever unfreezes loxodonta's own entry schema, decide whether entries carry grades natively or remain the implicit two-endpoint case.
- If a derived design genuinely needs intermediate rungs, extend by subdivision (for example 2a/2b), never by renumbering: recorded grades in existing trails must keep their meaning.

## Alternatives considered

- **New status values (`NOT_OBSERVED`, etc.)** — rejected: mutates frozen status taxonomies downstream (a client-visible format change), and conflates evidence strength with finding outcome, which are orthogonal.
- **Boolean `verified` flag** — rejected: collapses "a document was received" and "the artifact was examined," which is exactly the distinction assurance work turns on.
- **Leave it to each derived system** — rejected: the canon exists to prevent every derived trail from re-deriving the same idea inconsistently.

## References

- Related ADRs: `adrs/0002-writer-as-adversary.md` (the binary this generalizes; stands unamended).
- Glossary terms **added or sharpened**: `GLOSSARY.md#testimony` (added), `GLOSSARY.md#evidence-grade` (added), `GLOSSARY.md#genesis` (sharpened: provenance corollary).
- Glossary terms **retired**, and topologies overruled: none.
- Discussion: external code review of the first derived trail design, 2026-08-25; routed here because trail canon lives in this repo.
