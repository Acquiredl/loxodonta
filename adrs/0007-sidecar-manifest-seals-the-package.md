# ADR-0007: A sidecar manifest is the package's single sealing surface

**Status:** `accepted` (2026-08-25)
**Date:** 2026-08-25
**Deciders:** Acquiredl

## Context

Derived trail designs deliver more than a chain. The first one (the assessment trail in a sibling project) ships a *package*: the trail, a human-readable report generated from it, and an archive of evidence files — several artifacts crossing a trust boundary to a recipient who will ask, months later, "is this intact, and is it what was issued?"

An external review of that system (2026-08-25) found the gap precisely: the report prints the trail's head, so report and trail can be checked for *consistency with each other* — but a party who controls both artifacts can modify the trail, recompute the head, and reprint it in the report. Mutual vouching between two writer-reachable artifacts proves internal consistency, never provenance. The chain alone cannot close this: the report is generated *from* the trail after it closes, so no entry can ever commit the report's hash.

Loxodonta's own case never had this problem — a receipts log plus its file references is a one-artifact deliverable whose "manifest" is the chain head itself, and ADR-0003 anchors that head. The canon needed a ruling for the multi-artifact case without unfreezing v0.1.

Prior art consulted: **OCI image manifests** (a small document listing config and layers by digest; the manifest's own digest is the image's identity; registries and signatures pin the manifest, never the layers); **signed JARs** (`MANIFEST.MF` lists per-file digests; the signature covers the manifest, not the files); **in-toto / SLSA provenance** (a sealed statement *about* artifacts referenced by digest, deliberately outside the artifacts themselves); **TUF** (metadata declares which signatures must exist, so stripping one is a detectable failure rather than a silent downgrade). All converge on one pattern: seal the list, and the list vouches for the contents.

## Decision

> **A derived design that delivers multiple artifacts binds them with a *manifest*: a sidecar document, written last, listing the chain head and the hash of every post-close artifact. The manifest's hash is the package's single sealing surface — every outer seal (anchor now, issuer signature if a later ADR admits one) applies to the manifest hash and to nothing else. Loxodonta's own v0.1 format is untouched; its chain head remains the degenerate one-artifact manifest.**

The rulings, in dependency order:

**1. Scope.** Canon for derived trail designs only. `receipts.py` gains nothing; the freeze holds. (The same move as ADR-0006: loxodonta is the degenerate case of the general concept.)

**2. Topology: sidecar, not closing entry.** The manifest is a separate small document, not a final chain entry. The closing-entry alternative dies on a timeline problem: the report is generated from the trail after the chain closes and prints the head (the operator ritual), so a closing entry committing the report's hash would need the report to exist before the chain closes while the report needs the head after it. The only escapes — stripping the head from the report, or hashing "the report minus its seal block" — reintroduce exactly the canonical-form ambiguity SPEC §4 exists to kill. The sidecar has no timeline problem because it is written last: last-written can point at everything, and nothing needs to point back at it.

**Corollary (no cycles):** the report may print the assessment id and the chain head — both exist before the report is written. It must never print the manifest's own hash: the manifest lists the report, so it is written after the report, and anything sealed last is referenced by nothing. The manifest hash lives only outside the report (bundle readme, seal files, the anchor).

**3. One commitment home per fact.** Every fact is committed in exactly one place; the manifest never re-commits, only re-displays:

| Fact | Committed where |
|---|---|
| The rulebook — format version, engine identity, prompt hash, check-catalog version, eval-suite version, assessment id | **Genesis** (ADR-0006 provenance corollary) |
| What happened — findings, and every input consumed (questionnaires, retrieved pages) as evidence source references | **Chain entries** |
| Post-close artifacts — the report | **Manifest** |

Displayed convenience copies (target, date, id in the manifest header) are testimony; the committed truth is reachable through the chain head. **The chain is the evidence index:** the manifest carries no separate evidence listing. The verifier derives the expected archive contents by walking the entries and collecting source references; the archive must contain exactly that set — matching hashes, no extras. An unreferenced file smuggled into the archive is how a human reader gets misled, and deriving the expected set from the chain catches it for free.

**4. Sealing.** The manifest hash is the only surface outer seals apply to. Two seals exist, answering orthogonal questions: the **anchor** (ADR-0003's mechanism pointed at the manifest hash — nothing new to build) says *when* — "this manifest existed before block N" — and is the only seal the issuer cannot forge later, which is what closes the regeneration gap; the **issuer signature** says *who* and is deliberately deferred to its own ADR, because it crosses ADR-0001's territory and imports key custody. In a package design, anchoring only the bare head is a bug: a regenerated report plus regenerated manifest still contains the validly anchored head. The anchor moves outward to the manifest.

**Corollary (declared seal set):** the manifest commits the list of seals the package is supposed to carry (e.g. `"seals": ["anchor"]`). A declared-but-absent seal is a failure (`SEAL-MISSING`), never a silent downgrade — otherwise an adversary strips the seal files from a regenerated package and the verifier happily reports self-consistency (TUF's downgrade-resistance pattern). No cycle: the declaration says seals *will exist*; it hashes nothing. Residual honesty: an adversary who regenerates the manifest can declare no seals — the declaration shrinks the stripping attack from "delete a file" to "convince the recipient this issuer ships unsealed packages," which is the most any in-band mechanism can do; the last line of defense is recipient-side expectation.

**5. Verdict vocabulary.** Package verdicts name the mechanism, never the conclusion (`authentic` / `verified` / `genuine` are anti-terms in verdict output — a verifier that says "authentic" draws the operator's conclusion for them, the same overclaim as "immutable"). The ladder:

- `SELF-CONSISTENT` — chain walks clean, artifacts match their commitments, manifest coherent. Printed with its stated limit: *indistinguishable from a wholesale regeneration.* The ceiling for an unsealed package.
- `+ ANCHORED` — anchor proof valid; adds *when*.
- `+ SIGNED` — signature valid; adds *who* (vocabulary reserved here; semantics defined by the signature ADR).

Failures: `CHAIN-BROKEN` (trail integrity), `ARTIFACT-DIVERGED` (report or evidence off-manifest/off-chain — the package sibling of `FILES-DIVERGED`), `SEAL-INVALID` (present but failing), `SEAL-MISSING` (declared but absent). `UNSUPPORTED-FORMAT` is a refusal, not a verdict. Canon defines vocabulary and ordering; each derived design maps its own exit codes — SPEC §6's numbers stay receipts' own.

**6. Names.** *Manifest* (the sidecar list — ship's manifest, OCI, JAR, C2PA all use the word for exactly this), *package* (the delivered whole: trail + report + evidence + manifest + seals), *seal* (the category of outer commitments to the manifest hash — today the anchor; possibly a signature later). Glossary entries added.

## Consequences

**What gets easier:**

- The report ↔ trail mutual-vouching weakness has a canonical fix every derived design inherits, instead of each rediscovering it.
- Verification is three mechanical steps, outward-in: check the seals on the manifest; check each artifact against the manifest and the chain-derived evidence index; walk the chain. A recipient verifies with nothing running and no issuer cooperation.
- The manifest stays one page: the chain head commits the entire interior transitively, so the manifest never re-lists what the chain already committed.

**What gets harder or more constrained:**

- Package assembly gains a strict write order: chain closes → report written (may print id + head) → manifest written last → seals applied to the manifest hash. Tooling that writes these out of order produces cycles or unverifiable packages.
- The archive-completeness rule ("exactly the referenced set, no extras") means evidence archiving must be disciplined: a file consumed but never referenced from an entry cannot ship in the archive.
- Verdict wording is now a compatibility surface for derived designs, like receipts' exit codes.

**What we'll have to revisit if:**

- A derived design needs *multiple chains* in one package (e.g. one trail per assessor). The manifest lists several heads naturally, but the evidence-index rule ("the chain is the index") needs a merge rule first.
- A post-close artifact needs to be *referenced by* another post-close artifact — a second ordering layer inside the manifest would need rules.
- The signature ADR lands: `+ SIGNED` semantics, seal-set vocabulary, and key custody all activate there.

## Alternatives considered

- **Closing entry (fold the artifact list into the chain's final entry)** — rejected: the report-timeline problem above; also found no serious precedent, against four for the sidecar.
- **Manifest re-commits methodology and inputs (the external reviewer's four-block manifest)** — rejected: double-commits facts ADR-0006 already assigned to genesis, creating two committed answers that can drift. Their manifest was compensating for not having ADR-0006.
- **Manifest-side evidence index** — rejected: a second source of truth for a fact the chain already commits; deriving the expected archive from the entries is strictly more honest and catches smuggled extras.
- **Anchor the bare head, as in the single-log case** — rejected for packages: leaves the report swappable alongside a regenerated manifest.
- **Conclusion-flavored verdicts (`AUTHENTIC`)** — rejected: the verifier would be drawing the operator's conclusion; mechanism-naming verdicts are the house rule (tamper-evident, not immutable).

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (the door the deferred signature ADR must walk through); `0002-writer-as-adversary.md` (testimony vs. mechanical facts — displayed manifest fields are testimony); `0003-anchoring-minimal-ots-subset.md` (the anchor mechanism, here pointed at the manifest hash); `0006-evidence-grades-generalize-testimony.md` (the genesis provenance corollary this ADR's commitment-home table builds on).
- Glossary terms **added**: *Manifest*, *Package*, *Seal*. Anti-terms **added**: *authentic / verified / genuine* (in verdict output only).
- Prior art: OCI image manifest, signed JARs, in-toto/SLSA provenance, TUF (declared signature sets), C2PA manifests.
- Discussion: manifest/package grill, 2026-08-25 (this repo), prompted by the external review of the first derived trail design routed here per ADR-0006's precedent.
