# ADR-0008: Issuer signatures for derived packages — admitted, caged, and keyless nowhere else

**Status:** `accepted` (2026-08-25)
**Date:** 2026-08-25
**Deciders:** Acquiredl

## Context

ADR-0007 gave derived trail designs a package with a single sealing surface — the manifest hash — and reserved a `+ SIGNED` verdict rung without defining it. The recipient across the trust boundary has a question no seal so far answers: *who issued this package?* The anchor proves the manifest existed before block N; anyone can anchor anything. The chain proves internal consistency; the adversary writes chains too. "Issued by the party whose name is on it" is not derivable from anything inside a package the adversary can regenerate wholesale.

ADR-0001 rejected signatures with a precise argument: whoever holds the signing key can rewrite history and re-sign it, so on a single machine a key adds ceremony without adding proof — and key management is the entire UX cost of such a tool. It also left a door: "if signatures ever arrive they get their own ADR and glossary entry." This is that ADR, and it walks through the door without widening it.

Prior art consulted: **code signing** (Debian archive keys, Android APK signing, Authenticode — a publisher signs a finished release crossing a trust boundary to recipients who never met the build machine); **minisign / OpenBSD signify** (the minimal form: one keypair, no PKI, detached signature, fingerprint published out-of-band); **SSH host keys** (fingerprint comparison plus key continuity as identity evidence); **C2PA** (provenance manifests signed by their generator); **Sigstore** (what refusing PKI while wanting attributable signatures costs at industrial scale — infrastructure this repo's ethos refuses). Contrast case: the agent-log niche signs *entries* as the writer writes them (Obsigna, ai-audit-trail, systemd FSS) — the shape ADR-0001 rejected.

## Decision

> **The canon admits the *issuer signature*: a detached signature over a package manifest's shipped bytes, made at package close by a key held out of the writer's reach. It is the seal that answers *who*. It exists for derived designs' packages only — loxodonta's own logs never gain signatures, writer signatures remain rejected, and ADR-0001 stands unamended for the single-machine case it ruled on.**

The rulings:

**1. The distinction that admits it.** A *writer signature* signs history as it is written, by the canon's adversary, on one machine — the signature proves nothing the chain didn't, because the signer is the party being defended against. An *issuer signature* signs a finished manifest, once, at the trust boundary, for a recipient who has no trusted copy of anything: a different actor, a different moment, a different question. The entire code-signing world exists because of this distinction; the entry-signing niche ignores it.

**2. The cage: the claim, verbatim.** The signature claims exactly this — *this manifest, and transitively every artifact it lists, was issued by the holder of key K and has not changed since signing* — and nothing else. The non-claims, each a named overclaim:

- **Not "this is the original."** The issuer holds the key and can sign conflicting versions; ordering in time comes only from the anchor.
- **Not "the contents are correct."** Garbage findings, faithfully signed garbage findings (ADR-0002's slogan, one layer up). The stamp covers the envelope, never the truth inside it.
- **Not "signed by \<issuer name\>" — only "signed by key K."** The key↔name binding is established out-of-band (ruling 4); the verifier can confirm the key, never the owner.
- **Not an evidence-grade upgrade.** A grade-0 finding stays grade 0 inside a signed package; ADR-0006 grades evidence within the package, the signature seals the package. Layers never blend.
- **Not a replacement for the anchor.** The signature is the one seal the issuer *can* forge later, by re-signing; the anchor is the one it can't. See ruling 6.

Discipline rule: verifier output and issuer deliverables use the canonical sentence or a strict subset — never a paraphrase that drops a cage. The failure mode is not malice but marketing drift, one softened word per quarter until "signed" means "trustworthy."

**3. Custody: out of the writer's reach.** The private key must not be reachable by any process whose activity the trail records. The property is normative; the mechanism (password-manager entry applied at delivery, a separate account, a hardware token, an isolated signing service) is the design's choice, listed as illustration only — the same shape as the head record, which is the first object in the canon with this property. A writer-reachable key is worse than no signature: the adversary's forgery ships under the issuer's own fingerprint, converting the strongest seal into the adversary's best weapon. Consequence: signing is an issuer act at package close — ADR-0007's write order gains its final step (chain closes → report → manifest → seals, applied from outside the writer's reach). Phrased by reach, not ritual, so it survives automation: in a service deployment, "out of reach" means the signing service is not the assessment engine and the engine can request a signature but never hold the key. Honest limit: custody closes the writer-forges-a-stamp threat the canon names; it does not cover a rogue issuer or theft at the custody location — those are what the cage and ruling 6 are for.

**4. Key identity: math is the verifier's job, identity is the recipient's.** The public key ships in the package, so verification works offline with nothing running — and the packaged key is *testimony*: it proves internal consistency of the signature, nothing about who holds it (the substitution attack: an adversary regenerates the package and signs with their own included key; every mechanical check passes). Therefore the verifier prints the fingerprint and stops — `SIGNED (key: <fingerprint>)`, never `SIGNED by <name>`; naming the keyholder would draw the recipient's conclusion, the move the anti-terms ban. The issuer publishes the fingerprint through at least one channel the package cannot rewrite — engagement letter, issuer website, public repo — and key continuity (the same fingerprint across a recipient's packages) is the bonus channel. TOFU, named: a first-time recipient with no out-of-band channel holds only the packaged key, and for them `SIGNED` means key continuity going forward, nothing more. The PKI door is closed: certificates would bind names to keys mechanically at the price of the infrastructure ADR-0001 exists to refuse.

**5. Scheme: properties normative, Ed25519 as reference.** One small standard scheme, single keypair, detached signature, no certificate chain. Ed25519 is the reference (minisign, signify, and SSH all settled there); derived designs implement with their own stacks — loxodonta itself implements nothing (its stdlib has no Ed25519, and the freeze makes that a feature). The signature covers the manifest file's exact bytes as shipped, not a re-canonicalized form: the manifest is written last and never edited (ADR-0007), so it is already a fixed byte string, and no second canonical-form specification comes into existence. The signature file sits detached beside the manifest; seals never touch each other, so the anchor is unaffected by the signature's presence or absence.

**6. Rotation: on need only, never unpublish, and the anchor is the only clock.** The key's identity is its fingerprint; human aliases ("Issuer Key 2026") are testimony. Published fingerprints are never unpublished — packages outlive keys, and a recipient verifying in year five needs year-one's fingerprint still findable. Rotation happens on need (compromise or genuine loss), not on a calendar: every rotation pushes a fingerprint-comparison burden onto every recipient. Compromise is handled by an out-of-band notice with a date fence — no in-band revocation, which is the PKI door reopening. What bounds the damage is the seal interlock: **a signature has no clock** — the math cannot say when signing happened, and any adjacent date is testimony — while the anchor cannot be backdated by anyone. A stolen key signs forgeries freely, but honestly-issued packages carry anchors predating the compromise and a forgery can only obtain a young one. Signature-plus-old-anchor survives a breach; signature alone does not. This is the permanent answer to "we sign now — do we still need anchoring?"

**7. Verdict semantics.** `+ SIGNED (key: <fingerprint>)` means exactly: a signature over the manifest's shipped bytes verifies under the packaged public key, whose fingerprint follows. The failures already exist in ADR-0007's vocabulary: an invalid signature is `SEAL-INVALID`; a declared-but-absent one is `SEAL-MISSING`. No new verdict is needed — the sign the rulings composed.

## Consequences

**What gets easier:**

- The recipient's question — "did this issuer produce this?" — has a mechanical component (`SIGNED` + fingerprint) and a one-sentence human component (compare the fingerprint out-of-band).
- A forged "issued by X" package is provably forged: no stamp under X's published fingerprint, and X can say so checkably.
- Key compromise is survivable by design rather than by luck, because the anchor bounds it.

**What gets harder or more constrained:**

- The issuer owns a key forever: generation, backup, custody discipline every engagement, publication channels kept alive for the lifetime of every package ever issued. This is the cost ADR-0001 refused for loxodonta and this ADR accepts, knowingly, for issuers only.
- Package close gains a step that cannot be automated away from the issuer's side of the reach boundary.
- The cage's discipline rule makes claim wording a compatibility surface, like verdicts and exit codes before it.

**What we'll have to revisit if:**

- A derived design genuinely needs machine-verifiable *name* binding (procurement portals, automated vendor checks) — that pressure reopens the PKI/transparency-log question consciously, with Sigstore as the studied precedent.
- Multi-issuer packages appear (co-signed assessments) — the seal-set declaration extends naturally, but threshold semantics ("2 of 3 signers") would need rules.
- The signing service pattern (ruling 3's automation form) gets built — the reach boundary needs a concrete audit story at that point.

## Alternatives considered

- **Writer signatures (sign entries as written)** — rejected then, rejected now: the signer is the adversary; ADR-0001's argument is untouched.
- **Stay keyless entirely (anchor-only)** — rejected for packages: the anchor cannot answer *who*, and "did this issuer produce this?" is the recipient's first question at a trust boundary. Keyless remains correct for loxodonta's own single-machine logs.
- **PKI / certificates** — rejected: binds names to keys at the price of certificate authorities, chains, and revocation infrastructure; the out-of-band fingerprint plus continuity does the honest subset of the job.
- **Transparency log / Sigstore** — rejected for now: real infrastructure with an operator, against the nothing-running ethos; named as the conscious reopening path in the revisit triggers.
- **Signing timestamp as the clock** — rejected: a date next to a signature is testimony; the anchor is the only clock (ruling 6).

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (the door this walks through; stands unamended for the single-machine case); `0002-writer-as-adversary.md` (why custody is phrased by reach; the garbage-in slogan one layer up); `0003-anchoring-minimal-ots-subset.md` (the anchor as the only clock); `0006-evidence-grades-generalize-testimony.md` (grades never upgraded by signing); `0007-sidecar-manifest-seals-the-package.md` (the surface this seal applies to; the `+ SIGNED` rung this defines; `SEAL-INVALID` / `SEAL-MISSING`).
- Glossary terms **added**: *Issuer*, *Recipient* (Roles); *Issuer signature* (Core domain). Terms **sharpened**: *Seal* (the *who* parenthetical resolved). Anti-term **revised**: ~~signature~~ → ~~writer signature~~, with the issuer signature now defined.
- Prior art: code signing (Debian, APK, Authenticode), minisign/signify, SSH host-key continuity, C2PA, Sigstore (as the refused-infrastructure contrast).
- Discussion: issuer-signature grill, 2026-08-25 (this repo), continuing the package arc from ADR-0007.
