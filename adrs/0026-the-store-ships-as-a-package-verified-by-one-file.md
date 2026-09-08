# ADR-0026: A session or a drawer ships as a package, sealed by a manifest, verified by the recorder alone (ADR-0007 and ADR-0008 applied to loxodonta's own store)

**Status:** accepted 2026-09-08 (grilled from the two v0.2.0 external reviews; restated by the author)
**Deciders:** Acquiredl

## Context

The evidence lives in the store on the machine that wrote it. To show a
stranger what an agent did, the operator today sends loose files: chains,
maybe the anchor sidecars, with no way for the recipient to know they got
everything, that nothing was swapped in assembly, or when the set existed.
The harness transcript, the rich record the chain's commitments point at,
is gone after the harness's retention cycle (thirty days in Claude Code).
`supervisor export --raw` already zips chains and sidecars, but for field
data: drawers renamed to ordinals, no project record, no manifest.

Both external reviews of v0.2.0 (2026-09-08) named evidence portability as
the gap and set the same test: a security engineer who has never seen the
host receives the evidence, runs one command on a clean machine, gets a
verdict with what each layer proves and does not prove, and can state the
residual trust in one sentence.

The canon already has the design. ADR-0007 defined the *package*, the
*manifest* written last as the single sealing surface, the declared seal
set, and the verdict ladder `SELF-CONSISTENT`, `+ ANCHORED`, `+ SIGNED`,
and called loxodonta's own deliverable "the degenerate one-artifact case".
ADR-0008 admitted the issuer signature for packages, with Ed25519 as the
reference scheme and custody out of the writer's reach as the rule, and
said loxodonta implements no signature code itself. The GLOSSARY defines
*Package*, *Manifest*, *Seal*, *Issuer*, and *Recipient*. This ADR is the
moment loxodonta stops being the degenerate case, and it adds no vocabulary.

Two facts from the code shaped the rulings. The stdlib has no Ed25519, so
signing must come from a tool the operator and the recipient already have.
And `read_log` splits lines tolerantly, so a chain's bytes can change line
endings on a Windows unzip while its head stays the same; a manifest that
listed chains by file hash would show every Windows recipient a false
divergence.

Prior art beyond ADR-0007's set: **git's SSH commit signing**
(`gpg.format=ssh`) shells out to `ssh-keygen -Y sign` and verifies with
`ssh-keygen -Y verify`, chosen for the same reasons here: on every machine
since OpenSSH 8.0, Ed25519, no PKI. **Forensic evidence containers** (EnCase
E01, AFF4): the image, its hash manifest, the acquisition log, and the
examiner's notes, never the original system. **Sigstore bundles**: the
signature travels with its verification material and the transparency-log
inclusion proof, which is our sidecar.

## Decision

> **A package is a session's or a drawer's chains with their anchor
> sidecars, the project record, a witness snapshot labelled testimony, a
> plain-words README, and the transcript only on request, listed by a
> manifest written last that names chains by head and artifacts by hash
> and declares its seals. `supervisor package` builds it; `loxodonta
> verify-package` judges it layer by layer, the recorder's own verdicts
> verbatim and the package verdict last. It confirms the package is
> unaltered since packaging, when it existed, and which key packed it, and
> never that its contents are true.**

1. **Unit.** A **session**, selected by id or by any entry address inside
   it, siblings included (the way `show` and `verify ADDRESS` already
   select); or a **drawer**, selected by repository path (the way `digest
   --repo` does), the current repository when no selector is given. The
   manifest lists N chains either way. Store-wide stays `export --raw`'s
   job.
2. **Contents.** Always: every chain of each selected session, its anchor
   sidecars, `project.json`, `witness.json` (each session's completeness
   row and the scan verdict, labelled testimony, grade 0), and
   `README.md` in plain words: what is inside, how to verify, what each
   layer proves and does not. On request only, `--transcript`: the harness
   transcript, because the bad day's chain holds `Read: .env` with a
   fingerprint and the transcript holds the contents of `.env`; packaging
   it can hand the recipient the very secret the session exfiltrated, so
   it is the operator's explicit call, and the README says whether it is
   present. Never: file contents. The tool holds fingerprints, not the
   logged bytes, and cannot produce the logged version; on the recipient's
   machine the project record points nowhere and `FILES-UNRESOLVED` is the
   honest line, already coded (ADR-0012).
3. **Manifest, per ADR-0007.** `manifest.json`, written last, format tag
   `loxodonta-package/1` (the receipt format stays `0.1`). Chains are listed
   by **head** and entry count, never by file hash: the head is the
   commitment and the verifier recomputes it by walking. Post-close
   artifacts (sidecars, `witness.json`, `project.json`, `README.md`, the
   transcript) are listed by sha256 of their bytes, because nothing else
   commits them; the transcript's committed prefixes live in the chain and
   the manifest adds one new fact, the tail as of packaging. One
   commitment home per fact. The manifest's hash is the only sealing
   surface. `"seals"` declares which seals the package should carry, so a
   stripped seal is `SEAL-MISSING`, never a silent downgrade. The README
   never prints the manifest's hash: it is written before the manifest,
   and nothing may point at what is sealed last.
4. **Seals, both opt-in.** `--anchor` posts the manifest's hash to the
   calendars once and writes `manifest.json.anchors.jsonl`: an ordinary
   anchor record whose `head` is the manifest hash and which has no `n`.
   `--sign KEYFILE` shells out to `ssh-keygen -Y sign -n loxodonta-package`
   and writes `manifest.json.sig`; the public key ships beside it as
   `manifest.json.pub`, which is testimony (ADR-0008 ruling 4). Nothing
   leaves the machine without `--anchor`; the recorder never touches a
   private key, ssh-keygen does, including any passphrase or hardware
   touch.
5. **Verification, in the recorder.** `loxodonta verify-package PATH`,
   a zip or an unpacked folder, prints in this order: the manifest's
   summary; per chain, the recorder's own `verify --anchors` output
   verbatim, as `supervisor verify ADDRESS` prints it today; the transcript
   commitments judged against the packaged transcript when present; file
   references counted and stated as not checkable off the machine; each
   artifact against the manifest; each declared seal; then the package
   verdict on the last line in ADR-0007's words, then one line of residual
   trust. The recipient downloads one checksummed file, the same one that
   verifies a bare chain. There is no third file.
6. **Rungs and words.** `+ ANCHORED` means the **manifest** is anchored.
   Chain anchors from session end print as detail under each chain: they
   are the stronger evidence about the chain, and they seal a different
   object; blending them into the package rung is how "anchored" would
   drift toward "everything here is anchored". `+ SIGNED (key:
   SHA256:...)`, the fingerprint and never a name; the recipient compares
   it against a channel the package cannot rewrite. A recipient without
   `ssh-keygen` sees `signature not judged: ssh-keygen not on PATH`, and
   the ladder reports the rungs it could judge. Without seals the ceiling
   is `SELF-CONSISTENT`, printed with its stated limit: indistinguishable
   from a wholesale regeneration.
7. **Exit codes, mapped onto `verify`'s** so a script that reads those
   learns nothing new. `0` `SELF-CONSISTENT` with or without rungs
   (`VALID`); `1` `CHAIN-BROKEN` (`BROKEN`); `2` `ARTIFACT-DIVERGED`
   (`FILES-DIVERGED`, its package sibling per ADR-0007); `3`
   `SEAL-INVALID`, `SEAL-MISSING`, a chain's `ANCHOR-MISMATCH`
   (`HEAD-MISMATCH`: not what was issued); `4` `UNSUPPORTED-FORMAT`
   (`UNSUPPORTED-VERSION`: a refusal); `5` `TRANSCRIPT-DIVERGED`. Gravest
   wins. **Usage errors exit `64`** (sysexits `EX_USAGE`) in both
   `loxodonta.py` and `supervisor.py`, so verdict exit `2` no longer
   collides with an argparse error; the README's warning to read the
   verdict line rather than the code stays, as good advice rather than a
   workaround.
8. **Custody, for the solo operator** (ADR-0008 ruling 3, applied). A key
   any process of this user could use without the operator, an
   unencrypted key in `~/.ssh` or one loaded in `ssh-agent`, is
   writer-reachable, and a signature made with it is testimony: `--sign`
   promises no more than the key's custody does, and the docs say so. A
   FIDO2 key that needs a touch, or signing on another machine, is out of
   reach. The operator signing is the issuer wearing a second hat
   (GLOSSARY *Issuer*).
9. **Names.** It is a **package**, the GLOSSARY's word and ADR-0007's,
   whose verdicts the verifier prints. "Bundle", the everyday word and the
   reviews' word, is avoided so the concept has one name; the raw
   field-data export's zip becomes the "raw archive". The parties are the
   **issuer** and the **recipient**, unchanged from ADR-0008.

## What none of this survives

- **Garbage in.** ADR-0008's cage, one layer up: the package confirms it
  is unaltered since packaging, when it existed, and which key packed it.
  It never confirms that the record inside is true or complete. A harness
  that lied at write time ships faithfully packaged lies.
- **A key the writer could use.** Ruling 8. The signature is only as good
  as the custody, and the tool cannot see the custody.
- **No seals.** `SELF-CONSISTENT` alone is what a wholesale regeneration
  also produces. The chain anchors inside still speak for the chains; the
  package as a set is on record only from its own seals.
- **The transcript after retention.** Commitments bind the transcript only
  while it exists. `--transcript` at packaging is the only thing that
  keeps it; hashing more often does not.
- **File contents.** The recipient gets paths and fingerprints. The files
  travel separately or not at all.
- **The recipient's own job.** The verifier prints a fingerprint and a
  merkle root; comparing the fingerprint out of band and the root against
  a block source they trust is theirs (ADR-0003: the verifier never
  fetches headers; ADR-0008 ruling 4: math is the verifier's job, identity
  is the recipient's).

## Consequences

**What gets easier:**

- The strategic test both reviews set is met by the output itself: one
  file, one command, a verdict per layer, one sentence of residual trust.
- The bad day can be studied by someone who was never on the machine, with
  the witness's word on completeness carried along and labelled.
- The honeypot arc gets its dataset unit for free: one package per
  session, signed under a fingerprint published on the honeypot's page.

**What gets harder or more constrained:**

- `loxodonta.py` grows a command that reads zips and shells out to
  `ssh-keygen`; the single file gets longer, and the readability rule
  applies to every line of it.
- The manifest fields, the verdict words, and the exit table become a
  compatibility surface, like SPEC §6's numbers.
- Package assembly has a strict write order (chain snapshot, artifacts,
  README, manifest, seals), and `supervisor package` must honor it or the
  package is unverifiable.
- `verify --files` and `--transcript` on a packaged chain need the
  package's own base rules; the recorder's file-reference resolution
  (ADR-0012) already yields the honest sentence off the machine.

## Alternatives considered

- **A third standalone file, `verify_bundle.py`.** Rejected: the
  recipient already downloads one checksummed file to verify a chain, and
  the recorder is the verifier by design.
- **Seal the zip's own sha256, no manifest.** Rejected: a re-zip changes
  the hash through archive timestamps, and with no declared seal set a
  stripped proof passes silently.
- **Chain anchors count toward `+ ANCHORED`.** Rejected: two objects
  under one word.
- **Transcript by default, `--no-transcript` to omit.** Rejected: the
  default would leak the exfiltrated secret to the recipient by default.
- **Pure-Python Ed25519 verification in the recorder.** Rejected: a
  hundred lines of curve arithmetic no non-expert can read, the invented
  crypto ADR-0007 refuses, and the signer still needs a tool.
- **minisign or signify.** Rejected: installed nowhere by default; a
  recipient on a clean machine would fetch a tool before verifying.
- **The operator signs by hand; the tool never invokes ssh-keygen.**
  Rejected: hardware keys gain nothing from the ceremony, and the custody
  cage carries the honesty either way.
- **Both build and verify in `supervisor.py`.** Rejected: breaks the
  one-file-verifies story.
- **Call it a bundle.** Rejected: two words for one GLOSSARY concept.
- **File contents at their logged hashes.** Rejected: the tool cannot
  produce the logged version, only the current one, and ADR-0007's
  evidence-index rule would need a merge rule across chains first.

## References

- Related ADRs: `0003-anchoring-minimal-ots-subset.md` (the anchor path
  reused for the manifest; the verifier never fetches),
  `0005-supervisor-as-sibling-tool.md` and
  `0009-recall-surface-lives-in-the-supervisor.md` (the supervisor builds,
  the recorder judges), `0007-sidecar-manifest-seals-the-package.md` (the
  manifest, the declared seal set, the verdict ladder, all applied as
  written), `0008-issuer-signatures-for-derived-packages.md` (the issuer
  signature, its cage, custody by reach, fingerprint not name),
  `0012-file-references-rebase-to-project-root.md` (`FILES-UNRESOLVED` off
  the machine), `0017-transcript-commitments.md` (the packaged transcript
  judged against the chain), `0021-field-data-export-is-allowlisted-and-sent-through-gh.md`
  (the raw archive this package is not), `0025-a-head-record-is-what-the-machine-cannot-unsay.md`
  (grilled together).
- Glossary terms **sharpened**: *Package* (loxodonta's own store now ships
  as one; "bundle" avoided). Unchanged and now load-bearing: *Manifest*,
  *Seal*, *Issuer signature*, *Issuer*, *Recipient*.
- Prior art: git SSH commit signing (`ssh-keygen -Y`); forensic evidence
  containers (EnCase E01, AFF4); Sigstore bundles; and ADR-0007's set (OCI
  image manifests, signed JARs, in-toto, TUF, C2PA).
- Raised: the two external reviews of v0.2.0, 2026-09-08; the strategic
  test is theirs, in near-identical words.
