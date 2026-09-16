# ADR-0032: An authority timestamp sits beside the anchor, never instead of it (ADR-0003 amended by addition)

**Status:** accepted 2026-09-16 (grilled; restated by the author: *authority timestamp beside the anchor*)
**Deciders:** Acquiredl

## Context

ADR-0003 chose OpenTimestamps for the anchor and rejected an RFC 3161
timestamp authority in one line: "requires trusting/operating a TSA; the
prior-art survey names anchoring without infrastructure as this
project's concrete edge." The edge is real and this decision keeps it.
What it revisits is whether the edge is a reason to deny the operator
the other thing.

Three facts argued for revisiting, none of them new, all of them
sharper once the profile arc (ADR-0031) made the tool something a
beginner and an enterprise both pick up. An anchor matures when Bitcoin
confirms, hours after the session; an authority answers in one round
trip. A qualified timestamp under eIDAS is recognized evidence in EU
courts, and a block header, whatever its actual strength, formally is
not. And ADR-0025 already named "an enterprise that will not put
Bitcoin in a procurement document" as a real operator; that operator
often runs an authority of its own, inside the network, which is the
one case where "operating a TSA" is not a cost but the existing
practice.

The cost is a difference in kind, and the vocabulary has to carry it. An
anchor's proof is nobody's product: it replays offline from the entry
hash to a Bitcoin block header, and no party can be leaned on to make it
say something else. A token is somebody's signed word: it is trusted
exactly as far as the authority's certificate, and an authority that
lies about its clock can stamp any time it likes. ADR-0007 said a
signature has no clock; an authority timestamp is a signature with a
clock you have chosen to trust.

The stdlib is the other wall. It has no RSA and no ECDSA, so `verify`
cannot check a token's signature itself. ADR-0026 met the same wall for
the issuer signature and answered it once: shell out to a tool every
machine already has (`ssh-keygen -Y verify`), and when the tool is
absent say "signature not judged" as a note rather than guessing a
verdict. The same answer serves here through `openssl ts -verify`.

Prior art. **Authenticode** and **Adobe** document signing are the
mainstream RFC 3161 users: the token exists so a signature outlives its
certificate. **Sigstore** added RFC 3161 timestamps *beside* Rekor's own
log, not instead of it. **rsyslog with Guardtime KSI** is the commercial
anchor ADR-0003 already cited as the mechanistic analog. Nobody in that
list made the authority the default; every one made it an addition.

## Decision

> **The authority timestamp is a second commitment of the chain head,
> made beside the anchor when the operator names an authority, never by
> default and never instead of the anchor. The recorder encodes the
> request itself, keeps the token verbatim in its own sidecar, and
> judges it through `openssl` against a chain the operator saved, or
> says honestly that it did not.**

1. **It is not an anchor.** The glossary gains *authority timestamp*
   and the anchor keeps its name for the credential-free commitment
   alone. The beginner's tier name, `timestamped`, covers both; the
   mechanisms never share a word, because they do not share an evidence
   kind. Calling a token an anchor would let "anchored" mean two things,
   one of which a company can be leaned on to unsay.
2. **The flag, and where it applies.** `install-hook --authority URL`,
   available at the `timestamped` and `full` tiers and under `custom`.
   No authority is baked in: whom to trust is the whole choice, so the
   URL is the operator's to type. The docs list public authorities as
   examples and say plainly that the qualified kind is the one with
   standing. The working name `--tsa` is retired: the tier is for
   people who do not know the acronym.
3. **When: session end, before the anchor.** ADR-0025 put the one POST
   before the slow calendar so the calendar could never cost it; the
   authority is one POST too. The order inside the session-end budget
   becomes commitment, publish, authority timestamp, anchor. Same
   budget, cut off, quiet, best-effort. The keeper's anchor cadence
   requests both commitments for the same head when an authority is
   named; there is no second cadence to tune.
4. **The wire and the sidecar.** The recorder encodes a DER
   `TimeStampReq` by hand (version 1, a SHA-256 imprint of the head, a
   nonce, `certReq` true), POSTs it as `application/timestamp-query`,
   and reads only the response's status: granted, or not. The
   `TimeStampResp` is kept verbatim in `<log>.stamps.jsonl` with the
   head it stamps, that head's `n`, and the time asked; the recorder
   never parses the token further and never claims to know what is
   inside it. About forty stdlib lines to encode and twenty to read the
   status, beside ADR-0003's hundred and fifty for the anchor. The
   package carries the stamps sidecar as it carries the anchors sidecar,
   and the manifest hash can be stamped as it can be anchored (ADR-0026
   ruling 4).
5. **Judging: through `openssl`, offline, or not at all.** `verify
   --stamps --authority-chain FILE` runs `openssl ts -verify` on each
   token against the recorded head's digest and the certificate chain
   the operator saved from the authority. `verify` still never fetches
   (ADR-0003 stands): the chain file is on disk or the token is not
   judged. A token `openssl` rejects, or whose imprint is not its
   recorded head, is `STAMP-INVALID`, beside `ANCHOR-INVALID`, exit 3:
   not the recorded history. `openssl` not on the path, or no chain
   file given, prints `stamp not judged: ...` as a note and never a
   verdict, ADR-0026's exact posture. `verify-package` judges the
   packaged sidecar the same way and its verdict line gains `+ STAMPED`
   beside `+ ANCHORED` when the manifest is stamped.
6. **What stands.** OpenTimestamps is the default and the only
   commitment at `timestamped` until an authority is named. "Anchoring
   without infrastructure" stays the positioning edge, and the README
   says the authority is the addition for operators who need seconds or
   standing. The anchor remains the head record of first resort
   (ADR-0025). Nothing leaves the machine without the opt-in.

## What none of this survives, and what leaves the machine

- **The authority.** A colluding or compromised authority stamps any
  time it is asked to, past or future; the token is exactly as good as
  the authority's honesty and key custody. The anchor cannot be made to
  do this, which is why it stays. Ten-year evidence is the anchor's job.
- **Certificate life.** A token is judged against a chain that expires
  and can be revoked. Long-term validation (re-stamping before expiry,
  archival of the chain) is the operator's habit and is not built; the
  chain file the operator saved is what `verify` reads, and losing it
  turns every token into "not judged".
- **The stdlib wall, said plainly.** The recorder never claims to have
  checked a signature. `openssl` did, or nobody did, and the output says
  which.
- **What leaves.** The 32-byte head digest, to a company or an internal
  service, from your address, at your cadence. Where the calendars are
  public pools, an authority keeps request logs under its own terms.

## Consequences

**What gets easier:**

- An operator who needs a commitment in seconds, or one with standing
  in a courtroom, or one whose procurement forbids the word Bitcoin, has
  it in one flag beside the anchor they already have.
- An enterprise with an internal authority points the flag at it and
  nothing leaves the network.
- The judging posture is one the repo already explains: a tool the
  machine has, or an honest note.

**What gets harder or more constrained:**

- A second optional external tool, `openssl` beside `ssh-keygen`; the
  README's dependency sentence gains a clause.
- A second sidecar, a second `verify` flag, a second word on the
  package verdict line, and docs/ANCHORING.md grows a section on a
  commitment that is not an anchor; whether the page keeps its name is
  the PRD's to settle.
- The house check's synonym table (#241) gets its row: *anchor* is
  never the word for an authority timestamp.
- ADR-0003's alternatives section now has one entry that later became
  an addition; readers of that ADR are pointed here.

## Alternatives considered

- **Keep ADR-0003 as written.** Rejected: the edge is positioning, and
  positioning is not a reason to deny an operator a commitment they
  need for procurement or standing.
- **Make the authority the default, or the only commitment at
  `timestamped`.** Rejected: it puts a company, and a trust decision,
  in the default path of a tool whose default path leaves nothing to
  trust.
- **Replace the anchor with the authority.** Rejected: an authority can
  be leaned on; the anchor cannot.
- **Verify the token's signature in the stdlib.** Rejected: RSA
  PKCS#1 v1.5 alone is a few hundred lines of DER walking and modular
  arithmetic, ECDSA more, and a homegrown verifier is the wrong place
  for this repo to be clever. ADR-0026's delegation is the settled
  answer.
- **Bake in a default authority.** Rejected: whom to trust is the
  choice; a default makes it for them.
- **One sidecar for both, with a `kind` field.** Rejected: two evidence
  kinds in one file blur the line this ADR exists to draw.
- **Call it an anchor.** Rejected: see ruling 1.
- **`--tsa` as the flag.** Rejected: the acronym belongs to the
  mechanism, and the flag sits on the beginner's tier.

## References

- Related ADRs: `0003-anchoring-minimal-ots-subset.md` (amended by
  addition: its rejection of a TSA becomes an option beside the anchor;
  its default, its offline verify and its edge all stand),
  `0007-sidecar-manifest-seals-the-package.md` (a signature has no
  clock), `0024-anchor-at-session-end-opt-in-at-install.md` (opt-in at
  install, the session-end budget), `0025-a-head-record-is-what-the-machine-cannot-unsay.md`
  (fast POSTs before the slow calendar; the anchor as head record of
  first resort), `0026-the-store-ships-as-a-package-verified-by-one-file.md`
  (delegation to a tool the machine has; the note-not-verdict posture;
  the manifest's *when* seal), `0031-the-entries-go-to-a-url-that-can-only-add-never-delete.md`
  (the tier this flag sits on).
- Glossary terms **added**: *Authority timestamp*. **Sharpened**:
  *Anchor* (the credential-free commitment, named as such beside the
  other), *Profile* (the `timestamped` tier covers both).
- Prior art: RFC 3161; Authenticode and Adobe document signing;
  Sigstore's RFC 3161 timestamps beside Rekor; rsyslog with Guardtime
  KSI; eIDAS qualified timestamps.
- Raised: the author, 2026-09-15 ("OTS or another enterprise for
  external timestamping"); grilled 2026-09-16.
