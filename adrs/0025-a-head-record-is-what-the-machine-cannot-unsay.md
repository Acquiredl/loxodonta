# ADR-0025: A head record is what the machine's credentials cannot unsay; the recorder publishes heads to one (ADR-0024 ruling 5 amended)

**Status:** accepted 2026-09-08 (grilled from the two v0.2.0 external reviews; restated by the author)
**Deciders:** Acquiredl

## Context

Editing, deleting, or reordering a past entry is caught by `verify` at any
time. Regenerating the whole chain, or wiping it, is caught only by
something that remembers the old head. Three rememberers exist today: the
operator's own head record, kept by hand and rarely; the supervisor's
baseline, on the same machine, so a reason to shout and never proof
(ADR-0002); and the anchor (ADR-0003, ADR-0024), which is real but matures
in hours and whose proof sidecar sits on the machine, where the agent can
delete it (docs/ANCHORING.md §2 says so).

ADR-0024 ruling 5 rejected a fourth rememberer, a `gh` gist or repository
under the operator's login, in two steps. The first is a fact: the `gh`
token on the machine can run `gh gist delete`, and deleting a gist deletes
its revisions. The second generalized: "nor is a remote the machine can
log in to", which the GLOSSARY carried into its *Head record* entry along
with "on a single machine the tool cannot automate a true head record".

An external review of v0.2.0 (2026-09-08, the independent one) objected to
the second step: the security property of off-host storage is comparison
against history, not writer unreachability; an append-only remote the agent
can write to still catches a regenerated chain, because the old head cannot
be silently changed. Grilled, the objection holds and the gist verdict
holds with it. The two steps were conflated, and the property that
separates them is deletability.

Prior art, all older than this project. **Remote syslog**, the loghost:
since the 1980s the defense against an intruder who scrubs local logs has
been a machine across the network that the compromised host can append to
and nothing else. **Certificate Transparency** (RFC 6962) and **Sigstore
Rekor**: append-only logs anyone may write to; the security comes from
nothing being removable, not from vetting writers. **Object lock**, WORM
storage: a put-only credential under a retention lock cannot delete or
overwrite. Against these, a chat incoming webhook (Slack, Discord, Teams)
is the zero-infrastructure loghost: the URL posts and can do nothing else,
and the channel keeps what was posted. The GLOSSARY's own example of a head
record is "a message to self". This is that message, automated.

The goal this serves, bounded in the same grill: an operator can see every
tool call the harness completed, in order, know whether that record has
been touched since, and hand it to someone off the machine with the same
certainty. Completeness stays the integration's job (SPEC §8).

## Decision

> **A remote is a head record when it is off the machine and the
> credentials present on the machine cannot delete or overwrite what they
> wrote there. Same login is not the test; deletability is. The recorder
> publishes chain heads to such a remote, once the operator opts in: at
> session end before the anchor, and from the supervisor's keeper on a
> cadence.**

1. **The test, and what "credentials present on the machine" means.** Every
   token, key, cookie, and browser login that a process running as the
   operator can use, not only the `gh` token. A gist fails: the token
   deletes. A chat incoming webhook passes: it posts and does nothing else.
   An object store under a put-only credential with a retention lock
   passes. A channel whose administrator is logged in on the same machine
   passes only as far as that login cannot delete messages; the honest
   recommendation is a channel administered from somewhere else. The anchor
   passes with no credential at all, which is why it stays the head record
   of first resort.
2. **What is published: the fingerprint, never the work.** One small JSON
   body: `head`, `n`, `session`, `ts`, `event` (`session-end` or
   `cadence`), and one human-readable line under both `text` and `content`
   so Slack, Teams, and Discord render it with no configuration; a JSON
   receiver reads the structured fields. No paths, no project name, no
   action lines, no chain bytes. A published head is matched to its chain
   by the head itself.
3. **When: session end, before the anchor; the keeper, on a cadence.**
   `install-hook --publish-head URL` writes `--publish URL` onto the wired
   SessionEnd command, the way `--anchor-at-session-end` writes `--anchor`
   (ADR-0024 ruling 1). The order inside the session-end budget becomes
   commitment, publish, anchor: ADR-0024 put the commitment first so a slow
   calendar could never cost it, and the same rule says a slow calendar
   must never cost the one POST, which usually answers within a second
   and is cut off at three. Quiet and
   best-effort like the anchor; staleness is the supervisor's to surface.
   The supervisor's keeper publishes on `--publish-every`, beside
   `--anchor-every`, for always-on machines and for sessions that never
   reached their end. Publishing every N receipts inside the hook stays
   rejected for ADR-0024 ruling 1's reason: no network call in the
   recording path. Codex caps its SessionEnd hook at three seconds; whether
   one POST fits is measured before Codex gets the flag.
4. **The check: every published head is an entry hash inside the chain.**
   A regenerated chain fails on the earlier heads. A fake head the writer
   posts matches nothing and arrives after the real session end, which is
   itself a flag. In this release the check is the operator's ritual,
   `verify --expect-head` with a head copied from the remote; `verify
   --ledger FILE`, reading a saved copy of the remote's log and checking
   every head at its `n`, is the follow-up once there is a ledger to read.
5. **What stands.** The anchor remains the head record that needs no
   credential. The `gh` gist stays rejected. The supervisor's baseline is
   still not a head record. Nothing leaves the machine without the opt-in.

## What none of this survives, and what leaves the machine

- **The tail before the first publish.** Everything since the last head
  left the machine can be rewritten consistently: chain, transcript,
  commitments, and baseline are all writer-reachable, and the witness reads
  two writer-reachable files, so inside that window it can shout and never
  prove. Session-end publishing makes the window one session; the keeper's
  cadence bounds it for a session that is killed before its end, which is
  the bad day's shape: the hook was stripped, so no session end ever fired.
- **Existence, not contents.** A published head says a chain with this
  head and this many entries existed at this time. A wiped store is caught
  and not restored. Content survival is backup, and the honeypot arc may
  ask the recorder to publish chain bytes; that is its grill, not this one,
  because command lines leaving the machine at every session end is a
  different posture from a 32-byte digest.
- **The credential on the machine.** The webhook URL is on the hook's
  command line in the harness settings file, readable by the agent. That
  buys the agent the right to post fakes, which are visible noise, and to
  stop posting by killing the hook, which the completeness alarm watches.
  It buys no deletion, or the remote was never a head record.
- **The remote's own operator, and logins on the box.** Slack keeps the
  message because Slack chooses to; a workspace admin can delete it. If
  that admin login lives in a browser on the same machine, an agent with a
  browser tool reaches it. Ruling 1 names this; the tool cannot enforce it.
- **Garbage in, and everything outside a tool call.** A head record proves
  a record was not altered afterward. It says nothing about a harness that
  lied at write time, a failed call that fired no hook, a worktree the
  harness merged on its own, or a file the agent wrote that runs later as a
  cron job or a git hook: the write has its receipt and fingerprint, the
  later run has no session and no hook (ADR-0002, GLOSSARY *Coverage*).
- **What leaves.** `head`, `n`, `session`, `ts`, `event`, and one line
  repeating them, to a URL the operator chose, only after the opt-in. It
  reveals that this machine finished a session then, and how long the
  chain was. It names nothing.

## Consequences

**What gets easier:**

- A solo operator with a Slack or Discord account gets an automated head
  record in one install flag, immediate, with no wallet, no key, and no
  service to run.
- A regenerated or wiped chain is caught against a copy the agent cannot
  unsay, one session or one cadence late.
- An enterprise that will not put "Bitcoin" in a procurement document has a
  head record that is an object store with a retention lock, through the
  same one POST.

**What gets harder or more constrained:**

- Session end gains a second network step, bounded but real; a machine
  offline at session end publishes nothing that time and says nothing
  about it, which the operator sees only in the supervisor's staleness
  reading, as with the anchor.
- The GLOSSARY *Head record* entry and docs/ANCHORING.md §5 lose the
  sentence "nor is a remote the machine can log in to" and gain the test.
- Reading the remote back is not built. The comparison is the operator's
  until `--ledger` lands.

## Alternatives considered

- **Keep ADR-0024 ruling 5 as written.** Rejected: the generalization is
  false for a webhook and for WORM storage, and it kept the tool from
  automating the operator's one job on a single machine.
- **Require the remote to sit under an account the machine has no login
  to.** Rejected as a requirement: no webhook a solo operator has qualifies,
  and the deletability test already carries the property. Kept as the
  recommendation in ruling 1.
- **Publish the chain's bytes, the loghost proper.** Deferred to the
  honeypot arc: content survival is backup, and command lines would leave
  the machine on every session end.
- **Publish every N receipts inside the hook.** Rejected, ADR-0024 ruling
  1: no network call in the recording path; the witness owns the silence.
- **Have the supervisor read the remote back and compare.** Deferred: it
  needs a read credential per backend, and the first release should ship
  the property, not a client library.
- **Also publish the project name and chain file, for a readable
  channel.** Rejected: a project name would leave the machine on every
  session end; the head identifies the chain.

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (the head record as
  the answer to whole-chain regeneration), `0002-writer-as-adversary.md`
  (reach as the test; the baseline as a reason to shout),
  `0003-anchoring-minimal-ots-subset.md` (the anchor as the credential-free
  head record), `0024-anchor-at-session-end-opt-in-at-install.md` (ruling
  1 for the flag shape and the no-network-in-the-recording-path rule;
  ruling 5 amended here, its `gh` verdict kept).
- Glossary terms **sharpened**: *Head record* (the deletability test; the
  gist sentence rewritten; "cannot automate" retired). **Added**:
  *Published head*.
- Prior art: remote syslog and the loghost (RFC 5424, older in practice);
  Certificate Transparency (RFC 6962); Sigstore Rekor; S3 Object Lock;
  chat incoming webhooks as the zero-infrastructure case.
- Raised: the two external reviews of v0.2.0, 2026-09-08; grilled the same
  day with the package (ADR-0026).
