# ADR-0031: The entries go to a URL that can only add, never delete; the receiver is that URL; the profile is the one place to opt in

**Status:** accepted 2026-09-16 (grilled; restated by the author: *the entries go to a URL that can only add, never delete*)
**Deciders:** Acquiredl

## Context

ADR-0025 made the head record automatic: a chain head leaves the machine
to a remote the machine's credentials cannot delete from, and a
regenerated chain fails against the heads that already left. It also
named what a published head does not survive: a wiped store is caught
and not restored, because a head says a chain existed and never what it
held. The alternative that would close that, publishing the chain's
bytes, was deferred to the honeypot arc with the reason spelled out:
command lines leaving the machine at every session end is a different
posture from a 32-byte digest.

Two things brought it back outside the honeypot. The first is the
audience. The first community post (2026-09-14) drew views and no
comments, and the author's reading is that a security reader follows
the threat model and a beginner does not. A beginner cannot be asked to
compose `--anchor-at-session-end`, `--publish-head URL`,
`--anchor-every` and `--publish-every` into a coherent posture, and
today those are the only way to get one. The second is that the
strongest posture the tool can offer is not offered at all: with every
flag set, a wiped machine still takes the evidence with it.

Prior art, in two groups. For the off-box copy: **remote syslog** and the
loghost, **Certificate Transparency** and **Sigstore Rekor**, and **S3
Object Lock**, all already in ADR-0025, share one property, that the
sender can add and cannot take away. **Litestream** replicates an
append-only SQLite log to remote storage from a sidecar while the
format never learns about it (ADR-0005 cites it for the supervisor's
shape). The **OpenTelemetry Collector**, **Fluent Bit** and **Vector**
settle where vendor code lives: the producer on the untrusted box speaks
one dumb wire, and the pluggable exporters live in a separate collector
process. **Filebeat**'s registry is the cursor pattern: a per-file
position, batches, retries, and duplicates tolerated at the receiver.
For the bundle of choices: **Tor Browser's Security Level** (Standard,
Safer, Safest) and **Firefox's Enhanced Tracking Protection** (Standard,
Strict, Custom) give people who cannot judge individual settings a
ladder, with the raw settings still open to those who can; **Cloudflare's
SSL modes** ship a tier named plainly `Full` in a security product and
let the next line say what it means; **Apple's Lockdown Mode** is the
one-switch version.

## Decision

> **The recorder can send the entries themselves to a URL that can only
> add, never delete. The repo ships the receiver that is such a URL. The
> operator opts in once, at `install-hook`, by choosing a profile, and
> the strongest profile is the only one that sends the entries.**

1. **The profile is the opt-in surface.** `install-hook --profile
   local|timestamped|full|custom`. Strictly nested: `local` wires the
   hook and the transcript commitments and nothing leaves the machine;
   `timestamped` adds the session-end anchor and the keeper's anchor
   cadence, so a 32-byte digest leaves at each session end; `full` adds
   the published head and the published chain to one remote the
   operator names with `--remote URL`, and the keeper's publish cadence.
   `custom` is the raw flags as before. `full` without `--remote`
   refuses and prints the two ways to get one. The profile is written to
   the coverage marker beside the matchers (ADR-0030), so a profile that
   later changes is as visible to the supervisor as a matcher change,
   and `serve` reads it so the keeper's cadences follow without repeated
   flags; explicit `serve` flags still override. The tier names are the
   beginner's words and the mechanisms keep their own: an anchor is
   still an anchor at the `timestamped` tier. Never a "protection
   level": the tool detects and does not prevent, and a tier is named by
   what is remembered where.
2. **The published chain: the entries, verbatim, since the last send.**
   The body of one POST is the chain's lines exactly as they sit on
   disk, newline-delimited JSON, from the entry after the last one the
   remote acknowledged; the first send starts at genesis. The session
   id, the chain's file name, the `n` range and the head ride in request
   headers, so what the receiver appends is chain bytes and nothing
   else. No project name, no project record, no transcript. The memo
   beside the chain (`<log>.published.jsonl`, ADR-0025) records what
   left and up to which `n`, advances only on the remote's
   acknowledgement, and never holds the URL. Entries carry `n` and a
   hash, so a batch sent twice is harmless.
3. **When, and under what budget.** Session end, in ADR-0025's order:
   commitment, publish (head, then chain), anchor. The same budget rule
   as the head: cut off, quiet, best-effort. A chain batch that does not
   fit the budget is the keeper's on the next cadence, which the cursor
   makes resumable, so a long chain first sent from genesis arrives over
   a few cadences rather than costing the session end. No network call
   in the recording path (ADR-0024 ruling 1) stands: nothing is sent per
   receipt.
4. **The URL is the credential, and the receiver is one.** The
   head-record test of ADR-0025 applies unchanged: off the machine, and
   the credentials on the machine cannot delete or overwrite. A capability
   URL that posts and can do nothing else is that test met. The repo ships
   `receiver.py`, a third single file under the same constraints as the
   other two (stdlib only, readable in one sitting, ADR-0005's *single
   file per tool*): it mints its URL at startup, appends what arrives to
   one file per chain and one for heads, refuses everything that is not
   a POST, and has no read endpoint. Because what it appends is chain
   bytes from genesis on, **the receiver's file is a receipt log**, and
   `loxodonta verify --log` judges it with no new code: a regenerated
   chain arriving after the original fails the chain rule at the first
   entry that differs, which is the collision the copy exists to show.
5. **No vendor in the recorder, ever.** One wire shape. Anything that
   turns the receiver's files into somebody's storage grows on the
   receiver's side of the wire, never the recorder's. S3 direct, which
   would put a signing scheme and an access key into `loxodonta.py`, is
   not built.
6. **What stands.** The head-record test and the `gh` gist verdict
   (ADR-0025). The anchor as the head record that needs no credential
   (ADR-0003). The baseline as not a head record (ADR-0002). Nothing
   leaves the machine without the opt-in, and the `local` profile is the
   no-flag default.

## What none of this survives, and what leaves the machine

- **The tail since the last send.** As in ADR-0025: everything after the
  last acknowledged entry can still be rewritten consistently. The
  keeper's cadence bounds the window; session end closes it for sessions
  that reach one.
- **What leaves, said plainly.** At `full`, every entry: the timestamp,
  the actor, the action line, and the file references. Action lines are
  command lines and can contain anything the agent typed, including
  absolute paths and a secret pasted on a command line. This is the
  export's `--raw` stance (ADR-0021), and the install text says it
  before the first send. A beginner who wants the strongest tier is told
  what it costs in the same breath.
- **The receiver's own operator.** Whoever runs the receiver can read
  and delete its files. When that is the operator on a second machine,
  the property holds. When it is anyone else, that is a trust
  relationship this decision does not design.
- **The receiver's box.** A receiver reachable from the writer's machine
  by a credential other than the URL (an SSH key on the box, a shared
  filesystem) is reachable by the writer. Ruling 4's test names this; the
  tool cannot enforce it.
- **Garbage in.** The copy is of what the writer said. A harness that
  lied at write time is copied faithfully (ADR-0002).

## Consequences

**What gets easier:**

- A beginner types one word and gets a coherent posture, and the
  strongest posture the tool can offer exists for the first time: a wiped
  machine no longer takes the evidence with it, as of the last send.
- The receiver's copy is verified by the recorder as it is, so the
  off-box reading needs no client library and no new verdict vocabulary.
- An operator with an old laptop or a small VPS has a loghost in one
  file; the `full` tier stops being a property only enterprises reach.

**What gets harder or more constrained:**

- A third file, a third test suite, a third tour when it is walked, and
  the repo map in CLAUDE.md grows a line.
- Session end sends more bytes; the budget rule keeps it bounded and the
  keeper carries what did not fit.
- The README's claims grow one that main must stay true to: the copy
  survives a wipe *as of the last send*, never "your receipts are backed
  up".
- ADR-0025's deferral to the honeypot arc is taken up here instead; the
  honeypot inherits it rather than deciding it.

## Alternatives considered

- **Name the tiers by mechanism (`local` / `anchored` / `published`).**
  Rejected by the author: a beginner does not know what an anchor is.
  The mechanism keeps its name in the glossary and the code.
- **`local` / `local+` / `full security`.** The author's first names.
  `local+` says nothing about what the plus is; `full security` promises
  prevention. Plain `full` kept.
- **Call the bundle a posture, a mode, or a level.** Rejected: *posture*
  is this repo's word for an artifact's trust standing; the other two
  say nothing.
- **S3 (or GCS, or Azure) direct from the recorder.** Rejected: one
  vendor's signing scheme in a stdlib file, an access key on the machine
  that has to be put-only with a retention lock configured right, and
  then the second vendor asks. The collector pattern puts that on the
  receiver's side if it is ever wanted.
- **A multipart upload shaped for a chat webhook that takes attachments.**
  Rejected: a second body shape for one vendor. Chat webhooks stay the
  zero-infrastructure remote for the head, which is one small JSON body;
  the chain's zero-infrastructure remote is the receiver on any second
  box.
- **Ship no receiver and require the operator to find a remote.**
  Rejected: it makes `full` unreachable for most people and leaves the
  head-record test as homework.
- **A read endpoint on the receiver.** Rejected for the first release:
  the operator reads the files on that box, and the smallest surface
  wins.
- **Publish every N receipts inside the hook.** Stays rejected
  (ADR-0024 ruling 1).

## References

- Related ADRs: `0002-writer-as-adversary.md` (reach as the test),
  `0003-anchoring-minimal-ots-subset.md` (the anchor at the
  `timestamped` tier), `0005-supervisor-as-sibling-tool.md` (single file
  per tool; the receiver is the third), `0021-field-data-export-is-allowlisted-and-sent-through-gh.md`
  (the `--raw` stance applied to what leaves), `0024-anchor-at-session-end-opt-in-at-install.md`
  (opt-in at install, no network in the recording path),
  `0025-a-head-record-is-what-the-machine-cannot-unsay.md` (the test,
  the order at session end, the deferral taken up here),
  `0030-the-recorder-writes-down-what-coverage-it-wired.md` (the marker
  the profile is written to).
- Glossary terms **added**: *Profile*, *Published chain*, *Receiver*.
  **Sharpened**: none; *Head record* and *Published head* stand as
  written.
- Prior art: remote syslog and the loghost; Certificate Transparency
  (RFC 6962); Sigstore Rekor; S3 Object Lock; Litestream; the
  OpenTelemetry Collector, Fluent Bit and Vector for where vendor code
  lives; Filebeat's registry for the cursor; Tor Browser's Security
  Level, Firefox's Enhanced Tracking Protection and Cloudflare's SSL
  modes for the ladder and its plain names.
- Raised: the author, 2026-09-15, after the first community post; grilled
  2026-09-15 and 2026-09-16.
