# ADR-0024: Anchor at session end, opted in once at install; a same-login remote is not a head record

**Status:** accepted 2026-09-08 (grilled, issue #146; restated by the author)
**Deciders:** Acquiredl

## Context

Two attacks, two defenses. Editing, deleting, or reordering a past entry
is caught by `verify` at any time. Regenerating the whole chain (copy the
public format, write a consistent fake, delete the real one) is caught
only by something that remembers the old head: the operator's head record
(`verify --expect-head`), the supervisor's baseline (same machine, so a
reason to shout and never proof), or an anchor. Everything written after
the last anchored head can be replaced by a consistent fake, timestamps
included, until something outside the machine has seen the new head. That
is the window between anchors.

Anchoring has been a command (`loxodonta anchor`), or the supervisor's
`--anchor-every` cadence, off by default under the posture that nothing
leaves the machine without the operator's say-so. The author raised, and
then withdrew, "everything security on by default" (README grill,
2026-09-06): the posture stands. What was left to decide is how the
operator opts in with the least ceremony, what happens when the network
is not there, and whether an off-machine ledger through `gh` would be a
stronger closure than the anchor.

The hook already fires at `SessionEnd` and already writes the tail
transcript commitment there (ADR-0017), quietly: every failure path is a
silent skip, because the harness's SessionEnd budget is short (the
installer wires a 20-second timeout) and an exit hook that complains is
noise nobody can act on. The installer writes the hook's exact command
line into the harness settings, which is where the coverage matcher
already lives (ADR-0016).

Prior art. journald's forward-secure sealing seals the log on an interval
(fifteen minutes by default): the supervisor's `--anchor-every` shape.
Sigstore and cosign sign at an event boundary, the push or the release,
not on a timer; git's hooks fire at commit and push. Both shapes exist;
the event boundary is the one that needs no daemon running.

## Decision

> **The operator opts in once at install, and from then on every session
> end anchors its chain head, quietly and best-effort, with nothing else
> automated that leaves the machine.**

1. **The opt-in lives at install, on the hook.** `install-hook
   --anchor-at-session-end` writes `--anchor` onto the wired SessionEnd
   command (Claude Code and, with `--codex`, Codex). The choice is
   readable in the settings file by anyone, the recorder notice included,
   and `uninstall-hook` removes it with the rest. The supervisor's
   `--anchor-every` stays as the interval shape for an always-on machine.
   Anchoring every N receipts inside the hook is rejected: a network call
   in the recording path, on every Nth tool call, against a budget of
   about 135 ms per call.
2. **At session end, in this order: the tail commitment, then the
   anchor.** The head that gets anchored is the sealed one, and a slow
   calendar can never cost the commitment.
3. **Quiet, best-effort, under a fixed budget.** The hook posts the head
   to the calendars within a budget that fits under the harness's
   SessionEnd timeout, writes a sidecar record only for calendars that
   answered, and prints nothing on failure. Staleness is the supervisor's
   to surface, and its keeper already treats an aging head as quiet
   evidence, never a siren.
4. **The leftover budget upgrades pending proofs.** A calendar answers at
   once with a pending attestation; the Bitcoin-grade proof needs
   `anchor --upgrade` hours later, which only the supervisor's keeper or
   the operator's hand did. The session-end path spends what is left of
   its budget upgrading that drawer's pending proofs, oldest first, one
   request each, and stops when the budget is gone. A machine that never
   runs the supervisor reaches Bitcoin-grade on its own, one session late.
5. **The `gh` head ledger is rejected.** A gist or repository under the
   operator's login is reachable by an agent running as the operator on
   the same machine, because the `gh` token is on that machine; an agent
   that can run `curl` can run `gh gist delete`, and deleting a gist
   deletes its revisions. That is the writer-reachability that makes the
   supervisor's baseline a reason to shout and never proof, so such a
   ledger would be testimony, not a head record (GLOSSARY: *Head record*,
   "outside the writer's reach"). On a single machine the tool cannot
   automate a true head record; the anchor is that automation, the
   out-of-reach property outsourced to Bitcoin, and the manual head
   record stays the operator's ritual as documented.

## What none of this survives, and what leaves the machine

- **The agent killing the process that anchors.** The kill is itself a
  tool call, so the last receipt is the kill command; the supervisor's
  completeness alarm watches the silence that follows; and only an
  expectation held off the machine (a head arrives every session; none
  arrived) closes the case. Frequency shrinks the window. It does not
  close it. The docs keep saying so.
- **A spoofed calendar.** A proof from a calendar that never reaches
  Bitcoin fails to upgrade; one that claims a block it was never in fails
  the merkle-root check the verifier prints for the operator to confirm
  against a block source they trust. The verifier never fetches headers,
  on purpose (ADR-0003): a network dependency inside the one command whose
  job is local judgment. Copying the sidecar off the machine keeps that
  check independent of anything the agent can touch.
- **What leaves.** A 32-byte digest of the chain head, posted to the
  public calendars from the operator's address, only after the operator
  opted in at install. It reveals nothing about content; it does reveal
  that this address anchored something at that time.

## Consequences

**What gets easier:**

- One install command carries the choice, and an operator who never runs
  the supervisor still gets every session end anchored and, a session
  later, upgraded.
- The window between anchors is one session for anyone who opted in.

**What gets harder or more constrained:**

- Session end grows a network step, bounded but real; a machine offline
  at session end anchors nothing that time and says nothing about it,
  which the operator sees only in the supervisor's staleness reading.
- The README's anchor bullet and timing note change to say "at moments
  you choose, or at every session end once you opt in at install"; the
  pin test holds the demo unchanged.
- Codex does not get the flag. Codex caps a SessionEnd hook at three
  seconds (its docs), too short for a calendar round trip with any
  margin, so `install-hook --codex --anchor-at-session-end` refuses with a
  note rather than wiring an anchor that would usually be cut off; a
  Codex operator uses the supervisor's `--anchor-every`.

## Alternatives considered

- **Everything security-related on by default.** Withdrawn by the author
  before this grill: nothing leaves the machine without the say-so.
- **Only the supervisor's `--anchor-every`.** Already built and kept, but
  it costs a running supervisor, which the quick start does not assume.
- **Every N receipts in the hook.** Rejected, above.
- **The `gh` ledger, built as testimony.** Two copies of testimony are not
  more proof, and it is easy to mistake for evidence. Rejected.
- **Leave pending proofs to the keeper.** Honest, but leaves the
  no-supervisor operator at the calendar's tier forever. Rejected for the
  leftover-budget upgrade.

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (the ledger argument is
  this ADR's argument against keys, applied to a remote the machine can
  log in to), `0002-writer-as-adversary.md`, `0003-anchoring-minimal-ots-subset.md`
  (calendar and proof mechanics; the verifier never fetches),
  `0016-coverage-goes-wide.md` (the settings file as where a choice lives),
  `0017-transcript-commitments.md` (the SessionEnd path this extends).
- Raised: README grill, 2026-09-06; issue #146.
- Glossary terms **added or sharpened**: *Anchor* (the session-end
  anchor), *Head record* (a same-login remote is writer-reachable).
