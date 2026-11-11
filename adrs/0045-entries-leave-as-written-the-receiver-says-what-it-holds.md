# ADR-0045: Entries leave as they are written, and the receiver says what it holds

**Status:** proposed 2026-11-11. Ruled by the author on that date after a design review of the whole tool, as one answer to the proposal with its three choices and a one-second cap. Nothing is built or measured yet: accepted once the build lands and the numbers under *Measured* are written in.
**Deciders:** Acquiredl

## Context

At the `full` profile the entries go to a URL that only adds
(ADR-0031). They go at session end, and on the keeper's cadence for a
session that never reaches one. Until then a session's chain sits on
the machine of the writer the chain is kept against. Two things follow.

**The live session can be rewritten.** A session writes a receipt at
10:00, rewrites the chain file from that entry on at 10:05 with a
milder action line and new hashes, and ends at 11:00. The chain that
is sent is the rewritten one, and the receiver's copy is `VALID`,
since the receiver never held the entry of 10:00. The harness's own
events at the receiver's second door (ADR-0041) show that a call was
made. They do not hold what the action line said.

**The recorder asks its own notebook what was sent.** The send starts
after the highest `last` among the publish memo's chain rows, and the
memo lies beside the chain. One row with a `last` far ahead means
nothing is sent again, and the session end writes no failure, because
a chain with nothing after the cursor was not a step.

A third thing is #524: the anchor and stamp sidecars lie beside the
chain too, and a proof deleted there is gone.

ADR-0024 ruling 1 and ADR-0031 ruling 3 kept the network out of the
recording path, against a budget of about 135 ms a call. This ADR
spends from that budget, at `full` only, and says what it buys.

### Prior art, read on 2026-11-10

| System | What it does | What is taken from it |
|---|---|---|
| Schneier and Kelsey, *Secure Audit Logs to Support Computer Forensics* (1999) | with a channel to a trusted machine, each entry is sent as it is made and no key is needed; the keyed scheme is for the machine with no channel | send as written |
| Kafka's idempotent producer (KIP-98) | the broker holds the last sequence number for each producer, drops a duplicate, refuses a gap and says which number it expected | the far end is the authority on what it holds, and its answer says so |
| Certificate Transparency, Rekor | a write is answered with what the log now holds | the answer to a write |
| systemd-journald's sealing, and the forward-secure schemes behind it | a key on the logging machine that moves forward | not taken: a writer in the same account reads the key |
| RELP, audisp-remote | delivery to a far machine, acknowledged | delivery only: neither makes the far end the authority on the sequence |

## Decision

1. **The receiver's answer to a batch says what it holds.** The 200
   carries, beside `appended` and `dropped`, the `n` and the
   `entry_hash` of the last entry the receiver holds for that chain.
   The recorder sends from the entry after that one. The memo's chain
   rows stay as a note of what left and when, and decide nothing. A
   memo that names a later entry than the receiver holds is said, as
   an attempt row.

2. **The receiver refuses a batch that would leave a hole.** A batch
   whose first entry is past the one after the last it holds is
   answered 409 with what it holds, nothing is appended, and the
   sender goes again from there. An entry at or before the last one
   held that is not the line held is appended as before: that
   collision is what the copy exists to show (ADR-0031 ruling 4).

3. **At `full`, each entry is sent when it is written.** The
   installer writes the chain's URL onto the recording command as
   well as the session-end one, and the hook posts the entries the
   receiver does not hold before it returns. The send waits at most
   one second, name lookup included. A send that fails, is refused or
   runs out of time is never the hook's failure: the receipt is on
   disk, the hook exits as it would have, and the entries go with the
   next call, the session end or the keeper. Its outcome is written
   to the memo as an attempt row only when it differs from the last
   one written, so a receiver that is down leaves one row and not one
   a call. Below `full`, and under `custom` without the chain's flag,
   nothing changes and nothing is sent in the recording path.

4. **The session end and the keeper stay.** They send what the
   per-entry sends left, by the same rule: from what the receiver
   says it holds.

5. **Anchor and stamp rows travel.** After a step that adds or
   upgrades a row in a chain's anchors or stamps sidecar, the rows
   are posted to the same URL under a content type of their own, with
   the chain's name in the header the batch uses, and the receiver
   appends them to a file beside its copy of the chain, dropping a
   row it already holds. Attempt rows do not travel. `verify
   --anchors` and `verify --stamps` then judge the receiver's files
   as they judge the recorder's.

6. **Still no read endpoint.** Everything but a POST is refused, as
   before. What a POST is answered with is about the one chain it
   named, to a sender that holds the URL: a number and a hash of
   lines that sender, or an earlier one with the same URL, sent.

7. **The docs say it** once built: `docs/RECEIVER.md` section 4 (the
   answer, the 409, the sidecar rows), `docs/HOOK.md` (the per-entry
   send, its cap, what leaves and when), `docs/CLAIMS.md` and
   `docs/TOPOLOGY.md` where they say when the entries leave, the
   installer's notice at `full`, and addenda on ADR-0024 and ADR-0031
   for the rulings this narrows.

### What it claims, and what it does not

It claims that at `full`, with the receiver reachable, an entry is
out of the writer's reach within about a second of being written, so
a rewrite after that shows as a chain that disagrees with the
receiver's.

It does not claim:

- **The second before the send, or a send that failed.** A writer
  that stops the send, by the network or by the process, keeps the
  entries in reach for as long as it does. What shows it is at the
  receiver: the harness's events arriving for calls whose receipts
  do not (ADR-0041).
- **What the receipt says.** An entry leaves as written, and what
  was written is the recorder's reading of the call.
- **Anything below `full`.**
- **A receiver that lies.** Its answer is believed about what it
  holds.

### Measured

Not yet. Once built, on the author's machine, written here before
acceptance:

- The time one recording hook takes with and without the per-entry
  send, median and 95th percentile over a real session, to the
  receiver on the author's second machine.
- The same with the receiver stopped: each call costs the cap and no
  more, and the memo gains one attempt row.
- A memo row forged with a `last` far ahead: the next send goes from
  what the receiver holds.
- A chain rewritten from an entry already sent: the receiver's file
  no longer verifies from that entry.

## Consequences

**What gets easier:**

- The window in which a session can rewrite its own history closes
  from the length of the session to about a second.
- One answer to "what has left": the receiver's, and the recorder
  asks for it.
- Sibling chains need no rule of their own: each one's entries leave
  by its own calls.
- A proof survives the deletion of its sidecar.

**What gets harder or more constrained:**

- Every tool call at `full` pays for a connection to the receiver,
  and a receiver that is down costs a second a call until it is back.
- The recording command at `full` carries the URL, which is the
  credential, as the session-end command already does.
- The receiver gains a refusal and a second kind of file.
- Two earlier rulings are narrowed.

**What we'll have to revisit if:**

- The measured cost is more than a session can bear: the cap is one
  number, and a pause after a failed send is the next thing to try.
- A harness offers a hook that does not hold the agent while it runs.
- A receiver other than `receiver.py` is used that answers a batch
  with nothing: the recorder then falls back to the memo, and says so.

## Alternatives considered

- **The keeper sends every few seconds.** No cost to a tool call.
  Rejected: the keeper is a process the writer's account can stop,
  and the hook is fired by the harness.
- **A key that moves forward on the writer's machine.** Rejected: the
  writer reads it.
- **Keep the memo as the cursor and seal it.** Rejected: whatever
  sealed it would lie in the same reach.
- **A read endpoint for the cursor.** Rejected: ruling 6 gets the
  same answer from the write.
- **A message from the recorder when a session opens.** Not taken up:
  at `full` the harness already tells the receiver of every session.
- **A cap of half a second, or of three.** Half misses a slow TLS
  handshake on an ordinary day; three is three seconds a call while
  the receiver is down.

## References

- #524 (a proof deleted beside its chain), #263 (the cursor is per
  remote), #240 (attempt rows)
- ADR-0002 (the writer is the adversary), ADR-0004 (never stop
  recording), ADR-0024 ruling 1 and ADR-0031 rulings 2 to 4 (narrowed
  here), ADR-0038 (sidecar rows name their kind), ADR-0041 (the
  second record)
- `docs/RECEIVER.md` section 4, `docs/HOOK.md`
