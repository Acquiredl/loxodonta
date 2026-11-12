# ADR-0045: Entries leave as they are written, and the receiver says what it holds

**Status:** proposed 2026-11-11. Ruled by the author on that date after a design review of the whole tool, as one answer to the proposal with its three choices and a one-second cap. Built (#600) and not measured yet: accepted once the numbers under *Measured* are written in.
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

The rulings below are the second form of this decision. The first
had the recorder ask the receiver what it holds and then choose what
to send from its own files; its build (#600) showed that both halves
can be steered by a writer that holds the URL and owns the files.
The author ruled the reshape on 2026-11-11.

1. **The receiver keeps a line only when it is an entry.** A line is
   kept when it parses as an entry of SPEC section 2, its `n` is zero
   or more, and its `entry_hash` recomputes from its own bytes by the
   frozen rule (ADR-0036). A batch holding any other line is refused
   whole, 400, and nothing is appended. Two entries at one `n` are
   both entries and both kept: that collision is what the copy
   exists to show (ADR-0031 ruling 4).

2. **The receiver refuses a hole, and its answer says whether what
   it was sent connects.** A batch is refused, 409, with nothing
   appended, when an entry in it has an `n` more than one past the
   highest the receiver would then hold. Every answer to a batch,
   the 200 and the 409, carries the highest `n` held and whether the
   batch's first entry connects: it is a genesis, or its `prev` is
   the `entry_hash` of an entry held at the `n` before it that
   itself connects. So an entry connects only when every entry
   between it and its genesis is held, and a gap anywhere below
   shows in the answer to every entry above it.

3. **At `full`, each entry is sent when it is written, from the
   hook's own hand.** The installer writes the chain's URL onto the
   recording command as well as the session-end one, and the hook
   posts the line it has just appended. To do that it reads neither
   the chain nor the memo. An answer that the entry was kept and
   connects ends the step, and nothing is written down. An answer of
   a hole sends the entries after the highest held. An answer that
   the entry does not connect means entries below it are missing:
   the recorder finds the last of its own entries that does connect,
   by posting one entry at a time and halving the stretch between
   one that connects and one that does not, and sends on from the
   entry after it. An entry posted in that search is kept, and one
   already held is dropped, so nothing is sent in vain. The whole step
   waits at most one second, name lookup included, and what it did
   not reach goes with a later call, the session end or the keeper.
   A send that fails, is refused or runs out of time is never the
   hook's failure: the receipt is on disk and the hook exits as it
   would have. Its outcome is written to the memo as an attempt row
   only when it differs from the last row there, so a receiver that
   is down leaves one row and not one a call; a memo whose last row
   cannot be read gets the row. Below `full`, and under `custom`
   without the chain's flag, nothing is sent in the recording path.

4. **The session end asks every time, and the keeper asks when it
   has cause.** Each starts by posting the chain's last entry and
   goes on from the answer, as the hook does. The memo decides
   nothing at the session end for a receiver that answers as ruling
   2 says: its chain rows stay as a note of what left and when. The
   keeper stands down for a chain that has not changed since its
   last turn and whose end the memo names as held, so that an idle
   chain costs nothing; both of those lie in the writer's reach, and
   the limit is listed below. A remote that answers with no such statement is
   followed from the memo as before, with a note written once, and
   the limit of the memo stands for it.

5. **Anchor and stamp rows travel.** After a step that adds or
   upgrades a row in a chain's anchors or stamps sidecar, the rows
   are posted to the same URL under a content type of their own, with
   the chain's name in the header the batch uses, and the receiver
   appends them to a file beside its copy of the chain, dropping a
   row it already holds. Attempt rows do not travel. `verify
   --anchors` and `verify --stamps` then judge the receiver's files
   as they judge the recorder's. A send of rows that fails is written
   down as every quiet step is (#240), in the sidecar it was sending.

6. **Still no read endpoint.** Everything but a POST is refused, as
   before. What a POST is answered with is about the one chain it
   named, to a sender that holds the URL: a number, and whether the
   entry that sender posted connects.

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
- **A clean copy against a writer that posts.** The writer holds the
  URL and can post entries of its own making. They are kept beside
  the recorder's, and the copy then reads `BROKEN` where they
  collide. Nothing the recorder sent is lost by it, and the collision
  is the finding.
- **A remote that does not answer as the receiver does.** It is
  followed from the memo, which is in the writer's reach.
- **A keeper the writer has stood down.** For a session that never
  ends, a writer that forges a memo row naming the chain's end and
  sets the chain file's time back keeps the keeper from asking. The
  recording call and the session end ask all the same.
- **A note the writer wrote first.** An attempt row is written on a
  change of outcome, so a row forged with the failure to come hides
  the first real one. The receiver's reading is what shows a session
  whose receipts stopped (ADR-0046).

### Measured

Not yet. Once built, on the author's machine, written here before
acceptance:

- The time one recording hook takes with and without the per-entry
  send, median and 95th percentile over a real session, to the
  receiver on the author's second machine.
- The same with the receiver stopped: each call costs the cap and no
  more, and the memo gains one attempt row.
- A memo row forged with a `last` far ahead, or at the chain's end:
  the next recording call and the session end ask the receiver all
  the same.
- A line of the chain overwritten after it was sent: the entries
  written after it still arrive.
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
- The receiver gains two refusals and a second kind of file, and it
  now computes an entry's hash, where it appended bytes and judged
  nothing. It carries its own copy of that rule, as the supervisor
  and the verifier do.
- A line that is not an entry no longer reaches the receiver at all,
  so a chain damaged on disk arrives only as far as it is whole.
- Two earlier rulings are narrowed.

**What we'll have to revisit if:**

- The measured cost is more than a session can bear: the cap is one
  number, and a pause after a failed send is the next thing to try.
- A harness offers a hook that does not hold the agent while it runs.
- A receiver other than `receiver.py` is used that answers a batch
  with nothing: the recorder then falls back to the memo, and says so.

## Alternatives considered

- **The recorder asks what is held and sends from there.** The first
  form of this decision, built in #600 and withdrawn. The recorder
  still chose what to send by reading the memo and the chain, and
  took the receiver's count on its word: a line overwritten in the
  chain, a stray byte in the memo, a memo row at the chain's end, or
  a line posted to the receiver with a number of the writer's
  choosing each stopped the sends or skipped entries.
- **An entry connects when the one before it is held.** The second
  form as first built. An entry held above a gap answered for every
  entry after it, so a search for the gap that ran out of its second
  was never taken up again, and the entries below stayed missing.
  Connecting now runs back to the genesis.
- **Walk back one entry at a time.** Same build. About three entries
  a second on a long chain; halving finds the place in a dozen posts.
- **The receiver appends whatever it is sent.** As before this ADR.
  Rejected with the first form: an answer about lines nobody checked
  says nothing a sender can act on.
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
