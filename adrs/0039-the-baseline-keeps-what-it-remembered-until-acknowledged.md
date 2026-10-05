# ADR-0039: The baseline keeps what it remembered until the chain holds it again or the operator accepts the change; a memory that cannot be read is an alarm

**Status:** proposed 2026-10-01, drafted for the author to confirm: ruled by delegation on #401 (which covers the first half of #409), and built with both; the words are the author's to change.
**Deciders:** Acquiredl

## Context

The baseline is the supervisor's remembered copy of chain heads, kept
between looks so a change appends cannot explain is a reason to shout
(GLOSSARY *Baseline*, ADR-0002, ADR-0005). Until this decision it was
remembered anew after every diff: an alarm belonged to the look that
caught it, and the next look was quiet. #387 kept the remembered head
for one case, a chain that reads as no entries. Its review measured
what that left open (#401), and #409 measured the rest:

- **Delete for one look.** A `vanished` chain was dropped from the
  memory, so a chain put back at the same name a look later read as a
  new one: exit 0, no event.
- **Shrink and wait one look.** A chain cut short read `regressed`, and
  a regenerated one `rewritten`, once. The look after remembered the new
  head and was clean. A writer's cheapest route to a clean memory over a
  rewritten history was one alarmed look.
- **The quiet one.** A baseline that could not be read (not JSON, the
  wrong shape, a folder or a pipe at its name) was a note in the report,
  exit 0, and the look remembered afresh. A missing baseline was a cold
  start, silent. Corrupting or deleting the file bought a clean memory
  with no exit at all. Beside it, #403: one row of the wrong shape ended
  every scan in a traceback, exit 1, the `BROKEN` rung (ADR-0037).

And one dated line ADR-0014's #271 addendum asked for: under `serve`, a
turn nobody asked for writes the day book when it catches a baseline
event, because such an event was read once. #387 made one event found
on every look, so every keeper turn painted the day and counted it as
watched for as long as the chain stayed empty.

### Prior art, read at the primary source on 2026-10-01

When may a remembered state be replaced:

| System | What it does | Alarm | The acknowledgement | Where it breaks |
|---|---|---|---|---|
| AIDE | `--check` never writes; `--update` writes a new database to another file, and replacing the old one "should always be a manual operation" | Persists on every check | A file move by the operator, from read-only media | Relies on media the adversary cannot write |
| Open Source Tripwire | A check reports and leaves the database alone; an update shows a ballot box per violation and re-signs with the local passphrase; in its secure mode an update aborts if the file no longer matches the report being accepted | Persists until acknowledged | A verb, per item, behind a secret, accepting only the state that was reported | Needs a key; this project is keyless (ADR-0001) |
| OpenSSH `known_hosts` | Refuses a host whose key changed and never rewrites the stored key; `accept-new` trusts a new host and still refuses a changed one | Persists on every connection | Removing the entry (`ssh-keygen -R`), unauthenticated | Its adversary cannot reach the file |
| The Update Framework | A client never replaces trusted metadata with a lower version; it discards, aborts and reports a rollback | Persists every cycle | None on the client; only a statement signed by offline root keys resets it | Has an offline root of trust |
| Certificate Transparency (RFC 6962, RFC 9162) | A monitor accepts a new tree head only with a consistency proof from the one it holds; two conflicting heads are proof of misbehaviour | Permanent | None | Many monitors, signed heads |
| Prometheus with Alertmanager, Nagios | An alert is active for as long as its condition holds; a silence or an acknowledgement is a separate object with an author, a reason and an end, and never rewrites the monitor's state | Persists while the condition holds | A recorded object beside the state | No adversary who wants the alert gone |
| **Counter-examples:** Samhain's running daemon, OSSEC syscheck | Alarm once, then follow the change (OSSEC ignores a file after three changes by default) | One-shot | None needed | Both ship the alert to a server the monitored host cannot reach before it can be undone; Samhain's on-disk baseline still alarms again at the next start until `samhain -t update` |

Five of seven keep the remembered state until something explicit
happens, and none lets the checked party's new state overwrite the
baseline on its own. The two that follow the change do so because the
alert has already left the machine, which this supervisor's does not.
Certificate Transparency and TUF sharpen the release condition: a longer
chain clears `regressed` only if the entry at the remembered position
still hashes to the remembered head, so growth never clears `rewritten`
by length alone. On the acknowledgement the set agrees on four things:
the checker never acknowledges on its own behalf; it is a separate,
recorded act and not a side effect of looking; it accepts only the exact
state that was reported; and where it is unauthenticated it is worth
only as much as the record of it kept where the adversary cannot reach.
No keyless tool in the set has an acknowledgement that resists a local
adversary by itself.

A database that cannot be read or kept: AIDE exits 18 (an I/O error) or
24 (a database error) when its own database is missing, truncated or
unwritable, codes apart from "changes found". Tripwire's exit bit 8,
errors during the check, covers a missing database. Linux `auditd` makes
a silent failure to write its record an explicit choice and never the
default. NIST SP 800-53 AU-5 requires an alert when the logging process
fails. Samhain's manual warns that a deleted baseline means changes can
no longer be recognised. No counter-example was found: no integrity
checker read treats its own missing or unreadable database as a clean
run.

## Decision

> **A remembered chain that reads `regressed`, `rewritten` or `vanished`
> keeps the head and number the baseline remembered, and the scan says
> so on every look, exit 5, until the chain holds that head again or the
> operator accepts what is there with `supervisor acknowledge`. A
> baseline the scan cannot read or keep is exit 5 on every look, and the
> scan starts no new memory on its own. The supervisor never
> acknowledges on its own behalf.**

1. **The baseline keeps what it remembered.** The row keeps the
   remembered `head` and `n` and carries a marker of the standing alarm:
   the change, and when the look that first found it ran. Each later look
   that finds the same chain still changed keeps that time. The event in
   the report carries it, with what was remembered and what was found,
   so the operator has the head an acknowledgement names. A vanished
   chain keeps its row and reads `vanished` while nothing stands at its
   name; what is put back later is diffed against the remembered head,
   and the marker's change follows what is found while its time stays.
   A chain under a standing alarm has not grown: its stillness clock
   (ADR-0018) keeps the time it last moved, and it never reawakens. The
   verdict fields the digest reads stay this look's, as #387 left them.
2. **What clears it.** The chain again holding the remembered head at
   the remembered number, after which appends explain everything and the
   row follows the chain as it always did; or an acknowledgement. Growth
   never clears anything by length alone.
3. **The acknowledgement is one verb.** `supervisor acknowledge LOG
   STATE` names one chain, as the event's `log` prints it, and the state
   the operator accepts: the head the event's `found` printed, whole or
   its first 12 hex characters or more, or the word `gone`. It is refused,
   changing nothing, when no alarm stands for that chain, when the chain
   holds the remembered head again, or when the chain is no longer in the
   state named; the refusal says what it found. Accepted, the row
   remembers the chain as it stands (or is dropped, for `gone`), and one
   record goes into a list kept whole in the baseline: when, which chain,
   the change, what was remembered, what was accepted. Every later
   report carries the list, and it never raises an exit or changes an
   event. The verb runs no keeper, sends nothing off the machine, appends
   to no chain and writes nothing but the baseline. It moves no verdict:
   `verify`, the anchors and any published head judge the chain exactly
   as before.
4. **A baseline the scan cannot read or keep is an alarm.** Not JSON, a
   row of the wrong shape, a folder or a pipe at its name: the look
   reports it, exit 5, remembers and compares nothing, runs neither
   keeper (their throttle is in the file it cannot read), and leaves the
   file as it lies. So does a baseline missing where a day book stands
   that records a scan. A write the system refuses is exit 5 with the
   reason. `supervisor acknowledge --baseline` starts the memory afresh
   from every chain as it stands, records that it did and what stood
   there, and says that the calibration memory the old file held is lost.
   A store with neither file is a first look and seeds quietly, as
   before; so does a day book that records no scan, which is what
   opening the page before the first scan leaves.
5. **The day book keeps ADR-0014's rule** and raises no exit. A turn
   nobody asked for writes its row for an alarm the look found new (or
   whose change moved), a reawakening, or a blind memory the book does
   not already show; it does not write one for an alarm already
   standing. A standing alarm colours the day it was found and the days
   somebody looks, and does not mark every later day as watched. A turn
   somebody asked for writes its row as always.

Exit 5 and no new number: the ladder keeps its length, and a script that
reads 5 as "investigate" already does the right thing. What the alarm is
about is in the report's words, and `baseline.blind` says when the memory
itself is the reason.

## What none of this closes

The baseline stays in the writer's reach. A writer who rewrites a chain
and then rewrites the baseline to match, or runs `supervisor acknowledge`
itself, is not stopped by any of this, and no keyless tool read for the
prior-art pass has an acknowledgement that resists a local adversary.
The change closes the two cheap doors, delete for one look and shrink
and wait one look, and the quiet one, a memory that cannot be read. The
hard boundary is still the anchor and the published head (ADR-0002,
ADR-0025).

The named residual: deleting both the baseline and the day book reads
as a new install, and so does deleting the baseline and leaving a day
book that records no scan.

## Consequences

**What gets easier:**

- A writer can no longer clear the tripwire by waiting one look.
- A chain put back where one vanished is diffed against what was there.
- A corrupt, deleted or planted baseline is visible on every look, to a
  cron job reading the exit and to a pager reading `/metrics`, and one
  row of the wrong shape no longer stops every scan with a traceback.

**What gets harder or more constrained:**

- A chain removed on purpose alarms until the operator says `gone`: one
  acknowledgement per chain.
- An acknowledgement is testimony. It is a record in a writer-reachable
  file, shown on every report; it is worth as much as a copy of it kept
  out of reach, which is what the scrape's time series of
  `loxodonta_baseline_acknowledgements` and the scan's exit can be.
- While the memory is blind the keepers wait, so nothing is anchored or
  published on the keeper's cadence until somebody acknowledges it; the
  hook's session-end steps are not affected.
- A scan does not write over a baseline that changed while it ran (an
  acknowledgement, a calibration or another scan wrote it): it leaves
  that file standing and says so, and the next look reads it.

## Alternatives considered

- **Clear by growth past the remembered length** (#387's words). Rejected:
  Certificate Transparency and TUF both refuse it, and a regenerated
  longer chain would clear itself.
- **Keep the one-shot alarm.** Rejected: the two systems that alarm once
  can, because their alert has left the machine before it can be undone;
  this supervisor's has not.
- **Let the scan acknowledge after some number of looks.** Rejected: the
  checker never acknowledges on its own behalf.
- **Accept whatever stands there now.** Rejected: Tripwire's secure mode
  aborts an update whose file no longer matches the report, and an
  acknowledgement that accepted the present would accept a second change
  the operator never saw.
- **A new exit number for a blind memory.** Rejected: the ladder keeps
  its length, and 5 already means investigate.
- **Remember afresh from a blind look, as before, with exit 5.** Rejected:
  the next look would be clean, which is the one-look door again.

## References

- Related ADRs: `0001-hash-chain-not-signatures.md` (keyless),
  `0002-writer-as-adversary.md` (the baseline as a reason to shout),
  `0005-supervisor-as-sibling-tool.md`, `0014-the-day-book.md` (the #271
  addendum's dated line), `0018-session-lifecycle-reading.md` (the
  stillness clock), `0025-a-head-record-is-what-the-machine-cannot-unsay.md`
  (the published head), `0033-the-supervisor-exposes-its-counts-for-the-operators-own-siren-pull-only.md`
  (the new gauge), `0037-exit-1-means-broken-and-nothing-else.md`.
- Issues: #387, #401 (the ruling and the prior-art comment), #403, #409.
- Prior art: AIDE (`aide.1`, `aide.conf.5`); Open Source Tripwire
  (`tripwire.8`, `twfiles.5`); OpenSSH (`ssh_config.5`, `ssh-keygen.1`);
  The Update Framework specification 5.3.5, 5.3.10, 5.3.11, 5.4.3;
  RFC 6962 5.3 and 7.3, RFC 9162 8.2 and 8.3; Prometheus Alertmanager
  silences; Nagios acknowledgements; Samhain; OSSEC syscheck;
  `auditd.conf.5`; NIST SP 800-53 AU-5.
- Glossary terms **sharpened**: *Baseline*.

## Addendum, 2026-10-02: a folder the scan cannot list is exit 5 too

*Drafted for the author to confirm (#431).* Part 4 made a memory the
scan cannot read or keep an alarm; the census beside it still read a
store folder this user may not list as empty. A drawer or the receipts
folder closed with `chmod 000` hid its chains, said nothing of the
folder, and the "store empty" note was printed beside the events it
caused. Closing a folder is in the writer's reach, as deleting the
baseline is, so it gets the same answer: the scan names each folder its
census cannot list and exits 5 on every look while it stays closed, and
never calls the store empty beside it. Exit 5 now covers a change
appends cannot explain, a baseline the scan cannot read or keep, and a
folder the census cannot list. `export` carries it as the scan's exit 5
and says it on stderr, its own exit unchanged. The other readers
(recall, `adopt`, `package`, `acknowledge --baseline`) refuse by name
with 66 rather than act on part of the store, and `serve`'s views over
the store answer 503 by name. Every listing of the store by the
supervisor goes through one helper that names or raises such a folder,
on every Python.

## Addendum, 2026-10-05: the named residual also retires a standing alarm

*Drafted for the author to confirm.* The decision names one residual:
deleting both the baseline and the day book reads as a new install. A
red-team pass measured what follows from it. A live session the scan
had reported as `ALARM-SILENT`, exit 6, is unjudged after the two files
are deleted: the scan stamps its first observation now, the session's
calls fall before memory (ADR-0029 ruling 3), and it reads clean on
that look and on every later one. Deleting the baseline alone is still
exit 5.

No code changes. Both files are in the writer's reach, and a third
file that remembered them would be too. The answer is the one this
ADR already gives for the heads: what must outlast the writer is kept
off the machine. Nothing the supervisor remembers about sessions is
kept there today, and `docs/CLAIMS.md` says so among its limits.
