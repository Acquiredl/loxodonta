# ADR-0030: The recorder writes down what coverage it wired; the supervisor reads it

**Status:** accepted 2026-09-11 (restate-to-ratify passed)

**Deciders:** Acquiredl

## Context

ADR-0029 gave the calibration memory an inception: the supervisor's first
observation stamps itself, and a session older than that is
`BEFORE-MEMORY`, judged not at all. The ruling is right and the bug it
closed was real. What it did not consider is *when a new installer's
first observation happens*.

`docs/START.md` asks for five steps in this order: wire the hook (step
2), work normally for a week (step 3), scan (step 4). The supervisor's
first look is therefore step 4, a week after recording began, and every
session recorded in between falls before its memory.

Walked as a stranger against the published `v0.5.0` files, in a
sandboxed home, the two orders come out like this:

| order | judged | before memory |
|---|---|---|
| install, work a week, scan | 0 of 3 | 3 |
| install, scan, work, scan | 2 of 2 | 0 |

A new installer following the page exactly gets zero judged sessions and
an export that says nothing about completeness — the flagship claim, and
the whole reason issue #135 collects exports at all. That is worse for a
first reader than the deficit wall ADR-0029 removed: the wall was wrong
and loud, and this is silent.

The cause is not a defect in ADR-0029. It is that the supervisor is the
only thing allowed to say when coverage began, and it can only speak
from when it started looking. The moment coverage actually begins is
observable, exactly once, by a different program: `install-hook` knows
which matchers it wired at the instant it wires them.

Prior art consulted. **auditd** records rule changes as stamped
`RULE_CHANGE` events appended to the log itself: the tool that changes
coverage writes down the change, and the analyser reads that record
rather than inferring a boundary from when it started reading.
**dpkg** keeps what it installed and when in its own database, which
other tools consume instead of re-deriving. **TLS certificates** state
`notBefore` on the issuer's word, because the issuer is the authority
for when validity began, and relying parties do not infer it from when
they first saw the certificate. Against these sits **Prometheus**, whose
convention is the opposite — the collector owns the clock and anything
before its first scrape is simply absent. That is the design we have,
and it is the one that produced this bug.

This crosses a boundary ADR-0005 drew on purpose: `loxodonta.py` is the
frozen recorder, and the dependency runs supervisor → recorder, never
back. The crossing is narrow and the ground is already partly crossed.
`install-hook` checks that the supervisor sits beside the recorder and
refuses otherwise, and it writes `supervisor.py digest` into the
harness's own settings file (ADR-0020). The store is the recorder's
house: it creates it and every chain in it. Writing down what it just
wired is the recorder recording its own action, not reaching into the
supervisor's memory.

## Decision

Ratified restatement, in the author's words: *the recorder writes down
what coverage it wired, the supervisor reads it.*

1. **`install-hook` appends to `~/.loxodonta/coverage.json`**: one entry
   per change, each carrying `since`, `matchers` and `harness`. A run
   that wires nothing different appends nothing — the `heal()` rule
   `calibrate()` already follows. `harness` is load-bearing, because
   `install-hook --codex` wires `.*` into a different settings file and
   Codex's coverage must never speak for the Claude Code witness. This
   is a deliberate, narrow exception to ADR-0005's freeze, taken in the
   open rather than allowed to pass as routine: the recorder gains one
   writer for one file in its own store, no imports, no new command, and
   no format change to the chain.

2. **`uninstall-hook` writes nothing.** The asymmetry is the whole
   argument. A start-of-coverage claim says more calls owe receipts; an
   end-of-coverage claim says fewer do, and "nothing was owed from here"
   is exactly the silence the completeness alarm exists to catch
   (ADR-0002, `docs/OWASP.md`: an attacker can stop the recording, but
   cannot make the stopping quiet). A writer who could record the end
   could retire the alarm by writing a file.

3. **The supervisor reads `coverage.json` fresh on every scan and merges
   it in memory. It is never copied into the baseline.** One sentence
   stays true of the baseline: it holds what the supervisor observed,
   and nothing else. That line is what ADR-0029 spent a ruling
   establishing, and copying would blur it.

4. **A coverage epoch is accepted only before the supervisor's first
   observation.** Time the supervisor watched is its own. This is
   ADR-0029 ruling 6 applied to a second source rather than a second
   policy invented for it, and it holds by construction anyway: you
   install before you ever scan.

5. **Three sources, each named.** The supervisor's own observations
   carry no `source`; `calibrate --since` writes `operator`; this writes
   `recorder`. Any surface that judged a session by a non-observed epoch
   says so in words. On the same instant the operator's word wins, being
   the more deliberate act, and ADR-0029 already gave it standing.

6. **A store with no `coverage.json` behaves exactly as it does today.**
   Re-running `install-hook` after this ships stamps *now*, which helps
   from that moment forward and recovers no past install date, because
   nothing recorded one. Such a history stays before memory, correctly,
   and `calibrate --since` remains the way to state it when the operator
   knows. The before-memory words name both paths rather than leaving a
   reader to find them.

## Consequences

**What gets easier:**

- The five steps work as written. A reader installs, works, scans, and
  sees their own sessions judged, which is what the export is for and
  what issue #135 needs a reader to experience.
- Coverage gains a record of its own history on the machine, not only in
  the memory of whatever happened to be watching. A widening is written
  down once, by the thing that performed it, at the moment it performed
  it.

**What gets harder or more constrained:**

- `loxodonta.py` writes one more file. ADR-0005's freeze is narrower by
  exactly that much, and the next request to put something in the
  recorder will cite this ADR. It should have to argue against rulings 1
  and 2 rather than point at a precedent.
- `coverage.json` is writer-reachable, so a marker is testimony. This
  changes no trust position — ADR-0016 already placed calibration in the
  writer-reachable baseline and trusted it for nothing beyond
  calibration — but the file is now a third thing an adversary can edit
  to shape what the witness believes it should have seen. Ruling 2 keeps
  the dangerous direction closed; ruling 4 keeps observed time out of
  reach.
- Three sources of coverage epochs is one more than two. Ruling 5 makes
  every one of them say which it is, because a merged list where the
  reader cannot tell observation from testimony is worse than either
  alone.

**What we'll have to revisit if:**

- A harness arrives whose coverage changes without `install-hook` doing
  it. The marker records what this installer wired; a matcher edited by
  hand in the settings file is still seen only by the supervisor's next
  look, and that is the pre-existing behavior, unchanged.
- Adapters ever wire coverage from somewhere that is not the recorder
  (ADR-0020's Agents SDK processor has no `install-hook` at all). Such
  an integration writes no marker today and falls under ruling 6.

## Alternatives considered

- **`install-hook` writes the inception into the supervisor's
  baseline.** One fewer file and no merge. Rejected: it reverses
  ADR-0005's dependency into the supervisor's own memory rather than the
  recorder's store, and it destroys ruling 3's clean sentence about what
  the baseline is.
- **A line in `docs/START.md` telling readers to scan once at step 2.**
  Ships today, no code, and it works — the walk confirms it. Rejected as
  the answer, kept as the fallback: it grows a five-step page to six on
  the step a reader most likely skims, and the instruction exists only
  to work around something the tool should do itself. The page is the
  artifact #135 is testing, and testing it with a workaround baked in
  measures the workaround.
- **Infer the inception from the store's oldest receipt.** Free, and no
  new file. Rejected: a receipt proves the hook fired, not which
  matchers were wired, so it would assert today's coverage over an era
  nobody observed — the exact mistake ADR-0029 exists to prevent.
- **Have the supervisor stamp its inception from the settings file's
  mtime on a fresh store.** Exact for a genuinely fresh install.
  Rejected: ADR-0029 already rejected mtime as a floor because unrelated
  edits move it, and a rule that is honest only when nothing else has
  touched the file is a rule that fails quietly on every machine that is
  not new.

## References

- ADR-0029 (the inception this gives a better source; rulings unchanged,
  ruling 6's seeding path still the manual answer)
- ADR-0005 (the recorder's freeze; narrowed here, deliberately, by
  ruling 1)
- ADR-0016 (coverage, effective dating, and the writer-reachable
  calibration memory this joins)
- ADR-0020 (`install-hook --codex`, and why `harness` is on every entry)
- ADR-0002 and `docs/OWASP.md` (why ruling 2 refuses the end marker)
- Issue #135 (the readers this unblocks), `docs/START.md` (the five
  steps that must work as written)
