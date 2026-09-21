# Direction: where loxodonta is going, and what it declines

The ADRs record what was decided and why. This page records where those
decisions point, so that a reader, or an agent session that starts from
the code and not from a conversation, can tell a step toward the
destination from a step beside it. It was ruled in a direction grill on
2026-09-20 and 2026-09-21. Where a sentence describes something not yet
true of `main`, it is marked **toward**.

## 1. What it is for

loxodonta is the evidence layer for reviewing what an agent did: a record
whose rewriting shows, whose gaps can be counted against a second record,
and which a recipient can check with one small file. Everything else is a
reader.

ADR-0002 weighed four purposes and made one of them the product: purpose
B, the agent as untrusted writer. That stays the threat model, unamended.
This page adds who the design answers to: purpose C, third-party proof,
which ADR-0002 said would begin at Stage B. The [recipient](../GLOSSARY.md#recipient)
is the person across the trust boundary who is handed a
[package](../GLOSSARY.md#package) and has to believe it or not, with
nothing running and nobody to ask.

## 2. Who wins when goals pull apart

1. **The recipient.** Evidence matters to security only when someone other
   than the operator has to believe it.
2. **The reader meeting the project for the first time.** The argument
   stays sharp: claims name the mechanism, nothing is overclaimed, and the
   one thing this project does that the published work leaves open
   ([GROUNDING.md](GROUNDING.md) section 3) is said first.
3. After those, whoever builds on it, and the operator's screen, which
   keeps what it has (section 5).

## 3. A vertical is complete, or it does not count

An environment is supported when all four of these exist for it, and the
repo never calls one supported because capture alone works:

| | Capture | A second record the witness reads | A commitment to the rich record | A package |
|---|---|---|---|---|
| Claude Code | harness hook | yes, the transcript, writer-reachable | yes | yes |
| Codex CLI | harness hook | no | yes | yes |
| OpenAI Agents SDK | in the agent's process | no | no | yes |

One of three is complete today. The other two give a recipient a hash
chain and nothing more, and the docs say so where they describe them.

**Toward:** the [witness](../GLOSSARY.md#witness) is split from the reader
of Claude Code's transcript, and what passes between them becomes a
contract: a file of normalized tool events (a time, a tool name, a call
id, an outcome class, and never an input or an output), versioned
`loxodonta-second-record/0` while it is provisional. It freezes at `/1`
only with two producers behind it. Each [second record](../GLOSSARY.md#second-record)
states its reach wherever its count is shown, and a writer-reachable one
is said to catch faults, not a writer shaping both records.

Verticals are built one at a time. The next is LangGraph, carrying a real
recurring workload of the author's, because a vertical nobody runs can
only be declared complete, never watched working: every receipt in the
author's store so far was written under Claude Code, and what made that
reader good was field data no documentation held.

## 4. The road to 1.0

1.0 is the point where every contract a recipient depends on is frozen,
and each has been exercised by someone who is not the author. Four gates,
all required (ADR-0022, addendum of 2026-09-21):

1. **The verifier.** `verifier.py`, copied out of the recorder and never
   imported by it (ADR-0035); conformance vectors that pass on both files;
   a walk that refuses a duplicate key and a wrong-typed field by name;
   and a SPEC that states every property the verifier relies on, the
   sidecars and the package included, beside what the design cannot claim.
2. **The second-record contract at `/1`**, which means the second vertical
   is complete.
3. **The recorder held elsewhere**: one export from another machine read
   into [FIELD-DATA.md](FIELD-DATA.md).
4. **One recipient, unaided**: someone who is not the author is handed a
   package, the verifier and the docs, and reaches the author's verdict.

The order:

- **0.8.0** ships what `dev` already holds.
- **0.9.x**, for as long as it takes. First the foundation:
  - the verifier arc of ADR-0035: the reorder, alone and
    behaviour-preserving; `verify_log` as the real function; the stricter
    walk; the vectors; then the copy;
  - one typed way to read a sidecar row inside that region, with the rows
    written before rows carried a kind still read, in one place;
  - the SPEC's growth: the sidecars and the package as normative text, the
    sentence in section 5 that contradicts section 4 put right, the
    property that a rewrite preserving a line's meaning verifies clean
    stated as a property of the format, and the list of what the design
    cannot claim;
  - the witness split from its reader, and the `/0` format;
  - a page that lists every rule written once in the recorder and once in
    the supervisor, and a check in `tools/` that holds them equal;
  - one page mapping mechanisms to the controls they address, which is a
    mapping and never an attestation.

  Then the second vertical.
- **1.0** when gates 3 and 4 pass.

## 5. The supervisor's ceiling

A log nobody examines detects nothing: tamper-evidence requires auditing
(Crosby and Wallach, 2009, section 2). That grounds the supervisor's audit
function, the scan, the witness, the baseline, the keepers, and it
grounds nothing else in the file.

So `supervisor.py` grows only for the audit function and for what a
recipient receives. A scan that runs only while somebody is looking
(issues #271 and #281) is inside that line, because it is about auditing
happening at all. First-run onboarding (#147), new panels and new recall
features are outside it, and wait for a reader that lives in its own
repository. What the dashboard has, it keeps.

## 6. What it declines

- **Tool inputs and outputs.** A receipt is a minimal action line, and the
  transcript commitment covers the rich record by reference
  (`.out-of-scope/001`).
- **Standing in for an observability platform.** Those hold payloads,
  costs and trace views. This is the layer they lack, and a comparison on
  their features is one it loses on purpose.
- **Adapters for the sake of breadth.** Section 3.
- **Anything new for the operator's screen.** Section 5.
- **A hosted service in this repository.**
- **A repair command, and a way to update itself** (SPEC section 6,
  ADR-0015).
- **A generated control matrix.** A line that says a control is satisfied
  is a conclusion about someone's deployment, and the verdicts here name
  the mechanism and never the conclusion.
- **Before 1.0:** a receipt written before the call runs, a second record
  for Claude Code that is out of the writer's reach, capture through a
  proxy or a gateway.
- **Modular source**, until one of ADR-0035's named triggers fires.

## 7. What it can and cannot claim

In the published work's own terms, with the sources:
[GROUNDING.md](GROUNDING.md) section 2. The short form: tamper-evidence
for the part of a chain covered by a commitment held off the machine, and
a bound on when it existed. Never forward integrity, never resistance to
a cut tail without a published head, never protection at the moment of
the call, never who wrote it, and never that anything is prevented.

## 8. How it names things

Where naming conflicts, the established standard wins over this project's
own word. Applied in three tiers:

1. **The same concept, and a standard names it: use the standard's name.**
   No homegrown synonym is kept beside it. Where the project's word is
   already settled, the glossary entry carries the standard's term.
2. **A word shared with a standard that scopes it differently: keep it
   only with an explicit scoping sentence**, in the glossary and wherever
   the two senses could meet, and never use the word here in the
   standard's sense. No single standard owns *receipt* or *witness*, which
   is why both are scoped and neither is renamed; the frozen format
   carries `"actor":"receipts"` in every chain besides.
3. **A surface that implements a standard speaks that standard's terms.**
   If a part of this project ever speaks SCITT, that part says *entry*,
   and *Receipt* there means what RFC 9943 says it means.

The crosswalk from each term to the nearest standard term is
[GROUNDING.md](GROUNDING.md) section 6. A rename that touches a contract
(the package's `witness.json`, the completeness state words) is cheap only
before 1.0 freezes it.

## 9. Open rulings

- Whether an append is followed by an `fsync`. Measured on the author's
  machine at 2.2 ms where the store lives, against about 55 ms of
  interpreter start per hook call. An ADR either way: a refusal to spend
  the call is fine, an unrecorded window is not.
- What SPEC section 8 says about a lock taken from a holder that was
  paused and not dead. Tested: where the operating system lets the lock
  file go, the result is two entries claiming one `n` in the middle of
  the file, and no sibling chain starts because the tail still parses.

## 10. Where the decisions live

- `adrs/0035-the-recipients-verifier-is-copied-out-of-the-recorder-never-imported-by-it.md`
- `adrs/0022-the-tool-gets-a-version-tag-and-release.md`, the addendum
- [GLOSSARY.md](../GLOSSARY.md): *Witness*, *Second record*, *Recipient*
- [GROUNDING.md](GROUNDING.md): the published work all of this stands on
