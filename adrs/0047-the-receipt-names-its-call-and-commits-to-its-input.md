# ADR-0047: The receipt names its call and commits to its whole input

**Status:** proposed 2026-11-11. Ruled by the author on that date after a design review of the whole tool, as one answer to the proposal with its four choices. Nothing is built yet: accepted once the build lands.
**Deciders:** Acquiredl

## Context

The hook writes one action line for a tool call: the tool's name and
the first of nine known keys it finds in the call's input, cut to
160 characters with the count of what was dropped (#470). Three
things follow.

- A long command is cut. `Bash: curl ... (+440)` says that 440
  characters are gone and nothing of what they were. A transcript
  edited later to say something else there is contradicted by nothing
  in the receipt.
- Most of an input is never in the receipt. An `Edit` leaves the
  file's path and not the text replaced or the text put in. A tool
  whose input uses none of the nine keys leaves its name.
- A fingerprint that fails loses the receipt. The hook returns before
  it appends when a referenced file cannot be hashed, against its own
  rule that such a file is skipped and never fatal (SPEC section 8).

The harness sends the hook an id for each call, which the recorder
has ignored. The harness's events and its transcript name the same
call by the same id, and ADR-0046 pairs by it.

### Prior art, read on 2026-11-10

| System | What it does | What is taken from it |
|---|---|---|
| Git objects | an object's name is the hash of its length and its content, however little of it is shown | a short line that commits to all of what it summarises |
| Git trailers | a pinned grammar at the end of free text, read by tools and by people | where the commitment sits |
| auditd, `EXECVE` records | an argument too long is cut with its full length beside it, and a value that could not be read is a named marker in the record | the length beside the cut, and a failure that is written and never a missing record |
| RFC 5424 structured data | named fields in brackets beside the free message | the bracketed shape |

No system read hashes a command's whole input into its record. That
part is this tool's own.

## Decision

1. **A hook receipt ends with a pinned suffix.** After the action
   line as it is written today, cut and count included, one space and
   one bracketed group, with nothing after it:

   ```
   Bash: curl -s https://example.org/a (+440) [call=toolu_01AbC input sha256=<64 hex> bytes=612]
   ```

   The fields are `call`, then `input`, in that order, one space
   between them. A reader takes the last such group on the line and
   no other.

2. **`call` is the harness's id for the call,** as the payload gives
   it, when it is made only of letters, digits, `_` and `-` and is at
   most 128 characters. A payload that names none, or one that fails
   that, leaves the field out.

3. **`input` commits to the whole input.** `sha256` is the SHA-256 of
   the call's input in the canonical form of SPEC section 4, and
   `bytes` is the length of that form. An input section 4 has no form
   for, a number with a fraction in it, is not hashed, and the field
   reads `input=unhashed` so that its absence is written and not
   silent. A payload with no input leaves the field out.

4. **A fingerprint that fails never loses the receipt.** The receipt
   is appended without the reference that could not be made, and its
   action line says so in pinned words before the suffix. The hook's
   exit says what failed, as before.

5. **`supervisor show` reads the commitment.** For a receipt that
   carries an input hash and a call id, it says whether the
   transcript's record of that call hashes to the same: matches,
   differs, or the transcript holds no such call. This is testimony
   on the agent's machine, where the transcript is in the writer's
   reach, and it is said as such.

6. **This is SPEC v0.1.6, an amendment and not a new format.** The
   suffix is a third machine-read action line with a pinned grammar,
   beside the transcript commitment and the second-record note. The
   schema, the canonical form and the hashing of entries are
   untouched (ADR-0036), every chain written before it verifies as it
   did, and a verifier that knows nothing of the suffix reads the
   line as text. `loxodonta run` and `loxodonta log` write no suffix:
   they have no call and no input object.

7. **The docs say it:** `docs/SPEC.md` (section 2's pinned action
   lines, the amendment note), `docs/HOOK.md`, the glossary's
   *Receipt* entry if it describes the action line, and the tours
   where they show one.

### What it claims, and what it does not

It claims that a hook receipt written after this change names the
call it is for and holds a hash that any copy of that call's input
either reproduces or does not.

It does not claim:

- **That the input is in the receipt.** The receipt holds a summary
  and a hash. Showing what the input was needs a copy of it.
- **That the hash hides a short input.** An input that can be
  guessed can be confirmed against its hash. The line already holds
  its first 160 characters in the clear, and SPEC section 8's rule
  on secrets stands.
- **What the tool did.** The receipt records the call attempted, as
  before.
- **Receipts written before it.** A line from an earlier recorder
  that happens to end in such a group is the writer's text.

## Consequences

**What gets easier:**

- A cut line no longer leaves the rest of a command resting on the
  transcript alone.
- Calls and receipts can be paired one to one (ADR-0046).
- One more case where the hook kept its exit code and lost its
  receipt is gone.

**What gets harder or more constrained:**

- Each hook receipt is about a hundred bytes longer, roughly a third
  more chain.
- The spec pins a third action-line grammar, and every tool that
  prints an action line shows the suffix.
- An input with a fraction in it is named and not hashed.

**What we'll have to revisit if:**

- Inputs with fractions turn out to be common: section 4 then needs
  a form for them, which is a format question.
- A harness sends no id: pairing for it stays by count.
- The suffix crowds the dashboard or the digest: a reader may fold
  it, and the chain still holds it.

## Alternatives considered

- **Record the whole input.** Rejected: receipts are not
  transcripts, and action lines are plaintext forever (SPEC
  section 8).
- **A new schema field for the hash.** Rejected: that is a new
  format version, and the suffix needs none.
- **The call id alone.** Considered, and the author took both: the
  hash is what a cut line lacks.
- **A shorter hash.** Rejected: a commitment is worth its full
  width, and sixty-four characters is what every other hash here is.
- **Hash the input as Python writes it, fractions and all.**
  Rejected: it would pin one language's number spelling into the
  spec.

## References

- #470 (the count of what a cut dropped), ADR-0002, ADR-0017 (the
  transcript commitment, whose pinned line this follows), ADR-0036
  (the hashing is frozen), ADR-0041 (the second-record note),
  ADR-0046 (pairing by the call's id)
- `docs/SPEC.md` sections 2, 4 and 8, `docs/HOOK.md`
