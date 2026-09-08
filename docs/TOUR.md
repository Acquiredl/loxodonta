# A guided reading of loxodonta.py

This document walks `loxodonta.py` top to bottom, in file order, the way a
first reader meets it. It grew out of the 2026-08-21 readability walk
(issue #10) and is kept as reference documentation: each section explains
what the code does, what controls what, and — most importantly — *why it
was built that way*, with pointers to the ADRs that hold the decisions.
The sibling file, [TOUR-SUPERVISOR.md](TOUR-SUPERVISOR.md), walks
`supervisor.py` the same way.

It leans on one extended analogy, because it works. **The restaurant:**
an AI agent is a line cook working the kitchen overnight, unsupervised.
The receipt log is the ticket spike — every action prints a ticket,
spiked in order. In the morning the manager re-reads the spike. The
founding paranoia (ADR-0002): *the cook is the one printing the tickets.*
Everything in this file answers one question — what can a manager still
trust when the cook controls the printer?

The file reads in seven clusters:

| # | Cluster | What it is |
|---|---|---|
| 1 | Canonical form | How an entry becomes bytes, and bytes become a hash (SPEC §4) |
| 2 | The lock | One writer at a time (ADR-0004) |
| 3 | Core commands | `init` / `log` / `run` / `head` |
| 4 | Anchoring | The minimal OpenTimestamps subset (ADR-0003) |
| 5 | The walk & verdicts | `verify` / `report` / `explain` |
| 6 | The hook | One tool call, one entry, no volition (SPEC §8) |
| 7 | CLI wiring & epilogue | argparse assembly, `--version`, and the broken-pipe death |

Reading order mirrors trust order: before you can believe anything about
chains, locks, anchors, or hooks, "the bytes of an entry" has to be a
well-defined phrase. Everything downstream is one idea — a seal pressed
over exact lettering — applied repeatedly.

## 1. Canonical form — the house style for writing a ticket

The trust mechanism in miniature: take any entry line from a log, delete
its `entry_hash` field, rewrite what remains in the canonical style, and
SHA-256 it. The result is, character for character, the `entry_hash` that
was deleted. The hash is a **wax seal pressed over the exact lettering of
the ticket** — change one character anywhere and the seal no longer
matches. And the one field excluded from the hash is the hash itself: you
cannot seal the seal.

**The constants.** `ENTRY_FIELDS` is the ticket template — exactly seven
fields, no more, no fewer. It is a *set* because `verify` checks schema by
exact set comparison: a missing field and an extra field are equally
suspect. Extra fields matter because a spare field is a hiding place, and
it would be sealed into the hash. The genesis entry carries one extra
field, `v` — the first page of the logbook states which edition of the
house rules the book is written under.

**`canonical_bytes` — three rules, each closing one door:**

- `sort_keys=True`: JSON does not care about key order, but bytes do. Two
  honest writers describing the same entry must produce the same bytes,
  so alphabetical order removes the writer's handwriting from the seal.
- `separators=(",", ":")`: no whitespace, ever. Whitespace is invisible
  to a human re-reading a ticket and very visible to SHA-256 — a place
  where two "identical" tickets could differ silently. The house style
  simply has none.
- `ensure_ascii=False` + UTF-8: one spelling per character. An em-dash
  can be written raw or as an escape; both parse identically but hash
  differently. The canonical form picks raw UTF-8, permanently, so there
  is exactly one seal per ticket.

These three choices are frozen by SPEC §4, and the golden-fixture test
exists to make any accidental change to them fail loudly. Commands can be
added around the format forever; touching canonicalization would make
every seal ever pressed uncheckable.

**`now_ts`.** UTC, whole seconds, `Z` suffix — one clock for the whole
kitchen. Two things hide in this tiny function: entries can share a
timestamp, because **order is carried by `n`, never by `ts`**; and the
timestamp is the *cook's word* about when something happened — writer
testimony, not a mechanical fact. `verify` warns if time runs backward
but never fails a chain over it, because a cook who controls the printer
controls the clock too (ADR-0002).

**`entry_line`.** The line actually written to disk — and a deliberate
asymmetry: it does *not* pass `ensure_ascii=False`, so the stored file
spells non-ASCII as escapes (pure ASCII bytes) while the hash was
computed over raw UTF-8. Two layers, two jobs: the canonical form is the
ticket's *identity* (frozen, hashed); the stored line is its *travel
armor* — bytes that survive any editor, codepage, or terminal the file
meets. Verification never compares file bytes; it re-parses the JSON and
re-derives the canonical form fresh.

**`read_log` / `missing_log`.** Deliberately boring. The idiom to notice
— used the whole file — is `return missing_log(path)`: the helper prints
the error *and* returns the exit code, so every caller handles the case
in one line and every user hears the identical sentence. One voice for
one situation, defined once.

## 2. The lock — one cook holds the spike

This cluster exists because of a field fault (2026-08-14). The harness
fires **one hook process per tool call, in parallel** — not one cook but
eight hands reaching for the same spike at once. Each hand does
read-tail-then-append; uncoordinated, two hands interleave. The observed
outcome was a torn line; the *common* outcome, reproduced under test, was
worse — parallel writers silently losing entries in a chain that still
verifies VALID. Integrity intact, completeness gone. ADR-0004's answer
has two halves: this lock, and sibling chains (cluster 6).

**The architectural line:** the *format* guarantees nothing about
concurrency — the *integration* supplies mutual exclusion. v0.1 is
frozen, so the fix lives entirely in how the tool writes, not in what a
log is. A "writer" is a **process**, not a session; anything that makes
many processes share one chain must serialize them. An independent
implementation can verify these logs without knowing locks exist.

**`ChainLock` — a "spike in use" tag.** Before touching the spike, a
writer hangs a tag on the hook beside it: a sidecar file created with
`O_CREAT | O_EXCL` — *create, but fail if it exists*, atomically, with
the operating system as referee. The acquire loop is a polite wait: try;
if someone's tag is there, check staleness; nap 20 ms; give up after 10
seconds (`RECEIPTS_LOCK_TIMEOUT`). Two deliberately ugly corners, reasons
written beside them:

- **The Windows branch.** Windows reports `EACCES` during the instant
  another writer's tag is being taken down, indistinguishable from a real
  permissions fault — so the code refuses to guess, retries, and lets
  `locked_out` tell the two apart at timeout with two different
  sentences: no lock file present means "the directory refused you";
  a lock file present means "another writer holds it."
- **Staleness by age, not liveness.** The crash that strands a tag is
  the same crash that tears a ticket, so a tag must not wedge the spike
  forever. Proving "the holder is gone" needs per-platform process APIs
  (the very fork the design rejected), so any tag older than 60 seconds
  is taken down. The named trade: a writer legitimately stalled past 60 s
  can have its lock stolen — hence the window sits far above any honest
  append.

The operational consequence, worth knowing by heart: if a holder crashes,
arriving writers wait their 10 seconds each and **fail loudly** for up to
~60 seconds, then the kitchen unlocks itself. Loud loss over silent loss
is the deliberate half of the trade — a missing receipt that announces
itself is an incident; a silent one is exactly what this tool exists to
prevent.

**The boundary:** the tag hangs on a hook the cook can reach. A lock file
prevents accidents, never adversaries — an adversarial writer just
deletes it (ADR-0002). No component quietly promotes itself into a
security boundary it cannot hold.

**`tail_entry`.** Parse the spike's top ticket; `None` if it is damaged.
This is the "can this chain still be extended?" test. Who acts on `None`
is the interesting part: the CLI *refuses* (appending would bury the
damage — cluster 3); the unattended hook *routes around* (sibling chains
— cluster 6). Same detector, two responses.

## 3. Core commands — init / log / run / head

The manual surface. `receipts init` opens the logbook; `receipts log
--actor steph --action "rewrote the intro" --file README.md` spikes a
ticket that not only *says* it touched a file but records a
**fingerprint of the food itself** — the file's SHA-256 at that moment,
which `verify --files` can later compare against the counter.

**`genesis_entry`.** A fully normal sealed ticket plus the edition stamp.
Making genesis ordinary (rather than a special header) means the chain's
rules have no exceptions — entry 1 quotes genesis exactly the way entry
50 quotes entry 49.

**`cmd_init`.** One character carries the function: open mode `"x"`,
create-exclusive — the same atomic trick as the lock, different job. A
tool whose purpose is preserving history must not own a code path that
erases history by accident.

**`file_reference` — fingerprinting with a jurisdiction rule.** Paths are
stored relative to the logbook's directory, forward slashes only.
Absolute paths and `..` are **refused, never rewritten**: a file outside
the log's directory usually means the log is misplaced, and silently
"fixing" a path would make the ticket say something the operator did not
mean. In a tool where tickets are evidence, helpful rewriting is
corruption with good manners.

**`append_entry` / `append_locked` — the critical section, split.**
Everything that doesn't need the spike (fingerprints, sorting, acquiring
the lock, translating a timeout) stays outside; `append_locked` is only
the read-tail-then-write unit that must be exclusive — the requirement is
in the function's name. Inside, in order: an empty log and a damaged tail
are both refused with their own sentences; a case-only respelling of a
known path draws a warning ("case-insensitivity belongs to filesystems,
not the format" — caught on the machine that knows, warned not erred
because it might be intentional); and then **the single write** — one
append of one complete line. That line is where the torn-tail guarantee
is purchased: a crash can at worst truncate this one line, and can never
reach earlier bytes, because nothing ever rewrites earlier bytes.

**`cmd_run` — the babysitter wrapper.** Run the command, then write the
ticket, fingerprinting after the fact. Three ordering decisions, all
about who shapes the record: refuse *before* running if there is no log
(never execute work you cannot record); run first and hash after (the
receipt records what actually happened, and the invoked process never
sees or shapes its own receipt); and if the command succeeds but the
receipt fails, exit 1 anyway — *a lost receipt must never hide behind the
command's success code.*

**`cmd_head`.** Print the top seal — 64 hex characters the operator
copies somewhere the cook cannot reach. The smallest function in the
cluster and the heart of the ritual: a head recorded out of the writer's
reach is what turns whole-chain regeneration from a winning move into a
losing one.

## 4. Anchoring — the postmark

Cluster 3 ended on the head-record ritual: copy the top seal somewhere
the cook cannot reach. Its weakness is the operator — the ritual only
works if it is actually done, every time, out of reach. Anchoring
(ADR-0003, `docs/ANCHORING.md`) replaces discipline with a postmark.

**The story.** There is an old folk remedy for proving a manuscript's
date: mail yourself a sealed copy, and the post office's date stamp on
the envelope proves the work existed by that day. OpenTimestamps is that
remedy with three upgrades. *Mail the fingerprint, not the manuscript*:
a hash is tiny, reveals nothing, and matches exactly one document.
*Replace the clerk with something un-bribable*: the date stamp is a
Bitcoin block — millions of strangers keep identical copies of every
block ever minted, and nobody can sneak a new letter into everyone's
copy of last Tuesday. *Split the postage*: a free counter service (a
**calendar**) staples thousands of fingerprints into one bundle and gets
one stamp for all of them; what you keep is the **receipt trail** — the
staple-by-staple path from your fingerprint to the stamped bundle, which
anyone can re-follow without trusting the counter. One wrinkle: the
counter first hands you a **claim ticket** ("bundle goes out tonight"),
and you come back later to swap it for the finished trail.

What the postmark proves against the adversary: a cook who regenerates
the whole chain — every seal internally perfect — produces a head whose
receipt trail no longer lands on the stamped bundle, while the *old*
head still does. The old postmark proves a different history existed by
that date. The forger's only counter-move is destroying the receipts,
which is why one copy of the sidecar anywhere the writer cannot reach
preserves full proof power forever: the receipts are
**self-authenticating** — checking one needs no trust in whoever stored
it, only arithmetic.

**The map, story to code:**

| In the story | In the code |
|---|---|
| The manuscript | The chain, entries 0..n (one seal covers all of it) |
| The mailed fingerprint | The chain head (`cmd_head`) |
| The counter service | A calendar server (`DEFAULT_CALENDARS`; all four are used — redundancy, not ceremony) |
| The claim ticket | A pending attestation (`TAG_PENDING`) |
| Swapping ticket for trail | `anchor --upgrade` (`upgrade_anchors`, `splice_continuation`) |
| The receipt trail | The proof — a tree of append/prepend/sha256 steps (`parse_timestamp`) |
| Re-following the staples | `replay_proof` |
| The date stamp | A Bitcoin block: height = the date, merkle root = the stamped bundle (`TAG_BITCOIN`, `judge_proof`) |
| The skeptical friend, offline | `verify --anchors` (`check_anchors`) |
| The shoebox of receipts | The sidecar, `<log>.anchors.jsonl` |

**The subset discipline.** This is not an OpenTimestamps client — a full
client is a dependency or a vendored codebase, and both break this
repo's premises. It implements only what calendar proofs actually use:
three operations (sha256 / append / prepend) and two attestations
(Bitcoin, pending). Anything else is **refused by name, never guessed**
(`ProofError`), because a verifier of evidence that guesses at bytes it
does not understand is not a verifier. The same discipline bounds every
read: `ProofReader` bounds-checks each access, field lengths are capped
(`MAX_PROOF_BYTES`), and nesting is capped (`MAX_PROOF_DEPTH`) so a
crafted proof earns a verdict instead of crashing the interpreter —
proofs arrive from the network or from a writer-reachable file, and are
hostile bytes until proven otherwise.

**The proof is a tree, not a list.** A node holds attestations true *at
that point in the folding* plus operations that each transform the
digest and descend. One mailing can end in several outcomes — after an
upgrade, the same early steps branch into the calendar's old promise and
the completed Bitcoin trail. `replay_proof` walks the tree from your
32-byte head; at a Bitcoin attestation, the digest as it stands *is* the
block's merkle root to compare (displayed byte-reversed, per Bitcoin
convention). `judge_proof` then answers in preference order: any Bitcoin
attestation wins (offline, forever); else pending (whose commitment
digest doubles as the claim-ticket number `upgrade` polls); else refuse.

**Decisions worth knowing in the four commands:**

- `cmd_anchor` judges every proof *before* storing it — refuse to store
  what cannot replay. One counter failing is a warning; all counters
  failing is exit 1, said plainly, because a silently unanchored head
  defeats the whole trip.
- `upgrade_anchors` appends the upgraded proof as a new record and never
  rewrites the pending one. The shoebox is append-only like the chain:
  this tool owns no "edit evidence" code path, even for its own
  bookkeeping. Supersession is by presence — a completed record for the
  same (head, calendar) simply outranks the claim ticket.
- `check_anchors` accepts a head that matches *any* entry, not just the
  newest — anchoring entry 15 of a chain now 62 long is normal; later
  entries just are not covered until the next anchor run.
- The ANCHORED sentence ends at the honesty boundary: the verifier
  proves the fingerprint folds up to *that merkle root*; whether the
  root sits in the named block is a fact about the outside world,
  confirmed against a block source the operator trusts. Reading the
  block height for freshness is likewise the operator's half of the
  regeneration defense (ANCHORING.md §5).
- Verdict tiers: ANCHOR-MISMATCH and ANCHOR-INVALID share exit 3 with
  HEAD-MISMATCH — the "this is not the recorded history" tier, graver
  than exit 2 (files drifted) and never masked by it.

## 5. The walk and the verdicts — three readers, one checklist

Morning. Three readers pick up the spike, and all three read through the
**same** function, `walk()` — so the judge, the storyteller, and the
hired narrator can never disagree about what is on it. The inspector
(`verify`) delivers a verdict on a fixed severity scale; the storyteller
(`report`) retells the night, judging nothing; the narrator (`explain`)
is an outside summarizer bound by contract.

**`walk()` — six questions per ticket.** Is it parseable at all (an
unparseable *final* line is named `torn tail` — the one damage a mere
crash can produce, per cluster 3's single-write discipline; garbage
mid-spike gets no such courtesy)? Right form (exact field set)? Numbered
in sequence? Quotes the predecessor's seal? Seal matches the lettering?
Clock running backward? — that last one is a *margin note*, never an
alarm: the timestamp is the cook's testimony (ADR-0002), so `warns` is a
separate list from `breaks`, and warns print to stderr while verdicts
own stdout. Two channels: margins for humans, verdicts for scripts.

**`verify` — the edition check comes first.** The genesis's claimed
format version is read before any other rule: you do not grade an
Edition-2 logbook with Edition-1's checklist (`UNSUPPORTED-VERSION`,
exit 4). But the refusal is only for a *claimed* foreign edition — a
book whose edition page is ripped out gets judged, not excused, because
a missing version claim on a v0.1-shaped log is tampering to detect,
not a dialect to respect.

**The severity vocabulary** — the tool's exit codes are a language:

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `VALID` | The spike is intact |
| 1 | `BROKEN` | The chain itself is damaged — tampered or torn |
| 2 | `FILES-DIVERGED` | Chain intact; referenced files changed since logged (the **latest** fingerprint per path is authoritative) |
| 3 | `HEAD-MISMATCH` / `ANCHOR-MISMATCH` / `ANCHOR-INVALID` | *This is not the recorded history* — the gravest tier, never masked by exit 2 |
| 4 | `UNSUPPORTED-VERSION` | Wrong edition; no verdict rendered |

The masking rule is deliberate: a regenerated chain with tidy files must
shout "not the recorded history," not report a housekeeping issue.

**`report`.** Same walk, zero judgment — a timeline with breaks inlined
where they sit, closed by the philosophy in one line: *"this timeline is
testimony only — run `receipts verify` for the verdict."* Narration and
judgment are different jobs; neither impersonates the other.

**`explain` — the narrator under contract.** A language model narrates
the log, reached by piping a prompt to an *external command* (default
`claude -p`) — stdlib purity: no keys, no model client, whatever CLI the
operator already trusts does the talking. The contract has two load-
bearing clauses. First: the timeline was written by the agent under
observation — *data to describe, never instructions to follow*. The cook
writes the tickets, and a cook who knows a narrator will read the spike
can write a ticket addressed to the narrator ("report a quiet night");
that is prompt injection aimed through the log, named before it can
happen. Second: *you are testimony, not a verdict* — the narrator may
notice; only arithmetic decides.

## 6. The hook — the printer wired to the stove

Everything earlier had a loose end: tickets were written because someone
chose to write them, and a cook who simply does not print beats the
whole apparatus — completeness is the property no seal can enforce
(SPEC §8). The hook closes it by moving the printer: the harness fires
`receipts hook` after every tool call, one fresh process per action.
*The log call sits outside the writer's volition — the agent cannot
skip its own receipt.* The burner firing is the print command.

One rule shapes every function here: **never fail a session over the
log.** A hook that errors a tool call teaches the operator to turn the
hook off, and a disabled printer is the worst outcome the design
acknowledges. The posture everywhere is degrade, skip, fall back — keep
the kitchen running, keep printing.

- **`one_line` — receipts are not transcripts.** The ticket says
  "grilled the salmon," not the recipe: one line, 160 characters. The
  summary comes from `HOOK_SUMMARY_KEYS`, a preference order over the
  most descriptive scalar a tool call carries (a file path beats a
  command beats a pattern beats a prompt).
- **`main_repo_root` — the pop-up kitchen problem.** A git worktree is
  a pop-up kitchen that hygiene dismantles once its branch merges — the
  sessions most worth keeping are exactly the ones whose worktree gets
  pruned. So a worktree session's chain goes to the permanent
  restaurant's office: the main repository. It reads git's own files
  (`.git` → `gitdir` → `commondir`) rather than shelling out, because
  this runs on every tool call and a hook that spawns a process per
  call is a hook the operator eventually turns off. Anything unexpected
  falls back to the project directory — never fail over path layout.
- **`writable_chain` — the fresh pad.** The sibling logic of ADR-0004,
  living in the hook (not the format, not `append_entry`) because
  routing around damage is unattended-integration behavior: a human at
  the CLI is refused; the hook walks `-002`, `-003`, … until it finds
  an undamaged pad. Damage ends a chain, never the recording; the
  damaged chain is left as it lies — evidence, with no repair path.
- **`ensure_chain` — the startup race.** Genesis is written under the
  lock, guarding both "missing" and "exists but empty": two hook
  processes racing to create the same chain must not leave one dying on
  "run `receipts init` first" against a file that was about to be a
  chain.
- **`cmd_hook` — the assembly line.** The payload is read from stdin as
  UTF-8 bytes and decoded explicitly (JSON's interchange encoding —
  never the console codepage). Chain placement, most specific wins:
  `--log-dir` flag, else `$CLAUDE_PROJECT_DIR/receipts` through
  `main_repo_root`, else the working directory — with the env var read
  *in Python, not the shell*, which is why one installed hook command
  works under every shell on every platform. The session id is
  sanitized before it may name a file. A directory the hook creates
  gets a protective `.gitignore` (`*` + `!.gitignore`): action lines
  record every command a session ran, and that history must not ride
  into a commit by accident. Files are fingerprinted only when they sit
  under the log's directory and still exist — anything else is skipped,
  never fatal.

A deliberate scope boundary, worth knowing: the hook reads `tool_input`
and ignores `tool_response` — a hook ticket records what was attempted
on what, never how it went (only the `run` wrapper records exit codes).
Capturing outputs would drag tool output — secrets included — toward
the log. The cost: a hook chain cannot distinguish a failed command
from a successful one.

## 7. The front door and the quiet death

The last cluster is front of house: the menu board, the bouncer, and —
at the very bottom of the file — how to behave when someone slams the
door mid-sentence.

**`head_record`** is an argparse validator, and its placement is a
vocabulary boundary: a malformed `--expect-head` is a *usage error* —
the command was spoken wrong — never a *verdict* about the chain. The
inspector does not spend verdicts on questions that were not
well-formed. (Uppercase hex is politely lowercased at the door.)

**`main()`** carries two design ideas through its ceremony. Parent
parsers (`--log`; `--actor`/`--file`) are defined once and inherited,
so every command's shared flags behave identically because they *are*
the same flags. And each subcommand registers its handler via
`set_defaults(func=...)` — dispatch with no if-ladder to fall out of
sync with the menu.

**`--version`** is the one flag that belongs to no subcommand. It
prints three identities on one line — `loxodonta 0.1.0 (format 0.1,
commit 638dc8c)` — because the tool and the format are versioned
independently (ADR-0022): `TOOL_VERSION` says which recorder you are
running and is tagged together with `supervisor.py`; `FORMAT_VERSION`
says which chains it can read and is frozen (SPEC §2.1). The commit is
the checkout's `HEAD`, the same fact the supervisor's recorder notice
reports, read from local git only — `unknown` when the file sits
outside any checkout, as a release asset does. The flag is a custom
`argparse.Action` rather than the stock `version=` string so the git
question is asked only when `--version` is, never on the hook path.
Nothing fetches and nothing updates: a version is a label on the file,
not a channel to a newer one (ADR-0015).

**The `run --` split** happens *before* argparse ever runs: everything
after `--` is sliced off and handed to the wrapped command verbatim,
because flags like `-x` in `receipts run -- pytest -x` were never ours
to parse. A jurisdiction rule in the spirit of `file_reference`: the
wrapper owns nothing past the `--`, and the wrapped argument list
crosses the boundary untouched. `run` without `--` is a usage error —
a wrapper with nothing to wrap.

**The epilogue** handles `receipts report | head`: the reader hanging
up is not a fault — no verdict was asked of the unread lines — so the
tool dies quietly, not loudly. Three real-world scars, annotated in
place: Windows reports a plain `EINVAL` where POSIX raises
`BrokenPipeError`, so both are matched but EINVAL only on Windows
(elsewhere it means something else and should fly); stdout is pointed
at the null device before exit, because the interpreter flushes during
shutdown and flushing into the dead pipe would re-raise after the
handler ran; and the handling wraps `main()` once at the outermost
layer, since pipe death can strike any command that prints.

---

*This tour was written during the 2026-08-21 readability walk (issue #10)
and is maintained as reference documentation. If a section here
contradicts the code, the code moved — fix the tour in the same commit
next time.*
