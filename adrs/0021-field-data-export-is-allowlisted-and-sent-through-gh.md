# ADR-0021: Field-data export is built by allowlist, redacted by default, and sent through `gh`

**Status:** accepted 2026-09-03 (rulings Q1–Q4 ratified in the share-plan grill of 2026-09-02; restate-to-ratify passed)

**Deciders:** Acquiredl

## Context

Every claim in the README has been proven on one machine: the author's.
The recorder, the witness, the lifecycle reading, and the consumption
watch were all calibrated against one store, and the thresholds that
came out of that calibration (ADR-0018's dormancy tiers, the consumption
watch's hot floor) are honest only about that store. The next thing the
project needs is not a feature; it is evidence from machines that are
not this one: does the recorder hold up elsewhere, and what do real
workloads look like.

Asking for that evidence runs into the repo's own rules. The obvious
payload, `supervisor scan --json`, leaks the sender's identity by
construction: store paths, witness paths, and recorder paths carry the
user's home directory, and repo basenames name their projects. Chains
themselves carry every command line the agent ran (SPEC §8: plaintext
forever, no secrets). A "please send your scan output" ask would be
asking strangers to publish their username and their shell history, and
the redaction burden would fall on the person least equipped to judge
it.

The receiving side has constraints too. The repo runs one inbox
(issues; Discussions stays off), the supervisor is stdlib only, and
nothing in the repo may hold or require a server. Whatever the upload
path is, it must be something the sender already has and can read.

Prior art consulted: **`brew gist-logs`** (a diagnostic bundle uploaded
as a gist under the *sender's* account, then linked from an issue: the
sender keeps custody, the project keeps one inbox); **Debian's
`reportbug`** (a template-driven report with a fixed subject shape so
triage can sort by eye); **telemetry opt-in norms** (the payload is
readable before it leaves; nothing is sent that the sender has not
seen).

## Decision

> **`supervisor export` writes a scan-shaped, redacted summary built by
> an allowlist, never by filtering scan output. Raw chains are a strict
> opt-in (`--raw`) that shows a sample line and asks first. `--send`
> uploads the file as a secret gist under the sender's own GitHub
> account by shelling out to `gh`, then opens a `field-data` issue here
> from the template, linking the gist. The core stays stdlib only:
> `gh` is the network, the way `claude -p` is the narrator for
> `explain`.**

Ratified restatement: *what leaves your machine is a list we wrote
down, not a list we crossed out; you read it before it goes; it goes
under your name, into our one inbox.*

The shape, as ratified:

- **Allowlist, not filter.** The export names every field it emits.
  Nothing from `scan --json` passes through unnamed, so a new scan key
  can never leak by default. A **machine block**: recorder commit,
  Python version, OS family (not release), the hook matcher in force,
  which harnesses recorded (by actor), store size (chains, entries,
  bytes), the day-book summary, lifecycle
  counts, and the scan exit code. **Per session:** session id, repo as
  an ordinal (`repo-1`, `repo-2`; never the basename), entry count,
  time span, verdict, commitment status, completeness state with owed
  and received counts, dormancy tier, consumption state, sibling count,
  bookkeeping count, and a tool histogram over hook-actor entries only,
  whose keys come from a written list of harness built-ins: MCP calls
  fold into one `mcp` bucket (a server name says which servers a sender
  runs, and a custom one can be named after an employer), Agents SDK
  function tools into `function` (their names are the sender's own
  words), and anything else into `other`. No paths, no action lines,
  no file references, no anchor calendar URLs.
- **The file opens with a `redaction` block in plain words** saying
  what was removed and why, so the sender reads the rule before the
  data and the issue template can quote it.
- **Raw is opt-in and asks.** `--raw` bundles chain bytes and anchor
  sidecars with no `project.json`; before writing, it prints one sample
  action line from the sender's own chains and asks for a yes. Raw
  bundles are the only path that ships command lines, and the sender
  sees exactly what kind of thing that means before agreeing.
- **`--send` is `gh`, twice.** `gh gist create --secret` under the
  sender's account (custody stays with them; they can delete it), then
  `gh issue create` on this repo with the `field-data` label from the
  template: fixed title shape (`field-data: <os> / <N> sessions /
  <date>`), the gist link, the redaction block, pre-ticked consent
  lines (a second, unticked line for raw). No `gh` means `--send` says
  so and leaves the file for filing by hand; the export itself never
  needs it.
- **Exports get read, not stored.** Each one is read into a hand-kept
  `docs/FIELD-DATA.md`: one row per export (date, sessions, platform,
  what it taught), so the README's ask can point at visible payoff.

## Consequences

**What gets easier:**

- A stranger can send useful evidence in one command without reading
  the SPEC, and can read every byte of it first.
- Calibration questions (dormancy thresholds, the hot floor, the
  witness's owed-versus-received gap) get a second store to check
  against, then a third.
- The identity rule the repo holds for its author extends to its
  senders by construction, not by their diligence.

**What gets harder or more constrained:**

- The export schema is a new public contract. Fields can be added;
  renaming or removing one breaks the reading in `FIELD-DATA.md`.
- The supervisor gains its first shell-out to `gh`. It is the same
  shape as `explain`'s shell-out to `claude -p` and is confined to
  `--send`; the rule "stdlib only, shell out for the network" is now
  stated twice and should not be stated a third time without an ADR.
- A secret gist is unlisted, not private: anyone with the link can
  read it. The consent line says so.
- Raw bundles carry command lines. The sample-and-ask step is the
  whole safeguard; it is one prompt, and it must never be skippable by
  flag.

**What we'll have to revisit if:**

- `gh` stops being the thing senders have, or GitHub changes gist
  visibility semantics.
- Enough exports arrive that a hand-kept `FIELD-DATA.md` stops
  scaling; an aggregator would be a reader-side slice with its own
  allowlist.
- A sender asks for a field the allowlist drops; each such ask is
  weighed one at a time against what it would reveal.

## Alternatives considered

- **Filter `scan --json` through a deny-list** — rejected: every new
  scan key is a new leak until someone notices. The allowlist fails
  closed.
- **Upload to an endpoint of ours** — rejected: the repo holds no
  server, residency belongs nowhere here, and a sender cannot inspect
  where a POST went the way they can open a gist.
- **Raw chains by default** — rejected: command lines are the most
  sensitive thing the store holds and the least useful for the
  question being asked (does the recorder hold up; what do workloads
  look like).
- **GitHub Discussions as the inbox** — rejected: one inbox. The
  template lands in issues, where triage already lives.
- **An attachment on the issue instead of a gist** — rejected: issue
  attachments are anonymous binary blobs on the project's side; a gist
  stays under the sender's account, readable, deletable by them.

## References

- Related ADRs: `0005-supervisor-as-sibling-tool.md` (the supervisor
  speaks only public surfaces; `gh` is one more); `0011-central-
  receipts-store.md` (why store paths carry the home directory the
  export must drop); `0016-coverage-goes-wide.md` (the matcher the
  machine block reports); `0018-session-lifecycle-reading.md` (the
  thresholds field data should recalibrate).
- Glossary terms to add when built: *Field-data export*.
- Prior art: `brew gist-logs`, Debian `reportbug`, opt-in telemetry
  norms.
- Discussion: share-plan grill, 2026-09-02 (rulings Q1–Q4).
