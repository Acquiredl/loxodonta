# GLOSSARY — loxodonta

Ubiquitous language for this repo. The shared vocabulary between the codebase, its author, and the agent.

Every term in this file should be:
- Used in the code (variable names, file names, type names, function names).
- Used in your planning docs (PRDs, issues, ADRs).
- Used in conversations with the agent.

If a concept is in your head but not in this file, the agent will guess — and probably guess wrong. Add it.

---

## Roles

### Operator

The human who owns the machine and the receipt log, and who runs `verify`. The operator's job in the trust story is exactly one thing: keep a [head record](#head-record) somewhere the writer cannot reach.

### Writer

The process that appends entries to the log — in the target use case, an AI agent (directly in Stage A, via a harness hook in Stage C). The writer is **semi-trusted**: trusted to run, *not* trusted to leave history alone afterward. The writer is the tool's primary adversary — receipts exists so that a writer that edits, deletes, or reorders its own history is always caught.

**One writer per log — and the writer is a *process*, not a session.** The distinction is load-bearing and was learned the hard way (ADR-0004): a Claude Code session runs tool calls in parallel and the harness fires one hook process per call, so a chain keyed by session id has many writers at once. Where several processes must share a chain, the integration serializes them with a lock; the format itself offers no concurrency guarantee.

The writer/operator split is the load-bearing idea of the project: in Acu (the predecessor), writer and operator were the same person, so log tampering was "self-sabotage" and a plain JSONL file sufficed. An AI agent with filesystem access is a semi-trusted third party operating inside your machine — that is what makes the chain earn its keep.

### Head record

An operator-held copy of the chain head, stored **outside the writer's reach** — another machine, a password-manager note, a message to self. Input to `verify --expect-head`. The tool never stores heads locally on the operator's behalf (a state file the writer can reach is false security). Stage B anchors are head records with the out-of-reach property outsourced to Bitcoin. A [supervisor](#supervisor)'s baseline is deliberately **not** a head record — see the distinction there.

### Supervisor

An operator-side reader process that continuously verifies receipt logs against its [baseline](#baseline) and shouts on change — **a tripwire with a memory**. Its claim is detection latency only: it shortens the window between tampering and discovery and raises the cost of tampering; it is never a wall. Everything it stores is writer-reachable, so nothing it holds is a [head record](#head-record); anchors remain the only hard boundary (ADR-0002 stands unamended). It may drive anchoring — keeping heads anchored and proofs upgraded — and that is how the head-record ritual is honestly automated: the out-of-reach property comes from the anchor, never from the supervisor. The tripwire watches the *log*, not the machine: this is a flight-recorder accessory, not an intrusion-detection system. The supervisor is the repo's *reader* tool, serving two mornings from one file: suspicion (`scan`, the alarm band) and memory ([recall](#recall) — the front page, and the agent-facing digest/search/show surface of ADR-0009).

### Baseline

The supervisor's remembered copy of chain heads, used to detect change between looks. Writer-reachable by definition, therefore trusted for nothing: a baseline that disagrees with the log is a reason to shout, never a verdict about which side is true — verdicts still come only from `verify` and its inputs. Named after the Tripwire/AIDE convention, where the same weakness (an adversary who can reach the baseline) has the same documented answer: the trustworthy copy lives out of reach (here, the anchor).

### Day book

The supervisor's remembered copy of its own days: one row per UTC day holding that day's worst claim, its counts, and how often the page was opened. Sits beside the [baseline](#baseline) and shares its posture exactly — writer-reachable, trusted for nothing, owning no verdicts. Where the baseline answers "did anything change since the last look?", the day book answers "is this a trend or a one-off?", and a day nobody watched is recorded as a gap rather than a quiet day. That distinction is the point: detection latency is a function of how often the operator looks, so a run of unread days is the one failure mode the chains themselves can never report (ADR-0014).

### Issuer

The party who seals a [package](#package) and ships it across a trust boundary under its own name — the one taking responsibility for the deliverable. The issuer holds the signing key **out of the writer's reach** (the head-record property, applied to a second object) and applies the [issuer signature](#issuer-signature) at package close, after the manifest is written. In a solo deployment the operator and issuer are the same person wearing two hats; the roles diverge the moment issuing becomes a service, exactly as writer and operator diverged to found this project (ADR-0008).

### Recipient

The party across the trust boundary who receives a [package](#package) and verifies it with nothing running: checks the seals, walks the chain, and owns the one job the verifier cannot do — comparing the printed key fingerprint against a channel the package cannot rewrite. Math is the verifier's job; identity is the recipient's (ADR-0008).

---

## Core domain

### Receipt log

The single append-only JSON Lines file holding a chain of entries. Default filename `receipts.jsonl`. One writer per log. Anchors in code: the `--log` CLI flag and the spec's §1.

### Entry

One line of the receipt log: a JSON object with exactly `n`, `ts`, `actor`, `action`, `files`, `prev`, `entry_hash`. An entry *is* a receipt — the two words are interchangeable; "entry" is the code-facing term, "receipt" the human-facing one.

### Genesis

The entry with `n == 0` and `prev == null` — the only entry allowed a null `prev`, and the only entry carrying `v`, the format version. Written by `receipts init` with pinned contents (`actor: "receipts"`, `action: "genesis"`, `files: []`); only its timestamp varies. The chain's title page: who started it, when, and under which rulebook — all hash-committed, so a chain can't be relabeled to a different version without breaking. Derived trail designs extend the title page: their genesis payload must commit every ingredient whose change alters output (format version, engine identity, prompt hash, check-catalog version, evaluation-suite version), so "why did this assessment change" always has a recorded answer (ADR-0006, provenance corollary).

### Canonical form

The deterministic serialization of an entry (minus its `entry_hash` field) defined by the six rules in `docs/SPEC.md` §4: sorted keys, compact separators, UTF-8, integers only, no trailing newline. **The hash is always computed over canonical form**, regardless of how the line is written on disk.

### Entry hash

`SHA256(canonical form)` of the entry, lowercase hex, stored in the entry's `entry_hash` field. What the *next* entry's `prev` commits to.

### Chain rule

The invariant `entry[n].prev == entry[n-1].entry_hash` for all `n ≥ 1`. The property that makes the log a hash chain rather than a list of independent lines.

### Chain head

The `entry_hash` of the last entry. Commits to the entire history — this is the value an anchor pins externally.

### File reference

A `{path, sha256}` pair inside an entry's `files` array: the fingerprint of one file at log time. Paths are relative to the **project root** (SPEC §3 as amended v0.1.1, ADR-0012 — originally the log's directory, a rule the hook's layout silently defeated), forward slashes, sorted by path within the entry. A [store](#store) chain resolves them through its [project record](#project-record); a local chain resolves against its own directory, which for a log at the project root is the same base. Derived designs recording external evidence generalize this into the [source reference](#source-reference).

### Verify

The walk defined in `docs/SPEC.md` §6: schema → sequence → recomputed hash → chain rule → timestamp sanity (warning only), optionally file checks, optionally head comparison (`--expect-head`). Produces a verdict, never repairs anything. Verdicts come only from mechanical facts; writer-supplied testimony (`ts`, `actor`, `action`) can at most raise warnings.

### Testimony

Any writer-supplied content the verifier cannot recompute: `ts`, `actor`, `action` in this repo's entries, and the whole recorded payload in derived trail designs. Testimony is recorded faithfully and trusted for nothing — it can at most raise warnings (ADR-0002). The opposite end is a *mechanical fact*: something [verify](#verify) recomputes itself (hashes, sequence, chain rule, head). The two are the endpoints of the [evidence grade](#evidence-grade) scale.

### Evidence grade

An ordered label on a claim in a derived trail design saying what *kind* of evidence backs it: `self_reported` (0) → `document_evidenced` (1) → `artifact_inspected` (2) → `independently_observed` (3). A grade qualifies a claim's status, never changes it; it measures the independence of the evidence, not the correctness of the conclusion. Loxodonta's own entries are the two-endpoint case (testimony at 0, the chain at 3) and its frozen format does not carry the field. Canonical scale and rules: ADR-0006.

### Source reference

A derived design's generalization of the [file reference](#file-reference): the record, inside an entry, of an external source consumed as evidence — where it came from (URL or origin), when it was retrieved, the SHA256 of the **archived copy**, and optionally a locator pinning the exact passage a finding rests on. The honesty rule carries the entry: the origin and retrieval time are [testimony](#testimony), and the hash binds the copy in the package's evidence archive, *never* the live source — a hostile reading ("the writer hashed whatever it chose to save") is survivable only when the claim is worded that way. A source reference is what makes [evidence grade](#evidence-grade) 2 (`artifact_inspected`) *defensible* rather than asserted: a recorded fingerprint and locator of the artifact examined; a claim without one caps at grade 1. Committed in entries, per ADR-0007's one-commitment-home rule — which is also why the chain is the evidence index: walking the entries and collecting source references yields exactly the set the archive must contain, no extras. Loxodonta's own file reference is the degenerate case: a local file, path and hash, no retrieval story needed.

### Package

The delivered whole of a derived trail design that ships more than a chain: the trail, its post-close artifacts (report), the evidence archive, the [manifest](#manifest), and the [seals](#seal) — crossing a trust boundary to a recipient who verifies it with nothing running and no issuer cooperation. Loxodonta's own deliverable is the degenerate one-artifact case: a receipt log whose "manifest" is its own chain head. Canonical rules: ADR-0007.

### Manifest

The package's sidecar list: a small document, **written last**, holding the chain head and the hash of every post-close artifact. The manifest's hash is the package's **single sealing surface** — every seal applies to it and to nothing else, and it vouches for the whole package transitively. It commits only what the chain cannot (post-close artifacts); everything else it carries is displayed convenience, testimony whose committed truth is reachable through the head. The chain is the evidence index — the manifest carries no second one. Because it is written last, nothing may reference it: the report may print the assessment id and chain head, never the manifest's own hash. (ADR-0007; the word means what it means on a ship: a list of cargo, not cargo.)

### Seal

An outer commitment applied to the [manifest](#manifest) hash from beyond the package. Two kinds, answering orthogonal questions: the **anchor** (ADR-0003, pointed at the manifest hash) says *when* — the only seal the issuer cannot forge later, because a signature has no clock and no one can anchor into the past; the [**issuer signature**](#issuer-signature) says *who* (ADR-0008). The manifest commits its declared seal set, so a stripped seal is `SEAL-MISSING`, never a silent downgrade. An unsealed package can verify at most `SELF-CONSISTENT` — indistinguishable from a wholesale regeneration. Package verdicts name the mechanism, never the conclusion — see Anti-terms.

### Issuer signature

The *who*-[seal](#seal): a detached signature over the [manifest](#manifest)'s exact shipped bytes, made once at package close by the [issuer](#issuer)'s key — held out of the writer's reach, or the adversary's forgery ships under the issuer's own fingerprint. Its claim, verbatim and caged: *this manifest, and transitively every artifact it lists, was issued by the holder of key K and has not changed since signing.* Never "original" (the issuer can re-sign; only the anchor orders time), never "correct" (garbage in, faithfully signed garbage out), never "signed by \<name\>" (the verifier prints the key fingerprint; the key↔name binding lives out-of-band, in a channel the package cannot rewrite). Distinct from the **writer signature** — the adversary signing its own history — which remains rejected (ADR-0001). Canonical rules, custody, rotation: ADR-0008.

### Recall

The everyday reading of chains as *memory* rather than *evidence*: answering "what happened, when, in which repo" from what the chains already hold — session spans, files touched, action lines. Recall is testimony at machine scale: it renders writer-supplied lines and must say so, exactly as `report` does — the [verify](#verify) walk owns verdicts, recall owns none. The two readings share one log and serve different mornings: suspicion reads for broken seals; recall reads because the operator forgot. ADR-0002 called this operator forensics and predicted it "falls out for free"; the dogfood found it is the daily value that keeps the log watched.

### Digest

The budget-capped rendering of the current repo's recent entries, injected at session start by the SessionStart hook (Stage E, ADR-0009). Count-limited (default ~30 rows), grouped by session, each recent session's final entry tagged `last recorded action` — a fact, never an inference about how the session ended. The digest is [recall](#recall), so it carries recall's honesty labels: it cites the supervisor's last scan as testimony and owns no verdicts. Its rows are pointers, not content — each carries an [entry address](#entry-address) for pulling the full entry on demand. Local by design: other repos' memory is reached through search, never injected ("all memory" means all *reachable*, not all *injected* — a flat machine-wide injection would poison the context and evict the local signal).

### Entry address

The short prefix of an entry's [entry hash](#entry-hash) (displayed at 8 hex chars) used to name that entry everywhere in the recall surface — digest rows, search results, `show`, `timeline`. Globally unique across all chains on the machine by construction, with git's prefix rules: any unambiguous prefix is accepted; an ambiguous one errors listing the candidates. The address is the fingerprint: `show` recomputes the fetched entry's canonical hash and confirms it matches, so recall's pointers are self-verifying. Chosen over positional `chain:n` (two-part, session-UUID noise) and over timestamps (writer-supplied [testimony](#testimony) — an identifier must be a mechanical fact).

### Unlisted

A repo-level visibility declaration for cross-repo [recall](#recall): a marker file beside the chains (the project's [store](#store) subfolder; `receipts/.unlisted` in the legacy layout) meaning *this repo's entries never appear in recall rendered outside this repo*. Inside its own repo, recall works normally; the marker only governs `--all` surfaces (search, timeline). The default is listed — memory exists to be found, and the operator opts specific repos out. The [digest](#digest) needs no such control: it is local-only by construction, so injection cannot leak across repos. Note the honesty scope: unlisted is an output-rendering courtesy for the operator's own hygiene (e.g. keeping a private repo's name out of transcripts that feed public work), not a security boundary — the chains remain plain files any local process can read.

### Store

The one machine-wide home of every hook-written chain: `~/.loxodonta/receipts/<project-slug>/` (override: `LOXODONTA_HOME`), one subfolder per project, slug = `<basename>-<8 hex of the normalized project path's SHA256>` so two same-named projects can never share a drawer (ADR-0011). The store is the read side's unnamed default universe — `scan` with no arguments sweeps it; `--root` remains the explicit legacy mode. Chains in the store outlive their projects: the sessions most worth keeping are exactly the ones whose folder got deleted. The quickstart's cwd-local log is the deliberate exception — the sandbox stays touchable. Deleting the store is itself detectable from outside it: the baseline sits beside it, the witness lives at a different address, the anchor is unreachable.

### Project record

The small `project.json` written into a [store](#store) subfolder on first receipt, holding the project's real absolute path — what lets a [file reference](#file-reference) resolve years after the chain moved away from the work (ADR-0012). Writer-reachable, therefore [testimony](#testimony), trusted for nothing beyond pointing. Deliberately not called a manifest: that word is taken (ADR-0007).

### Tamper-evident

The precise security claim of this tool: modifications to history are *always detectable*, never *prevented*. Deliberately weaker than "immutable" — see Anti-terms. Scope in v0.1: *surgical* tampering (edit / delete / reorder / file swap) is detectable unconditionally; *whole-chain regeneration* is detectable only against a head record (`--expect-head`) or, in Stage B, an anchor.

### Completeness

The property receipts deliberately does **not** guarantee: that every action produced an entry. The chain proves integrity of *what was logged*; a writer that never calls `log` leaves no break to detect. Completeness comes from the integration — placing the `log` call outside the writer's volition (`receipts run`, pipeline gate scripts, the Stage C harness hook). Slogan form: *integrity is the tool's job; completeness is the integration's job.*

### Anchor *(Stage B)*

An external commitment of the chain head to a system the log owner doesn't control — OpenTimestamps onto the Bitcoin blockchain. Closes the whole-chain-regeneration gap named in ADR-0001. Anchor proofs live beside the log, not inside the entry format.

---

## Relationships

- A receipt log has exactly one genesis and zero-or-more subsequent entries.
- A workflow with parallel writers prefers one log **per writer** (sibling chains); merging happens only at display time in `report`. Where writers genuinely must share a file — the Stage C hook, where the session is the unit of history but every tool call is its own process — the integration serializes them with a lock (ADR-0004). The format still guarantees nothing here; the lock is the integration keeping the format's precondition true.
- An entry references zero-or-more files; a file may be referenced by many entries (its latest reference is authoritative for `--files` checks).
- An anchor commits to exactly one chain head; a log may accumulate many anchors over time.

---

## States and transitions

- Verification verdict is one of: `VALID` (exit 0) | `BROKEN` (exit 1, chain integrity failed at ≥1 entries) | `FILES-DIVERGED` (exit 2, chain intact but a referenced file was modified since logging) | `HEAD-MISMATCH` (exit 3, chain internally valid but its head differs from the operator's head record — the whole-chain-regeneration case). `UNSUPPORTED-VERSION` (exit 4) is a refusal to judge, not a verdict: the log's genesis declares a format this verifier doesn't speak.
- A log never transitions backward: append is the only legal write; anything else moves the verdict to `BROKEN`.

---

## Sub-terms and orthogonal categories

- A *broken* chain is still a readable log — `report` works on it; only its integrity claim is gone. Broken ≠ unparseable.
- A *torn tail* is the honest way a log gets damaged: the final line left partial. Two causes, both innocent — a crash mid-append, or two writers appending at once (ADR-0004). Verify reports it distinctly (entries before it are intact; operator trims the partial line by hand) but it is still `BROKEN`/exit 1. A malformed line anywhere *else* has no innocent explanation and reports as ordinary tampering.
- A *sibling chain* is a second, complete chain for the same session — `receipts-<session>-002.jsonl` — with its own genesis, head, and anchor. The hook starts one when the chain it would append to has a damaged tail: recording must not stop, and damage must not be repaired (ADR-0002, ADR-0004). Siblings are continuation by naming only; nothing links them cryptographically, and each verifies alone.
- An *anchored* chain is still just a chain — anchoring adds an external proof, it does not change any entry.

---

## Anti-terms (deliberately not used)

- ~~blockchain~~ — implies consensus, multiple writers, and tokens. This is a single-writer hash chain; say *hash chain*.
- ~~immutable~~ — overclaims. Nothing prevents mutation; mutation is detected. Say *tamper-evident* (and *anchored* once Stage B applies).
- ~~audit log / audit trail~~ — Acu's term for its *non-chained* JSONL gate log, the system this project improves on. Using it here blurs exactly the distinction the project exists to make. Say *receipt log*.
- ~~signature~~ *(unqualified)*, and ~~writer signature~~ in any form — no keys exist in v0.1, and the writer signing its own history proves nothing: the signer is the adversary (ADR-0001, unamended). The word now requires its qualifier: the [issuer signature](#issuer-signature) exists for derived packages (ADR-0008); no other signature does.
- ~~authentic / verified / genuine~~ *(in verdict output only)* — a verifier that prints these draws the operator's conclusion for them, the same overclaim as "immutable". Verdicts name the mechanism: `SELF-CONSISTENT`, `ANCHORED`, `SIGNED` (ADR-0007). Ordinary prose is unaffected.

---

## Cross-references

- ADRs that touched this glossary: `adrs/0001-hash-chain-not-signatures.md`, `adrs/0002-writer-as-adversary.md`, `adrs/0004-serialize-hook-appends.md`, `adrs/0005-supervisor-as-sibling-tool.md`, `adrs/0006-evidence-grades-generalize-testimony.md`, `adrs/0007-sidecar-manifest-seals-the-package.md`, `adrs/0008-issuer-signatures-for-derived-packages.md`, `adrs/0009-recall-surface-lives-in-the-supervisor.md`
- Related out-of-scope decisions: none yet.

---

*Last updated: 2026-08-26*
