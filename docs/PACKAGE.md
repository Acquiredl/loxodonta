# The package: a session or a drawer, sealed by a manifest, verified by one file

**Status:** accepted 2026-09-08 (ADR-0026, applying ADR-0007 and ADR-0008 to loxodonta's own store). This page specifies the package format `loxodonta-package/1` and the verifier's ladder. The receipt format of `docs/SPEC.md` (v0.1) is untouched: a chain inside a package is a chain, judged by the same walk.

## 1. What a package is

The evidence lives in the store on the machine that wrote it. To show it to someone who was never on that machine, the operator sends a **package**: the chains of one session, or of a repository's whole drawer, with their anchor sidecars, the drawer's project record, a witness snapshot labelled testimony, a plain-words README, the harness transcript on request, and last of all a **manifest** listing everything before it. The recipient downloads `loxodonta.py`, the same file that verifies a bare chain, and runs one command on the zip. It answers layer by layer, the recorder's own verdicts verbatim, and ends with the package verdict and one line of residual trust.

A package confirms that it is unaltered since packaging. It never confirms that the record inside is true or complete: a harness that lied at write time ships faithfully packaged lies (ADR-0002, ADR-0026). Without a seal it cannot say when the set existed or which key packed it either, and its ceiling verdict says so in as many words.

The GLOSSARY's words apply exactly: *package*, *manifest*, *seal*, *issuer*, *recipient*, *testimony*. It is not called a bundle, so the concept keeps one name; the field-data export's `--raw` zip is a *raw archive*, a different thing with no manifest (ADR-0026 ruling 9).

## 2. Building one

```
supervisor package <session-id | entry-address> [--out PATH] [--folder] [--witness DIR] [--transcript] [--anchor [--calendar URL]...] [--sign KEYFILE]
supervisor package [--repo PATH]                 [--out PATH] [--folder] [--witness DIR] [--transcript] [--anchor [--calendar URL]...] [--sign KEYFILE]
```

Two units, one selector each (ADR-0026 ruling 1); a selector and `--repo` together are a usage error, exit 64.

**A session.** The selector is a session id, or any entry address inside the session, resolved with the same rules `show` and `verify ADDRESS` use (any unambiguous prefix; an ambiguous one lists the candidates). Either way the whole session is packaged, sibling chains included, so the two selectors write the same package. The store is searched as a whole; the current directory does not matter.

**A drawer.** `--repo PATH` selects a repository's whole drawer: every session recorded for it and every sibling, resolved the way `digest --repo` resolves a repository (a git worktree names its main checkout), and including the drawers of the repository's own harness worktrees (`<repo>/.claude/worktrees/*`), which recall has read as the repository's history since 0.2.0 (ADR-0023 part 3); a sub-project elsewhere in the tree is its own memory and is not swept in. With no selector at all the unit is the current repository's drawer, as `digest` behaves: `CLAUDE_PROJECT_DIR`, else the current directory. A repository with no drawer in the store is refused with nothing written (a legacy `receipts/` layout moves into the store with `supervisor adopt` first). Store-wide packaging is not built: that is `export --raw`'s job, and it stays there.

By default the package is a zip in the current directory, `loxodonta-package-<session>.zip` for a session and `loxodonta-package-<project>.zip` for a drawer (the drawer's display name, the project folder's basename); `--out` names another file, and `--folder` writes an unpacked folder instead (with `--out`, that folder). An existing path is never overwritten.

The scan underneath is one ordinary supervisor tick over the store, as `export`'s is: its completeness row for each session packaged and its verdicts are what `witness.json` carries. `--witness` points it at the harness transcript layout, as for `scan`.

`--transcript` carries each packaged session's harness transcript, whichever unit is packaged: the file the scan's completeness watch paired with the session (by the transcript's file stem, the session id, under the witness layout), copied while it is still on disk. It is opt-in for the reason §3 gives, and it is the only thing that keeps a transcript past the harness's retention cycle (§8). A session whose transcript is gone is packaged without one, and the README says so; without the flag the only difference in what is written is the README's sentence that the transcript was not requested.

Assembly follows ADR-0007's write order, and `supervisor package` honors it or the package is unverifiable: the chain snapshot and sidecars first, each session's transcript beside its chains, then `project.json`, then `witness.json`, then `README.md`, then `manifest.json`, then the seals, the signature before the anchor: signing is the step that can fail on a passphrase or a touch, and the anchor is the one that leaves the machine, so a signing that fails costs no calendar submission. The zip keeps that member order: the manifest comes after everything it lists, and the seal files follow the manifest in the order they were applied: the signature, then the public key, then the anchor sidecar.

**The first seal, the anchor.** `--anchor` applies it (ADR-0026 ruling 4). Once the manifest is written, the supervisor drives `loxodonta anchor --manifest <manifest>`, which posts the manifest's sha256 to the OpenTimestamps calendars once and writes the proof beside it as `manifest.json.anchors.jsonl`: an ordinary anchor record (docs/ANCHORING.md §2) whose `head` is the manifest's digest and which has no `n`, since a manifest has no entries. The supervisor never speaks OTS itself. The manifest declares `"seals": ["anchor"]` before it is written, so a package stripped of its sidecar is `SEAL-MISSING` (§5), never a quiet downgrade. What leaves the machine is the manifest's 32-byte digest, to the public calendars, from the operator's address, and only with the flag: without it nothing is posted and the manifest declares `[]`. `--calendar URL` names other calendars, repeatable, as it does for `loxodonta anchor` and the hook. A calendar that accepts nothing leaves no package behind, zip or folder, since a package declaring a seal it does not carry could only ever verify `SEAL-MISSING`. The proof is pending until Bitcoin has it, a few hours; `loxodonta anchor --upgrade --manifest <package>/manifest.json` completes it later (for a zip, unpack first), rewriting only the sidecar, so the manifest and its seal stand. The shipped zip stays pending: an upgrade completes the unpacked copy's sidecar only, so to re-ship a completed proof, re-zip the unpacked folder with its members in the documented order (chains and their sidecars, the artifacts, the README, the manifest, then its seals), or hand over the completed sidecar beside the original zip.

**The second seal, the issuer signature.** `--sign KEYFILE` applies it (ADR-0026 ruling 4, applying ADR-0008), alone or with `--anchor`. Once the manifest is written, and before the anchor when both are asked for, the supervisor runs `ssh-keygen -Y sign -n loxodonta-package -f KEYFILE manifest.json`, which signs the manifest's exact shipped bytes with the SSH private key at `KEYFILE` and writes the detached signature beside it as `manifest.json.sig`. The public key ships next to it as `manifest.json.pub`, which is testimony (ADR-0008 ruling 4): `KEYFILE.pub` when it sits beside the key, else what `ssh-keygen -y -f KEYFILE` derives (which asks for an encrypted key's passphrase a second time), and in either case the key's two tokens only, type and key, since the comment is a name and the package carries none. Before anything is written the supervisor verifies the signature under the key that ships, the recipient's check twice over, so a stale `KEYFILE.pub` beside a regenerated key is refused at packaging rather than shipped as a package that could only ever read `SEAL-INVALID`. `KEYFILE` may start with `~`, which the supervisor expands to the home folder itself, since PowerShell and cmd hand it over unexpanded and ssh-keygen does not expand it either. Neither tool reads the private key: only ssh-keygen is run with it, and its own prompts, a passphrase or a hardware key's touch, reach the terminal because its output is not captured. The manifest declares `"seals": ["signature"]` (`["anchor", "signature"]` with both) before it is written, so a package stripped of either file is `SEAL-MISSING` (§5). ssh-keygen is OpenSSH's, on every machine since 8.0 (Windows 10 and later, macOS, every Linux); git's SSH commit signing uses the same tool for the same reasons: Ed25519, no PKI, nothing to install. Any key ssh-keygen signs with is accepted, RSA and ECDSA included, and a FIDO2 `sk-` key; Ed25519 is the reference (ADR-0008 ruling 5) and the choice for a key made for the purpose. A signing that fails, whether a key ssh-keygen cannot load, a wrong passphrase, or a machine without ssh-keygen, leaves no package behind, zip or folder, with ssh-keygen's own words above the error. On success the supervisor prints the key's fingerprint (`signed: key SHA256:...`): publishing it through a channel the package cannot rewrite is the issuer's one job past signing (§8). Nothing leaves the machine for a signature.

A session whose chains sit in two drawers (possible before ADR-0023) is refused rather than flattened, whichever unit holds it: the layout puts every chain beside one project record, and two drawers under one chain name would mean one silently overwriting the other. A drawer is checked session by session against the whole store, not only the drawers selected, since half of a split session may sit in a drawer no selector reaches; one split session refuses the whole drawer package, naming the session. A drawer package that looked complete and was not would be worse than the refusal.

## 3. What is inside

Flat, like a drawer, so the recorder's own rules apply to the chains unchanged:

| File | What it is | Listed in the manifest by |
|---|---|---|
| `receipts-<session>.jsonl`, `receipts-<session>-002.jsonl`, ... | the chains, byte for byte: one session's, or every session's of the drawer; siblings in sequence order (ADR-0004), sessions in census order, the repository's drawer before its worktree drawers | head and entry count |
| `receipts-<session>.jsonl.anchors.jsonl` | a chain's anchor sidecar, when the drawer has one (docs/ANCHORING.md §2) | sha256 and byte count |
| `project.json` | the drawer's project record: the project's absolute path on the recording machine (ADR-0012). For a drawer package, the repository's own; a worktree drawer's record does not travel, and the README says which sessions were recorded in one | sha256 and byte count |
| `witness.json` | one completeness row per session packaged and the verdict the supervisor's scan gave each chain, labelled testimony in the file (its shape: §4) | sha256 and byte count |
| `transcript-<session>.jsonl` | one session's harness transcript, byte for byte as it stood at packaging; only with `--transcript`, and only while it was still on disk. Every chain of the session names it in the manifest, siblings included | sha256 and byte count |
| `README.md` | plain words: what is inside, how to verify, what each layer shows and does not; says, per session, whether the transcript is here and if not why; prints the chain heads, never the manifest's hash | sha256 and byte count |
| `manifest.json` | the list of everything above, written last | it is the sealing surface; nothing lists it |
| `manifest.json.anchors.jsonl` | the manifest's anchor proof, with `--anchor` (§2): one record per calendar that answered, `head` the manifest's sha256, no `n`; the upgraded record joins it later | nothing: a seal is applied after the manifest is written, which declares it (`seals`) and cannot list it |
| `manifest.json.sig` | the issuer signature, with `--sign` (§2): ssh-keygen's detached signature over the manifest's shipped bytes, namespace `loxodonta-package` | nothing: the same |
| `manifest.json.pub` | the public key the signature was made with, its two tokens (type and key), testimony (ADR-0008 ruling 4): the verifier judges the signature under it and prints its fingerprint; whose key it is, the recipient settles out of band | nothing: the same |

On request only, the transcript (ADR-0026 ruling 2). The transcript is the rich record the chain's commitments point at, and it can carry the very secret a bad session exfiltrated: the bad day's chain holds `Read: .env` with a fingerprint, and the transcript holds the contents of `.env`. Packaging it can hand the recipient the very secret the session exfiltrated, so it is the operator's explicit call, `--transcript`, never the default, and the README says whether it is present. A session's transcript is the one the completeness watch pairs with it; a package carries one per session that still has one.

Never inside: file contents. The tool holds fingerprints of the files the agent touched, not their bytes, and cannot produce the logged version. On the recipient's machine the project record points nowhere, so `verify --files` on a packaged chain says `FILES-UNRESOLVED` (ADR-0012), and `verify-package` says the same thing once, in plain words.

## 4. The manifest

`manifest.json`, one JSON object, written last:

| Field | Meaning |
|---|---|
| `format` | `"loxodonta-package/1"`. The verifier refuses any other tag (`UNSUPPORTED-FORMAT`). The receipt format inside stays `0.1`. |
| `packed` | when the package was assembled, UTC. Testimony. |
| `tool` | which supervisor packed it, e.g. `"loxodonta supervisor 0.4.0"`. Testimony. |
| `unit` | `{"kind": "session", "session": "<id>", "project": "<drawer name>"}` for a session; `{"kind": "drawer", "project": "<drawer name>", "sessions": N}` for a drawer. Displayed convenience; testimony. The verifier prints whatever the unit holds and judges none of it. |
| `chains` | one row per chain, in the package: `path`, `head` (the last entry's `entry_hash`), `entries` (line count), `anchors` (the sidecar's file name, or `null`), and `transcript` (the packaged transcript's file name) only when one travels with the chain's session, every chain of that session naming the same file. The verifier refuses a `transcript` that is not a bare file name or that `artifacts` does not list. |
| `artifacts` | one row per post-close artifact: `path`, `sha256` of its bytes, `bytes`. Sidecars, transcripts, `project.json`, `witness.json`, `README.md`. |
| `seals` | the seals the package should carry: `[]` unsealed, `["anchor"]` with `--anchor`, `["signature"]` with `--sign`, `["anchor", "signature"]` with both, in that order (the order they are applied and judged). A declared seal that is absent is `SEAL-MISSING`, never a silent downgrade (ADR-0007). |

Why two ways of listing (ADR-0026 ruling 3). A chain's head is already its commitment, and the verifier recomputes it by walking; listing chains by file hash would add a second commitment to the same fact, and a false one on Windows, where `read_log` splits lines tolerantly and an unzip that turns `\n` into `\r\n` changes the bytes without changing the head. The post-close artifacts have no chain to commit them, so the manifest's sha256 is their only commitment: one commitment home per fact. The transcript is the case with two facts and two homes: its committed prefixes live in the chain, as transcript commitments (ADR-0017), and the manifest adds one new fact, the whole file as it stood at packaging, tail included.

Why the README never prints the manifest's hash (ADR-0007 ruling 2). The manifest lists the README, so the README is written first, and nothing may point at what is sealed last; a README that carried the hash would be a cycle. The README may print the chain heads and the session id, which exist before it does.

### The witness snapshot

`witness.json`, one JSON object, testimony (grade 0), listed by sha256 like any post-close artifact. Its fields:

| Field | Meaning |
|---|---|
| `testimony` | one sentence saying what the file is and that the verifier draws no verdict from it |
| `scanned` | when the packing scan ran, UTC |
| `unit` | the manifest's `unit`, repeated |
| `completeness` | a list, one row per session in the package's order, whatever the unit: the supervisor's completeness row (`repo`, `session`, `state`, `tools`, `receipts`, `deficit`, `words`). A session the scan gave no row is `{"session": "<id>"}` and nothing more. |
| `scan` | `exit`, the scan's exit code, and `chains`: one row per packaged chain, `log`, `verdict`, `entries`, `anchored` |

Why a list, and the same list for a session package: the scan's own report lists completeness rows the same way; the order is the package's, which a map keyed by session would carry only by convention; and a session package is then the one-row case of one shape rather than a second shape a reader must branch on.

## 5. Verifying

```
loxodonta verify-package PATH        # a zip, or an unpacked folder
```

A zip is unpacked into a temporary folder and judged there; a folder is judged as it stands. The manifest sits at the top of either. Before anything is judged, the package can be refused: a zip that declares more than a gigabyte unpacked, or that is damaged past what its end record shows, is refused unopened; a manifest whose shape is off is refused unread, and every path it lists must be a bare file name, since the layout is flat and a path that could leave the package is never followed; a chain row naming a transcript that is not a bare file name, or that the artifacts do not list, is refused the same way. The output, in this order (ADR-0026 ruling 5):

1. **The manifest's summary**: `package`, `format`, `packed ... (testimony)`, `unit`, `contents`, and which seals are declared.
2. **Each chain**, headed `chain: <name> (manifest: head <12 hex>…, N entries)`, followed by the recorder's own `verify --anchors` output verbatim. Anchor lines appear here as detail: `ANCHORED`, `ANCHOR-PENDING`, `NO-ANCHORS`, or a mismatch. When the manifest names a transcript on the chain, the recorder judges it the way `verify --transcript PATH` does, and those lines are part of the same output: `COMMITMENT HOLDS (entry N: first B bytes)` or `COMMITMENT DIVERGED (entry N)` per commitment, oldest first; then `transcript tail: B bytes after the last commitment (entry N), uncommitted by the chain`, the bytes only the manifest vouches for; and `TRANSCRIPT-DIVERGED` when a committed prefix differs or the transcript is shorter than a commitment. A chain that holds commitments when no transcript travelled gets `TRANSCRIPT-UNRESOLVED: N transcript commitment(s) in this chain, no transcript in this package — commitments unjudgeable; chain verdict unaffected`, a note and never a verdict (ADR-0017). Then the walked head and line count are compared with the manifest's row; a difference is reported as `<name>: off the manifest`.
3. **File references**: `file references: N recorded, not checkable off the machine`, counted across the chains.
4. **Each artifact** against the manifest: `<name>: matches the manifest (sha256 <12 hex>…, N bytes)`, or `DIVERGED from the manifest` with both digests, or `MISSING`. A packaged transcript is judged here as bytes too, the whole file as of packaging. The `witness.json` line adds `(testimony: the packing machine's reading, unaltered; no verdict is drawn from it)`. Files in the package the manifest does not list print as `unlisted: <name> (not in the manifest, not judged)`.
5. **Each declared seal.** The anchor is judged offline the way `verify --anchors` judges a chain's (docs/ANCHORING.md §3): every record of `manifest.json.anchors.jsonl` must name this manifest's sha256 and replay. A completed proof prints `seal anchor: ANCHORED: the manifest existed by Bitcoin block H — confirm merkle root R against a block source you trust`; a pending one prints `seal anchor: ANCHOR-PENDING: the manifest was submitted <ts> via <calendar> — run ...` with the upgrade command, and the rung waits; a calendar that never came back when another one settled the same manifest prints `seal anchor: ANCHOR-UNANSWERED: ...` and the rung is earned, since the anchor's claim is about the digest and not about any one calendar (#199); a record for another digest, or one whose proof does not replay, prints `seal anchor: SEAL-INVALID: <why>`; a declared anchor with no sidecar, or an empty one, prints `seal anchor: SEAL-MISSING: ...`. The signature is judged by ssh-keygen, never by the recorder itself: the shipped `manifest.json.pub` becomes a one-line allowed-signers file under the principal `issuer`, and `ssh-keygen -Y verify -n loxodonta-package` says whether `manifest.json.sig` is that key's signature over the manifest's exact bytes. A signature that holds prints `seal signature: SIGNED (key: SHA256:<fingerprint>): the manifest, and transitively every artifact it lists, was issued by the holder of that key and has not changed since signing — compare the fingerprint against a channel this package cannot rewrite`, the fingerprint from `ssh-keygen -lf` on the shipped key and never a name or the key's comment (ADR-0008 ruling 4); one that does not hold, because the manifest changed after signing or the shipped key is not the one that signed, prints `seal signature: SEAL-INVALID: <ssh-keygen's words> — ...`; a declared signature with no `.sig` or no `.pub` prints `seal signature: SEAL-MISSING: <which> not in this package — ...`. A recipient whose ssh-keygen is missing, cannot run, or predates `-Y verify` (OpenSSH 8.0) sees `seal signature: not judged: <which> — the rung is neither earned nor failed; ...`, and the ladder reports the rungs it could judge (ADR-0026 ruling 6). The seal files are judged here as seals, never named as unlisted. A kind this verifier does not know is named as declared and not judged.
6. When the ladder allows it, one line of **residual trust**; then **the package verdict**, the last line, in ADR-0007's words, with its rungs in ADR-0007's order: `+ ANCHORED` when the manifest's anchor completed, then `+ SIGNED (key: SHA256:...)` when its signature holds (`SELF-CONSISTENT + ANCHORED + SIGNED (key: SHA256:...): ..., and the manifest existed by Bitcoin block H, and the manifest, and transitively every artifact it lists, was issued by the holder of key SHA256:... and has not changed since signing`), so a script reads the last line as it does for `verify`. The residual-trust line names what each seal gives, when and which key, each with the recipient's own check attached (the merkle root against a block source; the fingerprint against a published one), and what still rests on the issuer's word: that the record inside is true and complete, in every case; that it existed before today, without a completed anchor; which key packed it, without a signature that holds.

The signature check is plain ssh-keygen's, and a recipient can run it by hand from the unpacked package, without this tool; the principal `issuer` and the namespace `loxodonta-package` are fixed, and the third line prints the fingerprint to compare:

```
printf 'issuer %s\n' "$(cat manifest.json.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I issuer -n loxodonta-package -s manifest.json.sig < manifest.json
ssh-keygen -lf manifest.json.pub
```

The verifier reads `witness.json` for its bytes only. Its state, its counts, and the scan's verdicts inside are the supervisor's reading on the packing machine, and they change nothing in the ladder: a package whose witness says `ALARM-SILENT` and a package whose witness says `COMPLETE` verify identically. That is the meaning of *testimony* here, and the output says so where the file is judged.

### The ladder

Verdicts name the mechanism, never the conclusion (no "authentic", no "verified": GLOSSARY, Anti-terms). Gravest wins: a refusal, then a broken chain, then a seal or an anchor that is not this history, then a transcript that no longer holds, then an artifact off its manifest.

- `SELF-CONSISTENT`: every chain walks clean and every artifact matches the manifest. Printed with its limit, by what the seals earned: with no seal declared, *indistinguishable from a wholesale regeneration, since no seal is declared*; with an anchor declared and still pending, *indistinguishable from a wholesale regeneration until its manifest anchor completes*; with a signature declared and no anchor, *since no anchor is declared*; with a signature declared that this machine could not judge, the line adds *its signature was not judged, since ssh-keygen is not on PATH*. A regenerated session, packed afresh, produces this same line; only a completed seal separates the two.
- `SELF-CONSISTENT + ANCHORED`: the manifest's anchor replays to a Bitcoin block. The set existed by block H, printed with the merkle root the recipient confirms against a block source they trust (ADR-0003: the verifier never fetches a header). The rung is the manifest's anchor and no other's (ADR-0026 ruling 6): an anchored chain inside prints `ANCHORED` under that chain as detail and earns the package nothing, because it seals a different object.
- `SELF-CONSISTENT + SIGNED (key: SHA256:...)`: the signature over the manifest's shipped bytes verifies under the packaged public key, whose fingerprint follows (ADR-0008 ruling 7). It means ADR-0008's caged sentence, *this manifest, and transitively every artifact it lists, was issued by the holder of key K and has not changed since signing*, and nothing else: not that this is the original (the issuer holds the key and can re-sign, and a signature has no clock, so without an anchor the limit reads *indistinguishable from a regeneration re-signed with that key*), not that the contents are correct, and not *signed by \<name\>*: the verifier prints a fingerprint and stops, and whose key it is the recipient settles against a channel the package cannot rewrite. After `+ ANCHORED` when both hold.
- `CHAIN-BROKEN`: a chain does not walk clean. The recorder's `BROKEN at entry N` lines above say where.
- `ARTIFACT-DIVERGED`: an artifact's bytes differ from the manifest's listing, an artifact or a chain the manifest lists is missing, or a chain walks to a head or a length other than the one listed (the chain is then an artifact off its manifest; a truncated chain walks clean and is caught here).
- `ANCHOR-MISMATCH`: an anchor packaged with a chain names a head that is nowhere in that chain, or a proof that does not replay; the chain's own `ANCHOR-MISMATCH` or `ANCHOR-INVALID` line above says which. Not the anchored history.
- `SEAL-MISSING`: the manifest declares a seal and the package carries no file for it: no anchor sidecar, or an empty one; no `manifest.json.sig`, or no `manifest.json.pub`. A package stripped of a seal fails rather than reading as merely unsealed (ADR-0007's declared seal set).
- `SEAL-INVALID`: the package carries a seal that is not this manifest's: an anchor record whose `head` is another digest or whose proof does not replay; a signature ssh-keygen rejects, because the manifest changed after signing or the shipped key is not the one that signed; a `.pub` that is not a key ssh-keygen reads. Evidence that does not verify is not evidence.
- `TRANSCRIPT-DIVERGED`: a committed prefix of the packaged transcript no longer matches its commitment, or the transcript is shorter than a commitment says, or the commitments contradict each other (`COMMITMENT-SHRANK`). The recorder's `COMMITMENT DIVERGED (entry N)` line above localizes it to the span between two commitments. A rewritten transcript also diverges from the manifest's sha256; the graver word is the verdict, since a rewritten transcript is never innocent (ADR-0017).
- `UNSUPPORTED-FORMAT`: a refusal, not a verdict. The manifest is missing or unreadable, or its `format` is a tag this verifier does not speak. Nothing else is judged or printed.

## 6. Exit codes

Mapped onto `verify`'s own (ADR-0026 ruling 7), so a script that reads those learns nothing new:

| Exit | Package verdict | `verify`'s twin |
|---|---|---|
| 0 | `SELF-CONSISTENT`, with or without `+ ANCHORED` and `+ SIGNED (key: ...)`; a declared signature this machine could not judge changes nothing here | `VALID` |
| 1 | `CHAIN-BROKEN` | `BROKEN` |
| 2 | `ARTIFACT-DIVERGED` | `FILES-DIVERGED`, its package sibling per ADR-0007 |
| 3 | `SEAL-INVALID`, `SEAL-MISSING`, a chain's `ANCHOR-MISMATCH` | `HEAD-MISMATCH`: not what was issued |
| 4 | `UNSUPPORTED-FORMAT`, a refusal | `UNSUPPORTED-VERSION` |
| 5 | `TRANSCRIPT-DIVERGED` | `TRANSCRIPT-DIVERGED` |

Usage errors exit `64` (sysexits `EX_USAGE`) in both tools (ADR-0026 ruling 7, #175), so a verdict exit is never an argparse error; the README's advice still stands as good advice: read the verdict line, not the code alone.

A seal file the manifest does not declare (an anchor sidecar beside a manifest declaring `[]`, a `.sig` beside one declaring `["anchor"]`) is not judged: it prints as `unlisted`, since the declared set is what a seal is judged against (ADR-0007), and a seal the manifest never claimed is not one a stripped file could be missing from.

## 7. Worked example: the bad-day session

The demo store (`python tools/demo_store.py --home <dir>`) holds a session that reads an injected page, reads `.env`, posts it off the machine, and switches the recorder off (`docs/demo/bad-day-session.jsonl`). Packaged and verified on a machine that is not the one that recorded it:

```
package: loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907
format: loxodonta-package/1
packed: 2026-09-09T04:11:33Z by loxodonta supervisor 0.4.0 (testimony)
unit: kind session, session b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907, project todo
contents: 1 chain(s), 3 artifact(s), seals: none declared
chain: receipts-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907.jsonl (manifest: head 751d054dfeff…, 6 entries)
NO-ANCHORS: loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907/receipts-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907.jsonl.anchors.jsonl not found — anchoring is optional; run `loxodonta anchor` to add one
VALID
file references: 1 recorded, not checkable off the machine
project.json: matches the manifest (sha256 3076b53b4813…, 148 bytes)
witness.json: matches the manifest (sha256 07f2525caddd…, 999 bytes) (testimony: the packing machine's reading, unaltered; no verdict is drawn from it)
README.md: matches the manifest (sha256 656c8efc9c08…, 2929 bytes)
residual trust: this package is unaltered since it was packed. That the record inside is true and complete, that it existed before today, and which key packed it, rests on the issuer's word alone, since no seal is declared.
SELF-CONSISTENT: every chain walks clean and every artifact matches the manifest; indistinguishable from a wholesale regeneration, since no seal is declared
```

Exit 0. Read it as a recipient would. The chain walks clean: the six entries, `Read: .env` and the `curl` that posted it included, are the ones the recorder wrote, in order, unedited since. The one file reference is the fingerprint of `.env` as the agent saw it; the file is not here and cannot be checked. The witness says `UNWITNESSED` in this build, because the demo store has no transcript layout; on the operator's machine it would say what the completeness alarm said, and either way the verifier repeats it without judging it. And the last two lines state what remains: nothing here changed since it was packed, and nothing here says the set existed before today or which key packed it, because no seal was declared.

The manifest the verifier judged against:

```json
{
  "format": "loxodonta-package/1",
  "packed": "2026-09-09T04:11:33Z",
  "tool": "loxodonta supervisor 0.4.0",
  "unit": {
    "kind": "session",
    "session": "b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907",
    "project": "todo"
  },
  "chains": [
    {
      "path": "receipts-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907.jsonl",
      "head": "751d054dfefff992437ec1e9ff7f326b0cc5d745cd60097a98c3421a7cc0555e",
      "entries": 6,
      "anchors": null
    }
  ],
  "artifacts": [
    {
      "path": "project.json",
      "sha256": "3076b53b4813572928b66f8f0e196e4b1cd77257dfe2127aeba045b9f3b340fb",
      "bytes": 148
    },
    {
      "path": "witness.json",
      "sha256": "07f2525caddd65331c147ceceaa402eede1925d0570246132ec84cfa003d1cd3",
      "bytes": 999
    },
    {
      "path": "README.md",
      "sha256": "656c8efc9c089c224c0d31264020a8a5c17054146a3c465714e64cf6cd1df4de",
      "bytes": 2929
    }
  ],
  "seals": []
}
```

(Digests shortened here; the file carries all 64 hex characters.) Three edits, and what the ladder says of each: change a word in `witness.json`, and the artifact line reads `DIVERGED from the manifest`, verdict `ARTIFACT-DIVERGED`, exit 2, while the chain still says `VALID`; change a character inside an entry of the chain, and the recorder's `BROKEN at entry 3` appears verbatim, verdict `CHAIN-BROKEN`, exit 1; rewrite the chain with `\r\n` line endings, as a Windows unzip may, and nothing changes, still `SELF-CONSISTENT`, because the head is recomputed by walking.

### The same package, sealed

Packaged with `--anchor`, the summary says `seals: anchor`, the manifest declares `"seals": ["anchor"]`, and `manifest.json.anchors.jsonl` travels after it. Until Bitcoin has the proof, the seal line reads `seal anchor: ANCHOR-PENDING: the manifest was submitted <ts> via <calendar> — run \`loxodonta anchor --upgrade --manifest manifest.json\` after a few hours; the rung is not earned until the proof completes`, and the last two lines say the ceiling holds *until its manifest anchor completes*. Once upgraded (the block and root here are the test suite's fake calendar's; a real proof names a real block):

```
seal anchor: ANCHORED: the manifest existed by Bitcoin block 850123 — confirm merkle root 143d59af7866… against a block source you trust
residual trust: this package is unaltered since it was packed, and it existed by Bitcoin block 850123 if the merkle root printed beside that block is the block's. That the record inside is true and complete, and which key packed it, rests on the issuer's word alone.
SELF-CONSISTENT + ANCHORED: every chain walks clean and every artifact matches the manifest, and the manifest existed by Bitcoin block 850123
```

Delete the sidecar and the last line reads `SEAL-MISSING`, exit 3; put another manifest's proof in its place and it reads `SEAL-INVALID`, exit 3. A chain inside that carries its own session-end anchor prints `ANCHORED: entries 0..N existed by Bitcoin block ...` under that chain in both cases and changes the package verdict in neither.

### The same package, signed

Packaged with `--sign ~/.ssh/issuer_ed25519` (a key generated for the purpose with `ssh-keygen -t ed25519 -f ~/.ssh/issuer_ed25519`; §8 says what its custody has to be for the seal to mean more than testimony), the supervisor ends with `signed: key SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ; publish this fingerprint through a channel the package cannot rewrite, since the recipient compares it against one (ADR-0008)`; the summary says `seals: signature`, the manifest declares `"seals": ["signature"]`, and `manifest.json.sig` and `manifest.json.pub` travel after it. The verifier's seal line and its last two lines:

```
seal signature: SIGNED (key: SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ): the manifest, and transitively every artifact it lists, was issued by the holder of that key and has not changed since signing — compare the fingerprint against a channel this package cannot rewrite
residual trust: this package is unaltered since it was packed, and it was issued by the holder of key SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ and has not changed since signing, if that fingerprint matches one the issuer published through a channel this package cannot rewrite. That the record inside is true and complete, and that it existed before today, rests on the issuer's word alone, since no anchor is declared.
SELF-CONSISTENT + SIGNED (key: SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ): every chain walks clean and every artifact matches the manifest, and the manifest, and transitively every artifact it lists, was issued by the holder of key SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ and has not changed since signing; indistinguishable from a regeneration re-signed with that key, since no anchor is declared
```

Exit 0. The fingerprint is the whole of what the verifier says about *who*: it is the recipient who holds it against the one the issuer published (a README in a public repo, an engagement letter, the issuer's page) and decides. Edit the manifest after signing and the seal line reads `seal signature: SEAL-INVALID: Signature verification failed: incorrect signature; Could not verify signature. — the signature is not the shipped key's over this manifest's bytes`, verdict `SEAL-INVALID`, exit 3; replace `manifest.json.pub` with another key's and it reads the same, since the signature is judged under the shipped key and no other; delete either file and the verdict is `SEAL-MISSING`, exit 3. On a machine without ssh-keygen the seal line reads `seal signature: not judged: ssh-keygen is not on PATH — ...`, the last line stays `SELF-CONSISTENT` with *its signature was not judged* added, and the exit code is whatever the rest of the ladder says.

With `--anchor` and `--sign` together the manifest declares `["anchor", "signature"]`, the zip carries the signature, then the key, then the sidecar, and once the anchor completes the last line reads the whole ladder in ADR-0007's order:

```
SELF-CONSISTENT + ANCHORED + SIGNED (key: SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ): every chain walks clean and every artifact matches the manifest, and the manifest existed by Bitcoin block 850123, and the manifest, and transitively every artifact it lists, was issued by the holder of key SHA256:2eRfqke+jYJBLot4Ywa/piXSrsFLSUv3Dw9+2lUgvkQ and has not changed since signing
```

That pairing is the one ADR-0008 ruling 6 was written for: the signature says which key, the anchor says when, and a key stolen later can only sign forgeries into young blocks.

## 8. What none of this survives

- **Garbage in.** The package is unaltered since packaging. Whether the recorder was told the truth, and whether every tool call got its receipt, is the harness's and the witness's word (SPEC §8, ADR-0002).
- **No seals, or a pending one.** `SELF-CONSISTENT` alone is what a wholesale regeneration also produces. The anchor lines under a chain speak for that chain and say when its head existed; the package as a set is on record only from its own seals, and only once the proof completes.
- **What the anchor says.** Existence by block H, of the manifest and so of the set it lists; nothing about who packed it (that is the signature's question, ADR-0008) and nothing about whether the record is true. A regenerated set can be re-anchored, but only into a recent block: the recipient reads the height against the history the package claims (docs/ANCHORING.md §1).
- **What the signature says.** ADR-0008's caged claim, verbatim: *this manifest, and transitively every artifact it lists, was issued by the holder of key K and has not changed since signing*, and nothing else. Not the original: the issuer holds the key and can sign conflicting versions, and a signature has no clock, so ordering in time comes only from the anchor. Not correct: garbage in, faithfully signed garbage out. Not *signed by \<name\>*: the verifier prints the fingerprint and stops. A stolen key signs forgeries freely, but a forgery can only obtain a young anchor, which is why a signature with an old anchor survives a breach and a signature alone does not (ADR-0008 ruling 6).
- **A key the writer could reach.** The custody cage (ADR-0026 ruling 8, applying ADR-0008 ruling 3): a key any process of this user could use without the operator, an unencrypted key in `~/.ssh` or one loaded in `ssh-agent`, is writer-reachable, and a signature made with it is testimony, since the agent whose session is being packaged could have signed a regenerated package under the same fingerprint. `--sign` promises no more than the key's custody does, and the tool cannot see the custody. A FIDO2 key that needs a touch, or signing on another machine, is out of reach; the operator signing is the issuer wearing a second hat (GLOSSARY, *Issuer*).
- **Rotation.** A published fingerprint is never unpublished: packages outlive keys, and a recipient verifying in year five needs year one's fingerprint still findable. Rotate on need, a compromise or a genuine loss, never on a calendar, and handle a compromise with an out-of-band notice carrying a date fence, the anchors before it standing (ADR-0008 ruling 6).
- **The transcript after retention.** Commitments in the chain bind the harness transcript only while it exists. `--transcript` at packaging is the only thing that keeps it; hashing more often does not. A package without it carries the commitments and nothing to judge them against, and the verifier says so under the chain. A package with it carries the bytes as they stood at packaging: what the transcript says is the harness's record, and before its first commitment it was the writer's to rewrite (ADR-0017), packaged faithfully either way.
- **A transcript's owner.** A transcript is tied to a chain by that chain's commitments. A chain with none cannot tell its transcript from another's: the manifest's word is all there is, and the verifier says nothing was judged.
- **The manifest's bytes.** The seal applies to the manifest's exact bytes. A folder package checked into git with line-ending conversion, or copied through anything that rewrites text, comes back with a different manifest and an honest seal, anchor or signature, reads `SEAL-INVALID`; ship the zip, which carries the bytes as sealed.
- **File contents.** Paths and fingerprints travel; files do not.
- **The recipient's own job.** The verifier prints a merkle root under an anchored chain and on the manifest's anchor line; confirming each against a block source they trust is theirs (ADR-0003: the verifier never fetches a header). It prints a key fingerprint on the signature line; comparing it against one the issuer published through a channel the package cannot rewrite is theirs too (ADR-0008 ruling 4: math is the verifier's job, identity is the recipient's). A first-time recipient with no such channel holds only the packaged key: for them `SIGNED` means key continuity across this issuer's packages from here on, nothing more.
