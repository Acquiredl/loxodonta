# Anchoring — Stage B format and behavior

**Status:** accepted 2026-08-13 (ADR-0003). This document specifies anchoring behavior; the entry format of `docs/SPEC.md` v0.1 is untouched — anchor proofs live beside the log, never inside it (SPEC §8).

## 1. What an anchor is

An anchor commits a chain head to Bitcoin via [OpenTimestamps](https://opentimestamps.org): the head digest is sent to public calendar servers, which aggregate many digests into a Merkle tree and commit its root inside a Bitcoin transaction. The completed proof is a list of byte operations that replays the head digest, step by step, up to the merkle root of a Bitcoin block header at a stated height.

An anchor proves **existence by block H**: entries `0..n` (whose head was anchored) existed, byte-exact, when block H was mined. It proves nothing about who wrote them (ADR-0001) and cannot prevent re-anchoring a regenerated chain — but a regenerated chain can only carry *young* anchors, so verify reports every anchor's height and the operator judges freshness: a log claiming months of history with only yesterday's anchors is a rewrite.

That proof has two halves, and the proof file holds only one. The attestation at its end names a height, and replaying the operations gives a merkle root; nothing in either shows that a block with that root was ever mined, so a regenerated chain can carry an attestation made up whole, claiming any height it likes. The other half is the block's header, which the recipient fetches from a source they trust. `verify --anchors` says which halves it held: without a header, the block an attestation claims and the words *not checked*; with a header whose merkle root is the one the proof replays to, existence by that block (§3, *Checking the block*).

## 2. The sidecar file

Anchors for `<log>` live in `<log>.anchors.jsonl` (e.g. `receipts.jsonl.anchors.jsonl`), one JSON object per line, append-only by convention:

```json
{"head": "<64-hex entry_hash>", "n": 12, "ts": "2026-08-13T14:00:00Z", "calendar": "https://a.pool.opentimestamps.org", "proof": "<base64 OTS timestamp>"}
```

- `head` — the chain head that was anchored (entry `n`'s `entry_hash`).
- `n` — that entry's sequence number at anchor time.
- `ts` — submission time, writer-supplied testimony like any timestamp.
- `calendar` — the calendar URL this proof came from.
- `proof` — base64 of the OTS-serialized timestamp: operations from the head digest to either a **pending** attestation (calendar has it, Bitcoin not yet) or a **Bitcoin** attestation (complete).

The sidecar is *evidence, not a chain*: a forged proof fails replay; a deleted proof destroys evidence but forges nothing. Copy the sidecar somewhere the writer can't reach — proofs are self-authenticating, so an out-of-reach copy is strictly stronger than a head record.

Beside the proofs, the session-end anchor leaves one more kind of row (#240). After each attempt the hook appends `{"budget":12.0,"kind":"attempt","outcome":"submitted","step":"anchor","ts":"2026-09-16T05:35:42Z"}`, keys sorted and compact as every sidecar line is written, or the same row with the outcome `no calendar answered within 12 seconds` when nothing answered inside the budget. It is the recorder's note on how the step went, written so the store can tell a hook that never fired from one that fired and got no answer; it is testimony and never a proof. `verify --anchors`, `anchor --upgrade`, the supervisor's keeper and `verify-package` skip attempt rows by their kind, so a sidecar holding only notes reads exactly as an empty one. The supervisor reads them: `scan --json` says per chain when a head last left the machine and which session-end step last failed, with the outcome line as the reason. The publish memo carries the same row for the published head (docs/HOOK.md), and there it names no URL at all. A verifier or supervisor from before this change reads an attempt row as an invalid anchor record (`ANCHOR-INVALID`, exit 3) or as a departure, so a package recipient needs this release or later.

## 3. Commands

```
loxodonta anchor [--log PATH] [--calendar URL]...   # submit the current head
loxodonta anchor --upgrade [...]                    # complete pending proofs
loxodonta anchor --manifest PATH [--calendar URL]...  # anchor a package manifest's sha256
loxodonta anchor --upgrade --manifest PATH          # complete that proof
loxodonta verify --anchors [...]                    # judge proofs, offline
loxodonta verify --anchors --block-header HEX [...] # ... and check their blocks
```

**`anchor`** reads the current head, POSTs the raw 32-byte digest to each calendar (`POST <calendar>/digest`), and appends one sidecar record per calendar that answered. Success is ≥1 record written (exit 0); no calendar reachable is exit 1. Default calendars: `a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`, `ots.btc.catallaxy.com`.

**`anchor --upgrade`** replays each pending proof to its calendar commitment, asks the calendar for the completion (`GET <calendar>/timestamp/<commitment-hex>`), and appends an upgraded record (same `head`, spliced proof ending in a Bitcoin attestation). Still-pending proofs (typically for a few hours after submission) are reported and left alone. A pending proof whose head another calendar has already settled is skipped with a line saying why, rather than re-asked every run: the anchor's claim is about the head, not about any one calendar (#199).

**`anchor --manifest PATH`** anchors a package manifest the same way, its sha256 in place of a chain head (ADR-0026 ruling 4): the proof lands in `PATH.anchors.jsonl` as an ordinary record with no `n`, since a manifest has no entries, and `--upgrade --manifest PATH` completes it. The door is general: `--manifest PATH` anchors the sha256 of any file's bytes, and the package manifest is the case it exists for. `supervisor package --anchor` drives this and `loxodonta verify-package` judges it (docs/PACKAGE.md §2 and §5).

**`verify --anchors`** — offline, like all of verify. For each sidecar record:

1. The record's `head` must equal the `entry_hash` of some entry in the log — the chain up to that entry *is* the anchored history. No match: `ANCHOR-MISMATCH` (this log is not the anchored history — the regeneration signature), **exit 3**, same tier as `HEAD-MISMATCH`.
2. The proof must replay from the head digest without error. Failed replay or a malformed proof: `ANCHOR-INVALID`, also exit 3 — evidence that doesn't verify is not evidence.
3. A clean replay reports one of:
   - `ANCHORED: entries 0..n: the attestation claims Bitcoin block H, and the block was not checked; that block's merkle root must read <R>, which --block-header with its header checks`: the proof completes to a Bitcoin attestation, and nothing here has seen the block. Not a failure, and the exit is unchanged. The printed root and height are exactly what to check, by hand against a block source you trust or with `--block-header` (ADR-0003; ruling 3 on #299).
   - `ANCHORED: entries 0..n existed by the block whose header hashes to <X>, whose merkle root <R> is the one the proof replays to; the attestation calls it Bitcoin block H, which is your header source's word, and the hash is what a second source can confirm`: a header given with `--block-header` holds the root the proof replays to.
   - `ANCHOR-PENDING: head <h>… submitted <ts> via <calendar> — run loxodonta anchor --upgrade` — not a failure; exit unchanged.
   - `ANCHOR-UNANSWERED: head <h>… submitted <ts> via <calendar> never came back, and another calendar settled this head — no upgrade is owed` — the record stays in the sidecar as evidence of where the submission went, and the line stops advising a command that cannot help. Calendars disagreeing is ordinary, and four of them is the default (#199).

A header that matched no attestation prints `HEADER-UNMATCHED: the block header with hash <X> holds merkle root <R>, which no Bitcoin attestation judged here replays to; ...` after the anchor lines and before the verdict. It checked nothing, and it is a note, never a verdict (below).

A missing sidecar under `--anchors` prints `NO-ANCHORS` and leaves the exit code to the other checks — anchoring is optional, and absence of local evidence is a fact for the operator (who knows whether they anchor) rather than a verdict. Verdict precedence is unchanged from SPEC §6: `BROKEN` (1) short-circuits; exit-3 findings (head, anchor or stamp) outrank `FILES-DIVERGED` (2).

### Checking the block

**`--block-header HEX`** gives the verifier one Bitcoin block header: its 80 bytes as 160 hex characters, from any source you trust. It is repeatable, one header per anchored block, and it needs `--anchors`. Given without it, the command is a usage error, exit 64, because the header was given to check an anchor, and a `VALID` with no anchor judged would read as though it had. A value that is not 160 hex characters is a usage error too. Nothing is fetched: the header is on the command line, or the block is not checked.

What is compared is 32 bytes. A header is version, previous block hash, merkle root, time, bits and nonce, and the merkle root is bytes 36 to 68, stored in the order Bitcoin's double sha256 leaves it. The last operations of a Bitcoin proof are that double sha256 (the transaction id, then each step up the block's merkle tree), so the digest the attestation sits on is compared with those bytes as they stand. Explorers print the root and the block hash byte-reversed, and so does the verifier, so the printed values read directly against an explorer's page.

A header carries no height, so the verifier cannot know that it is block H: it knows only which merkle root the header holds. Headers are matched to attestations by that root.

- An attestation whose root a header holds prints the second `ANCHORED` line, naming the block by the header's hash (double sha256 of the 80 bytes, reversed, as explorers show it). That hash is what to cross-check: ask a second source which block has it. The height the line repeats is the attestation's word and your source's, never the verifier's.
- An attestation whose root no header holds keeps the first line, *not checked*, whatever headers were given.
- A header whose root no attestation replays to prints `HEADER-UNMATCHED`. If you fetched it for a height an attestation claims, that attestation does not replay to that block, which is what a made-up attestation looks like. The verifier cannot know what the header was fetched for, so it notes the fact and draws no verdict from it.

The exit code does not move for any of this. A block not checked is not a failure, and neither is a header that checked nothing. `ANCHOR-MISMATCH` and `ANCHOR-INVALID` keep their meaning and their exit 3: a proof for a head this log does not hold, or one that does not replay, whatever headers were given. A script that must know a block was checked reads for the second `ANCHORED` line, and one that must know every header was used reads for `HEADER-UNMATCHED`.

**Getting a header.** The attestation names the height, so ask for that height's header, and check what comes back against a second source:

- A node you run: `bitcoin-cli getblockhash H`, then `bitcoin-cli getblockheader <hash> false`, which prints the 160 hex characters.
- A block explorer: most show a block's hash and merkle root by height, and many serve the raw header from their API. Take it from two explorers run by different people, and compare the block hash the verifier prints with the one both show for height H.

`verify-package` takes `--block-header` too (docs/PACKAGE.md §5). Each header is checked against every anchor the package carries, the chains' and the manifest's, and one that matched none of them is noted once, after the seals.

## 4. The OTS subset (wire format)

loxodonta implements the subset of the OTS format that calendar proofs actually use; anything else is refused by name, never guessed (ADR-0003).

- **varint**: unsigned, little-endian base-128, high bit = continuation.
- **varbytes**: varint length, then the bytes.
- **operations** (applied to the current digest `msg`): `0x08` sha256 → `SHA256(msg)`; `0xf0` append `arg` → `msg‖arg`; `0xf1` prepend `arg` → `arg‖msg`. Binary ops carry their operand as varbytes.
- **timestamp tree**: a sequence of elements; every element except the last is prefixed `0xff`. An element is either an attestation (`0x00`, then an 8-byte tag, then varbytes payload) or an operation (tag byte, operand if binary, then the subtree that continues from the new digest).
- **attestations**: Bitcoin block header = tag `05 88 96 0d 73 d7 19 01`, payload = varint block height, meaning "the current digest is the merkle root of block H", in the byte order the header stores it (§3, *Checking the block*). Pending calendar = tag `83 df e3 0d 2e f9 0c 8e`, payload = varbytes UTF-8 calendar URI. Unknown tags are preserved on rewrite and reported as unverifiable.
- **calendar HTTP**: `POST /digest` (body: raw digest bytes) returns a serialized timestamp starting at the digest; `GET /timestamp/<hex>` returns the continuation from a commitment, or HTTP 404 while Bitcoin confirmation is pending.

Proof bytes are stored exactly as calendars produced them (plus splicing on upgrade); the interoperability contract is that `ots verify` on the same bytes reaches the same block.

## 5. Operator ritual, updated

Stage A: record the head out of the writer's reach, compare with `verify --expect-head`.
Stage B replaces remembering a secret with two cheaper habits:

1. **Anchor at meaningful moments** — end of a session, end of a pipeline run: `loxodonta anchor` (later, `--upgrade` once, any time after a few hours). Or opt in once and let the hook do it: `loxodonta install-hook --anchor-at-session-end` anchors every session's head when the session ends, after the tail commitment, under a twelve-second budget, quietly on failure, and spends the leftover budget upgrading the drawer's pending proofs (ADR-0024). What leaves the machine is the 32-byte head digest, to the public calendars, from your address, only after the opt-in. A remote is a head record when the credentials on this machine cannot delete or overwrite what they wrote there (ADR-0025): a gist under your login is not one, because the `gh` token deletes it; a chat webhook or a retention-locked bucket is, and `install-hook --publish-head URL` sends each session's head there before the anchor.
2. **When verifying, check the blocks and read the heights.** `verify --anchors` proves the math up to a merkle root, and `--block-header` with each anchored block's header, from a source you trust, turns an attestation's claim into a checked block. Only the operator can judge whether "existed by block H" is *old enough* to cover the history the log claims.

Copying the sidecar off-machine remains recommended and makes the story airtight: proofs in hand, nothing on the writer's machine to trust at all.

## 6. The authority timestamp, which is not an anchor

An anchor is the credential-free commitment: its proof is nobody's product, it replays offline from the head digest to a Bitcoin block header, and no party can be leaned on to make it say something else. An **authority timestamp** is the other kind. The same 32-byte head goes to an RFC 3161 timestamp authority the operator names; the authority signs it under its own clock and hands back a token, which is somebody's signed word, trusted exactly as far as that authority's certificate. An authority that lies about its clock can stamp any time it likes, and the anchor cannot be made to do that, which is why the anchor stays. The two sit side by side and never share a word: the verb, the sidecar, the verdict and every message say **stamp**, never anchor (ADR-0032 ruling 1).

Why the second one is worth having: speed and standing. An anchor matures when Bitcoin confirms, hours after the session; an authority answers in one round trip. And a qualified timestamp under eIDAS is recognized evidence in EU courts, where a block header, whatever its actual strength, formally is not. The qualified kind is the one with standing; an ordinary token is not it, and neither is a free one. Public authorities exist to try this against, [FreeTSA](https://freetsa.org) and DigiCert's public timestamp service among them, and an enterprise that already runs an authority inside its own network points the flag there, where nothing leaves the network at all. **No authority is baked in**, at any tier: whom to trust is the whole choice, so the URL is yours to type. OpenTimestamps stays the default and the only commitment at the `timestamped` profile until you name one (ADR-0032 ruling 6).

### The stamps sidecar

Tokens for `<log>` live in `<log>.stamps.jsonl`, one JSON object per line, append-only by convention, keys sorted and compact as every sidecar line is written:

```json
{"authority":"https://freetsa.org/tsr","head":"<64-hex entry_hash>","n":12,"response":"<base64 TimeStampResp>","ts":"2026-09-17T05:35:42Z"}
```

- `head` — the chain head that was stamped (entry `n`'s `entry_hash`).
- `n` — that entry's sequence number when the token was asked for.
- `ts` — when it was asked, writer-supplied testimony like any timestamp.
- `authority` — the URL that was asked. Written down, where the publish memo writes no URL at all, because this one is not a credential: it names whom the operator chose to trust, which is the one thing a reader of the token needs to know (ADR-0032 ruling 4).
- `response` — base64 of the authority's whole `TimeStampResp`, verbatim. The recorder reads its status and nothing else; it never parses the token and never claims to know what is inside. `openssl ts -reply -in FILE -text` over those bytes prints the time the authority stated.

The attempt row of §2 is kept here too, under the step `stamp`. After each session-end query the hook appends `{"budget":3.0,"kind":"attempt","outcome":"granted","step":"stamp","ts":"2026-09-17T05:35:42Z"}`, or the same row with the one line the query produced instead — `no answer within 3 seconds`, `the remote answered 404`, `the authority answered status 2 (rejection)`, `the reply is larger than 64 KiB`, `the token could not be written`. Never the URL. `stamp` run by hand writes the same note when its query fails, and so do `publish` and `publish --chain` (#251), for the reason this verb had first: a head, or a batch of entries, that one of them could not send is one the supervisor should still read as unsent and lately tried, and the keeper's cadence is a run of these verbs. The anchor verb is the one that still leaves its note to its session-end half. Either way a refused query leaves the note and no token row, because a refusal is nobody's word. A head that already holds a token is not asked about again by either door and leaves no row at all; the verb says `already stamped` and exits 0, so a cadence cannot fill the sidecar with tokens for one head.

### Commands

```
loxodonta stamp --authority URL [--log PATH]              # a token over the current head
loxodonta stamp --authority URL --manifest PATH           # ... over a package manifest's sha256
loxodonta install-hook --profile timestamped --authority URL   # ... at every session end
loxodonta verify --stamps [--authority-chain FILE]        # judge tokens, offline
supervisor package ... --stamp URL                        # seal a package with one
loxodonta verify-package PATH --authority-chain FILE      # judge a package's tokens
```

**`stamp`** reads the current head and POSTs a DER `TimeStampReq` to the authority as `application/timestamp-query`: version 1, a SHA-256 imprint of the head, a nonce, and `certReq` true, so the token carries the certificate that signed it and can be judged later from the authority's chain file alone. The recorder reads only the response's status — granted (0), or granted with modifications (1), or not granted — and appends one record for a token it was granted. Exit 0 with a record written, or with `already stamped ...` when this head already holds a token and nothing was asked. Exit 1, one line on stderr naming which, and an attempt row in place of a token row when the authority refused, answered something that is not a timestamp response, could not be reached, sent more than this file reads back (64 KiB, and the line says the cap is ours), or granted a token this machine could not write down. That last one is never recorded as `granted`: a token nobody kept is not a stamp.

**`--manifest PATH`** stamps a file's sha256 instead of a chain head, the shape `anchor --manifest` has: the token lands in `PATH.stamps.jsonl` and its record carries no `n`, because a manifest has no entries. This is how `supervisor package --stamp URL` seals a package, and `verify-package --authority-chain FILE` is how the recipient judges what it sealed — the seal earns `+ STAMPED` beside `+ ANCHORED`, a declared token that is absent is `SEAL-MISSING`, and the package carries each chain's stamps sidecar as it carries the anchors sidecar, judged as detail under its chain. The certificate chain is the one thing the package must not carry, since a chain shipped by the issuer is the issuer's word about whom to trust (docs/PACKAGE.md §2).

**At session end**, once `install-hook --authority URL` has wired it (`docs/HOOK.md`), the same query runs after the tail commitment and the published head and before the anchor, so a slow calendar can never cost the fast POST and the anchor takes what is left of the twelve-second budget. Quiet on failure like its neighbours, and written down either way. **On the keeper's cadence**, when the coverage marker names an authority, `supervisor serve` stamps each ripe head on the turn that anchors it — the anchor cadence and no second one — which is the cover for the session that never reached its end.

**`verify --stamps [--authority-chain FILE]`** — offline, like all of verify. Nothing is fetched: the chain file is on disk, or the token is not judged. For each record:

1. The record's `head` must equal the `entry_hash` of some entry in the log — the chain up to that entry *is* the stamped history. No match: `STAMP-INVALID` (this log is not the stamped history), **exit 3**, the tier of `ANCHOR-MISMATCH` and `HEAD-MISMATCH`. That much needs no tool at all.
2. The token itself goes to `openssl ts -verify -digest <head> -sha256 -in <the stored response> -CAfile <your chain file>`. Accepted, it reports `STAMPED: entries 0..n existed when a key certified by <your chain file> signed this head under its own clock (the record names <URL>, testimony)`, adding that the time inside the token is that key's word and not this machine's. That is all openssl checked. The URL is the recorder's note of whom it asked, kept in a sidecar the writer can edit, so it is named as testimony and never as the signer; whose key it is rests on where you got the chain file, as ADR-0008 ruling 4 has it for the issuer signature. Rejected, it is `STAMP-INVALID`, also exit 3, carrying openssl's own reason — evidence that doesn't verify is not evidence. One rejection is the calendar's and not the token's (#264): openssl checks the authority's certificate as of the moment it verifies, so a genuine token fails once that certificate expires. When expiry is openssl's reason, `verify` asks again as of the time the token states (`-attime`). That time is the token's own, the one the authority signed, read from what `openssl ts -reply -token_out -text` prints, so the recorder still never parses a token; the reply's status text around the token is signed by nobody and never read for it. If the token holds then, it prints `stamp not judged: the authority's certificate expired after the token was issued`. If it fails then too, the reason is the token's own and it is `STAMP-INVALID`, openssl's second answer followed by `(judged as of the time the token states)`. If it states no time that can be read, or more than one, there is nothing to ask about, so openssl's first answer stands as `STAMP-INVALID`, followed by `the time the token states could not be read, so nothing shows the certificate was in date then`. The second check is the one that counts, because openssl checks the certificate before the signature: after expiry, a token with a flipped bit gets the same first answer as a genuine one.
3. No `--authority-chain` at all, a chain file that isn't there, no `openssl` on the path, a certificate that expired after the token was issued (step 2), or an `openssl` whose `ts -verify` has no `-attime` to ask about any moment but now: `stamp not judged: <reason>`. The token is present and nobody judged it, a note and never a verdict, and the exit code stays the chain's. This is the posture ADR-0026 set for the issuer signature and `ssh-keygen`, kept here for the same wall: the stdlib has no public-key cryptography, so either `openssl` checked the signature or nobody did, and the output says which.

Every token in the sidecar is judged against the one chain file, so a chain stamped by more than one authority over its life needs one chain file holding every authority's certificates (concatenated PEM). `--authority-chain` without `--stamps` is a usage error, exit 64: the file was named in order to have the tokens judged against it, and a run that quietly ignored it would answer `VALID` with nothing judged, which is the one outcome this posture exists to prevent. A missing sidecar under `--stamps` prints `NO-STAMPS` and leaves the exit code to the other checks, exactly as `NO-ANCHORS` does. Save the authority's certificate chain the day you wire it: that file is what `verify` reads, and losing it turns every token into "not judged". Certificate life is the operator's habit and is not built here — a chain expires and can be revoked, re-stamping before expiry is yours to schedule, and ten-year evidence is the anchor's job (ADR-0032). Past expiry, a token openssl accepts as of its own time is *not judged* and never `STAMPED`: once the certificate has run out nothing vouches for the key, and whoever holds it could sign any earlier time.
