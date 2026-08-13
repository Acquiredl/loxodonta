# Anchoring — Stage B format and behavior

**Status:** accepted 2026-08-13 (ADR-0003). This document specifies anchoring behavior; the entry format of `docs/SPEC.md` v0.1 is untouched — anchor proofs live beside the log, never inside it (SPEC §8).

## 1. What an anchor is

An anchor commits a chain head to Bitcoin via [OpenTimestamps](https://opentimestamps.org): the head digest is sent to public calendar servers, which aggregate many digests into a Merkle tree and commit its root inside a Bitcoin transaction. The completed proof is a list of byte operations that replays the head digest, step by step, up to the merkle root of a Bitcoin block header at a stated height.

An anchor proves **existence by block H**: entries `0..n` (whose head was anchored) existed, byte-exact, when block H was mined. It proves nothing about who wrote them (ADR-0001) and cannot prevent re-anchoring a regenerated chain — but a regenerated chain can only carry *young* anchors, so verify reports every anchor's height and the operator judges freshness: a log claiming months of history with only yesterday's anchors is a rewrite.

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

## 3. Commands

```
receipts anchor [--log PATH] [--calendar URL]...   # submit the current head
receipts anchor --upgrade [...]                    # complete pending proofs
receipts verify --anchors [...]                    # judge proofs, offline
```

**`anchor`** reads the current head, POSTs the raw 32-byte digest to each calendar (`POST <calendar>/digest`), and appends one sidecar record per calendar that answered. Success is ≥1 record written (exit 0); no calendar reachable is exit 1. Default calendars: `a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`, `ots.btc.catallaxy.com`.

**`anchor --upgrade`** replays each pending proof to its calendar commitment, asks the calendar for the completion (`GET <calendar>/timestamp/<commitment-hex>`), and appends an upgraded record (same `head`, spliced proof ending in a Bitcoin attestation). Still-pending proofs (typically for a few hours after submission) are reported and left alone.

**`verify --anchors`** — offline, like all of verify. For each sidecar record:

1. The record's `head` must equal the `entry_hash` of some entry in the log — the chain up to that entry *is* the anchored history. No match: `ANCHOR-MISMATCH` (this log is not the anchored history — the regeneration signature), **exit 3**, same tier as `HEAD-MISMATCH`.
2. The proof must replay from the head digest without error. Failed replay or a malformed proof: `ANCHOR-INVALID`, also exit 3 — evidence that doesn't verify is not evidence.
3. A clean replay reports one of:
   - `ANCHORED: entries 0..n existed by Bitcoin block H — confirm merkle root <R> against a block source you trust` — the offline tier ends at the block-header commitment; the printed root and height are exactly what to check (ADR-0003).
   - `ANCHOR-PENDING: submitted <ts> via <calendar> — run receipts anchor --upgrade` — not a failure; exit unchanged.

A missing or empty sidecar under `--anchors` prints `NO-ANCHORS` and leaves the exit code to the other checks — anchoring is optional, and absence of local evidence is a fact for the operator (who knows whether they anchor) rather than a verdict. Verdict precedence is unchanged from SPEC §6: `BROKEN` (1) short-circuits; exit-3 findings (head or anchor) outrank `FILES-DIVERGED` (2).

## 4. The OTS subset (wire format)

receipts implements the subset of the OTS format that calendar proofs actually use; anything else is refused by name, never guessed (ADR-0003).

- **varint**: unsigned, little-endian base-128, high bit = continuation.
- **varbytes**: varint length, then the bytes.
- **operations** (applied to the current digest `msg`): `0x08` sha256 → `SHA256(msg)`; `0xf0` append `arg` → `msg‖arg`; `0xf1` prepend `arg` → `arg‖msg`. Binary ops carry their operand as varbytes.
- **timestamp tree**: a sequence of elements; every element except the last is prefixed `0xff`. An element is either an attestation (`0x00`, then an 8-byte tag, then varbytes payload) or an operation (tag byte, operand if binary, then the subtree that continues from the new digest).
- **attestations**: Bitcoin block header = tag `05 88 96 0d 73 d7 19 01`, payload = varint block height, meaning "the current digest is the merkle root of block H". Pending calendar = tag `83 df e3 0d 2e f9 0c 8e`, payload = varbytes UTF-8 calendar URI. Unknown tags are preserved on rewrite and reported as unverifiable.
- **calendar HTTP**: `POST /digest` (body: raw digest bytes) returns a serialized timestamp starting at the digest; `GET /timestamp/<hex>` returns the continuation from a commitment, or HTTP 404 while Bitcoin confirmation is pending.

Proof bytes are stored exactly as calendars produced them (plus splicing on upgrade); the interoperability contract is that `ots verify` on the same bytes reaches the same block.

## 5. Operator ritual, updated

Stage A: record the head out of the writer's reach, compare with `verify --expect-head`.
Stage B replaces remembering a secret with two cheaper habits:

1. **Anchor at meaningful moments** — end of a session, end of a pipeline run: `receipts anchor` (later, `--upgrade` once, any time after a few hours).
2. **When verifying, read the heights.** `verify --anchors` proves the math; only the operator can judge whether "existed by block H" is *old enough* to cover the history the log claims.

Copying the sidecar off-machine remains recommended and makes the story airtight: proofs in hand, nothing on the writer's machine to trust at all.
