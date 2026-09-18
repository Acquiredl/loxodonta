# The topology: where each piece runs, and what its evidence is worth

Three files, the machine the agent works on, and up to four places beyond it. What a verdict is worth depends on what it was checked against. A chain checked against its own hashes shows an edit, a deletion or a reorder anywhere in it. A chain checked against something the writer can rewrite gives a reason to look. A chain checked against something the writer cannot reach is where a regenerated one shows. This page draws the places once, with what runs in each, what each holds, and what its evidence is worth. The page that owns each piece is linked from it.

```
 THE AGENT'S MACHINE                     |  ELSEWHERE
 all of it within the writer's reach     |  the writer can at most add
                                         |
 harness --hook--> loxodonta.py          |
                        |                |
                        v                |
 the store: chains, sidecars, memo       |
                        ^                |
                        | reads          |
 supervisor.py: scan, serve (dashboard,  |
   /metrics), recall, the keeper,        |
   package; its baseline and day book    |
                                         |
 what leaves on its own, by profile      |
 (local: nothing)                        |
                                         |
 timestamped, full                       |
   32-byte digest ---------------------->|  OpenTimestamps calendars,
   proof, into a sidecar <---------------|  then Bitcoin
                                         |
 with --authority URL                    |
   32-byte digest ---------------------->|  a timestamp authority
   token, into a sidecar <---------------|  you named
                                         |
 full                                    |
   head and entries -------------------->|  THE RECEIVER'S MACHINE
                                         |  receiver.py, heads.jsonl,
                                         |  receipts-<session>.jsonl
                                         |
 what leaves by hand                     |
   a package --------------------------->|  THE RECIPIENT
                                         |  loxodonta verify-package
```

The line down the middle is the one that matters. Everything left of it is the writer's to reach, whatever the file (ADR-0002). Everything right of it is somewhere the writer can at most add to.

## The agent's machine

**What runs there.** The harness, and the hook it fires after each completed tool call, which runs `loxodonta.py` to append one receipt to the session's chain in the store, `~/.loxodonta/receipts/<project>-<hash>/` ([HOOK.md](HOOK.md)). Beside it, `supervisor.py`: `scan`; `serve`, with the dashboard and `/metrics` bound to `127.0.0.1` ([METRICS.md](METRICS.md)); recall and its read-only MCP server ([MCP.md](MCP.md)); the keeper's anchor and publish cadences; and `package`.

**What it holds.** The chains; beside each chain its anchor sidecar, its stamps sidecar and the publish memo; beside the store, the supervisor's baseline and day book, and the coverage marker that records the profile.

**What it is worth.** `verify` here catches an edit, a deletion or a reorder of a past entry, because the chain's own hashes break. What nothing here can settle is a chain regenerated from scratch, or rewritten consistently from some entry on: the baseline may shout that a head it saw is gone, but every file that would remember the old head, the baseline included, is one the writer can rewrite or delete as well. The baseline, the day book, the memo and the marker are testimony, trusted for nothing, and a wiped store takes its chains with it, all but what already left. So the scan, the dashboard and every gauge on `/metrics` stay on this machine and say so: fast detection, a reason to shout, never proof. A gauge scraped to another box is still this machine's reading. An anchor proof in a sidecar is different in kind: it replays to the same Bitcoin block wherever it is read, so the writer can delete a proof and cannot forge one, which is why a copy of the sidecar kept off the machine is worth having ([ANCHORING.md](ANCHORING.md) §2).

## What leaves on its own

Chosen once, at `install-hook`, by the profile (ADR-0031). The hook sends at session end, and `supervisor serve` sends on the keeper's cadence, which covers a session that never reached its end ([HOOK.md](HOOK.md)).

| Profile | What leaves | Where it goes |
|---|---|---|
| `local` | nothing | nowhere; the head record is one you keep by hand (`head`, then `verify --expect-head`) |
| `timestamped` | a 32-byte digest of the chain head | the OpenTimestamps calendars, and, with `--authority URL`, a timestamp authority you named |
| `full` | the digest above, the published head, and the published chain: every entry since the last send | the digest as above; the head and the entries to the one remote you named with `--remote URL` |

At `full` the entries leave with their action lines, which are command lines, and the installer says so before it writes anything. On Codex the session-end anchor is refused, so the calendars get the digest on the keeper's cadence instead. Under `custom` the same steps are raw flags, and the head can go to any remote that passes the head-record test, a chat webhook among them (ADR-0025). By hand, `supervisor package` writes a file for you to carry off, and its `--anchor` and `--stamp` seals send the manifest's digest the same two ways ([PACKAGE.md](PACKAGE.md) §2).

## The calendars and the authority

**The OpenTimestamps calendars, then Bitcoin.** They take the digest and hand back a proof, which the recorder keeps in the anchor sidecar; `anchor --upgrade` completes it a few hours later. `verify --anchors` replays it offline, on any machine: entries `0..n` existed by block H. Two jobs stay yours: confirm the printed merkle root against a block source you trust, and judge whether that block is old enough for the history the chain claims, since a regenerated chain can only be anchored into a young one ([ANCHORING.md](ANCHORING.md)). The anchor is the head record that needs no credential.

**A timestamp authority you named.** It takes the same digest and hands back a token, kept verbatim in the stamps sidecar. `verify --stamps --authority-chain FILE` judges it through `openssl`, against the certificate chain you saved from that authority. It is somebody's signed word about when, trusted as far as that authority's honesty about its clock and its custody of its key, and it is never called an anchor ([ANCHORING.md](ANCHORING.md#6-the-authority-timestamp-which-is-not-an-anchor), ADR-0032).

## The receiver's machine

**What runs there.** `python receiver.py serve`, on a box the writer cannot reach: an old laptop, a small VPS, a second box on the same shelf. Its data directory, `~/.loxodonta/receiver` by default, holds the `token`, `heads.jsonl` with one line per published head, and one `receipts-<session>.jsonl` per published chain. The recorder judges those files on that box ([RECEIVER.md](RECEIVER.md)).

**Why it counts.** The URL is the only credential the writer's machine holds for it, and it can add and do nothing else: no route returns, lists or deletes. That is the head-record test of ADR-0025, met. The receiver never runs `verify` and serves nothing back.

**What it is worth.** This is where a verdict about regeneration is worth something, because the reference was written where the writer can only add.

- `python loxodonta.py verify --log ~/.loxodonta/receiver/receipts-<session>.jsonl` reads `VALID` when every batch continued the one before. It reads `BROKEN at entry N` when a regenerated chain arrived after entries up to `N - 1` had left: the copy holds both, in the order they came, and that collision is what the copy is for.
- A head from `heads.jsonl` is the reference for `verify --log CHAIN --expect-head HEAD`. The check compares the chain's last head, so it takes the newest head that left for that session, and a chain regenerated after that head left reads `HEAD-MISMATCH`, exit 3. The writer holds the URL too and can post a fake head, which matches no entry in the chain: visible noise, and a flag of its own (RECEIVER.md §3).

**What it does not survive.** The tail since the last send, which the writer can still rewrite consistently; the keeper's cadence bounds it and session end closes it. The receiver's own operator, who can read and delete its files. The box reached another way, by an SSH key, a shared filesystem or a browser login on the writer's machine. And garbage in: the copy is of what the writer said ([RECEIVER.md](RECEIVER.md) §8).

## The recipient of a package

**What runs there.** `loxodonta verify-package PATH [--authority-chain FILE]`, the same one file that verifies a bare chain, downloaded and checked against `SHA256SUMS` on a machine that was never the agent's ([PACKAGE.md](PACKAGE.md) §5).

**What it holds.** One package: a session's or a drawer's chains with their sidecars, the project record, a witness snapshot labelled testimony, a README, the harness transcript only on request, and the manifest written last, with whatever seals the operator applied. `supervisor package` built it on the agent's machine, from the store there, and the operator carried it off.

**What it is worth.** It is judged layer by layer, the recorder's own verdicts verbatim and the package verdict last. `SELF-CONSISTENT` says the package is unaltered since it was packed. A session regenerated and packed afresh reads the same; what separates the two is a completed manifest anchor, whose block height the recipient reads against the history the package claims. A signature says which key packed it and an authority timestamp says when, on that authority's word. None of them says the record inside is true or complete. Three jobs stay the recipient's: the merkle root against a block source, the key fingerprint against one the issuer published, and the authority's certificate chain, saved from the authority and never taken from the package.

## What does not exist

Said plainly, so nothing above reads as more:

- **Nothing gathers several machines into one reading.** Each agent's machine runs its own supervisor over its own store. The receiver keeps what it is sent and serves nothing back, `verify-package` judges the one package it is handed, and `/metrics` answers a scrape on its own machine and pushes nothing. No supervisor pulls chains or packages from many machines.
- **`verify --ledger` is not built** (#174). Nothing walks `heads.jsonl` and checks every head at its `n`; a published head is checked by hand, one at a time, with `verify --expect-head`.
- **The sidecars and the baseline do not travel to the receiver.** The published chain is chain lines and nothing else. The anchor and stamps sidecars, the memo and the baseline stay on the agent's machine unless you copy them off yourself; a package carries the two sidecars and none of the rest.
