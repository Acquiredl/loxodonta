# The topology: where each piece runs, and what its evidence is worth

Three files, the machine the agent works on, and the places beyond it that the record can reach. What a verdict is worth depends on what it was checked against. A chain checked against its own hashes shows an edit anywhere in it, and a deletion or a reorder anywhere before its last entry. A chain cut short at its tail, rewritten consistently from some entry on, or regenerated whole still walks clean, and shows only against something that remembers it as it was: something the writer can rewrite gives a reason to look, and something the writer cannot reach is where it shows. This page draws the places once, with what runs in each, what each holds, and what its evidence is worth. The page that owns each piece is linked from it.

```
 THE AGENT'S MACHINE                     |  ELSEWHERE
 all of it within the writer's reach     |  off the machine
                                         |
 harness --hook--> loxodonta.py          |
                        |                |
                        v                |
 the store: chains, sidecars, memo;      |
   beside it, the coverage marker        |
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
   head and entries -------------------->|  THE REMOTE YOU NAMED
   (serve: every chain in the store,     |  receiver.py, or any URL that
   from its first entry)                 |  appends and refuses delete
                                         |
 what leaves by hand                     |
   a package --------------------------->|  THE RECIPIENT
                                         |  loxodonta verify-package
   export --send, field data ----------->|  a secret gist under your gh
                                         |  login, and an issue on this repo
```

The line down the middle is the one that matters. Everything left of it is the writer's to reach, whatever the file (ADR-0002). Everything right of it is off the machine, and all of it but the field-data gist and issue is somewhere the writer can at most add to, as long as the remote you named for `full` refuses delete.

## The agent's machine

**What runs there.** The harness, and the hook it fires after each tool call that completes or fails (#239, ADR-0034), which runs `loxodonta.py` to append one receipt to the session's chain in the store, `~/.loxodonta/receipts/<project>-<hash>/` ([HOOK.md](HOOK.md)). Beside it, `supervisor.py`: `scan`; `serve`, with the dashboard and `/metrics` bound to `127.0.0.1` ([METRICS.md](METRICS.md)); recall and its read-only MCP server ([MCP.md](MCP.md)); the keeper's anchor and publish cadences; and `package`.

**What it holds.** The chains; beside each chain its anchor sidecar, its stamps sidecar and the publish memo; beside the store, the supervisor's baseline and day book, and the coverage marker that records the profile.

**What it is worth.** `verify` here catches an edit anywhere in a chain, and a deletion or a reorder anywhere before its last entry, because the chain's own hashes break. What nothing here can settle is a chain cut short at its tail, rewritten consistently from some entry on, or regenerated from scratch, since each of those still walks clean: the baseline may shout that a head it saw is gone or that a chain is shorter than it was, but every file that would remember the old head, the baseline included, is one the writer can rewrite or delete as well. The baseline, the day book, the memo and the marker are testimony, trusted for nothing, and a wiped store takes its chains with it, all but what already left. So the scan, the dashboard and every gauge on `/metrics` stay on this machine and say so: fast detection, a reason to shout, never proof. A gauge scraped to another box is still this machine's reading. An anchor proof in a sidecar is different in kind: it replays to the same Bitcoin block wherever it is read, so the writer can delete a proof and cannot forge one, which is why a copy of the sidecar kept off the machine is worth having ([ANCHORING.md](ANCHORING.md) §2).

## What leaves on its own

Chosen once, at `install-hook`, by the profile (ADR-0031), though a cadence flag typed at `serve` or `scan` overrides it at any profile: `serve --anchor-every 1h` sends digests even at `local`. The hook sends at session end. `supervisor serve`, with a cadence in force, is the keeper: it takes a fresh reading of the store a minute after the last one finished, with nobody watching the page (#271), and sends a chain's head, or its entries, only once that chain's last entry is older than the cadence, six hours at `timestamped` and `full`. So it covers a session killed before its end, and a session whose entries keep arriving inside the cadence sends nothing until it ends. Its own turns stay out of the day book, which answers whether anybody looked, unless a turn catches something read-once ([HOOK.md](HOOK.md), ADR-0014).

| Profile | What leaves | Where it goes |
|---|---|---|
| `local` | nothing | nowhere; the head record is one you keep by hand (`head`, then `verify --expect-head`) |
| `timestamped` | a 32-byte digest of the chain head | the OpenTimestamps calendars, and, with `--authority URL`, a timestamp authority you named |
| `full` | the digest above, the published head, and the published chain: every entry since the last send, and, from the keeper, every chain already in the store from its first entry, sessions recorded before you chose `full` included | the digest as above; the head and the entries to the one remote you named with `--remote URL`: `receiver.py`, or any URL that appends and refuses delete |

At `full` the entries leave with their action lines, which are command lines, and the installer says so, the chains already in the store included, before it writes anything. On Codex the session-end anchor is refused, so the calendars get the digest on the keeper's cadence instead. Under `custom` the same steps are raw flags, and the head can go to any remote that passes the head-record test, a chat webhook among them (ADR-0025). By hand, `supervisor package` writes a file for you to carry off, and its `--anchor` and `--stamp` seals send the manifest's digest the same two ways ([PACKAGE.md](PACKAGE.md) §2). `supervisor export --send` is the field-data path, not evidence: it uploads the export as a secret gist under your own `gh` login, which the token on this machine can delete, and opens an issue on this repo, and only `--raw`, which shows a sample line and asks first, adds the chains and their anchor sidecars ([START.md](START.md) step 5, [FIELD-DATA.md](FIELD-DATA.md)).

## The calendars and the authority

**The OpenTimestamps calendars, then Bitcoin.** They take the digest and hand back a proof, which the recorder keeps in the anchor sidecar; `anchor --upgrade` completes it a few hours later. `verify --anchors` replays it offline, on any machine: entries `0..n` existed by block H. Two jobs stay yours: confirm the printed merkle root against a block source you trust, and judge whether that block is old enough for the history the chain claims, since a regenerated chain can only be anchored into a young one ([ANCHORING.md](ANCHORING.md)). The anchor is the head record that needs no credential.

**A timestamp authority you named.** It takes the same digest and hands back a token, kept verbatim in the stamps sidecar. `verify --stamps --authority-chain FILE` judges it through `openssl`, against the certificate chain you saved from that authority. It is somebody's signed word about when, trusted as far as that authority's honesty about its clock and its custody of its key, and it is never called an anchor ([ANCHORING.md](ANCHORING.md#6-the-authority-timestamp-which-is-not-an-anchor), ADR-0032).

## The receiver's machine

**What runs there.** `python receiver.py serve`, on a box the writer cannot reach: an old laptop, a small VPS, a second box on the same shelf. Its data directory, `~/.loxodonta/receiver` by default, holds the `token`, `heads.jsonl` with one line per published head, and one `receipts-<session>.jsonl` per published chain. The recorder judges those files on that box ([RECEIVER.md](RECEIVER.md)).

**Why it counts.** The URL is the only credential the writer's machine holds for it, and it can add and do nothing else: no route returns, lists or deletes. That is the head-record test of ADR-0025, met. The receiver never runs `verify` and serves nothing back.

**What it is worth.** This is where a verdict about regeneration is worth something, because the reference was written where the writer can only add.

- `python loxodonta.py verify --log ~/.loxodonta/receiver/receipts-<session>.jsonl` reads `VALID` when every batch continued the one before. It reads `BROKEN at entry N` when a batch arrived carrying an `n` the file already held with a different hash: two versions of the chain reached the receiver, the copy holds both in the order they came, and that collision is what the copy is for. The order says which arrived first, not which is the original, since the writer holds the URL too; the heads checked at their `n`, below, tell which one was regenerated.
- Every head published for a session must be an entry hash inside its chain, at its `n` (ADR-0025 ruling 4). `verify --expect-head` compares a chain's last entry only, so by hand that is one run per head in `heads.jsonl`: cut the chain you are judging to its first `n + 1` lines, then run `verify --log` on the cut with `--expect-head HEAD`, where `HEAD-MISMATCH`, exit 3, says the chain is not the one whose head left. Checking the newest head alone is not enough: a head posted after a regeneration, by the writer, who holds the URL too, or by the keeper's next turn, matches the regenerated chain. Two different heads at one `n`, or an `n` that goes down, is the sign of regeneration by itself, except where one session left more than one chain: a sibling chain, whose heads carry the same session id and count again from 0, or, in a store from before ADR-0023, a session split across two drawers, whose two chains share one file name and so one receiver file, which then reads `BROKEN` too. `heads.jsonl` does not say which chain a head came from, so for such a session try each chain before reading `HEAD-MISMATCH` as regeneration.

**What it does not survive.** The tail since the last send, which the writer can still rewrite consistently. Session end closes it; before that, the keeper sends nothing until the head has sat unchanged past its cadence, which covers a session killed before its end and leaves a busy session's tail unsent until the session ends. The receiver's own operator, who can read and delete its files. The box reached another way, by an SSH key, a shared filesystem or a browser login on the writer's machine. And garbage in: the copy is of what the writer said ([RECEIVER.md](RECEIVER.md) §8).

## The recipient of a package

**What runs there.** `loxodonta verify-package PATH [--authority-chain FILE]` ([PACKAGE.md](PACKAGE.md) §5), the same one file that verifies a bare chain, downloaded and checked against `SHA256SUMS` ([README](../README.md#install)) on a machine that was never the agent's.

**What it holds.** One package: a session's or a drawer's chains with their sidecars, the project record, a witness snapshot labelled testimony, a README, the harness transcript only on request, and the manifest written last, with whatever seals the operator applied. `supervisor package` built it on the agent's machine, from the store there, and the operator carried it off.

**What it is worth.** It is judged layer by layer, the recorder's own verdicts verbatim and the package verdict last. `SELF-CONSISTENT` says the package is unaltered since it was packed. A session regenerated and packed afresh reads the same line. What separates the two is an anchor. Each chain's own, printed under it as detail, names the block its attestation claims, and with that block's header (`--block-header`) says the chain's head existed by it: a regenerated chain carries none or only young ones, and packed beside the original's proof it reads `ANCHOR-MISMATCH`. The manifest's anchor, once complete, dates the packing and nothing earlier. A signature says which key packed it and an authority timestamp says when, on that authority's word. None of them says the record inside is true or complete. Three jobs stay the recipient's: the merkle root against a block source, the key fingerprint against one the issuer published, and the authority's certificate chain, saved from the authority and never taken from the package.

## What does not exist

Said plainly, so nothing above reads as more:

- **Nothing gathers several machines into one reading.** Each agent's machine runs its own supervisor over its own store. The receiver keeps what it is sent and serves nothing back, `verify-package` judges the one package it is handed, and `/metrics` answers a scrape on its own machine and pushes nothing. No supervisor pulls chains or packages from many machines.
- **`verify --ledger` is not built** (#174). It would check every head in a saved copy of `heads.jsonl` at its `n` in one step; today that is the by-hand run above, one cut and one `verify --expect-head` per head.
- **The sidecars and the baseline do not travel to the receiver.** The published chain is chain lines and nothing else. The anchor and stamps sidecars, the memo and the baseline stay on the agent's machine unless you copy them off yourself; a package carries the two sidecars and none of the rest.
