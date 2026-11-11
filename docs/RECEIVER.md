# The receiver: the far end of the published chain

**Status:** accepted 2026-09-16 (ADR-0031 rulings 4 and 5). This page is how to run `receiver.py` and the wire contract between it and the recorder: the path, the verbs, the content types, the header names, the status codes. The receipt format of `docs/SPEC.md` (v0.1) is untouched: a chain file the receiver keeps is a chain, judged by the same walk.

## 1. What the receiver is

The repo's third single file. The recorder sends a chain's entries off the machine that wrote them (GLOSSARY *Published chain*) and its head (GLOSSARY *Published head*); the receiver is the machine they go to, run by the operator somewhere the writer cannot reach: an old laptop, a small VPS, a second box on the same shelf. It mints one URL when it starts, appends what arrives at that URL to its own disk, a chain's lines only when each is an entry, and refuses everything else. There is no route that returns, lists or deletes anything. That is what makes the URL pass the head-record test (GLOSSARY *Head record*, restated in section 9): a credential that can add and cannot take away.

What it holds is the operator's copy of what the writer said, at an address of the operator's choosing. The entries survive a wipe of the writer's machine as of the last send, and a regenerated chain lands beside the entries it replaced rather than over them, where the recorder's own `verify` shows the collision (section 6). The receiver is bound by the other two files' constraints: stdlib only, readable in one sitting, Python 3.9 and up, tested on Windows, macOS and Linux (ADR-0005's *single file per tool*).

What it is not. It is not a reader: it never runs `verify`, never serves a file back, and knows no vendor; anything that turns its files into somebody's storage grows on its side of the wire, never the recorder's (ADR-0031 ruling 5). It is not `tools/publish_echo.py`: the echo listens on the loopback address of the writer's own machine, prints what a published head holds, and keeps nothing, so nothing there has left the machine. The receiver is the remote the echo tells you to go and find.

Where the receiver sits beside the other two files, and what the evidence on each machine is worth, is drawn on one page in [TOPOLOGY.md](TOPOLOGY.md).

## 2. Running it

On the machine that will keep the copy:

```
python receiver.py serve
```

It prints where it keeps its files, where it listens and in what, and the URL:

```
receiver 0.11.0 keeping /home/op/.loxodonta/receiver, at most 1024 MiB a file and 10240 MiB in all
listening on 0.0.0.0:8790 (all interfaces), speaking plain HTTP (give --cert and --key for TLS)
publish to http://shelf:8790/7qpsWUkU86ML-NOuaGjSaetfYCGgGffLyTRvOJFMYPo
  (shelf is this machine's name; use the address the sending machine reaches this one by)
the URL is the credential: it can add and cannot read, list or delete; --new-token retires it
```

It binds all interfaces by default, because its whole point is another machine; `--bind 127.0.0.1` narrows it to one address, for a receiver behind a reverse proxy or a tunnel. Every later start prints the same URL, so a restart never forces a rewire. Run it under whatever keeps a process up on that box (systemd, launchd, a scheduled task). It is one process that gives each request a thread of its own, so a slow sender holds only its own connection. The writes still take turns: one append at a time, each ending in an fsync, so two batches for one chain never interleave.

Each request is due whole, headers and body, within sixty seconds of its connection opening, and a sender that goes quiet for thirty seconds is dropped sooner. That deadline carries a full 8 MiB batch at a little over one megabit a second. A sender that trickles its bytes to keep a connection open gets no longer than one that sends them all at once.

| Flag | What it does |
|---|---|
| `--data DIR` | where the token and the files live (default `~/.loxodonta/receiver`, or `$LOXODONTA_HOME/receiver`) |
| `--bind ADDRESS` | the address to listen on (default all interfaces) |
| `--port N` | the port (default 8790; `0` takes a free one and prints it) |
| `--cert FILE --key FILE` | speak TLS from this PEM pair (section 5) |
| `--new-token` | mint a new token; the old URL answers 404 from now on (section 3) |
| `--file-cap MIB` | the most any one file in the data directory may hold (default 1024 MiB); past it a request is refused with `507` (section 4, *The caps*) |
| `--total-cap MIB` | the most the data directory may hold in all (default 10240 MiB); past it a request is refused with `507` |
| `--version` | tool version, format version, and the checkout's commit, in step with the recorder and the supervisor |

What it keeps, in the data directory:

- `token`: the secret half of the URL, readable by this user alone where the filesystem has the notion.
- `heads.jsonl`: one line per published head, in the order received.
- `receipts-<session>.jsonl`, and `receipts-<session>-002.jsonl` for a sibling chain (GLOSSARY *sibling chain*): one file per chain, named by the sender under the rule in section 4, holding chain bytes from genesis on.
- `receipts-<session>.jsonl.anchors.jsonl` and `receipts-<session>.jsonl.stamps.jsonl`: the anchor proofs and the authority tokens of that chain, as the sender's sidecars hold them, without their attempt rows (section 4, *A chain's proofs*).
- `events-<YYYY-MM-DD>.jsonl`: one line per request of the harness's events (section 4, *The second door*), one file per UTC day of arrival, with every identity attribute removed.

## 3. The URL is the credential

Whoever holds the URL can add to the receiver's files, and only add. Paste it into the recorder on the writer's machine as the remote; the recorder's `publish --log LOG URL` sends a head to it by hand, `install-hook --publish-head URL` sends one at every session end, and the published chain goes to the same URL: `publish --chain --log LOG URL` by hand, `install-hook --profile custom --publish-chain URL` at every session end, told apart from a head by content type. One URL serves both, which is what `--profile full --remote URL` wires in one word (ADR-0031 ruling 1): paste this URL there and the head, the entries and the keeper's cadence all point at this receiver.

The URL sits on the writer's machine, in the wired hook command, where the agent can read it. What that buys the agent is the right to post fakes. At the first door they are visible noise (a fake head matches no entry in the chain; a fake batch collides with the honest copy at the same `n`, section 6). At the second door they are not: the reading over the folder cannot tell an event the agent posted from one the harness sent (section 7). It also buys the right to stop posting by killing the hook, which the supervisor's completeness alarm watches. It buys no deletion, or the URL was never a head record.

`--new-token` retires a URL that leaked: the receiver prints a new one and the old path answers 404 from the next start on. Rewire the sender with the new URL; the files on disk are untouched. The receiver's answer says what it holds whatever the URL, so a send to the new one goes on from there (section 4, *where it resumes*), and each file is unchanged.

## 4. The wire contract

The sender side of this contract is the recorder. Any other sender, and any other receiver, speaks it exactly.

**Two doors.** `POST` at `/<token>` takes a published head or a batch of a published chain; `POST` at `/<token>/v1/logs` takes the harness's events (*The second door*, below). Every other verb at either path is `405` with `Allow: POST`; every other path is `404`, whatever the verb. There is no verb and no path that returns, lists or deletes what the receiver holds.

**Three content types, three destinations.**

- `Content-Type: application/json` is a published head: one JSON object, the body ADR-0025 ruling 2 describes (`head`, `n`, `session`, `ts`, `event`, `text`, `content`). It is appended to `heads.jsonl` as one line, compact and key-sorted, whatever whitespace the sender used.
- `Content-Type: application/x-ndjson` is a batch of a published chain: lines of the chain as they sit in the chain file, each ended with `\n`, the entries the sender has in hand and then those the receiver's answer asks for (*The sender's side*, below). It is appended to the file the chain header names.
- `Content-Type: application/x-loxodonta-sidecar` is a chain's proofs (ADR-0045 ruling 5): the rows of its anchors or its stamps sidecar, as they sit there. It is kept beside the file the chain header names (*A chain's proofs*, below).

**The headers on a chain batch.**

| Header | Holds | Read by the receiver |
|---|---|---|
| `X-Loxodonta-Chain` | the chain's file name: `receipts-<session>.jsonl`, or `receipts-<session>-002.jsonl` for a sibling | yes, required: it names the file |
| `X-Loxodonta-Session` | the session id | no |
| `X-Loxodonta-Range` | the `n` of the batch's first and last entry, `first-last` | no |
| `X-Loxodonta-Head` | the chain head after the batch's last entry | no |

The receiver reads the chain header and nothing else; the other three ride along for an operator reading traffic at a proxy, and for any receiver built to this contract that wants them. This one stores the chain bytes of a batch and nothing besides.

**The chain header must be a receipt file name.** `receipts-`, then a session id of letters, digits, hyphens and underscores (the sibling suffix is made of the same), then `.jsonl`, at most 200 characters between the two. Anything else is refused with `400` and nothing is written: a separator (`/` or `\`), a parent reference (`..`), a dot inside the id, another extension, `.JSONL`, an empty header, a missing one. Nothing in a header ever becomes a path.

**The body.** `Content-Length` is required; a body declared past the cap of 8 MiB (8,388,608 bytes) is refused with `413` before a byte of it is read. A line ends at `\n` and nowhere else, a `\r` just before it being part of the ending, by the rule every reader of a chain keeps (docs/SPEC.md section 1). A chain batch must hold at least one line, and every line must be an entry (ADR-0045 ruling 1): one JSON object a strict parser takes, each key given once and no `NaN`, `Infinity` or `1e999`, holding the fields of docs/SPEC.md section 2 of their types, `v` on the genesis and only there, an `n` of 0 or more, a `prev` that is null on the genesis and only there, and an `entry_hash` that recomputes from the line by section 4. A batch with any other line is refused whole with `400`, naming the line's place in the batch and why, nothing written, because a file that is a receipt log holds entries and nothing else. The receiver carries its own copy of that rule, as the recorder does (docs/TWINS.md). It judges nothing further about how the lines it keeps relate to one another, beyond the hole below: judging is `verify`'s job.

**The append rule** that keeps each chain file a receipt log (ADR-0031 ruling 4, ADR-0045 ruling 2):

0. A batch holding an entry whose `n` is more than one past the highest `n` the file would hold once the entries before it were in, past 0 for a file that holds none, would leave a hole the file could never verify across. It is refused whole with `409` and the answer below, and nothing is written.
1. A line whose `n` and `entry_hash` the file already holds is an exact duplicate, the sender's retry after a lost acknowledgement, and is dropped.
2. A line whose `n` the file holds with a different `entry_hash` is a regenerated chain arriving after the original, or an entry the URL's holder made, and is appended: that collision is what the copy exists to show.
3. Every other line is appended in the order received.

**The caps.** Whoever holds the URL could otherwise post shape-valid batches until the disk is full and every honest send fails with it. So the receiver caps what it keeps: each file in its data directory at 1024 MiB, and the directory as a whole at 10240 MiB, unless `--file-cap` and `--total-cap` say otherwise. The sizes are the files as they are on disk, read at each request. Once the append rule has dropped the duplicates, a request whose remaining lines would take a file past its cap, or the directory past its own, is refused whole with `507` and one line naming the cap. Nothing is written, and nothing already kept is trimmed or rewritten to make room: the receiver only adds. A resend of lines the file already holds adds nothing, so it is never refused, and the sender's retry still gets its `2xx`. The status is `507 Insufficient Storage` rather than `413`, because the request is well formed and inside the body cap; it is this receiver's storage that has no room for it. `413` stays the one answer for a body too large to take at all, so the sender's failure line tells the two apart. Nothing of a refused request is held, so once the operator raises a cap or moves files off the box, the next send carries the same lines again.

**The answer.** `200` with a small JSON body, `{"appended": 3, "dropped": 0, "held_n": 12, "connects": true}` for a chain batch and `{"appended": 1}` for a head, sent only after the bytes are on disk, flushed and fsynced. Any `2xx` means on disk; the recorder writes a chain row in its memo on a `2xx` that appended something, and on nothing else. `held_n` is the highest `n` the file holds once the batch is in, `null` when it holds none, and `connects` says whether the batch's first entry connects: it is the genesis, or its `prev` is the `entry_hash` of an entry the file holds at the `n` before it that itself connects, so every entry between it and its genesis is held (ADR-0045 ruling 2). The highest `n` and not the last line, so a line of a lower `n` appended after it, a regenerated entry or one posted by whoever holds the URL, does not send an honest chain back over what it already sent. A `409` carries the same two keys, and `refused`, the one line saying why. Nothing else is said, and only to a POST about the chain it named: there is still no request for what the receiver holds (ADR-0045 ruling 6).

**What an answer costs the receiver.** While it runs, the receiver remembers of each chain file it has touched every entry it holds, by its hash and its `n`, which of them connect, and the file's size once it last read or wrote it. Every batch is judged from that memory: a duplicate, a hole, whether the first entry connects. An entry that arrives and connects makes each held entry above it whose `prev` names it connect in turn, up to the next gap, each entry once. A batch then costs the reading of its own lines, a hash of each, a look at the file's size and its last byte, the sizes of the folder's files for the caps, and the append with its fsync, never a read of the file. A chain not touched since the receiver started, and a file whose size is not the one remembered, are read and remembered again. The receiver is the only writer of its files. The memory costs about 130 bytes an entry that connects and 320 one that does not, and holds 500,000 entries at most across all chains, some 65 MB: past that, the chains touched longest ago are forgotten, and read again on their next touch.

**A chain's proofs.** `POST` at `/<token>` with `Content-Type: application/x-loxodonta-sidecar`, the chain header, and `X-Loxodonta-Sidecar: anchors` or `stamps`, carries the rows of that chain's anchors or stamps sidecar, one per line, as they sit there (ADR-0045 ruling 5). Each line must be one JSON object a strict parser takes, no key given twice and no `NaN`, `Infinity` or `1e999`, as the recorder reads a sidecar (docs/SPEC.md section 9.1), whose `kind` is `anchor` for `anchors`, `stamp` for `stamps`, or absent; a batch holding any other line, an attempt row among them, is refused whole with `400`, and so is any other value of that header. The rows are appended to `<chain file>.anchors.jsonl` or `<chain file>.stamps.jsonl`, beside the chain file the header names, so `loxodonta verify --log <chain file> --anchors` and `--stamps` read them there as they read the sender's. A row the file already holds byte for byte is dropped, since the sender sends every row each time, and nothing beside its chain is trusted to say which already left. The lock, the caps and the fsync are a batch's, and the answer is `200` with `{"appended": 1, "dropped": 2}`.

**The second door.** `POST` at `/<token>/v1/logs` with `Content-Type: application/json` is the harness's events (GLOSSARY *Harness events*; ADR-0041 rulings 2 and 3): `/v1/logs` is the path an OpenTelemetry exporter appends to the base address it is given, so the receiver's URL is the whole of what the sending machine holds. The body is one JSON object carrying no number JSON cannot (`NaN`, `Infinity`), or `400`; the receiver reads nothing else of it, and `Content-Length`, the body cap, the deadline and the idle timeout are as at the first door. Before the line is kept, every attribute whose key begins `user.` or `organization.`, matched exactly and case included, is removed from every `attributes` list and from the `values` of every `kvlistValue` at every level of the object, whoever the sender is, and the rest is kept whole. Each request becomes one line in `events-<YYYY-MM-DD>.jsonl`, named by the UTC day of arrival: a JSON object, compact and key-sorted, holding `received` (the arrival time, UTC, the receiver's clock), `from` (the client address) and `logs` (the posted object after the identity rule). The append lock, the fsync before the answer and the caps are the chain files'. The answer is `200` with the body `{}`, once the line is on disk. A body is taken as it is, at either door: a `Content-Encoding` other than `identity` is `415`.

| Status | When |
|---|---|
| `200` | appended (or every line was an exact duplicate: `appended` is `0`); at the second door, the line is on disk |
| `400` | the chain header is not a receipt file name or is missing; a line is not an entry; for a chain's proofs, the sidecar header is neither `anchors` nor `stamps`, or a line is not a row of its kind; the body ended early; `Content-Length` is not a length; at the second door, the body is not one JSON object; at either door, a body nested past what the reader takes, or a number JSON cannot carry (`NaN`, `Infinity`) |
| `404` | not the token's path, nor its events path |
| `405` | a verb other than `POST` at either door (`Allow: POST`) |
| `409` | a chain batch holding an entry more than one past the highest held, or past 0 when the file holds none; nothing is written, and the JSON body says what is held |
| `411` | no `Content-Length` |
| `413` | `Content-Length` past the cap |
| `415` | a content type that is none of the three, or at the second door not `application/json`; a `Content-Encoding` other than `identity` |
| `500` | the disk refused the write; nothing of the batch is acknowledged, and the sender's memo does not advance |
| `501` | a verb the stdlib server does not know at all |
| `507` | the lines would take a file past `--file-cap` or the data directory past `--total-cap`; nothing is written |

A refusal carries one line of plain text saying why, a `409` the JSON body above. The receiver's own log, on its stdout, is one line per request with the time, the client address, the verb and the status; the request path is on no line, because the path is the credential. For events that landed, the line says how many identity attributes were dropped.

**The sender's side.** The recorder speaks this contract from `publish --chain --log LOG URL`, from a wired recording hook, which sends each entry as it is written, and from a wired session end (`install-hook --profile full --remote URL`, or `--profile custom --publish-chain URL` for the chain alone, docs/HOOK.md); `supervisor scan|serve --publish-every AGE --publish-chain URL` sends by running that same command, so there is one sender and not three.

- **Where it resumes.** From the receiver's answer, and from nothing beside the chain (ADR-0045 rulings 3 and 4). A recording hook posts the lines it has just appended, from memory, reading neither the chain nor the memo; the session end, the keeper and `publish --chain` post the chain's last entry, read from the end of the file. Each goes on from the answer: kept, and the first entry connects, the send is done; a `409`, and the entries after the highest `n` held go, in order, as far as the entries the send began with; kept, and the first entry does not connect, an entry below it is missing. Among the chain's own entries those that connect are a prefix, so the last that does is found by posting one entry at a time, halving the stretch between the highest known to connect, or the start, and the lowest known not to, a dozen posts on a chain of thousands, and the entries after it go in batches. An entry posted in the search is kept, or dropped as one already held. A step whose time runs out ends there, and the next call, session end or keeper turn is told again that its entry does not connect and takes the search up again, with every entry an earlier step sent still held. A line of the chain that is not the entry its place holds ends the send, and the attempt row names the line. So a new remote receives each chain from its genesis and its file verifies (section 6), whatever an earlier remote already holds, and a remote sent to before resumes where it stopped, whatever the memo beside the chain says. That memo, `<log>.published.jsonl`, holds one row of kind `chain` per batch the session end, the keeper or `publish --chain` saw acknowledged and appended to, `first`, `last`, the head after `last`, the time, the event, and `remote_id`, a fingerprint of the remote that took it: the first 16 hex characters of the SHA-256 of the URL, never the URL, which is the credential (section 3). For this receiver the rows are a note of what left and when, and decide nothing. A remote that answers a `2xx` and says nothing of what it holds is followed from them as before ADR-0045: the send starts at the entry after the largest `last` among the rows naming its URL, or at genesis when there are none (#263); a row written by a recorder from before the fingerprint names no remote and counts for none; a chain row is appended on a `2xx` and on nothing else, so the cursor never passes an entry the remote did not acknowledge; and an attempt row says once, when it first is so, that the remote does not say what it holds.
- **How it batches.** Lines go in the order they sit on disk while the body stays under the 8 MiB cap; a longer tail goes in several batches, each its own POST, each acknowledged and written down before the next begins. The cap bounds how many entries share a batch, never whether one goes: an entry whose own line is past it goes alone. To a remote that does not say what it holds, such an entry is refused by the sender before it is sent, named by its `n` in the failure line and in the attempt row, since the cursor cannot pass what never landed.
- **What it never sends.** A line that is not an entry by the receiver's rule, which the recorder carries too: a torn tail, damage. A batch holding one is refused whole, so a send stops before it and the attempt row names it, and a chain damaged on disk arrives only as far as it is whole. The torn line stays on the writer's machine, as the damage `verify` reports.
- **What it spends.** A recording hook's send, after each receipt, runs under one second in all, name lookup included, and the hook exits as it would have whatever came of it; what did not go is the next call's, the session end's or the keeper's (ADR-0045 ruling 3). At session end the whole send runs under the head publish's budget, three seconds on Claude Code: each batch waits at most that long, name lookup included, and no batch begins once the budget is spent. Whatever did not fit is the next session end's or the keeper's, from what the receiver then says it holds. The recording call and the session end ask the receiver every time; the keeper, inside its cadence's ripeness test, sends a chain written to since its last turn on it, one whose memo does not show the end held, and one whose last send failed. On Codex, whose whole SessionEnd hook is capped at three seconds, the send gets what the head left of the session end's shared 1.5-second window, sends the batches that fit and leaves the rest to the keeper (docs/HOOK.md, *Codex CLI*).
- **When it fails.** By hand, the command says why on stderr — never the URL — and exits 69 (`EX_UNAVAILABLE`, ADR-0037). At session end it says nothing and appends one `attempt` row to the memo instead, step `publish-chain`, carrying the budget and what the socket said; no chain row is written, so the next send carries the same lines again. A recording hook's send writes the same row with `event` `receipt`, and only when its outcome differs from what the memo's last row says, read from the end of the file, so a receiver that is down leaves one row and not one a call, and its return leaves one more; a last row that cannot be read gets the row. A step that ends with entries still missing says so, and is never `sent`. `publish --chain` writes its row every time, `sent` or why not, as the session end does, and every row of the chain's send names its remote by the chain row's fingerprint, which is how the keeper knows the end left when nothing was appended.

By hand, with `curl`, sending a whole chain from the writer's machine:

```
curl -X POST https://shelf.example.net:8790/<token> \
  -H 'Content-Type: application/x-ndjson' \
  -H 'X-Loxodonta-Chain: receipts-<session>.jsonl' \
  --data-binary @receipts-<session>.jsonl
```

## 5. TLS

Wherever the chain is published — `--publish-chain`, and the `full` tier that folds it under one word — every entry crosses the network: the timestamp, the actor, the action line, the file references. Action lines are command lines and can carry anything the agent typed. Without `--cert` and `--key` they cross in the clear, and the startup line says so in as many words: *speaking plain HTTP*. That is acceptable on a wire the operator owns end to end (a LAN, an SSH tunnel, a VPN) and nowhere else.

`--cert FILE --key FILE` takes a PEM certificate and its PEM private key and speaks TLS through the stdlib's `ssl` module; the startup line then says *speaking TLS from FILE* and the URL begins with `https`. The receiver mints no certificate. A pair from a CA the sending machine already trusts is the simplest; a self-signed pair works when the sending machine is told to trust it, since the recorder checks certificates the way Python's `urllib` does and refuses one it cannot verify. To mint a self-signed pair with `openssl`:

```
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj "/CN=shelf.example.net" -days 365
```

Give `cert.pem` to the sending machine's trust store (or point Python at it with `SSL_CERT_FILE`), and keep `key.pem` on the receiver's box alone.

## 6. Verifying its files with the recorder

The receiver never judges. The operator on that box runs the recorder on the receiver's file, the same `verify` that judges a chain in the store, with no new code and no new verdict vocabulary:

```
python loxodonta.py verify --log ~/.loxodonta/receiver/receipts-<session>.jsonl
```

- `VALID`, exit 0: every batch that arrived continued the one before it. A retried batch left the file intact, because its lines were exact duplicates and were dropped.
- `BROKEN at entry N`, exit 1, where `N` is the first line after the copy that arrived first: a batch arrived whose entries carry an `n` the file already holds with a different hash. Two versions of the chain reached the receiver, and the copy holds both, in the order they arrived. The order says which came first, not which is the original, since the writer holds the URL too; the published heads, each checked at its own `n` (docs/TOPOLOGY.md), tell which one was regenerated. That verdict is the collision the copy exists to show, and the file is the evidence: leave it as it lies.

One older case reads the same way. A recorder before v0.2.0 could split a session across two drawers, two chains under one file name, and a receiver that takes both appends the second after the first, so the copy breaks where the second genesis begins. The bytes cannot tell that from a regeneration sent again from genesis, but the writer's store can: a split session has a chain of that name in two drawers. That copy is moved off the box's folder whole, never edited, and acknowledged gone.

A sibling chain (`receipts-<session>-002.jsonl`) verifies on its own, as siblings do. The heads file is not a chain and is not walked; a head in it is checked against a chain with `verify --log CHAIN --expect-head HEAD` (ADR-0025 ruling 4).

The walk judges the receiver's file the way it judges any chain, so what it says about the writer holds here too: the copy is of what the writer said. A harness that lied at write time is copied faithfully (ADR-0002). Every field but the hashes is testimony (GLOSSARY *Testimony*).

## 7. Reading the folder with the supervisor

The reading that counts runs here, on the box (ADR-0041 ruling 4). `supervisor scan --receiver DIR`, `serve --receiver DIR` and `acknowledge --receiver DIR` read the data directory as the universe: the chain copies directly in it are the chains, judged by the same walk as a chain in the store and remembered by the same baseline, so a collision there reads `BROKEN`, which is what the copy exists to show; `token` and `heads.jsonl` are not chains. The memory, `baseline.json` and `daybook.json` (and the dashboard's `views.json`), lives in a `supervisor` subfolder of the directory, which the caps do not count and the receiver never writes. `--receiver` with `--root` is a usage error, 64; a `DIR` that is not a folder is 66. No keeper runs over the folder: nothing is anchored, sent or appended from the far end. The on-machine supervisor, its reading, its states and its memory change nothing.

```
python supervisor.py scan --receiver ~/.loxodonta/receiver
python supervisor.py serve --receiver ~/.loxodonta/receiver
```

The events files are the second record (GLOSSARY *Second record*; section 4, *The second door*). The supervisor's events reader, the twin of its transcript reader in shape, reads every `events-*.jsonl` and takes a log record as a tool call when its `event.name` is `tool_result`: the tool is `tool_name`, the time `event.timestamp`, the session `session.id`, the place in the session's counter `event.sequence`. Every `tool_result` owes a receipt: the receiver has no coverage marker, and the vantage setup wires every tool; the report says so once. A `tool_decision` owes nothing, since a refused call has no result after it. A line the reader cannot parse is skipped and counted, never fatal, and so is a log record that names no session. Receipts are counted by tool from the chain copy as the store census counts them, the recorder's own bookkeeping entries excluded, and the two are reconciled tool by tool (ADR-0034) by the same code that reconciles the transcript on the agent's machine.

A session is judged once it has settled: nothing of it has arrived for the settle window, no event by `received` and no chain growth by the chain file's own modification time. Receipts reach the receiver as they are written, those whose send failed at session end, and a killed session's last ones only when the keeper on the agent's machine sends it on its cadence, so the window is `SUPERVISOR_SETTLE_SECONDS`, 7 hours by default (the keeper's six plus one; 1 hour is tight, 24 hours is generous). Until then the session is listed as `PENDING` with its counts and never alarmed. Any event of the session moves that clock, so events posted through the URL keep a session `PENDING` for as long as they keep arriving. Settled, it reads as one of:

- `ENDED-DEFICIT`: events arrived and receipts fell short, tool by tool.
- `SECOND-RECORD-ABSENT`: receipts arrived and no events did. Named, never clean, and its exit is the deficit's. A run launched with the telemetry cut reads this way, and the chain's own `second-record-cut:` note (docs/HOOK.md) is quoted on the row when the copy carries one.
- `SECOND-RECORD-GAP`: integers are missing between the session's lowest and highest `event.sequence`, and the row names them. The numbers are taken from every event of the session, whatever its `event.name`, not from `tool_result` events alone. A deficit beside a gap reads as the deficit, with the gap still named.
- `ENDED-CLEAN` or `ENDED-SURPLUS` otherwise. A surplus is expected while #476 stands (the hook on 2.1.287 writes two receipts for a failed call and one for a refused call, which the events count as one and none) and is no alarm.

None of these is live, so none raises the exit: an ended deficit is evidence here as it is on the agent's machine. A session whose chain copy's newest entry predates the day of the oldest events file the receiver holds, readable or not, is from before the second record's memory: counted in one block and not listed, as `BEFORE-MEMORY` sessions are (ADR-0029); `scan --before-memory` lists them. A file that cannot be read is named in the report and counts for nothing, so a session dated after it with no events read is `SECOND-RECORD-ABSENT`, with that note beside it.

Last heard: the report carries, per sending address (`from`), the newest `received`, and per session its newest arrival; the dashboard shows the per-address table. A machine that sends nothing at all is not seen by the receiver, and that table is where its silence shows. No heartbeat (ADR-0041 ruling 5).

## 8. What it refuses

- Any verb but `POST` at the token's path or its events path: `405`.
- Any path but the token's and its events path, `/v1/metrics` under the token included: `404`, so a leaked or guessed path learns nothing, and the retired path after `--new-token` learns nothing either.
- Any content type but the three at the token's path, or but `application/json` at the events path, and any `Content-Encoding` but `identity`: `415`.
- A chain header that is not a receipt file name: `400`, nothing written, nothing from the header touching the disk.
- A chain batch holding an entry more than one past the highest `n` the file would hold, a first batch that does not start at entry 0 among them: `409`, nothing written, the answer saying what is held (ADR-0045 ruling 2).
- A chain's proofs holding a line that is not a row of its sidecar's evidence kind, an attempt row among them: `400`, nothing written.
- A body with no declared length, or declared past the cap: `411`, `413`, before a byte is read.
- A batch with a line that is not an entry, its hash recomputed here: `400`, nothing written, the line named (ADR-0045 ruling 1).
- An events body that is not one JSON object (a list, a scalar, bytes that are not UTF-8), and at either door a body nested past what the reader takes: `400`, nothing written.
- A request that has not arrived whole, headers and body, sixty seconds after its connection opened, or a sender that goes quiet for thirty seconds, mid-body or before a TLS handshake it never starts: dropped silently, with no line on the receiver's log, so a stalling stranger cannot fill it. A slow sender holds only its own connection while it lasts; every other sender is served beside it.
- Lines that would take a file past its cap, or the data directory past the total cap: `507`, nothing written, nothing already kept touched.
- Every request for what it holds: there is no such request. The files are read on the box, by the operator, with the recorder.

## 9. The head-record test, restated

A remote is a head record when it is off the machine and the credentials present on the machine cannot delete or overwrite what they wrote there (GLOSSARY *Head record*, ADR-0025). Same login is not the test; deletability is. The receiver's URL passes: it is the only credential the writer's machine holds for the receiver, it can add, and it can do nothing else.

What none of this survives (ADR-0031):

- **The receiver's own operator.** Whoever runs the receiver can read and delete its files. When that is the operator on a second machine, the property holds. When it is anyone else, that is a trust relationship this design does not cover.
- **The receiver's box, reached another way.** A receiver reachable from the writer's machine by a credential other than the URL (an SSH key on the box, a shared filesystem, a login in a browser) is reachable by the writer. The tool cannot enforce this; the operator's choice of box does.
- **The tail since the last send.** Everything after the last acknowledged entry can still be rewritten consistently on the writer's machine. At `full` each entry is sent as it is written, so with the receiver reachable that tail is about a second long; a send stopped by the network or the process keeps it open for as long as it is stopped (ADR-0045). Session end closes the window for sessions that reach one; before that, the keeper sends nothing until the head has sat unchanged past its cadence, which covers a session killed before its end.
- **Garbage in.** The copy is of what the writer said.
- **A flood from the URL's holder.** The caps keep a flood from filling the disk, and they cannot tell it from honest sends: once a flood has used a cap up, honest lines are refused with `507` beside it. What already landed stays, so the flood sits on disk, shape-valid and visible, until the operator moves it off the box.
