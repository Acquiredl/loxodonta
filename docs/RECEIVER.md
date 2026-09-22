# The receiver: the far end of the published chain

**Status:** accepted 2026-09-16 (ADR-0031 rulings 4 and 5). This page is how to run `receiver.py` and the wire contract between it and the recorder: the path, the verbs, the content types, the header names, the status codes. The receipt format of `docs/SPEC.md` (v0.1) is untouched: a chain file the receiver keeps is a chain, judged by the same walk.

## 1. What the receiver is

The repo's third single file. The recorder sends a chain's entries off the machine that wrote them (GLOSSARY *Published chain*) and its head (GLOSSARY *Published head*); the receiver is the machine they go to, run by the operator somewhere the writer cannot reach: an old laptop, a small VPS, a second box on the same shelf. It mints one URL when it starts, appends whatever arrives at that URL to its own disk, and refuses everything else. There is no route that returns, lists or deletes anything. That is what makes the URL pass the head-record test (GLOSSARY *Head record*, restated in section 8): a credential that can add and cannot take away.

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
receiver 0.8.0 keeping /home/op/.loxodonta/receiver
listening on 0.0.0.0:8790 (all interfaces), speaking plain HTTP (give --cert and --key for TLS)
publish to http://shelf:8790/7qpsWUkU86ML-NOuaGjSaetfYCGgGffLyTRvOJFMYPo
  (shelf is this machine's name; use the address the sending machine reaches this one by)
the URL is the credential: it can add and cannot read, list or delete; --new-token retires it
```

It binds all interfaces by default, because its whole point is another machine; `--bind 127.0.0.1` narrows it to one address, for a receiver behind a reverse proxy or a tunnel. Every later start prints the same URL, so a restart never forces a rewire. Run it under whatever keeps a process up on that box (systemd, launchd, a scheduled task); it is one process and one thread, taking one request at a time, and each request ends in an fsync.

| Flag | What it does |
|---|---|
| `--data DIR` | where the token and the files live (default `~/.loxodonta/receiver`, or `$LOXODONTA_HOME/receiver`) |
| `--bind ADDRESS` | the address to listen on (default all interfaces) |
| `--port N` | the port (default 8790; `0` takes a free one and prints it) |
| `--cert FILE --key FILE` | speak TLS from this PEM pair (section 5) |
| `--new-token` | mint a new token; the old URL answers 404 from now on (section 3) |
| `--version` | tool version, format version, and the checkout's commit, in step with the recorder and the supervisor |

What it keeps, in the data directory:

- `token`: the secret half of the URL, readable by this user alone where the filesystem has the notion.
- `heads.jsonl`: one line per published head, in the order received.
- `receipts-<session>.jsonl`, and `receipts-<session>-002.jsonl` for a sibling chain (GLOSSARY *sibling chain*): one file per chain, named by the sender under the rule in section 4, holding chain bytes from genesis on.

## 3. The URL is the credential

Whoever holds the URL can add to the receiver's files, and only add. Paste it into the recorder on the writer's machine as the remote; the recorder's `publish --log LOG URL` sends a head to it by hand, `install-hook --publish-head URL` sends one at every session end, and the published chain goes to the same URL: `publish --chain --log LOG URL` by hand, `install-hook --profile custom --publish-chain URL` at every session end, told apart from a head by content type. One URL serves both, which is what `--profile full --remote URL` wires in one word (ADR-0031 ruling 1): paste this URL there and the head, the entries and the keeper's cadence all point at this receiver.

The URL sits on the writer's machine, in the wired hook command, where the agent can read it. What that buys the agent is the right to post fakes, which are visible noise (a fake head matches no entry in the chain; a fake batch collides with the honest copy at the same `n`, section 6), and the right to stop posting by killing the hook, which the supervisor's completeness alarm watches. It buys no deletion, or the URL was never a head record.

`--new-token` retires a URL that leaked: the receiver prints a new one and the old path answers 404 from the next start on. Rewire the sender with the new URL; the files on disk are untouched. To the sender's chain cursor a new URL is a new remote, so each chain goes again from its genesis to this same box (section 4, *where it resumes*), the append rule drops every line of it this receiver already holds, and each file is unchanged.

## 4. The wire contract

The sender side of this contract is the recorder. Any other sender, and any other receiver, speaks it exactly.

**One door.** `POST` at `/<token>`. Every other verb at that path is `405` with `Allow: POST`; every other path is `404`, whatever the verb. There is no verb and no path that returns, lists or deletes what the receiver holds.

**Two content types, two destinations.**

- `Content-Type: application/json` is a published head: one JSON object, the body ADR-0025 ruling 2 describes (`head`, `n`, `session`, `ts`, `event`, `text`, `content`). It is appended to `heads.jsonl` as one line, compact and key-sorted, whatever whitespace the sender used.
- `Content-Type: application/x-ndjson` is a batch of a published chain: the chain's lines exactly as they sit in the chain file, newline-delimited, from genesis on the first send and from the entry after the last acknowledged one on later sends. It is appended to the file the chain header names.

**The headers on a chain batch.**

| Header | Holds | Read by the receiver |
|---|---|---|
| `X-Loxodonta-Chain` | the chain's file name: `receipts-<session>.jsonl`, or `receipts-<session>-002.jsonl` for a sibling | yes, required: it names the file |
| `X-Loxodonta-Session` | the session id | no |
| `X-Loxodonta-Range` | the `n` of the batch's first and last entry, `first-last` | no |
| `X-Loxodonta-Head` | the chain head after the batch's last entry | no |

The receiver reads the chain header and nothing else; the other three ride along for an operator reading traffic at a proxy, and for any receiver built to this contract that wants them. This one stores chain bytes and nothing besides.

**The chain header must be a receipt file name.** `receipts-`, then a session id of letters, digits, hyphens and underscores (the sibling suffix is made of the same), then `.jsonl`, at most 200 characters between the two. Anything else is refused with `400` and nothing is written: a separator (`/` or `\`), a parent reference (`..`), a dot inside the id, another extension, `.JSONL`, an empty header, a missing one. Nothing in a header ever becomes a path.

**The body.** `Content-Length` is required; a body declared past the cap of 8 MiB (8,388,608 bytes) is refused with `413` before a byte of it is read. A chain batch must hold at least one line, and every line must be a JSON object carrying an integer `n` and a string `entry_hash`; a batch with a line that is not is refused whole with `400`, nothing written, because a file that is a receipt log holds entries and nothing else. The receiver judges nothing further about a line: judging is `verify`'s job.

**The append rule** that keeps each chain file a receipt log (ADR-0031 ruling 4):

1. A line whose `n` and `entry_hash` the file already holds is an exact duplicate, the sender's retry after a lost acknowledgement, and is dropped.
2. A line whose `n` the file holds with a different `entry_hash` is a regenerated chain arriving after the original, and is appended: that collision is what the copy exists to show.
3. Every other line is appended in the order received.

**The answer.** `200` with a small JSON body, `{"appended": 3, "dropped": 0}` for a chain batch and `{"appended": 1}` for a head, sent only after the bytes are on disk, flushed and fsynced. Any `2xx` means on disk; the recorder advances its memo on a `2xx` and on nothing else.

| Status | When |
|---|---|
| `200` | appended (or every line was an exact duplicate: `appended` is `0`) |
| `400` | the chain header is not a receipt file name or is missing; a line is not an entry; the body ended early; `Content-Length` is not a length |
| `404` | not the token's path |
| `405` | a verb other than `POST` at the token's path (`Allow: POST`) |
| `411` | no `Content-Length` |
| `413` | `Content-Length` past the cap |
| `415` | a content type that is neither of the two |
| `500` | the disk refused the write; nothing of the batch is acknowledged, and the sender's memo does not advance |
| `501` | a verb the stdlib server does not know at all |

A refusal carries one line of plain text saying why. The receiver's own log, on its stdout, is one line per request with the time, the client address, the verb and the status; the request path is on no line, because the path is the credential.

**The sender's side.** The recorder speaks this contract from `publish --chain --log LOG URL` and from a wired session end (`install-hook --profile full --remote URL`, or `--profile custom --publish-chain URL` for the chain alone, docs/HOOK.md); `supervisor scan|serve --publish-every AGE --publish-chain URL` sends by running that same command, so there is one sender and not three.

- **Where it resumes.** The memo beside the chain, `<log>.published.jsonl`, holds one row of kind `chain` per acknowledged batch — `first`, `last`, the head after `last`, the time, the event, and `remote_id`, a fingerprint of the remote that took it: the first 16 hex characters of the SHA-256 of the URL, never the URL, which is the credential (section 3). The next send to a URL starts at the entry after the largest `last` among the rows for that URL, or at genesis when there are none. So a new remote receives each chain from its genesis and its file verifies (section 6), whatever an earlier remote already holds, and a remote sent to before resumes where it stopped (#263). A row written by a recorder from before the fingerprint names no remote and counts for none: after the upgrade each chain goes once more from genesis, and a receiver that already holds it keeps its file unchanged, since every line is an exact duplicate and is dropped. A chain row is appended on a `2xx` and on nothing else, so the cursor never passes an entry the receiver did not acknowledge. A memo that was lost or never written sends from genesis again, the append rule's first clause drops the duplicates, and the file on the receiver is unchanged.
- **How it batches.** Lines go in the order they sit on disk while the body stays under the 8 MiB cap; a longer tail goes in several batches, each its own POST, each acknowledged and written down before the next begins. A single entry whose own line is past the cap is refused by the sender before it is sent, named by its `n` in the failure line and in the attempt row: the receiver would refuse it on the Content-Length and close, which reaches the sender as a bare connection word and would stall that chain on that line for good, since the cursor cannot pass what never landed.
- **What it never sends.** Reading stops at the first line that is not an entry — a torn tail, damage — because a batch holding such a line is refused whole. The torn line stays on the writer's machine, as the damage `verify` reports.
- **What it spends.** At session end the whole send runs under the head publish's budget, three seconds on Claude Code: each batch waits at most that long, name lookup included, and no batch begins once the budget is spent. Whatever did not fit is the keeper's, on its next turn, from the same cursor. On Codex, whose whole SessionEnd hook is capped at three seconds, the send gets what the head left of the session end's shared 1.5-second window, sends the batches that fit and leaves the rest at the cursor (docs/HOOK.md, *Codex CLI*).
- **When it fails.** By hand, the command says why on stderr — never the URL — and exits 1. At session end it says nothing and appends one `attempt` row to the memo instead, step `publish-chain`, carrying the budget and what the socket said; no chain row is written, so the next send carries the same lines again.

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

A sibling chain (`receipts-<session>-002.jsonl`) verifies on its own, as siblings do. The heads file is not a chain and is not walked; a head in it is checked against a chain with `verify --log CHAIN --expect-head HEAD` (ADR-0025 ruling 4).

The walk judges the receiver's file the way it judges any chain, so what it says about the writer holds here too: the copy is of what the writer said. A harness that lied at write time is copied faithfully (ADR-0002). Every field but the hashes is testimony (GLOSSARY *Testimony*).

## 7. What it refuses

- Any verb but `POST` at the token's path: `405`.
- Any path but the token's: `404`, so a leaked or guessed path learns nothing, and the retired path after `--new-token` learns nothing either.
- Any content type but the two: `415`.
- A chain header that is not a receipt file name: `400`, nothing written, nothing from the header touching the disk.
- A body with no declared length, or declared past the cap: `411`, `413`, before a byte is read.
- A batch with a line that is not shaped like an entry: `400`, nothing written.
- A sender that stalls for thirty seconds, mid-body or before a TLS handshake it never starts: dropped silently, with no line on the receiver's log, so a stalling stranger cannot fill it.
- Every request for what it holds: there is no such request. The files are read on the box, by the operator, with the recorder.

## 8. The head-record test, restated

A remote is a head record when it is off the machine and the credentials present on the machine cannot delete or overwrite what they wrote there (GLOSSARY *Head record*, ADR-0025). Same login is not the test; deletability is. The receiver's URL passes: it is the only credential the writer's machine holds for the receiver, it can add, and it can do nothing else.

What none of this survives (ADR-0031):

- **The receiver's own operator.** Whoever runs the receiver can read and delete its files. When that is the operator on a second machine, the property holds. When it is anyone else, that is a trust relationship this design does not cover.
- **The receiver's box, reached another way.** A receiver reachable from the writer's machine by a credential other than the URL (an SSH key on the box, a shared filesystem, a login in a browser) is reachable by the writer. The tool cannot enforce this; the operator's choice of box does.
- **The tail since the last send.** Everything after the last acknowledged entry can still be rewritten consistently on the writer's machine. Session end closes the window for sessions that reach one; before that, the keeper sends nothing until the head has sat unchanged past its cadence, which covers a session killed before its end and leaves a busy session's tail unsent until it ends.
- **Garbage in.** The copy is of what the writer said.
