# Claude Code hook — Stage C wiring

`receipts hook` turns a Claude Code `PostToolUse` payload (JSON on stdin) into one chained entry. This is the completeness mechanism promised in SPEC §8 and ADR-0002: the harness fires the hook after every **completed** tool call, so the log call sits outside the writer's volition — the agent cannot skip its own receipt, and a session becomes a verifiable flight recording with no cooperation from the agent at all. (A failed or denied call fires no hook — the harness's rule, not ours — and the supervisor's witness counts by exactly the same rule, so nothing is owed for it.)

## Wiring

In the project's `.claude/settings.json` (or your user settings):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /absolute/path/to/loxodonta.py hook"
          }
        ]
      }
    ]
  }
}
```

- With no `--log-dir`, the adapter reads the `CLAUDE_PROJECT_DIR` environment variable the harness sets for hooks and logs to that project's **drawer in the store** (ADR-0011): `~/.loxodonta/receipts/<project-slug>/` (override the home with `LOXODONTA_HOME`), writing a `project.json` project record on the first receipt so file references stay resolvable wherever the chain lives. Resolved in Python, not by the shell, so the same settings command works on every platform (Windows included). For machine-wide recording, run `python loxodonta.py install-hook` — it writes exactly the block above into your user-level `~/.claude/settings.json`. Don't wire the same hook at both user and project level: both fire, and every tool call is logged twice.
- Without `CLAUDE_PROJECT_DIR` (running the hook by hand, or a harness that doesn't set it), logs land in the working directory; `--log-dir receipts/` keeps them in one place — the hook creates the directory on first use and seeds it with a protective `.gitignore` (command history must not ride into a commit by accident). An explicit `--log-dir` outranks everything, the store included.
- **Worktrees log to the repository they belong to.** When the project directory is a git worktree, the drawer is keyed by the main repository's path, not the worktree's. Worktrees are disposable — pruned once their branch merges — so history keyed to one would be deleted by routine hygiene, losing exactly the sessions worth keeping. Every worktree's history therefore collects in one drawer. The linkage is read from the files git writes (`.git` → `commondir`), never by spawning `git`: this runs on every tool call. Anything unreadable falls back to the project directory's own drawer rather than failing the session.
- **Parallel tool calls share one chain, so the hook serializes itself.** A harness fires one hook process per tool call and runs tool calls concurrently; each append therefore takes an exclusive `<log>.lock` across read-tail-then-append (ADR-0004). Without it, racing writers tear a line or — more often — silently drop a receipt from a chain that still verifies `VALID`. Waiting writers retry for `RECEIPTS_LOCK_TIMEOUT` seconds (default 10) and then **fail loudly**: a missing receipt is the one thing this tool exists to prevent, so contention is never a quiet skip. A lock left untouched for 60s is treated as abandoned and broken, so a crashed writer cannot wedge a chain forever.
- **A damaged chain is retired, not repaired.** If the chain the hook would extend has a torn tail, it starts a sibling — `receipts-<session>-002.jsonl` — and records there. The damaged chain is left byte-for-byte as evidence (there is no repair command, by design: ADR-0002). Each sibling is a complete chain with its own genesis and head, and **anchors separately** — worth knowing before you rely on one head record per session. The `log` and `run` commands still refuse to extend a damaged tail; siblings are the hook's answer, because a harness cannot stop and ask.
- The shipped `matcher` is `"*"` — every completed tool call, reads and fetches included (ADR-0016): the forensic record must cover where an attack *enters* (reads of untrusted content) and *leaves* (network and MCP tools), not just where it changes state, and MCP tool names can't be enumerated in advance. You can narrow it (e.g. `"Edit|Write|NotebookEdit|Bash|PowerShell"`, the old default) to receipt only state-changing tools — but every uncovered tool call is a blind spot, and if you narrow, include every shell tool your harness actually runs: the desktop app on Windows issues most commands through a `PowerShell` tool, and a matcher that omits it silently misses those sessions' work. `install-hook` widens the old shipped default in place when it finds it, leaves any other matcher alone, and prints a notice; the supervisor observes matcher changes and judges each session by the coverage in force at its time, so changing your matcher never manufactures deficits over old sessions.
- The adapter reads `session_id`, `tool_name`, and `tool_input` from the payload; nothing else. Tool output is deliberately not recorded — receipts are not transcripts, and `action`/`path` values are plaintext forever (SPEC §8: no secrets).

## What gets written

- **One chain per session**: `receipts-<session_id>.jsonl`, auto-initialized on first use — plus a `-002` sibling if that chain is ever damaged (above). Separate sessions get separate chains; interleaving them is `report`'s display concern, not an integrity concern. Note the two senses of *sibling*: parallel **sessions** each get their own chain because they are separate histories, while a damaged chain gets a sibling because history must continue somewhere. Within one session, parallel tool calls share a chain and are serialized (SPEC §8, ADR-0004).
- **actor** — `claude-code` (override with `--actor`).
- **action** — the tool name plus its most descriptive argument, collapsed to one line: `Bash: pytest -q`, `Write: src/main.py`.
- **files** — a `{path, sha256}` fingerprint for `file_path` / `notebook_path` arguments that sit under the **project** and still exist after the call, recorded relative to the project root (SPEC §3 as amended v0.1.1, ADR-0012). Files outside the project (or already gone) are skipped, never fatal: a hook that fails the session over path layout teaches the operator to turn the hook off — the receipt still records the action itself. With the `"*"` matcher this includes **read** tools: a `Read` receipt fingerprints the file as it was when the agent saw it — for a forensic rebuild, "what content did the agent ingest" is exactly the question — and `verify --files` judges by a file's *latest* reference, so a read fingerprint never manufactures divergence noise. One caveat: the hash covers the whole file on disk, not the slice a ranged read returned; it identifies the artifact, not the excerpt.

## Coverage and cost

Wide coverage is one fresh hook process per tool call, machine-wide. Measured on the author's machine (Windows 11, CPython 3.13, NVMe): **~135 ms median per call, p95 ~158 ms**, end-to-end — cold interpreter spawn, payload on stdin, locked append. Chain length doesn't move it: appends to a ~380-entry chain measure the same 134 ms median, so a session never slows down as its history grows. Interpreter startup dominates everything.

Where the real limits sit:

- **Across sessions there is no contention.** Chains are per-session and locks per-chain, so any number of simultaneous agents record independently — the store's limit is your disk, not a shared lock.
- **Within one session**, parallel tool calls serialize on the chain's lock (ADR-0004, above). At ~135 ms per append, a burst of dozens of concurrent calls in a single session can stack toward the 10-second lock timeout — and the hook then **fails loudly** rather than skipping. If your harness fans out very wide inside one session, that is the edge to watch; nothing in the field has reached it.
- **The store is a log store — treat it like one.** Action lines are one-line, 160-character summaries, never transcripts, and never tool output (SPEC §2, §8) — but with `"*"` they include URLs fetched, queries searched, and prompt heads, because in a forensic reconstruction those *are* the evidence (a receipt that scrubbed the exfiltration URL would faithfully prove nothing). The chain deliberately holds evidence, so give `~/.loxodonta/` the handling you give logs: local ACLs, keep it out of backups that leave the machine, and never commit it (the drawer's `.gitignore` guards the accident, not the policy). Remember the recall digest is injected into session context — everything in a chain is discoverable by whatever reads that context, which is one more reason receipts must never contain secrets.

Failure semantics: on an unusable payload or an unappendable log the adapter prints one error line and exits 1 — visible in the harness, non-blocking for the session (the tool already ran; PostToolUse cannot roll it back, and receipts wouldn't want to).

## The transcript commitment (ADR-0017)

The chain is the *spine* of a forensic rebuild; the flesh — full commands, tool output, the conversation — lives in the harness transcript, a plain file the writer can reach. Every 25 entries, the hook staples the two together: it hashes the transcript **from byte zero** and appends a bookkeeping entry in the recorder's own voice —

```
{"actor": "receipts", "action": "transcript-commitment: bytes=1679210 sha256=c01237…", "files": [], …}
```

A committed prefix can never be rewritten undetected again: `verify --transcript` re-hashes each committed boundary and says which commitments hold (SPEC §2.2, §6). Because each commitment covers the whole prefix, a diverging one localizes the rewrite to the span since the previous commitment. `supervisor scan` hands each committed session its exact judge command.

The honest limits, stated plainly:

- **The window before the next commitment is open.** Bytes newer than the latest commitment — including the whole transcript during the first 25 calls — are rewritable until a commitment covers them, and the commitment will faithfully fingerprint whatever is there by then. At most ~25 calls of history are exposed at any moment.
- **The tail commitment depends on the client.** A SessionEnd hook writes one final commitment over the whole transcript, whatever the cadence position (issue #79) — but only where the client actually fires SessionEnd. The terminal CLI does, reliably, on `/exit` and Ctrl-D. Claude Desktop's Code mode offers no `/exit` and its SessionEnd behavior is undocumented, so sessions there commonly end with an **uncommitted tail** — the final <25 calls' bytes never locked in. The supervisor says so honestly ("tail uncommitted", ADR-0018) and its **tail keeper** closes the gap from the reading side: the scan writes the missing exit commitment itself, shrinking the open window to one scan cadence. A hard kill anywhere fires nothing, and the docs keep saying so.
- The commitment is **writer-authored**, like everything the recorder writes: it extends tamper-evidence to the transcript *by reference, forward from each commitment* — detection latency, not protection. Anchors remain the only hard boundary.

Cost: a commitment is one extra append (~4% more entries) and one transcript read+hash at the boundary — measured at ~1 ms per MB, inside a ~155 ms hook call that interpreter startup dominates either way (EXPERIMENTS §4). Bookkeeping entries never count against the completeness witness and never spend digest rows.

## Verifying a session

```
receipts verify --log receipts-<session>.jsonl            # chain integrity
receipts verify --log ... --transcript <transcript.jsonl> # + judge transcript commitments
receipts report --log receipts-<session>.jsonl            # human timeline
receipts anchor --log receipts-<session>.jsonl            # pin it to Bitcoin (Stage B)
```

The operator ritual from ANCHORING.md §5 applies unchanged; session chains are ordinary receipt logs.
