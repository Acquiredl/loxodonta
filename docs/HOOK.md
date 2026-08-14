# Claude Code hook — Stage C wiring

`receipts hook` turns a Claude Code `PostToolUse` payload (JSON on stdin) into one chained entry. This is the completeness mechanism promised in SPEC §8 and ADR-0002: the harness fires the hook after **every** tool call, so the log call sits outside the writer's volition — the agent cannot skip its own receipt, and a session becomes a verifiable flight recording with no cooperation from the agent at all.

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
            "command": "python3 /absolute/path/to/receipts.py hook"
          }
        ]
      }
    ]
  }
}
```

- The hook command runs in the session's working directory, so per-session logs land in the project root by default. Add `--log-dir receipts/` to keep them in one place — the hook creates the directory on first use and seeds it with a protective `.gitignore` (command history must not ride into a commit by accident).
- With no `--log-dir` at all, the adapter reads the `CLAUDE_PROJECT_DIR` environment variable the harness sets for hooks and logs to `<project>/receipts` — resolved in Python, not by the shell, so the same settings command works on every platform (Windows included). For machine-wide recording, put the block in your user-level `~/.claude/settings.json` with absolute paths and no arguments (`"python3 /path/to/receipts.py hook"` — or run `python dogfood.py install-global`, which writes exactly that). Don't wire the same hook at both user and project level: both fire, and every tool call is logged twice.
- **Worktrees log to the repository they belong to.** When the project directory is a git worktree, the chain goes to the main repository's `receipts/`, not the worktree's. Worktrees are disposable — pruned once their branch merges — so a chain written inside one is deleted by routine hygiene, losing exactly the sessions worth keeping. Every worktree's history therefore collects in one place. The linkage is read from the files git writes (`.git` → `commondir`), never by spawning `git`: this runs on every tool call. An explicit `--log-dir` still outranks it, and anything unreadable falls back to the project directory rather than failing the session.
- **Parallel tool calls share one chain, so the hook serializes itself.** A harness fires one hook process per tool call and runs tool calls concurrently; each append therefore takes an exclusive `<log>.lock` across read-tail-then-append (ADR-0004). Without it, racing writers tear a line or — more often — silently drop a receipt from a chain that still verifies `VALID`. Waiting writers retry for `RECEIPTS_LOCK_TIMEOUT` seconds (default 10) and then **fail loudly**: a missing receipt is the one thing this tool exists to prevent, so contention is never a quiet skip. A lock left untouched for 60s is treated as abandoned and broken, so a crashed writer cannot wedge a chain forever.
- **A damaged chain is retired, not repaired.** If the chain the hook would extend has a torn tail, it starts a sibling — `receipts-<session>-002.jsonl` — and records there. The damaged chain is left byte-for-byte as evidence (there is no repair command, by design: ADR-0002). Each sibling is a complete chain with its own genesis and head, and **anchors separately** — worth knowing before you rely on one head record per session. The `log` and `run` commands still refuse to extend a damaged tail; siblings are the hook's answer, because a harness cannot stop and ask.
- Narrow `matcher` (e.g. `"Edit|Write|Bash"`) to receipt only state-changing tools; `"*"` records everything, reads included.
- The adapter reads `session_id`, `tool_name`, and `tool_input` from the payload; nothing else. Tool output is deliberately not recorded — receipts are not transcripts, and `action`/`path` values are plaintext forever (SPEC §8: no secrets).

## What gets written

- **One chain per session**: `receipts-<session_id>.jsonl`, auto-initialized on first use — plus a `-002` sibling if that chain is ever damaged (above). Separate sessions get separate chains; interleaving them is `report`'s display concern, not an integrity concern. Note the two senses of *sibling*: parallel **sessions** each get their own chain because they are separate histories, while a damaged chain gets a sibling because history must continue somewhere. Within one session, parallel tool calls share a chain and are serialized (SPEC §8, ADR-0004).
- **actor** — `claude-code` (override with `--actor`).
- **action** — the tool name plus its most descriptive argument, collapsed to one line: `Bash: pytest -q`, `Write: src/main.py`.
- **files** — a `{path, sha256}` fingerprint for `file_path` / `notebook_path` arguments that sit under the log's directory and still exist after the call. Files outside the project (or already gone) are skipped, never fatal: a hook that fails the session over path layout teaches the operator to turn the hook off — the receipt still records the action itself.

Failure semantics: on an unusable payload or an unappendable log the adapter prints one error line and exits 1 — visible in the harness, non-blocking for the session (the tool already ran; PostToolUse cannot roll it back, and receipts wouldn't want to).

## Verifying a session

```
receipts verify --log receipts-<session>.jsonl            # chain integrity
receipts report --log receipts-<session>.jsonl            # human timeline
receipts anchor --log receipts-<session>.jsonl            # pin it to Bitcoin (Stage B)
```

The operator ritual from ANCHORING.md §5 applies unchanged; session chains are ordinary receipt logs.
