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
- Narrow `matcher` (e.g. `"Edit|Write|Bash"`) to receipt only state-changing tools; `"*"` records everything, reads included.
- The adapter reads `session_id`, `tool_name`, and `tool_input` from the payload; nothing else. Tool output is deliberately not recorded — receipts are not transcripts, and `action`/`path` values are plaintext forever (SPEC §8: no secrets).

## What gets written

- **One chain per session**: `receipts-<session_id>.jsonl`, auto-initialized on first use. Parallel sessions are sibling chains (SPEC §8: one writer per log); interleaving them is `report`'s display concern, not an integrity concern.
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
