# History — the stages before the first tag

This is the stage history that `CLAUDE.md` used to carry: what was built, in what order, with the dates, the issue and PR numbers, and the ADR that settled each step. The changelog starts at `v0.1.0` with no backfill (ADR-0022), so the story before the first tag lives in the ADRs and in this document.

## Stage A — the recorder (done 2026-08-13)

Spec review, then the stdlib-only CLI: `init` / `log` / `run` / `head` / `verify` / `report`. Tamper-demo tests (edit / delete / reorder / splice / regenerate, each caught) and a golden fixture pinning canonicalization. Stages A–C were implemented and merged together on 2026-08-13; SPEC v0.1 and ADR-0001/0002/0003 are `accepted`, and the format is frozen.

## Stage B — anchoring (done 2026-08-13)

`receipts anchor`: an OpenTimestamps commitment of the chain head to Bitcoin, through a minimal in-file OTS subset (ADR-0003, `docs/ANCHORING.md`). `verify --anchors` judges proofs offline.

## Stage C — the hook and explain (done 2026-08-13)

The Claude Code `PostToolUse` hook adapter (`receipts hook`, `docs/HOOK.md`), plus `receipts explain`: LLM narration of the log via an external command, default `claude -p`. The tool was still called *receipts* at this point; the rename is ADR-0010, below.

## The dogfood and Stage D — the supervisor (built 2026-08-22, closed 2026-08-31)

The dogfood closed early on 2026-08-21 (verdict: **push forward**). Stage D was grilled and ratified 2026-08-22 (ADR-0005) and **built the same day**: `supervisor.py` is a sibling stdlib-only single file driving receipts through the public CLI. Slices 1–11 merged (PRs #27, #29, #30, #28; suite at 201). It scans and serves (localhost only): recall front page with free-text search (GLOSSARY: *Recall*, testimony-labeled), status band with verdict tiers, baseline tripwire (scan exit 5), the completeness alarm over the transcript witness (flagship claim, exit 6; ratified state machine from the #15 prototype), anchor keeper with opt-in `--anchor-every` cadence, WebCrypto chain walker, and the fire-drill surface (`docs/FIRE-DRILL.md`). Security claim unchanged: *a tripwire with a memory* — detection latency only; anchors stay the only hard boundary. The hook stays outcome-blind (`.out-of-scope/001`).

The witness-calibration standing question closed 2026-08-29: the witness reads the wired PostToolUse matchers from the harness settings and skips failed tool calls (the harness fires no hook for them; the transcript marks these with `is_error` on the tool_result block, not on `toolUseResult`), so witnessed count equals receipts owed. Coverage went wide 2026-08-31 (ADR-0016, OWASP-grounded): the shipped matcher is `*` — every completed tool call owes a receipt — and calibration is effective-dated: the supervisor remembers the matchers it observes (baseline `calibration`) and judges each session by the coverage in force at its time, so matcher changes never manufacture deficits. GLOSSARY: *Coverage*. Measured envelope in `docs/HOOK.md` (~135 ms/call).

Stage D closed 2026-08-31, which also closed the release ritual: slice 12 (issue #25, the HITL readability walk + adversary pass + manual fire drill + dogfood handover) signed off, seven findings fixed tests-first (PR #63, suite 277). `docs/TOUR-SUPERVISOR.md` is the guided reading.

## Stage E — the recall surface (grilled and built 2026-08-26, ADR-0009)

The PRD is issue #40. `supervisor digest` (budget-capped, local-only session-start injection, wired by the SessionStart hook via `loxodonta.py install-hook`), `supervisor show` (one entry by entry address — an 8-hex `entry_hash` prefix, git prefix rules, re-hashed on fetch), `supervisor search` / `timeline` (the ladder past the digest window; `--all` walks the folder of repos, honoring `receipts/.unlisted`). Recall owns no verdicts: the digest cites the last scan as testimony and spawns nothing at session start. GLOSSARY: *Digest*, *Entry address*, *Unlisted*. Web front-end navigation was left as a later slice on `serve`.

## Going public (2026-08)

Public since 2026-08, under the Acquiredl identity only. Positioning discipline governs, from the operator-side prior-art survey (not in this repo): show our claims, avoid naming others unless necessary, never overclaim. The go-public opsec review happened 2026-08-26 (author scrub + dev-doc purge).

## The rename and the store (2026-08-29)

The tool is named loxodonta (ADR-0010): the recorder is `loxodonta.py`, and what it writes are *receipts*. The dogfood driver retired with the rename — its installer became `loxodonta install-hook`, its status/drill duties were already the supervisor's, and `DOGFOOD.md` remains a local, gitignored, operator-side journal. The same day, the chains moved into one machine-wide store (ADR-0011, grilled in issue #47, built in PR #51; file references rebase to the project root, ADR-0012). Sessions are recorded machine-wide: `python loxodonta.py install-hook` wires the `PostToolUse` hook into `~/.claude/settings.json`, and every Claude Code session writes per-session chains into the store — `~/.loxodonta/receipts/<project-slug>/` with a `project.json` project record. Sessions run in a worktree log to the main repo's drawer, since worktrees get pruned; `supervisor adopt --root <folder>` migrates legacy layouts. `supervisor scan` (no arguments) reads every chain in the store across every repo, not just this one; `--root <repos-folder>` is the legacy per-repo layout only. Code changes still go tests-first through the public CLI.

## The watching layer deepens (2026-08-29 to 2026-09-01)

Between the store and Stage F, the supervisor grew what `CLAUDE.md` never listed as a stage of its own: the dashboard rebuilt inside `serve` (ADR-0013, issue #48, slices #87–#90), the day book and its fourteen-day band (ADR-0014, built first in PR #56), the recorder notice (ADR-0015; the tool reports which recorder is running and never updates itself), the consumption watch (#67), transcript commitments and `verify --transcript` (ADR-0017, #76–#79), and the session lifecycle reading (ADR-0018, #99–#101). ADR-0016 and ADR-0017 were promoted to `main` on 2026-09-01.

## Stage F — harness neutrality (built 2026-09-02)

Built on `claude/agent-surface`; ADR-0019 and ADR-0020 `accepted`, restate-to-ratify passed. Prompted by the agent-first market read ("my agent uses your thing"). Read side: `supervisor mcp`, the recall surface as a **read-only** stdio MCP server — five tools one-to-one with the CLI (digest/show/search/timeline/verify), stdlib JSON-RPC, dual-era (2025-11-25 `initialize` and 2026-07-28 `_meta`), no write path by test (`docs/MCP.md`). Write side: adapters that speak the hook payload — `install-hook --codex` wires Codex CLI's PostToolUse/SessionEnd/SessionStart into `~/.codex/hooks.json` (the digest takes `--payload` there: repo from the payload's `cwd`, never read unasked because under `mcp` stdin is the wire; corrected 2026-09-03 after the Codex docs said plain-text SessionStart stdout is context); `adapters/openai_agents.py` is a stdlib-only `TracingProcessor` for the OpenAI Agents SDK (function + handoff spans, verified against `openai-agents` 0.22.0). The recorder learned two things: payload `cwd` names the project when `CLAUDE_PROJECT_DIR` is unset; `summary` is the last action-line key. Honest limits stated in the docs: coverage semantics differ per harness, the completeness witness is Claude-Code-only, the SDK adapter is in-process (one ring closer to the writer). GLOSSARY: *Adapter*. Suite 367.

## The share phase (2026-09-03)

ADR-0021 `accepted` 2026-09-03; PR #108 is the polish, issue #107 the build. The repo asks for field data from other machines: LICENSE, CI on three platforms (`.github/workflows/tests.yml`), the `field-data` issue template and label, CONTRIBUTING, and `supervisor export` — allowlisted, redacted by construction, `redaction` block first, `--raw` opt-in with sample-and-ask, `--send` through `gh` (secret gist under the sender, then a field-data issue). Exports are read into `docs/FIELD-DATA.md`. GLOSSARY: *Field-data export*. Community order ruled: r/ClaudeAI and Claude Code discussions first, then r/LocalLLaMA and Show HN once one outside export sits in FIELD-DATA.md; Acquiredl only.

## The presentation arc (in progress, from 2026-09-03)

Issue #119 was grilled 2026-09-03: ADR-0022 (the tool gets a version, a tag, and a release; 1.0 waits for field data) is `accepted`, the "audit log" anti-term carries its public reason, and root hygiene started (the legacy root `receipts/` folder removed, operator-side journals gitignored). The PRD is issue #120, sliced into #121–#135. #121, `--version` printing the tool version, the format version, and the recorder's commit on one line, merged to `dev` 2026-09-04 (PR #137). The house checker (#123, `tools/house_check.py`) and this document with the root map (#127) follow. The arc is still open: the first tag, `v0.1.0`, is cut from the promotion that lands it, and the changelog begins there.
