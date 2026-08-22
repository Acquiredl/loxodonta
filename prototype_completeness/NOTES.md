# PROTOTYPE — wipe me (issue #15)

**Run:** `python prototype_completeness/tui.py` (from the repo root; stdlib only, no install)

## The question

What are the right semantics for the supervisor's completeness alarm — the
state machine pairing liveness-witness activity with receipt arrival? See the
docstring in `machine.py` for the model under test.

## The knobs on trial

| Knob | Current value | Question it answers |
|---|---|---|
| Witness signal | **tool events**, not transcript growth | chat-only sessions must never alarm |
| `GRACE_SECONDS` | 30 | how long a deficit may stand before shouting (lock timeout is 10s) |
| `IDLE_END_SECONDS` | 1800 | when a quiet session counts as ended |
| Deficit stickiness | sticky forever | lost receipts never arrive; recovery keeps the scar |
| Alarm shapes | SILENT vs DEFICIT | "recording stopped" and "fork-shaped hole" are different incidents |
| Surplus | investigate-flag, never alarm | more receipts than witnessed tools = witness lag or fabrication |

## Scenario checklist (from issue #15)

- [ ] session active, no receipts arriving → `[D]` preset
- [ ] hook disabled / wedged lock mid-session → `[W]` preset
- [ ] silent fork: receipts arriving but short → `[F]` preset
- [ ] sibling continuation does not false-alarm → `[S]` preset
- [ ] two concurrent sessions stay independent → `[n]` then drive both
- [ ] clean session end reconciles clean → `[t] [r] … [e]`
- [ ] chat-only session never alarms → new session, only advance clock

## Verdict

*(fill in after driving it — the ratified state machine gets pasted into
issue #22, then this folder is deleted)*
