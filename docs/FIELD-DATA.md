# Field data

What other machines' stores taught this project. One row per export
that arrived through `supervisor export --send` (or was filed by hand
from the *Field data* issue template), read by a person, not aggregated
by a script. The export format is ADR-0021; the point of this page is
that sending one visibly changes something.

| date | issue | platform | sessions | what it taught |
|---|---|---|---|---|
| 2026-09-03 | none (the author's own dry run; not filed) | Windows | 38 | Two things. First, the export read a session's verdict from its last sibling, so the one session whose first chain broke and whose recording moved to `-002` exported as VALID; fixed in PR #111 (the worst sibling speaks for the session), together with `matchers: null` from misreading the baseline. Second, 24 of 38 sessions were ENDED-DEFICIT. Walking two transcripts against their chains: the missing receipts were Read, Grep, PowerShell and MCP calls from before coverage went wide on 2026-08-31, judged by today's `*` because the calibration memory's first epoch extends over all time before it (the witness over-counts; a ruling on pre-memory sessions is pending). On the tools the old matcher did cover, chain and transcript agreed to within a handful, and that handful was writes to files on another drive, the hook bug fixed 2026-08-30 (f2c1740). After the widening, chain and transcript agree tool for tool. The three ENDED-SURPLUS sessions are receipts from subagent tool calls (WebFetch and WebSearch, mostly), which the harness fires under the parent session id but writes to a separate transcript the witness does not read. |
| *(no outside export yet)* | | | | The first outside export lands here. Until then every number in the docs comes from one store: the author's. |

## How a row gets here

1. The issue arrives with the gist link and the redaction block.
2. The export is read end to end. Anything surprising (a verdict that
   should not be there, a completeness state that does not add up, a
   tool histogram nobody expected) is written up in the issue.
3. If it changes a threshold, a default, or a claim in the README, the
   change is made and linked from the row. If it changes nothing, the
   row says so; that is also information.
4. The issue is closed with the row's text as the last comment.
