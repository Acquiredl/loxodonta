# Field data

What other machines' stores taught this project. One row per export
that arrived through `supervisor export --send` (or was filed by hand
from the *Field data* issue template), read by a person, not aggregated
by a script. The export format is ADR-0021; the point of this page is
that sending one visibly changes something.

| date | issue | platform | sessions | what it taught |
|---|---|---|---|---|
| *(none yet)* | | | | The first outside export lands here. Until then every number in the docs comes from one store: the author's. |

## How a row gets here

1. The issue arrives with the gist link and the redaction block.
2. The export is read end to end. Anything surprising (a verdict that
   should not be there, a completeness state that does not add up, a
   tool histogram nobody expected) is written up in the issue.
3. If it changes a threshold, a default, or a claim in the README, the
   change is made and linked from the row. If it changes nothing, the
   row says so; that is also information.
4. The issue is closed with the row's text as the last comment.
