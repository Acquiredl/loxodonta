# Fire drill — rehearsing detection

The fire drill is the tamper playground graduated into its honest job:
proving, on demand, that every alarm you are trusting actually fires.
Everything below runs on **sandbox copies** under `<root>/.supervisor-drill/`
— real chains are never touched, and nothing a drill reports is a verdict
about a real chain.

Run it from the frontend (the *drill* button on any status-band chain) or
from the CLI:

```bash
python supervisor.py drill --root <your-repos-folder> --log <path-to-chain>
```

## The automated battery

The drill copies one chain into the sandbox and runs the four-way tamper
battery, verifying each copy through the public receipts CLI:

| Tamper | What it does to the copy | Expected alarm |
|---|---|---|
| edit | rewrites one entry's action without recomputing hashes | `BROKEN` |
| delete | removes one middle entry | `BROKEN` |
| reorder | swaps two entries | `BROKEN` |
| regenerate | rebuilds a fresh, internally-valid chain | `HEAD-MISMATCH` against the sandbox's known head |

Exit 0 means every alarm fired. Anything else means detection is broken —
do not trust the band until you know why.

## The manual checklist

The drill leaves its sandbox copies in place so you can inspect them.
Once per drill session, walk through:

1. **The walker's in-browser check** — the one item no test suite can
   automate. Open the walker on `.supervisor-drill/edit.jsonl`: the
   browser's own WebCrypto recomputation must flag exactly the rewritten
   entry ("recomputed in your browser: does NOT match the stored
   entry_hash") while its neighbors match. This is your second,
   independent check — the point is that you never have to take the
   supervisor's word.
2. **Non-ASCII agreement** — walk `.supervisor-drill/pristine.jsonl`:
   every entry matches, including any entry whose action carries
   non-ASCII text (em-dashes were the field's lesson). Browser and CLI
   must hash the same bytes.
3. **Tier rendering** — on the status band, confirm the drill has not
   blurred the claims: `VALID` and `ANCHORED` read as different claims,
   the exit-3 tier ("not the recorded history") reads gravest, and a
   superseded torn tail sits quiet while fresh damage shouts.
4. **The tripwire** (optional, uses a scratch root): regenerate a scratch
   chain between two `scan` ticks and watch the baseline raise its
   change event (scan exit 5). The drill's own sandbox is deliberately
   invisible to the census, so this rehearsal needs a scratch root.

When an item fails, that is the drill doing its job: investigate before
relying on the alarm it rehearses.
