# Architecture decision records

Each ADR records a decision that is hard to reverse and why it was made; filenames are kept as first published, and the table gives the short title.

| ADR | Title | Status |
|---|---|---|
| 0001 | [Hash chain, not digital signatures](0001-hash-chain-not-signatures.md) | accepted |
| 0002 | [The writer is the primary adversary](0002-writer-as-adversary.md) | accepted |
| 0003 | [Anchoring through a minimal in-file OpenTimestamps subset](0003-anchoring-minimal-ots-subset.md) | accepted |
| 0004 | [Serialize the hook's appends, never stop recording](0004-serialize-hook-appends.md) | accepted |
| 0005 | [The supervisor is a sibling single file](0005-supervisor-as-sibling-tool.md) | accepted |
| 0006 | [Evidence grades generalize testimony versus mechanical facts](0006-evidence-grades-generalize-testimony.md) | accepted |
| 0007 | [A sidecar manifest seals the package](0007-sidecar-manifest-seals-the-package.md) | accepted |
| 0008 | [Issuer signatures for derived packages only](0008-issuer-signatures-for-derived-packages.md) | accepted |
| 0009 | [The recall surface lives in the supervisor](0009-recall-surface-lives-in-the-supervisor.md) | accepted |
| 0010 | [The tool is named loxodonta](0010-the-tool-is-named-loxodonta.md) | accepted |
| 0011 | [Chains live in one machine-wide store](0011-central-receipts-store.md) | accepted |
| 0012 | [File references are relative to the project root](0012-file-references-rebase-to-project-root.md) | accepted |
| 0013 | [The dashboard grows inside `serve`](0013-dashboard-grows-in-serve.md) | accepted |
| 0014 | [The day book: per-day history beside the baseline](0014-the-day-book.md) | accepted |
| 0015 | [Report which recorder runs, never update it](0015-the-recorder-notice.md) | accepted |
| 0016 | [Coverage goes wide: record every completed tool call](0016-coverage-goes-wide.md) | accepted |
| 0017 | [The chain commits the transcript by prefix](0017-transcript-commitments.md) | accepted |
| 0018 | [Reading a session's lifecycle: dormancy and reawakening](0018-session-lifecycle-reading.md) | accepted |
| 0019 | [Recall speaks MCP, read-only](0019-recall-speaks-mcp-read-only.md) | accepted |
| 0020 | [Recorder adapters speak the hook contract](0020-recorder-adapters-speak-the-hook-contract.md) | accepted |
| 0021 | [Field-data export: allowlisted, redacted, sent through `gh`](0021-field-data-export-is-allowlisted-and-sent-through-gh.md) | accepted |
| 0022 | [A version, a tag and a release](0022-the-tool-gets-a-version-tag-and-release.md) | accepted |
| 0023 | [One session, one drawer](0023-one-session-one-drawer.md) | accepted |
| 0024 | [Anchor at session end, opted in at install](0024-anchor-at-session-end-opt-in-at-install.md) | accepted |
| 0025 | [A head record the machine cannot unsay](0025-a-head-record-is-what-the-machine-cannot-unsay.md) | accepted |
| 0026 | [A session or drawer ships as a package](0026-the-store-ships-as-a-package-verified-by-one-file.md) | accepted |
| 0027 | [The dashboard counts what the chain holds](0027-the-dashboard-counts-what-the-chain-holds.md) | accepted |
| 0028 | [A docs-only promotion carries no tag](0028-a-docs-only-promotion-carries-no-tag.md) | accepted |
| 0029 | [Sessions older than the supervisor's memory go unjudged](0029-sessions-older-than-the-supervisors-memory-are-not-judged.md) | accepted |
| 0030 | [The recorder writes down the coverage it wired](0030-the-recorder-writes-down-what-coverage-it-wired.md) | accepted |
| 0031 | [Entries go to a URL that only adds](0031-the-entries-go-to-a-url-that-can-only-add-never-delete.md) | accepted |
| 0032 | [An authority timestamp sits beside the anchor](0032-an-authority-timestamp-sits-beside-the-anchor-never-instead-of-it.md) | accepted |
| 0033 | [Pull-only metrics for the operator's own siren](0033-the-supervisor-exposes-its-counts-for-the-operators-own-siren-pull-only.md) | accepted |
| 0034 | [A failed call that ran owes a receipt](0034-a-failed-call-owes-a-receipt-when-its-words-say-it-ran-and-receipts-pay-tool-by-tool.md) | accepted |
| 0035 | [The verifier is copied out, never imported](0035-the-recipients-verifier-is-copied-out-of-the-recorder-never-imported-by-it.md) | accepted |
| 0036 | [The hashing is frozen across format versions](0036-the-hashing-is-frozen-across-format-versions.md) | accepted |
| 0037 | [Exit 1 means BROKEN and nothing else](0037-exit-1-means-broken-and-nothing-else.md) | accepted |
| 0038 | [Every sidecar row names its kind](0038-every-sidecar-row-names-its-kind.md) | accepted |
