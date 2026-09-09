# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The log starts at `v0.1.0`; the history before the first tag lives in the
ADRs under `adrs/` and in `docs/HISTORY.md`. The tool version is decoupled
from the receipt format, which stays at `0.1` (ADR-0022).

## [Unreleased]

### Added

- `install-hook --publish-head URL` (ADR-0025): opt in once, and every session end publishes the chain head to a remote the credentials on this machine cannot delete from (a chat incoming webhook, a retention-locked bucket), after the tail commitment and before the anchor, quietly and best-effort inside the same session-end budget. `hook --publish URL` carries it; a re-run of the installer without the flag turns it off; `uninstall-hook` removes it. What leaves is `head`, `n`, `session`, `ts`, `event`, and one readable line under both `text` and `content`; never a path, a project name, an action line, or chain bytes. Codex refuses the flag until the cost of one POST inside its three-second cap is measured. The installer refuses anything but a plain http or https URL with nothing a shell could act on, since the wired command runs through a shell; the three-second cap covers name lookup; a redirect is a failure.

### Changed

- Usage errors exit `64` (sysexits `EX_USAGE`) in both `loxodonta.py` and `supervisor.py`: an unknown flag, a missing required argument, or a malformed value (`--expect-head`, `--anchor-every`) no longer shares exit `2` with `FILES-DIVERGED`, so a verdict exit is never an argparse error. Argparse's message on stderr is unchanged, and every verdict exit is untouched: the recorder's `0` to `5`, and `scan`'s `0` to `7` (ADR-0026 ruling 7, #175).

## [0.2.0] - 2026-09-08

The release after the measurement: what the orientation-cost run (EXPERIMENTS §6) found is fixed or stated, the window between anchors is closed for anyone who opts in at install, and the front door says how the repo is built.

### Changed

- The coverage claim states its edge: what the harness does on a session's behalf outside any tool call (a worktree it merges when a session leaves it) fires no hook and leaves no receipt; HOOK.md, the GLOSSARY, and the README's defends-against table say so, and point at git's reflog for the pointer move (#156).
- One session, one drawer (ADR-0023): every receipt of a session goes to the drawer its first receipt chose, so a project directory that resolves differently mid-session can no longer split a session's chain in two. Store-routed writes only; `--log-dir` and the cwd-local default are untouched.
- The digest header says what it leaves out: when a chain holds bookkeeping entries (transcript commitments), the header adds `plus N bookkeeping entries not rendered (last n M)`, so a row's sequence number never reads as a missing receipt (#154).

### Added

- `install-hook --anchor-at-session-end` (ADR-0024): opt in once, and every session end anchors the chain head to Bitcoin through OpenTimestamps, after the tail commitment, quietly and best-effort under a fixed budget, then spends the leftover budget upgrading the drawer's pending proofs. `hook --anchor` and `hook --calendar` carry it. Nothing leaves the machine without the opt-in; the `gh` head ledger is rejected as writer-reachable.
- `supervisor verify ADDRESS`: the recorder's verdict on the chain holding an entry address, printed verbatim with its exit code, the CLI twin of the MCP tool (ADR-0019, one-to-one restored). `show` names the chain's full path and the verify command; the digest footer names it too, so an agent holding an address never has to hunt for the chain file (#155).
- A repository's recall (`digest`, `search`, `timeline`) also reads the drawers of its own harness worktrees (`<repo>/.claude/worktrees/`), so a session split before this release is shown whole.

### Fixed

- A worktree the harness deregistered under a running session still logs to its repository's drawer: the `.git` file names the repository even after `<main>/.git/worktrees/<name>` is gone.
- A long action line is cut between words, never inside one, and never between a letter and its accent or inside an emoji sequence; a run with no space near the limit is still cut at the limit (#157).

## [0.1.0] - 2026-09-07

The first tagged release, cut from the promotion that lands the presentation arc. The tool is versioned from here; the history before this tag lives in `adrs/` and `docs/HISTORY.md` (ADR-0022).

### Added

- `--version` on both `loxodonta.py` and `supervisor.py`: tool version, format version, and the checkout's commit on one line.
- Releases: a pushed `v*` tag publishes both files and `SHA256SUMS`, with this file's matching section as the notes.
- The house checker, `tools/house_check.py`: the GLOSSARY anti-terms and the front-door rules enforced by one stdlib script, locally and in CI; markdownlint and a weekly link check as Actions.
- The front-door pin test: the README's tamper demo, quick start, and bad-day commands run in the suite on all three platforms, and the verdicts they print are checked.
- The demo store builder, `tools/demo_store.py`: a deterministic multi-session store under a neutral home, the only source for screenshots and README excerpts. A bad-day session ships as `docs/demo/bad-day-session.jsonl`, byte-checked against a fresh build.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, a pull request template, and `docs/HISTORY.md` for the stages before this tag.
- EXPERIMENTS §6: the orientation-cost measurement on a second repo, pre-registered, run, and scored; the memory reason on the front door says only what it supports.
- The dashboard screenshot, the tamper demo as a GIF with its tape, the wordmark, and a social preview image, every one from the demo store or neutral ground.

### Changed

- The README, rebuilt from the positioning brief and reworked with the author until it read as a story: the receipt sentence, the attack, the bad day first, the tamper demo, Install, an Operator quick start, a bad-day walk, two reading paths.
- The recorder honors `SOURCE_DATE_EPOCH` for the receipt timestamp, so the demo store writes byte-identical chains; a timestamp is testimony either way (ADR-0002).
- CONTRIBUTING: the one local check command, the voice rule, the release ritual. CLAUDE.md cut to a map, GLOSSARY given an entry-point preamble, the legacy root `receipts/` folder removed.

[Unreleased]: https://github.com/Acquiredl/loxodonta/compare/v0.2.0...dev
[0.2.0]: https://github.com/Acquiredl/loxodonta/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Acquiredl/loxodonta/releases/tag/v0.1.0
