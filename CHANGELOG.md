# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The log starts at `v0.1.0`; the history before the first tag lives in the
ADRs under `adrs/` and in `docs/HISTORY.md`. The tool version is decoupled
from the receipt format, which stays at `0.1` (ADR-0022).

## [Unreleased]

### Added

- `--version` on both `loxodonta.py` and `supervisor.py`: tool version, format version, and the checkout's commit on one line.
- The house checker, `tools/house_check.py`: the GLOSSARY anti-terms and the front-door rules enforced by one stdlib script, locally and in CI.
- markdownlint and link-check GitHub Actions.
- The release workflow: a pushed `v*` tag publishes both files and `SHA256SUMS`, with the matching section of this file as the notes.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, and a pull request template.
- The demo store builder under `tools/`: a deterministic multi-session store, the only source for screenshots and README excerpts.

### Changed

- The README, rebuilt from the positioning brief: tagline, badge row, the two sentences, three reasons, the tamper demo as terminal text, Install, a numbered Quick start, and two reading paths; the status banner is gone, and the recorded-task excerpt comes from the demo store.

[Unreleased]: https://github.com/Acquiredl/loxodonta/compare/main...dev
