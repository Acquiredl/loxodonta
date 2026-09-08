# Security policy

## Reporting

Report privately through GitHub's private vulnerability reporting on this
repository: the *Security* tab, then *Report a vulnerability*. That is the
only channel; there is no email address. If the *Report a vulnerability*
button is not there yet (the author enables it by hand in the repository
settings), open a blank issue with no details and ask for a private channel.

## Scope

- The recorder, `loxodonta.py`: the chain writer, `verify`, anchoring.
- The supervisor, `supervisor.py`: `scan`, `serve`, the recall surface,
  `mcp`, `export`.
- The adapters under `adapters/`.
- The hook wiring: `install-hook` and the settings files it writes
  (`~/.claude/settings.json`, `~/.codex/hooks.json`).

## What the tool claims, so a report can say what broke

loxodonta is a tamper-evident receipt log with a watching layer: a tripwire
with a memory. Its claim is detection latency, never prevention. The threat
model (ADR-0002) is that the agent writing the log is the adversary: a writer
that edits, deletes, or reorders its own history breaks the chain, and
`verify` says so. Nothing on the machine is a security boundary. The one hard
boundary is the anchor, because that lives in a Bitcoin block no rewrite on
the machine can reach.

These are the design, not vulnerabilities:

- Anyone with write access to the store can rewrite a chain. That is the
  stated gap (SPEC §8); head records and anchors are how the operator closes
  it.
- A compromised writer lying at write time is chained faithfully. Receipts
  are testimony.
- A tool call that never fired the hook leaves no break. Completeness is the
  integration's job; the supervisor's witness alarms on the gap.
- Chains are plaintext by design (SPEC §8). Action lines, paths, and the
  digest are readable on purpose: in the forensic case the artifact is the
  evidence. A report that "the log is readable" or "the log contains command
  lines" is not a vulnerability.

These are vulnerabilities, and reports of them are wanted:

- A tamper that `verify` accepts: an edit, deletion, reorder, splice, or
  regeneration that the chain rule or the canonical form (SPEC §4, §5) lets
  through.
- An anchor proof that verifies against a head it does not commit to.
- A path by which a secret or file content reaches a receipt, an export, or
  the digest. Receipts must never contain secrets (SPEC §8); one that does
  is a bug in whatever wrote it.
- `serve` reachable from off the machine, or `mcp` gaining a write path.
- `install-hook` writing anything into the harness settings beyond the
  documented hook entries.
- A redaction the export states in its `redaction` block and does not
  perform.

## A good report

- The version: `python loxodonta.py --version` prints the tool version, the
  format version, and the commit.
- The chain, or the export (`python supervisor.py export`), that shows it. A
  chain copied out of `~/.loxodonta/receipts/` verifies on its own.
- The steps, from a fresh `init` where possible.

## What to expect

An acknowledgement; a fix on `main` as a patch release (ADR-0022: a hotfix
cherry-picked to `main` bumps the patch version) with a CHANGELOG line; and
credit under whatever name you give, or none if you prefer.
