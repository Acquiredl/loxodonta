# The docs

Every page in this folder, sorted by what you came for: running loxodonta, checking what it guarantees, or seeing how it was decided.

## Use

- [START.md](START.md): five steps to install the recorder on your own machine, try it, and send back what it saw.
- [HOOK.md](HOOK.md): how a hook in your agent's harness records one receipt per tool call, for Claude Code, Codex and others.
- [RECEIVER.md](RECEIVER.md): how to run the receiver, a machine the agent cannot reach that keeps a copy of its receipts and only adds.
- [METRICS.md](METRICS.md): every count the supervisor serves on `/metrics`, for the monitoring and alerting you already run.
- [MCP.md](MCP.md): how any agent that speaks MCP can read this machine's past receipts as memory, read-only.
- [FIRE-DRILL.md](FIRE-DRILL.md): a rehearsal on sandbox copies that shows, on demand, that every tamper alarm actually fires.
- [FIELD-DATA.md](FIELD-DATA.md): what exports from other machines taught the project, one row per export, read by a person.

## Reference

- [SPEC.md](SPEC.md): the receipt format, precise enough that an independent implementation in any language produces the same hashes.
- [PACKAGE.md](PACKAGE.md): how a session's receipts are shipped to someone else as a sealed zip that one file verifies.
- [ANCHORING.md](ANCHORING.md): how a chain's latest hash is committed to Bitcoin through OpenTimestamps, and what that does and does not prove.
- [TOPOLOGY.md](TOPOLOGY.md): where each piece runs, what each place holds, and what a verdict checked there is worth.
- [OWASP.md](OWASP.md): a first draft walking the OWASP Top 10 for LLM Applications, entry by entry: where loxodonta helps, where not.
- [GLOSSARY.md](../GLOSSARY.md): the project's vocabulary, and the words it deliberately refuses to use.

## Project

- [DIRECTION.md](DIRECTION.md): where the project is going, who it answers to first, and what it declines to build.
- [GROUNDING.md](GROUNDING.md): the published research and standards each design choice stands on, and where nothing was found.
- [HISTORY.md](HISTORY.md): the stages built before the first release, with dates, issue and pull request numbers, and the deciding ADRs.
- [EXPERIMENTS.md](EXPERIMENTS.md): what was actually tested behind the README's claims about agents using the chain, with protocol and numbers.
- [TOUR.md](TOUR.md): a guided reading of `loxodonta.py`, top to bottom, explaining what the code does and why.
- [TOUR-SUPERVISOR.md](TOUR-SUPERVISOR.md): the same guided reading for `supervisor.py`, the tool that watches and reads the receipts.
- [The ADRs](../adrs/README.md): every decision that is hard to reverse, with its status.
