# loxodonta and the OWASP Top 10 for LLM Applications (2026)

The [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) is the closest thing agent security has to a shared checklist. This doc walks it entry by entry and answers one question each time: is loxodonta a layer here, and if so, which kind?

The honesty frame comes first, because every claim below sits inside it. loxodonta is a tamper-evident receipt log with a watching layer: a tripwire with a memory. Its claim is detection latency, never prevention. Nothing here is a security boundary. The one hard boundary in the whole design is the anchor, because that lives in a Bitcoin block no rewrite on the machine can reach. Everything else detects fast and says so.

## Summary

| OWASP 2026 entry | Relationship |
|---|---|
| LLM01 Prompt Injection | Forensic layer: records all three legs of the lethal trifecta, survives the incident, alarms on recorder silence |
| LLM02 Sensitive Information Disclosure | Honest boundary: loxodonta is itself a log store and carries a documented disclosure posture |
| LLM03 Excessive Agency | Implements prescribed mitigation #8 (Monitor tool use), plus tamper evidence on the log itself |
| LLM04 Supply Chain | No claim |
| LLM05 Data and Model Poisoning | Substrate for mitigation #8: fingerprints and chains answer what-changed-when |
| LLM06 Unbounded Consumption | Substrate for mitigation #8: the chains can carry tool-use baselines (surface planned, not built) |
| LLM07 Misinformation | No claim |
| LLM08 Hidden Context Exposure | Honest boundary: the recall digest is discoverable hidden context by design, kept at the informational tier |
| LLM09 Vector and Embedding Weaknesses | No claim |
| LLM10 Improper Output Handling | No claim |

## LLM03 Excessive Agency: the prescribed control, plus tamper evidence on it

OWASP's mitigation #8 for Excessive Agency, "Monitor tool use", prescribes this tool's job verbatim:

> Log and monitor the activity of LLM tools and downstream systems to identify where undesirable actions are taking place, and respond accordingly.

OWASP files that mitigation under the controls that "will not prevent Excessive Agency but can limit the level of damage caused". That is exactly the claim loxodonta makes about itself: detection, never a wall.

loxodonta is that control, plus one thing OWASP's line does not ask for: tamper evidence on the log itself. The threat model (ADR-0002) is that the writer of the log is the adversary. An agent that can take undesirable actions can also edit the record of them afterward, and a plain log gives you no way to notice. Every receipt hashes the one before it, so an edit, a deletion, or a reorder is a visible chain break. The record of tool activity is the first thing a compromised agent wants to clean up. Here, cleanup shows.

The pieces that make up the control:

- **Coverage is every completed tool call.** The shipped `PostToolUse` matcher is `*` (ADR-0016): reads, searches, fetches, spawns, and MCP tools all owe a receipt, not just state changes. A sensor with an allowlist has blind spots an attacker can enumerate by reading this public repo.
- **The watching layer closes the loop.** OWASP's "and respond accordingly" needs someone to actually look. The supervisor scans every chain in the store, shouts on unexplainable change (the baseline tripwire, exit 5), and alarms when a visibly active session stops producing receipts (the completeness alarm, exit 6). Detection latency is a function of how often something looks; the supervisor is the something.
- **Circuit breakers stay out of scope.** OWASP's mitigation #9 (rate limiting, halting) is a control loxodonta deliberately does not implement. The hook is outcome-blind: this tool evidences someone else's circuit breaker, it never is one ([.out-of-scope/001](../.out-of-scope/001-outcome-capture-in-hook.md)).

## LLM01 Prompt Injection: the record that survives the incident

OWASP's 2026 entry states the ground truth plainly: "no reliable prevention mechanism exists today", and defense is architectural. Once prevention is off the table, the after-the-incident questions carry the weight: what did the compromised session actually do, in what order, and can anyone trust that record? loxodonta is built for exactly those questions.

**All three trifecta legs are recorded.** OWASP's mitigation preamble cites Simon Willison's lethal trifecta, and mitigation #8 budgets agent capability along the same three legs: access to private data, exposure to untrusted content, and external communication. A recorder that only logs state changes sees one leg. Wide coverage (ADR-0016) exists because the missing tools were exactly the ones the trifecta names: the ingest leg (`Read`, `WebFetch`: where injection enters) and the communication leg (network and MCP tools: where exfiltration leaves). A forensic record that misses two of the three legs cannot reconstruct the attacks that matter.

**Injection artifacts become receipts.** Action lines name what the tool touched: the fetched URL, the query, the file read. In the post-incident forensic, the injected URL *is* the evidence. This is also why the recorder never redacts (ADR-0016): a chain that scrubs the artifact faithfully proves nothing.

**The kill command is the last receipt.** The hook fires outside the agent's volition, so an injected session keeps leaving receipts unless the attack specifically disables the recorder. That disabling action is itself a tool call, so the last receipt before the silence is the kill command, and the supervisor's completeness alarm fires on the silence that follows. An attacker can stop the recording; an attacker cannot make the stopping quiet.

**Memory writes are logged out of the box.** OWASP's mitigation #9 says to treat agent memory writes as privileged operations and log them. On this stack, memory writes are file writes through tools, so each one already leaves a receipt with a fingerprint of the file written. One boundary, stated honestly: the receipt records the write, not the prompt that caused it. The prompt lives in the harness transcript, which the chain does not currently seal (sealing the transcript by reference is named future work, issue #69).

## LLM05 Data and Model Poisoning: the what-changed-when substrate

OWASP's mitigation #8 prescribes data version control to "track dataset changes, maintain version history, and enable rollback and forensic analysis when poisoning is detected".

loxodonta supplies the forensic half of that sentence. Every receipt fingerprints the files it touched (SHA256 at log time), and the chain orders those fingerprints tamper-evidently. When poisoning is detected, the chains answer: which files changed, in what order, in which session, driven by which actions, and `verify --files` says whether the file on disk today is still the one that was receipted. That is the record rollback decisions and incident timelines are built from.

The boundary: loxodonta is not a version control system. It stores fingerprints, never contents, so restoring a prior state needs the artifacts from somewhere else (git, backups, the dataset store). The chain tells you what to restore and proves nobody rewrote that answer; it does not hold the bytes.

## LLM06 Unbounded Consumption: baselines become possible

OWASP's mitigation #8 says to monitor agent-tool interactions and "establish baselines of normal tool behavior" to catch resource-intensive deviations.

Wide coverage makes the receipt chains exactly the dataset such baselines need: every completed tool call, timestamped, per session, per repo, machine-wide. Entries per session per hour is a consumption signal that already sits in the store today.

The honest label: the baseline *surface* is planned, not built (issue #67 tracks it as a supervisor surface). And the outcome-blind rule holds here too: loxodonta would evidence a circuit breaker's decision, never trip one.

## LLM02 Sensitive Information Disclosure: an honest boundary

OWASP's entry names logs and telemetry as disclosure surfaces in their own right, and its foundational mitigations include restricting and scrubbing logs. loxodonta is itself a log store and says so. Its posture:

- **Receipts are summaries, never transcripts.** An action line is one line by spec (§2), and the hook truncates it to 160 characters. Tool outputs, file contents, and conversation content never enter the chain.
- **No secrets in receipts.** SPEC §8: action and path values are plaintext forever, and the logger must not put credentials or sensitive content in them. Wide coverage sharpens the rule rather than relaxing it: because the recall digest is injected into sessions, everything in a chain must survive being read by the next attacker.
- **The store is local.** Chains live in `~/.loxodonta/receipts/` under a protective `.gitignore`; nothing ships anywhere. `serve` binds localhost only.
- **Custody, not amnesia, is the control.** The recorder never redacts (ADR-0016), because in the forensic use case the sensitive-looking artifact is often the evidence. The operator therefore treats the drawer with log-store handling: it is part of the machine's sensitive surface, and pretending otherwise would be the overclaim.

## LLM08 Hidden Context Exposure: discoverable by design

OWASP's guidance is to assume hidden context is discoverable and to design so its disclosure has little or no security impact. The recall digest, injected at every session start, is hidden context in exactly OWASP's sense: non-user-facing operational content placed in the model's context.

loxodonta's answer is to sit deliberately at the bottom of LLM08's severity ladder, the informational tier: no secrets, no security-relevant logic, no reliance on confidentiality.

- Receipts are secret-free by spec (§8) and capped one-line summaries, so the digest can only reveal what tool activity looked like, never credentials or content.
- Nothing consumes the digest as authority. It is recall, not instruction: it owns no verdicts, cites the last scan as testimony, and no security decision anywhere in the design depends on its contents staying hidden.
- The dashboard never leaves the machine: `serve` is localhost-only.

One deliberate disclosure remains, and it is documented rather than hidden: a digest row reveals that recording is happening and what was recently done on this repo. A repo can keep its rows out of cross-repo surfaces with an `.unlisted` marker, which the glossary is explicit about: an output-rendering courtesy, not a security boundary.

## What loxodonta is not

Stated once, without hedging. Overclaiming is the one failure mode a document like this cannot afford:

- **Not a security boundary.** Nothing is prevented. A compromised agent can still act; loxodonta shortens the time until someone knows.
- **Not prevention of prompt injection or excessive agency.** It is the damage-limitation and forensic layer OWASP files under exactly that heading.
- **Not authenticated provenance.** There are no keys (ADR-0001). Writer-supplied fields are testimony, trusted for nothing; verdicts come only from what the verifier recomputes, and they name mechanisms, never conclusions.
- **Not completeness by itself.** The chain proves integrity of what was logged; a call that never fired the hook leaves no break. Completeness comes from the integration (the hook, `run`) and is judged by the supervisor's witness against the coverage in force at the time.
- **Detection latency only; the anchor is the only hard boundary.** Every layer on the machine is writer-reachable and says so. Once a head is anchored, no rewrite on the machine can fake that record or its timestamp. That is the one claim that survives an arbitrarily capable local adversary, and it is the only one.

## Sources

- [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), entry texts as published in the [project repository](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final). Quoted mitigation lines: LLM03 #8, LLM05 #8, LLM06 #8.
- Repo-side grounding: [SPEC](SPEC.md) §2 and §8; [ADR-0001](../adrs/0001-hash-chain-not-signatures.md), [ADR-0002](../adrs/0002-writer-as-adversary.md), [ADR-0016](../adrs/0016-coverage-goes-wide.md); [.out-of-scope/001](../.out-of-scope/001-outcome-capture-in-hook.md).
