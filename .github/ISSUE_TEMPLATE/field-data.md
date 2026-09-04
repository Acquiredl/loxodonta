---
name: Field data
about: Send back what the recorder saw on your machine (supervisor export)
title: "field-data: <os> / <N> sessions / <YYYY-MM-DD>"
labels: field-data
---

<!-- `python supervisor.py export --send` fills this in for you. If you are
     filing by hand, paste the link to your secret gist below and copy the
     `redaction` block from the top of the export file. -->

**Export:** `<gist link>`

**What the export says it removed:**

```
<the redaction block, verbatim>
```

**Harness(es) recorded:** claude-code / codex / openai-agents / other

**Anything that surprised you** (a verdict you did not expect, a session that
looks wrong, a count that does not add up): optional, but this is the part
that teaches the most.

---

- [x] The export was built by the tool's allowlist; I did not edit it by hand.
- [x] I read the export before sending it and I am fine with it being public
      in this issue and in `docs/FIELD-DATA.md`.
- [ ] *(raw bundles only)* I ran `export --raw`, read the sample action line
      it showed me, and answered yes.
