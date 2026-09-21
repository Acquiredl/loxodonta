# Grounding: the published work this design stands on

A design argued from analogy is an opinion. This page ties each
load-bearing choice in loxodonta to published research, a standard, or a
rule of evidence, and says where the tie is direct, where it is only an
analogy, and where nothing was found.

**Method.** Four research passes on 2026-09-21. Every source below was
checked at its primary location that day, and the passage relied on was
read, unless the entry says otherwise. Section 7 lists what could not be
verified, and nothing in this page rests on it. Sources are paraphrased
with a pointer to the section relied on. A few titles contain a word this
repo's vocabulary refuses ([GLOSSARY](../GLOSSARY.md), *Anti-terms*); those
works are cited by author, venue, year and identifier.

## 1. Lineage

The design is a keyless hash chain whose head is committed, from time to
time, somewhere the writer cannot reach. That is a published design, and
an old one.

- Haber and Stornetta (1991) introduced linking: each time-stamped record
  carries a digest of the one before it.
- Bayer, Haber and Stornetta (1993) added the two pieces loxodonta uses:
  a widely witnessed public record as the place a digest is committed
  (section 3), and local linear linking with periodic summary values sent
  out to a service (section 5).
- Crosby and Wallach (2009) give the threat model: a logger that is
  untrusted from the start. Their section 2.4 separates that model from
  forward integrity, which assumes a logger that is honest until it is
  compromised and protects what it wrote before.

So this project's family is the first one, and it should not borrow the
second family's words. The keyed, forward-secure line (Bellare and Yee,
1997; Schneier and Kelsey, 1999; Ma and Tsudik, 2009) rests on a secret
that is erased as the log grows. loxodonta holds no secret (ADR-0001), so
it can claim none of what that secret buys.

## 2. What the design can claim, and what it cannot

**It can claim**

- Tamper-evidence, in the sense of Crosby and Wallach and of Bayer, Haber
  and Stornetta, for the part of a chain covered by a commitment held off
  the machine.
- A bound on time: a chain with that head existed by the time of the
  commitment.

**It cannot claim**

- **Forward integrity, or forward-secure stream integrity, for entries
  after the last commitment.** With no erased secret the writer can
  recompute everything since (Bellare and Yee, section 1; Ma and Tsudik,
  section 1).
- **Resistance to a cut tail where no published head exists.** Bellare
  and Yee saw in 1997 that an attacker can erase a suffix (section 2.3).
  Ma and Tsudik named the truncation attack, and noted that a remote
  verifier misses it unless it knows how long the log should be (section
  2.2). Schneier and Kelsey observe that a crash and a truncation look
  alike without a closing record (section 4.1). Here the closing record is
  the session-end commitment, its absence is the *uncommitted tail*
  annotation, and the [published head](../GLOSSARY.md#published-head) is
  what tells a verifier how long the chain was.
- **Protection at the moment of the call.** Paccagnella and others (CCS
  2020) removed events from buffers before they were committed, and their
  remedy commits inside the control path, before the process proceeds.
  Ahmad, Lee and Peinado (IEEE S&P 2022) bound the unprotected window at
  15 ms and report that an attacker needs a few hundred. A hook that
  fires after the call is asynchronous protection by construction. The
  matching remedy is a record written before the action runs, which this
  project declines before 1.0 ([DIRECTION.md](DIRECTION.md) section 6).
- **Who wrote it.** A time-stamp shows when and that nothing changed, and
  not who asked for it (Buldas and others, 2014, section 5.1).
- **Anything about entries written after a compromise** (Schneier and
  Kelsey, section 1).

**On how often to commit.** No source gives a number. Ma and Tsudik make
security a function of how often the logger reaches its verifier. Buldas
and others close a block on a count of records or on a time limit,
whichever comes first, so a quiet period leaves nothing uncommitted. RFC
6962 publishes a maximum delay and treats a breach of it as misbehaviour.
Bowers and others (RAID 2014) add heartbeats and a gap check, and Dörre
and Ottenhues (ACNS 2025) found a real truncation bug in a shipped system
and fixed it by sealing every epoch, the empty ones included.

**On being read.** Crosby and Wallach state it outright in section 2:
tamper-evidence requires auditing, and a log that is never examined
detects nothing. Paccagnella and others (NDSS 2020) add that the more
often a log is audited, the sooner tampering is found. This is the
grounding for the supervisor's audit function, for the day book's count
of unread days, and for the recipient.

**On `fsync`.** The literature is silent. Blass and Noubir (2023) size
their crash tolerance to the expected loss of cached writes, which is the
nearest thing to guidance found.

## 3. Completeness: what was never written

A hash chain shows that what was logged was not changed. It cannot show
that everything was logged. Hash-chained provenance, by itself, does not
address omission: an attacker can decline to write, or disable the
library (Bates and others, USENIX Security 2015, on earlier schemes).

**Auditing theory has a name for the property and a method for it.**
Completeness is one of the assertions an auditor tests: everything that
should have been recorded was (ISA 315 (Revised 2019), paragraph A190;
PCAOB AS 1105, paragraph .11). It is tested by direction: start from the
underlying documents and follow them into the ledger, because testing the
recorded items says nothing about the missing ones (ISA 500, paragraph
A27). Reconciliation between records is a named control for it (ISA 315,
appendix 3, paragraph 20).

That is the [witness](../GLOSSARY.md#witness): `verify` tests what is in
the chain, and the witness starts from a [second record](../GLOSSARY.md#second-record)
of the session and follows each tool event to its receipt.

**The comparison source is graded, not excluded.** The standards do not
require it to be independent of the party under audit. Independence raises
its reliability (ISA 500, paragraph A31; AS 1105, paragraph .08), and
evidence from inside is admitted and weighed by the controls over it (AS
1105, paragraph .10). This is why a second record's **reach** is a stated
property and not part of its definition.

**What the assurance is conditional on.** In PeerReview (Haeberlen,
Kuznetsov and Druschel, SOSP 2007) a witness is an active party that
collects and audits a node's log. Omissions surface because the
counterparty holds its own signed record of each message, and the result
holds only while at least one of the node and its witnesses is correct.
Crosby and Wallach assume at least one incorruptible auditor. Every
formal result found rests on a correct party the adversary cannot reach.
A second record on the writer's own machine therefore supports no
assurance against the writer. It catches faults: the disabled hook, the
wedged lock, the silent fork. The glossary says so, and so must every
surface that shows a count.

**How security frameworks treat it.** As an operational control. NIST SP
800-53 control AU-5 requires an alert when the logging process fails,
with real-time alerting as an enhancement; PCI DSS v4 requirement 10.7.2
lists the logging mechanisms among the failures that must be detected;
NIST SP 800-92 (section 5.1.3) says to decide how a source behaves when
logging fails, and notes that a second copy lets a responder see what was
changed or removed. None of them asks for a cryptographic way to find a
gap. The completeness alarm is an AU-5-style control for agent logs.

**The open gap.** As of 2026-09-21 no published mechanism was found that
reconciles an agent's log against an independently produced second record
of the session. The work that names the problem of actions never logged
leaves it open: the "Agent Flight Recorder" preprint (arXiv 2609.01931),
and two individual Internet-Drafts, `draft-sharif-agent-audit-trail-04`
and `draft-kuehlewind-audit-architecture-01`. They are cited here once,
for that, and nowhere else in this repository.

## 4. What a recipient needs

- **Five properties.** RFC 3227 (section 2.4) asks that evidence be
  admissible, authentic, complete, reliable and believable. Complete is on
  that list.
- **An examination someone else can repeat.** The ACPO Good Practice
  Guide's third principle wants a record of the process such that an
  independent third party could examine it and reach the same result
  (version 5, section 2.1). RFC 3227 (section 3.1) wants methods that are
  transparent and reproducible. ISO/IEC 27037 separates repeatability
  from reproducibility, the second meaning a different machine and a
  different operator, and defines a digital evidence copy as the evidence
  together with its means of verification. That is a package handed over
  with one verifier file.
- **A small, testable method, by analogy only.** Anderson (1972, section
  3.2.2) requires of a reference validation mechanism that it be tamper
  proof, that it be invoked every time, and that it be small enough for
  analysis and tests whose completeness can be assured. Saltzer and
  Schroeder (1975) name economy of mechanism, and warn, under compromise
  recording, that a record of tampering kept inside the system can be
  undone by a clever attacker. ISO/IEC 27041 favours methods built from
  small parts. All three speak of enforcement mechanisms and forensic
  methods, not of log verifiers. They support ADR-0035 by analogy, and
  none of them asks for a single file.
- **Rules of evidence.** Under the United States Federal Rules of
  Evidence, 902(13) and 902(14) let a machine-generated record or a copy
  identified by hash authenticate itself, on a qualified person's
  certification and with notice; they settle authenticity and nothing
  else. The Daubert factors govern expert testimony, so they bear on a
  verifier once an expert vouches for it: a published method that can be
  tested is what that expert needs.
- **Readiness comes first.** Forensic readiness is preparation before the
  incident by definition (Rowlingson, 2004; ISO/IEC 27043), and NIST SP
  800-86 warns that turning auditing on afterwards may alter evidence.
  This is the limit the project accepts: the recorder has to be there
  before the day it is needed.
- **Two kinds of time-stamp.** In the European Union only a qualified
  electronic time-stamp carries a presumption that its date and time are
  accurate (Regulation 910/2014, article 41(2)); any other gets
  non-discrimination and nothing more (article 41(1)). An anchor most
  plausibly falls under the second, which is an inference and no court's
  holding, and no ruling or statute found names OpenTimestamps. That
  matches ADR-0032: the [authority timestamp](../GLOSSARY.md#authority-timestamp)
  sits beside the anchor as a different kind of evidence, and neither is
  the other.
- **The writer the frameworks had in mind.** NIST SP 800-53 AU-9(4) warns
  that privileged users who are themselves audited may inhibit auditing
  or modify records; AU-9(2) wants storage on a separate system; PCI DSS
  v4 requirements 10.3.2 to 10.3.4 want protection from modification and
  prompt copies elsewhere. Every one of them assumes a human
  administrator. None contemplates an autonomous agent as the writer of
  its own log, which is the case ADR-0002 is about.

## 5. Agent logs in research and standards

- **What to record.** Chan and others (FAccT 2024) define activity logs as
  records of certain inputs and outputs of an agent, and treat detail as
  a trade against cost and privacy. OpenTelemetry's conventions for
  generative AI require only the tool's name on a tool-call span and make
  arguments and results opt-in, because they may be sensitive. AIUC-1
  control E015.2 asks for parameters and results. loxodonta records the
  minimal line, and commits the rich record by reference.
- **Integrity is asked for.** OWASP's agentic threat T8, repudiation and
  untraceability, and entry ASI10 of its 2026 top ten ask that agent logs
  be signed and protected from change. The IETF's working-group draft on
  identity for AI agents (`draft-ietf-wimse-aims-00`) says records must be
  tamper-evident. AIUC-1 E015.4 asks that they be tamper-evident and
  independently verifiable. The European Union's AI Act (articles 12, 19
  and 26(6)) requires automatic logs kept at least six months and asks
  nothing about their integrity; its high-risk obligations now apply from
  2 December 2027 (Regulation 2026/1744).
- **What a layer like this would be expected to speak.** The IETF's SCITT
  architecture (RFC 9943) and COSE receipts (RFC 9942), both Proposed
  Standards since June 2026, are the most mature. OpenTelemetry's
  generative-AI spans are at Development status with no stable release.
  The Model Context Protocol says only that a client should log tool
  usage.

## 6. Words that mean something else elsewhere

- **Receipt.** In RFC 9943 a receipt is a signed proof, issued by a
  transparency service, that a statement was registered. Here a receipt
  is an [entry](../GLOSSARY.md#entry): one line the recorder wrote,
  signed by nobody.
- **Witness.** In the transparency-log community a witness checks that a
  log's new checkpoint is consistent with the one it saw before, and
  cosigns it (C2SP, `tlog-witness`). Here the witness is the supervisor's
  role of counting receipts against a second record. The nearest thing
  here to a transparency-log witness is the [receiver](../GLOSSARY.md#receiver).

## 7. Not verified

Nothing above depends on these.

- Read as an abstract, a preview or a catalogue entry only: ISO/IEC 27037,
  27041, 27042, 27043 (clause bodies are paywalled; the four handling
  principles of 27037 clause 5.3 are known here from secondary sources
  only); Holt (2006); Hartung (2017); Accorsi (2009).
- From secondary sources only: the official wording of PCI DSS v4; ISO/IEC
  27002:2022 control 8.15; ISO/IEC 42001:2023 control A.6.2.8.
- Found by search and not read: Knight and Leveson (IEEE TSE, 1986), whose
  reported caution is that independently produced versions do not fail
  independently.
- Status only: ISO/IEC 24970 on AI system logging, at final ballot since
  28 August 2026; NIST SP 800-92 revision 1, an initial public draft since
  October 2023.
- No authoritative passage was found for the textbook terms *tracing* and
  *vouching*. The standards say *direction of testing*.
- No peer-reviewed survey of cryptographic secure-logging schemes from
  2018 to 2026 was found.

## 8. Sources

**Secure logging**

- Haber and Stornetta, "How to Time-Stamp a Digital Document", CRYPTO '90;
  J. Cryptology 3(2), 1991, doi:10.1007/BF00196791.
- Bayer, Haber and Stornetta, "Improving the Efficiency and Reliability of
  Digital Time-Stamping", *Sequences II*, Springer, 1993, pp. 329-334.
- Bellare and Yee, UCSD technical report on forward integrity, 23 November
  1997.
- Schneier and Kelsey, ACM TISSEC 2(2), 1999, pp. 159-176.
- Ma and Tsudik, "A New Approach to Secure Logging", ACM TOS 5(1), 2009;
  ePrint 2008/185.
- Crosby and Wallach, "Efficient Data Structures for Tamper-Evident
  Logging", USENIX Security 2009, pp. 317-334.
- Buldas, Truu, Laanoja and Gerhards, NordSec 2014, pp. 149-164; ePrint
  2014/552.
- Bowers, Hart, Juels and Triandopoulos, "PillarBox", RAID 2014; ePrint
  2013/625.
- Paccagnella and others, "Custos", NDSS 2020,
  doi:10.14722/ndss.2020.24065.
- Paccagnella, Liao, Tian and Bates, "Logging to the Danger Zone", CCS
  2020, pp. 1551-1574.
- Ahmad, Lee and Peinado, "HardLog", IEEE S&P 2022.
- Blass and Noubir, "Forward Security with Crash Recovery for Secure
  Logs", ACM TOPS 27(1), 2023; ePrint 2019/506.
- Dörre and Ottenhues, "Security Analysis of Forward Secure Log Sealing in
  Journald", ACNS 2025; ePrint 2023/867.
- RFC 6962 and RFC 9162 (Certificate Transparency, both Experimental); RFC
  3161.

**Completeness and accountability**

- Anderson, *Computer Security Technology Planning Study*, ESD-TR-73-51
  vol. I, 1972.
- Saltzer and Schroeder, "The Protection of Information in Computer
  Systems", Proc. IEEE 63(9), 1975.
- PCAOB AS 1105, *Audit Evidence*; IAASB ISA 500, *Audit Evidence*; IAASB
  ISA 315 (Revised 2019).
- Haeberlen, Kuznetsov and Druschel, "PeerReview", SOSP 2007.
- Bates, Tian, Butler and Moyer, "Trustworthy Whole-System Provenance for
  the Linux Kernel", USENIX Security 2015.
- C2SP, `tlog-witness`, c2sp.org/tlog-witness.

**Evidence and standards**

- RFC 3227 (BCP 55), 2002.
- ACPO Good Practice Guide for Digital Evidence, version 5.
- Rowlingson, "A Ten Step Process for Forensic Readiness", IJDE 2(3), 2004.
- NIST SP 800-86; NIST SP 800-92; NIST SP 800-53 revision 5, release
  5.2.0.
- United States Federal Rules of Evidence 901, 902(13), 902(14), 702;
  *Daubert v. Merrell Dow*, 509 U.S. 579 (1993).
- Regulation (EU) 910/2014 and Regulation (EU) 2024/1183.

**Agents**

- Chan and others, "Visibility into AI Agents", ACM FAccT 2024,
  arXiv:2401.13138.
- OWASP, *Agentic AI: Threats and Mitigations*, v1.1, 2025; *Top 10 for
  Agentic Applications 2026*.
- `draft-ietf-wimse-aims-00`, 2026.
- AIUC-1, requirement E015.
- OpenTelemetry semantic conventions for generative AI; the Model Context
  Protocol specification, 2026-07-28.
- Regulation (EU) 2024/1689 and Regulation (EU) 2026/1744.
- RFC 9942 and RFC 9943.
- The three works of section 3's last paragraph.
