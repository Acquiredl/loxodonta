# ADR-0035: The recipient's verifier is copied out of the recorder, never imported by it (ADR-0005 and ADR-0026 read anew)

**Status:** accepted 2026-09-21 (restate-to-ratify passed)
**Deciders:** Acquiredl

## Context

The direction grill of 2026-09-20 and 2026-09-21 ruled who the project
serves first when its goals pull apart: the recipient, the party across
the trust boundary who checks a package with nothing running. ADR-0002
weighed four purposes and made purpose B, the agent as untrusted writer,
the product; that stays the threat model. The ruling moves purpose C,
third-party proof, from "begins at Stage B" to the person the design
answers to.

What a recipient is handed today is `loxodonta.py`, because ADR-0026
made the recorder the verifier by design and rejected a separate
`verify_bundle.py`: "the recipient already downloads one checksummed
file to verify a chain." That was true of the file as it stood. Since
then it has grown the published chain, the authority timestamp, the
profiles and the attempt records, and it is 4,887 lines. Measured on
`dev` (9695718) over the call graph of its top-level definitions:

- the verify side (`verify`, `verify-package`, `head`) reaches 55
  definitions and 1,398 lines, a third of the file;
- it shares 20 definitions and 195 lines with the record side: the
  format core (`canonical_bytes` and `entry_hash`, six lines), the log
  and sidecar readers, and the OpenTimestamps proof parser;
- it reaches none of the code that publishes, makes anchors or stamps,
  installs hooks, or appends.

So the separation already exists in the code and is invisible in the
file. A recipient reads, or takes on trust, three lines for every one
that judges their evidence.

The standards a recipient works under ask for an examination a third
party can repeat to the same result (ACPO Good Practice Guide v5,
Principle 3; RFC 3227 section 3.1), and ISO/IEC 27037 defines a digital
evidence copy as the evidence together with its means of verification.
Anderson's 1972 study asks that a reference validation mechanism be
"small enough to be subject to analysis and tests", Saltzer and
Schroeder name economy of mechanism, and ISO/IEC 27041 favours methods
built from small parts. Those three speak of enforcement mechanisms and
forensic methods, not of log verifiers, so they apply here by analogy
and no further. None of them asks for a single file.

The obvious shape is a hand-written core that the recorder imports. It
was tested before it was chosen, on CPython 3.13, 2026-09-21. Python
loads an imported module from its bytecode cache when the cache's header
matches the source file's modification time and size, and it never reads
a cache for the script it is asked to run (PEP 3147, PEP 552). With a
two-file layout in a scratch folder, a rewritten cache ran in place of a
source file that was never touched: the source's SHA-256 did not move,
so a checksum, `git status` and the recorder notice (ADR-0015, which
reads the executed file's git state) would all have seen nothing. The
same rewrite aimed at the directly run script changed nothing. On the
operator's machine the writer has the operator's filesystem access
(ADR-0002), and under an imported core the recorder would import it on
every hook call. "The file you hashed is the code that ran" holds only
while nothing is imported, and that is the security content of the
single-file rule ADR-0005 stated as a readability rule.

Prior art consulted, from general knowledge and not from the grill's
verified research passes: **SQLite's amalgamation**, which ADR-0005
already cites (many source files, one generated file shipped, the single
file being an artifact); **`gpgv`**, the verify-only tool GnuPG ships
beside `gpg` so the checking side need not carry the signing side; and
the common practice of **committing generated code and failing CI when
it is stale**, which turns a rule kept by a comment into a rule kept by
a machine.

## Decision

> **`loxodonta.py` stays the single source and is reordered so the format
> core and the verify side are one contiguous region at the top. A script
> in `tools/` copies that region into `verifier.py`, which is committed
> and released beside the other files. CI fails when the committed copy is
> stale, and the conformance vectors run against both files and must
> agree. Nothing imports anything. This is a stage toward modular source
> with single-file artifacts built for release, and this ADR names what
> would start that move.**

Ratified restatement: *we copy the verify part of `loxodonta.py` into a
small `verifier.py`, so a recipient only has to trust the checking code.
We copy it rather than import it because, on the operator's machine, an
attacker can swap what an imported file does without changing the file,
so its checksum still passes. Copying from one source means the two can
never disagree. Later we may split the source into modules and build the
single files from them.*

The shape, as ruled:

- **One source, one home per rule.** The recorder stays a verifier:
  `loxodonta.py verify` and `verify-package` are unchanged, the README's
  six commands still need one file, and the supervisor still drives the
  recorder through its CLI (ADR-0005). ADR-0026's "the recorder is the
  verifier by design" holds for the operator. What changes is what the
  recipient is pointed at.
- **The region is a fence, and the suite holds it.** The verify and
  verify-package tests run against `verifier.py` as well as
  `loxodonta.py`. A verify-side function that reaches below the fence is
  a `NameError` in the copy and a red build, which is the mechanical
  check on the direction of the dependency.
- **Generating answers drift; copying answers the cache.** These are two
  reasons and the docs keep them apart. One source means the recipient's
  verifier and the operator's `verify` cannot differ, and the vectors
  show it. No import means no bytecode cache stands between the file
  that was hashed and the code that runs.
- **The order becomes the reading order.** Format, then the walk, then
  the judges, then everything that writes, sends or installs.
- **What the restructure carries with it.** `verify_log` as the real
  function with `cmd_verify` a thin wrapper, so the package judge stops
  building its own argument namespace (the 2026-09-20 review's item
  1.2); the walk that refuses a duplicate key and a wrong-typed field by
  name, found the same day; and the conformance vectors, which do not
  exist yet.

## Consequences

**What gets easier:**

- The file a recipient must trust shrinks to about a third, around
  1,600 lines with its header and entry point, and holds no code that
  sends, installs or appends.
- A recipient, or an expert vouching for the method, can repeat the
  examination with a published, deterministic file and a set of vectors
  to test it against.
- The verdict logic has one home, so the package judge and `verify`
  cannot drift, which the recall tests pinned by behaviour and the
  layout now holds by construction.

**What gets harder or more constrained:**

- A generator script is now load-bearing, in a repo that had no build
  step. It stays dumb on purpose: it copies a fenced region and a header,
  and understands nothing.
- File order is a constraint. A helper the verify side needs cannot live
  below the fence, however naturally it reads there.
- Two released files answer `verify`. They must be cut from the same
  commit, and `TOOL_VERSION` must agree in both, by test, as it does
  across the three tools today.
- The reorder is a large diff of moved code. It lands alone, as a
  behaviour-preserving change with the suite untouched, before any
  change in behaviour rides the new layout. `docs/TOUR.md` is re-walked
  after it.
- The limits stay the project's own. A checksum detects a changed file
  only against a reference the writer cannot reach, the release page's
  `SHA256SUMS` and not a copy beside the file; nothing here stops a
  writer from editing `loxodonta.py` on the operator's machine. Detected,
  not prevented. The cache finding matters where the writer can reach:
  the recipient's machine is outside it under any layout.

**What we'll have to revisit if:**

- The generator has to understand more than one contiguous region, for
  a second extracted file or a region that will not stay in one piece.
- Keeping the region contiguous starts to hurt how the file reads.
- The list of rules written twice, in the recorder and in the supervisor
  (`project_slug`, `remote_id`, `store_home`, and the constants they
  share), keeps growing. Modular source would give each of them one
  home, built into both artifacts.

Any of these starts the move to the destination this ADR names: source
in modules, single files built from them for release, still importing
nothing at run time.

## Alternatives considered

- **Leave it.** Rejected: the recipient is ruled first, and the file
  they are handed is two-thirds somebody else's business.
- **A fourth file written by hand.** Rejected: either `loxodonta.py
  verify` shells out to it, which puts two files in the quickstart and
  four in the install list, or the verify logic lives twice; and the 195
  shared lines join the written-twice list either way.
- **A hand-written core that the recorder imports.** The textbook shape:
  a small core, the dependency pointing inward, one implementation.
  Rejected for this threat model by the cache test above. It can be
  hardened, and each hardening is an oddity of its own.
- **Modular source with built single-file artifacts, now.** The
  destination, and deferred: it makes a build step load-bearing for every
  test and ends "the file you read is the file you run" for the source,
  in a working project that has been over-built before. Nothing built
  for this ADR is thrown away on the way there.
- **ADR-0026's rejection of a standalone verifier, re-read.** Its reason
  was one checksummed download and a recorder that verifies. Both are
  kept. The recipient still downloads one checksummed file; it is a
  third the size.

## Addendum, 2026-09-23: what running the script directly does and does not buy

The context above says "the file you hashed is the code that ran" holds
only while nothing is imported. That overstates it. The outside review
of v0.8.0 (2026-09-22) found the gap, and it was reproduced here on
CPython 3.13 the next day. A directly run script puts its own folder
first on `sys.path`, ahead of the standard library. A sourceless
`hashlib.pyc` dropped beside `loxodonta.py` was imported in place of the
standard module: the recorder ran code that was in no file anyone
hashed, its SHA-256 did not move, and `git status` showed nothing,
because this repository's own `.gitignore` ignores `*.pyc`. The same
holds for `verifier.py`, and for any module name either file imports.

So the claim is narrower than the context put it. Restated:

- **Keeping nothing imported removes one swap point, not every one.** An
  imported sibling can be swapped through its bytecode cache with its
  source untouched; a directly run script cannot, because Python never
  reads a cache for the script it is asked to run. That finding stands,
  and so does the rule that nothing here imports anything.
- **The checksum covers the file, never the run.** The interpreter, the
  standard library and every folder on `sys.path` are outside it. A
  writer with the operator's filesystem access (ADR-0002) can reach
  some of them on the operator's machine, and nothing in this file
  prevents that. Detected where a check can see it, never prevented.
- **`python -I` takes the script's folder off the path.** Isolated mode
  leaves the script's directory and the user's site-packages off
  `sys.path` and ignores `PYTHON*` variables; it exists in every Python
  the README supports. Under it the shadowing module above was never
  imported. The recipient, who runs `verifier.py` on a machine the
  writer never touched, is told to run it that way. On the operator's
  machine it narrows the gap and does not close it: the standard library
  itself is still within the writer's reach there.
- **Single-file stays, for the reason that holds.** It is kept for
  readability, a recipient reading one file, and for the one swap point
  it does remove. The security content of ADR-0005's rule is that
  narrow sentence, not "the file you hashed is the code that ran".

What this changes in practice goes in the docs a recipient reads
(`python -I verifier.py verify-package PACKAGE`) once `verifier.py` is
the file they are pointed at. Whether the installer should write `-I`
into the hook command it wires is a separate question for the operator's
side (#299).

## References

- Related ADRs: `0002-writer-as-adversary.md` (purposes B and C; the
  writer's reach); `0005-supervisor-as-sibling-tool.md` (single file per
  tool, read here as a security property as well as a readability one;
  `verifier.py` is a fourth file and not a fourth tool);
  `0015-the-recorder-notice.md` (what a cache rewrite would slip past);
  `0020-recorder-adapters-speak-the-hook-contract.md` (adapters are
  imported by the agent program, inside its trust position already);
  `0026-the-store-ships-as-a-package-verified-by-one-file.md` (the
  recorder as verifier, and the rejected third file).
- Verified in the grill's research passes (2026-09-21): Anderson,
  *Computer Security Technology Planning Study*, ESD-TR-73-51 vol. I,
  1972, section 3.2.2; Saltzer and Schroeder, "The Protection of
  Information in Computer Systems", Proc. IEEE 63(9), 1975; ISO/IEC
  27037:2012 and ISO/IEC 27041:2015 (abstracts and free previews only);
  ACPO Good Practice Guide for Digital Evidence v5, section 2.1; RFC
  3227, sections 2.4 and 3.1.
- Python: PEP 3147 (the `__pycache__` directory), PEP 552 (how a cache
  is matched to its source).
- Glossary: *Verifier* is added when the file exists.
- Discussion: the direction grill, 2026-09-20 and 2026-09-21; the code
  review takeaways of 2026-09-20, item 1.2.
