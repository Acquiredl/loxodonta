# Rules written twice

`loxodonta.py`, `supervisor.py` and `receiver.py` never import each other (ADR-0035): each is one file a reader can check alone, run from its own source. So a rule two of them need is written in each. This page lists every such rule, a twin: the names it covers, the files it lives in, and why it is written more than once.

The original of every twin is the recorder, `loxodonta.py`, and each copy carries one comment line directly above it that says so. A run of adjacent copies with nothing else in its block shares one line, over its first; any other copy has its own, so a statement without one is not a copy. To change a twin, edit the original in `loxodonta.py`, run `python tools/twin_check.py --write`, which copies it over each copy in place, then `python tools/twin_check.py --check`. When the original lies inside the verifier region, `--write` says so, and `python tools/build_verifier.py` carries it into `verifier.py`. `--write` never adds a copy a file lacks, and never rewrites a copy whose place holds other code (a second statement on its first line, say): it names each and exits 1, leaving that file as it was.

`python tools/twin_check.py --check` fails when a copy differs from its original, when a copy has no line naming its original, when a file no longer defines a name listed here, when this page is stale, when a top-level name is defined in two of the files without being listed here, and when an import binds a name one of the files defines. The suite runs it.

A top-level definition is a function or class, from its first decorator, or an assignment to a name (plain, annotated or augmented, or to an item or attribute of it), at the top of a file or inside a top-level `if`, `try`, `with`, `for`, `while` or `match` block. The check compares the definition's text, not the condition or loop around it, and does not see a name bound as a loop variable, by `with ... as` or `except ... as`, or by `global` inside a function.

This page is written from the list in `tools/twin_check.py` by `python tools/twin_check.py --page`: change the list, then rewrite the page.

## Twins

### The line rule

Names: `split_lines`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Where a line of a chain ends (SPEC section 1, #299): the recorder verifies by it, the supervisor lists and shows chains by it, and the receiver counts the lines of a batch and of the file it keeps by it.

### Escaping receipt text

Names: `NAMED_ESCAPES`, `STEERING_CATEGORIES`, `visible`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder shows receipt text in report, explain and verify's messages, the supervisor on every recall surface, and both must make the same hidden characters visible (#295).

### Which hook entries are the recorder's

Names: `RECORDER_NAMES`, `DIGEST_NAMES`, `WIRED_VERB`, `command_words`, `file_name`, `is_interpreter`, `owned_script`, `beside_a_recorder`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

install-hook and uninstall-hook claim entries by it; the supervisor's scan reads the wired matchers, the SessionEnd wiring and the recorder's path by it (#293, #303).

### The store's address

Names: `store_home`, `project_slug`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

A hook files each chain in its project's drawer, and the supervisor finds the drawer by the same two answers, so one project names one folder (ADR-0011).

### Versions

Names: `TOOL_VERSION`, `FORMAT_VERSION`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

The files ship in one release, whose tag must match the tool version in every file, and each prints both on `--version` (ADR-0022).

### The version line

Names: `checkout_commit`, `version_line`, `VersionAction`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Every file answers `--version` with the same line, tool, format and the commit it sits in, read by local git only and never fetched (ADR-0015, ADR-0022).

### A usage error

Names: `EX_USAGE`, `UsageParser`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

A wrong flag exits 64 from every file, never a number a script could read as an answer (ADR-0026 ruling 7).

### No chain to judge

Names: `EX_NOINPUT`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

`verify` exits 66 when there is no chain to judge, in the recorder and in the supervisor alike (ADR-0037).

### Writing to the console

Names: `speak_utf8`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Every file can print text a Windows console's code page cannot hold, and none of them may die on it (#294).

### The package

Names: `PACKAGE_FORMAT`, `PACKAGE_MAX_BYTES`, `SIGNATURE_NAMESPACE`, `SIGNATURE_PRINCIPAL`, `key_fingerprint`, `bare_name`, `WINDOWS_REFUSED_CHARACTERS`, `WINDOWS_UNZIP_UNDERSCORES`, `landing_name`, `one_file_twice`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The supervisor writes a package and the recorder, and the verifier cut from it, judge one: the format it names, the size it may unpack to, the namespace and principal its issuer signature is made and checked under, the key fingerprint both print, the bare names its manifest may list, and which two names some system opens as one file (ADR-0026, #358).

### Attempt rows

Names: `ATTEMPT_KIND`, `is_attempt`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder notes how a session-end step went in a row of kind `attempt`, and every reader that judges or schedules skips it, the recorder's and the supervisor's alike (#240).

### Reading a sidecar

Names: `read_log`, `sidecar_path`, `published_path`, `KeyGivenTwice`, `object_with_each_key_once`, `not_json`, `read_sidecar_records`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

Where each sidecar lives beside its chain, and how its lines are read: a line that is not a JSON object, past the digit or recursion limit, or not UTF-8, or that a strict parser refuses (a key given twice, NaN or Infinity), reads as unreadable and never stops the reader. The recorder judges by it; the supervisor's scan and keeper report and schedule by it (#299, #331, #344, #365).

### What a sidecar row is

Names: `CHAIN_KIND`, `ANCHOR_KIND`, `STAMP_KIND`, `HEAD_KIND`, `SIDECAR_KINDS`, `UNREADABLE_ROW`, `UNKNOWN_ROW`, `row_kind`, `is_chain_record`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

A row names its kind, a row with none reads as its sidecar's evidence, and a kind unknown there counts for nothing (ADR-0038). The recorder's judges and the supervisor's scan and keeper ask the one answer, so the scan never counts a proof, a token or a sent head that `verify` or `publish` would not (#344).

### Where the chain route left off

Names: `chain_cursor`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The keeper runs the recorder's `publish --chain` only when the recorder's cursor for that remote is behind the chain's end, so both read the memo alike, and a memo neither can read leaves a note rather than a send from genesis (#263, #344).

### Naming a remote

Names: `remote_id`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder writes a fingerprint of the receiver's URL into the publish memo, and the supervisor's keeper compares against it to find where the chain route left off (#263).

### A URL the tools send to

Names: `PUBLISH_SCHEMES`, `SHELL_HAZARDS`, `publish_url`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The supervisor's keeper hands its URLs to the recorder's `publish`, so its flags refuse the URLs `publish` refuses, as a usage error when the flag is given (ADR-0025).

### Written-down coverage

Names: `COVERAGE_NAME`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder writes down the coverage it wired under this name, and the supervisor's scan reads it there (ADR-0030).

### A chain batch's content type

Names: `CHAIN_TYPE`.

Original: `loxodonta.py`. Copies: `receiver.py`.

The recorder sends a batch of the chain under this content type, and the receiver takes a batch only under it (ADR-0031).

## Same name, not a twin

These names are defined in more than one file, and each file means its own thing by it. The check leaves them unjudged.

| Name | Files | Why they differ |
| --- | --- | --- |
| `main` | `loxodonta.py`, `supervisor.py`, `receiver.py` | Each file's own command line. |
| `cmd_verify` | `loxodonta.py`, `supervisor.py` | The recorder's `verify` judges the chain at a path; the supervisor's finds the chain holding an entry address, then prints the recorder's verdict on it. |
| `cmd_serve` | `supervisor.py`, `receiver.py` | The supervisor serves its dashboard and recall; the receiver serves the URL published chains are sent to. |
