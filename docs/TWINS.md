# Rules written twice

`loxodonta.py`, `supervisor.py` and `receiver.py` never import each other (ADR-0035): each is one file a reader can check alone, run from its own source. So a rule two of them need is written in each. This page lists every such rule, a twin: the names it covers, the files it lives in, and why it is written more than once.

The original of every twin is the recorder, `loxodonta.py`. To change a twin, change the recorder's text, then make each copy the same text, docstring included, since the check compares source. `python tools/twin_check.py --check` fails when a copy differs from its original, when a file no longer defines a name listed here, when this page is stale, and when a top-level name is defined in two of the files without being listed here. The suite runs it.

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

### The checkout's commit

Names: `checkout_commit`.

Original: `loxodonta.py`. Copies: `receiver.py`.

The recorder and the receiver print the commit they sit in on `--version` the same way: local git only, never fetched (ADR-0015).

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

Names: `PACKAGE_FORMAT`, `PACKAGE_MAX_BYTES`, `SIGNATURE_NAMESPACE`, `SIGNATURE_PRINCIPAL`, `key_fingerprint`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The supervisor writes a package and the recorder, and the verifier cut from it, judge one: the format it names, the size it may unpack to, the namespace and principal its signature is made and checked under, and the key fingerprint both print (ADR-0026).

### Attempt rows

Names: `ATTEMPT_KIND`, `is_attempt`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder notes how a session-end step went in a row of kind `attempt`, and every reader that judges or schedules skips it, the recorder's and the supervisor's alike (#240).

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
| `chain_cursor` | `loxodonta.py`, `supervisor.py` | Both find where the chain route left off, in different shapes; a twin once #344 gives the supervisor the recorder's. |
| `VersionAction` | `loxodonta.py`, `supervisor.py`, `receiver.py` | Each file's `--version`, the same line in all three, built from each file's own helpers: not a twin, since the supervisor and the receiver hold no `version_line`. |
