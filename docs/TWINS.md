# Rules written twice

`loxodonta.py`, `supervisor.py` and `receiver.py` never import each other (ADR-0035): each is one file a reader can check alone, run from its own source. So a rule two of them need is written in each. This page lists every such rule, a twin: the names it covers, the files it lives in, and why it is written more than once.

The original of every twin is the recorder, `loxodonta.py`, and each copy carries one comment line directly above it that says so. A run of adjacent copies with nothing else in its block shares one line, over its first; any other copy has its own, so a statement without one is not a copy. To change a twin, edit the original in `loxodonta.py`, run `python tools/twin_check.py --write`, which copies it over each copy in place, then `python tools/twin_check.py --check`. When the original lies inside the verifier region, `--write` says so, and `python tools/build_verifier.py` carries it into `verifier.py`. `--write` never adds a copy a file lacks, and never rewrites a copy whose place holds other code (a second statement on its first line, say): it names each and exits 1, leaving that file as it was.

`python tools/twin_check.py --check` fails when a copy differs from its original, when a copy has no line naming its original, when such a line is not directly above a copy, when a file no longer defines a name listed here, when this page is stale, when a top-level name is defined in two of the files without being listed here, and when an import binds a name one of the files defines. The suite runs it.

A top-level definition is a function or class, from its first decorator, or an assignment to a name (plain, annotated or augmented, or to an item or attribute of it), at the top of a file or inside a top-level `if`, `try`, `with`, `for`, `while` or `match` block. The check compares the definition's text, not the condition or loop around it, and does not see a name bound as a loop variable, by `with ... as` or `except ... as`, or by `global` inside a function.

This page is written from the list in `tools/twin_check.py` by `python tools/twin_check.py --page`: change the list, then rewrite the page.

## Twins

### The line rule

Names: `split_lines`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Where a line of a chain ends (SPEC section 1, #299): the recorder verifies by it, the supervisor lists and shows chains by it, and the receiver counts the lines of a batch and of the file it keeps by it.

### Escaping receipt text

Names: `NAMED_ESCAPES`, `STEERING_CATEGORIES`, `visible`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

The recorder shows receipt text in report, explain and verify's messages, the supervisor on every recall surface, and the receiver in the reason it gives for a line it refuses, and all must make the same hidden characters visible (#295).

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

Names: `GIT_TIMEOUT`, `checkout_commit`, `version_line`, `VersionAction`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Every file answers `--version` with the same line, tool, format and the commit it sits in, read by local git only and never fetched (ADR-0015, ADR-0022), and a git that has not answered within `GIT_TIMEOUT` reads as unknown (#572).

### A usage error

Names: `EX_USAGE`, `UsageParser`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

A wrong flag exits 64 from every file, never a number a script could read as an answer (ADR-0026 ruling 7).

### No chain to judge

Names: `EX_NOINPUT`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

`verify` exits 66 when there is no chain to judge, in the recorder and in the supervisor alike (ADR-0037).

### A file the verb must make and cannot

Names: `EX_CANTCREAT`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

A writer exits 73 when a file it must write cannot be, the supervisor's `drill` when its sandbox cannot be made, `package` when it cannot create or finish `--out`, and `calibrate`, `acknowledge` and `export` when the file they write cannot be; the keeper reads a recorder verb's 73 by the same name (ADR-0037, #430, #422, #448).

### What the keepers read from a recorder verb

Names: `EX_UNAVAILABLE`, `EX_TEMPFAIL`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The keepers name each exit of `anchor`, `stamp` and `publish` for what it is, and say a calendar, an authority or a remote did not do what was asked only for 69; 70 is the recorder itself failing, read by the name below, 75 another writer holding the chain's lock (ADR-0037, #557).

### A crash is never a verdict

Names: `EX_SOFTWARE`, `EXIT_READER_GONE`, `reader_gone`, `run_main`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Every file ends through `run_main`: a crash prints its traceback and exits 70, and a reader that hangs up gets a quiet 141, so neither is read as an answer, least of all as 1, the recorder's `BROKEN`, which `supervisor verify` passes on and the scan's ladder counts (ADR-0037, #449).

### Writing to the console

Names: `speak_utf8`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

Every file can print text a Windows console's code page cannot hold, and none of them may die on it (#294).

### The package

Names: `PACKAGE_FORMAT`, `PACKAGE_MAX_BYTES`, `SIGNATURE_NAMESPACE`, `SIGNATURE_PRINCIPAL`, `key_fingerprint`, `bare_name`, `WINDOWS_REFUSED_CHARACTERS`, `WINDOWS_UNZIP_UNDERSCORES`, `landing_name`, `one_file_twice`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The supervisor writes a package and the recorder, and the verifier cut from it, judge one: the format it names, the size it may unpack to, the namespace and principal its issuer signature is made and checked under, the key fingerprint both print, the bare names its manifest may list, and which two names some system opens as one file (ADR-0026, #358).

### Reading a sidecar

Names: `read_log`, `sidecar_path`, `published_path`, `IS_A_FOLDER`, `NOT_REGULAR`, `open_regular`, `file_problem`, `read_sidecar_records`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

Where each sidecar lives beside its chain, and how its lines are read: a line that is not a JSON object, past the digit or recursion limit, or not UTF-8, or that a strict parser refuses (a key given twice, NaN, Infinity or 1e999), reads as unreadable and never stops the reader, and so does a sidecar that is not a file, a folder or a pipe in its place. The recorder judges by it; the supervisor's scan and keeper report and schedule by it (#299, #331, #344, #364, #365).

### A strict JSON reading

Names: `KeyGivenTwice`, `object_with_each_key_once`, `NotStrictJson`, `not_json`, `finite_float`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

A line a strict JSON parser refuses (a key given twice, NaN, Infinity or 1e999) is no row: the recorder and the supervisor read every sidecar line by it, and the receiver refuses a sidecar batch holding one, so the receiver keeps no row the recorder's `verify` would not read (#365, ADR-0045).

### What a sidecar row is

Names: `ATTEMPT_KIND`, `CHAIN_KIND`, `HEAD_KIND`, `SIDECAR_KINDS`, `UNREADABLE_ROW`, `UNKNOWN_ROW`, `row_kind`, `is_chain_record`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

A row names its kind, a row with none reads as its sidecar's evidence, and a kind unknown there counts for nothing (ADR-0038). The recorder's judges and the supervisor's scan and keeper ask the one answer, so the scan never counts a proof, a token or a sent head that `verify` or `publish` would not, and every judge and scheduler skips an `attempt` row alike (#240, #344).

### A sidecar's evidence kinds

Names: `ANCHOR_KIND`, `STAMP_KIND`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

The kind of a proof row and of a token row (ADR-0038): the recorder writes and judges them by it, the supervisor counts them by it, and the receiver takes a sidecar batch only of rows of that kind, or of none (ADR-0045 ruling 5).

### An anchor row's shape

Names: `JSON_TYPE_WORDS`, `json_type`, `anchor_row_problem`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

Every reader asks it of an anchor row before acting on it: the recorder's judges call a row that fails it invalid, and the supervisor's scan counts an anchor row as a departure only when it passes, so the panel never says a head left by a row of the wrong shape (#348, #370).

### A stamp reply's status

Names: `STAMP_STATUS_WORDS`, `STAMP_GRANTED`, `der_element`, `der_expect`, `stamp_status`, `status_word`, `stamp_reply_problem`, `token_granted`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

Whether a stamp row's reply says granted with a token after it, read offline and the token never parsed: `verify --stamps` calls a reply that does not STAMP-INVALID, `stamp` asks about its head again, and the supervisor's scan counts only a granted reply as a departure, so none of them counts a row the others would not (#366, #370). A shape and status reader, not proof replay: judging stays with verify.

### Naming a remote

Names: `remote_id`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder writes a fingerprint of the receiver's URL into the publish memo, and the supervisor's keeper compares against it to find whether the memo says that remote holds the chain's last entry (#263, ADR-0045).

### A URL the tools send to

Names: `PUBLISH_SCHEMES`, `SHELL_HAZARDS`, `publish_url`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The supervisor's keeper hands its URLs to the recorder's `publish`, so its flags refuse the URLs `publish` refuses, as a usage error when the flag is given (ADR-0025).

### Which calendars an upgrade asks

Names: `DEFAULT_CALENDARS`, `DEFAULT_PORTS`, `SHOWN_CALENDAR`, `calendar_key`, `calendars_asked`, `unnamed_calendar`, `shown_address`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

`anchor --upgrade` asks only the default calendars and those it is told, and the supervisor's keeper says on a chain's row which pending proof waits at a calendar the keeper's upgrade does not ask, so both compare and show an address by one rule (#415).

### Written-down coverage

Names: `COVERAGE_NAME`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The recorder writes down the coverage it wired under this name, and the supervisor's scan reads it there (ADR-0030).

### The managed file

Names: `harness_managed_folder`, `managed_hooks_path`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

`install-hook --managed` writes the hook entries to this one file among the harness's managed settings, and the supervisor reads what is wired from the same file, so both name one path (ADR-0040).

### What the environment may say

Names: `MANAGED_READS`, `MANAGED_RUN`, `environment`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

A managed install writes `--managed` on the hook's and the digest's commands, and under it both read no variable but the ones the harness sets, so the store and the managed file they name are the built-in ones (ADR-0043).

### A number from the environment

Names: `number_setting`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

The supervisor and the receiver take a number from their environment only when they can use it, and refuse any other by name with 64 before any verb runs: never a traceback at import, and never a wait longer than a wait can take (#487, #589). The recorder's own knobs fall back to their defaults instead, and it holds the original as it holds every twin's.

### Finding a helper program

Names: `helper_path`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

openssl, ssh-keygen, git, gh and claude run by the full path a walk of PATH finds, never from the working directory, in every file that runs one (ADR-0043 ruling 4).

### A chain batch's content type

Names: `CHAIN_TYPE`.

Original: `loxodonta.py`. Copies: `receiver.py`.

The recorder sends a batch of the chain under this content type, and the receiver takes a batch only under it (ADR-0031).

### A sidecar batch's content type

Names: `SIDECAR_TYPE`.

Original: `loxodonta.py`. Copies: `receiver.py`.

The recorder sends a chain's anchor and stamp rows under this content type, and the receiver keeps them beside its copy of the chain only under it (ADR-0045 ruling 5).

### Canonical form

Names: `canonical_bytes`.

Original: `loxodonta.py`. Copies: `supervisor.py`, `receiver.py`.

SPEC section 4's bytes, frozen across format versions (ADR-0036): the recorder hashes entries by them, the supervisor hashes a call's input by them to compare with a receipt's suffix (ADR-0047), and the receiver recomputes the hash of every line it is sent (ADR-0045 ruling 1).

### What an entry is

Names: `ENTRY_FIELDS`, `GENESIS_FIELDS`, `entry_hash`, `path_leaving_base`, `shape_problem`, `entry_of`.

Original: `loxodonta.py`. Copies: `receiver.py`.

The receiver keeps a line only when it is an entry: SPEC section 2's fields of their types, an n of 0 or more, and an entry_hash that recomputes from the line (ADR-0045 ruling 1). The recorder asks the same of a line of its own chain before it sends it, so it never sends a line the receiver refuses, and names the line it stopped at instead.

### A receipt's suffix

Names: `CALL_ID_CHARACTERS`, `CALL_ID_LONGEST`, `UNHASHED_INPUT`, `is_call_id`, `holds_fraction`, `input_form`, `split_suffix`, `FOLDED_MARK`, `listed_action`.

Original: `loxodonta.py`. Copies: `supervisor.py`.

The hook writes the call's id and a hash of the call's input in SPEC section 4's canonical form at the end of its action line, and the supervisor reads that suffix, setting it aside to name the tool and, in `show`, hashing the transcript's record of the call by the same form to compare; both fold it out of the lines they list for a person and mark each line they fold with the same mark (ADR-0047, #619).

## Same name, not a twin

These names are defined in more than one file, and each file means its own thing by it. The check leaves them unjudged.

| Name | Files | Why they differ |
| --- | --- | --- |
| `main` | `loxodonta.py`, `supervisor.py`, `receiver.py` | Each file's own command line. |
| `cmd_verify` | `loxodonta.py`, `supervisor.py` | The recorder's `verify` judges the chain at a path; the supervisor's finds the chain holding an entry address, then prints the recorder's verdict on it. |
| `cmd_serve` | `supervisor.py`, `receiver.py` | The supervisor serves its dashboard and recall; the receiver serves the URL published chains are sent to. |
| `MANAGED_VERB` | `loxodonta.py`, `supervisor.py` | The verb whose `--managed` sets the bit: the recorder's `hook`, the supervisor's `digest` (ADR-0043). |
