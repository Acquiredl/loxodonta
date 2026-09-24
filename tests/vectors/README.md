# Conformance vectors

These are small receipt chains, each with the verdict a verifier must reach on it. They are here so that a second implementation of the format, in any language, can check itself against the same cases `loxodonta.py` and `verifier.py` are held to: an honest chain, each kind of tamper, the tail damage a crash leaves, the lines the walk refuses by name, text that needs escaping, and the head record. The format they test is [docs/SPEC.md](../../docs/SPEC.md), format `0.1`.

## The manifest

[`vectors.json`](vectors.json) lists every vector. Each row has:

- `name`: the row's name.
- `about`: what the chain holds and why the verdict is what it is.
- `args`: the command line, run from inside this folder, so every path in it is relative to here. The chain is named by `--log`.
- `exit`: the exit code expected.
- `last_line` or `last_line_prefix`: the last line of stdout expected, exactly or as its start. An empty `last_line` means nothing is printed on stdout.
- `canonical` (on some rows): `{"entry": N, "text": ...}`, entry N's canonical form (SPEC section 4) written out in full. Its SHA256 is that entry's `entry_hash`, so the bytes to reproduce are stated, not only their hash.
- `log_absent` (on one row): `true` when the file `--log` names is deliberately not in this folder, because a missing log is the case the row tests.

Rows that share a chain name it by `--log`: `valid-chain.jsonl` is run as `verify`, `verify --files`, `head` and with `--expect-head`. `notes.txt` is the file `valid-chain.jsonl` references, and `transcript.txt` is the transcript its commitments cover.

For another implementation, the exit code and the verdict word that starts the line (`VALID`, `BROKEN`, `HEAD-MISMATCH`, `UNSUPPORTED-VERSION`, `TRANSCRIPT-DIVERGED`) are the contract; the rest of the wording is loxodonta's. A `head` row's line is the chain head itself. Exit 1 is `BROKEN` and nothing else (ADR-0037): a log that is missing or empty is no input, exit 66, with nothing on stdout.

A chain whose genesis claims a version the verifier does not speak is walked for its hashes all the same, since the hashing is frozen across versions (ADR-0036): a hash or link that fails is `BROKEN`, exit 1, and only a chain whose hashes all hold is `UNSUPPORTED-VERSION`, exit 4. The `unsupported-version` rows hold both sides of that line.

## Running them

[`tests/test_vectors.py`](../test_vectors.py) runs every row against `loxodonta.py` and against `verifier.py`, and checks that the two give the same exit and the same output.

The chains are written by [`tools/build_vectors.py`](../../tools/build_vectors.py): the honest ones by the recorder itself, with `SOURCE_DATE_EPOCH` pinning the timestamps, and the lines no recorder writes by the script. `python tools/build_vectors.py --check` rebuilds them and fails if any byte differs, and the suite runs that check. Git keeps every file here byte for byte (`.gitattributes`), since a line ending changed on checkout would change a hash.
