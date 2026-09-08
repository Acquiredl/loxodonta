# The package: one session, sealed by a manifest, verified by one file

**Status:** accepted 2026-09-08 (ADR-0026, applying ADR-0007 and ADR-0008 to loxodonta's own store). This page specifies the package format `loxodonta-package/1` and the verifier's ladder. The receipt format of `docs/SPEC.md` (v0.1) is untouched: a chain inside a package is a chain, judged by the same walk.

## 1. What a package is

The evidence lives in the store on the machine that wrote it. To show it to someone who was never on that machine, the operator sends a **package**: the chains of one session with their anchor sidecars, the drawer's project record, a witness snapshot labelled testimony, a plain-words README, and last of all a **manifest** listing everything before it. The recipient downloads `loxodonta.py`, the same file that verifies a bare chain, and runs one command on the zip. It answers layer by layer, the recorder's own verdicts verbatim, and ends with the package verdict and one line of residual trust.

A package confirms that it is unaltered since packaging. It never confirms that the record inside is true or complete: a harness that lied at write time ships faithfully packaged lies (ADR-0002, ADR-0026). Without a seal it cannot say when the set existed either, and its ceiling verdict says so in as many words.

The GLOSSARY's words apply exactly: *package*, *manifest*, *seal*, *issuer*, *recipient*, *testimony*. It is not called a bundle, so the concept keeps one name; the field-data export's `--raw` zip is a *raw archive*, a different thing with no manifest (ADR-0026 ruling 9).

## 2. Building one

```
supervisor package <session-id | entry-address> [--out PATH] [--folder] [--witness DIR]
```

The selector is a session id, or any entry address inside the session, resolved with the same rules `show` and `verify ADDRESS` use (any unambiguous prefix; an ambiguous one lists the candidates). Either way the whole session is packaged, sibling chains included, so the two selectors write the same package. The store is searched as a whole; the current directory does not matter.

By default the package is a zip in the current directory, `loxodonta-package-<session>.zip`; `--out` names another file, and `--folder` writes an unpacked folder instead (with `--out`, that folder). An existing path is never overwritten.

The scan underneath is one ordinary supervisor tick over the store, as `export`'s is: its completeness row for the session and its verdicts are what `witness.json` carries. `--witness` points it at the harness transcript layout, as for `scan`.

Assembly follows ADR-0007's write order, and `supervisor package` honors it or the package is unverifiable: the chain snapshot and sidecars first, then `project.json`, then `witness.json`, then `README.md`, then `manifest.json`. The zip keeps that member order, so the manifest is the last member too.

Not built in this slice, each its own later slice: a drawer as the unit (`digest --repo`'s selection), `--transcript` (the harness transcript, on request only, because it can hold the very secret a bad day exfiltrated), and the two seals, `--anchor` and `--sign`. A session whose chains sit in two drawers (possible before ADR-0023) is refused rather than flattened: the layout puts every chain beside one project record.

## 3. What is inside

Flat, like a drawer, so the recorder's own rules apply to the chains unchanged:

| File | What it is | Listed in the manifest by |
|---|---|---|
| `receipts-<session>.jsonl`, `receipts-<session>-002.jsonl`, ... | the session's chains, byte for byte, siblings in sequence order (ADR-0004) | head and entry count |
| `receipts-<session>.jsonl.anchors.jsonl` | a chain's anchor sidecar, when the drawer has one (docs/ANCHORING.md §2) | sha256 and byte count |
| `project.json` | the drawer's project record: the project's absolute path on the recording machine (ADR-0012) | sha256 and byte count |
| `witness.json` | the supervisor's completeness row for the session and the verdict its scan gave each chain, labelled testimony in the file | sha256 and byte count |
| `README.md` | plain words: what is inside, how to verify, what each layer shows and does not; prints the chain heads, never the manifest's hash | sha256 and byte count |
| `manifest.json` | the list of everything above, written last | it is the sealing surface; nothing lists it |

Never inside: file contents. The tool holds fingerprints of the files the agent touched, not their bytes, and cannot produce the logged version. On the recipient's machine the project record points nowhere, so `verify --files` on a packaged chain says `FILES-UNRESOLVED` (ADR-0012), and `verify-package` says the same thing once, in plain words.

## 4. The manifest

`manifest.json`, one JSON object, written last:

| Field | Meaning |
|---|---|
| `format` | `"loxodonta-package/1"`. The verifier refuses any other tag (`UNSUPPORTED-FORMAT`). The receipt format inside stays `0.1`. |
| `packed` | when the package was assembled, UTC. Testimony. |
| `tool` | which supervisor packed it, e.g. `"loxodonta supervisor 0.2.0"`. Testimony. |
| `unit` | `{"kind": "session", "session": "<id>", "project": "<drawer name>"}`. Displayed convenience; testimony. |
| `chains` | one row per chain, in the package: `path`, `head` (the last entry's `entry_hash`), `entries` (line count), `anchors` (the sidecar's file name, or `null`). |
| `artifacts` | one row per post-close artifact: `path`, `sha256` of its bytes, `bytes`. Sidecars, `project.json`, `witness.json`, `README.md`. |
| `seals` | the seals the package should carry. `[]` in this format's first slice; `"anchor"` and `"signature"` join when `--anchor` and `--sign` do. A declared seal that is absent is `SEAL-MISSING`, never a silent downgrade (ADR-0007). |

Why two ways of listing (ADR-0026 ruling 3). A chain's head is already its commitment, and the verifier recomputes it by walking; listing chains by file hash would add a second commitment to the same fact, and a false one on Windows, where `read_log` splits lines tolerantly and an unzip that turns `\n` into `\r\n` changes the bytes without changing the head. The post-close artifacts have no chain to commit them, so the manifest's sha256 is their only commitment: one commitment home per fact.

Why the README never prints the manifest's hash (ADR-0007 ruling 2). The manifest lists the README, so the README is written first, and nothing may point at what is sealed last; a README that carried the hash would be a cycle. The README may print the chain heads and the session id, which exist before it does.

## 5. Verifying

```
loxodonta verify-package PATH        # a zip, or an unpacked folder
```

A zip is unpacked into a temporary folder and judged there. A folder is judged as it stands; if the recipient re-zipped the folder rather than its contents, the single subfolder holding the manifest is found. The output, in this order (ADR-0026 ruling 5):

1. **The manifest's summary**: `package`, `format`, `packed ... (testimony)`, `unit`, `contents`, and which seals are declared.
2. **Each chain**, headed `chain: <name> (manifest: head <12 hex>…, N entries)`, followed by the recorder's own `verify --anchors` output verbatim, the same lines `supervisor verify ADDRESS` prints on the machine. Anchor lines appear here as detail: `ANCHORED`, `ANCHOR-PENDING`, `NO-ANCHORS`, or a mismatch. Then the walked head and line count are compared with the manifest's row; a difference is reported as `<name>: off the manifest`.
3. **File references**: `file references: N recorded, not checkable off the machine`, counted across the chains.
4. **Each artifact** against the manifest: `<name>: matches the manifest (sha256 <12 hex>…, N bytes)`, or `DIVERGED from the manifest` with both digests, or `MISSING`. The `witness.json` line adds `(testimony: the packing machine's reading, unaltered; no verdict is drawn from it)`. Files in the package the manifest does not list print as `unlisted: <name> (not in the manifest, not judged)`.
5. **The package verdict**, in ADR-0007's words, and for `SELF-CONSISTENT` one closing line of **residual trust**.

The verifier reads `witness.json` for its bytes only. Its state, its counts, and the scan's verdicts inside are the supervisor's reading on the packing machine, and they change nothing in the ladder: a package whose witness says `ALARM-SILENT` and a package whose witness says `COMPLETE` verify identically. That is the meaning of *testimony* here, and the output says so where the file is judged.

### The ladder

Verdicts name the mechanism, never the conclusion (no "authentic", no "verified": GLOSSARY, Anti-terms). Gravest wins: a refusal, then a broken chain, then an anchor that is not this chain's history, then a transcript that no longer holds, then an artifact off its manifest.

- `SELF-CONSISTENT`: every chain walks clean and every artifact matches the manifest. Printed with its limit: *indistinguishable from a wholesale regeneration, since no seal is declared*. A regenerated session, packed afresh, produces this same line; only a seal can separate the two, and this slice declares none.
- `CHAIN-BROKEN`: a chain does not walk clean. The recorder's `BROKEN at entry N` lines above say where.
- `ARTIFACT-DIVERGED`: an artifact's bytes differ from the manifest's listing, an artifact or a chain the manifest lists is missing, or a chain walks to a head or a length other than the one listed (the chain is then an artifact off its manifest; a truncated chain walks clean and is caught here).
- `ANCHOR-MISMATCH`: an anchor packaged with a chain names a head that is nowhere in that chain, or a proof that does not replay; the chain's own `ANCHOR-MISMATCH` or `ANCHOR-INVALID` line above says which. Not the anchored history.
- `TRANSCRIPT-DIVERGED`: a chain's transcript commitments contradict each other (`COMMITMENT-SHRANK`). Judging commitments against a packaged transcript is the `--transcript` slice.
- `UNSUPPORTED-FORMAT`: a refusal, not a verdict. The manifest is missing or unreadable, or its `format` is a tag this verifier does not speak. Nothing else is judged or printed.

## 6. Exit codes

Mapped onto `verify`'s own (ADR-0026 ruling 7), so a script that reads those learns nothing new:

| Exit | Package verdict | `verify`'s twin |
|---|---|---|
| 0 | `SELF-CONSISTENT` (with or without `+ ANCHORED` / `+ SIGNED`, when the seal slices land) | `VALID` |
| 1 | `CHAIN-BROKEN` | `BROKEN` |
| 2 | `ARTIFACT-DIVERGED` | `FILES-DIVERGED`, its package sibling per ADR-0007 |
| 3 | `SEAL-INVALID`, `SEAL-MISSING` (seal slices), a chain's `ANCHOR-MISMATCH` (built) | `HEAD-MISMATCH`: not what was issued |
| 4 | `UNSUPPORTED-FORMAT`, a refusal | `UNSUPPORTED-VERSION` |
| 5 | `TRANSCRIPT-DIVERGED` | `TRANSCRIPT-DIVERGED` |

Usage errors are to exit `64` (sysexits `EX_USAGE`) in both tools, so a verdict exit is never an argparse error; that renumbering is its own slice, and until it lands the README's advice stands: read the verdict line, not the code alone.

## 7. Worked example: the bad-day session

The demo store (`python tools/demo_store.py --home <dir>`) holds a session that reads an injected page, reads `.env`, posts it off the machine, and switches the recorder off (`docs/demo/bad-day-session.jsonl`). Packaged and verified on a machine that is not the one that recorded it:

```
$ python supervisor.py package b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907 --folder
written: loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907 (session b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907, 1 chain(s), 5 files)
verify: python "loxodonta.py" verify-package "loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907"

$ python loxodonta.py verify-package loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907
package: loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907
format: loxodonta-package/1
packed: 2026-09-08T22:19:08Z by loxodonta supervisor 0.2.0 (testimony)
unit: session b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907, project todo
contents: 1 chain(s), 3 artifact(s), seals: none declared
chain: receipts-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907.jsonl (manifest: head 751d054dfeff…, 6 entries)
NO-ANCHORS: loxodonta-package-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907/receipts-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907.jsonl.anchors.jsonl not found — anchoring is optional; run `loxodonta anchor` to add one
VALID
file references: 1 recorded, not checkable off the machine
project.json: matches the manifest (sha256 1bcb3a94da77…, 152 bytes)
witness.json: matches the manifest (sha256 86d42238052e…, 900 bytes) (testimony: the packing machine's reading, unaltered; no verdict is drawn from it)
README.md: matches the manifest (sha256 78fa5f2c4c92…, 2928 bytes)
SELF-CONSISTENT: every chain walks clean and every artifact matches the manifest; indistinguishable from a wholesale regeneration, since no seal is declared
residual trust: this package is unaltered since it was packed. That the record inside is true and complete, and that it existed before today, rests on the issuer's word alone, since no seal is declared.
```

Exit 0. Read it as a recipient would. The chain walks clean: the six entries, `Read: .env` and the `curl` that posted it included, are the ones the recorder wrote, in order, unedited since. The one file reference is the fingerprint of `.env` as the agent saw it; the file is not here and cannot be checked. The witness says `UNWITNESSED` in this build, because the demo store has no transcript layout; on the operator's machine it would say what the completeness alarm said, and either way the verifier repeats it without judging it. And the last two lines state what remains: nothing here changed since it was packed, and nothing here says the set existed before today, because no seal was declared.

The manifest the verifier judged against:

```json
{
  "format": "loxodonta-package/1",
  "packed": "2026-09-08T22:19:08Z",
  "tool": "loxodonta supervisor 0.2.0",
  "unit": {"kind": "session", "session": "b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907", "project": "todo"},
  "chains": [
    {"path": "receipts-b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907.jsonl",
     "head": "751d054dfefff992437ec1e9ff7f326b0cc5d745cd60097a98c3421a7cc0555e",
     "entries": 6, "anchors": null}
  ],
  "artifacts": [
    {"path": "project.json", "sha256": "1bcb3a94da77…", "bytes": 152},
    {"path": "witness.json", "sha256": "86d42238052e…", "bytes": 900},
    {"path": "README.md", "sha256": "78fa5f2c4c92…", "bytes": 2928}
  ],
  "seals": []
}
```

(Digests shortened here; the file carries all 64 hex characters.) Three edits, and what the ladder says of each: change a word in `witness.json`, and the artifact line reads `DIVERGED from the manifest`, verdict `ARTIFACT-DIVERGED`, exit 2, while the chain still says `VALID`; change a character inside an entry of the chain, and the recorder's `BROKEN at entry 3` appears verbatim, verdict `CHAIN-BROKEN`, exit 1; rewrite the chain with `\r\n` line endings, as a Windows unzip may, and nothing changes, still `SELF-CONSISTENT`, because the head is recomputed by walking.

## 8. What none of this survives

- **Garbage in.** The package is unaltered since packaging. Whether the recorder was told the truth, and whether every tool call got its receipt, is the harness's and the witness's word (SPEC §8, ADR-0002).
- **No seals.** `SELF-CONSISTENT` alone is what a wholesale regeneration also produces. The anchor lines under a chain speak for that chain and say when its head existed; the package as a set is on record only from its own seals, which this slice does not yet write.
- **The transcript.** Commitments in the chain bind the harness transcript only while it exists, and the transcript is not in this package. `--transcript`, when it lands, is the only thing that keeps it.
- **File contents.** Paths and fingerprints travel; files do not.
- **The recipient's own job.** The verifier prints a merkle root under an anchored chain; confirming it against a block source they trust is theirs (ADR-0003), as comparing a key fingerprint out of band will be when `--sign` lands (ADR-0008).
