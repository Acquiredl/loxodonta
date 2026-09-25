"""Behavioral tests for the package's first seal (ADR-0026 rulings 4, 6
and 7, applying ADR-0007; #180): `supervisor package --anchor` posts the
manifest's sha256 to the calendars once and writes
`manifest.json.anchors.jsonl`; `loxodonta verify-package` judges that
anchor offline and earns `+ ANCHORED` on the verdict line only from it.

The store is written through `loxodonta hook`, with a completed anchor
on the chain's own sidecar, so every package here carries a chain
anchor that must stay detail and never earn the package rung. The
calendar is test_anchor's fake, so no network, ever. Every test drives
the public CLI as an issuer or a recipient would.
"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_package_anchor`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import (DROP, GENESIS_HASH, GENESIS_HEADER, MALFORMED_ROWS,
                         FakeCalendar, FakeCalendarHandler, block_header,
                         expected_merkle_root, header_hash, replayed_root,
                         start_calendar)
from test_package import (LOXODONTA, SUPERVISOR, PackageCase, completed_anchor,
                          neutral_env, run)

SESSION = "d0d0d0d0-aaaa-bbbb-cccc-000000000001"
SIDECAR = "manifest.json.anchors.jsonl"


class AnchoredStoreCase(PackageCase):
    """The fixture the seal tests share (this file's and the signature's):
    one session, recorded through the hook, its chain head anchored (a
    completed proof in the chain's sidecar); a fake calendar that answers
    pending and can complete on request. No tests of its own."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.witness = self.root / "no-witness"
        self.witness.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        # The neutral home, and no proxy in the way of 127.0.0.1.
        self.env = neutral_env(self.home)
        for command in ("pytest -q", "git status"):
            self.hook(SESSION, "Bash", {"command": command})
        (drawer,) = [p for p in (self.home / ".loxodonta" / "receipts").iterdir()
                     if p.is_dir()]
        self.chain = drawer / f"receipts-{SESSION}.jsonl"
        head = run(LOXODONTA, "head", "--log", str(self.chain)).stdout.strip()
        self.chain.with_name(self.chain.name + ".anchors.jsonl").write_text(
            completed_anchor(head), encoding="utf-8")

        self.server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
        self.server.nonce = b"fake-nonce"
        self.server.prefix = b"left-branch"
        self.server.suffix = b"right-branch"
        self.server.height = 850123
        self.server.mode = "pending"
        self.server.submitted = []
        self.server.polled = []
        self.server.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def hook(self, session, tool, tool_input):
        payload = json.dumps({"session_id": session,
                              "hook_event_name": "PostToolUse",
                              "tool_name": tool, "tool_input": tool_input,
                              "tool_response": {}})
        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook"],
            input=payload.encode("utf-8"), capture_output=True,
            env={**self.env, "PYTHONIOENCODING": "utf-8",
                 "CLAUDE_PROJECT_DIR": str(self.project)})
        self.assertEqual(result.returncode, 0, result.stderr)

    def anchored_folder(self, name="pkg"):
        """A folder package of the session, its manifest anchored with
        the fake calendar. Returns the folder."""
        folder = self.work / name
        result = self.package(SESSION, "--folder", "--out", str(folder),
                              "--anchor", "--calendar", self.server.url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return folder

    @staticmethod
    def manifest_digest(folder):
        return hashlib.sha256((folder / "manifest.json").read_bytes()).hexdigest()

    @staticmethod
    def sidecar_records(folder):
        return [json.loads(line) for line in
                (folder / SIDECAR).read_text("utf-8").splitlines()]


class SealedPackageTest(AnchoredStoreCase):
    """The anchor seal, built and judged."""

    def test_anchor_posts_the_manifest_digest_and_declares_the_seal(self):
        # ADR-0026 ruling 4: the manifest's sha256 goes to the calendars
        # once, after the manifest is written; the proof is an ordinary
        # anchor record whose head is that digest and which has no n;
        # and the manifest, written before the proof exists, declares
        # the seal so a stripped sidecar is caught.
        folder = self.anchored_folder()

        digest = self.manifest_digest(folder)
        self.assertEqual(self.server.submitted, [bytes.fromhex(digest)])
        records = self.sidecar_records(folder)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["head"], digest)
        self.assertNotIn("n", records[0])
        self.assertEqual(records[0]["calendar"], self.server.url)
        self.assertEqual(self.manifest_of(folder)["seals"], ["anchor"])

    def test_the_zip_carries_the_sidecar_after_the_manifest(self):
        # The zip keeps the write order, and the seal is applied after
        # the manifest exists, so its proof is the member after it.
        zipped = self.work / "sealed.zip"
        result = self.package(SESSION, "--out", str(zipped), "--anchor",
                              "--calendar", self.server.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with zipfile.ZipFile(zipped) as package:
            names = package.namelist()
            self.assertEqual(names[-2:], ["manifest.json", SIDECAR], names)
            digest = hashlib.sha256(package.read("manifest.json")).hexdigest()
            (record,) = [json.loads(line) for line in
                         package.read(SIDECAR).decode("utf-8").splitlines()]
        self.assertEqual(record["head"], digest)
        self.assertEqual(self.server.submitted, [bytes.fromhex(digest)])
        self.assertIn("anchored", result.stdout)
        self.assertIn("--upgrade --manifest", result.stdout)

    CHAIN_DETAIL = ("ANCHORED: entries 0..2: the attestation claims Bitcoin "
                    "block 850000, and the block was not checked")

    def test_a_pending_manifest_anchor_leaves_the_rung_unearned_with_a_note(self):
        # The proof names the calendar and no block yet: the verdict
        # stays SELF-CONSISTENT, its limit says why, and the chain's own
        # completed anchor stays detail under the chain (ruling 6).
        folder = self.anchored_folder()

        judged = self.verify_package(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        self.assertIn("seals: anchor", out)
        note = next((l for l in lines
                     if l.startswith("seal anchor: ANCHOR-PENDING")), None)
        self.assertIsNotNone(note, out)
        self.assertIn("--upgrade --manifest", note)
        self.assertIn(self.CHAIN_DETAIL, out)
        self.assertNotIn("unlisted:", out)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT:"), lines[-1])
        self.assertNotIn("ANCHORED", lines[-1])
        self.assertIn("indistinguishable from a wholesale regeneration",
                      lines[-1])
        self.assertNotIn("no seal is declared", lines[-1])
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        self.assertNotIn("no seal is declared", lines[-2])

    def test_a_completed_manifest_anchor_earns_the_rung(self):
        # Upgraded through the existing upgrade path, pointed at the
        # manifest, once the calendar has the Bitcoin attestation; the
        # verifier then prints the block and the merkle root for the
        # recipient to confirm (ADR-0003) and adds + ANCHORED.
        folder = self.anchored_folder()
        digest = self.manifest_digest(folder)
        self.server.mode = "complete"

        upgrade = run(LOXODONTA, "anchor", "--upgrade", "--manifest",
                      str(folder / "manifest.json"), env=self.env)

        self.assertEqual(upgrade.returncode, 0, upgrade.stdout + upgrade.stderr)
        commitment = hashlib.sha256(bytes.fromhex(digest)
                                    + self.server.nonce).hexdigest()
        self.assertEqual(self.server.polled, [commitment])
        self.assertIn("upgraded: manifest", upgrade.stdout)
        records = self.sidecar_records(folder)
        self.assertEqual([r["head"] for r in records], [digest, digest])
        self.assertTrue(all("n" not in r for r in records), records)

        judged = self.verify_package(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        seal = next((l for l in lines
                     if l.startswith("seal anchor: ANCHORED")), None)
        self.assertIsNotNone(seal, out)
        # No header was given, so the block is the attestation's claim,
        # and neither the seal line nor the verdict says the manifest
        # existed by it (ruling 3 on #299).
        self.assertTrue(seal.startswith(
            "seal anchor: ANCHORED: the manifest: the attestation claims "
            f"Bitcoin block {self.server.height}, and the block was not "
            "checked"), seal)
        self.assertIn(expected_merkle_root(digest, self.server.nonce,
                                           self.server.prefix,
                                           self.server.suffix), seal)
        self.assertNotIn("ANCHOR-PENDING: the manifest", out)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + ANCHORED:"),
                        lines[-1])
        self.assertIn(f"claims Bitcoin block {self.server.height}, a block "
                      "not checked here", lines[-1])
        self.assertNotIn("existed by", lines[-1])
        self.assertNotIn("indistinguishable", lines[-1])
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        self.assertIn(f"block {self.server.height}", lines[-2])
        # The chain's own anchor is still detail, at its own block.
        self.assertIn(self.CHAIN_DETAIL, out)

    def upgraded_folder(self):
        """A folder package whose manifest anchor has completed, and the
        manifest's replayed root, as the proof computes it."""
        folder = self.anchored_folder()
        self.server.mode = "complete"
        upgrade = run(LOXODONTA, "anchor", "--upgrade", "--manifest",
                      str(folder / "manifest.json"), env=self.env)
        self.assertEqual(upgrade.returncode, 0, upgrade.stdout + upgrade.stderr)
        root = replayed_root(self.manifest_digest(folder), self.server.nonce,
                             self.server.prefix, self.server.suffix)
        return folder, root

    def test_a_header_for_the_manifest_block_says_existed_by_it(self):
        # verify-package takes --block-header too: a header holding the
        # manifest anchor's root turns the claim into the block the
        # recipient named, by its hash, on the seal line and the verdict.
        folder, root = self.upgraded_folder()
        header = block_header(root)

        judged = self.verify_package(folder, "--block-header", header.hex())

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        seal = next(l for l in lines if l.startswith("seal anchor: ANCHORED"))
        self.assertTrue(seal.startswith(
            "seal anchor: ANCHORED: the manifest existed by the block whose "
            f"header hashes to {header_hash(header)}"), seal)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + ANCHORED:"),
                        lines[-1])
        self.assertIn("the manifest existed by the block whose header hashes "
                      f"to {header_hash(header)}", lines[-1])
        self.assertIn(f"Bitcoin block {self.server.height}", lines[-1])
        self.assertNotIn("not checked", lines[-1])
        self.assertIn(header_hash(header), lines[-2])
        self.assertNotIn("HEADER-UNMATCHED", out)
        # The chain's anchor has a root of its own, so it stays unchecked.
        self.assertIn(self.CHAIN_DETAIL, out)

    def test_a_header_for_a_chain_anchor_checks_it_and_is_not_noted(self):
        # Headers are matched across the whole package: one that checks a
        # chain's anchor and not the manifest's is used, never noted as
        # matching nothing, and it earns the package rung nothing.
        folder, _ = self.upgraded_folder()
        chain_root = hashlib.sha256(bytes.fromhex(
            run(LOXODONTA, "head", "--log", str(self.chain)).stdout.strip())
        ).digest()   # completed_anchor's proof: one sha256, then the block
        header = block_header(chain_root)

        judged = self.verify_package(folder, "--block-header", header.hex())

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        self.assertIn("ANCHORED: entries 0..2 existed by the block whose "
                      f"header hashes to {header_hash(header)}", out)
        self.assertNotIn("HEADER-UNMATCHED", out)
        lines = out.strip().splitlines()
        self.assertIn("a block not checked here", lines[-1])

    def test_a_header_matching_nothing_in_the_package_is_noted_once(self):
        folder, _ = self.upgraded_folder()

        judged = self.verify_package(folder, "--block-header", GENESIS_HEADER)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        self.assertEqual(out.count("HEADER-UNMATCHED"), 1, out)
        note = next(i for i, l in enumerate(lines)
                    if l.startswith("HEADER-UNMATCHED"))
        self.assertIn(GENESIS_HASH, lines[note])
        # After every anchor line it speaks for, before the verdict.
        seal = next(i for i, l in enumerate(lines)
                    if l.startswith("seal anchor: ANCHORED"))
        self.assertGreater(note, seal)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + ANCHORED:"),
                        lines[-1])
        self.assertIn("a block not checked here", lines[-1])

    def test_a_malformed_header_is_a_usage_error(self):
        folder = self.anchored_folder()

        judged = self.verify_package(folder, "--block-header", "00" * 79)

        self.assertEqual(judged.returncode, 64, judged.stdout + judged.stderr)
        self.assertIn("160 hex characters", judged.stderr)

    def test_a_manifest_settled_by_one_calendar_stops_advising_the_other(self):
        # #199 reaches the seal too: the anchor's claim is about the
        # manifest's digest, not about any one calendar. Once one of them
        # settles it, the straggler is not work the recipient owes, and
        # the rung is earned.
        lags = start_calendar(self, b"nonce-lags")
        folder = self.work / "two-calendars"
        built = self.package(SESSION, "--folder", "--out", str(folder),
                             "--anchor", "--calendar", self.server.url,
                             "--calendar", lags.url)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.server.mode = "complete"

        upgrade = run(LOXODONTA, "anchor", "--upgrade", "--manifest",
                      str(folder / "manifest.json"), env=self.env)

        self.assertEqual(upgrade.returncode, 0, upgrade.stdout + upgrade.stderr)
        self.assertEqual(lags.polled, [], "the lagging calendar was re-asked")

        judged = self.verify_package(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        self.assertIn("seal anchor: ANCHORED", out)
        self.assertNotIn("seal anchor: ANCHOR-PENDING", out)
        self.assertIn("seal anchor: ANCHOR-UNANSWERED", out)
        self.assertIn(lags.url, out)
        self.assertTrue(out.strip().splitlines()[-1].startswith(
            "SELF-CONSISTENT + ANCHORED:"), out.strip().splitlines()[-1])

    def test_a_stripped_sidecar_is_seal_missing_exit_3(self):
        # ADR-0007's declared seal set: the manifest says an anchor
        # exists, so deleting the proof is a failure, never a silent
        # downgrade to SELF-CONSISTENT.
        folder = self.anchored_folder()
        (folder / SIDECAR).unlink()

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SEAL-MISSING:"), lines[-1])
        self.assertTrue(any(l.startswith("seal anchor: SEAL-MISSING")
                            for l in lines), judged.stdout)
        # The chain and the artifacts are still fine; the seal is not.
        self.assertIn("VALID", judged.stdout)
        self.assertNotIn("residual trust", judged.stdout)

    def test_a_proof_for_another_digest_or_none_is_seal_invalid_exit_3(self):
        # A completed proof for some other digest, and a record whose
        # proof bytes do not replay: both are evidence that does not
        # verify, and neither is this manifest's anchor.
        folder = self.anchored_folder()
        other = completed_anchor("ab" * 32)
        garbage = json.dumps({"head": self.manifest_digest(folder),
                              "ts": "2026-08-13T14:00:00Z",
                              "calendar": self.server.url,
                              "proof": base64.b64encode(b"\x00\x01junk")
                              .decode()}) + "\n"
        for words, sidecar in (("another digest", other),
                               ("does not replay", garbage)):
            (folder / SIDECAR).write_text(sidecar, encoding="utf-8")

            judged = self.verify_package(folder)

            self.assertEqual(judged.returncode, 3,
                             words + ": " + judged.stdout + judged.stderr)
            lines = judged.stdout.strip().splitlines()
            self.assertTrue(lines[-1].startswith("SEAL-INVALID:"), lines[-1])
            self.assertTrue(any(l.startswith("seal anchor: SEAL-INVALID")
                                for l in lines), judged.stdout)
            self.assertNotIn("Traceback", judged.stderr)

    def test_without_anchor_nothing_leaves_and_chain_anchors_stay_detail(self):
        # A calendar named but no --anchor: the calendar sees nothing,
        # the manifest declares no seal, and no sidecar exists. The
        # chain's completed anchor prints under its chain and earns the
        # package nothing (ruling 6): the ceiling says no seal is
        # declared.
        folder = self.work / "unsealed"
        result = self.package(SESSION, "--folder", "--out", str(folder),
                              "--calendar", self.server.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.server.submitted, [])
        self.assertEqual(self.manifest_of(folder)["seals"], [])
        self.assertFalse((folder / SIDECAR).exists())
        self.assertNotIn("anchored", result.stdout)

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertIn(self.CHAIN_DETAIL, judged.stdout)
        self.assertNotIn("seal anchor", judged.stdout)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT:"), lines[-1])
        self.assertIn("since no seal is declared", lines[-1])
        self.assertEqual(self.server.submitted, [])

    def test_attempt_rows_ride_in_the_packaged_sidecar_and_are_not_judged(self):
        # #240: the hook's note on how a session-end anchor went sits in
        # the chain's sidecar beside the proof. The package carries the
        # sidecar as it is, and the verifier reads the note as a note:
        # the chain's anchor still prints as detail, nothing is invalid,
        # and the verdict is what it was without the row.
        sidecar = self.chain.with_name(self.chain.name + ".anchors.jsonl")
        with sidecar.open("a", encoding="utf-8") as out:
            out.write(json.dumps({
                "kind": "attempt", "step": "anchor",
                "ts": "2026-09-16T05:35:42Z", "budget": 12.0,
                "outcome": "no calendar answered within 12 seconds"}) + "\n")
        folder = self.work / "noted"
        result = self.package(SESSION, "--folder", "--out", str(folder))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn(self.CHAIN_DETAIL, judged.stdout)
        self.assertNotIn("INVALID", judged.stdout)
        self.assertNotIn("MISMATCH", judged.stdout)
        packed = (folder / sidecar.name).read_text("utf-8").splitlines()
        self.assertEqual(len(packed), 2, "the sidecar travels as it is")
        self.assertIn('"kind": "attempt"', packed[-1])

    def test_a_calendar_that_accepts_nothing_leaves_no_package(self):
        # A package declaring a seal it does not carry would only ever
        # verify SEAL-MISSING; the recorder's refusal is relayed and
        # nothing is written, zip or folder.
        closed = "http://127.0.0.1:9"  # discard port: nothing listens
        for shape in (("--folder", "--out", str(self.work / "gone")),
                      ("--out", str(self.work / "gone.zip"))):
            result = self.package(SESSION, *shape, "--anchor",
                                  "--calendar", closed)

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("not anchored", result.stderr)
            self.assertIn("nothing written", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(list(self.work.iterdir()), [], shape)

    def test_the_sealed_zip_verifies_with_the_seal_judged(self):
        zipped = self.work / "sealed.zip"
        self.package(SESSION, "--out", str(zipped), "--anchor",
                     "--calendar", self.server.url)

        judged = self.verify_package(zipped)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn("seal anchor: ANCHOR-PENDING", judged.stdout)
        self.assertNotIn("unlisted:", judged.stdout)
        self.assertTrue(judged.stdout.strip().splitlines()[-1]
                        .startswith("SELF-CONSISTENT:"))


UNKNOWN_ROW = json.dumps({"kind": "witness-note", "ts": "2026-09-24T10:00:00Z"})


class PackageRowKindTest(AnchoredStoreCase):
    """ADR-0038 in a package: the manifest's proof row names its kind,
    and a row of a kind this verifier does not know is named by its line
    in either anchors sidecar, earning nothing and moving no exit code."""

    def test_the_manifest_anchor_row_names_its_kind(self):
        folder = self.anchored_folder()

        (record,) = self.sidecar_records(folder)

        self.assertEqual(record["kind"], "anchor")
        self.assertEqual(set(record), {"kind", "head", "ts", "calendar",
                                       "proof"})

    def test_an_unknown_kind_beside_the_manifest_proof_is_named_not_judged(self):
        folder = self.anchored_folder()
        before = self.verify_package(folder)
        with (folder / SIDECAR).open("a", encoding="utf-8") as out:
            out.write(UNKNOWN_ROW + "\n")

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, before.returncode,
                         judged.stdout + judged.stderr)
        note = (f'seal anchor: ANCHOR-UNKNOWN-KIND: line 2 of {SIDECAR} is of '
                'kind "witness-note" — this verifier does not know the kind '
                'in this sidecar, and does not judge it')
        lines = judged.stdout.splitlines()
        self.assertIn(note, lines)
        self.assertEqual([l for l in lines if l != note],
                         before.stdout.splitlines())

    def test_a_manifest_sidecar_of_unknown_rows_only_is_seal_missing(self):
        # A row of an unknown kind earns nothing, so a sidecar holding
        # only that is a declared anchor the package does not carry.
        folder = self.anchored_folder()
        (folder / SIDECAR).write_text(UNKNOWN_ROW + "\n", encoding="utf-8")

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        self.assertIn("seal anchor: ANCHOR-UNKNOWN-KIND: line 1", judged.stdout)
        self.assertTrue(judged.stdout.strip().splitlines()[-1]
                        .startswith("SEAL-MISSING:"), judged.stdout)

    def test_an_unknown_kind_in_a_chain_sidecar_is_named_not_judged(self):
        sidecar = self.chain.with_name(self.chain.name + ".anchors.jsonl")
        folder = self.work / "plain"
        self.package(SESSION, "--folder", "--out", str(folder))
        before = self.verify_package(folder)
        with sidecar.open("a", encoding="utf-8") as out:
            out.write(UNKNOWN_ROW + "\n")
        folder = self.work / "noted"
        result = self.package(SESSION, "--folder", "--out", str(folder))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertEqual(judged.returncode, before.returncode)
        self.assertIn(SealedPackageTest.CHAIN_DETAIL, judged.stdout)
        # The sidecar by its bare name, never the unpack folder's path.
        self.assertIn(f"ANCHOR-UNKNOWN-KIND: line 2 of {sidecar.name} is of "
                      "kind \"witness-note\"", judged.stdout)
        self.assertNotIn(str(folder), "\n".join(
            l for l in judged.stdout.splitlines() if "UNKNOWN-KIND" in l))
        self.assertNotIn("INVALID", judged.stdout)
        self.assertEqual(judged.stdout.splitlines()[-1],
                         before.stdout.splitlines()[-1])


def changed(row, change):
    """`row` with `change` applied: a field replaced, or left out for
    DROP, as one compact sidecar line."""
    row = dict(row)
    for field, value in change.items():
        if value is DROP:
            row.pop(field, None)
        else:
            row[field] = value
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


class MalformedPackageRowTest(AnchoredStoreCase):
    """#348 in a package: a row of either anchors sidecar that is a JSON
    object but not the shape of an anchor row is evidence that does not
    verify, exit 3, with a reason naming the field and never its value,
    and never a traceback in the recipient's hands."""

    def test_a_malformed_row_beside_the_manifest_proof_is_seal_invalid(self):
        folder = self.anchored_folder()
        sidecar = folder / SIDECAR
        good = sidecar.read_text("utf-8")
        (record,) = self.sidecar_records(folder)
        for change, reason in MALFORMED_ROWS:
            with self.subTest(change=change):
                sidecar.write_text(good + changed(record, change) + "\n",
                                   encoding="utf-8")

                judged = self.verify_package(folder)

                self.assertEqual(judged.returncode, 3,
                                 judged.stdout + judged.stderr)
                self.assertIn(f"seal anchor: SEAL-INVALID: {reason} — "
                              "evidence that does not verify is not evidence",
                              judged.stdout)
                self.assertIn("seal anchor: ANCHOR-PENDING", judged.stdout)
                self.assertNotIn("Traceback", judged.stderr)
                self.assertNotIn("sneaky", judged.stdout)

    def test_a_malformed_row_in_a_chain_sidecar_is_anchor_invalid(self):
        chain_sidecar = self.chain.with_name(self.chain.name + ".anchors.jsonl")
        good = chain_sidecar.read_text("utf-8")
        (record,) = [json.loads(line) for line in good.splitlines()]
        for number, (change, reason) in enumerate(MALFORMED_ROWS):
            with self.subTest(change=change):
                chain_sidecar.write_text(good + changed(record, change) + "\n",
                                         encoding="utf-8")
                folder = self.work / f"malformed-{number}"
                packed = self.package(SESSION, "--folder", "--out", str(folder))
                self.assertEqual(packed.returncode, 0,
                                 packed.stdout + packed.stderr)

                judged = self.verify_package(folder)

                self.assertEqual(judged.returncode, 3,
                                 judged.stdout + judged.stderr)
                self.assertIn(f"ANCHOR-INVALID: {reason} — evidence that "
                              "does not verify is not evidence", judged.stdout)
                self.assertIn(SealedPackageTest.CHAIN_DETAIL, judged.stdout)
                self.assertNotIn("Traceback", judged.stderr)
                self.assertNotIn("sneaky", judged.stdout)


RELEASE = "v0.9.0"


def released_verifier(case, folder):
    """The v0.9.0 `verifier.py`, from its tag's bytes, written into
    `folder`; `case` skips when git or the tag is not there. The stamps
    suite's compatibility test uses it too."""
    try:
        shown = subprocess.run(
            ["git", "-C", str(LOXODONTA.parent), "show",
             f"{RELEASE}:verifier.py"], capture_output=True)
    except OSError:
        case.skipTest("git is not on PATH, so the released verifier's "
                      "bytes cannot be read")
    if shown.returncode != 0:
        case.skipTest(f"the {RELEASE} tag is not in this checkout "
                      "(a shallow clone fetches no tags), so the released "
                      "verifier's bytes cannot be read")
    path = folder / f"verifier-{RELEASE}.py"
    path.write_bytes(shown.stdout)
    return path


class ReleasedVerifierTest(AnchoredStoreCase):
    """ADR-0038's compatibility promise, held against the bytes a
    recipient already has: a package this recorder makes, its chain and
    its manifest anchored with rows that name their kind, verifies the
    same under the v0.9.0 verifier as under this one. That verifier
    skips only `attempt` rows, so it judges an `anchor` row as it judged
    a kind-less one."""

    def test_a_package_anchored_by_this_recorder_verifies_the_same_under_it(self):
        released = released_verifier(self, self.root)
        # The chain anchored by the recorder, so its sidecar holds an
        # `anchor` row beside the fixture's kind-less one.
        anchored = run(LOXODONTA, "anchor", "--log", str(self.chain),
                       "--calendar", self.server.url, env=self.env)
        self.assertEqual(anchored.returncode, 0, anchored.stderr)
        folder = self.anchored_folder()
        self.server.mode = "complete"
        upgrade = run(LOXODONTA, "anchor", "--upgrade", "--manifest",
                      str(folder / "manifest.json"), env=self.env)
        self.assertEqual(upgrade.returncode, 0, upgrade.stdout + upgrade.stderr)
        kinds = [r.get("kind") for r in self.sidecar_records(folder)]
        self.assertEqual(kinds, ["anchor", "anchor"])

        now = self.verify_package(folder)
        then = subprocess.run(
            [sys.executable, "-I", str(released), "verify-package",
             str(folder)], capture_output=True, cwd=str(self.work))
        then_out = then.stdout.decode("utf-8", "replace")

        self.assertEqual(now.returncode, 0, now.stdout + now.stderr)
        self.assertTrue(now.stdout.splitlines()[-1]
                        .startswith("SELF-CONSISTENT + ANCHORED:"), now.stdout)
        self.assertEqual((then.returncode, then_out.splitlines()),
                         (now.returncode, now.stdout.splitlines()))


if __name__ == "__main__":
    unittest.main()
