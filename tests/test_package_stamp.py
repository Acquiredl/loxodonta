"""Behavioral tests for the package's third seal (ADR-0032 rulings 4 and
5, applying ADR-0026 rulings 4, 6 and 7; issue #251): `supervisor
package --stamp URL` asks an RFC 3161 timestamp authority for a token
over the manifest's sha256 and ships it as `manifest.json.stamps.jsonl`;
`loxodonta verify-package --authority-chain FILE` judges that token
through openssl and earns `+ STAMPED` on the verdict line only from it.

The package also carries each chain's own stamps sidecar now, as it
carries the anchors sidecar, and judges those tokens as detail under
their chain — a token over a chain head seals a different object and can
never earn the package rung.

Two fixtures, and the line between them is openssl: the build-side
cases run against a fake authority on a free port that answers with a
canned granted response, so they run everywhere; the judged cases need
openssl both to make the authority and to judge its tokens, and skip
with the same wording the package-sign suite uses for a missing
ssh-keygen. No network, ever, and never internals.
"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_package_stamp`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env, start_calendar
from test_package import LOXODONTA, SUPERVISOR, PackageCase, neutral_env, run
from test_stamp import (GRANTED, MISSING_AUTHORITY_TOOLING, REQ_CONFIG,
                        TSA_CONFIG, start_authority)

SESSION = "d0d0d0d0-aaaa-bbbb-cccc-000000000002"
SIDECAR = "manifest.json.stamps.jsonl"


class StampedStoreCase(PackageCase):
    """The fixture these tests share: one session recorded through the
    hook, and a fake authority that grants a token to whoever asks. No
    tests of its own."""

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
        self.env = {**clean_env(), **neutral_env(self.home)}
        for command in ("pytest -q", "git status"):
            self.hook(SESSION, "Bash", {"command": command})
        (drawer,) = [p for p in (self.home / ".loxodonta" / "receipts").iterdir()
                     if p.is_dir()]
        self.chain = drawer / f"receipts-{SESSION}.jsonl"
        self.authority = start_authority(self)

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

    def stamp_chain(self, url=None):
        """A token over the chain's own head, the way an operator's
        `stamp` or a session end leaves one."""
        result = run(LOXODONTA, "stamp", "--log", str(self.chain),
                     "--authority", url or self.authority.url, env=self.env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def stamped_folder(self, name="pkg", *flags):
        folder = self.work / name
        result = self.package(SESSION, "--folder", "--out", str(folder),
                              "--stamp", self.authority.url, *flags)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return folder

    @staticmethod
    def manifest_digest(folder):
        return hashlib.sha256(
            (folder / "manifest.json").read_bytes()).hexdigest()

    @staticmethod
    def sidecar_records(folder, name=SIDECAR):
        return [json.loads(line) for line in
                (folder / name).read_text("utf-8").splitlines()]


class StampedPackageTest(StampedStoreCase):
    """The seal, built; and the halves of judging it that need no
    openssl."""

    def test_stamp_asks_over_the_manifest_digest_and_declares_the_seal(self):
        # ADR-0032 ruling 4 through ADR-0026 ruling 4: the manifest's
        # sha256 goes to the authority once, after the manifest is
        # written; the token is an ordinary stamp record whose head is
        # that digest and which has no n, because a manifest has no
        # entries; and the manifest, written before the token exists,
        # declares the seal so a stripped sidecar is caught.
        folder = self.stamped_folder()

        digest = self.manifest_digest(folder)
        (query,) = self.authority.received
        self.assertEqual(query["content_type"],
                         "application/timestamp-query")
        (record,) = self.sidecar_records(folder)
        self.assertEqual(record["head"], digest)
        self.assertNotIn("n", record)
        self.assertEqual(record["authority"], self.authority.url)
        self.assertEqual(base64.b64decode(record["response"]), GRANTED)
        self.assertEqual(self.manifest_of(folder)["seals"], ["stamp"])

    def test_the_zip_carries_the_token_after_the_manifest(self):
        # The zip keeps the write order, and the seal is applied after
        # the manifest exists, so its token is the member after it.
        zipped = self.work / "stamped.zip"
        result = self.package(SESSION, "--out", str(zipped), "--stamp",
                              self.authority.url)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with zipfile.ZipFile(zipped) as package:
            names = package.namelist()
            self.assertEqual(names[-2:], ["manifest.json", SIDECAR], names)
            digest = hashlib.sha256(package.read("manifest.json")).hexdigest()
            (record,) = [json.loads(line) for line in
                         package.read(SIDECAR).decode("utf-8").splitlines()]
        self.assertEqual(record["head"], digest)
        self.assertIn("stamped:", result.stdout)
        self.assertIn("--authority-chain", result.stdout)

    def test_the_seal_and_the_anchor_are_declared_in_the_ladders_order(self):
        # Both seals answer *when*, and the anchor is declared first
        # because its proof is nobody's product where a token is
        # somebody's signed word (ADR-0032 ruling 1). Applied the other
        # way round, the quick round trip before the slow one, so both
        # remotes see one request each.
        calendar = start_calendar(self, b"fake-nonce")

        folder = self.stamped_folder("both", "--anchor", "--calendar",
                                     calendar.url)

        self.assertEqual(self.manifest_of(folder)["seals"],
                         ["anchor", "stamp"])
        digest = self.manifest_digest(folder)
        self.assertEqual(calendar.submitted, [bytes.fromhex(digest)])
        self.assertEqual(len(self.authority.received), 1)
        self.assertEqual(self.sidecar_records(folder)[0]["head"], digest)
        self.assertEqual(self.sidecar_records(
            folder, "manifest.json.anchors.jsonl")[0]["head"], digest)

    def test_an_authority_that_grants_nothing_leaves_no_package(self):
        # A package declaring a seal it does not carry would only ever
        # verify SEAL-MISSING; the recorder's refusal is relayed and
        # nothing is written, zip or folder.
        closed = "http://127.0.0.1:9/tsr"  # discard port: nothing listens
        for shape in (("--folder", "--out", str(self.work / "gone")),
                      ("--out", str(self.work / "gone.zip"))):
            result = self.package(SESSION, *shape, "--stamp", closed)

            self.assertEqual(result.returncode, 1,
                             result.stdout + result.stderr)
            self.assertIn("not stamped", result.stderr)
            self.assertIn("nothing written", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(list(self.work.iterdir()), [], shape)

    def test_without_the_flag_nothing_leaves_and_no_seal_is_declared(self):
        folder = self.work / "unsealed"
        result = self.package(SESSION, "--folder", "--out", str(folder))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.authority.received, [])
        self.assertEqual(self.manifest_of(folder)["seals"], [])
        self.assertFalse((folder / SIDECAR).exists())
        self.assertNotIn("stamped:", result.stdout)

    def test_a_declared_token_that_is_stripped_is_seal_missing_exit_3(self):
        # ADR-0007's declared seal set: the manifest says a token
        # exists, so deleting it is a failure, never a silent downgrade
        # to SELF-CONSISTENT — and it is a failure without openssl too,
        # since absence needs no tool to see.
        folder = self.stamped_folder()
        (folder / SIDECAR).unlink()

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SEAL-MISSING:"), lines[-1])
        self.assertTrue(any(l.startswith("seal stamp: SEAL-MISSING")
                            for l in lines), judged.stdout)
        # The chain and the artifacts are still fine; the seal is not.
        self.assertIn("VALID", judged.stdout)
        self.assertNotIn("residual trust", judged.stdout)

    def test_a_token_over_another_digest_is_seal_invalid_exit_3(self):
        # A token is nobody's evidence about a manifest it is not over,
        # and saying which digest it is over needs no openssl.
        folder = self.stamped_folder()
        (record,) = self.sidecar_records(folder)
        record["head"] = "ab" * 32
        (folder / SIDECAR).write_text(json.dumps(record) + "\n", "utf-8")

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SEAL-INVALID:"), lines[-1])
        self.assertTrue(any(l.startswith("seal stamp: SEAL-INVALID")
                            for l in lines), judged.stdout)
        self.assertNotIn("Traceback", judged.stderr)

    def test_without_the_chain_file_the_token_is_a_note_and_no_rung(self):
        # ADR-0026's posture, twice over: a seal nobody could judge is
        # neither earned nor failed, the verdict says so in the limit,
        # and the exit stays the package's.
        folder = self.stamped_folder()

        judged = self.verify_package(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        self.assertIn("seal stamp: not judged: no --authority-chain FILE "
                      "given", out)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT:"), lines[-1])
        self.assertNotIn("STAMPED", lines[-1])
        self.assertIn("its authority timestamp was not judged", lines[-1])

    def test_a_chains_own_token_travels_into_the_package(self):
        # The stamps sidecar rides as the anchors sidecar does
        # (ADR-0032 ruling 4): it is listed as an artifact, its bytes are
        # checked against the manifest, and the chain's own token is
        # detail under its chain — the package rung is the manifest's
        # token or nothing.
        self.stamp_chain()
        folder = self.stamped_folder()

        name = self.chain.name + ".stamps.jsonl"
        self.assertTrue((folder / name).is_file())
        self.assertEqual((folder / name).read_bytes(),
                         Path(str(self.chain) + ".stamps.jsonl").read_bytes())
        listed = {a["path"] for a in self.manifest_of(folder)["artifacts"]}
        self.assertIn(name, listed)
        (chain,) = self.manifest_of(folder)["chains"]
        self.assertEqual(chain["stamps"], name)

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn(f"{name}: matches the manifest", judged.stdout)
        self.assertNotIn("unlisted:", judged.stdout)

    def test_an_attempt_row_rides_in_the_packaged_sidecar_and_is_not_judged(self):
        # #240: the recorder's note on how a query went sits in the
        # stamps sidecar beside the tokens. The package carries the
        # sidecar as it is, and the verifier reads the note as a note.
        self.stamp_chain()
        sidecar = Path(str(self.chain) + ".stamps.jsonl")
        with sidecar.open("a", encoding="utf-8") as out:
            out.write(json.dumps({
                "kind": "attempt", "step": "stamp",
                "ts": "2026-09-16T05:35:42Z", "budget": 3.0,
                "outcome": "the authority answered status 2 (rejection)"})
                + "\n")
        folder = self.stamped_folder()

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertNotIn("INVALID", judged.stdout)
        packed = (folder / sidecar.name).read_text("utf-8").splitlines()
        self.assertEqual(len(packed), 2, "the sidecar travels as it is")
        self.assertIn('"kind":"attempt"', packed[-1].replace(" ", ""))


@unittest.skipIf(MISSING_AUTHORITY_TOOLING,
                 f"{MISSING_AUTHORITY_TOOLING}; the authority timestamp is "
                 "judged by openssl, and this suite's authority is made by it")
class JudgedPackageStampTest(StampedStoreCase):
    """The seal, judged: an authority made here with openssl answers the
    recorder's queries with real tokens, and `verify-package
    --authority-chain FILE` judges them through `openssl ts -verify`."""

    def setUp(self):
        super().setUp()
        self.authority_dir = self.root / "authority"
        self.authority_dir.mkdir()
        (self.authority_dir / "req.cnf").write_text(REQ_CONFIG, "utf-8")
        (self.authority_dir / "tsa.cnf").write_text(TSA_CONFIG, "utf-8")
        self.chain_file = self.authority_dir / "tsa.crt"
        made = self.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", "tsa.key", "-out", "tsa.crt",
                            "-days", "2", "-config", "req.cnf",
                            "-extensions", "tsa_cert")
        self.assertEqual(made.returncode, 0, made.stderr)
        self.queries = 0
        self.authority.answer = self.sign

    def openssl(self, *args):
        return subprocess.run(["openssl", *args], cwd=str(self.authority_dir),
                              capture_output=True, encoding="utf-8",
                              errors="replace")

    def sign(self, query):
        """What a real authority does with the recorder's query: answer
        it with `openssl ts -reply` under the test authority's key."""
        self.queries += 1
        name = f"query-{self.queries}"
        (self.authority_dir / f"{name}.tsq").write_bytes(query)
        answered = self.openssl("ts", "-reply", "-queryfile", f"{name}.tsq",
                                "-config", "tsa.cnf", "-out", f"{name}.tsr")
        assert answered.returncode == 0, answered.stderr
        return (self.authority_dir / f"{name}.tsr").read_bytes()

    def judge(self, folder, chain_file=None):
        return self.verify_package(folder, "--authority-chain",
                                   str(chain_file or self.chain_file))

    def test_a_token_the_authority_issued_earns_the_rung(self):
        folder = self.stamped_folder()

        judged = self.judge(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        seal = next((l for l in lines if l.startswith("seal stamp: STAMPED")),
                    None)
        self.assertIsNotNone(seal, out)
        self.assertIn(self.authority.url, seal)
        self.assertIn(str(self.chain_file), seal)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + STAMPED:"),
                        lines[-1])
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        self.assertIn("the authority's clock and key custody", lines[-2])
        # A token is not an anchor, and the rung never says it is.
        self.assertNotIn("ANCHORED", out)
        self.assertNotIn("Bitcoin", lines[-1])

    def test_a_tampered_token_is_seal_invalid_exit_3(self):
        folder = self.stamped_folder()
        (record,) = self.sidecar_records(folder)
        response = bytearray(base64.b64decode(record["response"]))
        response[-40] ^= 0x01  # one bit, inside the signature
        record["response"] = base64.b64encode(bytes(response)).decode()
        (folder / SIDECAR).write_text(json.dumps(record) + "\n", "utf-8")

        judged = self.judge(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(any(l.startswith("seal stamp: SEAL-INVALID")
                            for l in lines), judged.stdout)
        self.assertTrue(lines[-1].startswith("SEAL-INVALID:"), lines[-1])
        self.assertNotIn("Traceback", judged.stderr)

    def test_a_token_from_another_authority_does_not_verify(self):
        # The chain file is whom the recipient trusts: a token signed by
        # anyone else does not verify against it.
        folder = self.stamped_folder()
        stranger = self.root / "stranger"
        stranger.mkdir()
        (stranger / "req.cnf").write_text(REQ_CONFIG, "utf-8")
        made = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", "tsa.key", "-out", "tsa.crt", "-days", "2",
             "-config", "req.cnf", "-extensions", "tsa_cert"],
            cwd=str(stranger), capture_output=True, encoding="utf-8",
            errors="replace")
        self.assertEqual(made.returncode, 0, made.stderr)

        judged = self.judge(folder, stranger / "tsa.crt")

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        self.assertIn("seal stamp: SEAL-INVALID", judged.stdout)

    def test_a_chains_tampered_token_is_named_stamp_invalid(self):
        # The exit-3 tier holds two mechanisms now, and the package
        # names the one that fired: an authority timestamp is never
        # called an anchor (ADR-0032 ruling 1).
        self.stamp_chain()
        folder = self.stamped_folder()
        packed = folder / (self.chain.name + ".stamps.jsonl")
        (record,) = [json.loads(line) for line in
                     packed.read_text("utf-8").splitlines()]
        response = bytearray(base64.b64decode(record["response"]))
        response[-40] ^= 0x01
        record["response"] = base64.b64encode(bytes(response)).decode()
        packed.write_text(json.dumps(record) + "\n", "utf-8")
        # The artifact listing commits the sidecar's bytes, so the
        # manifest has to be taught the edited bytes or ARTIFACT-DIVERGED
        # would be the graver finding and this one would go unsaid.
        self.relist(folder, packed)

        judged = self.judge(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        self.assertIn("STAMP-INVALID", judged.stdout)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("STAMP-INVALID:"), lines[-1])
        self.assertIn("is not evidence for that chain", lines[-1])
        self.assertNotIn("ANCHOR", lines[-1])

    def relist(self, folder, path):
        """The manifest's artifact row for `path`, rewritten to the bytes
        on disk now: the seal above it is what the test is about, and a
        package whose manifest disagrees with its own files would be
        judged on the disagreement first."""
        manifest = json.loads((folder / "manifest.json").read_text("utf-8"))
        for listing in manifest["artifacts"]:
            if listing["path"] == path.name:
                listing["sha256"] = hashlib.sha256(
                    path.read_bytes()).hexdigest()
                listing["bytes"] = path.stat().st_size
        (folder / "manifest.json").write_text(
            json.dumps(manifest, indent=2), "utf-8")

    def test_a_chains_good_token_is_detail_and_earns_the_package_nothing(self):
        # Ruling 6 reaches the third seal too: a token over a chain head
        # seals a different object, so it prints under its chain and the
        # package's own ceiling is untouched by it.
        self.stamp_chain()
        folder = self.work / "chain-only"
        result = self.package(SESSION, "--folder", "--out", str(folder))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        judged = self.judge(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        self.assertIn("STAMPED: entries 0..2 existed when", out)
        self.assertNotIn("seal stamp", out)
        lines = out.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT:"), lines[-1])
        self.assertNotIn("+ STAMPED", lines[-1])
        self.assertIn("since no seal is declared", lines[-1])

    def test_the_stamped_zip_verifies_with_the_seal_judged(self):
        zipped = self.work / "stamped.zip"
        self.package(SESSION, "--out", str(zipped), "--stamp",
                     self.authority.url)

        judged = self.judge(zipped)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn("seal stamp: STAMPED", judged.stdout)
        self.assertNotIn("unlisted:", judged.stdout)
        self.assertTrue(judged.stdout.strip().splitlines()[-1]
                        .startswith("SELF-CONSISTENT + STAMPED:"))


if __name__ == "__main__":
    unittest.main()
