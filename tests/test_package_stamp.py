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

    def test_without_openssl_the_token_is_present_and_not_judged(self):
        # The same posture as the sign suite's for a missing ssh-keygen:
        # a machine without the tool is told so, the rung is neither
        # earned nor failed, and the exit stays the rest of the ladder's.
        # The child gets a PATH with nothing on it.
        folder = self.stamped_folder()
        chain_file = self.root / "authority.pem"
        chain_file.write_text("not read: openssl is not there to read it\n",
                              encoding="utf-8")
        nowhere = self.root / "empty-path"
        nowhere.mkdir()

        judged = run(LOXODONTA, "verify-package", str(folder),
                     "--authority-chain", str(chain_file),
                     env={**self.env, "PATH": str(nowhere)},
                     cwd=str(self.work))

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        self.assertIn("seal stamp: not judged: openssl is not on PATH", out)
        lines = out.strip().splitlines()
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

    def test_an_unlisted_stamps_sidecar_stays_unlisted_and_unjudged(self):
        # A chain's tokens are judged only when the manifest lists its
        # stamps sidecar. A package with none verifies as it did before
        # stamps travelled, with no NO-STAMPS line pointing at a
        # temporary copy; and a sidecar dropped in afterwards is a file
        # nothing vouches for, named and judged by nobody, like any other.
        folder = self.work / "plain"
        built = self.package(SESSION, "--folder", "--out", str(folder))
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        (chain,) = self.manifest_of(folder)["chains"]
        self.assertIsNone(chain["stamps"])

        before = self.verify_package(folder)

        self.assertEqual(before.returncode, 0, before.stdout + before.stderr)
        self.assertNotIn("NO-STAMPS", before.stdout)
        self.assertNotIn("STAMP", before.stdout)

        dropped = folder / (self.chain.name + ".stamps.jsonl")
        dropped.write_text(json.dumps({
            "head": "ab" * 32, "n": 1, "ts": "2026-09-17T05:35:42Z",
            "authority": "https://authority.example.test/tsr",
            "response": base64.b64encode(GRANTED).decode()}) + "\n", "utf-8")

        after = self.verify_package(folder)

        out = after.stdout
        self.assertEqual(after.returncode, 0, out + after.stderr)
        self.assertIn(f"unlisted: {dropped.name} (not in the manifest, not "
                      "judged)", out)
        self.assertNotIn("STAMP-INVALID", out)
        self.assertNotIn("NO-STAMPS", out)
        self.assertTrue(out.strip().splitlines()[-1]
                        .startswith("SELF-CONSISTENT:"))

    def test_a_listed_stamps_sidecar_that_is_stripped_is_artifact_diverged(self):
        # The listing is what vouches for the sidecar, so taking the
        # file away is a package that is not what it lists.
        self.stamp_chain()
        folder = self.work / "stripped"
        built = self.package(SESSION, "--folder", "--out", str(folder))
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        (folder / (self.chain.name + ".stamps.jsonl")).unlink()

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 2, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("ARTIFACT-DIVERGED:"), lines[-1])

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
        self.queries = 0
        self.authority_dir, self.chain_file, self.sign = \
            self.openssl_authority("authority")
        self.authority.answer = self.sign

    def openssl(self, *args, where=None):
        return subprocess.run(["openssl", *args],
                              cwd=str(where or self.authority_dir),
                              capture_output=True, encoding="utf-8",
                              errors="replace")

    def openssl_authority(self, name):
        """An authority of its own, made here with openssl in a folder
        called `name`: its key, its self-signed timestamping certificate,
        and what a real authority does with a query, answering it with
        `openssl ts -reply` under that key. Returns (the folder, the
        certificate a recipient would save as its chain file, the
        answering function for a fake authority)."""
        folder = self.root / name
        folder.mkdir()
        # A subject of its own, as two real authorities have: openssl
        # finds a token's issuer in a chain file by subject name, and two
        # certificates sharing one would leave it choosing between them.
        (folder / "req.cnf").write_text(
            REQ_CONFIG.replace("CN = loxodonta test authority",
                               f"CN = loxodonta test authority {name}"),
            "utf-8")
        (folder / "tsa.cnf").write_text(TSA_CONFIG, "utf-8")
        made = self.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", "tsa.key", "-out", "tsa.crt",
                            "-days", "2", "-config", "req.cnf",
                            "-extensions", "tsa_cert", where=folder)
        self.assertEqual(made.returncode, 0, made.stderr)

        def sign(query):
            self.queries += 1
            stem = f"query-{self.queries}"
            (folder / f"{stem}.tsq").write_bytes(query)
            answered = self.openssl("ts", "-reply", "-queryfile",
                                    f"{stem}.tsq", "-config", "tsa.cnf",
                                    "-out", f"{stem}.tsr", where=folder)
            assert answered.returncode == 0, answered.stderr
            return (folder / f"{stem}.tsr").read_bytes()

        return folder, folder / "tsa.crt", sign

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
        self.assertIn(f"a key certified by {self.chain_file} signed this "
                      "manifest's sha256 under its own clock", seal)
        self.assertIn(f"(the record names {self.authority.url}, testimony)",
                      seal)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + STAMPED:"),
                        lines[-1])
        self.assertIn("a key certified by the --authority-chain file signed "
                      "the manifest's sha256 under its own clock", lines[-1])
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        self.assertIn("keeps an honest clock and sole custody of the key",
                      lines[-2])
        # The verdict and the trust line carry no name at all: the
        # manifest names no authority (ADR-0008 ruling 4's rule).
        self.assertNotIn(self.authority.url, lines[-1] + lines[-2])
        # A token is not an anchor, and the rung never says it is.
        self.assertNotIn("ANCHORED", out)
        self.assertNotIn("Bitcoin", lines[-1])

    def test_an_edited_authority_name_is_never_presented_as_the_signer(self):
        # The stamps record's `authority` sits in a file the manifest does
        # not list, so the writer can change it without touching a seal.
        # The token still verifies, since openssl never read the name,
        # and the output must never offer the edited name as the signer.
        folder = self.stamped_folder()
        edited = "https://someone-else.example/tsr"
        (record,) = self.sidecar_records(folder)
        record["authority"] = edited
        (folder / SIDECAR).write_text(json.dumps(record) + "\n", "utf-8")

        judged = self.judge(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        self.assertNotIn(f"{edited} signed", out)
        self.assertIn(f"(the record names {edited}, testimony)", out)
        lines = out.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + STAMPED:"),
                        lines[-1])
        self.assertNotIn("someone-else", lines[-1] + lines[-2])

    def test_two_authorities_are_judged_with_one_chain_file_holding_both(self):
        # One --authority-chain judges every token in the package, so a
        # chain stamped by one authority and a manifest stamped by
        # another need both chains in that one file: either alone fails
        # the other's token, and the two concatenated judge both.
        self.stamp_chain()
        _, other_chain, other_sign = self.openssl_authority("other")
        other = start_authority(self, answer=other_sign)
        folder = self.work / "two"
        built = self.package(SESSION, "--folder", "--out", str(folder),
                             "--stamp", other.url)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        both_chains = self.root / "both-authorities.pem"
        both_chains.write_text(self.chain_file.read_text("utf-8")
                          + other_chain.read_text("utf-8"), "utf-8")

        first_only = self.judge(folder)
        other_only = self.judge(folder, other_chain)
        both = self.judge(folder, both_chains)

        self.assertEqual(first_only.returncode, 3, first_only.stdout)
        self.assertIn("seal stamp: SEAL-INVALID", first_only.stdout)
        self.assertEqual(other_only.returncode, 3, other_only.stdout)
        self.assertIn("STAMP-INVALID", other_only.stdout)
        out = both.stdout
        self.assertEqual(both.returncode, 0, out + both.stderr)
        self.assertIn("STAMPED: entries 0..2 existed when a key certified by",
                      out)
        self.assertIn("seal stamp: STAMPED", out)
        self.assertTrue(out.strip().splitlines()[-1]
                        .startswith("SELF-CONSISTENT + STAMPED:"))

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
        # The edit also takes the sidecar off its manifest listing, an
        # exit-2 finding; exit 3 outranks it, so the verdict names the
        # token. The manifest itself is untouched, so its own token
        # still holds and the seal is no part of this.

        judged = self.judge(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 3, out + judged.stderr)
        lines = out.strip().splitlines()
        findings = [l for l in lines if l.startswith("STAMP-INVALID: head ")]
        self.assertEqual(len(findings), 1, out)
        self.assertTrue(lines[-1].startswith("STAMP-INVALID:"), lines[-1])
        self.assertIn("is not evidence for that chain", lines[-1])
        self.assertNotIn("ANCHOR", lines[-1])
        self.assertIn("seal stamp: STAMPED", out)

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
