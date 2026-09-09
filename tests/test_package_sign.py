"""Behavioral tests for the package's second seal (ADR-0026 rulings 4, 6,
7 and 8, applying ADR-0008; #181): `supervisor package --sign KEYFILE`
has ssh-keygen sign the manifest's shipped bytes and ships the signature
and the public key beside it; `loxodonta verify-package` has ssh-keygen
judge that signature and prints the key's fingerprint, never a name.

The store and the fake calendar are test_package_anchor's, so the anchor
and the signature can be judged together. The key is an Ed25519 pair
generated here with a neutral comment. Every test drives the public CLI
as an issuer or a recipient would; when ssh-keygen is not on PATH the
whole file skips, saying so, since the seal is made and judged by it.
"""

import os
import shutil
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

from test_package import LOXODONTA, SUPERVISOR, run
from test_package_anchor import SESSION, SIDECAR, AnchoredStoreCase

SIGNATURE = "manifest.json.sig"
PUBLIC_KEY = "manifest.json.pub"
# The test key's comment: a name-shaped word that must appear nowhere in
# the package or the verifier's output (ADR-0008 ruling 4).
ALIAS = "issuer-alias"


def public_key_of(keyfile):
    """The `.pub` ssh-keygen writes beside a private key."""
    return keyfile.with_name(keyfile.name + ".pub")


def fingerprint_of(keyfile):
    """The SHA256 fingerprint ssh-keygen prints for a key's public half."""
    listed = subprocess.run(["ssh-keygen", "-lf", str(public_key_of(keyfile))],
                            capture_output=True, encoding="utf-8")
    return listed.stdout.split()[1]


@unittest.skipUnless(shutil.which("ssh-keygen"),
                     "ssh-keygen is not on PATH; the issuer signature is "
                     "made and judged by it (OpenSSH 8.0+)")
class SignedPackageTest(AnchoredStoreCase):
    """The issuer signature, built and judged."""

    def setUp(self):
        super().setUp()
        self.keyfile = self.keypair("key", comment=ALIAS)

    def keypair(self, name, comment=""):
        """An Ed25519 pair under the test root, no passphrase; the private
        key's path. The comment is empty unless a test needs one."""
        path = self.root / name
        made = subprocess.run(
            ["ssh-keygen", "-q", "-N", "", "-t", "ed25519", "-C", comment,
             "-f", str(path)], capture_output=True, encoding="utf-8",
            errors="replace")
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        return path

    def signed_folder(self, name="signed", *flags):
        """A folder package of the session, its manifest signed with the
        test key (and whatever else `flags` asks for). Returns the folder."""
        folder = self.work / name
        result = self.package(SESSION, "--folder", "--out", str(folder),
                              "--sign", str(self.keyfile), *flags)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return folder

    def test_sign_writes_the_signature_and_the_public_key_and_declares_the_seal(self):
        # ADR-0026 ruling 4: after the manifest is written, ssh-keygen
        # signs its shipped bytes and the signature travels beside it
        # with the public key, testimony (ADR-0008 ruling 4); the
        # manifest, written before either exists, declares the seal.
        folder = self.signed_folder()

        self.assertEqual(self.manifest_of(folder)["seals"], ["signature"])
        signature = (folder / SIGNATURE).read_text("utf-8")
        self.assertTrue(signature.startswith("-----BEGIN SSH SIGNATURE-----"),
                        signature)
        # The key's two tokens travel; its comment, a name, stays home.
        expected = public_key_of(self.keyfile).read_text("utf-8").split()
        self.assertEqual(expected[2:], [ALIAS])
        self.assertEqual((folder / PUBLIC_KEY).read_text("utf-8").split(),
                         expected[:2])

    def test_the_zip_carries_the_signature_and_key_after_the_manifest(self):
        # The zip keeps the write order: the manifest, then the seal's
        # files, the signature before the key that made it.
        zipped = self.work / "signed.zip"
        result = self.package(SESSION, "--out", str(zipped),
                              "--sign", str(self.keyfile))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with zipfile.ZipFile(zipped) as package:
            names = package.namelist()
        self.assertEqual(names[-3:], ["manifest.json", SIGNATURE, PUBLIC_KEY],
                         names)
        self.assertIn("signed:", result.stdout)
        self.assertIn(fingerprint_of(self.keyfile), result.stdout)
        self.assertNotIn(ALIAS, result.stdout)

    def test_verify_prints_the_fingerprint_and_never_a_name(self):
        # ADR-0008 ruling 4: math is the verifier's job, identity the
        # recipient's, so the verifier prints the key fingerprint and
        # stops; the key's comment is nowhere in the package or the
        # output. ADR-0007's ladder: + SIGNED joins the verdict line.
        folder = self.signed_folder()
        fingerprint = fingerprint_of(self.keyfile)

        judged = self.verify_package(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        self.assertIn("seals: signature", out)
        seal = next((l for l in lines
                     if l.startswith("seal signature: SIGNED")), None)
        self.assertIsNotNone(seal, out)
        self.assertIn(f"(key: {fingerprint})", seal)
        self.assertTrue(lines[-1].startswith(
            f"SELF-CONSISTENT + SIGNED (key: {fingerprint}):"), lines[-1])
        self.assertIn("issued by the holder of key", lines[-1])
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        self.assertIn(fingerprint, lines[-2])
        self.assertNotIn(ALIAS, out)
        self.assertNotIn(ALIAS, (folder / PUBLIC_KEY).read_text("utf-8"))
        self.assertNotIn("unlisted:", out)
        self.assertNotIn("Traceback", judged.stderr)

    def test_anchored_and_signed_climbs_the_whole_ladder_in_order(self):
        # Both seals (ADR-0007 ruling 4, ADR-0026 rulings 4 and 6):
        # declared and applied anchor first, so the zip carries the
        # sidecar, then the signature, then the key, after the manifest;
        # and once the anchor completes the verdict line reads the ladder
        # in ADR-0007's order, when before which key.
        zipped = self.work / "both.zip"
        result = self.package(SESSION, "--out", str(zipped), "--anchor",
                              "--calendar", self.server.url,
                              "--sign", str(self.keyfile))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with zipfile.ZipFile(zipped) as package:
            self.assertEqual(package.namelist()[-4:],
                             ["manifest.json", SIDECAR, SIGNATURE, PUBLIC_KEY])
        self.assertEqual(self.manifest_of(zipped)["seals"],
                         ["anchor", "signature"])
        self.assertIn("anchored:", result.stdout)
        self.assertIn("signed:", result.stdout)

        folder = self.signed_folder("both", "--anchor", "--calendar",
                                    self.server.url)
        self.server.mode = "complete"
        upgrade = run(LOXODONTA, "anchor", "--upgrade", "--manifest",
                      str(folder / "manifest.json"), env=self.env)
        self.assertEqual(upgrade.returncode, 0, upgrade.stdout + upgrade.stderr)
        fingerprint = fingerprint_of(self.keyfile)

        judged = self.verify_package(folder)

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        self.assertIn("seals: anchor, signature", out)
        self.assertIn("seal anchor: ANCHORED", out)
        self.assertIn(f"seal signature: SIGNED (key: {fingerprint})", out)
        self.assertTrue(lines[-1].startswith(
            f"SELF-CONSISTENT + ANCHORED + SIGNED (key: {fingerprint}):"),
            lines[-1])
        self.assertIn(f"block {self.server.height}", lines[-1])
        self.assertNotIn("indistinguishable", lines[-1])
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        self.assertIn(f"block {self.server.height}", lines[-2])
        self.assertIn(fingerprint, lines[-2])
        self.assertNotIn(ALIAS, out)

    def test_an_edited_manifest_or_a_swapped_key_is_seal_invalid_exit_3(self):
        # ADR-0008 ruling 7: the signature covers the manifest's exact
        # shipped bytes, so a manifest edited after signing fails; and a
        # signature made by a key other than the shipped one fails too,
        # since the shipped key is what the signature is judged under
        # (the substitution attack, caught at the mechanical layer).
        folder = self.signed_folder()
        other = self.keypair("other")
        pristine = (folder / PUBLIC_KEY).read_bytes()
        edits = {
            "edited manifest": lambda: self.rewrite_manifest(
                folder, lambda m: m["unit"].update(project="renamed")),
            "swapped key": lambda: (folder / PUBLIC_KEY).write_bytes(
                public_key_of(other).read_bytes()),
        }
        for words, edit in edits.items():
            edit()

            judged = self.verify_package(folder)

            self.assertEqual(judged.returncode, 3,
                             words + ": " + judged.stdout + judged.stderr)
            lines = judged.stdout.strip().splitlines()
            self.assertTrue(lines[-1].startswith("SEAL-INVALID:"), lines[-1])
            self.assertTrue(any(l.startswith("seal signature: SEAL-INVALID")
                                for l in lines), judged.stdout)
            self.assertNotIn("SIGNED", judged.stdout)
            self.assertNotIn("residual trust", judged.stdout)
            self.assertNotIn("Traceback", judged.stderr)
            # Each edit is judged on its own: the manifest edit is undone
            # by rebuilding, the key swap by restoring the shipped key.
            (folder / PUBLIC_KEY).write_bytes(pristine)
            if words == "edited manifest":
                folder = self.signed_folder("again")

    def test_a_stripped_signature_or_key_is_seal_missing_exit_3(self):
        # ADR-0007's declared seal set: the manifest says a signature
        # exists, so deleting either file the seal needs is a failure,
        # never a silent downgrade to SELF-CONSISTENT. The chain and the
        # artifacts are still fine; the seal is not.
        for stripped in (SIGNATURE, PUBLIC_KEY):
            folder = self.signed_folder("without-" + stripped)
            (folder / stripped).unlink()

            judged = self.verify_package(folder)

            self.assertEqual(judged.returncode, 3,
                             stripped + ": " + judged.stdout + judged.stderr)
            lines = judged.stdout.strip().splitlines()
            self.assertTrue(lines[-1].startswith("SEAL-MISSING:"), lines[-1])
            seal = next((l for l in lines
                         if l.startswith("seal signature: SEAL-MISSING")), None)
            self.assertIsNotNone(seal, judged.stdout)
            self.assertIn(stripped, seal)
            self.assertIn("VALID", judged.stdout)
            self.assertNotIn("unlisted:", judged.stdout)
            self.assertNotIn("residual trust", judged.stdout)

    def bare_path(self):
        """The environment with PATH holding the interpreter's folder and
        nothing else, so ssh-keygen is not found; the rest stays."""
        return {**self.env, "PATH": os.path.dirname(sys.executable)}

    def test_without_ssh_keygen_the_signature_is_not_judged_and_the_rest_is(self):
        # ADR-0026 ruling 6: a recipient without ssh-keygen is told the
        # seal was not judged, and the ladder reports the rungs it could
        # judge: no rung from the signature and no failure either, while
        # the anchor, which the recorder judges by itself, still earns
        # its rung. The same package earns + SIGNED where ssh-keygen is.
        folder = self.signed_folder("both", "--anchor", "--calendar",
                                    self.server.url)
        self.server.mode = "complete"
        upgrade = run(LOXODONTA, "anchor", "--upgrade", "--manifest",
                      str(folder / "manifest.json"), env=self.env)
        self.assertEqual(upgrade.returncode, 0, upgrade.stdout + upgrade.stderr)

        judged = run(LOXODONTA, "verify-package", str(folder),
                     env=self.bare_path(), cwd=str(self.work))

        out = judged.stdout
        self.assertEqual(judged.returncode, 0, out + judged.stderr)
        lines = out.strip().splitlines()
        self.assertIn("seal signature: not judged: ssh-keygen not on PATH", out)
        self.assertNotIn("SEAL-", out)
        self.assertIn("seal anchor: ANCHORED", out)
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT + ANCHORED:"),
                        lines[-1])
        self.assertNotIn("SIGNED", lines[-1])
        self.assertIn("not judged", lines[-1])
        self.assertIn("not judged", lines[-2])
        self.assertNotIn("Traceback", judged.stderr)

        judged = self.verify_package(folder)

        self.assertTrue(judged.stdout.strip().splitlines()[-1].startswith(
            "SELF-CONSISTENT + ANCHORED + SIGNED (key: "), judged.stdout)

    def test_without_ssh_keygen_the_supervisor_cannot_sign_and_writes_nothing(self):
        # The supervisor signs nothing itself (ADR-0026 ruling 4): with
        # ssh-keygen out of reach there is no signature to ship, and a
        # package declaring a seal it does not carry would only ever
        # verify SEAL-MISSING.
        result = run(SUPERVISOR, "package", SESSION, "--witness",
                     str(self.witness), "--out", str(self.work / "gone.zip"),
                     "--sign", str(self.keyfile), env=self.bare_path(),
                     cwd=str(self.work))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not signed", result.stderr)
        self.assertIn("ssh-keygen", result.stderr)
        self.assertIn("nothing written", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_a_key_ssh_keygen_cannot_load_leaves_no_package(self):
        # A failed signing leaves nothing written, zip or folder, with
        # ssh-keygen's own words above the supervisor's; with --anchor
        # too, so an anchor already applied keeps no half-sealed package
        # alive. Nothing here reads the key: ssh-keygen names the file
        # it could not load.
        missing = self.root / "nokey"
        shapes = (("--folder", "--out", str(self.work / "gone")),
                  ("--out", str(self.work / "gone.zip")),
                  ("--out", str(self.work / "gone.zip"), "--anchor",
                   "--calendar", self.server.url))
        for shape in shapes:
            result = self.package(SESSION, *shape, "--sign", str(missing))

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("nokey", result.stderr)
            self.assertIn("not signed", result.stderr)
            self.assertIn("nothing written", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(list(self.work.iterdir()), [], shape)

    def test_the_public_key_is_derived_when_none_sits_beside_the_private_key(self):
        # ADR-0026 ruling 4: KEYFILE.pub is the usual source of the
        # shipped key; without it, ssh-keygen derives the public key from
        # the private one, and the package verifies the same.
        expected = public_key_of(self.keyfile).read_text("utf-8").split()[:2]
        public_key_of(self.keyfile).unlink()

        folder = self.signed_folder("derived")

        self.assertEqual((folder / PUBLIC_KEY).read_text("utf-8").split(),
                         expected)
        judged = self.verify_package(folder)
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertTrue(judged.stdout.strip().splitlines()[-1].startswith(
            "SELF-CONSISTENT + SIGNED (key: "), judged.stdout)


if __name__ == "__main__":
    unittest.main()
