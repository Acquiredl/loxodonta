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

from test_package import LOXODONTA, run
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


if __name__ == "__main__":
    unittest.main()
