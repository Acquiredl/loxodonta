"""Behavioral tests for the package (ADR-0026, applying ADR-0007; #176):
`supervisor package` builds one package of a session, `loxodonta
verify-package` judges it layer by layer, the recorder's own verdicts
verbatim and the package verdict last.

The store under test is the demo store (tools/demo_store.py) built under
a neutral home through the public CLI; the bad-day session is the worked
example. Every test drives the two commands as a recipient or an issuer
would and reads what they wrote and printed. No internals are imported.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"
DEMO_STORE = REPO_ROOT / "tools" / "demo_store.py"

BAD_DAY_SESSION = "b5d1e0a7-3c62-4f89-a0d4-8e21f6b4c907"
PACKAGE_FILES = {"project.json", "witness.json", "README.md",
                 "manifest.json"}


def run(script, *args, env=None, cwd=None):
    return subprocess.run(
        [sys.executable, str(script), *args], cwd=cwd,
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})})


def neutral_env(home):
    """The environment the packing machine runs under: the neutral home
    is home, the store is its .loxodonta, and nothing of the test
    process's own project leaks in."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_PROJECT_DIR", "LOXODONTA_HOME",
                        "SOURCE_DATE_EPOCH")}
    env.update({"LOXODONTA_HOME": str(home / ".loxodonta"),
                "HOME": str(home), "USERPROFILE": str(home)})
    return env


class PackageCase(unittest.TestCase):
    """The two fixtures share how they drive the two commands: a pinned
    witness so the scan never reads the developer's transcripts, a
    neutral home, and a working folder for what gets written."""

    def package(self, *args):
        return run(SUPERVISOR, "package", "--witness", str(self.witness),
                   *args, env=self.env, cwd=str(self.work))

    def verify_package(self, path):
        return run(LOXODONTA, "verify-package", str(path), env=self.env,
                   cwd=str(self.work))


class DemoStorePackageTest(PackageCase):
    """One demo store, built once; every test packages from it into its
    own working folder, so packages never see each other."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.home = Path(cls._tmp.name).resolve() / "home"
        cls.home.mkdir()
        built = run(DEMO_STORE, "--home", str(cls.home))
        assert built.returncode == 0, built.stderr
        cls.env = neutral_env(cls.home)
        # No transcript layout: the witness is absent on purpose, so the
        # completeness row says UNWITNESSED and reads no real session.
        cls.witness = cls.home / "no-witness"
        cls.witness.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self._work = tempfile.TemporaryDirectory()
        self.addCleanup(self._work.cleanup)
        self.work = Path(self._work.name).resolve()

    def bad_day_chain(self):
        found = (self.home / ".loxodonta" / "receipts").glob(
            f"*/receipts-{BAD_DAY_SESSION}.jsonl")
        chain = next(found, None)
        self.assertIsNotNone(chain, "the bad-day session is missing")
        return chain

    def test_package_by_session_id_writes_a_zip_named_for_the_session(self):
        result = self.package(BAD_DAY_SESSION)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        zips = list(self.work.glob("*.zip"))
        self.assertEqual(len(zips), 1, zips)
        self.assertIn(BAD_DAY_SESSION, zips[0].name)
        self.assertIn(zips[0].name, result.stdout + result.stderr)
        with zipfile.ZipFile(zips[0]) as package:
            names = package.namelist()
            chain = f"receipts-{BAD_DAY_SESSION}.jsonl"
            self.assertEqual(set(names), PACKAGE_FILES | {chain}, names)
            # The chain travels byte for byte, and the manifest is the
            # last thing written (ADR-0007: written last, sealing surface).
            self.assertEqual(package.read(chain),
                             self.bad_day_chain().read_bytes())
            self.assertEqual(names[-1], "manifest.json")
            manifest = json.loads(package.read("manifest.json"))
        self.assertEqual(manifest["format"], "loxodonta-package/1")
        self.assertEqual(manifest["seals"], [])
        self.assertEqual(manifest["unit"]["session"], BAD_DAY_SESSION)

    def test_the_bad_day_package_verifies_self_consistent(self):
        self.package(BAD_DAY_SESSION)
        package = next(self.work.glob("*.zip"))

        result = self.verify_package(package)

        out = result.stdout
        self.assertEqual(result.returncode, 0, out + result.stderr)
        lines = out.strip().splitlines()
        # The order ADR-0026 ruling 5 fixes: the manifest's summary, the
        # recorder's own verify output per chain (anchor lines included),
        # file references counted and stated as not checkable, each
        # artifact against the manifest, the package verdict, then one
        # line of residual trust.
        chain = f"receipts-{BAD_DAY_SESSION}.jsonl"
        order = [
            "format: loxodonta-package/1",
            f"chain: {chain}",
            "NO-ANCHORS",
            "VALID",
            "file references: 1 recorded, not checkable off the machine",
            "project.json",
            "witness.json",
            "README.md",
            "residual trust",
            "SELF-CONSISTENT",
        ]
        cursor = 0
        for needle in order:
            hits = [i for i in range(cursor, len(lines)) if needle in lines[i]]
            self.assertTrue(hits, f"{needle!r} missing after line {cursor}:"
                                  f"\n{out}")
            cursor = hits[0] + 1
        verdict = lines[-1]
        self.assertTrue(verdict.startswith("SELF-CONSISTENT"), verdict)
        self.assertIn("indistinguishable from a wholesale regeneration",
                      verdict)
        self.assertTrue(lines[-2].startswith("residual trust"), lines[-2])
        # witness.json is testimony, and the verifier says so where it
        # judges the file's bytes.
        witness_line = next(l for l in lines if l.startswith("witness.json"))
        self.assertIn("testimony", witness_line)

    def manifest_of(self, package):
        if package.is_dir():
            return json.loads((package / "manifest.json").read_text("utf-8"))
        with zipfile.ZipFile(package) as zipped:
            return json.loads(zipped.read("manifest.json"))

    def test_session_by_id_and_by_address_write_the_same_package(self):
        # Any entry address inside the session selects it, the way `show`
        # and `verify ADDRESS` select (ADR-0026 ruling 1); the middle
        # entry's address, so the match is not the head by accident.
        entries = [json.loads(line) for line in
                   self.bad_day_chain().read_text("utf-8").splitlines()]
        address = entries[3]["entry_hash"][:8]
        by_id = self.work / "by-id.zip"
        by_address = self.work / "by-address.zip"

        first = self.package(BAD_DAY_SESSION, "--out", str(by_id))
        second = self.package(address, "--out", str(by_address))

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        one, two = self.manifest_of(by_id), self.manifest_of(by_address)
        self.assertEqual(one["unit"], two["unit"])
        self.assertEqual(one["chains"], two["chains"])
        self.assertEqual([a["path"] for a in one["artifacts"]],
                         [a["path"] for a in two["artifacts"]])
        with zipfile.ZipFile(by_id) as a, zipfile.ZipFile(by_address) as b:
            self.assertEqual(a.namelist(), b.namelist())
            for name in a.namelist():
                if name not in ("witness.json", "README.md", "manifest.json"):
                    self.assertEqual(a.read(name), b.read(name), name)
        self.assertEqual(self.verify_package(by_address).returncode, 0)

    def folder_package(self):
        folder = self.work / "package"
        result = self.package(BAD_DAY_SESSION, "--folder", "--out",
                              str(folder))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((folder / "manifest.json").is_file())
        return folder

    def test_an_edited_witness_is_artifact_diverged_exit_2(self):
        folder = self.folder_package()
        witness = folder / "witness.json"
        data = json.loads(witness.read_text("utf-8"))
        data["completeness"]["state"] = "COMPLETE"
        witness.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = self.verify_package(folder)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        lines = result.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("ARTIFACT-DIVERGED"), lines[-1])
        self.assertTrue(any(l.startswith("witness.json: DIVERGED")
                            for l in lines), result.stdout)
        # The chain itself still walks clean: the finding is the artifact's.
        self.assertIn("VALID", result.stdout)

    def test_an_edited_chain_is_chain_broken_exit_1(self):
        folder = self.folder_package()
        chain = folder / f"receipts-{BAD_DAY_SESSION}.jsonl"
        raw = chain.read_bytes()
        self.assertIn(b"Read: .env", raw)
        chain.write_bytes(raw.replace(b"Read: .env", b"Read: .envx"))

        result = self.verify_package(folder)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        lines = result.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("CHAIN-BROKEN"), lines[-1])
        # The recorder's own words, verbatim, name the entry.
        self.assertIn("BROKEN at entry 3", result.stdout)

    def test_an_unknown_format_tag_is_unsupported_format_exit_4(self):
        folder = self.folder_package()
        manifest = folder / "manifest.json"
        data = json.loads(manifest.read_text("utf-8"))
        data["format"] = "loxodonta-package/9"
        manifest.write_text(json.dumps(data), encoding="utf-8")

        result = self.verify_package(folder)

        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        lines = result.stdout.strip().splitlines()
        # A refusal, not a verdict: nothing else is judged or printed.
        self.assertEqual(len(lines), 1, result.stdout)
        self.assertTrue(lines[0].startswith("UNSUPPORTED-FORMAT"), lines[0])
        self.assertIn("loxodonta-package/9", lines[0])
        self.assertIn("loxodonta-package/1", lines[0])

    def test_a_chain_rewritten_with_crlf_still_verifies(self):
        # A Windows unzip can change a chain's line endings without
        # changing its head; chains are listed by head and judged by
        # walking, never by file hash (ADR-0026 ruling 3).
        folder = self.folder_package()
        chain = folder / f"receipts-{BAD_DAY_SESSION}.jsonl"
        raw = chain.read_bytes()
        self.assertNotIn(b"\r\n", raw)
        chain.write_bytes(raw.replace(b"\n", b"\r\n"))

        result = self.verify_package(folder)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT"), lines[-1])

    def rewrite_manifest(self, folder, change):
        path = folder / "manifest.json"
        manifest = json.loads(path.read_text("utf-8"))
        change(manifest)
        path.write_text(json.dumps(manifest, indent=2), "utf-8")

    def test_a_manifest_path_that_leaves_the_package_is_refused(self):
        # The layout is flat: a listed path is a bare file name or the
        # package is refused unopened, so a stranger's manifest can never
        # make the verifier read, hash, or hang on a file outside it.
        folder = self.folder_package()
        outside = folder.parent / "outside-secret.txt"
        outside.write_text("not yours to hash\n", "utf-8")
        for bad in ("../outside-secret.txt", str(outside), "a/b.jsonl",
                    "a\\b.jsonl", "..", ""):
            self.rewrite_manifest(
                folder, lambda m, bad=bad: m["artifacts"].__setitem__(
                    0, {**m["artifacts"][0], "path": bad}))
            result = self.verify_package(folder)
            self.assertEqual(result.returncode, 4, bad + ": " + result.stdout)
            lines = result.stdout.strip().splitlines()
            self.assertTrue(lines[-1].startswith("UNSUPPORTED-FORMAT"), lines)
            self.assertNotIn("outside-secret", result.stdout)
            self.assertNotIn("Traceback", result.stderr)

    def test_a_malformed_manifest_is_refused_not_a_traceback(self):
        folder = self.folder_package()
        shapes = {
            "unit a string": lambda m: m.__setitem__("unit", "x"),
            "a chain a string": lambda m: m.__setitem__("chains", ["x"]),
            "an artifact a number": lambda m: m.__setitem__("artifacts", [42]),
            "seals a number": lambda m: m.__setitem__("seals", 42),
            "no seals key": lambda m: m.pop("seals"),
            "no chains": lambda m: m.__setitem__("chains", []),
            "an entry count a string": lambda m: m["chains"][0].__setitem__(
                "entries", "6"),
        }
        for words, change in shapes.items():
            self.rewrite_manifest(folder, change)
            result = self.verify_package(folder)
            self.assertEqual(result.returncode, 4, words + ": " + result.stdout)
            self.assertTrue(result.stdout.strip().splitlines()[-1]
                            .startswith("UNSUPPORTED-FORMAT"), words)
            self.assertNotIn("Traceback", result.stderr, words)
            # the same package, undamaged, verifies again
            self.package(BAD_DAY_SESSION, "--folder", "--out",
                         str(self.work / f"again-{len(words)}"))
            folder = self.work / f"again-{len(words)}"

    def test_a_damaged_zip_is_refused_unopened(self):
        # is_zipfile reads only the end record; damage in a member's
        # header surfaces when unpacking, and is a refusal, never a
        # traceback.
        result = self.package(BAD_DAY_SESSION)
        self.assertEqual(result.returncode, 0, result.stderr)
        zipped = next(self.work.glob("*.zip"))
        raw = bytearray(zipped.read_bytes())
        for i in range(40, 60):
            raw[i] ^= 0xFF
        zipped.write_bytes(bytes(raw))

        judged = self.verify_package(zipped)

        self.assertEqual(judged.returncode, 4, judged.stdout + judged.stderr)
        self.assertTrue(judged.stdout.strip().splitlines()[-1]
                        .startswith("UNSUPPORTED-FORMAT"), judged.stdout)
        self.assertNotIn("Traceback", judged.stderr)

    def test_a_chain_of_another_format_is_a_refusal_on_the_last_line(self):
        # A packaged chain whose genesis claims a format this verifier
        # does not speak: the recorder refuses it, and the package verdict
        # says so on the last line instead of failing to find a word.
        folder = self.folder_package()
        chain = next(p for p in folder.iterdir()
                     if p.name.startswith("receipts-")
                     and not p.name.endswith(".anchors.jsonl"))
        lines = chain.read_text("utf-8").splitlines()
        genesis = json.loads(lines[0])
        genesis["v"] = "9.9"
        lines[0] = json.dumps(genesis, sort_keys=True, separators=(",", ":"))
        chain.write_text("\n".join(lines) + "\n", "utf-8")

        result = self.verify_package(folder)

        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        last = result.stdout.strip().splitlines()[-1]
        self.assertTrue(last.startswith("UNSUPPORTED-FORMAT"), last)
        self.assertNotIn("Traceback", result.stderr)

    def test_out_into_a_missing_folder_is_created(self):
        result = self.package(BAD_DAY_SESSION, "--out",
                              str(self.work / "no" / "such" / "pkg.zip"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.work / "no" / "such" / "pkg.zip").exists())

    def test_readme_never_holds_the_manifest_hash_and_manifest_is_last(self):
        folder = self.folder_package()
        manifest = folder / "manifest.json"
        readme = (folder / "README.md").read_text("utf-8")
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.assertNotIn(digest, readme)
        self.assertNotIn(digest[:12], readme)
        # The README may print the chain heads, which exist before it.
        listed = json.loads(manifest.read_text("utf-8"))
        for chain in listed["chains"]:
            self.assertIn(chain["head"], readme)
        # Written last: nothing in the package is newer than the manifest,
        # and the manifest lists every other file.
        others = [p for p in folder.iterdir() if p.name != "manifest.json"]
        for other in others:
            self.assertLessEqual(other.stat().st_mtime,
                                 manifest.stat().st_mtime, other.name)
        named = ({c["path"] for c in listed["chains"]}
                 | {a["path"] for a in listed["artifacts"]})
        self.assertEqual(named, {p.name for p in others})


# --- A hook-built store with a sibling chain and an anchor sidecar ----------

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
SESSION = "c0c0c0c0-aaaa-bbbb-cccc-000000000001"


def ots_varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | 0x80 if n else byte)
        if not n:
            return bytes(out)


def completed_anchor(head, height=850000):
    """A minimal but genuine OTS timestamp record (docs/ANCHORING.md §4):
    one sha256 op, then a Bitcoin attestation, so `verify --anchors`
    replays it offline and prints ANCHORED. Reimplemented here, like
    test_anchor.py does, so the test proves the tool matches the format."""
    import base64
    payload = ots_varint(height)
    proof = b"\x08" + b"\x00" + TAG_BITCOIN + ots_varint(len(payload)) + payload
    return json.dumps({"head": head, "n": 3, "ts": "2026-08-22T09:00:00Z",
                       "calendar": "https://calendar.example.test",
                       "proof": base64.b64encode(proof).decode()}) + "\n"


class HookStorePackageTest(PackageCase):
    """A store written through `loxodonta hook`: one session whose
    recording continued in a -002 sibling, with an anchor sidecar on the
    first chain, so the package has more than one chain and more than
    one kind of artifact to carry."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "main.py").write_text("print(1)\n", "utf-8")
        self.witness = self.root / "no-witness"
        self.witness.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        self.env = neutral_env(self.home)
        for command in ("pytest -q", "git status", "git commit -m x"):
            self.hook(SESSION, "Bash", {"command": command})
        self.hook(SESSION + "-002", "Edit", {"file_path": "main.py"})
        drawers = [p for p in (self.home / ".loxodonta" / "receipts").iterdir()
                   if p.is_dir()]
        self.assertEqual(len(drawers), 1)
        self.chain = drawers[0] / f"receipts-{SESSION}.jsonl"
        self.sibling = drawers[0] / f"receipts-{SESSION}-002.jsonl"
        self.sidecar = drawers[0] / f"receipts-{SESSION}.jsonl.anchors.jsonl"
        head = run(LOXODONTA, "head", "--log", str(self.chain)).stdout.strip()
        self.sidecar.write_text(completed_anchor(head), encoding="utf-8")

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

    def test_siblings_travel_together_and_anchor_lines_print_verbatim(self):
        result = self.package(SESSION, "--folder", "--out",
                              str(self.work / "pkg"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        folder = self.work / "pkg"
        manifest = json.loads((folder / "manifest.json").read_text("utf-8"))
        self.assertEqual([c["path"] for c in manifest["chains"]],
                         [self.chain.name, self.sibling.name])
        self.assertEqual([c["anchors"] for c in manifest["chains"]],
                         [self.sidecar.name, None])
        self.assertEqual([c["entries"] for c in manifest["chains"]], [4, 2])
        # The sidecar is a post-close artifact, listed by hash (ruling 3).
        self.assertIn(self.sidecar.name,
                      [a["path"] for a in manifest["artifacts"]])
        self.assertEqual((folder / self.sidecar.name).read_bytes(),
                         self.sidecar.read_bytes())

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        out = judged.stdout
        self.assertEqual(out.count("\nchain: "), 2, out)
        # The recorder's own anchor line, under its chain, as detail
        # (ruling 6): the chain is anchored, the package is not.
        self.assertIn("ANCHORED: entries 0..3 existed by Bitcoin block 850000",
                      out)
        self.assertIn(f"{self.sidecar.name}: matches the manifest", out)
        lines = out.strip().splitlines()
        self.assertTrue(lines[-1].startswith("SELF-CONSISTENT"), lines[-1])
        self.assertNotIn("ANCHORED", lines[-1])

    def test_a_foreign_anchor_outranks_the_diverged_sidecar_exit_3(self):
        # Gravest wins (ruling 7): rewriting the sidecar diverges it from
        # the manifest (2), and the head it now names is nowhere in the
        # chain (3); the package says the graver thing last.
        self.package(SESSION, "--folder", "--out", str(self.work / "pkg"))
        folder = self.work / "pkg"
        (folder / self.sidecar.name).write_text(
            completed_anchor("ab" * 32), encoding="utf-8")

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("ANCHOR-MISMATCH"), lines[-1])
        self.assertTrue(any(l.startswith(f"{self.sidecar.name}: DIVERGED")
                            for l in lines), judged.stdout)

    def test_a_session_split_across_drawers_is_refused_not_flattened(self):
        # Before ADR-0023 a session could land in two drawers under the
        # same chain name. The package lays chains flat beside one
        # project record, so two drawers would mean one chain silently
        # overwriting the other: refused, named, nothing written.
        other = self.chain.parent.parent / "other-00000000"
        other.mkdir()
        (other / self.chain.name).write_bytes(self.chain.read_bytes())
        (other / "project.json").write_text(
            json.dumps({"path": (self.root / "other").as_posix()}), "utf-8")

        result = self.package(SESSION)

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("drawers", result.stderr)
        self.assertFalse(list(self.work.iterdir()))

    def test_an_unknown_selector_is_refused_and_writes_nothing(self):
        for selector in ("nonesuch", "deadbeef"):
            result = self.package(selector)
            self.assertNotEqual(result.returncode, 0, selector)
            self.assertIn(selector, result.stderr)
            self.assertFalse(list(self.work.iterdir()), selector)


if __name__ == "__main__":
    unittest.main()
