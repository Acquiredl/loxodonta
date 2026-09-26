"""A sidecar path that is not a file (#364).

The sidecars sit beside their chain, in the writer's reach, and
`mkdir <log>.anchors.jsonl` is one command. Every reader and every
writer takes a path there that is not a regular file, a folder or a
pipe, as a sidecar that cannot be read (SPEC section 9.1): a judge names
it as evidence that does not verify, the scan goes on to the next chain,
and a verb that would append to it says why it could not. Never a
traceback, never a stopped scan, never a hang.

Every test drives the public CLI: the recorder's verbs, its hook at
SessionEnd, the supervisor's scan and keeper, against the fake calendar,
authority and receiver the other suites use. No network, no internals.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_sidecar_not_a_file`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env  # noqa: E402
from test_package_anchor import SESSION, AnchoredStoreCase  # noqa: E402
from test_publish import PublishBase  # noqa: E402
from test_stamp import start_authority  # noqa: E402
from test_supervisor import (chains_by_session, home_outside,  # noqa: E402
                             isolated_env, make_chain, run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"

SUFFIXES = (".anchors.jsonl", ".stamps.jsonl", ".published.jsonl")
FOLDER = "it is a folder, not a file"
PIPE = "it is not a regular file"
NOT_EVIDENCE = "evidence that does not verify is not evidence"
# A pipe opened for reading waits for a writer that never comes, so a
# reader that opened one would hang: every run here is bounded.
BOUND = 60


def run_receipts(*args, cwd):
    return subprocess.run([sys.executable, str(LOXODONTA), *args], cwd=cwd,
                          capture_output=True, encoding="utf-8",
                          env=clean_env(), timeout=BOUND)


def start_calendar(case):
    server = FakeCalendar(("127.0.0.1", 0), FakeCalendarHandler)
    server.nonce = b"fake-nonce"
    server.prefix = b"left-branch"
    server.suffix = b"right-branch"
    server.height = 850000
    server.mode = "pending"
    server.submitted = []
    server.polled = []
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class PostCounter(FakeCalendarHandler):
    """A remote that takes every POST and keeps the path of each."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.received.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def serve_posts(case):
    """A remote that takes every POST, closed when `case` finishes."""
    server = FakeCalendar(("127.0.0.1", 0), PostCounter)
    server.received = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    case.addCleanup(server.server_close)
    case.addCleanup(server.shutdown)
    return server


class JudgedNotAFileTest(unittest.TestCase):
    """`verify --anchors` and `verify --stamps` with a folder, or a pipe,
    where the sidecar belongs: named by its bare name and why, the
    exit-3 tier an unreadable line has, and never NO-ANCHORS, which is
    what an absent sidecar says."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)

    def test_a_folder_where_the_anchors_sidecar_belongs_is_anchor_invalid(self):
        (self.workdir / "receipts.jsonl.anchors.jsonl").mkdir()

        result = run_receipts("verify", "--anchors", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("ANCHOR-INVALID: receipts.jsonl.anchors.jsonl cannot be "
                      f"read as a sidecar: {FOLDER} — {NOT_EVIDENCE}",
                      result.stdout)
        self.assertNotIn("NO-ANCHORS", result.stdout)

    def test_a_folder_where_the_stamps_sidecar_belongs_is_stamp_invalid(self):
        (self.workdir / "receipts.jsonl.stamps.jsonl").mkdir()

        result = run_receipts("verify", "--stamps", cwd=self.workdir)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("STAMP-INVALID: receipts.jsonl.stamps.jsonl cannot be "
                      f"read as a sidecar: {FOLDER} — {NOT_EVIDENCE}",
                      result.stdout)
        self.assertNotIn("NO-STAMPS", result.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_a_pipe_where_a_sidecar_belongs_is_named_and_never_waited_on(self):
        for flag, suffix, word in (("--anchors", ".anchors.jsonl",
                                    "ANCHOR-INVALID"),
                                   ("--stamps", ".stamps.jsonl",
                                    "STAMP-INVALID")):
            with self.subTest(sidecar=suffix):
                pipe = self.workdir / ("receipts.jsonl" + suffix)
                os.mkfifo(pipe)
                self.addCleanup(pipe.unlink)

                result = run_receipts("verify", flag, cwd=self.workdir)

                self.assertEqual(result.returncode, 3,
                                 result.stdout + result.stderr)
                self.assertIn(f"{word}: receipts.jsonl{suffix} cannot be "
                              f"read as a sidecar: {PIPE}", result.stdout)


class PackagedNotAFileTest(AnchoredStoreCase):
    """`verify-package` with a folder where a sidecar belongs: beside a
    chain it is that chain's ANCHOR-INVALID or STAMP-INVALID, which the
    package words as ANCHOR-MISMATCH or STAMP-INVALID, and the listed
    artifact it replaced diverges; beside the manifest, under a declared
    seal, it is SEAL-INVALID. Exit 3 each way (SPEC section 9.1)."""

    def test_a_folder_beside_a_packaged_chain_is_anchor_mismatch(self):
        folder = self.folder_package(SESSION)
        sidecar = folder / (self.chain.name + ".anchors.jsonl")
        sidecar.unlink()
        sidecar.mkdir()

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        self.assertNotIn("Traceback", judged.stderr)
        self.assertIn(f"ANCHOR-INVALID: {sidecar.name} cannot be read as a "
                      f"sidecar: {FOLDER}", judged.stdout)
        self.assertIn(f"{sidecar.name}: DIVERGED from the manifest: {FOLDER}",
                      judged.stdout)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("ANCHOR-MISMATCH"), lines[-1])

    def test_a_folder_for_a_listed_stamps_sidecar_is_stamp_invalid(self):
        folder = self.folder_package(SESSION)
        name = self.chain.name + ".stamps.jsonl"

        def list_stamps(manifest):
            (row,) = manifest["chains"]
            row["stamps"] = name
        self.rewrite_manifest(folder, list_stamps)
        (folder / name).mkdir()

        judged = self.verify_package(folder)

        self.assertEqual(judged.returncode, 3, judged.stdout + judged.stderr)
        self.assertNotIn("Traceback", judged.stderr)
        self.assertIn(f"STAMP-INVALID: {name} cannot be read as a sidecar: "
                      f"{FOLDER}", judged.stdout)
        lines = judged.stdout.strip().splitlines()
        self.assertTrue(lines[-1].startswith("STAMP-INVALID"), lines[-1])

    def test_a_folder_for_a_declared_seal_is_seal_invalid(self):
        for kind, name in (("anchor", "manifest.json.anchors.jsonl"),
                           ("stamp", "manifest.json.stamps.jsonl")):
            with self.subTest(seal=kind):
                folder = self.work / f"sealed-{kind}"
                packed = self.package(SESSION, "--folder", "--out",
                                      str(folder))
                self.assertEqual(packed.returncode, 0,
                                 packed.stdout + packed.stderr)
                self.rewrite_manifest(
                    folder, lambda manifest: manifest["seals"].append(kind))
                (folder / name).mkdir()

                judged = self.verify_package(folder)

                self.assertEqual(judged.returncode, 3,
                                 judged.stdout + judged.stderr)
                self.assertNotIn("Traceback", judged.stderr)
                self.assertIn(f"seal {kind}: SEAL-INVALID: {name} cannot be "
                              f"read as a sidecar: {FOLDER}", judged.stdout)
                self.assertNotIn("SEAL-MISSING", judged.stdout)
                lines = judged.stdout.strip().splitlines()
                self.assertTrue(lines[-1].startswith("SEAL-INVALID"),
                                lines[-1])


class PackedNotAFileTest(AnchoredStoreCase):
    """`supervisor package`, the issuer's side, with a folder where a
    chain's sidecar belongs."""

    def test_package_refuses_a_chain_whose_sidecar_is_a_folder(self):
        # The issuer's side: the sidecar travels as it stands, and a
        # folder cannot, so nothing is written rather than a package
        # that quietly lacks it.
        for suffix in (".anchors.jsonl", ".stamps.jsonl"):
            with self.subTest(sidecar=suffix):
                sidecar = self.chain.with_name(self.chain.name + suffix)
                if sidecar.exists():
                    sidecar.unlink()
                sidecar.mkdir()
                out = self.work / f"refused{suffix}"

                packed = self.package(SESSION, "--folder", "--out", str(out))

                self.assertEqual(packed.returncode, 1,
                                 packed.stdout + packed.stderr)
                self.assertNotIn("Traceback", packed.stderr)
                self.assertIn(f"{sidecar.name} cannot be packed: {FOLDER}",
                              packed.stderr)
                self.assertFalse(out.exists())
                sidecar.rmdir()


class WrittenNotAFileTest(unittest.TestCase):
    """The operator's verbs that append to a sidecar, with a folder in
    its place: each says what it could not write and why, with the exit
    ADR-0037 gives a file the verb must create and cannot (73), or a
    sidecar it must read and cannot (66); the folder stays a folder.
    Every run is bounded, so a verb that waited would fail, not hang."""

    WHY = FOLDER

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)

    def folder(self, suffix):
        """What stands where the sidecar belongs: a folder here."""
        path = self.workdir / ("receipts.jsonl" + suffix)
        path.mkdir()
        return path

    def still_there(self, path):
        return path.is_dir()

    def test_anchor_says_the_proof_could_not_be_written(self):
        calendar = start_calendar(self)
        sidecar = self.folder(".anchors.jsonl")

        result = run_receipts("anchor", "--calendar", calendar.url,
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("could not be written", result.stderr)
        self.assertIn(self.WHY, result.stderr)
        self.assertTrue(self.still_there(sidecar))

    def test_anchor_upgrade_says_the_sidecar_cannot_be_read(self):
        self.folder(".anchors.jsonl")

        result = run_receipts("anchor", "--upgrade", cwd=self.workdir)

        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("receipts.jsonl.anchors.jsonl cannot be read as a "
                      f"sidecar: {self.WHY}", result.stderr)

    def test_stamp_says_the_token_could_not_be_written(self):
        authority = start_authority(self)
        self.folder(".stamps.jsonl")

        result = run_receipts("stamp", "--authority", authority.url,
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(self.WHY, result.stderr)

    def test_publish_says_the_memo_could_not_be_written(self):
        # The remote took the head, so the verb says so; the memo that
        # would stop the keeper posting it again could not be written.
        receiver = serve_posts(self)
        url = f"http://127.0.0.1:{receiver.server_address[1]}/hook"
        self.folder(".published.jsonl")

        result = run_receipts("publish", url, cwd=self.workdir)

        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("published head", result.stdout)
        self.assertIn("the memo could not be written", result.stderr)
        self.assertIn(self.WHY, result.stderr)
        self.assertEqual(len(receiver.received), 1)

    def test_publish_chain_sends_nothing_without_the_memo(self):
        receiver = serve_posts(self)
        url = f"http://127.0.0.1:{receiver.server_address[1]}/chain"
        self.folder(".published.jsonl")

        result = run_receipts("publish", "--chain", url, cwd=self.workdir)

        self.assertEqual(result.returncode, 69, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("the memo could not be read", result.stderr)
        self.assertEqual(receiver.received, [])


@unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
class WrittenPipeTest(WrittenNotAFileTest):
    """The same verbs with a pipe, and no reader, where the sidecar
    belongs. An ordinary open of it for appending never returns, so each
    verb opens without waiting and answers as it does a folder."""

    WHY = PIPE

    def folder(self, suffix):
        path = self.workdir / ("receipts.jsonl" + suffix)
        os.mkfifo(path)
        return path

    def still_there(self, path):
        return stat.S_ISFIFO(os.lstat(path).st_mode)


@unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "symlink"),
                     "no named pipes here")
class WrittenPipeLinkTest(WrittenPipeTest):
    """A link to a pipe is followed, as every file is, and is a pipe."""

    def folder(self, suffix):
        pipe = self.workdir / ("elsewhere" + suffix)
        os.mkfifo(pipe)
        path = self.workdir / ("receipts.jsonl" + suffix)
        os.symlink(pipe, path)
        return path

    def still_there(self, path):
        return stat.S_ISFIFO(os.stat(path).st_mode)


class SessionEndNotAFileTest(PublishBase):
    """The hook at SessionEnd, wired for every step that writes a
    sidecar (the head, the chain, the stamp, the anchor), with a folder
    in the place of all three: quiet and exit 0, as it is on every
    other failure (ADR-0024), and the folders untouched."""

    def test_every_session_end_step_passes_a_folder_by_quietly(self):
        calendar = start_calendar(self)
        authority = start_authority(self)
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        folders = [self.chain().with_name(self.chain().name + suffix)
                   for suffix in SUFFIXES]
        for folder in folders:
            folder.mkdir()

        result = self.session_end(
            "--publish", self.receiver.url,
            "--publish-chain", self.receiver.url,
            "--stamp", authority.url,
            "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        # The seal of the transcript's tail is the one line: the steps
        # after it are quiet, a folder in their way or not.
        self.assertEqual(result.stderr, "")
        self.assertNotIn("Traceback", result.stdout)
        for folder in folders:
            self.assertTrue(folder.is_dir(), folder.name)

    def hook(self, payload, *extra):
        # PublishBase's hook, bounded: a step that waited on a pipe would
        # fail the test rather than hold the suite.
        env = isolated_env(self.home, CLAUDE_PROJECT_DIR=str(self.project),
                           LOXODONTA_HOME=str(self.store),
                           PYTHONIOENCODING="utf-8")
        result = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook", *extra],
            cwd=self.project, input=json.dumps(payload).encode("utf-8"),
            capture_output=True, env=env, timeout=BOUND)
        result.stdout = result.stdout.decode("utf-8", "replace")
        result.stderr = result.stderr.decode("utf-8", "replace")
        return result

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_every_session_end_step_passes_a_pipe_by_quietly(self):
        calendar = start_calendar(self)
        authority = start_authority(self)
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        pipes = [self.chain().with_name(self.chain().name + suffix)
                 for suffix in SUFFIXES]
        for pipe in pipes:
            os.mkfifo(pipe)

        result = self.session_end(
            "--publish", self.receiver.url,
            "--publish-chain", self.receiver.url,
            "--stamp", authority.url,
            "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        for pipe in pipes:
            self.assertTrue(stat.S_ISFIFO(os.lstat(pipe).st_mode), pipe.name)


class ScannedNotAFileTest(unittest.TestCase):
    """`supervisor scan`, and its keepers, with a folder or a pipe where
    a sidecar belongs: the scan finishes, every chain is in the report,
    a folder of proofs is the chain's ANCHOR-INVALID, and a keeper that
    cannot write says so in its note."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.env = isolated_env(home_outside(self))

    def scan(self, *extra):
        result = run_scan(self.root, *extra, env=self.env)
        self.assertNotIn("Traceback", result.stderr)
        return result, chains_by_session(json.loads(result.stdout))

    def test_a_folder_named_like_any_sidecar_never_stops_the_scan(self):
        for suffix in SUFFIXES:
            with self.subTest(sidecar=suffix):
                root = self.root / suffix[1:-6]
                log = make_chain(root / "alpha" / "receipts", "sess-aaaa")
                make_chain(root / "beta" / "receipts", "sess-bbbb")
                Path(str(log) + suffix).mkdir()

                result = run_scan(root, env=self.env)

                self.assertNotIn("Traceback", result.stderr)
                sessions = chains_by_session(json.loads(result.stdout))
                (chain,) = sessions[("alpha", "sess-aaaa")]
                (other,) = sessions[("beta", "sess-bbbb")]
                self.assertEqual(other["verdict"], "VALID")
                self.assertFalse(chain["anchored"])
                if suffix == ".anchors.jsonl":
                    self.assertEqual(result.returncode, 3, result.stdout)
                    self.assertEqual(chain["verdict"], "ANCHOR-INVALID")
                else:
                    self.assertEqual(result.returncode, 0,
                                     result.stdout + result.stderr)
                    self.assertEqual(chain["verdict"], "VALID")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_a_pipe_named_like_any_sidecar_is_never_waited_on(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        for suffix in SUFFIXES:
            os.mkfifo(str(log) + suffix)

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "supervisor.py"), "scan",
             "--root", str(self.root), "--json"],
            capture_output=True, encoding="utf-8", timeout=BOUND,
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

        self.assertNotIn("Traceback", result.stderr)
        (chain,) = chains_by_session(json.loads(result.stdout))[
            ("alpha", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "ANCHOR-INVALID")

    def test_the_anchor_keeper_says_the_proof_could_not_be_written(self):
        calendar = start_calendar(self)
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        Path(str(log) + ".anchors.jsonl").mkdir()

        result, sessions = self.scan("--anchor-every", "0s",
                                     "--calendar", calendar.url)

        (chain,) = sessions[("alpha", "sess-aaaa")]
        self.assertIn("could not be written", chain["anchors"]["note"])

    def test_the_publish_keeper_says_the_memo_could_not_be_written(self):
        receiver = serve_posts(self)
        url = f"http://127.0.0.1:{receiver.server_address[1]}/hook"
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        Path(str(log) + ".published.jsonl").mkdir()

        result, sessions = self.scan("--publish-every", "0s",
                                     "--publish-url", url,
                                     "--publish-chain", url)

        (chain,) = sessions[("alpha", "sess-aaaa")]
        note = chain["left"]["note"]
        self.assertIn("the memo could not be written", note)
        self.assertIn("the memo could not be read", note)
        self.assertEqual(len(receiver.received), 1, "the head went once")


if __name__ == "__main__":
    unittest.main()
