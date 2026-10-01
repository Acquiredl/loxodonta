"""A sidecar path that is not a file (#364), and a chain path (#374, #385).

The sidecars sit beside their chain, in the writer's reach, and
`mkdir <log>.anchors.jsonl` is one command. Every reader and every
writer takes a path there that is not a regular file, a folder or a
pipe, as a sidecar that cannot be read (SPEC section 9.1): a judge names
it as evidence that does not verify, the scan goes on to the next chain,
and a verb that would append to it says why it could not. Never a
traceback, never a stopped scan, never a hang.

The chain itself is in the same reach. `verify` and `head` call a chain
path that is not a regular file no input, the scan names it and goes on,
and `package` and `export` never copy it (SPEC section 6). The hook
reads it as damage and keeps its receipt in a sibling, and the other
writers refuse it as `verify` does (#385).

Every test drives the public CLI: the recorder's verbs, its hook at
SessionEnd, the supervisor's scan and keeper, against the fake calendar,
authority and receiver the other suites use. No network, no internals.
"""

import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_sidecar_not_a_file`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env  # noqa: E402
from test_export import OTHER_SESSION, ExportBase  # noqa: E402
from test_package_anchor import SESSION, AnchoredStoreCase  # noqa: E402
from test_publish import PublishBase  # noqa: E402
from test_stamp import start_authority  # noqa: E402
from test_supervisor import (chains_by_session, home_outside,  # noqa: E402
                             isolated_env, make_chain, run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

SUFFIXES = (".anchors.jsonl", ".stamps.jsonl", ".published.jsonl")
FOLDER = "it is a folder, not a file"
PIPE = "it is not a regular file"
NOT_EVIDENCE = "evidence that does not verify is not evidence"
NO_CHAIN = "cannot be read as a receipt log"
# A pipe opened for reading waits for a writer that never comes, so a
# reader that opened one would hang: every run here is bounded.
BOUND = 60


def run_receipts(*args, cwd):
    return subprocess.run([sys.executable, str(LOXODONTA), *args], cwd=cwd,
                          capture_output=True, encoding="utf-8",
                          env=clean_env(), timeout=BOUND)


HOOKED = "sess-1234abcd"


def fire_hook(case, log_dir, command):
    """One PostToolUse receipt for session HOOKED into `log_dir`, run
    with homes of `case`'s own and bounded."""
    payload = json.dumps({"session_id": HOOKED,
                          "hook_event_name": "PostToolUse",
                          "tool_name": "Bash",
                          "tool_input": {"command": command}})
    return subprocess.run(
        [sys.executable, str(LOXODONTA), "hook", "--log-dir", str(log_dir)],
        input=payload, capture_output=True, encoding="utf-8",
        cwd=str(log_dir), timeout=BOUND,
        env=isolated_env(home_outside(case), PYTHONIOENCODING="utf-8"))


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


class ChainNotAFileTest(unittest.TestCase):
    """`verify` and `head` with a folder, a pipe or a device where the
    chain belongs (#374): no input, exit 66, the reason on stderr and
    nothing on stdout, as for a missing chain (SPEC section 6). The chain
    is in the writer's reach as its sidecars are, so a pipe there is
    never waited on and a device never read."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.log = self.workdir / "receipts.jsonl"

    def assert_no_input(self, why):
        for verb in ("verify", "head"):
            with self.subTest(verb=verb):
                result = run_receipts(verb, cwd=self.workdir)

                self.assertEqual(result.returncode, 66,
                                 result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(f"receipts.jsonl {NO_CHAIN}: {why}",
                              result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_a_folder_where_the_chain_belongs_is_no_input(self):
        # In a folder's words on every platform, though Windows refuses
        # to open one as a denied permission (#270).
        self.log.mkdir()

        self.assert_no_input(FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_a_pipe_where_the_chain_belongs_is_never_waited_on(self):
        os.mkfifo(self.log)

        self.assert_no_input(PIPE)

    @unittest.skipUnless(hasattr(os, "symlink")
                         and os.path.exists("/dev/zero"), "no /dev/zero here")
    def test_a_device_where_the_chain_belongs_is_never_read(self):
        os.symlink("/dev/zero", self.log)

        self.assert_no_input(PIPE)


class WrittenChainNotAFileTest(unittest.TestCase):
    """The writers with a folder where the chain belongs (#385). The hook
    reads it as damage, as it reads a torn tail, and keeps the receipt in
    a sibling (ADR-0004); `log`, `run`, `anchor`, `publish` and `stamp`
    refuse it in `verify`'s words, exit 66, and `run` before its command
    runs. What stands there is left as it lies, and no lock is left
    beside it. Every run is bounded, so a writer that waited would fail,
    not hang."""

    WHY = FOLDER

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.log = self.workdir / "receipts.jsonl"

    def put(self, path):
        """What stands where the chain belongs: a folder here."""
        path.mkdir()

    def still_there(self, path):
        return path.is_dir()

    def assert_no_lock(self):
        self.assertEqual(list(self.workdir.glob("*.lock")), [])

    def test_the_hook_keeps_the_receipt_in_a_sibling(self):
        chain = self.workdir / f"receipts-{HOOKED}.jsonl"
        self.put(chain)

        result = fire_hook(self, self.workdir, "echo kept")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        sibling = self.workdir / f"receipts-{HOOKED}-002.jsonl"
        entries = [json.loads(line) for line
                   in sibling.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["action"] for e in entries],
                         ["genesis", "Bash: echo kept"])
        self.assertTrue(self.still_there(chain))
        self.assert_no_lock()

    def test_the_operators_verbs_refuse_it_as_verify_does(self):
        self.put(self.log)
        calendar = start_calendar(self)
        authority = start_authority(self)
        receiver = serve_posts(self)
        remote = f"http://127.0.0.1:{receiver.server_address[1]}"
        verbs = {
            "log": ["log", "--actor", "agent", "--action", "x"],
            "anchor": ["anchor", "--calendar", calendar.url],
            "publish": ["publish", remote + "/hook"],
            "publish --chain": ["publish", "--chain", remote + "/chain"],
            "stamp": ["stamp", "--authority", authority.url],
        }
        for verb, args in verbs.items():
            with self.subTest(verb=verb):
                result = run_receipts(*args, cwd=self.workdir)

                self.assertEqual(result.returncode, 66,
                                 result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn(f"receipts.jsonl {NO_CHAIN}: {self.WHY}",
                              result.stderr)
                self.assertTrue(self.still_there(self.log))
                self.assert_no_lock()
        self.assertEqual(calendar.submitted, [])
        self.assertEqual(authority.received, [])
        self.assertEqual(receiver.received, [])

    def test_run_refuses_it_before_its_command_runs(self):
        # No receipt can be written, so the command must not run: the
        # wrapper would execute work it cannot record.
        self.put(self.log)

        result = run_receipts(
            "run", "--actor", "agent", "--",
            sys.executable, "-c", "open('side-effect.txt', 'w').write('ran')",
            cwd=self.workdir)

        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(f"receipts.jsonl {NO_CHAIN}: {self.WHY}", result.stderr)
        self.assertFalse((self.workdir / "side-effect.txt").exists())
        self.assertTrue(self.still_there(self.log))
        self.assert_no_lock()


@unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
class WrittenChainPipeTest(WrittenChainNotAFileTest):
    """The same writers with a pipe, and no reader, where the chain
    belongs. An ordinary open of it for writing never returns, so the
    hook waited there for ever with the lock held (#385)."""

    WHY = PIPE

    def put(self, path):
        os.mkfifo(path)

    def still_there(self, path):
        return stat.S_ISFIFO(os.lstat(path).st_mode)


@unittest.skipUnless(hasattr(os, "symlink")
                     and os.path.exists("/dev/zero"), "no /dev/zero here")
class WrittenChainDeviceTest(WrittenChainNotAFileTest):
    """The same writers with a link to a device where the chain belongs:
    followed, as every file is, and never written."""

    WHY = PIPE

    def put(self, path):
        os.symlink("/dev/zero", path)

    def still_there(self, path):
        return os.path.islink(path)


class UnopenableChainTest(unittest.TestCase):
    """A socket or a loop of links where the chain belongs: the open
    fails before it can ask what it opened, so the hook asks the name,
    reads either as damage and keeps the receipt in a sibling (#385)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.chain = self.workdir / f"receipts-{HOOKED}.jsonl"

    def assert_kept_in_a_sibling(self):
        result = fire_hook(self, self.workdir, "echo kept")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        sibling = self.workdir / f"receipts-{HOOKED}-002.jsonl"
        entries = [json.loads(line) for line
                   in sibling.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["action"] for e in entries],
                         ["genesis", "Bash: echo kept"])
        self.assertEqual(list(self.workdir.glob("*.lock")), [])

    @unittest.skipUnless(hasattr(socket, "AF_UNIX") and hasattr(os, "mkfifo"),
                         "no Unix sockets here")
    def test_a_socket_where_the_chain_belongs(self):
        with socket.socket(socket.AF_UNIX) as bound:
            bound.bind(str(self.chain))

        self.assert_kept_in_a_sibling()
        self.assertTrue(stat.S_ISSOCK(os.lstat(self.chain).st_mode))

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix",
                         "no POSIX links here")
    def test_a_loop_of_links_where_the_chain_belongs(self):
        os.symlink(self.chain.name, self.chain)

        self.assert_kept_in_a_sibling()
        self.assertTrue(self.chain.is_symlink())


@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                 "root writes to a read-only file")
class UnwritableChainTest(unittest.TestCase):
    """A chain that reads as a file and will not take a line: read-only,
    the way through the CLI to the write's own refusal, which a pipe put
    at the name after the read meets too (#385). `log`, `run` and the
    hook say the chain could not be written, exit 73, a file the verb
    must write and cannot. A file that will not take a line is not
    damage, so no sibling starts; the chain is left byte for byte, and
    no lock beside it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.chain = self.workdir / f"receipts-{HOOKED}.jsonl"
        first = fire_hook(self, self.workdir, "echo first")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.before = self.chain.read_bytes()
        os.chmod(self.chain, stat.S_IREAD)
        # Writable again before the folder goes, which Windows refuses
        # while a file in it is read-only.
        self.addCleanup(os.chmod, self.chain, stat.S_IREAD | stat.S_IWRITE)

    def assert_not_written(self, result):
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("could not be written", result.stderr)
        self.assertIn("no entry was written", result.stderr)
        self.assertEqual(self.chain.read_bytes(), self.before)
        self.assertEqual(list(self.workdir.glob("*.lock")), [])

    def test_log_says_the_chain_could_not_be_written(self):
        result = run_receipts("log", "--log", str(self.chain),
                              "--actor", "agent", "--action", "x",
                              cwd=self.workdir)

        self.assert_not_written(result)

    def test_run_says_so_after_its_command_ran(self):
        result = run_receipts("run", "--log", str(self.chain),
                              "--actor", "agent", "--",
                              sys.executable, "-c", "pass", cwd=self.workdir)

        self.assert_not_written(result)
        self.assertIn("receipt not written for", result.stderr)

    def test_the_hook_says_the_chain_could_not_be_written(self):
        result = fire_hook(self, self.workdir, "echo second")

        self.assert_not_written(result)
        self.assertFalse(
            (self.workdir / f"receipts-{HOOKED}-002.jsonl").exists())


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
    chain's sidecar belongs, or a folder or a pipe where the chain does
    (#374)."""

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

    def assert_chain_refused(self, why):
        # Bounded: a package that waited on the pipe would fail here.
        out = self.work / "refused"
        packed = subprocess.run(
            [sys.executable, str(SUPERVISOR), "package", SESSION,
             "--witness", str(self.witness), "--folder", "--out", str(out)],
            capture_output=True, encoding="utf-8", errors="replace",
            env={**self.env, "PYTHONIOENCODING": "utf-8"},
            cwd=str(self.work), timeout=BOUND)

        self.assertEqual(packed.returncode, 1, packed.stdout + packed.stderr)
        self.assertNotIn("Traceback", packed.stderr)
        self.assertIn(f"{self.chain.name} cannot be packed: {why}",
                      packed.stderr)
        self.assertFalse(out.exists())

    def test_package_refuses_a_folder_where_the_chain_belongs(self):
        self.chain.unlink()
        self.chain.mkdir()

        self.assert_chain_refused(FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_package_refuses_a_pipe_where_the_chain_belongs(self):
        self.chain.unlink()
        os.mkfifo(self.chain)

        self.assert_chain_refused(PIPE)


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


@unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
class ReferencedPipeTest(unittest.TestCase):
    """A file reference that is a pipe or a device goes through the same
    open as a sidecar (#364, the pipe and device half of #270): `log
    --file` refuses it, and `verify --files` names it and goes on to its
    verdict. Neither waits on the pipe or reads the device."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)

    def pipe_and_device(self):
        os.mkfifo(self.workdir / "pipe")
        os.symlink("/dev/zero", self.workdir / "zero")
        return ("pipe", "zero")

    def test_log_refuses_a_pipe_or_a_device(self):
        for name in self.pipe_and_device():
            with self.subTest(reference=name):
                result = run_receipts("log", "--actor", "agent", "--action",
                                      "x", "--file", name, cwd=self.workdir)

                self.assertEqual(result.returncode, 66,
                                 result.stdout + result.stderr)
                self.assertIn(f"{name}: {PIPE}", result.stderr)
                self.assertNotIn("Errno", result.stderr)

    def test_verify_files_names_a_reference_that_became_a_pipe(self):
        later = self.workdir / "later"
        for make in (os.mkfifo, lambda p: os.symlink("/dev/zero", p)):
            with self.subTest(make=make):
                later.write_text("hi", encoding="utf-8")
                run_receipts("log", "--actor", "agent", "--action", "x",
                             "--file", "later", cwd=self.workdir)
                later.unlink()
                make(later)

                result = run_receipts("verify", "--files", cwd=self.workdir)

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn("MISSING (not a readable file here): later",
                              result.stdout)
                self.assertEqual(result.stdout.strip().splitlines()[-1],
                                 "VALID")
                later.unlink()


class ReferencedFolderTest(unittest.TestCase):
    """A file reference that is a folder, the directory half of #270:
    `log --file` and `run --file` refuse it in a folder's words, exit 66,
    on every platform, where Windows said `Permission denied`; `verify
    --files` names it and goes on to its verdict."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)
        (self.workdir / "sub").mkdir()

    def assert_refused(self, result):
        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertIn(f"sub: {FOLDER}", result.stderr)
        self.assertNotIn("Permission denied", result.stderr)
        self.assertNotIn("Errno", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_log_refuses_a_folder(self):
        result = run_receipts("log", "--actor", "agent", "--action", "x",
                              "--file", "sub", cwd=self.workdir)

        self.assert_refused(result)

    def test_run_refuses_a_folder_after_the_command_ran(self):
        result = run_receipts("run", "--actor", "agent", "--file", "sub",
                              "--", sys.executable, "-c", "pass",
                              cwd=self.workdir)

        self.assert_refused(result)
        self.assertIn("receipt not written for", result.stderr)

    def test_verify_files_names_a_reference_that_became_a_folder(self):
        later = self.workdir / "later"
        later.write_text("hi", encoding="utf-8")
        run_receipts("log", "--actor", "agent", "--action", "x",
                     "--file", "later", cwd=self.workdir)
        later.unlink()
        later.mkdir()

        result = run_receipts("verify", "--files", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MISSING (not a readable file here): later",
                      result.stdout)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "VALID")


class SessionEndNotAFileTest(PublishBase):
    """The hook at SessionEnd, wired for every step that writes a
    sidecar (the head, the chain, the stamp, the anchor), with a folder
    in the place of all three, or of the chain itself: quiet and exit 0,
    as it is on every other failure (ADR-0024), and the folders
    untouched."""

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

    def assert_quiet_where_the_chain_belongs(self, make):
        # The seal reads the chain before it writes, and a chain that
        # cannot be read is one more failure passed by quietly (#374);
        # no head is read, so nothing is sent.
        calendar = start_calendar(self)
        authority = start_authority(self)
        self.transcript.write_bytes(b"page one\n")
        self.tool_call()
        chain = self.chain()
        chain.unlink()
        make(chain)

        result = self.session_end(
            "--publish", self.receiver.url,
            "--publish-chain", self.receiver.url,
            "--stamp", authority.url,
            "--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.receiver.received, [])

    def test_the_session_end_passes_a_folder_where_the_chain_belongs(self):
        self.assert_quiet_where_the_chain_belongs(Path.mkdir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_the_session_end_passes_a_pipe_where_the_chain_belongs(self):
        self.assert_quiet_where_the_chain_belongs(os.mkfifo)


class ScannedNotAFileTest(unittest.TestCase):
    """`supervisor scan`, and its keepers, with a folder or a pipe where
    a sidecar belongs: the scan finishes, every chain is in the report,
    a folder of proofs is the chain's ANCHOR-INVALID, and a keeper that
    cannot write says so in its note. A folder or a pipe where a chain
    belongs is in the report too, with no verdict and verify's reason
    (#374)."""

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

    def assert_named(self, make, why):
        hollow = self.root / "alpha" / "receipts" / "receipts-sess-hollow.jsonl"
        hollow.parent.mkdir(parents=True)
        make(hollow)
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")

        # Bounded: a scan that waited on the pipe would fail here.
        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan",
             "--root", str(self.root), "--json"],
            capture_output=True, encoding="utf-8", timeout=BOUND,
            env={**self.env, "PYTHONIOENCODING": "utf-8"})

        self.assertNotIn("Traceback", result.stderr)
        # No verdict, verify's refusal as the evidence, and the refused
        # rung, 4, as for an empty chain; the other chain is judged.
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        sessions = chains_by_session(json.loads(result.stdout))
        (chain,) = sessions[("alpha", "sess-hollow")]
        self.assertEqual(chain["verdict"], "NO-VERDICT")
        self.assertEqual(chain["exit"], 4)
        self.assertEqual(chain["entries"], 0)
        self.assertTrue(any(f"{NO_CHAIN}: {why}" in line
                            for line in chain["detail"]), chain["detail"])
        (other,) = sessions[("beta", "sess-bbbb")]
        self.assertEqual(other["verdict"], "VALID")

    def test_a_folder_where_a_chain_belongs_is_named_and_the_scan_goes_on(self):
        self.assert_named(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
    def test_a_pipe_where_a_chain_belongs_is_named_and_never_waited_on(self):
        self.assert_named(os.mkfifo, PIPE)

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


@unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes here")
class ExportedPipeTest(ExportBase):
    """`supervisor export --raw` with a pipe where a chain belongs, and
    one where another chain's anchors sidecar does (#374): each is named
    on stderr and left out of the raw archive, never waited on, and the
    rest is written byte for byte."""

    def test_the_raw_archive_names_a_pipe_and_leaves_it_out(self):
        other = self.drawer() / f"receipts-{OTHER_SESSION}.jsonl"
        other.unlink()
        os.mkfifo(other)
        sidecar = self.log.with_name(self.log.name + ".anchors.jsonl")
        os.mkfifo(sidecar)

        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "export",
             "--witness", str(self.witness), "--raw"],
            input=b"yes\n", capture_output=True, cwd=str(self.work),
            env={**self.env, "PYTHONIOENCODING": "utf-8"}, timeout=BOUND)
        err = result.stderr.decode("utf-8", "replace")

        self.assertEqual(result.returncode, 0, err)
        self.assertNotIn("Traceback", err)
        self.assertIn(f"not archived: repo-1/{other.name}: {PIPE}", err)
        self.assertIn(f"not archived: repo-1/{sidecar.name}: {PIPE}", err)
        (archive,) = self.work.glob("loxodonta-export-*-raw.zip")
        with zipfile.ZipFile(archive) as raw:
            self.assertEqual(raw.namelist(), [f"repo-1/{self.log.name}"])
            self.assertEqual(raw.read(f"repo-1/{self.log.name}"),
                             self.log.read_bytes())


if __name__ == "__main__":
    unittest.main()
