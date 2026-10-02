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
writers refuse it as `verify` does (#385). A folder that refuses the
lock file, or a lock file that will not take its line, is a file the
writer must write and cannot, 73, the lock removed (#398).

So is every other file the tools read there (#386): the transcript the
hook commits and `verify --transcript` judges, a chain's project record,
the supervisor's own memory, and the `.git` file and `commondir` a
worktree's layout is read from. Each is named where it is read, or read
as a layout the tools cannot follow, left as it was, and never waited on.

So are the coverage marker, the harness settings and the export's
own names (#405). The scan reads the first two as absent and names
them; `install-hook` and `uninstall-hook` refuse settings that are not
a file before they write anything, and wire the hook beside a marker
that is not one, naming it; `export` refuses a name it cannot write.
A calendar row with a `file:` address is never fetched (#414).

Every test drives the public CLI: the recorder's verbs, its hook at
SessionEnd, the supervisor's scan and keeper, against the fake calendar,
authority and receiver the other suites use. No network, no internals.
"""

import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import resource  # POSIX only; imported here, never in a forked child
except ImportError:
    resource = None

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_sidecar_not_a_file`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import FakeCalendar, FakeCalendarHandler, clean_env  # noqa: E402
from test_export import OTHER_SESSION, ExportBase  # noqa: E402
from test_package_anchor import SESSION, AnchoredStoreCase  # noqa: E402
from test_publish import PublishBase  # noqa: E402
from test_serve import OPENER, ServerFixture  # noqa: E402
from test_stamp import start_authority  # noqa: E402
from test_supervisor import (chains_by_session, home_outside,  # noqa: E402
                             install_witness_hook, isolated_env, make_chain,
                             run_scan)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

SUFFIXES = (".anchors.jsonl", ".stamps.jsonl", ".published.jsonl")
FOLDER = "it is a folder, not a file"
PIPE = "it is not a regular file"
NOT_EVIDENCE = "evidence that does not verify is not evidence"
NO_CHAIN = "cannot be read as a receipt log"
NO_FIFOS = "no named pipes here"
# A pipe opened for reading waits for a writer that never comes, so a
# reader that opened one would hang: every run here is bounded.
BOUND = 60


def run_receipts(*args, cwd):
    return subprocess.run([sys.executable, str(LOXODONTA), *args], cwd=cwd,
                          capture_output=True, encoding="utf-8",
                          env=clean_env(), timeout=BOUND)


def kind(path):
    """What stands at `path`, as the file type bits of its own entry."""
    return stat.S_IFMT(os.lstat(path).st_mode)


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


@unittest.skipIf(os.name == "nt", "a folder's write bit is POSIX")
class ReadOnlyFolderTest(UnwritableChainTest):
    """The same three writers in a folder that refuses the lock file
    beside the chain (#398): the lock is the first thing an append
    creates, so the refusal comes there, and each says so as the
    hook does, exit 73, never a traceback."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.chain = self.workdir / f"receipts-{HOOKED}.jsonl"
        first = fire_hook(self, self.workdir, "echo first")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.before = self.chain.read_bytes()
        os.chmod(self.workdir, 0o555)
        self.addCleanup(os.chmod, self.workdir, 0o755)


class MissingFolderTest(unittest.TestCase):
    """`log` into a folder that is not there is a log that is not there,
    66, as `run` says it, never the 73 of a lock refused (#398)."""

    def test_log_into_a_missing_folder_is_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_receipts("log", "--log", "gone/receipts.jsonl",
                                  "--actor", "agent", "--action", "x",
                                  cwd=tmp)

        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("not found", result.stderr)
        self.assertIn("loxodonta init", result.stderr)


def no_file_may_grow():
    """In the child, before it starts: no file may grow past 0 bytes,
    so the lock file is created and the line written into it is refused
    (EFBIG; Python ignores SIGXFSZ, so the write fails, not the
    process)."""
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))


@unittest.skipIf(resource is None, "no file size limit here")
class LockNotWrittenTest(unittest.TestCase):
    """A lock file created and then refused its one line, as a full disk
    would refuse it (#398). The writer removes the lock it made before
    it says why, so the next append is not held off by it until the
    stale break, and `log`, `run` and the hook each answer 73 with no
    traceback, the chain as it was."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.chain = self.workdir / f"receipts-{HOOKED}.jsonl"
        first = fire_hook(self, self.workdir, "echo first")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.before = self.chain.read_bytes()

    def limited(self, *args, payload=None):
        env = isolated_env(home_outside(self), PYTHONIOENCODING="utf-8",
                           PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            [sys.executable, str(LOXODONTA), *args], input=payload,
            capture_output=True, encoding="utf-8", cwd=str(self.workdir),
            env=env, timeout=BOUND, preexec_fn=no_file_may_grow)

    def test_each_writer_removes_the_lock_it_made(self):
        payload = json.dumps({"session_id": HOOKED,
                              "hook_event_name": "PostToolUse",
                              "tool_name": "Bash",
                              "tool_input": {"command": "echo second"}})
        writers = {
            "log": ["log", "--log", str(self.chain),
                    "--actor", "agent", "--action", "x"],
            "run": ["run", "--log", str(self.chain), "--actor", "agent",
                    "--", sys.executable, "-c", "pass"],
            "hook": ["hook", "--log-dir", str(self.workdir)],
        }
        for verb, args in writers.items():
            with self.subTest(verb=verb):
                result = self.limited(*args, payload=payload)

                self.assertEqual(result.returncode, 73,
                                 result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("could not be written", result.stderr)
                self.assertIn("no entry was written", result.stderr)
                self.assertEqual(self.chain.read_bytes(), self.before)
                self.assertEqual(list(self.workdir.glob("*.lock")), [])


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


class BoundedHook:
    """PublishBase's hook, bounded: a step that waited on a pipe would
    fail the test rather than hold the suite."""

    def hook(self, payload, *extra):
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


class SessionEndNotAFileTest(BoundedHook, PublishBase):
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


class TranscriptNotAFileTest(unittest.TestCase):
    """`verify --transcript` with a folder, a pipe or a device where the
    transcript belongs (#386): named, never waited on and never read,
    and a note like a missing transcript, so the verdict is the chain's
    (SPEC section 6)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.transcript = self.workdir / "transcript.jsonl"
        page = b"page one\n"
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        run_receipts("log", "--actor", "receipts", "--action",
                     f"transcript-commitment: bytes={len(page)} "
                     f"sha256={hashlib.sha256(page).hexdigest()}",
                     cwd=self.workdir)

    def assert_named(self, why):
        result = run_receipts("verify", "--transcript", str(self.transcript),
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(f"TRANSCRIPT-UNRESOLVED: {self.transcript} cannot be "
                      f"read as a transcript: {why}", result.stdout)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "VALID")

    def test_a_folder_where_the_transcript_belongs_is_named(self):
        self.transcript.mkdir()

        self.assert_named(FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_transcript_belongs_is_never_waited_on(self):
        os.mkfifo(self.transcript)

        self.assert_named(PIPE)

    @unittest.skipUnless(hasattr(os, "symlink")
                         and os.path.exists("/dev/zero"), "no /dev/zero here")
    def test_a_device_where_the_transcript_belongs_is_never_read(self):
        os.symlink("/dev/zero", self.transcript)

        self.assert_named(PIPE)


class ProjectRecordNotAFileTest(unittest.TestCase):
    """A folder or a pipe where a chain's project record belongs,
    `project.json` beside it (#386): `log --file` refuses by the
    record's name, exit 66, and writes nothing, and `verify --files`
    names it and gives the chain's verdict, as it does for a record it
    cannot follow (SPEC section 3). Never waited on."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        project = self.workdir / "theproject"
        project.mkdir()
        (project / "report.md").write_bytes(b"v1\n")
        drawer = self.workdir / "drawer"
        drawer.mkdir()
        self.record = drawer / "project.json"
        self.record.write_text(json.dumps({"path": project.as_posix()}),
                               encoding="utf-8")
        self.log = drawer / "receipts-sess-rec.jsonl"
        run_receipts("init", "--log", str(self.log), cwd=self.workdir)
        logged = self.log_report()
        self.assertEqual(logged.returncode, 0, logged.stderr)
        self.record.unlink()

    def log_report(self):
        return run_receipts("log", "--log", str(self.log), "--actor", "agent",
                            "--action", "wrote report", "--file", "report.md",
                            cwd=self.workdir)

    def named(self, why):
        return f"{self.record} cannot be read as a project record: {why}"

    def assert_log_refused(self, make, why):
        make(self.record)
        before = self.log.read_bytes()

        result = self.log_report()

        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(self.named(why), result.stderr)
        self.assertEqual(self.log.read_bytes(), before)

    def assert_verify_named(self, make, why):
        make(self.record)

        result = run_receipts("verify", "--log", str(self.log), "--files",
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(f"FILES-UNRESOLVED: {self.named(why)} — file checks "
                      "skipped", result.stdout)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "VALID")

    def test_log_refuses_a_folder_where_the_record_belongs(self):
        self.assert_log_refused(Path.mkdir, FOLDER)

    def test_verify_files_names_a_folder_where_the_record_belongs(self):
        self.assert_verify_named(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_log_refuses_a_pipe_where_the_record_belongs(self):
        self.assert_log_refused(os.mkfifo, PIPE)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_verify_files_names_a_pipe_where_the_record_belongs(self):
        self.assert_verify_named(os.mkfifo, PIPE)


class HookedNotAFileTest(BoundedHook, PublishBase):
    """The hook with a folder or a pipe where the transcript or the
    project record belongs (#386). The every-25 commitment and the
    session end's seal pass a transcript that is not a file by, quietly
    and exit 0, as they pass a missing one. With the record, the receipt
    is still written, its file fingerprinted against the project the
    hook knows, as when it writes a new record, and the hook says so."""

    def assert_commitments_pass_by(self, make):
        make(self.transcript)
        before = kind(self.transcript)

        for call in range(25):  # one cadence (ADR-0017)
            result = self.tool_call(f"step {call}")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
        ended = self.session_end()

        self.assertEqual(ended.returncode, 0, ended.stderr)
        self.assertEqual(ended.stderr, "")
        lines = self.chain().read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 26, "genesis and 25 receipts, and no "
                         "commitment")
        self.assertEqual(kind(self.transcript), before)

    def test_the_commitments_pass_a_folder_where_the_transcript_belongs(self):
        self.assert_commitments_pass_by(Path.mkdir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_the_commitments_pass_a_pipe_where_the_transcript_belongs(self):
        self.assert_commitments_pass_by(os.mkfifo)

    def assert_record_passed_by(self, make, why):
        self.tool_call()  # files the drawer and writes its record
        record = self.chain().with_name("project.json")
        record.unlink()
        make(record)
        before = kind(record)
        notes = self.project / "notes.md"
        notes.write_bytes(b"hi\n")

        result = self.hook({"session_id": self.SESSION,
                            "hook_event_name": "PostToolUse",
                            "tool_name": "Write",
                            "tool_input": {"file_path": str(notes)},
                            "tool_response": {}})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"{record} cannot be read as a project record: {why}",
                      result.stderr)
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("Write: "), last)
        self.assertEqual(last["files"], [
            {"path": "notes.md", "sha256": hashlib.sha256(b"hi\n").hexdigest()}])
        self.assertEqual(kind(record), before)

    def test_a_folder_where_the_record_belongs_is_passed_by_and_named(self):
        self.assert_record_passed_by(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_record_belongs_is_passed_by_and_named(self):
        self.assert_record_passed_by(os.mkfifo, PIPE)


class WorktreeNotAFileTest(unittest.TestCase):
    """A project whose `.git` file names a gitdir holding a folder or a
    pipe where `commondir` belongs (#386). The hook reads that layout on
    every tool call, and `supervisor digest` at every session start:
    both read it as a layout they cannot follow, so the project stays
    itself (SPEC section 8), the receipt is written, and neither waits."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.project = base / "worktree"
        self.project.mkdir()
        self.gitdir = base / "main" / ".git" / "worktrees" / "worktree"
        self.gitdir.mkdir(parents=True)
        (self.project / ".git").write_text(
            f"gitdir: {self.gitdir.as_posix()}\n", encoding="utf-8")
        self.store = base / "store"
        self.env = {**isolated_env(base / "home",
                                   CLAUDE_PROJECT_DIR=str(self.project),
                                   LOXODONTA_HOME=str(self.store)),
                    "PYTHONIOENCODING": "utf-8"}

    def assert_the_project_stays_itself(self, make):
        make(self.gitdir / "commondir")
        payload = {"session_id": "sess-wt", "hook_event_name": "PostToolUse",
                   "tool_name": "Bash", "tool_input": {"command": "ls"},
                   "tool_response": {}}

        hooked = subprocess.run(
            [sys.executable, str(LOXODONTA), "hook"], cwd=str(self.project),
            input=json.dumps(payload).encode("utf-8"), capture_output=True,
            env=self.env, timeout=BOUND)
        digest = subprocess.run(
            [sys.executable, str(SUPERVISOR), "digest"], cwd=str(self.project),
            capture_output=True, encoding="utf-8", env=self.env,
            timeout=BOUND)

        self.assertEqual(hooked.returncode, 0, hooked.stderr)
        (drawer,) = (self.store / "receipts").iterdir()
        record = json.loads((drawer / "project.json").read_text(
            encoding="utf-8"))
        self.assertEqual(record["path"], self.project.as_posix())
        chain = (drawer / "receipts-sess-wt.jsonl").read_text(
            encoding="utf-8").splitlines()
        self.assertEqual(len(chain), 2, "genesis and the receipt")
        self.assertEqual(digest.returncode, 0, digest.stderr)
        self.assertNotIn("Traceback", digest.stderr)
        self.assertIn("recall digest -- worktree (", digest.stdout)

    def test_a_folder_where_commondir_belongs_leaves_the_project_itself(self):
        self.assert_the_project_stays_itself(Path.mkdir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_commondir_belongs_is_never_waited_on(self):
        self.assert_the_project_stays_itself(os.mkfifo)


class ScannedMemoryNotAFileTest(unittest.TestCase):
    """`supervisor scan` over the store with a folder or a pipe where a
    transcript, a drawer's project record, the baseline or the day book
    belongs (#386): the scan finishes and judges every chain, a session
    whose transcript is not a file reads UNWITNESSED with why, the
    baseline and the day book are named and read as absent, and what the
    writer put there is left as it was. Every scan is bounded."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.home = base / "storehome"
        self.witness = base / "witness"
        install_witness_hook(self.witness)
        self.drawer = self.home / "receipts" / "alpha-11111111"
        self.drawer.mkdir(parents=True)
        (self.drawer / "project.json").write_text(
            json.dumps({"path": "C:/work/alpha"}), encoding="utf-8")
        make_chain(self.drawer, "sess-aaaa")
        self.env = {**isolated_env(base / "home",
                                   LOXODONTA_HOME=str(self.home)),
                    "PYTHONIOENCODING": "utf-8"}

    def scan(self, repo="alpha"):
        # Bounded: a scan that waited on a pipe would fail here.
        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--json",
             "--witness", str(self.witness)],
            capture_output=True, encoding="utf-8", timeout=BOUND,
            env=self.env)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        (chain,) = chains_by_session(report)[(repo, "sess-aaaa")]
        self.assertEqual(chain["verdict"], "VALID")
        return report

    def assert_unwitnessed(self, make, why):
        folder = self.witness / "anyproj"
        folder.mkdir()
        make(folder / "sess-aaaa.jsonl")

        report = self.scan()

        (row,) = [row for row in report["completeness"]["sessions"]
                  if row["session"] == "sess-aaaa"]
        self.assertEqual(row["state"], "UNWITNESSED")
        self.assertIn(f"sess-aaaa.jsonl cannot be read as a transcript: "
                      f"{why}", row["note"])

    def test_a_folder_where_a_transcript_belongs_is_unwitnessed_with_why(self):
        self.assert_unwitnessed(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_a_transcript_belongs_is_unwitnessed_with_why(self):
        self.assert_unwitnessed(os.mkfifo, PIPE)

    def assert_filed_under_its_slug(self, make):
        # A drawer whose record cannot be read is filed under its own
        # slug, as one with a damaged record is.
        record = self.drawer / "project.json"
        record.unlink()
        make(record)
        before = kind(record)

        report = self.scan(repo="alpha-11111111")

        self.assertEqual([repo["repo"] for repo in report["repos"]],
                         ["alpha-11111111"])
        self.assertEqual(kind(record), before)

    def test_a_folder_where_a_project_record_belongs_is_read_past(self):
        self.assert_filed_under_its_slug(Path.mkdir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_a_project_record_belongs_is_read_past(self):
        self.assert_filed_under_its_slug(os.mkfifo)

    def assert_memory_named(self, name, make, why, words, where):
        memory = self.home / name
        make(memory)
        before = kind(memory)

        first = self.scan()
        second = self.scan()

        for report in (first, second):
            self.assertIn(f"{name} cannot be read as {words}: {why}",
                          where(report))
        self.assertEqual(kind(memory), before, "nothing written over it")

    def test_a_folder_where_the_baseline_belongs_is_named_and_kept(self):
        self.assert_memory_named("baseline.json", Path.mkdir, FOLDER,
                                 "a baseline",
                                 lambda report: report["baseline"]["note"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_baseline_belongs_is_named_and_kept(self):
        self.assert_memory_named("baseline.json", os.mkfifo, PIPE,
                                 "a baseline",
                                 lambda report: report["baseline"]["note"])

    def test_a_folder_where_the_day_book_belongs_is_named_and_kept(self):
        self.assert_memory_named("daybook.json", Path.mkdir, FOLDER,
                                 "a day book",
                                 lambda report: report["history_note"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_day_book_belongs_is_named_and_kept(self):
        self.assert_memory_named("daybook.json", os.mkfifo, PIPE,
                                 "a day book",
                                 lambda report: report["history_note"])

    def assert_read_past(self, path, make, why, key, words):
        # Read on every scan, and in the writer's reach (#405): named in
        # the report, read as absent, and left as the writer put it.
        if path.exists():
            path.unlink()
        make(path)
        before = kind(path)

        report = self.scan()

        self.assertIn(f"{path.as_posix()} cannot be read as {words}: {why}",
                      report[key])
        self.assertEqual(kind(path), before, "nothing written over it")

    def test_a_folder_where_the_marker_belongs_is_read_past(self):
        self.assert_read_past(self.home / "coverage.json", Path.mkdir, FOLDER,
                              "marker_note", "a coverage marker")

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_marker_belongs_is_read_past(self):
        self.assert_read_past(self.home / "coverage.json", os.mkfifo, PIPE,
                              "marker_note", "a coverage marker")

    def test_a_folder_where_the_settings_belong_is_read_past(self):
        self.assert_read_past(self.witness.parent / "settings.json",
                              Path.mkdir, FOLDER, "settings_note",
                              "harness settings")

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_settings_belong_is_read_past(self):
        self.assert_read_past(self.witness.parent / "settings.json",
                              os.mkfifo, PIPE, "settings_note",
                              "harness settings")


class ServedViewsNotAFileTest(ServerFixture):
    """`serve` with a folder or a pipe where the saved views belong
    (#386): the views route answers, with no view and the reason, and a
    view saved there is not written over it."""

    def views(self, body=None):
        if body is None:
            return json.loads(self.get("/api/views")[2])
        request = urllib.request.Request(
            self.url + "/api/views", data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with OPENER.open(request, timeout=BOUND) as response:
            return json.loads(response.read().decode("utf-8"))

    def assert_named(self, make, why):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        book = self.root / ".supervisor-views.json"
        make(book)
        before = kind(book)
        self.serve()

        for reply in (self.views(),
                      self.views({"save": {"name": "alpha lately"}})):
            self.assertEqual(reply["views"], [])
            self.assertIn(f".supervisor-views.json cannot be read as the "
                          f"saved views: {why}", reply["note"])
        self.assertEqual(kind(book), before, "nothing written over it")

    def test_a_folder_where_the_views_belong_is_named(self):
        self.assert_named(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_views_belong_is_named(self):
        self.assert_named(os.mkfifo, PIPE)


class AdoptedMarkerNotAFileTest(unittest.TestCase):
    """`supervisor adopt` with a folder or a pipe where a legacy
    folder's `.unlisted` marker belongs (#386): the chain moves into the
    store, and the marker is named and left, never copied, never waited
    on."""

    def assert_left(self, make, why):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        root = base / "repos"
        receipts = root / "alpha" / "receipts"
        make_chain(receipts, "sess-aaaa")
        marker = receipts / ".unlisted"
        make(marker)
        before = kind(marker)
        home = base / "home"

        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "adopt", "--root", str(root)],
            capture_output=True, encoding="utf-8", timeout=BOUND,
            env={**isolated_env(home), "PYTHONIOENCODING": "utf-8"})

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("adopted alpha/receipts/receipts-sess-aaaa.jsonl",
                      result.stdout)
        self.assertIn(f"alpha/receipts/.unlisted: {why}", result.stdout)
        (drawer,) = (home / ".loxodonta" / "receipts").iterdir()
        self.assertTrue((drawer / "receipts-sess-aaaa.jsonl").is_file())
        self.assertFalse(os.path.lexists(drawer / ".unlisted"))
        self.assertEqual(kind(marker), before)

    def test_a_folder_where_the_marker_belongs_is_named_and_left(self):
        self.assert_left(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_marker_belongs_is_named_and_left(self):
        self.assert_left(os.mkfifo, PIPE)


class InstalledNotAFileTest(unittest.TestCase):
    """`install-hook` and `uninstall-hook`, each half, with a folder or a
    pipe where the harness settings or the coverage marker belong
    (#405), never waited on. Settings that are not a file are refused
    by name, exit 66, before a byte is written anywhere in the home. A
    marker that is not one is bookkeeping, no reason to refuse: the
    hook is wired, exit 0, and the marker is named and left as it was.
    Every run is bounded."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.env = {**isolated_env(self.home), "PYTHONIOENCODING": "utf-8"}
        self.marker = self.home / ".loxodonta" / "coverage.json"

    def written(self):
        """Every regular file in the home: none, when nothing was."""
        return sorted(path.relative_to(self.home).as_posix()
                      for path in self.home.rglob("*") if path.is_file())

    def assert_refused(self, path, make, why, *verb):
        path.parent.mkdir(parents=True, exist_ok=True)
        make(path)
        before = kind(path)
        try:
            result = subprocess.run([sys.executable, str(LOXODONTA), *verb],
                                    capture_output=True, encoding="utf-8",
                                    env=self.env, timeout=BOUND)

            self.assertEqual(result.returncode, 66,
                             result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn(f"refusing to touch {path}: {why}", result.stderr)
            self.assertEqual(kind(path), before, "left as the writer put it")
            self.assertEqual(self.written(), [])
        finally:
            # The next verb finds the same name free to be spoiled again.
            (path.rmdir if path.is_dir() else path.unlink)()

    def assert_wired_beside(self, make, why):
        self.marker.parent.mkdir(parents=True)
        make(self.marker)
        before = kind(self.marker)
        for verb, settings in (
                (("install-hook",), ".claude/settings.json"),
                (("install-hook", "--codex"), ".codex/hooks.json")):
            with self.subTest(verb=" ".join(verb)):
                result = subprocess.run(
                    [sys.executable, str(LOXODONTA), *verb],
                    capture_output=True, encoding="utf-8", env=self.env,
                    timeout=BOUND)

                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn(f"warning: {self.marker} cannot be read as a "
                              f"coverage marker: {why} — the marker was not "
                              "written, and the hook is wired without it",
                              result.stderr)
                self.assertIn("installed in", result.stdout)
                wired = json.loads((self.home / settings).read_text(
                    encoding="utf-8"))
                self.assertIn("PostToolUse", wired["hooks"])
                self.assertEqual(kind(self.marker), before,
                                 "left as the writer put it")

    def settings_files(self):
        """Each verb that reads a settings file, with the file it reads."""
        claude = self.home / ".claude" / "settings.json"
        codex = self.home / ".codex" / "hooks.json"
        return ((("install-hook",), claude),
                (("install-hook", "--codex"), codex),
                (("uninstall-hook",), claude),
                (("uninstall-hook", "--codex"), codex))

    def test_a_folder_where_the_settings_belong_is_refused(self):
        for verb, path in self.settings_files():
            with self.subTest(verb=" ".join(verb)):
                self.assert_refused(path, Path.mkdir, FOLDER, *verb)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_settings_belong_is_never_waited_on(self):
        for verb, path in self.settings_files():
            with self.subTest(verb=" ".join(verb)):
                self.assert_refused(path, os.mkfifo, PIPE, *verb)

    def test_a_folder_where_the_marker_belongs_is_named_beside_the_hook(
            self):
        self.assert_wired_beside(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_marker_belongs_is_never_waited_on(self):
        self.assert_wired_beside(os.mkfifo, PIPE)


class ServedMarkerNotAFileTest(unittest.TestCase):
    """`serve` reads the coverage marker once, before it takes its port,
    to steer its keepers (ADR-0031): with a folder or a pipe there it
    starts, finds no profile on record, and is never held (#405)."""

    def assert_started(self, make):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = Path(tmp.name).resolve()
        (home / ".loxodonta").mkdir()
        make(home / ".loxodonta" / "coverage.json")
        proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--port", "0",
             "--witness", str(home / "witness")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env={**isolated_env(home), "PYTHONIOENCODING": "utf-8"})
        self.addCleanup(proc.communicate)
        self.addCleanup(proc.kill)
        # Both startup lines, read on a thread joined to a bound: a start
        # held at the marker prints neither, and is killed above.
        said = []
        reader = threading.Thread(target=lambda: said.extend(
            [proc.stdout.readline(), proc.stdout.readline()]), daemon=True)
        reader.start()
        reader.join(BOUND)

        self.assertFalse(reader.is_alive(), "serve never said it started")
        self.assertIn("http://127.0.0.1:", said[0])
        self.assertIn("anchor off (no profile on record; no flag)", said[1])

    def test_a_folder_where_the_marker_belongs_is_read_past(self):
        self.assert_started(Path.mkdir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_where_the_marker_belongs_is_never_waited_on(self):
        self.assert_started(os.mkfifo)


class ExportedNameNotAFileTest(ExportBase):
    """`supervisor export` with a folder or a pipe at the name it writes
    by default, a predictable one in the folder it runs in, or at the
    raw archive's beside it (#405): refused by name with exit 73, a code
    no scan verdict uses, never waited on, and left as it was."""

    def names(self, suffix):
        """Where the export of a scan made now lands: today's name, and
        tomorrow's, for a run that crosses midnight UTC."""
        now = datetime.now(timezone.utc)
        return [self.work / ("loxodonta-export-"
                             + (now + timedelta(days=ahead)).strftime(
                                 "%Y-%m-%d") + suffix)
                for ahead in (0, 1)]

    def assert_refused(self, make, why, suffix, then, *args):
        planted = self.names(suffix)
        for path in planted:
            make(path)
        before = [kind(path) for path in planted]
        try:
            result = subprocess.run(
                [sys.executable, str(SUPERVISOR), "export",
                 "--witness", str(self.witness), *args],
                input=b"yes\n", capture_output=True, cwd=str(self.work),
                env={**self.env, "PYTHONIOENCODING": "utf-8"},
                timeout=BOUND)
            err = result.stderr.decode("utf-8", "replace")

            self.assertEqual(result.returncode, 73, err)
            self.assertNotIn("Traceback", err)
            self.assertTrue(any(f"{path.name} could not be written: {why} "
                                f"— {then}" in err for path in planted), err)
            self.assertEqual([kind(path) for path in planted], before)
        finally:
            for path in planted:
                (path.rmdir if path.is_dir() else path.unlink)()

    def assert_both_refused(self, make, why):
        with self.subTest(name="the export"):
            self.assert_refused(make, why, ".json", "nothing was written")
            self.assertEqual(list(self.work.iterdir()), [])
        with self.subTest(name="the raw archive"):
            self.assert_refused(make, why, "-raw.zip",
                                "loxodonta-export-", "--raw")
            self.exported_file()

    def test_a_folder_at_either_name_is_refused(self):
        self.assert_both_refused(Path.mkdir, FOLDER)

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_at_either_name_is_never_waited_on(self):
        self.assert_both_refused(os.mkfifo, PIPE)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "needs a folder this user may not write in")
    def test_a_folder_it_may_not_write_in_is_refused_by_name(self):
        """Any write the system refuses is named with exit 73, as the
        recorder names one (`unwritable_log`): never a traceback."""
        os.chmod(self.work, 0o555)
        self.addCleanup(os.chmod, self.work, 0o755)
        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "export",
             "--witness", str(self.witness)],
            capture_output=True, cwd=str(self.work),
            env={**self.env, "PYTHONIOENCODING": "utf-8"}, timeout=BOUND)
        err = result.stderr.decode("utf-8", "replace")

        self.assertEqual(result.returncode, 73, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("could not be written: ", err)
        self.assertIn("— nothing was written", err)
        self.assertEqual(list(self.work.iterdir()), [])


def misdirected(sidecar, nonce, away):
    """Point the one anchor row of `sidecar` at a `file:` calendar in
    `away`, every other row kept, and return the path urllib would read
    that row's completion from: a path the row chose (#414)."""
    rows = [json.loads(line) for line in
            sidecar.read_text(encoding="utf-8").splitlines()]
    (anchor,) = [row for row in rows if row.get("kind") == "anchor"]
    rows = [dict(row, calendar=away.as_uri()) if row is anchor else row
            for row in rows]
    sidecar.write_bytes("".join(json.dumps(row) + "\n"
                                for row in rows).encode("utf-8"))
    commitment = hashlib.sha256(bytes.fromhex(anchor["head"])
                                + nonce).hexdigest()
    target = away / "timestamp" / commitment
    target.parent.mkdir(parents=True)
    return target


class CalendarSchemeTest(unittest.TestCase):
    """`anchor --upgrade` with a pending proof whose row names a `file:`
    calendar (#414): the row is named as one this recorder cannot ask
    and is never fetched, so a file at the path it chose is never read
    and a pipe there is never waited on. Nothing is written, exit 0."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "step 1",
                     cwd=self.workdir)
        calendar = start_calendar(self)
        anchored = run_receipts("anchor", "--calendar", calendar.url,
                                cwd=self.workdir)
        self.assertEqual(anchored.returncode, 0, anchored.stderr)
        self.sidecar = self.workdir / "receipts.jsonl.anchors.jsonl"
        self.target = misdirected(self.sidecar, calendar.nonce,
                                  self.workdir / "elsewhere")

    def assert_never_fetched(self, make):
        make(self.target)
        before = (kind(self.target), self.sidecar.read_bytes())

        result = run_receipts("anchor", "--upgrade", cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("the record's calendar is not a URL this recorder can "
                      "ask", result.stderr)
        self.assertEqual((kind(self.target), self.sidecar.read_bytes()),
                         before)

    def test_a_file_the_calendar_row_points_at_is_never_read(self):
        self.assert_never_fetched(
            lambda path: path.write_bytes(b"no completion of any proof"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_the_calendar_row_points_at_is_never_waited_on(self):
        self.assert_never_fetched(os.mkfifo)


class SessionEndCalendarSchemeTest(BoundedHook, PublishBase):
    """The session end's upgrade half with a pending row naming a `file:`
    calendar (#414): passed by quietly, as every other row it cannot
    ask, and the pipe at the path it chose is never waited on."""

    @unittest.skipUnless(hasattr(os, "mkfifo"), NO_FIFOS)
    def test_a_pipe_the_calendar_row_points_at_is_never_waited_on(self):
        calendar = start_calendar(self)
        self.tool_call()
        self.session_end("--anchor", "--calendar", calendar.url)
        target = misdirected(
            self.chain().with_name(self.chain().name + ".anchors.jsonl"),
            calendar.nonce, self.root / "elsewhere")
        os.mkfifo(target)
        self.tool_call()

        result = self.session_end("--anchor", "--calendar", calendar.url)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertTrue(stat.S_ISFIFO(os.lstat(target).st_mode))


if __name__ == "__main__":
    unittest.main()
