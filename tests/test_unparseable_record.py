"""A project record or a worktree's `.git` the tools cannot take apart (#406).

A chain's project record, `project.json` beside it, sits in the
writer's reach, and so does a worktree's `.git` file. A record that
holds a JSON value that is not an object (`[]`), a record that is not
JSON, one nested too deep to read, and one naming a project that is
gone are each read as #386 reads a folder or a pipe at that name: the
hook fingerprints against the project it knows, says so, and writes
the receipt; `verify --files`, the recorder's and the recipient's
`verifier.py`, names the record as unresolved and gives the chain's
verdict; `log --file` and `run --file` refuse by the record's name,
exit 66, and `run` refuses before its command runs. A `.git` file or a
`commondir` holding a byte that is not UTF-8 is a layout the hook and
the supervisor cannot follow, so the project stays itself (SPEC
section 8). The supervisor's scan labels a drawer whose record holds no
object by the drawer's own name, as it does a damaged one.

Every test drives the public CLI, bounded, with homes of its own.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_unparseable_record`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env  # noqa: E402
from test_supervisor import (chains_by_session, home_outside,  # noqa: E402
                             install_witness_hook, isolated_env, make_chain)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"
VERIFIER = REPO_ROOT / "verifier.py"

BOUND = 60

# What the writer can leave at `project.json`, each a record no reader
# can take apart: a JSON value that is not an object, text that is not
# JSON, and nesting past what the reader follows.
NOT_AN_OBJECT = b"[]\n"
NOT_JSON = b'{"path": \n'
TOO_DEEP = b"[" * 100000 + b"]" * 100000


def run_tool(script, *args, cwd):
    return subprocess.run([sys.executable, str(script), *args], cwd=cwd,
                          capture_output=True, encoding="utf-8",
                          env=clean_env(), timeout=BOUND)


class RecordUnparseableTest(unittest.TestCase):
    """A store-shaped chain whose project record is spoiled after its
    first receipt: the writers refuse by the record's name, and the
    readers name it and give the chain's verdict."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name).resolve()
        self.project = self.workdir / "theproject"
        self.project.mkdir()
        (self.project / "report.md").write_bytes(b"v1\n")
        drawer = self.workdir / "drawer"
        drawer.mkdir()
        self.record = drawer / "project.json"
        self.record.write_text(json.dumps({"path": self.project.as_posix()}),
                               encoding="utf-8")
        self.log = drawer / "receipts-sess-rec.jsonl"
        run_tool(LOXODONTA, "init", "--log", str(self.log), cwd=self.workdir)
        logged = self.log_report()
        self.assertEqual(logged.returncode, 0, logged.stderr)

    def log_report(self):
        return run_tool(LOXODONTA, "log", "--log", str(self.log),
                        "--actor", "agent", "--action", "wrote report",
                        "--file", "report.md", cwd=self.workdir)

    def gone(self):
        """The record names a project that is no longer there."""
        elsewhere = self.workdir / "moved-away"
        self.record.write_text(json.dumps({"path": elsewhere.as_posix()}),
                               encoding="utf-8")

    def spoil(self, content):
        if content is None:
            self.gone()
        else:
            self.record.write_bytes(content)

    def assert_log_refused(self, content):
        self.spoil(content)
        before = self.log.read_bytes()

        result = self.log_report()

        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(str(self.record), result.stderr)
        self.assertEqual(self.log.read_bytes(), before)

    def assert_run_refused_before_its_command(self, content):
        self.spoil(content)
        before = self.log.read_bytes()
        marker = self.workdir / "ran.txt"

        result = run_tool(
            LOXODONTA, "run", "--log", str(self.log), "--actor", "agent",
            "--file", "report.md", "--", sys.executable, "-c",
            f"open({str(marker)!r}, 'w').close()", cwd=self.workdir)

        self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(str(self.record), result.stderr)
        self.assertFalse(marker.exists(), "the command ran before the "
                         "refusal")
        self.assertEqual(self.log.read_bytes(), before)

    def assert_verify_named(self, script, content):
        self.spoil(content)

        result = run_tool(script, "verify", "--log", str(self.log), "--files",
                          cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        (unresolved,) = [line for line in result.stdout.splitlines()
                         if line.startswith("FILES-UNRESOLVED: ")]
        self.assertIn(str(self.record), unresolved)
        self.assertTrue(unresolved.endswith(" — file checks skipped"),
                        unresolved)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "VALID")

    def test_log_refuses_a_record_holding_a_list(self):
        self.assert_log_refused(NOT_AN_OBJECT)

    def test_log_refuses_a_record_that_is_not_json(self):
        self.assert_log_refused(NOT_JSON)

    def test_log_refuses_a_record_nested_too_deep(self):
        self.assert_log_refused(TOO_DEEP)

    def test_log_refuses_a_record_naming_a_project_that_is_gone(self):
        self.assert_log_refused(None)

    def test_run_refuses_a_record_holding_a_list_before_its_command(self):
        self.assert_run_refused_before_its_command(NOT_AN_OBJECT)

    def test_run_refuses_a_record_that_is_not_json_before_its_command(self):
        self.assert_run_refused_before_its_command(NOT_JSON)

    def test_run_refuses_a_record_naming_a_gone_project_before_its_command(
            self):
        self.assert_run_refused_before_its_command(None)

    def test_verify_files_names_a_record_holding_a_list(self):
        self.assert_verify_named(LOXODONTA, NOT_AN_OBJECT)

    def test_verify_files_names_a_record_that_is_not_json(self):
        self.assert_verify_named(LOXODONTA, NOT_JSON)

    def test_verify_files_names_a_record_nested_too_deep(self):
        self.assert_verify_named(LOXODONTA, TOO_DEEP)

    def test_verify_files_names_a_record_naming_a_project_that_is_gone(self):
        self.assert_verify_named(LOXODONTA, None)

    def test_the_verifier_names_a_record_holding_a_list(self):
        self.assert_verify_named(VERIFIER, NOT_AN_OBJECT)

    def test_the_verifier_names_a_record_nested_too_deep(self):
        self.assert_verify_named(VERIFIER, TOO_DEEP)


class HookedRecordUnparseableTest(unittest.TestCase):
    """The hook with a project record it cannot take apart: the receipt
    is written, its file fingerprinted against the project the hook
    knows, and the hook names the record on stderr."""

    SESSION = "sess-unparseable-0001"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name).resolve()
        self.project = root / "theproject"
        self.project.mkdir()
        self.store = root / "store"
        self.home = home_outside(self)

    def hook(self, payload):
        env = isolated_env(self.home, CLAUDE_PROJECT_DIR=str(self.project),
                           LOXODONTA_HOME=str(self.store),
                           PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, str(LOXODONTA), "hook"], cwd=str(self.project),
            input=json.dumps(payload).encode("utf-8"), capture_output=True,
            env=env, timeout=BOUND)

    def chain(self):
        (drawer,) = (self.store / "receipts").iterdir()
        return drawer / f"receipts-{self.SESSION}.jsonl"

    def assert_receipt_written(self, content):
        first = self.hook({"session_id": self.SESSION,
                           "hook_event_name": "PostToolUse",
                           "tool_name": "Bash",
                           "tool_input": {"command": "ls"}})
        self.assertEqual(first.returncode, 0, first.stderr)
        record = self.chain().with_name("project.json")
        if content is None:
            record.write_text(json.dumps(
                {"path": (self.project.parent / "gone").as_posix()}),
                encoding="utf-8")
        else:
            record.write_bytes(content)
        notes = self.project / "notes.md"
        notes.write_bytes(b"hi\n")

        result = self.hook({"session_id": self.SESSION,
                            "hook_event_name": "PostToolUse",
                            "tool_name": "Write",
                            "tool_input": {"file_path": str(notes)},
                            "tool_response": {}})

        stderr = result.stderr.decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0, stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertIn(f"warning: {record}", stderr)
        self.assertIn(f"the files are fingerprinted against {self.project}",
                      stderr)
        last = json.loads(self.chain().read_text(
            encoding="utf-8").splitlines()[-1])
        self.assertTrue(last["action"].startswith("Write: "), last)
        self.assertEqual(last["files"], [
            {"path": "notes.md", "sha256": hashlib.sha256(b"hi\n").hexdigest()}])

    def test_a_record_holding_a_list_is_passed_by_and_named(self):
        self.assert_receipt_written(NOT_AN_OBJECT)

    def test_a_record_that_is_not_json_is_passed_by_and_named(self):
        self.assert_receipt_written(NOT_JSON)

    def test_a_record_naming_a_project_that_is_gone_is_passed_by_and_named(
            self):
        self.assert_receipt_written(None)


class WorktreeNotUtf8Test(unittest.TestCase):
    """A project whose `.git` file, or whose gitdir's `commondir`, holds
    a byte that is not UTF-8. The hook reads that layout on every tool
    call and `supervisor digest` at every session start: both read it
    as a layout they cannot follow, so the project stays itself (SPEC
    section 8) and the receipt is written."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.project = base / "worktree"
        self.project.mkdir()
        self.gitdir = base / "main" / ".git" / "worktrees" / "worktree"
        self.gitdir.mkdir(parents=True)
        self.store = base / "store"
        self.env = {**isolated_env(base / "home",
                                   CLAUDE_PROJECT_DIR=str(self.project),
                                   LOXODONTA_HOME=str(self.store)),
                    "PYTHONIOENCODING": "utf-8"}

    def assert_the_project_stays_itself(self):
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

        self.assertEqual(hooked.returncode, 0,
                         hooked.stderr.decode("utf-8", "replace"))
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

    def test_a_dot_git_file_that_is_not_utf8_leaves_the_project_itself(self):
        (self.project / ".git").write_bytes(
            b"gitdir: " + self.gitdir.as_posix().encode("utf-8")
            + b"\xff\n")

        self.assert_the_project_stays_itself()

    def test_a_commondir_that_is_not_utf8_leaves_the_project_itself(self):
        (self.project / ".git").write_text(
            f"gitdir: {self.gitdir.as_posix()}\n", encoding="utf-8")
        (self.gitdir / "commondir").write_bytes(b"../..\xff\n")

        self.assert_the_project_stays_itself()


class ScannedRecordUnparseableTest(unittest.TestCase):
    """`supervisor scan` over the store with a drawer whose project
    record holds no object, or nests too deep to read: the scan finishes,
    judges the chain, and labels the drawer by its own slug, as it does
    one whose record is damaged."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.home = base / "storehome"
        self.witness = base / "witness"
        install_witness_hook(self.witness)
        self.drawer = self.home / "receipts" / "alpha-11111111"
        self.drawer.mkdir(parents=True)
        make_chain(self.drawer, "sess-aaaa")
        self.env = {**isolated_env(base / "home",
                                   LOXODONTA_HOME=str(self.home)),
                    "PYTHONIOENCODING": "utf-8"}

    def assert_filed_under_its_slug(self, content):
        (self.drawer / "project.json").write_bytes(content)

        result = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--json",
             "--witness", str(self.witness)],
            capture_output=True, encoding="utf-8", timeout=BOUND,
            env=self.env)

        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([repo["repo"] for repo in report["repos"]],
                         ["alpha-11111111"])
        (chain,) = chains_by_session(report)[("alpha-11111111", "sess-aaaa")]
        self.assertEqual(chain["verdict"], "VALID")

    def test_a_record_holding_a_list_is_labelled_by_the_drawer(self):
        self.assert_filed_under_its_slug(NOT_AN_OBJECT)

    def test_a_record_nested_too_deep_is_labelled_by_the_drawer(self):
        self.assert_filed_under_its_slug(TOO_DEEP)


if __name__ == "__main__":
    unittest.main()
