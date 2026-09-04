"""Behavioral tests for `tools/demo_store.py` (#125): the demo store
builder, the only source for every screenshot, GIF, and README excerpt.

The builder writes a multi-session store under a neutral home through
the public CLI alone, pinned to fixed timestamps (SOURCE_DATE_EPOCH) so
two runs agree byte for byte. The tests drive it as a command and read
what it produced: the store must verify, scan clean, name nothing
outside the neutral home, and hold one session that reads as a story.
"""

import ast
import getpass
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"
DEMO_STORE = REPO_ROOT / "tools" / "demo_store.py"

# The session whose digest is the README's recorded-task excerpt.
STORY_SESSION = "7c1f3a2e-4b8d-4f0e-9a61-2d5e8c3b7f10"


def run(script, *args, env=None, cwd=None):
    return subprocess.run(
        [sys.executable, str(script), *args], cwd=cwd,
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})})


def neutral_env(home):
    """The environment a reader of the demo store runs under: the
    neutral home is home, the store is its .loxodonta, and nothing of
    the test process's own project leaks in."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_PROJECT_DIR", "LOXODONTA_HOME",
                        "SOURCE_DATE_EPOCH")}
    env.update({"LOXODONTA_HOME": str(home / ".loxodonta"),
                "HOME": str(home), "USERPROFILE": str(home)})
    return env


def build(home, *args):
    return run(DEMO_STORE, "--home", str(home), *args)


def snapshot(root):
    """Every file under root as relative path -> bytes. Ignores nothing."""
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def chains(home):
    return sorted((home / ".loxodonta" / "receipts").glob(
        "*/receipts-*.jsonl"))


def entries(chain):
    return [json.loads(line) for line in
            chain.read_text(encoding="utf-8").splitlines()]


class DemoStoreTest(unittest.TestCase):
    """One build, shared by the read-only tests below."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.home = Path(cls._tmp.name).resolve() / "home"
        cls.home.mkdir()
        cls.result = build(cls.home)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_one_command_writes_the_store_and_prints_where(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        store = self.home / ".loxodonta"
        self.assertIn(store.as_posix(),
                      self.result.stdout.replace("\\", "/"))
        self.assertGreaterEqual(len(chains(self.home)), 3)
        # The demo project exists so file fingerprints resolve.
        self.assertTrue(
            (self.home / "projects" / "todo" / "todo.py").is_file())
        drawers = [p for p in (store / "receipts").iterdir() if p.is_dir()]
        self.assertEqual(len(drawers), 1)
        record = json.loads(
            (drawers[0] / "project.json").read_text("utf-8"))
        self.assertEqual(record["path"],
                         (self.home / "projects" / "todo").as_posix())

    def test_refuses_to_clobber_an_existing_store_without_force(self):
        before = snapshot(self.home)
        again = build(self.home)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(len(again.stderr.strip().splitlines()), 1,
                         again.stderr)
        self.assertIn("--force", again.stderr)
        self.assertEqual(snapshot(self.home), before)

    def test_every_chain_verifies_valid_and_the_scan_exits_0(self):
        for chain in chains(self.home):
            verify = run(LOXODONTA, "verify", "--log", str(chain))
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertIn("VALID", verify.stdout)
        scan = run(SUPERVISOR, "scan", "--json", env=neutral_env(self.home))
        self.assertEqual(scan.returncode, 0, scan.stdout + scan.stderr)
        report = json.loads(scan.stdout)
        self.assertEqual(report["exit"], 0)
        self.assertEqual(len(report["repos"]), 1, report["repos"])

    def test_store_names_nothing_outside_the_neutral_home(self):
        real_home = Path(os.path.expanduser("~")).resolve()
        forbidden = [str(real_home), real_home.as_posix(), real_home.name,
                     str(REPO_ROOT), REPO_ROOT.as_posix(), "Acquiredl"]
        user = getpass.getuser()
        if len(user) >= 3:
            forbidden.append(user)
        files = snapshot(self.home / ".loxodonta")
        self.assertTrue(files)
        neutral = self.home.as_posix().lower()
        for relpath, data in files.items():
            body = data.decode("utf-8", "replace").lower()
            # The neutral home may itself sit under the real one (a temp
            # dir does); its own path is the one path allowed to appear.
            masked = body.replace("\\\\", "/").replace(neutral, "<home>")
            for word in forbidden:
                self.assertNotIn(word.lower(), masked,
                                 f"{word!r} in {relpath}")
            # Any absolute path the store holds stays under the neutral
            # home (JSON strings, backslashes read as slashes).
            for token in body.replace("\\\\", "/").split('"'):
                if ":/" in token or token.startswith("/"):
                    self.assertTrue(
                        token.startswith(self.home.as_posix().lower()),
                        f"{token!r} in {relpath}")

    def test_one_session_reads_as_a_tdd_story(self):
        found = (self.home / ".loxodonta" / "receipts").glob(
            f"*/receipts-{STORY_SESSION}.jsonl")
        chain = next(found, None)
        self.assertIsNotNone(chain, "the story session is missing")
        actions = [e["action"] for e in entries(chain)]
        beats = [
            ("a test-writing step", lambda a: a.startswith(
                ("Write: tests/test_todo.py", "Edit: tests/test_todo.py"))),
            ("an edit of the module",
             lambda a: a.startswith("Edit: todo.py")),
            ("a suite run",
             lambda a: a.startswith("Bash: python -m unittest")),
            ("a commit", lambda a: a.startswith("Bash: git commit")),
        ]
        cursor = 0
        for name, matches in beats:
            hits = [i for i in range(cursor, len(actions))
                    if matches(actions[i])]
            self.assertTrue(hits,
                            f"{name} missing after row {cursor}: {actions}")
            cursor = hits[0] + 1
        # And the recall surface renders it: the digest is the excerpt.
        digest = run(SUPERVISOR, "digest", "--repo",
                     str(self.home / "projects" / "todo"),
                     env=neutral_env(self.home))
        self.assertEqual(digest.returncode, 0, digest.stderr)
        for needle in ("tests/test_todo.py", "unittest", "git commit"):
            self.assertIn(needle, digest.stdout)

    def test_builder_speaks_only_the_public_cli(self):
        source = DEMO_STORE.read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0]
                                for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        # The stdlib modules a builder that only plays the harness needs.
        # A fixed list rather than sys.stdlib_module_names, which arrived
        # in Python 3.10; the README promises 3.9.
        allowed = {"argparse", "datetime", "json", "os", "shutil",
                   "subprocess", "sys"}
        self.assertTrue(imported <= allowed, imported - allowed)
        self.assertNotIn("loxodonta", imported)
        self.assertNotIn("supervisor", imported)
        # It never names a chain file: the recorder owns every chain byte.
        self.assertNotIn("jsonl", source)
        self.assertNotIn("receipts-", source)


class DemoStoreDeterminismTest(unittest.TestCase):
    def test_two_runs_produce_byte_identical_stores(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve() / "home"
            home.mkdir()
            first = build(home)
            self.assertEqual(first.returncode, 0, first.stderr)
            before = snapshot(home)
            self.assertTrue(before)
            second = build(home, "--force")
            self.assertEqual(second.returncode, 0, second.stderr)
            after = snapshot(home)
            self.assertEqual(sorted(after), sorted(before))
            for relpath in before:
                self.assertEqual(after[relpath], before[relpath], relpath)


if __name__ == "__main__":
    unittest.main()
