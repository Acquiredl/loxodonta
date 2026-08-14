"""Behavioral tests for concurrent appends (ADR-0004).

SPEC §8 allows one writer per log, where a writer is a *process*. The
Stage C hook shares a session-keyed chain across every tool call, and a
harness runs tool calls in parallel — so the integration has to serialize
its writers. These tests drive real concurrent processes through the
public CLI; nothing here mocks a race.

The two faults being prevented, both seen or reachable in the field:
a torn line (a partial entry on disk) and a forked chain (two entries
claiming the same `n`).
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RECEIPTS = REPO_ROOT / "receipts.py"


def run_receipts(*args, cwd, extra_env=None):
    env = dict(os.environ)
    env.pop("CLAUDE_PROJECT_DIR", None)
    env.pop("RECEIPTS_LOCK_TIMEOUT", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(RECEIPTS), *args],
        cwd=cwd, capture_output=True, text=True, env=env,
    )


def hook_payload(session="sess-1234abcd", tool="Bash", command="ls"):
    return json.dumps({
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    })


class ConcurrentAppendTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.log = self.workdir / "receipts.jsonl"
        run_receipts("init", cwd=self.workdir)

    def entries(self, path=None):
        text = (path or self.log).read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def test_parallel_appends_all_land_and_the_chain_stays_valid(self):
        writers = 8

        with ThreadPoolExecutor(max_workers=writers) as pool:
            results = list(pool.map(
                lambda i: run_receipts(
                    "log", "--actor", "agent", "--action", f"step {i}",
                    cwd=self.workdir),
                range(writers)))

        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)

        entries = self.entries()
        self.assertEqual(len(entries), writers + 1)  # genesis + each writer
        self.assertEqual([e["n"] for e in entries], list(range(writers + 1)),
                         "no forked chain: n is dense and ordered")
        actions = sorted(e["action"] for e in entries[1:])
        self.assertEqual(actions, sorted(f"step {i}" for i in range(writers)),
                         "every writer's entry survives")

        verify = run_receipts("verify", "--log", str(self.log), cwd=self.workdir)
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_parallel_hook_calls_all_land(self):
        # The fault as it actually reached the field: many hook processes,
        # one session chain.
        calls = 8
        log_dir = self.workdir / "receipts"

        def fire(i):
            return subprocess.run(
                [sys.executable, str(RECEIPTS), "hook",
                 "--log-dir", str(log_dir)],
                cwd=self.workdir, input=hook_payload(command=f"cmd {i}"),
                capture_output=True, text=True,
            )

        with ThreadPoolExecutor(max_workers=calls) as pool:
            results = list(pool.map(fire, range(calls)))

        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)

        chain = log_dir / "receipts-sess-1234abcd.jsonl"
        entries = self.entries(chain)
        self.assertEqual(len(entries), calls + 1)
        self.assertEqual([e["n"] for e in entries], list(range(calls + 1)))

        verify = run_receipts("verify", "--log", str(chain), cwd=self.workdir)
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_the_lock_is_released_after_a_normal_append(self):
        run_receipts("log", "--actor", "agent", "--action", "one",
                     cwd=self.workdir)

        leftovers = list(self.workdir.glob("*.lock"))
        self.assertEqual(leftovers, [], "a held lock would wedge the next run")

    def test_a_stale_lock_is_broken_rather_than_wedging_the_log(self):
        # The crash that strands a lock is the same crash that tears a line;
        # a lock nobody holds must not stop recording forever.
        lock = Path(str(self.log) + ".lock")
        lock.write_text("stale\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(lock, (old, old))

        result = run_receipts("log", "--actor", "agent", "--action", "after",
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries()[-1]["action"], "after")

    def test_a_held_lock_fails_loudly_rather_than_dropping_the_entry(self):
        # A silently missing receipt is the thing this tool exists to
        # prevent (ADR-0002), so contention that cannot be resolved is a
        # noisy failure, never a quiet skip.
        lock = Path(str(self.log) + ".lock")
        lock.write_text("held\n", encoding="utf-8")

        result = run_receipts("log", "--actor", "agent", "--action", "lost",
                              cwd=self.workdir,
                              extra_env={"RECEIPTS_LOCK_TIMEOUT": "0.5"})

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("lock", result.stderr.lower())
        self.assertEqual(len(self.entries()), 1, "nothing was written")


class SiblingChainTest(unittest.TestCase):
    """A damaged tail ends a chain, not the recording (ADR-0004)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name)
        self.log_dir = self.workdir / "receipts"

    def fire_hook(self, command="ls"):
        return subprocess.run(
            [sys.executable, str(RECEIPTS), "hook",
             "--log-dir", str(self.log_dir)],
            cwd=self.workdir, input=hook_payload(command=command),
            capture_output=True, text=True,
        )

    def chain(self, suffix=""):
        return self.log_dir / f"receipts-sess-1234abcd{suffix}.jsonl"

    def tear(self, path):
        """Truncate the final line, exactly as a torn append leaves it."""
        text = path.read_text(encoding="utf-8")
        path.write_text(text[:-12], encoding="utf-8")

    def test_hook_starts_a_sibling_when_the_tail_is_damaged(self):
        self.fire_hook(command="before the tear")
        self.tear(self.chain())
        damaged = self.chain().read_bytes()

        result = self.fire_hook(command="after the tear")

        self.assertEqual(result.returncode, 0, result.stderr)
        sibling = self.chain("-002")
        self.assertTrue(sibling.exists(), "recording continues in a sibling")
        entries = [json.loads(l) for l
                   in sibling.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(entries[0]["action"], "genesis")
        self.assertIn("after the tear", entries[1]["action"])
        self.assertEqual(self.chain().read_bytes(), damaged,
                         "the damaged chain is evidence: untouched")

    def test_the_sibling_verifies_on_its_own(self):
        self.fire_hook()
        self.tear(self.chain())
        self.fire_hook()

        verify = run_receipts("verify", "--log", str(self.chain("-002")),
                              cwd=self.workdir)
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_damage_to_a_sibling_advances_to_the_next(self):
        self.fire_hook()
        self.tear(self.chain())
        self.fire_hook()
        self.tear(self.chain("-002"))

        result = self.fire_hook(command="third chain")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.chain("-003").exists())

    def test_a_healthy_chain_is_never_abandoned(self):
        self.fire_hook()
        self.fire_hook()

        self.assertFalse(self.chain("-002").exists())
        entries = [json.loads(l) for l
                   in self.chain().read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["n"] for e in entries], [0, 1, 2])

    def test_the_log_command_still_refuses_to_extend_a_damaged_tail(self):
        # Siblings are the *hook's* answer to damage, because the harness
        # cannot stop and ask. A human at the CLI gets the refusal, so the
        # no-repair rule (ADR-0002) keeps its teeth.
        log = self.workdir / "receipts.jsonl"
        run_receipts("init", cwd=self.workdir)
        run_receipts("log", "--actor", "agent", "--action", "one",
                     cwd=self.workdir)
        self.tear(log)

        result = run_receipts("log", "--actor", "agent", "--action", "two",
                              cwd=self.workdir)

        self.assertEqual(result.returncode, 1)
        self.assertIn("damaged", result.stderr)
        self.assertFalse((self.workdir / "receipts-002.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
