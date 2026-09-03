"""Behavioral tests for the recorder adapters beyond Claude Code
(ADR-0020): the Codex CLI hook and the OpenAI Agents SDK trace
processor.

Both adapters speak the hook contract — the JSON payload `loxodonta
hook` already reads — so the recorder learns two small things (a
payload's `cwd` names the project when the harness sets no
CLAUDE_PROJECT_DIR; `summary` is a last-resort action key) and the
installer learns one more home (`~/.codex/hooks.json`). Tests drive the
public CLI and the adapter's public class; nothing reaches into
internals, and every chain written is judged by `loxodonta verify`.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
sys.path.insert(0, str(REPO_ROOT))

from adapters.openai_agents import ReceiptRecorder  # noqa: E402


def run_loxodonta(*args, stdin=None, env=None, cwd=None):
    result = subprocess.run(
        [sys.executable, str(LOXODONTA), *args], cwd=cwd,
        input=(json.dumps(stdin).encode("utf-8")
               if isinstance(stdin, dict) else stdin),
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})})
    result.stdout = result.stdout.decode("utf-8", errors="replace")
    result.stderr = result.stderr.decode("utf-8", errors="replace")
    return result


def clean_env(**extra):
    """No ambient harness or store: what the test sets is all there is."""
    env = dict(os.environ)
    for name in ("CLAUDE_PROJECT_DIR", "LOXODONTA_HOME", "CODEX_HOME"):
        env.pop(name, None)
    env.update(extra)
    return env


def drawer_of(store, project_name):
    drawers = [p for p in (Path(store) / "receipts").iterdir()
               if p.is_dir() and p.name.startswith(project_name + "-")]
    assert len(drawers) == 1, [p.name for p in drawers]
    return drawers[0]


def entries(log):
    return [json.loads(line) for line in
            Path(log).read_text(encoding="utf-8").splitlines() if line]


def codex_payload(cwd, tool="Bash", tool_input=None, tool_response=None,
                  session="019374ab-codex-session", event="PostToolUse",
                  transcript=None):
    """The shape Codex sends its command hooks (its docs): the Claude
    Code fields plus cwd, turn_id, model, permission_mode, tool_use_id."""
    payload = {"session_id": session, "turn_id": "turn-1",
               "transcript_path": transcript, "cwd": str(cwd),
               "hook_event_name": event, "model": "gpt-5-codex",
               "permission_mode": "default"}
    if event == "PostToolUse":
        payload.update({"tool_name": tool, "tool_use_id": "call-1",
                        "tool_input": tool_input or {},
                        "tool_response": tool_response or {}})
    return payload


class CodexHookTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.store = self.root / "storehome"
        self.project = self.root / "someproject"
        self.project.mkdir()
        self.env = clean_env(LOXODONTA_HOME=str(self.store))

    def hook(self, payload, **env):
        # cwd of the hook process differs from the project on purpose:
        # the payload, not the process, names the project.
        return run_loxodonta("hook", "--actor", "codex", stdin=payload,
                             env={**self.env, **env}, cwd=str(self.root))

    def test_payload_cwd_routes_the_chain_to_the_store_drawer(self):
        result = self.hook(codex_payload(
            self.project, tool="Bash", tool_input={"command": "npm test"},
            tool_response={"output": "3 passed, 1 failed", "exit_code": 1}))
        self.assertEqual(result.returncode, 0, result.stderr)
        drawer = drawer_of(self.store, "someproject")
        log = drawer / "receipts-019374ab-codex-session.jsonl"
        self.assertTrue(log.exists())
        record = json.loads((drawer / "project.json").read_text("utf-8"))
        self.assertEqual(Path(record["path"]).resolve(), self.project)
        last = entries(log)[-1]
        self.assertEqual(last["actor"], "codex")
        self.assertEqual(last["action"], "Bash: npm test")
        # Outcome-blind (.out-of-scope/001): the receipt says what was
        # attempted, never how it went.
        self.assertNotIn("failed", json.dumps(last))
        self.assertNotIn("exit_code", json.dumps(last))
        self.assertFalse((self.root / "receipts").exists())
        self.assertFalse(list(self.root.glob("receipts-*.jsonl")))

    def test_claude_project_dir_still_outranks_the_payload_cwd(self):
        other = self.root / "otherproject"
        other.mkdir()
        result = self.hook(codex_payload(self.project),
                           CLAUDE_PROJECT_DIR=str(other))
        self.assertEqual(result.returncode, 0, result.stderr)
        drawer_of(self.store, "otherproject")
        self.assertFalse([p for p in (self.store / "receipts").iterdir()
                          if p.name.startswith("someproject-")])

    def test_apply_patch_and_mcp_tools_leave_receipts(self):
        self.hook(codex_payload(self.project, tool="apply_patch",
                                tool_input={"command": "*** Begin Patch\n"
                                            "*** Update File: a.py"}))
        self.hook(codex_payload(self.project, tool="mcp__github__create_issue",
                                tool_input={"title": "flaky test"}))
        log = drawer_of(self.store, "someproject") \
            / "receipts-019374ab-codex-session.jsonl"
        actions = [e["action"] for e in entries(log)[1:]]
        self.assertEqual(actions, [
            "apply_patch: *** Begin Patch *** Update File: a.py",
            "mcp__github__create_issue"])
        judged = run_loxodonta("verify", "--log", str(log), env=self.env)
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn("VALID", judged.stdout)

    def test_session_end_seals_the_rollout_transcript(self):
        rollout = self.root / "rollout-2026-09-02.jsonl"
        rollout.write_text('{"type":"session_meta"}\n', encoding="utf-8")
        self.hook(codex_payload(self.project, tool="Bash",
                                tool_input={"command": "ls"},
                                transcript=str(rollout)))
        result = self.hook(codex_payload(self.project, event="SessionEnd",
                                         transcript=str(rollout)))
        self.assertEqual(result.returncode, 0, result.stderr)
        log = drawer_of(self.store, "someproject") \
            / "receipts-019374ab-codex-session.jsonl"
        last = entries(log)[-1]
        self.assertEqual(last["actor"], "receipts")
        self.assertTrue(last["action"].startswith("transcript-commitment:"))


class CodexInstallTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / "home"
        (self.home / ".codex").mkdir(parents=True)
        self.env = clean_env(HOME=str(self.home), USERPROFILE=str(self.home))
        self.hooks_path = self.home / ".codex" / "hooks.json"

    def install(self, *args, env=None):
        return run_loxodonta("install-hook", "--codex", *args,
                             env={**self.env, **(env or {})})

    def hooks(self, path=None):
        return json.loads((path or self.hooks_path).read_text("utf-8"))

    def test_writes_hooks_json_with_post_tool_use_and_session_end(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = self.hooks()["hooks"]
        post = hooks["PostToolUse"]
        self.assertEqual(len(post), 1)
        self.assertEqual(post[0]["matcher"], ".*")
        command = post[0]["hooks"][0]["command"]
        self.assertIn("loxodonta.py", command)
        self.assertIn(" hook", command)
        self.assertIn("--actor codex", command)
        self.assertEqual(post[0]["hooks"][0]["type"], "command")
        self.assertTrue(post[0]["hooks"][0]["timeout"])
        end = hooks["SessionEnd"][0]["hooks"][0]
        self.assertEqual(end["command"], command)
        self.assertLessEqual(end["timeout"], 3)  # Codex caps SessionEnd
        # Codex asks the user to trust new hooks once; the installer says so.
        self.assertIn("/hooks", result.stdout)
        # The Claude Code settings are not touched by a Codex install.
        self.assertFalse((self.home / ".claude").exists())

    def test_is_idempotent_and_keeps_foreign_hooks(self):
        self.hooks_path.write_text(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "python3 lint.py"}]}],
            "PostToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "python3 notify.py"}]}],
        }}), encoding="utf-8")
        first = self.install()
        self.assertEqual(first.returncode, 0, first.stderr)
        again = self.install()
        self.assertIn("already installed", again.stdout)
        hooks = self.hooks()["hooks"]
        self.assertEqual(hooks["PreToolUse"][0]["hooks"][0]["command"],
                         "python3 lint.py")
        commands = [h["command"] for b in hooks["PostToolUse"]
                    for h in b["hooks"]]
        self.assertIn("python3 notify.py", commands)
        self.assertEqual(sum("loxodonta.py" in c for c in commands), 1)
        self.assertTrue((self.hooks_path.parent / "hooks.json.bak").exists())

    def test_codex_home_env_moves_the_file(self):
        elsewhere = self.root / "codex-elsewhere"
        elsewhere.mkdir()
        result = self.install(env={"CODEX_HOME": str(elsewhere)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((elsewhere / "hooks.json").exists())
        self.assertFalse(self.hooks_path.exists())

    def test_uninstall_removes_only_ours(self):
        self.hooks_path.write_text(json.dumps({"hooks": {
            "PostToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "python3 notify.py"}]}],
        }}), encoding="utf-8")
        self.install()
        result = run_loxodonta("uninstall-hook", "--codex", env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = self.hooks()["hooks"]
        commands = [h["command"] for b in hooks.get("PostToolUse", [])
                    for h in b["hooks"]]
        self.assertEqual(commands, ["python3 notify.py"])
        self.assertNotIn("SessionEnd", hooks)
        again = run_loxodonta("uninstall-hook", "--codex", env=self.env)
        self.assertIn("nothing of ours", again.stdout)

    def test_refuses_to_clobber_broken_json(self):
        self.hooks_path.write_text("{not json", encoding="utf-8")
        result = self.install()
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing", result.stderr)
        self.assertEqual(self.hooks_path.read_text("utf-8"), "{not json")


def span(kind, name=None, input_=None, trace="trace_" + "ab" * 16,
         **extra):
    """A stand-in for an SDK span: only the attributes the adapter reads."""
    data = SimpleNamespace(type=kind, name=name, input=input_, **extra)
    return SimpleNamespace(span_data=data, trace_id=trace,
                           span_id="span_1", error=None)


class AgentsSdkRecorderTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.store = self.root / "storehome"
        self.project = self.root / "agentprog"
        self.project.mkdir()
        # The adapter runs in-process and spawns the recorder, which
        # reads the store's home from the environment.
        previous = {k: os.environ.get(k)
                    for k in ("LOXODONTA_HOME", "CLAUDE_PROJECT_DIR")}
        os.environ["LOXODONTA_HOME"] = str(self.store)
        os.environ.pop("CLAUDE_PROJECT_DIR", None)

        def restore():
            for k, v in previous.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        self.recorder = ReceiptRecorder(loxodonta=LOXODONTA,
                                        project=self.project)

    def chain(self, trace="trace_" + "ab" * 16):
        return drawer_of(self.store, "agentprog") / f"receipts-{trace}.jsonl"

    def test_function_span_leaves_a_receipt_in_the_projects_drawer(self):
        self.recorder.on_span_end(span(
            "function", "run_shell", '{"command": "pytest -q"}'))
        log = self.chain()
        last = entries(log)[-1]
        self.assertEqual(last["actor"], "openai-agents")
        self.assertEqual(last["action"], "run_shell: pytest -q")
        record = json.loads((log.parent / "project.json").read_text("utf-8"))
        self.assertEqual(Path(record["path"]).resolve(), self.project)

    def test_handoff_span_is_recorded_as_a_handoff(self):
        self.recorder.on_span_end(span("handoff", from_agent="triage",
                                       to_agent="billing"))
        self.assertEqual(entries(self.chain())[-1]["action"],
                         "handoff: triage -> billing")

    def test_arguments_without_a_named_key_fall_back_to_a_summary(self):
        self.recorder.on_span_end(span(
            "function", "lookup_ticket", '{"ticket": 42, "note": "vip"}'))
        self.assertEqual(entries(self.chain())[-1]["action"],
                         'lookup_ticket: {"ticket": 42, "note": "vip"}')

    def test_missing_arguments_record_the_tool_name_alone(self):
        # RunConfig(trace_include_sensitive_data=False) blanks input.
        self.recorder.on_span_end(span("function", "lookup_ticket", None))
        self.assertEqual(entries(self.chain())[-1]["action"], "lookup_ticket")

    def test_other_span_kinds_leave_nothing(self):
        for kind in ("agent", "generation", "response", "guardrail",
                     "turn", "task", "custom"):
            self.recorder.on_span_end(span(kind, name="x", input_="{}"))
        self.recorder.on_trace_start(None)
        self.recorder.on_trace_end(None)
        self.recorder.on_span_start(span("function", "x", "{}"))
        self.assertFalse((self.store / "receipts").exists())

    def test_a_failed_tool_still_leaves_its_receipt(self):
        failed = span("function", "run_shell", '{"command": "make"}')
        failed.error = {"message": "exit 2"}
        self.recorder.on_span_end(failed)
        last = entries(self.chain())[-1]
        self.assertEqual(last["action"], "run_shell: make")
        self.assertNotIn("exit 2", json.dumps(last))

    def test_a_run_is_one_chain_in_span_order_and_it_verifies(self):
        steps = [("read_file", '{"path": "a.py"}'),
                 ("edit_file", '{"path": "a.py", "content": "..."}'),
                 ("run_shell", '{"command": "pytest"}')]
        for name, args in steps:
            self.recorder.on_span_end(span("function", name, args))
        self.recorder.on_span_end(span("handoff", from_agent="coder",
                                       to_agent="reviewer"))
        log = self.chain()
        actions = [e["action"] for e in entries(log)[1:]]
        self.assertEqual(actions, ["read_file: a.py", "edit_file: a.py",
                                   "run_shell: pytest",
                                   "handoff: coder -> reviewer"])
        judged = run_loxodonta("verify", "--log", str(log),
                               env={"LOXODONTA_HOME": str(self.store)})
        self.assertEqual(judged.returncode, 0, judged.stdout + judged.stderr)
        self.assertIn("VALID", judged.stdout)
        # A second trace is a sibling chain, never a shared file.
        other = "trace_" + "cd" * 16
        self.recorder.on_span_end(span("function", "run_shell",
                                       '{"command": "ls"}', trace=other))
        self.assertTrue(self.chain(other).exists())
        self.assertEqual(len(entries(log)), 5)

    def test_a_missing_recorder_is_reported_not_raised(self):
        recorder = ReceiptRecorder(loxodonta=self.root / "nowhere.py",
                                   project=self.project)
        import io
        import contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ok = recorder.record({"session_id": "s", "tool_name": "x",
                                  "hook_event_name": "PostToolUse",
                                  "tool_input": {}, "cwd": str(self.project)})
        self.assertFalse(ok)
        self.assertIn("not recorded", err.getvalue())

    def test_is_a_real_tracing_processor_when_the_sdk_is_present(self):
        try:
            from agents.tracing import TracingProcessor
        except ImportError:
            self.skipTest("openai-agents not installed")
        self.assertIsInstance(self.recorder, TracingProcessor)
        from agents.tracing import add_trace_processor  # accepts it
        add_trace_processor(self.recorder)


if __name__ == "__main__":
    unittest.main()
