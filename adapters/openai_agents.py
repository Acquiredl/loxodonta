#!/usr/bin/env python3
"""loxodonta adapter for the OpenAI Agents SDK (Python) — ADR-0020.

One receipt per completed tool call and per handoff, recorded by
listening to the SDK's tracing spans and handing each one to the
recorder through the public hook contract (`loxodonta hook`, the same
payload the Claude Code and Codex hooks send). This file is stdlib
only: the SDK is imported when present so the class is a real
`TracingProcessor`, and read as plain Python when it is not.

Wiring, three lines in your program:

    from agents import add_trace_processor
    from adapters.openai_agents import ReceiptRecorder
    add_trace_processor(ReceiptRecorder())

Each run's trace becomes one chain in the store — the drawer for the
program's working directory (ADR-0011), chain `receipts-<trace_id>.jsonl`
— so `supervisor digest`, `search`, and the MCP server read Agents SDK
history exactly as they read a Claude Code session's.

What is recorded, and what is not. Function-tool spans (including MCP
tools, which the SDK wraps as function tools) and handoff spans leave
receipts; model turns, guardrails, and hosted server-side tools do not
— they are not actions on this machine. A receipt says what was
attempted on what, never how it went (`.out-of-scope/001`): a tool that
raised still leaves its receipt, with no error flag. Tool arguments are
summarized on the action line the same way the hooks summarize them
(the recorder picks the most descriptive scalar: a command, a path, a
query); when the SDK is run with sensitive data excluded from traces,
the arguments are absent and the line carries the tool name alone.

The honesty note this adapter carries that the hooks do not: it runs
inside the agent program's own process. The model still cannot skip a
receipt — the processor fires from the SDK, not from anything the model
controls — but the program's author can, by not installing it, and a
tool the model runs could edit this program's source. The harness hooks
(Claude Code, Codex) sit one process further out. GLOSSARY: Completeness
is the integration's job; this is the integration, and this is its
boundary.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

try:  # pragma: no cover — exercised only where the SDK is installed
    from agents.tracing import TracingProcessor as _Base
except ImportError:  # the SDK is the program's dependency, never ours
    _Base = object

RECORDED_SPANS = ("function", "handoff")
ACTOR = "openai-agents"


def default_recorder():
    """Where `loxodonta.py` is: an explicit LOXODONTA_PY, else the repo
    layout this file ships in, else a copy beside this file."""
    named = os.environ.get("LOXODONTA_PY")
    if named:
        return Path(named)
    here = Path(__file__).resolve().parent
    for candidate in (here.parent / "loxodonta.py", here / "loxodonta.py"):
        if candidate.is_file():
            return candidate
    return here.parent / "loxodonta.py"


def arguments_of(raw):
    """The tool's arguments as the hook's `tool_input` dict. A JSON
    object passes through with a `summary` of the whole thing appended
    (the recorder prefers its named keys — command, path, query — and
    falls back to the summary when none is present); anything else
    becomes a summary alone; nothing becomes nothing."""
    if isinstance(raw, str) and raw.strip():
        try:
            raw = json.loads(raw)
        except ValueError:
            return {"summary": raw}
    if isinstance(raw, dict) and raw:
        arguments = dict(raw)
        arguments.setdefault("summary", json.dumps(
            raw, ensure_ascii=False, separators=(", ", ": ")))
        return arguments
    if raw is None or raw == "" or raw == {}:
        return {}
    return {"summary": json.dumps(raw, ensure_ascii=False)}


def payload_for(span, project):
    """The hook payload for one ended span, or None when the span is
    not an action worth a receipt."""
    data = getattr(span, "span_data", None)
    kind = getattr(data, "type", None)
    if kind not in RECORDED_SPANS:
        return None
    if kind == "handoff":
        tool = "handoff"
        tool_input = {"summary": f"{getattr(data, 'from_agent', '?')} -> "
                                 f"{getattr(data, 'to_agent', '?')}"}
    else:
        tool = getattr(data, "name", None) or "tool"
        tool_input = arguments_of(getattr(data, "input", None))
    trace = getattr(span, "trace_id", None) or "untraced"
    return {"session_id": str(trace),
            "hook_event_name": "PostToolUse",
            "tool_name": str(tool),
            "tool_input": tool_input,
            "cwd": project}


class ReceiptRecorder(_Base):
    """A tracing processor that leaves one receipt per tool call and
    handoff. Synchronous on purpose: a receipt is written before the
    run moves on, in span order, and nothing is lost if the program
    dies — the price is one recorder process per tool call (~135 ms,
    docs/HOOK.md), small beside a model turn."""

    def __init__(self, loxodonta=None, project=None, actor=ACTOR,
                 python=None):
        self.loxodonta = Path(loxodonta) if loxodonta else default_recorder()
        self.project = os.path.abspath(project or os.getcwd())
        self.actor = actor
        self.python = python or sys.executable

    # The TracingProcessor surface. Only span ends carry actions.
    def on_trace_start(self, trace):
        pass

    def on_trace_end(self, trace):
        pass

    def on_span_start(self, span):
        pass

    def on_span_end(self, span):
        payload = payload_for(span, self.project)
        if payload is not None:
            self.record(payload)

    def shutdown(self):
        pass

    def force_flush(self):
        pass

    def record(self, payload):
        """Hand one payload to `loxodonta hook`. A recorder failure is
        reported on stderr and never raised: the agent run must not
        die over its own flight recorder, but a silent recorder is
        worse than a loud one."""
        try:
            done = subprocess.run(
                [self.python, str(self.loxodonta), "hook",
                 "--actor", self.actor],
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as failure:
            print(f"loxodonta: receipt not recorded ({failure})",
                  file=sys.stderr)
            return False
        if done.returncode != 0:
            complaint = done.stderr.decode("utf-8", errors="replace").strip()
            print(f"loxodonta: receipt not recorded (exit {done.returncode})"
                  + (f": {complaint}" if complaint else ""), file=sys.stderr)
            return False
        return True
