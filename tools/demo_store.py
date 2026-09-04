"""Demo store builder (#125): a believable multi-session store under a
neutral home, written through the public CLI alone.

    python tools/demo_store.py --home <dir> [--force]

Writes the store to <dir>/.loxodonta and the demo project, a tiny todo
CLI, to <dir>/projects/todo, then prints where. Every receipt goes
through `loxodonta.py hook` with a synthetic PostToolUse payload: this
script never touches a chain byte, it only plays the harness. Content
is fixed, timestamps are pinned with SOURCE_DATE_EPOCH, so two runs
produce byte-identical stores. This is the only source for every
screenshot, GIF, and README excerpt, and it must stay stdlib-only.

The sessions below are data: each is a session id, a start time, and
the tool calls in order, each with the seconds that pass before it.
Write and Edit calls are also applied to the project files, so the
fingerprints the recorder takes evolve the way a real session's would.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

LOXODONTA = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "loxodonta.py")

# --- The demo project: a todo CLI as it stood before the first session --

PROJECT_FILES = {
    "todo.py": '''\
"""todo: a tiny command-line todo list kept in todo.txt."""
import sys

STORE = "todo.txt"


def load():
    try:
        with open(STORE, encoding="utf-8") as f:
            return [line.rstrip("\\n") for line in f]
    except FileNotFoundError:
        return []


def save(items):
    with open(STORE, "w", encoding="utf-8") as f:
        f.write("".join(item + "\\n" for item in items))


def cmd_add(args):
    items = load()
    items.append("[ ] " + " ".join(args))
    save(items)


def cmd_list(args):
    for n, item in enumerate(load()):
        print(f"{n}. {item}")


def main(argv):
    commands = {"add": cmd_add, "list": cmd_list}
    if not argv or argv[0] not in commands:
        print("usage: todo.py add <text> | list", file=sys.stderr)
        return 2
    commands[argv[0]](argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
''',
    "tests/__init__.py": "",
    "tests/test_todo.py": '''\
import os
import subprocess
import sys
import tempfile
import unittest

TODO = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "todo.py")


class TodoTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def todo(self, *args):
        return subprocess.run([sys.executable, TODO, *args], cwd=self.dir,
                              capture_output=True, text=True)

    def test_add_then_list(self):
        self.todo("add", "buy milk")
        self.assertIn("[ ] buy milk", self.todo("list").stdout)

    def test_unknown_command_is_a_usage_error(self):
        self.assertEqual(self.todo("frobnicate").returncode, 2)
''',
    "README.md": "# todo\n\nA tiny command-line todo list.\n",
    ".gitignore": "todo.txt\n__pycache__/\n",
}

# --- The sessions ---------------------------------------------------------

DONE_TEST = '''\

    def test_done_marks_an_item(self):
        self.todo("add", "buy milk")
        self.todo("done", "0")
        self.assertIn("[x] buy milk", self.todo("list").stdout)
'''

README_V2 = '''\
# todo

A tiny command-line todo list kept in `todo.txt` next to you.

```
python todo.py add buy milk
python todo.py list
python todo.py done 1
```

Tests: `python -m unittest -q`.
'''

# Each session: (session_id, started at, [(seconds later, tool, tool_input)]).
# The first is the story: tests first, an edit, the suite, a commit. Its
# digest is the README's recorded-task excerpt.
SESSIONS = [
    ("7c1f3a2e-4b8d-4f0e-9a61-2d5e8c3b7f10",
     datetime(2026, 8, 18, 13, 42, 7, tzinfo=timezone.utc), [
         (0, "Read", {"file_path": "todo.py"}),
         (14, "Read", {"file_path": "tests/test_todo.py"}),
         (96, "Edit", {"file_path": "tests/test_todo.py",
                       "old_string": "        self.assertEqual(self.todo("
                                     "\"frobnicate\").returncode, 2)\n",
                       "new_string": "        self.assertEqual(self.todo("
                                     "\"frobnicate\").returncode, 2)\n"
                                     + DONE_TEST}),
         (21, "Bash", {"command": "python -m unittest -q"}),
         (143, "Edit", {"file_path": "todo.py",
                        "old_string": "def main(argv):\n"
                                      "    commands = {\"add\": cmd_add, "
                                      "\"list\": cmd_list}\n",
                        "new_string": "def cmd_done(args):\n"
                                      "    items = load()\n"
                                      "    n = int(args[0])\n"
                                      "    items[n] = \"[x]\" + items[n][3:]\n"
                                      "    save(items)\n\n\n"
                                      "def main(argv):\n"
                                      "    commands = {\"add\": cmd_add, "
                                      "\"list\": cmd_list, "
                                      "\"done\": cmd_done}\n"}),
         (38, "Edit", {"file_path": "todo.py",
                       "old_string": "usage: todo.py add <text> | list",
                       "new_string": "usage: todo.py add <text> | list | "
                                     "done <n>"}),
         (19, "Bash", {"command": "python -m unittest -q"}),
         (27, "Bash", {"command": "git add -A"}),
         (9, "Bash", {"command": "git commit -m \"done: mark an item "
                                 "complete\""}),
     ]),
    ("d94b0e61-2f7a-4c35-8b1d-6e0f4a9c2b58",
     datetime(2026, 8, 20, 9, 15, 33, tzinfo=timezone.utc), [
         (0, "Bash", {"command": "python todo.py add \"water the plants\""}),
         (11, "Bash", {"command": "python todo.py list"}),
         (48, "Grep", {"pattern": "enumerate", "path": "todo.py"}),
         (17, "Read", {"file_path": "todo.py"}),
         (122, "Edit", {"file_path": "tests/test_todo.py",
                        "old_string": "        self.todo(\"done\", \"0\")",
                        "new_string": "        self.todo(\"done\", \"1\")"}),
         (26, "Bash", {"command": "python -m unittest -q"}),
         (88, "Edit", {"file_path": "todo.py",
                       "old_string": "enumerate(load())",
                       "new_string": "enumerate(load(), 1)"}),
         (31, "Edit", {"file_path": "todo.py",
                       "old_string": "    n = int(args[0])\n",
                       "new_string": "    n = int(args[0]) - 1\n"}),
         (22, "Bash", {"command": "python -m unittest -q"}),
         (35, "Bash", {"command": "git commit -am \"list: count from 1, "
                                  "the way people do\""}),
     ]),
    ("3e8a5c07-9d12-4b6f-a4e3-1c7b2d9f0a64",
     datetime(2026, 8, 25, 16, 4, 51, tzinfo=timezone.utc), [
         (0, "Glob", {"pattern": "**/*.py"}),
         (8, "Read", {"file_path": "README.md"}),
         (12, "Read", {"file_path": "todo.py"}),
         (9, "Read", {"file_path": ".gitignore"}),
         (131, "Write", {"file_path": "README.md", "content": README_V2}),
         (24, "Bash", {"command": "python todo.py list"}),
         (41, "Bash", {"command": "git add README.md"}),
         (7, "Bash", {"command": "git commit -m \"README: usage\""}),
     ]),
]

# --- The driver -----------------------------------------------------------


def play(project, tool, tool_input):
    """Apply a Write or Edit to the project files, so the fingerprint
    the recorder takes is of the file as the session left it. A miss
    is a bug in the data above, and says so."""
    path = os.path.join(project, tool_input.get("file_path", ""))
    if tool == "Write":
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(tool_input["content"])
    elif tool == "Edit":
        with open(path, encoding="utf-8", newline="\n") as f:
            text = f.read()
        if text.count(tool_input["old_string"]) != 1:
            sys.exit(f"error: edit does not apply to {path}: "
                     f"{tool_input['old_string']!r}")
        text = text.replace(tool_input["old_string"],
                            tool_input["new_string"])
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def hook(home, project, session, when, tool, tool_input):
    """One receipt through the public CLI, at a pinned time."""
    payload = {"session_id": session, "hook_event_name": "PostToolUse",
               "cwd": project, "tool_name": tool, "tool_input": tool_input,
               "tool_response": {}}
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_PROJECT_DIR", "LOXODONTA_HOME")}
    env.update({"LOXODONTA_HOME": os.path.join(home, ".loxodonta"),
                "HOME": home, "USERPROFILE": home,
                "SOURCE_DATE_EPOCH": str(int(when.timestamp())),
                "PYTHONIOENCODING": "utf-8"})
    done = subprocess.run([sys.executable, LOXODONTA, "hook"], cwd=project,
                          input=json.dumps(payload).encode("utf-8"),
                          capture_output=True, env=env)
    if done.returncode != 0:
        sys.exit("error: the recorder refused a receipt: "
                 + done.stderr.decode("utf-8", "replace").strip())


def build(home, force):
    home = os.path.abspath(home)
    store = os.path.join(home, ".loxodonta")
    project = os.path.join(home, "projects", "todo")
    if os.path.exists(store):
        if not force:
            sys.exit(f"error: {store} already exists; pass --force to "
                     "replace it")
        shutil.rmtree(store)
        shutil.rmtree(project, ignore_errors=True)
    for name, content in PROJECT_FILES.items():
        path = os.path.join(project, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    receipts = 0
    for session, when, calls in SESSIONS:
        for gap, tool, tool_input in calls:
            when = datetime.fromtimestamp(when.timestamp() + gap,
                                          timezone.utc)
            play(project, tool, tool_input)
            hook(home, project, session, when, tool, tool_input)
            receipts += 1
    print(f"wrote demo store {store}: {len(SESSIONS)} sessions, "
          f"{receipts} receipts, project {project}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="write the demo store under a neutral home")
    parser.add_argument("--home", required=True,
                        help="a directory standing in for a user's home")
    parser.add_argument("--force", action="store_true",
                        help="replace a store already there")
    args = parser.parse_args(argv)
    build(args.home, args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
