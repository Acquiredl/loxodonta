"""Behavioral tests for `supervisor export` (ADR-0021): the field-data
export that a stranger can send back without publishing their username,
their project names, or their shell history.

The store under test is built through the public CLI with deliberately
distinctive strings in every place the real store leaks identity — the
home directory, the project name, the command lines — and the tests
assert those strings never reach the export. The allowlist is pinned as
an exact key set, so a new scan field cannot slip in unnamed.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOXODONTA = REPO_ROOT / "loxodonta.py"
SUPERVISOR = REPO_ROOT / "supervisor.py"

HOME_SECRET = "HOMESECRET-q7x"
PROJECT_SECRET = "PROJSECRET-m4k"
COMMAND_SECRET = "CMDSECRET-z9p"
FILE_SECRET = "FILESECRET-r2v.py"
SESSION = "e1e1e1e1-aaaa-bbbb-cccc-000000000001"
OTHER_SESSION = "e2e2e2e2-aaaa-bbbb-cccc-000000000002"


def run(script, *args, stdin=None, env=None, cwd=None):
    return subprocess.run(
        [sys.executable, str(script), *args], cwd=cwd,
        input=stdin.encode("utf-8") if isinstance(stdin, str) else stdin,
        capture_output=True, encoding=None,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})})


def text(result):
    return (result.stdout.decode("utf-8", "replace"),
            result.stderr.decode("utf-8", "replace"))


class ExportBase(unittest.TestCase):
    """A store with one project, two sessions, and every kind of entry
    the histogram must sort: hook receipts, a bookkeeping entry, and a
    hand-logged entry from a non-harness actor."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.home = self.root / HOME_SECRET
        self.store = self.home / ".loxodonta"
        self.project = self.root / PROJECT_SECRET
        self.project.mkdir()
        (self.project / FILE_SECRET).write_text("print(1)\n", "utf-8")
        self.witness = self.root / "no-witness"
        self.witness.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("CLAUDE_PROJECT_DIR", "LOXODONTA_HOME")}
        self.env.update({"LOXODONTA_HOME": str(self.store),
                         "HOME": str(self.home), "USERPROFILE": str(self.home)})
        self.hook(SESSION, "Bash", {"command": f"echo {COMMAND_SECRET}"})
        self.hook(SESSION, "Bash", {"command": "pytest -q"})
        self.hook(SESSION, "Edit", {"file_path": str(self.project / FILE_SECRET)})
        self.hook(OTHER_SESSION, "Read", {"file_path": str(self.project / FILE_SECRET)})
        self.log = self.drawer() / f"receipts-{SESSION}.jsonl"
        # A hand-logged entry from a non-harness actor, and a bookkeeping
        # entry: neither is a tool call, and the histogram must say so.
        run(LOXODONTA, "log", "--log", str(self.log), "--actor", "tester",
            "--action", f"note: {COMMAND_SECRET}")
        run(LOXODONTA, "log", "--log", str(self.log), "--actor", "receipts",
            "--action", "transcript-commitment: bytes=10 sha256=00")

    def hook(self, session, tool, tool_input):
        payload = json.dumps({"session_id": session,
                              "hook_event_name": "PostToolUse",
                              "tool_name": tool, "tool_input": tool_input,
                              "tool_response": {}})
        result = run(LOXODONTA, "hook", stdin=payload,
                     env={**self.env, "CLAUDE_PROJECT_DIR": str(self.project)})
        self.assertEqual(result.returncode, 0, text(result)[1])

    def drawer(self):
        drawers = [p for p in (self.store / "receipts").iterdir() if p.is_dir()]
        self.assertEqual(len(drawers), 1)
        return drawers[0]

    def export(self, *args, stdin=None, env=None):
        return run(SUPERVISOR, "export", "--witness", str(self.witness),
                   *args, stdin=stdin, env={**self.env, **(env or {})},
                   cwd=str(self.work))

    def exported_file(self):
        files = list(self.work.glob("loxodonta-export-*.json"))
        self.assertEqual(len(files), 1, files)
        return files[0]


class ExportFileTest(ExportBase):
    def test_writes_prints_and_leaks_nothing(self):
        result = self.export()
        out, err = text(result)
        self.assertEqual(result.returncode, 0, err)
        path = self.exported_file()
        body = path.read_text("utf-8")
        # Printed is written (the console may translate newlines).
        self.assertEqual(out.replace("\r\n", "\n").strip(), body.strip())
        self.assertIn(path.name, err)  # and the sender is told where
        for secret in (HOME_SECRET, PROJECT_SECRET, COMMAND_SECRET,
                       FILE_SECRET, "receipts-", ".jsonl", "pytest"):
            self.assertNotIn(secret, body, secret)
        # No path of any shape survives: nothing that looks like one.
        self.assertNotIn(str(self.root), body)
        self.assertNotIn("\\\\", body)
        self.assertNotIn(":/", body)

    def test_redaction_block_comes_first_and_says_what_was_removed(self):
        self.export()
        body = self.exported_file().read_text("utf-8")
        self.assertTrue(body.lstrip().startswith('{\n  "redaction"'), body[:80])
        redaction = json.loads(body)["redaction"]
        words = " ".join(redaction["removed"]).lower()
        for removed in ("path", "command", "repo name", "file"):
            self.assertIn(removed, words)
        self.assertIn("allowlist", redaction["words"].lower())

    def test_the_allowlist_is_exactly_the_documented_shape(self):
        self.export()
        data = json.loads(self.exported_file().read_text("utf-8"))
        self.assertEqual(list(data), ["redaction", "export", "machine",
                                      "sessions"])
        self.assertEqual(sorted(data["machine"]), sorted([
            "recorder_commit", "python", "os", "matchers", "store",
            "day_book", "lifecycle", "scan_exit"]))
        self.assertEqual(sorted(data["machine"]["store"]),
                         ["bytes", "chains", "entries"])
        for session in data["sessions"]:
            self.assertEqual(sorted(session), sorted([
                "session", "repo", "entries", "span", "verdict",
                "commitments", "completeness", "dormancy", "consumption",
                "siblings", "bookkeeping", "tools"]), session)
            self.assertEqual(sorted(session["span"]), ["first", "last"])
            self.assertEqual(sorted(session["completeness"]),
                             ["owed", "received", "state"])

    def test_sessions_are_counted_not_named(self):
        self.export()
        data = json.loads(self.exported_file().read_text("utf-8"))
        by_id = {s["session"]: s for s in data["sessions"]}
        self.assertEqual(set(by_id), {SESSION, OTHER_SESSION})
        first = by_id[SESSION]
        self.assertEqual(first["repo"], "repo-1")
        self.assertEqual(by_id[OTHER_SESSION]["repo"], "repo-1")
        self.assertEqual(first["verdict"], "VALID")
        self.assertEqual(first["entries"], 6)  # genesis + 3 hook + 2 logged
        self.assertEqual(first["siblings"], 1)
        self.assertEqual(first["bookkeeping"], 1)
        # Hook actors get a per-tool histogram; everything else is `other`.
        self.assertEqual(first["tools"], {"Bash": 2, "Edit": 1, "other": 1})
        self.assertEqual(by_id[OTHER_SESSION]["tools"], {"Read": 1})
        self.assertTrue(first["span"]["first"] <= first["span"]["last"])
        self.assertEqual(first["completeness"]["state"], "UNWITNESSED")
        machine = data["machine"]
        self.assertEqual(machine["store"]["chains"], 2)
        self.assertEqual(machine["store"]["entries"], 8)
        self.assertGreater(machine["store"]["bytes"], 0)
        self.assertRegex(machine["python"], r"^3\.\d+$")
        self.assertIn(machine["os"], ("Windows", "Linux", "Darwin"))
        self.assertEqual(machine["scan_exit"], 0)
        self.assertIsInstance(machine["day_book"], list)
        self.assertEqual(sorted(machine["lifecycle"]), ["events", "kept"])

    def test_out_names_the_file(self):
        target = self.work / "mine.json"
        result = self.export("--out", str(target))
        self.assertEqual(result.returncode, 0, text(result)[1])
        self.assertTrue(target.exists())
        self.assertFalse(list(self.work.glob("loxodonta-export-*.json")))


class ExportRawTest(ExportBase):
    def test_raw_shows_a_sample_line_and_refuses_without_yes(self):
        for answer in ("no", "", "y\n"):
            result = self.export("--raw", stdin=answer)
            out, err = text(result)
            self.assertNotEqual(result.returncode, 0, answer)
            # The sample is a real hook receipt from the sender's own
            # chains, secrets and all: that is the point of showing it.
            # Both sessions were written within the same second and the
            # last receipt of each names the file, so whichever wins
            # the tie shows FILE_SECRET.
            shown = out + err
            self.assertIn(FILE_SECRET, shown)
            self.assertIn("yes", (out + err).lower())
            self.assertFalse(list(self.work.glob("*.zip")), answer)
        self.assertFalse(list(self.work.glob("loxodonta-export-*.json")))

    def test_raw_bundle_is_the_chains_byte_for_byte_without_project_json(self):
        result = self.export("--raw", stdin="yes\n")
        out, err = text(result)
        self.assertEqual(result.returncode, 0, err)
        bundles = list(self.work.glob("loxodonta-export-*-raw.zip"))
        self.assertEqual(len(bundles), 1)
        with zipfile.ZipFile(bundles[0]) as bundle:
            names = bundle.namelist()
            self.assertTrue(all(n.startswith("repo-1/") for n in names), names)
            self.assertFalse(any("project.json" in n for n in names))
            self.assertFalse(any(PROJECT_SECRET in n for n in names))
            chain = f"repo-1/{self.log.name}"
            self.assertIn(chain, names)
            self.assertEqual(bundle.read(chain), self.log.read_bytes())
        # The redacted export is written too: the bundle rides with it.
        self.exported_file()
        self.assertIn(bundles[0].name, err)


def fake_gh(bin_dir, log):
    """A `gh` that records its argv and answers with URLs, on both
    shell families."""
    posix = bin_dir / "gh"
    posix.write_bytes((  # LF on every platform; 3.9's write_text has no newline=
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> \"{log.as_posix()}\"\n"
        "if [ \"$1\" = gist ]; then echo https://gist.github.com/fake/abc123;"
        " else echo https://github.com/Acquiredl/loxodonta/issues/999; fi\n"
    ).encode("utf-8"))
    posix.chmod(0o755)
    (bin_dir / "gh.cmd").write_text(
        "@echo off\r\n"
        f"echo %* >> \"{log}\"\r\n"
        "if \"%1\"==\"gist\" (echo https://gist.github.com/fake/abc123) "
        "else (echo https://github.com/Acquiredl/loxodonta/issues/999)\r\n",
        encoding="utf-8")


class ExportSendTest(ExportBase):
    def setUp(self):
        super().setUp()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.gh_log = self.root / "gh-calls.log"

    def test_send_is_gh_twice_from_the_template(self):
        fake_gh(self.bin, self.gh_log)
        env = {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")}
        result = self.export("--send", env=env)
        out, err = text(result)
        self.assertEqual(result.returncode, 0, err)
        calls = self.gh_log.read_text("utf-8").strip().splitlines()
        self.assertEqual(len(calls), 2, calls)
        gist, issue = calls
        self.assertTrue(gist.startswith("gist create"), gist)
        self.assertNotIn("--public", gist)  # secret is gh's default
        self.assertIn(self.exported_file().name, gist)
        self.assertTrue(issue.startswith("issue create"), issue)
        self.assertIn("--repo Acquiredl/loxodonta", issue)
        self.assertIn("--label field-data", issue)
        self.assertIn("--body-file", issue)
        # The issue body is left beside the export for reading and for
        # filing by hand; it carries the gist link and the redaction block.
        bodies = list(self.work.glob("loxodonta-export-*.issue.md"))
        self.assertEqual(len(bodies), 1)
        body = bodies[0].read_text("utf-8")
        self.assertIn("https://gist.github.com/fake/abc123", body)
        self.assertIn("allowlist", body.lower())
        self.assertIn("- [x]", body)
        self.assertIn("- [ ] *(raw bundles only)*", body)
        for secret in (HOME_SECRET, PROJECT_SECRET, COMMAND_SECRET):
            self.assertNotIn(secret, body)
        self.assertIn("field-data: ", issue)
        self.assertIn("2 sessions", issue)
        self.assertIn("issues/999", out + err)

    def test_send_without_gh_says_so_and_leaves_the_file(self):
        empty = self.root / "empty-bin"
        empty.mkdir()
        result = self.export("--send", env={"PATH": str(empty)})
        out, err = text(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gh", err)
        self.exported_file()
        self.assertTrue(list(self.work.glob("loxodonta-export-*.issue.md")))

    def test_raw_send_ships_the_bundle_and_ticks_the_raw_line(self):
        fake_gh(self.bin, self.gh_log)
        env = {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")}
        result = self.export("--raw", "--send", stdin="yes\n", env=env)
        self.assertEqual(result.returncode, 0, text(result)[1])
        gist = self.gh_log.read_text("utf-8").splitlines()[0]
        self.assertIn("-raw.zip", gist)
        body = next(self.work.glob("*.issue.md")).read_text("utf-8")
        self.assertIn("- [x] *(raw bundles only)*", body)


if __name__ == "__main__":
    unittest.main()
