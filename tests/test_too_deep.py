"""A file in the writer's reach nested past the JSON reader (#463).

The harness settings, the coverage marker and a SessionStart payload
are all the writer's to fill, and one hundred thousand `[` then as
many `]` is valid JSON that Python's reader refuses with
RecursionError, which is neither OSError nor ValueError. Every reader
of them treats a file too deep to read exactly as one that is not
JSON: `install-hook` and `uninstall-hook` refuse such settings by name,
65, before a byte is written; the marker is bookkeeping, read as none;
the scan and `serve` read either as absent; `digest --payload` reads
such a payload as no payload (#487 item 16). Never a traceback.

Every test drives the public CLI, in homes of the test's own.
"""

import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_too_deep`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import (LOXODONTA, SUPERVISOR, isolated_env, run,  # noqa: E402
                     temp_folder)
from test_supervisor import (install_witness_hook, make_chain,  # noqa: E402
                             unreadable_depth)

BOUND = 120


def too_deep():
    """Nesting this interpreter's reader refuses: valid JSON, unreadable."""
    depth = unreadable_depth()
    return "[" * depth + "]" * depth


NOT_JSON = "{ not json at all"


class InstalledTooDeepTest(unittest.TestCase):
    """`install-hook` and `uninstall-hook`, each harness, with settings
    or a coverage marker nested too deep to read."""

    def setUp(self):
        self.home = temp_folder(self)
        self.env = isolated_env(self.home)
        self.marker = self.home / ".loxodonta" / "coverage.json"

    def written(self):
        """Every regular file in the home, with its bytes."""
        return {path.relative_to(self.home).as_posix(): path.read_bytes()
                for path in self.home.rglob("*") if path.is_file()}

    def test_settings_too_deep_are_refused_by_name_untouched(self):
        deep = too_deep()
        claude = self.home / ".claude" / "settings.json"
        codex = self.home / ".codex" / "hooks.json"
        for verb, path in ((("install-hook",), claude),
                           (("install-hook", "--codex"), codex),
                           (("uninstall-hook",), claude),
                           (("uninstall-hook", "--codex"), codex)):
            with self.subTest(verb=" ".join(verb)):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(deep, encoding="utf-8")
                before = self.written()

                result = run(LOXODONTA, *verb, env=self.env, timeout=BOUND)

                # 65, as for settings that are not JSON (load_settings).
                self.assertEqual(result.returncode, 65,
                                 result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn(f"refusing to touch {path}: ", result.stderr)
                self.assertIn("fix it by hand first", result.stderr)
                self.assertEqual(self.written(), before,
                                 "nothing written anywhere in the home")
                path.unlink()

    def install_beside(self, content, *verb):
        self.marker.parent.mkdir(parents=True, exist_ok=True)
        self.marker.write_text(content, encoding="utf-8")
        result = run(LOXODONTA, *verb, env=self.env, timeout=BOUND)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def test_a_marker_too_deep_is_read_as_one_that_is_not_json(self):
        deep = too_deep()
        for verb in (("install-hook",), ("install-hook", "--codex"),
                     ("uninstall-hook",), ("uninstall-hook", "--codex")):
            with self.subTest(verb=" ".join(verb)):
                plain = self.install_beside(NOT_JSON, *verb)
                after_plain = self.marker.read_text(encoding="utf-8")

                result = self.install_beside(deep, *verb)

                self.assertEqual(result.returncode, plain.returncode,
                                 result.stdout + result.stderr)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                after = self.marker.read_text(encoding="utf-8")
                if after_plain == NOT_JSON:
                    # A verb that writes no marker leaves it as it was.
                    self.assertEqual(after, deep)
                else:
                    # The install wrote a fresh marker over the one it
                    # could not read, as over one that is not JSON.
                    self.assertEqual(len(json.loads(after)["epochs"]),
                                     len(json.loads(after_plain)["epochs"]))


class ScannedTooDeepTest(unittest.TestCase):
    """`supervisor scan` over the store with the harness settings or the
    coverage marker nested too deep to read: read as absent, the exit a
    file that is not JSON gives, every chain still judged."""

    def setUp(self):
        base = temp_folder(self)
        self.home = base / "storehome"
        self.witness = base / "witness"
        install_witness_hook(self.witness)
        drawer = self.home / "receipts" / "alpha-11111111"
        drawer.mkdir(parents=True)
        (drawer / "project.json").write_text(
            json.dumps({"path": "C:/work/alpha"}), encoding="utf-8")
        make_chain(drawer, "sess-aaaa")
        self.env = isolated_env(base / "home", LOXODONTA_HOME=str(self.home))

    def scan(self, path, content):
        path.write_text(content, encoding="utf-8")
        result = run(SUPERVISOR, "scan", "--json", "--witness",
                     str(self.witness), timeout=BOUND, env=self.env)
        self.assertNotIn("Traceback", result.stderr)
        report = json.loads(result.stdout)
        verdicts = [chain["verdict"] for repo in report["repos"]
                    for session in repo["sessions"]
                    for chain in session["chains"]]
        return result.returncode, verdicts

    def assert_read_as_not_json(self, path):
        self.assertEqual(self.scan(path, too_deep()),
                         self.scan(path, NOT_JSON))

    def test_settings_too_deep_read_as_settings_that_are_not_json(self):
        self.assert_read_as_not_json(self.witness.parent / "settings.json")

    def test_a_marker_too_deep_reads_as_one_that_is_not_json(self):
        self.assert_read_as_not_json(self.home / "coverage.json")


class ServedTooDeepTest(unittest.TestCase):
    """`serve` reads the coverage marker before it takes its port, to
    steer its keepers (ADR-0031): one nested too deep to read starts it
    with no profile on record, as one that is not JSON does."""

    def test_a_marker_too_deep_starts_serve_with_no_profile(self):
        home = temp_folder(self)
        (home / ".loxodonta").mkdir()
        (home / ".loxodonta" / "coverage.json").write_text(
            too_deep(), encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--port", "0",
             "--witness", str(home / "witness")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env=isolated_env(home))
        self.addCleanup(proc.communicate, timeout=BOUND)
        self.addCleanup(proc.kill)
        said = []
        reader = threading.Thread(target=lambda: said.extend(
            [proc.stdout.readline(), proc.stdout.readline()]), daemon=True)
        reader.start()
        reader.join(BOUND)

        self.assertFalse(reader.is_alive(), "serve never said it started")
        self.assertIn("http://127.0.0.1:", said[0])
        self.assertIn("anchor off (no profile on record; no flag)", said[1])


class DigestedTooDeepTest(unittest.TestCase):
    """`digest --payload` with a SessionStart payload nested too deep to
    read (#487 item 16): no payload, as one that is not JSON is, so the
    digest falls back to the working directory and a chainless one
    stays silent."""

    def test_a_payload_too_deep_reads_as_no_payload(self):
        home = temp_folder(self)
        folder = temp_folder(self)
        env = isolated_env(home)
        plain = run(SUPERVISOR, "digest", "--payload", stdin=NOT_JSON,
                    env=env, cwd=str(folder), timeout=BOUND)

        result = run(SUPERVISOR, "digest", "--payload", stdin=too_deep(),
                     env=env, cwd=str(folder), timeout=BOUND)

        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual((result.returncode, result.stdout),
                         (plain.returncode, plain.stdout))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
