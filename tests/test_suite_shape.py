"""The suite's own shape (#118): every test module imports on its own.

`python -m unittest discover -s tests` puts `tests/` on `sys.path`, so a
module that says `from test_recall import forge_chain` resolves under
discovery and nowhere else. CI runs discovery, so the suite stays green
while `python -m unittest tests.test_mcp` — the single-module red/green
loop a contributor runs while fixing one thing — dies on an import error
before a test ever runs.

This test imports every `tests/test_*.py` the way that loop does, as
`tests.<name>` from the repo root, each in its own subprocess so a broken
module names itself instead of taking the parent interpreter with it. It
is a test about the suite, not about the recorder.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"


class EveryModuleRunsAlone(unittest.TestCase):

    def test_every_test_module_imports_from_the_repo_root(self):
        modules = sorted(p.stem for p in TESTS_DIR.glob("test_*.py"))
        # A glob that found nothing would pass this test by saying nothing.
        self.assertGreater(len(modules), 1, "no test modules found to import")
        for name in modules:
            with self.subTest(module=name):
                done = subprocess.run(
                    [sys.executable, "-c",
                     "import importlib; "
                     "importlib.import_module('tests.%s')" % name],
                    cwd=str(REPO_ROOT), capture_output=True, encoding="utf-8",
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"})
                self.assertEqual(
                    done.returncode, 0,
                    "tests/%s.py does not import on its own — a contributor "
                    "cannot run `python -m unittest tests.%s`:\n%s"
                    % (name, name, done.stderr))


if __name__ == "__main__":
    unittest.main()
