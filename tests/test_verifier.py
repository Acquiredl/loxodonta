"""verifier.py, the recipient's copy of the verify side (ADR-0035).

The recorder holds the verify side as one fenced region, and
tools/build_verifier.py copies it into verifier.py. These tests hold the
copy to what the ADR rules. It is current, so CI fails when the region
moved and the copy did not. It reaches nothing it lacks, which is the
mechanical check that nothing in the region calls below the fence. It
imports nothing that sends. It speaks only the verbs that judge.

Then the verify tests run a second time with the verifier answering:
each class named in TWINNED runs again with its LOXODONTA pointed at
tests/fixtures/verifier_twin.py, which hands `head`, `verify` and
`verify-package` to verifier.py and every writer verb to the recorder. A
verdict the copy reached differently from the recorder fails there.
"""

import ast
import builtins
import importlib
import os
import subprocess
import symtable
import sys
import unittest
from pathlib import Path

# This folder on sys.path, so the sibling imports below also resolve
# when the module runs alone (`python -m unittest tests.test_verifier`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "verifier.py"
BUILD = REPO_ROOT / "tools" / "build_verifier.py"
TWIN = REPO_ROOT / "tests" / "fixtures" / "verifier_twin.py"

# Modules whose import would let the copy open a connection, start a
# thread, or run a shell line. The recorder needs them to send and to
# wrap commands; a file that only judges has no use for any of them.
SENDING_MODULES = {"socket", "ssl", "http", "urllib", "threading",
                   "asyncio", "smtplib", "ftplib", "shlex", "signal"}


def run(*args):
    return subprocess.run(
        [sys.executable, *map(str, args)], capture_output=True,
        encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})


class TheCopyTest(unittest.TestCase):

    def test_the_committed_copy_is_current(self):
        checked = run(BUILD, "--check")
        self.assertEqual(checked.returncode, 0,
                         checked.stdout + checked.stderr)

    def test_every_name_the_copy_reads_is_defined_in_it(self):
        # A function in the region that calls a definition below the fence
        # works in the recorder and is a NameError in the copy, on only
        # the path that reaches it. symtable finds it on every path: each
        # global a scope reads must be defined at the copy's top level or
        # be a builtin.
        source = VERIFIER.read_text(encoding="utf-8")
        top = symtable.symtable(source, str(VERIFIER), "exec")
        defined = {s.get_name() for s in top.get_symbols()
                   if s.is_assigned() or s.is_imported()}
        defined |= {"__file__", "__name__", "__doc__"}

        read = set()

        def collect(table):
            for symbol in table.get_symbols():
                if symbol.is_referenced() and (
                        table is top or symbol.is_global()):
                    read.add(symbol.get_name())
            for child in table.get_children():
                collect(child)

        collect(top)
        missing = sorted(name for name in read - defined
                         if not hasattr(builtins, name))
        self.assertEqual(missing, [], "verifier.py reads names it does not "
                         "define: a region function reaches below the fence")

    def test_the_copy_imports_nothing_that_sends(self):
        imported = set()
        for node in ast.walk(ast.parse(VERIFIER.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported & SENDING_MODULES, set())

    def test_the_copy_speaks_only_the_verbs_that_judge(self):
        for verb in ("init", "log", "run", "anchor", "publish", "stamp",
                     "hook", "install-hook"):
            with self.subTest(verb=verb):
                refused = run(VERIFIER, verb)
                self.assertEqual(refused.returncode, 64, refused.stderr)
                self.assertIn("invalid choice", refused.stderr)


# The classes that exercise `head`, `verify` and `verify-package`, by
# module. A class here runs twice: once as written, once on the copy.
TWINNED = {
    "test_cli": ["VerifyTest", "TranscriptVerifyTest", "FileReferenceTest",
                 "HeadTest", "TamperTest", "TornTailTest", "GoldenFixtureTest",
                 "ShapeTest", "LoneSurrogateTest", "UnopenableReferenceTest",
                 "UnreadableLineTest", "LineRuleTest", "NotUtf8LogTest"],
    "test_concurrency": ["ForkedTailTest"],
    "test_anchor": ["AnchorTest", "BlockHeaderTest"],
    "test_stamp": ["JudgedStampTest", "OutlivedCertificateTest"],
    "test_package": ["DemoStorePackageTest"],
    "test_package_anchor": ["SealedPackageTest"],
    "test_package_sign": ["SignedPackageTest"],
    "test_package_stamp": ["StampedPackageTest", "JudgedPackageStampTest",
                           "OutlivedPackageStampTest"],
}


def on_the_copy(base):
    """`base`, with every module along its MRO calling the twin wherever
    it called the recorder. Helpers inherited from a base class in another
    module read that module's LOXODONTA, so each is pointed at the twin
    for the length of one test and put back after."""
    modules = {sys.modules[klass.__module__] for klass in base.__mro__
               if hasattr(sys.modules.get(klass.__module__), "LOXODONTA")}

    def setUp(self):
        for module in modules:
            self.addCleanup(setattr, module, "LOXODONTA", module.LOXODONTA)
            module.LOXODONTA = TWIN
        base.setUp(self)

    return type(base.__name__ + "OnVerifier", (base,),
                {"setUp": setUp, "__module__": __name__,
                 "__qualname__": base.__name__ + "OnVerifier"})


for module_name, class_names in TWINNED.items():
    module = importlib.import_module(module_name)
    for class_name in class_names:
        twin = on_the_copy(getattr(module, class_name))
        globals()[twin.__name__] = twin
del module, twin


if __name__ == "__main__":
    unittest.main()
