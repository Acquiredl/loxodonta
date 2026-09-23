"""The recorder, with the verifier answering for the verbs it holds.

tests/test_verifier.py points the verify tests here, so the same tests
judge verifier.py (ADR-0035): `head`, `verify` and `verify-package` go to
the copy, and every other verb, the writers that build the chains those
tests judge, goes to loxodonta.py. It runs the chosen file as its own
process, as a recipient would, and exits with that file's exit code.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
VERIFIER_VERBS = {"head", "verify", "verify-package"}

verb = sys.argv[1] if len(sys.argv) > 1 else None
script = ROOT / ("verifier.py" if verb in VERIFIER_VERBS else "loxodonta.py")
sys.exit(subprocess.run([sys.executable, str(script), *sys.argv[1:]]).returncode)
