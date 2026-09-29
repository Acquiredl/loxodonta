"""The lines a recipient reads about one row, one file or one field.

A verdict about one sidecar row names the row's line (`line N of
<sidecar>`), so a recipient with a long sidecar can find it; a row's
missing field is said in words, never printed as Python's `None`; inside
a package, advice about a tool the recipient does not have is left out;
and a manifest the verifier refuses is refused for the one reason that
holds. The verdict words and the exit codes are unchanged.

Every expected line here was written out and approved before the code
that prints it, and each runs against loxodonta.py and verifier.py
alike, through the command line, as a recipient runs them.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "tests" / "vectors"
TOOLS = (REPO_ROOT / "loxodonta.py", REPO_ROOT / "verifier.py")

TAIL = "evidence that does not verify is not evidence"
OTHER_HEAD = "ab" * 32
ANCHORS = "receipts.jsonl.anchors.jsonl"
STAMPS = "receipts.jsonl.stamps.jsonl"


def run(tool, *args, cwd):
    return subprocess.run([sys.executable, "-I", str(tool), *args],
                          cwd=str(cwd), capture_output=True,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"})


def vector_row(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8")
                      .splitlines()[0])


def write_lines(path, lines):
    # Bytes, not write_text(newline=), which 3.9 lacks: LF everywhere.
    Path(path).write_bytes("".join(line + "\n" for line in lines)
                           .encode("utf-8"))


class Case(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name)

    def lines_under_both(self, *args, exit_code):
        """stdout's lines, the same under both files."""
        seen = []
        for tool in TOOLS:
            result = run(tool, *args, cwd=self.work)
            self.assertEqual(result.returncode, exit_code,
                             f"{tool.name}: {result.stdout}{result.stderr}")
            self.assertNotIn("Traceback", result.stderr)
            seen.append(result.stdout.splitlines())
        self.assertEqual(seen[0], seen[1], "the two files disagree")
        return seen[0]


class AnchorRowLineTest(Case):
    """Cases 1 to 6: each anchor row's verdict names its line, and a
    pending row's missing time or calendar is said in words."""

    def setUp(self):
        super().setUp()
        shutil.copy(VECTORS / "anchor-pending.jsonl",
                    self.work / "receipts.jsonl")
        pending = vector_row("anchor-pending.jsonl.anchors.jsonl")
        no_ts = {k: v for k, v in pending.items() if k != "ts"}
        no_calendar = {k: v for k, v in pending.items() if k != "calendar"}
        write_lines(self.work / ANCHORS, [
            json.dumps(pending),
            json.dumps(dict(pending, head=["x"])),
            "not json",
            json.dumps(dict(pending, head=OTHER_HEAD)),
            json.dumps(dict(pending,
                            proof=base64.b64encode(b"\x00\x01").decode())),
            json.dumps(no_ts),
            json.dumps(no_calendar),
        ])
        self.out = self.lines_under_both("verify", "--log", "receipts.jsonl",
                                         "--anchors", exit_code=3)

    def test_1_an_unreadable_line_is_named_by_its_line(self):
        self.assertIn(f"ANCHOR-INVALID: line 3 of {ANCHORS} is not a record "
                      f"— {TAIL}", self.out)

    def test_2_a_row_of_the_wrong_shape_is_named_by_its_line(self):
        self.assertIn(f"ANCHOR-INVALID: line 2 of {ANCHORS}: record's head "
                      f"is an array, not a string — {TAIL}", self.out)

    def test_3_a_head_the_chain_lacks_is_named_by_its_line(self):
        self.assertIn(f"ANCHOR-MISMATCH: line 4 of {ANCHORS}: anchored head "
                      f"{OTHER_HEAD} appears nowhere in this log — this log "
                      "is not the anchored history", self.out)

    def test_4_a_proof_that_does_not_replay_is_named_by_its_line(self):
        self.assertIn(f"ANCHOR-INVALID: line 5 of {ANCHORS}: truncated proof "
                      f"— {TAIL}", self.out)

    def test_5_a_pending_row_with_no_time_says_so(self):
        self.assertIn("ANCHOR-PENDING: head fab3462eec00… submitted at an "
                      "unrecorded time via https://calendar.example/ — run "
                      "`loxodonta anchor --upgrade`", self.out)

    def test_6_a_pending_row_with_no_calendar_says_upgrade_cannot_help(self):
        self.assertIn("ANCHOR-PENDING: head fab3462eec00… submitted "
                      "2026-09-23T12:05:00Z via no recorded calendar — "
                      "`loxodonta anchor --upgrade` cannot complete it; "
                      "`loxodonta anchor --force` submits the head again",
                      self.out)

    def test_no_line_prints_none(self):
        self.assertFalse([line for line in self.out if "None" in line],
                         self.out)


class StampRowLineTest(Case):
    """Cases 7 to 10: each stamp row's verdict names its line, and a row
    of the wrong shape names its field, as an anchor row's does."""

    def setUp(self):
        super().setUp()
        shutil.copy(VECTORS / "stamp-kindless.jsonl",
                    self.work / "receipts.jsonl")
        token = vector_row("stamp-kindless.jsonl.stamps.jsonl")
        write_lines(self.work / STAMPS, [
            "not json",
            json.dumps({k: v for k, v in token.items() if k != "head"}),
            json.dumps(dict(token, head=OTHER_HEAD)),
            json.dumps(dict(token, response="!!")),
            json.dumps(dict(token, response=5)),
        ])
        self.out = self.lines_under_both("verify", "--log", "receipts.jsonl",
                                         "--stamps", exit_code=3)

    def test_7_an_unreadable_line_is_named_by_its_line(self):
        self.assertIn(f"STAMP-INVALID: line 1 of {STAMPS} is not a record — "
                      f"{TAIL}", self.out)

    def test_8_a_row_with_no_head_names_the_field(self):
        self.assertIn(f"STAMP-INVALID: line 2 of {STAMPS}: record has no "
                      f"head — {TAIL}", self.out)

    def test_8_a_response_of_the_wrong_type_names_the_field(self):
        self.assertIn(f"STAMP-INVALID: line 5 of {STAMPS}: record's response "
                      f"is a number, not a string — {TAIL}", self.out)

    def test_9_a_head_the_chain_lacks_is_named_by_its_line(self):
        self.assertIn(f"STAMP-INVALID: line 3 of {STAMPS}: stamped head "
                      f"{OTHER_HEAD} appears nowhere in this log — this log "
                      "is not the stamped history", self.out)

    def test_10_a_reply_that_is_not_base64_is_named_by_its_line(self):
        self.assertIn(f"STAMP-INVALID: line 4 of {STAMPS}, head "
                      "fab3462eec00… (entry 3): the response is not base64 — "
                      f"{TAIL}", self.out)


class SealRowLineTest(Case):
    """A manifest's seal rows are named by their line, as a chain's are."""

    def test_an_unreadable_anchor_seal_line_is_named_by_its_line(self):
        package = self.work / "package"
        shutil.copytree(VECTORS / "package-anchored", package)
        sidecar = package / "manifest.json.anchors.jsonl"
        with open(sidecar, "a", encoding="utf-8", newline="\n") as f:
            f.write("not json\n")
        rows = len(sidecar.read_text(encoding="utf-8").splitlines())

        out = self.lines_under_both("verify-package", "package", exit_code=3)

        self.assertIn(f"seal anchor: SEAL-INVALID: line {rows} of "
                      f"manifest.json.anchors.jsonl is not a record — {TAIL}",
                      out)

    def test_an_unreadable_stamp_seal_line_is_named_by_its_line(self):
        package = self.work / "package"
        shutil.copytree(VECTORS / "package-unsealed", package)
        manifest = json.loads((package / "manifest.json")
                              .read_text(encoding="utf-8"))
        manifest["seals"] = ["stamp"]
        (package / "manifest.json").write_text(json.dumps(manifest),
                                               encoding="utf-8")
        write_lines(package / "manifest.json.stamps.jsonl", ["not json"])

        out = self.lines_under_both("verify-package", "package", exit_code=3)

        self.assertIn("seal stamp: SEAL-INVALID: line 1 of "
                      f"manifest.json.stamps.jsonl is not a record — {TAIL}",
                      out)


class PackageLineTest(Case):
    """Cases 12 to 14."""

    def package(self, vector="package-unsealed"):
        package = self.work / "package"
        shutil.copytree(VECTORS / vector, package)
        return package

    def edit_manifest(self, package, edit):
        manifest = json.loads((package / "manifest.json")
                              .read_text(encoding="utf-8"))
        edit(manifest)
        (package / "manifest.json").write_text(json.dumps(manifest),
                                               encoding="utf-8")

    def test_12_a_folder_where_a_chain_belongs_is_named_as_one(self):
        package = self.package()
        (package / "receipts-vector.jsonl").unlink()
        (package / "receipts-vector.jsonl").mkdir()

        out = self.lines_under_both("verify-package", "package", exit_code=2)

        self.assertIn("receipts-vector.jsonl: DIVERGED from the manifest: it "
                      "is a folder, not a file", out)
        self.assertEqual(out[-1].split(":")[0], "ARTIFACT-DIVERGED")

    def test_13_no_anchors_in_a_package_gives_no_advice(self):
        self.package()

        out = self.lines_under_both("verify-package", "package", exit_code=0)

        self.assertIn("NO-ANCHORS: receipts-vector.jsonl.anchors.jsonl is "
                      "not in this package — anchoring is optional", out)
        self.assertFalse([line for line in out if "`loxodonta" in line], out)

    def test_13_no_stamps_in_a_package_gives_no_advice(self):
        package = self.package()
        self.edit_manifest(package, lambda m: m["chains"][0].update(
            stamps="receipts-vector.jsonl.stamps.jsonl"))

        out = self.lines_under_both("verify-package", "package", exit_code=0)

        self.assertIn("NO-STAMPS: receipts-vector.jsonl.stamps.jsonl is not "
                      "in this package — the authority timestamp is optional",
                      out)
        self.assertFalse([line for line in out if "`loxodonta" in line], out)

    def test_outside_a_package_the_advice_stays(self):
        shutil.copy(VECTORS / "valid-chain.jsonl", self.work / "receipts.jsonl")

        out = self.lines_under_both("verify", "--log", "receipts.jsonl",
                                    "--anchors", exit_code=0)

        self.assertIn("NO-ANCHORS: receipts.jsonl.anchors.jsonl not found — "
                      "anchoring is optional; run `loxodonta anchor` to add "
                      "one", out)

    def test_14_a_refused_manifest_names_the_one_reason(self):
        cases = [
            (lambda m: m["artifacts"][0].update(path="C:x"),
             "manifest.json lists an artifact whose path 'C:x' is not a bare "
             "file name"),
            (lambda m: m["chains"][0].pop("head"),
             "manifest.json lists a chain with no head"),
            (lambda m: m["chains"][0].update(head=7),
             "manifest.json lists a chain whose head is a number, not a "
             "string"),
            (lambda m: m["chains"][0].update(entries="4"),
             "manifest.json lists a chain whose entries is a string, not an "
             "integer"),
            (lambda m: m["chains"][0].update(entries=True),
             "manifest.json lists a chain whose entries is true or false, not "
             "an integer"),
            (lambda m: m["chains"].__setitem__(0, ["x"]),
             "manifest.json lists a chain that is an array, not an object"),
            (lambda m: m["artifacts"][0].pop("sha256"),
             "manifest.json lists an artifact with no sha256"),
            (lambda m: m["artifacts"][0].update(bytes="42"),
             "manifest.json lists an artifact whose bytes is a string, not an "
             "integer"),
        ]
        for edit, reason in cases:
            with self.subTest(reason=reason):
                shutil.rmtree(self.work / "package", ignore_errors=True)
                package = self.package()
                self.edit_manifest(package, edit)

                out = self.lines_under_both("verify-package", "package",
                                            exit_code=4)

                self.assertEqual(out, [f"UNSUPPORTED-FORMAT: {reason}"])


if __name__ == "__main__":
    unittest.main()
