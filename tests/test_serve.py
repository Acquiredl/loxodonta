"""Endpoint smoke tests for the supervisor's HTTP face (`supervisor.py serve`).

The face is serialization only, zero decisions (ADR-0005): a localhost-only
stdlib server, a status endpoint speaking the scan shape unchanged, and an
inline single-page frontend — no framework, no build step, nothing fetched
from anywhere but this machine. Tests drive real HTTP against an ephemeral
port; how the browser paints the band is manual fire-drill territory, but
the claims the page is built from are strings we can hold still here.
"""

import base64
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"
RECEIPTS = REPO_ROOT / "receipts.py"

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")

# Straight to 127.0.0.1 — never through a proxy someone's shell configured.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def make_chain(log_dir, session, entries=2):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the face is tested against what the tool writes."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"receipts-{session}.jsonl"
    subprocess.run([sys.executable, str(RECEIPTS), "init", "--log", str(log)],
                   capture_output=True, check=True)
    for i in range(entries):
        subprocess.run(
            [sys.executable, str(RECEIPTS), "log", "--log", str(log),
             "--actor", "claude-code", "--action", f"step {i}"],
            capture_output=True, check=True)
    return log


def ots_varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | 0x80 if n else byte)
        if not n:
            return bytes(out)


def write_completed_anchor(log, height=850000):
    """A minimal but genuine OTS timestamp: one sha256 op, then a Bitcoin
    attestation — enough for `verify --anchors` to replay offline and
    report ANCHORED, with no network and no calendar (ANCHORING.md §4)."""
    # Both ends of every pipe in this file pinned to UTF-8 (PYTHONIOENCODING
    # for the child, encoding= for the parent) — `text=True` alone decodes
    # with the locale codec, cp1252 on Windows, and disagrees with a
    # UTF-8-emitting child.
    head = subprocess.run(
        [sys.executable, str(RECEIPTS), "head", "--log", str(log)],
        capture_output=True, encoding="utf-8", check=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}).stdout.strip()
    payload = ots_varint(height)
    proof = (b"\x08"
             + b"\x00" + TAG_BITCOIN + ots_varint(len(payload)) + payload)
    record = {"head": head, "n": 2, "ts": "2026-08-22T09:00:00Z",
              "calendar": "https://calendar.example.test",
              "proof": base64.b64encode(proof).decode()}
    Path(str(log) + ".anchors.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8")


def log_entry(log, action, actor="claude-code", files=()):
    """One more receipt through the public CLI, optionally fingerprinting
    files (which must exist — receipts hashes them at log time)."""
    file_args = [arg for f in files for arg in ("--file", str(f))]
    subprocess.run(
        [sys.executable, str(RECEIPTS), "log", "--log", str(log),
         "--actor", actor, "--action", action, *file_args],
        capture_output=True, check=True)


class ServerFixture(unittest.TestCase):
    """A temp root and a real `serve` subprocess on an ephemeral port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def serve(self):
        """Start `serve` on an ephemeral port and read the announced URL."""
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if match is None:
            self.proc.kill()
            _, err = self.proc.communicate()
            self.fail(f"serve announced no localhost URL: {line!r}\n{err}")
        self.url = match.group()

    def _stop(self):
        self.proc.kill()
        self.proc.communicate()

    def get(self, path):
        with OPENER.open(self.url + path, timeout=30) as response:
            return (response.status, response.headers.get("Content-Type", ""),
                    response.read().decode("utf-8"))

    def recall(self, **filters):
        query = "?" + urllib.parse.urlencode(filters) if filters else ""
        _, _, body = self.get("/api/recall" + query)
        return json.loads(body)


class ServeTest(ServerFixture):
    def test_serve_binds_localhost_only(self):
        # The announcement is the bind: an ephemeral port on 127.0.0.1,
        # answering — nothing is offered to any other interface.
        self.serve()

        status, _, _ = self.get("/")

        self.assertEqual(status, 200)
        self.assertTrue(self.url.startswith("http://127.0.0.1:"))

    def test_status_endpoint_speaks_the_scan_shape_unchanged(self):
        # One valid chain, one anchored, one tampered: the endpoint must
        # return byte-for-byte the same report the scan CLI prints —
        # serialization only, zero decisions.
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        anchored = make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        write_completed_anchor(anchored)
        tampered = make_chain(self.root / "gamma" / "receipts", "sess-cccc")
        lines = tampered.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["action"] = "something else entirely"
        lines[1] = json.dumps(entry)
        tampered.write_text("".join(l + "\n" for l in lines),
                            encoding="utf-8")
        self.serve()

        status, ctype, body = self.get("/api/status")

        self.assertEqual(status, 200)
        self.assertIn("application/json", ctype)
        cli = subprocess.run(
            [sys.executable, str(SUPERVISOR), "scan", "--root",
             str(self.root), "--json"],
            capture_output=True, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(json.loads(body), json.loads(cli.stdout))

    def test_front_page_is_inline_html_with_no_outside_dependencies(self):
        self.serve()

        status, ctype, page = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn("/api/status", page, "the band renders the scan")
        self.assertNotIn("<script src", page, "no framework, no CDN")
        self.assertNotIn("<link", page, "nothing fetched from off-machine")

    def test_front_page_renders_tiers_as_distinct_claims(self):
        # The strings the band is built from: VALID and ANCHORED are
        # different claims, the exit-3 tier reads gravest, and superseded
        # damage is quiet evidence rather than a live alarm.
        self.serve()

        _, _, page = self.get("/")

        self.assertIn("ANCHORED", page)
        self.assertIn("VALID", page)
        self.assertIn("not the recorded history", page)
        self.assertIn("superseded", page)
        self.assertIn("verify", page, "verdicts come from receipts verify")

    def test_front_page_gives_the_tripwire_its_own_voice(self):
        # A change event is a reason to investigate, never a verdict —
        # the band draws it in its own words, apart from every tier.
        self.serve()

        _, _, page = self.get("/")

        self.assertIn("CHANGED SINCE LAST LOOK", page)
        self.assertIn('id="tripwire"', page)

    def test_front_page_watches_completeness_in_its_own_voice(self):
        self.serve()

        _, _, page = self.get("/")

        self.assertIn('id="watch"', page)
        self.assertIn("witnessed", page)

    def test_front_page_carries_the_anchor_panel(self):
        # Block heights are the headline: the operator's half of the
        # regeneration defense should be the easiest read on the page.
        self.serve()

        _, _, page = self.get("/")

        self.assertIn('id="anchors"', page)
        self.assertIn("block", page)
        self.assertIn("regeneration defense", page)

    def test_no_anti_terms_in_the_user_visible_surface(self):
        self.serve()

        _, _, page = self.get("/")

        lowered = page.lower()
        for anti_term in ("blockchain", "immutable", "audit"):
            self.assertNotIn(anti_term, lowered)

    def test_unknown_path_is_404(self):
        self.serve()

        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/no-such-surface")
        self.assertEqual(caught.exception.code, 404)


class WalkerTest(ServerFixture):
    """The chain walker (issue #20): a per-chain entries endpoint the
    browser walks entry by entry, recomputing hashes itself via
    WebCrypto — a second, independent check in the reader's hands. The
    in-browser recomputation is a manual fire-drill item; what tests can
    hold still is the endpoint and the page's boundary language."""

    def walk(self, log_param):
        _, _, body = self.get("/api/chain?log="
                              + urllib.parse.quote(str(log_param)))
        return json.loads(body)

    def test_the_walker_endpoint_serves_entries_with_damage_inlined(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        with open(log, "a", encoding="utf-8", newline="\n") as f:
            f.write('{"n":3,"half-written')
        self.serve()

        report = self.walk("alpha/receipts/receipts-sess-aaaa.jsonl")

        kinds = [("entry" if "entry" in line else "damage")
                 for line in report["lines"]]
        self.assertEqual(kinds, ["entry", "entry", "entry", "damage"],
                         "a broken chain is still a readable log — the "
                         "damage sits where it sits")
        genesis = report["lines"][0]["entry"]
        self.assertEqual(genesis["n"], 0)
        self.assertIn("entry_hash", genesis)
        self.assertIn("half-written", report["lines"][3]["damage"])

    def test_non_ascii_content_survives_the_endpoint_intact(self):
        # The mojibake lesson: an em-dash action must reach the browser
        # as the exact characters that were hashed.
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        log_entry(log, "close the grill — Recall enters the glossary")
        self.serve()

        report = self.walk("alpha/receipts/receipts-sess-aaaa.jsonl")

        actions = [line["entry"]["action"] for line in report["lines"]]
        self.assertIn("close the grill — Recall enters the glossary",
                      actions)

    def test_paths_outside_the_root_are_refused(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        for outside in ("../../../windows/win.ini",
                        "alpha/receipts/receipts-sess-aaaa.jsonl/../../"
                        "../../secrets.jsonl",
                        "no/such/chain.jsonl"):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.walk(outside)
            self.assertEqual(caught.exception.code, 404, outside)

    def test_walker_language_reports_recomputation_never_a_verdict(self):
        self.serve()

        _, _, page = self.get("/")

        self.assertIn('id="walker"', page)
        self.assertIn("recomputed in your browser", page)
        self.assertIn("verify", page)


class DrillSurfaceTest(ServerFixture):
    """The drill from the frontend: a POST runs the battery on sandbox
    copies, and the checklist — including the walker check no test can
    automate — is served where the surface links to it."""

    def test_the_drill_runs_over_http_and_reports_rehearsal(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                   entries=3)
        self.serve()

        request = urllib.request.Request(
            self.url + "/api/drill?log="
            + urllib.parse.quote("alpha/receipts/receipts-sess-aaaa.jsonl"),
            method="POST")
        with OPENER.open(request, timeout=60) as response:
            report = json.loads(response.read().decode("utf-8"))

        self.assertTrue(report["all_fired"])
        self.assertEqual(len(report["drills"]), 4)
        self.assertIn("sandbox", report["rehearsal"])

    def test_the_checklist_is_served_where_the_surface_links_to_it(self):
        self.serve()

        status, ctype, body = self.get("/checklist")

        self.assertEqual(status, 200)
        self.assertIn("text/plain", ctype)
        self.assertIn("WebCrypto", body)
        self.assertIn("walker", body)

    def test_the_front_page_carries_the_drill_surface(self):
        self.serve()

        _, _, page = self.get("/")

        self.assertIn('id="firedrill"', page)
        self.assertIn("rehearsal", page)
        self.assertIn("/checklist", page)


class RecallTest(ServerFixture):
    """The memory surface (GLOSSARY: Recall): the timeline endpoint reads
    chains as testimony — what was attempted, when, in which repo — and
    owns no verdicts. Sessions read newest first; siblings read as one
    story; the field-proven question ("did I work in X this week?") is
    one repo + one date range away."""

    def test_front_page_opens_on_recall(self):
        self.serve()

        _, _, page = self.get("/")

        self.assertIn("what was attempted", page,
                      "the testimony label is the surface's first claim")
        self.assertLess(page.index('id="recall"'), page.index('id="band"'),
                        "the memory view lands first; alarms sit around it")

    def test_timeline_lists_sessions_across_repos_newest_first(self):
        make_chain(self.root / "alpha" / "receipts", "sess-old")
        time.sleep(1.2)  # receipts stamps whole seconds; force an order
        make_chain(self.root / "beta" / "receipts", "sess-new")
        self.serve()

        report = self.recall()

        self.assertEqual([(s["repo"], s["session"])
                          for s in report["sessions"]],
                         [("beta", "sess-new"), ("alpha", "sess-old")])
        newest = report["sessions"][0]
        self.assertEqual(newest["entries"], 3)  # genesis + 2
        self.assertLessEqual(newest["started"], newest["ended"])

    def test_sibling_chains_read_as_one_session_story(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa-002",
                   entries=1)
        self.serve()

        report = self.recall()

        (story,) = report["sessions"]
        self.assertEqual(story["session"], "sess-aaaa")
        self.assertEqual(len(story["chains"]), 2)
        self.assertEqual(story["entries"], 5)  # (genesis+2) + (genesis+1)

    def test_filter_by_repo(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        self.serve()

        report = self.recall(repo="alpha")

        self.assertEqual([s["repo"] for s in report["sessions"]], ["alpha"])

    def test_one_repo_one_week_gives_exact_session_spans(self):
        # The journaled query, demoed: "did I work in alpha this week?"
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        self.serve()
        day = self.recall()["sessions"][0]["started"][:10]
        before = (datetime.date.fromisoformat(day)
                  - datetime.timedelta(days=1)).isoformat()
        after = (datetime.date.fromisoformat(day)
                 + datetime.timedelta(days=1)).isoformat()

        this_week = self.recall(repo="alpha", **{"from": day, "to": day})
        last_week = self.recall(repo="alpha", to=before)
        next_week = self.recall(repo="alpha", **{"from": after})

        (span,) = this_week["sessions"]
        self.assertEqual(span["entries"], 4)
        self.assertTrue(span["started"] and span["ended"],
                        "an exact span, not a shrug")
        self.assertEqual(last_week["sessions"], [])
        self.assertEqual(next_week["sessions"], [])

    def test_filter_by_file_path_matches_references_and_action_lines(self):
        # A fingerprinted file matches; so does a path that only survives
        # in the action line — the field's common case, where the hook
        # leaves files[] empty.
        ref_log = make_chain(self.root / "alpha" / "receipts", "sess-refs")
        (ref_log.parent / "touched.py").write_text("pass\n",
                                                   encoding="utf-8")
        # --file takes paths relative to the log's directory (SPEC §3).
        log_entry(ref_log, "edited a file", files=["touched.py"])
        action_log = make_chain(self.root / "beta" / "receipts", "sess-act")
        log_entry(action_log, "Write: src/widget.py")
        make_chain(self.root / "gamma" / "receipts", "sess-none")
        self.serve()

        by_reference = self.recall(path="touched.py")
        by_action = self.recall(path="widget.py")

        self.assertEqual([s["session"] for s in by_reference["sessions"]],
                         ["sess-refs"])
        self.assertEqual([s["session"] for s in by_action["sessions"]],
                         ["sess-act"])

    def test_recall_owns_no_verdicts_and_still_reads_damaged_chains(self):
        # Recall renders testimony and judges nothing: no verdict language
        # on the surface, and a torn chain is still remembered — its
        # readable receipts shown, the judging left to the status band.
        log = make_chain(self.root / "alpha" / "receipts", "sess-torn")
        with open(log, "a", encoding="utf-8", newline="\n") as f:
            f.write('{"n":3,"half-written')
        self.serve()

        _, _, body = self.get("/api/recall")

        report = json.loads(body)
        self.assertIn("what was attempted", report["testimony"])
        (story,) = report["sessions"]
        self.assertEqual(story["entries"], 3, "the readable receipts remain")
        for verdict_word in ("VALID", "BROKEN", "ANCHORED"):
            self.assertNotIn(verdict_word, body)


class SearchTest(ServerFixture):
    """Free-text recall search: one box over every action line on the
    machine. Search finds what was *written* — the writer's word — so it
    is testimony like the rest of recall, and each hit carries the
    context (repo, session, chain, entry) the timeline links on."""

    def search(self, **params):
        query = "?" + urllib.parse.urlencode(params) if params else ""
        _, _, body = self.get("/api/search" + query)
        return json.loads(body)

    def test_search_finds_action_lines_across_repos_with_context(self):
        alpha = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        log_entry(alpha, "deploy the albatross")
        beta = make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        log_entry(beta, "feed the elephant")
        self.serve()

        report = self.search(q="albatross")

        (hit,) = report["hits"]
        self.assertEqual(hit["repo"], "alpha")
        self.assertEqual(hit["session"], "sess-aaaa")
        self.assertEqual(hit["chain"], "receipts-sess-aaaa.jsonl")
        self.assertIsInstance(hit["n"], int)
        self.assertIn("albatross", hit["action"])
        self.assertEqual(report["matched"], 1)

        both = self.search(q="the")
        self.assertEqual({h["repo"] for h in both["hits"]},
                         {"alpha", "beta"})

    def test_search_is_case_insensitive(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        log_entry(log, "Write: Notes.md")
        self.serve()

        report = self.search(q="write: notes")

        self.assertEqual(report["matched"], 1)

    def test_hits_read_newest_first(self):
        old = make_chain(self.root / "alpha" / "receipts", "sess-old")
        log_entry(old, "shared word, older")
        time.sleep(1.2)  # receipts stamps whole seconds; force an order
        new = make_chain(self.root / "beta" / "receipts", "sess-new")
        log_entry(new, "shared word, newer")
        self.serve()

        report = self.search(q="shared word")

        self.assertEqual([h["session"] for h in report["hits"]],
                         ["sess-new", "sess-old"])

    def test_empty_query_and_no_match_are_graceful(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        for report in (self.search(), self.search(q=""),
                       self.search(q="no such words anywhere")):
            self.assertEqual(report["hits"], [])
            self.assertEqual(report["matched"], 0)

    def test_search_is_testimony_and_owns_no_verdicts(self):
        log = make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        log_entry(log, "an ordinary step")
        self.serve()

        _, _, body = self.get("/api/search?q=ordinary")

        report = json.loads(body)
        self.assertIn("what was attempted", report["testimony"])
        for verdict_word in ("VALID", "BROKEN", "ANCHORED"):
            self.assertNotIn(verdict_word, body)

    def test_front_page_carries_the_search_box(self):
        self.serve()

        _, _, page = self.get("/")

        self.assertIn("/api/search", page, "the box asks the endpoint")
        self.assertIn('id="ask-search"', page)


if __name__ == "__main__":
    unittest.main()

