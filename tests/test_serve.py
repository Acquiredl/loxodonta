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
import shutil
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
LOXODONTA = REPO_ROOT / "loxodonta.py"

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")

# Straight to 127.0.0.1 — never through a proxy someone's shell configured.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def make_chain(log_dir, session, entries=2):
    """A real chain, built through the public CLI — not a hand-forged
    fixture — so the face is tested against what the tool writes."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"receipts-{session}.jsonl"
    subprocess.run([sys.executable, str(LOXODONTA), "init", "--log", str(log)],
                   capture_output=True, check=True)
    for i in range(entries):
        subprocess.run(
            [sys.executable, str(LOXODONTA), "log", "--log", str(log),
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
        [sys.executable, str(LOXODONTA), "head", "--log", str(log)],
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
        [sys.executable, str(LOXODONTA), "log", "--log", str(log),
         "--actor", actor, "--action", action, *file_args],
        capture_output=True, check=True)


class ServerFixture(unittest.TestCase):
    """A temp root and a real `serve` subprocess on an ephemeral port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def serve(self, extra_env=None):
        """Start `serve` on an ephemeral port and read the announced URL."""
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--root",
             str(self.root), "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8",
                 **(extra_env or {})})
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


class StoreServeTest(ServerFixture):
    """serve over the central store (ADR-0011/0013): no --root, the
    drawers are the universe, repos label themselves through their
    project records."""

    def setUp(self):
        super().setUp()
        self.home = self.root / "storehome"

    def serve_store(self):
        witness = self.root / "no-witness"
        witness.mkdir(exist_ok=True)
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "serve", "--port", "0",
             "--witness", str(witness)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8",
                 "LOXODONTA_HOME": str(self.home)})
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:\d+", line)
        if match is None:
            self.proc.kill()
            _, err = self.proc.communicate()
            self.fail(f"serve announced no localhost URL: {line!r}\n{err}")
        self.url = match.group()

    def drawer(self, slug, project_path):
        d = self.home / "receipts" / slug
        d.mkdir(parents=True, exist_ok=True)
        (d / "project.json").write_text(
            json.dumps({"path": str(project_path)}), encoding="utf-8")
        return d

    def test_status_and_recall_read_the_drawers(self):
        alpha = self.drawer("alpha-11111111", r"C:\work\alpha")
        make_chain(alpha, "sess-aaaa", entries=3)
        self.serve_store()

        _, _, body = self.get("/api/status")
        report = json.loads(body)
        self.assertEqual([r["repo"] for r in report["repos"]], ["alpha"])

        timeline = self.recall()
        self.assertEqual([s["repo"] for s in timeline["sessions"]],
                         ["alpha"])
        self.assertEqual(timeline["sessions"][0]["session"], "sess-aaaa")

    def test_search_and_walker_reach_drawer_chains(self):
        alpha = self.drawer("alpha-11111111", r"C:\work\alpha")
        log = make_chain(alpha, "sess-aaaa")
        log_entry(log, "the drawer needle")
        self.serve_store()

        _, _, body = self.get("/api/search?q=drawer+needle")
        report = json.loads(body)
        self.assertEqual(report["matched"], 1)
        self.assertEqual(report["hits"][0]["repo"], "alpha")

        _, _, body = self.get(
            "/api/chain?log=" + urllib.parse.quote(log.as_posix()))
        walked = json.loads(body)
        self.assertEqual(walked["lines"][0]["entry"]["action"], "genesis")


class DashboardTest(ServerFixture):
    """The alarm-first front page (ADR-0013): the verdict strip leads,
    drawers follow, events sit above the browsing surfaces, and the
    terminal identity never carries information."""

    def page(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()
        _, _, page = self.get("/")
        return page

    def test_the_verdict_strip_leads_the_page(self):
        page = self.page()
        self.assertIn('id="strip"', page)
        self.assertIn('id="stateline"', page)
        self.assertLess(page.index('id="strip"'), page.index('id="tiles"'))
        self.assertLess(page.index('id="tiles"'),
                        page.index('id="tripwire"'))
        # The three states the JS can pick, by the ratified tier order.
        self.assertIn("NOT THE RECORDED HISTORY", page)
        self.assertIn("RECEIPTS STOPPED ARRIVING", page)
        self.assertIn("all quiet", page)

    def test_the_rail_carries_status_and_the_attention_queue(self):
        # The redesign's shell (#48, ratified 2026-09-01): a sticky rail
        # holds the status block, the attention queue, and the fortnight;
        # the work area holds everything the operator chose to look at.
        page = self.page()
        self.assertIn('id="rail"', page)
        self.assertIn('id="work"', page)
        self.assertLess(page.index('id="rail"'), page.index('id="work"'))
        self.assertIn('id="attention"', page)
        # The queue's ordering contract: live alarms outrank damaged
        # history, which outranks reasons to look.
        self.assertIn('const SEVERITY = ["alarm", "regenerated", '
                      '"broken", "tripwire", "hot"];', page)
        # The designed empty state — quiet is never blank.
        self.assertIn("nothing wants your eyes", page)

    def test_the_page_asks_nothing_of_any_other_host(self):
        # The cockpit renders offline: system fonts only, no CDN, no
        # third-party requests of any kind (#48 ruling).
        page = self.page()
        for outside in ("fonts.googleapis", "fonts.gstatic", "cdn.",
                        "//unpkg", "@import", 'src="http',
                        'href="http'):
            self.assertNotIn(outside, page)

    def test_the_panes_are_the_operators_to_resize(self):
        # A fixed frame that needs scrolling teaches the operator to
        # stop reading: the divider drags (and takes arrow keys) to
        # trade width, and each pane body grows by its own corner —
        # the browser's native resize, no library.
        page = self.page()
        self.assertIn('id="divider"', page)
        self.assertIn('role="separator"', page)
        self.assertIn("resize: vertical", page)
        self.assertIn("col-resize", page)

    def test_the_worktable_splits_sessions_from_inspection(self):
        # Slice 2 of the #48 shape: pane one is what you are looking
        # at (the sessions table), pane two is the thing under
        # inspection (chains as verify saw them, walk/judge actions).
        page = self.page()
        self.assertIn('id="worktable"', page)
        self.assertIn('id="sessions-table"', page)
        self.assertIn('id="inspect-chains"', page)
        self.assertIn("click a row to inspect", page)
        self.assertIn("walk this session", page)
        # The ADR-0017 surfacing: the judge command renders copy-ready,
        # and only for sessions the watch paired with a transcript.
        self.assertIn('id="inspect-judge"', page)
        self.assertIn("judge transcript", page)
        self.assertIn("seen.judge", page)

    def test_the_worktable_carries_all_four_tabs(self):
        # Slice 3 of the #48 shape: projects, search, and evidence join
        # sessions in pane one — the old full-width sections retire, and
        # every id they carried keeps its name inside its tab.
        page = self.page()
        for tab in ("sessions", "projects", "search", "evidence"):
            self.assertIn('data-tab="' + tab + '"', page)
            self.assertIn('id="pane-' + tab + '"', page)
        for kept in ('id="tiles"', 'id="ask-search"', 'id="tripwire"',
                     'id="watch"', 'id="consumption"', 'id="anchors"',
                     'id="filters"'):
            self.assertIn(kept, page)

    def test_the_activity_pane_draws_the_store(self):
        # Slice 4 of the #48 shape: pane two's second tab draws the
        # store — receipts per session, tempo against the store's own
        # norm (with the watch's honest empty state), looks per day
        # (red rides a HOT word, never colour alone), plus the
        # working-hours clock and the session gantt, moved in whole.
        page = self.page()
        self.assertIn('id="p2-activity"', page)
        self.assertIn('data-p2="activity"', page)
        for chart in ("chart-receipts", "chart-tempo", "chart-looks"):
            self.assertIn('id="' + chart + '"', page)
        self.assertIn("no session ran hot", page)
        self.assertIn("HOT", page)
        self.assertIn('id="clock"', page)
        self.assertIn('id="gantt"', page)
        # No chart library, no canvas fingerprinting — bars are SVG
        # built in the page's own script.
        self.assertIn("createElementNS", page)

    def test_the_page_carries_the_consumption_watch(self):
        # Issue #67: hot sessions render in the events section, in the
        # investigate voice — and the status endpoint carries the watch
        # the rows are drawn from.
        page = self.page()
        self.assertIn('id="consumption"', page)
        self.assertIn("RUNNING-HOT", page)
        self.assertIn("never a breaker", page,
                      "the circuit-breaker boundary is stated on the page")
        _, _, status = self.get("/api/status")
        self.assertIn("consumption", json.loads(status))

    def test_freshness_is_displayed_never_hidden(self):
        page = self.page()
        self.assertIn('id="freshness"', page)
        self.assertIn("last scan", page)
        self.assertIn("30000", page, "the 30s poll is the freshness deal")

    def test_identity_is_decoration_never_information(self):
        page = self.page()
        self.assertIn('class="wordmark" aria-hidden="true"', page)
        self.assertIn('id="elephant" aria-hidden="true" hidden', page)
        self.assertIn("data:image/svg+xml", page)
        # No art in agent-facing surfaces: the JSON endpoints stay lean.
        _, _, status = self.get("/api/status")
        self.assertNotIn("Y88888P", status)

    def test_drawer_tiles_open_the_project_timeline(self):
        page = self.page()
        self.assertIn('id="tiles"', page)
        self.assertIn("openDrawer", page)
        self.assertIn("ask-repo", page,
                      "a tile drives the timeline's repo filter")

    def test_timeline_stories_carry_walkable_paths(self):
        # Tile -> timeline -> entries: a story names its chains by path
        # so the walker can open them (the last rung of the ladder).
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()
        story = self.recall()["sessions"][0]
        self.assertEqual(story["paths"],
                         ["alpha/receipts/receipts-sess-aaaa.jsonl"])
        _, _, page = self.get("/")
        self.assertIn("walk this session", page)

    def test_scan_report_carries_its_own_timestamp(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()
        _, _, body = self.get("/api/status")
        report = json.loads(body)
        self.assertRegex(report["scanned"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class FortnightTest(ServerFixture):
    """The third question a monitoring surface owes its operator: is
    this a trend or a one-off? Fourteen days sit under the strip, one
    cell per day, and a day nobody watched reads as a gap in the
    memory — never as a quiet day."""

    def test_the_fortnight_sits_under_the_strip_above_recall(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        _, _, page = self.get("/")

        self.assertIn('id="fortnight"', page)
        self.assertLess(page.index('id="strip"'), page.index('id="fortnight"'),
                        "the alarm still leads; the trend explains it")
        self.assertLess(page.index('id="fortnight"'),
                        page.index('id="worktable"'),
                        "context for the alarm precedes the memory view")
        self.assertIn("trend or a one-off", page,
                      "the band says which question it answers")

    def test_the_status_endpoint_carries_the_fourteen_days(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        _, _, body = self.get("/api/status")

        history = json.loads(body)["history"]
        self.assertEqual(len(history), 14)
        self.assertTrue(history[-1]["watched"], "today is being watched")
        self.assertEqual(history[-1]["worst"], 0)

    def test_the_page_remembers_that_it_was_opened(self):
        # Detection latency is a function of how often the operator
        # looks, so the surface counts its own looks: a run of unwatched
        # days is the one failure the chain cannot report.
        self.serve()
        self.get("/")
        self.get("/")

        _, _, body = self.get("/api/status")

        today = json.loads(body)["history"][-1]
        self.assertGreaterEqual(today["looks"], 2,
                                "each opening of the page is a look")

    def test_the_verdict_palette_survives_colour_vision_deficiency(self):
        self.serve()

        _, _, page = self.get("/")

        # Roughly 8% of men cannot separate red from green: the three
        # states must part by more than hue.
        self.assertIn("--quiet:", page)
        self.assertIn("--damage:", page)
        self.assertIn("--grave:", page)
        self.assertNotIn("#1d7a3e", page,
                         "the stoplight green is gone from the surface")
        # Colour is never the only encoding — every state is named in
        # text and marked with a shape.
        for shape in ("●", "▲", "✕"):
            self.assertIn(shape, page)
        self.assertIn('id="statemark"', page)


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
        served, printed = json.loads(body), json.loads(cli.stdout)
        # Two ticks, two clocks: the freshness stamp is the one field
        # allowed to differ between them.
        served.pop("scanned"), printed.pop("scanned")
        self.assertEqual(served, printed)

    def test_front_page_is_inline_html_with_no_outside_dependencies(self):
        self.serve()

        status, ctype, page = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn("/api/status", page, "the band renders the scan")
        self.assertNotIn("<script src", page, "no framework, no CDN")
        # A <link> is allowed only when it fetches nothing: the favicon
        # rides inline as a data URI (ADR-0013's identity, zero assets).
        for tag in re.findall(r"<link[^>]*>", page):
            self.assertIn('href="data:', tag,
                          "nothing fetched from off-machine")
        self.assertNotIn("http://", page.split("<script>")[0].replace(
            "http://www.w3.org/2000/svg", ""), "no external references")

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
        self.assertIn("verify", page, "verdicts come from loxodonta verify")
        # The band renders only what the scan can say: the tick never
        # passes --files (.out-of-scope/002), so a FILES-DIVERGED tier
        # would be dead display code wearing a claim nothing can earn.
        self.assertNotIn("FILES-DIVERGED", page)

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


class OffMachineTest(ServerFixture):
    """Nothing is ever offered off-machine — including to a browser
    that was lied to by DNS. A page at attacker.example whose name
    rebinds to 127.0.0.1 reads as same-origin to the browser, so CORS
    never protects; the Host header is the only witness left (walk
    finding, 2026-08-31). And no cross-origin page may poke the drill."""

    def test_a_rebound_host_header_is_refused(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        request = urllib.request.Request(
            self.url + "/api/status",
            headers={"Host": "attacker.example"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            OPENER.open(request, timeout=30)

        self.assertEqual(caught.exception.code, 403)

    def test_a_foreign_origin_post_is_refused(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                   entries=3)
        self.serve()

        request = urllib.request.Request(
            self.url + "/api/drill?log="
            + urllib.parse.quote("alpha/receipts/receipts-sess-aaaa.jsonl"),
            method="POST", headers={"Origin": "https://attacker.example"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            OPENER.open(request, timeout=60)

        self.assertEqual(caught.exception.code, 403)

    def test_the_machine_itself_is_still_answered(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa",
                   entries=3)
        self.serve()

        status, _, _ = self.get("/api/status")
        self.assertEqual(status, 200)
        # The page's own drill POST carries a localhost Origin.
        request = urllib.request.Request(
            self.url + "/api/drill?log="
            + urllib.parse.quote("alpha/receipts/receipts-sess-aaaa.jsonl"),
            method="POST", headers={"Origin": self.url})
        with OPENER.open(request, timeout=60) as response:
            self.assertEqual(response.status, 200)


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
        # The memory view (the sessions pane) leads the worktable;
        # evidence — tripwire, watch, anchors — sits behind its own tab.
        self.assertLess(page.index('id="pane-sessions"'),
                        page.index('id="pane-evidence"'),
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


class ActivityTest(ServerFixture):
    """The shape behind the working-hours heat map and the per-drawer
    sparklines: receipts counted into UTC hour buckets, per repo.

    Buckets stay in UTC and stay hourly because the question the heat
    map answers ("when do I actually work?") is a local-time question,
    and only the browser knows the operator's zone. Aggregating to days
    here would bake a UTC midnight into an answer about their evenings.
    """

    def test_activity_counts_receipts_into_utc_hour_buckets(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=3)
        self.serve()

        _, _, body = self.get("/api/activity")

        report = json.loads(body)
        self.assertIn("alpha", report["activity"])
        buckets = report["activity"]["alpha"]
        self.assertEqual(sum(buckets.values()), 3,
                         "the genesis is administrative, never activity")
        for key in buckets:
            self.assertRegex(key, r"^\d{4}-\d{2}-\d{2}T\d{2}$")

    def test_activity_separates_the_drawers(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa", entries=2)
        make_chain(self.root / "beta" / "receipts", "sess-bbbb", entries=5)
        self.serve()

        report = json.loads(self.get("/api/activity")[2])

        self.assertEqual(sum(report["activity"]["alpha"].values()), 2)
        self.assertEqual(sum(report["activity"]["beta"].values()), 5)

    def test_activity_owns_no_verdicts(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()

        report = json.loads(self.get("/api/activity")[2])

        self.assertIn("testimony", report)
        blob = json.dumps(report)
        for verdict in ("VALID", "BROKEN", "ANCHORED"):
            self.assertNotIn(verdict, blob,
                             "activity counts what was attempted, "
                             "never what verify decided")


class PageScriptTest(ServerFixture):
    """The page's script has to parse, and nothing else here proves it.

    Every string assertion in this file passed while the whole script
    was a syntax error and the page rendered "remembering…" forever —
    the payload is inline in a non-raw Python string, so one unescaped
    backslash silently becomes a real newline inside a JS literal. This
    catches that class of fault. Opportunistic: node is not a
    dependency of this repo and the test skips where it is absent."""

    def test_the_inline_script_parses(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("no node on this machine to parse-check with")
        self.serve()
        page = self.get("/")[2]

        script = page.split("<script>")[1].split("</script>")[0]
        probe = Path(self._tmp.name) / "page.js"
        probe.write_text(script, encoding="utf-8")
        result = subprocess.run([node, "--check", str(probe)],
                                capture_output=True, encoding="utf-8")

        self.assertEqual(result.returncode, 0,
                         "the inline script does not parse:\n"
                         + result.stderr)


class ChartTest(ServerFixture):
    """The chart vocabulary borrowed from the scenarios: a session Gantt
    on a shared time axis, a working-hours heat map, and a sparkline in
    each drawer tile."""

    def page(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        self.serve()
        return self.get("/")[2]

    def test_the_gantt_gives_each_session_a_bar_on_a_shared_axis(self):
        page = self.page()

        self.assertIn('id="gantt"', page)
        self.assertIn("renderGantt", page)
        # Ch. 18's move: the label rides the bar, so a session's name is
        # already where the eye lands.
        self.assertIn("bar-label", page)

    def test_the_heat_map_reads_in_the_operators_own_timezone(self):
        page = self.page()

        self.assertIn('id="clock"', page)
        self.assertIn("getDay", page)
        self.assertIn("getHours", page,
                      "local hours, not UTC — the question is about "
                      "the operator's evenings")

    def test_the_heat_map_never_borrows_the_alarm_palette(self):
        page = self.page()

        self.assertIn("--busy:", page,
                      "a sequential ramp of its own; counting receipts "
                      "is not alerting about them")

    def test_drawer_tiles_carry_a_sparkline(self):
        page = self.page()

        self.assertIn("renderSpark", page)
        self.assertIn("spark", page)


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



class ScanBatchingTest(ServerFixture):
    """ADR-0005: one verify per chain per tick, never per HTTP request —
    and never two scans racing each other over the baseline file."""

    def test_rapid_status_requests_answer_from_one_scan(self):
        make_chain(self.root / "alpha" / "receipts", "sess-aaaa")
        # a generous TTL so this test's two looks land inside one tick
        self.serve(extra_env={"SUPERVISOR_SCAN_TTL_SECONDS": "300"})
        _, _, first = self.get("/api/status")
        # a chain born between rapid looks is invisible until the next
        # tick: the second answer comes from the same scan, not a new one
        make_chain(self.root / "beta" / "receipts", "sess-bbbb")
        _, _, second = self.get("/api/status")
        self.assertEqual(first, second)
