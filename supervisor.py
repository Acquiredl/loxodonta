#!/usr/bin/env python3
"""supervisor.py — the operator that never sleeps (ADR-0005).

A reader-side companion to receipts.py: it watches every receipt log
under a root full of repos and shouts on change — a tripwire with a
memory, never a wall. It drives receipts exclusively through the public
CLI and judges nothing itself: verdicts come from `receipts verify`,
and everything the supervisor holds is writer-reachable, so nothing
here is a head record (GLOSSARY: Supervisor, Baseline).

  python supervisor.py scan --root DIR --json
  python supervisor.py serve --root DIR

`scan` is one tick without timers: a census of every chain under the
root, a verdict for each, machine-readable JSON on stdout, and an exit
code cron can shout about — 0 when nothing demands attention, else the
worst verify exit found.

`serve` is the face: a localhost-only stdlib HTTP server whose status
endpoint answers each request with a fresh scan, and whose front page —
one inline HTML file, no framework, no build step — renders the status
band: every chain on the machine, its verdict drawn by tier. Nothing is
ever offered off-machine.
"""

import argparse
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECEIPTS = HERE / "receipts.py"


# --- Census -------------------------------------------------------------------

def find_chains(root):
    """Every receipt log under the root. Three shapes, because history has
    three shapes: the root itself being a repo, each sibling repo's
    receipts/, and chains stranded in worktrees by sessions that ran
    before the hook learned to log to the main repo. Anchor sidecars are
    proofs about a chain, not chains."""
    patterns = ("receipts/*.jsonl",
                "*/receipts/*.jsonl",
                "*/.claude/worktrees/*/receipts/*.jsonl")
    return sorted(p for pattern in patterns for p in root.glob(pattern)
                  if not p.name.endswith(".anchors.jsonl"))


def split_seq(stem):
    """(base, seq) — a trailing three-digit sibling suffix split off.

    A sibling chain (`-002`, `-003`) is continuation by naming alone
    (ADR-0004): it belongs to whatever the name says before the suffix,
    in suffix order. An unsuffixed name is seq 1."""
    prefix, dash, tail = stem.rpartition("-")
    if dash and len(tail) == 3 and tail.isdigit():
        return prefix, int(tail)
    return stem, 1


def chain_identity(root, log):
    """(repo, session, seq) — which repo a chain belongs to, which session
    wrote it, and where it sits in the session's run of sibling chains,
    all read from where the log lies and what it is named."""
    parts = log.relative_to(root).parts
    repo = root.name if parts[0] == "receipts" else parts[0]
    session = log.stem
    if session.startswith("receipts-"):
        session = session[len("receipts-"):]
    session, seq = split_seq(session)
    return repo, session, seq


# --- Verdict runner -----------------------------------------------------------

def verify(log):
    """The single seam to receipts (ADR-0005): one subprocess per chain,
    verdict read from the exit code and the documented verdict lines.
    --anchors judges sidecar proofs offline too, because VALID and
    ANCHORED are different claims (ADR-0002) and an anchor contradicting
    the log is the gravest finding there is."""
    # Both ends of the pipe pinned to UTF-8: verdict lines land in the
    # frontend, and a shell's codepage must never garble evidence.
    result = subprocess.run(
        [sys.executable, str(RECEIPTS), "verify", "--anchors",
         "--log", str(log)],
        capture_output=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    lines = result.stdout.strip().splitlines()
    if lines:
        verdict = lines[-1].split(":")[0].split(" at ")[0]
    else:
        # verify refused without a verdict line (an empty or unopenable
        # log). Its own words on stderr are the evidence; the supervisor
        # invents no verdict of its own.
        verdict = "NO-VERDICT"
        lines = result.stderr.strip().splitlines()
    return verdict, result.returncode, lines


def sibling_of(log):
    """Where recording moved when this chain's tail tore (ADR-0004):
    receipts-<session>.jsonl continues in receipts-<session>-002.jsonl,
    and -002 continues in -003."""
    base, seq = split_seq(log.name[:-len(".jsonl")])
    return log.with_name(f"{base}-{seq + 1:03d}.jsonl")


def superseded(log, detail):
    """True when this chain's only damage is the honest crash pattern — a
    torn final line — and a sibling exists beside it: ADR-0004 already
    handled this tear, and recording continued. The tear stays in the
    report as evidence; only the exit code stands down, or the scan
    becomes an alarm that never stops sounding. Any other damage is
    tampering to shout about, sibling or not."""
    broken = [l for l in detail if l.startswith("BROKEN")]
    return (len(broken) == 1 and "torn tail" in broken[0]
            and sibling_of(log).exists())


# --- Scan ---------------------------------------------------------------------

def scan_root(root):
    """One tick without timers: census + verdicts as a report dict —
    what `scan` prints and what the status endpoint serves."""
    # Walk in display order — repo, then session, then sibling sequence —
    # so the grouping below is plain insertion, no re-sorting.
    census = sorted((chain_identity(root, log), log)
                    for log in find_chains(root))
    repos = {}
    worst = 0
    for (repo, session, _), log in census:
        verdict, exit_code, detail = verify(log)
        stood_down = exit_code != 0 and superseded(log, detail)
        chain = {
            "log": log.as_posix(),
            # Stranded in a worktree: still this repo's history, but pruning
            # the worktree deletes it — worth saying, not worth hiding.
            "worktree": ".claude" in log.relative_to(root).parts,
            "entries": sum(1 for _ in open(log, encoding="utf-8")),
            "verdict": verdict,
            "exit": exit_code,
            # VALID says the chain agrees with itself; ANCHORED says it
            # agrees with a Bitcoin block. Different claims, kept apart.
            "anchored": any(line.startswith("ANCHORED") for line in detail),
            "superseded": stood_down,
            "detail": detail,
        }
        repos.setdefault(repo, {}).setdefault(session, []).append(chain)
        if not stood_down:
            worst = max(worst, exit_code)

    return {
        "root": root.as_posix(),
        "exit": worst,
        "repos": [
            {"repo": repo,
             "sessions": [{"session": session, "chains": chains}
                          for session, chains in sessions.items()]}
            for repo, sessions in repos.items()
        ],
    }


def cmd_scan(args):
    report = scan_root(Path(args.root).resolve())
    print(json.dumps(report, indent=None if args.json else 2))
    return report["exit"]


# --- Serve --------------------------------------------------------------------
# The face. Serialization only, zero decisions (ADR-0005): every request
# answers from a fresh scan, and the page below renders what the scan
# said — verdicts still come from `receipts verify`, nowhere else.

class Face(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # the scan is the story; per-request chatter is noise

    def do_GET(self):
        if self.path == "/api/status":
            body = json.dumps(scan_root(self.server.root)).encode("utf-8")
            self.reply(body, "application/json")
        elif self.path == "/":
            self.reply(PAGE.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def reply(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def cmd_serve(args):
    root = Path(args.root).resolve()
    # 127.0.0.1 is the whole posture: nothing about this machine's
    # activity is ever offered to another one.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Face)
    server.root = root
    print(f"watching {root.as_posix()} on "
          f"http://127.0.0.1:{server.server_address[1]}/ "
          "(localhost only)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


# The status band, one inline page. Tier styling is the point: the exit-3
# tier ("this is not the recorded history") reads gravest and is never
# outranked by housekeeping; VALID and ANCHORED are visibly different
# claims; superseded tears stay on the page as quiet evidence while new
# damage shouts. Data goes into the DOM through textContent only.
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>supervisor — status band</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 64rem;
         margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  header h1 { margin-bottom: 0.2rem; }
  header .stance { color: color-mix(in srgb, currentColor 60%, transparent);
                   margin-top: 0; }
  #summary { padding: 0.6rem 1rem; border-radius: 0.5rem; margin: 1rem 0;
             font-weight: 600; border: 1px solid transparent; }
  #summary.quiet { background: #1d7a3e22; border-color: #1d7a3e; }
  #summary.shouting { background: #b3261e22; border-color: #b3261e; }
  h2 { border-bottom: 1px solid color-mix(in srgb, currentColor 25%, transparent);
       padding-bottom: 0.2rem; margin-top: 2rem; }
  .session { margin: 0.8rem 0 0.8rem 0.5rem; }
  .session > .name { font-family: monospace; opacity: 0.8; }
  .chain { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: baseline;
           padding: 0.5rem 0.8rem; margin: 0.4rem 0; border-radius: 0.5rem;
           border: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  .chain .file { font-family: monospace; font-size: 0.85rem; opacity: 0.75; }
  .chain .claim { flex-basis: 100%; margin: 0; font-size: 0.9rem;
                  opacity: 0.85; }
  .chain details { flex-basis: 100%; font-size: 0.85rem; }
  .chain pre { overflow-x: auto; opacity: 0.8; }
  .chip { font-family: monospace; font-weight: 700; font-size: 0.85rem;
          padding: 0.15rem 0.6rem; border-radius: 0.4rem;
          border: 2px solid transparent; }
  .badge { font-size: 0.75rem; padding: 0.1rem 0.5rem; border-radius: 0.4rem;
           background: color-mix(in srgb, currentColor 12%, transparent); }

  /* The tier ladder. Visual weight goes down as you read down — and the
     top rung belongs to "not the recorded history", always. */
  .tier-regenerated { border: 3px solid #7a0c0c;
                      background: #7a0c0c1a; }
  .tier-regenerated .chip { background: #7a0c0c; color: #fff; }
  .tier-broken { border-color: #b3261e; background: #b3261e14; }
  .tier-broken .chip { color: #b3261e; border-color: #b3261e; }
  .tier-refused .chip { color: #8a6d00; border-color: #8a6d00; }
  .tier-diverged .chip { color: #8a6d00; border-color: #8a6d0055; }
  .tier-anchored .chip { background: #1d7a3e; color: #fff; }
  .tier-valid .chip { color: #1d7a3e; border-color: #1d7a3e; }
  .tier-superseded { opacity: 0.55; }
  .tier-superseded .chip { color: inherit;
                           border-color: color-mix(in srgb, currentColor 40%, transparent); }
</style>
</head>
<body>
<header>
  <h1>supervisor</h1>
  <p class="stance">a tripwire with a memory — verdicts come from
  <code>receipts verify</code>; this page draws them and decides nothing</p>
</header>
<div id="summary">reading the scan…</div>
<main id="band"></main>
<script>
"use strict";

// Which rung of the ladder a chain stands on. Order matters: standing
// down (superseded) is checked first, then the gravest claim, downward.
function tier(chain) {
  if (chain.superseded) return "superseded";
  if (chain.exit === 3) return "regenerated";
  if (chain.verdict === "BROKEN") return "broken";
  if (chain.verdict === "FILES-DIVERGED") return "diverged";
  if (chain.verdict === "VALID") {
    return chain.anchored ? "anchored" : "valid";
  }
  return "refused";  // UNSUPPORTED-VERSION, NO-VERDICT
}

// What each rung is allowed to claim — VALID and ANCHORED deliberately
// say different things, because they are different things.
const CLAIM = {
  regenerated: "not the recorded history — an anchor or head record " +
               "contradicts this chain",
  broken: "chain integrity failed — history was altered after the fact",
  refused: "no verdict — a chain nobody can judge still demands attention",
  diverged: "chain intact, but files differ from their logged fingerprints",
  valid: "intact against itself — tamper-evident, not yet anchored",
  anchored: "intact and anchored — this history existed by the named " +
            "Bitcoin block",
  superseded: "torn tail, already handled — recording continued in a " +
              "sibling chain; kept as quiet evidence",
};

const CHIP = {
  regenerated: c => c.verdict, broken: () => "BROKEN",
  refused: c => c.verdict, diverged: () => "FILES-DIVERGED",
  valid: () => "VALID", anchored: () => "ANCHORED",
  superseded: () => "BROKEN · superseded",
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function chainRow(chain) {
  const rung = tier(chain);
  const row = el("div", "chain tier-" + rung);
  row.appendChild(el("span", "chip", CHIP[rung](chain)));
  const file = chain.log.split("/").pop();
  row.appendChild(el("span", "file",
                     file + " · " + chain.entries + " entries"));
  if (chain.worktree) {
    row.appendChild(el("span", "badge", "stranded in a worktree"));
  }
  const anchoredLine =
    chain.detail.find(line => line.startsWith("ANCHORED"));
  row.appendChild(el("p", "claim",
    rung === "anchored" && anchoredLine ? anchoredLine : CLAIM[rung]));
  if (chain.detail.length) {
    const details = el("details");
    details.appendChild(el("summary", "", "what verify said"));
    details.appendChild(el("pre", "", chain.detail.join("\\n")));
    row.appendChild(details);
  }
  return row;
}

function render(report) {
  const summary = document.getElementById("summary");
  const chains = report.repos.flatMap(r =>
    r.sessions.flatMap(s => s.chains));
  const quietEvidence = chains.filter(c => c.superseded).length;
  if (report.exit === 0) {
    summary.className = "quiet";
    summary.textContent = "all quiet — " + chains.length + " chain(s) " +
      "under " + report.root +
      (quietEvidence ? " (" + quietEvidence + " superseded tear(s) kept " +
                       "as evidence)" : "");
  } else {
    summary.className = "shouting";
    summary.textContent = "attention — something under " + report.root +
      " is not in good standing (worst verify exit: " + report.exit + ")";
  }

  const band = document.getElementById("band");
  band.replaceChildren();
  for (const repo of report.repos) {
    band.appendChild(el("h2", "", repo.repo));
    for (const session of repo.sessions) {
      const box = el("div", "session");
      box.appendChild(el("div", "name", "session " + session.session));
      for (const chain of session.chains) {
        box.appendChild(chainRow(chain));
      }
      band.appendChild(box);
    }
  }
  if (!report.repos.length) {
    band.appendChild(el("p", "", "no chains under this root yet — work " +
      "a session with the hook installed and receipts will appear here."));
  }
}

async function load() {
  try {
    const response = await fetch("/api/status");
    render(await response.json());
  } catch (error) {
    const summary = document.getElementById("summary");
    summary.className = "shouting";
    summary.textContent = "the scan did not answer: " + error;
  }
}

load();
setInterval(load, 30000);
</script>
</body>
</html>
"""


def main(argv):
    parser = argparse.ArgumentParser(prog="supervisor",
                                     description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="one tick: census + verdicts, JSON out, exit code")
    scan.add_argument("--root", required=True,
                      help="the folder your repos live in")
    scan.add_argument("--json", action="store_true",
                      help="compact machine output (default pretty-prints)")
    scan.set_defaults(func=cmd_scan)
    serve = sub.add_parser(
        "serve", help="the face: status band on a localhost-only server")
    serve.add_argument("--root", required=True,
                       help="the folder your repos live in")
    serve.add_argument("--port", type=int, default=7717,
                       help="localhost port (0 picks a free one; "
                            "default 7717)")
    serve.set_defaults(func=cmd_serve)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
