#!/usr/bin/env python3
"""receiver.py — the far end of the published chain (ADR-0031).

The third single file. The recorder sends a chain's entries and its
head off the machine that wrote them (GLOSSARY: Published chain,
Published head); this is the machine they go to. It mints one URL,
appends whatever arrives at that URL to its own disk, and refuses
everything else: no read, no list, no delete. That is what makes the
URL pass the head-record test (GLOSSARY: Head record): a credential
that can add and cannot take away, so a wiped machine no longer takes
the evidence with it, as of the last send.

  python receiver.py serve                       # ~/.loxodonta/receiver, all interfaces, port 8790
  python receiver.py serve --data DIR --port N   # elsewhere, another port
  python receiver.py serve --bind 127.0.0.1      # this address only
  python receiver.py serve --cert C --key K      # TLS from your own pair
  python receiver.py serve --new-token           # rotate the URL; the old one answers 404
  python receiver.py --version                   # tool, format, and commit

What it keeps, in its data directory: `token`, the secret half of the
URL; `heads.jsonl`, one line per published head; and one
`receipts-<session>.jsonl` per chain, named by the sender and holding
chain bytes from genesis on, so `loxodonta verify --log` judges it as
it is. The operator on this box reads those files with the recorder;
nothing here serves them back over the wire. The wire contract, header
names included, is docs/RECEIVER.md. Stdlib only, like everything here.
"""

import argparse
import hmac
import json
import os
import re
import secrets
import socket
import socketserver
import subprocess
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

# Two versions, moving independently (ADR-0022): TOOL_VERSION says which
# receiver is running and is tagged together with loxodonta.py and
# supervisor.py — the three constants must agree (the suite says so).
# FORMAT_VERSION is the frozen receipt format of the chain files it
# keeps (SPEC §2.1).
TOOL_VERSION = "0.7.0"
FORMAT_VERSION = "0.1"

DEFAULT_PORT = 8790
TOKEN_FILE = "token"
HEADS_FILE = "heads.jsonl"

# The wire contract (docs/RECEIVER.md). One POST is either a published
# head, one JSON object, or a batch of a published chain, newline-
# delimited entries exactly as they sit in the chain file; the content
# type says which. A chain batch names its file in one header.
HEAD_TYPE = "application/json"
CHAIN_TYPE = "application/x-ndjson"
CHAIN_HEADER = "X-Loxodonta-Chain"

# The only file names a header can reach: the recorder's own chain
# names, `receipts-<session>.jsonl` and the sibling
# `receipts-<session>-002.jsonl` (GLOSSARY: sibling chain). A session id
# is letters, digits, hyphens and underscores, and the sibling suffix is
# made of the same, so one class covers both; the length keeps the name
# inside what every filesystem takes. Nothing else in a header ever
# becomes a path: no separator, no dot, no other extension.
CHAIN_NAME = re.compile(r"^receipts-[A-Za-z0-9_-]{1,200}\.jsonl$")

# The most one POST may carry. A session's chain runs to a few hundred
# bytes per entry, so this holds many thousands of entries in one batch;
# a body declared larger is refused before a byte of it is read.
BODY_CAP = 8 * 1024 * 1024


# --- The data directory and the token ------------------------------------------

def data_home():
    """Where the receiver keeps its files when `--data` is not given:
    the store home's `receiver` folder, the same home the recorder uses
    (`~/.loxodonta`, or wherever LOXODONTA_HOME points)."""
    home = (os.environ.get("LOXODONTA_HOME")
            or os.path.join(os.path.expanduser("~"), ".loxodonta"))
    return os.path.join(home, "receiver")


def token_path(data):
    return os.path.join(data, TOKEN_FILE)


def mint_token(data):
    """A fresh token, written to the data directory readable by this
    user alone where the filesystem has the notion, and returned."""
    token = secrets.token_urlsafe(32)
    fd = os.open(token_path(data), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(token + "\n")
    return token


def current_token(data, rotate=False):
    """The token on disk, or a new one when there is none yet, when the
    stored one is not the shape this file writes, or when the operator
    asked to rotate. Rotation is how a leaked URL is retired: the old
    path answers 404 from the next start on."""
    if not rotate:
        try:
            with open(token_path(data), encoding="utf-8") as f:
                stored = f.read().strip()
        except OSError:
            stored = ""
        if stored and all(c.isalnum() or c in "-_" for c in stored):
            return stored
    return mint_token(data)


# --- Appending, durably --------------------------------------------------------

def append_durably(path, lines):
    """Append each line, then flush and fsync before returning: the 2xx
    that follows means the bytes are on the disk, not in a buffer a
    power cut would lose."""
    with open(path, "ab") as f:
        for line in lines:
            f.write(line + b"\n")
        f.flush()
        os.fsync(f.fileno())


def head_line(body):
    """The one line a published head becomes: the JSON object that was
    posted, compact and key-sorted so the heads file reads one head per
    line whatever whitespace the sender used. None when the body is not
    one JSON object."""
    try:
        head = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(head, dict):
        return None
    return json.dumps(head, sort_keys=True, separators=(",", ":")).encode("utf-8")


def chain_lines(body):
    """A chain batch as the lines it holds, each without its newline (a
    carriage return before it is dropped too, so a proxy that rewrote
    the line endings changes nothing on disk). The sender's trailing
    newline is not an empty last line."""
    lines = body.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return [line[:-1] if line.endswith(b"\r") else line for line in lines]


# --- The server ----------------------------------------------------------------

class Receiver(HTTPServer):
    """One request at a time: every append ends in an fsync, and a single
    thread means two batches for the same chain can never interleave."""

    def server_bind(self):
        # The stdlib's server_bind looks up the bound host's fully
        # qualified name, a reverse DNS query nothing here ever reads
        # and a long stall on some machines. Bind, name it ourselves.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Door(BaseHTTPRequestHandler):
    """The one door: POST at the token's path. Everything else is turned
    away with a status and one short line, and the request path is
    never written anywhere, because the path is the credential."""

    timeout = 30  # a sender that stalls mid-body is dropped, not waited on

    def at_the_token(self):
        path = urlsplit(self.path).path
        return hmac.compare_digest(path, "/" + self.server.token)

    def refuse_method(self):
        """Every verb but POST: 405 at the token's path, so an operator
        with the right URL learns it is the verb that is wrong, and 404
        anywhere else. There is no verb that reads, lists or deletes."""
        if self.at_the_token():
            self.answer(405, "the receiver takes POST only", allow="POST")
        else:
            self.answer(404, "not the receiver's path")

    do_GET = do_HEAD = do_PUT = do_DELETE = refuse_method
    do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = refuse_method

    def declared_length(self):
        """The body length the sender declared, judged before any of it
        is read: None with the refusal already sent when it is missing,
        malformed, or past the cap."""
        declared = self.headers.get("Content-Length")
        if declared is None:
            self.answer(411, "Content-Length is required")
            return None
        try:
            length = int(declared)
        except ValueError:
            length = -1
        if length < 0:
            self.answer(400, "Content-Length is not a length")
            return None
        if length > BODY_CAP:
            self.answer(413, f"the body cap is {BODY_CAP} bytes")
            return None
        return length

    def content_type(self):
        return (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    def do_POST(self):
        if not self.at_the_token():
            self.answer(404, "not the receiver's path")
            return
        kind = self.content_type()
        if kind not in (HEAD_TYPE, CHAIN_TYPE):
            self.answer(415, f"a head is {HEAD_TYPE}, a chain batch is "
                             f"{CHAIN_TYPE}")
            return
        # The chain's name is judged before the body is read: a batch
        # for a file this receiver would not write is not worth reading.
        name = self.headers.get(CHAIN_HEADER) if kind == CHAIN_TYPE else None
        if kind == CHAIN_TYPE and not CHAIN_NAME.match(name or ""):
            self.answer(400, f"{CHAIN_HEADER} must be a receipt file name, "
                             "receipts-<session>.jsonl")
            return
        length = self.declared_length()
        if length is None:
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.answer(400, "the body ended before its declared length")
            return
        if kind == HEAD_TYPE:
            line = head_line(body)
            if line is None:
                self.answer(400, "a head is one JSON object")
                return
            append_durably(os.path.join(self.server.data, HEADS_FILE), [line])
            self.answer(200, json.dumps({"appended": 1}))
            return
        lines = chain_lines(body)
        append_durably(os.path.join(self.server.data, name), lines)
        self.answer(200, json.dumps({"appended": len(lines), "dropped": 0}))

    def answer(self, status, text, allow=None):
        body = (text + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"{stamp} {self.client_address[0]} {self.command} {status} "
              f"{text}", flush=True)

    def log_request(self, *_):
        pass  # `answer` prints the line, without the path

    def log_message(self, *_):
        pass


def cmd_serve(args):
    data = os.path.abspath(args.data or data_home())
    os.makedirs(data, exist_ok=True)
    token = current_token(data, rotate=args.new_token)
    try:
        server = Receiver((args.bind, args.port), Door)
    except OSError as e:
        print(f"error: cannot listen on {args.bind}:{args.port}: "
              f"{e.strerror or e}", file=sys.stderr)
        return 1
    server.data = data
    server.token = token
    port = server.server_address[1]
    everywhere = args.bind in ("", "0.0.0.0", "::")
    host = socket.gethostname() if everywhere else args.bind
    print(f"receiver {TOOL_VERSION} keeping {data}")
    print(f"listening on {args.bind}:{port} "
          f"({'all interfaces' if everywhere else 'this address only'}), "
          "speaking plain HTTP (give --cert and --key for TLS)")
    print(f"publish to http://{host}:{port}/{token}")
    if everywhere:
        print(f"  ({host} is this machine's name; use the address the "
              "sending machine reaches this one by)")
    print("the URL is the credential: it can add and cannot read, list or "
          "delete; --new-token retires it", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


# --- The command line ----------------------------------------------------------

def checkout_commit(home):
    """The short commit of the checkout `home` sits in, or "unknown" —
    the recorder's own version fact (ADR-0015, ADR-0022). Local git
    only: a version is a label on the file, never a channel to fetch a
    newer one."""
    try:
        asked = subprocess.run(
            ["git", "-C", home, "rev-parse", "--short", "HEAD"],
            capture_output=True, encoding="utf-8")
    except (OSError, ValueError):
        return "unknown"
    return asked.stdout.strip() if asked.returncode == 0 else "unknown"


class VersionAction(argparse.Action):
    """`--version`, answered only when asked: tool, format, commit."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        home = os.path.dirname(os.path.abspath(__file__))
        print(f"{parser.prog} {TOOL_VERSION} (format {FORMAT_VERSION}, "
              f"commit {checkout_commit(home)})")
        parser.exit()


EX_USAGE = 64  # sysexits(3) EX_USAGE: the command was spoken wrong


class UsageParser(argparse.ArgumentParser):
    """argparse, with usage errors on an exit of their own, as the other
    two files have it: a wrong flag exits 64, never a number a script
    could mistake for something the receiver said."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, f"{self.prog}: error: {message}\n")


def main(argv):
    parser = UsageParser(prog="receiver",
                         description=__doc__.splitlines()[0])
    parser.add_argument("--version", action=VersionAction,
                        help="print tool version, format version, and "
                             "the checkout's commit, then exit")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="listen for published chains "
                                         "and heads, and keep them")
    serve.add_argument("--data", metavar="DIR",
                       help="where the token and the files live "
                            "(default: ~/.loxodonta/receiver)")
    serve.add_argument("--bind", default="0.0.0.0", metavar="ADDRESS",
                       help="the address to listen on (default: all "
                            "interfaces, since the sender is another "
                            "machine); 127.0.0.1 narrows it to this one")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT,
                       help=f"the port to listen on (default: {DEFAULT_PORT}; "
                            "0 picks a free one and prints it)")
    serve.add_argument("--new-token", action="store_true",
                       help="mint a new token; the old URL answers 404 "
                            "from now on")
    serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
