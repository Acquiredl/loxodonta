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
import ssl
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

# The shape of a token this file mints (secrets.token_urlsafe), so a
# hand-edited token file that would not make a clean URL is replaced.
TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]+$")


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
        if TOKEN_SHAPE.match(stored):
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


def receipt_of(line):
    """(n, entry_hash) when the line is shaped like an entry: one JSON
    object carrying an integer n and a string entry_hash, the two fields
    the append rule reads. None otherwise; the receiver judges nothing
    else about a line, since judging is `loxodonta verify`'s job."""
    try:
        entry = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(entry, dict):
        return None
    n, digest = entry.get("n"), entry.get("entry_hash")
    if isinstance(n, bool) or not isinstance(n, int) or not isinstance(digest, str):
        return None
    return n, digest


def chain_lines(body):
    """A chain batch as [(line, n, entry_hash)], each line without its
    newline (a carriage return before it is dropped too, so a proxy that
    rewrote the line endings changes nothing on disk). The sender's
    trailing newline is not an empty last line. A batch with no lines,
    or with any line that is not shaped like an entry, raises ValueError
    naming the line: the whole batch is refused, nothing of it written,
    because a file that is a receipt log must hold entries and nothing
    else."""
    lines = body.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        raise ValueError("the batch holds no lines")
    batch = []
    for number, line in enumerate(lines, 1):
        if line.endswith(b"\r"):
            line = line[:-1]
        receipt = receipt_of(line)
        if receipt is None:
            raise ValueError(f"line {number} is not an entry (a JSON object "
                             "with an integer n and an entry_hash)")
        batch.append((line, *receipt))
    return batch


def known_pairs(path):
    """Every (n, entry_hash) the chain file already holds, so a resent
    line is known and a rewritten one is not. A file that is not there
    yet knows nothing."""
    known = set()
    try:
        with open(path, "rb") as f:
            for line in f:
                receipt = receipt_of(line)
                if receipt is not None:
                    known.add(receipt)
    except FileNotFoundError:
        pass
    return known


def new_lines(batch, known):
    """The append rule that keeps the file a receipt log (ADR-0031
    ruling 4). A line whose n and entry_hash the file already holds is
    an exact duplicate, the sender's retry after a lost acknowledgement,
    and is dropped. A line whose n the file holds with a different hash
    is a regenerated chain arriving after the original, and is appended:
    that collision is what the copy exists to show, and verify reports
    it. Everything else is appended in the order received."""
    keep = []
    for line, n, digest in batch:
        if (n, digest) in known:
            continue
        known.add((n, digest))  # the same line twice in one batch lands once
        keep.append(line)
    return keep


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

    def handle_error(self, request, client_address):
        # A sender that stalled past the timeout, or spoke plain HTTP to
        # a TLS door: one line, never the stdlib's traceback.
        print(f"{client_address[0]} dropped: {sys.exc_info()[1]}", flush=True)


class Door(BaseHTTPRequestHandler):
    """The one door: POST at the token's path. Everything else is turned
    away with a status and one short line, and the request path is
    never written anywhere, because the path is the credential."""

    timeout = 30  # a sender that stalls mid-body is dropped, not waited on

    def at_the_token(self):
        # A token is ASCII, so a path that is not is never the token's;
        # asked first, because compare_digest refuses non-ASCII text.
        path = urlsplit(self.path).path
        return path.isascii() and hmac.compare_digest(path, "/" + self.server.token)

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
        name = None
        if kind == CHAIN_TYPE:
            name = self.headers.get(CHAIN_HEADER) or ""
            if not CHAIN_NAME.match(name):
                self.answer(400, f"{CHAIN_HEADER} must be a receipt file "
                                 "name, receipts-<session>.jsonl")
                return
        length = self.declared_length()
        if length is None:
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.answer(400, "the body ended before its declared length")
            return
        if kind == HEAD_TYPE:
            self.keep_head(body)
        else:
            self.keep_batch(body, name)

    def keep_head(self, body):
        line = head_line(body)
        if line is None:
            self.answer(400, "a head is one JSON object")
            return
        path = os.path.join(self.server.data, HEADS_FILE)
        if self.kept(path, [line]):
            self.answer(200, json.dumps({"appended": 1}))

    def keep_batch(self, body, name):
        try:
            batch = chain_lines(body)
        except ValueError as why:
            self.answer(400, str(why))
            return
        path = os.path.join(self.server.data, name)
        lines = new_lines(batch, known_pairs(path))
        if self.kept(path, lines):
            self.answer(200, json.dumps({"appended": len(lines),
                                         "dropped": len(batch) - len(lines)}))

    def kept(self, path, lines):
        """True once the lines are on disk (nothing to write counts). A
        disk that refuses is a 500 with the reason, so the sender's memo
        never advances over bytes that did not land."""
        if not lines:
            return True
        try:
            append_durably(path, lines)
        except OSError as e:
            self.answer(500, f"could not write: {e.strerror or e}")
            return False
        return True

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


def tls_context(cert, key):
    """The server side of TLS from the operator's own pair, through the
    stdlib alone. The receiver mints no certificate: a pair from a CA the
    sending machine trusts, or a self-signed one the operator installs
    there, is the operator's choice (docs/RECEIVER.md)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def cmd_serve(args):
    if bool(args.cert) != bool(args.key):
        print("receiver serve: error: --cert and --key go together",
              file=sys.stderr)
        return EX_USAGE
    data = os.path.abspath(args.data or data_home())
    try:
        os.makedirs(data, exist_ok=True)
        token = current_token(data, rotate=args.new_token)
    except OSError as e:
        print(f"error: cannot write to {data}: {e.strerror or e}",
              file=sys.stderr)
        return 1
    try:
        server = Receiver((args.bind, args.port), Door)
    except OSError as e:
        print(f"error: cannot listen on {args.bind}:{args.port}: "
              f"{e.strerror or e}", file=sys.stderr)
        return 1
    server.data = data
    server.token = token
    scheme = "http"
    if args.cert:
        try:
            server.socket = tls_context(args.cert, args.key).wrap_socket(
                server.socket, server_side=True)
        except (OSError, ssl.SSLError) as e:
            print(f"error: cannot serve TLS from {args.cert} and {args.key}: "
                  f"{e}", file=sys.stderr)
            server.server_close()
            return 1
        scheme = "https"
    port = server.server_address[1]
    everywhere = args.bind in ("", "0.0.0.0")
    host = socket.gethostname() if everywhere else args.bind
    print(f"receiver {TOOL_VERSION} keeping {data}")
    print(f"listening on {args.bind}:{port} "
          f"({'all interfaces' if everywhere else 'this address only'}), "
          + (f"speaking TLS from {args.cert}" if args.cert else
             "speaking plain HTTP (give --cert and --key for TLS)"))
    print(f"publish to {scheme}://{host}:{port}/{token}")
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
    serve.add_argument("--cert", metavar="FILE",
                       help="a PEM certificate (with --key): speak TLS")
    serve.add_argument("--key", metavar="FILE",
                       help="the certificate's PEM private key (with --cert)")
    serve.add_argument("--new-token", action="store_true",
                       help="mint a new token; the old URL answers 404 "
                            "from now on")
    serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
