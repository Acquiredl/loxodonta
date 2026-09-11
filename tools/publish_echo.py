#!/usr/bin/env python3
"""publish_echo.py: see what `--publish-head` sends, before you wire it.

`install-hook --publish-head URL` posts one small JSON body at every
session end, and the docs say what is in it: `head`, `n`, `session`,
`ts`, `event`, and one readable line under both `text` and `content`;
never a path, a project name, an action line, or chain bytes. This
script is how an operator reads that for themselves instead of taking
the sentence on trust. It listens on the loopback address, prints every
POST body it takes with the field names beside it, and answers 200.

    python tools/publish_echo.py                  # port 8787
    python tools/publish_echo.py --port 0         # any free port, printed
    python tools/publish_echo.py --once           # take one POST, then stop

Point a session end at it for one run:

    loxodonta install-hook --publish-head http://127.0.0.1:8787/head

or send a chain's current head by hand, with no hook involved:

    loxodonta publish --log LOG http://127.0.0.1:8787/head

**This is not a head record, and it is not somewhere to publish to.**
A head record has to sit off the machine, beyond every credential a
process running as you could use (GLOSSARY *Head record*, ADR-0025).
An address on this machine fails both halves of that, so a head sent
here has not left, and nothing here would survive the writer. Read what
the body holds, then wire the hook at a real remote: a chat incoming
webhook, or an object store under a put-only credential with a
retention lock. Stdlib only, like everything here.
"""

import argparse
import datetime
import http.server
import json
import sys

DEFAULT_PORT = 8787


class Echo(http.server.BaseHTTPRequestHandler):
    """One handler, one job: show the operator the body, answer 200.

    Nothing is stored and nothing is judged. A body that is not JSON is
    printed raw rather than swallowed, because the interesting case for
    a reader is the one the docs did not describe.
    """

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        seen = datetime.datetime.now(datetime.timezone.utc)
        print("\n=== %s  POST %s  (%d bytes) ==="
              % (seen.strftime("%Y-%m-%dT%H:%M:%SZ"), self.path, length))
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            print("not JSON:", repr(raw))
        else:
            print(json.dumps(body, indent=2, sort_keys=True))
            if isinstance(body, dict):
                # The line that answers the question this tool exists for:
                # every field that left, named, with nothing folded away.
                print("fields: %s" % ", ".join(sorted(body)))
        sys.stdout.flush()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
        if self.server.stop_after_one:
            self.server.keep_serving = False

    def log_message(self, fmt, *args):
        return          # the body above is the point, not an access line


class EchoServer(http.server.HTTPServer):
    """An HTTPServer that can be asked to stop after one POST, so a test
    (or an operator checking one session end) needs no second window."""

    def __init__(self, address, handler, stop_after_one=False):
        super().__init__(address, handler)
        self.stop_after_one = stop_after_one
        self.keep_serving = True


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="publish_echo",
        description="print what `--publish-head` posts, on this machine only")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="port to listen on; 0 picks a free one "
                             f"(default: {DEFAULT_PORT})")
    parser.add_argument("--once", action="store_true",
                        help="stop after the first POST instead of staying up")
    args = parser.parse_args(argv)

    server = EchoServer(("127.0.0.1", args.port), Echo,
                        stop_after_one=args.once)
    port = server.server_address[1]
    print("publish echo listening on http://127.0.0.1:%d/  (ctrl-c to stop)"
          % port)
    print("this address is on your machine, so it is not a head record; "
          "wire the hook at a real remote once you have read a body")
    sys.stdout.flush()
    try:
        while server.keep_serving:
            server.handle_request()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
