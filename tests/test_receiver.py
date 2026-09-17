"""Behavioral tests for the receiver (`receiver.py`, ADR-0031 rulings 4
and 5, issue #247): the far end of the published chain and the
published head, a URL that can only add, never delete.

Every test starts the receiver as a subprocess on a free port and talks
to it the way the world does: raw HTTP through urllib, or the recorder's
own `publish`. Nothing is imported from the tool and nothing is mocked.
The acceptance test is the recorder's: after honest batches the
receiver's chain file verifies VALID, and a regenerated chain's batch
lands beside the entries it replaced and verifies BROKEN there.
"""

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

# This folder on sys.path, so the sibling import below also resolves
# when the module runs alone (`python -m unittest tests.test_receiver`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_anchor import clean_env

REPO_ROOT = Path(__file__).resolve().parent.parent
RECEIVER = REPO_ROOT / "receiver.py"
LOXODONTA = REPO_ROOT / "loxodonta.py"

PUBLISH_TO = re.compile(r"^publish to (https?://\S+)$", re.M)

# Straight to 127.0.0.1, never through a proxy someone's shell configured.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port():
    """A port nothing is listening on right now, for the tests that need
    the same URL across two starts (a port the receiver picks itself
    would change with every start)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def post(url, body, content_type, headers=None):
    """One POST; (status, body) whatever the status was."""
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": content_type, **(headers or {})})
    try:
        with OPENER.open(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as refused:
        return refused.code, refused.read()


class ReceiverFixture(unittest.TestCase):
    """A private data directory and a real `receiver.py serve` on a free
    port, narrowed to 127.0.0.1 unless a test says otherwise."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.data = self.root / "receiver"

    def start(self, *extra, port=0, bind="127.0.0.1"):
        """Start the receiver and read what it printed up to the URL.
        Returns the process, with `.url` and `.said` set on it."""
        argv = [sys.executable, str(RECEIVER), "serve",
                "--data", str(self.data), "--port", str(port)]
        if bind:
            argv += ["--bind", bind]
        proc = subprocess.Popen(
            argv + list(extra), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, encoding="utf-8", env=clean_env())
        self.addCleanup(self.stop, proc)
        said = []
        while True:
            line = proc.stdout.readline()
            if not line:
                proc.kill()
                self.fail("the receiver printed no URL:\n%s%s"
                          % ("".join(said), proc.stderr.read()))
            said.append(line)
            found = PUBLISH_TO.search(line)
            if found:
                break
        proc.url = found.group(1)
        proc.said = "".join(said)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()

    def stored(self):
        """Every file the receiver keeps, by name."""
        return sorted(p.name for p in self.data.iterdir())


class UrlTest(ReceiverFixture):
    """The URL is the credential: minted once, reprinted on every start,
    rotated on request, and the old one then answers nothing."""

    def test_the_url_is_minted_once_reprinted_and_rotated(self):
        port = free_port()
        first = self.start(port=port)
        self.stop(first)
        self.assertIn("token", self.stored())

        again = self.start(port=port)
        self.assertEqual(again.url, first.url)
        self.stop(again)

        rotated = self.start("--new-token", port=port)
        self.assertNotEqual(rotated.url, first.url)

        head = json.dumps({"head": "a" * 64, "n": 1}).encode("utf-8")
        status, _ = post(first.url, head, "application/json")
        self.assertEqual(status, 404)
        status, _ = post(rotated.url, head, "application/json")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
