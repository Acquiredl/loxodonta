"""Behavioral tests for the recall-only MCP server (`supervisor mcp`,
ADR-0019).

The server is the recall surface (ADR-0009) spoken over the Model
Context Protocol's stdio binding, so an agent that cannot run our
SessionStart hook - Codex, an Agents SDK program, any MCP client - can
still read its own history. Five tools, one-to-one with the CLI:
digest, show, search, timeline, verify. No write path exists on this
surface, and these tests hold it to that: the tool list never names a
writer, and every chain is byte-identical after a full session.

The wire is exercised as a real client would: a subprocess, one JSON-RPC
message per line, both protocol eras (the 2025-11-25 `initialize`
handshake and the 2026-07-28 per-request `_meta` form).
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_recall import forge_chain, run_py

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR = REPO_ROOT / "supervisor.py"

LEGACY = "2025-11-25"
MODERN = "2026-07-28"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT = "io.modelcontextprotocol/clientInfo"
META_CAPS = "io.modelcontextprotocol/clientCapabilities"
META_SERVER = "io.modelcontextprotocol/serverInfo"


class McpClient:
    """A minimal stdio MCP client: writes one message per line, reads
    one response per request. Notifications get no reply."""

    def __init__(self, *args, env_extra=None, cwd=None):
        env = {**os.environ, "PYTHONIOENCODING": "utf-8",
               **(env_extra or {})}
        env.pop("CLAUDE_PROJECT_DIR", None)
        self.proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "mcp", *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd, env=env)
        self.next_id = 1

    def send(self, message):
        line = json.dumps(message) + "\n"
        self.proc.stdin.write(line.encode("utf-8"))
        self.proc.stdin.flush()

    def raw(self, text):
        self.proc.stdin.write((text + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        return self.read()

    def read(self):
        line = self.proc.stdout.readline()
        assert line, "server closed stdout without answering"
        return json.loads(line.decode("utf-8"))

    def request(self, method, params=None, meta=None):
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        self.next_id += 1
        if params is not None or meta is not None:
            params = dict(params or {})
            if meta is not None:
                params["_meta"] = meta
            message["params"] = params
        self.send(message)
        reply = self.read()
        assert reply.get("id") == message["id"], reply
        return reply

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)

    def initialize(self, version=LEGACY):
        reply = self.request("initialize", {
            "protocolVersion": version, "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}})
        self.notify("notifications/initialized")
        return reply

    def call(self, name, arguments=None, meta=None):
        return self.request("tools/call",
                            {"name": name, "arguments": arguments or {}},
                            meta=meta)

    def close(self):
        # communicate() closes stdin itself once it has nothing to write;
        # closing it first makes POSIX communicate() flush a closed file.
        try:
            out, err = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, err = self.proc.communicate()
            raise AssertionError("server did not exit on EOF")
        return self.proc.returncode, out.decode("utf-8"), err.decode("utf-8")


def modern_meta(version=MODERN):
    return {META_VERSION: version,
            META_CLIENT: {"name": "test", "version": "0"},
            META_CAPS: {}}


def text_of(reply):
    result = reply["result"]
    return "".join(c["text"] for c in result["content"]
                   if c.get("type") == "text")


def sha256_tree(folder):
    """One fingerprint over every chain file under a folder."""
    h = hashlib.sha256()
    for path in sorted(Path(folder).rglob("*.jsonl")):
        h.update(path.relative_to(folder).as_posix().encode("utf-8"))
        h.update(path.read_bytes())
    return h.hexdigest()


class McpBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = {"LOXODONTA_HOME": str(self.home)}
        self.repo = self.root / "alpha"
        self.repo.mkdir()
        self.log, self.hashes = forge_chain(
            self.repo, "aaaa1111-1111-1111-1111-111111111111", [
                ("2026-08-20T10:00:00Z", "Edit: one.py"),
                ("2026-08-20T10:05:00Z", "Bash: pytest -q"),
                ("2026-08-20T10:07:00Z", "Bash: git commit -m done"),
            ])
        self.clients = []

    def client(self, *args):
        c = McpClient(*args, "--repo", str(self.repo), env_extra=self.env)
        self.clients.append(c)
        return c

    def cli(self, *args):
        return run_py(SUPERVISOR, *args, "--repo", str(self.repo),
                      env_extra=self.env)

    def tearDown(self):
        for c in self.clients:
            if c.proc.poll() is None:
                c.proc.kill()
                c.proc.communicate()


class HandshakeTest(McpBase):
    def test_legacy_initialize_echoes_a_supported_version(self):
        c = self.client()
        reply = c.initialize(LEGACY)
        result = reply["result"]
        self.assertEqual(result["protocolVersion"], LEGACY)
        self.assertIn("tools", result["capabilities"])
        self.assertIn("loxodonta", result["serverInfo"]["name"])
        # The instructions tell the model what this surface is and is not.
        self.assertIn("testimony", result["instructions"].lower())
        self.assertIn("never writes", result["instructions"].lower())
        self.assertEqual(c.request("ping")["result"], {})
        code, out, err = c.close()
        self.assertEqual(code, 0, err)

    def test_legacy_initialize_with_an_unknown_version_offers_ours(self):
        c = self.client()
        reply = c.initialize("1900-01-01")
        self.assertEqual(reply["result"]["protocolVersion"], LEGACY)
        c.close()

    def test_modern_discover_names_versions_and_identity(self):
        c = self.client()
        reply = c.request("server/discover", meta=modern_meta())
        result = reply["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertIn(MODERN, result["supportedVersions"])
        self.assertIn("tools", result["capabilities"])
        self.assertIn("loxodonta", result["_meta"][META_SERVER]["name"])
        c.close()

    def test_modern_unsupported_version_is_error_32022_with_choices(self):
        c = self.client()
        reply = c.request("tools/list", meta=modern_meta("1900-01-01"))
        self.assertEqual(reply["error"]["code"], -32022)
        self.assertIn(MODERN, reply["error"]["data"]["supported"])
        self.assertEqual(reply["error"]["data"]["requested"], "1900-01-01")
        c.close()

    def test_modern_request_missing_required_meta_is_invalid_params(self):
        c = self.client()
        meta = modern_meta()
        del meta[META_CAPS]
        reply = c.request("tools/list", meta=meta)
        self.assertEqual(reply["error"]["code"], -32602)
        c.close()

    def test_wire_hygiene_and_error_codes(self):
        c = self.client()
        c.initialize()
        bad = c.raw("this is not json")
        self.assertEqual(bad["error"]["code"], -32700)
        self.assertIsNone(bad["id"])
        unknown = c.request("resources/list")
        self.assertEqual(unknown["error"]["code"], -32601)
        # A notification is swallowed, never answered: the next reply
        # belongs to the next request.
        c.notify("notifications/cancelled", {"requestId": 99})
        self.assertEqual(c.request("ping")["result"], {})
        code, out, err = c.close()
        self.assertEqual(code, 0, err)
        # Nothing but MCP messages ever reached stdout.
        for line in out.splitlines():
            json.loads(line)


class ToolListTest(McpBase):
    def test_five_recall_tools_and_no_writer(self):
        c = self.client()
        c.initialize()
        tools = c.request("tools/list")["result"]["tools"]
        names = [t["name"] for t in tools]
        self.assertEqual(names,
                         ["digest", "show", "search", "timeline", "verify"])
        for writer in ("log", "run", "hook", "anchor", "init",
                       "install-hook", "adopt"):
            self.assertNotIn(writer, names)
        for tool in tools:
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertTrue(tool["annotations"]["readOnlyHint"], tool["name"])
            self.assertFalse(tool["annotations"]["destructiveHint"])
            self.assertFalse(tool["annotations"]["openWorldHint"])
            self.assertTrue(tool["description"])
        # Deterministic order across calls (prompt-cache friendly).
        again = c.request("tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in again], names)
        c.close()

    def test_modern_list_carries_result_type_and_server_meta(self):
        c = self.client()
        result = c.request("tools/list", meta=modern_meta())["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertIn(META_SERVER, result["_meta"])
        self.assertEqual(len(result["tools"]), 5)
        c.close()


class ToolCallTest(McpBase):
    def test_digest_is_the_cli_word_for_word(self):
        c = self.client()
        c.initialize()
        reply = c.call("digest")
        self.assertFalse(reply["result"].get("isError", False), reply)
        cli = self.cli("digest")
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(text_of(reply), cli.stdout)
        self.assertIn("testimony", text_of(reply))
        c.close()

    def test_digest_of_an_empty_repo_says_so_instead_of_silence(self):
        empty = self.root / "empty"
        empty.mkdir()
        c = McpClient("--repo", str(empty), env_extra=self.env)
        self.clients.append(c)
        c.initialize()
        text = text_of(c.call("digest"))
        self.assertIn("no receipts", text)
        c.close()

    def test_show_matches_cli_and_self_verifies(self):
        c = self.client()
        c.initialize()
        address = self.hashes[2][:8]
        reply = c.call("show", {"address": address})
        cli = self.cli("show", address)
        self.assertEqual(text_of(reply), cli.stdout)
        self.assertIn("self-verified", text_of(reply))
        self.assertIn("Bash: pytest -q", text_of(reply))
        c.close()

    def test_show_of_an_unknown_address_is_a_tool_error_in_the_cli_words(self):
        c = self.client()
        c.initialize()
        reply = c.call("show", {"address": "deadbeef"})
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("no entry under", text_of(reply))
        c.close()

    def test_search_and_timeline_match_the_cli(self):
        c = self.client()
        c.initialize()
        search = c.call("search", {"text": "pytest"})
        self.assertEqual(text_of(search), self.cli("search", "pytest").stdout)
        self.assertIn("matched 1", text_of(search))
        address = self.hashes[2][:8]
        timeline = c.call("timeline", {"address": address,
                                       "before": 1, "after": 1})
        self.assertEqual(text_of(timeline),
                         self.cli("timeline", address,
                                  "--before", "1", "--after", "1").stdout)
        self.assertIn("<- here", text_of(timeline))
        c.close()

    def test_verify_speaks_the_judges_verdict(self):
        c = self.client()
        c.initialize()
        good = c.call("verify", {"address": self.hashes[1][:8]})
        self.assertFalse(good["result"].get("isError", False), good)
        self.assertIn("VALID", text_of(good))
        c.close()
        # Tamper with a past entry; the same tool now carries the break.
        lines = self.log.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace("Edit: one.py", "Edit: two.py")
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        c = self.client()
        c.initialize()
        bad = c.call("verify", {"address": self.hashes[2][:8]})
        self.assertTrue(bad["result"]["isError"])
        self.assertIn("BROKEN", text_of(bad))
        c.close()

    def test_arguments_are_validated_before_anything_runs(self):
        c = self.client()
        c.initialize()
        missing = c.call("show", {})
        self.assertTrue(missing["result"]["isError"])
        self.assertIn("address", text_of(missing))
        wrong_type = c.call("search", {"text": "x", "limit": "ten"})
        self.assertTrue(wrong_type["result"]["isError"])
        unknown = c.call("no-such-tool")
        self.assertEqual(unknown["error"]["code"], -32602)
        c.close()

    def test_a_full_session_leaves_every_chain_byte_identical(self):
        before = sha256_tree(self.root)
        c = self.client()
        c.initialize()
        c.call("digest")
        c.call("search", {"text": "commit"})
        c.call("show", {"address": self.hashes[3][:8]})
        c.call("timeline", {"address": self.hashes[3][:8]})
        c.call("verify", {"address": self.hashes[3][:8]})
        c.close()
        self.assertEqual(sha256_tree(self.root), before)

    def test_all_flag_reaches_other_repos_but_honors_unlisted(self):
        other = self.root / "beta"
        other.mkdir()
        forge_chain(other, "bbbb2222-2222-2222-2222-222222222222", [
            ("2026-08-21T09:00:00Z", "Edit: hidden.py"),
        ])
        shy = self.root / "gamma"
        shy.mkdir()
        forge_chain(shy, "cccc3333-3333-3333-3333-333333333333", [
            ("2026-08-21T09:00:00Z", "Edit: shy.py"),
        ])
        (shy / "receipts" / ".unlisted").write_text("", encoding="utf-8")
        c = self.client()
        c.initialize()
        local = text_of(c.call("search", {"text": "Edit"}))
        self.assertNotIn("hidden.py", local)
        wide = text_of(c.call("search", {"text": "Edit", "all": True}))
        self.assertIn("hidden.py", wide)
        self.assertNotIn("shy.py", wide)
        c.close()


if __name__ == "__main__":
    unittest.main()
