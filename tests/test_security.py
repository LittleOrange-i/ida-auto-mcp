"""Tests for tool permissions and the HTTP transport's request checks.

They import the tool registry without starting idalib, so no IDA
installation is needed:

    python -m unittest discover -s tests -v
"""

import builtins
import http.client
import io
import json
import threading
import unittest

from ida_auto_mcp import tools  # noqa: F401 - registers the tools
from ida_auto_mcp._registry import mcp
from ida_auto_mcp.mcp_server import (
    MAX_HTTP_BODY,
    McpServer,
    _host_allowed,
    _is_loopback,
    _origin_allowed,
)

WRITE_TOOLS = {
    "save_database",
    "rename_address",
    "set_comment",
    "append_comment",
    "set_function_type",
    "declare_type",
    "apply_type",
    "enum_upsert",
    "infer_types",
    "declare_stack_var",
    "delete_stack_var",
    "define_function",
    "define_code",
    "undefine_code",
    "patch_bytes",
    "patch_asm",
}
SCRIPT_TOOLS = {"run_script"}


def listed_tools(server: McpServer) -> set[str]:
    response = server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    return {t["name"] for t in response["result"]["tools"]}


def call_tool(server: McpServer, name: str, arguments: dict) -> dict:
    response = server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    return response["result"]


class ToolPermissionTests(unittest.TestCase):
    def setUp(self):
        self._saved_groups = set(mcp.enabled_groups)
        mcp.enabled_groups.clear()

    def tearDown(self):
        mcp.enabled_groups.clear()
        mcp.enabled_groups.update(self._saved_groups)

    def test_gated_tools_are_registered(self):
        registered = set(mcp._tools)
        self.assertEqual(len(registered), 55)
        self.assertLessEqual(WRITE_TOOLS | SCRIPT_TOOLS, registered)

    def test_default_lists_only_read_only_tools(self):
        expected = set(mcp._tools) - WRITE_TOOLS - SCRIPT_TOOLS
        self.assertEqual(listed_tools(mcp), expected)

    def test_allow_write_lists_write_tools_only(self):
        mcp.enabled_groups.add("write")
        listed = listed_tools(mcp)
        self.assertLessEqual(WRITE_TOOLS, listed)
        self.assertNotIn("run_script", listed)

    def test_allow_script_lists_run_script_only(self):
        mcp.enabled_groups.add("script")
        listed = listed_tools(mcp)
        self.assertIn("run_script", listed)
        self.assertTrue(WRITE_TOOLS.isdisjoint(listed))

    def test_disabled_run_script_is_not_executed(self):
        marker = "_ida_auto_mcp_test_marker"
        result = call_tool(
            mcp, "run_script", {"script": f"import builtins; builtins.{marker} = 1"}
        )
        self.assertTrue(result["isError"])
        self.assertIn("--allow-script", result["content"][0]["text"])
        self.assertFalse(hasattr(builtins, marker))

    def test_disabled_write_tool_names_its_flag(self):
        result = call_tool(mcp, "patch_bytes", {"address": "0x1000", "hex_bytes": "90"})
        self.assertTrue(result["isError"])
        self.assertIn("--allow-write", result["content"][0]["text"])

    def test_enabled_run_script_executes(self):
        mcp.enabled_groups.add("script")
        result = call_tool(mcp, "run_script", {"script": "print('hi')"})
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["output"], "hi\n")


class HostCheckTests(unittest.TestCase):
    def test_loopback_names(self):
        for name in ("localhost", "LOCALHOST", "127.0.0.1", "127.8.9.1", "::1", "[::1]"):
            self.assertTrue(_is_loopback(name), name)
        for name in ("", "0.0.0.0", "192.168.1.2", "evil.example", "localhost.evil.example"):
            self.assertFalse(_is_loopback(name), name)

    def test_specific_bind_accepts_only_its_own_address(self):
        self.assertTrue(_host_allowed("192.168.1.2", "192.168.1.2"))
        self.assertTrue(_host_allowed("localhost", "192.168.1.2"))
        self.assertFalse(_host_allowed("evil.example", "192.168.1.2"))
        self.assertFalse(_host_allowed("evil.example", "127.0.0.1"))

    def test_wildcard_bind_accepts_any_host_but_only_loopback_origins(self):
        self.assertTrue(_host_allowed("192.168.1.2", "0.0.0.0"))
        self.assertFalse(_host_allowed("", "0.0.0.0"))
        self.assertFalse(_origin_allowed("http://192.168.1.2:8765", "0.0.0.0"))
        self.assertTrue(_origin_allowed("http://localhost:5173", "0.0.0.0"))

    def test_odd_origins_are_rejected(self):
        for origin in ("null", "file://", "chrome-extension://abc", "http://[::1"):
            self.assertFalse(_origin_allowed(origin, "127.0.0.1"), origin)

    def test_http_server_rejects_unusable_tokens(self):
        for token in ("", " ", "abc ", " abc", "pässwort", "tab\tinside"):
            with self.assertRaises(ValueError, msg=repr(token)):
                McpServer("test").http_server("127.0.0.1", 0, token)


class MalformedMessageTests(unittest.TestCase):
    def test_bad_messages_get_errors_and_do_not_stop_stdio(self):
        bad_lines = [
            b"[]",
            b'[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]',
            b"123",
            b'"text"',
            b"null",
            b'{"jsonrpc": "2.0", "id": 1, "method": ["ping"]}',
            b'{"jsonrpc": "2.0", "id": 1}',
            b'{"jsonrpc": "2.0", "id": ' + b"9" * 5000 + b', "method": "ping"}',
            b"[" * 100000 + b"]" * 100000,
            b"\xff\xfe",
            b"{not json",
        ]
        ping = b'{"jsonrpc": "2.0", "id": "last", "method": "ping"}'
        stdout = io.BytesIO()
        McpServer("test").stdio(io.BytesIO(b"\n".join(bad_lines + [ping]) + b"\n"), stdout)

        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(replies), len(bad_lines) + 1)
        for reply in replies[:-1]:
            self.assertIn(reply["error"]["code"], (-32700, -32600))
        self.assertEqual(replies[-1], {"jsonrpc": "2.0", "result": {}, "id": "last"})


class HttpTransportTests(unittest.TestCase):
    TOKEN = "test-token-123"

    @classmethod
    def setUpClass(cls):
        cls.httpd = McpServer("test").http_server("127.0.0.1", 0, cls.TOKEN)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method="POST", headers=None, path="/mcp"):
        body = None
        if method == "POST":
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def auth(self, **extra):
        return {
            "Authorization": f"Bearer {self.TOKEN}",
            "Content-Type": "application/json",
            **extra,
        }

    def test_valid_token_is_accepted(self):
        status, _, body = self.request(headers=self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["result"], {})

    def test_missing_token_is_rejected(self):
        status, headers, _ = self.request(headers={"Content-Type": "application/json"})
        self.assertEqual(status, 401)
        self.assertEqual(headers.get("WWW-Authenticate"), "Bearer")

    def test_wrong_token_is_rejected(self):
        for value in ("Bearer nope", f"Basic {self.TOKEN}", self.TOKEN, "Bearer"):
            status, _, _ = self.request(headers={"Authorization": value})
            self.assertEqual(status, 401, value)

    def test_foreign_host_is_rejected(self):
        status, _, _ = self.request(headers=self.auth(Host=f"evil.example:{self.port}"))
        self.assertEqual(status, 403)

    def test_foreign_origin_is_rejected(self):
        for origin in ("https://evil.example", "null"):
            status, headers, _ = self.request(headers=self.auth(Origin=origin))
            self.assertEqual(status, 403, origin)
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_loopback_origin_gets_cors_header(self):
        origin = "http://localhost:6274"
        status, headers, _ = self.request(headers=self.auth(Origin=origin))
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), origin)

    def test_loopback_origin_can_read_401(self):
        origin = "http://localhost:6274"
        status, headers, _ = self.request(headers={"Origin": origin})
        self.assertEqual(status, 401)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), origin)

    def test_preflight_from_foreign_origin_is_rejected(self):
        status, headers, _ = self.request(
            "OPTIONS",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_preflight_from_loopback_origin_allows_authorization(self):
        origin = "http://127.0.0.1:6274"
        status, headers, _ = self.request(
            "OPTIONS",
            headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), origin)
        self.assertIn("Authorization", headers.get("Access-Control-Allow-Headers", ""))

    def test_oversized_body_gets_413(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            # The client really sends the body, and must still get the 413
            conn.request("POST", "/mcp", body=b" " * (MAX_HTTP_BODY + 1), headers=self.auth())
            response = conn.getresponse()
            self.assertEqual(response.status, 413)
            self.assertIn(b"too large", response.read())
        finally:
            conn.close()

    def test_chunked_body_gets_411(self):
        def chunks():
            for _ in range(64):
                yield b" " * 16384

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", "/mcp", body=chunks(), headers=self.auth(), encode_chunked=True)
            self.assertEqual(conn.getresponse().status, 411)
        finally:
            conn.close()

    def test_unknown_path_is_404(self):
        status, _, _ = self.request(path="/other", headers=self.auth())
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
