"""Minimal MCP (Model Context Protocol) server implementation.

Supports stdio and HTTP Streamable transports.
Automatic tool schema generation from Python type hints.

Adapted from zeromcp (https://github.com/mrexodia/zeromcp),
Copyright (c) 2025 Duncan Ogilvie, MIT License. See THIRD_PARTY_NOTICES.md.
"""

import hmac
import ipaddress
import json
import secrets
import socket
import sys
import time
import inspect
import traceback
from typing import (
    Any,
    BinaryIO,
    Callable,
    Annotated,
    Union,
    get_origin,
    get_args,
    get_type_hints,
    is_typeddict,
)
from types import UnionType
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

# Largest request body the HTTP transport accepts
MAX_HTTP_BODY = 16 * 1024 * 1024


class McpServer:
    """MCP server with stdio and HTTP transports."""

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._tools: dict[str, Callable] = {}
        # Tools outside the always-on set: tool name -> permission group
        self._tool_groups: dict[str, str] = {}
        # Permission groups switched on at startup (e.g. "write", "script")
        self.enabled_groups: set[str] = set()

        self._handlers: dict[str, Callable] = {
            "initialize": self._handle_initialize,
            "notifications/initialized": lambda **kw: None,
            "notifications/cancelled": lambda **kw: None,
            "ping": lambda **kw: {},
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": lambda **kw: {"resources": []},
            "resources/templates/list": lambda **kw: {"resourceTemplates": []},
            "resources/read": self._handle_resources_read,
            "prompts/list": lambda **kw: {"prompts": []},
        }

    def tool(self, func: Callable, group: str | None = None) -> Callable:
        """Register a function as an MCP tool.

        A tool registered with a group is only listed and callable while
        that group is in enabled_groups.
        """
        self._tools[func.__name__] = func
        if group:
            self._tool_groups[func.__name__] = group
        return func

    def is_enabled(self, name: str) -> bool:
        """Whether a registered tool may be listed and called."""
        group = self._tool_groups.get(name)
        return group is None or group in self.enabled_groups

    def dispatch(self, request: bytes | str | dict) -> dict | None:
        """Dispatch a JSON-RPC 2.0 request and return response or None for notifications."""
        if isinstance(request, (bytes, str)):
            try:
                request = json.loads(request)
            except (ValueError, RecursionError) as e:
                # Bad JSON or UTF-8, oversized integers, too-deep nesting
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                    "id": None,
                }

        if not isinstance(request, dict) or not isinstance(
            request.get("method"), str
        ):
            # Includes batches (JSON arrays), which MCP doesn't use
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Invalid Request"},
                "id": request.get("id") if isinstance(request, dict) else None,
            }

        method = request["method"]
        params = request.get("params") or {}
        request_id = request.get("id")

        handler = self._handlers.get(method)
        if handler is None:
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": request_id,
            }

        try:
            if isinstance(params, list):
                result = handler(*params)
            else:
                result = self._call_with_params(handler, params)

            if request_id is None:
                return None  # Notification - no response
            return {"jsonrpc": "2.0", "result": result, "id": request_id}
        except Exception as e:
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": str(e),
                    "data": traceback.format_exc(),
                },
                "id": request_id,
            }

    def _call_with_params(self, func: Callable, params: dict) -> Any:
        """Call a function mapping dict params to its signature."""
        sig = inspect.signature(func)
        kwargs = {}
        for name, param in sig.parameters.items():
            if name in params:
                kwargs[name] = params[name]
            elif name.startswith("_"):
                continue
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                continue
        return func(**kwargs)

    # === MCP Protocol Handlers ===

    def _handle_initialize(
        self,
        protocolVersion="2024-11-05",
        capabilities=None,
        clientInfo=None,
        **kw,
    ):
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": self.name, "version": self.version},
        }

    def _handle_tools_list(self, **kw):
        return {
            "tools": [
                self._build_tool_schema(name, func)
                for name, func in self._tools.items()
                if self.is_enabled(name)
            ]
        }

    def _handle_tools_call(self, name: str, arguments: dict | None = None, **kw):
        func = self._tools.get(name)
        if func is None:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }
        if not self.is_enabled(name):
            group = self._tool_groups[name]
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"Tool {name} is disabled. Restart the server with "
                            f"--allow-{group} to enable it."
                        ),
                    }
                ],
                "isError": True,
            }
        try:
            result = self._call_with_params(func, arguments or {})
            text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": (
                    result if isinstance(result, dict) else {"result": result}
                ),
                "isError": False,
            }
        except Exception as e:
            return {
                "content": [
                    {"type": "text", "text": f"Error: {e}\n{traceback.format_exc()}"}
                ],
                "isError": True,
            }

    def _handle_resources_read(self, uri: str, **kw):
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps({"error": f"Resource not found: {uri}"}),
                }
            ],
            "isError": True,
        }

    # === Tool Schema Generation ===

    def _build_tool_schema(self, name: str, func: Callable) -> dict:
        """Generate MCP tool schema from function type hints."""
        hints = get_type_hints(func, include_extras=True)
        hints.pop("return", None)
        sig = inspect.signature(func)

        properties = {}
        required = []

        for param_name, param_type in hints.items():
            properties[param_name] = self._type_to_json_schema(param_type)
            param = sig.parameters.get(param_name)
            if not param or param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {
            "name": name,
            "description": (func.__doc__ or f"Tool: {name}").strip(),
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def _type_to_json_schema(self, py_type: Any) -> dict:
        """Convert Python type hint to JSON Schema."""
        origin = get_origin(py_type)

        if origin is Annotated:
            args = get_args(py_type)
            schema = self._type_to_json_schema(args[0])
            if len(args) > 1 and isinstance(args[-1], str):
                schema["description"] = args[-1]
            return schema

        if origin in (Union, UnionType):
            return {
                "anyOf": [self._type_to_json_schema(t) for t in get_args(py_type)]
            }

        if origin is list:
            args = get_args(py_type)
            items = self._type_to_json_schema(args[0]) if args else {}
            return {"type": "array", "items": items}

        if origin is dict:
            return {"type": "object"}

        if is_typeddict(py_type):
            return self._typed_dict_to_schema(py_type)

        TYPE_MAP = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
            type(None): "null",
        }
        return {"type": TYPE_MAP.get(py_type, "object")}

    def _typed_dict_to_schema(self, td_cls) -> dict:
        hints = get_type_hints(td_cls, include_extras=True)
        required_keys = getattr(td_cls, "__required_keys__", set(hints.keys()))
        return {
            "type": "object",
            "properties": {
                k: self._type_to_json_schema(v) for k, v in hints.items()
            },
            "required": [k for k in hints if k in required_keys],
        }

    # === Transports ===

    def stdio(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None):
        """Run MCP server over stdio (one JSON-RPC message per line)."""
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer

        while True:
            try:
                line = stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                data = self._respond(line)
                if data is not None:
                    stdout.write(data + b"\n")
                    stdout.flush()
            except (BrokenPipeError, KeyboardInterrupt, EOFError):
                break

    def _respond(self, message: bytes) -> bytes | None:
        """Dispatch one message and serialize the reply. Never raises, so a
        single bad message can't stop either transport."""
        try:
            response = self.dispatch(message)
            if response is None:
                return None
            return json.dumps(response).encode("utf-8")
        except Exception as e:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": f"Internal error: {e}"},
                    "id": None,
                }
            ).encode("utf-8")

    def serve(
        self, host: str = "127.0.0.1", port: int = 8765, token: str | None = None
    ):
        """Run MCP server over HTTP (Streamable HTTP transport on /mcp).

        Every request must send "Authorization: Bearer <token>". Without a
        token, a random one is generated and printed to stderr.
        """
        token = (token or "").strip()
        if not token:
            token = secrets.token_urlsafe(32)
            print(f"[ida-auto-mcp] HTTP bearer token: {token}", file=sys.stderr)
        server = self.http_server(host, port, token)
        print(
            f"[ida-auto-mcp] HTTP server: http://{host}:{port}/mcp", file=sys.stderr
        )
        if not _is_loopback(host):
            print(
                f"[ida-auto-mcp] WARNING: listening on {host} makes the server "
                "reachable from other machines over unencrypted HTTP. Anyone "
                "with the token can call every enabled tool.",
                file=sys.stderr,
            )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()

    def http_server(self, host: str, port: int, token: str) -> "_McpHttpServer":
        """Create (but do not start) the HTTP transport server."""
        if not token or token != token.strip() or not (
            token.isascii() and token.isprintable()
        ):
            raise ValueError(
                "The HTTP token must be non-empty printable ASCII without "
                "leading or trailing spaces"
            )
        server = _McpHttpServer((host, port), _McpHttpHandler)
        server.mcp = self
        server.token = token
        server.bound_host = host
        return server


# === HTTP request checks ===

_WILDCARD_HOSTS = {"", "0.0.0.0", "::"}


def _is_loopback(hostname: str) -> bool:
    """Whether a host name or address refers to this machine's loopback."""
    hostname = hostname.strip("[]").lower()
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _hostname_of(host_header: str) -> str:
    """Host name from a Host header value such as "127.0.0.1:8765"."""
    try:
        return urlsplit("//" + host_header).hostname or ""
    except ValueError:
        return ""


def _host_allowed(hostname: str, bound_host: str) -> bool:
    """Whether a request's Host may address this server.

    Loopback names are always accepted, plus the bound address itself. A
    server bound to all interfaces accepts any Host and relies on the token.
    """
    if _is_loopback(hostname):
        return True
    bound = bound_host.strip("[]").lower()
    if bound in _WILDCARD_HOSTS:
        return bool(hostname)
    return hostname == bound


def _origin_allowed(origin: str, bound_host: str) -> bool:
    """Whether a browser Origin may call this server: only pages served from
    this machine (or from the specific address the server is bound to)."""
    try:
        parts = urlsplit(origin)
        hostname = parts.hostname or ""
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    if _is_loopback(hostname):
        return True
    bound = bound_host.strip("[]").lower()
    return bound not in _WILDCARD_HOSTS and hostname == bound


class _McpHttpServer(HTTPServer):
    mcp: McpServer
    token: str
    bound_host: str


class _McpHttpHandler(BaseHTTPRequestHandler):
    server: _McpHttpServer
    # Socket idle timeout, so a client that stalls mid-request can't block
    # this single-threaded server indefinitely
    timeout = 30
    # Set once the request's Origin header has been checked and accepted
    _origin_ok = False

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/mcp":
            self._reject(404, "Not Found")
            return
        if not self._check_host_and_origin() or not self._check_token():
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._reject(411, "Content-Length required")
            return
        if length < 0:
            self._reject(400, "Invalid Content-Length")
            return
        if length > MAX_HTTP_BODY:
            self._reject(413, "Request body too large")
            return

        body = self.rfile.read(length)
        data = self.server.mcp._respond(body)

        if data is None:
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self._send_cors()
            self.end_headers()
            self.wfile.write(b"Accepted")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self._send_cors()
            self.end_headers()
            self.wfile.write(data)

    def do_OPTIONS(self):
        if not self._check_host_and_origin():
            return
        self.send_response(204)
        self._send_cors()
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version",
        )
        self.end_headers()

    def _check_host_and_origin(self) -> bool:
        """Reject requests addressed to a foreign host name (DNS rebinding)
        or sent by a web page that is not served from this machine."""
        bound = self.server.bound_host
        if not _host_allowed(_hostname_of(self.headers.get("Host", "")), bound):
            self._reject(403, "Host not allowed")
            return False
        origin = self.headers.get("Origin")
        if origin is not None and not _origin_allowed(origin, bound):
            self._reject(403, "Origin not allowed")
            return False
        self._origin_ok = origin is not None
        return True

    def _check_token(self) -> bool:
        scheme, _, supplied = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            supplied.strip().encode(), self.server.token.encode()
        ):
            self._reject(
                401,
                "Missing or invalid bearer token",
                {"WWW-Authenticate": "Bearer"},
            )
            return False
        return True

    def _reject(self, code: int, message: str, headers: dict | None = None):
        # Closing the socket with request data still unread resets the
        # connection, and the client may never see the error. Read a body of
        # acceptable size first; otherwise drain it after responding.
        unread = self._expected_body_length()
        if unread and unread <= MAX_HTTP_BODY:
            self.rfile.read(unread)
            unread = 0

        data = json.dumps({"error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if self._origin_ok:
            self._send_cors()
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

        if unread != 0:
            self._drain_after_response()

    def _expected_body_length(self) -> int | None:
        """Bytes of request body still to come: 0 for none, None if unknown
        (chunked or an invalid Content-Length)."""
        value = self.headers.get("Content-Length")
        if value is None:
            return None if "Transfer-Encoding" in self.headers else 0
        try:
            length = int(value)
        except ValueError:
            return None
        return length if length >= 0 else None

    def _drain_after_response(self):
        """Half-close our side, then drop whatever the client still sends
        until it closes the connection, for a few seconds at most."""
        try:
            self.connection.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + 5
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.connection.settimeout(remaining)
                if not self.connection.recv(65536):
                    break
        except OSError:
            pass

    def _send_cors(self):
        # Only reached once _check_host_and_origin has accepted the Origin
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def log_message(self, format, *args):
        pass
