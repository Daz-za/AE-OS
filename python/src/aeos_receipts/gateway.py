"""An MCP gateway that authenticates agents by SPIFFE identity over mutual TLS.

Agents send MCP JSON-RPC requests (initialize, tools/list, tools/call) as HTTP POSTs to
/mcp, as in MCP's Streamable HTTP transport, over a TLS connection on which both sides
present X.509-SVIDs. The gateway takes the agent's identity from its verified
certificate, never from the request, checks that the identity may use the tool, runs the
tool, and records the call and its result in the receipt log under that identity. Each
session's first record carries the fingerprint of the agent's SVID, so an auditor can
match the records to the certificate the agent presented.

Connections without a valid SVID from the trust domain fail during the TLS handshake,
before any request is read.
"""
from __future__ import annotations

import http.client
import json
import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from . import identity
from .log import ReceiptLog
from .recorder import Recorder

Tool = Callable[[Dict[str, Any]], Any]
PROTOCOL_VERSION = "2025-06-18"


class Gateway:
    """Route authenticated tool calls to tools and record them.

    tools        tool name -> function taking the call's arguments
    permissions  SPIFFE ID -> tool names it may call; other identities may call nothing
    """

    def __init__(self, log: ReceiptLog, tools: Dict[str, Tool], *,
                 permissions: Dict[str, Iterable[str]], trust_domain: str,
                 svid_files: Tuple[Path, Path], bundle_file: Path,
                 on_behalf_of: Optional[Dict[str, str]] = None) -> None:
        self.log, self.tools, self.trust_domain = log, tools, trust_domain
        self.permissions = {k: set(v) for k, v in permissions.items()}
        self.obo = on_behalf_of or {}
        self.context = identity.server_context(svid_files, bundle_file)
        self._recorders: Dict[str, Recorder] = {}
        self._sessions: Dict[str, Tuple[str, str]] = {}   # MCP session -> (SPIFFE ID, SVID)
        self._lock = threading.Lock()
        self.server: Optional[ThreadingHTTPServer] = None

    def recorder(self, spiffe_id: str) -> Recorder:
        with self._lock:
            if spiffe_id not in self._recorders:
                self._recorders[spiffe_id] = Recorder(
                    self.log, agent=spiffe_id, on_behalf_of=self.obo.get(spiffe_id),
                    allow_tools=sorted(self.permissions.get(spiffe_id, ())))
            return self._recorders[spiffe_id]

    def handle(self, peer: str, svid_sha256: str, session: Optional[str],
               msg: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
        """Answer one JSON-RPC request from an authenticated peer."""
        method, rid = msg.get("method"), msg.get("id")
        if method == "initialize":
            session = secrets.token_hex(8)
            self._sessions[session] = (peer, svid_sha256)
            self.recorder(peer).session(session, subject="mcp", extra={
                "svid_sha256": bytes.fromhex(svid_sha256), "authenticated_by": "x509-svid-mtls",
                "trust_domain": self.trust_domain})
            return _ok(rid, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                             "serverInfo": {"name": "aeos-gateway", "version": "0.1"}}), session
        known = self._sessions.get(session or "")
        if known is None or known[0] != peer:
            # A session belongs to the identity that opened it.
            return _err(rid, -32001, "unknown session for this identity"), None
        if method == "tools/list":
            allowed = self.permissions.get(peer, set())
            return _ok(rid, {"tools": [{"name": n, "inputSchema": {"type": "object"}}
                                       for n in sorted(self.tools) if n in allowed]}), session
        if method != "tools/call":
            return _err(rid, -32601, f"method not supported: {method}"), session
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        rec = self.recorder(peer)
        call_id = str(rid)
        _, refusal = rec.call(name, call_id=call_id, session_id=session, arguments=args)
        if refusal:
            return _ok(rid, {"isError": True, "content": [{"type": "text", "text":
                       f"Refused: {peer} may not use {name}"}]}), session
        try:
            out = self.tools[name](args)
        except Exception as e:                      # the tool's failure is the agent's answer
            rec.result(call_id, session_id=session, error={"message": str(e)})
            return _ok(rid, {"isError": True, "content": [{"type": "text", "text": str(e)}]}), \
                session
        rec.result(call_id, session_id=session, result=out)
        return _ok(rid, {"content": [{"type": "text", "text": json.dumps(out)}],
                         "structuredContent": out}), session

    def end(self, session: str) -> None:
        known = self._sessions.pop(session, None)
        if known:
            self.recorder(known[0]).end(session)

    def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """Serve in a background thread; returns the port."""
        gw = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                try:
                    peer, fp = identity.peer_identity(self.connection,
                                                      trust_domain=gw.trust_domain)
                except identity.IdentityError as e:
                    self._send(403, _err(None, -32002, str(e)), None)
                    return
                length = int(self.headers.get("Content-Length") or 0)
                try:
                    msg = json.loads(self.rfile.read(min(length, 1 << 20)))
                except ValueError:
                    self._send(400, _err(None, -32700, "parse error"), None)
                    return
                if self.path != "/mcp" or not isinstance(msg, dict):
                    self._send(404, _err(None, -32600, "invalid request"), None)
                    return
                reply, session = gw.handle(peer, fp, self.headers.get("Mcp-Session-Id"), msg)
                self._send(200, reply, session)

            def do_DELETE(self) -> None:
                try:
                    peer, _ = identity.peer_identity(self.connection,
                                                     trust_domain=gw.trust_domain)
                except identity.IdentityError:
                    self._send(403, {}, None)
                    return
                session = self.headers.get("Mcp-Session-Id", "")
                if gw._sessions.get(session, ("",))[0] == peer:
                    gw.end(session)
                self._send(200, {}, None)

            def _send(self, code: int, doc: Dict[str, Any], session: Optional[str]) -> None:
                data = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if session:
                    self.send_header("Mcp-Session-Id", session)
                self.end_headers()
                self.wfile.write(data)

        server = ThreadingHTTPServer((host, port), Handler)
        server.socket = self.context.wrap_socket(server.socket, server_side=True)
        self.server = server
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server.server_address[1]

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def _ok(rid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


class AgentClient:
    """An agent's MCP client: connects with its SVID and checks the gateway's SPIFFE ID."""

    def __init__(self, port: int, svid_files: Tuple[Path, Path], bundle_file: Path, *,
                 gateway_id: str, trust_domain: str, host: str = "127.0.0.1") -> None:
        self.host, self.port = host, port
        self.context = identity.client_context(svid_files, bundle_file)
        self.gateway_id, self.trust_domain = gateway_id, trust_domain
        self.session: Optional[str] = None
        self._next = 0

    def _post(self, method: str, params: Optional[Dict[str, Any]] = None,
              http_method: str = "POST") -> Dict[str, Any]:
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context,
                                           timeout=10)
        try:
            conn.connect()
            identity.peer_identity(conn.sock, trust_domain=self.trust_domain,
                                   expect=self.gateway_id)
            self._next += 1
            body = json.dumps({"jsonrpc": "2.0", "id": self._next, "method": method,
                               "params": params or {}})
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if self.session:
                headers["Mcp-Session-Id"] = self.session
            conn.request(http_method, "/mcp", body=body, headers=headers)
            res = conn.getresponse()
            data = res.read()
            if res.getheader("Mcp-Session-Id"):
                self.session = res.getheader("Mcp-Session-Id")
            return json.loads(data or b"{}")
        finally:
            conn.close()

    def initialize(self) -> Dict[str, Any]:
        return self._post("initialize", {"protocolVersion": PROTOCOL_VERSION,
                                         "capabilities": {}, "clientInfo": {"name": "agent"}})

    def call(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("tools/call", {"name": tool, "arguments": arguments})

    def close(self) -> None:
        if self.session:
            self._post("", http_method="DELETE")
            self.session = None


PLAIN_TLS_ERRORS = {
    "CERTIFICATE_EXPIRED": "the certificate has expired",
    "UNKNOWN_CA": "the certificate was not issued by a trusted authority",
    "CERTIFICATE_REQUIRED": "no certificate was presented",
    "BAD_CERTIFICATE": "the certificate was rejected",
}


def handshake_error(e: BaseException) -> str:
    """A plain description of why a TLS connection was refused."""
    if isinstance(e, ssl.SSLCertVerificationError):
        return e.verify_message or str(e)
    if isinstance(e, ssl.SSLError):
        reason = e.reason or ""
        for code, text in PLAIN_TLS_ERRORS.items():
            if reason.endswith(code):
                return text
        return reason or str(e)
    return str(e)
