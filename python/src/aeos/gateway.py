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

With an authority key, the gateway also requires a capability token (in the
`AEOS-Capability` header) on every tool call, and checks it with facts it knows itself:
the SPIFFE ID from the connection, the tool, the call's amount and the time. It records
each decision as a `policy.decision` linked to the call, with the intent the token is
bound to, and meters each intent's total budget (see delegation.py).

With a policy, the gateway then runs a Rego policy compiled to WebAssembly on each call
(see policy.py) and records its decision with the exact input it saw. The gateway does
not run a call the policy escalates. It answers with the escalation's CID, and the agent
repeats the call with a person's signed approval in the `AEOS-Approval` header; the
gateway records the approval before asking the policy again.
"""
from __future__ import annotations

import base64
import http.client
import json
import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from . import books, delegation, identity, policy as policy_mod
from .canon import canonical_json, cid_str, json_digest
from .log import ReceiptLog, now_ms
from .recorder import Recorder

Tool = Callable[[Dict[str, Any]], Any]
PROTOCOL_VERSION = "2025-06-18"


class Gateway:
    """Route authenticated tool calls to tools and record them.

    tools           tool name -> function taking the call's arguments
    permissions     SPIFFE ID -> tool names it may call; other identities may call nothing
    authority_key   when set, every tool call needs a capability token signed by this key
    intents         the signed intent envelopes tokens may be bound to, by CID
    principal_keys  each person's public key, by SPIFFE ID, to check envelope signatures
                    and approvals
    policy          a compiled policy to run on every call that passes the other checks
    policy_facts    tool name, arguments -> facts the policy needs, such as the invoice
    """

    def __init__(self, log: ReceiptLog, tools: Dict[str, Tool], *,
                 permissions: Dict[str, Iterable[str]], trust_domain: str,
                 svid_files: Tuple[Path, Path], bundle_file: Path,
                 on_behalf_of: Optional[Dict[str, str]] = None,
                 authority_key: Optional[bytes] = None,
                 intents: Optional[Dict[str, delegation.IntentEnvelope]] = None,
                 principal_keys: Optional[Dict[str, bytes]] = None,
                 policy: Optional[policy_mod.Policy] = None,
                 policy_facts: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None
                 ) -> None:
        self.log, self.tools, self.trust_domain = log, tools, trust_domain
        self.permissions = {k: set(v) for k, v in permissions.items()}
        self.obo = on_behalf_of or {}
        self.context = identity.server_context(svid_files, bundle_file)
        self._recorders: Dict[str, Recorder] = {}
        self._sessions: Dict[str, Tuple[str, str]] = {}   # MCP session -> (SPIFFE ID, SVID)
        self.authority_key = authority_key
        self.intents = dict(intents or {})
        self.principal_keys = dict(principal_keys or {})
        self.budget = delegation.Budget()
        self.tokens: Dict[str, bytes] = {}                 # SHA-256 hex -> token presented
        self.policy, self.policy_facts = policy, policy_facts
        self.escalations: Dict[str, Tuple[str, str, bytes]] = {}  # CID -> agent, tool, args
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
               msg: Dict[str, Any], token: Optional[str] = None,
               approval: Optional[str] = None) -> Tuple[Dict[str, Any], Optional[str]]:
        """Answer one JSON-RPC request from an authenticated peer."""
        method, rid = msg.get("method"), msg.get("id")
        if method == "initialize":
            session = secrets.token_hex(8)
            self._sessions[session] = (peer, svid_sha256)
            extra = {"svid_sha256": bytes.fromhex(svid_sha256),
                     "authenticated_by": "x509-svid-mtls", "trust_domain": self.trust_domain}
            if self.authority_key is not None:
                extra["authorization"] = delegation.POLICY
            if self.policy is not None:
                extra["policy_sha256"] = self.policy.sha256
            self.recorder(peer).session(session, subject="mcp", extra=extra)
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
        at = now_ms()
        cap = self._authorize(peer, name, args, token, at) \
            if self.authority_key is not None else None
        entry, refusal = rec.call(name, call_id=call_id, session_id=session, arguments=args,
                                  on_behalf_of=cap["principal"] if cap else None, ts=at)
        reserved = cap["envelope"] if cap and cap["allowed"] else None
        reasons = [f"{peer} may not use {name}"] if refusal else []
        if cap:                                     # each check's outcome is recorded
            rec.decision(entry, name, decision="allow" if cap["allowed"] else "deny",
                         policy=delegation.POLICY, body=cap["body"],
                         on_behalf_of=cap["principal"], ts=at)
            reasons += cap["body"]["reasons"]
        if reasons:
            if reserved is not None:
                self.budget.release(reserved, cap["body"]["amount"])
            return _refused(rid, "; ".join(reasons)), session
        obo = cap["principal"] if cap else None
        if self.policy is not None:
            stop = self._apply_policy(rec, entry, rid, peer, name, args, approval, obo, at)
            if stop is not None:
                if reserved is not None:
                    self.budget.release(reserved, cap["body"]["amount"])
                return stop, session
        tool = self.tools[name]
        try:                                        # the books also need the call's record
            out = tool(args, entry) if getattr(tool, "takes_call", False) else tool(args)
        except Exception as e:                      # the tool's failure is the agent's answer
            if reserved is not None:                  # a call that did not run spends nothing
                self.budget.release(reserved, cap["body"]["amount"])
            rec.result(call_id, session_id=session, error={"message": str(e)}, on_behalf_of=obo)
            if isinstance(e, books.Refused):
                return _refused(rid, str(e)), session
            return _ok(rid, {"isError": True, "content": [{"type": "text", "text": str(e)}]}), \
                session
        rec.result(call_id, session_id=session, result=out, on_behalf_of=obo)
        return _ok(rid, {"content": [{"type": "text", "text": json.dumps(out)}],
                         "structuredContent": out}), session

    def _apply_policy(self, rec: Recorder, call: Any, rid: Any, peer: str, tool: str,
                      args: Dict[str, Any], approval: Optional[str], obo: Optional[str],
                      at: int) -> Optional[Dict[str, Any]]:
        """Record the policy's decision; the reply when the call must not run yet."""
        assert self.policy is not None
        doc: Dict[str, Any] = {"tool": tool, "agent": peer, "principal": obo,
                               "arguments": args}
        if self.policy_facts:
            doc.update(self.policy_facts(tool, args))
        if approval:
            answer, problem = self._approval(rec, call, approval, peer, tool, args, at)
            if problem:
                rec.decision(call, tool, decision="deny", policy=policy_mod.POLICY,
                             body={"reasons": [problem]}, on_behalf_of=obo, ts=at)
                return _refused(rid, problem)
            escalation = answer.pop("escalation")
            doc["approval"] = answer
        try:
            d = self.policy.evaluate(doc)
        except policy_mod.PolicyError as e:
            d = {"decision": "deny", "reasons": [str(e)]}
        if approval and d["decision"] == "allow":
            with self._lock:                          # the escalation is settled
                self.escalations.pop(escalation, None)
        entry = rec.decision(call, tool, decision=d["decision"], policy=policy_mod.POLICY,
                             body={"reasons": d["reasons"],
                                   "policy_sha256": self.policy.sha256,
                                   "data_sha256": self.policy.data_sha256,
                                   "entrypoint": self.policy.entrypoint,
                                   "input_json": canonical_json(doc)},
                             on_behalf_of=obo, ts=at)
        if d["decision"] == "allow":
            return None
        if d["decision"] == "deny":
            return _refused(rid, "; ".join(d["reasons"]))
        escalation = cid_str(entry.cid)
        with self._lock:
            self.escalations[escalation] = (peer, tool, json_digest(args))
        return _ok(rid, {"isError": True, "structuredContent": {
            "escalation": escalation, "reasons": d["reasons"]},
            "content": [{"type": "text", "text": "Escalated: " + "; ".join(d["reasons"])
                         + f". Repeat the call with an approval of escalation {escalation}, "
                         "signed by an approver."}]})

    def _approval(self, rec: Recorder, call: Any, text: str, peer: str, tool: str,
                  args: Dict[str, Any], at: int) -> Tuple[Dict[str, Any], Optional[str]]:
        """Check a signed approval and record it; (what the policy sees, problem)."""
        try:
            a = delegation.Approval.from_json(json.loads(base64.urlsafe_b64decode(
                text + "=" * (-len(text) % 4))))
        except (ValueError, KeyError, TypeError):
            return {}, "the approval could not be read"
        with self._lock:
            asked = self.escalations.get(a.escalation)
            if asked is None:
                return {}, "the approval does not answer an open escalation at this gateway"
            if asked != (peer, tool, json_digest(args)) or a.tool != tool or \
                    a.args_sha256 != asked[2]:
                return {}, "the approval is for a different call"
            if not a.verify(self.principal_keys.get(a.approver, b"")):
                return {}, "the approval's signature does not verify"
        rec.approval(call, a, ts=at)
        return {"approver": a.approver, "decision": a.decision, "escalation": a.escalation}, \
            None

    def _authorize(self, peer: str, tool: str, args: Dict[str, Any], token: Optional[str],
                   at: int) -> Dict[str, Any]:
        """Check a tool call's capability token; the decision and what to record."""
        amount = delegation.call_amount(args)
        body: Dict[str, Any] = {"amount": amount, "reasons": []}
        raw = delegation.parse_token(token) if token else None
        envelope, principal = None, None
        if not raw:
            body["reasons"] = ["no readable capability token was presented"]
        elif amount < 0:
            body["reasons"] = ["the amount is not a whole, non-negative number of minor units"]
        else:
            sha = delegation.token_sha256(raw)
            body["token_sha256"] = sha
            with self._lock:
                self.tokens[sha.hex()] = raw
            d = delegation.authorize(raw, self.authority_key or b"", subject=peer, tool=tool,
                                     amount=amount, at=at)
            body["reasons"] = list(d.reasons)
            if d.intent:
                body["intent"] = d.intent
                envelope = self.intents.get(d.intent)
            if d.allowed:
                if envelope is None:
                    body["reasons"] = ["the token's intent is not one this gateway holds"]
                elif not envelope.verify(self.principal_keys.get(envelope.principal, b"")):
                    body["reasons"] = ["the intent's signature does not verify"]
                else:
                    principal = envelope.principal
                    over = self.budget.reserve(envelope, amount)
                    if over:
                        body["reasons"] = [over]
        return {"allowed": not body["reasons"], "body": body, "envelope": envelope,
                "principal": principal}

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
                reply, session = gw.handle(peer, fp, self.headers.get("Mcp-Session-Id"), msg,
                                           self.headers.get("AEOS-Capability"),
                                           self.headers.get("AEOS-Approval"))
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


def _refused(rid: Any, why: str) -> Dict[str, Any]:
    return _ok(rid, {"isError": True, "content": [{"type": "text", "text": f"Refused: {why}"}]})


def _err(rid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


class AgentClient:
    """An agent's MCP client: connects with its SVID and checks the gateway's SPIFFE ID."""

    def __init__(self, port: int, svid_files: Tuple[Path, Path], bundle_file: Path, *,
                 gateway_id: str, trust_domain: str, host: str = "127.0.0.1",
                 token: Optional[bytes] = None) -> None:
        self.host, self.port = host, port
        self.context = identity.client_context(svid_files, bundle_file)
        self.gateway_id, self.trust_domain = gateway_id, trust_domain
        self.session: Optional[str] = None
        self.token = token                      # capability token sent with each request
        self._next = 0

    def _post(self, method: str, params: Optional[Dict[str, Any]] = None,
              http_method: str = "POST", approval: Optional[bytes] = None) -> Dict[str, Any]:
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
            if self.token:
                headers["AEOS-Capability"] = base64.urlsafe_b64encode(self.token).decode()
            if approval:
                headers["AEOS-Approval"] = base64.urlsafe_b64encode(approval).decode()
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

    def call(self, tool: str, arguments: Dict[str, Any],
             approval: Optional["delegation.Approval"] = None) -> Dict[str, Any]:
        """Call a tool; `approval` is a person's signed answer to an escalation."""
        return self._post("tools/call", {"name": tool, "arguments": arguments},
                          approval=json.dumps(approval.to_json()).encode() if approval else None)

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
