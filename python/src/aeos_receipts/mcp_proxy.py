"""Record every MCP tool call an agent makes, with signed receipts.

The proxy runs between an MCP client (the agent) and an MCP server over stdio:

    agent  <-stdio->  aeos-receipts mcp-proxy  <-stdio->  MCP server

For each `tools/call` it appends a `tool.call` record (tool name, SHA-256 of the
arguments, the agent and the person it acts for) and, when the server answers, a
`tool.result` record linked to the call. If an allow-list is set, calls to other
tools are refused before they reach the server and the refusal is recorded as a
`policy.decision`. Messages are passed through unchanged otherwise.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, BinaryIO, Dict, Iterable, List, Optional

from .canon import json_digest
from .log import Entry, ReceiptLog, make_record


class McpRecorder:
    """Protocol logic, separated from process plumbing so it can be tested directly."""

    def __init__(self, log: ReceiptLog, agent: str, on_behalf_of: Optional[str] = None,
                 allow_tools: Optional[Iterable[str]] = None, store_content: bool = False,
                 checkpoint_every: int = 0) -> None:
        self.log = log
        self.agent = agent
        self.obo = on_behalf_of
        self.allow = set(allow_tools) if allow_tools else None
        self.store_content = store_content
        self.checkpoint_every = checkpoint_every
        self.session: Optional[Entry] = None
        self._pending: Dict[str, Entry] = {}       # JSON-RPC id -> tool.call entry
        self._lock = threading.Lock()
        self._since_checkpoint = 0

    def _append(self, kind: str, subject: Optional[str], body: Dict[str, Any],
                parents: List[bytes], content: Optional[Dict[str, Any]] = None) -> Entry:
        rec = make_record(kind, self.agent, on_behalf_of=self.obo, subject=subject,
                          body=body, parents=parents)
        e = self.log.append(rec, content if self.store_content else None)
        self._since_checkpoint += 1
        if self.checkpoint_every and self._since_checkpoint >= self.checkpoint_every:
            self.log.checkpoint()
            self._since_checkpoint = 0
        return e

    def start(self, server: str) -> None:
        with self._lock:
            self.session = self._append("session.start", server,
                                        {"allow_list": sorted(self.allow) if self.allow
                                         else None}, [])

    def end(self) -> None:
        with self._lock:
            parents = [self.session.cid] if self.session else []
            self._append("session.end", None, {"unanswered_calls": len(self._pending)},
                         parents)
            self.log.checkpoint()

    def _parents(self) -> List[bytes]:
        return [self.session.cid] if self.session else []

    def from_client(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle one client message. Returns a reply to send straight back to the
        client when the call is refused; otherwise None (forward the message)."""
        if msg.get("method") != "tools/call" or "id" not in msg:
            return None
        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}
        with self._lock:
            call = self._append("tool.call", tool, {"args_sha256": json_digest(args),
                                                     "rpc_id": str(msg["id"])},
                                self._parents(), {"arguments": args})
            if self.allow is not None and tool not in self.allow:
                reason = "tool-not-in-allow-list"
                self._append("policy.decision", tool,
                             {"decision": "deny", "policy": "aeos-allow-list/v0",
                              "reasons": [reason]}, [call.cid])
                return {"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "isError": True,
                    "content": [{"type": "text",
                                 "text": f"Refused by AE-OS policy: {reason} ({tool})"}]}}
            self._pending[str(msg["id"])] = call
        return None

    def from_server(self, msg: Dict[str, Any]) -> None:
        if "id" not in msg or "method" in msg:
            return
        with self._lock:
            call = self._pending.pop(str(msg["id"]), None)
            if call is None:
                return
            if "error" in msg:
                body = {"outcome": "rpc-error", "result_sha256": json_digest(msg["error"])}
                content = {"error": msg["error"]}
            else:
                result = msg.get("result") or {}
                body = {"outcome": "error" if result.get("isError") else "ok",
                        "result_sha256": json_digest(result)}
                content = {"result": result}
            self._append("tool.result", self.log.record(call)["subject"], body, [call.cid],
                         content)


def _messages(line: bytes) -> List[Dict[str, Any]]:
    """Parse one stdio line into JSON-RPC messages (a single message or a batch)."""
    try:
        data = json.loads(line)
    except ValueError:
        return []
    items = data if isinstance(data, list) else [data]
    return [m for m in items if isinstance(m, dict)]


def run(log: ReceiptLog, command: List[str], *, agent: str, on_behalf_of: Optional[str],
        allow_tools: Optional[List[str]], store_content: bool, checkpoint_every: int,
        stdin: BinaryIO = sys.stdin.buffer, stdout: BinaryIO = sys.stdout.buffer) -> int:
    rec = McpRecorder(log, agent, on_behalf_of, allow_tools, store_content, checkpoint_every)
    rec.start(" ".join(command))
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out_lock = threading.Lock()

    def send_client(data: bytes) -> None:
        with out_lock:
            stdout.write(data)
            stdout.flush()

    def pump_server() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            for m in _messages(line):
                try:
                    rec.from_server(m)
                except Exception as e:  # recording must never break the session
                    print(f"aeos-receipts: could not record server message: {e}",
                          file=sys.stderr)
            send_client(line)

    t = threading.Thread(target=pump_server, daemon=True)
    t.start()
    assert proc.stdin is not None
    try:
        for line in stdin:
            try:
                data = json.loads(line)
            except ValueError:
                data = None
            if isinstance(data, list):       # JSON-RPC batch: refuse items individually
                keep, refusals = [], []
                for m in data:
                    r = rec.from_client(m) if isinstance(m, dict) else None
                    (refusals if r else keep).append(r or m)
                if refusals:
                    send_client(json.dumps(refusals).encode() + b"\n")
                    if not keep:
                        continue
                    line = json.dumps(keep).encode() + b"\n"
            elif isinstance(data, dict):
                refusal = rec.from_client(data)
                if refusal is not None:
                    send_client(json.dumps(refusal).encode() + b"\n")
                    continue
            proc.stdin.write(line)
            proc.stdin.flush()
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass
        code = proc.wait()
        t.join(timeout=5)
        rec.end()
    return code
