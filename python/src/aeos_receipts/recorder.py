"""Record agent tool calls from any source: gateways, agent frameworks, or your own code.

`Recorder` turns tool-call events into receipt-log records. The HTTP sink (including its
OpenTelemetry endpoint) and the agent hook command use it, and it can be called directly:

    rec = Recorder(log, agent="spiffe://acme.example/agent/ap")
    rec.call("erp.invoice.pay", call_id="c1", arguments={"invoice": "INV-1"}, session_id="s1")
    rec.result("c1", result={"payment": "PAY-88"}, session_id="s1")
    rec.end("s1")

Each session gets one `session.start` record, found again by its `session_id`, so events
for one session may arrive through different processes or after a restart. A call that is
reported twice (for example, an exporter retrying a batch) is recorded once.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .canon import json_digest
from .log import Entry, ReceiptLog, make_record

_MISSING: Any = object()
ALLOW_LIST_POLICY = "aeos-allow-list/v0"


class Recorder:
    def __init__(self, log: ReceiptLog, *, agent: str, on_behalf_of: Optional[str] = None,
                 allow_tools: Optional[Iterable[str]] = None, store_content: bool = False,
                 checkpoint_every: int = 0) -> None:
        self.log = log
        self.agent = agent
        self.obo = on_behalf_of
        self.allow = set(allow_tools) if allow_tools is not None else None
        self.store_content = store_content
        self.checkpoint_every = checkpoint_every
        self._lock = threading.RLock()
        self._sessions: Dict[str, Entry] = {}                       # session_id -> start
        self._calls: Dict[Tuple[Optional[str], str], Entry] = {}    # (session, call) -> call
        self._results: Dict[Tuple[Optional[str], str], Entry] = {}
        self._ended: Dict[str, Entry] = {}
        self._scanned = 0
        self._checkpoint_size: Optional[int] = None

    # ---- index of what is already in the log ------------------------------------------

    def _refresh(self) -> None:
        """Index records appended since the last look, by this or another process."""
        entries = self.log.entries()
        for e in entries[self._scanned:]:
            rec = self.log.record(e)
            body = rec.get("body") or {}
            sid, cid = body.get("session_id"), body.get("call_id")
            kind = rec.get("kind")
            if kind == "session.start" and isinstance(sid, str):
                self._sessions.setdefault(sid, e)
            elif kind == "session.end" and isinstance(sid, str):
                self._ended.setdefault(sid, e)
            elif kind == "tool.call" and isinstance(cid, str):
                self._calls.setdefault((sid, cid), e)
            elif kind == "tool.result" and isinstance(cid, str):
                self._results.setdefault((sid, cid), e)
        self._scanned = len(entries)

    def _append(self, kind: str, *, agent: Optional[str], obo: Optional[str],
                subject: Optional[str], body: Dict[str, Any], parents: List[bytes],
                ts: Optional[int], content: Optional[Dict[str, Any]] = None) -> Entry:
        rec = make_record(kind, agent or self.agent,
                          on_behalf_of=obo if obo is not None else self.obo,
                          subject=subject, body=body, parents=parents, ts=ts)
        e = self.log.append(rec, content if self.store_content else None)
        self._maybe_checkpoint()
        return e

    def _maybe_checkpoint(self) -> None:
        if not self.checkpoint_every:
            return
        if self._checkpoint_size is None or \
                len(self.log) - self._checkpoint_size >= self.checkpoint_every:
            cps = self.log.checkpoints()             # another process may have signed one
            self._checkpoint_size = cps[-1].size if cps else 0
        if len(self.log) - self._checkpoint_size >= self.checkpoint_every:
            self._checkpoint_size = self.log.checkpoint().size

    # ---- events -----------------------------------------------------------------------

    def session(self, session_id: str, *, agent: Optional[str] = None,
                on_behalf_of: Optional[str] = None, subject: Optional[str] = None,
                extra: Optional[Dict[str, Any]] = None, ts: Optional[int] = None) -> Entry:
        """The session's `session.start` record, written the first time the session is seen."""
        with self._lock:
            self._refresh()
            if session_id in self._sessions:
                return self._sessions[session_id]
            body = {"session_id": session_id,
                    "allow_list": sorted(self.allow) if self.allow else None, **(extra or {})}
            e = self._append("session.start", agent=agent, obo=on_behalf_of, subject=subject,
                             body=body, parents=[], ts=ts)
            self._sessions[session_id] = e
            return e

    def call(self, tool: str, *, call_id: str, session_id: Optional[str] = None,
             arguments: Any = _MISSING, args_sha256: Optional[bytes] = None,
             agent: Optional[str] = None, on_behalf_of: Optional[str] = None,
             extra: Optional[Dict[str, Any]] = None, ts: Optional[int] = None
             ) -> Tuple[Entry, Optional[str]]:
        """Record that an agent asked to use a tool.

        Returns the `tool.call` entry and, when the tool is outside the allow-list, the
        reason it was refused (the refusal is recorded as a `policy.decision`). Pass the
        arguments themselves, or only their digest if the source does not share them.
        """
        with self._lock:
            self._refresh()
            key = (session_id, call_id)
            if key in self._calls:                       # reported again: keep the first
                return self._calls[key], self._refusal(tool)
            parents = [self.session(session_id, agent=agent, on_behalf_of=on_behalf_of,
                                    ts=ts).cid] if session_id else []
            body: Dict[str, Any] = {"call_id": call_id}
            if session_id:
                body["session_id"] = session_id
            if arguments is not _MISSING:
                body["args_sha256"] = json_digest(arguments)
            elif args_sha256 is not None:
                body["args_sha256"] = args_sha256
            body.update(extra or {})
            content = {"arguments": arguments} if arguments is not _MISSING else None
            e = self._append("tool.call", agent=agent, obo=on_behalf_of, subject=tool,
                             body=body, parents=parents, ts=ts, content=content)
            self._calls[key] = e
            reason = self._refusal(tool)
            if reason:
                self._append("policy.decision", agent=agent, obo=on_behalf_of, subject=tool,
                             body={"decision": "deny", "policy": ALLOW_LIST_POLICY,
                                   "reasons": [reason]}, parents=[e.cid], ts=ts)
            return e, reason

    def decision(self, call: Entry, tool: str, *, decision: str, policy: str,
                 body: Optional[Dict[str, Any]] = None, agent: Optional[str] = None,
                 on_behalf_of: Optional[str] = None, ts: Optional[int] = None) -> Entry:
        """Record a policy decision about a call, linked to the call's record."""
        with self._lock:
            return self._append("policy.decision", agent=agent, obo=on_behalf_of, subject=tool,
                                body={"decision": decision, "policy": policy, **(body or {})},
                                parents=[call.cid], ts=ts)

    def _refusal(self, tool: str) -> Optional[str]:
        if self.allow is not None and tool not in self.allow:
            return "tool-not-in-allow-list"
        return None

    def result(self, call_id: str, *, session_id: Optional[str] = None,
               result: Any = _MISSING, error: Any = _MISSING, outcome: Optional[str] = None,
               result_sha256: Optional[bytes] = None, tool: Optional[str] = None,
               agent: Optional[str] = None, on_behalf_of: Optional[str] = None,
               extra: Optional[Dict[str, Any]] = None, ts: Optional[int] = None) -> Entry:
        """Record a tool's answer, linked to its call.

        `outcome` defaults to "error" when `error` is given and "ok" otherwise. A result
        whose call was never reported is still recorded, marked `"call_seen": false`.
        """
        with self._lock:
            self._refresh()
            key = (session_id, call_id)
            if key in self._results:
                return self._results[key]
            call = self._calls.get(key)
            body: Dict[str, Any] = {"call_id": call_id}
            if session_id:
                body["session_id"] = session_id
            body["outcome"] = outcome or ("error" if error is not _MISSING else "ok")
            content: Optional[Dict[str, Any]] = None
            if error is not _MISSING:
                body["result_sha256"] = json_digest(error)
                content = {"error": error}
            elif result is not _MISSING:
                body["result_sha256"] = json_digest(result)
                content = {"result": result}
            elif result_sha256 is not None:
                body["result_sha256"] = result_sha256
            if call is not None:
                parents = [call.cid]
                tool = tool or self.log.record(call)["subject"]
            else:
                body["call_seen"] = False
                parents = [self.session(session_id, agent=agent, on_behalf_of=on_behalf_of,
                                        ts=ts).cid] if session_id else []
            body.update(extra or {})
            e = self._append("tool.result", agent=agent, obo=on_behalf_of, subject=tool,
                             body=body, parents=parents, ts=ts, content=content)
            self._results[key] = e
            return e

    def end(self, session_id: str, *, agent: Optional[str] = None,
            on_behalf_of: Optional[str] = None, ts: Optional[int] = None,
            checkpoint: bool = True) -> Entry:
        """Write `session.end` with the number of calls that never got a result, then sign
        a checkpoint so the session is covered."""
        with self._lock:
            self._refresh()
            if session_id in self._ended:
                return self._ended[session_id]
            start = self.session(session_id, agent=agent, on_behalf_of=on_behalf_of, ts=ts)
            unanswered = sum(1 for k in self._calls if k[0] == session_id
                             and k not in self._results)
            e = self._append("session.end", agent=agent, obo=on_behalf_of, subject=None,
                             body={"session_id": session_id, "unanswered_calls": unanswered},
                             parents=[start.cid], ts=ts)
            self._ended[session_id] = e
            if checkpoint and self.log.can_sign:
                self.log.checkpoint()
                self._checkpoint_size = len(self.log)
            return e
