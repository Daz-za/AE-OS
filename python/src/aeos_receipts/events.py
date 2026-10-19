"""Tool-call events from gateways and agent frameworks, and how they become records.

Two input formats are accepted.

AE-OS events (JSON objects, one per line in a file or a list in an HTTP body):

    {"event": "tool.call", "tool": "erp.invoice.pay", "call_id": "c1", "session_id": "s1",
     "arguments": {...} | "args_sha256": "<hex>", "agent": "spiffe://...",
     "on_behalf_of": "...", "ts": 1760000000000, "source": {"gateway": "edge-1"}}
    {"event": "tool.result", "call_id": "c1", "session_id": "s1",
     "result": {...} | "error": {...} | "result_sha256": "<hex>", "outcome": "ok"}
    {"event": "session.start", "session_id": "s1"}
    {"event": "session.end", "session_id": "s1"}

A tool.call needs "event", "tool" and "call_id"; a tool.result needs "event" and "call_id";
session events need "session_id". Other fields are optional.

OpenTelemetry traces (OTLP/JSON): spans that describe a tool call under the OpenTelemetry
GenAI and MCP semantic conventions (`gen_ai.operation.name` = "execute_tool", or
`mcp.method.name` = "tools/call") become a `tool.call` and a `tool.result` record.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional

from .recorder import Recorder


class EventError(ValueError):
    pass


def _text(ev: Dict[str, Any], key: str, required: bool = False) -> Optional[str]:
    v = ev.get(key)
    if v is None:
        if required:
            raise EventError(f"'{key}' is required")
        return None
    if not isinstance(v, (str, int)) or isinstance(v, bool):
        raise EventError(f"'{key}' must be text")
    return str(v)


def _digest(ev: Dict[str, Any], key: str) -> Optional[bytes]:
    v = ev.get(key)
    if v is None:
        return None
    try:
        d = bytes.fromhex(v)
    except (TypeError, ValueError):
        raise EventError(f"'{key}' must be hex") from None
    if len(d) != 32:
        raise EventError(f"'{key}' must be a SHA-256 digest (64 hex digits)")
    return d


def _extra(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src = ev.get("source")
    if src is None:
        return None
    if not isinstance(src, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                            for k, v in src.items()):
        raise EventError("'source' must be an object of text values")
    return {"source": dict(src)}


def _ts(ev: Dict[str, Any]) -> Optional[int]:
    v = ev.get("ts")
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise EventError("'ts' must be milliseconds since the Unix epoch")
    return v


def apply(rec: Recorder, ev: Any) -> Dict[str, Any]:
    """Record one AE-OS event. Returns what was recorded, and for a `tool.call` the
    decision ("allow" or "deny") so a gateway can act on it."""
    if not isinstance(ev, dict):
        raise EventError("an event must be a JSON object")
    kind = ev.get("event")
    who = {"agent": _text(ev, "agent"), "on_behalf_of": _text(ev, "on_behalf_of"),
           "ts": _ts(ev)}
    sid = _text(ev, "session_id")
    if kind == "session.start":
        e = rec.session(_text(ev, "session_id", True), extra=_extra(ev), **who)
        return {"event": kind, "index": e.index}
    if kind == "session.end":
        e = rec.end(_text(ev, "session_id", True), **who)
        return {"event": kind, "index": e.index}
    if kind == "tool.call":
        args = {"arguments": ev["arguments"]} if "arguments" in ev else \
            {"args_sha256": _digest(ev, "args_sha256")}
        e, refusal = rec.call(_text(ev, "tool", True), call_id=_text(ev, "call_id", True),
                              session_id=sid, extra=_extra(ev), **args, **who)
        out = {"event": kind, "index": e.index, "decision": "deny" if refusal else "allow"}
        if refusal:
            out["reason"] = refusal
        return out
    if kind == "tool.result":
        outcome = ev.get("outcome")
        if outcome is not None and outcome not in ("ok", "error", "rpc-error"):
            raise EventError("'outcome' must be ok, error or rpc-error")
        if "error" in ev:
            payload = {"error": ev["error"]}
        elif "result" in ev:
            payload = {"result": ev["result"]}
        else:
            payload = {"result_sha256": _digest(ev, "result_sha256")}
        e = rec.result(_text(ev, "call_id", True), session_id=sid, outcome=outcome,
                       tool=_text(ev, "tool"), extra=_extra(ev), **payload, **who)
        return {"event": kind, "index": e.index}
    raise EventError(f"unknown event {kind!r}")


# --------------------------------------------------------------------------------------
# OpenTelemetry (OTLP/JSON) spans
# --------------------------------------------------------------------------------------

def _any_value(v: Dict[str, Any]) -> Any:
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return bool(v["boolValue"])
    if "intValue" in v:
        return int(v["intValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "arrayValue" in v:
        return [_any_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return _attributes(v["kvlistValue"].get("values", []))
    if "bytesValue" in v:
        return v["bytesValue"]
    return None


def _attributes(kvs: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {kv["key"]: _any_value(kv.get("value") or {}) for kv in kvs if "key" in kv}


def _structured(v: Any) -> Any:
    """Arguments and results may arrive as a JSON string; use the parsed value if so."""
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _is_tool_span(a: Dict[str, Any]) -> bool:
    return a.get("gen_ai.operation.name") == "execute_tool" or \
        a.get("mcp.method.name") == "tools/call"


def otlp_events(payload: Any) -> Iterator[Dict[str, Any]]:
    """AE-OS events for each tool-call span in an OTLP/JSON traces payload."""
    if not isinstance(payload, dict):
        raise EventError("an OTLP payload must be a JSON object")
    for rs in payload.get("resourceSpans", []):
        resource = _attributes((rs.get("resource") or {}).get("attributes", []))
        for ss in rs.get("scopeSpans", []):
            for span in ss.get("spans", []):
                a = _attributes(span.get("attributes", []))
                if not _is_tool_span(a):
                    continue
                tool = a.get("gen_ai.tool.name") or a.get("mcp.method.name")
                call_id = str(a.get("gen_ai.tool.call.id") or a.get("jsonrpc.request.id")
                              or span.get("spanId") or "")
                trace = span.get("traceId")
                sid = a.get("mcp.session.id") or (f"otel-trace:{trace}" if trace else None)
                source = {"trace_id": trace, "span_id": span.get("spanId"),
                          "service": resource.get("service.name"),
                          "reported_agent": (a.get("gen_ai.agent.id")
                                             or a.get("gen_ai.agent.name"))}
                source = {k: str(v) for k, v in source.items() if v}
                common = {"tool": tool, "call_id": call_id, "session_id": sid,
                          "source": source}
                call = {"event": "tool.call", **common,
                        "ts": int(span.get("startTimeUnixNano", 0)) // 1_000_000 or None}
                if "gen_ai.tool.call.arguments" in a:
                    call["arguments"] = _structured(a["gen_ai.tool.call.arguments"])
                yield {k: v for k, v in call.items() if v is not None}
                failed = (span.get("status") or {}).get("code") in (2, "STATUS_CODE_ERROR") \
                    or "error.type" in a
                outcome = "ok"
                if failed:
                    outcome = "rpc-error" if "rpc.response.status_code" in a else "error"
                result = {"event": "tool.result", **common, "outcome": outcome,
                          "ts": int(span.get("endTimeUnixNano", 0)) // 1_000_000 or None}
                if "gen_ai.tool.call.result" in a:
                    result["result"] = _structured(a["gen_ai.tool.call.result"])
                elif failed and "error.type" in a:
                    result["error"] = {"error.type": a["error.type"]}
                yield {k: v for k, v in result.items() if v is not None}
