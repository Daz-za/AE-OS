import json

import pytest

from aeos_receipts import ReceiptLog, Recorder
from aeos_receipts.canon import json_digest
from aeos_receipts.events import EventError, apply, otlp_events

AGENT = "spiffe://acme.example/gateway/edge-1"


def _attr(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}
    return {"key": k, "value": {"stringValue": v}}


def span(name, attrs, span_id="00f067aa0ba902b7", status=None):
    s = {"traceId": "4bf92f3577b34da6a3ce929d0e0e4736", "spanId": span_id,
         "name": name, "kind": 3, "startTimeUnixNano": "1760000000000000000",
         "endTimeUnixNano": "1760000000250000000",
         "attributes": [_attr(k, v) for k, v in attrs.items()]}
    if status:
        s["status"] = status
    return s


def otlp(*spans):
    return {"resourceSpans": [{
        "resource": {"attributes": [_attr("service.name", "acme-mcp-gateway")]},
        "scopeSpans": [{"scope": {"name": "gateway"}, "spans": list(spans)}]}]}


def test_mcp_tool_span_becomes_call_and_result(tmp_path):
    payload = otlp(
        span("tools/call erp.invoice.pay", {
            "mcp.method.name": "tools/call", "gen_ai.tool.name": "erp.invoice.pay",
            "jsonrpc.request.id": "42", "mcp.session.id": "sess-9",
            "gen_ai.tool.call.arguments": json.dumps({"invoice": "INV-1"})}),
        span("initialize", {"mcp.method.name": "initialize"}, span_id="1111111111111111"),
    )
    events = list(otlp_events(payload))
    assert [e["event"] for e in events] == ["tool.call", "tool.result"]
    call, result = events
    assert call["call_id"] == "42" and call["session_id"] == "sess-9"
    assert call["arguments"] == {"invoice": "INV-1"} and call["ts"] == 1760000000000
    assert call["source"]["service"] == "acme-mcp-gateway"
    assert result["outcome"] == "ok" and result["ts"] == 1760000000250

    log = ReceiptLog.create(tmp_path / "log")
    rec = Recorder(log, agent=AGENT)
    for ev in events:
        apply(rec, ev)
    for ev in otlp_events(payload):          # an exporter retry adds nothing
        apply(rec, ev)
    recs = [log.record(e) for e in log.entries()]
    assert [r["kind"] for r in recs] == ["session.start", "tool.call", "tool.result"]
    assert recs[1]["body"]["args_sha256"] == json_digest({"invoice": "INV-1"})
    assert recs[1]["body"]["source"]["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_failed_genai_tool_span():
    payload = otlp(span("execute_tool lookup", {
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup",
        "gen_ai.tool.call.id": "call_1", "error.type": "tool_error"},
        status={"code": 2}))
    call, result = otlp_events(payload)
    assert call["session_id"].startswith("otel-trace:") and call["call_id"] == "call_1"
    assert "arguments" not in call
    assert result["outcome"] == "error" and result["error"] == {"error.type": "tool_error"}


def test_event_validation(tmp_path):
    rec = Recorder(ReceiptLog.create(tmp_path / "log"), agent=AGENT, allow_tools=["a"])
    with pytest.raises(EventError):
        apply(rec, {"event": "tool.call", "call_id": "c1"})
    with pytest.raises(EventError):
        apply(rec, {"event": "tool.call", "tool": "a", "call_id": "c1", "args_sha256": "zz"})
    with pytest.raises(EventError):
        apply(rec, {"event": "nonsense"})
    out = apply(rec, {"event": "tool.call", "tool": "b", "call_id": "c2",
                      "agent": "spiffe://acme.example/agent/x"})
    assert out["decision"] == "deny" and out["reason"] == "tool-not-in-allow-list"
    assert rec.log.record(rec.log.entries()[0])["agent"] == "spiffe://acme.example/agent/x"
