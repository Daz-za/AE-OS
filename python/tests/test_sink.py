import io
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from aeos_receipts import ReceiptLog, Recorder
from aeos_receipts.sink import ingest, make_handler, serve

from test_events import otlp, span

AGENT = "spiffe://acme.example/gateway/edge-1"
TOKEN = "test-token"


@pytest.fixture
def server(tmp_path):
    rec = Recorder(ReceiptLog.create(tmp_path / "log"), agent=AGENT)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(rec, TOKEN))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield rec, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


def post(url, body, token=TOKEN, ctype="application/json"):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": ctype,
                                          "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_events_endpoint(server):
    rec, url = server
    code, doc = post(url + "/v1/events", [
        {"event": "tool.call", "tool": "erp.invoice.pay", "call_id": "c1", "session_id": "s1",
         "arguments": {"invoice": "INV-1"}},
        {"event": "tool.result", "call_id": "c1", "session_id": "s1", "result": {"ok": True}},
        {"event": "bogus"},
    ])
    assert code == 200
    assert [d["event"] for d in doc["recorded"]] == ["tool.call", "tool.result"]
    assert doc["recorded"][0]["decision"] == "allow"
    assert doc["problems"] == ["event 2: unknown event 'bogus'"]
    assert len(rec.log) == 3


def test_traces_endpoint(server):
    rec, url = server
    payload = otlp(span("tools/call t", {"mcp.method.name": "tools/call",
                                         "gen_ai.tool.name": "t", "jsonrpc.request.id": "1"}))
    assert post(url + "/v1/traces", payload) == (200, {})
    assert [rec.log.record(e)["kind"] for e in rec.log.entries()] == \
        ["session.start", "tool.call", "tool.result"]


def test_rejects_bad_token_and_protobuf(server):
    _, url = server
    assert post(url + "/v1/events", {}, token="wrong")[0] == 401
    assert post(url + "/v1/traces", {}, ctype="application/x-protobuf")[0] == 415


def test_open_sink_needs_a_token(tmp_path):
    rec = Recorder(ReceiptLog.create(tmp_path / "log"), agent=AGENT)
    with pytest.raises(ValueError):
        serve(rec, "0.0.0.0", 0, None)


def test_ingest_collector_file(tmp_path):
    rec = Recorder(ReceiptLog.create(tmp_path / "log"), agent=AGENT)
    lines = [json.dumps(otlp(span("tools/call t", {"mcp.method.name": "tools/call",
                                                    "gen_ai.tool.name": "t",
                                                    "jsonrpc.request.id": str(i)},
                                  span_id=f"{i:016x}"))) for i in range(3)]
    count, problems = ingest(rec, io.StringIO("\n".join(lines + ["not json"])), "otlp")
    assert count == 6 and len(problems) == 1 and problems[0].startswith("line 4:")
    assert len(rec.log) == 7


def test_malformed_otlp_is_a_client_error(server):
    _, url = server
    code, doc = post(url + "/v1/traces", {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"attributes": [{"key": "mcp.method.name", "value": {"stringValue": "tools/call"}}],
         "startTimeUnixNano": "soon"}]}]}]})
    assert code == 400 and doc["error"].startswith("unreadable payload")
