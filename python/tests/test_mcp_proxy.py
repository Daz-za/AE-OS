import io
import json
import sys
from pathlib import Path

from aeos_receipts import ReceiptLog, verify_receipt
from aeos_receipts.canon import json_digest
from aeos_receipts.mcp_proxy import run

SERVER = [sys.executable, str(Path(__file__).with_name("fake_mcp_server.py"))]
AGENT = "spiffe://acme.example/agent/ap-clerk/1"


def _session(tmp_path, messages, **kw):
    log = ReceiptLog.create(tmp_path / "log")
    stdin = io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in messages))
    stdout = io.BytesIO()
    opts = dict(agent=AGENT, on_behalf_of="spiffe://acme.example/human/cfo",
                allow_tools=None, store_content=False, checkpoint_every=0)
    opts.update(kw)
    code = run(log, SERVER, stdin=stdin, stdout=stdout, **opts)
    replies = [json.loads(x) for x in stdout.getvalue().splitlines()]
    return code, log, replies


def _call(i, name, args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def test_proxy_records_calls_and_results(tmp_path):
    code, log, replies = _session(tmp_path, [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _call(1, "invoice.pay", {"invoice": "INV-1", "amount": 1250}),
        _call(2, "invoice.read", {"invoice": "INV-2"}),
    ])
    assert code == 0
    assert [r["id"] for r in replies] == [0, 1, 2]
    recs = [log.record(e) for e in log.entries()]
    kinds = [r["kind"] for r in recs]
    assert kinds[0] == "session.start" and kinds[-1] == "session.end"
    assert kinds.count("tool.call") == 2 and kinds.count("tool.result") == 2
    call = next(r for r in recs if r["kind"] == "tool.call" and r["subject"] == "invoice.pay")
    assert call["body"]["args_sha256"] == json_digest({"invoice": "INV-1", "amount": 1250})
    assert call["obo"] == "spiffe://acme.example/human/cfo"
    result = next(r for r in recs if r["kind"] == "tool.result" and r["subject"] == "invoice.pay")
    assert result["body"]["outcome"] == "ok"
    assert log.verify().ok
    for e in log.entries():
        assert verify_receipt(log.receipt(e), log.public_key) == []


def test_allow_list_refuses_and_records_decision(tmp_path):
    code, log, replies = _session(tmp_path, [
        _call(1, "invoice.pay", {"invoice": "INV-9"}),
        _call(2, "invoice.read", {"invoice": "INV-9"}),
    ], allow_tools=["invoice.read"])
    by_id = {r["id"]: r for r in replies}
    assert by_id[1]["result"]["isError"] is True
    assert "Refused by AE-OS policy" in by_id[1]["result"]["content"][0]["text"]
    assert by_id[2]["result"]["isError"] is False
    recs = [log.record(e) for e in log.entries()]
    deny = [r for r in recs if r["kind"] == "policy.decision"]
    assert len(deny) == 1 and deny[0]["body"]["decision"] == "deny"
    assert sum(1 for r in recs if r["kind"] == "tool.result") == 1


def test_batch_refusal_does_not_reach_server(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    batch = [_call(1, "invoice.pay", {}), _call(2, "invoice.read", {})]
    stdin = io.BytesIO(json.dumps(batch).encode() + b"\n")
    stdout = io.BytesIO()
    # the fake server does not support batches, so only check what the proxy sent back
    run(log, [sys.executable, "-c", "import sys; [None for _ in sys.stdin]"], stdin=stdin,
        stdout=stdout, agent=AGENT, on_behalf_of=None, allow_tools=["invoice.read"],
        store_content=False, checkpoint_every=0)
    refused = json.loads(stdout.getvalue().splitlines()[0])
    assert [r["id"] for r in refused] == [1]


def test_store_content_keeps_arguments(tmp_path):
    _, log, _ = _session(tmp_path, [_call(1, "invoice.read", {"invoice": "INV-3"})],
                         store_content=True)
    files = list((tmp_path / "log" / "content").glob("*.json"))
    assert any("INV-3" in f.read_text() for f in files)


def test_cli_splits_server_command_at_double_dash(tmp_path, monkeypatch):
    from aeos_receipts import cli
    seen = {}
    monkeypatch.setattr(cli.mcp_proxy, "run",
                        lambda log, cmd, **kw: seen.update(cmd=cmd, **kw) or 0)
    cli.main(["init", str(tmp_path / "log")])
    assert cli.main(["mcp-proxy", str(tmp_path / "log"), "--agent", AGENT,
                     "--allow-tool", "x", "--", "server", "--port", "1"]) == 0
    assert seen["cmd"] == ["server", "--port", "1"] and seen["agent"] == AGENT
    assert seen["allow_tools"] == ["x"]
