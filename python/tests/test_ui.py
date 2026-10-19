import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from aeos import ReceiptLog, ui
from aeos.log import verify_receipt


@pytest.fixture
def page(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    app, port = ui.App(), [0]
    server = ThreadingHTTPServer(("127.0.0.1", 0), ui.make_handler(app, "secret", port))
    port[0] = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def call(path, body=None, code="secret", host=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port[0]}{path}",
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"X-AEOS-Code": code})
        if host:
            req.add_header("Host", host)
        try:
            with urllib.request.urlopen(req) as res:
                return res.status, res.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    yield call
    server.shutdown()
    server.server_close()
    app.close()


def test_static_files_are_served_and_packaged(page):
    status, body = page("/")
    assert status == 200 and b"<title>AE-OS</title>" in body
    for name in ("/app.js", "/check.js", "/verify.js", "/style.css", "/check.css"):
        assert page(name)[0] == 200


def test_functions_need_the_access_code_and_a_local_host_name(page):
    assert page("/api/state", code="wrong")[0] == 403
    assert page("/api/state", host="attacker.example")[0] == 403
    assert page("/api/state")[0] == 200


def test_example_records_receipt_and_checks(page, tmp_path):
    status, body = page("/api/demo", {})
    state = json.loads(body)
    assert status == 200 and state["status"]["records"] == 6 and "1. A receipt log" in state["story"]

    records = json.loads(page("/api/records")[1])
    assert records["total"] == 6 and records["records"][2]["record"]["kind"] == "policy.decision"

    receipt = json.loads(page("/api/receipt?index=4")[1])
    key = bytes.fromhex(state["status"]["public_key"])
    assert verify_receipt(receipt, key) == []
    assert page("/api/receipt?index=99")[0] == 400

    check = json.loads(page("/api/verify", {})[1])
    assert check["ok"] and check["checkpoints"] == 2
    assert json.loads(page("/api/growth")[1])["type"] == "aeos-consistency/v0"


def test_create_and_open_a_log(page, tmp_path):
    status, body = page("/api/create", {"name": "Acme AP", "mode": "claude"})
    state = json.loads(body)
    assert status == 200 and state["status"]["log_id"] == "urn:aeos:acme-ap"
    assert "hooks" in state["next_steps"] and state["status"]["can_sign"]
    assert (tmp_path / "config" / "aeos" / "keys" / "acme-ap.key").exists()

    assert page("/api/create", {"name": "Acme AP"})[0] == 400        # folder already used
    status, body = page("/api/open", {"folder": str(tmp_path / "acme-ap-log")})
    assert status == 200 and json.loads(body)["key"].endswith("acme-ap.key")
    assert json.loads(page("/api/checkpoint", {})[1])["status"]["checkpoints"] == 1
    assert page("/api/open", {"folder": str(tmp_path / "nowhere")})[0] == 400


def test_find_key_prefers_the_log_folder(tmp_path):
    log = ReceiptLog.create(tmp_path / "log", log_id="urn:aeos:x", key_path=None)
    assert ui.find_key(log.path) == log.path / "signing.key"


def test_full_walk_through_shows_agents_decisions_books_and_audit(page, tmp_path):
    assert page("/api/audit", {})[0] == 400                  # nothing open yet
    status, body = page("/api/full-demo", {})
    state = json.loads(body)
    assert status == 200 and state["evidence"] and state["story_kind"] == "full"
    assert state["key"].endswith("log-signing.key") and state["status"]["can_sign"]

    roles = {a["id"].rsplit("/", 1)[-1]: a["role"]
             for a in json.loads(page("/api/agents")[1])["identities"]}
    assert roles["books"] == "service" and roles["accounts-payable"] == "agent"

    view = json.loads(page("/api/decisions")[1])
    assert view["counts"]["Books of account"] == {"deny": 2}
    escalated = next(d for d in view["decisions"] if d["decision"] == "escalate")
    assert any(a["by"].endswith("cfo-2b81") for a in escalated["approvals"])
    everything = json.loads(page("/api/decisions?all=1")[1])["decisions"]
    assert len(everything) > len(view["decisions"])

    ledger = json.loads(page("/api/books")[1])["ledgers"][0]
    assert ledger["totals"] == {"debit": "USD 12,000.00", "credit": "USD 12,000.00",
                                "balanced": True}
    assert [p["state"] for p in ledger["periods"]] == ["closed", "open"]

    audit = json.loads(page("/api/audit", {})[1])
    assert audit["ok"] and audit["problems"] == []

    status, body = page("/api/open", {"folder": state["evidence"]})   # reopen by evidence folder
    assert status == 200 and json.loads(body)["evidence"] == state["evidence"]
    page("/api/demo", {})                                     # the short example has no evidence
    assert page("/api/audit", {})[0] == 400


def test_kestrel_is_set_up_step_by_step(page, tmp_path):
    status, body = page("/api/new-workspace", {"folder": str(tmp_path / "kestrel")})
    state = json.loads(body)
    assert status == 200 and state["workspace"] and "status" not in state   # no log yet
    ws = json.loads(page("/api/ws")[1])
    assert ws["running"]["organization"]["trust_domain"] == "kestrel.example"
    assert [s["state"] for s in ws["steps"]] == ["todo"] * len(ws["steps"])
    assert not ws["serving"]
    org = json.loads(page("/api/ws/step?step=organization")[1])
    assert org
    status, body = page("/api/ws/step", {"step": "pki"})
    assert status == 200
    ws = json.loads(page("/api/ws")[1])
    done = {s["id"] for s in ws["steps"] if s["state"] == "done"}
    assert done == {"organization", "pki"}
    pki = json.loads(page("/api/ws/step?step=pki")[1])
    assert "kestrel.example" in json.dumps(pki)

    page("/api/ws/step", {"step": "gateway"})
    ws = json.loads(page("/api/ws")[1])
    assert ws["serving"] and all(s["state"] == "done" for s in ws["steps"])
    assert [c["film"] for c in ws["chapters"]] == [1, 2, 3, 4, 5, 6]
    answer = json.loads(page("/api/ws/call", {"agent": "stock/02", "tool": "erp.stock.ageing",
                                              "args": {"site": "OHIO"}})[1])
    assert answer["trace"]["outcome"] == "done"
    feed = json.loads(page("/api/feed?after=0")[1])
    assert any(r["kind"] == "tool.call" for r in feed["records"])
    assert feed["total"] == json.loads(page("/api/state")[1])["status"]["records"]


def test_workspace_build_try_and_trace(page, tmp_path):
    status, body = page("/api/new-workspace", {"folder": str(tmp_path / "acme"), "example": "acme"})
    assert status == 200 and json.loads(body)["workspace"]
    page("/api/ws/step", {"step": "gateway"})
    ws = json.loads(page("/api/ws")[1])
    assert ws["problems"] == [] and "erp.invoice.pay" in ws["tools"]

    doc = ws["doc"]
    doc["agents"][0]["authorized_by"] = "nobody"
    saved = json.loads(page("/api/ws/save", {"doc": doc})[1])
    assert not saved["saved"] and saved["problems"]
    doc["agents"][0]["authorized_by"] = "controller"
    doc["rules"]["approval_above"] = "100.00"
    saved = json.loads(page("/api/ws/save", {"doc": doc})[1])
    assert saved["saved"] and saved["applied"]

    status, body = page("/api/ws/call", {"agent": "accounts-payable", "tool": "erp.invoice.pay",
                                         "args": {"invoice": "INV-1001", "amount_minor": 420000}})
    answer = json.loads(body)
    assert "trace" in answer, (body, json.loads(page("/api/ws")[1])["steps"])
    assert answer["trace"]["outcome"] == "waiting"
    status, body = page("/api/ws/approve", {"escalation": answer["trace"]["escalation"],
                                            "person": "cfo"})
    assert json.loads(body)["trace"]["outcome"] == "done"
    trace = json.loads(page(f"/api/trace?ref={answer['trace']['call']}")[1])
    assert trace["outcome"] == "answered"
    decisions = json.loads(page("/api/decisions")[1])["decisions"]
    assert decisions[0]["agent"] == "Accounts payable agent"
    assert json.loads(page("/api/ws/seal", {})[1])["witnesses"]
    assert json.loads(page("/api/audit", {})[1])["ok"]


def test_changes_that_cannot_start_are_not_saved(page, tmp_path):
    import sys
    page("/api/new-workspace", {"folder": str(tmp_path / "acme"), "example": "acme"})
    page("/api/ws/step", {"step": "gateway"})
    doc = json.loads(page("/api/ws")[1])["doc"]
    doc["systems"].append({"id": "broken", "type": "mcp-stdio", "tools": [],
                           "command": [sys.executable, "-c", "import sys; sys.exit(1)"]})
    saved = json.loads(page("/api/ws/save", {"doc": doc})[1])
    assert not saved["saved"] and "could not start" in saved["problems"][0]
    ws = json.loads(page("/api/ws")[1])                  # still open and running
    assert all(s["id"] != "broken" for s in ws["doc"]["systems"])
    status, body = page("/api/ws/call", {"agent": "reporting", "tool": "erp.invoice.list",
                                         "args": {}})
    assert status == 200 and json.loads(body)["ok"]
