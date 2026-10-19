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
