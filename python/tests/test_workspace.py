import datetime as dt
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aeos import audit, cli, report, workspace

FAKE_MCP = Path(__file__).with_name("fake_mcp_server.py")
TODAY = f"{dt.date.today():%Y-%m-%d}"


@pytest.fixture
def ws(tmp_path):
    return workspace.create(tmp_path / "acme")


def steps(answer):
    return {s["step"]: s["state"] for s in answer["trace"]["steps"]}


def test_the_example_is_ready_and_mistakes_are_named(ws):
    assert workspace.check(workspace.load(ws), ws) == []
    doc = workspace.example()
    doc["agents"][0]["authorized_by"] = "nobody"
    doc["agents"][0]["tools"].append("crm.customer.get")
    doc["agents"][0]["budget"] = "5.00"
    doc["people"][1]["approver"] = False
    doc["witnesses"]["required"] = 3
    problems = workspace.check(doc, ws)
    assert "agent accounts-payable: authorized by must name one of the people" in problems
    assert "agent accounts-payable: no system provides crm.customer.get" in problems
    assert "agent accounts-payable: the budget is smaller than the limit per call" in problems
    assert any(p.startswith("rules: mark at least one person as an approver") for p in problems)
    assert any(p.startswith("witnesses: how many") for p in problems)
    with pytest.raises(workspace.WorkspaceError):
        workspace.save(ws, doc)
    with pytest.raises(workspace.WorkspaceError):
        workspace.create(ws)                     # not an empty folder


def test_amounts():
    assert workspace.minor("4200.00") == 420_000
    assert workspace.minor("1,250.5") == 125_050
    assert workspace.minor(7) == 700
    for bad in ("-1", "1.001", "ten"):
        with pytest.raises(ValueError):
            workspace.minor(bad)


def test_calls_pass_each_check_and_the_evidence_audits(ws):
    p = workspace.Platform(ws)
    p.start()
    try:
        got = p.call("accounts-payable", "erp.invoice.get", {"invoice": "INV-1001"})
        assert got["ok"] and got["result"]["amount_minor"] == 420_000
        assert steps(got) == {"identity": "pass", "allow": "pass", "authority": "pass",
                              "rules": "pass", "tool": "pass", "receipt": "pass"}

        big = {"invoice": "INV-1002", "amount_minor": 780_000}
        waiting = p.call("accounts-payable", "erp.invoice.pay", big)
        assert waiting["trace"]["outcome"] == "waiting"
        assert steps(waiting)["approval"] == "wait" and steps(waiting)["tool"] == "skip"
        esc = waiting["trace"]["escalation"]
        own = p.approve(esc, "controller")       # authorized the agent: may not approve
        assert own["trace"]["outcome"] == "refused"
        done = p.approve(esc, "cfo")
        assert done["ok"] and done["result"]["payment"].startswith("PAY-")
        assert steps(done)["approval"] == "pass"
        approval = next(s for s in done["trace"]["steps"] if s["step"] == "approval")
        assert "Chief financial officer" in approval["text"]
        first = report.trace(p.log, str(waiting["trace"]["call"]))
        assert first["outcome"] == "answered"

        sanctioned = p.call("accounts-payable", "erp.invoice.pay",
                            {"invoice": "INV-1003", "amount_minor": 95_000})
        assert "sanctions list" in sanctioned["text"] and steps(sanctioned)["rules"] == "fail"
        again = p.call("accounts-payable", "erp.invoice.pay", big)   # paid already
        assert "not approved for payment" in again["text"]

        not_allowed = p.call("reporting", "erp.invoice.pay", big)
        assert steps(not_allowed)["allow"] == "fail"
        assert steps(not_allowed)["authority"] == "fail"

        lines = [{"account": "6100", "debit_minor": 780_000},
                 {"account": "2000", "credit_minor": 780_000}]
        booked = p.call("accounts-payable", "ledger.post",
                        {"date": TODAY, "text": "INV-1002", "lines": lines})
        assert steps(booked)["books"] == "pass"
        assert booked["result"]["document"].endswith("/000001")
        p.change_period(TODAY[:7], "closed", "controller")
        late = p.call("accounts-payable", "ledger.post",
                      {"date": TODAY, "text": "late", "lines": lines})
        assert steps(late)["books"] == "fail" and "is closed" in late["text"]
        with pytest.raises(workspace.WorkspaceError):
            p.change_period(TODAY[:7], "open", "cfo")      # not a controller
    finally:
        p.stop()
    findings, problems = audit.run(ws)
    assert problems == []

    # A restart keeps the books, the budget spent and the paid invoices.
    p = workspace.Platform(ws)
    p.start()
    try:
        assert sum(p.gateway.budget.spent.values()) == 780_000
        assert p.ledger.periods[TODAY[:7]] == "closed"
        p.change_period(TODAY[:7], "open", "controller")
        booked = p.call("accounts-payable", "ledger.post",
                        {"date": TODAY, "text": "next", "lines": lines})
        assert booked["result"]["document"].endswith("/000002")
        p.renew()                                   # new certificates; calls still work
        assert p.call("reporting", "erp.invoice.list", {})["ok"]
    finally:
        p.stop()
    assert audit.run(ws)[1] == []


def test_an_open_escalation_survives_a_restart(ws):
    big = {"invoice": "INV-1002", "amount_minor": 780_000}
    with workspace.Platform(ws) as p:
        esc = p.call("accounts-payable", "erp.invoice.pay", big)["trace"]["escalation"]
    with workspace.Platform(ws) as p:
        assert esc in p.gateway.escalations
        with pytest.raises(workspace.WorkspaceError):
            p.approve(esc, "cfo")               # the arguments are not known here
        assert p.approve(esc, "cfo", args=big)["ok"]
    assert audit.run(ws)[1] == []


def test_your_own_tools_from_python_and_an_mcp_server(ws):
    (ws / "crm.py").write_text(
        "TOOLS = {'crm.customer.get': lambda args: {'customer': args['id'], 'name': 'Bolt'}}\n")
    shutil.copy(FAKE_MCP, ws / "server.py")
    doc = workspace.load(ws)
    doc["systems"] += [{"id": "crm", "type": "python", "file": "crm.py"},
                       {"id": "files", "type": "mcp-stdio",
                        "command": [sys.executable, "server.py"], "prefix": "files.",
                        "tools": ["files.invoice.read"]}]
    doc["agents"][1]["tools"] += ["crm.customer.get", "files.invoice.read"]
    workspace.save(ws, doc)
    with workspace.Platform(ws) as p:
        got = p.call("reporting", "crm.customer.get", {"id": "C-7"})
        assert got["result"] == {"customer": "C-7", "name": "Bolt"}
        got = p.call("reporting", "files.invoice.read", {"n": 1})
        assert got["ok"] and "done invoice.read" in json.dumps(got["result"])
    assert audit.run(ws)[1] == []


def test_your_own_compiled_rules(ws):
    shutil.copy(workspace.PAYMENTS_WASM, ws / "my-rules.wasm")
    doc = workspace.load(ws)
    doc["rules"] = {"type": "wasm", "file": "my-rules.wasm",
                    "entrypoint": "aeos/payments/decision",
                    "data": {"escalate_above_minor": 0, "sanctioned_vendors": []}}
    workspace.save(ws, doc)
    with workspace.Platform(ws) as p:
        got = p.call("accounts-payable", "erp.invoice.pay",
                     {"invoice": "INV-1003", "amount_minor": 95_000})
        assert got["trace"]["outcome"] == "waiting"      # every payment needs approval now
    assert audit.run(ws)[1] == []


def test_command_line(ws, capsys):
    assert cli.main(["check", str(ws)]) == 0
    assert cli.main(["call", str(ws), "--as", "accounts-payable", "erp.invoice.pay",
                     "invoice=INV-1002", "amount_minor=780000", "--approve-as", "cfo"]) == 0
    out = capsys.readouterr().out
    assert "WAIT" in out and "Approved by Chief financial officer" in out
    assert cli.main(["period", str(ws), TODAY[:7], "close", "--as", "controller"]) == 0
    assert cli.main(["seal", str(ws)]) == 0
    capsys.readouterr()
    assert cli.main(["call", str(ws), "--as", "reporting", "erp.invoice.get",
                     "invoice=INV-1001", "--json"]) == 0
    answer = json.loads(capsys.readouterr().out)["answers"][0]
    assert cli.main(["trace", str(ws), str(answer["trace"]["call"])]) == 0
    assert "Reporting agent used erp.invoice.get" in capsys.readouterr().out
    assert cli.main(["audit", str(ws)]) == 0


@pytest.mark.skipif(os.name == "nt", reason="sends SIGTERM")
def test_up_serves_agents_from_another_process(ws, capsys):
    proc = subprocess.Popen([sys.executable, "-m", "aeos", "up", str(ws)],
                            stdout=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if workspace.running(ws):
                break
            time.sleep(0.1)
        assert workspace.running(ws)
        assert cli.main(["call", str(ws), "--as", "accounts-payable", "erp.invoice.pay",
                         "invoice=INV-1002", "amount_minor=780000", "--approve-as", "cfo"]) == 0
        assert cli.main(["period", str(ws), TODAY[:7], "close", "--as", "controller"]) == 0
        lines = '[{"account":"6100","debit_minor":5},{"account":"2000","credit_minor":5}]'
        assert cli.main(["call", str(ws), "--as", "accounts-payable", "ledger.post",
                         f"date={TODAY}", "text=x", f"lines={lines}"]) == 1
        assert "is closed" in capsys.readouterr().out    # the running books saw the change
    finally:
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=20)
    assert "Stopped" in out
    assert not (ws / "private" / "running.json").exists()
    assert audit.run(ws)[1] == []
