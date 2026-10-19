import json

from aeos import ReceiptLog, cli, demo, fulldemo, report


def test_views_of_the_short_example(tmp_path, capsys):
    demo.run(tmp_path / "d", out=lambda _: None)
    log = ReceiptLog.open(tmp_path / "d" / "log")
    view = report.decisions(log)
    assert view["counts"] == {"ap-limits/v3": {"escalate": 1}}
    assert view["decisions"][0]["approvals"][0]["answer"] == "approve"   # linked by parent
    assert report.books_view(log) == {"ledgers": [], "refused": []}
    assert cli.main(["books", str(tmp_path / "d" / "log")]) == 0
    assert "holds no books" in capsys.readouterr().out


def test_commands_on_an_evidence_folder(tmp_path, capsys):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    capsys.readouterr()

    assert cli.main(["books", str(folder)]) == 0
    out = capsys.readouterr().out
    assert "6100 Professional fees" in out and "September 2026: closed" in out
    assert "debits (USD 1,250.00) and credits (USD 1,205.00) differ" in out

    assert cli.main(["decisions", str(folder)]) == 0
    out = capsys.readouterr().out
    assert "Books of account: 2 refused" in out
    # A refusal by the books names the agent that asked, not the books service.
    assert "agent/accounts-payable called ledger.post" in out
    assert "the tool is not on the session's allow list" in out

    assert cli.main(["agents", str(folder / "log"), "--json"]) == 0
    ids = {a["id"]: a for a in json.loads(capsys.readouterr().out)["identities"]}
    assert ids["spiffe://acme.example/service/books"]["entries"] == 4
    assert ids["spiffe://acme.example/human/controller-7f3c"]["period_changes"] == 2
    # Calls, not decisions: payroll's one call was refused by two checks; the books'
    # refusals count against the agent that asked.
    assert ids["spiffe://acme.example/agent/payroll"]["refused"] == 1
    assert ids["spiffe://acme.example/agent/accounts-payable"]["refused"] == 4

    assert cli.main(["books", str(tmp_path / "nowhere")]) == 2
