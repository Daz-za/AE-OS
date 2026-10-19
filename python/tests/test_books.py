import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ReceiptLog, Recorder, audit, books, fulldemo, keys
from aeos.canon import cid_str
from aeos.log import make_record, now_ms

CONTROLLER = "spiffe://acme.example/human/controller"
CLERK = "spiffe://acme.example/human/clerk"
AGENT = "spiffe://acme.example/agent/ap"
SERVICE = "spiffe://acme.example/service/books"
ACCOUNTS = {"1000": "Bank", "2000": "Accounts payable", "5200": "Freight"}


def dr(account, amount):
    return {"account": account, "debit_minor": amount}


def cr(account, amount):
    return {"account": account, "credit_minor": amount}


@pytest.fixture
def setup(tmp_path):
    log = ReceiptLog.create(tmp_path / "log", log_id="urn:example:test")
    key, clerk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    people = {CONTROLLER: keys.public_bytes(key), CLERK: keys.public_bytes(clerk)}
    b = books.Books(log, agent=SERVICE, entity="ACME", ledger="0L", currency="USD",
                    accounts=ACCOUNTS, controllers={CONTROLLER: people[CONTROLLER]})

    def change(period, state, signer=key, by=CONTROLLER):
        return b.transition(books.PeriodTransition("ACME", "0L", period, state, by,
                                                   now_ms()).sign(signer))

    change("2026-09", "closed")
    change("2026-10", "open")
    rec = Recorder(log, agent=AGENT)
    calls = iter(range(1000))

    def post(**args):
        call, _ = rec.call(books.TOOL, call_id=str(next(calls)), arguments=args)
        return b.post(args, call)

    return log, b, post, change, people, clerk


def refused(post, **args):
    with pytest.raises(books.Refused) as e:
        post(**args)
    return e.value.reasons


def test_entries_must_balance_and_be_in_an_open_period(setup):
    log, b, post, *_ = setup
    one = post(date="2026-10-05", text="ok", lines=[dr("2000", 500), cr("1000", 500)])
    assert one["document"] == "ACME/2026/000001"
    assert refused(post, date="2026-10-05", lines=[dr("2000", 500), cr("1000", 499)]) == \
        ["debits (USD 5.00) and credits (USD 4.99) differ"]
    assert refused(post, date="2026-10-05", lines=[dr("2000", 500)]) == \
        ["an entry needs at least two lines"]
    assert "account 9999 is not in the chart of accounts" in \
        refused(post, date="2026-10-05", lines=[dr("9999", 5), cr("1000", 5)])
    assert "each line needs either a debit or a credit, in whole cents" in \
        refused(post, date="2026-10-05", lines=[dr("2000", 5.5), cr("1000", 5)])
    assert refused(post, date="2026-09-30", lines=[dr("2000", 5), cr("1000", 5)]) == \
        ["September 2026 is closed; date the entry in an open period"]
    assert refused(post, date="2026-11-01", lines=[dr("2000", 5), cr("1000", 5)]) == \
        ["November 2026 has not been opened"]
    two = post(date="2026-10-06", text="ok", lines=[dr("5200", 125), cr("2000", 125)])
    assert two["document"] == "ACME/2026/000002"          # refusals used no numbers
    denials = [log.record(e) for e in log.entries()
               if log.record(e)["kind"] == "policy.decision"]
    assert len(denials) == 6 and all(d["body"]["policy"] == books.POLICY for d in denials)
    assert b.balances() == {"2000": 375, "1000": -500, "5200": 125}


def test_reversal_undoes_an_entry_once(setup):
    log, b, post, *_ = setup
    post(date="2026-10-05", text="x", lines=[dr("5200", 125), cr("2000", 125)])
    undo = post(date="2026-10-07", text="duplicate", reverses="ACME/2026/000001")
    assert undo["document"] == "ACME/2026/000002"
    assert b.balances() == {"5200": 0, "2000": 0}
    assert refused(post, date="2026-10-07", reverses="ACME/2026/000001") == \
        ["document ACME/2026/000001 was already reversed by ACME/2026/000002"]
    assert refused(post, date="2026-10-07", reverses="ACME/2026/000099") == \
        ["document ACME/2026/000099 is not in these books"]
    assert "September 2026 is closed" in \
        refused(post, date="2026-09-07", reverses="ACME/2026/000002")[0]
    assert refused(post, date="2026-10-07", reverses="ACME/2026/000002",
                   lines=[dr("2000", 5), cr("1000", 5)]) == \
        ["a reversal takes its lines from the original entry; send either lines or reverses"]
    assert refused(post, date="19 Oct", lines=[dr("2000", 5), cr("1000", 5)]) == \
        ["the entry needs a date written as YYYY-MM-DD"]


def test_only_a_controller_changes_periods(setup):
    log, b, post, change, people, clerk = setup
    with pytest.raises(books.Refused):
        change("2026-09", "open", signer=clerk, by=CLERK)
    with pytest.raises(books.Refused):                   # claims to be the controller
        change("2026-09", "open", signer=clerk)
    assert b.periods["2026-09"] == "closed"


def replay(log, people):
    records = [(e.index, cid_str(e.cid), log.record(e)) for e in log.entries()]
    return books.replay(records, people)


def test_replay_rebuilds_the_books_and_catches_forged_entries(setup):
    log, b, post, change, people, _ = setup
    first = post(date="2026-10-05", text="x", lines=[dr("2000", 500), cr("1000", 500)])
    post(date="2026-10-06", text="undo", reverses=first["document"])
    summary, problems = replay(log, people)
    assert problems == [] and summary["entries"] == 2 and summary["reversals"] == 1
    assert summary["signers"] == [CONTROLLER] and summary["debits"] == 0

    period_change = log.entries()[0]                         # not a ledger.post call
    forged = {"entity": "ACME", "ledger": "0L", "document": "ACME/2026/000004",
              "period": "2026-09", "date": "2026-09-30", "currency": "USD", "text": "late",
              "lines": [dr("2000", 900), cr("1000", 800)]}
    log.append(make_record("journal.entry", SERVICE, subject=books.TOOL, body=forged,
                           parents=[period_change.cid]))
    bad_date = dict(forged, document="ACME/2026/000005", date="30/09/2026")
    log.append(make_record("journal.entry", SERVICE, subject=books.TOOL, body=bad_date,
                           parents=[period_change.cid]))
    _, problems = replay(log, people)              # a malformed date is reported, not raised
    assert any("needs a date written as YYYY-MM-DD" in p for p in problems)
    assert any("debits (USD 9.00) and credits (USD 8.00) differ" in p for p in problems)
    assert any("September 2026 is closed" in p for p in problems)
    assert any("breaks the numbering; expected ACME/2026/000003" in p for p in problems)
    assert any("not linked to a ledger.post call" in p for p in problems)

    _, problems = replay(log, {CONTROLLER: people[CLERK]})
    assert any("period change is not signed by" in p for p in problems)

    _, problems = books.replay([(e.index, cid_str(e.cid), log.record(e)) for e in log.entries()],
                               people, controllers=[CLERK], accounts={"1000": "Bank"},
                               service="spiffe://acme.example/service/other")
    assert any("who is not a controller" in p for p in problems)
    assert any("account 2000 is not in the chart of accounts" in p for p in problems)
    assert any("was not written by the books service" in p for p in problems)


def test_full_demo_books_pass_the_audit(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    findings, problems = audit.run(folder)
    assert problems == []
    found = next(f for f in findings if f.startswith("The books hold"))
    assert "4 journal entries" in found and "One is a reversal" in found
    assert "The books refused 2 entries" in found
