from aeos_receipts import ReceiptLog, Recorder
from aeos_receipts.canon import json_digest

AGENT = "spiffe://acme.example/agent/ap-clerk/1"


def _kinds(log):
    return [log.record(e)["kind"] for e in log.entries()]


def test_session_call_result_end_are_linked(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    rec = Recorder(log, agent=AGENT)
    call, refusal = rec.call("erp.invoice.pay", call_id="c1", session_id="s1",
                             arguments={"invoice": "INV-1"})
    assert refusal is None
    res = rec.result("c1", session_id="s1", result={"payment": "PAY-88"})
    rec.end("s1")
    assert _kinds(log) == ["session.start", "tool.call", "tool.result", "session.end"]
    start, c, r, end = [log.record(e) for e in log.entries()]
    assert c["parents"] == [log.entries()[0].cid] and r["parents"] == [call.cid]
    assert c["body"]["args_sha256"] == json_digest({"invoice": "INV-1"})
    assert r["subject"] == "erp.invoice.pay" and r["body"]["outcome"] == "ok"
    assert end["body"]["unanswered_calls"] == 0
    assert log.checkpoints()[-1].size == 4
    assert res.index == 2 and log.verify().ok


def test_repeated_reports_are_recorded_once(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    rec = Recorder(log, agent=AGENT)
    for _ in range(2):
        rec.call("t", call_id="c1", session_id="s1", arguments={})
        rec.result("c1", session_id="s1", result={})
    assert len(log) == 3


def test_a_second_process_finds_the_session_and_call(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    Recorder(log, agent=AGENT).call("t", call_id="c1", session_id="s1", arguments={})
    other = Recorder(ReceiptLog.open(tmp_path / "log"), agent=AGENT)
    other.result("c1", session_id="s1", error={"message": "timeout"})
    other.call("t", call_id="c2", session_id="s1", arguments={})
    other.end("s1")
    recs = [log.record(e) for e in ReceiptLog.open(tmp_path / "log").entries()]
    assert [r["kind"] for r in recs].count("session.start") == 1
    assert recs[2]["body"]["outcome"] == "error"
    assert recs[-1]["body"]["unanswered_calls"] == 1


def test_allow_list_refusal_is_recorded(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    rec = Recorder(log, agent=AGENT, allow_tools=["erp.invoice.read"])
    _, refusal = rec.call("erp.invoice.pay", call_id="c1", arguments={})
    assert refusal == "tool-not-in-allow-list"
    decision = log.record(log.entries()[-1])
    assert decision["kind"] == "policy.decision" and decision["body"]["decision"] == "deny"


def test_result_without_a_call_and_digest_only_inputs(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    rec = Recorder(log, agent=AGENT)
    rec.call("t", call_id="c1", args_sha256=b"\x11" * 32)
    rec.result("c9", result_sha256=b"\x22" * 32, tool="t")
    c, r = [log.record(e) for e in log.entries()]
    assert c["body"]["args_sha256"] == b"\x11" * 32 and c["parents"] == []
    assert r["body"]["call_seen"] is False and r["body"]["result_sha256"] == b"\x22" * 32


def test_checkpoint_every(tmp_path):
    log = ReceiptLog.create(tmp_path / "log")
    rec = Recorder(log, agent=AGENT, checkpoint_every=3)
    for i in range(4):
        rec.call("t", call_id=f"c{i}", session_id="s1", arguments={})
    assert [c.size for c in log.checkpoints()] == [3]
