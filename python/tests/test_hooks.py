import json
import subprocess
import sys

from aeos import ReceiptLog, Recorder
from aeos.hooks import run

AGENT = "spiffe://acme.example/agent/claude-ap"


def hook(event, **extra):
    return {"session_id": "sess-1", "transcript_path": "/tmp/t.jsonl", "cwd": "/work",
            "hook_event_name": event, **extra}


def test_hook_session(tmp_path):
    ReceiptLog.create(tmp_path / "log")

    def rec():
        return Recorder(ReceiptLog.open(tmp_path / "log"), agent=AGENT,
                        allow_tools=["mcp__erp__invoice_read"])

    events = [
        hook("SessionStart", source="startup"),
        hook("PreToolUse", tool_name="mcp__erp__invoice_read", tool_use_id="tu1",
             tool_input={"invoice": "INV-1"}),
        hook("PostToolUse", tool_name="mcp__erp__invoice_read", tool_use_id="tu1",
             tool_input={"invoice": "INV-1"}, tool_response={"amount": 1250}),
        hook("PreToolUse", tool_name="mcp__erp__invoice_pay", tool_use_id="tu2",
             tool_input={"invoice": "INV-1"}),
        hook("Notification", message="ignored"),
        hook("SessionEnd", reason="exit"),
    ]
    outputs = [run(rec, json.dumps(e)) for e in events]
    assert all(code == 0 for code, _, _ in outputs)
    denied = json.loads(outputs[3][1])["hookSpecificOutput"]
    assert denied["permissionDecision"] == "deny"
    log = ReceiptLog.open(tmp_path / "log")
    assert [log.record(e)["kind"] for e in log.entries()] == [
        "session.start", "tool.call", "tool.result", "tool.call", "policy.decision",
        "session.end"]
    assert log.record(log.entries()[-1])["body"]["unanswered_calls"] == 1
    assert log.verify().ok and log.checkpoints()[-1].size == 6


def test_hook_refuses_tool_when_it_cannot_record(tmp_path):
    def broken():
        return Recorder(ReceiptLog.open(tmp_path / "missing"), agent=AGENT)

    pre = json.dumps(hook("PreToolUse", tool_name="Bash", tool_use_id="tu1", tool_input={}))
    code, out, err = run(broken, pre)
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "could not record" in err
    code, out, _ = run(broken, pre, fail_open=True)
    assert code == 1 and out == ""


def test_hook_command_line(tmp_path):
    ReceiptLog.create(tmp_path / "log")
    cmd = [sys.executable, "-m", "aeos", "hook", str(tmp_path / "log"),
           "--agent", AGENT]
    ev = hook("PostToolUseFailure", tool_name="Bash", tool_use_id="tu9", tool_input={},
              error="command failed")
    p = subprocess.run(cmd, input=json.dumps(ev), capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    log = ReceiptLog.open(tmp_path / "log")
    r = log.record(log.entries()[-1])
    assert r["kind"] == "tool.result" and r["body"]["outcome"] == "error"


def test_unreadable_input_blocks():
    assert run(lambda: None, "not json")[0] == 2
    assert run(lambda: None, "not json", fail_open=True)[0] == 1
