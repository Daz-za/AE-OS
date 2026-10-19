"""Record the tool calls of agents built on the Claude Agent SDK or run in Claude Code.

Claude Code runs hook commands and the Agent SDK runs hook callbacks; both pass the event
as JSON. `aeos hook` (or `handle` from a callback) records these events:

    SessionStart         session.start
    PreToolUse           tool.call, and a refusal when the tool is outside the allow-list
    PostToolUse          tool.result with outcome "ok"
    PostToolUseFailure   tool.result with outcome "error"
    SessionEnd           session.end, then a signed checkpoint

Other events are ignored. If a tool call cannot be recorded, the hook refuses the call,
so no tool runs without a record; `fail_open` turns that off.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional, Tuple

from .recorder import Recorder

HANDLED = ("SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionEnd")


def _deny(reason: str) -> Dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def handle(rec: Recorder, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Record one hook event. Returns the JSON the hook should print, if any."""
    name = event.get("hook_event_name")
    sid = event.get("session_id")
    sid = str(sid) if sid else None
    extra = {"sub_agent": str(event["agent_type"])} if event.get("agent_type") else None
    if name == "SessionStart" and sid:
        rec.session(sid)
    elif name == "PreToolUse":
        tool = str(event.get("tool_name", ""))
        _, refusal = rec.call(tool, call_id=str(event.get("tool_use_id", "")), session_id=sid,
                              arguments=event.get("tool_input") or {}, extra=extra)
        if refusal:
            return _deny(f"Refused by AE-OS policy: {refusal} ({tool})")
    elif name == "PostToolUse":
        rec.result(str(event.get("tool_use_id", "")), session_id=sid,
                   result=event.get("tool_response"), tool=event.get("tool_name"))
    elif name == "PostToolUseFailure":
        rec.result(str(event.get("tool_use_id", "")), session_id=sid,
                   error={"error": event.get("error")}, tool=event.get("tool_name"))
    elif name == "SessionEnd" and sid:
        rec.end(sid)
    return None


def run(recorder: Callable[[], Recorder], raw: str, fail_open: bool = False
        ) -> Tuple[int, str, str]:
    """Process one hook invocation. `recorder` opens the log; it is called inside the
    error handling so a log that cannot be opened also refuses the tool call.
    Returns (exit code, stdout, stderr)."""
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("hook input must be a JSON object")
    except ValueError as e:
        # The event is unknown, so block it: exit status 2 refuses a PreToolUse call.
        return (1 if fail_open else 2), "", f"aeos hook: unreadable input: {e}\n"
    try:
        out = handle(recorder(), event)
    except Exception as e:  # report, and keep tools from running unrecorded
        msg = f"aeos hook: could not record {event.get('hook_event_name')}: {e}\n"
        if event.get("hook_event_name") == "PreToolUse" and not fail_open:
            return 0, json.dumps(_deny("AE-OS could not record this tool call")) + "\n", msg
        return 1, "", msg
    return 0, (json.dumps(out) + "\n") if out else "", ""
