# aeos-receipts

Signed, independently verifiable receipts for AI agent actions. Part of [AE-OS](https://ae-os.org).

Every action an agent takes becomes a record in an append-only Merkle log (the structure Certificate Transparency uses). The log operator signs checkpoints. Anyone holding the log's public key can then check, offline, that a given record is in the log and that the log has only grown since a checkpoint they kept earlier.

The format is specified in [spec/receipts-v0.md](../spec/receipts-v0.md).

## Install

```
pip install -e python          # from a clone of this repository
```

Requires Python 3.9 or later and the `cryptography` package.

## Record an agent's MCP tool calls

Put the proxy between the agent and any MCP server that runs over stdio:

```
aeos-receipts init ./ap-log --log-id urn:example:acme:ap
aeos-receipts mcp-proxy ./ap-log \
    --agent spiffe://acme.example/agent/accounts-payable \
    --on-behalf-of spiffe://acme.example/human/controller \
    --allow-tool erp.invoice.read --allow-tool erp.invoice.pay \
    -- python my_erp_mcp_server.py
```

Configure the agent to launch the `aeos-receipts mcp-proxy ...` command in place of the server command. The proxy passes messages through unchanged and records a `tool.call` and a `tool.result` for every tool use. With `--allow-tool`, calls to other tools are refused before they reach the server and the refusal is recorded. Records hold SHA-256 digests of arguments and results; add `--store-content` to also keep the full content beside the log.

## Record tool calls from a gateway or agent framework

The MCP proxy above works when the agent talks to its MCP servers over stdio. For agents that reach their tools through a gateway, or agents built on a framework, the log can receive tool-call reports instead. Each report becomes the same `tool.call` and `tool.result` records the proxy writes, so receipts and verification work the same way.

### From a gateway, over HTTP

```
export AEOS_SINK_TOKEN=$(python -c "import secrets; print(secrets.token_hex(24))")
aeos-receipts sink ./ap-log --agent spiffe://acme.example/gateway/edge-1 --listen 127.0.0.1:4318
```

The sink accepts:

| Endpoint | Content |
|---|---|
| `POST /v1/traces` | OpenTelemetry traces as OTLP/JSON. Spans that follow the OpenTelemetry GenAI and MCP conventions for tool calls (`gen_ai.operation.name` set to `execute_tool`, or `mcp.method.name` set to `tools/call`) are recorded; other spans are skipped. Point the gateway's OTLP exporter at the sink with the protocol set to `http/json`, or add the sink as an extra exporter in an OpenTelemetry Collector. |
| `POST /v1/events` | AE-OS events, one JSON object or a list, for gateways with webhook or plugin support. The reply to a `tool.call` event says `allow` or `deny` under the sink's allow-list, so a gateway can enforce the decision it has just recorded. |
| `GET /healthz` | Liveness check |

When a token is set (`AEOS_SINK_TOKEN` or `--token-file`), POST requests must carry `Authorization: Bearer <token>`. A sink listening beyond localhost refuses to start without one. The sink records what its callers report, so give the token only to components that authenticate the agents themselves. It signs a checkpoint every 100 records (`--checkpoint-every`) and again when it stops.

Arguments and results are recorded as digests only when the report includes them. OpenTelemetry treats `gen_ai.tool.call.arguments` and `gen_ai.tool.call.result` as opt-in attributes, so turn them on in the gateway if auditors need to match arguments to records.

An AE-OS event looks like this. A `tool.call` needs `event`, `tool` and `call_id`, a `tool.result` needs `event` and `call_id`, and the other fields are optional:

```json
{"event": "tool.call", "tool": "erp.invoice.pay", "call_id": "c-17", "session_id": "s-4",
 "arguments": {"invoice": "INV-20417", "amount_minor": 1250000},
 "agent": "spiffe://acme.example/agent/accounts-payable", "on_behalf_of": "spiffe://acme.example/human/controller",
 "source": {"gateway": "edge-1"}}
{"event": "tool.result", "call_id": "c-17", "session_id": "s-4", "result": {"payment": "PAY-88"}}
```

A `tool.result` may carry `error` in place of `result`, or `result_sha256` (and `args_sha256` on a call) when the caller shares only digests. `session.start` and `session.end` events take a `session_id`; `session.end` records how many calls never got a result and signs a checkpoint.

### From files

Gateways that write audit logs to files, and the OpenTelemetry Collector's file exporter, can be recorded after the fact:

```
aeos-receipts ingest ./ap-log events.jsonl --agent spiffe://acme.example/gateway/edge-1
aeos-receipts ingest ./ap-log traces.jsonl --format otlp --agent spiffe://acme.example/gateway/edge-1
```

A call reported again with the same `session_id` and `call_id` is recorded once, so a file can be ingested again safely. `ingest` signs a checkpoint when it finishes.

### From Claude Code

Claude Code runs hook commands before and after each tool use. Add this to `.claude/settings.json` to record every tool call and refuse tools outside an allow-list:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "aeos-receipts hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "aeos-receipts hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "aeos-receipts hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "PostToolUseFailure": [{"matcher": "*", "hooks": [{"type": "command", "command": "aeos-receipts hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "SessionEnd": [{"hooks": [{"type": "command", "command": "aeos-receipts hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}]
  }
}
```

If a `PreToolUse` event cannot be recorded, for example because the log is unavailable or the input is unreadable, the hook refuses the tool call so nothing runs without a record. Add `--fail-open` to let tools run anyway. The hook signs a checkpoint at session end.

### From the Claude Agent SDK

Agents built with the Claude Agent SDK for Python can call the same handler from a hook callback:

```python
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
from aeos_receipts import ReceiptLog, Recorder
from aeos_receipts.hooks import handle

rec = Recorder(ReceiptLog.open("ap-log"), agent="spiffe://acme.example/agent/ap",
               allow_tools=["mcp__erp__invoice_read"])

async def record(input_data, tool_use_id, context):
    return handle(rec, input_data) or {}

options = ClaudeAgentOptions(hooks={
    event: [HookMatcher(hooks=[record])]
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure")
})
```

Call `rec.end(session_id)` when the agent's session finishes, to record it and sign a checkpoint.

### From your own code

`Recorder` is the piece all of the above share, and any framework's callbacks can use it:

```python
from aeos_receipts import ReceiptLog, Recorder

rec = Recorder(ReceiptLog.open("ap-log"), agent="spiffe://acme.example/agent/ap")
call, refusal = rec.call("erp.invoice.pay", call_id="c-17", session_id="s-4",
                         arguments={"invoice": "INV-20417"})
rec.result("c-17", session_id="s-4", result={"payment": "PAY-88"})
rec.end("s-4")
```

## Give an auditor evidence

```
aeos-receipts checkpoint ./ap-log                     # sign the current state
aeos-receipts receipt ./ap-log 12 -o receipt.json     # receipt for record 12
aeos-receipts verify-receipt receipt.json --public-key <hex>

aeos-receipts consistency ./ap-log --old 40 -o proof.json   # log grew from size 40 without edits
aeos-receipts verify-consistency proof.json --public-key <hex>

aeos-receipts verify ./ap-log                         # recompute and check everything
aeos-receipts show ./ap-log                           # readable records
```

The auditor should get the public key from a source they trust, not from the files under review.

## Use it as a library

```python
from aeos_receipts import ReceiptLog, make_record, verify_receipt

log = ReceiptLog.create("ap-log")
e = log.append(make_record("tool.call", "spiffe://acme.example/agent/ap",
                           subject="erp.invoice.pay", body={"amount_minor": 125000}))
receipt = log.receipt(e)
assert verify_receipt(receipt, log.public_key) == []
```

`examples/invoice_demo.py` walks through an escalated invoice payment, the auditor's checks and a tampering attempt.

## Status and limits

Version 0.1 is an early release for evaluation.

- The signing key is a file. Keep it outside the log directory (`--key`) and away from the agent; hardware or KMS keys are planned.
- The whole log is held in memory and hashed on load, which suits logs up to a few hundred thousand records. Each `aeos-receipts hook` call loads the log, so start a new log per agent or per period when a single log grows large.
- A receipt proves a record is in the log. Whether the log is complete depends on the agent being able to reach its tools only through a recorded path: the proxy, a gateway that reports to the sink, or the hook.
