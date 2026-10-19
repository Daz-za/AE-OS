# aeos

The Python library, command line and browser workspace for [AE-OS](https://ae-os.org). It runs the AE-OS architecture on one computer: a certificate authority and SPIFFE identities for agents, delegated authority signed by a person, an MCP gateway, rules compiled to WebAssembly, books of account, witnesses, and a signed, independently verifiable receipt for every agent action.

Every action an agent takes becomes a record in an append-only Merkle log (the structure Certificate Transparency uses). The log operator signs checkpoints. Anyone holding the log's public key can then check, offline, that a given record is in the log and that the log has only grown since a checkpoint they kept earlier.

The format is specified in [spec/receipts-v0.md](../spec/receipts-v0.md).

## Install

```
pipx install "git+https://github.com/Daz-za/ae-os#subdirectory=python"
pip install -e python          # or, from a clone of this repository
```

Then run `aeos ui` to set up the workspace in your web browser (see [Build a workspace](#build-a-workspace)), or try `aeos demo` and create a log of your own with `aeos setup`. The [getting-started guide](../docs/getting-started.md) covers each step for people new to the command line.

Requires Python 3.10 or later, with the `cryptography`, `biscuit-python` and `wasmtime` packages (installed automatically). Rebuilding the example policy needs [OPA](https://www.openpolicyagent.org/); running it does not.

## Build a workspace

`aeos new FOLDER` writes `workspace.json`, one file that describes an organization, filled in from Kestrel Foods in the film on ae-os.org (`--example acme` for the smaller Acme example): legal entities, people, the instruction a person signs, agents with their tools, systems that provide tools (records in the file, an example ERP, a Python file, or an MCP server), rules, books of account and witnesses. `aeos build FOLDER` sets it up step by step and prints what each step made. `aeos ui FOLDER` does the same in a web browser. It draws the architecture with each call travelling through it, plays the film's close as real calls, and shows each part as a module with the code that uses it on its own. `aeos up FOLDER` runs the workspace for other programs, and `aeos call`, `aeos period`, `aeos seal` and `aeos trace` work from the terminal. The folder is also an evidence folder for `aeos audit`. See [docs/building.md](../docs/building.md).

## Work in the web browser

`aeos ui` opens a page on this computer. It starts with the workspace described above: **Start the guided tour** sets up Kestrel Foods and leads you through it, and **Continue** followed by a folder's name reopens a workspace you made earlier in the same folder. Under Other ways in, the page runs the short and narrated examples and opens any log or evidence folder. For an open folder it lists the records, agents, decisions and books, downloads receipts, signs checkpoints, checks receipts from other logs and runs the audit.

The page is served only at 127.0.0.1, this computer's own address. Each launch makes a new access code that is part of the address; other websites open in the same browser do not have it and cannot use the page. `aeos ui FOLDER` opens a workspace, log or evidence folder directly, and `--no-browser` prints the address so you can paste it into a browser on this computer.

## Record an agent's MCP tool calls

Put the proxy between the agent and any MCP server that runs over stdio:

```
aeos init ./ap-log --log-id urn:example:acme:ap
aeos mcp-proxy ./ap-log \
    --agent spiffe://acme.example/agent/accounts-payable \
    --on-behalf-of spiffe://acme.example/human/controller \
    --allow-tool erp.invoice.read --allow-tool erp.invoice.pay \
    -- python my_erp_mcp_server.py
```

Configure the agent to launch the `aeos mcp-proxy ...` command in place of the server command. The proxy passes messages through unchanged and records a `tool.call` and a `tool.result` for every tool use. With `--allow-tool`, calls to other tools are refused before they reach the server and the refusal is recorded. Records hold SHA-256 digests of arguments and results; add `--store-content` to also keep the full content beside the log.

## Record tool calls from a gateway or agent framework

The MCP proxy above works when the agent talks to its MCP servers over stdio. For agents that reach their tools through a gateway, or agents built on a framework, the log can receive tool-call reports instead. Each report becomes the same `tool.call` and `tool.result` records the proxy writes, so receipts and verification work the same way.

### From a gateway, over HTTP

```
export AEOS_SINK_TOKEN=$(python -c "import secrets; print(secrets.token_hex(24))")
aeos sink ./ap-log --agent spiffe://acme.example/gateway/edge-1 --listen 127.0.0.1:4318
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
aeos ingest ./ap-log events.jsonl --agent spiffe://acme.example/gateway/edge-1
aeos ingest ./ap-log traces.jsonl --format otlp --agent spiffe://acme.example/gateway/edge-1
```

A call reported again with the same `session_id` and `call_id` is recorded once, so a file can be ingested again safely. `ingest` signs a checkpoint when it finishes.

### From Claude Code

Claude Code runs hook commands before and after each tool use. Add this to `.claude/settings.json` to record every tool call and refuse tools outside an allow-list:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "aeos hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "aeos hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "aeos hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "PostToolUseFailure": [{"matcher": "*", "hooks": [{"type": "command", "command": "aeos hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}],
    "SessionEnd": [{"hooks": [{"type": "command", "command": "aeos hook ./ap-log --agent spiffe://acme.example/agent/claude-ap --allow-tool mcp__erp__invoice_read"}]}]
  }
}
```

If a `PreToolUse` event cannot be recorded, for example because the log is unavailable or the input is unreadable, the hook refuses the tool call so nothing runs without a record. Add `--fail-open` to let tools run anyway. The hook signs a checkpoint at session end.

### From the Claude Agent SDK

Agents built with the Claude Agent SDK for Python can call the same handler from a hook callback:

```python
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
from aeos import ReceiptLog, Recorder
from aeos.hooks import handle

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
from aeos import ReceiptLog, Recorder

rec = Recorder(ReceiptLog.open("ap-log"), agent="spiffe://acme.example/agent/ap")
call, refusal = rec.call("erp.invoice.pay", call_id="c-17", session_id="s-4",
                         arguments={"invoice": "INV-20417"})
rec.result("c-17", session_id="s-4", result={"payment": "PAY-88"})
rec.end("s-4")
```

## Give an auditor evidence

```
aeos checkpoint ./ap-log                     # sign the current state
aeos receipt ./ap-log 12 -o receipt.json     # receipt for record 12
aeos verify-receipt receipt.json --public-key <hex>

aeos consistency ./ap-log --old 40 -o proof.json   # log grew from size 40 without edits
aeos verify-consistency proof.json --public-key <hex>

aeos verify ./ap-log                         # recompute and check everything
aeos show ./ap-log                           # readable records
```

The auditor should get the public key from a source they trust, not from the files under review.

Auditors who prefer not to install anything can check receipts and growth proofs in a web browser at [ae-os.org/verify](https://ae-os.org/verify). The page runs [`verify.js`](src/aeos/ui/verify.js), the same checker that `aeos ui` uses; the files stay on the auditor's device. Its tests (`node --test src/aeos/ui/verify.test.mjs`) run the shared test vectors.

## Use it as a library

```python
from aeos import ReceiptLog, make_record, verify_receipt

log = ReceiptLog.create("ap-log")
e = log.append(make_record("tool.call", "spiffe://acme.example/agent/ap",
                           subject="erp.invoice.pay", body={"amount_minor": 125000}))
receipt = log.receipt(e)
assert verify_receipt(receipt, log.public_key) == []
```

`examples/invoice_demo.py` walks through an escalated invoice payment, the auditor's checks and a tampering attempt.

## The narrated example

`aeos demo --full` builds the AE-OS architecture one part at a time, with Acme's supplier payments as the example, and explains each part as it goes:

- a SPIFFE trust domain issues 15-minute X.509-SVIDs to agents and to an MCP gateway;
- a person signs an intent envelope (which tools, the limit per payment, the total budget, the expiry), and an authorization service turns it into a [Biscuit](https://www.biscuitsec.org/) capability token bound to the agent's SPIFFE ID; the agent can add checks to hand a narrower token to a helper, and nobody can remove one;
- the agent and the gateway authenticate each other over mutual TLS; the gateway checks the token against the identity in the agent's certificate, the tool, the amount and the time, meters the intent's budget, and records every call and decision;
- expired certificates and certificates not issued under the trust bundle's root are refused during the handshake, and an identity without permission for a tool is refused and recorded;
- payment rules written in Rego (`policy/payments.rego`) and compiled to WebAssembly run in a wasmtime sandbox on every call that passes the identity and token checks; a payment above the threshold runs only when the agent repeats it with an approver's signed approval, and the person who authorized the agent may not approve it;
- a books service keeps Acme's general ledger: an entry is recorded only if it balances and its date is in an open period, only a controller's signed period change opens or closes a period, and a correction is a reversal, dated in an open period, that cites the original entry, which stays unchanged;
- two witnesses cosign the log's checkpoint, and a witness refuses a rewritten history.

It leaves an evidence folder that `aeos audit FOLDER` checks from end to end. These commands describe it in plain language, and also accept a log folder:

```
aeos agents FOLDER      # who acted: people, agents and services, and what each did
aeos decisions FOLDER   # what was refused or sent to a person, and why (--all adds the allowed calls)
aeos books FOLDER       # periods, journal entries, refused entries and the trial balance
```

Each takes `--json` for other programs. They read what the log holds; `aeos audit` is the command that checks it. The audit replays every authorization decision from the token and the signed intent, runs the same compiled policy again on each recorded input, and rebuilds the books from their entries. The modules are `identity`, `delegation`, `policy`, `books`, `gateway`, `witness` and `audit`; the formats are in [spec/identity-and-witnesses-draft.md](../spec/identity-and-witnesses-draft.md). The local trust domain stands in for SPIRE and does no machine or workload attestation.

## Status and limits

Version 0.1 is an early release for evaluation.

- The signing key is a file. Keep it outside the log directory (`--key`) and away from the agent.
- The whole log is held in memory and hashed on load, which suits logs up to a few hundred thousand records. Each `aeos hook` call loads the log, so start a new log per agent or per period when a single log grows large.
- A receipt proves a record is in the log. Whether the log is complete depends on the agent being able to reach its tools only through a recorded path: the proxy, a gateway that reports to the sink, or the hook.
- The gateway meters each intent's total budget in its own memory, and several gateways do not share it. A workspace rebuilds the budget spent from the log when it starts.
