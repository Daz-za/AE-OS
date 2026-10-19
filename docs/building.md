# Build your own AE-OS

This guide shows how to describe your organization, add your own tools and rules, and connect your own agents. It assumes `aeos` is installed (see [getting-started.md](getting-started.md)).

## The workspace

A workspace is a folder with one file, `workspace.json`, that describes your organization:

| Section | What it holds |
|---|---|
| `organization` | The name, and a domain name your organization controls, such as `acme.example`. Every person, agent and service gets an identity under it, such as `spiffe://acme.example/agent/accounts-payable` |
| `people` | Each person, and whether they are a controller (opens and closes months in the books) or an approver (releases payments that the rules hold back) |
| `agents` | Each AI agent: the person who authorizes it, its purpose, its tools, its limit per call, its total budget and how many hours the authority lasts |
| `systems` | Where the tools come from: the example ERP, a Python file of your own, or an MCP server |
| `rules` | The built-in payment rules, your own compiled rules, or none |
| `books` | The legal entity, the ledger, the currency and the chart of accounts |
| `witnesses` | Independent services that countersign each checkpoint, a signed summary of the log so far, and how many must sign |

Create one from the example and open it in your web browser:

```
aeos new my-aeos
aeos ui my-aeos
```

In the **Build** tab you can edit every section. A map at the top shows how a call travels from a person to an agent, through the gateway's checks, to your systems, the books and the log. **Save and apply** checks the file and saves it. When the page runs the platform, it restarts it with the new file; when `aeos up` runs it, restart `aeos up`. You can also edit `workspace.json` in any text editor and run `aeos check my-aeos` to find mistakes.

The **Try it** tab lets you act as one of your agents. Choose a tool, fill in the arguments and send the call. The page shows each check the call passed or failed, in the order the gateway ran them:

| Check | What it asks |
|---|---|
| Identity | Did the agent prove who it is with a valid certificate, over mutual TLS? |
| Allow list | Is this tool one of the agent's tools? |
| Delegated authority | Does the agent's capability token (the token that carries the authority a person signed for it) cover this tool and this amount, within the budget and the time? |
| Rules | Do your rules allow it, refuse it, or send it to a person? |
| Approval | When the rules sent it to a person, did an approver sign an approval of this exact call? |
| Tool | Did the tool run? |
| Books of account | For a journal entry: does it balance, use known accounts, and fall in an open month? |
| Receipt | Was the call recorded, and has a signed checkpoint sealed it? |

The buttons above the form run ready-made cases, such as a payment that needs approval or an agent without the tool trying to pay. When a call waits for approval, choose who signs and approve or reject it.

The **Decisions**, **Books**, **Agents** and **Records** tabs show what happened, and each refused or escalated call has a **Show each check** button. **Audit** runs the auditor's check of the whole folder.

## Run it without the browser

```
aeos up my-aeos
```

This runs the platform until you press Ctrl+C, when it seals the log and the witnesses cosign it. From another terminal:

```
aeos call my-aeos --as accounts-payable erp.invoice.get invoice=INV-1001
aeos call my-aeos --as accounts-payable erp.invoice.pay invoice=INV-1002 amount_minor=780000 --approve-as cfo
aeos period my-aeos 2026-10 close --as controller
aeos seal my-aeos
aeos decisions my-aeos
aeos trace my-aeos 8
aeos audit my-aeos
```

Amounts in tool calls are in minor units: `amount_minor=780000` is 7,800.00. `aeos trace` shows the checks for any recorded call, by its record number. Without `aeos up` running, `aeos call` starts the platform for that one call.

## Connect your own tools

### A Python file

Put a Python file in the workspace folder that defines `TOOLS`, a dictionary of tool name to function. Each function receives the call's arguments as a dictionary and returns something JSON can hold.

```python
# my-aeos/crm.py
CUSTOMERS = {"C-7": {"name": "Bolt Logistics", "credit_limit_minor": 5_000_000}}

def get_customer(args):
    return {"customer": args["id"], **CUSTOMERS[args["id"]]}

TOOLS = {"crm.customer.get": get_customer}
```

Add it to `systems` and give the tool to an agent:

```json
{"id": "crm", "type": "python", "file": "crm.py"}
```

An exception raised by the function is returned to the agent as the tool's error, and recorded.

If your rules need facts the call does not carry, such as the invoice a payment names, define `facts(tool, args)` in the same file. It returns a dictionary that is added to what the rules see.

### An MCP server

Any MCP server that runs as a local process over standard input and output can provide tools:

```json
{"id": "files", "type": "mcp-stdio", "command": ["python3", "server.py"],
 "prefix": "files.", "tools": ["files.read"]}
```

`prefix` is added to the server's tool names, so tools from different servers cannot clash. List the prefixed names under `tools`, so they can be given to agents before the server starts.

## Write your own rules

Rules are written in [Rego](https://www.openpolicyagent.org/docs/policy-language) and compiled to WebAssembly with Open Policy Agent. The built-in payment rules, [policy/payments.rego](../policy/payments.rego), are a good starting point. Change the `package` line to match your entrypoint, for example `package acme.payments` for `acme/payments/decision`.

The gateway gives your rules this input on every call that passes the identity, allow list and authority checks:

```json
{"tool": "erp.invoice.pay", "agent": "spiffe://acme.example/agent/accounts-payable",
 "principal": "spiffe://acme.example/human/controller",
 "arguments": {"invoice": "INV-1002", "amount_minor": 780000},
 "invoice": {"vendor": "V-0907", "amount_minor": 780000, "currency": "USD", "status": "approved for payment"},
 "approval": {"approver": "spiffe://acme.example/human/cfo", "decision": "approve"}}
```

The rules call a supplier a vendor: `invoice.vendor`, and `data.sanctioned_vendors` holds the sanctioned suppliers. `invoice` comes from the example ERP (or your own `facts` function), and `approval` is present only when the agent repeats a call with a person's signed approval. The rule you name as the entrypoint must produce:

```json
{"decision": "allow" | "deny" | "escalate", "reasons": ["plain words for each reason"]}
```

Compile it and point the workspace at it:

```
opa build -t wasm -e acme/payments/decision my-rules.rego -o bundle.tar.gz
tar -xzf bundle.tar.gz
mv policy.wasm my-aeos/my-rules.wasm
```

```json
"rules": {"type": "wasm", "file": "my-rules.wasm", "entrypoint": "acme/payments/decision",
          "data": {"escalate_above_minor": 100000}}
```

`data` is what your rules read as `data`. The approvers marked under `people` are added as `data.approvers` unless you set them yourself. The audit runs the same compiled rules again on every recorded input. The workspace keeps a copy of each version in `policies/`, named by its SHA-256, so older records can still be checked after you change the rules.

## Connect your own agent

While `aeos up` or the browser page runs a workspace, each agent's connection files are in `my-aeos/private/connect/<agent>/`: its certificate and private key, the trust bundle (the certificates the agent uses to check the gateway), its capability token, and `gateway.json` with the port. From Python:

```python
from aeos import workspace

agent = workspace.remote_client("my-aeos", "accounts-payable")
agent.initialize()
reply = agent.call("erp.invoice.get", {"invoice": "INV-1001"})
agent.close()
```

Any MCP client can connect instead. It sends MCP requests as HTTP POSTs to `/mcp` over mutual TLS with the agent's certificate, checks that the gateway's certificate names `spiffe://<trust domain>/gateway/mcp`, and sends the token in the `AEOS-Capability` header. To repeat an escalated call, it adds the person's signed approval in the `AEOS-Approval` header.

Certificates last 15 minutes. The platform renews them every few minutes and rewrites the connection files, so read them again when you reconnect. In production, SPIRE, an identity service, issues each agent its certificate.

## Use the platform from code

```python
from aeos import workspace

with workspace.Platform("my-aeos") as platform:
    answer = platform.call("accounts-payable", "erp.invoice.pay",
                           {"invoice": "INV-1002", "amount_minor": 780000})
    for step in answer["trace"]["steps"]:
        print(step["label"], step["state"], step["text"])
    if answer["trace"]["outcome"] == "waiting":
        platform.approve(answer["trace"]["escalation"], "cfo")
```

Leaving the `with` block seals the log. The parts are also usable on their own: `identity`, `delegation`, `policy`, `books`, `gateway`, `witness`, `log` and `audit`. [`fulldemo.py`](../python/src/aeos/fulldemo.py) wires them together step by step.

## What the folder holds

| Path | What it is |
|---|---|
| `workspace.json` | Your description of the organization |
| `log/` | The receipt log: every record and signed checkpoint |
| `evidence.json`, `trust/`, `svids/`, `intents/`, `tokens/`, `policies/`, `witnesses.json` | What an auditor needs, besides the log |
| `private/` | Private keys, the connection files and the example ERP's payments. Never give this folder to anyone |

To give an auditor the evidence, copy the folder without `private/`. They run `aeos audit` on it, with your public keys, which they get from you through a channel they trust.

## Limits of this preview

- The people's signing keys are files in `private/people/`, so the platform can sign an authority or an approval for a person when you ask it to. In production each person signs with their own passkey or smart card.
- The local identity service stands in for SPIRE and does no machine or workload attestation.
- One computer runs everything. The budget spent and open escalations are rebuilt from the log when the platform starts.
