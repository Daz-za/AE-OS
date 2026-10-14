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
- The whole log is held in memory and hashed on load, which suits logs up to a few hundred thousand records.
- A receipt proves a record is in the log. Whether the log is complete depends on the agent being unable to reach its tools except through the proxy.
