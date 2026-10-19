"""Walk through one agent paying one invoice, then check the evidence as an auditor would.

Run from the repository root after `pip install -e python`:

    python examples/invoice_demo.py
"""
import json
import tempfile
from pathlib import Path

from aeos import ReceiptLog, make_record, verify_consistency_doc, verify_receipt
from aeos.canon import json_digest

AGENT = "spiffe://acme.example/agent/accounts-payable/7f3a"
CONTROLLER = "spiffe://acme.example/human/controller/j-smith"

work = Path(tempfile.mkdtemp())
log = ReceiptLog.create(work / "ap-log", log_id="urn:example:acme:ap")

# 1. The agent session starts, acting for the controller.
session = log.append(make_record("session.start", AGENT, on_behalf_of=CONTROLLER,
                                 subject="erp-mcp-server", body={}))

# 2. The agent asks to pay an invoice above its authority limit, so policy escalates it.
args = {"invoice": "INV-20417", "vendor": "V-1182", "amount_minor": 1_250_000}
call = log.append(make_record("tool.call", AGENT, on_behalf_of=CONTROLLER,
                              subject="erp.invoice.pay",
                              body={"args_sha256": json_digest(args)}, parents=[session.cid]))
decision = log.append(make_record("policy.decision", AGENT, subject="erp.invoice.pay",
                                  body={"decision": "escalate", "policy": "ap-limits/v3",
                                        "reasons": ["above-agent-limit"]},
                                  parents=[call.cid]))

# 3. The controller approves; the payment goes through.
approval = log.append(make_record("approval", CONTROLLER, subject="erp.invoice.pay",
                                  body={"decision": "approve"}, parents=[decision.cid]))
result = log.append(make_record("tool.result", AGENT, on_behalf_of=CONTROLLER,
                                subject="erp.invoice.pay",
                                body={"outcome": "ok",
                                      "result_sha256": json_digest({"payment": "PAY-88"})},
                                parents=[approval.cid]))
first = log.checkpoint()

# 4. Later activity, and a new checkpoint.
log.append(make_record("session.end", AGENT, body={}, parents=[session.cid]))
second = log.checkpoint()

# 5. The auditor receives a receipt for the payment and the log's public key.
receipt = log.receipt(result, first)
print("Receipt check:", verify_receipt(receipt, log.public_key) or "valid")

# 6. The auditor kept the first checkpoint and asks for proof the log only grew since then.
proof = log.consistency(first, second)
print("Consistency check:", verify_consistency_doc(proof, log.public_key) or "valid")

# 7. The auditor confirms the payment arguments they were shown match the record.
recorded = log.record(call)["body"]["args_sha256"]
print("Arguments match record:", recorded == json_digest(args))

# 8. Someone changes the recorded decision from "escalate" to "allow". Verification catches it.
lines = (work / "ap-log" / "records.jsonl").read_text().splitlines()
d = json.loads(lines[2])
d["view"]["body"]["decision"] = "allow"
lines[2] = json.dumps(d)
(work / "ap-log" / "records.jsonl").write_text("\n".join(lines) + "\n")
print("Log after tampering:", ReceiptLog.open(work / "ap-log", read_only=True).verify().problems)
