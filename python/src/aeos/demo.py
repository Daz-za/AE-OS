"""A guided walk-through: an AI agent pays an invoice and an auditor checks the evidence.

Run it with `aeos demo`. It leaves a small example log on disk so you can try
the other commands on it afterwards.
"""
from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path
from typing import Callable

from .canon import json_digest
from .log import ReceiptLog, make_record, verify_consistency_doc, verify_receipt

AGENT = "spiffe://acme.example/agent/accounts-payable"
CONTROLLER = "spiffe://acme.example/human/controller/j-smith"


def run(folder: Path, out: Callable[[str], None] = print) -> int:
    folder = Path(folder)
    if folder.exists() and any(folder.iterdir()):
        out(f"{folder} already has files in it. Choose an empty or new folder, for example:\n"
            f"  aeos demo {folder}-2")
        return 2
    step = 0

    def say(title: str, text: str) -> None:
        nonlocal step
        step += 1
        out(f"\n{step}. {title}")
        out(textwrap.fill(text, 88, initial_indent="   ", subsequent_indent="   "))

    out("AE-OS demo: an AI agent pays a supplier invoice at Acme, a fictional "
        "company,\nand an auditor checks the evidence.")

    log = ReceiptLog.create(folder / "log", log_id="urn:example:acme:accounts-payable",
                            key_path=None)
    say("A receipt log is created",
        f"The log lives in {folder / 'log'}. It also holds a signing key (signing.key). "
        "Anyone with the matching public key can check the log's receipts, and only the "
        "holder of the signing key can issue them. In real use, keep the signing key away "
        "from the log and from the agent.")

    session = log.append(make_record("session.start", AGENT, on_behalf_of=CONTROLLER,
                                     subject="erp", body={}))
    args = {"invoice": "INV-20417", "vendor": "V-1182", "amount_minor": 1_250_000}
    call = log.append(make_record("tool.call", AGENT, on_behalf_of=CONTROLLER,
                                  subject="erp.invoice.pay",
                                  body={"args_sha256": json_digest(args)},
                                  parents=[session.cid]))
    decision = log.append(make_record("policy.decision", AGENT, subject="erp.invoice.pay",
                                      body={"decision": "escalate", "policy": "ap-limits/v3",
                                            "reasons": ["above-agent-limit"]},
                                      parents=[call.cid]))
    say("The agent asks to pay an invoice",
        "The accounts payable agent, acting for the controller, asks to pay invoice "
        "INV-20417 for USD 12,500.00. The log records the request with a fingerprint of the "
        "payment details. The amount is above the agent's limit, so the policy sends it to "
        "the controller for approval, and that decision is recorded too.")

    approval = log.append(make_record("approval", CONTROLLER, subject="erp.invoice.pay",
                                      body={"decision": "approve"}, parents=[decision.cid]))
    result = log.append(make_record("tool.result", AGENT, on_behalf_of=CONTROLLER,
                                    subject="erp.invoice.pay",
                                    body={"outcome": "ok",
                                          "result_sha256": json_digest({"payment": "PAY-88"})},
                                    parents=[approval.cid]))
    first = log.checkpoint()
    say("The controller approves and the payment is made",
        "The approval and the payment are recorded, each linked to the record before it. "
        f"The log then signs a checkpoint: a sealed statement that it held {first.size} "
        "records with this exact content at this moment.")

    receipt = log.receipt(result, first)
    (folder / "payment-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (folder / "public-key.txt").write_text(log.public_key.hex() + "\n")
    problems = verify_receipt(receipt, log.public_key)
    say("The auditor checks a receipt for the payment",
        "The auditor receives payment-receipt.json and the log's public key "
        "(public-key.txt). With nothing else, they confirm the payment record is in the "
        "signed log. Result: " + ("VALID" if not problems else "INVALID " + str(problems)))

    log.append(make_record("session.end", AGENT, body={}, parents=[session.cid]))
    second = log.checkpoint()
    proof = log.consistency(first, second)
    (folder / "growth-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    problems = verify_consistency_doc(proof, log.public_key)
    say("Later, the auditor confirms nothing was rewritten",
        "The auditor kept the first checkpoint. When the log signs a new one, a short "
        "proof shows the new log still contains the earlier records unchanged. Result: "
        + ("VALID" if not problems else "INVALID " + str(problems)))

    recorded = log.record(call)["body"]["args_sha256"]
    say("The auditor matches the invoice to the record",
        "The auditor takes the payment details from the company's accounting system (ERP), computes their fingerprint "
        "and compares it with the one in the log. Match: "
        + ("yes" if recorded == json_digest(args) else "no"))

    copy = folder / "tampered-copy"
    shutil.copytree(folder / "log", copy, ignore=shutil.ignore_patterns("signing.key"))
    lines = (copy / "records.jsonl").read_text().splitlines()
    d = json.loads(lines[decision.index])
    d["view"]["body"]["decision"] = "allow"
    lines[decision.index] = json.dumps(d)
    (copy / "records.jsonl").write_text("\n".join(lines) + "\n")
    found = ReceiptLog.open(copy, read_only=True).verify().problems
    say("Someone edits the record afterwards, and verification catches it",
        "In a copy of the log (tampered-copy), the policy decision is changed from "
        "\"escalate\" to \"allow\", as if the payment never needed approval. Checking the "
        "copy finds it: " + "; ".join(found) + ". In plain terms, the record was changed "
        "after it was signed, so its content no longer matches its fingerprint.")

    out("\nThe example files are in " + str(folder) + ". Try:")
    out(f"  aeos status {folder / 'log'}")
    out(f"  aeos show {folder / 'log'}")
    out(f"  aeos verify-receipt {folder / 'payment-receipt.json'} "
        f"--public-key {folder / 'public-key.txt'}")
    out(f"  aeos verify {folder / 'tampered-copy'}")
    out("To start a log of your own, run: aeos setup")
    return 0
