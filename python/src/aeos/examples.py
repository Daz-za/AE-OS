"""The example workspaces `aeos new` writes, and the close the browser page plays.

Kestrel Foods is the company in the film on ae-os.org: a US food group with a UK
subsidiary that has its own system and ledger, a bank called First Coast Bank, and a
quarter-end close run by agents under one instruction the CFO signed. Acme is the smaller
supplier-payments example used by the walk-through. Both are fictional, and every figure
in them is made up for the example.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List

FORMAT = "aeos-workspace/v0"
POST = "ledger.post"


def _entry(entity: str, date: str, text: str, debit: str, credit: str,
           amount: int) -> Dict[str, Any]:
    return {"entity": entity, "date": date, "text": text,
            "lines": [{"account": debit, "debit_minor": amount},
                      {"account": credit, "credit_minor": amount}]}


KESTREL: Dict[str, Any] = {
    "format": FORMAT,
    "organization": {
        "name": "Kestrel Foods", "trust_domain": "kestrel.example",
        "entities": [
            {"id": "KF-US", "name": "Kestrel Foods Inc.", "country": "United States"},
            {"id": "KF-UK", "name": "Kestrel Foods UK Ltd", "country": "United Kingdom"},
        ]},
    "people": [
        {"id": "cfo", "name": "CFO", "role": "Signs the close instruction and its limits",
         "approver": True},
        {"id": "controller", "name": "Controller",
         "role": "Owns the close calendar and period locks", "controller": True},
        {"id": "treasurer", "name": "Treasurer", "role": "Owns the bank accounts"},
        {"id": "head-of-tax", "name": "Head of Tax", "role": "Owns the tax provision"},
        {"id": "head-of-fpa", "name": "Head of FP&A", "role": "Owns the forecast"},
    ],
    "instructions": [
        {"id": "q3-close", "signed_by": "cfo",
         "purpose": "Close Q3 by 08:00 on 1 October. Send any adjustment above $250,000 "
                    "to me. No postings to closed periods. No payments.",
         "per_call_limit": "0.00", "budget": "0.00", "valid_hours": 18},
    ],
    "agents": [
        {"id": "bank-rec/01", "name": "Bank reconciliation agent", "team": "Cash",
         "instruction": "q3-close",
         "purpose": "Match September's bank lines and confirm the balance with First "
                    "Coast Bank",
         "tools": ["bank.statement.get", "bank.balance.confirm"]},
        {"id": "fx-reval/03", "name": "FX revaluation agent", "team": "Tax and FX",
         "instruction": "q3-close",
         "purpose": "Get the month-end exchange rates for revaluing EUR and GBP balances",
         "tools": ["bank.rates.get"]},
        {"id": "accruals/05", "name": "Accruals agent", "team": "Close",
         "instruction": "q3-close",
         "purpose": "Book September's accruals and prepayment releases",
         "tools": [POST], "entities": ["KF-US"]},
        {"id": "cutoff/01", "name": "Revenue cut-off agent", "team": "Revenue",
         "instruction": "q3-close",
         "purpose": "Check shipments around quarter end and defer revenue not yet earned",
         "tools": ["erp.shipments.cutoff", POST],
         "entities": ["KF-US"]},
        {"id": "stock/02", "name": "Inventory agent", "team": "Inventory",
         "instruction": "q3-close",
         "purpose": "Review stock ageing and propose write-downs",
         "tools": ["erp.stock.ageing", POST],
         "entities": ["KF-US"]},
        {"id": "ic-match/01", "name": "Intercompany agent, US", "team": "Intercompany",
         "instruction": "q3-close",
         "purpose": "Agree the balance Kestrel UK owes Kestrel Foods",
         "tools": ["erp.intercompany.balance"]},
        {"id": "ic-match/04", "name": "Intercompany agent, UK", "team": "Intercompany",
         "instruction": "q3-close",
         "purpose": "Agree the UK side and record goods in transit",
         "tools": ["uk-erp.intercompany.balance", POST],
         "entities": ["KF-UK"]},
    ],
    "systems": [
        {"id": "first-coast-bank", "type": "records", "name": "First Coast Bank", "tools": {
            "bank.statement.get": {"key": "account", "records": {
                "FCB-0042": {"entity": "KF-US", "month": "2026-09", "lines": 1204,
                             "matched": 1204, "open_items_cleared": 37}}},
            "bank.balance.confirm": {"key": "account", "records": {
                "FCB-0042": {"entity": "KF-US", "date": "2026-09-30",
                             "balance": "18400000.00", "confirmed_by": "First Coast Bank"}}},
            "bank.rates.get": {"key": "currency", "records": {
                "GBP": {"date": "2026-09-30", "usd_per_unit": "1.3420"},
                "EUR": {"date": "2026-09-30", "usd_per_unit": "1.1710"}}},
        }},
        {"id": "kestrel-erp", "type": "records", "name": "Kestrel ERP, US", "tools": {
            "erp.stock.ageing": {"key": "site", "records": {
                "OHIO": {"site": "Ohio warehouse", "older_than_180_days": "612000.00",
                         "of_which_seasonal": "202000.00",
                         "evidence": ["180-day ageing report", "3 count sheets",
                                      "sales forecast"]}}},
            "erp.shipments.cutoff": {"key": "quarter", "records": {
                "2026-Q3": {"shipments_checked": 2380, "orders_to_defer": 14,
                            "revenue_to_defer": "96400.00"}}},
            "erp.intercompany.balance": {"key": "counterparty", "records": {
                "KF-UK": {"entity": "KF-US", "receivable": "3214500.00",
                          "in_transit": [{"shipment": "KX-2291", "left": "2026-09-29",
                                          "arrives": "2026-10-02", "amount": "41300.00"}]}}},
        }},
        {"id": "kestrel-uk-erp", "type": "records", "name": "Kestrel ERP, UK", "tools": {
            "uk-erp.intercompany.balance": {"key": "counterparty", "records": {
                "KF-US": {"entity": "KF-UK", "payable": "3173200.00"}}},
        }},
    ],
    "rules": {"type": "close", "approval_above": "250000.00",
              "blocked_tools": {"bank.payment.send": "the close instruction allows no "
                                                    "payments"}},
    "books": {
        "ledger": "GL", "currency": "USD", "entities": ["KF-US", "KF-UK"],
        "accounts": {"1000": "Cash at First Coast Bank", "1250": "Intercompany receivable",
                     "1300": "Inventory", "1350": "Goods in transit",
                     "1400": "Prepaid insurance", "2000": "Trade payables",
                     "2100": "Accrued expenses", "2250": "Intercompany payable",
                     "2400": "Deferred revenue", "4000": "Revenue",
                     "5300": "Inventory write-down", "6200": "Utilities",
                     "6300": "Insurance", "6500": "Freight"},
        "periods": {"2026-07": "closed", "2026-08": "closed", "2026-09": "open"},
    },
    "witnesses": {"names": ["external-auditor", "industry-witness"], "required": 2},
}


ACME: Dict[str, Any] = {
    "format": FORMAT,
    "organization": {"name": "Acme", "trust_domain": "acme.example"},
    "people": [
        {"id": "controller", "name": "Financial controller", "controller": True},
        {"id": "cfo", "name": "Chief financial officer", "approver": True},
    ],
    "agents": [
        {"id": "accounts-payable", "name": "Accounts payable agent",
         "authorized_by": "controller",
         "purpose": "Pay approved supplier invoices and book them",
         "tools": ["erp.invoice.list", "erp.invoice.get", "erp.invoice.pay", POST],
         "per_call_limit": "10000.00", "budget": "20000.00", "valid_hours": 8},
        {"id": "reporting", "name": "Reporting agent", "authorized_by": "controller",
         "purpose": "Read invoices for the month-end report",
         "tools": ["erp.invoice.list", "erp.invoice.get"],
         "per_call_limit": "0.00", "budget": "0.00", "valid_hours": 8},
    ],
    "systems": [
        {"id": "erp", "type": "example-erp", "invoices": [
            {"invoice": "INV-1001", "supplier": "V-1182", "amount": "4200.00",
             "status": "approved for payment"},
            {"invoice": "INV-1002", "supplier": "V-0907", "amount": "7800.00",
             "status": "approved for payment"},
            {"invoice": "INV-1003", "supplier": "V-0666", "amount": "950.00",
             "status": "approved for payment"},
            {"invoice": "INV-1004", "supplier": "V-1182", "amount": "1250.00",
             "status": "awaiting approval"},
        ]},
    ],
    "rules": {"type": "payments", "approval_above": "5000.00",
              "sanctioned_suppliers": ["V-0666"]},
    "books": {"entity": "ACME-US", "ledger": "GL", "currency": "USD",
              "accounts": {"1000": "Bank", "2000": "Accounts payable", "5200": "Freight",
                           "6100": "Professional fees"}},
    "witnesses": {"names": ["external-auditor", "industry-witness"], "required": 2},
}

EXAMPLES = {"kestrel": KESTREL, "acme": ACME}


def example(name: str = "kestrel") -> Dict[str, Any]:
    if name not in EXAMPLES:
        raise ValueError(f"there is no example called {name}; choose "
                         + " or ".join(EXAMPLES))
    return copy.deepcopy(EXAMPLES[name])


# The quarter-end close from the film, as calls the agents make. Each chapter matches a
# chapter of the film on ae-os.org. "needs" names the agents a chapter uses, so a page can
# say when a changed workspace no longer has them.
CHAPTERS: List[Dict[str, Any]] = [
    {"id": "instruction", "title": "The instruction", "film": 1,
     "text": "The CFO signs one instruction for the close. Each agent receives a "
             "credential for its own task, carrying the instruction's limits.",
     "steps": []},
    {"id": "work", "title": "Agents at work", "film": 2,
     "text": "Each agent does one job within its credential, through the gateway.",
     "steps": [
         {"agent": "bank-rec/01", "tool": "bank.statement.get",
          "args": {"account": "FCB-0042"},
          "says": "Matches September's bank statement to the books"},
         {"agent": "bank-rec/01", "tool": "bank.balance.confirm",
          "args": {"account": "FCB-0042"},
          "says": "Confirms the balance with First Coast Bank"},
         {"agent": "fx-reval/03", "tool": "bank.rates.get", "args": {"currency": "GBP"},
          "says": "Gets the month-end pound to dollar rate"},
         {"agent": "accruals/05", "tool": POST,
          "args": _entry("KF-US", "2026-09-30", "Accrue September utilities", "6200",
                         "2100", 4_820_000),
          "says": "Accrues September utilities of $48,200"},
         {"agent": "accruals/05", "tool": POST,
          "args": _entry("KF-US", "2026-09-30", "Release prepaid insurance for September",
                         "6300", "1400", 1_250_000),
          "says": "Releases $12,500 of prepaid insurance"},
         {"agent": "cutoff/01", "tool": "erp.shipments.cutoff",
          "args": {"quarter": "2026-Q3"},
          "says": "Checks 2,380 shipments around quarter end for cut-off"},
         {"agent": "cutoff/01", "tool": POST,
          "args": _entry("KF-US", "2026-09-30", "Defer revenue on 14 orders shipped after "
                         "quarter end", "4000", "2400", 9_640_000),
          "says": "Defers $96,400 of revenue on 14 orders"},
     ]},
    {"id": "controls", "title": "The controls", "film": 3,
     "text": "The books refuse a posting into a closed month, and the rules send an "
             "adjustment above the CFO's $250,000 limit to the CFO for a decision.",
     "steps": [
         {"agent": "accruals/05", "tool": POST,
          "args": _entry("KF-US", "2026-08-31", "Freight invoice INV-7781", "6500", "2000",
                         1_820_000),
          "says": "Tries to post invoice INV-7781 for $18,200 into August, which the "
                  "Controller has closed"},
         {"agent": "stock/02", "tool": "erp.stock.ageing", "args": {"site": "OHIO"},
          "says": "Reads the stock ageing at the Ohio warehouse"},
         {"agent": "stock/02", "tool": POST,
          "args": _entry("KF-US", "2026-09-30", "Write down stock older than 180 days, "
                         "Ohio warehouse", "5300", "1300", 61_200_000),
          "says": "Proposes a $612,000 write-down, above the $250,000 limit the CFO set"},
     ]},
    {"id": "intercompany", "title": "Across companies", "film": 4,
     "text": "The two companies' agents compare balances, find the shipment in transit and "
             "agree one figure. Each agent may post only to its own company's books.",
     "steps": [
         {"agent": "ic-match/01", "tool": "erp.intercompany.balance",
          "args": {"counterparty": "KF-UK"},
          "says": "Kestrel Foods says Kestrel UK owes $3,214,500"},
         {"agent": "ic-match/04", "tool": "uk-erp.intercompany.balance",
          "args": {"counterparty": "KF-US"},
          "says": "Kestrel UK says it owes $3,173,200"},
         {"agent": "ic-match/04", "tool": POST,
          "args": _entry("KF-US", "2026-09-30", "Goods in transit, shipment KX-2291",
                         "1350", "2250", 4_130_000),
          "says": "Tries to post into Kestrel Foods' books, and the rules refuse it"},
         {"agent": "ic-match/04", "tool": POST,
          "args": _entry("KF-UK", "2026-09-30", "Goods in transit, shipment KX-2291",
                         "1350", "2250", 4_130_000),
          "says": "Records the $41,300 shipment in transit, so both sides agree"},
     ]},
    {"id": "decision", "title": "The CFO's decision", "film": 5,
     "text": "The write-down waits for the CFO. The agent recommends $612,000, all stock "
             "older than 180 days. The alternative is $410,000, keeping $202,000 of "
             "seasonal stock under review for 30 days.",
     "decision": {
         "person": "cfo", "agent": "stock/02",
         "options": [
             {"label": "Approve $612,000", "verdict": "approve"},
             {"label": "Approve $410,000 instead", "verdict": "reject",
              "then": {"agent": "stock/02", "tool": POST,
                       "args": _entry("KF-US", "2026-09-30", "Write down stock older than "
                                      "180 days, keeping seasonal stock under review",
                                      "5300", "1300", 41_000_000),
                       "says": "Proposes $410,000, which the CFO then approves"}},
         ]},
     "steps": []},
    {"id": "closed", "title": "Closed and checked", "film": 6,
     "text": "The Controller closes September in both companies. The log is sealed, the "
             "witnesses cosign, and the auditor checks everything.",
     "steps": [
         {"period": "2026-09", "entity": "KF-US", "state": "closed", "by": "controller",
          "says": "The Controller closes September for Kestrel Foods"},
         {"period": "2026-09", "entity": "KF-UK", "state": "closed", "by": "controller",
          "says": "The Controller closes September for Kestrel UK"},
         {"seal": True, "says": "The log signs a checkpoint and the witnesses cosign it"},
         {"audit": True, "says": "The auditor checks the whole evidence folder"},
     ]},
]


def chapters() -> List[Dict[str, Any]]:
    out = copy.deepcopy(CHAPTERS)
    for ch in out:
        agents = {s["agent"] for s in ch["steps"] if "agent" in s}
        if "decision" in ch:
            agents.add(ch["decision"]["agent"])
        ch["needs"] = sorted(agents)
    return out
