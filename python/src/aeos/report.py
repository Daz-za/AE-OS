"""Plain-language views of a log for `aeos agents`, `aeos decisions`, `aeos books` and the GUI.

Each function reads a receipt log and returns a JSON-ready dict; `lines_*` turns the same
dict into text for the terminal. The views only read what the log holds: they do not check
signatures or replay decisions. `aeos verify` and `aeos audit` do that.
"""
from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import books
from .canon import cid_str
from .delegation import money
from .log import ReceiptLog

# Which check made a decision, in the reader's words.
CHECKS = {
    "aeos-allow-list/v0": "Gateway allow list",
    "aeos-capability/v0": "Delegated authority",
    "aeos-policy/v0": "Payment rules",
    "aeos-books/v0": "Books of account",
}
REASONS = {"tool-not-in-allow-list": "the tool is not on the session's allow list"}


def when(ms: Optional[int]) -> str:
    if ms is None:
        return ""
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def locate(folder: Path) -> Tuple[Path, Optional[Path]]:
    """(log folder, evidence folder or None) for a log folder or an evidence folder."""
    folder = Path(folder)
    if (folder / "evidence.json").exists():
        manifest = json.loads((folder / "evidence.json").read_text())
        return folder / manifest.get("log", "log"), folder
    if (folder.parent / "evidence.json").exists() and (folder / "log.json").exists():
        return folder, folder.parent
    return folder, None


def chart(evidence: Optional[Path]) -> Dict[str, str]:
    """The chart of accounts named in an evidence folder, if any."""
    if evidence is None:
        return {}
    manifest = json.loads((evidence / "evidence.json").read_text())
    return dict((manifest.get("books") or {}).get("accounts") or {})


def _records(log: ReceiptLog) -> List[Tuple[int, Dict[str, Any]]]:
    return [(e.index, log.record(e)) for e in log.entries()]


def agents(log: ReceiptLog) -> Dict[str, Any]:
    """Who acted: each identity, how it connected, and what it did."""
    seen: Dict[str, Dict[str, Any]] = {}

    def row(who: str) -> Dict[str, Any]:
        return seen.setdefault(who, {"id": who, "sessions": 0, "connected": set(),
                                     "on_behalf_of": set(), "tools": Counter(), "calls": 0,
                                     "refused": set(), "escalated": set(), "approvals": 0,
                                     "entries": 0, "period_changes": 0,
                                     "first": None, "last": None})

    calls: Dict[str, str] = {}                  # call fingerprint -> the agent that made it
    for e in log.entries():
        rec = log.record(e)
        who, kind, body = rec.get("agent") or "", rec.get("kind"), rec.get("body") or {}
        if kind == "policy.decision":
            # Count calls, not decisions: one call can be refused by more than one check,
            # and the books record their refusals under their own identity.
            call = next((cid_str(p) for p in rec.get("parents") or []
                         if cid_str(p) in calls), None)
            if call and body.get("decision") in ("deny", "escalate"):
                row(calls[call])["refused" if body["decision"] == "deny" else "escalated"].add(call)
            continue
        r = row(who)
        r["first"] = r["first"] or rec.get("ts")
        r["last"] = rec.get("ts")
        if rec.get("obo"):
            r["on_behalf_of"].add(rec["obo"])
        if kind == "session.start":
            r["sessions"] += 1
            r["connected"].add(body.get("authenticated_by") or "not stated")
        elif kind == "tool.call":
            calls[cid_str(e.cid)] = who
            r["calls"] += 1
            r["tools"][rec.get("subject") or ""] += 1
        elif kind == "approval":
            r["approvals"] += 1
        elif kind == "journal.entry":
            r["entries"] += 1
        elif kind == "period.transition":
            r["period_changes"] += 1
    out = []
    for r in seen.values():
        r["connected"] = sorted(r["connected"])
        r["on_behalf_of"] = sorted(r["on_behalf_of"])
        r["tools"] = dict(r["tools"])
        r["refused"], r["escalated"] = len(r["refused"]), len(r["escalated"])
        r["role"] = ("person" if "/human/" in r["id"] else
                     "service" if "/service/" in r["id"] else "agent")
        out.append(r)
    out.sort(key=lambda r: (["person", "agent", "service"].index(r["role"]), r["id"]))
    return {"identities": out}


def decisions(log: ReceiptLog, everything: bool = False) -> Dict[str, Any]:
    """Each check's answer to each call. By default only refusals, escalations and approvals."""
    counts: Dict[str, Counter] = {}
    items: List[Dict[str, Any]] = []
    approvals: Dict[str, List[Dict[str, Any]]] = {}
    for index, rec in _records(log):
        body = rec.get("body") or {}
        if rec.get("kind") == "approval":
            answer = {"index": index, "by": body.get("approver") or rec.get("agent"),
                      "answer": body.get("decision"), "time": rec.get("ts")}
            # The approval names the escalation it answers, or links to it as a parent.
            refs = {str(r) for r in [body.get("escalation")] +
                    [cid_str(p) for p in rec.get("parents") or []] if r}
            for ref in refs:
                approvals.setdefault(ref, []).append(answer)
    calls: Dict[str, Dict[str, Any]] = {}
    for e in log.entries():
        rec = log.record(e)
        if rec.get("kind") == "tool.call":
            calls[cid_str(e.cid)] = rec
        if rec.get("kind") != "policy.decision":
            continue
        # The books record their refusals under their own identity; the call names the caller.
        call = next((calls[cid_str(p)] for p in rec.get("parents") or []
                     if cid_str(p) in calls), None)
        caller = call or rec
        body = rec.get("body") or {}
        check = CHECKS.get(str(body.get("policy")), str(body.get("policy")))
        decision = str(body.get("decision"))
        counts.setdefault(check, Counter())[decision] += 1
        if decision == "allow" and not everything:
            continue
        item = {"index": e.index, "time": rec.get("ts"), "agent": caller.get("agent"),
                "on_behalf_of": caller.get("obo"), "tool": rec.get("subject"), "check": check,
                "decision": decision,
                "reasons": [REASONS.get(r, r) for r in body.get("reasons") or []]}
        if body.get("amount"):
            item["amount"] = money(int(body["amount"]), str(body.get("currency") or "USD"))
        item["approvals"] = approvals.get(cid_str(e.cid), [])
        items.append(item)
    return {"counts": {k: dict(v) for k, v in counts.items()}, "decisions": items,
            "everything": everything}


def books_view(log: ReceiptLog, accounts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Periods, journal entries, refusals and the trial balance rebuilt from the entries."""
    accounts = accounts or {}
    ledgers: Dict[Tuple[str, str], Dict[str, Any]] = {}
    refused: List[Dict[str, Any]] = []

    def ledger(entity: str, name: str) -> Dict[str, Any]:
        return ledgers.setdefault((entity, name), {"entity": entity, "ledger": name,
                                                   "currency": None, "periods": {},
                                                   "entries": [], "bodies": []})

    for index, rec in _records(log):
        kind, body = rec.get("kind"), rec.get("body") or {}
        if kind == "period.transition":
            led = ledger(str(body.get("entity")), str(body.get("ledger")))
            p = str(body.get("period"))
            led["periods"][p] = {"period": p, "name": books.period_name(p)
                                 if books.valid_period(p) else p,
                                 "state": body.get("state"), "by": body.get("by"),
                                 "time": body.get("time"), "index": index}
        elif kind == "journal.entry":
            led = ledger(str(body.get("entity")), str(body.get("ledger")))
            led["currency"] = led["currency"] or body.get("currency")
            led["bodies"].append(body)
            cur = str(body.get("currency") or "USD")
            lines = [{"account": ln.get("account"),
                      "name": accounts.get(str(ln.get("account")), ""),
                      "debit": money(int(ln["debit_minor"]), cur) if ln.get("debit_minor") else "",
                      "credit": money(int(ln["credit_minor"]), cur) if ln.get("credit_minor") else ""}
                     for ln in body.get("lines") or []]
            led["entries"].append({"index": index, "document": body.get("document"),
                                   "date": body.get("date"), "text": body.get("text") or "",
                                   "reverses": body.get("reverses"), "lines": lines})
        elif kind == "policy.decision" and body.get("policy") == "aeos-books/v0":
            refused.append({"index": index, "time": rec.get("ts"),
                            "reasons": list(body.get("reasons") or [])})
    out = []
    for led in ledgers.values():
        cur = str(led["currency"] or "USD")
        tb = books.trial_balance(led.pop("bodies"))
        rows = []
        for acct in sorted(tb):
            bal = tb[acct]
            rows.append({"account": acct, "name": accounts.get(acct, ""),
                         "debit": money(bal, cur) if bal > 0 else "" if bal else "nil",
                         "credit": money(-bal, cur) if bal < 0 else ""})
        debits = sum(v for v in tb.values() if v > 0)
        credits = -sum(v for v in tb.values() if v < 0)
        led["periods"] = sorted(led["periods"].values(), key=lambda p: p["period"])
        led["trial_balance"] = rows
        led["totals"] = {"debit": money(debits, cur), "credit": money(credits, cur),
                         "balanced": debits == credits}
        out.append(led)
    return {"ledgers": out, "refused": refused}


def _name(who: Optional[str]) -> str:
    return who or "nobody"


def lines_agents(view: Dict[str, Any]) -> List[str]:
    if not view["identities"]:
        return ["No identities in this log yet."]
    out = []
    for r in view["identities"]:
        out.append(f"{r['id']} ({r['role']})")
        if r["sessions"]:
            how = ", ".join("a certificate over mutual TLS" if c == "x509-svid-mtls" else c
                            for c in r["connected"] if c != "not stated")
            out.append(f"  Connected {r['sessions']} time{'s' * (r['sessions'] != 1)}"
                       + (f", authenticated by {how}" if how else ""))
        if r["on_behalf_of"]:
            out.append(f"  Acted for {', '.join(r['on_behalf_of'])}")
        if r["calls"]:
            tools = ", ".join(f"{t} ({n})" for t, n in sorted(r["tools"].items()))
            out.append(f"  Tool calls ({r['calls']}): {tools}")
        if r["refused"]:
            out.append(f"  Calls refused: {r['refused']}")
        if r["escalated"]:
            out.append(f"  Calls sent to a person for approval: {r['escalated']}")
        if r["approvals"]:
            out.append(f"  Approvals given: {r['approvals']}")
        if r["period_changes"]:
            out.append(f"  Signed {r['period_changes']} period "
                       f"change{'s' * (r['period_changes'] != 1)}")
        if r["entries"]:
            out.append(f"  Wrote {r['entries']} journal entr{'ies' if r['entries'] != 1 else 'y'}")
        out.append(f"  Active {when(r['first'])} to {when(r['last'])}")
    return out


def lines_decisions(view: Dict[str, Any]) -> List[str]:
    out = []
    if not view["counts"]:
        return ["No decisions in this log yet."]
    words = {"allow": "allowed", "deny": "refused", "escalate": "sent to a person"}
    for check, c in view["counts"].items():
        parts = ", ".join(f"{n} {words.get(d, d)}" for d, n in sorted(c.items()))
        out.append(f"{check}: {parts}")
    if view["decisions"]:
        out.append("")
    for d in view["decisions"]:
        head = f"#{d['index']} {when(d['time'])}  {d['check']}: {words.get(d['decision'], d['decision'])}"
        out.append(head)
        out.append(f"  {_name(d['agent'])} called {d['tool']}"
                   + (f" for {d['on_behalf_of']}" if d.get("on_behalf_of") else "")
                   + (f", {d['amount']}" if d.get("amount") else ""))
        for r in d["reasons"]:
            out.append(f"  - {r}")
        for a in d["approvals"]:
            out.append(f"  {'Approved' if a['answer'] == 'approve' else 'Rejected'} by "
                       f"{a['by']} (record #{a['index']})")
    if not view["everything"] and not view["decisions"]:
        out.append("Nothing was refused or sent to a person.")
    return out


def lines_books(view: Dict[str, Any]) -> List[str]:
    if not view["ledgers"] and not view["refused"]:
        return ["This log holds no books of account."]
    out = []
    for led in view["ledgers"]:
        out.append(f"{led['entity']} {led['ledger']} ({led['currency'] or 'no entries yet'})")
        for p in led["periods"]:
            out.append(f"  {p['name']}: {p['state']}, signed by {p['by']}")
        out.append("")
        out.append("  Journal")
        for e in led["entries"]:
            note = f" (reverses {e['reverses']})" if e.get("reverses") else ""
            out.append(f"  {e['document']}  {e['date']}  {e['text']}{note}")
            for ln in e["lines"]:
                side = f"Dr {ln['debit']}" if ln["debit"] else f"    Cr {ln['credit']}"
                out.append(f"      {ln['account']} {ln['name']:<22} {side}")
        out.append("")
        out.append("  Trial balance")
        out.append(f"  {'Account':<27} {'Debit':>16} {'Credit':>16}")
        for r in led["trial_balance"]:
            out.append(f"  {r['account']} {r['name']:<22} {r['debit']:>16} {r['credit']:>16}")
        t = led["totals"]
        out.append(f"  {'Total':<27} {t['debit']:>16} {t['credit']:>16}"
                   + ("" if t["balanced"] else "  DOES NOT BALANCE"))
    if view["refused"]:
        out.append("")
        out.append("  Refused by the books")
        for r in view["refused"]:
            out.append(f"  #{r['index']} {when(r['time'])}: {'; '.join(r['reasons'])}")
    return out
