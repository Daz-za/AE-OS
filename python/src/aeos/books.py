"""Books of account: the AE-OS Accounting Kernel, on a small scale.

The evidence log records what agents and people did. The books record what that means in
the accounts, and they keep their own rules: a Merkle proof shows an entry is unchanged,
but says nothing about whether debits equal credits or whether the period was open.

Each journal entry is one `journal.entry` record in the log, written by the books
service and linked to the tool call that asked for it. Balances are computed from those
records each time they are needed. Before an entry is recorded the books check that:

- it has at least two lines, on accounts in the chart of accounts, and its debits equal
  its credits (the paper's invariant I7);
- its date falls in a period that is open (I9). Periods open and close only through a
  `period.transition` record signed by a controller. A correction is a reversal entry,
  dated in an open period, that cites the original; the original stays as it was.

A refused entry is recorded as a `policy.decision` deny and uses no document number, so
each series of document numbers (entity and year) has no gaps.

One `Books` keeps one ledger of one legal entity, in one currency; a workspace keeps one for
each of its entities in the same log. The books service runs as a tool inside the gateway
process; its SPIFFE ID names it in records, and it is not issued a certificate.
"""
from __future__ import annotations

import datetime as dt
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys
from .canon import cid_str, dag_cbor
from .delegation import money
from .log import Entry, ReceiptLog, b64, make_record, now_ms, unb64

POLICY = "aeos-books/v0"
TRANSITION_CONTEXT = b"aeos/period-transition/v0\n"
STATES = ("open", "closed")
TOOL = "ledger.post"


class Refused(Exception):
    """The books refused an entry; the reasons are in plain language."""

    def __init__(self, reasons: List[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def period_of(date: str) -> str:
    """The posting period of a date: "2026-10-19" is in period "2026-10"."""
    return dt.date.fromisoformat(date).strftime("%Y-%m")


def valid_period(period: Any) -> bool:
    try:
        return isinstance(period, str) and \
            dt.datetime.strptime(period, "%Y-%m").strftime("%Y-%m") == period
    except ValueError:
        return False


def period_name(period: str) -> str:
    return dt.datetime.strptime(period, "%Y-%m").strftime("%B %Y")


@dataclass
class PeriodTransition:
    """A controller's signed instruction to open or close one posting period."""

    entity: str
    ledger: str
    period: str               # "YYYY-MM"
    state: str                # "open" or "closed"
    by: str                   # the controller's SPIFFE ID
    time: int                 # ms since the epoch
    signature: bytes = field(default=b"", repr=False)

    def fields(self) -> Dict[str, Any]:
        return {"entity": self.entity, "ledger": self.ledger, "period": self.period,
                "state": self.state, "by": self.by, "time": self.time}

    def message(self) -> bytes:
        return TRANSITION_CONTEXT + dag_cbor(self.fields())

    def sign(self, key: Ed25519PrivateKey) -> "PeriodTransition":
        self.signature = key.sign(self.message())
        return self

    def verify(self, public_key: bytes) -> bool:
        return keys.verify(public_key, self.signature, self.message())

    def to_json(self) -> Dict[str, Any]:
        return {**self.fields(), "signature": b64(self.signature)}

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "PeriodTransition":
        return cls(**{k: d[k] for k in ("entity", "ledger", "period", "state", "by", "time")},
                   signature=unb64(d["signature"]))


def _whole(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def check_lines(lines: Any, accounts: Optional[Dict[str, str]], currency: str) -> List[str]:
    """Why these lines cannot be an entry (I7); empty when they can."""
    if not isinstance(lines, list) or len(lines) < 2:
        return ["an entry needs at least two lines"]
    problems, debits, credits = [], 0, 0
    for line in lines:
        account = line.get("account") if isinstance(line, dict) else None
        dr = line.get("debit_minor", 0) if isinstance(line, dict) else None
        cr = line.get("credit_minor", 0) if isinstance(line, dict) else None
        if not isinstance(account, str) or not account:
            problems.append("a line has no account")
        elif accounts is not None and account not in accounts:
            problems.append(f"account {account} is not in the chart of accounts")
        if not ((_whole(dr) and cr == 0) or (_whole(cr) and dr == 0)):
            problems.append("each line needs either a debit or a credit, in whole cents")
            continue
        debits, credits = debits + dr, credits + cr
    if not problems and debits != credits:
        problems.append(f"debits ({money(debits, currency)}) and credits "
                        f"({money(credits, currency)}) differ")
    return list(dict.fromkeys(problems))


def check_period(date: Any, periods: Dict[str, str]) -> List[str]:
    """Why an entry cannot be dated `date` (I9); empty when it can."""
    try:
        period = period_of(date)
    except (TypeError, ValueError, AttributeError):
        return ["the entry needs a date written as YYYY-MM-DD"]
    state = periods.get(period)
    if state == "closed":
        return [f"{period_name(period)} is closed; date the entry in an open period"]
    if state != "open":
        return [f"{period_name(period)} has not been opened"]
    return []


class Books:
    """One ledger of one legal entity, recorded in the evidence log."""

    def __init__(self, log: ReceiptLog, *, agent: str, entity: str, ledger: str,
                 currency: str, accounts: Dict[str, str],
                 controllers: Dict[str, bytes]) -> None:
        self.log, self.agent = log, agent
        self.entity, self.ledger, self.currency = entity, ledger, currency
        self.accounts, self.controllers = accounts, controllers
        self.periods: Dict[str, str] = {}
        self.entries: Dict[str, Tuple[Entry, Dict[str, Any]]] = {}   # document -> record
        self.reversed: Dict[str, str] = {}                            # document -> reversal
        self.next_number: Dict[str, int] = {}                         # year -> next number
        self._scanned = 0
        self._lock = threading.Lock()

    def restore(self) -> "Books":
        """Rebuild periods, entries and numbering from what this log already holds."""
        with self._lock:
            self._catch_up()
        return self

    def _catch_up(self) -> None:
        """Apply records added since the last look, such as a period change signed in
        another process. Applying a record twice changes nothing."""
        entries = self.log.entries()
        for e in entries[self._scanned:]:
            rec = self.log.record(e)
            body = rec.get("body") or {}
            if body.get("entity") != self.entity or body.get("ledger") != self.ledger:
                continue
            if rec.get("kind") == "period.transition":
                try:
                    t = PeriodTransition(**{k: body[k] for k in ("entity", "ledger", "period",
                                                                 "state", "by", "time")},
                                         signature=body["signature"])
                except (KeyError, TypeError):
                    continue
                if t.by in self.controllers and t.verify(self.controllers[t.by]):
                    self.periods[t.period] = t.state
            elif rec.get("kind") == "journal.entry" and rec.get("agent") == self.agent:
                document = str(body["document"])
                self.entries[document] = (e, rec)
                if body.get("reverses"):
                    self.reversed[str(body["reverses"])] = document
                year, number = document.rsplit("/", 2)[-2:]
                self.next_number[year] = max(self.next_number.get(year, 1), int(number) + 1)
        self._scanned = len(entries)

    def transition(self, t: PeriodTransition) -> Entry:
        """Record a controller's signed period change and apply it."""
        if t.entity != self.entity or t.ledger != self.ledger:
            raise Refused(["the period change names another entity or ledger"])
        if t.state not in STATES or not valid_period(t.period):
            raise Refused(["a period change needs a period written as YYYY-MM and a state "
                           "of open or closed"])
        if t.by not in self.controllers or not t.verify(self.controllers[t.by]):
            raise Refused(["the period change is not signed by a controller"])
        with self._lock:
            self._catch_up()
            e = self.log.append(make_record(
                "period.transition", t.by, subject=f"{t.entity}/{t.ledger}/{t.period}",
                body={**t.fields(), "signature": t.signature}))
            self.periods[t.period] = t.state
            return e

    def tool(self) -> Callable[..., Dict[str, Any]]:
        """The `ledger.post` tool for the gateway; it receives the call's record."""
        def post(args: Dict[str, Any], call: Entry) -> Dict[str, Any]:
            return self.post(args, call)
        post.takes_call = True  # type: ignore[attr-defined]
        return post

    def post(self, args: Dict[str, Any], call: Entry) -> Dict[str, Any]:
        """Check and record one journal entry asked for by `call`.

        args: {"date", "text", "lines": [{"account", "debit_minor" | "credit_minor"}]}, or
        {"date", "text", "reverses": "<document>"} to reverse an earlier entry.
        """
        with self._lock:
            self._catch_up()
            date, reverses = args.get("date"), args.get("reverses")
            original = None
            if reverses is not None:
                original = self.entries.get(reverses) if isinstance(reverses, str) else None
                if "lines" in args:
                    problems = ["a reversal takes its lines from the original entry; send "
                                "either lines or reverses"]
                elif original is None:
                    problems = [f"document {reverses} is not in these books"]
                elif reverses in self.reversed:
                    problems = [f"document {reverses} was already reversed by "
                                f"{self.reversed[reverses]}"]
                else:
                    problems = []
                lines = [{"account": ln["account"], "debit_minor": ln.get("credit_minor", 0),
                          "credit_minor": ln.get("debit_minor", 0)}
                         for ln in (original[1]["body"]["lines"] if original else [])]
            else:
                lines = args.get("lines")
                problems = check_lines(lines, self.accounts, self.currency)
            problems += check_period(date, self.periods)
            if problems:
                self.log.append(make_record(
                    "policy.decision", self.agent, subject=TOOL, parents=[call.cid],
                    body={"decision": "deny", "policy": POLICY, "reasons": problems}))
                raise Refused(problems)
            year = date[:4]
            number = self.next_number.get(year, 1)
            document = f"{self.entity}/{year}/{number:06d}"
            body: Dict[str, Any] = {
                "entity": self.entity, "ledger": self.ledger, "document": document,
                "period": period_of(date), "date": date, "currency": self.currency,
                "text": str(args.get("text", "")),
                "lines": [{"account": ln["account"],
                           **({"debit_minor": ln["debit_minor"]} if ln.get("debit_minor")
                              else {"credit_minor": ln["credit_minor"]})} for ln in lines]}
            parents = [call.cid]
            if original is not None:
                body["reverses"] = reverses
                parents.append(original[0].cid)
            e = self.log.append(make_record("journal.entry", self.agent, subject=TOOL,
                                            body=body, parents=parents, ts=now_ms()))
            self.next_number[year] = number + 1
            self.entries[document] = (e, self.log.record(e))
            if original is not None:
                self.reversed[reverses] = document
            return {"document": document, "entry": cid_str(e.cid)}

    def balances(self) -> Dict[str, int]:
        """Each account's balance, debit positive, worked out from the entries."""
        return trial_balance(rec["body"] for _, rec in self.entries.values())


def trial_balance(bodies: Any) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for body in bodies:
        for ln in body["lines"]:
            out[ln["account"]] = out.get(ln["account"], 0) + ln.get("debit_minor", 0) \
                - ln.get("credit_minor", 0)
    return out


def replay(records: List[Tuple[int, str, Dict[str, Any]]], principal_keys: Dict[str, bytes],
           *, controllers: Optional[List[str]] = None, accounts: Optional[Dict[str, str]] = None,
           service: Optional[str] = None) -> Tuple[Dict[str, Any], List[str]]:
    """Check the books in a log from its records, in log order.

    `records` are (index, CID, record) triples for the whole log. With `controllers`,
    `accounts` and `service` (from the evidence folder), period changes must be signed by
    a controller, lines must use accounts in the chart, and entries must be written by the
    books service. Returns a summary and the problems found.
    """
    periods: Dict[Tuple[str, str], Dict[str, str]] = {}
    seen: Dict[str, Dict[str, Any]] = {}
    numbers: Dict[Tuple[str, str], int] = {}
    reversed_: Dict[str, str] = {}
    problems: List[str] = []
    transitions, refused, signers, bodies = 0, 0, set(), []
    calls = {cid: rec for _, cid, rec in records if rec["kind"] == "tool.call"}
    for index, cid, rec in records:
        body = rec["body"]
        where = f"record {index}"
        if rec["kind"] == "policy.decision" and body.get("policy") == POLICY:
            refused += 1
            continue
        if rec["kind"] == "period.transition":
            transitions += 1
            try:
                t = PeriodTransition(**{k: body[k] for k in ("entity", "ledger", "period",
                                                             "state", "by", "time")},
                                     signature=body["signature"])
            except (KeyError, TypeError):
                problems.append(f"{where}: the period change is incomplete")
                continue
            if rec["agent"] != t.by or not t.verify(principal_keys.get(t.by, b"")):
                problems.append(f"{where}: the period change is not signed by {t.by}")
                continue
            if controllers is not None and t.by not in controllers:
                problems.append(f"{where}: the period change is signed by {t.by}, who is not "
                                "a controller")
                continue
            if t.state not in STATES or not valid_period(t.period):
                problems.append(f"{where}: the period change has no valid period or state")
                continue
            signers.add(t.by)
            periods.setdefault((t.entity, t.ledger), {})[t.period] = t.state
            continue
        if rec["kind"] != "journal.entry":
            continue
        doc = body.get("document", "")
        if service is not None and rec["agent"] != service:
            problems.append(f"{where}: document {doc} was not written by the books service")
        call = calls.get(cid_str(rec["parents"][0])) if rec["parents"] else None
        if call is None or call["subject"] != TOOL:
            problems.append(f"{where}: document {doc} is not linked to a {TOOL} call")
        bad_lines = check_lines(body.get("lines"), accounts, body.get("currency", ""))
        problems += [f"{where}: document {doc}: {p}" for p in bad_lines]
        bad_date = check_period(body.get("date"), periods.get((body.get("entity"),
                                                              body.get("ledger")), {}))
        problems += [f"{where}: document {doc}: {p}" for p in bad_date]
        try:
            if body.get("period") != period_of(body.get("date")):
                problems.append(f"{where}: document {doc}'s period does not match its date")
        except (TypeError, ValueError, AttributeError):
            pass                                        # reported by check_period
        entity, year = body.get("entity", ""), str(body.get("date", ""))[:4]
        expected = numbers.get((entity, year), 0) + 1
        if doc != f"{entity}/{year}/{expected:06d}":
            problems.append(f"{where}: document {doc} breaks the numbering; expected "
                            f"{entity}/{year}/{expected:06d}")
        numbers[(entity, year)] = expected
        if bad_lines:
            continue
        if "reverses" in body:
            orig = seen.get(body["reverses"])
            if orig is None or len(rec["parents"]) < 2 or \
                    cid_str(rec["parents"][1]) != orig["cid"]:
                problems.append(f"{where}: document {doc} reverses a document that is not "
                                "earlier in these books")
            elif body["reverses"] in reversed_:
                problems.append(f"{where}: document {body['reverses']} is reversed twice")
            elif (orig["body"].get("entity"), orig["body"].get("ledger")) != \
                    (body.get("entity"), body.get("ledger")) or \
                    trial_balance([orig["body"], body]) != \
                    {k: 0 for k in trial_balance([orig["body"]])}:
                problems.append(f"{where}: document {doc} does not exactly reverse "
                                f"{body['reverses']}")
            else:
                reversed_[body["reverses"]] = doc
        seen[doc] = {"cid": cid, "body": body}
        bodies.append(body)
    balances = trial_balance(bodies)
    summary = {"entries": len(bodies), "reversals": len(reversed_), "refused": refused,
               "transitions": transitions, "signers": sorted(signers), "balances": balances,
               "debits": sum(v for v in balances.values() if v > 0),
               "credits": -sum(v for v in balances.values() if v < 0),
               "documents": sorted(seen)}
    return summary, problems
