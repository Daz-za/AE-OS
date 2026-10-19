"""A workspace: one file that describes a company's AE-OS, and the runtime that runs it.

`workspace.json` names the organization, its people, its agents and what each may do,
the systems that provide tools, the rules, the books of account and the witnesses.
`Platform` reads it and runs the whole stack on one computer: an identity service, an
authorization service, the MCP gateway with the rules, the books, the log and the
witnesses. The workspace folder is also an evidence folder, so `aeos audit`, the reports
and the browser page work on it unchanged.

    aeos new my-company          create a workspace from the example
    aeos check my-company        find mistakes in workspace.json
    aeos up my-company           run it; agents connect with the files in private/connect/
    aeos call my-company --as accounts-payable erp.invoice.get invoice=INV-1001

Private keys stay in private/. In this preview the people's signing keys are files on
this computer, so the platform can sign an intent or an approval for a person when asked
to. In production each person signs with their own passkey or smart card.
"""
from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import threading
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import books, delegation, identity, keys, policy, report, witness
from .canon import cid_str, json_digest
from .gateway import AgentClient, Gateway
from .log import ReceiptLog, now_ms

FORMAT = "aeos-workspace/v0"
FILE = "workspace.json"
PAYMENTS_WASM = Path(__file__).with_name("policies") / "payments.wasm"
PAYMENTS_ENTRYPOINT = "aeos/payments/decision"
SYSTEM_TYPES = ("example-erp", "python", "mcp-stdio")
RULE_TYPES = ("payments", "wasm", "none")
RENEW_EVERY = 300                    # seconds; SVIDs live 15 minutes, renewed well before
_ID = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")


class WorkspaceError(Exception):
    """The workspace cannot be used as it stands."""


# ---- the file ------------------------------------------------------------------------

def example() -> Dict[str, Any]:
    """The workspace `aeos new` writes: Acme, a fictional company, paying supplier invoices."""
    return {
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
             "tools": ["erp.invoice.list", "erp.invoice.get", "erp.invoice.pay", books.TOOL],
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


def load(folder: Path) -> Dict[str, Any]:
    path = Path(folder) / FILE
    if not path.exists():
        raise WorkspaceError(f"{folder} has no {FILE}. Create one with: aeos new {folder}")
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        raise WorkspaceError(f"{path} is not valid JSON: {e}") from None
    return doc


def save(folder: Path, doc: Dict[str, Any]) -> None:
    """Write workspace.json after checking it; raises WorkspaceError with the problems."""
    problems = check(doc, Path(folder))
    if problems:
        raise WorkspaceError("; ".join(problems))
    path = Path(folder) / FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n")
    tmp.replace(path)


def create(folder: Path, doc: Optional[Dict[str, Any]] = None) -> Path:
    """A new workspace folder holding workspace.json."""
    folder = Path(folder)
    if folder.exists() and any(folder.iterdir()):
        raise WorkspaceError(f"{folder} already has files in it. Choose an empty or new folder.")
    folder.mkdir(parents=True, exist_ok=True)
    save(folder, doc or example())
    return folder


def minor(value: Any) -> int:
    """An amount written as "1234.50" (or a number) in minor units, for two-decimal currencies."""
    try:
        d = Decimal(str(value).replace(",", "").strip())
    except InvalidOperation:
        raise ValueError(f"{value!r} is not an amount") from None
    cents = d * 100
    if d < 0 or cents != cents.to_integral_value():
        raise ValueError(f"{value!r} is not an amount of at most two decimals")
    return int(cents)


def spiffe(doc: Dict[str, Any], kind: str, ident: str) -> str:
    """The SPIFFE ID of a person ("human"), agent, service or gateway in this workspace."""
    return f"spiffe://{doc['organization']['trust_domain']}/{kind}/{ident}"


def tool_names(doc: Dict[str, Any], folder: Optional[Path] = None) -> Dict[str, str]:
    """Each tool the systems provide, with the system that provides it. MCP servers are
    asked for their tools only while the platform runs, so their tools are listed under
    the system's `tools` field when given."""
    out: Dict[str, str] = {}
    for s in doc.get("systems") or []:
        if s.get("type") == "example-erp":
            for t in ExampleErp.TOOLS:
                out[t] = s.get("id", "")
        elif s.get("type") == "python" and folder is not None:
            try:
                for t in _python_module(folder, s).TOOLS:
                    out[t] = s.get("id", "")
            except Exception:                       # reported by check()
                pass
        for t in s.get("tools") or []:
            out[str(t)] = s.get("id", "")
    if doc.get("books"):
        out[books.TOOL] = "books"
    return out


def check(doc: Any, folder: Optional[Path] = None) -> List[str]:
    """Mistakes in a workspace, in plain language. An empty list means it can run."""
    if not isinstance(doc, dict):
        return ["the workspace must be a JSON object"]
    p: List[str] = []
    if doc.get("format") != FORMAT:
        p.append(f"format must be {FORMAT}")
    org = doc.get("organization") or {}
    if not org.get("name"):
        p.append("the organization needs a name")
    try:
        identity.parse_spiffe_id(f"spiffe://{org.get('trust_domain')}/x")
        if not re.fullmatch(r"[a-z0-9.-]+", str(org.get("trust_domain"))):
            raise identity.IdentityError("")
    except identity.IdentityError:
        p.append("the trust domain must be a domain name in lower case, such as acme.example")

    def ids(items: Any, what: str) -> List[str]:
        if not isinstance(items, list):
            p.append(f"{what} must be a list")
            return []
        seen: List[str] = []
        for it in items:
            i = (it or {}).get("id") if isinstance(it, dict) else None
            if not isinstance(i, str) or not _ID.match(i):
                p.append(f"each entry in {what} needs an id of lower-case letters, digits and "
                         f"hyphens (found {i!r})")
            elif i in seen:
                p.append(f"{what} has the id {i} twice")
            else:
                seen.append(i)
        return seen

    people = ids(doc.get("people"), "people")
    agents = ids(doc.get("agents"), "agents")
    systems = ids(doc.get("systems"), "systems")
    clash = set(people) & set(agents)
    if clash:
        p.append(f"{', '.join(sorted(clash))} is used for a person and for an agent")
    if not systems:
        p.append("add at least one system that provides tools")
    for s in doc.get("systems") or []:
        if not isinstance(s, dict):
            continue
        kind, sid = s.get("type"), s.get("id")
        if kind not in SYSTEM_TYPES:
            p.append(f"system {sid}: the type must be one of {', '.join(SYSTEM_TYPES)}")
        elif kind == "example-erp":
            for inv in s.get("invoices") or []:
                try:
                    if not inv.get("invoice") or not inv.get("supplier"):
                        raise ValueError("")
                    minor(inv.get("amount"))
                except (ValueError, AttributeError):
                    p.append(f"system {sid}: each invoice needs an invoice number, a supplier "
                             "and an amount")
                    break
        elif kind == "python":
            if folder is not None:
                try:
                    mod = _python_module(folder, s)
                    if not isinstance(getattr(mod, "TOOLS", None), dict):
                        p.append(f"system {sid}: {s.get('file')} must define TOOLS, a dict of "
                                 "tool name to function")
                except Exception as e:
                    p.append(f"system {sid}: {s.get('file')} could not be loaded ({e})")
        elif kind == "mcp-stdio":
            if not isinstance(s.get("command"), list) or not s.get("command"):
                p.append(f"system {sid}: command must be a list, such as "
                         '["python3", "server.py"]')
            if not isinstance(s.get("tools"), list):
                p.append(f"system {sid}: list the server's tools under tools, so agents can be "
                         "given them")
    tools = tool_names(doc, folder)
    persons = {x.get("id"): x for x in doc.get("people") or [] if isinstance(x, dict)}
    for a in doc.get("agents") or []:
        if not isinstance(a, dict):
            continue
        aid = a.get("id")
        if a.get("authorized_by") not in persons:
            p.append(f"agent {aid}: authorized by must name one of the people")
        unknown = [t for t in a.get("tools") or [] if t not in tools]
        if unknown:
            p.append(f"agent {aid}: no system provides {', '.join(unknown)}")
        try:
            limit, budget = minor(a.get("per_call_limit", "0")), minor(a.get("budget", "0"))
            if budget < limit:
                p.append(f"agent {aid}: the budget is smaller than the limit per call")
        except ValueError as e:
            p.append(f"agent {aid}: {e}")
        hours = a.get("valid_hours", 8)
        if not isinstance(hours, (int, float)) or not 0 < hours <= 24 * 31:
            p.append(f"agent {aid}: hours valid must be between 1 and 744")
    rules = doc.get("rules") or {"type": "none"}
    kind = rules.get("type")
    if kind not in RULE_TYPES:
        p.append(f"rules: the type must be one of {', '.join(RULE_TYPES)}")
    elif kind == "payments":
        try:
            minor(rules.get("approval_above", "0"))
        except ValueError as e:
            p.append(f"rules: the approval amount: {e}")
        if not any(x.get("approver") for x in persons.values()):
            p.append("rules: mark at least one person as an approver, or payments above "
                     "the approval amount can never be approved")
    elif kind == "wasm":
        f = Path(folder or ".") / str(rules.get("file", ""))
        if not rules.get("file") or (folder is not None and not f.is_file()):
            p.append("rules: file must name your compiled rules (.wasm) in the workspace folder")
        if not rules.get("entrypoint"):
            p.append("rules: entrypoint must name the rule that gives the decision, such as "
                     "acme/payments/decision")
    b = doc.get("books")
    if b:
        if not b.get("entity") or not b.get("ledger"):
            p.append("books: give the entity and the ledger")
        if not re.fullmatch(r"[A-Z]{3}", str(b.get("currency", ""))):
            p.append("books: the currency must be a three-letter code, such as USD")
        if not isinstance(b.get("accounts"), dict) or not b.get("accounts"):
            p.append("books: the chart of accounts needs at least one account")
        if not any(x.get("controller") for x in persons.values()):
            p.append("books: mark at least one person as a controller, who opens and closes "
                     "months")
    w = doc.get("witnesses") or {}
    names = w.get("names") or []
    if not names or not all(isinstance(n, str) and _ID.match(n) for n in names):
        p.append("witnesses: give at least one witness name of lower-case letters, digits and "
                 "hyphens")
    elif not isinstance(w.get("required"), int) or not 1 <= w["required"] <= len(names):
        p.append("witnesses: how many must cosign must be between 1 and the number of witnesses")
    return p


# ---- systems: where the tools come from ----------------------------------------------

class ExampleErp:
    """A small ERP held in memory: invoices to read and pay. Payments are kept in
    private/state/<system>.json, so a paid invoice stays paid after a restart."""

    TOOLS = ("erp.invoice.list", "erp.invoice.get", "erp.invoice.pay")

    def __init__(self, spec: Dict[str, Any], state: Path) -> None:
        self.state = state
        self.invoices = {str(i["invoice"]): {"supplier": str(i["supplier"]),
                                              "amount_minor": minor(i["amount"]),
                                              "status": str(i.get("status") or
                                                            "approved for payment")}
                         for i in spec.get("invoices") or []}
        self.paid: Dict[str, str] = json.loads(state.read_text()) if state.exists() else {}
        self._lock = threading.Lock()

    def invoice(self, number: str) -> Optional[Dict[str, Any]]:
        inv = self.invoices.get(number)
        if inv is None:
            return None
        return {**inv, "status": "paid" if number in self.paid else inv["status"]}

    def tools(self, currency: str) -> Dict[str, Callable[[Dict[str, Any]], Any]]:
        def listing(args: Dict[str, Any]) -> Any:
            return {"invoices": [{"invoice": n, **self.invoice(n), "currency": currency}
                                 for n in sorted(self.invoices)]}

        def get(args: Dict[str, Any]) -> Any:
            inv = self.invoice(str(args.get("invoice")))
            if inv is None:
                raise ValueError(f"no invoice {args.get('invoice')}")
            return {"invoice": args["invoice"], **inv, "currency": currency}

        def pay(args: Dict[str, Any]) -> Any:
            number = str(args.get("invoice"))
            inv = self.invoice(number)
            if inv is None:
                raise ValueError(f"no invoice {number}")
            if args.get("amount_minor") != inv["amount_minor"]:
                raise ValueError("the amount does not match the invoice")
            with self._lock:
                if number not in self.paid:
                    self.paid[number] = f"PAY-{len(self.paid) + 301}"
                    self.state.parent.mkdir(parents=True, exist_ok=True)
                    self.state.write_text(json.dumps(self.paid, indent=2) + "\n")
            return {"invoice": number, "payment": self.paid[number],
                    "amount_minor": inv["amount_minor"], "currency": currency}

        return {"erp.invoice.list": listing, "erp.invoice.get": get, "erp.invoice.pay": pay}

    def facts(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        inv = self.invoice(str(args.get("invoice", "")))
        if inv is None:
            return {}
        return {"invoice": {"vendor": inv["supplier"], "amount_minor": inv["amount_minor"],
                            "currency": "", "status": inv["status"]}}


def _python_module(folder: Path, spec: Dict[str, Any]) -> Any:
    path = (Path(folder) / str(spec.get("file", ""))).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"no file {spec.get('file')}")
    mod_spec = importlib.util.spec_from_file_location(f"aeos_system_{spec.get('id')}", path)
    if mod_spec is None or mod_spec.loader is None:
        raise ImportError(f"{path} is not a Python file")
    mod = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(mod)
    return mod


class McpServer:
    """A local MCP server started as a process, spoken to over stdio (JSON lines)."""

    def __init__(self, spec: Dict[str, Any], cwd: Path) -> None:
        self.prefix = str(spec.get("prefix", ""))
        self.proc = subprocess.Popen(list(spec["command"]), cwd=cwd, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)
        self._next = 0
        self._lock = threading.Lock()
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "aeos-gateway"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.names = [t["name"] for t in self.request("tools/list", {}).get("tools", [])]

    def _send(self, msg: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._next += 1
            rid = self._next
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            assert self.proc.stdout is not None
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise RuntimeError("the MCP server stopped")
                msg = json.loads(line)
                if msg.get("id") == rid:
                    if "error" in msg:
                        raise RuntimeError(msg["error"].get("message", "MCP error"))
                    return msg.get("result") or {}

    def tools(self) -> Dict[str, Callable[[Dict[str, Any]], Any]]:
        def make(name: str) -> Callable[[Dict[str, Any]], Any]:
            def call(args: Dict[str, Any]) -> Any:
                res = self.request("tools/call", {"name": name, "arguments": args})
                if res.get("isError"):
                    raise RuntimeError(" ".join(c.get("text", "") for c in
                                                res.get("content") or []) or "tool error")
                return res.get("structuredContent") or {"content": res.get("content")}
            return call
        return {self.prefix + n: make(n) for n in self.names}

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---- the runtime ---------------------------------------------------------------------

def _merge_json(path: Path, new: Dict[str, Any]) -> Dict[str, Any]:
    """Add to a JSON object file, keeping what it held: old records must still verify."""
    old = json.loads(path.read_text()) if path.exists() else {}
    merged = {**old, **new}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(merged, indent=2) + "\n")
    return merged


def _key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    return keys.load_key(path) if path.exists() else keys.generate_key(path)


class Platform:
    """Runs a workspace: identities, authority, gateway, rules, books, log and witnesses."""

    def __init__(self, folder: Path) -> None:
        self.folder = Path(folder).resolve()
        self.doc = load(self.folder)
        problems = check(self.doc, self.folder)
        if problems:
            raise WorkspaceError("; ".join(problems))
        self.private = self.folder / "private"
        self.gateway: Optional[Gateway] = None
        self.port: Optional[int] = None
        self.tokens: Dict[str, bytes] = {}          # agent id -> its capability token
        self.svid_files: Dict[str, Tuple[Path, Path]] = {}
        self._servers: List[McpServer] = []
        self._stop = threading.Event()
        self._renewer: Optional[threading.Thread] = None
        self._asked: Dict[str, Dict[str, Any]] = {}   # arguments of calls made here, by digest
        self._lock = threading.RLock()

    # names
    @property
    def domain(self) -> str:
        return str(self.doc["organization"]["trust_domain"])

    def person(self, pid: str) -> str:
        return spiffe(self.doc, "human", pid)

    def agent(self, aid: str) -> str:
        return spiffe(self.doc, "agent", aid)

    @property
    def gateway_id(self) -> str:
        return spiffe(self.doc, "gateway", "mcp")

    @property
    def books_service(self) -> str:
        return spiffe(self.doc, "service", "books")

    @property
    def currency(self) -> str:
        return str((self.doc.get("books") or {}).get("currency") or "USD")

    def names(self) -> Dict[str, str]:
        """Readable names for the workspace's SPIFFE IDs."""
        out = {self.person(p["id"]): p.get("name") or p["id"] for p in self.doc["people"]}
        out.update({self.agent(a["id"]): a.get("name") or a["id"] for a in self.doc["agents"]})
        out[self.gateway_id] = "the gateway"
        out[self.books_service] = "the books service"
        return out

    def person_key(self, pid: str) -> Ed25519PrivateKey:
        if pid not in {p["id"] for p in self.doc["people"]}:
            raise WorkspaceError(f"{pid} is not one of the people in this workspace")
        return _key(self.private / "people" / f"{pid}.key")

    # setup
    def open(self) -> "Platform":
        """Keys, log, books and witnesses, without serving the gateway. Enough to sign a
        period change or seal the log while `aeos up` runs in another process."""
        with self._lock:
            f, priv = self.folder, self.private
            priv.mkdir(parents=True, exist_ok=True)
            priv.chmod(0o700)
            for d in ("trust", "svids", "intents", "tokens", "policies"):
                (f / d).mkdir(exist_ok=True)
            ca = priv / "ca"
            self.td = identity.TrustDomain.load(self.domain, ca) if (ca / "root.pem").exists() \
                else identity.TrustDomain(self.domain)
            self.td.save(ca)
            (f / "trust" / "bundle.pem").write_bytes(self.td.bundle_pem())

            self.people = {p["id"]: self.person_key(p["id"]) for p in self.doc["people"]}
            self.principals = _merge_json(f / "trust" / "principals.json",
                                          {self.person(i): keys.public_bytes(k).hex()
                                           for i, k in self.people.items()})
            auth_path = priv / "authority.key"
            if auth_path.exists():
                self.authority = delegation.Authority(auth_path.read_bytes())
            else:
                self.authority = delegation.Authority()
                auth_path.write_bytes(self.authority.private_bytes())
                auth_path.chmod(0o600)
            (f / "trust" / "authority-public-key.txt").write_text(
                self.authority.public_key.hex() + "\n")

            log_dir = f / "log"
            if (log_dir / "log.json").exists():
                self.log = ReceiptLog.open(log_dir, key_path=priv / "log-signing.key")
            else:
                self.log = ReceiptLog.create(log_dir, log_id=f"urn:aeos:{self.domain}",
                                             key_path=priv / "log-signing.key")
            (f / "public-key.txt").write_text(self.log.public_key.hex() + "\n")

            self.ledger: Optional[books.Books] = None
            b = self.doc.get("books")
            self.controllers = [p["id"] for p in self.doc["people"] if p.get("controller")]
            if b:
                self.ledger = books.Books(
                    self.log, agent=self.books_service, entity=b["entity"], ledger=b["ledger"],
                    currency=b["currency"], accounts=dict(b["accounts"]),
                    controllers={self.person(c): keys.public_bytes(self.people[c])
                                 for c in self.controllers}).restore()
                if not self.ledger.periods:                 # a new ledger: open this month
                    self.change_period(f"{dt.date.today():%Y-%m}", "open", self.controllers[0])
            self._witnesses()
            self._manifest(self.controllers)
            return self

    def start(self, port: int = 0) -> int:
        """Prepare the evidence folder and serve the gateway; returns its port."""
        with self._lock:
            self.open()
            f, priv = self.folder, self.private
            tools, facts = self._systems()
            if self.ledger is not None:
                tools[books.TOOL] = self.ledger.tool()
            rules = self._rules()
            intents = self._intents(self.people, self.authority)

            gw_svid = self._issue("gateway", self.gateway_id)
            self.gateway = Gateway(
                self.log, tools, trust_domain=self.domain, svid_files=gw_svid,
                bundle_file=f / "trust" / "bundle.pem",
                permissions={self.agent(a["id"]): list(a.get("tools") or [])
                             for a in self.doc["agents"]},
                authority_key=self.authority.public_key, intents=intents,
                principal_keys={k: bytes.fromhex(v) for k, v in self.principals.items()},
                policy=rules, policy_facts=facts if rules is not None else None)
            self._restore(self.gateway)
            for a in self.doc["agents"]:
                self._issue(a["id"], self.agent(a["id"]))
            self.port = self.gateway.start(port=port)
            self._manifest(self.controllers)
            for a in self.doc["agents"]:
                self._connect_files(a["id"])
            (priv / "running.json").write_text(json.dumps(
                {"port": self.port, "pid": os.getpid()}) + "\n")
            self._stop.clear()
            self._renewer = threading.Thread(target=self._renew_loop, daemon=True)
            self._renewer.start()
            return self.port

    def _systems(self) -> Tuple[Dict[str, Callable], Callable[[str, Dict], Dict]]:
        tools: Dict[str, Callable] = {}
        fact_fns: List[Callable[[str, Dict], Dict]] = []
        for s in self.doc["systems"]:
            if s["type"] == "example-erp":
                erp = ExampleErp(s, self.private / "state" / f"{s['id']}.json")
                tools.update(erp.tools(self.currency))
                fact_fns.append(erp.facts)
            elif s["type"] == "python":
                mod = _python_module(self.folder, s)
                tools.update(mod.TOOLS)
                if callable(getattr(mod, "facts", None)):
                    fact_fns.append(mod.facts)
            elif s["type"] == "mcp-stdio":
                server = McpServer(s, self.folder)
                self._servers.append(server)
                tools.update(server.tools())

        def facts(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            for fn in fact_fns:
                out.update(fn(tool, args) or {})
            if "invoice" in out and isinstance(out["invoice"], dict):
                out["invoice"]["currency"] = out["invoice"].get("currency") or self.currency
            return out
        return tools, facts

    def _rules(self) -> Optional[policy.Policy]:
        rules = self.doc.get("rules") or {"type": "none"}
        approvers = [self.person(p["id"]) for p in self.doc["people"] if p.get("approver")]
        if rules["type"] == "payments":
            data = {"escalate_above_minor": minor(rules.get("approval_above", "0")),
                    "sanctioned_vendors": list(rules.get("sanctioned_suppliers") or []),
                    "approvers": approvers}
            module = policy.Policy.load(PAYMENTS_WASM, data, PAYMENTS_ENTRYPOINT)
        elif rules["type"] == "wasm":
            data = {"approvers": approvers, **(rules.get("data") or {})}
            module = policy.Policy.load(self.folder / rules["file"], data, rules["entrypoint"])
        else:
            return None
        pdir = self.folder / "policies"
        (pdir / f"{module.sha256.hex()}.wasm").write_bytes(module.wasm)
        (pdir / f"data-{module.data_sha256.hex()}.json").write_text(
            json.dumps(data, indent=2) + "\n")
        return module

    def _intents(self, people: Dict[str, Ed25519PrivateKey],
                 authority: delegation.Authority) -> Dict[str, delegation.IntentEnvelope]:
        """Each agent's signed intent, kept while its terms and time still hold, and the
        capability token minted from it."""
        held: Dict[str, delegation.IntentEnvelope] = {}
        for p in (self.folder / "intents").glob("*.json"):
            env = delegation.IntentEnvelope.from_json(json.loads(p.read_text()))
            held[env.cid] = env
        now = dt.datetime.now(dt.timezone.utc)
        soon = int((now + dt.timedelta(minutes=30)).timestamp() * 1000)
        for a in self.doc["agents"]:
            who, principal = self.agent(a["id"]), self.person(a["authorized_by"])
            terms = (principal, who, list(a.get("tools") or []),
                     minor(a.get("per_call_limit", "0")), minor(a.get("budget", "0")),
                     self.currency, str(a.get("purpose", "")))
            env = next((e for e in sorted(held.values(), key=lambda e: -e.not_after)
                        if (e.principal, e.audience, list(e.actions), e.per_action_max_minor,
                            e.budget_minor, e.currency, e.purpose) == terms
                        and e.not_after > soon), None)
            if env is None:
                env = delegation.IntentEnvelope(
                    principal=principal, audience=who, purpose=terms[6], actions=terms[2],
                    per_action_max_minor=terms[3], budget_minor=terms[4], currency=terms[5],
                    not_after=int((now + dt.timedelta(hours=float(a.get("valid_hours", 8))))
                                  .timestamp() * 1000)).sign(people[a["authorized_by"]])
                (self.folder / "intents" / f"{env.cid}.json").write_text(
                    json.dumps(env.to_json(), indent=2) + "\n")
                held[env.cid] = env
            raw = authority.mint(env, keys.public_bytes(people[a["authorized_by"]])).to_bytes()
            self.tokens[a["id"]] = raw
            (self.folder / "tokens" / f"{delegation.token_sha256(raw).hex()}.biscuit") \
                .write_bytes(raw)
        return held

    def _restore(self, gw: Gateway) -> None:
        """Bring back what the gateway keeps in memory: spending against each intent and
        escalations that are still open."""
        records = [(e, self.log.record(e)) for e in self.log.entries()]
        by_cid = {e.cid: r for e, r in records}
        ran = {r["parents"][0] for _, r in records if r["kind"] == "tool.result"
               and r["parents"] and r["body"].get("outcome") != "error"}
        settled = set()
        for e, r in records:
            body = r["body"]
            if r["kind"] == "policy.decision" and body.get("policy") == delegation.POLICY \
                    and body.get("decision") == "allow" and r["parents"] \
                    and r["parents"][0] in ran and body.get("intent"):
                gw.budget.spent[body["intent"]] = gw.budget.spent.get(body["intent"], 0) \
                    + int(body.get("amount") or 0)
            if r["kind"] == "approval" and len(r["parents"]) > 1:
                call = r["parents"][1]
                if any(rr["kind"] == "policy.decision" and rr["parents"] == [call]
                       and rr["body"].get("policy") == policy.POLICY
                       and rr["body"].get("decision") == "allow" for _, rr in records):
                    settled.add(cid_str(r["parents"][0]))
        for e, r in records:
            body = r["body"]
            if r["kind"] == "policy.decision" and body.get("policy") == policy.POLICY \
                    and body.get("decision") == "escalate" and cid_str(e.cid) not in settled:
                call = by_cid.get(r["parents"][0]) if r["parents"] else None
                if call is not None:
                    gw.escalations[cid_str(e.cid)] = (call["agent"], call["subject"],
                                                      call["body"].get("args_sha256"))

    def _witnesses(self) -> None:
        w = self.doc["witnesses"]
        self.witnesses = [witness.Witness(n, _key(self.private / "witnesses" / f"{n}.key"),
                                          self.private / "witnesses" / f"{n}.json")
                          for n in w["names"]]
        old = json.loads((self.folder / "witnesses.json").read_text()) \
            if (self.folder / "witnesses.json").exists() else {}
        (self.folder / "witnesses.json").write_text(json.dumps(
            {"required": int(w["required"]),
             "keys": {**old.get("keys", {}), **{x.name: x.public_key.hex()
                                                for x in self.witnesses}}}, indent=2) + "\n")

    def _issue(self, name: str, spiffe_id: str) -> Tuple[Path, Path]:
        svid = self.td.issue(spiffe_id)
        files = svid.write(self.private / "svids", name)
        shutil.copy(files[0], self.folder / "svids" / f"{identity.fingerprint(svid.leaf)[:16]}.pem")
        self.svid_files[name] = files
        return files

    def _connect_files(self, aid: str) -> Path:
        """What an agent outside this process needs to connect: its certificate and key,
        the trust bundle, its capability token and where the gateway listens."""
        d = self.private / "connect" / aid
        d.mkdir(parents=True, exist_ok=True)
        cert, key = self.svid_files[aid]
        shutil.copy(cert, d / "svid.pem")
        shutil.copy(key, d / "svid.key")
        (d / "svid.key").chmod(0o600)
        shutil.copy(self.folder / "trust" / "bundle.pem", d / "bundle.pem")
        (d / "token.txt").write_text(base64.urlsafe_b64encode(
            self.tokens[aid]).decode() + "\n")
        (d / "gateway.json").write_text(json.dumps(
            {"host": "127.0.0.1", "port": self.port, "gateway_id": self.gateway_id,
             "trust_domain": self.domain, "agent": self.agent(aid)}, indent=2) + "\n")
        return d

    def _manifest(self, controllers: List[str]) -> None:
        path = self.folder / "evidence.json"
        old = json.loads(path.read_text()) if path.exists() else {}
        manifest = {"format": "aeos-evidence/v0", "trust_domain": self.domain,
                    "bundle": "trust/bundle.pem", "svids": "svids", "log": "log",
                    "witnesses": "witnesses.json", "authority": "trust/authority-public-key.txt",
                    "principals": "trust/principals.json", "intents": "intents",
                    "tokens": "tokens", "workspace": FILE}
        if self.doc.get("rules", {}).get("type", "none") != "none" or old.get("policies"):
            manifest["policies"] = "policies"
        b = self.doc.get("books")
        if b or old.get("books"):
            was = old.get("books") or {}
            manifest["books"] = {
                "service": self.books_service,
                "controllers": sorted(set(was.get("controllers") or []) |
                                      {self.person(c) for c in controllers}),
                "accounts": {**(was.get("accounts") or {}), **((b or {}).get("accounts") or {})}}
        path.write_text(json.dumps(manifest, indent=2) + "\n")

    def _renew_loop(self) -> None:
        while not self._stop.wait(RENEW_EVERY):
            try:
                self.renew()
            except Exception:                           # try again next time
                pass

    def renew(self) -> None:
        """New certificates for the gateway and the agents, before the old ones expire.
        SPIRE does this in production; agents re-read their files in private/connect/."""
        with self._lock:
            if self.td.refresh(self.private / "ca"):
                (self.folder / "trust" / "bundle.pem").write_bytes(self.td.bundle_pem())
            cert, key = self._issue("gateway", self.gateway_id)
            assert self.gateway is not None
            self.gateway.context.load_cert_chain(str(cert), str(key))
            for a in self.doc["agents"]:
                self._issue(a["id"], self.agent(a["id"]))
                self._connect_files(a["id"])

    def stop(self, seal: bool = True) -> None:
        self._stop.set()
        with self._lock:
            if self.gateway is not None:
                self.gateway.stop()
                for sha, raw in self.gateway.tokens.items():
                    (self.folder / "tokens" / f"{sha}.biscuit").write_bytes(raw)
                self.gateway = None
            for s in self._servers:
                s.stop()
            self._servers = []
            (self.private / "running.json").unlink(missing_ok=True)
            if seal and hasattr(self, "log"):
                self.seal()

    def __enter__(self) -> "Platform":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # actions
    def client(self, aid: str) -> AgentClient:
        """An MCP client for one of the workspace's agents, with its certificate and token.
        When `aeos up` serves the workspace in another process, its connection files."""
        if self.gateway is None:
            return remote_client(self.folder, aid)
        if aid not in self.tokens:
            raise WorkspaceError(f"{aid} is not one of the agents in this workspace")
        return AgentClient(self.port, self.svid_files[aid], self.folder / "trust" / "bundle.pem",
                           gateway_id=self.gateway_id, trust_domain=self.domain,
                           token=self.tokens[aid])

    def call(self, aid: str, tool: str, args: Dict[str, Any],
             approval: Optional[delegation.Approval] = None) -> Dict[str, Any]:
        """Make one tool call as an agent; the gateway's answer and the trace of checks."""
        self._asked[json_digest(args).hex()] = args
        c = self.client(aid)
        c.initialize()
        try:
            reply = c.call(tool, args, approval=approval)
        finally:
            c.close()
        return answer(self.log, reply, self.agent(aid), tool, self.names())

    def approve(self, escalation: str, person: str, verdict: str = "approve",
                args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """A person answers an escalation: sign the answer and repeat the call with it.
        `args` are the call's arguments, needed when the call was not made here."""
        try:
            esc = self.log.record(self.log.entry(escalation))
            call = self.log.record(self.log.entry(cid_str(esc["parents"][0])))
        except (KeyError, IndexError, ValueError):
            raise WorkspaceError("there is no such escalation in the log") from None
        if esc["kind"] != "policy.decision" or esc["body"].get("decision") != "escalate":
            raise WorkspaceError("that record is not an escalation")
        agent_id, tool, digest = call["agent"], call["subject"], call["body"]["args_sha256"]
        args = args if args is not None else self._asked.get(digest.hex())
        if args is None or json_digest(args) != digest:
            raise WorkspaceError("this escalation is for a call made elsewhere; the agent "
                                 "repeats that call itself with the person's approval")
        aid = agent_id.rsplit("/", 1)[-1]
        a = delegation.Approval(escalation=escalation, approver=self.person(person),
                                decision=verdict, tool=tool, args_sha256=digest,
                                time=now_ms()).sign(self.person_key(person))
        return self.call(aid, tool, args, approval=a)

    def change_period(self, period: str, state: str, person: str) -> Dict[str, Any]:
        """A controller opens or closes a period, signing the change."""
        if self.ledger is None:
            raise WorkspaceError("this workspace has no books")
        p = next((x for x in self.doc["people"] if x["id"] == person), None)
        if p is None or not p.get("controller"):
            raise WorkspaceError(f"{person} is not a controller")
        e = self.ledger.transition(books.PeriodTransition(
            entity=self.ledger.entity, ledger=self.ledger.ledger, period=period, state=state,
            by=self.person(person), time=now_ms()).sign(self.person_key(person)))
        return {"period": period, "state": state, "record": e.index}

    def seal(self) -> Dict[str, Any]:
        """Sign a checkpoint and have the witnesses cosign it."""
        with self._lock:
            cp = self.log.checkpoint()
            got = witness.request_cosignatures(self.log, cp, self.witnesses)
            return {"size": cp.size, "witnesses": [g["witness"] for g in got]}


def answer(log: ReceiptLog, reply: Dict[str, Any], agent: str, tool: str,
           names: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The gateway's reply in plain terms, with the trace of the call it made."""
    result = reply.get("result") or {}
    text = " ".join(c.get("text", "") for c in result.get("content") or [])
    out: Dict[str, Any] = {"ok": not result.get("isError"), "text": text,
                           "result": result.get("structuredContent")}
    for e in reversed(log.entries()):                 # the agent's latest call of this tool
        r = log.record(e)
        if r["kind"] == "tool.call" and r["agent"] == agent and r["subject"] == tool:
            out["trace"] = report.trace(log, str(e.index), names)
            break
    return out


def names_of(folder: Path) -> Dict[str, str]:
    """Readable names for the SPIFFE IDs in a workspace, or nothing for another folder."""
    try:
        doc = load(folder)
        dom = doc["organization"]["trust_domain"]
        out = {f"spiffe://{dom}/human/{p['id']}": p.get("name") or p["id"]
               for p in doc.get("people") or []}
        out.update({f"spiffe://{dom}/agent/{x['id']}": x.get("name") or x["id"]
                    for x in doc.get("agents") or []})
        return out
    except (WorkspaceError, KeyError, TypeError):
        return {}


def connect(folder: Path) -> Tuple[Platform, bool]:
    """The workspace's platform: attached to `aeos up` when it runs, or started here.
    Returns (platform, started); stop a platform started here when done."""
    p = Platform(folder)
    if running(folder):
        return p.open(), False
    p.start()
    return p, True


def running(folder: Path) -> Optional[Dict[str, Any]]:
    """Where `aeos up` serves this workspace, if it is running."""
    path = Path(folder) / "private" / "running.json"
    if not path.exists():
        return None
    info = json.loads(path.read_text())
    try:                                     # something answers on the gateway's port
        socket.create_connection(("127.0.0.1", int(info["port"])), timeout=1).close()
    except (OSError, ValueError, KeyError):
        return None
    return info


def remote_client(folder: Path, aid: str) -> AgentClient:
    """An MCP client for an agent of a workspace that `aeos up` is serving."""
    d = Path(folder) / "private" / "connect" / aid
    if not (d / "gateway.json").exists():
        raise WorkspaceError(f"no connection files for {aid}; is it one of the agents?")
    g = json.loads((d / "gateway.json").read_text())
    return AgentClient(int(g["port"]), (d / "svid.pem", d / "svid.key"), d / "bundle.pem",
                       gateway_id=g["gateway_id"], trust_domain=g["trust_domain"],
                       token=base64.urlsafe_b64decode(
                           (d / "token.txt").read_text().strip()))


def parse_args(pairs: List[str]) -> Dict[str, Any]:
    """Tool arguments from key=value words; values that read as JSON (numbers, lists)
    are taken as JSON, the rest as text."""
    out: Dict[str, Any] = {}
    for p in pairs:
        if "=" not in p:
            raise ValueError(f"{p!r} is not key=value")
        k, v = p.split("=", 1)
        try:
            out[k] = json.loads(v)
        except ValueError:
            out[k] = v
    return out


__all__ = ["Platform", "WorkspaceError", "check", "create", "example", "load", "save",
           "minor", "parse_args", "remote_client", "running", "answer"]
