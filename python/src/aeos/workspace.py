"""A workspace: one file that describes a company's AE-OS, and the runtime that runs it.

`workspace.json` names the organization and its legal entities, its people, the
instructions they sign, its agents and what each may do, the systems that provide tools,
the rules, the books of account and the witnesses. `Platform` sets the company up step by
step, the way the architecture is built (see STEPS), and then runs the whole stack on one
computer: a certificate authority and SPIFFE identities, an authorization service, the MCP
gateway with the rules, the books, the receipt log and the witnesses. The workspace folder
is also an evidence folder, so `aeos audit`, the reports and the browser page work on it
unchanged.

    aeos new my-company          create a workspace from the Kestrel Foods example
    aeos build my-company        set it up step by step, without starting the gateway
    aeos up my-company           run it; agents connect with the files in private/connect/
    aeos call my-company --as stock/02 erp.stock.ageing site=OHIO

Private keys stay in private/. Here the people's signing keys are files on
this computer, so the platform can sign an instruction or an approval for a person when
asked to. In production each person signs with their own passkey or smart card.
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

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from biscuit_auth import Biscuit

from . import books, delegation, examples, identity, keys, policy, report, witness
from .canon import cid_of_bytes, cid_str, dag_cbor, json_digest
from .gateway import AgentClient, Gateway
from .log import ReceiptLog, make_record, now_ms

FORMAT = examples.FORMAT
FILE = "workspace.json"
POLICIES = Path(__file__).with_name("policies")
PAYMENTS_WASM = POLICIES / "payments.wasm"
PAYMENTS_ENTRYPOINT = "aeos/payments/decision"
CLOSE_WASM = POLICIES / "close.wasm"
CLOSE_ENTRYPOINT = "aeos/close/decision"
SYSTEM_TYPES = ("records", "example-erp", "python", "mcp-stdio")
RULE_TYPES = ("close", "payments", "wasm", "none")
RENEW_EVERY = 300                    # seconds; SVIDs live 15 minutes, renewed well before
_ID = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")
_AGENT_ID = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(/[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?){0,3}$")
_ENTITY = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,30}$")

# The order a company is set up in, as the architecture builds it. Each step can run on
# its own (Platform.run); "section" names the matching section of How it works on
# ae-os.org and "film" the chapter of the film.
STEPS: List[Dict[str, Any]] = [
    {"id": "organization", "title": "Organization", "layer": "people", "section": None,
     "film": None, "module": "workspace",
     "text": "Name the company and its legal entities, and choose its trust domain: the "
             "domain name under which every person, agent and service gets an identity."},
    {"id": "pki", "title": "Certificate authority", "layer": "controls",
     "section": "02 Identity", "film": 1, "module": "identity",
     "text": "Create the company's own certificate authority: a root certificate, kept "
             "offline in production, and an intermediate that signs short-lived "
             "certificates. Anyone who trusts the root can check every identity the "
             "company issues."},
    {"id": "people", "title": "People", "layer": "people", "section": "01 Authority",
     "film": 1, "module": "keys",
     "text": "Give each person a signing key. People sign instructions, approvals and "
             "period changes. In production they sign with a passkey or a digital identity "
             "wallet."},
    {"id": "agents", "title": "Agents", "layer": "agents", "section": "03 Agents",
     "film": 2, "module": "workspace",
     "text": "Describe each agent as one bundle: its identity, task, tools, limit per call "
             "and the books it may post to. The bundle's fingerprint is computed from its "
             "contents, so any change makes a new agent."},
    {"id": "identities", "title": "SPIFFE identities", "layer": "controls",
     "section": "02 Identity", "film": 1, "module": "identity",
     "text": "Issue each agent and the gateway an identity certificate in the SPIFFE "
             "standard that lasts 15 minutes. Agents prove who they are with it over "
             "mutual TLS, where both sides show a certificate, and hold no passwords. The "
             "platform renews them every 5 minutes. In production SPIRE, an identity "
             "service, issues them after checking the machine and the software."},
    {"id": "log", "title": "Receipt log", "layer": "ledger", "section": "07 Records",
     "film": 6, "module": "log",
     "text": "Start the receipt log, which records every step and regularly signs a "
             "checkpoint that fixes everything recorded so far, and register the "
             "independent witnesses who cosign each checkpoint."},
    {"id": "books", "title": "Books of account", "layer": "ledger", "section": "06 Books",
     "film": 3, "module": "books",
     "text": "Open a ledger for each entity with its chart of accounts. A controller signs "
             "which months are open and closed. The books refuse entries that do not "
             "balance or fall in a closed month."},
    {"id": "rules", "title": "Rules", "layer": "controls", "section": "05 Rules", "film": 3,
     "module": "policy",
     "text": "Load the company's rules, written in Rego, the policy language of Open Policy "
             "Agent, and compiled to WebAssembly. For "
             "each call they decide to allow it, refuse it or send it to a person, and the "
             "rules' fingerprint is recorded with every decision."},
    {"id": "systems", "title": "Systems", "layer": "systems", "section": "04 Connections",
     "film": 2, "module": "gateway",
     "text": "Connect the systems that provide tools, such as a bank and the companies' "
             "ERP systems. Agents reach them only through the gateway."},
    {"id": "instruction", "title": "Delegated authority", "layer": "people",
     "section": "01 Authority", "film": 1, "module": "delegation",
     "text": "A person signs an instruction with its limits. The authorization service "
             "checks the signature and issues each agent a capability token narrowed to "
             "its own task."},
    {"id": "gateway", "title": "Gateway", "layer": "controls", "section": "04 Connections",
     "film": 2, "module": "gateway",
     "text": "Start the gateway for MCP, the protocol agents use to call tools. Every call passes its checks in order: identity, allow "
             "list, delegated authority and rules, then the tool, the books and the "
             "receipt."},
]
STEP_IDS = [s["id"] for s in STEPS]


class WorkspaceError(Exception):
    """The workspace cannot be used as it stands."""


# ---- the file ------------------------------------------------------------------------

def example(name: str = "kestrel") -> Dict[str, Any]:
    """The workspace `aeos new` writes: Kestrel Foods, or "acme" for the payments example."""
    return examples.example(name)


def load(folder: Path) -> Dict[str, Any]:
    path = Path(folder) / FILE
    if not path.exists():
        raise WorkspaceError(f"{folder} has no {FILE}. Create one with: aeos new {folder}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
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
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
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


def fname(ident: str) -> str:
    """A file name for an agent ID, which may hold slashes, such as "stock/02"."""
    return ident.replace("/", "_")


def entities(doc: Dict[str, Any]) -> List[str]:
    """The entities that keep books: books.entities, or the older single books.entity."""
    b = doc.get("books") or {}
    if isinstance(b.get("entities"), list):
        return [str(e) for e in b["entities"]]
    return [str(b["entity"])] if b.get("entity") else []


def entity_names(doc: Dict[str, Any]) -> Dict[str, str]:
    out = {e: e for e in entities(doc)}
    for e in (doc.get("organization") or {}).get("entities") or []:
        if isinstance(e, dict) and e.get("id"):
            out[str(e["id"])] = str(e.get("name") or e["id"])
    return out


def tool_names(doc: Dict[str, Any], folder: Optional[Path] = None) -> Dict[str, str]:
    """Each tool the systems provide, with the system that provides it. MCP servers are
    asked for their tools only while the platform runs, so their tools are listed under
    the system's `tools` field when given."""
    out: Dict[str, str] = {}
    for s in doc.get("systems") or []:
        if not isinstance(s, dict):
            continue
        if s.get("type") == "example-erp":
            for t in ExampleErp.TOOLS:
                out[t] = s.get("id", "")
        elif s.get("type") == "python" and folder is not None:
            try:
                for t in _python_module(folder, s).TOOLS:
                    out[t] = s.get("id", "")
            except Exception:                       # reported by check()
                pass
        tools = s.get("tools") or []
        for t in (tools if isinstance(tools, (list, dict)) else []):
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
    org_entities = []
    for e in org.get("entities") or []:
        if not isinstance(e, dict) or not _ENTITY.match(str(e.get("id", ""))):
            p.append("each legal entity needs an id of capital letters, digits and hyphens, "
                     "such as KF-US")
        else:
            org_entities.append(e["id"])

    def ids(items: Any, what: str, pattern: "re.Pattern[str]" = _ID) -> List[str]:
        if not isinstance(items, list):
            p.append(f"{what} must be a list")
            return []
        seen: List[str] = []
        for it in items:
            i = (it or {}).get("id") if isinstance(it, dict) else None
            if not isinstance(i, str) or not pattern.match(i):
                extra = ", with / between parts such as stock/02" if pattern is _AGENT_ID else ""
                p.append(f"each entry in {what} needs an id of lower-case letters, digits and "
                         f"hyphens{extra} (found {i!r})")
            elif i in seen:
                p.append(f"{what} has the id {i} twice")
            else:
                seen.append(i)
        return seen

    people = ids(doc.get("people"), "people")
    agents = ids(doc.get("agents"), "agents", _AGENT_ID)
    systems = ids(doc.get("systems"), "systems")
    instructions = ids(doc.get("instructions") or [], "instructions")
    clash = set(people) & set(agents)
    if clash:
        p.append(f"{', '.join(sorted(clash))} is used for a person and for an agent")
    if not systems:
        p.append("add at least one system that provides tools")
    for s in doc.get("systems") or []:
        if isinstance(s, dict):
            p += _check_system(s, folder)
    tools = tool_names(doc, folder)
    persons = {x.get("id"): x for x in doc.get("people") or [] if isinstance(x, dict)}
    by_id = {x.get("id"): x for x in doc.get("instructions") or [] if isinstance(x, dict)}
    for ins in by_id.values():
        iid = ins.get("id")
        if ins.get("signed_by") not in persons:
            p.append(f"instruction {iid}: signed by must name one of the people")
        if not str(ins.get("purpose") or "").strip():
            p.append(f"instruction {iid}: write what the instruction is for")
        p += _amounts(f"instruction {iid}", ins)
        p += _hours(f"instruction {iid}", ins)
    book_entities = entities(doc)
    for a in doc.get("agents") or []:
        if not isinstance(a, dict):
            continue
        aid = a.get("id")
        if ("instruction" in a) == ("authorized_by" in a):
            p.append(f"agent {aid}: give either the instruction it works under or the person "
                     "who authorizes it")
        elif "instruction" in a:
            ins = by_id.get(a.get("instruction"))
            if ins is None:
                p.append(f"agent {aid}: instruction must name one of the instructions")
            else:
                try:
                    if minor(a.get("per_call_limit", "0")) > minor(ins.get("per_call_limit",
                                                                         "0")):
                        p.append(f"agent {aid}: the limit per call is above the "
                                 "instruction's")
                except ValueError as e:
                    p.append(f"agent {aid}: {e}")
        else:
            if a.get("authorized_by") not in persons:
                p.append(f"agent {aid}: authorized by must name one of the people")
            p += _amounts(f"agent {aid}", a)
            p += _hours(f"agent {aid}", a)
        unknown = [t for t in a.get("tools") or [] if t not in tools]
        if unknown:
            p.append(f"agent {aid}: no system provides {', '.join(unknown)}")
        for e in a.get("entities") or []:
            if e not in book_entities:
                p.append(f"agent {aid}: there are no books for {e}")
    rules = doc.get("rules") or {"type": "none"}
    kind = rules.get("type")
    approvers = any(x.get("approver") for x in persons.values())
    if kind not in RULE_TYPES:
        p.append(f"rules: the type must be one of {', '.join(RULE_TYPES)}")
    elif kind in ("payments", "close"):
        try:
            minor(rules.get("approval_above", "0"))
        except ValueError as e:
            p.append(f"rules: the approval amount: {e}")
        if not approvers:
            p.append("rules: mark at least one person as an approver, or calls above the "
                     "approval amount can never be approved")
        if kind == "close" and not isinstance(rules.get("blocked_tools") or {}, dict):
            p.append("rules: blocked tools must map each tool to the reason it is refused")
    elif kind == "wasm":
        f = Path(folder or ".") / str(rules.get("file", ""))
        if not rules.get("file") or (folder is not None and not f.is_file()):
            p.append("rules: file must name your compiled rules (.wasm) in the workspace folder")
        if not rules.get("entrypoint"):
            p.append("rules: entrypoint must name the rule that gives the decision, such as "
                     "acme/payments/decision")
    b = doc.get("books")
    if b:
        if not book_entities or not b.get("ledger"):
            p.append("books: give the entities and the ledger")
        for e in book_entities:
            if not _ENTITY.match(e):
                p.append(f"books: {e} is not an entity id of capital letters, digits and "
                         "hyphens")
            elif org_entities and e not in org_entities:
                p.append(f"books: {e} is not one of the organization's entities")
        if not re.fullmatch(r"[A-Z]{3}", str(b.get("currency", ""))):
            p.append("books: the currency must be a three-letter code, such as USD")
        if not isinstance(b.get("accounts"), dict) or not b.get("accounts"):
            p.append("books: the chart of accounts needs at least one account")
        periods = b.get("periods") or {}
        if not isinstance(periods, dict) or not all(
                books.valid_period(k) and v in books.STATES for k, v in periods.items()):
            p.append("books: each period must be written as YYYY-MM and be open or closed")
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


def _amounts(who: str, d: Dict[str, Any]) -> List[str]:
    try:
        limit, budget = minor(d.get("per_call_limit", "0")), minor(d.get("budget", "0"))
    except ValueError as e:
        return [f"{who}: {e}"]
    return [f"{who}: the budget is smaller than the limit per call"] if budget < limit else []


def _hours(who: str, d: Dict[str, Any]) -> List[str]:
    hours = d.get("valid_hours", 8)
    if not isinstance(hours, (int, float)) or isinstance(hours, bool) or not 0 < hours <= 744:
        return [f"{who}: hours valid must be between 1 and 744"]
    return []


def _check_system(s: Dict[str, Any], folder: Optional[Path]) -> List[str]:
    p: List[str] = []
    kind, sid = s.get("type"), s.get("id")
    if kind not in SYSTEM_TYPES:
        p.append(f"system {sid}: the type must be one of {', '.join(SYSTEM_TYPES)}")
    elif kind == "records":
        tools = s.get("tools")
        if not isinstance(tools, dict) or not tools:
            p.append(f"system {sid}: give at least one tool, each with its records")
            return p
        for name, t in tools.items():
            if not isinstance(t, dict) or not isinstance(t.get("records"), dict) or \
                    not all(isinstance(r, dict) for r in t["records"].values()):
                p.append(f"system {sid}: tool {name} needs records, each a set of named values")
            elif t.get("key") is not None and not isinstance(t.get("key"), str):
                p.append(f"system {sid}: tool {name}: the key must be the name of an argument")
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
        cmd = s.get("command")
        if not isinstance(cmd, list) or not cmd:
            p.append(f"system {sid}: command must be a list, such as "
                     '["python", "server.py"]')
        elif shutil.which(str(cmd[0])) is None:
            p.append(f"system {sid}: the program {cmd[0]} was not found on this computer")
        elif folder is not None and len(cmd) > 1 and str(cmd[1]).endswith(".py") \
                and not (Path(folder) / str(cmd[1])).is_file():
            p.append(f"system {sid}: there is no file {cmd[1]} in the workspace folder")
        if not isinstance(s.get("tools"), list):
            p.append(f"system {sid}: list the server's tools under tools, so agents can be "
                     "given them")
    return p


# ---- systems: where the tools come from ----------------------------------------------

class Records:
    """Records a system holds, served as read-only tools: a bank statement, a stock
    ageing report. A tool with a `key` returns the record named by that argument."""

    def __init__(self, spec: Dict[str, Any]) -> None:
        self.spec = spec

    def tools(self) -> Dict[str, Callable[[Dict[str, Any]], Any]]:
        def make(name: str, key: Optional[str], records: Dict[str, Any]) -> Callable:
            def get(args: Dict[str, Any]) -> Any:
                if not key or args.get(key) is None:
                    return {"records": [{**({key: k} if key else {"id": k}), **r}
                                        for k, r in records.items()]}
                found = records.get(str(args[key]))
                if found is None:
                    raise ValueError(f"{name} has no record for {key} {args[key]}")
                return {key: args[key], **found}
            return get
        return {name: make(name, t.get("key"), t.get("records") or {})
                for name, t in (self.spec.get("tools") or {}).items()}


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


def _part(doc: Dict[str, Any], step: str) -> Any:
    """The part of the workspace a setup step depends on; a change to it means the step
    must run again."""
    org = doc.get("organization") or {}
    td = org.get("trust_domain")
    agents = doc.get("agents") or []
    return {
        "organization": org,
        "pki": td,
        "people": [td, doc.get("people")],
        "agents": [td, agents],
        "identities": [td, [a.get("id") for a in agents]],
        "log": [td, doc.get("witnesses")],
        "books": [doc.get("books"), org.get("entities"),
                  [p.get("id") for p in doc.get("people") or [] if p.get("controller")]],
        "rules": [doc.get("rules"), [p.get("id") for p in doc.get("people") or []
                                     if p.get("approver")],
                  [[a.get("id"), a.get("entities")] for a in agents]],
        "systems": doc.get("systems"),
        "instruction": [td, doc.get("instructions"), doc.get("people"), agents,
                        (doc.get("books") or {}).get("currency")],
        "gateway": doc,
    }[step]


def _when(t: dt.datetime) -> int:
    return int(t.timestamp() * 1000)


def _cert_view(cert: x509.Certificate) -> Dict[str, Any]:
    key = cert.public_key()
    curve = getattr(getattr(key, "curve", None), "name", "")
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        uris = []
    try:
        ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        ca = False
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "spiffe": uris[0] if uris else None, "ca": ca,
            "key": {"secp384r1": "ECDSA P-384", "secp256r1": "ECDSA P-256"}.get(curve, curve),
            "not_before": _when(cert.not_valid_before_utc),
            "not_after": _when(cert.not_valid_after_utc),
            "fingerprint": identity.fingerprint(cert)}


class Platform:
    """Sets up and runs a workspace: certificate authority, identities, authority,
    gateway, rules, books, log and witnesses."""

    def __init__(self, folder: Path) -> None:
        self.folder = Path(folder).resolve()
        self.doc = load(self.folder)
        problems = check(self.doc, self.folder)
        if problems:
            raise WorkspaceError("; ".join(problems))
        self.private = self.folder / "private"
        self.gateway: Optional[Gateway] = None
        self.port: Optional[int] = None
        self.ledgers: Dict[str, books.Books] = {}
        self.ledger: Optional[books.Books] = None    # the first entity's books
        self.tokens: Dict[str, bytes] = {}          # agent id -> its capability token
        self.intents: Dict[str, delegation.IntentEnvelope] = {}
        self.svid_files: Dict[str, Tuple[Path, Path]] = {}
        self.rules: Optional[policy.Policy] = None
        self.tools: Dict[str, Callable] = {}
        self.facts: Optional[Callable[[str, Dict], Dict]] = None
        self._servers: List[McpServer] = []
        self._stop = threading.Event()
        self._renewer: Optional[threading.Thread] = None
        self._asked: Dict[str, Dict[str, Any]] = {}   # arguments of calls made here, by digest
        self._ran: List[str] = []                     # setup steps run in this process
        self._lock = threading.RLock()

    # names
    @property
    def domain(self) -> str:
        return str(self.doc["organization"]["trust_domain"])

    def person(self, pid: str) -> str:
        return spiffe(self.doc, "human", pid)

    def agent(self, aid: str) -> str:
        return spiffe(self.doc, "agent", aid)

    def agent_id(self, spiffe_id: str) -> str:
        """The workspace's id for an agent's SPIFFE ID."""
        prefix = f"spiffe://{self.domain}/agent/"
        return spiffe_id[len(prefix):] if spiffe_id.startswith(prefix) else spiffe_id

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

    @property
    def controllers(self) -> List[str]:
        return [p["id"] for p in self.doc["people"] if p.get("controller")]

    # ---- setup, step by step ---------------------------------------------------------

    def _marks(self) -> Dict[str, str]:
        path = self.private / "setup.json"
        try:
            return json.loads(path.read_text()) if path.exists() else {}
        except ValueError:
            return {}

    def _mark(self, step: str) -> None:
        marks = self._marks()
        marks[step] = json_digest(_part(self.doc, step)).hex()
        self.private.mkdir(parents=True, exist_ok=True)
        (self.private / "setup.json").write_text(json.dumps(marks, indent=2) + "\n")

    def status(self) -> List[Dict[str, Any]]:
        """Each setup step with its state: "done", "changed" (done, but the workspace has
        changed since, so it runs again on the next start) or "todo"."""
        marks, out = self._marks(), []
        serving = self.gateway is not None or running(self.folder) is not None
        for s in STEPS:
            mark = marks.get(s["id"])
            if s["id"] == "gateway":
                state = "done" if serving else "todo"
            elif mark is None:
                state = "todo"
            else:
                state = "done" if mark == json_digest(_part(self.doc, s["id"])).hex() \
                    else "changed"
            out.append({**s, "state": state})
        return out

    def run(self, step: str) -> Dict[str, Any]:
        """Run one setup step, after any earlier step this process has not run yet, and
        describe what it made. Every step can run again safely."""
        if step not in STEP_IDS:
            raise WorkspaceError(f"there is no setup step called {step}")
        with self._lock:
            for s in STEP_IDS[:STEP_IDS.index(step) + 1]:
                if s not in self._ran or s == step:
                    getattr(self, f"_step_{s}")()
                    self._ran.append(s)
                    if s != "gateway":
                        self._mark(s)
            return self.describe(step)

    def _step_organization(self) -> None:
        f, priv = self.folder, self.private
        priv.mkdir(parents=True, exist_ok=True)
        priv.chmod(0o700)
        for d in ("trust", "svids", "intents", "tokens", "policies", "agents"):
            (f / d).mkdir(exist_ok=True)
        self._manifest()

    def _step_pki(self) -> None:
        ca = self.private / "ca"
        td = None
        if (ca / "root.pem").exists():
            td = identity.TrustDomain.load(self.domain, ca)
            if _cert_view(td.root)["spiffe"] != f"spiffe://{self.domain}":
                td = None                       # the trust domain was renamed: a new CA
        if td is None:
            td = identity.TrustDomain(self.domain)
            td.save(ca)
        self.td = td
        (self.folder / "trust" / "bundle.pem").write_bytes(self.td.bundle_pem())

    def _step_people(self) -> None:
        self.people = {p["id"]: self.person_key(p["id"]) for p in self.doc["people"]}
        self.principals = _merge_json(self.folder / "trust" / "principals.json",
                                      {self.person(i): keys.public_bytes(k).hex()
                                       for i, k in self.people.items()})

    def bundle(self, a: Dict[str, Any]) -> Dict[str, Any]:
        """An agent's bundle (its Agent Primitive Object): what defines the agent."""
        out = {"id": a["id"], "spiffe_id": self.agent(a["id"]),
               "name": a.get("name") or a["id"], "purpose": str(a.get("purpose", "")),
               "tools": sorted(a.get("tools") or []),
               "per_call_limit_minor": minor(a.get("per_call_limit", "0")),
               "currency": self.currency, "entities": list(a.get("entities") or [])}
        if a.get("team"):
            out["team"] = a["team"]
        if "instruction" in a:
            out["instruction"] = a["instruction"]
        else:
            out["authorized_by"] = self.person(a["authorized_by"])
            out["budget_minor"] = minor(a.get("budget", "0"))
        return out

    def _step_agents(self) -> None:
        for a in self.doc["agents"]:
            b = self.bundle(a)
            cid = cid_str(cid_of_bytes(dag_cbor(b)))
            (self.folder / "agents" / f"{cid}.json").write_text(json.dumps(
                {"cid": cid, "bundle": b}, indent=2) + "\n")

    def _step_identities(self) -> None:
        for a in self.doc["agents"]:
            self._issue(a["id"], self.agent(a["id"]))

    def _step_log(self) -> None:
        f, priv = self.folder, self.private
        log_dir = f / "log"
        if (log_dir / "log.json").exists():
            self.log = ReceiptLog.open(log_dir, key_path=priv / "log-signing.key")
        else:
            self.log = ReceiptLog.create(log_dir, log_id=f"urn:aeos:{self.domain}",
                                         key_path=priv / "log-signing.key")
        (f / "public-key.txt").write_text(self.log.public_key.hex() + "\n")
        self._witnesses()

    def _step_books(self) -> None:
        b = self.doc.get("books")
        self.ledgers = {}
        if b:
            for e in entities(self.doc):
                self.ledgers[e] = books.Books(
                    self.log, agent=self.books_service, entity=e, ledger=b["ledger"],
                    currency=b["currency"], accounts=dict(b["accounts"]),
                    controllers={self.person(c): keys.public_bytes(self.people[c])
                                 for c in self.controllers}).restore()
            for e, led in self.ledgers.items():
                if led.periods:
                    continue
                start = b.get("periods") or {f"{dt.date.today():%Y-%m}": "open"}
                for period, state in sorted(start.items()):
                    self.change_period(period, state, self.controllers[0], entity=e)
        self.ledger = next(iter(self.ledgers.values()), None)
        self._manifest()

    def _step_rules(self) -> None:
        self.rules = self._rules()

    def _step_systems(self) -> None:
        for s in self._servers:
            s.stop()
        self._servers = []
        self.tools, self.facts = self._systems()

    def _step_instruction(self) -> None:
        priv = self.private
        auth_path = priv / "authority.key"
        if auth_path.exists():
            self.authority = delegation.Authority(auth_path.read_bytes())
        else:
            self.authority = delegation.Authority()
            auth_path.write_bytes(self.authority.private_bytes())
            auth_path.chmod(0o600)
        (self.folder / "trust" / "authority-public-key.txt").write_text(
            self.authority.public_key.hex() + "\n")
        self.intents = self._intents()

    def _step_gateway(self) -> None:
        f, priv = self.folder, self.private
        tools = dict(self.tools)
        if self.ledgers:
            tools[books.TOOL] = self._ledger_tool()
        if self.gateway is not None:
            self.gateway.stop()
        gw_svid = self._issue("gateway", self.gateway_id)
        self.gateway = Gateway(
            self.log, tools, trust_domain=self.domain, svid_files=gw_svid,
            bundle_file=f / "trust" / "bundle.pem",
            permissions={self.agent(a["id"]): list(a.get("tools") or [])
                         for a in self.doc["agents"]},
            authority_key=self.authority.public_key, intents=self.intents,
            principal_keys={k: bytes.fromhex(v) for k, v in self.principals.items()},
            policy=self.rules, policy_facts=self.facts if self.rules is not None else None)
        self._restore(self.gateway)
        for a in self.doc["agents"]:
            self._issue(a["id"], self.agent(a["id"]))
        self.port = self.gateway.start(port=self._port)
        self._manifest()
        for a in self.doc["agents"]:
            self._connect_files(a["id"])
        (priv / "running.json").write_text(json.dumps(
            {"port": self.port, "pid": os.getpid()}) + "\n")
        self._stop.clear()
        self._renewer = threading.Thread(target=self._renew_loop, daemon=True)
        self._renewer.start()

    _port = 0

    def open(self) -> "Platform":
        """Keys, log, books and witnesses, without serving the gateway. Enough to sign a
        period change or seal the log while `aeos up` runs in another process."""
        with self._lock:
            for s in ("organization", "pki", "people", "log", "books"):
                if s not in self._ran:
                    getattr(self, f"_step_{s}")()
                    self._ran.append(s)
            return self

    def start(self, port: int = 0) -> int:
        """Run every setup step and serve the gateway; returns its port."""
        self._port = port
        try:
            with self._lock:
                self._ran = []
                self.run("gateway")
                assert self.port is not None
                return self.port
        except Exception:
            self.stop(seal=False)              # leave nothing half started
            raise

    def _ledger_tool(self) -> Callable[..., Dict[str, Any]]:
        """`ledger.post` for every entity's books: the `entity` argument picks the books,
        and the first entity's are used when it is left out."""
        first = next(iter(self.ledgers))

        def post(args: Dict[str, Any], call: Any) -> Dict[str, Any]:
            entity = args.get("entity", first)
            led = self.ledgers.get(entity) if isinstance(entity, str) else None
            if led is None:
                reasons = [f"there are no books for {entity} here"]
                self.log.append(make_record(
                    "policy.decision", self.books_service, subject=books.TOOL,
                    parents=[call.cid], body={"decision": "deny", "policy": books.POLICY,
                                              "reasons": reasons}))
                raise books.Refused(reasons)
            return led.post(args, call)
        post.takes_call = True  # type: ignore[attr-defined]
        return post

    def _systems(self) -> Tuple[Dict[str, Callable], Callable[[str, Dict], Dict]]:
        tools: Dict[str, Callable] = {}
        fact_fns: List[Callable[[str, Dict], Dict]] = []
        for s in self.doc["systems"]:
            if s["type"] == "records":
                tools.update(Records(s).tools())
            elif s["type"] == "example-erp":
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

    def rules_data(self) -> Optional[Tuple[Path, Dict[str, Any], str]]:
        """The compiled rules, the data they read and their entrypoint; None for none."""
        rules = self.doc.get("rules") or {"type": "none"}
        approvers = [self.person(p["id"]) for p in self.doc["people"] if p.get("approver")]
        if rules["type"] == "payments":
            return PAYMENTS_WASM, {
                "escalate_above_minor": minor(rules.get("approval_above", "0")),
                "sanctioned_vendors": list(rules.get("sanctioned_suppliers") or []),
                "approvers": approvers}, PAYMENTS_ENTRYPOINT
        if rules["type"] == "close":
            limit = minor(rules.get("approval_above", "0"))
            return CLOSE_WASM, {
                "escalate_above_minor": limit,
                "escalate_reason": f"amounts above {delegation.money(limit, self.currency)} "
                                   "need approval from someone on the approvers list",
                "approvers": approvers,
                "blocked_tools": dict(rules.get("blocked_tools") or {}),
                "agent_entities": {self.agent(a["id"]): list(a["entities"])
                                   for a in self.doc["agents"] if a.get("entities")},
                "default_entity": (entities(self.doc) or [""])[0]}, CLOSE_ENTRYPOINT
        if rules["type"] == "wasm":
            return self.folder / rules["file"], {"approvers": approvers,
                                                 **(rules.get("data") or {})}, \
                rules["entrypoint"]
        return None

    def _rules(self) -> Optional[policy.Policy]:
        found = self.rules_data()
        if found is None:
            return None
        path, data, entrypoint = found
        module = policy.Policy.load(path, data, entrypoint)
        pdir = self.folder / "policies"
        (pdir / f"{module.sha256.hex()}.wasm").write_bytes(module.wasm)
        (pdir / f"data-{module.data_sha256.hex()}.json").write_text(
            json.dumps(data, indent=2) + "\n")
        return module

    def _terms(self) -> List[Tuple[str, Dict[str, Any], List[Dict[str, Any]]]]:
        """Each intent to sign: (signer, terms, agents it covers). An instruction covers
        all its agents with one envelope; an agent authorized directly gets its own."""
        out = []
        for ins in self.doc.get("instructions") or []:
            covered = [a for a in self.doc["agents"] if a.get("instruction") == ins["id"]]
            if not covered:
                continue
            out.append((ins["signed_by"], {
                "principal": self.person(ins["signed_by"]),
                "audience": f"spiffe://{self.domain}/agent",
                "purpose": str(ins.get("purpose", "")),
                "actions": sorted({t for a in covered for t in a.get("tools") or []}),
                "per_action_max_minor": minor(ins.get("per_call_limit", "0")),
                "budget_minor": minor(ins.get("budget", "0")), "currency": self.currency,
                "hours": float(ins.get("valid_hours", 8))}, covered))
        for a in self.doc["agents"]:
            if "authorized_by" in a:
                out.append((a["authorized_by"], {
                    "principal": self.person(a["authorized_by"]),
                    "audience": self.agent(a["id"]), "purpose": str(a.get("purpose", "")),
                    "actions": sorted(a.get("tools") or []),
                    "per_action_max_minor": minor(a.get("per_call_limit", "0")),
                    "budget_minor": minor(a.get("budget", "0")), "currency": self.currency,
                    "hours": float(a.get("valid_hours", 8))}, [a]))
        return out

    def _intents(self) -> Dict[str, delegation.IntentEnvelope]:
        """Each signed intent, kept while its terms and time still hold, and each agent's
        capability token: minted from the intent and, under an instruction, narrowed to
        the agent's own identity, tools and limit."""
        held: Dict[str, delegation.IntentEnvelope] = {}
        for p in (self.folder / "intents").glob("*.json"):
            env = delegation.IntentEnvelope.from_json(json.loads(p.read_text()))
            held[env.cid] = env
        now = dt.datetime.now(dt.timezone.utc)
        soon = int((now + dt.timedelta(minutes=30)).timestamp() * 1000)
        index: Dict[str, Any] = {}
        for signer, t, covered in self._terms():
            same = [e for e in held.values()
                    if (e.principal, e.audience, e.purpose, sorted(e.actions),
                        e.per_action_max_minor, e.budget_minor, e.currency)
                    == (t["principal"], t["audience"], t["purpose"], t["actions"],
                        t["per_action_max_minor"], t["budget_minor"], t["currency"])
                    and e.not_after > soon]
            env = max(same, key=lambda e: e.not_after) if same else None
            if env is None:
                env = delegation.IntentEnvelope(
                    principal=t["principal"], audience=t["audience"], purpose=t["purpose"],
                    actions=t["actions"], per_action_max_minor=t["per_action_max_minor"],
                    budget_minor=t["budget_minor"], currency=t["currency"],
                    not_after=int((now + dt.timedelta(hours=t["hours"])).timestamp() * 1000)
                ).sign(self.people[signer])
                (self.folder / "intents" / f"{env.cid}.json").write_text(
                    json.dumps(env.to_json(), indent=2) + "\n")
                held[env.cid] = env
            base = self.authority.mint(env, keys.public_bytes(self.people[signer]))
            for a in covered:
                token = base if env.audience == self.agent(a["id"]) else \
                    delegation.attenuate(base, subject=self.agent(a["id"]),
                                         actions=sorted(a.get("tools") or []),
                                         max_minor=minor(a.get("per_call_limit", "0")))
                raw = token.to_bytes()
                sha = delegation.token_sha256(raw).hex()
                self.tokens[a["id"]] = raw
                (self.folder / "tokens" / f"{sha}.biscuit").write_bytes(raw)
                index[a["id"]] = {"intent": env.cid, "token_sha256": sha}
        (self.private / "tokens.json").write_text(json.dumps(index, indent=2) + "\n")
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
                       and rr["body"].get("decision") == "allow"
                       for _, rr in records):
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
        files = svid.write(self.private / "svids", fname(name))
        shutil.copy(files[0], self.folder / "svids" / f"{identity.fingerprint(svid.leaf)[:16]}.pem")
        self.svid_files[name] = files
        return files

    def _connect_files(self, aid: str) -> Path:
        """What an agent outside this process needs to connect: its certificate and key,
        the trust bundle, its capability token and where the gateway listens."""
        d = self.private / "connect" / fname(aid)
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

    def _manifest(self) -> None:
        path = self.folder / "evidence.json"
        old = json.loads(path.read_text()) if path.exists() else {}
        manifest = {"format": "aeos-evidence/v0", "trust_domain": self.domain,
                    "bundle": "trust/bundle.pem", "svids": "svids", "log": "log",
                    "witnesses": "witnesses.json", "authority": "trust/authority-public-key.txt",
                    "principals": "trust/principals.json", "intents": "intents",
                    "tokens": "tokens", "agents": "agents", "workspace": FILE}
        if self.doc.get("rules", {}).get("type", "none") != "none" or old.get("policies"):
            manifest["policies"] = "policies"
        b = self.doc.get("books")
        if b or old.get("books"):
            was = old.get("books") or {}
            manifest["books"] = {
                "service": self.books_service,
                "controllers": sorted(set(was.get("controllers") or []) |
                                      {self.person(c) for c in self.controllers}),
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
                self.port = None
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

    # ---- what each step made, for the page and `aeos init` ---------------------------

    def describe(self, step: str) -> Dict[str, Any]:
        """What a setup step made, read from the workspace folder."""
        info = next(s for s in self.status() if s["id"] == step)
        out: Dict[str, Any] = {"step": info}
        if info["state"] == "todo" and step != "organization":
            return out
        try:
            out.update(getattr(self, f"_view_{step}")())
        except (OSError, ValueError, KeyError) as e:
            out["problem"] = f"Could not read what this step made: {e}"
        return out

    def _view_organization(self) -> Dict[str, Any]:
        org = self.doc["organization"]
        return {"name": org["name"], "trust_domain": self.domain,
                "entities": [{"id": e, "name": n} for e, n in entity_names(self.doc).items()],
                "folder": str(self.folder),
                "ids": {"person": self.person("<person>"), "agent": self.agent("<agent>"),
                        "gateway": self.gateway_id, "books": self.books_service}}

    def _view_pki(self) -> Dict[str, Any]:
        ca = self.private / "ca"
        root = x509.load_pem_x509_certificate((ca / "root.pem").read_bytes())
        inter = x509.load_pem_x509_certificate((ca / "intermediate.pem").read_bytes())
        return {"root": _cert_view(root), "intermediate": _cert_view(inter),
                "bundle": "trust/bundle.pem", "keys": "private/ca/"}

    def _view_people(self) -> Dict[str, Any]:
        principals = json.loads((self.folder / "trust" / "principals.json").read_text())
        return {"file": "trust/principals.json", "people": [
            {"id": p["id"], "name": p.get("name") or p["id"], "role": p.get("role", ""),
             "spiffe_id": self.person(p["id"]),
             "public_key": principals.get(self.person(p["id"])),
             "approver": bool(p.get("approver")), "controller": bool(p.get("controller"))}
            for p in self.doc["people"]]}

    def _view_agents(self) -> Dict[str, Any]:
        out = []
        for a in self.doc["agents"]:
            b = self.bundle(a)
            cid = cid_str(cid_of_bytes(dag_cbor(b)))
            out.append({**b, "cid": cid, "file": f"agents/{cid}.json"})
        return {"agents": out}

    def _view_identities(self) -> Dict[str, Any]:
        out = []
        for name, sid in [("gateway", self.gateway_id)] + \
                [(a["id"], self.agent(a["id"])) for a in self.doc["agents"]]:
            path = self.private / "svids" / f"{fname(name)}.pem"
            if not path.exists():
                continue
            leaf = identity.load_chain(path.read_bytes())[0]
            out.append({"name": name, **_cert_view(leaf)})
        return {"svids": out, "ttl_minutes": int(identity.SVID_TTL.total_seconds() // 60),
                "renew_minutes": RENEW_EVERY // 60}

    def _view_log(self) -> Dict[str, Any]:
        log = self.log if hasattr(self, "log") else ReceiptLog.open(self.folder / "log")
        cps = log.checkpoints()
        w = json.loads((self.folder / "witnesses.json").read_text())
        return {"log_id": log.log_id, "public_key": log.public_key.hex(), "records": len(log),
                "checkpoints": len(cps), "root": cps[-1].root.hex() if cps else None,
                "witnesses": [{"name": k, "public_key": v} for k, v in w["keys"].items()
                              if k in self.doc["witnesses"]["names"]],
                "required": w["required"]}

    def _view_books(self) -> Dict[str, Any]:
        log = self.log if hasattr(self, "log") else ReceiptLog.open(self.folder / "log")
        b = self.doc["books"] or {}
        view = report.books_view(log, dict(b.get("accounts") or {}))
        names = entity_names(self.doc)
        return {"ledger": b.get("ledger"), "currency": b.get("currency"),
                "accounts": b.get("accounts"),
                "entities": [{"id": led["entity"], "name": names.get(led["entity"],
                                                                     led["entity"]),
                              "periods": led["periods"], "entries": len(led["entries"])}
                             for led in view["ledgers"]]}

    def _view_rules(self) -> Dict[str, Any]:
        found = self.rules_data()
        if found is None:
            return {"type": "none"}
        path, data, entrypoint = found
        wasm = path.read_bytes()
        source = path.with_suffix(".rego")
        return {"type": (self.doc.get("rules") or {}).get("type"), "entrypoint": entrypoint,
                "wasm_sha256": policy.policy_sha256(wasm).hex(), "wasm_bytes": len(wasm),
                "data": data,
                "source": source.read_text() if source.exists() else None,
                "file": f"policies/{policy.policy_sha256(wasm).hex()}.wasm"}

    def _view_systems(self) -> Dict[str, Any]:
        out = []
        tools = tool_names(self.doc, self.folder)
        for s in self.doc["systems"]:
            out.append({"id": s["id"], "name": s.get("name") or s["id"], "type": s["type"],
                        "tools": sorted(t for t, sid in tools.items() if sid == s["id"])})
        if self.doc.get("books"):
            out.append({"id": "books", "name": "Books of account", "type": "books",
                        "tools": [books.TOOL]})
        return {"systems": out, "gateway": self.gateway_id}

    def _view_instruction(self) -> Dict[str, Any]:
        index = json.loads((self.private / "tokens.json").read_text())
        auth = (self.folder / "trust" / "authority-public-key.txt").read_text().strip()
        intents: Dict[str, Dict[str, Any]] = {}
        for aid, ref in index.items():
            env = delegation.IntentEnvelope.from_json(json.loads(
                (self.folder / "intents" / f"{ref['intent']}.json").read_text()))
            item = intents.setdefault(env.cid, {
                "cid": env.cid, "file": f"intents/{env.cid}.json",
                "signed_by": env.principal, **env.fields(),
                "signature": base64.b64encode(env.signature).decode(), "tokens": []})
            raw = (self.folder / "tokens" / f"{ref['token_sha256']}.biscuit").read_bytes()
            token = Biscuit.from_bytes(raw, delegation.PublicKey.from_bytes(
                bytes.fromhex(auth), delegation.Algorithm.Ed25519))
            item["tokens"].append({
                "agent": aid, "sha256": ref["token_sha256"], "bytes": len(raw),
                "blocks": [token.block_source(i) for i in range(token.block_count())]})
        return {"authority_public_key": auth, "intents": list(intents.values())}

    def _view_gateway(self) -> Dict[str, Any]:
        info = running(self.folder) or {}
        return {"gateway": self.gateway_id, "port": self.port or info.get("port"),
                "connect": "private/connect/",
                "checks": [label for _, label in report.STEPS]}

    # ---- actions -----------------------------------------------------------------------

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
        a = delegation.Approval(escalation=escalation, approver=self.person(person),
                                decision=verdict, tool=tool, args_sha256=digest,
                                time=now_ms()).sign(self.person_key(person))
        return self.call(self.agent_id(agent_id), tool, args, approval=a)

    def change_period(self, period: str, state: str, person: str,
                      entity: Optional[str] = None) -> Dict[str, Any]:
        """A controller opens or closes a period of one entity's books, signing the change."""
        if not self.ledgers:
            raise WorkspaceError("this workspace has no books")
        led = self.ledgers.get(entity) if entity else self.ledger
        if led is None:
            raise WorkspaceError(f"there are no books for {entity}")
        p = next((x for x in self.doc["people"] if x["id"] == person), None)
        if p is None or not p.get("controller"):
            raise WorkspaceError(f"{person} is not a controller")
        e = led.transition(books.PeriodTransition(
            entity=led.entity, ledger=led.ledger, period=period, state=state,
            by=self.person(person), time=now_ms()).sign(self.person_key(person)))
        return {"entity": led.entity, "period": period, "state": state, "record": e.index}

    def seal(self) -> Dict[str, Any]:
        """Sign a checkpoint and have the witnesses cosign it."""
        with self._lock:
            cps = self.log.checkpoints()
            if cps and cps[-1].size == len(self.log):     # nothing new since the last one
                cp = cps[-1]
                done = {c["witness"] for c in witness.load_cosignatures(self.log.path)
                        if c.get("size") == cp.size and c.get("time", 0) >= cp.ts}
                if done >= {w.name for w in self.witnesses}:
                    return {"size": cp.size, "witnesses": sorted(done)}
            else:
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


def describe_lines(view: Dict[str, Any]) -> List[str]:
    """A setup step's description as lines of text, for `aeos build`."""
    step = view["step"]
    n = STEP_IDS.index(step["id"]) + 1
    out = [f"{n}. {step['title']}" + (f"  (How it works: {step['section']})"
                                      if step.get("section") else ""),
           f"   {step['text']}"]

    def add(text: str) -> None:
        out.append(f"   - {text}")
    sid = step["id"]
    if view.get("problem"):
        add(view["problem"])
    elif sid == "organization":
        add(f"{view['name']}, trust domain {view['trust_domain']}")
        for e in view["entities"]:
            add(f"entity {e['id']}: {e['name']}")
        add(f"agents are named like {view['ids']['agent']}")
    elif sid == "pki":
        for k in ("root", "intermediate"):
            c = view[k]
            add(f"{k} CA: {c['key']}, valid to {report.when(c['not_after'])}, "
                f"fingerprint {c['fingerprint'][:16]}…")
        add(f"trust bundle: {view['bundle']}")
    elif sid == "people":
        for x in view["people"]:
            add(f"{x['name']}: {x['spiffe_id']}, key {str(x['public_key'])[:16]}…")
    elif sid == "agents":
        for a in view["agents"]:
            add(f"{a['id']}: {', '.join(a['tools'])}; bundle {a['cid'][:20]}…")
    elif sid == "identities":
        for c in view["svids"]:
            add(f"{c['spiffe']}: certificate valid to {report.when(c['not_after'])}")
    elif sid == "log":
        add(f"log {view['log_id']}, {view['records']} records, public key "
            f"{view['public_key'][:16]}…")
        add(f"witnesses: {', '.join(w['name'] for w in view['witnesses'])}; "
            f"{view['required']} must cosign")
    elif sid == "books":
        for e in view["entities"]:
            add(f"{e['id']} {view['ledger']}: " + ", ".join(
                f"{p['name']} {p['state']}" for p in e["periods"]))
    elif sid == "rules":
        if view.get("type") == "none":
            add("no rules")
        else:
            add(f"{view['entrypoint']}, WebAssembly SHA-256 {view['wasm_sha256'][:16]}…")
    elif sid == "systems":
        for x in view["systems"]:
            add(f"{x['name']}: {', '.join(x['tools'])}")
    elif sid == "instruction":
        for i in view["intents"]:
            add(f"signed by {i['signed_by']}: \"{i['purpose']}\" ({i['cid'][:20]}…)")
            for t in i["tokens"]:
                add(f"  token for {t['agent']}: {len(t['blocks'])} block"
                    f"{'' if len(t['blocks']) == 1 else 's'}, SHA-256 {t['sha256'][:16]}…")
    elif sid == "gateway":
        add(f"{view['gateway']} on port {view['port']}")
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


def is_set_up(folder: Path) -> bool:
    """Whether every setup step before the gateway has run for this workspace as it is."""
    try:
        p = Platform(folder)
    except WorkspaceError:
        return False
    return all(s["state"] == "done" for s in p.status() if s["id"] != "gateway")


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
    try:
        info = json.loads(path.read_text())
        # something answers on the gateway's port
        socket.create_connection(("127.0.0.1", int(info["port"])), timeout=1).close()
    except (OSError, ValueError, KeyError):
        return None
    return info


def remote_client(folder: Path, aid: str) -> AgentClient:
    """An MCP client for an agent of a workspace that `aeos up` is serving."""
    d = Path(folder) / "private" / "connect" / fname(aid)
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


__all__ = ["Platform", "WorkspaceError", "STEPS", "check", "create", "example", "load", "save",
           "minor", "parse_args", "remote_client", "running", "answer", "is_set_up"]
