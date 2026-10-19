"""A point-and-click view of a workspace, a receipt log or an evidence folder: `aeos ui`.

With a workspace (see workspace.py) the page shows the architecture as it runs: it sets
the company up step by step, plays the film's quarter-end close as real calls, sends tool
calls as an agent and shows each check the call passed or failed, and edits
workspace.json.

The page is served only to this computer (127.0.0.1). Each launch makes a fresh access
code that is part of the address the browser opens. Other websites open in the same
browser do not have it and cannot use the page's functions. Receipts and growth proofs are checked inside
the browser by verify.js, the same checker that ae-os.org uses.
"""
from __future__ import annotations

import hmac
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .. import audit, books, demo, examples, fulldemo, report, setup, status, workspace
from ..canon import cid_str
from ..log import ReceiptLog, to_view

HERE = Path(__file__).parent
STATIC = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/check.js": ("check.js", "text/javascript"),
          "/workspace.js": ("workspace.js", "text/javascript"),
          "/diagram.js": ("diagram.js", "text/javascript"),
          "/verify.js": ("verify.js", "text/javascript"),
          "/style.css": ("style.css", "text/css"), "/check.css": ("check.css", "text/css")}
MAX_BODY = 1024 * 1024
PAGE = 50


class UserError(Exception):
    """A problem to show on the page in plain words."""


def find_key(folder: Path) -> Optional[Path]:
    """The signing key for a log: in its folder (demo logs), or where setup keeps keys."""
    if (folder / "signing.key").exists():
        return folder / "signing.key"
    if (folder.parent / "evidence.json").exists() and \
            (folder.parent / "private" / "log-signing.key").exists():
        return folder.parent / "private" / "log-signing.key"      # demo --full keeps it here
    try:
        log_id = json.loads((folder / "log.json").read_text()).get("log_id", "")
    except (OSError, ValueError):
        return None
    if log_id.startswith("urn:aeos:"):
        guess = setup.default_key_dir() / f"{log_id[len('urn:aeos:'):]}.key"
        if guess.exists():
            return guess
    return None


def _workspaces_here(limit: int = 6) -> List[str]:
    """Workspace folders directly inside the current folder, newest first, so the opening
    page can offer to continue one."""
    try:
        found = [d for d in Path.cwd().iterdir() if (d / workspace.FILE).is_file()]
    except OSError:
        return []
    found.sort(key=lambda d: (d / workspace.FILE).stat().st_mtime, reverse=True)
    return [str(d) for d in found[:limit]]


class App:
    """The page's functions. Every method returns a JSON-ready dict."""

    def __init__(self, folder: Optional[Path] = None, key: Optional[Path] = None) -> None:
        self.folder: Optional[Path] = None
        self.key: Optional[Path] = None
        self.evidence: Optional[Path] = None
        self.platform: Optional[workspace.Platform] = None
        self.started = False                  # True when this page runs the platform itself
        self.lock = threading.Lock()
        if folder is not None:
            self.open({"folder": str(folder), "key": str(key) if key else ""})

    def _log(self) -> ReceiptLog:
        if self.folder is None:
            raise UserError("No log is open yet.")
        return ReceiptLog.open(self.folder, key_path=self.key)

    def state(self, _: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {"folder": str(self.folder) if self.folder else None,
                               "key": str(self.key) if self.key else None,
                               "evidence": str(self.evidence) if self.evidence else None,
                               "cwd": str(Path.cwd()), "modes": setup.MODES,
                               "workspace": self.platform is not None,
                               "workspaces": _workspaces_here()}
        if self.platform is not None:
            out["organization"] = self.platform.doc["organization"]["name"]
        if self.folder is not None and (self.folder / "log.json").exists():
            s = status.summary(self._log())
            out["status"] = s
            out["lines"] = status.describe(s, str(self.folder))
        return out

    def close(self) -> None:
        """Stop the platform if this page started it."""
        if self.platform is not None and self.started:
            self.platform.stop()
        self.platform, self.started = None, False

    def _open_workspace(self, folder: Path, serve: bool = False) -> Dict[str, Any]:
        """Open a workspace: attach to `aeos up` when it runs, start it when it is set up
        (or when `serve` asks, running any changed steps), or keep it ready for setting
        up step by step."""
        self.close()
        try:
            p = workspace.Platform(folder)
            if workspace.running(folder):
                self.platform, self.started = p.open(), False
            else:
                self.platform, self.started = p, True
                if serve or workspace.is_set_up(folder):
                    p.start()
        except Exception as e:             # a tool that fails to start, a bad file
            self.platform, self.started = None, False
            raise UserError(f"The workspace cannot run yet: {e}. Fix workspace.json, or "
                            f"run: aeos check {folder}") from None
        self.folder = (folder / "log").resolve()
        self.key = (folder / "private" / "log-signing.key").resolve()
        self.evidence = folder.resolve()
        return self.state({})

    def open(self, req: Dict[str, Any]) -> Dict[str, Any]:
        given = Path(str(req.get("folder") or "")).expanduser()
        if (given / workspace.FILE).exists():
            return self._open_workspace(given)
        self.close()
        folder, evidence = report.locate(given)
        if not (folder / "log.json").exists():
            raise UserError(f"There is no receipt log in {folder}. Choose the folder that "
                            "holds log.json, or an evidence folder.")
        key = Path(str(req["key"])).expanduser() if req.get("key") else find_key(folder)
        if key is not None and not key.exists():
            raise UserError(f"There is no signing key file at {key}.")
        try:
            ReceiptLog.open(folder, key_path=key)
        except ValueError as e:
            raise UserError(f"This log cannot be opened: {e}.") from None
        self.folder, self.key = folder.resolve(), key.resolve() if key else None
        self.evidence = evidence.resolve() if evidence else None
        return self.state({})

    def _new_folder(self, req: Dict[str, Any], default: str) -> Path:
        base = str(req.get("folder") or default)
        folder, n = Path(base).expanduser(), 2
        while folder.exists() and any(folder.iterdir()):
            folder = Path(f"{base}-{n}").expanduser()
            n += 1
        return folder

    def new_workspace(self, req: Dict[str, Any]) -> Dict[str, Any]:
        name = str(req.get("example") or "kestrel")
        folder = self._new_folder(req, "kestrel-foods" if name == "kestrel" else "acme")
        try:
            workspace.create(folder, workspace.example(name))
        except workspace.WorkspaceError as e:
            raise UserError(str(e)) from None
        return self._open_workspace(folder)

    def _platform(self) -> workspace.Platform:
        if self.platform is None:
            raise UserError("Open a workspace first, or start one from the example.")
        return self.platform

    def ws(self, _: Dict[str, Any]) -> Dict[str, Any]:
        """The workspace as the page needs it."""
        p = self._platform()
        doc = workspace.load(p.folder)
        erp = [s for s in doc.get("systems") or [] if s.get("type") == "example-erp"]
        invoices = []
        for s in erp:
            state = p.private / "state" / f"{s['id']}.json"
            paid = json.loads(state.read_text()) if state.exists() else {}
            invoices += [{**i, "amount_minor": workspace.minor(i["amount"]),
                          "status": "paid" if i["invoice"] in paid else i.get("status")}
                         for i in s.get("invoices") or []]
        gw = p.gateway
        serving = gw is not None or workspace.running(p.folder) is not None
        agents = {a["id"] for a in p.doc["agents"]}
        books = workspace.entities(p.doc)
        chapters = examples.chapters()
        for ch in chapters:
            ch["missing"] = [a for a in ch["needs"] if a not in agents] + [
                f"books for {e}" for e in ch["needs_entities"] if e not in books]
            if ch["id"] == "instruction" and not p.doc.get("instructions"):
                ch["missing"].append("a signed instruction")
        return {"doc": doc, "running": p.doc, "folder": str(p.folder),
                "file": str(p.folder / workspace.FILE),
                "problems": workspace.check(doc, p.folder),
                "tools": workspace.tool_names(p.doc, p.folder),
                "steps": p.status(), "serving": serving,
                "served_here": self.started and gw is not None, "port": p.port or
                (workspace.running(p.folder) or {}).get("port"),
                "connect": str(p.private / "connect"), "invoices": invoices,
                "periods": {e: dict(sorted(led.periods.items()))
                            for e, led in p.ledgers.items()},
                "entities": workspace.entity_names(p.doc),
                "domain": p.domain, "names": p.names(),
                "escalations": [{"escalation": k, "agent": p.agent_id(v[0]), "tool": v[1]}
                                for k, v in (gw.escalations.items() if gw else [])],
                "records": len(p.log) if hasattr(p, "log") else 0,
                "chapters": chapters, "changed": doc != p.doc}

    def ws_step(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Run one setup step (POST), or describe it (GET)."""
        p = self._platform()
        step = str(req.get("step") or "")
        if step not in workspace.STEP_IDS:
            raise UserError(f"There is no setup step called {step}.")
        if req.get("_method") == "GET":
            return p.describe(step)
        if workspace.running(p.folder) and p.gateway is None:
            raise UserError("aeos up is running this workspace in another window. Stop it "
                            "to set the workspace up again here.")
        try:
            view = p.run(step)
        except (workspace.WorkspaceError, books.Refused) as e:
            raise UserError(str(e)) from None
        except Exception as e:
            p.stop(seal=False)
            raise UserError(f"This step could not run: {e}") from None
        self.started = True
        return view

    def ws_save(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Save workspace.json; when this page runs the platform, restart it to apply."""
        p = self._platform()
        doc = req.get("doc")
        problems = workspace.check(doc, p.folder)
        if problems:
            return {"saved": False, "problems": problems}
        before = (p.folder / workspace.FILE).read_text()
        serving = p.port is not None
        workspace.save(p.folder, doc)
        if self.started:
            try:
                self._open_workspace(p.folder, serve=serving)
            except UserError as e:          # keep what ran before, and say why
                (p.folder / workspace.FILE).write_text(before)
                self._open_workspace(p.folder, serve=serving)
                return {"saved": False, "problems": [
                    f"It could not start with these changes, so they were not saved. {e}"]}
            return {"saved": True, "applied": True, **self.ws({})}
        return {"saved": True, "applied": False, **self.ws({})}

    def feed(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Records added since `after`, in brief, for the live view."""
        log = self._log()
        entries = log.entries()
        after = max(0, int(req.get("after", len(entries))))
        names = self._names()
        out = []
        for e in entries[after:after + 200]:
            r = log.record(e)
            b = r.get("body") or {}
            out.append({"index": e.index, "kind": r.get("kind"),
                        "who": names.get(r.get("agent") or "", r.get("agent")),
                        "subject": r.get("subject"), "result": b.get("decision") or
                        b.get("outcome") or b.get("document") or b.get("state")})
        return {"total": len(entries), "records": out}

    def ws_call(self, req: Dict[str, Any]) -> Dict[str, Any]:
        p = self._platform()
        if p.port is None and not workspace.running(p.folder):
            raise UserError("The gateway is not running yet. Finish the steps under Set up, "
                            "or select Set up everything.")
        args = req.get("args") or {}
        if not isinstance(args, dict):
            raise UserError("The arguments must be a JSON object, such as {\"invoice\": \"INV-1001\"}.")
        try:
            return p.call(str(req.get("agent")), str(req.get("tool")), args)
        except workspace.WorkspaceError as e:
            raise UserError(str(e)) from None

    def ws_approve(self, req: Dict[str, Any]) -> Dict[str, Any]:
        p = self._platform()
        try:
            return p.approve(str(req.get("escalation")), str(req.get("person")),
                             "reject" if req.get("verdict") == "reject" else "approve")
        except workspace.WorkspaceError as e:
            raise UserError(str(e)) from None

    def ws_period(self, req: Dict[str, Any]) -> Dict[str, Any]:
        p = self._platform()
        try:
            p.change_period(str(req.get("period")), "open" if req.get("state") == "open"
                            else "closed", str(req.get("person")),
                            entity=str(req["entity"]) if req.get("entity") else None)
        except (workspace.WorkspaceError, books.Refused) as e:
            raise UserError(str(e)) from None
        return self.ws({})

    def ws_seal(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return self._platform().seal()

    def trace(self, req: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return report.trace(self._log(), str(req.get("ref", "")), self._names())
        except (IndexError, KeyError, ValueError) as e:
            raise UserError(f"No tool call found for record {req.get('ref')}: {e}") from None

    def full_demo(self, req: Dict[str, Any]) -> Dict[str, Any]:
        folder = self._new_folder(req, "aeos-full-demo")
        lines: List[str] = []
        self.close()
        if fulldemo.run(folder, out=lines.append) != 0:
            raise UserError("The walk-through stopped: " + " ".join(lines[-3:]))
        self.open({"folder": str(folder)})
        return {**self.state({}), "story": "\n".join(lines), "story_kind": "full"}

    def _evidence(self) -> Path:
        if self.evidence is None:
            raise UserError("This needs an evidence folder, such as the one the full "
                            "walk-through makes. Open the folder that holds evidence.json.")
        return self.evidence

    def audit(self, _: Dict[str, Any]) -> Dict[str, Any]:
        findings, problems = audit.run(self._evidence())
        good, bad = status.MEANING["audit"]
        return {"ok": not problems, "findings": findings, "problems": problems,
                "meaning": good if not problems else bad}

    def agents(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return report.agents(self._log())

    def _names(self) -> Dict[str, str]:
        if self.platform is not None:
            return self.platform.names()
        return workspace.names_of(self.evidence) if self.evidence else {}

    def decisions(self, req: Dict[str, Any]) -> Dict[str, Any]:
        view = report.decisions(self._log(), everything=str(req.get("all")) in ("1", "true"))
        names = self._names()
        for d in view["decisions"]:
            for k in ("agent", "on_behalf_of"):
                d[k] = names.get(d.get(k) or "", d.get(k))
            for a in d["approvals"]:
                a["by"] = names.get(a.get("by") or "", a.get("by"))
        return view

    def books(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return report.books_view(self._log(), report.chart(self.evidence))

    def demo(self, req: Dict[str, Any]) -> Dict[str, Any]:
        folder = self._new_folder(req, "aeos-demo")
        lines: List[str] = []
        self.close()
        demo.run(folder, out=lines.append)
        self.folder, self.key = (folder / "log").resolve(), (folder / "log" / "signing.key").resolve()
        self.evidence = None
        return {**self.state({}), "story": "\n".join(lines), "story_kind": "short"}

    def create(self, req: Dict[str, Any]) -> Dict[str, Any]:
        lines: List[str] = []
        wizard = setup.Wizard(out=lines.append, assume_defaults=True)
        opts = {k: (str(req[k]).strip() or None) if req.get(k) is not None else None
                for k in ("log", "name", "key", "agent", "mode")}
        if opts["mode"] is not None and opts["mode"] not in setup.MODES:
            raise UserError("Choose how the agent's tool calls reach the log.")
        self.close()
        if setup.run(wizard, **opts) != 0:
            raise UserError(" ".join(x.strip() for x in lines[1:] if x.strip()))
        slug = setup._slug(opts["name"] or "acme-accounts-payable")
        folder = Path(opts["log"] or f"./{slug}-log").expanduser()
        key = Path(opts["key"]).expanduser() if opts["key"] else \
            setup.default_key_dir() / f"{slug}.key"
        self.folder, self.key = folder.resolve(), key.resolve() if key else None
        self.evidence = None
        steps = (folder / "NEXT-STEPS.txt").read_text()
        return {**self.state({}), "next_steps": steps}

    def records(self, req: Dict[str, Any]) -> Dict[str, Any]:
        log = self._log()
        entries = log.entries()
        start = max(0, int(req.get("start", 0)))
        page = entries[start:start + PAGE]
        return {"total": len(entries), "start": start,
                "records": [{"index": e.index, "cid": cid_str(e.cid),
                             "record": to_view(log.record(e))} for e in page]}

    def verify(self, _: Dict[str, Any]) -> Dict[str, Any]:
        rep = self._log().verify()
        good, bad = status.MEANING["log"]
        return {"ok": rep.ok, "problems": rep.problems, "records": rep.records,
                "checkpoints": rep.checkpoints, "meaning": good if rep.ok else bad}

    def checkpoint(self, _: Dict[str, Any]) -> Dict[str, Any]:
        log = self._log()
        if not log.can_sign:
            raise UserError("Signing needs the log's signing key. Open the log again and "
                            "give the signing key file.")
        log.checkpoint()
        return self.state({})

    def receipt(self, req: Dict[str, Any]) -> Dict[str, Any]:
        log = self._log()
        try:
            e = log.entry(str(req.get("index", "")))
        except (IndexError, KeyError, ValueError):
            raise UserError(f"There is no record {req.get('index')} in this log.") from None
        covered = any(c.size > e.index for c in log.checkpoints())
        if not covered and not log.can_sign:
            raise UserError("No signed checkpoint covers this record yet, and signing one "
                            "needs the log's signing key.")
        return log.receipt(e)

    def growth(self, req: Dict[str, Any]) -> Dict[str, Any]:
        log = self._log()
        cps = log.checkpoints()
        if len(cps) < 2:
            raise UserError("A growth proof compares two signed checkpoints; this log has "
                            f"{len(cps)}.")
        old = next((c for c in cps if c.size == int(req.get("old", -1))), cps[0])
        return log.consistency(old, cps[-1])


ROUTES: Dict[Tuple[str, str], Callable[[App, Dict[str, Any]], Dict[str, Any]]] = {
    ("GET", "/api/state"): App.state, ("POST", "/api/open"): App.open,
    ("POST", "/api/demo"): App.demo, ("POST", "/api/create"): App.create,
    ("GET", "/api/records"): App.records, ("POST", "/api/verify"): App.verify,
    ("POST", "/api/checkpoint"): App.checkpoint, ("GET", "/api/receipt"): App.receipt,
    ("GET", "/api/growth"): App.growth, ("POST", "/api/full-demo"): App.full_demo,
    ("POST", "/api/audit"): App.audit, ("GET", "/api/agents"): App.agents,
    ("GET", "/api/decisions"): App.decisions, ("GET", "/api/books"): App.books,
    ("GET", "/api/trace"): App.trace, ("POST", "/api/new-workspace"): App.new_workspace,
    ("GET", "/api/ws"): App.ws, ("POST", "/api/ws/save"): App.ws_save,
    ("POST", "/api/ws/call"): App.ws_call, ("POST", "/api/ws/approve"): App.ws_approve,
    ("POST", "/api/ws/period"): App.ws_period, ("POST", "/api/ws/seal"): App.ws_seal,
    ("POST", "/api/ws/step"): App.ws_step, ("GET", "/api/ws/step"): App.ws_step,
    ("GET", "/api/feed"): App.feed,
}


def make_handler(app: App, code: str, port_ref: List[int]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "aeos-ui"

        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def _send(self, status_code: int, data: bytes, ctype: str,
                  extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(status_code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self'; img-src 'self' data:; "
                             "frame-ancestors 'none'; form-action 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, status_code: int, doc: Dict[str, Any]) -> None:
            self._send(status_code, json.dumps(doc).encode(), "application/json")

        def _host_ok(self) -> bool:
            # Refuse other hostnames, so a website cannot reach the page through DNS
            # tricks that point its own name at this computer.
            port = port_ref[0]
            return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _handle(self, method: str) -> None:
            if not self._host_ok():
                self._json(403, {"error": "forbidden"})
                return
            url = urlparse(self.path)
            if method == "GET" and url.path in STATIC:
                name, ctype = STATIC[url.path]
                self._send(200, (HERE / name).read_bytes(), ctype)
                return
            route = ROUTES.get((method, url.path))
            if route is None:
                self._json(404, {"error": "not found"})
                return
            given = self.headers.get("X-AEOS-Code", "")
            if not hmac.compare_digest(given.encode(), code.encode()):
                self._json(403, {"error": "This page's access code has changed. Close it and "
                                          "open the address that aeos ui printed."})
                return
            req: Dict[str, Any] = {k: v[0] for k, v in parse_qs(url.query).items()}
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    self._json(413, {"error": "request too large"})
                    return
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except ValueError:
                    self._json(400, {"error": "request is not JSON"})
                    return
                if isinstance(body, dict):
                    req.update(body)
            req["_method"] = method
            try:
                with app.lock:
                    self._json(200, route(app, req))
            except (UserError, workspace.WorkspaceError, books.Refused) as e:
                self._json(400, {"error": str(e)})
            except Exception as e:              # always answer, so the page can say why
                self._json(500, {"error": f"Something went wrong: {e}"})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    return Handler


def serve(folder: Optional[Path] = None, key: Optional[Path] = None, port: int = 0,
          open_browser: bool = True, out: Callable[[str], None] = print) -> int:
    try:
        app = App(folder, key)
    except UserError as e:
        out(str(e))
        return 2
    code = secrets.token_urlsafe(24)
    port_ref = [port]
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, code, port_ref))
    port_ref[0] = server.server_address[1]
    url = f"http://127.0.0.1:{port_ref[0]}/#code={code}"
    out("AE-OS is open in your web browser. If it did not open, copy this address "
        f"into the browser:\n  {url}\nThe page works only on this computer. Press Ctrl+C here "
        "to close it.")
    if open_browser:
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        out("\nClosed.")
    finally:
        server.server_close()
        app.close()
    return 0

