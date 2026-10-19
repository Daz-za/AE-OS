"""A point-and-click view of a receipt log in the web browser: `aeos ui`.

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

from .. import demo, setup, status
from ..canon import cid_str
from ..log import ReceiptLog, to_view

HERE = Path(__file__).parent
STATIC = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/check.js": ("check.js", "text/javascript"),
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
    try:
        log_id = json.loads((folder / "log.json").read_text()).get("log_id", "")
    except (OSError, ValueError):
        return None
    if log_id.startswith("urn:aeos:"):
        for d in (setup.default_key_dir(), setup.earlier_key_dir()):
            guess = d / f"{log_id[len('urn:aeos:'):]}.key"
            if guess.exists():
                return guess
    return None


class App:
    """The page's functions. Every method returns a JSON-ready dict."""

    def __init__(self, folder: Optional[Path] = None, key: Optional[Path] = None) -> None:
        self.folder: Optional[Path] = None
        self.key: Optional[Path] = None
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
                               "cwd": str(Path.cwd()), "modes": setup.MODES}
        if self.folder is not None:
            s = status.summary(self._log())
            out["status"] = s
            out["lines"] = status.describe(s, str(self.folder))
        return out

    def open(self, req: Dict[str, Any]) -> Dict[str, Any]:
        folder = Path(str(req.get("folder") or "")).expanduser()
        if not (folder / "log.json").exists():
            raise UserError(f"There is no receipt log in {folder}. Choose the folder that "
                            "holds log.json.")
        key = Path(str(req["key"])).expanduser() if req.get("key") else find_key(folder)
        if key is not None and not key.exists():
            raise UserError(f"There is no signing key file at {key}.")
        try:
            ReceiptLog.open(folder, key_path=key)
        except ValueError as e:
            raise UserError(f"This log cannot be opened: {e}.") from None
        self.folder, self.key = folder.resolve(), key.resolve() if key else None
        return self.state({})

    def demo(self, req: Dict[str, Any]) -> Dict[str, Any]:
        folder = Path(str(req.get("folder") or "aeos-demo")).expanduser()
        n = 2
        while folder.exists() and any(folder.iterdir()):
            folder = Path(f"{str(req.get('folder') or 'aeos-demo')}-{n}").expanduser()
            n += 1
        lines: List[str] = []
        demo.run(folder, out=lines.append)
        self.folder, self.key = (folder / "log").resolve(), (folder / "log" / "signing.key").resolve()
        return {**self.state({}), "story": "\n".join(lines)}

    def create(self, req: Dict[str, Any]) -> Dict[str, Any]:
        lines: List[str] = []
        wizard = setup.Wizard(out=lines.append, assume_defaults=True)
        opts = {k: (str(req[k]).strip() or None) if req.get(k) is not None else None
                for k in ("log", "name", "key", "agent", "mode")}
        if opts["mode"] is not None and opts["mode"] not in setup.MODES:
            raise UserError("Choose how the agent's tool calls reach the log.")
        if setup.run(wizard, **opts) != 0:
            raise UserError(" ".join(x.strip() for x in lines[1:] if x.strip()))
        slug = setup._slug(opts["name"] or "acme-accounts-payable")
        folder = Path(opts["log"] or f"./{slug}-log").expanduser()
        key = Path(opts["key"]).expanduser() if opts["key"] else \
            setup.default_key_dir() / f"{slug}.key"
        self.folder, self.key = folder.resolve(), key.resolve() if key else None
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
    ("GET", "/api/growth"): App.growth,
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
            try:
                with app.lock:
                    self._json(200, route(app, req))
            except UserError as e:
                self._json(400, {"error": str(e)})
            except (OSError, ValueError, KeyError) as e:
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
    return 0

