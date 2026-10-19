"""An HTTP log sink that gateways and agent frameworks send tool-call events to.

    POST /v1/traces    OpenTelemetry traces as OTLP/JSON (exporter protocol "http/json")
    POST /v1/events    AE-OS events: one JSON object or a list (see events.py)
    GET  /healthz      liveness check

Every request needs `Authorization: Bearer <token>`. The sink records what its callers
report, so give the token only to components that authenticate the agents themselves,
such as an MCP gateway.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, TextIO, Tuple

from .events import EventError, apply, otlp_events
from .recorder import Recorder

MAX_BODY = 10 * 1024 * 1024


def record_events(rec: Recorder, events: Iterable[Any]) -> Tuple[List[Dict[str, Any]],
                                                                  List[str]]:
    """Apply events in order. Returns what was recorded and a problem per rejected event."""
    done, problems = [], []
    for n, ev in enumerate(events):
        try:
            done.append(apply(rec, ev))
        except (EventError, KeyError, TypeError, ValueError, AttributeError) as e:
            problems.append(f"event {n}: {e}")
    return done, problems


def ingest(rec: Recorder, lines: Iterable[str], fmt: str) -> Tuple[int, List[str]]:
    """Record events from JSON lines: AE-OS events, or OTLP/JSON as written by the
    OpenTelemetry Collector's file exporter (one traces payload per line)."""
    count, problems = 0, []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            events = list(otlp_events(data)) if fmt == "otlp" else \
                (data if isinstance(data, list) else [data])
        except (EventError, ValueError, TypeError, KeyError, AttributeError) as e:
            problems.append(f"line {n}: {e}")
            continue
        done, bad = record_events(rec, events)
        count += len(done)
        problems += [f"line {n}, {p}" for p in bad]
    return count, problems


def make_handler(rec: Recorder, token: Optional[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "aeos-sink"

        def log_message(self, fmt: str, *args: Any) -> None:     # quieter default logging
            sys.stderr.write("aeos sink: " + (fmt % args) + "\n")

        def _send(self, code: int, doc: Dict[str, Any]) -> None:
            data = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if token is None:
                return True
            given = self.headers.get("Authorization", "")
            return hmac.compare_digest(given.encode(), f"Bearer {token}".encode())

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "records": len(rec.log)})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._authorized():
                self._send(401, {"error": "missing or wrong bearer token"})
                return
            if self.path not in ("/v1/traces", "/v1/events"):
                self._send(404, {"error": "not found"})
                return
            ctype = self.headers.get("Content-Type", "").split(";")[0].strip()
            if ctype != "application/json":
                self._send(415, {"error": "send JSON; for OpenTelemetry exporters set the "
                                          "protocol to http/json"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0:
                self._send(400, {"error": "bad Content-Length"})
                return
            if length > MAX_BODY:
                self._send(413, {"error": f"body larger than {MAX_BODY} bytes"})
                return
            try:
                data = json.loads(self.rfile.read(length) or b"null")
                if self.path == "/v1/traces":
                    events = list(otlp_events(data))
                else:
                    events = data if isinstance(data, list) else [data]
            except (EventError, ValueError, TypeError, KeyError, AttributeError) as e:
                self._send(400, {"error": f"unreadable payload: {e}"})
                return
            done, problems = record_events(rec, events)
            if self.path == "/v1/traces":
                doc: Dict[str, Any] = {}
                if problems:
                    doc["partialSuccess"] = {"errorMessage": "; ".join(problems)}
                self._send(200, doc)
            else:
                self._send(400 if problems and not done else 200,
                           {"recorded": done, "problems": problems})

    return Handler


def serve(rec: Recorder, host: str, port: int, token: Optional[str],
          out: TextIO = sys.stderr) -> None:
    """Serve until interrupted or terminated, then sign a checkpoint covering everything
    recorded."""
    if token is None and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("a sink reachable from other machines needs a token")
    server = ThreadingHTTPServer((host, port), make_handler(rec, token))

    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)        # stop cleanly under a service manager too
    print(f"aeos sink listening on http://{host}:{server.server_port}", file=out)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if rec.log.can_sign:
            rec.log.checkpoint()
