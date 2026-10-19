"""Command line for AE-OS Receipts.

    aeos-receipts init LOG [--log-id ID] [--key PATH]
    aeos-receipts append LOG --agent ID --kind KIND [--subject S] [--body JSON] [--parent CID]...
    aeos-receipts checkpoint LOG
    aeos-receipts receipt LOG REF [-o FILE]
    aeos-receipts verify-receipt FILE --public-key HEX
    aeos-receipts consistency LOG --old N [--new M] [-o FILE]
    aeos-receipts verify-consistency FILE --public-key HEX
    aeos-receipts verify LOG
    aeos-receipts show LOG [REF]
    aeos-receipts mcp-proxy LOG --agent ID [--on-behalf-of ID] [--allow-tool T]... -- CMD...
    aeos-receipts sink LOG --agent ID [--listen HOST:PORT] [--token-file FILE]
    aeos-receipts ingest LOG FILE --agent ID [--format events|otlp]
    aeos-receipts hook LOG --agent ID [--allow-tool T]...      (Claude Agent SDK / Claude Code)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, hooks, mcp_proxy, sink
from .canon import cid_parse, cid_str
from .log import ReceiptLog, make_record, to_view, verify_consistency_doc, verify_receipt
from .recorder import Recorder


def _public_key(value: str) -> bytes:
    """Accept a hex key, a file holding one, or a log.json file."""
    p = Path(value)
    if p.is_file():
        text = p.read_text().strip()
        if text.startswith("{"):
            return bytes.fromhex(json.loads(text)["public_key"])
        return bytes.fromhex(text)
    return bytes.fromhex(value)


def _write(doc: dict, out: Optional[str]) -> None:
    text = json.dumps(doc, indent=2) + "\n"
    if out:
        Path(out).write_text(text)
    else:
        sys.stdout.write(text)


def _report(problems: List[str], ok_message: str) -> int:
    if problems:
        print("INVALID")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"VALID: {ok_message}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="aeos-receipts",
                                 description="Signed, verifiable receipts for AI agent actions.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a new log")
    p.add_argument("log")
    p.add_argument("--log-id")
    p.add_argument("--key", help="signing key path (created if missing); "
                                 "keep it outside the log directory in production")

    p = sub.add_parser("append", help="append a record by hand")
    p.add_argument("log")
    p.add_argument("--key")
    p.add_argument("--agent", required=True)
    p.add_argument("--on-behalf-of")
    p.add_argument("--kind", required=True)
    p.add_argument("--subject")
    p.add_argument("--body", default="{}", help="JSON object of strings, integers, booleans")
    p.add_argument("--parent", action="append", default=[], help="CID of a causing record")

    p = sub.add_parser("checkpoint", help="sign the current state of the log")
    p.add_argument("log")
    p.add_argument("--key")

    p = sub.add_parser("receipt", help="export a receipt for one record")
    p.add_argument("log")
    p.add_argument("ref", help="record index or CID")
    p.add_argument("--key")
    p.add_argument("-o", "--out")

    p = sub.add_parser("verify-receipt", help="check a receipt offline")
    p.add_argument("file")
    p.add_argument("--public-key", required=True, help="hex, a file holding hex, or log.json")

    p = sub.add_parser("consistency", help="prove a newer checkpoint extends an older one")
    p.add_argument("log")
    p.add_argument("--old", type=int, required=True, help="size of the older checkpoint")
    p.add_argument("--new", type=int, help="size of the newer checkpoint (default: latest)")
    p.add_argument("-o", "--out")

    p = sub.add_parser("verify-consistency", help="check a consistency proof offline")
    p.add_argument("file")
    p.add_argument("--public-key", required=True)

    p = sub.add_parser("verify", help="recompute and check an entire log")
    p.add_argument("log")

    p = sub.add_parser("show", help="print records as readable JSON")
    p.add_argument("log")
    p.add_argument("ref", nargs="?")

    p = sub.add_parser("mcp-proxy", help="record the tool calls of an MCP stdio server")
    p.add_argument("log")
    p.add_argument("--key")
    p.add_argument("--agent", required=True, help="the agent's identity, e.g. a SPIFFE ID")
    p.add_argument("--on-behalf-of", help="the person or organization the agent acts for")
    p.add_argument("--allow-tool", action="append", help="permit only these tools")
    p.add_argument("--store-content", action="store_true",
                   help="also keep full arguments and results under content/")
    p.add_argument("--checkpoint-every", type=int, default=100)

    def recorder_options(p: argparse.ArgumentParser, checkpoint_every: int) -> None:
        p.add_argument("log")
        p.add_argument("--key")
        p.add_argument("--agent", required=True,
                       help="identity recorded when an event names none, e.g. a SPIFFE ID")
        p.add_argument("--on-behalf-of", help="the person or organization the agent acts for")
        p.add_argument("--allow-tool", action="append", help="permit only these tools")
        p.add_argument("--store-content", action="store_true",
                       help="also keep full arguments and results under content/")
        p.add_argument("--checkpoint-every", type=int, default=checkpoint_every)

    p = sub.add_parser("sink", help="receive tool-call events from gateways over HTTP")
    recorder_options(p, 100)
    p.add_argument("--listen", default="127.0.0.1:4318", help="host:port (default %(default)s)")
    p.add_argument("--token-file", help="file holding the bearer token callers must send "
                   "(default: the AEOS_SINK_TOKEN environment variable)")

    p = sub.add_parser("ingest", help="record tool-call events from a file of JSON lines")
    recorder_options(p, 100)
    p.add_argument("file", help="JSON lines file, or - for standard input")
    p.add_argument("--format", choices=["events", "otlp"], default="events")

    p = sub.add_parser("hook", help="record one Claude Agent SDK or Claude Code hook event")
    recorder_options(p, 0)
    p.add_argument("--fail-open", action="store_true",
                   help="let a tool run even if its call could not be recorded")

    argv = list(sys.argv[1:] if argv is None else argv)
    server_cmd: List[str] = []
    if "--" in argv:                       # everything after -- is the MCP server command
        cut = argv.index("--")
        argv, server_cmd = argv[:cut], argv[cut + 1:]
    a = ap.parse_args(argv)

    if a.cmd == "init":
        log = ReceiptLog.create(Path(a.log), log_id=a.log_id,
                                key_path=Path(a.key) if a.key else None)
        print(json.dumps({"log_id": log.log_id, "public_key": log.public_key.hex(),
                          "key_id": log.meta["key_id"]}, indent=2))
        return 0

    if a.cmd == "verify-receipt":
        doc = json.loads(Path(a.file).read_text())
        return _report(verify_receipt(doc, _public_key(a.public_key)),
                       f"record {doc.get('index')} ({doc.get('cid')}) is in log "
                       f"{doc.get('log_id')} at checkpoint size {doc['checkpoint']['size']}")

    if a.cmd == "verify-consistency":
        doc = json.loads(Path(a.file).read_text())
        return _report(verify_consistency_doc(doc, _public_key(a.public_key)),
                       f"checkpoint size {doc['new']['size']} extends checkpoint size "
                       f"{doc['old']['size']}")

    key = Path(a.key) if getattr(a, "key", None) else None

    def recorder() -> Recorder:
        return Recorder(ReceiptLog.open(Path(a.log), key_path=key), agent=a.agent,
                        on_behalf_of=a.on_behalf_of, allow_tools=a.allow_tool,
                        store_content=a.store_content, checkpoint_every=a.checkpoint_every)

    if a.cmd == "hook":
        code, out, err = hooks.run(recorder, sys.stdin.read(), fail_open=a.fail_open)
        sys.stdout.write(out)
        sys.stderr.write(err)
        return code
    if a.cmd == "ingest":
        f = sys.stdin if a.file == "-" else open(a.file, encoding="utf-8")
        rec = recorder()
        with f:
            count, problems = sink.ingest(rec, f, a.format)
        if count and rec.log.can_sign:
            rec.log.checkpoint()
        for p in problems:
            print(f"skipped {p}", file=sys.stderr)
        print(f"recorded {count} events" + (f", skipped {len(problems)}" if problems else ""))
        return 1 if problems else 0
    if a.cmd == "sink":
        host, _, port = a.listen.rpartition(":")
        token = Path(a.token_file).read_text().strip() if a.token_file else \
            os.environ.get("AEOS_SINK_TOKEN")
        try:
            sink.serve(recorder(), host or "127.0.0.1", int(port), token or None)
        except ValueError as e:
            print(f"aeos-receipts sink: {e}", file=sys.stderr)
            return 2
        return 0

    read_only = a.cmd in ("verify", "show", "consistency")
    log = ReceiptLog.open(Path(a.log), key_path=key, read_only=read_only)

    if a.cmd == "append":
        body = json.loads(a.body)
        rec = make_record(a.kind, a.agent, on_behalf_of=a.on_behalf_of, subject=a.subject,
                          body=body, parents=[cid_parse(c) for c in a.parent])
        e = log.append(rec)
        print(json.dumps({"index": e.index, "cid": cid_str(e.cid)}))
        return 0
    if a.cmd == "checkpoint":
        print(json.dumps(log.checkpoint().to_json(), indent=2))
        return 0
    if a.cmd == "receipt":
        _write(log.receipt(log.entry(a.ref)), a.out)
        return 0
    if a.cmd == "consistency":
        cps = log.checkpoints()
        old = next((c for c in cps if c.size == a.old), None)
        new = cps[-1] if a.new is None else next((c for c in cps if c.size == a.new), None)
        if old is None or new is None:
            print("no signed checkpoint with that size", file=sys.stderr)
            return 2
        _write(log.consistency(old, new), a.out)
        return 0
    if a.cmd == "verify":
        rep = log.verify()
        return _report(rep.problems, f"{rep.records} records and {rep.checkpoints} signed "
                                     f"checkpoints in {log.log_id}")
    if a.cmd == "show":
        entries = [log.entry(a.ref)] if a.ref else log.entries()
        for e in entries:
            print(json.dumps({"index": e.index, "cid": cid_str(e.cid),
                              "record": to_view(log.record(e))}))
        return 0
    if a.cmd == "mcp-proxy":
        if not server_cmd:
            ap.error("mcp-proxy needs the server command after --")
        return mcp_proxy.run(log, server_cmd, agent=a.agent, on_behalf_of=a.on_behalf_of,
                             allow_tools=a.allow_tool, store_content=a.store_content,
                             checkpoint_every=a.checkpoint_every)
    return 2


if __name__ == "__main__":
    sys.exit(main())
