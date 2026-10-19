"""A plain-language summary of a receipt log, for `aeos-receipts status` and the GUI."""
from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any, Dict, List

from .log import ReceiptLog


def _when(ms: int) -> str:
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def summary(log: ReceiptLog) -> Dict[str, Any]:
    kinds: Counter = Counter()
    refused = errors = 0
    agents = set()
    last_ts = None
    for e in log.entries():
        rec = log.record(e)
        kinds[rec.get("kind")] += 1
        agents.add(rec.get("agent"))
        body = rec.get("body") or {}
        if rec.get("kind") == "policy.decision" and body.get("decision") == "deny":
            refused += 1
        if rec.get("kind") == "tool.result" and body.get("outcome") != "ok":
            errors += 1
        last_ts = rec.get("ts")
    cps = log.checkpoints()
    return {"log_id": log.log_id, "key_id": log.meta.get("key_id"),
            "public_key": log.public_key.hex(), "records": len(log),
            "sessions": kinds["session.start"], "tool_calls": kinds["tool.call"],
            "refused_calls": refused, "failed_calls": errors, "agents": len(agents),
            "last_record": last_ts, "checkpoints": len(cps),
            "last_checkpoint_size": cps[-1].size if cps else 0,
            "last_checkpoint_ts": cps[-1].ts if cps else None,
            "can_sign": log.can_sign}


def _n(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def describe(s: Dict[str, Any], folder: str) -> List[str]:
    lines = [f"Log {s['log_id']}"]
    if not s["records"]:
        lines.append("  No records yet")
        lines.append(f"  Public key for auditors (key id {s['key_id']}): {s['public_key']}")
        return lines
    lines += [f"  {_n(s['records'], 'record')} from {s['agents']} "
              f"{'identity' if s['agents'] == 1 else 'identities'} (people and agents) across "
              f"{_n(s['sessions'], 'session')}",
              f"  {_n(s['tool_calls'], 'tool call')}, {s['refused_calls']} refused by policy, "
              f"{s['failed_calls']} ended in an error"]
    if s["last_record"]:
        lines.append(f"  Latest record: {_when(s['last_record'])}")
    if s["checkpoints"]:
        lines.append(f"  Latest signed checkpoint covers {s['last_checkpoint_size']} records "
                     f"({_when(s['last_checkpoint_ts'])})")
    else:
        lines.append("  No signed checkpoint yet")
    unsealed = s["records"] - s["last_checkpoint_size"]
    if unsealed > 0:
        tip = f"aeos-receipts checkpoint {folder}" if s["can_sign"] else \
            f"aeos-receipts checkpoint {folder} --key <signing key file>"
        lines.append(f"  {_n(unsealed, 'newer record')} not yet covered by a signed "
                     f"checkpoint. To sign one now: {tip}")
    else:
        lines.append("  Every record is covered by a signed checkpoint")
    lines.append(f"  Public key for auditors (key id {s['key_id']}): {s['public_key']}")
    return lines
