"""A plain-language summary of a receipt log, for `aeos status` and the GUI."""
from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any, Dict, List

from .log import ReceiptLog


# What a check's result means for the reader: (when valid, when invalid).
MEANING = {
    "receipt": ("This record is in the log exactly as shown, and the log's owner signed "
                "a checkpoint that includes it.",
                "Do not rely on this receipt. Ask the log's owner for a fresh receipt, and "
                "check that you used their public key from a source you trust."),
    "consistency": ("The newer checkpoint contains every record of the older one, "
                    "unchanged. Nothing was removed or rewritten in between.",
                    "The log's history differs from what you were shown before. Keep both "
                    "checkpoints as evidence and raise it with the log's owner."),
    "log": ("Every record matches its fingerprint, every link points to an earlier record, "
            "and every signed checkpoint matches the records it covers.",
            "Records were changed, removed or reordered after they were written. Keep a "
            "copy of the folder as it is now, and compare it with a backup or with "
            "receipts issued earlier."),
    "audit": ("Every record is unchanged; each session record names a certificate that was "
              "valid, at that time, for the identity the session was recorded under; where the "
              "gateway required capability tokens, each decision gives the recorded answer "
              "when replayed from the token and the signed intent, and every call that ran "
              "had an allow decision; and the required number of trusted witnesses cosigned the latest checkpoint.",
              "Do not rely on this evidence until each problem listed is explained. Keep a "
              "copy of the folder as it is now."),
}


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
        tip = f"aeos checkpoint {folder}" if s["can_sign"] else \
            f"aeos checkpoint {folder} --key <signing key file>"
        lines.append(f"  {_n(unsealed, 'newer record')} not yet covered by a signed "
                     f"checkpoint. To sign one now: {tip}")
    else:
        lines.append("  Every record is covered by a signed checkpoint")
    lines.append(f"  Public key for auditors (key id {s['key_id']}): {s['public_key']}")
    return lines
