"""AE-OS: agent identities, delegated authority, an MCP gateway, rules, books of account and
witnesses, with an independently verifiable action record for every agent action, sealed in a
signed audit trail."""

__version__ = "0.1.0"

from .canon import Link, canonical_json, cid_str, dag_cbor, json_digest  # noqa: E402
from .log import (ActionLog, Checkpoint, make_record, verify_action_record,  # noqa: E402
                  verify_consistency_doc)
from .recorder import Recorder  # noqa: E402

__all__ = ["ActionLog", "Checkpoint", "Link", "Recorder", "canonical_json", "cid_str",
           "dag_cbor", "json_digest", "make_record", "verify_action_record",
           "verify_consistency_doc"]


def __getattr__(name: str):
    # Deprecated version 0 names, kept for one release (see log.py).
    from . import log
    if name in log.DEPRECATED_ALIASES:
        return getattr(log, name)
    raise AttributeError(f"module 'aeos' has no attribute {name!r}")
