"""AE-OS: agent identities, delegated authority, an MCP gateway, rules, books of account and
witnesses, with a signed, independently verifiable receipt for every agent action."""

__version__ = "0.1.0"

from .canon import Link, canonical_json, cid_str, dag_cbor, json_digest  # noqa: E402
from .log import (Checkpoint, ReceiptLog, make_record, verify_consistency_doc,  # noqa: E402
                  verify_receipt)
from .recorder import Recorder  # noqa: E402

__all__ = ["Checkpoint", "Link", "ReceiptLog", "Recorder", "canonical_json", "cid_str",
           "dag_cbor", "json_digest", "make_record", "verify_consistency_doc", "verify_receipt"]
