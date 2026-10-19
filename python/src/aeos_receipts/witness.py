"""Witnesses: independent parties that cosign a log's checkpoints.

A signed checkpoint alone does not stop a log operator from showing different auditors
different histories (a "split view"). A witness keeps the last checkpoint it cosigned
for each log. Before cosigning a newer one it checks the log's signature and a
consistency proof from its last checkpoint, so it never cosigns two histories that
disagree. A checkpoint counts as final once k of the n witnesses an auditor trusts have
cosigned it.

The cosignature follows the design of C2SP tlog-cosignature (a timestamped Ed25519
signature over the checkpoint), applied to AE-OS v0 checkpoints:

    message = "aeos-receipts/cosignature/v0\\n" || DAG-CBOR({checkpoint message, time})

where "checkpoint message" is the exact byte string the log signed (spec section 3).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys, merkle
from .canon import dag_cbor
from .log import Checkpoint, ReceiptLog, b64, now_ms, unb64

COSIGNATURE_CONTEXT = b"aeos-receipts/cosignature/v0\n"


class WitnessRefused(Exception):
    """The witness will not cosign this checkpoint; the reason is in the message."""


def cosignature_message(cp: Checkpoint, time: int) -> bytes:
    return COSIGNATURE_CONTEXT + dag_cbor({"checkpoint": cp.message(), "time": time})


class Witness:
    """A witness with an Ed25519 key and a memory of the checkpoints it cosigned.

    `state` maps log_id to the last cosigned {"size", "root"}; pass a file path to keep
    it between runs.
    """

    def __init__(self, name: str, key: Ed25519PrivateKey,
                 state_path: Optional[Path] = None) -> None:
        self.name, self._key, self.state_path = name, key, state_path
        self.state: Dict[str, Dict[str, Any]] = {}
        if state_path and Path(state_path).exists():
            self.state = json.loads(Path(state_path).read_text())

    @property
    def public_key(self) -> bytes:
        return keys.public_bytes(self._key)

    def last_size(self, log_id: str) -> int:
        return int(self.state.get(log_id, {}).get("size", 0))

    def cosign(self, cp: Checkpoint, log_public_key: bytes, proof: Sequence[bytes],
               time: Optional[int] = None) -> Dict[str, Any]:
        """Check the checkpoint and cosign it, or raise WitnessRefused."""
        if not cp.verify(log_public_key):
            raise WitnessRefused(f"{self.name}: the checkpoint's signature does not verify")
        seen = self.state.get(cp.log_id)
        if seen:
            old_size, old_root = int(seen["size"]), bytes.fromhex(seen["root"])
            if cp.size < old_size:
                raise WitnessRefused(f"{self.name}: checkpoint size {cp.size} is smaller than "
                                     f"size {old_size}, which it already cosigned")
            if not merkle.verify_consistency(old_size, cp.size, list(proof), old_root, cp.root):
                what = "has a different root from" if cp.size == old_size else \
                    "does not extend"
                raise WitnessRefused(
                    f"{self.name}: this {cp.size}-record checkpoint {what} the {old_size}-record "
                    "checkpoint it already cosigned. The log is presenting two histories (a "
                    "split view).")
        time = now_ms() if time is None else time
        sig = self._key.sign(cosignature_message(cp, time))
        self.state[cp.log_id] = {"size": cp.size, "root": cp.root.hex()}
        if self.state_path:
            Path(self.state_path).write_text(json.dumps(self.state, indent=2) + "\n")
        return {"witness": self.name, "key_id": keys.key_id(self.public_key),
                "log": cp.log_id, "size": cp.size, "time": time, "sig": b64(sig)}


def request_cosignatures(log: ReceiptLog, cp: Checkpoint, witnesses: Iterable[Witness]
                         ) -> List[Dict[str, Any]]:
    """Ask each witness to cosign `cp`; store the cosignatures in cosignatures.jsonl.

    Returns the cosignatures obtained. A refusal is raised to the caller, because it means
    the log has shown a witness a different history.
    """
    got = []
    for w in witnesses:
        proof = log.consistency_proof(min(w.last_size(cp.log_id), cp.size), cp.size)
        got.append(w.cosign(cp, log.public_key, proof))
    with open(log.path / "cosignatures.jsonl", "a") as f:
        for c in got:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    return got


def verify_cosignatures(cp: Checkpoint, cosignatures: Iterable[Dict[str, Any]],
                        witness_keys: Dict[str, bytes], k: int) -> List[str]:
    """Check that at least k of the trusted witnesses cosigned this checkpoint.

    `witness_keys` maps each trusted witness name to its public key. Returns problems;
    an empty list means the checkpoint is witnessed.
    """
    good, problems = set(), []
    for c in cosignatures:
        if c.get("log") != cp.log_id or c.get("size") != cp.size:
            continue
        name = c.get("witness")
        key = witness_keys.get(name)
        if key is None:
            continue
        try:
            ok = (c.get("key_id") == keys.key_id(key)
                  and keys.verify(key, unb64(c["sig"]), cosignature_message(cp, int(c["time"]))))
        except (KeyError, ValueError, TypeError):
            ok = False
        if ok:
            good.add(name)
        else:
            problems.append(f"cosignature from {name} does not verify")
    if len(good) < k:
        problems.append(f"checkpoint size {cp.size} has valid cosignatures from {len(good)} "
                        f"trusted witnesses; at least {k} needed")
    return problems


def load_cosignatures(log_path: Path) -> List[Dict[str, Any]]:
    p = Path(log_path) / "cosignatures.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
