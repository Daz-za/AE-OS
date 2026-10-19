"""File-backed, append-only receipt log.

A log is a directory:

    log.json            log identity and public key
    records.jsonl       one line per record: index, CID, canonical bytes, readable view
    checkpoints.jsonl   signed checkpoints (log id, size, Merkle root, time)
    signing.key         Ed25519 private key (create elsewhere with --key for production)
    content/            optional full arguments and results, named by record CID

The Merkle leaf for record i is the record's binary CID, so the tree commits to the
exact canonical bytes of every record.
"""
from __future__ import annotations

import base64
import contextlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from . import keys, merkle
from .canon import (Link, cid_of_bytes, cid_parse, cid_str, dag_cbor, decode_dag_cbor)

try:  # POSIX advisory locking; on other platforms only one writer process is supported
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

FORMAT = "aeos-receipts/v0"
CHECKPOINT_CONTEXT = b"aeos-receipts/checkpoint/v0\n"

RECORD_KINDS = {"session.start", "session.end", "tool.call", "tool.result",
                "policy.decision", "approval", "journal.entry", "period.transition", "note"}


def now_ms() -> int:
    return int(time.time() * 1000)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


# --------------------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------------------


def make_record(kind: str, agent: str, *, on_behalf_of: Optional[str] = None,
                subject: Optional[str] = None, body: Optional[Dict[str, Any]] = None,
                parents: Sequence[bytes] = (), ts: Optional[int] = None) -> Dict[str, Any]:
    """Build a record. `agent` and `on_behalf_of` are URIs, ideally SPIFFE IDs.

    kind      what happened (see RECORD_KINDS; custom kinds start with "x-")
    subject   what it happened to, for example the tool name
    body      small facts about the action: digests, decision, reasons, amounts
    parents   CIDs of the records that caused this one
    """
    if kind not in RECORD_KINDS and not kind.startswith("x-"):
        raise ValueError(f"unknown record kind {kind!r}")
    if not agent:
        raise ValueError("agent identity is required")
    return {"v": 0, "kind": kind, "agent": agent, "obo": on_behalf_of, "subject": subject,
            "body": body or {}, "parents": [Link(p) for p in parents],
            "ts": now_ms() if ts is None else ts}


def to_view(v: Any) -> Any:
    """Readable JSON view of a decoded record: bytes as hex, links as CID strings."""
    if isinstance(v, Link):
        return {"/": cid_str(bytes(v))}
    if isinstance(v, bytes):
        return {"hex": v.hex()}
    if isinstance(v, list):
        return [to_view(x) for x in v]
    if isinstance(v, dict):
        return {k: to_view(x) for k, x in v.items()}
    return v


# --------------------------------------------------------------------------------------
# Checkpoints and receipts
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Checkpoint:
    log_id: str
    size: int
    root: bytes
    ts: int
    key_id: str
    sig: bytes = b""

    def message(self) -> bytes:
        return CHECKPOINT_CONTEXT + dag_cbor({"log": self.log_id, "size": self.size,
                                              "root": self.root, "ts": self.ts})

    def to_json(self) -> Dict[str, Any]:
        return {"log": self.log_id, "size": self.size, "root": self.root.hex(), "ts": self.ts,
                "key_id": self.key_id, "sig": b64(self.sig)}

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Checkpoint":
        return cls(d["log"], int(d["size"]), bytes.fromhex(d["root"]), int(d["ts"]),
                   d["key_id"], unb64(d["sig"]))

    def verify(self, public_key: bytes) -> bool:
        return (self.key_id == keys.key_id(public_key)
                and keys.verify(public_key, self.sig, self.message()))


def verify_receipt(receipt: Dict[str, Any], public_key: bytes) -> List[str]:
    """Check a receipt offline. Returns a list of problems; an empty list means valid."""
    problems: List[str] = []
    try:
        if receipt.get("type") != "aeos-receipt/v0":
            return ["not an aeos-receipt/v0 document"]
        cp = Checkpoint.from_json(receipt["checkpoint"])
        raw = unb64(receipt["record"])
        index = int(receipt["index"])
        proof = [bytes.fromhex(h) for h in receipt["inclusion_proof"]]
    except (KeyError, ValueError, TypeError) as e:
        return [f"malformed receipt: {e}"]
    if cp.log_id != receipt.get("log_id"):
        problems.append("checkpoint belongs to a different log")
    if not cp.verify(public_key):
        problems.append("checkpoint signature does not verify with the given public key")
    try:
        decode_dag_cbor(raw)
    except ValueError as e:
        problems.append(f"record bytes are not canonical: {e}")
    cid = cid_of_bytes(raw)
    if cid_str(cid) != receipt.get("cid"):
        problems.append("record CID does not match the record bytes")
    if not merkle.verify_inclusion(merkle.leaf_hash(cid), index, cp.size, proof, cp.root):
        problems.append("inclusion proof does not lead to the checkpoint root")
    return problems


def verify_consistency_doc(doc: Dict[str, Any], public_key: bytes) -> List[str]:
    """Check that a newer checkpoint extends an older one (nothing rewritten or removed)."""
    try:
        old = Checkpoint.from_json(doc["old"])
        new = Checkpoint.from_json(doc["new"])
        proof = [bytes.fromhex(h) for h in doc["proof"]]
    except (KeyError, ValueError, TypeError) as e:
        return [f"malformed consistency proof: {e}"]
    problems = []
    if old.log_id != new.log_id:
        problems.append("checkpoints belong to different logs")
    for name, cp in (("old", old), ("new", new)):
        if not cp.verify(public_key):
            problems.append(f"{name} checkpoint signature does not verify")
    if not merkle.verify_consistency(old.size, new.size, proof, old.root, new.root):
        problems.append("the newer checkpoint does not extend the older one")
    return problems


# --------------------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------------------


@dataclass
class Entry:
    index: int
    cid: bytes
    raw: bytes


@dataclass
class VerifyReport:
    records: int = 0
    checkpoints: int = 0
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


class ReceiptLog:
    def __init__(self, path: Path, meta: Dict[str, Any],
                 key: Optional[keys.Ed25519PrivateKey]) -> None:
        self.path = Path(path)
        self.meta = meta
        self.log_id: str = meta["log_id"]
        self.public_key = bytes.fromhex(meta["public_key"])
        self._key = key
        self._entries: List[Entry] = []
        self._leaves: List[bytes] = []
        self._by_cid: Dict[bytes, int] = {}
        self._offset = 0

    # ---- creation and opening ---------------------------------------------------------

    @classmethod
    def create(cls, path: Path, *, log_id: Optional[str] = None,
               key_path: Optional[Path] = None) -> "ReceiptLog":
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        if (path / "log.json").exists():
            raise FileExistsError(f"{path} already holds a receipt log")
        key_path = Path(key_path) if key_path else path / "signing.key"
        key = keys.load_key(key_path) if key_path.exists() else keys.generate_key(key_path)
        pub = keys.public_bytes(key)
        meta = {"format": FORMAT, "log_id": log_id or f"urn:uuid:{uuid.uuid4()}",
                "public_key": pub.hex(), "key_id": keys.key_id(pub), "created": now_ms()}
        (path / "log.json").write_text(json.dumps(meta, indent=2) + "\n")
        (path / "records.jsonl").touch()
        (path / "checkpoints.jsonl").touch()
        return cls(path, meta, key)

    @classmethod
    def open(cls, path: Path, *, key_path: Optional[Path] = None,
             read_only: bool = False) -> "ReceiptLog":
        path = Path(path)
        meta = json.loads((path / "log.json").read_text())
        if meta.get("format") != FORMAT:
            raise ValueError(f"unsupported log format {meta.get('format')!r}")
        key = None
        if not read_only:
            kp = Path(key_path) if key_path else path / "signing.key"
            if kp.exists():
                key = keys.load_key(kp)
                if keys.public_bytes(key).hex() != meta["public_key"]:
                    raise ValueError("signing key does not match the log's public key")
        log = cls(path, meta, key)
        log._load_new()
        return log

    # ---- internals --------------------------------------------------------------------

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        with open(self.path / ".lock", "a") as lf:
            if fcntl:
                fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                self._load_new()
                yield
            finally:
                if fcntl:
                    fcntl.flock(lf, fcntl.LOCK_UN)

    def _load_new(self) -> None:
        """Read records appended since the last read (possibly by another process)."""
        with open(self.path / "records.jsonl", "rb") as f:
            f.seek(self._offset)
            for line in f:
                if not line.endswith(b"\n"):
                    break                      # partial write in progress
                self._offset += len(line)
                d = json.loads(line)
                raw = unb64(d["cbor"])
                cid = cid_of_bytes(raw)
                self._add(Entry(int(d["i"]), cid, raw))

    def _add(self, e: Entry) -> None:
        self._entries.append(e)
        self._leaves.append(merkle.leaf_hash(e.cid))
        self._by_cid[e.cid] = e.index

    # ---- writing ----------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def can_sign(self) -> bool:
        """True when the signing key is loaded, so checkpoints can be issued."""
        return self._key is not None

    def append(self, record: Dict[str, Any], content: Optional[Dict[str, Any]] = None
               ) -> Entry:
        """Append a record and return its index and CID.

        `content` (optional) is stored beside the log under content/<cid>.json, for
        operators who keep full arguments and results. The record itself holds digests.
        """
        raw = dag_cbor(record)
        cid = cid_of_bytes(raw)
        with self._locked():
            if cid in self._by_cid:            # same bytes, same record: idempotent
                return self._entries[self._by_cid[cid]]
            for p in record.get("parents", []):
                if bytes(p) not in self._by_cid:
                    raise KeyError(f"parent {cid_str(bytes(p))} is not in this log")
            e = Entry(len(self._entries), cid, raw)
            if content is not None:
                cdir = self.path / "content"
                cdir.mkdir(exist_ok=True)
                (cdir / f"{cid_str(cid)}.json").write_text(json.dumps(content, indent=2))
            line = json.dumps({"i": e.index, "cid": cid_str(cid), "cbor": b64(raw),
                               "view": to_view(decode_dag_cbor(raw))},
                              separators=(",", ":")) + "\n"
            with open(self.path / "records.jsonl", "ab") as f:
                f.write(line.encode())
                f.flush()
            self._offset += len(line.encode())
            self._add(e)
            return e

    def checkpoint(self, ts: Optional[int] = None) -> Checkpoint:
        """Sign the current tree head and record it in checkpoints.jsonl."""
        if self._key is None:
            raise PermissionError("no signing key loaded for this log")
        with self._locked():
            cp = Checkpoint(self.log_id, len(self._leaves), merkle.root(self._leaves),
                            now_ms() if ts is None else ts, self.meta["key_id"])
            cp = Checkpoint(**{**cp.__dict__, "sig": self._key.sign(cp.message())})
            with open(self.path / "checkpoints.jsonl", "a") as f:
                f.write(json.dumps(cp.to_json(), separators=(",", ":")) + "\n")
            return cp

    # ---- reading ----------------------------------------------------------------------

    def checkpoints(self) -> List[Checkpoint]:
        with open(self.path / "checkpoints.jsonl") as f:
            return [Checkpoint.from_json(json.loads(line)) for line in f if line.strip()]

    def entry(self, ref: str) -> Entry:
        """Look up a record by index or CID string."""
        self._load_new()
        if ref.isdigit():
            return self._entries[int(ref)]
        return self._entries[self._by_cid[cid_parse(ref)]]

    def record(self, e: Entry) -> Dict[str, Any]:
        return decode_dag_cbor(e.raw)

    def entries(self) -> List[Entry]:
        self._load_new()
        return list(self._entries)

    def receipt(self, e: Entry, checkpoint: Optional[Checkpoint] = None) -> Dict[str, Any]:
        """Receipt for one record against a checkpoint that covers it.

        Uses the latest checkpoint, signing a new one if none covers the record yet.
        """
        if checkpoint is None:
            covering = [c for c in self.checkpoints() if c.size > e.index]
            checkpoint = covering[-1] if covering else self.checkpoint()
        if checkpoint.size <= e.index:
            raise ValueError("checkpoint does not cover this record")
        proof = merkle.inclusion_proof(e.index, self._leaves[:checkpoint.size])
        return {"type": "aeos-receipt/v0", "log_id": self.log_id, "index": e.index,
                "cid": cid_str(e.cid), "record": b64(e.raw),
                "inclusion_proof": [h.hex() for h in proof],
                "checkpoint": checkpoint.to_json()}

    def consistency_proof(self, old_size: int, new_size: int) -> List[bytes]:
        """Hashes proving the tree of new_size extends the tree of old_size (RFC 9162)."""
        self._load_new()
        if not 0 <= old_size <= new_size <= len(self._leaves):
            raise ValueError("checkpoint sizes are out of range for this log")
        if old_size in (0, new_size):
            return []
        return merkle.consistency_proof(old_size, self._leaves[:new_size])

    def consistency(self, old: Checkpoint, new: Checkpoint) -> Dict[str, Any]:
        if not old.size <= new.size <= len(self._leaves):
            raise ValueError("checkpoint sizes are out of range for this log")
        proof = merkle.consistency_proof(old.size, self._leaves[:new.size]) if old.size else []
        return {"type": "aeos-consistency/v0", "old": old.to_json(), "new": new.to_json(),
                "proof": [h.hex() for h in proof]}

    # ---- full verification ------------------------------------------------------------

    def verify(self) -> VerifyReport:
        """Recompute everything from the files: record bytes, CIDs, causal links,
        readable views, and every checkpoint's signature and root."""
        rep = VerifyReport()
        leaves: List[bytes] = []
        seen: Dict[bytes, int] = {}
        with open(self.path / "records.jsonl", "rb") as f:
            for n, line in enumerate(f):
                rep.records += 1
                try:
                    d = json.loads(line)
                    raw = unb64(d["cbor"])
                    rec = decode_dag_cbor(raw)
                except (ValueError, KeyError) as ex:
                    rep.problems.append(f"line {n + 1}: unreadable record ({ex})")
                    leaves.append(b"")
                    continue
                cid = cid_of_bytes(raw)
                if d.get("i") != n:
                    rep.problems.append(f"line {n + 1}: index {d.get('i')} out of sequence")
                if d.get("cid") != cid_str(cid):
                    rep.problems.append(f"record {n}: stored CID does not match its bytes")
                if d.get("view") != to_view(rec):
                    rep.problems.append(f"record {n}: readable view differs from signed bytes")
                for p in rec.get("parents", []):
                    if bytes(p) not in seen:
                        rep.problems.append(f"record {n}: parent is missing or later in the log")
                seen[cid] = n
                leaves.append(merkle.leaf_hash(cid))
        prev: Optional[Checkpoint] = None
        for cp in self.checkpoints():
            rep.checkpoints += 1
            label = f"checkpoint size {cp.size}"
            if cp.log_id != self.log_id:
                rep.problems.append(f"{label}: belongs to a different log")
            if not cp.verify(self.public_key):
                rep.problems.append(f"{label}: signature does not verify")
            if cp.size > len(leaves):
                rep.problems.append(f"{label}: covers more records than the log holds")
            elif merkle.root(leaves[:cp.size]) != cp.root:
                rep.problems.append(f"{label}: root does not match the records "
                                    "(records were changed, removed or reordered)")
            if prev is not None and cp.size < prev.size:
                rep.problems.append(f"{label}: smaller than the checkpoint before it")
            prev = cp
        return rep
