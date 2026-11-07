"""File-backed, append-only audit trail of action records.

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
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from . import keys, merkle
from .canon import (Link, cid_of_bytes, cid_parse, cid_str, dag_cbor, decode_dag_cbor)

try:  # POSIX advisory locking; on other platforms only one writer process is supported
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

# These two strings are part of the signed bytes and the on-disk format, so they keep their
# original text (spec/action-records-v1.md sections 3 and 6).
FORMAT = "aeos-receipts/v0"
CHECKPOINT_CONTEXT = b"aeos-receipts/checkpoint/v0\n"

# Readers accept both document types. Writers keep emitting the version 0 type, with the
# issuer signature as an extra field, until deployed verifiers (ae-os.org/verify) read
# `aeos-action-record/v1`; WRITTEN_TYPE then moves to it in a later release.
ACTION_RECORD_TYPE = "aeos-action-record/v1"
LEGACY_RECEIPT_TYPE = "aeos-receipt/v0"
WRITTEN_TYPE = LEGACY_RECEIPT_TYPE

# The issuer signs the binary CID of each action record under this context, which is
# separate from the checkpoint's. Records without a signature are "log-signed only".
STATEMENT_CONTEXT = b"aeos-action-record/statement/v1\n"
# The first signed append to a trail first appends this record, itself issuer-signed. It sits
# in the Merkle tree, so no checkpoint can be valid once it is removed, and from it onward
# every record must carry a valid issuer signature (see `ActionLog.verify`).
MARKER_KIND = "x-issuer-signing"
ISSUER_SIGNED = "issuer-signed"
LOG_SIGNED_ONLY = "log-signed only"

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
# Checkpoints and action records
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
        # Checked field by field in the order, and with the messages, the Rust verifier uses.
        def get(k: str) -> Any:
            if not isinstance(d, dict) or k not in d:
                raise ValueError(f"missing field '{k}'")
            return d[k]

        def text(k: str) -> str:
            v = get(k)
            if not isinstance(v, str):
                raise ValueError(f"field '{k}' must be text")
            return v

        def integer(k: str, what: str, minimum: Optional[int] = None) -> int:
            v = get(k)
            if not isinstance(v, int) or isinstance(v, bool) or (minimum is not None
                                                                 and v < minimum):
                raise ValueError(f"field '{k}' must be {what}")
            return v

        log_id = text("log")
        size = integer("size", "a non-negative integer", 0)
        root = bytes.fromhex(text("root"))
        ts = integer("ts", "an integer")
        return cls(log_id, size, root, ts, text("key_id"), unb64(text("sig")))

    def verify(self, public_key: bytes) -> bool:
        return (self.key_id == keys.key_id(public_key)
                and keys.verify(public_key, self.sig, self.message()))


def _read_line(line: bytes) -> Tuple[Dict[str, Any], bytes]:
    """One records.jsonl line as (its JSON object, its record bytes); ValueError when the
    line cannot be read. The messages for a missing or mistyped field are the ones the
    Rust verifier gives."""
    try:
        d = json.loads(line)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None
    if not isinstance(d, dict) or "cbor" not in d:
        raise ValueError("missing field 'cbor'")
    if not isinstance(d["cbor"], str):
        raise ValueError("field 'cbor' must be text")
    return d, unb64(d["cbor"])


def is_record(rec: Any) -> bool:
    """Whether a decoded record has the shape every reader of the trail relies on."""
    return (isinstance(rec, dict) and isinstance(rec.get("kind"), str)
            and isinstance(rec.get("agent"), str) and isinstance(rec.get("body"), dict)
            and isinstance(rec.get("ts"), int) and not isinstance(rec.get("ts"), bool)
            and isinstance(rec.get("parents"), list)
            and all(isinstance(p, Link) for p in rec["parents"]))


def _present(value: Any) -> bool:
    """A field counts as there unless it is absent, null or empty (the same in every
    verifier); anything else present must then be a valid base64 signature."""
    return value is not None and value != ""


def statement_message(cid: bytes) -> bytes:
    return STATEMENT_CONTEXT + cid


def verify_action_record(doc: Dict[str, Any], public_key: bytes) -> List[str]:
    """Check an action record with its Receipt offline.

    Accepts `aeos-action-record/v1` and the version 0 type `aeos-receipt/v0`. Returns a list of
    problems; an empty list means the action record is verified. A record with no issuer
    signature (everything written under version 0) is not a problem; see
    `verify_action_record_detail` to tell the two apart.
    """
    return verify_action_record_detail(doc, public_key)[0]


def verify_action_record_detail(doc: Dict[str, Any], public_key: bytes
                                ) -> "tuple[List[str], str]":
    """Like `verify_action_record`, plus how the record is vouched for: ISSUER_SIGNED when it
    carries an issuer signature that verifies, LOG_SIGNED_ONLY when it carries none. A
    signature that is present but wrong is a problem, never "log-signed only"."""
    problems: List[str] = []
    try:
        if doc.get("type") not in (ACTION_RECORD_TYPE, LEGACY_RECEIPT_TYPE):
            return [f"not an {ACTION_RECORD_TYPE} document (or {LEGACY_RECEIPT_TYPE})"], \
                LOG_SIGNED_ONLY
        cp = Checkpoint.from_json(doc["checkpoint"])
        raw = unb64(doc["record"])
        index = int(doc["index"])
        proof = [bytes.fromhex(h) for h in doc["inclusion_proof"]]
    except (KeyError, ValueError, TypeError) as e:
        return [f"malformed action record: {e}"], LOG_SIGNED_ONLY
    if cp.log_id != doc.get("log_id"):
        problems.append("checkpoint belongs to a different log")
    if not cp.verify(public_key):
        problems.append("checkpoint signature does not verify with the given public key")
    try:
        decode_dag_cbor(raw)
    except ValueError as e:
        problems.append(f"record bytes are not canonical: {e}")
    cid = cid_of_bytes(raw)
    if cid_str(cid) != doc.get("cid"):
        problems.append("record CID does not match the record bytes")
    if not merkle.verify_inclusion(merkle.leaf_hash(cid), index, cp.size, proof, cp.root):
        problems.append("inclusion proof does not lead to the checkpoint root")
    state = LOG_SIGNED_ONLY
    if "statement_signature" in doc:
        state = ISSUER_SIGNED
        try:
            sig_doc = doc["statement_signature"]
            sig_key_id, sig = sig_doc["key_id"], unb64(sig_doc["sig"])
        except (KeyError, ValueError, TypeError):
            problems.append("issuer signature is malformed")
        else:
            if sig_key_id != keys.key_id(public_key):
                problems.append("issuer signature names a different key than the given "
                                "public key")
            elif not keys.verify(public_key, sig, statement_message(cid)):
                problems.append("issuer signature does not verify with the given public key")
    return problems, state


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
    sig: Optional[bytes] = None          # issuer signature over the CID, when there is one
    signer: Optional[str] = None         # key id of that signature


@dataclass
class VerifyReport:
    records: int = 0
    checkpoints: int = 0
    issuer_signed: int = 0               # records whose issuer signature verified
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


class ActionLog:
    def __init__(self, path: Path, meta: Dict[str, Any],
                 key: Optional[keys.Ed25519PrivateKey]) -> None:
        self.path = Path(path)
        self.meta = meta
        self.log_id: str = meta["log_id"]
        self.public_key = bytes.fromhex(meta["public_key"])
        self._key = key
        self._marker_index: Optional[int] = None   # the issuer-signing marker, once written
        self._first_signed_seen = False
        self.key_source: Optional[Path] = None     # where open() looked for the key
        self._entries: List[Entry] = []
        self._leaves: List[bytes] = []
        self._by_cid: Dict[bytes, int] = {}
        self._offset = 0

    # ---- creation and opening ---------------------------------------------------------

    @classmethod
    def create(cls, path: Path, *, log_id: Optional[str] = None,
               key_path: Optional[Path] = None) -> "ActionLog":
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        if (path / "log.json").exists():
            raise FileExistsError(f"{path} already holds an audit trail")
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
             read_only: bool = False) -> "ActionLog":
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
        if not read_only:
            log.key_source = kp
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
                position = len(self._entries)
                try:
                    d, raw = _read_line(line)
                except ValueError:
                    d, raw = {}, b""           # reported by verify(); the trail still opens
                cid = cid_of_bytes(raw)
                try:
                    sig = unb64(d["sig"]) if _present(d.get("sig")) else None
                except (ValueError, TypeError):
                    sig = None             # reported by verify(); the record itself still loads
                if sig is not None and not self._first_signed_seen:
                    # the marker, when there is one, is the first signed record
                    self._first_signed_seen = True
                    try:
                        first = decode_dag_cbor(raw)
                        is_marker = isinstance(first, dict) and first.get("kind") == MARKER_KIND
                    except ValueError:
                        is_marker = False        # verify() reports the unreadable record
                    if is_marker:
                        self._marker_index = position
                self._add(Entry(position, cid, raw, sig, d.get("key_id") if sig else None))

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

    def require_signing(self) -> None:
        """Raise unless the signing key is loaded: a writer that cannot sign must not write."""
        if self._key is None:
            where = f"looked for {self.key_source}" if self.key_source else "none was given"
            raise PermissionError(f"this audit trail cannot sign, so nothing can be written to "
                                  f"it: no signing key found ({where}). Open it with the key "
                                  "file (--key).")

    def append(self, record: Dict[str, Any], content: Optional[Dict[str, Any]] = None, *,
               allow_unsigned: bool = False,
               before: Optional[Callable[[int], None]] = None) -> Entry:
        """Append a record, signed with the issuer key, and return its index and CID.

        The first signed append to a trail first appends an issuer-signing marker record
        (kind `x-issuer-signing`, carrying the key id), itself signed; from it on, every
        record must be signed, which is how a stripped signature is detected.

        Without the signing key this raises, as `checkpoint()` does: a writer that cannot
        sign must not write. `allow_unsigned=True` is only for importing existing version 0
        data, which has no issuer signatures; a trail that holds signed records then reports
        the unsigned ones that follow as problems (see `verify`).

        `content` (optional) is stored beside the log under content/<cid>.json, for
        operators who keep full arguments and results. The record itself holds digests.

        `before(index)` runs with the trail locked, once the record is known to be new and
        before anything is written, with the position the record will take (after the marker,
        if this append writes one). If it raises, nothing is written: this is how a caller
        refuses a record it has just judged, with no other writer able to move the position.
        """
        if not allow_unsigned:
            self.require_signing()
        raw = dag_cbor(record)
        cid = cid_of_bytes(raw)
        with self._locked():
            if cid in self._by_cid:            # same bytes, same record: idempotent
                return self._entries[self._by_cid[cid]]
            for p in record.get("parents", []):
                if bytes(p) not in self._by_cid:
                    raise KeyError(f"parent {cid_str(bytes(p))} is not in this log")
            if before is not None:
                before(len(self._entries) + (1 if not allow_unsigned
                                             and self._marker_index is None else 0))
            if not allow_unsigned and self._marker_index is None:
                marker = make_record(MARKER_KIND, self.log_id,
                                     body={"key_id": self.meta["key_id"]},
                                     ts=record.get("ts"))
                self._marker_index = self._write(marker, None).index
                self._first_signed_seen = True
                if cid in self._by_cid:        # the record was the marker itself
                    return self._entries[self._by_cid[cid]]
            return self._write(record, content, signed=not allow_unsigned)

    def _write(self, record: Dict[str, Any], content: Optional[Dict[str, Any]],
               signed: bool = True) -> Entry:
        """Write one record to the file, under the lock; signed unless importing version 0."""
        raw = dag_cbor(record)
        cid = cid_of_bytes(raw)
        sig = (self._key.sign(statement_message(cid))
               if signed and self._key is not None else None)
        e = Entry(len(self._entries), cid, raw, sig,
                  self.meta["key_id"] if sig else None)
        if content is not None:
            cdir = self.path / "content"
            cdir.mkdir(exist_ok=True)
            (cdir / f"{cid_str(cid)}.json").write_text(json.dumps(content, indent=2))
        fields: Dict[str, Any] = {"i": e.index, "cid": cid_str(cid), "cbor": b64(raw)}
        if sig:
            fields.update(key_id=e.signer, sig=b64(sig))
        fields["view"] = to_view(decode_dag_cbor(raw))
        line = json.dumps(fields, separators=(",", ":")) + "\n"
        with open(self.path / "records.jsonl", "ab") as f:
            f.write(line.encode())
            f.flush()
        self._offset += len(line.encode())
        self._add(e)
        return e

    def checkpoint(self, ts: Optional[int] = None) -> Checkpoint:
        """Sign the current tree head and record it in checkpoints.jsonl."""
        self.require_signing()
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

    def readable(self) -> List[Tuple[Entry, Dict[str, Any]]]:
        """The records that decode and have the shape of a record. A trail someone has
        tampered with can hold others; verify() reports each of them."""
        out = []
        for e in self.entries():
            try:
                rec = decode_dag_cbor(e.raw)
            except ValueError:
                continue
            if is_record(rec):
                out.append((e, rec))
        return out

    def action_record(self, e: Entry, checkpoint: Optional[Checkpoint] = None) -> Dict[str, Any]:
        """The record with its Receipt, against a checkpoint that covers it.

        Uses the latest checkpoint, signing a new one if none covers the record yet.
        """
        if checkpoint is None:
            covering = [c for c in self.checkpoints() if c.size > e.index]
            checkpoint = covering[-1] if covering else self.checkpoint()
        if checkpoint.size <= e.index:
            raise ValueError("checkpoint does not cover this record")
        proof = merkle.inclusion_proof(e.index, self._leaves[:checkpoint.size])
        doc = {"type": WRITTEN_TYPE, "log_id": self.log_id, "index": e.index,
               "cid": cid_str(e.cid), "record": b64(e.raw),
               "inclusion_proof": [h.hex() for h in proof],
               "checkpoint": checkpoint.to_json()}
        if e.sig:
            doc["statement_signature"] = {"key_id": e.signer, "sig": b64(e.sig)}
        return doc

    def receipt(self, e: Entry, checkpoint: Optional[Checkpoint] = None) -> Dict[str, Any]:
        """Deprecated name of `action_record`, kept for one release."""
        warnings.warn("ActionLog.receipt() is renamed action_record()", DeprecationWarning,
                      stacklevel=2)       # points at the caller
        return self.action_record(e, checkpoint)

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
        marker_at: Optional[int] = None
        with open(self.path / "records.jsonl", "rb") as f:
            for n, line in enumerate(f):
                rep.records += 1
                try:
                    d, raw = _read_line(line)
                    rec = decode_dag_cbor(raw)
                    if not isinstance(rec, dict):
                        raise ValueError("not a map")
                except ValueError as ex:
                    rep.problems.append(f"line {n + 1}: unreadable record ({ex})")
                    leaves.append(b"")
                    continue
                cid = cid_of_bytes(raw)
                i = d.get("i")
                if not (isinstance(i, int) and not isinstance(i, bool) and i == n):
                    rep.problems.append(f"line {n + 1}: index {d.get('i')} out of sequence")
                if d.get("cid") != cid_str(cid):
                    rep.problems.append(f"record {n}: stored CID does not match its bytes")
                if d.get("view") != to_view(rec):
                    rep.problems.append(f"record {n}: readable view differs from signed bytes")
                parents = rec.get("parents")
                for p in parents if isinstance(parents, list) else []:
                    if not (isinstance(p, Link) and bytes(p) in seen):
                        rep.problems.append(f"record {n}: parent is missing or later in the log")
                if marker_at is None and rec.get("kind") == MARKER_KIND:
                    # From the marker on, every record must carry a valid issuer signature.
                    marker_at = n
                    body = rec.get("body")
                    if not isinstance(body, dict) or body.get("key_id") != self.meta["key_id"]:
                        rep.problems.append(f"record {n}: the issuer-signing marker names a "
                                            "different key than the trail's")
                if _present(d.get("sig")):
                    try:
                        good = (d.get("key_id") == self.meta["key_id"]
                                and keys.verify(self.public_key, unb64(d["sig"]),
                                                statement_message(cid)))
                    except (ValueError, TypeError):
                        good = False
                    if good:
                        rep.issuer_signed += 1
                    else:
                        rep.problems.append(f"record {n}: issuer signature does not verify")
                else:
                    if _present(d.get("key_id")):
                        rep.problems.append(f"record {n}: issuer key id present without a "
                                            "signature")
                    if marker_at is not None:
                        rep.problems.append(f"record {n}: issuer signature missing (the "
                                            f"issuer-signing marker is record {marker_at})")
                seen[cid] = n
                leaves.append(merkle.leaf_hash(cid))
        prev: Optional[Checkpoint] = None
        with open(self.path / "checkpoints.jsonl", "rb") as f:
            checkpoint_lines = [(n, line) for n, line in enumerate(f) if line.strip()]
        for n, line in checkpoint_lines:
            rep.checkpoints += 1
            try:
                cp = Checkpoint.from_json(json.loads(line))
            except (KeyError, ValueError, TypeError, RecursionError) as ex:
                rep.problems.append(f"checkpoints line {n + 1}: unreadable checkpoint ({ex})")
                continue
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


# Version 0 names, kept for one release so code written against them keeps working.
DEPRECATED_ALIASES = {"ReceiptLog": "ActionLog", "verify_receipt": "verify_action_record"}


def deprecated_alias(name: str, *, stacklevel: int) -> Any:
    """The object a deprecated version 0 name stands for, warning at the caller's line."""
    new = DEPRECATED_ALIASES[name]
    warnings.warn(f"aeos.{name} is renamed {new}; the old name is removed after the "
                  "next release", DeprecationWarning, stacklevel=stacklevel + 1)
    return globals()[new]


def __getattr__(name: str) -> Any:
    if name in DEPRECATED_ALIASES:
        return deprecated_alias(name, stacklevel=2)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
