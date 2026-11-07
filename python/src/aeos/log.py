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
import logging
import os
import threading
import time
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, TypeVar

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

_T = TypeVar("_T")

# Passkey registry records and confirming assertions. Each is written together with what it
# belongs to, judged against the live passkey directory, so only `Recorder` writes them
# (spec/action-records-v1.md section 10.4); `ActionLog.append` refuses them.
PASSKEY_KINDS = frozenset({"x-passkey-enrolled", "x-passkey-revoked", "x-approver-rebound",
                           "x-approval-evidence"})
# Beside records.jsonl while a batch of records is being written: {"offset", "length"}. Its
# presence means the batch is unfinished; the next writer cuts the file back to `offset`, and
# readers ignore everything from there on (section 6).
PENDING = ".pending"
TORN = "torn"                      # bytes cut from an unfinished write, kept as <offset>.bin

LOG = logging.getLogger(__name__)

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


def _lines(data: bytes) -> List[bytes]:
    """records.jsonl lines, each with its newline, and a last one without if it is unended."""
    parts = data.split(b"\n")
    return [p + b"\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _fsync_dir(path: Path) -> None:
    """Make a file's creation, renaming or removal in `path` durable (POSIX only)."""
    if not hasattr(os, "O_DIRECTORY"):
        return                                   # pragma: no cover - Windows has no such call
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_durably(path: Path, data: bytes) -> None:
    """Write a whole file and flush it to the disk."""
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


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
    """An audit trail on disk, safe to share between threads and between processes.

    Lock order, across AE-OS: the passkey directory, then the gateway, then the recorder,
    then this trail's file lock. A thread takes them in that order and never the other way
    round; the trail's in-memory index lock is taken inside the file lock, and readers take
    it alone.

    A write is durable when it returns: each batch of records is announced in `.pending`,
    written and flushed to the disk, and only then is `.pending` removed. A batch whose
    `.pending` is still there was cut short (the writer died, or the power failed); readers
    ignore it, and the next writer cuts it off, keeping the cut bytes under torn/.
    """

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
        # Guards the in-memory index (_entries, _leaves, _by_cid, _offset) so a reader in one
        # thread never loads a line a writer in another has written but not yet indexed.
        self._index_lock = threading.RLock()
        self._holder: Optional[int] = None         # thread holding the file lock, if any

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
        _write_durably(path / "records.jsonl", b"")
        _write_durably(path / "checkpoints.jsonl", b"")
        _write_durably(path / "log.json", (json.dumps(meta, indent=2) + "\n").encode())
        _fsync_dir(path)
        if key_path.parent != path:
            _fsync_dir(key_path.parent)
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
        """Hold the trail's file lock, then its index lock, with any unfinished write cut off
        and the index brought up to date.

        Lock order: directory, gateway, recorder, file (see the class). A thread that already
        holds this lock and asks for it again, for example by writing from inside the judge
        of a write, would wait for itself forever, so it is refused at once instead."""
        if self._holder == threading.get_ident():
            raise RuntimeError("this thread is already writing to the audit trail: a write "
                               "from inside another write would deadlock")
        with open(self.path / ".lock", "a") as lf:
            if fcntl:
                fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                with self._index_lock:
                    self._holder = threading.get_ident()
                    try:
                        if fcntl:                   # no writer is mid-write: safe to cut
                            self._recover_pending()
                        self._load_new_locked()
                        if fcntl:
                            self._cut(self._offset, "an unterminated last line")
                        yield
                    finally:
                        self._holder = None
            finally:
                if fcntl:
                    fcntl.flock(lf, fcntl.LOCK_UN)

    def _pending_offset(self) -> Optional[int]:
        """Where the unfinished write announced in `.pending` starts, or None if there is none.
        A `.pending` that cannot be read is being written, or was cut short, before any record
        of its batch was: it holds nothing back."""
        try:
            doc = json.loads((self.path / PENDING).read_bytes())
            offset = doc["offset"]
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            return None
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            return None
        return offset

    def _recover_pending(self) -> None:
        """Cut off a batch that `.pending` says was never finished, then remove `.pending`.
        Called with the file lock held, so its writer is gone. Raises if it cannot."""
        if not (self.path / PENDING).exists():
            return
        offset = self._pending_offset()
        if offset is None:                     # announced, then cut before any record was
            (self.path / PENDING).unlink()
            _fsync_dir(self.path)
            return
        if offset < self._offset:
            raise RuntimeError(f"audit trail {self.log_id}: this process indexed records past "
                               f"the unfinished write at offset {offset}")
        self._cut(offset, "an unfinished write")
        (self.path / PENDING).unlink()
        _fsync_dir(self.path)

    def _cut(self, offset: int, what: str) -> None:
        """Cut records.jsonl back to `offset`, keeping the bytes cut under torn/. Called with
        the file lock held; never without one (a write in progress would be cut)."""
        path = self.path / "records.jsonl"
        if path.stat().st_size <= offset:
            return
        with open(path, "rb") as f:
            f.seek(offset)
            cut = f.read()
        torn = self.path / TORN
        torn.mkdir(exist_ok=True)
        keep, n = torn / f"{offset}.bin", 1
        while keep.exists():
            keep, n = torn / f"{offset}.{n}.bin", n + 1
        _write_durably(keep, cut)
        _fsync_dir(torn)
        os.truncate(path, offset)
        with open(path, "rb+") as f:
            os.fsync(f.fileno())
        LOG.warning("audit trail %s: cut %s of %d bytes at offset %d, kept in %s",
                    self.log_id, what, len(cut), offset, keep)

    def _load_new(self) -> None:
        """Read records appended since the last read (possibly by another process). Lines are
        indexed under the index lock, so a read in one thread and a write in another never
        both count the same line."""
        with self._index_lock:
            self._load_new_locked()

    def _load_new_locked(self) -> None:
        """Index the whole new lines, stopping before an unfinished write: a line not yet
        ended, or anything from the offset of a `.pending` present before or after the read."""
        before = self._pending_offset()
        with open(self.path / "records.jsonl", "rb") as f:
            f.seek(self._offset)
            data = f.read()
        after = self._pending_offset()
        end = min([self._offset + len(data)] + [o for o in (before, after) if o is not None])
        data = data[:max(0, end - self._offset)]
        for line in _lines(data):
            if not line.endswith(b"\n"):
                break                          # partial write in progress
            self._offset += len(line)
            position = len(self._entries)
            try:
                d, raw = _read_line(line)
            except ValueError:
                d, raw = {}, b""               # reported by verify(); the trail still opens
            cid = cid_of_bytes(raw)
            try:
                sig = unb64(d["sig"]) if _present(d.get("sig")) else None
            except (ValueError, TypeError):
                sig = None                 # reported by verify(); the record itself still loads
            if sig is not None and not self._first_signed_seen:
                # the marker, when there is one, is the first signed record
                self._first_signed_seen = True
                try:
                    first = decode_dag_cbor(raw)
                    is_marker = isinstance(first, dict) and first.get("kind") == MARKER_KIND
                except ValueError:
                    is_marker = False            # verify() reports the unreadable record
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
               allow_unsigned: bool = False) -> Entry:
        """Append a record, signed with the issuer key, and return its index and CID. It is on
        the disk when this returns.

        The first signed append to a trail first appends an issuer-signing marker record
        (kind `x-issuer-signing`, carrying the key id), itself signed; from it on, every
        record must be signed, which is how a stripped signature is detected.

        Without the signing key this raises, as `checkpoint()` does: a writer that cannot
        sign must not write. `allow_unsigned=True` is only for importing existing version 0
        data, which has no issuer signatures; a trail that holds signed records then reports
        the unsigned ones that follow as problems (see `verify`).

        Passkey registry records and confirming assertions (PASSKEY_KINDS) are refused: they
        are written only through `Recorder` with a passkey directory, which writes each with
        what it belongs to and judges it first.

        `content` (optional) is stored beside the log under content/<cid>.json, for
        operators who keep full arguments and results. The record itself holds digests.

        Takes the trail's file lock (lock order: directory, gateway, recorder, file).
        """
        kind = record.get("kind") if isinstance(record, dict) else None
        if kind in PASSKEY_KINDS:
            raise ValueError(f"a {kind} record is written only through Recorder with a passkey "
                             "directory")
        return self._append_all([record], [content], allow_unsigned=allow_unsigned)[0]

    def _append_all(self, records: Sequence[Dict[str, Any]],
                    contents: Optional[Sequence[Optional[Dict[str, Any]]]] = None, *,
                    allow_unsigned: bool = False) -> List[Entry]:
        """Append several records together, as `append` does each, in one write under one
        lock: a reader sees all of them or none, and a write cut short leaves none behind once
        the next writer takes the lock. A record may name an earlier one of the same call as
        its parent. A batch already in the trail is returned as it is, not written again; one
        only partly there is refused.

        Takes the trail's file lock (lock order: directory, gateway, recorder, file).
        """
        return self._append_judged(records, contents, allow_unsigned=allow_unsigned)[0]

    def _append_judged(self, records: Sequence[Dict[str, Any]],
                       contents: Optional[Sequence[Optional[Dict[str, Any]]]] = None, *,
                       allow_unsigned: bool = False,
                       judge: Optional[Callable[[int], Optional[Callable[[], None]]]] = None,
                       directory: Any = None
                       ) -> Tuple[List[Entry], Optional[Callable[[], None]]]:
        """`_append_all` for the recorder, ordered against the passkey directory.

        With the file lock held and the index current, `directory` (a passkeys.Directory) is
        first brought up to the trail, so it holds every registry change and every assertion
        used by any process. Then `judge(position)` runs, with the position the first record
        will take, before anything is written: it raises to refuse, writing nothing, and
        otherwise returns what applies its judgement (or None). That is handed back with the
        entries, for the caller to run once the batch is on the disk; it also marks the batch
        as seen by the directory. The judge must not change anything or write to this trail.

        Lock order: directory, gateway, recorder, file. The caller holds the directory lock
        throughout; the judge runs with the file lock held, so it may only use a lock earlier
        in that order that its thread already holds, never wait for one, and a write to this
        trail from inside it raises at once.
        """
        if not allow_unsigned:
            self.require_signing()
        contents = list(contents) if contents is not None else [None] * len(records)
        if len(contents) != len(records):
            raise ValueError("one content (or None) per record")
        with self._locked():
            if directory is not None:
                directory.sync(self._records_from(directory.seen))
            cids = [cid_of_bytes(dag_cbor(r)) for r in records]
            present = [c in self._by_cid for c in cids]
            if all(present):                   # the same batch again: idempotent
                return [self._entries[self._by_cid[c]] for c in cids], None
            if any(present):
                there = sorted(self._by_cid[c] for c in cids if c in self._by_cid)
                raise ValueError(
                    f"audit trail {self.log_id}: records {there} of this batch are already in "
                    "the trail and the rest are not; a batch is written whole, so the trail "
                    "holds a write that was cut short")
            slots: List[int] = []               # each record's place among those to write
            todo: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]] = []
            batch_slot: Dict[bytes, int] = {}
            parents_ok = set(self._by_cid)
            for record, content, cid in zip(records, contents, cids):
                if cid in batch_slot:
                    slots.append(batch_slot[cid])
                    continue
                for p in record.get("parents", []):
                    if bytes(p) not in parents_ok:
                        raise KeyError(f"parent {cid_str(bytes(p))} is not in this log")
                parents_ok.add(cid)
                batch_slot[cid] = len(todo)
                slots.append(len(todo))
                todo.append((record, content))
            marker = None
            if not allow_unsigned and self._marker_index is None:
                marker = make_record(MARKER_KIND, self.log_id,
                                     body={"key_id": self.meta["key_id"]},
                                     ts=todo[0][0].get("ts"))
                if cid_of_bytes(dag_cbor(marker)) in batch_slot:
                    marker = None              # the record being written is the marker itself
            verdict = None
            if judge is not None:
                verdict = judge(len(self._entries) + (1 if marker is not None else 0))
            written = self._write_all(([(marker, None)] if marker is not None else []) + todo,
                                      signed=not allow_unsigned)
            if not allow_unsigned and self._marker_index is None:
                self._marker_index = written[0].index
                self._first_signed_seen = True
            mine = written[1:] if marker is not None else written
            if directory is None or verdict is None:
                return [mine[k] for k in slots], verdict
            end, applies = written[-1].index + 1, verdict

            def commit() -> None:
                applies()
                directory.seen = max(directory.seen, end)

            return [mine[k] for k in slots], commit

    def _records_from(self, start: int) -> List[Tuple[int, bytes, Any]]:
        """(position, CID, decoded record or None) for each entry from `start` on."""
        out: List[Tuple[int, bytes, Any]] = []
        for e in self._entries[start:]:
            try:
                rec: Any = decode_dag_cbor(e.raw)
            except ValueError:
                rec = None
            out.append((e.index, e.cid, rec))
        return out

    def _write(self, record: Dict[str, Any], content: Optional[Dict[str, Any]],
               signed: bool = True) -> Entry:
        """Write one record to the file, under the lock; signed unless importing version 0."""
        return self._write_all([(record, content)], signed)[0]

    def _write_all(self, batch: Sequence[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]],
                   signed: bool = True) -> List[Entry]:
        """Write records to the file in one write, with the file and index locks held, flush
        them to the disk, and only then index them and store their content.

        With file locking, the batch is first announced in `.pending` (flushed to the disk)
        and `.pending` is removed once the records are; if the write fails here, the batch is
        cut off at once, and if the process dies, the next writer cuts it off. Without file
        locking (one writer process only), nothing is ever cut: a line left unfinished is
        ended with a newline first, and verify() reports it."""
        path = self.path / "records.jsonl"
        if not fcntl and path.stat().st_size > self._offset:
            with open(path, "ab") as f:            # end the stranded line, never cut it
                f.write(b"\n")
                f.flush()
                os.fsync(f.fileno())
            self._load_new_locked()
        entries: List[Entry] = []
        data = b""
        for record, _ in batch:
            raw = dag_cbor(record)
            cid = cid_of_bytes(raw)
            sig = (self._key.sign(statement_message(cid))
                   if signed and self._key is not None else None)
            e = Entry(len(self._entries) + len(entries), cid, raw, sig,
                      self.meta["key_id"] if sig else None)
            fields: Dict[str, Any] = {"i": e.index, "cid": cid_str(cid), "cbor": b64(raw)}
            if sig:
                fields.update(key_id=e.signer, sig=b64(sig))
            fields["view"] = to_view(decode_dag_cbor(raw))
            data += (json.dumps(fields, separators=(",", ":")) + "\n").encode()
            entries.append(e)
        offset = self._offset
        pending = self.path / PENDING
        if fcntl:
            _write_durably(pending, json.dumps({"offset": offset, "length": len(data)}).encode())
            _fsync_dir(self.path)
        try:
            with open(path, "ab") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            if fcntl:
                self._cut(offset, "a failed write")     # raises if it cannot
                pending.unlink()
                _fsync_dir(self.path)
            raise
        if fcntl:
            pending.unlink()
            _fsync_dir(self.path)
        self._offset += len(data)
        for e in entries:
            self._add(e)
        for e, (_, content) in zip(entries, batch):
            if content is not None:
                cdir = self.path / "content"
                cdir.mkdir(exist_ok=True)
                (cdir / f"{cid_str(e.cid)}.json").write_text(json.dumps(content, indent=2))
        return entries

    def checkpoint(self, ts: Optional[int] = None) -> Checkpoint:
        """Sign the current tree head and record it in checkpoints.jsonl, on the disk when
        this returns."""
        self.require_signing()
        with self._locked():
            cp = Checkpoint(self.log_id, len(self._leaves), merkle.root(self._leaves),
                            now_ms() if ts is None else ts, self.meta["key_id"])
            cp = Checkpoint(**{**cp.__dict__, "sig": self._key.sign(cp.message())})
            with open(self.path / "checkpoints.jsonl", "a") as f:
                f.write(json.dumps(cp.to_json(), separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return cp

    # ---- reading ----------------------------------------------------------------------

    def checkpoints(self) -> List[Checkpoint]:
        with open(self.path / "checkpoints.jsonl") as f:
            return [Checkpoint.from_json(json.loads(line)) for line in f if line.strip()]

    def entry(self, ref: str) -> Entry:
        """Look up a record by index or CID string."""
        with self._index_lock:
            self._load_new_locked()
            if ref.isdigit():
                return self._entries[int(ref)]
            return self._entries[self._by_cid[cid_parse(ref)]]

    def record(self, e: Entry) -> Dict[str, Any]:
        return decode_dag_cbor(e.raw)

    def entries(self) -> List[Entry]:
        with self._index_lock:
            self._load_new_locked()
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
        with self._index_lock:                 # another process may have written more since
            self._load_new_locked()
            leaves = list(self._leaves)
        if checkpoint.size > len(leaves):
            raise ValueError("the checkpoint covers records this trail does not hold")
        proof = merkle.inclusion_proof(e.index, leaves[:checkpoint.size])
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
        with self._index_lock:
            self._load_new_locked()
            leaves = list(self._leaves)
        if not 0 <= old_size <= new_size <= len(leaves):
            raise ValueError("checkpoint sizes are out of range for this log")
        if old_size in (0, new_size):
            return []
        return merkle.consistency_proof(old_size, leaves[:new_size])

    def consistency(self, old: Checkpoint, new: Checkpoint) -> Dict[str, Any]:
        with self._index_lock:                 # another process may have written more since
            self._load_new_locked()
            leaves = list(self._leaves)
        if not old.size <= new.size <= len(leaves):
            raise ValueError("checkpoint sizes are out of range for this log")
        proof = merkle.consistency_proof(old.size, leaves[:new.size]) if old.size else []
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
        pending = self._pending_offset()
        with open(self.path / "records.jsonl", "rb") as f:
            data = f.read()
        if pending is not None and pending < len(data):
            data = data[:pending]
            first = data.count(b"\n") + 1
            rep.problems.append(f"line {first} on: an unfinished write, not yet recovered "
                                "(.pending is present)")
        lines = _lines(data)
        if lines and not lines[-1].endswith(b"\n"):
            rep.problems.append(f"line {len(lines)}: an unfinished write, not yet recovered")
            lines.pop()
        for n, line in enumerate(lines):
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
