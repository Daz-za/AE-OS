"""Passkey approvals an auditor can check without trusting the writer of the trail.

Records that carry it (spec/action-records-v1.md, section 10):

    approval              a person's answer to an escalated call; for a passkey approver its
                          `evidence` summary names the assertion that proves a yes, or the
                          sign-in a no rests on
    x-approval-evidence   child of the approval: the WebAuthn assertion itself
    x-passkey-enrolled    a passkey joins an approver's registry
    x-passkey-revoked     a passkey leaves it
    x-approver-rebound    the approver's identity changed, which ends every earlier passkey

The registry is rebuilt from those records in trail order, in the same pass that checks the
approvals, so "was this passkey the approver's when the approval was recorded" is answered by
position in the trail, which the checkpoints commit to, not by a timestamp the writer chose. The
relying party id and origin an assertion is checked against are the ones enrolled for the
passkey, never the ones the evidence claims.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .canon import cid_parse, cid_str, json_digest
from .webauthn import (BATCH_CONTEXT_NAME, CID_LEN, DOCUMENT_TOOL, MAX_BATCH, RESERVED,
                       WebAuthnError, assertion_sha256, b64url, batch_digest, challenge_for,
                       check_origin, enrol_challenge, parse_cose_key, request_digest, unb64url,
                       verify_assertion, verify_registration)

KIND_ENROLLED = "x-passkey-enrolled"
KIND_REVOKED = "x-passkey-revoked"
KIND_REBOUND = "x-approver-rebound"
KIND_EVIDENCE = "x-approval-evidence"
EVIDENCE_KIND = "passkey-assertion"
ENROL_TOOL = "aeos/passkey-enrol"          # the "tool" a confirmation of a registry change signs
REVOKE_TOOL = "aeos/passkey-revoke"
REBIND_TOOL = "aeos/approver-rebind"
REGISTRY_KINDS = (KIND_ENROLLED, KIND_REVOKED, KIND_REBOUND)

Record = Tuple[int, bytes, Dict[str, Any]]      # (index in the trail, binary CID, record)
Item = Tuple[str, bytes, bytes]                 # (tool, args_sha256, escalation CID; b"" for a document)


def first_parent(rec: Any) -> Optional[bytes]:
    """The CID of a record's first parent, or None if it has none or they are malformed."""
    try:
        p = rec["parents"][0]
        return bytes(p) if isinstance(p, bytes) else None
    except (KeyError, IndexError, TypeError):
        return None


def evidence_children(records: List[Record]) -> Dict[bytes, List[Dict[str, Any]]]:
    """The `x-approval-evidence` records of a trail, by the record each is a child of."""
    out: Dict[bytes, List[Dict[str, Any]]] = {}
    for _, _, rec in records:
        parent = first_parent(rec) if isinstance(rec, dict) and \
            rec.get("kind") == KIND_EVIDENCE else None
        if parent is not None:
            out.setdefault(parent, []).append(rec)
    return out


# ---- evidence -------------------------------------------------------------------------------


def _bytes(body: Dict[str, Any], name: str, size: Optional[int] = None) -> bytes:
    v = body.get(name)
    if not isinstance(v, bytes) or (size is not None and len(v) != size) or not v:
        raise WebAuthnError(f"the evidence's {name} is missing or malformed")
    return v


def _text(body: Dict[str, Any], name: str) -> str:
    v = body.get(name)
    if not isinstance(v, str) or not v:
        raise WebAuthnError(f"the evidence's {name} is missing or malformed")
    return v


@dataclass(frozen=True)
class Evidence:
    """A WebAuthn assertion and what it claims to be for (record kind `x-approval-evidence`)."""

    credential_id: bytes
    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes
    nonce: bytes
    rp_id: str
    origin: str
    request_digest: bytes
    batch: Optional[Tuple[Item, ...]] = None

    @property
    def assertion_sha256(self) -> bytes:
        return assertion_sha256(self.authenticator_data, self.client_data_json, self.signature)

    def summary(self) -> Dict[str, Any]:
        """What the approval record itself holds."""
        return {"kind": EVIDENCE_KIND, "assertion_sha256": self.assertion_sha256}

    def body(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "kind": EVIDENCE_KIND, "credential_id": self.credential_id,
            "authenticator_data": self.authenticator_data,
            "client_data_json": self.client_data_json, "signature": self.signature,
            "nonce": self.nonce, "rp_id": self.rp_id, "origin": self.origin,
            "request_digest": self.request_digest, "assertion_sha256": self.assertion_sha256}
        if self.batch is not None:
            out["batch"] = {"context": BATCH_CONTEXT_NAME, "items": [
                {"tool": t, "args_sha256": a, **({"escalation": e} if e else {})}
                for t, a, e in self.batch]}
        return out

    @classmethod
    def parse(cls, body: Any) -> "Evidence":
        """The evidence in a record body; WebAuthnError says what is malformed."""
        if not isinstance(body, dict) or body.get("kind") != EVIDENCE_KIND:
            raise WebAuthnError("the evidence is not a passkey assertion")
        batch = None
        if body.get("batch") is not None:
            raw = body["batch"]
            items = raw.get("items") if isinstance(raw, dict) else None
            if (not isinstance(raw, dict) or raw.get("context") != BATCH_CONTEXT_NAME
                    or not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH):
                raise WebAuthnError("the evidence's batch is malformed")
            parsed = []
            for it in items:
                esc = it.get("escalation", b"") if isinstance(it, dict) else None
                if (not isinstance(it, dict) or not isinstance(it.get("tool"), str)
                        or not isinstance(it.get("args_sha256"), bytes)
                        or len(it["args_sha256"]) != 32 or not isinstance(esc, bytes)):
                    raise WebAuthnError("a batch item is malformed")
                parsed.append((it["tool"], it["args_sha256"], esc))
            batch = tuple(parsed)
        ev = cls(_bytes(body, "credential_id"), _bytes(body, "authenticator_data"),
                 _bytes(body, "client_data_json"), _bytes(body, "signature"),
                 _bytes(body, "nonce"), _text(body, "rp_id"), _text(body, "origin"),
                 _bytes(body, "request_digest", 32), batch)
        if _bytes(body, "assertion_sha256", 32) != ev.assertion_sha256:
            raise WebAuthnError("the assertion does not match its digest")
        return ev

    def to_json(self) -> Dict[str, Any]:
        """Export form: byte values as unpadded base64url."""
        def enc(v: Any) -> Any:
            if isinstance(v, bytes):
                return b64url(v)
            if isinstance(v, list):
                return [enc(x) for x in v]
            if isinstance(v, dict):
                return {k: enc(x) for k, x in v.items()}
            return v
        return enc(self.body())

    @classmethod
    def from_json(cls, d: Any) -> "Evidence":
        def dec(k: str, v: Any) -> Any:
            if k in ("credential_id", "authenticator_data", "client_data_json", "signature",
                     "nonce", "request_digest", "assertion_sha256", "args_sha256", "escalation"):
                return unb64url(v)
            if isinstance(v, list):
                return [{kk: dec(kk, vv) for kk, vv in x.items()} for x in v]
            if isinstance(v, dict):
                return {kk: dec(kk, vv) for kk, vv in v.items()}
            return v
        if not isinstance(d, dict):
            raise WebAuthnError("the evidence is not an object")
        return cls.parse({k: dec(k, v) for k, v in d.items()})


@dataclass(frozen=True)
class SignIn:
    """What identified a person: a sign-in, as a kind, a reference and the SHA-256 of the
    evidence. It is the evidence of a rejection, a root passkey and a rebinding. This audit
    cannot check it; it reports it."""

    kind: str
    ref: str
    sha256: bytes

    def summary(self) -> Dict[str, Any]:
        return {"kind": self.kind, "ref": self.ref, "sha256": self.sha256}

    @classmethod
    def parse(cls, v: Any) -> "SignIn":
        if not (isinstance(v, dict) and isinstance(v.get("kind"), str) and v["kind"]
                and v["kind"] != EVIDENCE_KIND and isinstance(v.get("ref"), str)
                and isinstance(v.get("sha256"), bytes) and len(v["sha256"]) == 32):
            raise WebAuthnError("identity evidence needs a kind, a ref and a 32-byte sha256")
        return cls(v["kind"], v["ref"], v["sha256"])

    def to_json(self) -> Dict[str, Any]:
        return {"kind": self.kind, "ref": self.ref, "sha256": b64url(self.sha256)}

    @classmethod
    def from_json(cls, d: Any) -> "SignIn":
        if not isinstance(d, dict):
            raise WebAuthnError("the identity evidence is not an object")
        return cls.parse({**d, "sha256": unb64url(d.get("sha256"))})   # type: ignore[arg-type]

    def describe(self) -> str:
        return f"{self.kind} {self.ref} (sha256 {self.sha256.hex()[:16]}…)"


def enrol_args_sha256(approver: str, identity: str, credential_id: bytes, public_key: bytes,
                      rp_id: str, origin: str) -> bytes:
    """The request a registered passkey signs to let a new one join."""
    return json_digest({"approver": approver, "identity": identity,
                        "credential_id": b64url(credential_id), "public_key": b64url(public_key),
                        "rp_id": rp_id, "origin": origin})


def revoke_args_sha256(approver: str, credential_id: bytes) -> bytes:
    return json_digest({"approver": approver, "credential_id": b64url(credential_id)})


def rebind_args_sha256(approver: str, identity: str, evidence: SignIn) -> bytes:
    return json_digest({"approver": approver, "identity": identity,
                        "identity_evidence": evidence.to_json()})


# ---- the registry ---------------------------------------------------------------------------


@dataclass
class Credential:
    approver: str
    credential_id: bytes
    public_key: bytes                  # COSE_Key, as enrolled
    key: Tuple[int, Any]
    rp_id: str
    origin: str
    identity: str
    epoch: int                         # the approver's epoch it was enrolled in
    enrolled_at: int                   # trail position of the enrolment
    root: bool
    pinned: bool                       # its epoch's root passkey is pinned in the principals
    basis: str                         # the identity evidence its epoch rests on
    revoked_at: Optional[int] = None
    sign_count: int = 0                # the highest counter seen


@dataclass
class Principal:
    """A passkey approver in the trusted principals file."""

    pins: List[Dict[str, Any]] = field(default_factory=list)   # trusted root credentials
    witness_key: Optional[bytes] = None                        # optional gateway witness key


def load_principals(doc: Any) -> Tuple[Dict[str, bytes], Dict[str, Principal]]:
    """Split a principals file into Ed25519 keys and passkey approvers."""
    if not isinstance(doc, dict):
        raise ValueError("the principals file is not an object")
    ed, pk = {}, {}
    for who, v in doc.items():
        if isinstance(v, str):
            ed[who] = bytes.fromhex(v)
        elif isinstance(v, dict) and v.get("type") == "webauthn":
            creds = v.get("credentials", [])
            wk = v.get("witness_key")
            if not isinstance(creds, list) or not all(isinstance(c, dict) for c in creds):
                raise ValueError(f"{who}: credentials must be a list of objects")
            pk[who] = Principal(list(creds), bytes.fromhex(wk) if isinstance(wk, str) else None)
        else:
            raise ValueError(f"{who}: not a key or a webauthn entry")
    return ed, pk


class Directory:
    """Passkey approvers and their credentials, rebuilt from the trail in order."""

    def __init__(self, principals: Dict[str, Principal]) -> None:
        self.principals = principals
        self.creds: Dict[bytes, Credential] = {}
        self.identity: Dict[str, List[Tuple[int, str]]] = {}      # approver -> (position, identity)
        self.epochs: Dict[str, List[int]] = {}                    # approver -> positions that began one
        self.basis: Dict[str, Tuple[bool, str]] = {}              # approver -> (pinned, evidence) now
        self.problems: List[str] = []
        self.notes: List[Tuple[str, str]] = []      # (kind, text): binding, clone or reject
        self.ledger = UseLedger()
        self.children: Dict[bytes, List[Evidence]] = {}
        # (assertion, was a batch, pinned, approver, basis) for each approval verified
        self.verified: List[Tuple[bytes, bool, bool, str, str]] = []
        self.witness_checked = 0           # verified approvals whose gateway signature verified
        self.witness_unchecked = 0         # ... that carry one and no witness key was given
        self.rejections = 0

    # -- queries --

    def identity_at(self, approver: str, position: int) -> Optional[str]:
        current = None
        for at, who in self.identity.get(approver, []):
            if at < position:
                current = who
        return current

    def epoch_at(self, approver: str, position: int) -> int:
        return sum(1 for at in self.epochs.get(approver, []) if at < position)

    def has_valid(self, approver: str, position: int) -> bool:
        return any(self.refusal(c, approver, position) is None for c in self.creds.values()
                   if c.approver == approver)

    def refusal(self, c: Credential, approver: str, position: int) -> Optional[str]:
        """Why `c` may not act for `approver` at a trail position, or None if it may."""
        if c.approver != approver:
            return f"the passkey is not {approver}'s"
        if c.enrolled_at >= position:
            return "the passkey was not yet enrolled at this record"
        if c.revoked_at is not None and c.revoked_at < position:
            return "the passkey had been revoked at this record"
        if c.epoch != self.epoch_at(approver, position) or \
                c.identity != self.identity_at(approver, position):
            return ("the passkey was enrolled for a different identity from the approver's "
                    "current one at this record")
        return None

    # -- the checks --

    def check(self, *, approver: str, position: int, key: str, tool: str, args_sha256: bytes,
              escalation: Optional[bytes], ev: Evidence, label: str) -> List[str]:
        """Check one assertion for one request, as the person at `approver` at `position`.
        `escalation` is the escalation an approval answers, or None for a confirmation of a
        registry change, which must be a single request. `key` names what the assertion
        answers, so a retry of the same answer is not a replay."""
        c = self.creds.get(ev.credential_id)
        if c is None:
            return ["the passkey is not in the registry"]
        why = self.refusal(c, approver, position)
        if why:
            return [why]
        if (ev.rp_id, ev.origin) != (c.rp_id, c.origin):
            return [f"the evidence names {ev.rp_id} at {ev.origin}, but the passkey was "
                    f"enrolled for {c.rp_id} at {c.origin}"]
        item = (tool, args_sha256, escalation or b"")
        try:
            if escalation is None:
                if ev.batch is not None:
                    return ["a confirmation of a registry change must be a single request, "
                            "not a batch"]
                expected = request_digest(tool, args_sha256)
            elif tool.startswith(RESERVED):
                return [f"the tool {tool} is reserved: no approval may be for it"]
            elif ev.batch is None:
                expected = request_digest(tool, args_sha256, escalation)
            else:
                if item not in ev.batch:
                    return [f"the {label} is not one of the items the passkey signed"]
                if len(set(ev.batch)) != len(ev.batch):
                    return ["the batch repeats an item"]
                reserved = [t for i, (t, _, _) in enumerate(ev.batch)
                            if t.startswith(RESERVED) and not (i == 0 and t == DOCUMENT_TOOL)]
                if reserved:
                    return [f"the batch holds the reserved tool {reserved[0]}"]
                expected = batch_digest(ev.batch)
        except WebAuthnError as e:
            return [str(e)]
        if ev.request_digest != expected:
            return ["the passkey signed a different request from the one " + label]
        try:
            got = verify_assertion(c.key, ev.authenticator_data, ev.client_data_json,
                                   ev.signature, rp_id=c.rp_id, origin=c.origin,
                                   challenge=challenge_for(ev.nonce, expected))
        except WebAuthnError as e:
            return [f"the passkey's assertion does not stand: {e}"]
        used = self.ledger.use(position, ev, key, item)
        if used:
            return [used]
        if (got.sign_count or c.sign_count) and got.sign_count <= c.sign_count:
            self.notes.append(("clone", f"record {position}: the passkey's signature counter did "
                               f"not rise ({c.sign_count}, then {got.sign_count}): it may have "
                               "been cloned"))
        c.sign_count = max(c.sign_count, got.sign_count)
        return []

    # -- building: one pass over the trail, in order --

    def begin(self, records: List[Record]) -> None:
        """Index the evidence children of a trail before stepping through it."""
        for parent, recs in evidence_children(records).items():
            for rec in recs:
                try:
                    self.children.setdefault(parent, []).append(Evidence.parse(rec["body"]))
                except WebAuthnError:
                    pass                       # reported where the parent looks for it

    def step(self, index: int, cid: bytes, rec: Dict[str, Any]) -> None:
        """Apply a registry record at its position, collecting a problem if it is refused."""
        try:
            self.apply(index, cid, rec, self.children.get(cid, []))
        except (WebAuthnError, KeyError, TypeError, ValueError, AttributeError) as e:
            self.problems.append(f"record {index}: {e}")

    @classmethod
    def build(cls, records: List[Record], principals: Dict[str, Principal]) -> "Directory":
        """The registry alone, from a trail's registry records (the approvals are not checked)."""
        d = cls(principals)
        d.begin(records)
        for index, cid, rec in records:
            if isinstance(rec, dict) and rec.get("kind") in REGISTRY_KINDS:
                d.step(index, cid, rec)
        return d

    def _declared(self, who: Any) -> str:
        if not isinstance(who, str) or who not in self.principals:
            raise WebAuthnError(f"{who!r} is not a passkey approver in the principals you trust")
        return who

    def _confirm(self, index: int, cid: bytes, who: str, tool: str, args: bytes,
                 found: List[Evidence], summary: Any) -> None:
        """The change at `index` is asserted by a registered passkey, as a single request."""
        if not isinstance(summary, dict) or summary.get("kind") != EVIDENCE_KIND:
            raise WebAuthnError("no confirmation by a registered passkey")
        mine = [e for e in found if e.assertion_sha256 == summary.get("assertion_sha256")]
        if not mine:
            raise WebAuthnError("the confirming assertion is not in the trail")
        errs = self.check(approver=who, position=index, key=cid_str(cid), tool=tool,
                          args_sha256=args, escalation=None, ev=mine[0],
                          label="change confirmed")
        if errs:
            raise WebAuthnError("the change is not confirmed by a registered passkey: "
                                + errs[0])

    def apply(self, index: int, cid: bytes, rec: Dict[str, Any], found: List[Evidence]) -> None:
        """Apply one registry record at `index`; raises WebAuthnError if it is refused.
        `found` are the confirming assertions that follow it."""
        b = rec["body"]
        kind = rec["kind"]
        who = self._declared(b.get("approver"))
        identity = b.get("identity")
        if kind != KIND_REVOKED and (not isinstance(identity, str) or not identity):
            raise WebAuthnError("the record names no identity")
        if kind == KIND_REBOUND:
            sign_in = SignIn.parse(b.get("identity_evidence"))
            if self.has_valid(who, index):          # a passkey stands: it must say yes
                self._confirm(index, cid, who, REBIND_TOOL,
                              rebind_args_sha256(who, identity, sign_in), found,
                              b.get("evidence"))
            self._begin_epoch(index, who, identity, sign_in, pinned=False)
            self.notes.append(("binding", f"record {index}: {who} is bound to {identity} on "
                               f"{sign_in.describe()}, which this audit cannot check"))
            return
        cred_id = b.get("credential_id")
        if not isinstance(cred_id, bytes) or not cred_id:
            raise WebAuthnError("the record names no credential")
        if kind == KIND_REVOKED:
            target = self.creds.get(cred_id)
            if target is None or target.approver != who:
                raise WebAuthnError("the revoked passkey is not one of this approver's")
            if target.revoked_at is not None:
                raise WebAuthnError("the passkey was already revoked")
            self._confirm(index, cid, who, REVOKE_TOOL, revoke_args_sha256(who, cred_id),
                          found, b.get("evidence"))
            target.revoked_at = index
            return
        public_key, rp_id, origin = b.get("public_key"), b.get("rp_id"), b.get("origin")
        if cred_id in self.creds:
            raise WebAuthnError("the passkey is already in the registry")
        if not isinstance(public_key, bytes):
            raise WebAuthnError("the record names no public key")
        key = parse_cose_key(public_key)
        check_origin(rp_id, origin)
        root = not self.has_valid(who, index)
        if root:
            sign_in = SignIn.parse(b.get("identity_evidence"))
            reg = b.get("registration")
            if not isinstance(reg, dict):
                raise WebAuthnError("a first passkey needs its registration response")
            verify_registration(reg.get("client_data_json"), reg.get("attestation_object"),
                                rp_id=rp_id, origin=origin,
                                challenge=enrol_challenge(who, sign_in.sha256),
                                credential_id=cred_id, public_key=public_key)
            pinned = self._pinned(who, cred_id, public_key, rp_id, origin, identity)
            self._begin_epoch(index, who, identity, sign_in, pinned)
            self.notes.append(("binding", f"record {index}: the first passkey of {who} rests on "
                               f"{sign_in.describe()}, which this audit cannot check"
                               + (" (pinned in your principals)" if pinned else
                                  " (not pinned in your principals)")))
        else:
            if identity != self.identity_at(who, index):
                raise WebAuthnError("the new passkey is enrolled for an identity other than "
                                    "the approver's current one")
            self._confirm(index, cid, who, ENROL_TOOL,
                          enrol_args_sha256(who, identity, cred_id, public_key, rp_id, origin),
                          found, b.get("evidence"))
        pinned, basis = self.basis[who]
        self.creds[cred_id] = Credential(who, cred_id, public_key, key, rp_id, origin, identity,
                                         self.epoch_at(who, index + 1), index, root, pinned,
                                         basis)

    def _begin_epoch(self, index: int, who: str, identity: str, sign_in: SignIn,
                     pinned: bool) -> None:
        """A root passkey or a rebinding starts a new epoch: no earlier passkey is valid in it."""
        self.epochs.setdefault(who, []).append(index)
        self.identity.setdefault(who, []).append((index, identity))
        self.basis[who] = (pinned, sign_in.describe())

    def _pinned(self, who: str, cred_id: bytes, public_key: bytes, rp_id: str, origin: str,
                identity: str) -> bool:
        """Whether the principals pin this root passkey; refused if they pin others only."""
        pins = self.principals[who].pins
        if not pins:
            return False
        for p in pins:
            if p.get("credential_id") == b64url(cred_id):
                if (p.get("public_key") != b64url(public_key) or p.get("rp_id") != rp_id
                        or p.get("origin") != origin or p.get("identity") != identity):
                    raise WebAuthnError("the first passkey differs from the one you pinned")
                return True
        raise WebAuthnError("the first passkey is not one you pinned for this approver")


class UseLedger:
    """Each nonce and each assertion is used once, except an assertion shared by the approvals
    of its own batch, and a retried answer to the same escalation. Filled in trail order."""

    def __init__(self) -> None:
        self.assertions: Dict[bytes, List[Tuple[int, str, Item]]] = {}
        self.nonces: Dict[bytes, Tuple[bytes, int]] = {}

    def use(self, position: int, ev: Evidence, key: str, item: Item) -> Optional[str]:
        a = ev.assertion_sha256
        prior = self.assertions.get(a)
        if prior:
            if any(k == key for _, k, _ in prior):
                return None
            if ev.batch is not None and all(i != item for _, _, i in prior):
                self.assertions[a].append((position, key, item))
                return None
            return f"the assertion was already used at record {prior[0][0]}"
        seen = self.nonces.get(ev.nonce)
        if seen is not None:
            return f"the nonce was already used by the assertion at record {seen[1]}"
        self.nonces[ev.nonce] = (a, position)
        self.assertions[a] = [(position, key, item)]
        return None


# ---- approvals --------------------------------------------------------------------------------


def arguments_of(escalation: Dict[str, Any], args_sha256: bytes) -> Optional[Dict[str, Any]]:
    """The call's arguments as the escalating decision recorded them, if they are there and
    are the ones the approval names."""
    try:
        args = json.loads(escalation["body"]["input_json"])["arguments"]
        return args if isinstance(args, dict) and json_digest(args) == args_sha256 else None
    except (KeyError, TypeError, ValueError):
        return None


def document_problem(ev: Evidence, arguments: Optional[Dict[str, Any]]) -> Optional[str]:
    """A batch that signs a document must sign the one the call acted on: the call's
    `document_sha256` argument (hex) is the batch's leading document item."""
    if ev.batch and ev.batch[0][0] == DOCUMENT_TOOL and (
            arguments is None or arguments.get("document_sha256") != ev.batch[0][1].hex()):
        return "the batch signs a document other than the one this decision acted on"
    return None


def escalation_cid(text: Any) -> bytes:
    """The binary CID an approval's `escalation` text names."""
    if not isinstance(text, str):
        raise WebAuthnError("the approval names no escalation")
    try:
        raw = cid_parse(text)
    except ValueError:
        raise WebAuthnError("the approval's escalation is not a CID") from None
    if len(raw) != CID_LEN:
        raise WebAuthnError("the approval's escalation is not a 36-byte CID")
    return raw


def check_approval(d: Directory, index: int, cid: bytes, rec: Dict[str, Any],
                   escalation: Dict[str, Any], evidence_children: List[Dict[str, Any]]
                   ) -> List[str]:
    """Problems with a passkey approver's approval. An approval only ever authorises: a
    rejection verifies nothing, rests on the sign-in that identified the person, and is
    reported; one that carries an assertion is refused as contradictory."""
    b = rec["body"]
    decision, summary = b.get("decision"), b.get("evidence")
    if decision == "reject":
        if (isinstance(summary, dict) and summary.get("kind") == EVIDENCE_KIND) or \
                evidence_children:
            return ["a rejection carries a passkey assertion, which can only approve"]
        try:
            sign_in = SignIn.parse(summary)
        except WebAuthnError:
            return ["a rejection by a passkey approver carries no identity evidence (the "
                    "sign-in it rests on)"]
        d.rejections += 1
        d.notes.append(("reject", f"record {index}: a rejection by {b.get('approver')} on "
                        f"{sign_in.describe()}, which this audit cannot check; it authorises "
                        "nothing"))
        return []
    if decision != "approve":
        return [f"the decision {decision!r} is neither approve nor reject"]
    if not isinstance(summary, dict) or summary.get("kind") != EVIDENCE_KIND or \
            not isinstance(summary.get("assertion_sha256"), bytes):
        return ["a passkey approver's approval carries no passkey assertion (a gateway "
                "signature alone is not proof)"]
    mine = [c for c in evidence_children
            if c.get("body", {}).get("assertion_sha256") == summary["assertion_sha256"]]
    if not mine:
        return ["the approval's passkey assertion is not in the trail"]
    try:
        ev = Evidence.parse(mine[0]["body"])
        esc = escalation_cid(b["escalation"])
    except WebAuthnError as e:
        return [str(e)]
    errs = d.check(approver=b["approver"], position=index, key=b["escalation"],
                   tool=b["tool"], args_sha256=b["args_sha256"], escalation=esc, ev=ev,
                   label="approved")
    if errs:
        return errs
    why = document_problem(ev, arguments_of(escalation, b["args_sha256"]))
    if why:
        return [why]
    c = d.creds[ev.credential_id]
    d.verified.append((ev.assertion_sha256, ev.batch is not None, c.pinned, b["approver"],
                       c.basis))
    return []
