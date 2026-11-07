"""A deterministic software authenticator and a hand-built trail for the passkey tests and the
test vectors. Keys come from seeds, so every byte regenerates; none is a real key.

The authenticator does what a phone or security key does: it holds a credential key and signs
`authenticatorData || SHA-256(clientDataJSON)` over a challenge. It can be told to do it
wrongly (other origin or relying party, no user verification, other client data type), so each
refusal is tested against a well-formed answer.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import delegation, passkeys, webauthn
from aeos.canon import cid_of_bytes, cid_str, dag_cbor, json_digest
from aeos.log import make_record

RP_ID = "approve.acme.example"
ORIGIN = "https://approve.acme.example"
T0 = 1_760_000_000_000
APPROVER = "spiffe://acme.example/human/cfo/a-jones"
CONTROLLER = "spiffe://acme.example/human/controller/j-smith"
AGENT = "spiffe://acme.example/agent/accounts-payable/7f3a"
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _int(n: int) -> bytes:
    """A CBOR integer in shortest form."""
    major, v = (0, n) if n >= 0 else (1, -1 - n)
    if v < 24:
        return bytes([(major << 5) | v])
    if v < 256:
        return bytes([(major << 5) | 24, v])
    return bytes([(major << 5) | 25]) + v.to_bytes(2, "big")


def cose_es256(x: bytes, y: bytes, *, crv: int = 1, kty: int = 2, alg: int = -7) -> bytes:
    """A canonical COSE_Key for an ES256 key (the field values can be bent for tests)."""
    return (b"\xa5" + b"\x01" + _int(kty) + b"\x03" + _int(alg) + b"\x20" + _int(crv)
            + b"\x21\x58\x20" + x + b"\x22\x58\x20" + y)


def cose_eddsa(x: bytes, *, crv: int = 6) -> bytes:
    return b"\xa4\x01\x01\x03\x27\x20" + _int(crv) + b"\x21\x58\x20" + x


class SoftAuthenticator:
    def __init__(self, seed: str, *, alg: int = webauthn.COSE_ES256, rp_id: str = RP_ID,
                 origin: str = ORIGIN) -> None:
        raw = hashlib.sha256(b"aeos passkey test vectors; never a real key: " + seed.encode()
                             ).digest()
        self.alg, self.rp_id, self.origin = alg, rp_id, origin
        self.credential_id = hashlib.sha256(b"credential id " + raw).digest()
        self.counter = 0
        if alg == webauthn.COSE_ES256:
            self.key: Any = ec.derive_private_key(int.from_bytes(raw, "big") % (_N - 1) + 1,
                                                  ec.SECP256R1())
        else:
            self.key = Ed25519PrivateKey.from_private_bytes(raw)

    @property
    def cose_key(self) -> bytes:
        if self.alg == webauthn.COSE_ES256:
            n = self.key.public_key().public_numbers()
            return cose_es256(n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big"))
        return cose_eddsa(self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                              serialization.PublicFormat.Raw))

    def assertion(self, challenge: bytes, *, rp_id: Optional[str] = None,
                  origin: Optional[str] = None, up: bool = True, uv: bool = True,
                  flags: int = 0, client_type: str = "webauthn.get",
                  extra_client: Optional[Dict[str, Any]] = None
                  ) -> Tuple[bytes, bytes, bytes]:
        """(authenticatorData, clientDataJSON, signature) for a challenge. A synced passkey
        reports a counter of 0, as `counter=0` here; it never moves."""
        client = {"type": client_type, "challenge": webauthn.b64url(challenge),
                  "origin": origin or self.origin, "crossOrigin": False, **(extra_client or {})}
        cdj = json.dumps(client, separators=(",", ":")).encode()
        ad = (hashlib.sha256((rp_id or self.rp_id).encode()).digest()
              + bytes([(0x01 if up else 0) | (0x04 if uv else 0) | flags])
              + struct.pack(">I", self.counter))
        signed = ad + hashlib.sha256(cdj).digest()
        if self.alg == webauthn.COSE_ES256:
            sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        else:
            sig = self.key.sign(signed)
        return ad, cdj, sig

    def evidence(self, nonce: bytes, tool: str, args_sha256: bytes, *,
                 batch: Optional[Sequence[Tuple[str, bytes]]] = None, **wrong: Any
                 ) -> passkeys.Evidence:
        """The evidence for one request, or for a batch the request is one item of."""
        digest = (webauthn.batch_digest(batch) if batch is not None
                  else webauthn.request_digest(tool, args_sha256))
        ad, cdj, sig = self.assertion(webauthn.challenge_for(nonce, digest), **wrong)
        return passkeys.Evidence(self.credential_id, ad, cdj, sig, nonce, self.rp_id,
                                 self.origin, digest, tuple(batch) if batch is not None else None)


def nonce(n: int) -> bytes:
    return hashlib.sha256(b"test nonce %d" % n).digest()


class Trail:
    """Records appended in order with their CIDs, as an auditor would read a trail."""

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []
        self.cids: List[bytes] = []
        self._ts = T0

    def add(self, kind: str, agent: str, *, subject: Optional[str] = None,
            body: Optional[Dict[str, Any]] = None, parents: Sequence[bytes] = ()) -> bytes:
        self._ts += 1000
        rec = make_record(kind, agent, subject=subject, body=body, parents=parents, ts=self._ts)
        self.records.append(rec)
        self.cids.append(cid_of_bytes(dag_cbor(rec)))
        return self.cids[-1]

    def triples(self) -> List[Tuple[int, bytes, Dict[str, Any]]]:
        """(position, CID, record), the CIDs recomputed from the records as they now stand."""
        return [(i, cid_of_bytes(dag_cbor(r)), r) for i, r in enumerate(self.records)]

    # -- the registry --

    def evidence_child(self, parent: bytes, who: str, ev: passkeys.Evidence,
                       subject: Optional[str] = None) -> bytes:
        return self.add("x-approval-evidence", who, subject=subject, body=ev.body(),
                        parents=[parent])

    def enrol(self, auth: SoftAuthenticator, *, who: str = APPROVER, identity: str = "a@acme.example",
              confirmed_by: Optional[SoftAuthenticator] = None, n: int = 0,
              identity_evidence: Optional[Dict[str, Any]] = None, **over: Any) -> bytes:
        body: Dict[str, Any] = {"approver": who, "identity": identity,
                                "credential_id": auth.credential_id, "public_key": auth.cose_key,
                                "rp_id": auth.rp_id, "origin": auth.origin, **over}
        ev = None
        if confirmed_by is None:
            body["identity_evidence"] = identity_evidence or {
                "kind": "oidc-sign-in", "ref": "https://login.acme.example/session/1",
                "sha256": hashlib.sha256(b"sign-in " + identity.encode()).digest()}
        else:
            args = passkeys.enrol_args_sha256(who, identity, auth.credential_id, auth.cose_key,
                                              auth.rp_id, auth.origin)
            ev = confirmed_by.evidence(nonce(n), passkeys.ENROL_TOOL, args)
            body["evidence"] = ev.summary()
        cid = self.add(passkeys.KIND_ENROLLED, who, body=body)
        if ev is not None:
            self.evidence_child(cid, who, ev)
        return cid

    def revoke(self, target: SoftAuthenticator, by: SoftAuthenticator, *, who: str = APPROVER,
               n: int = 0) -> bytes:
        ev = by.evidence(nonce(n), passkeys.REVOKE_TOOL,
                         passkeys.revoke_args_sha256(who, target.credential_id))
        cid = self.add(passkeys.KIND_REVOKED, who,
                       body={"approver": who, "credential_id": target.credential_id,
                             "evidence": ev.summary()})
        self.evidence_child(cid, who, ev)
        return cid

    def rebind(self, identity: str, *, who: str = APPROVER) -> bytes:
        return self.add(passkeys.KIND_REBOUND, who, body={
            "approver": who, "identity": identity, "identity_evidence": {
                "kind": "oidc-sign-in", "ref": "https://login.acme.example/session/2",
                "sha256": hashlib.sha256(b"sign-in " + identity.encode()).digest()}})

    # -- a call that is escalated, and the approval of it --

    def escalated_call(self, args: Dict[str, Any], tool: str = "erp.invoice.pay"
                       ) -> Tuple[bytes, bytes, bytes]:
        """(session, call, escalation) for a call with these arguments."""
        s = self.add("session.start", AGENT, body={"session_id": "s%d" % len(self.cids)})
        c = self.add("tool.call", AGENT, subject=tool, body={
            "args_sha256": json_digest(args), "call_id": "c%d" % len(self.cids)}, parents=[s])
        e = self.add("policy.decision", AGENT, subject=tool, body={
            "decision": "escalate", "policy": "aeos-policy/v0", "reasons": ["above-limit"],
            "input_json": json.dumps({"tool": tool, "arguments": args},
                                     separators=(",", ":"), sort_keys=True)}, parents=[c])
        return s, c, e

    def approve(self, call: bytes, esc: bytes, tool: str, args: Dict[str, Any],
                ev: Optional[passkeys.Evidence], *, who: str = APPROVER,
                decision: str = "approve", signature: Optional[bytes] = None,
                child: bool = True, summary: Optional[Dict[str, Any]] = None,
                witness: Optional[Ed25519PrivateKey] = None) -> bytes:
        body: Dict[str, Any] = {"escalation": cid_str(esc), "approver": who,
                                "decision": decision, "tool": tool,
                                "args_sha256": json_digest(args), "time": self._ts + 1}
        if witness is not None:
            signature = delegation.Approval(
                body["escalation"], who, decision, tool, body["args_sha256"],
                body["time"]).sign(witness).signature
        if signature is not None:
            body["signature"] = signature
        if ev is not None:
            body["evidence"] = summary or ev.summary()
        cid = self.add("approval", who, subject=tool, body=body, parents=[esc, call])
        if ev is not None and child:
            self.evidence_child(cid, who, ev, tool)
        return cid


def principals(*, pins: Sequence[Dict[str, Any]] = (), witness_key: Optional[bytes] = None,
               who: str = APPROVER) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"type": "webauthn", "credentials": list(pins)}
    if witness_key is not None:
        entry["witness_key"] = witness_key.hex()
    return {who: entry}


def pin(auth: SoftAuthenticator, identity: str = "a@acme.example") -> Dict[str, Any]:
    return {"credential_id": webauthn.b64url(auth.credential_id),
            "public_key": webauthn.b64url(auth.cose_key), "rp_id": auth.rp_id,
            "origin": auth.origin, "identity": identity}


WITNESS = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"aeos passkey test vectors; never a real key: gateway witness").digest())
WITNESS_PUBLIC = WITNESS.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw)
