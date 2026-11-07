"""The passkey approval scenarios: small trails and the verdict a verifier must reach.

`testvectors/generate.py` writes each one to testvectors/passkey-approvals-v1.json with the
verdict this implementation gives, after checking it against `expect` here; the tests run them
again. `expect` lists a fragment of each problem a verifier must report, in order; an empty list
means the trail verifies.
"""
from __future__ import annotations

import copy
import dataclasses
from typing import Any, Callable, Dict, List, Sequence, Tuple

from aeos import passkeys, webauthn
from aeos.canon import json_digest
from aeos.webauthn import DOCUMENT_TOOL
from webauthn_support import (APPROVER, WITNESS, WITNESS_PUBLIC, ORIGIN, RP_ID, SoftAuthenticator, Trail, cose_eddsa,
                              cose_es256, nonce, pin, principals)

TOOL = "erp.invoice.pay"
OTHER = "spiffe://acme.example/human/cfo/b-ngubane"
ARGS = {"invoice": "I2", "amount_minor": 900}
A, B, C = (SoftAuthenticator(s) for s in ("cfo-laptop", "cfo-phone", "cfo-key"))
E = SoftAuthenticator("cfo-ed25519", alg=webauthn.COSE_EDDSA)

Scenario = Tuple[str, Trail, Dict[str, Any], List[str]]


def _flip(b: bytes, i: int = 0) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def _redigest(ev: passkeys.Evidence, **change: Any) -> passkeys.Evidence:
    """Evidence with fields changed; its digest follows the bytes, as a forger would make it."""
    return dataclasses.replace(ev, **change)


def _single(auth: SoftAuthenticator = A, n: int = 1, *, ev_fn: Callable = None,
            approve: Dict[str, Any] = None, enrol: bool = True) -> Tuple[Trail, bytes, bytes]:
    t = Trail()
    if enrol:
        t.enrol(auth)
    _, c, e = t.escalated_call(ARGS)
    ev = auth.evidence(nonce(n), TOOL, json_digest(ARGS))
    if ev_fn:
        ev = ev_fn(ev)
    t.approve(c, e, TOOL, ARGS, ev, **(approve or {}))
    return t, c, e


def _batch_items(n: int = 4) -> List[Tuple[str, Dict[str, Any]]]:
    return [(TOOL, {"invoice": f"I{i}", "amount_minor": 100 * i}) for i in range(1, n + 1)]


def _batch(tamper: Callable[[int, passkeys.Evidence], passkeys.Evidence] = None,
           items: Sequence[Tuple[str, Dict[str, Any]]] = None, doc: bytes = None,
           call_doc: bytes = None) -> Trail:
    """Four approvals sharing one assertion over four items (and a document, if given)."""
    items = list(items or _batch_items())
    t = Trail()
    t.enrol(A)
    signed = [(tool, json_digest(a)) for tool, a in items]
    if doc is not None:
        signed.insert(0, (DOCUMENT_TOOL, doc))
    ev = A.evidence(nonce(1), "", b"", batch=signed)
    for i, (tool, a) in enumerate(items):
        a = dict(a, **({"document_sha256": (call_doc or doc).hex()} if doc is not None else {}))
        _, c, e = t.escalated_call(a, tool)
        t.approve(c, e, tool, a, tamper(i, ev) if tamper else ev)
    return t


def _batch_with_documents(doc: bytes, call_doc: bytes) -> Trail:
    items = _batch_items(2)
    calls = [dict(a, document_sha256=call_doc.hex()) for _, a in items]
    t = Trail()
    t.enrol(A)
    signed = [(DOCUMENT_TOOL, doc)] + [(TOOL, json_digest(a)) for a in calls]
    ev = A.evidence(nonce(1), "", b"", batch=signed)
    for a in calls:
        _, c, e = t.escalated_call(a)
        t.approve(c, e, TOOL, a, ev)
    return t


def scenarios() -> List[Scenario]:
    out: List[Scenario] = []
    p = principals()

    def add(name: str, trail: Trail, expect: Sequence[str], pr: Dict[str, Any] = None) -> None:
        out.append((name, trail, pr if pr is not None else p, list(expect)))

    # 1. a valid approval
    add("valid single approval (ES256)", _single()[0], [])
    add("valid single approval (EdDSA)", _single(E)[0], [])
    add("valid approval, first passkey pinned in the principals", _single()[0], [],
        principals(pins=[pin(A)]))
    add("valid approval that also carries a gateway witness signature",
        _single(approve={"witness": WITNESS})[0], [], principals(witness_key=WITNESS_PUBLIC))
    add("valid approval whose gateway witness signature does not verify",
        _single(approve={"signature": b"\x07" * 64})[0],
        ["the approval's gateway signature does not verify"],
        principals(witness_key=WITNESS_PUBLIC))

    # 2. the assertion belongs to another request
    t, c, e = _single()
    other = {"invoice": "I2", "amount_minor": 900_000}
    t2 = Trail()
    t2.enrol(A)
    _, c2, e2 = t2.escalated_call(other)
    t2.approve(c2, e2, TOOL, other, A.evidence(nonce(1), TOOL, json_digest(ARGS)))
    add("assertion for another call (different args_sha256)", t2, ["signed a different request"])
    t2 = Trail()
    t2.enrol(A)
    _, c2, e2 = t2.escalated_call(other)
    liar = _redigest(A.evidence(nonce(1), TOOL, json_digest(ARGS)),
                     request_digest=webauthn.request_digest(TOOL, json_digest(other)))
    t2.approve(c2, e2, TOOL, other, liar)
    add("assertion for another call, claim rewritten to match", t2,
        ["the challenge is not the one for this request"])
    t2 = Trail()
    t2.enrol(A)
    _, c2, e2 = t2.escalated_call(ARGS, "erp.invoice.refund")
    t2.approve(c2, e2, "erp.invoice.refund", ARGS, A.evidence(nonce(1), TOOL, json_digest(ARGS)))
    add("assertion for another tool", t2, ["signed a different request"])

    # 3. the passkey's life
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2)
    _, c, e = t.escalated_call(ARGS)
    before = t.approve(c, e, TOOL, ARGS, B.evidence(nonce(1), TOOL, json_digest(ARGS)))
    t.revoke(B, by=A, n=3)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, B.evidence(nonce(4), TOOL, json_digest(ARGS)))
    add("passkey revoked before the approval; an approval before the revocation still verifies",
        t, ["had been revoked"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.revoke(A, by=A, n=3)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), TOOL, json_digest(ARGS)))
    add("passkey revoked by its own assertion, then used", t, ["had been revoked"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    ev = B.evidence(nonce(1), TOOL, json_digest(ARGS))
    t.approve(c, e, TOOL, ARGS, ev)
    t.enrol(B, confirmed_by=A, n=2)
    add("passkey enrolled after the approval", t,
        ["the passkey was not yet enrolled"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.enrol(B, confirmed_by=A, n=2)
    ev = B.evidence(nonce(1), TOOL, json_digest(ARGS))
    t2 = Trail()
    t2.records, t2.cids = t.records[:], t.cids[:]
    t2.approve(c, e, TOOL, ARGS, ev)
    add("passkey enrolled before the approval (a second passkey, confirmed by the first)", t2, [])
    t = Trail()
    t.enrol(A)
    add("approver in the principals with no passkey at all", _approve_with(t, B), [
        "the passkey is not in the registry"])
    t = Trail()
    t.enrol(A)
    t.enrol(B, who=OTHER, identity="b@acme.example")
    add("approver's passkey enrolled for someone else", _approve_with(t, B), [
        "is not a passkey approver", "the passkey is not in the registry"],
        principals(who=APPROVER))

    # 4. the ceremony
    for name, wrong, why in (
            ("assertion made at another origin", {"origin": "https://evil.example"},
             "the origin is not the one enrolled"),
            ("assertion made for another relying party", {"rp_id": "evil.example"},
             "the relying party id hash is not the one enrolled"),
            ("user verification not performed", {"uv": False}, "user verification was not performed"),
            ("user presence not asserted", {"up": False}, "user presence was not asserted"),
            ("client data type is webauthn.create", {"client_type": "webauthn.create"},
             "the client data type is not webauthn.get"),
            ("assertion made in a cross-origin frame", {"extra_client": {"crossOrigin": True}},
             "cross-origin"),
            ("assertion carries attested credential data", {"flags": 0x40},
             "attested credential data"),
            ("backup state without backup eligibility", {"flags": 0x10}, "backup state")):
        add(name, _single(ev_fn=lambda ev, w=wrong: _wrong(ev, **w))[0], [why])
    add("evidence names an origin other than the one enrolled",
        _single(ev_fn=lambda ev: _redigest(ev, origin="https://evil.example"))[0],
        ["the evidence names"])
    evil = SoftAuthenticator("cfo-laptop", rp_id="evil.example", origin="https://evil.example")
    add("assertion honestly made for another relying party, evidence claims it",
        _single(ev_fn=lambda ev: evil.evidence(nonce(1), TOOL, json_digest(ARGS)))[0],
        ["the evidence names"])
    t = Trail()
    t.enrol(A, rp_id="approve.acme.example", origin="https://other.example")
    add("enrolment whose origin is not under its relying party id", t,
        ["the origin's host is not the relying party id"])

    # 5. tampering
    for name, fn in (
            ("signature bit flipped, digest refreshed",
             lambda ev: _redigest(ev, signature=_flip(ev.signature, 10))),
            ("authenticator data bit flipped, digest refreshed",
             lambda ev: _redigest(ev, authenticator_data=_flip(ev.authenticator_data, 34))),
            ("client data bit flipped, digest refreshed",
             lambda ev: _redigest(ev, client_data_json=_flip(ev.client_data_json, 30)))):
        add(name, _single(ev_fn=fn)[0], ["does not stand"])
    t, c, e = _single()
    bad = copy.deepcopy(t)
    child = bad.records[-1]["body"]
    child["signature"] = _flip(child["signature"], 10)
    bad.cids[-1] = _recid(bad.records[-1])
    add("signature bit flipped, digest left stale", bad, ["the assertion does not match its digest"])
    t = _single()[0]
    t.records[-2]["body"].pop("evidence")
    add("approval with its evidence summary removed", t, ["carries no passkey assertion"])
    t, _, _ = _single(approve={"child": False})
    add("approval whose evidence record is missing", t, ["is not in the trail"])

    # 6. batches
    add("batch of four, every approval verifies", _batch(), [])
    add("batch with one item replaced after signing",
        _batch(tamper=lambda i, ev: _redigest(ev, batch=_swap(ev.batch, 2) ) if i == 2 else ev),
        ["not one of the items the passkey signed"])
    add("batch with an item removed from one approval's evidence",
        _batch(tamper=lambda i, ev: _redigest(ev, batch=ev.batch[:3]) if i == 3 else ev),
        ["not one of the items the passkey signed"])
    add("batch with an item added to one approval's evidence",
        _batch(tamper=lambda i, ev: _redigest(ev, batch=ev.batch + (("erp.invoice.pay",
                                                                      b"\x09" * 32),))
               if i == 0 else ev),
        ["signed a different request"])
    add("batch reordered in one approval's evidence",
        _batch(tamper=lambda i, ev: _redigest(ev, batch=ev.batch[::-1]) if i == 1 else ev),
        ["signed a different request"])
    add("batch that repeats an item",
        _batch_repeat(), ["batch repeats an item"])
    add("batch of one", _batch(items=_batch_items(1)), [])

    # tech lead: a batch signs the document the decision acted on
    doc = bytes(range(32))
    add("batch signing a document, the one each decision acted on",
        _batch_with_documents(doc, doc), [])
    add("batch signing a document other than the one the decision acted on",
        _batch_with_documents(doc, b"\xee" * 32),
        ["signs a document other than the one this decision acted on"] * 2)

    # 7. single use
    t = Trail()
    t.enrol(A)
    for i, inv in enumerate(("I2", "I3")):
        a = {"invoice": inv, "amount_minor": 900}
        _, c, e = t.escalated_call(a)
        t.approve(c, e, TOOL, a, A.evidence(nonce(1), TOOL, json_digest(a)))
    add("two approvals sharing a nonce", t, ["the nonce was already used"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    ev = A.evidence(nonce(1), TOOL, json_digest(ARGS))
    t.approve(c, e, TOOL, ARGS, ev)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev)
    add("one assertion replayed for a second escalation of the same call", t,
        ["the assertion was already used"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    ev = A.evidence(nonce(1), TOOL, json_digest(ARGS))
    t.approve(c, e, TOOL, ARGS, ev)
    t.approve(c, e, TOOL, ARGS, ev)
    add("one answer recorded again after a failed write (same escalation)", t, [])

    # 8. the registry
    t = Trail()
    t.enrol(A)
    t.add(passkeys.KIND_ENROLLED, APPROVER, body={
        "approver": APPROVER, "identity": "a@acme.example", "credential_id": B.credential_id,
        "public_key": B.cose_key, "rp_id": RP_ID, "origin": ORIGIN})
    add("second passkey added with no confirmation by a registered one", t,
        ["no confirmation by a registered passkey"])
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=C, n=2)
    add("second passkey confirmed by an unregistered passkey", t,
        ["not confirmed by a registered passkey: the passkey is not in the registry"])
    t = Trail()
    t.enrol(A)
    t.revoke(A, by=C, n=2)
    add("revocation by an unregistered passkey", t, ["not confirmed by a registered passkey"])
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2)
    t.revoke(A, by=A, n=3)
    t.enrol(C, confirmed_by=A, n=4)
    add("passkey confirmed by one that was already revoked", t, ["had been revoked"])
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2)
    t.revoke(A, by=B, n=3)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, B.evidence(nonce(4), TOOL, json_digest(ARGS)))
    add("one passkey revoked by another; the other still approves", t, [])
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2, identity="someone-else@acme.example")
    add("new passkey enrolled for an identity other than the approver's", t,
        ["enrolled for an identity other than the approver's current one"])
    t = Trail()
    t.enrol(A, identity_evidence={"kind": "oidc-sign-in"})
    add("first passkey with no identity evidence", t, ["needs identity evidence"])
    t = Trail()
    t.enrol(A)
    add("first passkey that is not the one pinned", t, ["is not one you pinned"],
        principals(pins=[pin(B)]))
    t = Trail()
    t.enrol(A, public_key=B.cose_key)
    add("first passkey pinned by id but enrolled with another key", t,
        ["differs from the one you pinned"], principals(pins=[pin(A)]))
    t = Trail()
    t.enrol(A)
    add("registry records for an approver the principals do not list as a passkey approver", t,
        ["is not a passkey approver"], {APPROVER: "00" * 32})
    t = Trail()
    t.enrol(A)
    t.enrol(A)
    add("the same passkey enrolled twice", t, ["already in the registry"])
    for name, key, why in (
            ("key on the wrong curve (P-384 label)",
             cose_es256(A.cose_key[-70:-38], A.cose_key[-32:], crv=2), "not on the P-256 curve"),
            ("key that is not a point on the curve",
             cose_es256(b"\x01" * 32, b"\x02" * 32), "not a point on the P-256 curve"),
            ("key with coordinates that are not reduced",
             cose_es256(b"\xff" * 32, b"\xff" * 32), "not reduced"),
            ("EdDSA key of small order", cose_eddsa(b"\x01" + b"\x00" * 31), "small order"),
            ("EdDSA key on the Ed448 curve", cose_eddsa(E.cose_key[-32:], crv=7),
             "not on the Ed25519 curve"),
            ("key with the wrong algorithm label",
             cose_es256(A.cose_key[-70:-38], A.cose_key[-32:], alg=-257), "not supported"),
            ("key with trailing bytes", A.cose_key + b"\x00", "trailing bytes"),
            ("key not in canonical order",
             A.cose_key[:1] + A.cose_key[5:7] + A.cose_key[1:5] + A.cose_key[7:], "canonical")):
        t = Trail()
        t.enrol(A, public_key=key)
        add(name, t, [why])

    # 9. a witness is not proof
    t, c, e = _single(approve={"signature": b"\x07" * 64})
    t.records[-2]["body"].pop("evidence")
    add("gateway-signed approval with no passkey assertion", t,
        ["carries no passkey assertion"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, None, signature=b"\x07" * 64)
    add("approval with only a gateway signature", t, ["carries no passkey assertion"])

    # tech lead: an approval only ever authorises
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, None, decision="reject")
    add("rejection by a passkey approver needs no assertion and authorises nothing", t, [])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), TOOL, json_digest(ARGS)), decision="reject")
    add("rejection carrying an assertion (an assertion can only approve)", t,
        ["a rejection carries a passkey assertion"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), TOOL, json_digest(ARGS)), decision="decline")
    add("a decision that is neither approve nor reject", t, ["neither approve nor reject"])

    # tech lead: the identity the passkey was enrolled under is still the approver's
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), TOOL, json_digest(ARGS)))
    t.rebind("new-address@acme.example")
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(2), TOOL, json_digest(ARGS)))
    add("identity rebound after enrolment: the approval before verifies, the one after fails",
        t, ["enrolled for a different identity from the approver's current one"])
    t = Trail()
    t.enrol(A)
    t.rebind("new-address@acme.example")
    t.enrol(B, identity="new-address@acme.example")
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, B.evidence(nonce(1), TOOL, json_digest(ARGS)))
    add("identity rebound, then a new passkey enrolled on fresh identity evidence", t, [])
    t = Trail()
    t.add(passkeys.KIND_REBOUND, APPROVER, body={"approver": APPROVER, "identity": "x@acme.example"})
    add("rebinding with no identity evidence", t, ["needs identity evidence"])
    return out


def _wrong(ev: passkeys.Evidence, **wrong: Any) -> passkeys.Evidence:
    ad, cdj, sig = A.assertion(webauthn.challenge_for(ev.nonce, ev.request_digest), **wrong)
    return _redigest(ev, authenticator_data=ad, client_data_json=cdj, signature=sig)


def _swap(batch: Tuple[Tuple[str, bytes], ...], i: int) -> Tuple[Tuple[str, bytes], ...]:
    return batch[:i] + ((batch[i][0], b"\x09" * 32),) + batch[i + 1:]


def _approve_with(t: Trail, auth: SoftAuthenticator) -> Trail:
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, auth.evidence(nonce(1), TOOL, json_digest(ARGS)))
    return t


def _batch_repeat() -> Trail:
    items = [(TOOL, ARGS), (TOOL, ARGS)]
    t = Trail()
    t.enrol(A)
    ev = A.evidence(nonce(1), "", b"", batch=[(TOOL, json_digest(ARGS))] * 2)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev)
    return t


def _recid(rec: Dict[str, Any]) -> bytes:
    from aeos.canon import cid_of_bytes, dag_cbor
    return cid_of_bytes(dag_cbor(rec))
