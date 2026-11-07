"""The passkey approval scenarios: small trails and the verdict a verifier must reach.

`testvectors/generate.py` writes each one to testvectors/passkey-approvals-v1.json with the
verdict this implementation gives, after checking it against `expect` here; the tests run them
again. `expect` lists a fragment of each problem a verifier must report, in order; an empty list
means the trail verifies.
"""
from __future__ import annotations

import copy
import dataclasses
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aeos import passkeys, webauthn
from aeos.canon import cid_of_bytes, dag_cbor, json_digest
from aeos.webauthn import DOCUMENT_TOOL
from webauthn_support import (APPROVER, ORIGIN, RP_ID, WITNESS, WITNESS_PUBLIC, SoftAuthenticator,
                              Trail, cose_eddsa, cose_es256, nonce, pin, principals, sign_in_of)

TOOL = "erp.invoice.pay"
OTHER = "spiffe://acme.example/human/cfo/b-ngubane"
ARGS = {"invoice": "I2", "amount_minor": 900}
A, B, C = (SoftAuthenticator(s) for s in ("cfo-laptop", "cfo-phone", "cfo-key"))
E = SoftAuthenticator("cfo-ed25519", alg=webauthn.COSE_EDDSA)

Scenario = Tuple[str, Trail, Dict[str, Any], List[str]]
LOCAL = SoftAuthenticator("cfo-laptop", rp_id="localhost", origin="http://localhost:8443")
DEMO_CASES = {"demo: approval for a passkey made at http://localhost"}   # run with --demo


def flip(b: bytes, i: int = 0) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def redigest(ev: passkeys.Evidence, **change: Any) -> passkeys.Evidence:
    """Evidence with fields changed; its digest follows the bytes, as a forger would make it."""
    return dataclasses.replace(ev, **change)


def ev_for(auth: SoftAuthenticator, n: int, esc: bytes, args: Dict[str, Any] = ARGS,
           tool: str = TOOL, **kw: Any) -> passkeys.Evidence:
    return auth.evidence(nonce(n), tool, json_digest(args), esc, **kw)


def _single(auth: SoftAuthenticator = A, n: int = 1, *, ev_fn: Callable = None,
            approve: Dict[str, Any] = None) -> Trail:
    t = Trail()
    t.enrol(auth)
    _, c, e = t.escalated_call(ARGS)
    ev = ev_for(auth, n, e)
    t.approve(c, e, TOOL, ARGS, ev_fn(ev) if ev_fn else ev, **(approve or {}))
    return t


def _wrong(ev: passkeys.Evidence, **wrong: Any) -> passkeys.Evidence:
    ad, cdj, sig = A.assertion(webauthn.challenge_for(ev.nonce, ev.request_digest), **wrong)
    return redigest(ev, authenticator_data=ad, client_data_json=cdj, signature=sig)


def _batch_items(n: int = 4) -> List[Tuple[str, Dict[str, Any]]]:
    return [(TOOL, {"invoice": f"I{i}", "amount_minor": 100 * i}) for i in range(1, n + 1)]


def _batch(tamper: Callable[[int, passkeys.Evidence], passkeys.Evidence] = None,
           items: Sequence[Tuple[str, Dict[str, Any]]] = None, doc: bytes = None,
           call_doc: bytes = None) -> Trail:
    """Approvals sharing one assertion over their calls (and a document, if given)."""
    items = list(items or _batch_items())
    t = Trail()
    t.enrol(A)
    calls = []
    for tool, a in items:
        a = dict(a, **({"document_sha256": (call_doc or doc).hex()} if doc is not None else {}))
        _, c, e = t.escalated_call(a, tool)
        calls.append((tool, a, c, e))
    signed = [(DOCUMENT_TOOL, json_digest({}) if doc is None else doc, b"")][:0 if doc is None
                                                                            else 1]
    signed += [(tool, json_digest(a), e) for tool, a, _, e in calls]
    ev = A.evidence(nonce(1), "", b"", batch=signed)
    for i, (tool, a, c, e) in enumerate(calls):
        t.approve(c, e, tool, a, tamper(i, ev) if tamper else ev)
    return t


def _decided(allow_twice: bool = False, omit_approval: bool = False,
             wrong_call: bool = False, ed: bool = False) -> Trail:
    """A call escalated, approved and allowed, with the policy's decisions in the trail."""
    t = Trail()
    t.enrol(A)
    _, c0, e = t.escalated_call(ARGS)
    c1 = t.repeat_call(TOOL, ARGS)
    if not omit_approval:
        t.approve(c1 if not wrong_call else c0, e, TOOL, ARGS, ev_for(A, 1, e))
    t.decide(c1, TOOL, ARGS, "allow", approver=APPROVER)
    if allow_twice:
        c2 = t.repeat_call(TOOL, ARGS)
        t.approve(c2, e, TOOL, ARGS, ev_for(A, 1, e))
        t.decide(c2, TOOL, ARGS, "allow", approver=APPROVER)
    return t


def scenarios() -> List[Scenario]:
    out: List[Scenario] = []
    p = principals()

    def add(name: str, trail: Trail, expect: Sequence[str], pr: Dict[str, Any] = None) -> None:
        assert name not in {o[0] for o in out}, name
        out.append((name, trail, pr if pr is not None else p, list(expect)))

    # 1. a valid approval
    add("valid single approval (ES256)", _single(), [])
    add("valid single approval (EdDSA)", _single(E), [])
    add("valid approval, first passkey pinned in the principals", _single(), [],
        principals(pins=[pin(A)]))
    add("valid approval that also carries a gateway witness signature",
        _single(approve={"witness": WITNESS}), [], principals(witness_key=WITNESS_PUBLIC))
    add("valid approval carrying a gateway signature that is not checked",
        _single(approve={"witness": WITNESS}), [])
    add("valid approval whose gateway witness signature does not verify",
        _single(approve={"signature": b"\x07" * 64}),
        ["the approval's gateway signature does not verify"],
        principals(witness_key=WITNESS_PUBLIC))
    add("valid approval decided and allowed (the policy decision rests on it)", _decided(), [])

    # 2. the assertion belongs to another request
    other = {"invoice": "I2", "amount_minor": 900_000}
    t = Trail()
    t.enrol(A)
    _, c2, e2 = t.escalated_call(other)
    t.approve(c2, e2, TOOL, other, ev_for(A, 1, e2, ARGS))
    add("assertion for another call (different args_sha256)", t, ["signed a different request"])
    t = Trail()
    t.enrol(A)
    _, c2, e2 = t.escalated_call(other)
    liar = redigest(ev_for(A, 1, e2, ARGS), request_digest=webauthn.request_digest(
        TOOL, json_digest(other), e2))
    t.approve(c2, e2, TOOL, other, liar)
    add("assertion for another call, claim rewritten to match", t,
        ["the challenge is not the one for this request"])
    t = Trail()
    t.enrol(A)
    _, c2, e2 = t.escalated_call(ARGS, "erp.invoice.refund")
    t.approve(c2, e2, "erp.invoice.refund", ARGS, ev_for(A, 1, e2, ARGS, TOOL))
    add("assertion for another tool", t, ["signed a different request"])
    t = Trail()
    t.enrol(A)
    _, c1, e1 = t.escalated_call(ARGS)
    _, c2, e2 = t.escalated_call(ARGS)
    t.approve(c2, e2, TOOL, ARGS, ev_for(A, 1, e1))
    add("yes for one escalation presented for another escalation of the same call", t,
        ["signed a different request"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS, "aeos/passkey-enrol")
    t.approve(c, e, "aeos/passkey-enrol", ARGS, ev_for(A, 1, e, ARGS, "aeos/passkey-enrol"))
    add("approval for a reserved aeos/ tool", t, ["is reserved"])

    # 3. the passkey's life
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 1, e))
    t.revoke(B, by=A, n=3)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 4, e))
    add("passkey revoked before the approval; an approval before the revocation still verifies",
        t, ["had been revoked"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.revoke(A, by=A, n=3)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 1, e))
    add("passkey revoked by its own assertion, then used", t, ["had been revoked"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 1, e))
    t.enrol(B, confirmed_by=A, n=2)
    add("passkey enrolled after the approval", t, ["the passkey is not in the registry"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.enrol(B, confirmed_by=A, n=2)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 1, e))
    add("passkey enrolled before the approval (a second passkey, confirmed by the first)", t, [])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 1, e))
    add("approver whose passkey is not in the registry", t,
        ["the passkey is not in the registry"])
    t = Trail()
    t.enrol(A)
    t.enrol(B, who=OTHER, identity="b@acme.example")
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 1, e))
    add("approver's passkey enrolled for someone else", t,
        ["is not a passkey approver", "the passkey is not in the registry"], principals())

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
            ("assertion made with a top origin", {"extra_client": {"topOrigin": ORIGIN}},
             "cross-origin"),
            ("assertion carries attested credential data", {"flags": 0x40},
             "attested credential data"),
            ("backup state without backup eligibility", {"flags": 0x10}, "backup state"),
            ("extension flag set with no extension data", {"ed_flag": True}, "extension"),
            ("extension data without the extension flag", {"extensions": b"\xa0", "ed_flag": False},
             "no extension flag"),
            ("extension data that is not a map", {"extensions": b"\x01"}, "exactly one CBOR map"),
            ("extension data with trailing bytes", {"extensions": b"\xa0\x00"},
             "exactly one CBOR map"),
            ("extension map not in canonical order",
             {"extensions": b"\xa2\x61b\x01\x61a\x01"}, "canonical"),
            ("client data with a repeated key",
             {"client_raw": b'{"type":"webauthn.get","type":"webauthn.create"}'},
             "repeated keys")):
        add(name, _single(ev_fn=lambda ev, w=wrong: _wrong(ev, **w)), [why])
    add("extension data that is one canonical map", _single(ev_fn=lambda ev: _wrong(
        ev, extensions=b"\xa1\x69credProps\xa1\x62rk\xf5")), [])
    add("assertion whose client data starts with a byte order mark",
        _single(ev_fn=lambda ev: _bom(ev)), [])
    add("evidence names an origin other than the one enrolled",
        _single(ev_fn=lambda ev: redigest(ev, origin="https://evil.example")),
        ["the evidence names"])
    evil = SoftAuthenticator("cfo-laptop", rp_id="evil.example", origin="https://evil.example")
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(evil, 1, e))
    add("assertion honestly made for another relying party, evidence claims it", t,
        ["the evidence names"])
    t = Trail()
    t.enrol(A, rp_id="approve.acme.example", origin="https://other.example")
    add("enrolment whose origin is not under its relying party id", t,
        ["the origin's host is not the relying party id"])
    for name, rp, origin, why in (
            ("enrolment with an upper-case origin", RP_ID, "https://Approve.acme.example",
             "browser serialisation"),
            ("enrolment with a default port in the origin", RP_ID, ORIGIN + ":443",
             "browser serialisation"),
            ("enrolment for a relying party that is a public suffix", "co.za", "https://co.za",
             "public suffix"),
            ("enrolment for a relying party of one label", "intranet", "https://intranet",
             "two or more labels"),
            ("enrolment for a relying party that is an IP address", "10.0.0.5",
             "https://10.0.0.5", "IP address"),
            ("enrolment for a relying party that is a shared hosting suffix", "github.io",
             "https://github.io", "public suffix")):
        t = Trail()
        t.enrol(A, rp_id=rp, origin=origin)
        add(name, t, [why])

    t = Trail()
    t.enrol(LOCAL)
    add("passkey made at http://localhost, audit run without --demo", t,
        ["localhost is not a relying party id this audit accepts"])
    t = Trail()
    t.enrol(LOCAL)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(LOCAL, 1, e))
    add("demo: approval for a passkey made at http://localhost", t, [])

    # 5. tampering
    for name, fn in (
            ("signature bit flipped, digest refreshed",
             lambda ev: redigest(ev, signature=flip(ev.signature, 10))),
            ("authenticator data bit flipped, digest refreshed",
             lambda ev: redigest(ev, authenticator_data=flip(ev.authenticator_data, 34))),
            ("client data bit flipped, digest refreshed",
             lambda ev: redigest(ev, client_data_json=flip(ev.client_data_json, 30)))):
        add(name, _single(ev_fn=fn), ["does not stand"])
    t = _single()
    t.records[-1]["body"]["signature"] = flip(t.records[-1]["body"]["signature"], 10)
    add("signature bit flipped, digest left stale", t, ["the assertion does not match its digest"])
    t = _single()
    t.records[-2]["body"].pop("evidence")
    add("approval with its evidence summary removed", t, ["carries no passkey assertion"])
    add("approval whose evidence record is missing", _single(approve={"child": False}),
        ["is not in the trail"])

    # 6. batches
    add("batch of four, every approval verifies", _batch(), [])
    add("batch with one item replaced after signing",
        _batch(tamper=lambda i, ev: redigest(ev, batch=_swap(ev.batch, 2)) if i == 2 else ev),
        ["not one of the items the passkey signed"])
    add("batch with an item removed from one approval's evidence",
        _batch(tamper=lambda i, ev: redigest(ev, batch=ev.batch[:3]) if i == 3 else ev),
        ["not one of the items the passkey signed"])
    add("batch with an item added to one approval's evidence",
        _batch(tamper=lambda i, ev: redigest(ev, batch=ev.batch + (
            (TOOL, b"\x09" * 32, ev.batch[0][2]),)) if i == 0 else ev),
        ["signed a different request"])
    add("batch reordered in one approval's evidence",
        _batch(tamper=lambda i, ev: redigest(ev, batch=ev.batch[::-1]) if i == 1 else ev),
        ["signed a different request"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), "", b"", batch=[(TOOL, json_digest(ARGS), e)] * 2))
    add("batch that repeats an item", t, ["batch repeats an item"])
    add("batch of one", _batch(items=_batch_items(1)), [])
    doc = bytes(range(32))
    add("batch signing a document, the one each decision acted on", _batch(doc=doc), [])
    add("batch signing a document other than the one the decision acted on",
        _batch(doc=doc, call_doc=b"\xee" * 32),
        ["signs a document other than the one this decision acted on"] * 4)

    # 7. single use, in trail order
    t = Trail()
    t.enrol(A)
    for inv in ("I2", "I3"):
        a = {"invoice": inv, "amount_minor": 900}
        _, c, e = t.escalated_call(a)
        t.approve(c, e, TOOL, a, ev_for(A, 1, e, a))
    add("two approvals sharing a nonce", t, ["the nonce was already used"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    ev = ev_for(A, 1, e)
    t.approve(c, e, TOOL, ARGS, ev)
    c2 = t.repeat_call(TOOL, ARGS)
    _, c3, e3 = t.escalated_call(ARGS)
    t.approve(c3, e3, TOOL, ARGS, ev)
    add("one assertion replayed for a second escalation of the same call", t,
        ["signed a different request"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    ev = ev_for(A, 1, e)
    t.approve(c, e, TOOL, ARGS, ev)
    t.approve(c, e, TOOL, ARGS, ev)
    add("one answer recorded again after a failed write (same escalation)", t, [])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 5, e))
    t.enrol(B, confirmed_by=A, n=5)
    add("confirmation reuses an approval's nonce", t, ["the nonce was already used"])
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=5)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 5, e))
    add("approval reuses a confirmation's nonce", t, ["the nonce was already used"])

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
    ev = A.evidence(nonce(2), passkeys.ENROL_TOOL, json_digest({"another": "change"}))
    t.add(passkeys.KIND_ENROLLED, APPROVER, body={
        "approver": APPROVER, "identity": "a@acme.example", "credential_id": B.credential_id,
        "public_key": B.cose_key, "rp_id": RP_ID, "origin": ORIGIN, "evidence": ev.summary()})
    t.evidence_child(t.cids[-1], APPROVER, ev)
    add("confirmation signed for another change", t,
        ["signed a different request from the change it confirms"])
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
    t.approve(c, e, TOOL, ARGS, ev_for(B, 4, e))
    add("one passkey revoked by another; the other still approves", t, [])
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2, identity="someone-else@acme.example")
    add("new passkey enrolled for an identity other than the approver's", t,
        ["enrolled for an identity other than the approver's current one"])
    t = Trail()
    t.enrol(A)
    t.records[-1]["body"]["identity_evidence"] = {"kind": "oidc-sign-in"}
    add("first passkey with no identity evidence", t, ["identity evidence needs"])
    t = Trail()
    t.enrol(A)
    t.records[-1]["body"].pop("registration")
    add("first passkey with no registration response", t, ["needs its registration response"])
    for name, reg, why in (
            ("first passkey registered for another sign-in", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, b"\x01" * 32)), "challenge is not the one"),
            ("first passkey registered without user verification", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256),
                uv=False), "user verification was not performed"),
            ("first passkey registered at another origin", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256),
                origin="https://evil.example"), "origin is not the one enrolled"),
            ("first passkey registered under another credential id", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256),
                credential_id=b"\x07" * 32), "credential id is not the one enrolled"),
            ("first passkey registered with another public key", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256),
                public_key=B.cose_key), "public key is not the one enrolled"),
            ("first passkey registered as a create, not a get", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256),
                client_type="webauthn.get"), "client data type is not webauthn.create"),
            ("first passkey registered with an attestation format", lambda: A.registration(
                webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256),
                fmt="packed"), "format is not none")):
        t = Trail()
        t.enrol(A, registration=reg())
        add(name, t, [why])
    t = Trail()
    t.enrol(A)
    add("first passkey that is not the one pinned", t, ["is not one you pinned"],
        principals(pins=[pin(B)]))
    t = Trail()
    t.enrol(A, public_key=B.cose_key)
    add("first passkey pinned by id but enrolled with another key", t,
        ["public key is not the one enrolled"], principals(pins=[pin(A)]))
    t = Trail()
    t.enrol(A)
    pinned = pin(A)
    pinned.pop("identity")
    add("pin that does not name the identity", t, ["differs from the one you pinned"],
        principals(pins=[pinned]))
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

    # confirmations are single requests and aeos/ is reserved
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    enrol_args = passkeys.enrol_args_sha256(APPROVER, "a@acme.example", C.credential_id,
                                            C.cose_key, C.rp_id, C.origin)
    batch = [(TOOL, json_digest(ARGS), e), (passkeys.ENROL_TOOL, enrol_args, e)]
    ev = A.evidence(nonce(9), "", b"", batch=batch)
    t.approve(c, e, TOOL, ARGS, ev)
    t.add(passkeys.KIND_ENROLLED, APPROVER, body={
        "approver": APPROVER, "identity": "a@acme.example", "credential_id": C.credential_id,
        "public_key": C.cose_key, "rp_id": C.rp_id, "origin": C.origin,
        "evidence": ev.summary()})
    t.evidence_child(t.cids[-1], APPROVER, ev)
    add("batch enrols an attacker key", t,
        ["must be a single request", "reserved tool"])

    # 9. a witness is not proof
    t = _single(approve={"signature": b"\x07" * 64})
    t.records[-2]["body"].pop("evidence")
    add("gateway-signed approval with no passkey assertion", t, ["carries no passkey assertion"])
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, None, signature=b"\x07" * 64)
    add("approval with only a gateway signature", t, ["carries no passkey assertion"])

    # an approval only ever authorises; a no rests on the sign-in
    for name, decision, ev, why in (
            ("rejection by a passkey approver on its sign-in evidence", "reject",
             sign_in_of("a@acme.example"), None),
            ("rejection with no identity evidence", "reject", None, "carries no identity evidence"),
            ("rejection carrying an assertion (an assertion can only approve)", "reject", "ev",
             "a rejection carries a passkey assertion"),
            ("a decision that is neither approve nor reject", "decline", "ev",
             "neither approve nor reject")):
        t = Trail()
        t.enrol(A)
        _, c, e = t.escalated_call(ARGS)
        t.approve(c, e, TOOL, ARGS, ev_for(A, 1, e) if ev == "ev" else ev, decision=decision)
        add(name, t, [why] if why else [])

    # the identity and the epoch
    t = Trail()
    t.enrol(A)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 1, e))
    t.rebind("new-address@acme.example", confirmed_by=A, n=2)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 3, e))
    add("identity rebound after enrolment: the approval before verifies, the one after fails",
        t, ["enrolled for a different identity from the approver's current one"])
    t = Trail()
    t.enrol(A)
    t.rebind("new-address@acme.example", confirmed_by=A, n=2)
    t.enrol(B, identity="new-address@acme.example")
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(B, 1, e))
    add("identity rebound, then a new passkey enrolled on fresh identity evidence", t, [])
    t = Trail()
    t.enrol(A)
    t.rebind("b@acme.example", confirmed_by=A, n=2)
    t.enrol(B, identity="b@acme.example")
    t.rebind("a@acme.example", confirmed_by=B, n=3)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 4, e))
    add("identity rebound away and back: the first passkey stays ended", t,
        ["enrolled for a different identity from the approver's current one"],
        principals(pins=[pin(A), pin(B, "b@acme.example")]))
    t = Trail()
    t.enrol(A)
    t.rebind("b@acme.example")
    t.rebind("a@acme.example")
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, ev_for(A, 1, e))
    add("rebinding with no confirmation while a passkey stands", t,
        ["no confirmation by a registered passkey", "no confirmation by a registered passkey"])
    t = Trail()
    t.add(passkeys.KIND_REBOUND, APPROVER, body={"approver": APPROVER, "identity": "x@acme.example"})
    add("rebinding with no identity evidence", t, ["identity evidence needs"])

    # the signature counter
    for name, counts, notes in (("signature counter that rises", (3, 7), 0),
                                ("signature counter that stays at zero", (0, 0), 0),
                                ("signature counter that does not rise", (5, 5), 1),
                                ("signature counter that falls", (5, 2), 1)):
        t = Trail()
        t.enrol(A)
        for k, n in enumerate(counts):
            a = {"invoice": f"I{k}", "amount_minor": 900}
            _, c, e = t.escalated_call(a)
            t.approve(c, e, TOOL, a, _wrong_counter(ev_for(A, k + 1, e, a), n))
        add(name, t, [])

    # a decision rests on a verified approval, and one approval allows one call
    add("decision rests on no approval record", _decided(omit_approval=True),
        ["not an earlier, verified approval of this call"])
    t = Trail()
    t.enrol(A)
    _, c0, e = t.escalated_call(ARGS)
    rogue = t.add("tool.call", "spiffe://acme.example/agent/rogue/1", subject=TOOL, body={
        "args_sha256": json_digest(ARGS), "call_id": "rogue"})
    t.approve(rogue, e, TOOL, ARGS, ev_for(A, 1, e))
    t.decide(rogue, TOOL, ARGS, "allow", approver=APPROVER)
    add("another agent's call rides the escalation", t,
        ["attached to a call by another agent", "not an earlier, verified approval of this call"])
    add("approval attached to another call than the one decided", _decided(wrong_call=True),
        ["not an earlier, verified approval of this call"])
    add("one approval allows two calls", _decided(allow_twice=True),
        ["already allowed the call"])
    t = Trail()
    t.enrol(A)
    _, c0, e = t.escalated_call(ARGS)
    c1 = t.repeat_call(TOOL, ARGS)
    t.approve(c1, e, TOOL, ARGS, ev_for(A, 1, e, ARGS, TOOL), witness=None)
    t.records[-2]["body"].pop("evidence")
    t.decide(c1, TOOL, ARGS, "allow", approver=APPROVER)
    add("decision rests on an approval that does not verify", t,
        ["carries no passkey assertion", "not an earlier, verified approval of this call"])
    t = Trail()
    t.enrol(A)
    _, c0, e = t.escalated_call(ARGS)
    c1 = t.repeat_call(TOOL, ARGS)
    t.decide(c1, TOOL, ARGS, "allow", approver=APPROVER)
    t.approve(c1, e, TOOL, ARGS, ev_for(A, 1, e))
    add("decision recorded before the approval it rests on", t,
        ["not an earlier, verified approval of this call"])
    return out


def _bom(ev: passkeys.Evidence) -> passkeys.Evidence:
    ad, cdj, sig = A.assertion(webauthn.challenge_for(ev.nonce, ev.request_digest),
                               client_raw=None)
    cdj = b"\xef\xbb\xbf" + cdj
    signed = ad + __import__("hashlib").sha256(cdj).digest()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    sig = A.key.sign(signed, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return redigest(ev, authenticator_data=ad, client_data_json=cdj, signature=sig)


def _wrong_counter(ev: passkeys.Evidence, counter: int) -> passkeys.Evidence:
    return _wrong(ev, counter=counter)


def _swap(batch: Tuple[Tuple[str, bytes, bytes], ...], i: int):
    return batch[:i] + ((batch[i][0], b"\x09" * 32, batch[i][2]),) + batch[i + 1:]
