"""Passkey approvals: WebAuthn verification, the registry in the trail, batches and vectors."""
import copy
import json
import random
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aeos import ActionLog, audit, delegation, fulldemo, identity, keys, passkeys, policy, webauthn
from aeos.canon import cid_of_bytes, cid_str, dag_cbor, decode_dag_cbor, json_digest
from aeos.gateway import AgentClient, Gateway
from aeos.log import now_ms
from passkey_scenarios import ARGS, TOOL, A, B, E, scenarios
from webauthn_support import (APPROVER, WITNESS_PUBLIC, SoftAuthenticator, Trail, cose_es256,
                              nonce, pin, principals, sign_in_of)

VECTORS = Path(__file__).resolve().parents[2] / "testvectors" / "passkey-approvals-v1.json"
CASES = scenarios()


@pytest.mark.parametrize("name,trail,pr,expect", CASES, ids=[c[0] for c in CASES])
def test_each_scenario_gives_its_verdict(name, trail, pr, expect):
    findings, problems, notes = audit.check_approvals(trail.triples(), pr)
    assert len(problems) == len(expect), problems
    for want, got in zip(expect, problems):
        assert want in got
    if not expect and any(r["kind"] == "approval" and r["body"]["decision"] == "approve"
                          for r in trail.records):
        assert findings and "checked from the evidence in the trail alone" in findings[0]


def test_a_verified_batch_is_reported_as_one_tap_with_several_approvals():
    name, trail, pr, _ = next(c for c in CASES if c[0] == "batch of four, every approval verifies")
    findings, problems, _ = audit.check_approvals(trail.triples(), pr)
    assert problems == [] and "4 approvals by passkey were checked" in findings[0]
    assert "(1 assertion, 1 signing several at once)" in findings[0]


# ---- the vectors, run again from their bytes the way another implementation would -------------


def _load():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_the_vectors_replay_from_their_bytes():
    doc = _load()
    for c in doc["cases"]:
        triples = []
        for i, r in enumerate(c["records"]):
            raw = bytes.fromhex(r["cbor"])
            assert cid_str(cid_of_bytes(raw)) == r["cid"]
            triples.append((i, cid_of_bytes(raw), decode_dag_cbor(raw)))
        _, problems, notes = audit.check_approvals(triples, c["principals"])
        assert problems == c["expect_problems"] and notes == c["expect_notes"], c["name"]
    for k in doc["cose_keys"]:
        try:
            webauthn.parse_cose_key(bytes.fromhex(k["cose_key"]))
            got = None
        except webauthn.WebAuthnError as e:
            got = str(e)
        assert got == k["expect_error"], k["name"]
    for a in doc["assertions"]:
        try:
            webauthn.verify_assertion(
                webauthn.parse_cose_key(bytes.fromhex(a["cose_key"])),
                bytes.fromhex(a["authenticator_data"]), bytes.fromhex(a["client_data_json"]),
                bytes.fromhex(a["signature"]), rp_id=a["rp_id"], origin=a["origin"],
                challenge=bytes.fromhex(a["challenge"]))
            got = None
        except webauthn.WebAuthnError as e:
            got = str(e)
        assert got == a["expect_error"], a["name"]


def test_the_constructions_are_what_the_spec_says():
    c = _load()["constructions"]
    import hashlib
    args, tool, n = bytes.fromhex(c["args_sha256"]), c["tool"], bytes.fromhex(c["nonce"])
    esc = bytes.fromhex(c["escalation"])
    assert len(esc) == 36
    rd = hashlib.sha256(b"aeos/request/v2\n" + tool.encode() + b"\n" + args + esc).digest()
    assert rd.hex() == c["request_digest"]
    assert hashlib.sha256(b"aeos/request/v1\n" + tool.encode() + b"\n" + args).hexdigest() \
        == c["request_digest_without_escalation"]
    assert hashlib.sha256(b"aeos/approval-challenge/v1\n" + n + rd).hexdigest() == c["challenge"]
    body = b"\n".join(i["tool"].encode() + b"\0" + bytes.fromhex(i["args_sha256"])
                      + bytes.fromhex(i["escalation"]) for i in c["batch_items"])
    bd = hashlib.sha256(b"aeos/approval-batch/v2\n" + body).digest()
    assert bd.hex() == c["batch_digest"]
    assert hashlib.sha256(b"aeos/approval-challenge/v1\n" + n + bd).hexdigest() \
        == c["batch_challenge"]
    e = c["enrol"]
    assert hashlib.sha256(b"aeos/enrol-challenge/v1\n" + e["approver"].encode() + b"\n"
                          + bytes.fromhex(e["identity_evidence_sha256"])).hexdigest() \
        == e["challenge"]


# ---- the webauthn module ---------------------------------------------------------------------


def test_a_synced_passkey_with_a_counter_of_zero_verifies_and_the_counter_is_advisory():
    ch = webauthn.challenge_for(nonce(1), webauthn.request_digest(TOOL, json_digest(ARGS), b"\1" * 36))
    ad, cdj, sig = A.assertion(ch)
    got = webauthn.verify_assertion(webauthn.parse_cose_key(A.cose_key), ad, cdj, sig,
                                    rp_id=A.rp_id, origin=A.origin, challenge=ch)
    assert got.sign_count == 0
    A.counter = 7
    try:
        ad, cdj, sig = A.assertion(ch)
    finally:
        A.counter = 0
    assert webauthn.verify_assertion(webauthn.parse_cose_key(A.cose_key), ad, cdj, sig,
                                     rp_id=A.rp_id, origin=A.origin, challenge=ch).sign_count == 7


def test_construction_inputs_are_checked():
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.request_digest("t", b"short")
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.request_digest("t", b"\0" * 32, b"short")
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.batch_digest([])
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.batch_digest([("a\0b", b"\0" * 32, b"\2" * 36)])
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.challenge_for(b"short", b"\0" * 32)
    esc = b"\2" * 36
    assert webauthn.batch_digest([("a", b"\0" * 32, esc), ("b", b"\1" * 32, esc)]) != \
        webauthn.batch_digest([("b", b"\1" * 32, esc), ("a", b"\0" * 32, esc)])
    with pytest.raises(webauthn.WebAuthnError):          # an item without an escalation
        webauthn.batch_digest([("a", b"\0" * 32, b"")])


def test_the_keys_of_a_real_authenticator_shape_parse_and_bent_ones_do_not():
    for auth, alg in ((A, -7), (E, -8)):
        assert webauthn.parse_cose_key(auth.cose_key)[0] == alg
    x, y = A.cose_key[-70:-38], A.cose_key[-32:]
    for bad in (b"", b"\xa0", A.cose_key[:-1], cose_es256(x, y, kty=1), cose_es256(x, y[:31]),
                cose_es256(x, y, crv=3)):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.parse_cose_key(bad)
    # a non-shortest-form integer for the algorithm label
    nonshortest = bytes.fromhex("a5010203" + "1826" + "2001" + "215820") + x + b"\x22\x58\x20" + y
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.parse_cose_key(nonshortest)


def test_origins_a_credential_may_declare():
    webauthn.check_origin("acme.example", "https://approve.acme.example")
    webauthn.check_origin("localhost", "http://localhost:8443")
    for rp, origin in (("acme.example", "http://acme.example"), ("acme.example", "https://x.example"),
                       ("acme.example", "https://acme.example/path"),
                       ("acme.example", "https://evilacme.example"), ("", "https://acme.example"),
                       ("Acme.example", "https://acme.example")):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.check_origin(rp, origin)


def test_garbage_assertions_are_refused_not_raised():
    rng = random.Random(3)
    key = webauthn.parse_cose_key(A.cose_key)
    ch = b"\0" * 32
    for _ in range(300):
        args = [rng.randbytes(rng.choice([0, 1, 36, 37, 38, 80, 200])) for _ in range(3)]
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.verify_assertion(key, *args, rp_id=A.rp_id, origin=A.origin, challenge=ch)
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.parse_cose_key(rng.randbytes(rng.choice([1, 5, 40, 70, 77])))


# ---- evidence and the approval ----------------------------------------------------------------

ESC = b"\x01" * 36


def test_evidence_survives_json_and_an_approval_carries_it():
    ev = A.evidence(nonce(1), TOOL, json_digest(ARGS), ESC)
    again = passkeys.Evidence.from_json(json.loads(json.dumps(ev.to_json())))
    assert again == ev and again.assertion_sha256 == ev.assertion_sha256
    a = delegation.Approval("esc", APPROVER, "approve", TOOL, json_digest(ARGS), 5, evidence=ev)
    back = delegation.Approval.from_json(json.loads(json.dumps(a.to_json())))
    assert back.evidence == ev and back.signature == b""
    no = delegation.Approval("esc", APPROVER, "reject", TOOL, json_digest(ARGS), 5,
                             evidence=sign_in_of("a@acme.example"))
    back = delegation.Approval.from_json(json.loads(json.dumps(no.to_json())))
    assert back.evidence == sign_in_of("a@acme.example")
    key = Ed25519PrivateKey.generate()
    signed = delegation.Approval("esc", APPROVER, "approve", TOOL, json_digest(ARGS), 5).sign(key)
    wire = delegation.Approval.from_json(json.loads(json.dumps(signed.to_json())))
    assert wire.verify(keys.public_bytes(key)) and wire.evidence is None


def test_evidence_that_is_not_what_it_says_is_refused():
    body = A.evidence(nonce(1), TOOL, json_digest(ARGS), ESC).body()
    for field in ("credential_id", "nonce", "rp_id", "request_digest", "signature"):
        broken = dict(body)
        broken.pop(field)
        with pytest.raises(webauthn.WebAuthnError):
            passkeys.Evidence.parse(broken)
    for bad in (None, [], {"kind": "other"}, dict(body, batch="x"),
                dict(body, batch={"context": "nope", "items": []}),
                dict(body, batch={"context": webauthn.BATCH_CONTEXT_NAME,
                                  "items": [{"tool": 1, "args_sha256": b""}]})):
        with pytest.raises(webauthn.WebAuthnError):
            passkeys.Evidence.parse(bad)


def test_origins_a_credential_may_declare():
    webauthn.check_origin("acme.example", "https://approve.acme.example")
    webauthn.check_origin("localhost", "http://localhost:8443")
    webauthn.check_origin("acme.example", "https://acme.example:8443")
    for rp, origin in (("acme.example", "http://acme.example"), ("acme.example", "https://x.example"),
                       ("acme.example", "https://acme.example/path"),
                       ("acme.example", "https://evilacme.example"), ("", "https://acme.example"),
                       ("Acme.example", "https://acme.example"),
                       ("acme.example", "https://ACME.example"),
                       ("acme.example", "https://acme.example:443"),
                       ("localhost", "http://localhost:80"), ("co.za", "https://co.za"),
                       ("com", "https://com"), ("1.2.3.4", "https://1.2.3.4"),
                       ("::1", "https://[::1]"), ("a_b.example", "https://a_b.example")):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.check_origin(rp, origin)


def test_client_data_is_read_as_the_spec_reads_it():
    ch = b"\0" * 32
    key = webauthn.parse_cose_key(A.cose_key)
    ad, cdj, sig = A.assertion(ch)
    kw = dict(rp_id=A.rp_id, origin=A.origin, challenge=ch)
    assert webauthn.verify_assertion(key, ad, cdj, sig, **kw)
    # a BOM before the JSON is stripped, as section 7.2 requires; the signature covers the bytes
    bom = b"\xef\xbb\xbf" + cdj
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    import hashlib
    sig2 = A.key.sign(ad + hashlib.sha256(bom).digest(), ec.ECDSA(hashes.SHA256()))
    assert webauthn.verify_assertion(key, ad, bom, sig2, **kw)
    assert webauthn.decode_cbor(b"\xa1\x01\x02")[0] == {1: 2}
    for bad in (b"\xa2\x02\x01\x01\x01", b"\xa2\x01\x01\x01\x01", b"\x9f\xff", b"\xf9\x00\x00",
                b"\xc1\x00", b"\x18\x01"):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.decode_cbor(bad)


# ---- the gateway takes a passkey approval, the registry is live, and the folder audits -------

DOMAIN = "acme.example"
AGENT = f"spiffe://{DOMAIN}/agent/ap"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp"
PERSON = f"spiffe://{DOMAIN}/human/controller"
CFO = APPROVER
DATA = {"escalate_above_minor": 500, "sanctioned_vendors": [], "approvers": [CFO]}
INVOICES = {"I2": {"vendor": "V1", "amount_minor": 900, "status": "approved for payment"}}
IDENTITY = "a@acme.example"


@pytest.fixture
def gateway(tmp_path):
    td = identity.TrustDomain(DOMAIN)
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(td.bundle_pem())
    files = {n: td.issue(i).write(tmp_path / "svid", n) for n, i in (("gw", GATEWAY),
                                                                      ("ap", AGENT))}
    person = Ed25519PrivateKey.generate()
    env = delegation.IntentEnvelope(PERSON, AGENT, "pay", [TOOL], 10_000, 10_000, "USD",
                                    now_ms() + 3_600_000).sign(person)
    auth = delegation.Authority()
    token = auth.mint(env, keys.public_bytes(person))
    log = ActionLog.create(tmp_path / "log", log_id="urn:example:pk")
    from aeos import Recorder
    directory = passkeys.Directory(passkeys.load_principals(principals())[1])
    rec = Recorder(log, agent=CFO, passkeys=directory)
    sign_in = sign_in_of(IDENTITY)
    rec.passkey_enrolled(CFO, identity=IDENTITY, credential_id=A.credential_id,
                         public_key=A.cose_key, rp_id=A.rp_id, origin=A.origin,
                         identity_evidence=sign_in,
                         registration=A.registration(webauthn.enrol_challenge(CFO, sign_in.sha256)))
    rules = policy.Policy.load(fulldemo.POLICY_WASM, DATA, "aeos/payments/decision")
    gw = Gateway(log, {TOOL: lambda a: {"paid": a["invoice"]}}, permissions={AGENT: [TOOL]},
                 trust_domain=DOMAIN, svid_files=files["gw"], bundle_file=bundle,
                 authority_key=auth.public_key, intents={env.cid: env},
                 principal_keys={PERSON: keys.public_bytes(person)}, policy=rules,
                 policy_facts=lambda t, a: {"invoice": INVOICES[a["invoice"]]}
                 if a.get("invoice") in INVOICES else {}, passkey_directory=directory)
    port = gw.start()
    c = AgentClient(port, files["ap"], bundle, gateway_id=GATEWAY, trust_domain=DOMAIN,
                    token=token.to_bytes())
    c.initialize()
    yield gw, log, c, rec, {"td": td, "tmp": tmp_path, "rules": rules, "files": files,
                           "bundle": bundle}
    gw.stop()


def _text(reply):
    return reply["result"]["content"][0]["text"]


def _approval(esc, auth, n, args, decision="approve", **kw):
    ev = auth.evidence(nonce(n), TOOL, json_digest(args), passkeys.escalation_cid(esc), **kw)
    return delegation.Approval(esc, CFO, decision, TOOL, json_digest(args), now_ms(),
                               evidence=ev)


def test_the_gateway_takes_a_passkey_approval_and_the_trail_audits(gateway):
    gw, log, c, _, _ = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    none = delegation.Approval(esc, CFO, "approve", TOOL, json_digest(args), now_ms())
    assert "no passkey assertion" in _text(c.call(TOOL, args, approval=none))
    assert "passkey's assertion was refused" in _text(
        c.call(TOOL, args, approval=_approval(esc, B, 1, args)))
    wrong = _approval(esc, A, 1, args)
    wrong.evidence = A.evidence(nonce(1), TOOL, json_digest({"x": 1}),
                                passkeys.escalation_cid(esc))
    assert "signed a different request" in _text(c.call(TOOL, args, approval=wrong))
    anonymous = _approval(esc, A, 9, args, decision="reject")
    assert "carries no identity evidence" in _text(c.call(TOOL, args, approval=anonymous))
    ok = c.call(TOOL, args, approval=_approval(esc, A, 2, args))
    assert ok["result"]["structuredContent"] == {"paid": "I2"}
    recs = [(e.index, bytes(e.cid), log.record(e)) for e in log.entries()]
    assert [r["kind"] for _, _, r in recs].count("x-approval-evidence") == 1
    findings, problems, _ = audit.check_approvals(recs, principals())
    assert problems == [] and "1 approval by passkey was checked" in findings[0]
    # the same trail with the evidence record removed no longer verifies
    stripped = [t for t in recs if t[2]["kind"] != "x-approval-evidence"]
    assert audit.check_approvals(stripped, principals())[1]


def test_a_rejection_by_a_passkey_approver_carries_its_sign_in(gateway):
    gw, log, c, _, _ = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    no = delegation.Approval(esc, CFO, "reject", TOOL, json_digest(args), now_ms(),
                             evidence=sign_in_of(IDENTITY))
    assert "rejected" in _text(c.call(TOOL, args, approval=no))
    recs = [(e.index, bytes(e.cid), log.record(e)) for e in log.entries()]
    _, problems, notes = audit.check_approvals(recs, principals())
    assert problems == [] and any("a rejection by" in n for n in notes)


def test_the_gateway_refuses_the_same_assertion_twice(gateway):
    gw, log, c, _, _ = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    gw.passkey_directory.ledger.use(0, A.evidence(nonce(5), TOOL, b"\0" * 32, ESC), "other",
                                    (TOOL, b"", ESC))
    assert "nonce was already used" in _text(
        c.call(TOOL, args, approval=_approval(esc, A, 5, args)))


def test_a_revoked_passkey_is_refused_at_once_without_a_restart(gateway):
    gw, log, c, rec, _ = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    args_enrol = passkeys.enrol_args_sha256(CFO, IDENTITY, B.credential_id, B.cose_key,
                                            B.rp_id, B.origin)
    rec.passkey_enrolled(CFO, identity=IDENTITY, credential_id=B.credential_id,
                         public_key=B.cose_key, rp_id=B.rp_id, origin=B.origin,
                         confirmation=A.evidence(nonce(7), passkeys.ENROL_TOOL, args_enrol))
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    # the new passkey is live the moment it is recorded ...
    rec.passkey_revoked(CFO, credential_id=B.credential_id,
                        confirmation=A.evidence(nonce(8), passkeys.REVOKE_TOOL,
                                                passkeys.revoke_args_sha256(CFO, B.credential_id)))
    # ... and so is its revocation
    assert "had been revoked" in _text(c.call(TOOL, args, approval=_approval(esc, B, 3, args)))
    ok = c.call(TOOL, args, approval=_approval(esc, A, 4, args))
    assert ok["result"]["structuredContent"] == {"paid": "I2"}


def test_the_recorder_refuses_a_registry_change_the_directory_refuses(gateway):
    gw, log, c, rec, _ = gateway
    with pytest.raises(webauthn.WebAuthnError, match="no confirmation"):
        rec.passkey_enrolled(CFO, identity=IDENTITY, credential_id=B.credential_id,
                             public_key=B.cose_key, rp_id=B.rp_id, origin=B.origin)
    assert B.credential_id not in gw.passkey_directory.creds


def _folder(g, tmp_path, pr):
    """An evidence folder around the gateway's trail, as `aeos audit` reads it."""
    import shutil
    from aeos import witness
    gw, log, c, rec, ctx = g
    folder = tmp_path / "folder"
    (folder / "trust").mkdir(parents=True)
    (folder / "svids").mkdir()
    (folder / "policies").mkdir()
    shutil.copytree(log.path, folder / "log")
    (folder / "trust" / "bundle.pem").write_bytes(ctx["bundle"].read_bytes())
    for name, (cert, _) in ctx["files"].items():
        shutil.copy(cert, folder / "svids" / f"{name}.pem")
    rules = ctx["rules"]
    (folder / "policies" / f"{rules.sha256.hex()}.wasm").write_bytes(rules.wasm)
    (folder / "policies" / f"data-{rules.data_sha256.hex()}.json").write_text(json.dumps(DATA))
    (folder / "trust" / "principals.json").write_text(json.dumps(pr))
    wkey = Ed25519PrivateKey.generate()
    cp = log.checkpoint()
    w = witness.Witness("w1", wkey)
    witness.request_cosignatures(log, cp, [w])
    shutil.copy(log.path / "cosignatures.jsonl", folder / "log" / "cosignatures.jsonl")
    shutil.copy(log.path / "checkpoints.jsonl", folder / "log" / "checkpoints.jsonl")
    (folder / "witnesses.json").write_text(json.dumps(
        {"required": 1, "keys": {"w1": keys.public_bytes(wkey).hex()}}))
    (folder / "evidence.json").write_text(json.dumps({
        "format": "aeos-evidence/v0", "trust_domain": DOMAIN, "bundle": "trust/bundle.pem",
        "svids": "svids", "log": "log", "witnesses": "witnesses.json",
        "principals": "trust/principals.json", "policies": "policies"}))
    return folder


def test_a_full_folder_audit_checks_a_passkey_approval_and_names_the_caveat(gateway, tmp_path):
    gw, log, c, rec, ctx = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    ok = c.call(TOOL, args, approval=_approval(esc, A, 2, args))
    assert ok["result"]["structuredContent"] == {"paid": "I2"}
    folder = _folder(gateway, tmp_path, principals(witness_key=None))
    findings, problems = audit.run(folder)
    assert problems == []
    text = " | ".join(findings)
    assert "1 approval by passkey was checked from the evidence in the trail alone" in text
    assert "rest on identity evidence that this audit cannot check (" + CFO + " on oidc-sign-in" \
        in text and "pin the first passkey" in text
    assert "each of the 1 approvals is signed by its approver" in text
    assert "(not pinned in your principals)" in text
    # pinning the first passkey removes that trust, and says so
    (folder / "trust" / "principals.json").write_text(json.dumps(principals(pins=[pin(A)])))
    findings, problems = audit.run(folder)
    text = " | ".join(findings)
    assert problems == [] and "1 of them rest on a first passkey that you pinned" in text
    assert "cannot check (" + CFO not in text
    # a pin for another passkey makes the registry, and so the audit, fail
    (folder / "trust" / "principals.json").write_text(json.dumps(principals(pins=[pin(B)])))
    assert any("is not one you pinned" in p for p in audit.run(folder)[1])


# ---- the audit of a whole evidence folder ---------------------------------------------------


def test_ed25519_approvals_and_the_full_demo_audit_unchanged(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    findings, problems = audit.run(folder)
    assert problems == [] and not any("passkey" in f for f in findings)


def test_an_ed25519_decision_rests_on_its_approval_too(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    log = ActionLog.open(folder / "log", read_only=True)
    recs = [(e.index, bytes(e.cid), log.record(e)) for e in log.entries()]
    pdoc = json.loads((folder / "trust" / "principals.json").read_text())
    findings, problems, _ = audit.check_approvals(recs, pdoc)
    assert problems == []
    kept = [t for t in recs if t[2]["kind"] != "approval"]       # the approvals removed
    cut = audit.check_approvals(kept, pdoc)[1]
    assert any("not an earlier, verified approval of this call" in p for p in cut)


def test_a_gateway_signature_alone_is_not_proof_for_a_passkey_approver(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    pdoc = json.loads((folder / "trust" / "principals.json").read_text())
    pdoc[fulldemo.CFO] = {"type": "webauthn", "credentials": [],
                          "witness_key": pdoc[fulldemo.CFO]}      # its Ed25519 key, as a witness
    (tmp_path / "p.json").write_text(json.dumps(pdoc))
    _, problems = audit.run(folder, principals=tmp_path / "p.json")
    assert any("carries no passkey assertion" in p for p in problems)
    assert not any("signed by" in p for p in problems)


# ---- notes and findings ----------------------------------------------------------------------


def _find(name):
    return next(c for c in CASES if c[0] == name)


def test_a_gateway_signature_is_counted_only_when_it_verifies():
    _, trail, pr, _ = _find("valid approval that also carries a gateway witness signature")
    findings, problems, _ = audit.check_approvals(trail.triples(), pr)
    assert problems == [] and any("also carries the gateway's own signature, which verified"
                                  in f for f in findings)
    _, trail, pr, _ = _find("valid approval carrying a gateway signature that is not checked")
    findings, problems, _ = audit.check_approvals(trail.triples(), pr)
    assert problems == [] and any("carries a gateway signature that was not checked" in f
                                  for f in findings)
    assert not any("verified against the witness key" in f for f in findings)


def test_a_counter_that_does_not_rise_is_a_note_and_a_synced_zero_is_not():
    for name, expected in (("signature counter that does not rise", 1),
                           ("signature counter that falls", 1),
                           ("signature counter that rises", 0),
                           ("signature counter that stays at zero", 0)):
        _, trail, pr, _ = _find(name)
        findings, problems, notes = audit.check_approvals(trail.triples(), pr)
        assert problems == [] and sum("may have been cloned" in n for n in notes) == expected
        assert sum("may have been cloned" in f for f in findings) == 0   # run() adds them


def test_a_trail_with_a_pinned_and_an_unpinned_root_splits_the_finding():
    _, trail, pr, _ = _find("valid approval, first passkey pinned in the principals")
    findings, _, _ = audit.check_approvals(trail.triples(), pr)
    assert any("rest on a first passkey that you pinned" in f for f in findings)
    assert not any("cannot check (" in f for f in findings)
    _, trail, pr, _ = _find("valid single approval (ES256)")
    findings, _, notes = audit.check_approvals(trail.triples(), pr)
    assert any("rest on identity evidence that this audit cannot check (" in f for f in findings)
    assert any("not pinned in your principals" in n for n in notes)


# ---- verifiers never crash on malformed evidence ------------------------------------------------

ODD = [None, 0, 5, -1, True, "", "x", b"", b"\x00", b"\x00" * 31, b"\x00" * 33, [], [1], {}, {"a": 1},
       "x" * 300]


def _fuzz(trail, pr, rng, per_key):
    runs = 0
    for i, rec in enumerate(trail.records):
        for key in list(rec["body"]) + ["agent", "subject", "parents", "kind"]:
            for _ in range(per_key):
                records = copy.deepcopy(trail.records)
                target = records[i]
                odd = rng.choice(ODD)
                if key in target["body"]:
                    target["body"][key] = odd
                elif key in target:
                    target[key] = odd
                triples = [(j, cid_of_bytes(dag_cbor(r)) if j != i else b"\x01" * 36, r)
                           for j, r in enumerate(records)]
                audit.check_approvals(triples, pr)           # must not raise
                runs += 1
    return runs


def test_malformed_records_are_reported_never_raised():
    rng = random.Random(11)
    picks = [c for c in CASES if c[0] in (
        "valid single approval (ES256)", "batch of four, every approval verifies",
        "identity rebound after enrolment: the approval before verifies, the one after fails",
        "passkey revoked before the approval; an approval before the revocation still verifies",
        "batch signing a document, the one each decision acted on",
        "valid approval decided and allowed (the policy decision rests on it)",
        "rejection by a passkey approver on its sign-in evidence")]
    assert sum(_fuzz(t, pr, rng, 5) for _, t, pr, _ in picks) > 1000


def test_malformed_nested_evidence_is_reported_never_raised():
    rng = random.Random(5)
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2)
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), "", b"", batch=[(TOOL, json_digest(ARGS), e)]))
    for i, rec in enumerate(t.records):
        if rec["kind"] not in ("x-approval-evidence", "x-passkey-enrolled"):
            continue
        keys_ = list(rec["body"]) + list(rec["body"].get("registration", {}))
        for key in keys_:
            for odd in ODD:
                records = copy.deepcopy(t.records)
                if key in records[i]["body"]:
                    records[i]["body"][key] = odd
                else:
                    records[i]["body"]["registration"][key] = odd
                triples = [(j, cid_of_bytes(dag_cbor(r)), r) for j, r in enumerate(records)]
                audit.check_approvals(triples, principals())
        if "batch" in rec["body"]:
            for odd in ODD:
                for inner in ("context", "items"):
                    records = copy.deepcopy(t.records)
                    records[i]["body"]["batch"][inner] = odd
                    triples = [(j, cid_of_bytes(dag_cbor(r)), r) for j, r in enumerate(records)]
                    audit.check_approvals(triples, principals())
    for bad in ({"x": 1}, [], "x", {"A": {"type": "webauthn", "credentials": 5}},
                {"A": {"type": "other"}}, {"A": 5}):
        with pytest.raises((ValueError, TypeError, AttributeError)):
            passkeys.load_principals(bad)
