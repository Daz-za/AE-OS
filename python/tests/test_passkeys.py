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
                              nonce, principals)

VECTORS = Path(__file__).resolve().parents[2] / "testvectors" / "passkey-approvals-v1.json"
CASES = scenarios()


@pytest.mark.parametrize("name,trail,pr,expect", CASES, ids=[c[0] for c in CASES])
def test_each_scenario_gives_its_verdict(name, trail, pr, expect):
    findings, problems = audit.check_approvals(trail.triples(), pr)
    assert len(problems) == len(expect), problems
    for want, got in zip(expect, problems):
        assert want in got
    if not expect and any(r["kind"] == "approval" and r["body"]["decision"] == "approve"
                          for r in trail.records):
        assert findings and "checked from the evidence in the trail alone" in findings[0]


def test_a_verified_batch_is_reported_as_one_tap_with_several_approvals():
    name, trail, pr, _ = next(c for c in CASES if c[0] == "batch of four, every approval verifies")
    findings, problems = audit.check_approvals(trail.triples(), pr)
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
        assert audit.check_approvals(triples, c["principals"])[1] == c["expect_problems"], c["name"]
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
    rd = hashlib.sha256(b"aeos/request/v1\n" + tool.encode() + b"\n" + args).digest()
    assert rd.hex() == c["request_digest"]
    assert hashlib.sha256(b"aeos/approval-challenge/v1\n" + n + rd).hexdigest() == c["challenge"]
    body = b"\n".join(i["tool"].encode() + b"\0" + bytes.fromhex(i["args_sha256"])
                      for i in c["batch_items"])
    bd = hashlib.sha256(b"aeos/approval-batch/v1\n" + body).digest()
    assert bd.hex() == c["batch_digest"]
    assert hashlib.sha256(b"aeos/approval-challenge/v1\n" + n + bd).hexdigest() \
        == c["batch_challenge"]


# ---- the webauthn module ---------------------------------------------------------------------


def test_a_synced_passkey_with_a_counter_of_zero_verifies_and_the_counter_is_advisory():
    ch = webauthn.challenge_for(nonce(1), webauthn.request_digest(TOOL, json_digest(ARGS)))
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
        webauthn.batch_digest([])
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.batch_digest([("a\0b", b"\0" * 32)])
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.challenge_for(b"short", b"\0" * 32)
    assert webauthn.batch_digest([("a", b"\0" * 32), ("b", b"\1" * 32)]) != \
        webauthn.batch_digest([("b", b"\1" * 32), ("a", b"\0" * 32)])


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


def test_evidence_survives_json_and_an_approval_carries_it():
    ev = A.evidence(nonce(1), TOOL, json_digest(ARGS))
    again = passkeys.Evidence.from_json(json.loads(json.dumps(ev.to_json())))
    assert again == ev and again.assertion_sha256 == ev.assertion_sha256
    a = delegation.Approval("esc", APPROVER, "approve", TOOL, json_digest(ARGS), 5, evidence=ev)
    back = delegation.Approval.from_json(json.loads(json.dumps(a.to_json())))
    assert back.evidence == ev and back.signature == b""
    key = Ed25519PrivateKey.generate()
    signed = delegation.Approval("esc", APPROVER, "approve", TOOL, json_digest(ARGS), 5).sign(key)
    wire = delegation.Approval.from_json(json.loads(json.dumps(signed.to_json())))
    assert wire.verify(keys.public_bytes(key)) and wire.evidence is None


def test_evidence_that_is_not_what_it_says_is_refused():
    body = A.evidence(nonce(1), TOOL, json_digest(ARGS)).body()
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


# ---- the gateway accepts a passkey approval and the trail then audits ------------------------

DOMAIN = "acme.example"
AGENT = f"spiffe://{DOMAIN}/agent/ap"
GATEWAY = f"spiffe://{DOMAIN}/gateway/erp"
PERSON = f"spiffe://{DOMAIN}/human/controller"
CFO = APPROVER
DATA = {"escalate_above_minor": 500, "sanctioned_vendors": [], "approvers": [CFO]}
INVOICES = {"I2": {"vendor": "V1", "amount_minor": 900, "status": "approved for payment"}}


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
    rec = Recorder(log, agent=CFO)
    rec.passkey_enrolled(CFO, identity="a@acme.example", credential_id=A.credential_id,
                         public_key=A.cose_key, rp_id=A.rp_id, origin=A.origin,
                         identity_evidence={"kind": "oidc-sign-in", "ref": "s1",
                                            "sha256": b"\x01" * 32})
    records = [(e.index, bytes(e.cid), log.record(e)) for e in log.entries()]
    directory = passkeys.Directory.build(records, passkeys.load_principals(principals())[1])
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
    yield gw, log, c, rec
    gw.stop()


def _text(reply):
    return reply["result"]["content"][0]["text"]


def test_the_gateway_takes_a_passkey_approval_and_the_trail_audits(gateway):
    gw, log, c, _ = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]

    def approval(auth, n, **kw):
        ev = auth.evidence(nonce(n), TOOL, json_digest(args), **kw)
        return delegation.Approval(esc, CFO, "approve", TOOL, json_digest(args), now_ms(),
                                   evidence=ev)

    none = delegation.Approval(esc, CFO, "approve", TOOL, json_digest(args), now_ms())
    assert "no passkey assertion" in _text(c.call(TOOL, args, approval=none))
    assert "passkey's assertion was refused" in _text(
        c.call(TOOL, args, approval=approval(B, 1)))
    wrong = approval(A, 1)
    wrong = delegation.Approval(esc, CFO, "approve", TOOL, json_digest(args), now_ms(),
                                evidence=A.evidence(nonce(1), TOOL, json_digest({"x": 1})))
    assert "refused" in _text(c.call(TOOL, args, approval=wrong))
    rejection = delegation.Approval(esc, CFO, "reject", TOOL, json_digest(args), now_ms(),
                                    evidence=approval(A, 9).evidence)
    assert "a rejection carries" in _text(c.call(TOOL, args, approval=rejection))
    ok = c.call(TOOL, args, approval=approval(A, 2))
    assert ok["result"]["structuredContent"] == {"paid": "I2"}
    entries = log.entries()
    recs = [(e.index, bytes(e.cid), log.record(e)) for e in entries]
    assert [r["kind"] for _, _, r in recs].count("x-approval-evidence") == 1
    findings, problems = audit.check_approvals(recs, principals())
    assert problems == [] and "1 approval by passkey was checked" in findings[0]
    # the same trail with the evidence record removed no longer verifies
    stripped = [t for t in recs if t[2]["kind"] != "x-approval-evidence"]
    assert audit.check_approvals(stripped, principals())[1]


def test_the_gateway_refuses_the_same_assertion_twice(gateway):
    gw, log, c, _ = gateway
    args = {"invoice": "I2", "amount_minor": 900}
    gw.passkey_directory.ledger.use(0, A.evidence(nonce(5), TOOL, b"\0" * 32), "other", (TOOL, b""))
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    ev = A.evidence(nonce(5), TOOL, json_digest(args))
    a = delegation.Approval(esc, CFO, "approve", TOOL, json_digest(args), now_ms(), evidence=ev)
    assert "nonce was already used" in _text(c.call(TOOL, args, approval=a))


# ---- the audit of a whole evidence folder -------------------------------------------------------


def test_ed25519_approvals_and_the_full_demo_audit_unchanged(tmp_path):
    folder = tmp_path / "full"
    assert fulldemo.run(folder, out=lambda _: None) == 0
    findings, problems = audit.run(folder)
    assert problems == [] and not any("passkey" in f for f in findings)


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


# ---- verifiers never crash on malformed evidence ------------------------------------------------

ODD = [None, 0, 5, -1, True, "", "x", b"", b"\x00", b"\x00" * 31, b"\x00" * 33, [], [1], {}, {"a": 1},
       "x" * 300]


def test_malformed_records_are_reported_never_raised():
    rng = random.Random(11)
    picks = [c for c in CASES if c[0] in (
        "valid single approval (ES256)", "batch of four, every approval verifies",
        "identity rebound after enrolment: the approval before verifies, the one after fails",
        "passkey revoked before the approval; an approval before the revocation still verifies",
        "batch signing a document, the one each decision acted on")]
    runs = 0
    for _, trail, pr, _ in picks:
        for i, rec in enumerate(trail.records):
            for key in list(rec["body"]) + ["agent", "subject", "parents", "kind"]:
                for _ in range(6):
                    t2 = copy.copy(trail)
                    t2.records = copy.deepcopy(trail.records)
                    target = t2.records[i]
                    odd = rng.choice(ODD)
                    if key in target["body"]:
                        target["body"][key] = odd
                    elif key in target:
                        target[key] = odd if key != "parents" else odd
                    triples = [(j, cid_of_bytes(dag_cbor(r)) if j != i else b"\x01" * 36, r)
                               for j, r in enumerate(t2.records)]
                    audit.check_approvals(triples, pr)           # must not raise
                    runs += 1
    assert runs > 1000


def test_malformed_nested_evidence_is_reported_never_raised():
    rng = random.Random(5)
    t = Trail()
    t.enrol(A)
    t.enrol(B, confirmed_by=A, n=2)
    _, c, e = t.escalated_call(ARGS)
    items = [(TOOL, json_digest(ARGS))]
    t.approve(c, e, TOOL, ARGS, A.evidence(nonce(1), "", b"", batch=items))
    for i, rec in enumerate(t.records):
        if rec["kind"] != "x-approval-evidence":
            continue
        for key in list(rec["body"]):
            for odd in ODD:
                t2 = copy.deepcopy(t.records)
                t2[i]["body"][key] = odd
                triples = [(j, cid_of_bytes(dag_cbor(r)), r) for j, r in enumerate(t2)]
                audit.check_approvals(triples, principals())
        if "batch" in rec["body"]:
            for odd in ODD:
                for inner in ("context", "items"):
                    t2 = copy.deepcopy(t.records)
                    t2[i]["body"]["batch"][inner] = odd
                    triples = [(j, cid_of_bytes(dag_cbor(r)), r) for j, r in enumerate(t2)]
                    audit.check_approvals(triples, principals())
    for bad in ({"x": 1}, [], "x", {"A": {"type": "webauthn", "credentials": 5}},
                {"A": {"type": "other"}}, {"A": 5}):
        with pytest.raises((ValueError, TypeError, AttributeError)):
            passkeys.load_principals(bad)
