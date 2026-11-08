"""Attestation statements, the authenticator trust file, key classes and the hardware-key step-up."""
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import attestation_support as ats
from aeos import attestation, audit, cli, delegation, keys, mds, passkeys, policy, webauthn
from aeos.canon import dag_cbor, json_digest
from passkey_scenarios import ARGS, TOOL, TRUST, K, S, A
from webauthn_support import APPROVER, T0, SoftAuthenticator, Trail, nonce, principals, sign_in_of

W3C = json.loads((Path(__file__).parent / "fixtures" / "webauthn-l3-registrations.json")
                 .read_text())
CH = webauthn.enrol_challenge(APPROVER, sign_in_of("a@acme.example").sha256)
BE_BS = webauthn.FLAG_BE | webauthn.FLAG_BS


def _register(auth, reg):
    return webauthn.verify_registration(reg["client_data_json"], reg["attestation_object"],
                                        rp_id=auth.rp_id, origin=auth.origin, challenge=CH,
                                        credential_id=auth.credential_id,
                                        public_key=auth.cose_key)


def _reg(auth, fmt, attest, *, aaguid=None, flags=0):
    return auth.registration(CH, fmt=fmt, attest=attest, flags=flags,
                             aaguid=ats.aaguid(ats.KEY_MODEL) if aaguid is None else aaguid)


def _class(reg, trust=TRUST, at=T0):
    t = None if trust is None else attestation.AuthenticatorTrust.load(trust)
    return attestation.key_class(reg.statement, reg.flags, reg.aaguid, t, at)


# ---- an independent source: the W3C's own registration examples ---------------------------


def _w3c_parts(v):
    ao = bytes.fromhex(v["attestation_object"])
    obj, _ = webauthn.decode_cbor(ao, canonical=False)
    ad = obj["authData"]
    n = int.from_bytes(ad[53:55], "big")
    _, end = webauthn._cose_fields(ad, 55 + n)
    return obj, ad, ad[55:55 + n], ad[55 + n:end]


@pytest.mark.parametrize("v", W3C["registrations"], ids=[v["name"] for v in W3C["registrations"]])
def test_every_w3c_registration_example_verifies_and_chains_to_the_w3c_ca(v):
    root = x509.load_der_x509_certificate(bytes.fromhex(W3C["attestation_ca_cert"]))
    obj, ad, cred_id, cose = _w3c_parts(v)
    cdj = bytes.fromhex(v["client_data_json"])
    try:
        alg, key = webauthn.parse_cose_key(cose)
    except webauthn.WebAuthnError:       # ES384, ES512, RS256 and Ed448 credentials
        alg, key = None, None
    if obj["fmt"] == "packed" and "x5c" in obj["attStmt"] or alg is not None:
        st = attestation.verify_statement(obj["fmt"], obj["attStmt"], ad,
                                          hashlib.sha256(cdj).digest(), ad[37:53], alg, key)
        if st.x5c:
            assert attestation.chain_problem(st.x5c, [root], T0) is None
    if alg is not None and ad[32] & webauthn.FLAG_UV:
        def register():
            return webauthn.verify_registration(
                cdj, bytes.fromhex(v["attestation_object"]), rp_id=W3C["rp_id"],
                origin=W3C["origin"], challenge=bytes.fromhex(v["challenge"]),
                credential_id=cred_id, public_key=cose)
        if "Origin" in v["name"]:            # AE-OS refuses a cross-origin ceremony
            with pytest.raises(webauthn.WebAuthnError, match="cross-origin"):
                register()
        else:
            assert register().statement.fmt == obj["fmt"]


def test_the_w3c_examples_get_the_key_class_their_flags_and_chains_give():
    by_name = {v["name"]: v for v in W3C["registrations"]}
    root = base64.b64encode(bytes.fromhex(W3C["attestation_ca_cert"])).decode()
    u2f = by_name["FIDO U2F Attestation with ES256 Credential"]
    obj, ad, _, cose = _w3c_parts(u2f)
    leaf = x509.load_der_x509_certificate(obj["attStmt"]["x5c"][0])
    trust = attestation.AuthenticatorTrust.load(attestation.trust_doc([
        {"description": "W3C example U2F key", "device_bound": True,
         "attestation_root_certificates": [root],
         "attestation_certificate_key_identifiers": [ats.key_id(leaf).hex()]}], "W3C examples"))
    alg, key = webauthn.parse_cose_key(cose)
    cdh = hashlib.sha256(bytes.fromhex(u2f["client_data_json"])).digest()
    st = attestation.verify_statement("fido-u2f", obj["attStmt"], ad, cdh, ad[37:53], alg, key)
    assert attestation.key_class(st, ad[32], ad[37:53], trust, T0)[0] == attestation.HARDWARE
    tpm = by_name["TPM Attestation with ES256 Credential"]      # its flags say backup eligible
    obj, ad, _, cose = _w3c_parts(tpm)
    alg, key = webauthn.parse_cose_key(cose)
    cdh = hashlib.sha256(bytes.fromhex(tpm["client_data_json"])).digest()
    st = attestation.verify_statement("tpm", obj["attStmt"], ad, cdh, ad[37:53], alg, key)
    assert attestation.key_class(st, ad[32], ad[37:53], trust, T0)[0] == attestation.SYNCED


# ---- each format, made by the synthetic makers ----------------------------------------------


@pytest.mark.parametrize("fmt,kind", [("packed", "basic"), ("tpm", "attca"),
                                      ("android-key", "basic"), ("apple", "anonca"),
                                      ("fido-u2f", "basic")])
def test_each_format_verifies_and_a_trusted_device_bound_model_is_a_hardware_key(fmt, kind):
    aaguid = bytes(16) if fmt == "fido-u2f" else ats.aaguid(ats.KEY_MODEL)
    reg = _register(K, _reg(K, fmt, ats.attester(fmt, K), aaguid=aaguid))
    assert (reg.statement.fmt, reg.statement.attestation) == (fmt, kind)
    assert _class(reg)[0] == attestation.HARDWARE
    assert _class(reg, trust=None) == (attestation.UNKNOWN,
                                       "no authenticator trust file was given to this audit")
    synced = _register(K, _reg(K, fmt, ats.attester(fmt, K), aaguid=aaguid, flags=BE_BS))
    assert _class(synced)[0] == attestation.SYNCED


def test_none_and_self_attestation_name_no_model():
    assert _class(_register(K, K.registration(CH)))[0] == attestation.UNKNOWN
    reg = _register(K, _reg(K, "packed", ats.attester("packed", K, self_attested=True)))
    assert reg.statement.attestation == "self"
    assert "self attestation" in _class(reg)[1]
    e = SoftAuthenticator("ed-key", alg=webauthn.COSE_EDDSA)
    reg = e.registration(CH, fmt="packed", attest=lambda ad, cdh: {
        "alg": -8, "sig": e.key.sign(ad + cdh)})
    assert webauthn.verify_registration(reg["client_data_json"], reg["attestation_object"],
                                        rp_id=e.rp_id, origin=e.origin, challenge=CH,
                                        credential_id=e.credential_id,
                                        public_key=e.cose_key).statement.attestation == "self"


def _stmt(fmt, mutate, **kw):
    base = ats.attester(fmt, K, **kw)
    return lambda ad, cdh: mutate(base(ad, cdh), ad, cdh)


def _leaf_stmt(fmt, leaf_fn):
    """A statement whose attestation certificate `leaf_fn(ad, cdh)` builds."""
    def attest(ad, cdh):
        leaf, key = leaf_fn(ad, cdh)
        if fmt == "packed":
            return ats.packed(ad, cdh, key, [leaf, ats.KEYWORKS.ca])
        if fmt == "tpm":
            return ats.tpm(ad, cdh, K.key, key, [leaf, ats.KEYWORKS.ca])
        if fmt == "android-key":
            return {"alg": -7, "sig": ats.es256(key, ad + cdh),
                    "x5c": [ats.der(leaf), ats.der(ats.KEYWORKS.ca)]}
        return {"x5c": [ats.der(leaf), ats.der(ats.KEYWORKS.ca)]}
    return attest


AK = ats.p256_key("bent attestation key")
M = ats.KEYWORKS


def _set(d, **kv):
    return {**d, **kv}


BENT = [
    ("none with a statement", "none", lambda ad, cdh: {"sig": b"\x01"},
     "a none attestation carries an empty statement"),
    ("packed field it does not define", "packed",
     _stmt("packed", lambda s, ad, cdh: _set(s, ecdaaKeyId=b"\x01")), "does not define"),
    ("packed algorithm that is not the key's", "packed",
     _stmt("packed", lambda s, ad, cdh: _set(s, alg=-8)), "does not match its algorithm"),
    ("packed algorithm that is not supported", "packed",
     _stmt("packed", lambda s, ad, cdh: _set(s, alg=-65535)), "-65535 is not supported"),
    ("packed signature changed", "packed",
     _stmt("packed", lambda s, ad, cdh: _set(s, sig=s["sig"][:-1] + b"\x00")),
     "signature does not verify"),
    ("packed x5c that is not certificates", "packed",
     _stmt("packed", lambda s, ad, cdh: _set(s, x5c=[b"\x30\x00"])), "not DER X.509"),
    ("packed x5c that is empty", "packed",
     _stmt("packed", lambda s, ad, cdh: _set(s, x5c=[])), "x5c must be a list"),
    ("packed certificate without OU Authenticator Attestation", "packed",
     _leaf_stmt("packed", lambda ad, cdh: (M.leaf("k", AK, subject=x509.Name([
         x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "ZA"),
         x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Keyworks"),
         x509.NameAttribute(x509.NameOID.COMMON_NAME, "k")])), AK)),
     "subject is not C, O, OU=Authenticator Attestation and CN"),
    ("packed certificate that is a CA", "packed",
     _leaf_stmt("packed", lambda ad, cdh: (ats.cert(
         ats._name(C="ZA", O="Keyworks", OU="Authenticator Attestation", CN="k"),
         AK.public_key(), M.ca_name, M.ca_key, serial="ca leaf", ca=True), AK)),
     "is a CA certificate"),
    ("packed AAGUID extension marked critical", "packed",
     _leaf_stmt("packed", lambda ad, cdh: (M.leaf("k", AK, extensions=[
         (ats.aaguid_extension(ad[37:53]), True)]), AK)), "marked critical"),
    ("packed AAGUID extension malformed", "packed",
     _leaf_stmt("packed", lambda ad, cdh: (M.leaf("k", AK, extensions=[
         (x509.UnrecognizedExtension(attestation.OID_AAGUID, b"\x04\x02ab"), False)]), AK)),
     "AAGUID extension is malformed"),
    ("tpm version 1.2", "tpm", _stmt("tpm", lambda s, ad, cdh: _set(s, ver="1.2")),
     "not version 2.0"),
    ("tpm pubArea of another key", "tpm", _stmt("tpm", lambda s, ad, cdh: _set(
        s, pubArea=ats.tpm_pub_area(b"\x01" * 32, b"\x02" * 32))),
     "pubArea's key is not the credential public key"),
    ("tpm pubArea with trailing bytes", "tpm",
     _stmt("tpm", lambda s, ad, cdh: _set(s, pubArea=s["pubArea"] + b"\x00")),
     "trailing bytes"),
    ("tpm certInfo with the wrong magic", "tpm",
     _stmt("tpm", lambda s, ad, cdh: _set(s, certInfo=b"\x00" + s["certInfo"][1:])),
     "TPM_GENERATED_VALUE"),
    ("tpm certInfo over another registration", "tpm", _stmt("tpm", lambda s, ad, cdh: _set(
        s, certInfo=ats.tpm_cert_info(s["pubArea"], bytes(32)))),
     "extraData is not the digest"),
    ("tpm certInfo naming another key", "tpm", _stmt("tpm", lambda s, ad, cdh: _set(
        s, certInfo=ats.tpm_cert_info(ats.tpm_pub_area(b"\x01" * 32, b"\x02" * 32),
                                      hashlib.sha256(ad + cdh).digest()))),
     "does not name the pubArea"),
    ("tpm truncated certInfo", "tpm",
     _stmt("tpm", lambda s, ad, cdh: _set(s, certInfo=s["certInfo"][:20])), "truncated"),
    ("tpm attestation certificate with a subject", "tpm", _leaf_stmt("tpm", lambda ad, cdh: (
        M.leaf("tpm", AK, extensions=ats.tpm_aik_extensions()), AK)),
     "empty subject"),
    ("tpm attestation certificate without its EKU", "tpm", _leaf_stmt("tpm", lambda ad, cdh: (
        M.leaf("tpm", AK, subject=x509.Name([]), extensions=ats.tpm_aik_extensions()[:1]), AK)),
     "tcg-kp-AIKCertificate"),
    ("tpm attestation certificate without the TPM's names", "tpm", _leaf_stmt(
        "tpm", lambda ad, cdh: (M.leaf("tpm", AK, subject=x509.Name([]),
                                       extensions=ats.tpm_aik_extensions()[1:]), AK)),
     "manufacturer, model and version"),
    ("android-key for another challenge", "android-key", _leaf_stmt(
        "android-key", lambda ad, cdh: (M.leaf("a", K.key, extensions=[
            (ats.android_key_description(bytes(32)), False)]), K.key)),
     "challenge is not the client data hash"),
    ("android-key certificate of another key", "android-key", _leaf_stmt(
        "android-key", lambda ad, cdh: (M.leaf("a", AK, extensions=[
            (ats.android_key_description(cdh), False)]), AK)),
     "certificate's key is not the credential key"),
    ("android-key without a key description", "android-key", _leaf_stmt(
        "android-key", lambda ad, cdh: (M.leaf("a", K.key), K.key)),
     "no Android key description"),
    ("apple nonce for another registration", "apple", _leaf_stmt(
        "apple", lambda ad, cdh: (M.leaf("p", K.key, extensions=[
            (ats.apple_nonce(ad, bytes(32)), False)]), K.key)),
     "nonce is not for this registration"),
    ("apple certificate of another key", "apple", _leaf_stmt(
        "apple", lambda ad, cdh: (M.leaf("p", AK, extensions=[
            (ats.apple_nonce(ad, cdh), False)]), AK)),
     "certificate's key is not the credential key"),
    ("apple without a nonce", "apple", _leaf_stmt(
        "apple", lambda ad, cdh: (M.leaf("p", K.key), K.key)), "has no nonce"),
    ("fido-u2f with two certificates", "fido-u2f", _stmt(
        "fido-u2f", lambda s, ad, cdh: _set(s, x5c=s["x5c"] + [ats.der(M.ca)])),
     "exactly one certificate"),
    ("fido-u2f signature over another registration", "fido-u2f", _stmt(
        "fido-u2f", lambda s, ad, cdh: _set(s, sig=ats.u2f(ad, bytes(32), ats.p256_key(
            "Keyworks Key 5 u2f"), K.key, ats.u2f_leaf(M, ats.KEY_MODEL, ats.p256_key(
                "Keyworks Key 5 u2f")))["sig"])), "signature does not verify"),
]


@pytest.mark.parametrize("name,fmt,attest,why", BENT, ids=[b[0] for b in BENT])
def test_a_bent_statement_is_refused_and_says_why(name, fmt, attest, why):
    reg = _reg(K, fmt, attest)
    with pytest.raises(webauthn.WebAuthnError) as e:
        _register(K, reg)
    assert why in str(e.value) and "attestation statement does not verify" in str(e.value)


def test_android_key_with_all_applications_is_refused():
    def attest(ad, cdh):
        ext = ats.android_key_description(cdh)
        raw = ext.value
        # add allApplications [600] NULL to the TEE list (the last SEQUENCE)
        extra = b"\xbf\x84\x58\x02\x05\x00"
        inner = raw[2:] if raw[1] < 0x80 else raw[2 + (raw[1] & 0x7F):]
        tee_at = inner.rindex(b"\x30")
        tee = inner[tee_at:]
        tee = ats._der(0x30, tee[2:] + extra)
        bent = ats._der(0x30, inner[:tee_at] + tee)
        leaf = M.leaf("a", K.key, extensions=[(x509.UnrecognizedExtension(
            attestation.OID_ANDROID_KEY, bent), False)])
        return {"alg": -7, "sig": ats.es256(K.key, ad + cdh), "x5c": [ats.der(leaf)]}
    with pytest.raises(webauthn.WebAuthnError, match="allApplications"):
        _register(K, _reg(K, "android-key", attest))


def test_fido_u2f_needs_an_es256_credential_and_a_p256_certificate():
    e = SoftAuthenticator("ed-u2f", alg=webauthn.COSE_EDDSA)
    reg = e.registration(CH, fmt="fido-u2f", attest=lambda ad, cdh: {
        "sig": b"\x01", "x5c": [ats.der(ats.u2f_leaf(M, "x", ats.p256_key("x")))]})
    with pytest.raises(webauthn.WebAuthnError, match="must be an ES256 key"):
        webauthn.verify_registration(reg["client_data_json"], reg["attestation_object"],
                                     rp_id=e.rp_id, origin=e.origin, challenge=CH,
                                     credential_id=e.credential_id, public_key=e.cose_key)
    ed_leaf = ats.cert(ats._name(CN="u2f"), Ed25519PrivateKey.generate().public_key(),
                       M.root_name, M.root_key, serial="ed u2f", ca=False)
    with pytest.raises(webauthn.WebAuthnError, match="not a P-256 key"):
        _register(K, _reg(K, "fido-u2f", lambda ad, cdh: {"sig": b"\x01",
                                                          "x5c": [ats.der(ed_leaf)]}))


def test_rsa_attestation_signatures_verify_and_short_keys_do_not():
    key = rsa.generate_private_key(65537, 2048)
    leaf = M.leaf("rsa model", key)

    def attest(alg, pad):
        return lambda ad, cdh: {"alg": alg, "sig": key.sign(ad + cdh, pad, hashes.SHA256()),
                                "x5c": [ats.der(leaf), ats.der(M.ca)]}
    pss = padding.PSS(padding.MGF1(hashes.SHA256()), 32)
    assert _register(K, _reg(K, "packed", attest(-257, padding.PKCS1v15()))).statement.x5c
    assert _register(K, _reg(K, "packed", attest(-37, pss))).statement.x5c
    with pytest.raises(webauthn.WebAuthnError, match="signature does not verify"):
        _register(K, _reg(K, "packed", attest(-257, pss)))
    short = rsa.generate_private_key(65537, 1024)
    short_leaf = M.leaf("short rsa", short)
    with pytest.raises(webauthn.WebAuthnError, match="shorter than 2048 bits"):
        _register(K, _reg(K, "packed", lambda ad, cdh: {
            "alg": -257, "sig": short.sign(ad + cdh, padding.PKCS1v15(), hashes.SHA256()),
            "x5c": [ats.der(short_leaf)]}))


def test_an_attestation_object_may_list_its_keys_in_any_order_but_never_repeat_one():
    reg = _reg(K, "packed", ats.attester("packed", K))
    obj, _ = webauthn.decode_cbor(reg["attestation_object"])
    def enc_text(t):
        return bytes([0x60 | len(t)]) + t.encode()
    body = webauthn.decode_cbor(reg["attestation_object"])[0]
    reordered = (b"\xa3" + enc_text("authData") + dag_cbor(body["authData"])
                 + enc_text("fmt") + dag_cbor("packed") + enc_text("attStmt")
                 + dag_cbor(body["attStmt"]))
    assert webauthn.verify_registration(reg["client_data_json"], reordered, rp_id=K.rp_id,
                                        origin=K.origin, challenge=CH,
                                        credential_id=K.credential_id,
                                        public_key=K.cose_key).statement.fmt == "packed"
    repeated = b"\xa3" + enc_text("fmt") + dag_cbor("none") + enc_text("fmt") + dag_cbor("none") \
        + enc_text("authData") + dag_cbor(body["authData"])
    with pytest.raises(webauthn.WebAuthnError, match="repeats a key"):
        webauthn.verify_registration(reg["client_data_json"], repeated, rp_id=K.rp_id,
                                     origin=K.origin, challenge=CH,
                                     credential_id=K.credential_id, public_key=K.cose_key)
    assert obj["fmt"] == "packed"


# ---- the chain and the trust file -------------------------------------------------------------


def test_the_chain_must_lead_to_a_trusted_root_through_cas_valid_at_the_time():
    key = ats.p256_key("chain leaf")
    leaf = M.leaf("chain", key)
    chain = [ats.der(leaf), ats.der(M.ca)]
    assert attestation.chain_problem(chain, [M.root], T0) is None
    assert attestation.chain_problem(chain + [ats.der(M.root)], [M.root], T0) is None
    assert "does not lead to a root" in attestation.chain_problem(chain, [ats.SYNCWORKS.root], T0)
    assert "not valid at the time" in attestation.chain_problem(
        chain, [M.root], int(dt.datetime(2050, 1, 1).timestamp() * 1000))
    assert "not signed by the next one" in attestation.chain_problem(
        [ats.der(leaf), ats.der(ats.SYNCWORKS.ca)], [M.root], T0)
    not_ca = M.leaf("not a ca", ats.p256_key("not a ca"))
    assert "not a CA" in attestation.chain_problem([ats.der(leaf), ats.der(not_ca)],
                                                   [M.root], T0)
    # the root allows one intermediate; two are too many
    deep_key = ed = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    deep = ats.cert(ats._name(CN="deeper CA"), ed.public_key(), M.ca_name, M.ca_key,
                    serial="deep", ca=True)
    deep_leaf = ats.cert(ats._name(CN="deep leaf"), key.public_key(), ats._name(CN="deeper CA"),
                         deep_key, serial="deep leaf", ca=False)
    assert "path length" in attestation.chain_problem(
        [ats.der(deep_leaf), ats.der(deep), ats.der(M.ca)], [M.root], T0)


@pytest.mark.parametrize("doc,why", [
    ({"format": "x"}, "is not aeos-authenticator-trust/v1"),
    ({"format": attestation.TRUST_FORMAT}, "no list of authenticators"),
    (attestation.trust_doc([{"device_bound": "yes"}], ""), "device_bound must be"),
    (attestation.trust_doc([{"device_bound": True, "aaguid": "NOT-A-UUID"}], ""),
     "lower-case UUID"),
    (attestation.trust_doc([{"device_bound": True,
                             "aaguid": "00000000-0000-0000-0000-000000000000"}], ""),
     "all-zero AAGUID"),
    (attestation.trust_doc([{"device_bound": True,
                             "attestation_certificate_key_identifiers": ["AB"]}], ""),
     "lower-case hex SHA-1"),
    (attestation.trust_doc([{"device_bound": True}], ""), "needs an aaguid"),
    (attestation.trust_doc([{"device_bound": True, "aaguid": str(
        __import__("uuid").UUID(bytes=ats.aaguid("x")))}], ""), "needs attestation_root"),
    (attestation.trust_doc([{"device_bound": True, "aaguid": str(
        __import__("uuid").UUID(bytes=ats.aaguid("x"))),
        "attestation_root_certificates": ["not base64!"]}], ""), "not base64 DER"),
    (attestation.trust_doc([TRUST["authenticators"][0], TRUST["authenticators"][0]], ""),
     "names a model another entry names"),
])
def test_a_malformed_trust_file_is_refused_and_says_why(doc, why):
    with pytest.raises(ValueError, match=why):
        attestation.AuthenticatorTrust.load(doc)


# ---- what an assertion record states ------------------------------------------------------


def test_evidence_states_its_key_class_and_flags_and_a_contradiction_is_refused():
    ev = K.evidence(nonce(1), TOOL, json_digest(ARGS), b"\x01" * 36, flags=BE_BS)
    body = ev.claimed("synced").body()
    assert (body["key_class"], body["backup_eligible"], body["backup_state"]) == \
        ("synced", True, True)
    assert passkeys.Evidence.parse(body).key_class == "synced"
    assert passkeys.Evidence.from_json(ev.claimed("synced").to_json()) == ev.claimed("synced")
    assert "key_class" not in ev.body()
    for bent, why in (({"key_class": "unknown"}, "contradicts its backup eligibility"),
                      ({"backup_state": False}, "does not carry"),
                      ({"key_class": "titanium"}, "not all there"),
                      ({"backup_eligible": None}, "not all there")):
        with pytest.raises(webauthn.WebAuthnError, match=why):
            passkeys.Evidence.parse({**body, **bent})


def test_an_ed25519_approval_cannot_meet_a_hardware_key_step_up():
    key = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    pr = {APPROVER: keys.public_bytes(key).hex()}
    for requires, expect in ((None, []), (attestation.HARDWARE_KEY, ["only a passkey approval"])):
        t = Trail()
        _, c, e = t.escalated_call(ARGS, requires=requires)
        t.approve(c, e, TOOL, ARGS, None, witness=key)
        problems = audit.check_approvals(t.triples(), pr)[1]
        assert len(problems) == len(expect) and all(w in p for w, p in zip(expect, problems))


def test_a_later_assertion_that_changes_backup_eligibility_fails_even_without_registration():
    t = Trail()
    t.enrol(A)
    t.enrol(S, confirmed_by=A, n=2)                       # added with no registration response
    for n, flags in ((3, BE_BS), (4, 0)):
        a = {"invoice": f"I{n}", "amount_minor": 900}
        _, c, e = t.escalated_call(a)
        t.approve(c, e, TOOL, a, S.evidence(nonce(n), TOOL, json_digest(a), e, flags=flags))
    _, problems, notes = audit.check_approvals(t.triples(), principals(), authenticators=TRUST)
    assert len(problems) == 1 and "changed since it was first used" in problems[0]
    assert any("added without a registration response" in n for n in notes)


def test_an_honest_writer_with_older_trust_is_a_note_not_a_problem():
    t = Trail()
    t.enrol(K, registration=ats_registration(K), key_class="unknown")
    _, c, e = t.escalated_call(ARGS)
    t.approve(c, e, TOOL, ARGS, K.evidence(nonce(1), TOOL, json_digest(ARGS), e)
              .claimed("unknown"))
    findings, problems, notes = audit.check_approvals(t.triples(), principals(),
                                                      authenticators=TRUST)
    assert problems == []
    assert any("the enrolment says the passkey is a passkey of unknown kind, but it is a "
               "hardware security key" in n for n in notes)
    assert any("the evidence says a passkey of unknown kind made the approval, but it was a "
               "hardware security key (with the authenticator trust you gave)" in n
               for n in notes)
    assert "By key class: 1 made with a hardware security key" in findings


def ats_registration(auth):
    return auth.registration(CH, fmt="packed", attest=ats.attester("packed", auth),
                             aaguid=ats.aaguid(ats.KEY_MODEL))


# ---- the step-up, live: the policy asks for it, the gateway enforces it, the audit checks it --


def test_a_policy_may_require_a_hardware_key_only_on_an_escalation():
    from aeos import fulldemo
    rules = policy.Policy.load(fulldemo.POLICY_WASM, {
        "escalate_above_minor": 500, "hardware_key_above_minor": 800, "sanctioned_vendors": [],
        "approvers": [APPROVER]}, "aeos/payments/decision")
    inv = {"vendor": "V1", "amount_minor": 900, "status": "approved for payment"}
    d = rules.evaluate({"tool": TOOL, "arguments": ARGS, "invoice": inv})
    assert d["decision"] == "escalate" and d["requires"] == attestation.HARDWARE_KEY
    small = {"invoice": "I2", "amount_minor": 700}
    assert "requires" not in rules.evaluate({"tool": TOOL, "arguments": small,
                                             "invoice": dict(inv, amount_minor=700)})
    for bad in ({"decision": "allow", "requires": "hardware-key"},
                {"decision": "escalate", "requires": "smart-card"}):
        with pytest.raises(policy.PolicyError, match="requires something other"):
            policy.answer(bad)


DATA = {"escalate_above_minor": 500, "hardware_key_above_minor": 800, "sanctioned_vendors": [],
        "approvers": [APPROVER]}


@pytest.fixture
def stepped(tmp_path):
    """A gateway whose payment rules want a hardware key above 800, and an approver with a
    synced passkey (the first) and a hardware security key added by it."""
    import test_passkeys as tp
    from aeos import Recorder, fulldemo, identity
    from aeos.gateway import AgentClient, Gateway
    from aeos.log import ActionLog, now_ms
    td = identity.TrustDomain(tp.DOMAIN)
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(td.bundle_pem())
    files = {n: td.issue(i).write(tmp_path / "svid", n) for n, i in (("gw", tp.GATEWAY),
                                                                      ("ap", tp.AGENT))}
    person = Ed25519PrivateKey.generate()
    env = delegation.IntentEnvelope(tp.PERSON, tp.AGENT, "pay", [TOOL], 10_000, 10_000, "USD",
                                    now_ms() + 3_600_000).sign(person)
    auth = delegation.Authority()
    token = auth.mint(env, keys.public_bytes(person))
    log = ActionLog.create(tmp_path / "log", log_id="urn:example:stepped")
    directory = passkeys.Directory(passkeys.load_principals(principals())[1],
                                   authenticators=attestation.AuthenticatorTrust.load(TRUST))
    rec = Recorder(log, agent=APPROVER, passkeys=directory)
    sign_in = sign_in_of(tp.IDENTITY)
    rec.passkey_enrolled(APPROVER, identity=tp.IDENTITY, credential_id=S.credential_id,
                         public_key=S.cose_key, rp_id=S.rp_id, origin=S.origin,
                         identity_evidence=sign_in, registration=S.registration(
                             webauthn.enrol_challenge(APPROVER, sign_in.sha256), fmt="apple",
                             attest=ats.attester("apple", S, model=ats.CLOUD_MODEL),
                             flags=BE_BS, aaguid=ats.aaguid(ats.CLOUD_MODEL)))
    args = passkeys.enrol_args_sha256(APPROVER, tp.IDENTITY, K.credential_id, K.cose_key,
                                      K.rp_id, K.origin)
    rec.passkey_enrolled(APPROVER, identity=tp.IDENTITY, credential_id=K.credential_id,
                         public_key=K.cose_key, rp_id=K.rp_id, origin=K.origin,
                         registration=K.registration(
                             webauthn.add_challenge(APPROVER, tp.IDENTITY), fmt="tpm",
                             attest=ats.attester("tpm", K, model=ats.TPM_MODEL),
                             aaguid=ats.aaguid(ats.TPM_MODEL)),
                         confirmation=S.evidence(nonce(50), passkeys.ENROL_TOOL, args,
                                                 flags=BE_BS))
    rules = policy.Policy.load(fulldemo.POLICY_WASM, DATA, "aeos/payments/decision")
    gw = Gateway(log, {TOOL: lambda a: {"paid": a["invoice"]}}, permissions={tp.AGENT: [TOOL]},
                 trust_domain=tp.DOMAIN, svid_files=files["gw"], bundle_file=bundle,
                 authority_key=auth.public_key, intents={env.cid: env},
                 principal_keys={tp.PERSON: keys.public_bytes(person)}, policy=rules,
                 policy_facts=lambda t, a: {"invoice": tp.INVOICES[a["invoice"]]}
                 if a.get("invoice") in tp.INVOICES else {}, passkey_directory=directory)
    port = gw.start()
    c = AgentClient(port, files["ap"], bundle, gateway_id=tp.GATEWAY, trust_domain=tp.DOMAIN,
                    token=token.to_bytes())
    c.initialize()
    yield gw, log, c, rec, {"td": td, "tmp": tmp_path, "rules": rules, "files": files,
                           "bundle": bundle}
    gw.stop()


def _approval(esc, auth, n, args, flags=0):
    from aeos.log import now_ms
    ev = auth.evidence(nonce(n), TOOL, json_digest(args), passkeys.escalation_cid(esc),
                       flags=flags)
    return delegation.Approval(esc, APPROVER, "approve", TOOL, json_digest(args), now_ms(),
                               evidence=ev)


def _text(reply):
    return reply["result"]["content"][0]["text"]


def test_the_gateway_asks_for_a_hardware_key_and_takes_only_one(stepped, tmp_path):
    import test_passkeys as tp
    gw, log, c, rec, ctx = stepped
    args = {"invoice": "I2", "amount_minor": 900}
    reply = c.call(TOOL, args)["result"]
    esc = reply["structuredContent"]["escalation"]
    assert reply["structuredContent"]["requires"] == attestation.HARDWARE_KEY
    assert "with a hardware security key" in reply["content"][0]["text"]
    refused = _text(c.call(TOOL, args, approval=_approval(esc, S, 1, args, flags=BE_BS)))
    assert "requires a hardware security key, but the approval was made with a synced " \
        "passkey" in refused
    ok = c.call(TOOL, args, approval=_approval(esc, K, 2, args))
    assert ok["result"]["structuredContent"] == {"paid": "I2"}
    recs = [(e.index, bytes(e.cid), log.record(e)) for e in log.entries()]
    enrolled = [r["body"]["key_class"] for _, _, r in recs if r["kind"] == "x-passkey-enrolled"]
    assert enrolled == ["synced", "hardware"]
    stated = [(r["body"]["key_class"], r["body"]["backup_eligible"], r["body"]["backup_state"])
              for _, _, r in recs if r["kind"] == "x-approval-evidence"]
    assert stated == [("synced", True, True), ("hardware", False, False)]
    esc_rec = next(r for _, _, r in recs if r["kind"] == "policy.decision"
                   and r["body"]["decision"] == "escalate")
    assert esc_rec["body"]["requires"] == attestation.HARDWARE_KEY
    findings, problems, _ = audit.check_approvals(recs, principals(), authenticators=TRUST)
    assert problems == [] and "1 of them answers an escalation that required a hardware " \
        "security key, and it was made with one" in findings
    # without the trust file the hardware key cannot be shown to be one
    problems = audit.check_approvals(recs, principals())[1]
    assert any("given no authenticator trust file" in p for p in problems)
    # the whole folder, with the policy replayed and the trust file named by the auditor
    folder = tp._folder(stepped, tmp_path, principals())
    (folder / "policies" / f"data-{ctx['rules'].data_sha256.hex()}.json").write_text(
        json.dumps(DATA))
    (tmp_path / "trust.json").write_text(json.dumps(TRUST))
    findings, problems = audit.run(folder, authenticators=tmp_path / "trust.json")
    assert problems == []
    text = " | ".join(findings)
    assert "the authenticator trust used lists 5 models (synthetic test roots" in text
    assert "is a hardware security key: its tpm attestation chains to a root you trust" in text
    # the same folder names its own trust file in evidence.json
    manifest = json.loads((folder / "evidence.json").read_text())
    (folder / "trust" / "authenticators.json").write_text(json.dumps(TRUST))
    manifest["authenticators"] = "trust/authenticators.json"
    (folder / "evidence.json").write_text(json.dumps(manifest))
    assert audit.run(folder)[1] == []
    (folder / "trust" / "authenticators.json").write_text("{}")
    assert any("authenticator trust file could not be read" in p for p in audit.run(folder)[1])
    assert cli.main(["audit", str(folder), "--authenticators", str(tmp_path / "trust.json")]) == 0


def test_a_requirement_dropped_from_the_record_is_caught_when_the_policy_runs_again(tmp_path):
    from aeos import fulldemo
    from aeos.canon import canonical_json
    from aeos.log import make_record
    rules = policy.Policy.load(fulldemo.POLICY_WASM, DATA, "aeos/payments/decision")
    (tmp_path / f"{rules.sha256.hex()}.wasm").write_bytes(rules.wasm)
    (tmp_path / f"data-{rules.data_sha256.hex()}.json").write_text(json.dumps(DATA))
    doc = {"tool": TOOL, "arguments": ARGS, "invoice": {
        "vendor": "V1", "amount_minor": 900, "status": "approved for payment"}}

    def decision(**extra):
        rec = make_record("policy.decision", "spiffe://acme.example/agent/ap", subject=TOOL,
                          body={"decision": "escalate", "policy": policy.POLICY, "reasons": [],
                                "policy_sha256": rules.sha256, "data_sha256": rules.data_sha256,
                                "entrypoint": rules.entrypoint,
                                "input_json": canonical_json(doc), **extra}, parents=[])
        return [(audit._At(0, b"\x01" * 36), rec)]

    for extra, expect in (({"requires": attestation.HARDWARE_KEY}, []),
                          ({}, ["recorded the requirement None, but the policy gives "
                                "'hardware-key'"])):
        findings, problems = [], []
        audit._check_policies(decision(**extra), tmp_path, {}, passkeys.Directory({}),
                              findings, problems)
        assert len(problems) == len(expect) and all(w in p for w, p in zip(expect, problems))


def test_an_ed25519_approver_cannot_answer_a_hardware_key_escalation_live(stepped):
    gw, log, c, rec, ctx = stepped
    from aeos.log import now_ms
    args = {"invoice": "I2", "amount_minor": 900}
    esc = c.call(TOOL, args)["result"]["structuredContent"]["escalation"]
    key = Ed25519PrivateKey.generate()
    gw.principal_keys["spiffe://acme.example/human/cfo/ed"] = keys.public_bytes(key)
    a = delegation.Approval(esc, "spiffe://acme.example/human/cfo/ed", "approve", TOOL,
                            json_digest(args), now_ms()).sign(key)
    assert "only a passkey approver can approve it" in _text(c.call(TOOL, args, approval=a))


# ---- the FIDO Metadata Service BLOB ---------------------------------------------------------


FIDO_ROOT_KEY = ats.p256_key("synthetic FIDO metadata root")
FIDO_ROOT_NAME = ats._name(C="ZA", O="Synthetic Metadata (test only)", CN="Metadata Root")
FIDO_ROOT = ats.cert(FIDO_ROOT_NAME, FIDO_ROOT_KEY.public_key(), FIDO_ROOT_NAME, FIDO_ROOT_KEY,
                     serial="mds root", ca=True)
SIGNER_KEY = ats.p256_key("synthetic FIDO metadata signer")
SIGNER = ats.cert(ats._name(CN="Metadata BLOB signer"), SIGNER_KEY.public_key(),
                  FIDO_ROOT_NAME, FIDO_ROOT_KEY, serial="mds signer", ca=False)


def _jwt(payload, *, key=SIGNER_KEY, chain=(SIGNER,), alg="ES256"):
    def enc(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")
    header = {"alg": alg, "typ": "JWT", "x5c": [base64.b64encode(ats.der(c)).decode()
                                                for c in chain]}
    signing = enc(json.dumps(header).encode()) + b"." + enc(json.dumps(payload).encode())
    der = key.sign(signing, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return signing + b"." + enc(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _mds_entry(model, *, protection=("hardware", "secure_element"), status="FIDO_CERTIFIED_L2",
               u2f=False):
    st = {"description": f"{model} (synthetic)", "keyProtection": list(protection),
          "attestationRootCertificates": [ats.b64(M.root)]}
    e = {"metadataStatement": st, "statusReports": [
        {"status": "FIDO_CERTIFIED", "effectiveDate": "2024-01-01"},
        {"status": status, "effectiveDate": "2025-01-01"}]}
    if u2f:
        e["attestationCertificateKeyIdentifiers"] = [ats.u2f_key_id().hex().upper()]
    else:
        e["aaguid"] = str(__import__("uuid").UUID(bytes=ats.aaguid(model)))
    return e


PAYLOAD = {"legalHeader": "synthetic", "no": 87, "nextUpdate": "2025-12-01", "entries": [
    _mds_entry(ats.KEY_MODEL), _mds_entry(ats.TPM_MODEL, protection=["hardware", "tee"]),
    _mds_entry("Soft One", protection=["software"]),
    _mds_entry("Leaky", status="ATTESTATION_KEY_COMPROMISE"),
    _mds_entry("U2F", u2f=True),
    {"metadataStatement": {"description": "no model"}}, "not an entry"]}


def test_a_metadata_blob_becomes_a_trust_file_that_classes_keys():
    root_pem = FIDO_ROOT.public_bytes(serialization.Encoding.PEM)
    doc, counts, warning = mds.import_blob(_jwt(PAYLOAD), root_pem, T0)
    assert counts == {"kept": 4, "device_bound": 3, "withdrawn": 1, "unusable": 2}
    assert warning is None and doc["source"].startswith("FIDO Metadata Service BLOB no. 87")
    trust = attestation.AuthenticatorTrust.load(doc)
    bound = {m.description: m.device_bound for m in trust.models}
    assert bound == {"Key 5 (synthetic)": True, "TPM 2 (synthetic)": True,
                     "Soft One (synthetic)": False, "U2F (synthetic)": True}
    reg = _register(K, _reg(K, "packed", ats.attester("packed", K)))
    assert attestation.key_class(reg.statement, reg.flags, reg.aaguid, trust, T0)[0] == \
        attestation.HARDWARE
    u2f = _register(K, _reg(K, "fido-u2f", ats.attester("fido-u2f", K), aaguid=bytes(16)))
    assert attestation.key_class(u2f.statement, u2f.flags, u2f.aaguid, trust, T0)[0] == \
        attestation.HARDWARE
    late = int(dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc).timestamp() * 1000)
    assert "next update was due on 2025-12-01" in mds.import_blob(_jwt(PAYLOAD), root_pem,
                                                                  late)[2]


def test_a_metadata_blob_that_does_not_stand_is_refused():
    root = ats.der(FIDO_ROOT)
    for blob, why in (
            (b"not a token", "not a JSON Web Token"),
            (_jwt(PAYLOAD)[:-4] + b"AAAA", "signature does not verify"),
            (_jwt(PAYLOAD, chain=(M.ca,)), "signing certificate does not stand"),
            (_jwt(PAYLOAD, alg="none"), "no supported algorithm"),
            (_jwt({"no": 1}), "no entries")):
        with pytest.raises(mds.MetadataError, match=why):
            mds.import_blob(blob, root, T0)
    with pytest.raises(mds.MetadataError, match="not PEM or DER"):
        mds.import_blob(_jwt(PAYLOAD), b"garbage", T0)


def test_the_authenticator_trust_command_writes_the_file(tmp_path, capsys):
    (tmp_path / "blob.jwt").write_bytes(_jwt(PAYLOAD))
    (tmp_path / "root.pem").write_bytes(FIDO_ROOT.public_bytes(serialization.Encoding.PEM))
    out = tmp_path / "trust.json"
    assert cli.main(["authenticator-trust", str(tmp_path / "blob.jwt"), "--root",
                     str(tmp_path / "root.pem"), "-o", str(out)]) == 0
    assert attestation.AuthenticatorTrust.load(json.loads(out.read_text())).models
    err = capsys.readouterr().err
    assert "4 authenticator models, 3 of them device-bound; left out 1 whose trust was " \
        "withdrawn" in err
    (tmp_path / "blob.jwt").write_bytes(b"x.y.z")
    assert cli.main(["authenticator-trust", str(tmp_path / "blob.jwt"), "--root",
                     str(tmp_path / "root.pem")]) == 1
