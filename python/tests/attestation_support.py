"""Synthetic authenticator makers for the attestation tests and the test vectors.

Every root, intermediate and attestation key here is derived from a public seed and every
certificate is built with fixed fields and deterministic signatures, so the vectors regenerate
byte for byte. None of it is a real maker's key or certificate: `Maker` plays the part of a
company that builds security keys, and `attestation_object` the part of its authenticator.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import struct
import uuid
from typing import Any, Dict, List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from aeos import attestation
from aeos.canon import dag_cbor

_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SEED = b"aeos attestation test vectors; never a real key: "
FROM = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
UNTIL = dt.datetime(2045, 1, 1, tzinfo=dt.timezone.utc)


def _raw(name: str) -> bytes:
    return hashlib.sha256(SEED + name.encode()).digest()


def ed_key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_raw(name))


def p256_key(name: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(_raw(name), "big") % (_N - 1) + 1,
                                 ec.SECP256R1())


def aaguid(name: str) -> bytes:
    return uuid.UUID(bytes=_raw("aaguid " + name)[:16], version=4).bytes


def _name(**attrs: str) -> x509.Name:
    oids = {"C": NameOID.COUNTRY_NAME, "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "CN": NameOID.COMMON_NAME}
    return x509.Name([x509.NameAttribute(oids[k], v) for k, v in attrs.items()])


def _serial(name: str) -> int:
    return int.from_bytes(_raw("serial " + name)[:8], "big") | 1


def _sign(builder: x509.CertificateBuilder, key: Any) -> x509.Certificate:
    if isinstance(key, Ed25519PrivateKey):
        return builder.sign(key, None)
    return builder.sign(key, hashes.SHA256(), ecdsa_deterministic=True)


def cert(subject: x509.Name, public_key: Any, issuer: x509.Name, issuer_key: Any, *,
         serial: str, ca: bool, pathlen: Optional[int] = None,
         extensions: Sequence[Any] = (), not_before: dt.datetime = FROM,
         not_after: dt.datetime = UNTIL) -> x509.Certificate:
    """A certificate; `extensions` are (extension, critical) pairs."""
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(public_key).serial_number(_serial(serial))
         .not_valid_before(not_before).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen if ca else None),
                        critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False,
                                          False), critical=True)
    for ext, critical in extensions:
        b = b.add_extension(ext, critical=critical)
    return _sign(b, issuer_key)


def der(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.DER)


def b64(c: x509.Certificate) -> str:
    return base64.b64encode(der(c)).decode()


def _der(tag: int, body: bytes) -> bytes:
    """One DER item: `tag` is the full identifier, as bytes for a high tag number."""
    n = len(body)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + \
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    return (tag if isinstance(tag, bytes) else bytes([tag])) + length + body


def aaguid_extension(value: bytes) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(attestation.OID_AAGUID, _der(0x04, value))


class Maker:
    """A synthetic maker of authenticators: a root, an intermediate under it, and one
    attestation key per model, all from seeds. `root_key` signs with Ed25519, or ECDSA."""

    def __init__(self, name: str, *, ecdsa_root: bool = False) -> None:
        self.name = name
        self.root_key: Any = p256_key(name + " root") if ecdsa_root else ed_key(name + " root")
        self.root_name = _name(C="ZA", O=f"{name} (synthetic)", CN=f"{name} Attestation Root")
        self.root = cert(self.root_name, self.root_key.public_key(), self.root_name,
                         self.root_key, serial=name + " root", ca=True, pathlen=1)
        self.ca_key = ed_key(name + " intermediate")
        self.ca_name = _name(C="ZA", O=f"{name} (synthetic)", CN=f"{name} Attestation CA")
        self.ca = cert(self.ca_name, self.ca_key.public_key(), self.root_name, self.root_key,
                       serial=name + " intermediate", ca=True, pathlen=0)

    def leaf(self, model: str, key: Any, *, aaguid_: Optional[bytes] = None,
             subject: Optional[x509.Name] = None, extensions: Sequence[Any] = (),
             not_after: dt.datetime = UNTIL, issuer: Optional[Any] = None) -> x509.Certificate:
        """An attestation certificate for `key`, issued by the intermediate (or by `issuer`, a
        (name, key) pair, to forge one)."""
        exts = list(extensions)
        if aaguid_ is not None:
            exts.append((aaguid_extension(aaguid_), False))
        name, signer = issuer if issuer is not None else (self.ca_name, self.ca_key)
        return cert(subject if subject is not None else _name(
            C="ZA", O=f"{self.name} (synthetic)", OU="Authenticator Attestation", CN=model),
            key.public_key(), name, signer, serial=f"{self.name} {model}", ca=False,
            extensions=exts, not_after=not_after)


def trust_entry(maker: Maker, model: str, *, aaguid_: Optional[bytes] = None,
                key_ids: Sequence[bytes] = (), device_bound: bool = True) -> Dict[str, Any]:
    e: Dict[str, Any] = {"description": f"{maker.name} {model} (synthetic)",
                         "device_bound": device_bound,
                         "attestation_root_certificates": [b64(maker.root)]}
    if aaguid_ is not None:
        e["aaguid"] = str(uuid.UUID(bytes=aaguid_))
    if key_ids:
        e["attestation_certificate_key_identifiers"] = [k.hex() for k in key_ids]
    return e


# ---- statements ---------------------------------------------------------------------------


def es256(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


def packed(auth_data: bytes, cdh: bytes, key: Any, chain: Sequence[x509.Certificate] = ()
           ) -> Dict[str, Any]:
    """A packed statement: full (with `chain`) or self (signed by the credential key)."""
    out: Dict[str, Any] = {"alg": -7, "sig": es256(key, auth_data + cdh)}
    if chain:
        out["x5c"] = [der(c) for c in chain]
    return out


def tpm_pub_area(x: bytes, y: bytes) -> bytes:
    """TPMT_PUBLIC for a P-256 signing key with no policy."""
    return (struct.pack(">HHI", 0x0023, 0x000B, 0x00060472) + struct.pack(">H", 0)
            + struct.pack(">HHHH", 0x0010, 0x0010, 0x0003, 0x0010)
            + struct.pack(">H", 32) + x + struct.pack(">H", 32) + y)


def tpm_cert_info(pub_area: bytes, extra: bytes) -> bytes:
    """TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY naming `pub_area`."""
    name = struct.pack(">H", 0x000B) + hashlib.sha256(pub_area).digest()
    tpm2b = lambda b: struct.pack(">H", len(b)) + b                      # noqa: E731
    return (struct.pack(">IH", 0xFF544347, 0x8017) + tpm2b(b"\x00\x0b" + b"\x11" * 32)
            + tpm2b(extra) + bytes(17) + bytes(8) + tpm2b(name) + tpm2b(b"\x00\x0b" + bytes(32)))


def tpm_aik_extensions() -> List[Any]:
    tpm = x509.DirectoryName(x509.Name([
        x509.NameAttribute(attestation.OID_TPM_MANUFACTURER, "id:53594E54"),
        x509.NameAttribute(attestation.OID_TPM_MODEL, "SynTPM"),
        x509.NameAttribute(attestation.OID_TPM_VERSION, "id:00010002")]))
    return [(x509.SubjectAlternativeName([tpm]), True),
            (x509.ExtendedKeyUsage([attestation.OID_TCG_KP_AIK]), False)]


def tpm(auth_data: bytes, cdh: bytes, credential: ec.EllipticCurvePrivateKey,
        aik: ec.EllipticCurvePrivateKey, chain: Sequence[x509.Certificate]) -> Dict[str, Any]:
    n = credential.public_key().public_numbers()
    pub = tpm_pub_area(n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big"))
    info = tpm_cert_info(pub, hashlib.sha256(auth_data + cdh).digest())
    return {"alg": -7, "certInfo": info, "pubArea": pub, "sig": es256(aik, info),
            "ver": "2.0", "x5c": [der(c) for c in chain]}


def android_key_description(cdh: bytes, *, tee: bool = True, level: int = 2,
                            keymaster: Optional[int] = None, purpose: int = 2
                            ) -> x509.UnrecognizedExtension:
    """KeyDescription: generated in secure hardware (`level` 2 StrongBox, 1 TEE, 0 software)
    for `purpose` (2 is SIGN), listed as hardware-enforced (or, with `tee` off, software)."""
    auth = (_der(0xA1, _der(0x31, _der(0x02, bytes([purpose]))))    # purpose [1] SET {..}
            + _der(b"\xbf\x85\x3e", _der(0x02, b"\x00")))           # origin [702] GENERATED
    km = level if keymaster is None else keymaster
    body = (_der(0x02, b"\x03") + _der(0x0A, bytes([level])) + _der(0x02, b"\x04")
            + _der(0x0A, bytes([km])) + _der(0x04, cdh) + _der(0x04, b"")
            + _der(0x30, b"" if tee else auth) + _der(0x30, auth if tee else b""))
    return x509.UnrecognizedExtension(attestation.OID_ANDROID_KEY, _der(0x30, body))


def apple_nonce(auth_data: bytes, cdh: bytes) -> x509.UnrecognizedExtension:
    nonce = hashlib.sha256(auth_data + cdh).digest()
    return x509.UnrecognizedExtension(attestation.OID_APPLE_NONCE,
                                      _der(0x30, _der(0xA1, _der(0x04, nonce))))


def u2f(auth_data: bytes, cdh: bytes, key: ec.EllipticCurvePrivateKey,
        credential: ec.EllipticCurvePrivateKey, leaf: x509.Certificate) -> Dict[str, Any]:
    n = struct.unpack(">H", auth_data[53:55])[0]
    point = credential.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
    data = b"\x00" + auth_data[:32] + cdh + auth_data[55:55 + n] + point
    return {"sig": es256(key, data), "x5c": [der(leaf)]}


def attestation_object(fmt: str, att_stmt: Dict[str, Any], auth_data: bytes) -> bytes:
    return dag_cbor({"fmt": fmt, "attStmt": att_stmt, "authData": auth_data})


def key_id(c: x509.Certificate) -> bytes:
    """The key identifier the FIDO Metadata Service lists a fido-u2f model by."""
    return x509.SubjectKeyIdentifier.from_public_key(c.public_key()).digest


# ---- whole registrations ------------------------------------------------------------------

KEYWORKS = Maker("Keyworks")                         # makes device-bound security keys
SYNCWORKS = Maker("Syncworks", ecdsa_root=True)      # a synced passkey provider
KEY_MODEL, TPM_MODEL, PHONE_MODEL, CLOUD_MODEL = "Key 5", "TPM 2", "Phone K", "Cloud"
FORGER = (KEYWORKS.ca_name, ed_key("a forger, not Keyworks"))


def attester(fmt: str, auth: Any, *, maker: Maker = KEYWORKS, model: str = KEY_MODEL,
             forged: bool = False, tee: bool = True, expired: bool = False,
             self_attested: bool = False, aaguid_ext: Optional[bytes] = None,
             bind_aaguid: bool = True, android_level: int = 2) -> Any:
    """`attest(authenticator_data, client_data_hash)` for a SoftAuthenticator `auth`: the
    statement a `maker`'s `model` makes in format `fmt`, or a bent one. Packed and TPM
    certificates name the model's AAGUID unless `bind_aaguid` is off."""
    issuer = FORGER if forged else None
    until = dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc) if expired else UNTIL

    def attest(ad: bytes, cdh: bytes) -> Dict[str, Any]:
        model_aaguid = ad[37:53]
        if fmt == "packed":
            if self_attested:
                return packed(ad, cdh, auth.key)
            key = p256_key(f"{maker.name} {model} attestation")
            leaf = maker.leaf(model, key, aaguid_=(aaguid_ext or model_aaguid) if bind_aaguid
                              else None, issuer=issuer, not_after=until)
            return packed(ad, cdh, key, [leaf, maker.ca])
        if fmt == "tpm":
            aik = p256_key(f"{maker.name} {model} aik")
            leaf = maker.leaf(model, aik, aaguid_=model_aaguid if bind_aaguid else None,
                              subject=x509.Name([]),
                              extensions=tpm_aik_extensions(), issuer=issuer, not_after=until)
            return tpm(ad, cdh, auth.key, aik, [leaf, maker.ca])
        if fmt == "android-key":
            leaf = maker.leaf(model, auth.key, extensions=[(android_key_description(
                cdh, tee=tee, level=android_level), False)], issuer=issuer, not_after=until)
            return {"alg": -7, "sig": es256(auth.key, ad + cdh), "x5c": [der(leaf), der(maker.ca)]}
        if fmt == "apple":
            leaf = maker.leaf(model, auth.key, extensions=[(apple_nonce(ad, cdh), False)],
                              issuer=issuer, not_after=until)
            return {"x5c": [der(leaf), der(maker.ca)]}
        if fmt == "fido-u2f":
            key = p256_key(f"{maker.name} {model} u2f")
            leaf = u2f_leaf(maker, model, key, forged=forged)
            return u2f(ad, cdh, key, auth.key, leaf)
        raise ValueError(fmt)

    return attest


def u2f_leaf(maker: Maker, model: str, key: Any, *, forged: bool = False) -> x509.Certificate:
    """A fido-u2f attestation certificate, issued by the maker's root itself."""
    name, signer = (maker.root_name, ed_key("a forger, not the root")) if forged else \
        (maker.root_name, maker.root_key)
    return cert(_name(CN=f"{maker.name} {model} U2F"), key.public_key(), name, signer,
                serial=f"{maker.name} {model} u2f", ca=False)


def u2f_key_id(maker: Maker = KEYWORKS, model: str = KEY_MODEL) -> bytes:
    return key_id(u2f_leaf(maker, model, p256_key(f"{maker.name} {model} u2f")))


def trust(*, device_bound: bool = True, models: Sequence[str] = (KEY_MODEL, TPM_MODEL,
                                                                    PHONE_MODEL)
          ) -> Dict[str, Any]:
    """The test trust file: Keyworks' models (device-bound unless told otherwise), its U2F
    key by key identifier, and Syncworks' cloud passkeys, which are not device-bound."""
    entries = [trust_entry(KEYWORKS, m, aaguid_=aaguid(m), device_bound=device_bound)
               for m in models]
    entries.append(trust_entry(KEYWORKS, "U2F", key_ids=[u2f_key_id()],
                               device_bound=device_bound))
    entries.append(trust_entry(SYNCWORKS, CLOUD_MODEL, aaguid_=aaguid(CLOUD_MODEL),
                               device_bound=False))
    return attestation.trust_doc(entries, "synthetic test roots; never trust them for real")
