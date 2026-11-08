"""WebAuthn attestation statements, the authenticator trust file, and the key class.

A registration response can carry an attestation statement: a signature by the authenticator's
maker over the new credential, which says which model of authenticator holds it. This module
verifies the statement formats of W3C WebAuthn Level 3, section 8 (`packed`, `tpm`,
`android-key`, `apple` and `fido-u2f`; `none` carries nothing to verify) offline, with
`cryptography` only, and then decides the credential's **key class**, deterministically:

    hardware   the attestation chains to a root the auditor trusts for an authenticator model
               listed as device-bound, and the credential is not backup eligible (BE is 0)
    synced     the credential is backup eligible (BE is 1): it can be copied to other devices
    unknown    anything else: no attestation, self attestation, a model or root not trusted

The roots and models come from an **authenticator trust file** the auditor supplies
(`aeos-authenticator-trust/v1`, usually exported from the FIDO Metadata Service with
`aeos authenticator-trust`); nothing is fetched at audit time. Certificates are checked for
validity at the time the enrolment record states.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import re
import struct
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

TRUST_FORMAT = "aeos-authenticator-trust/v1"
FORMATS = ("none", "packed", "tpm", "android-key", "apple", "fido-u2f")
HARDWARE, SYNCED, UNKNOWN = "hardware", "synced", "unknown"
KEY_CLASSES = (HARDWARE, SYNCED, UNKNOWN)
HARDWARE_KEY = "hardware-key"            # the step-up an escalation can require
REQUIREMENTS = (HARDWARE_KEY,)
FLAG_BE = 0x08
ZERO_AAGUID = bytes(16)
MAX_CHAIN = 5

OID_AAGUID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")       # id-fido-gen-ce-aaguid
OID_ANDROID_KEY = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")  # Android key description
OID_APPLE_NONCE = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
OID_TCG_KP_AIK = x509.ObjectIdentifier("2.23.133.8.3")
OID_TPM_MANUFACTURER = x509.ObjectIdentifier("2.23.133.2.1")
OID_TPM_MODEL = x509.ObjectIdentifier("2.23.133.2.2")
OID_TPM_VERSION = x509.ObjectIdentifier("2.23.133.2.3")

# TPM 2.0 constants (TPM 2.0 Library, Part 2)
TPM_GENERATED = 0xFF544347
TPM_ST_ATTEST_CERTIFY = 0x8017
TPM_ALG_ECC, TPM_ALG_NULL = 0x0023, 0x0010
TPM_ECC_NIST_P256 = 0x0003
TPM_HASH: Dict[int, Any] = {0x000B: hashes.SHA256, 0x000C: hashes.SHA384, 0x000D: hashes.SHA512}

# COSE algorithms an attestation statement may be signed with (IANA COSE Algorithms).
_EC = {-7: (ec.SECP256R1, hashes.SHA256), -35: (ec.SECP384R1, hashes.SHA384),
       -36: (ec.SECP521R1, hashes.SHA512)}
_RSA = {-257: (hashes.SHA256, False), -258: (hashes.SHA384, False), -259: (hashes.SHA512, False),
        -37: (hashes.SHA256, True), -38: (hashes.SHA384, True), -39: (hashes.SHA512, True)}
_EDDSA = -8


class AttestationError(ValueError):
    """An attestation statement that does not verify; the message says which check failed."""


# ---- signatures --------------------------------------------------------------------------


def _hash_of(alg: int) -> Any:
    if alg in _EC:
        return _EC[alg][1]
    if alg in _RSA:
        return _RSA[alg][0]
    if alg == _EDDSA:
        return hashes.SHA512
    raise AttestationError(f"the attestation's algorithm {alg!r} is not supported (ES256, "
                           "ES384, ES512, EdDSA, RS256, RS384, RS512, PS256, PS384 and PS512 "
                           "are)")


def _verify(key: Any, alg: Any, sig: Any, data: bytes) -> None:
    """Check `sig` over `data` with `key` (a `cryptography` public key) for COSE `alg`."""
    if not isinstance(alg, int) or isinstance(alg, bool):
        raise AttestationError("the attestation's algorithm is not a COSE algorithm number")
    if not isinstance(sig, bytes) or not sig:
        raise AttestationError("the attestation statement has no signature")
    _hash_of(alg)
    try:
        if alg in _EC:
            curve, h = _EC[alg]
            if not isinstance(key, ec.EllipticCurvePublicKey) or \
                    not isinstance(key.curve, curve):
                raise AttestationError("the attestation key does not match its algorithm")
            key.verify(sig, data, ec.ECDSA(h()))
        elif alg in _RSA:
            h, pss = _RSA[alg]
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
                raise AttestationError("the attestation key does not match its algorithm, or "
                                       "is an RSA key shorter than 2048 bits")
            pad = (padding.PSS(padding.MGF1(h()), h().digest_size) if pss
                   else padding.PKCS1v15())
            key.verify(sig, data, pad, h())
        else:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise AttestationError("the attestation key does not match its algorithm")
            key.verify(sig, data)
    except InvalidSignature:
        raise AttestationError("the attestation signature does not verify") from None


def _spki(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


# ---- DER, for the certificate extensions WebAuthn reads -----------------------------------


def _tlv(data: bytes, pos: int) -> Tuple[int, int, int, int]:
    """(class and constructed bits, tag number, start of the value, end) of one DER item."""
    if pos + 2 > len(data):
        raise AttestationError("a certificate extension is truncated")
    first = data[pos]
    tag, pos = first & 0x1F, pos + 1
    if tag == 0x1F:                       # high tag number, base 128
        tag = 0
        for _ in range(4):
            if pos >= len(data):
                raise AttestationError("a certificate extension is truncated")
            b = data[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        else:
            raise AttestationError("a certificate extension has an oversized tag")
    if pos >= len(data):
        raise AttestationError("a certificate extension is truncated")
    n, pos = data[pos], pos + 1
    if n & 0x80:
        width = n & 0x7F
        if not 1 <= width <= 3 or pos + width > len(data):
            raise AttestationError("a certificate extension has a malformed length")
        n, pos = int.from_bytes(data[pos:pos + width], "big"), pos + width
    if pos + n > len(data):
        raise AttestationError("a certificate extension is truncated")
    return first & 0xE0, tag, pos, pos + n


def _items(data: bytes, start: int, end: int) -> List[Tuple[int, int, int, int]]:
    out = []
    while start < end:
        cls, tag, vs, ve = _tlv(data, start)
        out.append((cls, tag, vs, ve))
        start = ve
    return out


def _der_int(data: bytes, vs: int, ve: int) -> int:
    return int.from_bytes(data[vs:ve], "big", signed=True)


def _extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> Optional[Any]:
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None


def _raw(ext: Any) -> bytes:
    value = ext.value
    if not isinstance(value, x509.UnrecognizedExtension):
        raise AttestationError("a certificate extension is not in the form WebAuthn defines")
    return bytes(value.value)


# ---- certificates ------------------------------------------------------------------------


def load_certs(x5c: Any) -> List[x509.Certificate]:
    if not isinstance(x5c, list) or not 1 <= len(x5c) <= MAX_CHAIN or \
            not all(isinstance(c, bytes) and c for c in x5c):
        raise AttestationError(f"x5c must be a list of 1 to {MAX_CHAIN} DER certificates")
    try:
        return [x509.load_der_x509_certificate(c) for c in x5c]
    except ValueError:
        raise AttestationError("a certificate in x5c is not DER X.509") from None


def _leaf_key(cert: x509.Certificate) -> Any:
    try:
        return cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        raise AttestationError("the attestation certificate's key is not supported") from None


def _check_aaguid_extension(cert: x509.Certificate, aaguid: bytes) -> None:
    """If the certificate names an AAGUID it must be the authenticator data's, and the
    extension must not be critical (WebAuthn section 8.2.1)."""
    ext = _extension(cert, OID_AAGUID)
    if ext is None:
        return
    if ext.critical:
        raise AttestationError("the certificate's AAGUID extension is marked critical")
    raw = _raw(ext)
    cls, tag, vs, ve = _tlv(raw, 0)
    if (cls, tag) != (0, 4) or ve != len(raw) or ve - vs != 16:
        raise AttestationError("the certificate's AAGUID extension is malformed")
    if raw[vs:ve] != aaguid:
        raise AttestationError("the certificate names another AAGUID from the authenticator "
                               "data")


def _not_ca(cert: x509.Certificate) -> None:
    ext = _extension(cert, x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    if ext is not None and ext.value.ca:
        raise AttestationError("the attestation certificate is a CA certificate")


def _at(ms: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc)


def _valid_at(cert: x509.Certificate, when: dt.datetime) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _is_ca(cert: x509.Certificate) -> Tuple[bool, Optional[int]]:
    ext = _extension(cert, x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    if ext is None or not ext.value.ca:
        return False, None
    ku = _extension(cert, x509.oid.ExtensionOID.KEY_USAGE)
    if ku is not None and not ku.value.key_cert_sign:
        return False, None
    return True, ext.value.path_length


def _issued(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False


def chain_problem(x5c: Sequence[bytes], roots: Sequence[x509.Certificate],
                  at_ms: int) -> Optional[str]:
    """Why the chain `x5c` (leaf first) does not lead to one of `roots`, valid at `at_ms`, or
    None if it does. Each issuer must be a CA certificate allowed to sign certificates, within
    its path length, and every certificate valid at that time."""
    try:
        path = load_certs(list(x5c))
    except AttestationError as e:
        return str(e)
    when = _at(at_ms)
    root_der = {r.public_bytes(serialization.Encoding.DER) for r in roots}
    # the chain may end with the root itself; stop at the first certificate that is one
    for i, c in enumerate(path):
        if i and c.public_bytes(serialization.Encoding.DER) in root_der:
            path = path[:i + 1]
            break
    for c in path:
        if not _valid_at(c, when):
            return (f"the certificate {c.subject.rfc4514_string() or '(no subject)'} is not "
                    "valid at the time of the enrolment")
    for i in range(len(path) - 1):
        child, parent = path[i], path[i + 1]
        ca, pathlen = _is_ca(parent)
        if not ca:
            return "a certificate in the chain is signed by one that is not a CA"
        if pathlen is not None and i > pathlen:
            return "the chain is longer than a CA certificate's path length allows"
        if not _issued(child, parent):
            return "a certificate in the chain is not signed by the next one"
    last = path[-1]
    if last.public_bytes(serialization.Encoding.DER) in root_der and len(path) > 1:
        return None
    for root in roots:
        ca, pathlen = _is_ca(root)
        if ca and (pathlen is None or len(path) - 1 <= pathlen) and _valid_at(root, when) \
                and _issued(last, root):
            return None
    return "the chain does not lead to a root you trust for this authenticator model"


# ---- the statement formats (WebAuthn Level 3, section 8) ----------------------------------


@dataclass(frozen=True)
class Statement:
    """What a verified attestation statement says."""

    fmt: str
    attestation: str                 # none, self, basic, attca or anonca (section 6.5.4)
    x5c: Tuple[bytes, ...] = ()      # the certificate chain, leaf first


def _x5c_leaf(att_stmt: Dict[str, Any]) -> Tuple[List[x509.Certificate], Any]:
    certs = load_certs(att_stmt.get("x5c"))
    return certs, _leaf_key(certs[0])


def _only(att_stmt: Dict[str, Any], allowed: Sequence[str], fmt: str) -> None:
    extra = sorted(set(att_stmt) - set(allowed))
    if extra:
        raise AttestationError(f"the {fmt} attestation statement has fields it does not "
                               f"define: {', '.join(map(str, extra))}")


def _packed(att: Dict[str, Any], auth_data: bytes, cdh: bytes, aaguid: bytes,
            cred_alg: int, cred_key: Any) -> Statement:
    _only(att, ("alg", "sig", "x5c"), "packed")
    alg, sig, signed = att.get("alg"), att.get("sig"), auth_data + cdh
    if "x5c" not in att:                       # self attestation
        if alg != cred_alg:
            raise AttestationError("a self attestation's algorithm is not the credential's")
        _verify(cred_key, alg, sig, signed)
        return Statement("packed", "self")
    certs, key = _x5c_leaf(att)
    _verify(key, alg, sig, signed)
    leaf = certs[0]
    if leaf.version != x509.Version.v3:
        raise AttestationError("the attestation certificate is not version 3")
    subject = {a.oid: a.value for a in leaf.subject}
    country = subject.get(NameOID.COUNTRY_NAME)
    if not (isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country)
            and subject.get(NameOID.ORGANIZATION_NAME) and subject.get(NameOID.COMMON_NAME)
            and subject.get(NameOID.ORGANIZATIONAL_UNIT_NAME) == "Authenticator Attestation"):
        raise AttestationError("the attestation certificate's subject is not C, O, "
                               "OU=Authenticator Attestation and CN")
    _check_aaguid_extension(leaf, aaguid)
    _not_ca(leaf)
    return Statement("packed", "basic", tuple(att["x5c"]))


def _u16(b: bytes, pos: int) -> Tuple[int, int]:
    if pos + 2 > len(b):
        raise AttestationError("a TPM structure is truncated")
    return struct.unpack(">H", b[pos:pos + 2])[0], pos + 2


def _tpm2b(b: bytes, pos: int) -> Tuple[bytes, int]:
    n, pos = _u16(b, pos)
    if pos + n > len(b):
        raise AttestationError("a TPM structure is truncated")
    return b[pos:pos + n], pos + n


def _tpm(att: Dict[str, Any], auth_data: bytes, cdh: bytes, aaguid: bytes, cred_alg: int,
         cred_key: Any) -> Statement:
    _only(att, ("ver", "alg", "x5c", "sig", "certInfo", "pubArea"), "tpm")
    if att.get("ver") != "2.0":
        raise AttestationError("the TPM attestation is not version 2.0")
    pub, info = att.get("pubArea"), att.get("certInfo")
    if not isinstance(pub, bytes) or not isinstance(info, bytes):
        raise AttestationError("the TPM attestation has no pubArea or certInfo")
    # pubArea (TPMT_PUBLIC): the credential's public key, as the TPM holds it
    typ, p = _u16(pub, 0)
    name_alg, p = _u16(pub, p)
    p += 4                                      # objectAttributes
    _, p = _tpm2b(pub, p)                       # authPolicy
    if typ != TPM_ALG_ECC or not isinstance(cred_key, ec.EllipticCurvePublicKey):
        raise AttestationError("the TPM key is not an ECC key matching the credential (RSA "
                               "credentials are not supported)")
    symmetric, p = _u16(pub, p)
    scheme, p = _u16(pub, p)                    # TPMT_ECC_SCHEME: a hash follows a scheme
    if scheme != TPM_ALG_NULL:
        _, p = _u16(pub, p)
    curve, p = _u16(pub, p)
    kdf, p = _u16(pub, p)                       # TPMT_KDF_SCHEME, likewise
    if kdf != TPM_ALG_NULL:
        _, p = _u16(pub, p)
    x, p = _tpm2b(pub, p)
    y, p = _tpm2b(pub, p)
    if p != len(pub):
        raise AttestationError("the TPM pubArea has trailing bytes")
    n = cred_key.public_numbers()
    if symmetric != TPM_ALG_NULL or curve != TPM_ECC_NIST_P256 or \
            x != n.x.to_bytes(32, "big") or y != n.y.to_bytes(32, "big"):
        raise AttestationError("the TPM pubArea's key is not the credential public key")
    if name_alg not in TPM_HASH:
        raise AttestationError("the TPM pubArea's name algorithm is not supported")
    # certInfo (TPMS_ATTEST): the TPM certifies that key
    if len(info) < 6 or struct.unpack(">I", info[:4])[0] != TPM_GENERATED:
        raise AttestationError("the TPM certInfo's magic is not TPM_GENERATED_VALUE")
    st, p = _u16(info, 4)
    if st != TPM_ST_ATTEST_CERTIFY:
        raise AttestationError("the TPM certInfo is not TPM_ST_ATTEST_CERTIFY")
    _, p = _tpm2b(info, p)                      # qualifiedSigner
    extra, p = _tpm2b(info, p)
    p += 17 + 8                                 # clockInfo, firmwareVersion
    name, p = _tpm2b(info, p)
    _, p = _tpm2b(info, p)                      # qualifiedName
    if p != len(info):
        raise AttestationError("the TPM certInfo has trailing bytes or is truncated")
    alg = att.get("alg")
    if not isinstance(alg, int) or isinstance(alg, bool):
        raise AttestationError("the attestation's algorithm is not a COSE algorithm number")
    h = _hash_of(alg)
    digest = hashes.Hash(h())
    digest.update(auth_data + cdh)
    if extra != digest.finalize():
        raise AttestationError("the TPM certInfo's extraData is not the digest of what was "
                               "attested")
    nh = hashes.Hash(TPM_HASH[name_alg]())
    nh.update(pub)
    if name != struct.pack(">H", name_alg) + nh.finalize():
        raise AttestationError("the TPM certInfo does not name the pubArea")
    certs, key = _x5c_leaf(att)
    _verify(key, alg, att.get("sig"), info)
    aik = certs[0]
    if aik.version != x509.Version.v3 or len(aik.subject) != 0:
        raise AttestationError("the TPM attestation certificate is not version 3 with an "
                               "empty subject")
    san = _extension(aik, x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    names = [a.oid for d in (san.value.get_values_for_type(x509.DirectoryName) if san else [])
             for a in d]
    if not {OID_TPM_MANUFACTURER, OID_TPM_MODEL, OID_TPM_VERSION} <= set(names):
        raise AttestationError("the TPM attestation certificate does not name the TPM's "
                               "manufacturer, model and version")
    eku = _extension(aik, x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
    if eku is None or OID_TCG_KP_AIK not in list(eku.value):
        raise AttestationError("the TPM attestation certificate is not for attestation keys "
                               "(tcg-kp-AIKCertificate)")
    _not_ca(aik)
    _check_aaguid_extension(aik, aaguid)
    return Statement("tpm", "attca", tuple(att["x5c"]))


def _android_key(att: Dict[str, Any], auth_data: bytes, cdh: bytes, aaguid: bytes,
                 cred_alg: int, cred_key: Any) -> Statement:
    _only(att, ("alg", "sig", "x5c"), "android-key")
    certs, key = _x5c_leaf(att)
    _verify(key, att.get("alg"), att.get("sig"), auth_data + cdh)
    if _spki(key) != _spki(cred_key):
        raise AttestationError("the attestation certificate's key is not the credential key")
    ext = _extension(certs[0], OID_ANDROID_KEY)
    if ext is None:
        raise AttestationError("the attestation certificate has no Android key description")
    raw = _raw(ext)
    cls, tag, vs, ve = _tlv(raw, 0)
    fields = _items(raw, vs, ve) if (cls, tag) == (0x20, 16) and ve == len(raw) else []
    if len(fields) < 8 or fields[4][:2] != (0, 4) or fields[6][:2] != (0x20, 16) or \
            fields[7][:2] != (0x20, 16):
        raise AttestationError("the Android key description is malformed")
    if raw[fields[4][2]:fields[4][3]] != cdh:
        raise AttestationError("the Android key description's challenge is not the client "
                               "data hash")

    def authorizations(f: Tuple[int, int, int, int]) -> Dict[int, Tuple[int, int]]:
        out: Dict[int, Tuple[int, int]] = {}
        for c, t, s, e in _items(raw, f[2], f[3]):
            if c != 0xA0:
                raise AttestationError("the Android key description is malformed")
            out[t] = (s, e)
        return out

    soft, tee = authorizations(fields[6]), authorizations(fields[7])
    if 600 in soft or 600 in tee:
        raise AttestationError("the Android key is usable by every application (allApplications)")

    def origin_generated(auth: Dict[int, Tuple[int, int]]) -> bool:
        if 702 not in auth:
            return False
        _, t, s, e = _tlv(raw, auth[702][0])
        return t == 2 and _der_int(raw, s, e) == 0

    def purpose_sign(auth: Dict[int, Tuple[int, int]]) -> bool:
        if 1 not in auth:
            return False
        c, t, s, e = _tlv(raw, auth[1][0])
        return t == 17 and any(_der_int(raw, a, b) == 2 for _, _, a, b in _items(raw, s, e))

    if not (origin_generated(tee) and purpose_sign(tee)):
        raise AttestationError("the Android key was not generated in, and for signing by, the "
                               "trusted execution environment")
    return Statement("android-key", "basic", tuple(att["x5c"]))


def _apple(att: Dict[str, Any], auth_data: bytes, cdh: bytes, aaguid: bytes, cred_alg: int,
           cred_key: Any) -> Statement:
    _only(att, ("x5c",), "apple")
    certs, key = _x5c_leaf(att)
    ext = _extension(certs[0], OID_APPLE_NONCE)
    if ext is None:
        raise AttestationError("the Apple attestation certificate has no nonce")
    raw = _raw(ext)
    cls, tag, vs, ve = _tlv(raw, 0)
    inner = _items(raw, vs, ve) if (cls, tag) == (0x20, 16) and ve == len(raw) else []
    if len(inner) != 1 or inner[0][:2] != (0xA0, 1):
        raise AttestationError("the Apple attestation nonce is malformed")
    c2, t2, s2, e2 = _tlv(raw, inner[0][2])
    if (c2, t2) != (0, 4) or e2 != inner[0][3]:
        raise AttestationError("the Apple attestation nonce is malformed")
    if raw[s2:e2] != hashlib.sha256(auth_data + cdh).digest():
        raise AttestationError("the Apple attestation nonce is not for this registration")
    if _spki(key) != _spki(cred_key):
        raise AttestationError("the attestation certificate's key is not the credential key")
    return Statement("apple", "anonca", tuple(att["x5c"]))


def _fido_u2f(att: Dict[str, Any], auth_data: bytes, cdh: bytes, aaguid: bytes, cred_alg: int,
              cred_key: Any) -> Statement:
    _only(att, ("sig", "x5c"), "fido-u2f")
    certs, key = _x5c_leaf(att)
    if len(certs) != 1:
        raise AttestationError("a fido-u2f attestation holds exactly one certificate")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise AttestationError("the fido-u2f attestation key is not a P-256 key")
    if cred_alg != -7 or not isinstance(cred_key, ec.EllipticCurvePublicKey):
        raise AttestationError("a fido-u2f credential must be an ES256 key")
    n = struct.unpack(">H", auth_data[53:55])[0]
    cred_id = auth_data[55:55 + n]
    point = cred_key.public_bytes(serialization.Encoding.X962,
                                  serialization.PublicFormat.UncompressedPoint)
    _verify(key, -7, att.get("sig"), b"\x00" + auth_data[:32] + cdh + cred_id + point)
    return Statement("fido-u2f", "basic", tuple(att["x5c"]))


_VERIFIERS = {"packed": _packed, "tpm": _tpm, "android-key": _android_key, "apple": _apple,
              "fido-u2f": _fido_u2f}


def verify_statement(fmt: Any, att_stmt: Any, auth_data: bytes, client_data_hash: bytes,
                     aaguid: bytes, cred_alg: int, cred_key: Any) -> Statement:
    """Verify one attestation statement (WebAuthn section 8) over the registration's
    authenticator data and client data hash. `cred_key` is the credential public key as a
    `cryptography` object. Raises AttestationError; says nothing about trust in the chain."""
    if not isinstance(att_stmt, dict):
        raise AttestationError("the attestation statement is not a map")
    if fmt == "none":
        if att_stmt:
            raise AttestationError("a none attestation carries an empty statement")
        return Statement("none", "none")
    verify = _VERIFIERS.get(fmt) if isinstance(fmt, str) else None
    if verify is None:
        raise AttestationError(f"the attestation format {fmt!r} is not supported (none, "
                               "packed, tpm, android-key, apple and fido-u2f are)")
    return verify(att_stmt, auth_data, client_data_hash, aaguid, cred_alg, cred_key)


# ---- the trust file ----------------------------------------------------------------------


@dataclass(frozen=True)
class Authenticator:
    """One authenticator model in the trust file."""

    description: str
    device_bound: bool
    roots: Tuple[x509.Certificate, ...]
    aaguid: Optional[bytes] = None
    key_identifiers: Tuple[bytes, ...] = ()


class AuthenticatorTrust:
    """The authenticator models and attestation roots an auditor trusts (`aeos-authenticator-
    trust/v1`): models by AAGUID, and fido-u2f models by the key identifiers of their
    attestation certificates, as the FIDO Metadata Service lists them."""

    def __init__(self, models: Sequence[Authenticator], source: str = "") -> None:
        self.models = list(models)
        self.source = source
        self._by_aaguid = {m.aaguid: m for m in self.models if m.aaguid is not None}
        self._by_key_id = {k: m for m in self.models for k in m.key_identifiers}

    @classmethod
    def load(cls, doc: Any) -> "AuthenticatorTrust":
        """Read a trust file; ValueError says what is wrong with it."""
        if not isinstance(doc, dict) or doc.get("format") != TRUST_FORMAT:
            raise ValueError(f"the authenticator trust file is not {TRUST_FORMAT}")
        entries = doc.get("authenticators")
        if not isinstance(entries, list):
            raise ValueError("the authenticator trust file has no list of authenticators")
        models: List[Authenticator] = []
        seen: set = set()
        for n, e in enumerate(entries):
            where = f"authenticator {n + 1}"
            if not isinstance(e, dict) or not isinstance(e.get("device_bound"), bool):
                raise ValueError(f"{where}: device_bound must be true or false")
            aaguid = None
            if e.get("aaguid") is not None:
                text = e["aaguid"]
                try:
                    aaguid = uuid.UUID(text).bytes if isinstance(text, str) else None
                except ValueError:
                    aaguid = None
                if aaguid is None or str(uuid.UUID(bytes=aaguid)) != text:
                    raise ValueError(f"{where}: aaguid must be a lower-case UUID")
                if aaguid == ZERO_AAGUID:
                    raise ValueError(f"{where}: the all-zero AAGUID names no model")
            ids = e.get("attestation_certificate_key_identifiers", [])
            if not isinstance(ids, list) or not all(
                    isinstance(i, str) and re.fullmatch(r"[0-9a-f]{40}", i) for i in ids):
                raise ValueError(f"{where}: attestation_certificate_key_identifiers must be "
                                 "lower-case hex SHA-1 key identifiers")
            if aaguid is None and not ids:
                raise ValueError(f"{where}: needs an aaguid or attestation certificate key "
                                 "identifiers")
            keys = [aaguid] if aaguid else []
            keys += ids
            if seen & set(keys):
                raise ValueError(f"{where}: names a model another entry names")
            seen |= set(keys)
            roots = e.get("attestation_root_certificates")
            if not isinstance(roots, list) or not roots:
                raise ValueError(f"{where}: needs attestation_root_certificates")
            try:
                certs = tuple(x509.load_der_x509_certificate(base64.b64decode(r, validate=True))
                              for r in roots)
            except (ValueError, TypeError):
                raise ValueError(f"{where}: a root certificate is not base64 DER") from None
            desc = e.get("description", "")
            models.append(Authenticator(desc if isinstance(desc, str) else "", e["device_bound"],
                                        certs, aaguid, tuple(bytes.fromhex(i) for i in ids)))
        src = doc.get("source", "")
        return cls(models, src if isinstance(src, str) else "")

    def model_for(self, fmt: str, aaguid: bytes, x5c: Sequence[bytes]
                  ) -> Optional[Authenticator]:
        if fmt != "fido-u2f":                 # a U2F key names its model by certificate only
            return self._by_aaguid.get(aaguid) if aaguid != ZERO_AAGUID else None
        if x5c:
            leaf = load_certs(list(x5c))[0]
            ids = {x509.SubjectKeyIdentifier.from_public_key(_leaf_key(leaf)).digest}
            ski = _extension(leaf, x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if ski is not None:
                ids.add(ski.value.digest)
            for i in sorted(ids):
                if i in self._by_key_id:
                    return self._by_key_id[i]
        return None


def trust_doc(models: Sequence[Dict[str, Any]], source: str) -> Dict[str, Any]:
    """A trust file from entries in its own field names (for exporters and tests)."""
    return {"format": TRUST_FORMAT, "source": source, "authenticators": list(models)}


# ---- the key class -----------------------------------------------------------------------


def aaguid_text(aaguid: bytes) -> str:
    return str(uuid.UUID(bytes=aaguid))


def key_class(statement: Optional[Statement], flags: Optional[int], aaguid: bytes,
              trust: Optional[AuthenticatorTrust], at_ms: int) -> Tuple[str, str]:
    """(key class, the reason in plain words) for a credential, from its verified attestation
    statement and the flags of its registration (None for both when it was added without a
    registration response)."""
    if flags is None or statement is None:
        return UNKNOWN, "it was added without a registration response, so its model is unknown"
    if flags & FLAG_BE:
        return SYNCED, "it is backup eligible (BE is set), so it can be copied to other devices"
    if statement.attestation == "none":
        return UNKNOWN, "its registration carries no attestation (format none)"
    if statement.attestation == "self":
        return UNKNOWN, "it attests only to itself (self attestation), which names no model"
    if trust is None:
        return UNKNOWN, "no authenticator trust file was given to this audit"
    model = trust.model_for(statement.fmt, aaguid, statement.x5c)
    if model is None:
        named = ("AAGUID " + aaguid_text(aaguid)) if aaguid != ZERO_AAGUID and \
            statement.fmt != "fido-u2f" else "its attestation certificate"
        return UNKNOWN, f"its model ({named}) is not in the authenticator trust you gave"
    name = model.description or ("AAGUID " + aaguid_text(aaguid))
    why = chain_problem(statement.x5c, model.roots, at_ms)
    if why:
        return UNKNOWN, f"its {statement.fmt} attestation for {name} does not stand: {why}"
    if not model.device_bound:
        return UNKNOWN, f"the authenticator trust you gave does not list {name} as device-bound"
    return HARDWARE, (f"its {statement.fmt} attestation chains to a root you trust for {name}, "
                      "a device-bound model, and it is not backup eligible")


__all__ = ["AttestationError", "Authenticator", "AuthenticatorTrust", "HARDWARE", "HARDWARE_KEY",
           "KEY_CLASSES", "REQUIREMENTS", "SYNCED", "Statement", "TRUST_FORMAT", "UNKNOWN",
           "chain_problem", "key_class", "trust_doc", "verify_statement"]
