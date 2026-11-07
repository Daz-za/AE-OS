"""WebAuthn assertion verification and the AE-OS challenge constructions.

A person approves with a passkey: the authenticator signs a challenge built from one request
(or one batch of requests). Everything an auditor needs to check that signature is public and
uses only `cryptography`, so nothing here trusts the party that wrote the record.

The verification follows W3C WebAuthn Level 3 (Recommendation, 25 August 2026), section 7.2
("Verifying an Authentication Assertion"), for the parts a relying party can check offline: the
client data (UTF-8 without a BOM, `type`, `challenge`, `origin`, no `crossOrigin` or `topOrigin`,
no repeated keys), the authenticator data (`rpIdHash`, the UP and UV flags, the backup flags, the
extensions as one canonical CBOR map) and the signature over `authenticatorData ||
SHA-256(clientDataJSON)` for ES256 (COSE -7) and EdDSA (COSE -8). The signature counter is
advisory: synced passkeys report 0, so it is returned and never required to rise. Single use is
the nonce's job, checked by the caller.

Public keys are COSE_Key maps in the CTAP2 canonical encoding (WebAuthn section 6.5.1.1) and are
parsed strictly: a key that is not canonical, is on another curve, is off the curve, or is of
small order is refused.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import keys

CHALLENGE_CONTEXT = b"aeos/approval-challenge/v1\n"
REQUEST_CONTEXT = b"aeos/request/v1\n"            # a request that answers no escalation
ESCALATED_CONTEXT = b"aeos/request/v2\n"          # a request that answers one escalation
BATCH_CONTEXT = b"aeos/approval-batch/v2\n"
BATCH_CONTEXT_NAME = "aeos/approval-batch/v2"
ENROL_CONTEXT = b"aeos/enrol-challenge/v1\n"
RESERVED = "aeos/"                                 # tool names no approval may be for
CID_LEN = 36                                       # a binary CIDv1 (dag-cbor, sha2-256)
DOCUMENT_TOOL = "aeos/document"          # the leading item of a batch that signs a document
MIN_NONCE = 16
MAX_BATCH = 256

COSE_ES256, COSE_EDDSA = -7, -8
FLAG_UP, FLAG_BE, FLAG_BS, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x08, 0x10, 0x04, 0x40, 0x80
_P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1


class WebAuthnError(ValueError):
    """An assertion or key that does not stand; the message says which check failed."""


# ---- the constructions ---------------------------------------------------------------


def request_digest(tool: str, args_sha256: bytes, escalation: Optional[bytes] = None) -> bytes:
    """The digest of one request. An approval answers one escalation, so its request is

        SHA-256(b"aeos/request/v2\\n" || tool || b"\\n" || args_sha256 || escalation)

    with the escalation's 36-byte binary CID, and a yes binds to that escalation alone. A request
    that answers none (a confirmation of a registry change, section 10.4) is
    SHA-256(b"aeos/request/v1\\n" || tool || b"\\n" || args_sha256)."""
    if len(args_sha256) != 32 or (escalation is not None and len(escalation) != CID_LEN):
        raise WebAuthnError("args_sha256 must be 32 bytes and an escalation a 36-byte CID")
    if escalation is None:
        return hashlib.sha256(REQUEST_CONTEXT + tool.encode("utf-8") + b"\n" + args_sha256).digest()
    return hashlib.sha256(ESCALATED_CONTEXT + tool.encode("utf-8") + b"\n" + args_sha256
                          + escalation).digest()


def batch_digest(items: Sequence[Tuple[str, bytes, bytes]]) -> bytes:
    """SHA-256(b"aeos/approval-batch/v2\\n" || item_1 || b"\\n" || item_2 ...), where an item is
    tool || b"\\0" || args_sha256 || escalation, in the order shown to the person. The one
    exception is a leading document item (tool aeos/document), which has no escalation."""
    if not 1 <= len(items) <= MAX_BATCH:
        raise WebAuthnError(f"a batch holds 1 to {MAX_BATCH} items")
    parts = []
    for n, (tool, args, esc) in enumerate(items):
        document = tool == DOCUMENT_TOOL and n == 0 and esc == b""
        if (not isinstance(tool, str) or "\0" in tool or len(args) != 32
                or not (document or len(esc) == CID_LEN)):
            raise WebAuthnError("a batch item is a tool name without NUL, a 32-byte digest and "
                                "an escalation (a document has none)")
        parts.append(tool.encode("utf-8") + b"\0" + args + esc)
    return hashlib.sha256(BATCH_CONTEXT + b"\n".join(parts)).digest()


def challenge_for(nonce: bytes, digest: bytes) -> bytes:
    """What the authenticator signs: SHA-256(b"aeos/approval-challenge/v1\\n" || nonce || digest)."""
    if len(nonce) < MIN_NONCE or len(digest) != 32:
        raise WebAuthnError(f"the nonce must be at least {MIN_NONCE} bytes")
    return hashlib.sha256(CHALLENGE_CONTEXT + nonce + digest).digest()


def enrol_challenge(approver: str, identity_evidence_sha256: bytes) -> bytes:
    """The challenge of a root passkey's registration: SHA-256(b"aeos/enrol-challenge/v1\\n" ||
    approver || b"\\n" || SHA-256 of the identity evidence)."""
    if len(identity_evidence_sha256) != 32:
        raise WebAuthnError("the identity evidence digest must be 32 bytes")
    return hashlib.sha256(ENROL_CONTEXT + approver.encode("utf-8") + b"\n"
                          + identity_evidence_sha256).digest()


def assertion_sha256(authenticator_data: bytes, client_data_json: bytes, signature: bytes) -> bytes:
    """SHA-256(authenticator_data || SHA-256(client_data_json) || signature)."""
    return hashlib.sha256(authenticator_data + hashlib.sha256(client_data_json).digest()
                          + signature).digest()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64url(s: str) -> bytes:
    if not isinstance(s, str) or "=" in s:
        raise WebAuthnError("not unpadded base64url")
    try:
        out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        raise WebAuthnError("not base64url") from None
    if b64url(out) != s:
        raise WebAuthnError("not canonical base64url")
    return out


# ---- CTAP2 canonical CBOR ----------------------------------------------------------------


def _head(data: bytes, pos: int) -> Tuple[int, int, int]:
    """(major, argument, next position) of a definite-length, shortest-form CBOR head."""
    if pos >= len(data):
        raise WebAuthnError("the CBOR is truncated")
    major, info = data[pos] >> 5, data[pos] & 31
    pos += 1
    if info < 24:
        return major, info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if width is None or pos + width > len(data):
        raise WebAuthnError("the CBOR is not definite-length")
    n = int.from_bytes(data[pos:pos + width], "big")
    if n < {24: 24, 25: 0x100, 26: 0x10000, 27: 0x100000000}[info]:
        raise WebAuthnError("the CBOR is not in shortest form")
    return major, n, pos + width


def decode_cbor(data: bytes, pos: int = 0, depth: int = 0) -> Tuple[Any, int]:
    """(value, next position) of one CTAP2 canonical CBOR item: integers, byte and text strings,
    arrays, maps with integer or text keys in canonical order (length first, then bytewise, no
    repeats), booleans and null. Floats, tags and indefinite lengths are refused."""
    if depth > 8:
        raise WebAuthnError("the CBOR is nested too deeply")
    major, n, pos = _head(data, pos)
    if major == 0:
        return n, pos
    if major == 1:
        return -1 - n, pos
    if major in (2, 3):
        if pos + n > len(data):
            raise WebAuthnError("the CBOR is truncated")
        raw = data[pos:pos + n]
        if major == 3:
            try:
                return raw.decode("utf-8"), pos + n
            except UnicodeDecodeError:
                raise WebAuthnError("the CBOR holds text that is not UTF-8") from None
        return raw, pos + n
    if major == 4:
        out: List[Any] = []
        for _ in range(n):
            v, pos = decode_cbor(data, pos, depth + 1)
            out.append(v)
        return out, pos
    if major == 5:
        m: Dict[Any, Any] = {}
        last = None
        for _ in range(n):
            start = pos
            kmaj, _k, _ = _head(data, pos)
            if kmaj not in (0, 1, 3):
                raise WebAuthnError("a CBOR map key is not an integer or text")
            k, pos = decode_cbor(data, pos, depth + 1)
            raw = data[start:pos]
            if last is not None and not (len(raw), raw) > (len(last), last):
                raise WebAuthnError("the CBOR map is not in canonical key order (or repeats a key)")
            last = raw
            m[k], pos = decode_cbor(data, pos, depth + 1)
        return m, pos
    if major == 7 and n in (20, 21, 22):
        return {20: False, 21: True, 22: None}[n], pos
    raise WebAuthnError("the CBOR holds a float, tag or other value that is not allowed")


# ---- COSE keys -------------------------------------------------------------------------


def _cose_fields(data: bytes, start: int = 0) -> Tuple[Dict[Any, Any], int]:
    """The fields of a COSE_Key at `start` and where it ends."""
    try:
        v, end = decode_cbor(data, start)
    except WebAuthnError as e:
        raise WebAuthnError(f"the key: {e}") from None
    if not isinstance(v, dict) or not all(isinstance(k, int) for k in v) or \
            not 3 <= len(v) <= 5 or not all(isinstance(x, (int, bytes)) for x in v.values()):
        raise WebAuthnError("the key is not a COSE_Key map of integers and byte strings")
    return v, end


def parse_cose_key(data: bytes) -> Tuple[int, Any]:
    """(COSE algorithm, public key object) from a canonical COSE_Key, or WebAuthnError."""
    if not isinstance(data, bytes) or not data or len(data) > 256:
        raise WebAuthnError("the key is empty or too long")
    fields, end = _cose_fields(data)
    if end != len(data):
        raise WebAuthnError("the key has trailing bytes")
    alg, kty, crv = fields.get(3), fields.get(1), fields.get(-1)
    if alg == COSE_ES256:
        if set(fields) != {1, 3, -1, -2, -3} or kty != 2:
            raise WebAuthnError("an ES256 key must be an EC2 key with x and y")
        if crv != 1:
            raise WebAuthnError("the key is not on the P-256 curve")
        x, y = fields[-2], fields[-3]
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise WebAuthnError("the key's coordinates are not 32 bytes")
        xi, yi = int.from_bytes(x, "big"), int.from_bytes(y, "big")
        if xi >= _P256_P or yi >= _P256_P:
            raise WebAuthnError("the key's coordinates are not reduced")
        try:
            return alg, ec.EllipticCurvePublicNumbers(xi, yi, ec.SECP256R1()).public_key()
        except ValueError:
            raise WebAuthnError("the key is not a point on the P-256 curve") from None
    if alg == COSE_EDDSA:
        if set(fields) != {1, 3, -1, -2} or kty != 1:
            raise WebAuthnError("an EdDSA key must be an OKP key with x")
        if crv != 6:
            raise WebAuthnError("the key is not on the Ed25519 curve")
        x = fields[-2]
        if not isinstance(x, bytes) or len(x) != 32:
            raise WebAuthnError("the key's x is not 32 bytes")
        n = int.from_bytes(x, "little")
        if (n & ((1 << 255) - 1)) >= keys._P or keys._decode_point(x) is None:
            raise WebAuthnError("the key is not a canonical Ed25519 point")
        if keys.is_small_order(x):
            raise WebAuthnError("the key is of small order")
        return alg, Ed25519PublicKey.from_public_bytes(x)
    raise WebAuthnError(f"the key's algorithm {alg!r} is not supported (ES256 and EdDSA are)")


# ---- relying party and origin ------------------------------------------------------------

# Suffixes under which anyone can register a name, so no one of them is a relying party. A short
# guard, not the Public Suffix List: an RP ID is also at least two labels, never an IP address.
PUBLIC_SUFFIXES = frozenset("""
co.za org.za gov.za ac.za net.za web.za nom.za edu.za co.uk org.uk ac.uk gov.uk me.uk
com.au net.au org.au edu.au gov.au co.nz org.nz net.nz co.jp ne.jp or.jp com.br com.cn com.mx
com.ar com.tr com.hk com.sg co.in co.il co.kr com.tw github.io gitlab.io herokuapp.com
vercel.app netlify.app pages.dev workers.dev web.app firebaseapp.com appspot.com blogspot.com
cloudfront.net azurewebsites.net s3.amazonaws.com amazonaws.com cloudflare.net trycloudflare.com
""".split())
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def check_origin(rp_id: str, origin: str) -> None:
    """The relying party id and origin a credential may declare. The RP ID is a lower-case
    domain of at least two labels (or `localhost`), not an IP address and not a public suffix.
    The origin is in its browser serialisation: `https://host[:port]` (or `http` on localhost),
    lower case, no path, and no default port. Its host is the RP ID or under it."""
    if not isinstance(rp_id, str) or not isinstance(origin, str):
        raise WebAuthnError("the relying party id and origin must be text")
    try:
        ipaddress.ip_address(rp_id.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise WebAuthnError("the relying party id is an IP address, not a domain")
    labels = rp_id.split(".")
    if rp_id != "localhost" and (len(labels) < 2 or not all(_LABEL.match(x) for x in labels)):
        raise WebAuthnError("the relying party id is not a lower-case domain of two or more labels")
    if rp_id in PUBLIC_SUFFIXES:
        raise WebAuthnError("the relying party id is a public suffix")
    try:
        u = urlsplit(origin)
        host, port = u.hostname, u.port
    except ValueError:
        raise WebAuthnError("the origin is not a web origin") from None
    ok_scheme = u.scheme == "https" or (u.scheme == "http" and host == "localhost")
    default = {"https": 443, "http": 80}.get(u.scheme)
    netloc = host + (f":{port}" if port is not None else "") if host else ""
    if (not ok_scheme or not host or u.path or u.query or u.fragment or u.username
            or origin != f"{u.scheme}://{netloc}" or port == default or origin != origin.lower()):
        raise WebAuthnError("the origin is not in its browser serialisation (lower-case "
                            "scheme://host[:port], https, no default port)")
    if host != rp_id and not host.endswith("." + rp_id):
        raise WebAuthnError("the origin's host is not the relying party id or under it")


# ---- the assertion -----------------------------------------------------------------------


@dataclass(frozen=True)
class Assertion:
    flags: int
    sign_count: int                 # advisory only


def _no_repeats(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("repeated key")
        out[k] = v
    return out


def _client_data(client_data_json: bytes) -> Dict[str, Any]:
    """The client data as WebAuthn section 7.2 reads it: UTF-8 decoded with one leading BOM
    stripped, then parsed as JSON with no repeated key."""
    try:
        text = client_data_json.decode("utf-8")
        if text.startswith("\ufeff"):
            text = text[1:]
        client = json.loads(text, object_pairs_hook=_no_repeats)
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("the client data is not JSON without repeated keys") from None
    if not isinstance(client, dict):
        raise WebAuthnError("the client data is not a JSON object")
    return client


def _check_client(client: Dict[str, Any], *, type_: str, origin: str, challenge: bytes) -> None:
    if client.get("type") != type_:
        raise WebAuthnError(f"the client data type is not {type_}")
    if client.get("origin") != origin:
        raise WebAuthnError("the origin is not the one enrolled for this passkey")
    cross = client.get("crossOrigin")
    if (cross is not None and cross is not False) or "topOrigin" in client:
        raise WebAuthnError("the assertion was made in a cross-origin context")
    try:
        got = unb64url(client.get("challenge"))            # type: ignore[arg-type]
    except WebAuthnError:
        raise WebAuthnError("the client data's challenge is not base64url") from None
    if got != challenge:
        raise WebAuthnError("the challenge is not the one for this request")


def _check_flags(ad: bytes, rp_id: str) -> int:
    if len(ad) < 37:
        raise WebAuthnError("the authenticator data is too short")
    if ad[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest():
        raise WebAuthnError("the relying party id hash is not the one enrolled for this passkey")
    flags = ad[32]
    if not flags & FLAG_UP:
        raise WebAuthnError("user presence was not asserted")
    if not flags & FLAG_UV:
        raise WebAuthnError("user verification was not performed")
    if flags & FLAG_BS and not flags & FLAG_BE:
        raise WebAuthnError("backup state is set on a credential that is not backup eligible")
    return flags


def _check_extensions(ext: bytes, flags: int) -> None:
    """With the ED flag, exactly one canonical CBOR map; without it, nothing."""
    if not flags & FLAG_ED:
        if ext:
            raise WebAuthnError("the authenticator data has bytes after it but no extension flag")
        return
    try:
        v, end = decode_cbor(ext)
    except WebAuthnError as e:
        raise WebAuthnError(f"the extension data is not canonical CBOR: {e}") from None
    if not isinstance(v, dict) or end != len(ext):
        raise WebAuthnError("the extension data is not exactly one CBOR map")


def verify_assertion(public_key: Tuple[int, Any], authenticator_data: bytes,
                     client_data_json: bytes, signature: bytes, *, rp_id: str, origin: str,
                     challenge: bytes) -> Assertion:
    """Check one assertion against the key, relying party, origin and challenge the caller
    holds (from the registry, never from the evidence). Raises WebAuthnError."""
    if not (isinstance(authenticator_data, bytes) and isinstance(client_data_json, bytes)
            and isinstance(signature, bytes)):
        raise WebAuthnError("the assertion is incomplete")
    if len(authenticator_data) > 1024 or len(client_data_json) > 8192 or len(signature) > 1024:
        raise WebAuthnError("the assertion is oversized")
    _check_client(_client_data(client_data_json), type_="webauthn.get", origin=origin,
                  challenge=challenge)
    ad = authenticator_data
    flags = _check_flags(ad, rp_id)
    if flags & FLAG_AT:
        raise WebAuthnError("an assertion carries no attested credential data")
    _check_extensions(ad[37:], flags)
    signed = ad + hashlib.sha256(client_data_json).digest()
    alg, key = public_key
    try:
        if alg == COSE_ES256:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif not keys.verify(key.public_bytes_raw(), signature, signed):
            raise InvalidSignature
    except InvalidSignature:
        raise WebAuthnError("the signature does not verify") from None
    return Assertion(flags, int.from_bytes(ad[33:37], "big"))


def verify_registration(client_data_json: bytes, attestation_object: bytes, *, rp_id: str,
                        origin: str, challenge: bytes, credential_id: bytes,
                        public_key: bytes) -> None:
    """Check the registration response ("none" attestation) of a root passkey: made with user
    presence and verification, at the enrolled relying party and origin, for this challenge,
    and holding the credential id and public key being enrolled. A "none" attestation carries
    no signature: this ties the pieces together, it does not prove possession of the key."""
    if not (isinstance(client_data_json, bytes) and isinstance(attestation_object, bytes)):
        raise WebAuthnError("the registration response is incomplete")
    if len(client_data_json) > 8192 or len(attestation_object) > 4096:
        raise WebAuthnError("the registration response is oversized")
    _check_client(_client_data(client_data_json), type_="webauthn.create", origin=origin,
                  challenge=challenge)
    obj, end = decode_cbor(attestation_object)
    if end != len(attestation_object) or not isinstance(obj, dict) or \
            set(obj) != {"fmt", "attStmt", "authData"}:
        raise WebAuthnError("the attestation object is not exactly fmt, attStmt and authData")
    if obj["fmt"] != "none" or obj["attStmt"] != {}:
        raise WebAuthnError("the attestation format is not none")
    ad = obj["authData"]
    if not isinstance(ad, bytes):
        raise WebAuthnError("the attestation object holds no authenticator data")
    flags = _check_flags(ad, rp_id)
    if not flags & FLAG_AT:
        raise WebAuthnError("the registration carries no attested credential data")
    if len(ad) < 55:
        raise WebAuthnError("the attested credential data is too short")
    n = int.from_bytes(ad[53:55], "big")
    if n > 1023 or ad[55:55 + n] != credential_id:
        raise WebAuthnError("the registered credential id is not the one enrolled")
    start = 55 + n
    _, key_end = _cose_fields(ad, start)
    if ad[start:key_end] != public_key:
        raise WebAuthnError("the registered public key is not the one enrolled")
    _check_extensions(ad[key_end:], flags)


__all__: List[str] = ["Assertion", "WebAuthnError", "assertion_sha256", "batch_digest",
                      "challenge_for", "check_origin", "decode_cbor", "enrol_challenge",
                      "parse_cose_key", "request_digest", "verify_assertion",
                      "verify_registration"]
