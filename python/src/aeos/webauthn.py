"""WebAuthn assertion verification and the AE-OS challenge constructions.

A person approves with a passkey: the authenticator signs a challenge built from one request
(or one batch of requests). Everything an auditor needs to check that signature is public and
uses only `cryptography`, so nothing here trusts the party that wrote the record.

The verification follows W3C WebAuthn Level 3, section 7.2 ("Verifying an Authentication
Assertion"), for the parts a relying party can check offline: the client data (`type`,
`challenge`, `origin`, no `crossOrigin` or `topOrigin`), the authenticator data (`rpIdHash`, the
UP and UV flags, the backup flags) and the signature over `authenticatorData || SHA-256(
clientDataJSON)` for ES256 (COSE -7) and EdDSA (COSE -8). The signature counter is advisory:
synced passkeys report 0, so it is returned and never required to rise. Single use is the
nonce's job, checked by the caller.

Public keys are COSE_Key maps in the CTAP2 canonical encoding (WebAuthn section 6.5.1.1) and are
parsed strictly: a key that is not canonical, is on another curve, is off the curve, or is of
small order is refused.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, List, Sequence, Tuple
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import keys

CHALLENGE_CONTEXT = b"aeos/approval-challenge/v1\n"
REQUEST_CONTEXT = b"aeos/request/v1\n"
BATCH_CONTEXT = b"aeos/approval-batch/v1\n"
BATCH_CONTEXT_NAME = "aeos/approval-batch/v1"
DOCUMENT_TOOL = "aeos/document"          # the leading item of a batch that signs a document
MIN_NONCE = 16
MAX_BATCH = 256

COSE_ES256, COSE_EDDSA = -7, -8
FLAG_UP, FLAG_BE, FLAG_BS, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x08, 0x10, 0x04, 0x40, 0x80
_P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1


class WebAuthnError(ValueError):
    """An assertion or key that does not stand; the message says which check failed."""


# ---- the constructions ---------------------------------------------------------------


def request_digest(tool: str, args_sha256: bytes) -> bytes:
    """SHA-256(b"aeos/request/v1\\n" || tool || b"\\n" || args_sha256): names one request."""
    if len(args_sha256) != 32:
        raise WebAuthnError("args_sha256 must be 32 bytes")
    return hashlib.sha256(REQUEST_CONTEXT + tool.encode("utf-8") + b"\n" + args_sha256).digest()


def batch_digest(items: Sequence[Tuple[str, bytes]]) -> bytes:
    """SHA-256(b"aeos/approval-batch/v1\\n" || item_1 || b"\\n" || item_2 ...), where an item is
    tool || b"\\0" || args_sha256, in the order shown to the person."""
    if not 1 <= len(items) <= MAX_BATCH:
        raise WebAuthnError(f"a batch holds 1 to {MAX_BATCH} items")
    parts = []
    for tool, args in items:
        if not isinstance(tool, str) or "\0" in tool or len(args) != 32:
            raise WebAuthnError("a batch item is a tool name without NUL and a 32-byte digest")
        parts.append(tool.encode("utf-8") + b"\0" + args)
    return hashlib.sha256(BATCH_CONTEXT + b"\n".join(parts)).digest()


def challenge_for(nonce: bytes, digest: bytes) -> bytes:
    """What the authenticator signs: SHA-256(b"aeos/approval-challenge/v1\\n" || nonce || digest)."""
    if len(nonce) < MIN_NONCE or len(digest) != 32:
        raise WebAuthnError(f"the nonce must be at least {MIN_NONCE} bytes")
    return hashlib.sha256(CHALLENGE_CONTEXT + nonce + digest).digest()


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


# ---- COSE keys -------------------------------------------------------------------------


def _head(data: bytes, pos: int) -> Tuple[int, int, int]:
    """(major, argument, next position) of a definite-length, shortest-form CBOR head."""
    if pos >= len(data):
        raise WebAuthnError("the key is truncated")
    major, info = data[pos] >> 5, data[pos] & 31
    pos += 1
    if info < 24:
        return major, info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if width is None or pos + width > len(data):
        raise WebAuthnError("the key is not definite-length CBOR")
    n = int.from_bytes(data[pos:pos + width], "big")
    if n < {24: 24, 25: 0x100, 26: 0x10000, 27: 0x100000000}[info]:
        raise WebAuthnError("the key is not in shortest-form CBOR")
    return major, n, pos + width


def parse_cose_key(data: bytes) -> Tuple[int, Any]:
    """(COSE algorithm, public key object) from a canonical COSE_Key, or WebAuthnError."""
    if not isinstance(data, bytes) or not data or len(data) > 256:
        raise WebAuthnError("the key is empty or too long")
    major, count, pos = _head(data, 0)
    if major != 5 or not 3 <= count <= 5:
        raise WebAuthnError("the key is not a COSE_Key map")
    fields, last = {}, None
    for _ in range(count):
        start = pos
        kmaj, k, pos = _head(data, pos)
        if kmaj not in (0, 1):
            raise WebAuthnError("a COSE_Key label is not an integer")
        label = k if kmaj == 0 else -1 - k
        key_bytes = data[start:pos]
        if last is not None and not (len(key_bytes), key_bytes) > (len(last), last):
            raise WebAuthnError("the key is not in CTAP2 canonical order (or repeats a label)")
        last = key_bytes
        vmaj, v, pos = _head(data, pos)
        if vmaj in (0, 1):
            fields[label] = v if vmaj == 0 else -1 - v
        elif vmaj == 2:
            if pos + v > len(data):
                raise WebAuthnError("the key is truncated")
            fields[label] = data[pos:pos + v]
            pos += v
        else:
            raise WebAuthnError("a COSE_Key value is not an integer or byte string")
    if pos != len(data):
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


# ---- the assertion -----------------------------------------------------------------------


@dataclass(frozen=True)
class Assertion:
    flags: int
    sign_count: int                 # advisory only


def check_origin(rp_id: str, origin: str) -> None:
    """The relying party id and origin a credential may declare: a web origin, https (or
    http on localhost), whose host is the relying party id or a subdomain of it."""
    if not isinstance(rp_id, str) or not isinstance(origin, str) or not rp_id or rp_id != rp_id.lower():
        raise WebAuthnError("the relying party id must be non-empty lower-case text")
    try:
        u = urlsplit(origin)
        host, _ = u.hostname, u.port
    except ValueError:
        raise WebAuthnError("the origin is not a web origin") from None
    ok_scheme = u.scheme == "https" or (u.scheme == "http" and host == "localhost")
    if (not ok_scheme or not host or u.path or u.query or u.fragment or u.username
            or origin != f"{u.scheme}://{u.netloc}"):
        raise WebAuthnError("the origin is not a web origin (scheme://host[:port], https)")
    if host != rp_id and not host.endswith("." + rp_id):
        raise WebAuthnError("the origin's host is not the relying party id or under it")


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
    try:
        client = json.loads(client_data_json.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("the client data is not JSON") from None
    if not isinstance(client, dict):
        raise WebAuthnError("the client data is not a JSON object")
    if client.get("type") != "webauthn.get":
        raise WebAuthnError("the client data type is not webauthn.get")
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
    ad = authenticator_data
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
    if flags & FLAG_AT:
        raise WebAuthnError("an assertion carries no attested credential data")
    if bool(flags & FLAG_ED) != (len(ad) > 37):
        raise WebAuthnError("the extension data flag does not match the authenticator data")
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


__all__: List[str] = ["Assertion", "WebAuthnError", "assertion_sha256", "batch_digest",
                      "challenge_for", "check_origin", "parse_cose_key", "request_digest",
                      "verify_assertion"]
