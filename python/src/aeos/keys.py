"""Ed25519 signing keys for log checkpoints."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                                Ed25519PublicKey)


def generate_key(path: Path) -> Ed25519PrivateKey:
    """Create a new key and write it as unencrypted PKCS#8 PEM, readable by the owner only."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def load_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def key_id(public_key: bytes) -> str:
    """Short identifier for a public key: first 16 hex digits of its SHA-256."""
    return hashlib.sha256(public_key).hexdigest()[:16]


# Edwards25519, for the strict checks below. Ed25519 verifiers disagree about keys and
# signature points of small order (a forgery that verifies for every message under a
# small-order key is possible), and about scalars that are not reduced. AE-OS refuses all of
# them, as Rust's `verify_strict` does, so every verifier gives one answer.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(enc: bytes):
    """The affine point an encoding names, or None if it names none."""
    if len(enc) != 32:
        return None
    n = int.from_bytes(enc, "little")
    y, sign = (n & ((1 << 255) - 1)) % _P, n >> 255
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x2 = u * pow(v, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = (_P - x) % _P
    return x, y


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, _P) % _P,
            (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P)


def is_small_order(enc: bytes) -> bool:
    """True if the encoded point has an order dividing 8 (including the identity)."""
    point = _decode_point(enc)
    if point is None:
        return False
    for _ in range(3):
        point = _add(point, point)
    return point == (0, 1)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Strict Ed25519 verification: small-order keys and R points, and unreduced S, fail."""
    if (len(signature) != 64 or is_small_order(public_key) or is_small_order(signature[:32])
            or int.from_bytes(signature[32:], "little") >= _L):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
