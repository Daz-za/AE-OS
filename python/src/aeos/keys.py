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


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
