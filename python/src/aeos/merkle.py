"""RFC 9162 (Certificate Transparency v2) Merkle tree hashing and proofs.

leaf hash = SHA-256(0x00 || data), node hash = SHA-256(0x01 || left || right).
Inclusion proofs follow RFC 9162 s.2.1.3 and consistency proofs s.2.1.4.
All functions take a list of leaf hashes.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import List, Sequence

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: Sequence[bytes]) -> bytes:
    """Merkle tree hash over leaf hashes, computed bottom-up."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    level = list(leaves)
    # RFC 9162 trees are left-balanced; pairing left to right and promoting an odd
    # last node unchanged produces the same root as the recursive definition.
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """PATH(m, D[n]) from RFC 9162 s.2.1.3.1."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes],
                     expected_root: bytes) -> bool:
    """RFC 9162 s.2.1.3.2. `leaf` is the leaf hash."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn, sn = fn >> 1, sn >> 1
        else:
            r = node_hash(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and hmac.compare_digest(r, expected_root)


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def consistency_proof(old_size: int, leaves: Sequence[bytes]) -> List[bytes]:
    """PROOF(m, D[n]) from RFC 9162 s.2.1.4.1."""
    n = len(leaves)
    if not 0 < old_size <= n:
        raise ValueError("old size must be between 1 and the current size")
    if old_size == n:
        return []
    return _subproof(old_size, leaves, True)


def verify_consistency(old_size: int, new_size: int, proof: Sequence[bytes],
                       old_root: bytes, new_root: bytes) -> bool:
    """RFC 9162 s.2.1.4.2."""
    if old_size == new_size:
        return len(proof) == 0 and hmac.compare_digest(old_root, new_root)
    if not 0 < old_size < new_size:
        return False
    proof = list(proof)
    if not proof:
        return False
    if old_size & (old_size - 1) == 0:          # power of two: old root is a subtree
        proof = [old_root] + proof
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn, sn = fn >> 1, sn >> 1
        else:
            sr = node_hash(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return (sn == 0 and hmac.compare_digest(fr, old_root)
            and hmac.compare_digest(sr, new_root))
