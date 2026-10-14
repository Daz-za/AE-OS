"""Merkle tree tests, including the RFC 6962 test vectors used by Certificate Transparency."""
import hashlib

import pytest

from aeos_receipts import merkle

# Leaf inputs and roots from the Certificate Transparency reference test suite.
LEAVES = [bytes.fromhex(h) for h in [
    "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
    "606162636465666768696a6b6c6d6e6f"]]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
HASHES = [merkle.leaf_hash(x) for x in LEAVES]


def _recursive_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = merkle._split(len(leaves))
    return merkle.node_hash(_recursive_root(leaves[:k]), _recursive_root(leaves[k:]))


def test_empty_tree():
    assert merkle.root([]) == hashlib.sha256(b"").digest()


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_roots(n):
    assert merkle.root(HASHES[:n]).hex() == ROOTS[n - 1]


def test_bottom_up_root_matches_recursive_definition():
    hs = [merkle.leaf_hash(bytes([i])) for i in range(70)]
    for n in range(1, 70):
        assert merkle.root(hs[:n]) == _recursive_root(hs[:n])


def test_every_inclusion_proof_verifies_and_tampering_fails():
    hs = [merkle.leaf_hash(b"leaf%d" % i) for i in range(33)]
    for n in range(1, 34):
        r = merkle.root(hs[:n])
        for i in range(n):
            proof = merkle.inclusion_proof(i, hs[:n])
            assert merkle.verify_inclusion(hs[i], i, n, proof, r)
            assert not merkle.verify_inclusion(merkle.leaf_hash(b"x"), i, n, proof, r)
            if proof:
                bad = list(proof)
                bad[0] = merkle.leaf_hash(b"bad")
                assert not merkle.verify_inclusion(hs[i], i, n, bad, r)
            if n > 1:
                assert not merkle.verify_inclusion(hs[i], (i + 1) % n, n, proof, r)


def test_every_consistency_proof_verifies_and_rewrites_fail():
    hs = [merkle.leaf_hash(b"leaf%d" % i) for i in range(33)]
    for n in range(1, 34):
        new_root = merkle.root(hs[:n])
        for m in range(1, n + 1):
            old_root = merkle.root(hs[:m])
            proof = merkle.consistency_proof(m, hs[:n])
            assert merkle.verify_consistency(m, n, proof, old_root, new_root)
            # a history where an old leaf was rewritten must not be provably consistent
            forged = list(hs[:n])
            forged[m - 1] = merkle.leaf_hash(b"rewritten")
            forged_root = merkle.root(forged)
            forged_proof = merkle.consistency_proof(m, forged)
            assert not merkle.verify_consistency(m, n, forged_proof, old_root, forged_root)
            if m < n:
                assert not merkle.verify_consistency(m, n, [], old_root, new_root)
