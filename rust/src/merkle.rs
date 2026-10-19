//! RFC 9162 (Certificate Transparency v2) Merkle tree hashing and proof verification.
//!
//! leaf hash = SHA-256(0x00 || data), node hash = SHA-256(0x01 || left || right).

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn empty_root() -> Hash {
    Sha256::digest(b"").into()
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(left: &[u8], right: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Merkle tree hash over leaf hashes. RFC 9162 trees are left-balanced; pairing left
/// to right and promoting an odd last node unchanged gives the same root.
pub fn root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Hash> = level
            .chunks_exact(2)
            .map(|p| node_hash(&p[0], &p[1]))
            .collect();
        if level.len() % 2 == 1 {
            next.push(level[level.len() - 1]);
        }
        level = next;
    }
    level[0]
}

/// Compare two digests without stopping at the first difference.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// RFC 9162 section 2.1.3.2. `leaf` is the leaf hash.
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Vec<u8>],
    expected_root: &[u8],
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn, mut r) = (index, size - 1, *leaf);
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ != 0 && fn_ & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && same(&r, expected_root)
}

/// RFC 9162 section 2.1.4.2.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof: &[Vec<u8>],
    old_root: &[u8],
    new_root: &[u8],
) -> bool {
    if old_size == new_size {
        return proof.is_empty() && same(old_root, new_root);
    }
    if !(0 < old_size && old_size < new_size) || proof.is_empty() {
        return false;
    }
    let mut path: Vec<Vec<u8>> = Vec::with_capacity(proof.len() + 1);
    if old_size & (old_size - 1) == 0 {
        // power of two: the old root is itself a subtree of the new tree
        path.push(old_root.to_vec());
    }
    path.extend_from_slice(proof);
    let (mut fn_, mut sn) = (old_size - 1, new_size - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (path[0].clone(), path[0].clone());
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr).to_vec();
            sr = node_hash(c, &sr).to_vec();
            if fn_ & 1 == 0 {
                while fn_ != 0 && fn_ & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c).to_vec();
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && same(&fr, old_root) && same(&sr, new_root)
}
