//! `commit` — Merkle commit-reveal over opaque leaves. See `phase1-spec.md` §7.
//!
//! `core` owns the *protocol* of commit-reveal, not its semantics. Leaves are
//! opaque 32-byte hashes; what a leaf *means* — a decoded-frame hash for a
//! `Transcode`, an ordered-input hash for a `Stitch` — is defined above `core`.
//! That keeps this primitive tight and frozen.
//!
//! **Why a Merkle commitment and not a single output hash (rejected alternative):**
//! a lone `SHA-256` of the whole output is tamper-evident but cannot be opened on a
//! *random subset* with a cheap, sound proof — the worker would have to ship the
//! whole output to prove any part. The Merkle root lets the verifier reveal and
//! prove only the challenged leaves.
//!
//! **Sans-IO / no randomness (§11):** committing, opening, and verifying are pure,
//! deterministic functions of their inputs. The *challenge* (which indices) is the
//! caller's random choice (`sched`/`verifier`); `core` neither samples nor stores
//! it — it only verifies inclusion against the committed root.
//!
//! ## Tree construction (frozen)
//! Level 0 is the per-leaf node `H(0x00 ‖ leaf)`; an internal node is
//! `H(0x01 ‖ left ‖ right)` (RFC-6962-style domain separation, so an internal
//! node can never be presented as a leaf without a SHA-256 preimage). The node
//! count is padded up to the next power of two with a fixed zero node, so every
//! level is full and a leaf's position determines the hash order at each step.
//! An inclusion proof therefore binds to its leaf *index*: the index bits choose
//! left/right at every level, so a valid leaf cannot be replayed at another index.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The Merkle root over a task's opaque leaves. Submitted at task completion,
/// **before** the worker learns which indices will be challenged (commit-reveal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

/// A position in the leaf vector. Identifies *which* leaf a challenge selects and a
/// reveal opens; the proof's hash order is derived from this index's bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeafIndex(pub u32);

/// The set of leaf indices to reveal — chosen by the **caller** (`sched`/`verifier`)
/// after seeing the [`Commitment`], never sampled by `core`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Challenge {
    pub indices: Vec<LeafIndex>,
}

/// The authenticating path for one leaf: the sibling node at each level from the
/// leaf up to (but excluding) the root. Direction at each level comes from the
/// leaf index, so the proof is meaningless without its index.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<[u8; 32]>,
}

/// A worker's answer to a [`Challenge`]: the revealed opaque leaves and the proof
/// that each sits at its claimed index under the committed root. `leaves[i]` is
/// proven by `proofs[i]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Reveal {
    pub leaves: Vec<(LeafIndex, [u8; 32])>,
    pub proofs: Vec<MerkleProof>,
}

/// Domain-separated leaf node: `H(0x00 ‖ leaf)`.
fn hash_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

/// Domain-separated internal node: `H(0x01 ‖ left ‖ right)`.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

impl Commitment {
    /// Build the Merkle root over `leaves`. Pure and deterministic. An empty leaf
    /// set commits to the zero root (a degenerate, opens-to-nothing commitment).
    #[must_use]
    pub fn commit(leaves: &[[u8; 32]]) -> Commitment {
        if leaves.is_empty() {
            return Commitment([0u8; 32]);
        }
        let mut level: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
        level.resize(level.len().next_power_of_two(), [0u8; 32]);
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
        }
        Commitment(level[0])
    }
}

/// Build an inclusion proof for `index` against `leaves`. Pure; deterministic.
/// Returns `None` if `index` is out of range — `core` never invents a proof.
#[must_use]
pub fn prove(leaves: &[[u8; 32]], index: LeafIndex) -> Option<MerkleProof> {
    let idx0 = index.0 as usize;
    if idx0 >= leaves.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
    level.resize(level.len().next_power_of_two(), [0u8; 32]);

    let mut idx = idx0;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        siblings.push(level[idx ^ 1]);
        idx >>= 1;
        level = level
            .chunks(2)
            .map(|pair| hash_node(&pair[0], &pair[1]))
            .collect();
    }
    Some(MerkleProof { siblings })
}

impl Reveal {
    /// Open every index named by `challenge` against `leaves`. Pure; deterministic.
    /// Returns `None` if any index is out of range.
    #[must_use]
    pub fn open(leaves: &[[u8; 32]], challenge: &Challenge) -> Option<Reveal> {
        let mut revealed = Vec::with_capacity(challenge.indices.len());
        let mut proofs = Vec::with_capacity(challenge.indices.len());
        for &idx in &challenge.indices {
            let proof = prove(leaves, idx)?;
            revealed.push((idx, leaves[idx.0 as usize]));
            proofs.push(proof);
        }
        Some(Reveal {
            leaves: revealed,
            proofs,
        })
    }
}

/// Fold one leaf with its proof, using the index bits to order each hash, and check
/// the result equals the committed `root`. A leftover index bit after the proof is
/// consumed means the index does not belong to a tree of this height — rejected.
fn verify_one(root: &Commitment, index: LeafIndex, leaf: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut h = hash_leaf(leaf);
    let mut idx = index.0 as usize;
    for sib in &proof.siblings {
        h = if idx & 1 == 0 {
            hash_node(&h, sib)
        } else {
            hash_node(sib, &h)
        };
        idx >>= 1;
    }
    idx == 0 && h == root.0
}

/// Pure. `true` iff every revealed leaf is provably the committed leaf at its index
/// under `root`. The worker cannot alter a leaf after committing, and cannot predict
/// the challenge (the caller chooses indices *after* receiving the commitment). A
/// length mismatch between `leaves` and `proofs` is rejected outright.
#[must_use]
pub fn verify_inclusion(root: &Commitment, reveal: &Reveal) -> bool {
    if reveal.leaves.len() != reveal.proofs.len() {
        return false;
    }
    reveal
        .leaves
        .iter()
        .zip(reveal.proofs.iter())
        .all(|((idx, leaf), proof)| verify_one(root, *idx, leaf, proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic distinct leaves: leaf `i` is the byte `i` repeated.
    fn leaves(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i; 32]).collect()
    }

    fn challenge(indices: &[u32]) -> Challenge {
        Challenge {
            indices: indices.iter().map(|&i| LeafIndex(i)).collect(),
        }
    }

    #[test]
    fn single_leaf_round_trips() {
        let ls = leaves(1);
        let root = Commitment::commit(&ls);
        let reveal = Reveal::open(&ls, &challenge(&[0])).unwrap();
        assert!(reveal.proofs[0].siblings.is_empty(), "height-0 tree, no siblings");
        assert!(verify_inclusion(&root, &reveal));
    }

    #[test]
    fn every_index_verifies_power_of_two() {
        let ls = leaves(8);
        let root = Commitment::commit(&ls);
        for i in 0..8 {
            let reveal = Reveal::open(&ls, &challenge(&[i])).unwrap();
            assert!(verify_inclusion(&root, &reveal), "index {i} should verify");
        }
    }

    #[test]
    fn every_index_verifies_non_power_of_two() {
        // 5 leaves → padded to 8 internally; every real index still opens soundly.
        let ls = leaves(5);
        let root = Commitment::commit(&ls);
        for i in 0..5 {
            let reveal = Reveal::open(&ls, &challenge(&[i])).unwrap();
            assert!(verify_inclusion(&root, &reveal), "index {i} should verify");
        }
    }

    #[test]
    fn multi_leaf_challenge_round_trips() {
        let ls = leaves(7);
        let root = Commitment::commit(&ls);
        let reveal = Reveal::open(&ls, &challenge(&[1, 4, 6])).unwrap();
        assert!(verify_inclusion(&root, &reveal));
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let ls = leaves(8);
        let root = Commitment::commit(&ls);
        let mut reveal = Reveal::open(&ls, &challenge(&[3])).unwrap();
        // Flip a byte of the revealed leaf — the proof no longer folds to the root.
        reveal.leaves[0].1[0] ^= 0xFF;
        assert!(!verify_inclusion(&root, &reveal));
    }

    #[test]
    fn corrupted_proof_is_rejected() {
        let ls = leaves(8);
        let root = Commitment::commit(&ls);
        let mut reveal = Reveal::open(&ls, &challenge(&[3])).unwrap();
        reveal.proofs[0].siblings[0][0] ^= 0x01;
        assert!(!verify_inclusion(&root, &reveal));
    }

    #[test]
    fn relabeled_index_is_rejected() {
        // A genuine leaf-2 opening replayed under index 5 must fail: direction is
        // index-bound, so the fold no longer reaches the root.
        let ls = leaves(8);
        let root = Commitment::commit(&ls);
        let mut reveal = Reveal::open(&ls, &challenge(&[2])).unwrap();
        reveal.leaves[0].0 = LeafIndex(5);
        assert!(!verify_inclusion(&root, &reveal));
    }

    #[test]
    fn reveal_against_a_different_root_fails() {
        // The negative test the spec calls out: a reveal built from one leaf set
        // must not verify against a *different* commitment.
        let set_a = leaves(8);
        let mut set_b = leaves(8);
        set_b[3] = [0xAB; 32]; // perturb one leaf so the roots differ
        let root_a = Commitment::commit(&set_a);
        let root_b = Commitment::commit(&set_b);
        assert_ne!(root_a, root_b);

        let reveal_b = Reveal::open(&set_b, &challenge(&[3])).unwrap();
        assert!(verify_inclusion(&root_b, &reveal_b), "valid against its own root");
        assert!(
            !verify_inclusion(&root_a, &reveal_b),
            "must not verify against a foreign root"
        );
    }

    #[test]
    fn length_mismatch_is_rejected() {
        let ls = leaves(4);
        let root = Commitment::commit(&ls);
        let mut reveal = Reveal::open(&ls, &challenge(&[0, 1])).unwrap();
        reveal.proofs.pop(); // leaves: 2, proofs: 1
        assert!(!verify_inclusion(&root, &reveal));
    }

    #[test]
    fn out_of_range_index_yields_no_proof() {
        let ls = leaves(4);
        assert!(prove(&ls, LeafIndex(4)).is_none());
        assert!(Reveal::open(&ls, &challenge(&[2, 9])).is_none());
    }

    #[test]
    fn empty_reveal_is_vacuously_true() {
        // No leaves challenged ⇒ nothing to disprove. The challenger decides coverage.
        let root = Commitment::commit(&leaves(4));
        assert!(verify_inclusion(&root, &Reveal::default()));
    }
}
