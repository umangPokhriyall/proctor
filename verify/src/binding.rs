//! `binding` — the enforced anti-swap commit chain (phase3-spec.md §3.4, amendment §1.2.4).
//!
//! Commit-reveal is decorative unless the chain is *enforced*. The worker uploads its
//! encrypted output blob and submits `commitment = Commitment::commit(&[SHA-256(blob)])`
//! — a **single-leaf** Merkle root, which is the frozen-`core` expression of
//! "commitment = SHA-256(ciphertext)". Before the verifier picks any challenge frames it
//! re-derives that commitment from the bytes it downloaded and requires an exact match.
//!
//! Two properties fall out:
//! 1. **Freshness.** The match means the blob is frozen *before* any frame is sampled, so
//!    the worker could not have predicted (and special-cased) the challenged timestamps.
//! 2. **Content addressing.** The accepted [`OutputRef`] is derived from the blob hash, so
//!    release references the exact verified bytes — a verified blob cannot be swapped after
//!    the fact (the verified-then-swapped TOCTOU; pairs with the Phase 4 fencing token).

use proctor_core::{Commitment, OutputRef};
use sha2::{Digest, Sha256};

use crate::VerifyError;

/// SHA-256 of the ciphertext blob — the single Merkle leaf the worker committed to.
fn blob_leaf(blob: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(blob);
    h.finalize().into()
}

/// Derive the content-addressed [`OutputRef`] from the blob's SHA-256: the leading 128
/// bits, big-endian. `OutputRef` is a frozen `u128` handle; addressing it to the committed
/// bytes is what makes release reference the exact verified blob. 128 bits gives a ~2^64
/// birthday bound — ample for a content address — and we do not relitigate the frozen width.
fn content_address(leaf: &[u8; 32]) -> OutputRef {
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&leaf[..16]);
    OutputRef(u128::from_be_bytes(hi))
}

/// The single-leaf commitment a committer submits for `blob`:
/// `Commitment::commit(&[SHA-256(blob)])` — exactly what [`check_binding`] re-derives. Exposed
/// (additive seam) so a committer-side self-check (the `bench` harness) can derive the precise
/// commitment without re-implementing the hash; the worker/verifier already compute this.
#[must_use]
pub fn commit_for_blob(blob: &[u8]) -> Commitment {
    Commitment::commit(&[blob_leaf(blob)])
}

/// Check the single-leaf commit binding: `Commitment::commit(&[SHA-256(blob)])` must
/// equal the worker's `submitted` commitment (frozen `core::Commitment`, single leaf).
/// Returns the content-addressed [`OutputRef`] on success, or
/// [`VerifyError::BindingMismatch`] on any divergence.
///
/// **This must pass before any challenge frame is chosen** (phase3-spec.md §0 step 1) —
/// the per-segment flow ([`crate::compare`]) calls it first and aborts on mismatch.
pub fn check_binding(blob: &[u8], submitted: &Commitment) -> Result<OutputRef, VerifyError> {
    let leaf = blob_leaf(blob);
    let expected = Commitment::commit(&[leaf]);
    if &expected == submitted {
        Ok(content_address(&leaf))
    } else {
        Err(VerifyError::BindingMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The honest worker commits to exactly the bytes it uploaded.
    fn honest_commit(blob: &[u8]) -> Commitment {
        Commitment::commit(&[blob_leaf(blob)])
    }

    #[test]
    fn honest_blob_binds_and_is_content_addressed() {
        let blob = b"nonce || ciphertext || tag :: the encrypted output wire bytes";
        let commitment = honest_commit(blob);

        let output = check_binding(blob, &commitment).expect("honest blob must bind");

        // The OutputRef is the content address of the committed bytes: deterministic and
        // exactly the leading 128 bits of SHA-256(blob).
        let leaf = blob_leaf(blob);
        let mut hi = [0u8; 16];
        hi.copy_from_slice(&leaf[..16]);
        assert_eq!(output, OutputRef(u128::from_be_bytes(hi)));
    }

    #[test]
    fn blob_swapped_after_commit_is_rejected() {
        // Worker commits to `blob`, then serves a mutated blob (the post-commit swap).
        let blob = b"the originally committed ciphertext blob";
        let commitment = honest_commit(blob);

        let mut swapped = blob.to_vec();
        swapped[0] ^= 0x01; // one flipped bit ⇒ a different SHA-256 ⇒ a different root

        assert!(matches!(
            check_binding(&swapped, &commitment),
            Err(VerifyError::BindingMismatch)
        ));
    }

    #[test]
    fn wholesale_substitution_is_rejected() {
        let committed = b"committed bytes";
        let commitment = honest_commit(committed);
        let other = b"a completely different output blob";
        assert!(matches!(
            check_binding(other, &commitment),
            Err(VerifyError::BindingMismatch)
        ));
    }

    #[test]
    fn distinct_blobs_get_distinct_output_refs() {
        let a = check_binding(b"blob-a", &honest_commit(b"blob-a")).unwrap();
        let b = check_binding(b"blob-b", &honest_commit(b"blob-b")).unwrap();
        assert_ne!(a, b, "content addresses must distinguish different blobs");
    }
}
