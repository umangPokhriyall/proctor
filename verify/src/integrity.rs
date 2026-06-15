//! `integrity` — Stitch verification: **content-address integrity, no SSIM**
//! (phase5-spec.md §5.2).
//!
//! A `Stitch` concatenates already-accepted segment outputs; its verification is
//! *integrity*, not *fidelity*. The verifier re-checks that every input the stitch
//! claims is exactly the accepted, **unswapped** output at its committed content
//! address — `Commitment::commit(&[SHA-256(blob)])` and `OutputRef =
//! lead128(SHA-256(blob))` must both match the input's declared
//! `(OutputRef, Commitment)` from the `StitchSpec`. There is no re-encode and no SSIM.
//!
//! **Why not byte-compare the worker's concatenated output?** The output is sealed
//! under AES-256-GCM with a fresh random nonce, so an independent re-concat-and-seal
//! cannot reproduce the worker's bytes. The enforceable, meaningful property is that
//! the inputs are the committed, accepted bytes in the declared order (the anti-swap
//! chain extended to the stitch manifest). The worker's own output is bound to its
//! commitment separately by [`check_binding`](crate::binding) before this runs. This is
//! the secondary path; the transcode path is the load-bearing fidelity proof
//! (kickoff §6: "Stitch may degrade to content-address checks only").

use proctor_core::{Commitment, OutputRef, VerifyDetail};

use crate::binding::check_binding;

/// One stitch input as the verifier re-checks it: the `(OutputRef, Commitment)` the
/// `StitchSpec` declared, plus the ciphertext bytes fetched from the blob store at that
/// address.
pub struct StitchInput<'a> {
    /// The content address the input claims (from the `StitchSpec`).
    pub output_ref: OutputRef,
    /// The commitment the input claims (from the `StitchSpec`).
    pub commitment: Commitment,
    /// The ciphertext bytes served at `output_ref`.
    pub blob: &'a [u8],
}

/// Verify a stitch's integrity over its (ordered) inputs. Returns the frozen
/// [`VerifyDetail`]: [`VerifyDetail::Ok`] iff **every** input's served bytes bind to
/// its declared `(OutputRef, Commitment)`; [`VerifyDetail::IntegrityViolation`] on the
/// first input whose bytes do not (a swap, a wrong address, or a corrupted blob). No
/// SSIM, no re-encode.
#[must_use]
pub fn verify_stitch_integrity(inputs: &[StitchInput<'_>]) -> VerifyDetail {
    for input in inputs {
        match check_binding(input.blob, &input.commitment) {
            // The bytes bind to the claimed commitment *and* land at the claimed address.
            Ok(addr) if addr == input.output_ref => {}
            _ => return VerifyDetail::IntegrityViolation,
        }
    }
    VerifyDetail::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn leaf(blob: &[u8]) -> [u8; 32] {
        Sha256::digest(blob).into()
    }

    fn address(blob: &[u8]) -> OutputRef {
        let l = leaf(blob);
        let mut hi = [0u8; 16];
        hi.copy_from_slice(&l[..16]);
        OutputRef(u128::from_be_bytes(hi))
    }

    fn honest(blob: &[u8]) -> (OutputRef, Commitment) {
        (address(blob), Commitment::commit(&[leaf(blob)]))
    }

    #[test]
    fn all_inputs_binding_in_order_is_ok() {
        let a = b"segment-0 ciphertext".to_vec();
        let b = b"segment-1 ciphertext".to_vec();
        let (ra, ca) = honest(&a);
        let (rb, cb) = honest(&b);
        let inputs = vec![
            StitchInput { output_ref: ra, commitment: ca, blob: &a },
            StitchInput { output_ref: rb, commitment: cb, blob: &b },
        ];
        assert_eq!(verify_stitch_integrity(&inputs), VerifyDetail::Ok);
    }

    #[test]
    fn swapped_input_bytes_are_an_integrity_violation() {
        let a = b"the accepted segment-0 output".to_vec();
        let (ra, ca) = honest(&a);
        // The store serves different bytes at the claimed address (post-acceptance swap).
        let swapped = b"a different blob entirely".to_vec();
        let inputs = vec![StitchInput { output_ref: ra, commitment: ca, blob: &swapped }];
        assert_eq!(verify_stitch_integrity(&inputs), VerifyDetail::IntegrityViolation);
    }

    #[test]
    fn right_commitment_but_wrong_declared_address_is_rejected() {
        // The bytes bind to the commitment, but the declared OutputRef is not their
        // content address — a manifest inconsistency, rejected.
        let a = b"segment bytes".to_vec();
        let (_ra, ca) = honest(&a);
        let inputs = vec![StitchInput {
            output_ref: OutputRef(0xDEAD_BEEF),
            commitment: ca,
            blob: &a,
        }];
        assert_eq!(verify_stitch_integrity(&inputs), VerifyDetail::IntegrityViolation);
    }

    #[test]
    fn empty_stitch_is_vacuously_ok() {
        assert_eq!(verify_stitch_integrity(&[]), VerifyDetail::Ok);
    }
}
