//! proctor `verify` — SSIM comparator, ROC threshold calibration, detection-probability
//! math, and commit-reveal verification.
//!
//! The comparator is **SSIM against a calibrated ROC threshold** (locked decision #4),
//! not pHash: we measure *transcode fidelity* against cheap-downscale and frame-substitution
//! attacks, which demands a structural metric. The threshold is read from a committed ROC
//! file (Phase 3) — never a hardcoded constant.
//!
//! This crate must never re-execute ffmpeg itself (that is the `verifier` binary's job) and
//! must never know about transport.
//!
//! Phase 0 declares **shape only** — every body is `todo!()`. Real logic + the SSIM dep
//! land in Phase 3.

use proctor_core::{Commitment, Reveal};
use thiserror::Error;

/// A decoded video frame (planar luma, for SSIM). Layout is finalized in Phase 3.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub luma: Vec<u8>,
}

/// A decision threshold read from the committed ROC study (Phase 3), with its provenance.
/// Never a hardcoded number — `provenance` points at the `bench/results/` file it came from.
pub struct RocThreshold {
    pub value: f64,
    pub provenance: String,
}

/// Structural-similarity score in `[0.0, 1.0]` between a reference frame and a candidate frame.
pub fn ssim(reference: &Frame, candidate: &Frame) -> f64 {
    todo!(
        "Phase 3: SSIM ({}x{} vs {}x{})",
        reference.width,
        reference.height,
        candidate.width,
        candidate.height
    )
}

/// Per-task detection probability `1 - (1 - p)^(f * n)` for sampling fraction `p`,
/// tamper fraction `f`, and `n` segments. Backs the sampling-rate choice in Phase 3.
pub fn detection_probability(p: f64, f: f64, n: u32) -> f64 {
    todo!("Phase 3: detection-probability curve (p={p}, f={f}, n={n})")
}

/// Verify a worker's revealed commitment against the verifier-recomputed output hash.
pub fn verify_commitment(reveal: &Reveal, recomputed: &Commitment) -> bool {
    todo!("Phase 3: commit-reveal check ({reveal:?} vs {recomputed:?})")
}

/// Errors surfaced by the verification path.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Reference and candidate frames have mismatched dimensions.
    #[error("frame dimension mismatch: {0:?} vs {1:?}")]
    DimensionMismatch((u32, u32), (u32, u32)),
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
