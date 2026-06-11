//! proctor `verify` — the trusted re-execution comparator (phase3-spec.md).
//!
//! The comparator is **hand-rolled SSIM against a calibrated ROC threshold** (locked
//! decision #4), not pHash: we measure *transcode fidelity* against cheap-downscale,
//! wrong-bitrate, and frame-substitution attacks, which demands a structural metric.
//! Every number is owned and explainable (measure-never-guess), not delegated to an
//! opaque crate.
//!
//! `verify` is `#![forbid(unsafe_code)]`. The only place it touches ffmpeg is through
//! [`crypto::ffmpeg_no_disk`] (the no-disk memfd primitive), so all `unsafe` stays
//! confined to `crypto::sys` and no media ever lands on a disk-backed file.
//!
//! **Session 1 (this commit)** lands the two leaf primitives: [`ssim`] (single-scale
//! SSIM over luma) and [`frame`] (Y-plane extraction at a timestamp over the no-disk
//! ffmpeg path). `binding`, `compare`, `detection`, and `roc` arrive in later sessions.

#![forbid(unsafe_code)]

use thiserror::Error;

pub mod frame;
pub mod ssim;

pub use frame::{extract_y_frame, Frame};
pub use ssim::ssim;

/// Errors surfaced by the verification path.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Two frames handed to [`ssim`] have different dimensions — SSIM is undefined
    /// across mismatched planes. The caller (`compare`) extracts both at the same
    /// `(w, h)`, so this is a programming error, never a worker-controlled input.
    #[error("frame dimension mismatch: {0:?} vs {1:?}")]
    DimensionMismatch((u32, u32), (u32, u32)),
    /// A raw `gray` extraction returned a byte count other than `w * h` — the
    /// decoded plane was truncated or the requested geometry was not honoured.
    #[error("extracted frame is {got} luma bytes, expected w*h = {expected}")]
    FrameSize {
        /// The expected luma byte count (`width * height`).
        expected: usize,
        /// The byte count ffmpeg actually produced.
        got: usize,
    },
    /// A failure in the underlying no-disk crypto/ffmpeg path (spawn, timeout,
    /// non-zero exit, or memfd I/O).
    #[error("no-disk ffmpeg/crypto failure: {0}")]
    Crypto(#[from] crypto::CryptoError),
}
