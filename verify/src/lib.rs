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
//! **Session 1** landed the two leaf primitives: [`ssim`] (single-scale SSIM over luma)
//! and [`frame`] (Y-plane extraction over the no-disk ffmpeg path). **Session 2** added
//! [`binding`] (the enforced single-leaf commit chain → content-addressed `OutputRef`)
//! and [`compare`] (the per-segment verify flow). **Session 3** added [`detection`] (the exact
//! hypergeometric detection-probability family with the `P_MIN` floor). **Session 4** adds [`roc`]
//! (calibration/held-out split, FAR/FRR with Clopper–Pearson intervals, threshold selection) and
//! the `verify_eval` study.

#![forbid(unsafe_code)]

use thiserror::Error;

pub mod binding;
pub mod compare;
pub mod detection;
pub mod frame;
pub mod roc;
pub mod ssim;

pub use binding::check_binding;
pub use compare::{
    verify_segment, RocThreshold, SamplePlan, SegmentInputs, Verdict, ROC_THRESHOLD_PATH,
};
pub use detection::{p_detect_binomial, p_detect_hypergeometric, P_MIN};
pub use frame::{extract_y_frame, Frame};
pub use roc::{
    clopper_pearson, rates, select_threshold_youden, Class, DataSet, Sample, Stratum, Variant,
};
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
    /// The single-leaf commit binding failed: `Commitment::commit(&[SHA-256(blob)])`
    /// did not equal the worker's submitted commitment (phase3-spec.md §3.4). The
    /// output is tamper-evident; no challenge frame is chosen.
    #[error("commit binding failed: blob does not match the submitted commitment")]
    BindingMismatch,
    /// The committed ROC threshold file could not be read or parsed. The verifier
    /// refuses to run on an unknown threshold rather than invent one.
    #[error("could not load ROC threshold from {path}: {reason}")]
    ThresholdLoad {
        /// The path that failed to load.
        path: String,
        /// The underlying I/O or parse error.
        reason: String,
    },
}
