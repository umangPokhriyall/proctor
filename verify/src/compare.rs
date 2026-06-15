//! `compare` — the per-segment verification flow (phase3-spec.md §0 steps 1–4, §3.5).
//!
//! The verifier independently re-checks one segment, entirely in anonymous RAM:
//!
//! 1. **Bind** ([`binding::check_binding`](crate::binding)): re-derive the single-leaf
//!    commitment from the downloaded output blob and require it to match the worker's.
//!    Only *after* binding passes does the verifier choose challenge frames — the blob
//!    is frozen, so the worker could not have predicted them.
//! 2. **Reconstruct ground truth:** decrypt the source segment (`Role::Source`) into a
//!    memfd and independently transcode it with the frozen [`TargetProfile`] — the
//!    verifier's reference output, in RAM.
//! 3. **Compare:** decrypt the worker's output (`Role::Output`); at seeded random
//!    timestamps, extract the Y plane from both worker output and reference and compute
//!    SSIM. The segment score is the **minimum** MSSIM across sampled frames (conservative
//!    — it catches a localized frame substitution that a mean would average away).
//! 4. **Decide:** pass iff the score ≥ the threshold loaded from the committed ROC file.
//!
//! Every memfd is `zeroize_and_close`d on every path. The verdict is the frozen,
//! categorical [`VerifyDetail`] — no numeric threshold ever crosses the API.
//!
//! **Frozen-`core` detail mapping.** The spec's descriptive outcomes map onto the frozen
//! `VerifyDetail` variants: `Passed → Ok`, `FailedBinding → CommitmentMismatch`,
//! `FailedSsimBelowThreshold → FidelityBelowThreshold`, and `FailedDecrypt` /
//! `FailedReencode` → `Inconclusive` (the verifier could not reach a fidelity verdict).

use std::path::Path;

use proctor_core::{Commitment, OutputRef, TargetProfile, VerifyDetail};
use serde::{Deserialize, Serialize};

use crypto::{
    decrypt_into_memfd, transcode_no_disk, EncryptedSegment, MemFd, SecretKey, SegmentAad,
};

use crate::binding::check_binding;
use crate::frame::extract_y_frames;
use crate::ssim::ssim;
use crate::VerifyError;

/// The canonical location of the committed ROC threshold (phase3-spec.md §5). Production
/// wiring obtains the threshold via [`RocThreshold::load`] from this path — never a literal.
pub const ROC_THRESHOLD_PATH: &str = "bench/results/verify/roc-threshold.json";

/// The fidelity decision threshold, read from the committed ROC study with its provenance.
/// Never a hardcoded constant: the value is selected on a calibration set (Session 4) and
/// written to [`ROC_THRESHOLD_PATH`]; [`crate::compare::verify_segment`] takes it injected
/// so the same value drives both production and the reproducible eval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocThreshold {
    /// Minimum acceptable min-MSSIM for an honest transcode.
    pub value: f64,
    /// Provenance note (corpus hash, ffmpeg version, date) recorded by the ROC study.
    #[serde(default)]
    pub provenance: String,
}

impl RocThreshold {
    /// Load the threshold from a committed `roc-threshold.json`. Fails with
    /// [`VerifyError::ThresholdLoad`] if the file is missing or malformed — the verifier
    /// refuses to run on an unknown threshold rather than invent one.
    pub fn load(path: impl AsRef<Path>) -> Result<RocThreshold, VerifyError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| VerifyError::ThresholdLoad {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        serde_json::from_slice(&bytes).map_err(|e| VerifyError::ThresholdLoad {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }
}

/// How the verifier samples challenge frames for one segment. The seed makes the eval
/// reproducible (phase3-spec.md §3.5); production seeds from OS randomness. Both worker
/// output and reference are extracted at `(width, height)` so SSIM compares one geometry.
#[derive(Debug, Clone, Copy)]
pub struct SamplePlan {
    /// Number of challenge frames (clamped to ≥ 1 — every segment is sampled).
    pub frames: u32,
    /// Seed for the position RNG; fixed in the eval, OS-random in production.
    pub seed: u64,
    /// Segment duration in seconds (informational/provenance). The batched comparison
    /// samples normalized positions in `[0, 1)` and indexes frames, so the score does
    /// not depend on this value; it records the segment length for the study artifacts.
    pub duration_secs: f64,
    /// Common extraction width for both planes.
    pub width: u32,
    /// Common extraction height for both planes.
    pub height: u32,
}

/// Everything the verifier needs to independently re-check one segment. All key/AAD
/// material is **injected** — `verify` never fetches keys (consistent with `crypto`).
pub struct SegmentInputs<'a> {
    /// The worker's submitted single-leaf commitment over `SHA-256(output_blob)`.
    pub submitted: &'a Commitment,
    /// The worker's encrypted output blob, exactly as downloaded (the bytes the
    /// commitment binds and that decrypt to the worker's transcode under `Role::Output`).
    pub output_blob: &'a [u8],
    /// The encrypted source segment the worker was given (decrypts under `Role::Source`).
    pub source: &'a EncryptedSegment,
    /// The per-segment key (injected).
    pub key: &'a SecretKey,
    /// AAD identity for the source ciphertext.
    pub source_aad: &'a SegmentAad,
    /// AAD identity for the output ciphertext.
    pub output_aad: &'a SegmentAad,
    /// The frozen profile the worker was required to hit; the verifier re-encodes to it.
    pub profile: &'a TargetProfile,
}

/// The categorical outcome of [`verify_segment`], plus diagnostics that never cross the
/// wire. `detail` is the frozen [`VerifyDetail`]; `output` is the content-addressed
/// [`OutputRef`] once binding passes; `score` is the min-MSSIM when the comparison ran.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// The categorical verdict (frozen `core` type — no numeric threshold here).
    pub detail: VerifyDetail,
    /// Content address of the verified blob; `Some` once binding passed.
    pub output: Option<OutputRef>,
    /// The minimum MSSIM across sampled frames; `Some` only when the comparison ran.
    pub score: Option<f64>,
}

impl Verdict {
    /// Whether the segment was accepted (the only passing `VerifyDetail` is `Ok`).
    pub fn passed(&self) -> bool {
        matches!(self.detail, VerifyDetail::Ok)
    }

    fn fail(detail: VerifyDetail, output: Option<OutputRef>, score: Option<f64>) -> Self {
        Verdict { detail, output, score }
    }
}

/// Run the §0 per-segment flow against `threshold`. Returns a categorical [`Verdict`];
/// all media lives in memfds and is scrubbed on every path. The threshold is injected
/// (obtained via [`RocThreshold::load`] in production) so the same value drives the eval.
pub fn verify_segment(
    inputs: &SegmentInputs<'_>,
    plan: &SamplePlan,
    threshold: &RocThreshold,
) -> Verdict {
    // Step 1 — bind before anything else. A mismatch is tamper-evident: reject outright.
    let output_ref = match check_binding(inputs.output_blob, inputs.submitted) {
        Ok(r) => r,
        Err(_) => return Verdict::fail(VerifyDetail::CommitmentMismatch, None, None),
    };

    // Step 2 — reconstruct ground truth: decrypt source into RAM, reference-transcode.
    let source_mf =
        match decrypt_into_memfd(inputs.source, inputs.key, inputs.source_aad, "proctor-verify-src")
        {
            Ok(mf) => mf,
            Err(_) => return Verdict::fail(VerifyDetail::Inconclusive, Some(output_ref), None),
        };
    let reference_mf = match transcode_no_disk(&source_mf, inputs.profile) {
        Ok(mf) => mf,
        Err(_) => {
            source_mf.zeroize_and_close();
            return Verdict::fail(VerifyDetail::Inconclusive, Some(output_ref), None);
        }
    };
    // The decrypted source is no longer needed once the reference exists.
    source_mf.zeroize_and_close();

    // Decrypt the worker's output into RAM (the blob already bound to `output_ref`).
    let worker_mf = match parse_and_decrypt(inputs) {
        Ok(mf) => mf,
        Err(_) => {
            reference_mf.zeroize_and_close();
            return Verdict::fail(VerifyDetail::Inconclusive, Some(output_ref), None);
        }
    };

    // Step 3 — sample frames, score by the conservative minimum MSSIM.
    let score = match sampled_min_ssim(&worker_mf, &reference_mf, plan) {
        Ok(s) => s,
        Err(_) => {
            worker_mf.zeroize_and_close();
            reference_mf.zeroize_and_close();
            return Verdict::fail(VerifyDetail::Inconclusive, Some(output_ref), None);
        }
    };
    worker_mf.zeroize_and_close();
    reference_mf.zeroize_and_close();

    // Step 4 — decide against the committed threshold.
    if score >= threshold.value {
        Verdict {
            detail: VerifyDetail::Ok,
            output: Some(output_ref),
            score: Some(score),
        }
    } else {
        Verdict::fail(VerifyDetail::FidelityBelowThreshold, Some(output_ref), Some(score))
    }
}

/// Parse the worker's output blob as an [`EncryptedSegment`] and decrypt it into a memfd
/// under `Role::Output`. Separated so the error paths in [`verify_segment`] stay flat.
fn parse_and_decrypt(inputs: &SegmentInputs<'_>) -> Result<MemFd, VerifyError> {
    let enc = EncryptedSegment::from_bytes(inputs.output_blob)?;
    Ok(decrypt_into_memfd(
        &enc,
        inputs.key,
        inputs.output_aad,
        "proctor-verify-out",
    )?)
}

/// Score the segment by the minimum MSSIM across sampled frames, using the **batched**
/// decode ([`extract_y_frames`]) — one ffmpeg pass per memfd, no per-frame spawn (the
/// Phase 3 cost remedy, phase5-spec.md §5.1). The minimum (not the mean) is the
/// conservative choice: a single substituted frame drags the score down even when the
/// rest of the segment is faithful. Both memfds are extracted at the same fractions and
/// geometry, so frame `i` of the worker aligns with frame `i` of the reference.
fn sampled_min_ssim(
    worker: &MemFd,
    reference: &MemFd,
    plan: &SamplePlan,
) -> Result<f64, VerifyError> {
    let fractions = sample_fractions(plan.seed, plan.frames);
    let worker_frames = extract_y_frames(worker, &fractions, plan.width, plan.height)?;
    let reference_frames = extract_y_frames(reference, &fractions, plan.width, plan.height)?;

    let mut min = f64::INFINITY;
    for (worker_frame, reference_frame) in worker_frames.iter().zip(reference_frames.iter()) {
        let score = ssim(reference_frame, worker_frame)?;
        if score < min {
            min = score;
        }
    }
    if min.is_finite() {
        Ok(min)
    } else {
        // No frames decoded — cannot reach a fidelity verdict.
        Err(VerifyError::FrameSize {
            expected: plan.width as usize * plan.height as usize,
            got: 0,
        })
    }
}

/// Deterministic challenge positions as fractions of the segment in `[0, 1)`, from
/// `seed`, via SplitMix64. Reproducible for the eval; production passes an OS-random
/// seed. `frames` is clamped to ≥ 1 so every segment is sampled at least once (mirrors
/// the detection `P_MIN` floor). The batched extractor maps each fraction to a frame
/// index, so positions — not absolute timestamps — are what the comparison needs.
fn sample_fractions(seed: u64, frames: u32) -> Vec<f64> {
    let mut state = seed;
    (0..frames.max(1))
        .map(|_| {
            // SplitMix64 — a small, well-distributed seeded generator (no `rand` dep).
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            // Top 53 bits → a uniform fraction in [0, 1).
            (z >> 11) as f64 / (1u64 << 53) as f64
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proctor_core::{Codec, Container, JobId, SegmentId};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use crypto::{encrypt, Role};

    fn ffmpeg_available() -> bool {
        Command::new("ffmpeg")
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn corpus(name: &str) -> Option<Vec<u8>> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../bench/corpus")
            .join(name);
        std::fs::read(p).ok()
    }

    fn profile() -> TargetProfile {
        TargetProfile {
            codec: Codec::H264,
            width: 320,
            height: 240,
            bitrate_kbps: 800,
            container: Container::Mp4,
        }
    }

    fn aad(role: Role) -> SegmentAad {
        SegmentAad {
            job: JobId(11),
            segment: SegmentId(4),
            role,
        }
    }

    /// Produce an honest encrypted output blob: transcode `plaintext` to `profile` over
    /// memfds, then seal under `Role::Output` — exactly what an honest worker uploads.
    fn sealed_transcode(plaintext: &[u8], key: &SecretKey) -> Vec<u8> {
        let mut src = MemFd::create("proctor-test-src").unwrap();
        src.write_all(plaintext).unwrap();
        let mut out = transcode_no_disk(&src, &profile()).expect("test transcode");
        let bytes = out.read_to_secret_buf().unwrap().as_bytes().to_vec();
        src.zeroize_and_close();
        out.zeroize_and_close();
        encrypt(&bytes, key, &aad(Role::Output)).unwrap().to_bytes()
    }

    fn plan() -> SamplePlan {
        SamplePlan {
            frames: 3,
            seed: 0x5EED_1234_ABCD_0001, // any fixed seed keeps the eval reproducible
            duration_secs: 3.0,
            width: 160,
            height: 120,
        }
    }

    // A test-only fixed threshold (the spec permits a fixed test threshold; production
    // loads roc-threshold.json). High enough that an honest near-identical re-encode
    // clears it and a cross-clip substitution does not.
    fn fixed_threshold() -> RocThreshold {
        RocThreshold {
            value: 0.9,
            provenance: "test-fixed".to_string(),
        }
    }

    #[test]
    fn honest_segment_passes() {
        if !ffmpeg_available() {
            eprintln!("SKIP honest_segment_passes: ffmpeg not found");
            return;
        }
        let Some(plaintext) = corpus("gradient.mp4") else {
            eprintln!("SKIP: corpus gradient.mp4 unavailable");
            return;
        };
        let key = SecretKey::generate().unwrap();
        let source = encrypt(&plaintext, &key, &aad(Role::Source)).unwrap();
        let output_blob = sealed_transcode(&plaintext, &key);
        let commitment = Commitment::commit(&[sha256(&output_blob)]);

        let inputs = SegmentInputs {
            submitted: &commitment,
            output_blob: &output_blob,
            source: &source,
            key: &key,
            source_aad: &aad(Role::Source),
            output_aad: &aad(Role::Output),
            profile: &profile(),
        };
        let verdict = verify_segment(&inputs, &plan(), &fixed_threshold());

        assert!(verdict.passed(), "honest segment must pass, got {verdict:?}");
        assert_eq!(verdict.detail, VerifyDetail::Ok);
        assert!(verdict.output.is_some(), "binding must have produced an OutputRef");
        assert!(verdict.score.unwrap() >= 0.9);
    }

    #[test]
    fn frame_substituted_segment_fails() {
        if !ffmpeg_available() {
            eprintln!("SKIP frame_substituted_segment_fails: ffmpeg not found");
            return;
        }
        let (Some(source_plain), Some(substitute_plain)) =
            (corpus("gradient.mp4"), corpus("motion.mp4"))
        else {
            eprintln!("SKIP: corpus clips unavailable");
            return;
        };
        let key = SecretKey::generate().unwrap();
        // The worker was given `gradient` but outputs a transcode of `motion` (a wholesale
        // frame substitution), and commits honestly to those cheating bytes.
        let source = encrypt(&source_plain, &key, &aad(Role::Source)).unwrap();
        let output_blob = sealed_transcode(&substitute_plain, &key);
        let commitment = Commitment::commit(&[sha256(&output_blob)]);

        let inputs = SegmentInputs {
            submitted: &commitment,
            output_blob: &output_blob,
            source: &source,
            key: &key,
            source_aad: &aad(Role::Source),
            output_aad: &aad(Role::Output),
            profile: &profile(),
        };
        let verdict = verify_segment(&inputs, &plan(), &fixed_threshold());

        assert!(!verdict.passed(), "substituted segment must fail, got {verdict:?}");
        assert_eq!(verdict.detail, VerifyDetail::FidelityBelowThreshold);
        // Binding still passed (the worker committed to its real bytes), so an OutputRef
        // exists; the fidelity score is what rejects it.
        assert!(verdict.output.is_some());
        assert!(verdict.score.unwrap() < 0.9, "cross-clip SSIM should be well below 0.9");
    }

    #[test]
    fn binding_failure_short_circuits_before_compare() {
        // A commitment that does not match the blob is rejected at step 1, with no
        // OutputRef and no score — the challenge frames are never chosen.
        let key = SecretKey::generate().unwrap();
        let source = encrypt(b"irrelevant source", &key, &aad(Role::Source)).unwrap();
        let output_blob = b"some encrypted output blob".to_vec();
        let wrong = Commitment::commit(&[sha256(b"different bytes")]);

        let inputs = SegmentInputs {
            submitted: &wrong,
            output_blob: &output_blob,
            source: &source,
            key: &key,
            source_aad: &aad(Role::Source),
            output_aad: &aad(Role::Output),
            profile: &profile(),
        };
        let verdict = verify_segment(&inputs, &plan(), &fixed_threshold());

        assert_eq!(verdict.detail, VerifyDetail::CommitmentMismatch);
        assert!(verdict.output.is_none());
        assert!(verdict.score.is_none());
    }

    #[test]
    fn roc_threshold_round_trips_through_json() {
        let t = RocThreshold {
            value: 0.873,
            provenance: "corpus@abcd ffmpeg@7.0 2026-06-11".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: RocThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, 0.873);
        assert_eq!(back.provenance, t.provenance);
    }

    #[test]
    fn roc_threshold_load_missing_file_errors() {
        let err = RocThreshold::load("/no/such/roc-threshold.json").unwrap_err();
        assert!(matches!(err, VerifyError::ThresholdLoad { .. }));
    }

    fn sha256(b: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().into()
    }
}
