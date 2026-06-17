//! `pipeline` — crypto/verification cost in the live pipeline (phase6-spec.md §5). Real
//! `crypto` (no-disk AEAD + transcode) and `verify` (batched-decode SSIM) over real ffmpeg.
//!
//! - **Crypto as % of end-to-end** ([`measure_crypto_pct`]): per segment, `decrypt + encrypt`
//!   (the crypto) against `transcode_no_disk` (the bulk), under `C` concurrent transcodes —
//!   confirming the Phase-2 standalone 0.10–1.03% stays small in the contended live pipeline.
//! - **Verification cost** ([`measure_verify_cost`]): `verify_segment` (bind → reference
//!   transcode → **batched** decode of all sampled frames → SSIM) as a multiple of one
//!   transcode — confirming ≈1.20×, far below the Phase-3 ~10× per-frame-spawn artifact.
//! - **Verifier-capacity utilization at `P_MIN`** ([`verifier_capacity`]): derived from the
//!   measured verify ratio and the `P_MIN = 0.02` floor — the trusted verifier pool's share
//!   of worker compute at the floor (≈2.4%) and the sampling rate that would saturate it.

use std::time::Instant;

use proctor_core::{Codec, Commitment, Container, JobId, SegmentId, TargetProfile};

use crypto::{
    aead, decrypt_into_memfd, transcode_no_disk, EncryptedSegment, MemFd, Role, SecretKey,
    SegmentAad,
};
use verify::{commit_for_blob, verify_segment, RocThreshold, SamplePlan, SegmentInputs, P_MIN};

use crate::metrics::Latencies;

/// What can go wrong in a pipeline measurement.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("verify: {0}")]
    Verify(#[from] verify::VerifyError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("a worker thread panicked")]
    Thread,
}

const JOB: JobId = JobId(1);
const SEG: SegmentId = SegmentId(0);
const KEY_RAW: [u8; 32] = [0x5Au8; 32];

fn profile() -> TargetProfile {
    TargetProfile {
        codec: Codec::H264,
        width: 320,
        height: 240,
        bitrate_kbps: 800,
        container: Container::Mp4,
    }
}

fn source_aad() -> SegmentAad {
    SegmentAad { job: JOB, segment: SEG, role: Role::Source }
}
fn output_aad() -> SegmentAad {
    SegmentAad { job: JOB, segment: SEG, role: Role::Output }
}

/// Encrypt `media` as the source segment and produce the honest encrypted output blob (a real
/// transcode of the source, sealed) plus its single-leaf commitment — exactly what a worker
/// uploads and the verifier binds against.
fn stage(media: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Commitment), PipelineError> {
    let key = SecretKey::from_bytes(KEY_RAW)?;
    let source_ct = aead::encrypt(media, &key, &source_aad())?.to_bytes();

    let mut src = MemFd::create("pipe-stage-src")?;
    src.write_all(media)?;
    let mut out = transcode_no_disk(&src, &profile())?;
    src.zeroize_and_close();
    let plaintext = out.read_to_secret_buf()?;
    let output_blob = aead::encrypt(plaintext.as_bytes(), &key, &output_aad())?.to_bytes();
    out.zeroize_and_close();

    let commitment = commit_for_blob(&output_blob);
    Ok((source_ct, output_blob, commitment))
}

// --- crypto as % of end-to-end --------------------------------------------------------

/// Crypto-cost result at one concurrency level.
pub struct CryptoPctResult {
    pub concurrency: usize,
    pub samples: u64,
    /// `decrypt + encrypt` wall time per segment (ns).
    pub crypto_ns: Latencies,
    /// `transcode_no_disk` wall time per segment (ns).
    pub transcode_ns: Latencies,
    /// Crypto share of (crypto + transcode), in parts-per-million (÷1e4 = percent).
    pub crypto_ppm: Latencies,
}

impl CryptoPctResult {
    /// Crypto percentage at p50 (median).
    #[must_use]
    pub fn crypto_pct_p50(&self) -> f64 {
        self.crypto_ppm.summary().p50_ns as f64 / 10_000.0
    }
    /// Crypto percentage at p99.
    #[must_use]
    pub fn crypto_pct_p99(&self) -> f64 {
        self.crypto_ppm.summary().p99_ns as f64 / 10_000.0
    }
}

/// One timed iteration: `(crypto_ns, transcode_ns, crypto_ppm)`.
type CryptoSample = (u64, u64, u64);

/// Measure crypto-as-%-of-e2e for `media` at concurrency `c` (one transcode pipeline per
/// thread, `iters` segments each): `decrypt → transcode → encrypt`, timing the crypto
/// (decrypt + encrypt) against the transcode under contention.
pub fn measure_crypto_pct(media: &[u8], c: usize, iters: u64) -> Result<CryptoPctResult, PipelineError> {
    let (source_ct, _out, _c) = stage(media)?;
    let c = c.max(1);

    let collected: Result<Vec<Vec<CryptoSample>>, PipelineError> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..c {
            let source_ct = &source_ct;
            handles.push(scope.spawn(move || -> Result<Vec<CryptoSample>, PipelineError> {
                let key = SecretKey::from_bytes(KEY_RAW)?;
                let enc = EncryptedSegment::from_bytes(source_ct)?;
                let (sa, oa) = (source_aad(), output_aad());
                let prof = profile();
                let mut rows = Vec::with_capacity(iters as usize);
                for _ in 0..iters {
                    let t = Instant::now();
                    let src = decrypt_into_memfd(&enc, &key, &sa, "pipe-src")?;
                    let dec_ns = t.elapsed().as_nanos() as u64;

                    let t = Instant::now();
                    let mut out = transcode_no_disk(&src, &prof)?;
                    let tr_ns = t.elapsed().as_nanos() as u64;
                    src.zeroize_and_close();

                    let t = Instant::now();
                    let plaintext = out.read_to_secret_buf()?;
                    let _sealed = aead::encrypt(plaintext.as_bytes(), &key, &oa)?;
                    let enc_ns = t.elapsed().as_nanos() as u64;
                    out.zeroize_and_close();

                    let crypto = dec_ns + enc_ns;
                    let total = crypto + tr_ns;
                    let ppm = if total > 0 { (crypto as u128 * 1_000_000 / total as u128) as u64 } else { 0 };
                    rows.push((crypto, tr_ns, ppm));
                }
                Ok(rows)
            }));
        }
        handles.into_iter().map(|h| h.join().map_err(|_| PipelineError::Thread)?).collect()
    });

    let mut crypto_ns = Latencies::new();
    let mut transcode_ns = Latencies::new();
    let mut crypto_ppm = Latencies::new();
    let mut samples = 0u64;
    for rows in collected? {
        for (crypto, tr, ppm) in rows {
            crypto_ns.record(crypto);
            transcode_ns.record(tr);
            crypto_ppm.record(ppm);
            samples += 1;
        }
    }
    Ok(CryptoPctResult { concurrency: c, samples, crypto_ns, transcode_ns, crypto_ppm })
}

// --- verification cost ----------------------------------------------------------------

/// Verification-cost result.
pub struct VerifyCostResult {
    pub samples: u64,
    pub transcode_ns: Latencies,
    pub verify_ns: Latencies,
    /// `verify_p50 / transcode_p50` — the per-sampled-segment verification cost as a multiple
    /// of one transcode.
    pub ratio: f64,
    /// How many of the `samples` verifications passed (`VerifyDetail::Ok`) — a sanity check
    /// that the timed path is the full SSIM path, not an early binding reject.
    pub passed: u64,
}

/// Measure the batched-decode verification cost for `media`: one `transcode_no_disk` baseline
/// against one `verify_segment` (bind → reference transcode → batched decode → SSIM), over
/// `samples`. Returns the distributions and the ratio (expected ≈1.20×).
pub fn measure_verify_cost(
    media: &[u8],
    threshold: &RocThreshold,
    samples: u64,
) -> Result<VerifyCostResult, PipelineError> {
    let (source_ct, output_blob, commitment) = stage(media)?;
    let key = SecretKey::from_bytes(KEY_RAW)?;
    let (sa, oa) = (source_aad(), output_aad());
    let prof = profile();
    let plan = SamplePlan { frames: 4, seed: 0x5EED_0001, duration_secs: 1.0, width: 160, height: 120 };

    let mut transcode_ns = Latencies::new();
    let mut verify_ns = Latencies::new();
    let mut passed = 0u64;
    for _ in 0..samples {
        // Baseline: one transcode (what the worker did).
        let mut src = MemFd::create("pipe-vc-src")?;
        src.write_all(media)?;
        let t = Instant::now();
        let out = transcode_no_disk(&src, &prof)?;
        transcode_ns.record(t.elapsed().as_nanos() as u64);
        src.zeroize_and_close();
        drop(out);

        // The verify: bind → reference transcode → batched decode of all frames → SSIM.
        let enc = EncryptedSegment::from_bytes(&source_ct)?;
        let inputs = SegmentInputs {
            submitted: &commitment,
            output_blob: &output_blob,
            source: &enc,
            key: &key,
            source_aad: &sa,
            output_aad: &oa,
            profile: &prof,
        };
        let t = Instant::now();
        let verdict = verify_segment(&inputs, &plan, threshold);
        verify_ns.record(t.elapsed().as_nanos() as u64);
        if verdict.passed() {
            passed += 1;
        }
    }
    let ratio = verify_ns.summary().p50_ns as f64 / transcode_ns.summary().p50_ns.max(1) as f64;
    Ok(VerifyCostResult { samples, transcode_ns, verify_ns, ratio, passed })
}

// --- verifier-capacity utilization at P_MIN -------------------------------------------

/// Verifier-capacity envelope at the `P_MIN` floor, derived from the measured verify ratio.
pub struct VerifierCapacity {
    pub verify_ratio: f64,
    pub p_min: f64,
    /// Verifier compute as a fraction of worker compute at the floor: `P_MIN · ratio`.
    pub util_at_floor: f64,
    /// For each `(n_workers, m_verifiers)`: verifier utilization at the floor, and the
    /// sampling rate that would saturate the verifier pool.
    pub envelopes: Vec<CapacityPoint>,
}

/// One capacity point.
pub struct CapacityPoint {
    pub n_workers: u32,
    pub m_verifiers: u32,
    /// Verifier utilization at `p = P_MIN`: `P_MIN · ratio · N / M` (≥1 ⇒ bottleneck).
    pub util_at_floor: f64,
    /// The sampling rate `p` that saturates the M verifiers: `M / (ratio · N)`.
    pub p_saturating: f64,
}

/// Derive the verifier-capacity envelope from the measured `verify_ratio` (verifier and worker
/// assumed equal per-core throughput — same `transcode_no_disk` core on this single host).
#[must_use]
pub fn verifier_capacity(verify_ratio: f64, points: &[(u32, u32)]) -> VerifierCapacity {
    let envelopes = points
        .iter()
        .map(|&(n, m)| {
            let nf = f64::from(n.max(1));
            let mf = f64::from(m.max(1));
            CapacityPoint {
                n_workers: n,
                m_verifiers: m,
                util_at_floor: P_MIN * verify_ratio * nf / mf,
                p_saturating: mf / (verify_ratio * nf),
            }
        })
        .collect();
    VerifierCapacity {
        verify_ratio,
        p_min: P_MIN,
        util_at_floor: P_MIN * verify_ratio,
        envelopes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_math_is_consistent() {
        // ratio 1.2, P_MIN 0.02 ⇒ floor utilization 2.4% of worker compute.
        let cap = verifier_capacity(1.2, &[(4, 1), (64, 1)]);
        assert!((cap.util_at_floor - 0.024).abs() < 1e-9);
        // At the floor a single verifier is far from saturated for 4 workers...
        let four = &cap.envelopes[0];
        assert!(four.util_at_floor < 1.0);
        // ...and the saturating sampling rate exceeds the floor there.
        assert!(four.p_saturating > P_MIN);
        // For 64 workers a single verifier's floor utilization is higher (more sampled load).
        let many = &cap.envelopes[1];
        assert!(many.util_at_floor > four.util_at_floor);
    }
}
