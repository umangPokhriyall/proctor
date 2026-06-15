//! proctor `verifier` — the trusted, CPU-bound re-execution comparator (phase5-spec.md §5).
//!
//! A **separate binary** from `sched` (locked decision #3): CPU-bound re-execution never
//! pollutes the I/O-bound scheduler. `BRPOP` a [`VerifyRequest`] off `inbox:verifier`,
//! then by kind:
//! - **Transcode** — bind the worker's output to its commitment **before any challenge
//!   frame** (`verify::check_binding`, inside `verify_segment`), decrypt source+output
//!   into anonymous RAM, reference-`transcode_no_disk` the source, and compare via
//!   **batched-decode** SSIM (`verify::frame::extract_y_frames` — one ffmpeg pass per
//!   memfd, no per-frame spawn) against the threshold loaded from `roc-threshold.json`.
//! - **Stitch** — bind the output, then `verify::integrity` over the inputs' content
//!   addresses (no SSIM, no re-encode).
//!
//! Returns a frozen [`VerifyResult`] on `sched:inbound`. `#![forbid(unsafe_code)]`; all
//! `unsafe` is in `crypto::sys`; no async runtime. The verifier is key-trusted but
//! no-disk: all media lives in memfds, scrubbed on every path.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use proctor_core::{
    decode, encode, Commitment, TaskId, TaskKind, VerifyDetail, VerifyRequest, VerifyResult,
};
use sha2::{Digest, Sha256};

use crypto::{
    BlobStore, EncryptedSegment, KeySource, LocalBlobStore, LocalKeySource, Role, SegmentAad,
};
use verify::{
    check_binding, verify_segment, verify_stitch_integrity, RocThreshold, SamplePlan,
    SegmentInputs, StitchInput, ROC_THRESHOLD_PATH,
};

/// The comparison geometry the verifier extracts at. It **must** equal the geometry the
/// ROC threshold was calibrated at — `comparison_geometry` in `roc-threshold.json`
/// (currently `160x120`) — because a threshold is only valid at its calibration
/// geometry. The threshold *value* is always loaded from the committed file (never a
/// literal); this geometry is the fixed comparison protocol that pairs with it.
const COMPARISON_WIDTH: u32 = 160;
const COMPARISON_HEIGHT: u32 = 120;

/// Return-channel frame tag for a [`VerifyResult`] on `sched:inbound`: the frame is
/// `[TAG_VERDICT] ++ postcard(result)` so `sched::loops` can route the shared list. MUST
/// match `sched::loops::inbound::VERDICT` (the verifier does not depend on `sched`).
const TAG_VERDICT: u8 = 2;

/// Errors that abort the verifier loop (a single bad request is logged, not fatal).
#[derive(Debug, thiserror::Error)]
enum VerifierError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("verify: {0}")]
    Verify(#[from] verify::VerifyError),
    #[error("config: {0}")]
    Config(String),
}

/// Verify one request, mapping every internal failure to a categorical
/// [`VerifyResult`]. Pure w.r.t. transport: it takes the seams and the threshold, so it
/// is unit-tested directly (no Redis).
fn verify_request<B, K>(
    req: &VerifyRequest,
    blob: &B,
    keys: &K,
    threshold: &RocThreshold,
    frames: u32,
) -> VerifyResult
where
    B: BlobStore,
    K: KeySource,
{
    match &req.kind {
        TaskKind::Transcode(spec) => verify_transcode(req, spec, blob, keys, threshold, frames),
        TaskKind::Stitch(spec) => verify_stitch(req, spec, blob),
    }
}

/// Transcode verification (SSIM). All binding/sampling/decision live in
/// `verify::verify_segment`; here we only resolve the seams and map errors.
fn verify_transcode<B, K>(
    req: &VerifyRequest,
    spec: &proctor_core::TranscodeSpec,
    blob: &B,
    keys: &K,
    threshold: &RocThreshold,
    frames: u32,
) -> VerifyResult
where
    B: BlobStore,
    K: KeySource,
{
    // Fetch the worker's output (by content address) and the encrypted source.
    let output_blob = match blob.get(&req.output) {
        Ok(b) => b,
        Err(_) => return inconclusive(req.task),
    };
    let source_ct = match blob.get_ref(&spec.source) {
        Ok(b) => b,
        Err(_) => return inconclusive(req.task),
    };
    let source = match EncryptedSegment::from_bytes(&source_ct) {
        Ok(s) => s,
        Err(_) => return inconclusive(req.task),
    };
    let key = match keys.key(spec.job, spec.segment) {
        Ok(k) => k,
        Err(_) => return inconclusive(req.task),
    };

    let source_aad = SegmentAad {
        job: spec.job,
        segment: spec.segment,
        role: Role::Source,
    };
    let output_aad = SegmentAad {
        job: spec.job,
        segment: spec.segment,
        role: Role::Output,
    };
    // Frames are sampled at a seed chosen *after* the commitment is fixed, so the worker
    // could not pre-special-case them; `verify_segment` binds before choosing any frame.
    let plan = SamplePlan {
        frames: frames.max(1),
        seed: challenge_seed(&req.commitment),
        duration_secs: 1.0,
        width: COMPARISON_WIDTH,
        height: COMPARISON_HEIGHT,
    };

    let inputs = SegmentInputs {
        submitted: &req.commitment,
        output_blob: &output_blob,
        source: &source,
        key: &key,
        source_aad: &source_aad,
        output_aad: &output_aad,
        profile: &spec.profile,
    };
    let verdict = verify_segment(&inputs, &plan, threshold);
    VerifyResult {
        task: req.task,
        passed: verdict.passed(),
        detail: verdict.detail,
    }
}

/// Stitch integrity verification (no SSIM). Bind the worker's output to its commitment
/// first, then re-check every input's content address against its committed
/// `(OutputRef, Commitment)`.
fn verify_stitch<B>(req: &VerifyRequest, spec: &proctor_core::StitchSpec, blob: &B) -> VerifyResult
where
    B: BlobStore,
{
    // Bind the worker's own output before anything else (mirrors §5.1 step 1).
    let output_blob = match blob.get(&req.output) {
        Ok(b) => b,
        Err(_) => return inconclusive(req.task),
    };
    if check_binding(&output_blob, &req.commitment).is_err() {
        return VerifyResult {
            task: req.task,
            passed: false,
            detail: VerifyDetail::CommitmentMismatch,
        };
    }

    // Fetch each declared input by its content address for the integrity check.
    let mut fetched: Vec<(proctor_core::OutputRef, Commitment, Vec<u8>)> =
        Vec::with_capacity(spec.inputs.len());
    for (_segment, output_ref, commitment) in &spec.inputs {
        match blob.get(output_ref) {
            Ok(bytes) => fetched.push((*output_ref, *commitment, bytes)),
            Err(_) => return inconclusive(req.task),
        }
    }
    let inputs: Vec<StitchInput<'_>> = fetched
        .iter()
        .map(|(output_ref, commitment, bytes)| StitchInput {
            output_ref: *output_ref,
            commitment: *commitment,
            blob: bytes,
        })
        .collect();

    let detail = verify_stitch_integrity(&inputs);
    VerifyResult {
        task: req.task,
        passed: matches!(detail, VerifyDetail::Ok),
        detail,
    }
}

/// The verifier could not reach a verdict (a seam/decrypt/re-execute failure). Never a
/// fabricated pass.
fn inconclusive(task: TaskId) -> VerifyResult {
    VerifyResult {
        task,
        passed: false,
        detail: VerifyDetail::Inconclusive,
    }
}

/// A challenge seed bound to the (already-fixed) commitment plus a wall-clock nonce, so
/// the sampled frames are unpredictable to the worker (which committed before this runs).
fn challenge_seed(commitment: &Commitment) -> u64 {
    let mut h = Sha256::new();
    h.update(commitment.0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(nanos.to_le_bytes());
    let digest = h.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("sha256 digest is 32 bytes"))
}

/// Runtime configuration from the environment (no ingest API — locked #2).
struct Config {
    redis_url: String,
    prefix: String,
    blob_root: std::path::PathBuf,
    key_dir: Option<std::path::PathBuf>,
    threshold_path: std::path::PathBuf,
    frames: u32,
    brpop_secs: u64,
}

impl Config {
    fn from_env() -> Result<Self, VerifierError> {
        let redis_url = std::env::var("PROCTOR_REDIS_URL")
            .map_err(|_| VerifierError::Config("PROCTOR_REDIS_URL is required".into()))?;
        let prefix =
            std::env::var("PROCTOR_REDIS_PREFIX").unwrap_or_else(|_| "proctor:sched".into());
        let blob_root = std::env::var("PROCTOR_BLOB_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("proctor-blobs"));
        let key_dir = std::env::var("PROCTOR_KEY_DIR").ok().map(std::path::PathBuf::from);
        let threshold_path = std::env::var("PROCTOR_ROC_THRESHOLD")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(ROC_THRESHOLD_PATH));
        let frames: u32 = parse_env("PROCTOR_VERIFY_FRAMES", 4)?;
        let brpop_secs: u64 = parse_env("PROCTOR_BRPOP_SECS", 5)?;
        Ok(Self {
            redis_url,
            prefix,
            blob_root,
            key_dir,
            threshold_path,
            frames,
            brpop_secs,
        })
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> Result<T, VerifierError> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|_| VerifierError::Config(format!("{name}: cannot parse {v:?}"))),
        Err(_) => Ok(default),
    }
}

/// Load benchmark keys from `dir`: files named `{job}-{segment}.key` holding exactly 32
/// raw bytes (phase5-spec.md hard rule 3; production key delivery is TLS — NOT built).
fn load_keys(dir: Option<&std::path::Path>) -> Result<LocalKeySource, VerifierError> {
    let mut keys = LocalKeySource::new();
    let Some(dir) = dir else {
        return Ok(keys);
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(keys),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("key") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some((job, segment)) = stem.split_once('-') else {
            continue;
        };
        let (Ok(job), Ok(segment)) = (job.parse::<u64>(), segment.parse::<u64>()) else {
            continue;
        };
        let bytes =
            std::fs::read(&path).map_err(|e| VerifierError::Config(format!("{path:?}: {e}")))?;
        let raw: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifierError::Config(format!("{path:?}: key must be exactly 32 bytes")))?;
        keys.insert(
            proctor_core::JobId(job),
            proctor_core::SegmentId(segment),
            raw,
        );
    }
    Ok(keys)
}

fn main() {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("proctor verifier: {e}");
            eprintln!(
                "proctor verifier: set PROCTOR_REDIS_URL (and optionally PROCTOR_BLOB_ROOT, \
                 PROCTOR_KEY_DIR, PROCTOR_ROC_THRESHOLD, PROCTOR_VERIFY_FRAMES)."
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = serve(cfg) {
        eprintln!("proctor verifier: fatal: {e}");
        std::process::exit(1);
    }
}

/// Load the threshold + seams, then the `BRPOP inbox:verifier` → verify → `LPUSH
/// sched:inbound` loop. The threshold is loaded once from the committed file; the
/// verifier refuses to run on an unknown threshold rather than invent one.
fn serve(cfg: Config) -> Result<(), VerifierError> {
    let threshold = RocThreshold::load(&cfg.threshold_path)?;
    let blob = LocalBlobStore::open(&cfg.blob_root).map_err(verify::VerifyError::from)?;
    let keys = load_keys(cfg.key_dir.as_deref())?;

    let client = redis::Client::open(cfg.redis_url.as_str())?;
    let mut conn = client.get_connection()?;
    let inbox = format!("{}:inbox:verifier", cfg.prefix);
    let inbound = format!("{}:inbound", cfg.prefix);

    eprintln!(
        "proctor verifier: threshold {} (from {:?}); comparing at {COMPARISON_WIDTH}x{COMPARISON_HEIGHT}; blobs at {:?}",
        threshold.value, cfg.threshold_path, cfg.blob_root
    );

    loop {
        let popped: Option<(String, Vec<u8>)> = redis::cmd("BRPOP")
            .arg(&inbox)
            .arg(cfg.brpop_secs)
            .query(&mut conn)?;
        let Some((_, bytes)) = popped else {
            continue; // idle timeout — keep polling
        };
        let req: VerifyRequest = match decode(&bytes) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("proctor verifier: undecodable VerifyRequest dropped: {e}");
                continue;
            }
        };
        let result = verify_request(&req, &blob, &keys, &threshold, cfg.frames);
        // Tag the frame so `sched::loops` can route the shared `sched:inbound` list
        // (`[VERDICT] ++ postcard(result)`). Must match `sched::loops::inbound::VERDICT`.
        let mut frame = vec![TAG_VERDICT];
        frame.extend_from_slice(&encode(&result));
        let _: i64 = redis::cmd("LPUSH").arg(&inbound).arg(frame).query(&mut conn)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use crypto::{aead, transcode_no_disk, MemFd, SecretKey};
    use proctor_core::{
        Codec, Container, JobId, OutputRef, SegmentId, TargetProfile, TranscodeSpec,
    };

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut p = std::env::temp_dir();
            p.push(format!("proctor-verifier-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../bench/corpus")
                .join(name),
        )
        .ok()
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

    // A fixed test threshold (production loads roc-threshold.json). High enough that an
    // honest near-identical re-encode clears it and a cross-clip substitution does not.
    fn fixed_threshold() -> RocThreshold {
        RocThreshold {
            value: 0.9,
            provenance: "test-fixed".to_string(),
        }
    }

    fn leaf(blob: &[u8]) -> [u8; 32] {
        Sha256::digest(blob).into()
    }
    fn commitment_of(blob: &[u8]) -> Commitment {
        Commitment::commit(&[leaf(blob)])
    }

    /// Seal an honest transcode of `plaintext` under `Role::Output`, exactly as a worker uploads.
    fn sealed_transcode(
        plaintext: &[u8],
        key: &SecretKey,
        job: JobId,
        segment: SegmentId,
    ) -> Vec<u8> {
        let mut src = MemFd::create("proctor-test-src").unwrap();
        src.write_all(plaintext).unwrap();
        let mut out = transcode_no_disk(&src, &profile()).expect("test transcode");
        let bytes = out.read_to_secret_buf().unwrap().as_bytes().to_vec();
        src.zeroize_and_close();
        out.zeroize_and_close();
        let aad = SegmentAad { job, segment, role: Role::Output };
        aead::encrypt(&bytes, key, &aad).unwrap().to_bytes()
    }

    /// Stage source + honest output in `store` and return a transcode VerifyRequest, the
    /// honest output blob, and its content address.
    fn stage_transcode(
        store: &LocalBlobStore,
        keys: &mut LocalKeySource,
        source_plain: &[u8],
        output_plain: &[u8],
    ) -> (VerifyRequest, Vec<u8>, OutputRef) {
        let (job, segment) = (JobId(7), SegmentId(3));
        let raw_key = [0x33u8; 32];
        keys.insert(job, segment, raw_key);
        let key = SecretKey::from_bytes(raw_key).unwrap();

        let source_aad = SegmentAad { job, segment, role: Role::Source };
        let source_ct = aead::encrypt(source_plain, &key, &source_aad).unwrap().to_bytes();
        let source_ref = store.put_source(&source_ct).unwrap();

        let output_blob = sealed_transcode(output_plain, &key, job, segment);
        let output_ref = store.put(&output_blob).unwrap();
        let commitment = commitment_of(&output_blob);

        let spec = TranscodeSpec {
            job,
            segment,
            profile: profile(),
            source: source_ref,
        };
        let req = VerifyRequest {
            task: TaskId(101),
            kind: TaskKind::Transcode(spec),
            commitment,
            output: output_ref,
        };
        (req, output_blob, output_ref)
    }

    #[test]
    fn honest_transcode_verifies_ok() {
        if !ffmpeg_available() {
            eprintln!("SKIP honest_transcode_verifies_ok: ffmpeg not found");
            return;
        }
        let Some(plaintext) = corpus("gradient.mp4") else {
            eprintln!("SKIP: corpus unavailable");
            return;
        };
        let dir = TempDir::new("honest");
        let store = LocalBlobStore::open(&dir.0).unwrap();
        let mut keys = LocalKeySource::new();
        // Honest: the worker output is a transcode of the very source it was given.
        let (req, _blob, _out) = stage_transcode(&store, &mut keys, &plaintext, &plaintext);

        let result = verify_request(&req, &store, &keys, &fixed_threshold(), 3);
        assert!(result.passed, "honest segment must pass: {result:?}");
        assert_eq!(result.detail, VerifyDetail::Ok);
        assert_eq!(result.task, TaskId(101));
    }

    #[test]
    fn frame_substituted_transcode_is_below_threshold() {
        if !ffmpeg_available() {
            eprintln!("SKIP frame_substituted_transcode_is_below_threshold: ffmpeg not found");
            return;
        }
        let (Some(source_plain), Some(other_plain)) =
            (corpus("gradient.mp4"), corpus("motion.mp4"))
        else {
            eprintln!("SKIP: corpus unavailable");
            return;
        };
        let dir = TempDir::new("substitute");
        let store = LocalBlobStore::open(&dir.0).unwrap();
        let mut keys = LocalKeySource::new();
        // Given `gradient`, the worker outputs a transcode of `motion` (substitution),
        // committing honestly to those cheating bytes (binding passes; fidelity fails).
        let (req, _blob, _out) = stage_transcode(&store, &mut keys, &source_plain, &other_plain);

        let result = verify_request(&req, &store, &keys, &fixed_threshold(), 3);
        assert!(!result.passed, "substituted segment must fail: {result:?}");
        assert_eq!(result.detail, VerifyDetail::FidelityBelowThreshold);
    }

    #[test]
    fn swapped_blob_after_commit_is_commitment_mismatch() {
        if !ffmpeg_available() {
            eprintln!("SKIP swapped_blob_after_commit_is_commitment_mismatch: ffmpeg not found");
            return;
        }
        let Some(plaintext) = corpus("gradient.mp4") else {
            eprintln!("SKIP: corpus unavailable");
            return;
        };
        let dir = TempDir::new("swap");
        let store = LocalBlobStore::open(&dir.0).unwrap();
        let mut keys = LocalKeySource::new();
        let (req, honest_blob, output_ref) =
            stage_transcode(&store, &mut keys, &plaintext, &plaintext);

        // Post-commit swap: overwrite the bytes served at the committed content address.
        let mut swapped = honest_blob.clone();
        swapped[0] ^= 0x01;
        std::fs::write(store.root().join(format!("{:032x}", output_ref.0)), &swapped).unwrap();

        let result = verify_request(&req, &store, &keys, &fixed_threshold(), 3);
        assert!(!result.passed);
        assert_eq!(
            result.detail,
            VerifyDetail::CommitmentMismatch,
            "a blob swapped after commit must be rejected at binding, before any frame"
        );
    }

    #[test]
    fn stitch_with_authentic_inputs_is_ok_and_swap_is_violation() {
        use proctor_core::{RenditionId, StitchSpec};
        let dir = TempDir::new("stitch");
        let store = LocalBlobStore::open(&dir.0).unwrap();
        let keys = LocalKeySource::new();

        // Two accepted inputs, content-addressed in the store.
        let in0 = b"accepted segment-0 ciphertext".to_vec();
        let in1 = b"accepted segment-1 ciphertext".to_vec();
        let r0 = store.put(&in0).unwrap();
        let r1 = store.put(&in1).unwrap();
        let c0 = commitment_of(&in0);
        let c1 = commitment_of(&in1);

        // A worker stitch output (its own bytes), bound to its own commitment.
        let output_blob = b"the stitched rendition ciphertext".to_vec();
        let output_ref = store.put(&output_blob).unwrap();
        let commitment = commitment_of(&output_blob);

        let spec = StitchSpec {
            job: JobId(7),
            rendition: RenditionId(0),
            inputs: vec![(SegmentId(0), r0, c0), (SegmentId(1), r1, c1)],
        };
        let req = VerifyRequest {
            task: TaskId(202),
            kind: TaskKind::Stitch(spec),
            commitment,
            output: output_ref,
        };

        // Authentic inputs ⇒ Ok (integrity, no SSIM).
        let ok = verify_request(&req, &store, &keys, &fixed_threshold(), 3);
        assert!(ok.passed);
        assert_eq!(ok.detail, VerifyDetail::Ok);

        // Swap one input's bytes at its address ⇒ IntegrityViolation.
        let mut swapped = in0.clone();
        swapped[0] ^= 0x01;
        std::fs::write(store.root().join(format!("{:032x}", r0.0)), &swapped).unwrap();
        let bad = verify_request(&req, &store, &keys, &fixed_threshold(), 3);
        assert!(!bad.passed);
        assert_eq!(bad.detail, VerifyDetail::IntegrityViolation);
    }
}
