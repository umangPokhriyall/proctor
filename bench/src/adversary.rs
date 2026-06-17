//! `adversary` — the bench-only cheating workers and the falsifiable security proof
//! (phase6-spec.md §6, amendment §1.1/§1.2/§1.3). **The production `worker/` stays honest;
//! every cheat path lives here.**
//!
//! Five attack classes, reusing the Phase-3 synthesis: **cheap-downscale**,
//! **wrong-bitrate**, **frame-substitution**, **garbage** (the four SSIM-fidelity attacks),
//! and **byte-swap** (the post-commit blob swap, caught deterministically at binding). Each
//! adversary forges an encrypted output blob + commitment for a source segment; the **real**
//! `verify::verify_segment` then decides caught/not — the genuine detector, not a re-impl.
//!
//! Three artifacts are built on top:
//! - **Slow-zombie chaos at scale** ([`slow_zombie_at_scale`]) over a real Redis: many tasks
//!   each run lease → reclaim → re-lease → the zombie's epoch-stale submit is rejected by the
//!   store CAS → **zero double-outputs** (fencing safety under load).
//! - **End-to-end detection** ([`simulate_detection`]): jobs of `n` segments with `m = ⌈f·n⌉`
//!   tampered (catch outcomes bootstrapped from the **measured** per-segment pool), the
//!   verifier samples `k = ⌈p·n⌉` without replacement; compared to the predicted
//!   `P_hyper(f,n;p) × (1 − FAR)`.
//! - **Adaptive escalation** ([`simulate_escalation`]): a persistent cheater walks the **real**
//!   reputation tiers (`sched::reputation`) — first catch → tier up → `p` rises → eventual Ban.

use std::ffi::OsString;
use std::time::{SystemTime, UNIX_EPOCH};

use proctor_core::{
    Commitment, JobId, LogicalTime, SegmentId, SubmissionMsg, TargetProfile, TaskId, VerifyDetail,
    WorkerId,
};
use rand::seq::SliceRandom;
use rand::Rng;

use crypto::{aead, ffmpeg_no_disk, transcode_no_disk, EncryptedSegment, MemFd, Role, SecretKey, SegmentAad};
use sched::engine::{content_address, DispatchStep, Engine, EngineConfig};
use sched::reputation::{self, Standing, PRISTINE};
use sched::sample::Sampler;
use sched::store::{Priority, RedisStore, Tier};
use verify::detection::{sample_count, tampered_count};
use verify::{commit_for_blob, p_detect_hypergeometric, verify_segment, RocThreshold, SamplePlan, SegmentInputs};

use crate::decomp::MeasureError;
use crate::metrics::now_ns;

// --- attack synthesis args (Phase 3 §5; the real worker never uses these) --------------

/// Cheap-downscale: minimal-effort low-resolution encode (decodes blurry vs the reference).
const DOWNSCALE_ARGS: &[&str] =
    &["-an", "-c:v", "libx264", "-preset", "ultrafast", "-b:v", "800k", "-vf", "scale=96:72"];
/// Wrong-bitrate: right geometry, far-too-low bitrate (heavy block artifacts).
const BITRATE_ARGS: &[&str] =
    &["-an", "-c:v", "libx264", "-preset", "medium", "-b:v", "40k", "-vf", "scale=320:240"];
/// Frame-substitution: a *different* clip re-encoded at the right geometry.
const SUBSTITUTE_ARGS: &[&str] =
    &["-an", "-c:v", "libx264", "-preset", "medium", "-b:v", "800k", "-vf", "scale=320:240"];
/// Garbage: blanked (black) output at the right geometry.
const GARBAGE_ARGS: &[&str] = &[
    "-an", "-c:v", "libx264", "-preset", "ultrafast", "-b:v", "800k", "-vf",
    "scale=320:240,drawbox=x=0:y=0:w=iw:h=ih:color=black:t=fill",
];

/// The five bench-only attack classes (plus `Honest`, the control).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttackClass {
    Honest,
    CheapDownscale,
    WrongBitrate,
    FrameSubstitution,
    Garbage,
    ByteSwap,
}

impl AttackClass {
    /// All attack classes (excludes `Honest`).
    pub const ATTACKS: [AttackClass; 5] = [
        AttackClass::CheapDownscale,
        AttackClass::WrongBitrate,
        AttackClass::FrameSubstitution,
        AttackClass::Garbage,
        AttackClass::ByteSwap,
    ];

    /// Stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AttackClass::Honest => "honest",
            AttackClass::CheapDownscale => "cheap_downscale",
            AttackClass::WrongBitrate => "wrong_bitrate",
            AttackClass::FrameSubstitution => "frame_substitution",
            AttackClass::Garbage => "garbage",
            AttackClass::ByteSwap => "byte_swap",
        }
    }

    /// The `VerifyDetail` a catch of this class yields (drives reputation): the binding
    /// attack is the heaviest `CommitmentMismatch`; the fidelity attacks are
    /// `FidelityBelowThreshold`.
    #[must_use]
    pub fn catch_detail(self) -> VerifyDetail {
        match self {
            AttackClass::ByteSwap => VerifyDetail::CommitmentMismatch,
            _ => VerifyDetail::FidelityBelowThreshold,
        }
    }
}

/// What can go wrong forging or scoring an attack.
#[derive(Debug, thiserror::Error)]
pub enum AdversaryError {
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A per-segment detection outcome from the real verifier.
#[derive(Clone, Copy, Debug)]
pub struct SegmentCatch {
    pub caught: bool,
    pub detail: VerifyDetail,
}

fn aad(job: JobId, segment: SegmentId, role: Role) -> SegmentAad {
    SegmentAad { job, segment, role }
}

/// Encode `plain` with the attack `args` over the no-disk path, returning the output video
/// bytes (still plaintext — the adversary then seals them).
fn encode_attack(plain: &[u8], args: &[&str]) -> Result<Vec<u8>, AdversaryError> {
    let mut input = MemFd::create("adv-src")?;
    input.write_all(plain)?;
    let mut out = MemFd::create("adv-out")?;
    let mut full: Vec<OsString> = vec![
        "-nostdin".into(), "-hide_banner".into(), "-loglevel".into(), "error".into(), "-y".into(),
        "-i".into(), input.proc_path().into(),
    ];
    full.extend(args.iter().map(|a| OsString::from(*a)));
    full.push("-f".into());
    full.push("mp4".into());
    full.push(out.proc_path().into());

    let res = ffmpeg_no_disk(&full, &[&input, &out]);
    input.zeroize_and_close();
    match res {
        Ok(()) => {
            let bytes = out.read_to_secret_buf()?.as_bytes().to_vec();
            out.zeroize_and_close();
            Ok(bytes)
        }
        Err(e) => {
            out.zeroize_and_close();
            Err(e.into())
        }
    }
}

/// Honest transcode over the real worker path (`transcode_no_disk` at the target profile).
fn encode_honest(plain: &[u8], profile: &TargetProfile) -> Result<Vec<u8>, AdversaryError> {
    let mut input = MemFd::create("adv-honest-src")?;
    input.write_all(plain)?;
    let res = transcode_no_disk(&input, profile);
    input.zeroize_and_close();
    let mut out = res?;
    let bytes = out.read_to_secret_buf()?.as_bytes().to_vec();
    out.zeroize_and_close();
    Ok(bytes)
}

/// Forge an adversary's `(output_blob, commitment)` for `class` over a source segment.
/// SSIM attacks transcode the source (or a substitute clip) with the class args and commit
/// honestly to the cheating bytes (binding passes, fidelity fails). `ByteSwap` transcodes
/// honestly, commits, then flips a blob byte post-commit (binding fails → CommitmentMismatch).
fn forge(
    class: AttackClass,
    src_plain: &[u8],
    sub_plain: &[u8],
    key: &SecretKey,
    out_aad: &SegmentAad,
    profile: &TargetProfile,
) -> Result<(Vec<u8>, Commitment), AdversaryError> {
    let plaintext = match class {
        AttackClass::Honest | AttackClass::ByteSwap => encode_honest(src_plain, profile)?,
        AttackClass::CheapDownscale => encode_attack(src_plain, DOWNSCALE_ARGS)?,
        AttackClass::WrongBitrate => encode_attack(src_plain, BITRATE_ARGS)?,
        AttackClass::Garbage => encode_attack(src_plain, GARBAGE_ARGS)?,
        AttackClass::FrameSubstitution => encode_attack(sub_plain, SUBSTITUTE_ARGS)?,
    };
    let mut blob = aead::encrypt(&plaintext, key, out_aad)?.to_bytes();
    let commitment = commit_for_blob(&blob);
    if class == AttackClass::ByteSwap {
        // Post-commit swap: serve different bytes than were committed. The verifier's
        // check_binding re-derives the commitment from these bytes and rejects.
        blob[0] ^= 0x01;
    }
    Ok((blob, commitment))
}

/// Forge `class` over a source segment and run the **real** `verify::verify_segment` (binding
/// then SSIM) against it — the genuine per-segment detector. Returns caught/not + the detail.
#[allow(clippy::too_many_arguments)]
pub fn attack_and_verify(
    class: AttackClass,
    src_plain: &[u8],
    sub_plain: &[u8],
    key_raw: [u8; 32],
    job: JobId,
    segment: SegmentId,
    profile: &TargetProfile,
    plan: &SamplePlan,
    threshold: &RocThreshold,
) -> Result<SegmentCatch, AdversaryError> {
    let key = SecretKey::from_bytes(key_raw)?;
    let source_aad = aad(job, segment, Role::Source);
    let output_aad = aad(job, segment, Role::Output);
    let source_ct = aead::encrypt(src_plain, &key, &source_aad)?.to_bytes();
    let source_enc = EncryptedSegment::from_bytes(&source_ct)?;

    let (output_blob, commitment) = forge(class, src_plain, sub_plain, &key, &output_aad, profile)?;
    let inputs = SegmentInputs {
        submitted: &commitment,
        output_blob: &output_blob,
        source: &source_enc,
        key: &key,
        source_aad: &source_aad,
        output_aad: &output_aad,
        profile,
    };
    let verdict = verify_segment(&inputs, plan, threshold);
    Ok(SegmentCatch { caught: !verdict.passed(), detail: verdict.detail })
}

// --- end-to-end detection (Monte Carlo over the measured per-segment pool) --------------

/// The predicted effective detection: `P_hyper(f, n; p) × (1 − FAR)` — the committed Phase-3
/// hypergeometric times the measured per-class false-accept rate (the honest composition).
#[must_use]
pub fn predicted_detection(f: f64, n: u32, p: f64, far: f64) -> f64 {
    p_detect_hypergeometric(f, n, p) * (1.0 - far)
}

/// One job: place `m = ⌈f·n⌉` tampered segments (each caught-or-not bootstrapped from `pool`,
/// the measured per-segment outcomes), the verifier samples `k = ⌈p·n⌉` without replacement;
/// the worker is caught iff any sampled tampered segment was a caught outcome.
fn job_caught<R: Rng>(pool: &[bool], f: f64, n: u32, p: f64, rng: &mut R) -> bool {
    let m = tampered_count(f, n) as usize;
    let k = sample_count(p, n) as usize;
    if m == 0 || k == 0 || pool.is_empty() {
        return false;
    }
    // n slots: m tampered (bootstrap a real catch outcome each), n−m honest (never caught).
    let mut slots = vec![false; n as usize];
    for slot in slots.iter_mut().take(m) {
        *slot = *pool.choose(rng).expect("non-empty pool");
    }
    slots.shuffle(rng);
    // Sampling k of n without replacement ≡ taking the first k after the shuffle.
    slots.iter().take(k).any(|&caught| caught)
}

/// Monte-Carlo end-to-end worker-detection rate over `trials` jobs at `(f, n, p)`, using the
/// measured per-segment catch `pool`. Returns the caught count (for a Clopper–Pearson CI).
pub fn simulate_detection<R: Rng>(pool: &[bool], f: f64, n: u32, p: f64, trials: u64, rng: &mut R) -> u64 {
    (0..trials).filter(|_| job_caught(pool, f, n, p, rng)).count() as u64
}

// --- adaptive escalation (the real reputation policy) ----------------------------------

/// One step of a persistent cheater's reputation trajectory.
#[derive(Clone, Copy, Debug)]
pub struct EscalationStep {
    pub job: u64,
    pub tier_before: Tier,
    pub p: f64,
    pub caught: bool,
    pub standing_after: Standing,
    pub tier_after: Tier,
}

/// A persistent cheater's full trajectory until Ban (or `max_jobs`).
pub struct EscalationTrace {
    pub steps: Vec<EscalationStep>,
    pub banned_at_job: Option<u64>,
    pub first_caught_job: Option<u64>,
}

/// Simulate a persistent cheater of one class (`pool` = its measured per-segment catch
/// outcomes, `detail` = its catch verdict) tampering fraction `f` of each `n`-segment job.
/// Sampling `p` is driven by the **real** `sched::reputation` tier of the accumulating
/// standing: a catch applies `record_verdict(detail)` (escalates); a clean job credits a pass
/// (`Ok`, slow trust). Runs until the worker is `Banned` or `max_jobs`.
pub fn simulate_escalation<R: Rng>(
    pool: &[bool],
    f: f64,
    n: u32,
    detail: VerifyDetail,
    max_jobs: u64,
    rng: &mut R,
) -> EscalationTrace {
    let mut standing: Standing = PRISTINE;
    let mut steps = Vec::new();
    let mut banned_at = None;
    let mut first_caught = None;
    for job in 1..=max_jobs {
        let tier_before = reputation::tier_of(standing);
        let p = reputation::p_for(tier_before);
        let caught = job_caught(pool, f, n, p, rng);
        if caught {
            first_caught.get_or_insert(job);
            standing = reputation::record_verdict(standing, detail);
        } else {
            // A clean job (no sampled-tampered flagged) reads as a pass: slow-trust credit.
            standing = reputation::record_verdict(standing, VerifyDetail::Ok);
        }
        let tier_after = reputation::tier_of(standing);
        steps.push(EscalationStep { job, tier_before, p, caught, standing_after: standing, tier_after });
        if tier_after == Tier::Banned {
            banned_at = Some(job);
            break;
        }
    }
    EscalationTrace { steps, banned_at_job: banned_at, first_caught_job: first_caught }
}

// --- slow-zombie chaos at scale (real Redis fencing under load) -------------------------

/// The result of the slow-zombie chaos run.
pub struct ChaosReport {
    pub tasks: u64,
    /// Zombie (stale-epoch) submits rejected by the store CAS — must equal `tasks`.
    pub zombies_rejected: u64,
    /// Legitimate re-executions released — must equal `tasks`.
    pub legit_released: u64,
    /// Tasks where the zombie's output was ALSO released — MUST be 0 (fencing breach).
    pub double_outputs: u64,
    /// Re-lease fencing epochs that strictly exceeded the zombie's — must equal `tasks`.
    pub epoch_advances: u64,
}

/// A never-sample RNG so a submission is content-addressed released immediately (no verifier
/// needed — submit-time epoch fencing is the property under test).
struct NeverSample;
impl rand::RngCore for NeverSample {
    fn next_u32(&mut self) -> u32 {
        u32::MAX
    }
    fn next_u64(&mut self) -> u64 {
        u64::MAX
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0xFF);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn now_secs() -> LogicalTime {
    LogicalTime(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

fn cleanup_prefix(url: &str, prefix: &str) -> Result<(), MeasureError> {
    let client = redis::Client::open(url)?;
    let mut conn = client.get_connection()?;
    let keys: Vec<String> = redis::cmd("KEYS").arg(format!("{prefix}:*")).query(&mut conn)?;
    if !keys.is_empty() {
        let mut del = redis::cmd("DEL");
        for k in &keys {
            del.arg(k);
        }
        let _: i64 = del.query(&mut conn)?;
    }
    Ok(())
}

/// Run the slow-zombie chaos schedule across `tasks` tasks over a loopback Redis: each task is
/// leased (epoch e1) → reclaimed (the single authority, epoch bumped) → re-leased (epoch e2 >
/// e1); the **zombie** then submits with its stale e1 (rejected by the store CAS, no output)
/// and the legitimate holder submits with e2 (released). Asserts **zero double-outputs**.
pub fn slow_zombie_at_scale(url: &str, n_workers: u32, tasks: u64) -> Result<ChaosReport, MeasureError> {
    let prefix = format!("proctor:chaos:{}:{}", std::process::id(), now_ns());
    let cfg = EngineConfig {
        lease_ttl: 1,
        liveness_window: 86_400,
        sizing: sched::backpressure::Sizing::from_measured(n_workers.max(2)),
        default_priority: Priority::default(),
    };
    let engine = Engine::new(RedisStore::connect(url, &prefix)?, cfg, Sampler::new(NeverSample));
    for w in 1..=u64::from(n_workers.max(2)) {
        engine.register_worker(WorkerId(w), now_secs())?;
    }

    let mut zombies_rejected = 0u64;
    let mut legit_released = 0u64;
    let mut double_outputs = 0u64;
    let mut epoch_advances = 0u64;

    for i in 0..tasks {
        let id = TaskId(i + 1);
        engine.inject(crate::dummy_transcode_task(id.0), Priority::default(), now_secs())?;
        // Lease to the first worker (the future zombie).
        let DispatchStep::Dispatched { worker: w1, epoch: e1, .. } = engine.dispatch_one_live(now_secs())?
        else {
            continue;
        };
        // The holder goes silent; the single reclaim authority re-enqueues at a bumped epoch.
        engine.reclaim(LogicalTime(now_secs().0 + 10))?;
        let DispatchStep::Dispatched { worker: w2, epoch: e2, .. } = engine.dispatch_one_live(now_secs())?
        else {
            continue;
        };
        if e2.0 > e1.0 {
            epoch_advances += 1;
        }
        // Distinct content for zombie vs legit so a double-output is observable as two addresses.
        let (out_z, com_z) = content_address(zombie_leaf(id, true));
        let (out_l, com_l) = content_address(zombie_leaf(id, false));

        // The zombie wakes and submits with its STALE epoch e1 — rejected at the store CAS.
        let z = engine.on_submission_live(
            SubmissionMsg { task: id, worker: w1, epoch: e1, commitment: com_z, output: out_z },
            now_secs(),
        )?;
        if matches!(z, sched::engine::SubmitOutcome::RejectedZombie) {
            zombies_rejected += 1;
        }
        // The legitimate re-execution submits with the current epoch e2 — accepted + released.
        let l = engine.on_submission_live(
            SubmissionMsg { task: id, worker: w2, epoch: e2, commitment: com_l, output: out_l },
            now_secs(),
        )?;
        if matches!(l, sched::engine::SubmitOutcome::Accepted(_)) {
            legit_released += 1;
        }
        // The zombie's output must NOT be released; exactly one output exists for the segment.
        if engine.released(out_z).is_some() {
            double_outputs += 1;
        }
    }
    cleanup_prefix(url, &prefix)?;
    Ok(ChaosReport { tasks, zombies_rejected, legit_released, double_outputs, epoch_advances })
}

/// A distinct 32-byte blob leaf per (task, zombie?) so zombie and legit map to different
/// content addresses.
fn zombie_leaf(task: TaskId, zombie: bool) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[..8].copy_from_slice(&task.0.to_be_bytes());
    leaf[8] = u8::from(zombie);
    leaf[9] = if zombie { 0xAA } else { 0xBB };
    leaf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn predicted_detection_is_hyper_times_one_minus_far() {
        // byte-swap (FAR 0) → detection == raw hypergeometric.
        let h = p_detect_hypergeometric(0.25, 16, 0.10);
        assert!((predicted_detection(0.25, 16, 0.10, 0.0) - h).abs() < 1e-12);
        // FAR 0.21 → materially below the raw hypergeometric.
        assert!(predicted_detection(0.25, 16, 0.10, 0.21) < h);
    }

    #[test]
    fn simulate_detection_tracks_the_prediction_for_a_perfect_detector() {
        // A pool that always catches (FAR 0): measured ≈ hypergeometric within sampling noise.
        let pool = vec![true; 20];
        let mut rng = StdRng::seed_from_u64(1);
        let trials = 20_000;
        let caught = simulate_detection(&pool, 0.25, 16, 0.10, trials, &mut rng);
        let measured = caught as f64 / trials as f64;
        let predicted = predicted_detection(0.25, 16, 0.10, 0.0);
        assert!((measured - predicted).abs() < 0.02, "measured {measured} vs predicted {predicted}");
    }

    #[test]
    fn escalation_bans_a_blatant_cheater_and_respects_the_floor() {
        // A near-always-caught downscale cheater tampering half its segments is banned, and the
        // first catch happens while still at the Pristine floor (p = P_MIN).
        let pool = vec![true; 16]; // FAR ~0 for a blatant cheater
        let mut rng = StdRng::seed_from_u64(7);
        let trace = simulate_escalation(&pool, 0.5, 16, VerifyDetail::FidelityBelowThreshold, 1_000, &mut rng);
        assert!(trace.banned_at_job.is_some(), "a persistent cheater must reach Banned");
        assert!(trace.first_caught_job.is_some());
        // The very first sampled job is at the pristine floor p = P_MIN.
        assert!((trace.steps[0].p - sched::reputation::P_MIN).abs() < 1e-12);
    }
}
