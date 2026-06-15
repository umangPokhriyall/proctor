//! `live_smoke` — the live single-host smoke run (phase5-spec.md §7).
//!
//! Stands up the **real library code** — `crypto` (no-disk AEAD + transcode), `verify`
//! (batched-decode SSIM + binding), and `sched` (the epoch-fenced `RedisStore`, dispatch,
//! content-addressed release, detail-aware reputation) — over a **local Redis**, a tmpfs
//! [`LocalBlobStore`], a [`LocalKeySource`], and the committed 1–2 segment corpus. It
//! proves the live path enforces the same properties the Phase 4 sim proved:
//!
//! - **(a) Honest end-to-end:** a `Transcode` flows place → lease → fetch → decrypt →
//!   transcode → encrypt → commit → upload → submit → **(sampled) verify** → release; at
//!   least one segment is verified `Ok` and released **at its content address**.
//! - **(b) Process-level zombie (§1.1):** a worker that misses its lease is reclaimed and
//!   re-dispatched to another worker; the slow worker's late `SubmissionMsg` (stale epoch)
//!   is **rejected by the live store** and **exactly one** output is released.
//! - **(c) Batched-decode cost:** the batched extractor (one ffmpeg pass) is far cheaper
//!   than the Phase 3 per-frame-spawn path on the same segment.
//!
//! The worker and verifier are binary crates, so their thin orchestration loops are
//! reproduced here as threads/inline calls; the **load-bearing logic is the real library
//! code**. The engine still emits dispatch onto its in-process `Bus` (the Redis push
//! dispatch is Phase 6); the harness relays `Bus → Redis` inboxes so the workers/verifier
//! read from Redis and return over the live `sched:inbound` channel. Gated on ffmpeg +
//! Redis; loud-skip otherwise (never a fabricated pass).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use proctor_core::{
    decode, encode, Assignment, Codec, Commitment, Container, JobId, LogicalTime, OutputRef,
    SegmentId, SegmentRef, SubmissionMsg, Task, TargetProfile, TaskId, TaskKind, TranscodeSpec,
    VerifyDetail, VerifyRequest, VerifyResult, WorkerId,
};
use sha2::{Digest, Sha256};

use crypto::{
    aead, decrypt_into_memfd, transcode_no_disk, BlobStore, EncryptedSegment, KeySource,
    LocalBlobStore, LocalKeySource, MemFd, Role, SecretKey, SegmentAad,
};
use sched::engine::{Engine, EngineConfig, SubmitOutcome};
use sched::loops::{self, inbound, InboundRouted};
use sched::sample::Sampler;
use sched::store::{Priority, RedisStore};

// --- gating ---------------------------------------------------------------------------

fn ffmpeg_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The Redis URL iff a Redis is reachable (PING), else `None` (the caller loud-skips).
fn redis_url_if_reachable() -> Option<String> {
    let url = std::env::var("PROCTOR_TEST_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(url.as_str()).ok()?;
    let mut conn = client.get_connection().ok()?;
    redis::cmd("PING").query::<String>(&mut conn).ok()?;
    Some(url)
}

// --- fixtures -------------------------------------------------------------------------

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut p = std::env::temp_dir();
        p.push(format!("proctor-smoke-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn corpus(name: &str) -> Option<Vec<u8>> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(name),
    )
    .ok()
}

fn threshold_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results/verify/roc-threshold.json")
}

fn unique_prefix(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("proctor:smoke:{}:{nanos}:{tag}", std::process::id())
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

/// The worker's commitment + content address for a blob: `Commitment::commit(&[SHA-256])`
/// and `OutputRef = lead128(SHA-256)` — what `verify::check_binding` / `sched` agree on.
fn commit_output(blob: &[u8]) -> (Commitment, OutputRef) {
    let leaf: [u8; 32] = Sha256::digest(blob).into();
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&leaf[..16]);
    (Commitment::commit(&[leaf]), OutputRef(u128::from_be_bytes(hi)))
}

/// Encrypt a source segment under a fresh per-segment key, stage it in the blob store, and
/// register the key. Returns the source's content address.
fn seed_segment(
    blob: &LocalBlobStore,
    keys: &mut LocalKeySource,
    job: JobId,
    segment: SegmentId,
    plaintext: &[u8],
) -> SegmentRef {
    let raw = [0x40u8 ^ (segment.0 as u8); 32];
    keys.insert(job, segment, raw);
    let key = SecretKey::from_bytes(raw).unwrap();
    let aad = SegmentAad { job, segment, role: Role::Source };
    let ct = aead::encrypt(plaintext, &key, &aad).unwrap().to_bytes();
    blob.put_source(&ct).unwrap()
}

fn transcode_task(id: u64, job: JobId, segment: SegmentId, source: SegmentRef) -> Task {
    Task::new(
        TaskId(id),
        TaskKind::Transcode(TranscodeSpec {
            job,
            segment,
            profile: profile(),
            source,
        }),
    )
}

// --- a force-sample RNG (matches sched::sim) ------------------------------------------

/// `ConstRng(0)` always samples (`gen_bool(p>0)` is true) so every submission is verified.
struct ConstRng(u64);
impl rand::RngCore for ConstRng {
    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0 as u8);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
fn always_sample() -> Sampler<ConstRng> {
    Sampler::new(ConstRng(0))
}
fn never_sample() -> Sampler<ConstRng> {
    Sampler::new(ConstRng(u64::MAX))
}

// --- the worker / verifier hot loops (real crypto + verify; thin loop reproduced) -----

/// The Transcode hot loop, exactly as `worker::transcode_task` runs it: fetch ciphertext →
/// decrypt into anonymous RAM → `transcode_no_disk` → encrypt → commit → upload → submit
/// (carrying the lease epoch). Plaintext stays in memfds, scrubbed on every path.
fn run_transcode_inline(
    asg: &Assignment,
    spec: &TranscodeSpec,
    blob: &LocalBlobStore,
    keys: &LocalKeySource,
    worker: WorkerId,
) -> Option<SubmissionMsg> {
    let key = keys.key(spec.job, spec.segment).ok()?;
    let source_aad = SegmentAad { job: spec.job, segment: spec.segment, role: Role::Source };
    let output_aad = SegmentAad { job: spec.job, segment: spec.segment, role: Role::Output };

    let ct = blob.get_ref(&spec.source).ok()?;
    let enc = EncryptedSegment::from_bytes(&ct).ok()?;
    let src = decrypt_into_memfd(&enc, &key, &source_aad, "smoke-src").ok()?;
    let mut out = match transcode_no_disk(&src, &spec.profile) {
        Ok(o) => o,
        Err(_) => {
            src.zeroize_and_close();
            return None;
        }
    };
    src.zeroize_and_close();
    let blob_bytes = {
        let plaintext = match out.read_to_secret_buf() {
            Ok(p) => p,
            Err(_) => {
                out.zeroize_and_close();
                return None;
            }
        };
        match aead::encrypt(plaintext.as_bytes(), &key, &output_aad) {
            Ok(e) => e.to_bytes(),
            Err(_) => {
                out.zeroize_and_close();
                return None;
            }
        }
    };
    out.zeroize_and_close();

    let (commitment, output) = commit_output(&blob_bytes);
    blob.put(&blob_bytes).ok()?;
    Some(SubmissionMsg {
        task: asg.task,
        worker,
        epoch: asg.lease.epoch,
        commitment,
        output,
    })
}

/// Transcode verification, exactly as `verifier` runs it: bind (inside `verify_segment`)
/// before any frame, reference-transcode, batched-decode SSIM vs the committed threshold.
fn verify_request_inline(
    req: &VerifyRequest,
    blob: &LocalBlobStore,
    keys: &LocalKeySource,
    threshold: &verify::RocThreshold,
) -> VerifyResult {
    let inconclusive = VerifyResult {
        task: req.task,
        passed: false,
        detail: VerifyDetail::Inconclusive,
    };
    let TaskKind::Transcode(spec) = &req.kind else {
        return inconclusive;
    };
    let (Ok(output_blob), Ok(source_ct)) = (blob.get(&req.output), blob.get_ref(&spec.source))
    else {
        return inconclusive;
    };
    let (Ok(source), Ok(key)) = (
        EncryptedSegment::from_bytes(&source_ct),
        keys.key(spec.job, spec.segment),
    ) else {
        return inconclusive;
    };
    let source_aad = SegmentAad { job: spec.job, segment: spec.segment, role: Role::Source };
    let output_aad = SegmentAad { job: spec.job, segment: spec.segment, role: Role::Output };
    let plan = verify::SamplePlan {
        frames: 4,
        seed: 0x5EED_0001,
        duration_secs: 1.0,
        width: 160,
        height: 120,
    };
    let inputs = verify::SegmentInputs {
        submitted: &req.commitment,
        output_blob: &output_blob,
        source: &source,
        key: &key,
        source_aad: &source_aad,
        output_aad: &output_aad,
        profile: &spec.profile,
    };
    let verdict = verify::verify_segment(&inputs, &plan, threshold);
    VerifyResult {
        task: req.task,
        passed: verdict.passed(),
        detail: verdict.detail,
    }
}

// --- thread spawners + Bus→Redis relay ------------------------------------------------

fn spawn_worker(
    url: String,
    prefix: String,
    worker: WorkerId,
    blob: Arc<LocalBlobStore>,
    keys: Arc<LocalKeySource>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_connection().unwrap();
        let inbox = format!("{prefix}:inbox:{}", worker.0);
        let inbound_key = format!("{prefix}:inbound");
        while !stop.load(Ordering::Relaxed) {
            let popped: Option<(String, Vec<u8>)> = redis::cmd("BRPOP")
                .arg(&inbox)
                .arg(1)
                .query(&mut conn)
                .unwrap_or(None);
            let Some((_, bytes)) = popped else { continue };
            let Ok(asg) = decode::<Assignment>(&bytes) else { continue };
            if let TaskKind::Transcode(spec) = asg.kind.clone() {
                if let Some(sub) = run_transcode_inline(&asg, &spec, &blob, &keys, worker) {
                    let mut frame = vec![inbound::SUBMISSION];
                    frame.extend_from_slice(&encode(&sub));
                    let _: Result<i64, _> =
                        redis::cmd("LPUSH").arg(&inbound_key).arg(frame).query(&mut conn);
                }
            }
        }
    })
}

fn spawn_verifier(
    url: String,
    prefix: String,
    blob: Arc<LocalBlobStore>,
    keys: Arc<LocalKeySource>,
    threshold: verify::RocThreshold,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_connection().unwrap();
        let inbox = format!("{prefix}:inbox:verifier");
        let inbound_key = format!("{prefix}:inbound");
        while !stop.load(Ordering::Relaxed) {
            let popped: Option<(String, Vec<u8>)> = redis::cmd("BRPOP")
                .arg(&inbox)
                .arg(1)
                .query(&mut conn)
                .unwrap_or(None);
            let Some((_, bytes)) = popped else { continue };
            let Ok(req) = decode::<VerifyRequest>(&bytes) else { continue };
            let result = verify_request_inline(&req, &blob, &keys, &threshold);
            let mut frame = vec![inbound::VERDICT];
            frame.extend_from_slice(&encode(&result));
            let _: Result<i64, _> =
                redis::cmd("LPUSH").arg(&inbound_key).arg(frame).query(&mut conn);
        }
    })
}

/// Relay assignments the engine pushed to its in-process `Bus` onto the Redis worker
/// inboxes (the Phase-6 dispatch loop will do this in `sched` itself).
fn relay_assignments(
    engine: &Engine<RedisStore, ConstRng>,
    conn: &mut redis::Connection,
    prefix: &str,
    workers: &[WorkerId],
) {
    for &w in workers {
        while let Some(asg) = engine.bus().pop_assignment(w) {
            let key = format!("{prefix}:inbox:{}", w.0);
            let _: Result<i64, _> = redis::cmd("LPUSH").arg(&key).arg(encode(&asg)).query(conn);
        }
    }
}

/// Relay verify requests the engine pushed to its `Bus` onto the Redis verifier inbox.
fn relay_verify(engine: &Engine<RedisStore, ConstRng>, conn: &mut redis::Connection, prefix: &str) {
    while let Some(req) = engine.bus().pop_verify() {
        let key = format!("{prefix}:inbox:verifier");
        let _: Result<i64, _> = redis::cmd("LPUSH").arg(&key).arg(encode(&req)).query(conn);
    }
}

fn deliver_submission(conn: &mut redis::Connection, prefix: &str, sub: &SubmissionMsg) {
    let mut frame = vec![inbound::SUBMISSION];
    frame.extend_from_slice(&encode(sub));
    let _: i64 = redis::cmd("LPUSH")
        .arg(format!("{prefix}:inbound"))
        .arg(frame)
        .query(conn)
        .unwrap();
}

/// Best-effort namespace cleanup (the test RedisStore key-scrub Drop is sched-internal).
fn cleanup(conn: &mut redis::Connection, prefix: &str) {
    if let Ok(keys) = redis::cmd("KEYS")
        .arg(format!("{prefix}:*"))
        .query::<Vec<String>>(conn)
    {
        if !keys.is_empty() {
            let mut del = redis::cmd("DEL");
            for k in &keys {
                del.arg(k);
            }
            let _ = del.query::<i64>(conn);
        }
    }
}

/// Assert that exactly `expected` blobs in the store are released, each at its content
/// address with a commitment binding the exact bytes (the lazy anti-swap confirm passes).
fn assert_released_at_content_address(
    engine: &Engine<RedisStore, ConstRng>,
    root: &std::path::Path,
    expected: usize,
) {
    let mut released = 0usize;
    for entry in fs::read_dir(root).unwrap().flatten() {
        let path = entry.path();
        let bytes = fs::read(&path).unwrap();
        let (commitment, output) = commit_output(&bytes);
        // Content-addressed store: the file name IS the content address.
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("{:032x}", output.0),
            "every stored blob is named by its content address"
        );
        if let Some(r) = engine.released(output) {
            assert_eq!(
                r.commitment, commitment,
                "release binds the exact bytes at the content address"
            );
            let leaf: [u8; 32] = Sha256::digest(&bytes).into();
            assert!(
                engine.confirm_release(leaf),
                "the lazy anti-swap confirm must pass for a released blob"
            );
            released += 1;
        }
    }
    assert_eq!(
        released, expected,
        "exactly {expected} segment(s) released at their content address"
    );
}

// --- (a) honest end-to-end ------------------------------------------------------------

#[test]
fn honest_end_to_end_verified_and_released() {
    let Some(url) = redis_url_if_reachable() else {
        eprintln!("SKIP honest_end_to_end_verified_and_released: no reachable Redis");
        return;
    };
    if !ffmpeg_available() {
        eprintln!("SKIP honest_end_to_end_verified_and_released: ffmpeg not found");
        return;
    }
    let (Some(g), Some(d)) = (corpus("gradient.mp4"), corpus("detail.mp4")) else {
        eprintln!("SKIP honest_end_to_end_verified_and_released: corpus unavailable");
        return;
    };
    let threshold = verify::RocThreshold::load(threshold_path()).expect("committed ROC threshold");

    let dir = TempDir::new("honest");
    let blob = Arc::new(LocalBlobStore::open(&dir.0).unwrap());
    let mut keys = LocalKeySource::new();
    let job = JobId(1);
    let (s0, s1) = (SegmentId(0), SegmentId(1));
    let src0 = seed_segment(&blob, &mut keys, job, s0, &g);
    let src1 = seed_segment(&blob, &mut keys, job, s1, &d);
    let keys = Arc::new(keys);

    let prefix = unique_prefix("honest");
    let (wa, wb) = (WorkerId(1), WorkerId(2));
    let stop = Arc::new(AtomicBool::new(false));
    let handles = vec![
        spawn_worker(url.clone(), prefix.clone(), wa, blob.clone(), keys.clone(), stop.clone()),
        spawn_worker(url.clone(), prefix.clone(), wb, blob.clone(), keys.clone(), stop.clone()),
        spawn_verifier(url.clone(), prefix.clone(), blob.clone(), keys.clone(), threshold, stop.clone()),
    ];

    // Driver: a RedisStore-backed engine that always samples (so the verifier is exercised).
    let store = RedisStore::connect(&url, prefix.clone()).unwrap();
    let engine = Engine::new(store, EngineConfig::for_workers(2), always_sample());
    engine.register_worker(wa, LogicalTime(0)).unwrap();
    engine.register_worker(wb, LogicalTime(0)).unwrap();
    engine.inject(transcode_task(1, job, s0, src0), Priority::default(), LogicalTime(0)).unwrap();
    engine.inject(transcode_task(2, job, s1, src1), Priority::default(), LogicalTime(0)).unwrap();

    let client = redis::Client::open(url.as_str()).unwrap();
    let mut relay = client.get_connection().unwrap();
    let now = LogicalTime(1);
    let deadline = Instant::now() + Duration::from_secs(120);
    while engine.release_count() < 2 && Instant::now() < deadline {
        loops::dispatch_tick(&engine, now).unwrap();
        relay_assignments(&engine, &mut relay, &prefix, &[wa, wb]);
        relay_verify(&engine, &mut relay, &prefix);
        if let Err(e) = loops::inbound_tick(&engine, 1, now) {
            eprintln!("inbound routing error (continuing): {e}");
        }
        relay_assignments(&engine, &mut relay, &prefix, &[wa, wb]);
        relay_verify(&engine, &mut relay, &prefix);
    }

    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    assert_eq!(
        engine.release_count(),
        2,
        "both honest segments must be sampled-verified Ok and released"
    );
    // Released only happens via the sampled path here, so a release implies a passing verdict.
    assert_released_at_content_address(&engine, blob.root(), 2);

    cleanup(&mut relay, &prefix);
}

// --- (b) process-level zombie ---------------------------------------------------------

#[test]
fn process_level_zombie_submit_is_rejected_with_one_output() {
    let Some(url) = redis_url_if_reachable() else {
        eprintln!("SKIP process_level_zombie_submit_is_rejected_with_one_output: no reachable Redis");
        return;
    };
    if !ffmpeg_available() {
        eprintln!("SKIP process_level_zombie_submit_is_rejected_with_one_output: ffmpeg not found");
        return;
    }
    let Some(g) = corpus("gradient.mp4") else {
        eprintln!("SKIP process_level_zombie_submit_is_rejected_with_one_output: corpus unavailable");
        return;
    };

    let dir = TempDir::new("zombie");
    let blob = LocalBlobStore::open(&dir.0).unwrap();
    let mut keys = LocalKeySource::new();
    let job = JobId(1);
    let seg = SegmentId(0);
    let src = seed_segment(&blob, &mut keys, job, seg, &g);

    let prefix = unique_prefix("zombie");
    let store = RedisStore::connect(&url, prefix.clone()).unwrap();
    // Unsampled: a submission is content-addressed released immediately (no verifier needed
    // for the fencing property — submit-time epoch fencing is what we are proving).
    let engine = Engine::new(store, EngineConfig::for_workers(2), never_sample());
    let (wa, wb) = (WorkerId(1), WorkerId(2));
    engine.register_worker(wa, LogicalTime(0)).unwrap();
    engine.register_worker(wb, LogicalTime(0)).unwrap();
    engine.inject(transcode_task(1, job, seg, src), Priority::default(), LogicalTime(1)).unwrap();

    // 1. Lease to WA. The slow worker does its work but its submission is WITHHELD.
    assert!(loops::dispatch_tick(&engine, LogicalTime(1)).unwrap() >= 1);
    let asg_a = engine.bus().pop_assignment(wa).expect("WA is leased the task");
    let e1 = asg_a.lease.epoch;
    let TaskKind::Transcode(spec_a) = asg_a.kind.clone() else { panic!("expected transcode") };
    let sub_a = run_transcode_inline(&asg_a, &spec_a, &blob, &keys, wa).expect("WA transcode");
    assert_eq!(sub_a.epoch, e1, "WA's submission carries its lease epoch");

    // 2. WA misses its deadline → the single reclaim authority re-dispatches. Refresh only
    //    WB's liveness so the re-dispatch goes to ANOTHER worker (WA is now stale).
    let later = LogicalTime(1 + 100 + 1); // past now + lease_ttl
    let reclaimed = loops::reclaim_tick(&engine, later).unwrap();
    assert!(reclaimed.contains(&TaskId(1)), "the expired lease is reclaimed");
    engine.register_worker(wb, later).unwrap();
    assert!(loops::dispatch_tick(&engine, later).unwrap() >= 1);
    let asg_b = engine.bus().pop_assignment(wb).expect("re-dispatched to WB");
    let e2 = asg_b.lease.epoch;
    assert!(e2 > e1, "the re-lease mints a strictly greater fencing epoch");
    let TaskKind::Transcode(spec_b) = asg_b.kind.clone() else { panic!("expected transcode") };
    let sub_b = run_transcode_inline(&asg_b, &spec_b, &blob, &keys, wb).expect("WB transcode");
    assert_eq!(sub_b.epoch, e2);

    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_connection().unwrap();

    // 3. The zombie WA resumes FIRST and submits while the task is leased to WB: its
    //    stale epoch (e1 < e2) is fenced by the live Redis store's epoch CAS.
    deliver_submission(&mut conn, &prefix, &sub_a);
    let routed_a = loops::inbound_tick(&engine, 2, later).unwrap().expect("WA return routed");
    assert_eq!(
        routed_a,
        InboundRouted::Submission(SubmitOutcome::RejectedZombie),
        "the slow zombie's late submit must be rejected (StaleEpoch)"
    );
    assert_eq!(engine.release_count(), 0, "the zombie produced no output");

    // 4. WB's legitimate submission (current epoch) flows through and is released.
    deliver_submission(&mut conn, &prefix, &sub_b);
    let routed_b = loops::inbound_tick(&engine, 2, later).unwrap().expect("WB return routed");
    assert!(
        matches!(routed_b, InboundRouted::Submission(SubmitOutcome::Accepted(_))),
        "the legitimate re-execution is accepted, got {routed_b:?}"
    );
    assert_eq!(
        engine.release_count(),
        1,
        "exactly one output exists for the segment despite the zombie race"
    );

    cleanup(&mut conn, &prefix);
}

// --- (c) batched-decode cost spot-check -----------------------------------------------

#[test]
fn batched_decode_is_cheaper_than_per_frame_spawn() {
    if !ffmpeg_available() {
        eprintln!("SKIP batched_decode_is_cheaper_than_per_frame_spawn: ffmpeg not found");
        return;
    }
    let Some(media) = corpus("gradient.mp4") else {
        eprintln!("SKIP batched_decode_is_cheaper_than_per_frame_spawn: corpus unavailable");
        return;
    };

    let mut mf = MemFd::create("smoke-cost").unwrap();
    mf.write_all(&media).unwrap();

    // Phase 3 cost: one ffmpeg process-spawn PER frame (the ~10x artifact). Phase 5 remedy:
    // one spawn for ALL sampled frames. Same K, same geometry, same machine — relative.
    const K: usize = 8;
    let (w, h) = (160u32, 120u32);
    let timestamps: Vec<f64> = (0..K).map(|i| i as f64 * 0.4).collect();
    let fractions: Vec<f64> = (0..K).map(|i| i as f64 / K as f64).collect();

    let t_pf = Instant::now();
    for &ts in &timestamps {
        verify::extract_y_frame(&mf, ts, w, h).expect("per-frame extract");
    }
    let per_frame = t_pf.elapsed();

    let t_b = Instant::now();
    let frames = verify::extract_y_frames(&mf, &fractions, w, h).expect("batched extract");
    let batched = t_b.elapsed();
    mf.zeroize_and_close();

    assert_eq!(frames.len(), K, "batched returns one plane per sampled position");
    eprintln!(
        "batched-decode cost spot-check: {K} frames — per-frame-spawn {per_frame:?} vs batched {batched:?} \
         (Phase 3 figure: ~94–100 ms/frame extraction; full distribution → Phase 6)"
    );
    assert!(
        batched < per_frame,
        "batched decode ({batched:?}) must be cheaper than the Phase 3 per-frame-spawn path ({per_frame:?})"
    );
}
