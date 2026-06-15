//! proctor `worker` — the untrusted hot loop (phase5-spec.md §4).
//!
//! Register → `BRPOP` a pushed [`Assignment`] → dispatch by kind → for a Transcode,
//! fetch ciphertext → decrypt into anonymous RAM → `transcode_no_disk` → encrypt in
//! RAM → commit `Commitment::commit(&[SHA-256(blob)])` / `output = lead128(SHA-256)`
//! → upload to the content-addressed blob store → submit **carrying the lease
//! epoch**, heartbeating during the work. The worker **receives** assignments; it
//! never self-selects (locked decision #6). It persists no plaintext and no keys.
//!
//! **Purity & honesty boundaries (phase5-spec.md §8):**
//! - `#![forbid(unsafe_code)]` — all `unsafe` lives in `crypto::sys`; no async/tokio.
//! - Concurrency is `min(cap, cgroup cpu.max)` — never host loadavg/num_cpus
//!   ([`concurrency`], the legacy mechanical-sympathy bug, structurally avoided).
//! - Plaintext lives only in anonymous-RAM memfds and `mlock`'d zeroizing buffers
//!   (inherited from `crypto`); the per-segment key is `mlock`'d/zeroized. Only
//!   ciphertext is uploaded. The worker holds the key — the documented
//!   confidentiality boundary the microVM flagship exists to close (THREAT-MODEL.md).

#![forbid(unsafe_code)]

mod concurrency;
mod stitch_task;
mod transcode_task;
mod transport;

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proctor_core::{Commitment, HeartbeatMsg, OutputRef, TaskKind, WorkerId};
use sha2::{Digest, Sha256};

use crypto::{LocalBlobStore, LocalKeySource};
use transport::{Sender, Transport};

/// Errors surfaced by the worker hot loop. Crypto/decode failures fail the task (no
/// plaintext leaks); transport errors fail the loop.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// A crypto-path failure (decrypt/encrypt/transcode/blob/key) — never yields plaintext.
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    /// A pushed message did not decode as the expected wire type.
    #[error("decode: {0}")]
    Decode(#[from] proctor_core::ProtoError),
    /// A Redis transport error.
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    /// A Redis Lua script returned an unexpected control reply.
    #[error("redis script: {0}")]
    Script(String),
    /// A stitch input's served bytes did not match its committed `(OutputRef, Commitment)`.
    #[error("stitch input content-address mismatch (swapped input)")]
    InputAddressMismatch,
    /// The blob store and the worker's commitment math derived different content
    /// addresses — unreachable by construction; a defensive guard against drift.
    #[error("blob store / commitment content-address disagreement")]
    AddressDisagreement,
    /// A configuration / environment error (e.g. an unparseable env var).
    #[error("config: {0}")]
    Config(String),
}

/// The worker's commitment and content address for an output blob: the single-leaf
/// Merkle root `Commitment::commit(&[SHA-256(blob)])` and `OutputRef =
/// lead128(SHA-256(blob))`. These are exactly what `verify::check_binding` re-derives
/// and what `sched` releases by (phase5-spec.md §4.2, amendment §1.2.4) — proven by
/// the `transcode_task` test that calls the real `check_binding`.
#[must_use]
pub(crate) fn commit_output(blob: &[u8]) -> (Commitment, OutputRef) {
    let leaf: [u8; 32] = Sha256::digest(blob).into();
    let commitment = Commitment::commit(&[leaf]);
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&leaf[..16]);
    (commitment, OutputRef(u128::from_be_bytes(hi)))
}

/// Runtime configuration, all from the environment (no ingest API — locked #2).
struct Config {
    redis_url: String,
    prefix: String,
    worker: WorkerId,
    blob_root: std::path::PathBuf,
    key_dir: Option<std::path::PathBuf>,
    cap: u32,
    heartbeat: Duration,
    brpop_secs: u64,
}

impl Config {
    fn from_env() -> Result<Self, WorkerError> {
        let redis_url = std::env::var("PROCTOR_REDIS_URL")
            .map_err(|_| WorkerError::Config("PROCTOR_REDIS_URL is required".into()))?;
        let prefix =
            std::env::var("PROCTOR_REDIS_PREFIX").unwrap_or_else(|_| "proctor:sched".into());
        let worker = WorkerId(parse_env("PROCTOR_WORKER_ID", 1)?);
        let blob_root = std::env::var("PROCTOR_BLOB_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("proctor-blobs"));
        let key_dir = std::env::var("PROCTOR_KEY_DIR").ok().map(std::path::PathBuf::from);
        let cap: u32 = parse_env("PROCTOR_WORKER_CAP", 4)?;
        let heartbeat = Duration::from_millis(parse_env("PROCTOR_HEARTBEAT_MS", 2000)?);
        let brpop_secs: u64 = parse_env("PROCTOR_BRPOP_SECS", 5)?;
        Ok(Self {
            redis_url,
            prefix,
            worker,
            blob_root,
            key_dir,
            cap,
            heartbeat,
            brpop_secs,
        })
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> Result<T, WorkerError> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|_| WorkerError::Config(format!("{name}: cannot parse {v:?}"))),
        Err(_) => Ok(default),
    }
}

/// Load benchmark keys from `dir`: files named `{job}-{segment}.key` holding exactly
/// 32 raw bytes. Benchmark keys on disk are permitted (phase5-spec.md hard rule 3);
/// production key delivery is over TLS (`crypto::keysource`, NOT built). Returns the
/// seeded [`LocalKeySource`]; an empty/absent dir yields an empty source.
fn load_keys(dir: Option<&std::path::Path>) -> Result<LocalKeySource, WorkerError> {
    let mut keys = LocalKeySource::new();
    let Some(dir) = dir else {
        return Ok(keys);
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(keys), // absent key dir is fine (the harness may seed in-process)
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
            std::fs::read(&path).map_err(|e| WorkerError::Config(format!("{path:?}: {e}")))?;
        let raw: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| WorkerError::Config(format!("{path:?}: key must be exactly 32 bytes")))?;
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
            eprintln!("proctor worker: {e}");
            eprintln!(
                "proctor worker: set PROCTOR_REDIS_URL (and optionally PROCTOR_WORKER_ID, \
                 PROCTOR_BLOB_ROOT, PROCTOR_KEY_DIR, PROCTOR_WORKER_CAP)."
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = serve(cfg) {
        eprintln!("proctor worker: fatal: {e}");
        std::process::exit(1);
    }
}

/// The worker lifecycle: register, then the bounded inbox loop. Concurrency is
/// `min(cap, cgroup cpu.max)`; one std thread per concurrent task, gated by a permit
/// channel so the worker never runs more than its CPU budget allows.
fn serve(cfg: Config) -> Result<(), WorkerError> {
    let conc = concurrency::effective_concurrency(cfg.cap);
    let blob = Arc::new(LocalBlobStore::open(&cfg.blob_root)?);
    let keys = Arc::new(load_keys(cfg.key_dir.as_deref())?);

    let mut transport = Transport::connect(&cfg.redis_url, cfg.prefix.clone())?;
    transport.register(cfg.worker, now_secs())?;
    let sender = transport.handle();

    eprintln!(
        "proctor worker {}: registered; concurrency {} (cap {}, cgroup-bounded); blobs at {:?}",
        cfg.worker.0, conc, cfg.cap, cfg.blob_root
    );

    // A permit channel is a simple counting semaphore: `conc` tokens, one held per
    // in-flight task, returned when the task thread finishes.
    let (permits_tx, permits_rx) = mpsc::channel::<()>();
    for _ in 0..conc {
        permits_tx.send(()).expect("permit channel open");
    }

    loop {
        // Block until a slot frees up, then poll the inbox for an assignment.
        permits_rx.recv().expect("at least one permit producer is alive");
        let assignment = match transport.next_assignment(cfg.worker, cfg.brpop_secs)? {
            Some(a) => a,
            None => {
                // Idle timeout: return the permit and keep waiting.
                permits_tx.send(()).expect("permit channel open");
                continue;
            }
        };

        let blob = blob.clone();
        let keys = keys.clone();
        let sender = sender.clone();
        let permit_return = permits_tx.clone();
        let worker = cfg.worker;
        let heartbeat = cfg.heartbeat;

        std::thread::spawn(move || {
            run_one(&assignment, blob.as_ref(), keys.as_ref(), &sender, worker, heartbeat);
            // Return the permit whether the task succeeded or failed.
            let _ = permit_return.send(());
        });
    }
}

/// Run one assignment to completion: start a heartbeat, dispatch by kind, and submit
/// the result onto the return channel. A task-level failure is logged and dropped —
/// the scheduler's reclaim path re-dispatches the task (a failed worker is a liveness
/// event, not a safety one; fencing handles the zombie).
fn run_one(
    assignment: &proctor_core::Assignment,
    blob: &LocalBlobStore,
    keys: &LocalKeySource,
    sender: &Sender,
    worker: WorkerId,
    heartbeat: Duration,
) {
    let hb = sender.start_heartbeat(
        HeartbeatMsg {
            task: assignment.task,
            worker,
            epoch: assignment.lease.epoch,
        },
        heartbeat,
    );

    let result = match &assignment.kind {
        TaskKind::Transcode(spec) => {
            transcode_task::run_transcode(assignment, spec, blob, keys, worker)
        }
        TaskKind::Stitch(spec) => stitch_task::run_stitch(assignment, spec, blob, keys, worker),
    };

    // Stop heartbeating before the (epoch-carrying) submit.
    hb.stop();

    match result {
        Ok(submission) => {
            if let Err(e) = sender.send_submission(&submission) {
                eprintln!(
                    "proctor worker {}: task {} submit failed: {e}",
                    worker.0, assignment.task.0
                );
            }
        }
        Err(e) => {
            eprintln!(
                "proctor worker {}: task {} failed: {e}",
                worker.0, assignment.task.0
            );
        }
    }
}

/// Wall-clock seconds since the epoch, for the registry `last_heartbeat` field.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_output_is_deterministic_and_content_addressed() {
        let (c1, o1) = commit_output(b"abc");
        let (c2, o2) = commit_output(b"abc");
        assert_eq!(c1, c2);
        assert_eq!(o1, o2);
        let (_, o3) = commit_output(b"abd");
        assert_ne!(o1, o3, "distinct blobs ⇒ distinct content addresses");
    }
}
