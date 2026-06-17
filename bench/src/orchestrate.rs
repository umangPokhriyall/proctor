//! `orchestrate` — spawn the live single-host cluster (phase6-spec.md §3).
//!
//! Brings up one `sched`, N `worker`s, and M `verifier`s as **`taskset -c`-pinned**
//! subprocesses (mechanical sympathy: disjoint cores, NUMA topology documented in
//! `METHODOLOGY.md`) over a **loopback** Redis, all sharing the staged blob store and key
//! directory ([`crate::preprocess`]). Single host is the documented caveat (locked decision
//! #5): geography is orthogonal to the placement / crypto / verification / fencing
//! properties measured here. Teardown kills the children and flushes the test Redis
//! namespace so a run leaves nothing behind.
//!
//! Core-pinning is the external `taskset` command, never FFI — `bench` is
//! `#![forbid(unsafe_code)]` (phase6-spec.md hard rule 1). If `taskset` is absent the
//! processes still run, unpinned, with a logged caveat.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use proctor_core::WorkerId;

/// What can go wrong bringing the cluster up.
#[derive(Debug, thiserror::Error)]
pub enum OrchestrateError {
    #[error("io spawning {label}: {source}")]
    Spawn {
        label: String,
        #[source]
        source: std::io::Error,
    },
    #[error("binary not found: {0} (build the workspace first: `cargo build`)")]
    BinaryMissing(PathBuf),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
}

/// How to bring up the cluster.
pub struct Config {
    /// Loopback Redis URL (`redis://127.0.0.1:6379`).
    pub redis_url: String,
    /// Key prefix namespacing this run (unique per run so namespaces never collide).
    pub prefix: String,
    /// Shared content-addressed ciphertext store (`PROCTOR_BLOB_ROOT`).
    pub blob_root: PathBuf,
    /// Shared per-segment key directory (`PROCTOR_KEY_DIR`).
    pub key_dir: PathBuf,
    /// Committed ROC threshold file the verifiers load (never a literal).
    pub roc_threshold: PathBuf,
    /// Number of worker processes (ids `1..=workers`, matching `sched`'s registered set).
    pub workers: u32,
    /// Number of verifier processes.
    pub verifiers: u32,
    /// Directory the processes append their event logs to (`{label}.log`).
    pub event_log_dir: PathBuf,
    /// Cores available for pinning; processes are pinned round-robin (disjoint if enough).
    pub cores: Vec<usize>,
    /// Directory holding the built `sched`/`worker`/`verifier` binaries.
    pub bin_dir: PathBuf,
    /// Optional bounded run length passed to `sched` (`PROCTOR_RUN_SECS`).
    pub run_secs: Option<u64>,
}

impl Config {
    /// The directory the currently-running binary lives in — where `cargo` also put the
    /// sibling `sched`/`worker`/`verifier` binaries.
    #[must_use]
    pub fn sibling_bin_dir() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("target/debug"))
    }

    /// The host's CPU ids `0..nproc` as the default pinning pool.
    #[must_use]
    pub fn host_cores() -> Vec<usize> {
        let n = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        (0..n).collect()
    }
}

/// A running cluster. Dropping it (or calling [`Cluster::teardown`]) kills every child and
/// flushes the Redis namespace.
pub struct Cluster {
    children: Vec<(String, Child)>,
    redis_url: String,
    prefix: String,
}

/// Whether `taskset` is callable (core-pinning; the caller runs unpinned if absent).
#[must_use]
pub fn taskset_available() -> bool {
    Command::new("taskset")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn binary(bin_dir: &Path, name: &str) -> Result<PathBuf, OrchestrateError> {
    let p = bin_dir.join(name);
    if p.exists() {
        Ok(p)
    } else {
        Err(OrchestrateError::BinaryMissing(p))
    }
}

/// Bring up `sched` + N `worker`s + M `verifier`s. Each process is pinned to a distinct core
/// (round-robin over `cfg.cores`) when `taskset` is present. Returns the live [`Cluster`].
pub fn spawn(cfg: &Config) -> Result<Cluster, OrchestrateError> {
    let sched_bin = binary(&cfg.bin_dir, "sched")?;
    let worker_bin = binary(&cfg.bin_dir, "worker")?;
    let verifier_bin = binary(&cfg.bin_dir, "verifier")?;
    std::fs::create_dir_all(&cfg.event_log_dir).map_err(|e| OrchestrateError::Spawn {
        label: "event_log_dir".into(),
        source: e,
    })?;

    let pin = taskset_available() && !cfg.cores.is_empty();
    if !pin {
        eprintln!("proctor bench: taskset unavailable or no cores — running unpinned (caveat)");
    }
    let mut core_idx = 0usize;
    let next_core = |cfg: &Config, core_idx: &mut usize| -> Option<usize> {
        if !pin {
            return None;
        }
        let c = cfg.cores[*core_idx % cfg.cores.len()];
        *core_idx += 1;
        Some(c)
    };

    let mut children = Vec::new();

    // sched: the placement authority. Knows the worker count so its tier cache + the Redis
    // registry agree; emits the lifecycle event log.
    {
        let core = next_core(cfg, &mut core_idx);
        let mut cmd = pinned(&sched_bin, core);
        cmd.env("PROCTOR_REDIS_URL", &cfg.redis_url)
            .env("PROCTOR_REDIS_PREFIX", &cfg.prefix)
            .env("PROCTOR_WORKERS", cfg.workers.to_string())
            .env("PROCTOR_EVENT_LOG", cfg.event_log_dir.join("sched.log"));
        if let Some(secs) = cfg.run_secs {
            cmd.env("PROCTOR_RUN_SECS", secs.to_string());
        }
        children.push(("sched".to_string(), spawn_child("sched", cmd)?));
    }

    // Workers 1..=N, ids matching sched's registered set. One task at a time (CPU-bound).
    for w in 1..=cfg.workers {
        let core = next_core(cfg, &mut core_idx);
        let label = format!("worker-{w}");
        let mut cmd = pinned(&worker_bin, core);
        cmd.env("PROCTOR_REDIS_URL", &cfg.redis_url)
            .env("PROCTOR_REDIS_PREFIX", &cfg.prefix)
            .env("PROCTOR_WORKER_ID", WorkerId(u64::from(w)).0.to_string())
            .env("PROCTOR_BLOB_ROOT", &cfg.blob_root)
            .env("PROCTOR_KEY_DIR", &cfg.key_dir)
            .env("PROCTOR_WORKER_CAP", "1")
            .env("PROCTOR_EVENT_LOG", cfg.event_log_dir.join(format!("{label}.log")));
        children.push((label.clone(), spawn_child(&label, cmd)?));
    }

    // Verifiers: trusted re-execution comparators (separate binary, locked decision #3).
    for v in 0..cfg.verifiers {
        let core = next_core(cfg, &mut core_idx);
        let label = format!("verifier-{v}");
        let mut cmd = pinned(&verifier_bin, core);
        cmd.env("PROCTOR_REDIS_URL", &cfg.redis_url)
            .env("PROCTOR_REDIS_PREFIX", &cfg.prefix)
            .env("PROCTOR_BLOB_ROOT", &cfg.blob_root)
            .env("PROCTOR_KEY_DIR", &cfg.key_dir)
            .env("PROCTOR_ROC_THRESHOLD", &cfg.roc_threshold)
            .env("PROCTOR_EVENT_LOG", cfg.event_log_dir.join(format!("{label}.log")));
        children.push((label.clone(), spawn_child(&label, cmd)?));
    }

    Ok(Cluster {
        children,
        redis_url: cfg.redis_url.clone(),
        prefix: cfg.prefix.clone(),
    })
}

/// Build a `Command` for `bin`, wrapped in `taskset -c {core}` when a core is given.
fn pinned(bin: &Path, core: Option<usize>) -> Command {
    match core {
        Some(c) => {
            let mut cmd = Command::new("taskset");
            cmd.arg("-c").arg(c.to_string()).arg(bin);
            cmd
        }
        None => Command::new(bin),
    }
}

fn spawn_child(label: &str, mut cmd: Command) -> Result<Child, OrchestrateError> {
    // Inherit stderr (the bins log there); silence stdout (none is produced).
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());
    cmd.spawn().map_err(|e| OrchestrateError::Spawn {
        label: label.to_string(),
        source: e,
    })
}

impl Cluster {
    /// Kill every child, wait for it, then flush the Redis namespace. Idempotent-ish:
    /// consumes the cluster.
    pub fn teardown(mut self) {
        self.kill_all();
        if let Err(e) = self.flush_namespace() {
            eprintln!("proctor bench: namespace flush failed: {e}");
        }
    }

    fn kill_all(&mut self) {
        for (label, child) in &mut self.children {
            if let Err(e) = child.kill() {
                // AlreadyExited is fine (a bounded sched may have exited on its own).
                if e.kind() != std::io::ErrorKind::InvalidInput {
                    eprintln!("proctor bench: kill {label}: {e}");
                }
            }
            let _ = child.wait();
        }
        self.children.clear();
    }

    fn flush_namespace(&self) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(self.redis_url.as_str())?;
        let mut conn = client.get_connection()?;
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{}:*", self.prefix))
            .query(&mut conn)?;
        if !keys.is_empty() {
            let mut del = redis::cmd("DEL");
            for k in &keys {
                del.arg(k);
            }
            let _: i64 = del.query(&mut conn)?;
        }
        Ok(())
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        // Best-effort: if the caller did not call teardown(), still don't leak children.
        self.kill_all();
        let _ = self.flush_namespace();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_a_clean_error() {
        let cfg = Config {
            redis_url: "redis://127.0.0.1:6379".into(),
            prefix: "proctor:bench:test".into(),
            blob_root: std::env::temp_dir(),
            key_dir: std::env::temp_dir(),
            roc_threshold: PathBuf::from("/nonexistent/roc.json"),
            workers: 1,
            verifiers: 1,
            event_log_dir: std::env::temp_dir().join("proctor-orch-test"),
            cores: vec![],
            bin_dir: PathBuf::from("/nonexistent/bin/dir"),
            run_secs: Some(1),
        };
        assert!(matches!(spawn(&cfg), Err(OrchestrateError::BinaryMissing(_))));
    }

    #[test]
    fn sibling_bin_dir_and_host_cores_are_sane() {
        assert!(Config::sibling_bin_dir().is_absolute() || Config::sibling_bin_dir().exists());
        assert!(!Config::host_cores().is_empty());
    }
}
