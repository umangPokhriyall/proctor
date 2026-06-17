//! `orchestrate` — spawn the live single-host cluster (phase6-spec.md §3, phase7-spec.md §3).
//!
//! Brings up one `sched`, N `worker`s, and M `verifier`s as **`taskset -c`-pinned**
//! subprocesses (mechanical sympathy: disjoint cores, NUMA topology documented in
//! `METHODOLOGY.md`) over a **loopback** Redis, all sharing the staged blob store and key
//! directory ([`crate::preprocess`]). Single host is the documented caveat (locked decision
//! #5): geography is orthogonal to the placement / crypto / verification / fencing
//! properties measured here. Teardown kills the children and flushes the test Redis
//! namespace so a run leaves nothing behind.
//!
//! **NUMA-aware pinning (phase7-spec.md §3):** [`Pinning::plan`] derives the per-role core
//! assignment from the host [`crate::topology::Topology`] — a dedicated core each for `sched`,
//! Redis, and every verifier, then **one disjoint physical core per worker** (spilling across
//! sockets, not hyperthread siblings, until the physical cores run out). The plan records
//! which socket Redis sits on so the loopback RTT is attributable. Phase 6's flat round-robin
//! over logical CPUs was honest on a 4c/8t laptop but cannot produce a real scaling curve
//! above the physical-core count; this is the bare-metal fix.
//!
//! Worker/verifier processes hold mlock'd keys and memfd plaintext; the orchestrator raises
//! their `RLIMIT_MEMLOCK` (soft → the host's hard ceiling) via the external `prlimit` so the
//! mlock path does not fail under high concurrency (phase7-spec.md §3).
//!
//! Core-pinning is the external `taskset` command and the memlock raise is external `prlimit`,
//! never FFI — `bench` is `#![forbid(unsafe_code)]` (phase6/phase7-spec hard rule 1). If
//! `taskset`/`prlimit` are absent the processes still run (unpinned / inherited limit) with a
//! logged caveat.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use proctor_core::WorkerId;

use crate::topology::Topology;

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
    /// NUMA-aware per-role core assignment (dedicated cores + disjoint worker cores).
    pub pinning: Pinning,
    /// Raise `RLIMIT_MEMLOCK` (soft → hard ceiling) on the worker/verifier processes via
    /// `prlimit` so the mlock'd-key / memfd path survives high concurrency (phase7-spec §3).
    pub raise_memlock: bool,
    /// Directory holding the built `sched`/`worker`/`verifier` binaries.
    pub bin_dir: PathBuf,
    /// Optional bounded run length passed to `sched` (`PROCTOR_RUN_SECS`).
    pub run_secs: Option<u64>,
}

/// A NUMA-aware core assignment: a dedicated core for each control/IO/verify role, then one
/// **disjoint physical core per worker** (phase7-spec.md §3). `worker_cores[i]` is the
/// `taskset` target for worker `i+1`; once the physical cores are exhausted the tail spills
/// onto hyperthread siblings (oversubscription, recorded in [`Pinning::description`]).
#[derive(Debug, Clone)]
pub struct Pinning {
    /// Logical CPU for `sched`, or `None` to run it unpinned.
    pub sched_core: Option<usize>,
    /// Logical CPU dedicated to Redis. `bench` does not launch Redis (it is external), so this
    /// is **advisory**: the operator pins `redis-server` here; it is recorded in
    /// [`Pinning::description`] so the loopback RTT and NUMA effects are attributable.
    pub redis_core: Option<usize>,
    /// Logical CPU per verifier (`verifier_cores[i]` → verifier `i`).
    pub verifier_cores: Vec<usize>,
    /// Logical CPU per worker (`worker_cores[i]` → worker `i+1`).
    pub worker_cores: Vec<usize>,
    /// Human-readable socket-placement summary for `METHODOLOGY.md` and the spawn log.
    pub description: String,
}

impl Pinning {
    /// No pinning at all — every process inherits the parent CPU affinity (the fallback when
    /// `taskset` is unavailable, and the default for unit tests that never spawn).
    #[must_use]
    pub fn unpinned() -> Self {
        Self {
            sched_core: None,
            redis_core: None,
            verifier_cores: Vec::new(),
            worker_cores: Vec::new(),
            description: "unpinned (no taskset / explicit opt-out)".to_string(),
        }
    }

    /// Derive a NUMA-aware plan from the host `topo`: dedicate cores (node-0-first) to `sched`,
    /// Redis, and each of `verifiers`, then assign **one disjoint physical core per worker**
    /// across the remaining cores (node 0 then node 1…). If `workers` exceeds the free physical
    /// cores, the tail spills round-robin onto the worker pool's hyperthread siblings and the
    /// `description` records exactly where oversubscription begins.
    #[must_use]
    pub fn plan(topo: &Topology, workers: u32, verifiers: u32) -> Self {
        // Physical cores are already node-major ordered (node 0 first), so infra lands on node 0.
        let cores = &topo.physical_cores;
        let mut next = 0usize; // index into the physical-core list as we hand out dedicated cores
        let take = |next: &mut usize| -> Option<&crate::topology::PhysicalCore> {
            let c = cores.get(*next);
            if c.is_some() {
                *next += 1;
            }
            c
        };

        let sched_pc = take(&mut next).cloned();
        let redis_pc = take(&mut next).cloned();
        let mut verifier_cores = Vec::with_capacity(verifiers as usize);
        for _ in 0..verifiers {
            if let Some(pc) = take(&mut next) {
                verifier_cores.push(pc.rep_cpu);
            }
        }

        // The worker pool is whatever physical cores remain after the dedicated roles.
        let worker_pool: Vec<&crate::topology::PhysicalCore> = cores[next.min(cores.len())..]
            .iter()
            .collect();
        let disjoint = worker_pool.len();
        // Siblings of the worker pool, flattened — the oversubscription spill list.
        let spill: Vec<usize> = worker_pool.iter().flat_map(|c| c.siblings.iter().copied()).collect();
        let spill = if spill.is_empty() { topo.logical_cpus.clone() } else { spill };

        let mut worker_cores = Vec::with_capacity(workers as usize);
        let mut oversub_at: Option<u32> = None;
        for w in 0..workers as usize {
            if w < disjoint {
                worker_cores.push(worker_pool[w].rep_cpu);
            } else {
                if oversub_at.is_none() {
                    oversub_at = Some(w as u32 + 1);
                }
                worker_cores.push(spill[w % spill.len().max(1)]);
            }
        }

        let sched_core = sched_pc.as_ref().map(|c| c.rep_cpu);
        let redis_core = redis_pc.as_ref().map(|c| c.rep_cpu);
        let redis_node = redis_pc.as_ref().map_or(0, |c| c.node);
        let nodes = topo.nodes.len();
        let mut description = format!(
            "{} NUMA node(s), {} physical core(s) / {} logical CPU(s){}; \
             sched→cpu{:?} redis→cpu{:?}(node {}) verifiers→{:?}; \
             {} worker(s) on {} disjoint physical core(s)",
            nodes,
            topo.physical_core_count(),
            topo.logical_cpus.len(),
            if topo.detected { "" } else { " [sysfs fallback: sibling/socket info approximate]" },
            sched_core,
            redis_core,
            redis_node,
            verifier_cores,
            workers,
            disjoint.min(workers as usize),
        );
        match oversub_at {
            Some(w) => description.push_str(&format!(
                "; OVERSUBSCRIPTION begins at worker {w} (only {disjoint} physical core(s) free \
                 for workers — the tail shares hyperthread siblings; this curve is not clean above N={})",
                disjoint,
            )),
            None => description.push_str(" (no oversubscription)"),
        }

        Self { sched_core, redis_core, verifier_cores, worker_cores, description }
    }
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
    tool_available("taskset")
}

/// Whether an external helper (`taskset`, `prlimit`) responds to `--version`.
fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The host's `RLIMIT_MEMLOCK` **hard** ceiling, parsed from `/proc/self/limits`
/// (`"unlimited"` or a byte count). Raising the worker/verifier soft limit to this ceiling
/// needs no privilege (it never raises the hard limit) yet gives the mlock path maximum
/// headroom; on a root bare-metal box the ceiling is typically `unlimited`. `None` if the
/// limit cannot be read.
fn memlock_hard_ceiling() -> Option<String> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    for line in limits.lines() {
        if line.starts_with("Max locked memory") {
            // "Max locked memory   <soft>   <hard>   bytes"
            let cols: Vec<&str> = line.split_whitespace().collect();
            // hard is the second numeric/"unlimited" column after the "Max locked memory" label.
            return cols.get(cols.len().wrapping_sub(2)).map(ToString::to_string);
        }
    }
    None
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

    let pin = taskset_available();
    if !pin {
        eprintln!("proctor bench: taskset unavailable — running unpinned (caveat)");
    }
    // Raise the worker/verifier RLIMIT_MEMLOCK soft limit to the host hard ceiling via prlimit
    // (no privilege needed; never raises the hard limit). sched holds no mlock'd keys.
    let memlock: Option<String> = if cfg.raise_memlock && tool_available("prlimit") {
        let m = memlock_hard_ceiling();
        if m.is_none() {
            eprintln!("proctor bench: could not read RLIMIT_MEMLOCK ceiling — leaving it inherited");
        }
        m
    } else {
        if cfg.raise_memlock {
            eprintln!("proctor bench: prlimit unavailable — RLIMIT_MEMLOCK left inherited (caveat)");
        }
        None
    };
    let core_or_none = |c: Option<usize>| if pin { c } else { None };

    eprintln!("proctor bench: pinning — {}", cfg.pinning.description);
    if cfg.raise_memlock {
        if let Some(m) = &memlock {
            eprintln!("proctor bench: worker/verifier RLIMIT_MEMLOCK soft → {m} (prlimit)");
        }
    }

    let mut children = Vec::new();

    // sched: the placement authority. Knows the worker count so its tier cache + the Redis
    // registry agree; emits the lifecycle event log. Dedicated core, no memlock raise.
    {
        let mut cmd = launch(&sched_bin, core_or_none(cfg.pinning.sched_core), None);
        cmd.env("PROCTOR_REDIS_URL", &cfg.redis_url)
            .env("PROCTOR_REDIS_PREFIX", &cfg.prefix)
            .env("PROCTOR_WORKERS", cfg.workers.to_string())
            .env("PROCTOR_EVENT_LOG", cfg.event_log_dir.join("sched.log"));
        if let Some(secs) = cfg.run_secs {
            cmd.env("PROCTOR_RUN_SECS", secs.to_string());
        }
        children.push(("sched".to_string(), spawn_child("sched", cmd)?));
    }

    // Workers 1..=N, ids matching sched's registered set. One task at a time (CPU-bound),
    // each on its own disjoint physical core; RLIMIT_MEMLOCK raised for the mlock'd-key path.
    for w in 1..=cfg.workers {
        let core = core_or_none(cfg.pinning.worker_cores.get((w - 1) as usize).copied());
        let label = format!("worker-{w}");
        let mut cmd = launch(&worker_bin, core, memlock.as_deref());
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
    // Dedicated cores; RLIMIT_MEMLOCK raised (they too decrypt into mlock'd/memfd memory).
    for v in 0..cfg.verifiers {
        let core = core_or_none(cfg.pinning.verifier_cores.get(v as usize).copied());
        let label = format!("verifier-{v}");
        let mut cmd = launch(&verifier_bin, core, memlock.as_deref());
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

/// Build a `Command` launching `bin`, composing the external wrappers outermost-first:
/// `prlimit --memlock=M:M taskset -c {core} {bin}`. Each wrapper is applied only when
/// requested, so an unpinned, limit-inherited launch is just `Command::new(bin)`. Both
/// wrappers are external commands (no FFI; `bench` is `#![forbid(unsafe_code)]`).
fn launch(bin: &Path, core: Option<usize>, memlock: Option<&str>) -> Command {
    let mut chain: Vec<OsString> = Vec::new();
    if let Some(m) = memlock {
        chain.push("prlimit".into());
        chain.push(format!("--memlock={m}:{m}").into());
    }
    if let Some(c) = core {
        chain.push("taskset".into());
        chain.push("-c".into());
        chain.push(c.to_string().into());
    }
    chain.push(bin.into());
    let mut cmd = Command::new(&chain[0]);
    cmd.args(&chain[1..]);
    cmd
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
            pinning: Pinning::unpinned(),
            raise_memlock: false,
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

    #[test]
    fn pinning_plan_dedicates_cores_and_pins_workers_disjoint() {
        let topo = Topology::detect();
        let phys = topo.physical_core_count();
        let plan = Pinning::plan(&topo, 2, 1);
        // One core per requested worker; dedicated roles drawn before workers.
        assert_eq!(plan.worker_cores.len(), 2);
        assert_eq!(plan.verifier_cores.len(), 1);
        assert!(plan.sched_core.is_some());
        assert!(plan.redis_core.is_some());
        assert!(!plan.description.is_empty());
        // When the host has enough physical cores, sched/redis/verifier/worker cores are all
        // distinct (disjoint pinning); on a tiny host the tail may oversubscribe — allowed.
        if phys >= 5 {
            let mut all = vec![plan.sched_core.unwrap(), plan.redis_core.unwrap()];
            all.extend(&plan.verifier_cores);
            all.extend(&plan.worker_cores);
            let unique: std::collections::HashSet<_> = all.iter().collect();
            assert_eq!(unique.len(), all.len(), "expected disjoint cores on a >=5-core host");
        }
    }

    #[test]
    fn unpinned_plan_pins_nothing() {
        let p = Pinning::unpinned();
        assert!(p.sched_core.is_none() && p.worker_cores.is_empty());
    }
}
