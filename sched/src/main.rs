//! proctor `sched` — the epoch-fenced control-plane binary.
//!
//! Wires the engine over a [`Store`]: a Redis store when `PROCTOR_REDIS_URL` is set and
//! reachable, else the in-memory store (single host, locked decision #5).
//!
//! - **Live Redis path (phase6-spec.md §2):** the real push transport. The server spins the
//!   dispatch loop ([`loops::dispatch_tick_live`] / [`Engine::dispatch_one_live`]) — which
//!   `LPUSH`es each encoded `Assignment` onto `{prefix}:inbox:{worker}`, the list the real
//!   `worker` bin `BRPOP`s — the single reclaim authority, and the inbound return channel
//!   ([`loops::inbound_tick_live`]), routing heartbeats / submissions (a sampled draw pushes
//!   its `VerifyRequest` to `{prefix}:inbox:verifier`) / verdicts. The `bench` harness
//!   injects workloads directly into the same Redis (no ingest API, locked decision #2).
//! - **In-memory fallback:** a few bounded ticks confirming the wiring runs without a Redis
//!   (no live transport — `MemoryStore` is not an `OutboundChannel`).
//!
//! Logical time is **wall-clock seconds** so the lease/liveness clock shares one domain with
//! the worker/verifier processes (their registry `last_heartbeat` is wall seconds too). No
//! async runtime, `#![forbid(unsafe_code)]` (locked decision #1).

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proctor_core::{LogicalTime, TaskId, WorkerId};
use sched::backpressure::Sizing;
use sched::engine::{DispatchStep, Engine, EngineConfig};
use sched::loops;
use sched::sample::Sampler;
use sched::store::{MemoryStore, Priority, RedisStore};

fn main() {
    let prefix = env_or("PROCTOR_REDIS_PREFIX", "proctor:sched");
    match std::env::var("PROCTOR_REDIS_URL") {
        Ok(url) => match RedisStore::connect(&url, prefix.clone()) {
            Ok(store) => {
                eprintln!("proctor sched: Redis store at {url} (prefix {prefix})");
                run_live(store);
            }
            Err(e) => {
                eprintln!(
                    "proctor sched: Redis unavailable ({e}); in-memory store (no live transport)"
                );
                run_inmemory(MemoryStore::new());
            }
        },
        Err(_) => {
            eprintln!("proctor sched: in-memory store (set PROCTOR_REDIS_URL to use Redis)");
            run_inmemory(MemoryStore::new());
        }
    }
}

/// The live Redis control-plane server (phase6-spec.md §2): dispatch → reclaim → inbound,
/// forever (or for `PROCTOR_RUN_SECS`, for bounded bench runs). Workers and the verifier are
/// separate processes the `bench` orchestrator spawns; this loop is the placement authority.
fn run_live(store: RedisStore) {
    let n = env_parse("PROCTOR_WORKERS", 0u32);
    let lease_ttl = env_parse("PROCTOR_LEASE_TTL_SECS", 30u64);
    let liveness = env_parse("PROCTOR_LIVENESS_SECS", 60u64);
    let brpop = env_parse("PROCTOR_BRPOP_SECS", 1u64);
    let run_secs = std::env::var("PROCTOR_RUN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let mut events = EventLog::from_env();

    let cfg = EngineConfig {
        lease_ttl,
        liveness_window: liveness,
        sizing: Sizing::from_measured(n.max(1)),
        default_priority: Priority::default(),
    };
    let engine = Engine::new(store, cfg, Sampler::from_entropy());

    // Register the configured worker set so placement has candidates and the in-process tier
    // cache agrees with the Redis registry. The real worker bins also self-register
    // (idempotent REGISTER) and keep liveness fresh by heartbeating during work.
    for w in 1..=u64::from(n) {
        if let Err(e) = engine.register_worker(WorkerId(w), now_logical()) {
            eprintln!("proctor sched: register worker {w} failed: {e}");
        }
    }
    eprintln!(
        "proctor sched: live server — {n} worker slot(s); lease_ttl={lease_ttl}s liveness={liveness}s\
         {}",
        run_secs.map_or(String::new(), |s| format!("; run for {s}s"))
    );

    let start = Instant::now();
    loop {
        let now = now_logical();

        // 1. Drain the ready queue, pushing each Assignment onto its worker's Redis inbox.
        loop {
            match engine.dispatch_one_live(now) {
                Ok(DispatchStep::Dispatched { task, .. }) => events.log("dispatched", task),
                Ok(_) => break, // empty queue or no eligible worker (held) — stop the drain
                Err(e) => {
                    eprintln!("proctor sched: dispatch error: {e}");
                    break;
                }
            }
        }

        // 2. The single reclaim authority — expired leases return to Pending + re-enqueue.
        match loops::reclaim_tick(&engine, now) {
            Ok(reclaimed) => {
                for t in reclaimed {
                    events.log("reclaimed", t);
                }
            }
            Err(e) => eprintln!("proctor sched: reclaim error: {e}"),
        }

        // 3. One inbound return frame (blocking up to `brpop` secs), routed live (a sampled
        //    submission pushes its VerifyRequest back onto the verifier inbox).
        if let Err(e) = loops::inbound_tick_live(&engine, brpop, now) {
            eprintln!("proctor sched: inbound error (continuing): {e}");
        }

        if let Some(limit) = run_secs {
            if start.elapsed() >= Duration::from_secs(limit) {
                break;
            }
        }
    }
    eprintln!(
        "proctor sched: live server exiting (outputs released: {})",
        engine.release_count()
    );
}

/// In-memory fallback: a few bounded dispatch + reclaim ticks confirming the wiring runs
/// without a Redis. No live transport (`MemoryStore` is not an `OutboundChannel`); the bench
/// harness requires a real Redis for the live single-host run.
fn run_inmemory(store: MemoryStore) {
    let engine = Engine::new(store, EngineConfig::for_workers(4), Sampler::from_entropy());
    for t in 0..3u64 {
        let now = LogicalTime(t);
        if let Err(e) = loops::dispatch_tick(&engine, now) {
            eprintln!("proctor sched: dispatch tick failed: {e}");
            return;
        }
        if let Err(e) = loops::reclaim_tick(&engine, now) {
            eprintln!("proctor sched: reclaim tick failed: {e}");
            return;
        }
    }
    eprintln!(
        "proctor sched: engine wired (in-memory). Set PROCTOR_REDIS_URL for the live Redis \
         transport the bench harness drives (Phase 6)."
    );
}

/// Wall-clock seconds since the UNIX epoch as the scheduler's logical time — the same clock
/// domain the worker/verifier registry timestamps use, so lease/liveness math is consistent
/// across processes on the single host.
fn now_logical() -> LogicalTime {
    LogicalTime(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// An optional per-process lifecycle event log (phase6-spec.md §3): one CSV line
/// `event,task_id,ts_ns` per event, where `ts_ns` is wall-clock UNIX nanoseconds (a
/// single-host shared clock; the bench merges these by task id). Disabled — a zero-cost
/// no-op — unless `PROCTOR_EVENT_LOG` names a file.
struct EventLog {
    file: Option<std::fs::File>,
}

impl EventLog {
    fn from_env() -> Self {
        let file = std::env::var("PROCTOR_EVENT_LOG").ok().and_then(|p| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .map_err(|e| eprintln!("proctor sched: event log {p}: {e}"))
                .ok()
        });
        Self { file }
    }

    fn log(&mut self, event: &str, task: TaskId) {
        if let Some(f) = self.file.as_mut() {
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let _ = writeln!(f, "{event},{},{ns}", task.0);
        }
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
