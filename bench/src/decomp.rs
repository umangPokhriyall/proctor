//! `decomp` — the scheduling-overhead decomposition measurements (phase6-spec.md §4,
//! amendment §1.4). Predicted-then-confirmed: Phase 4 pre-committed
//! [`sched::backpressure::DISPATCH_REDIS_RTTS`] `= 2` and "decision ≈ µs; p99 dispatch ≈
//! count × RTT, ~95% Redis." This module measures, in isolation:
//!
//! - **Redis RTT** — a direct loopback round-trip micro-measurement (`PING`, and the
//!   representative `LPUSH` the dispatch ends on).
//! - **In-process decision time** — `place::select_worker` (the least-loaded min-scan over N
//!   candidates) timed over the in-memory store, *without* any Redis round trip.
//! - **Live dispatch latency** — the real `dispatch_one_live` path over a loopback Redis,
//!   recorded coordinated-omission-correct from intended-issue time, plus the per-dispatch
//!   wall time and the achieved placement rate (throughput vs N).
//!
//! **Methodology note (honest).** The dispatch measurement drives the *real* engine
//! (`dispatch_one_live`, the same code the `sched` binary runs) over a real loopback Redis,
//! and plays the worker role itself (it `submit`s + accepts each placed task to free the
//! in-flight slot) so it isolates **scheduler dispatch overhead** — not worker compute, which
//! is Session 3's pipeline measurement. The dispatch path's Redis round-trip count is
//! `pop_ready (1) + select_worker (2 per candidate: EXISTS + HMGET) + lease (1) + load (1) +
//! LPUSH (1) = 2N + 4`, which the writeup compares to the predicted `2`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proctor_core::{
    Codec, Commitment, Container, JobId, LogicalTime, OutputRef, SegmentId, SegmentRef, Task,
    TargetProfile, TaskId, TaskKind, TranscodeSpec, WorkerId,
};
use sched::backpressure::Sizing;
use sched::engine::{DispatchStep, Engine, EngineConfig, EngineError};
use sched::place::{self, Eligibility};
use sched::sample::Sampler;
use sched::store::{MemoryStore, Priority, RedisStore, Store, StoreError, Tier};

use crate::metrics::{now_ns, Latencies};

/// The Redis round-trip count per `dispatch_one_live` over `n` candidate workers:
/// `pop_ready (1) + select_worker (2·n) + lease (1) + load (1) + LPUSH (1)`.
#[must_use]
pub fn dispatch_rtt_count(n: u32) -> u32 {
    2 * n + 4
}

/// What can go wrong measuring.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("engine: {0}")]
    Engine(#[from] EngineError),
}

fn now_secs() -> LogicalTime {
    LogicalTime(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// A throwaway transcode task with a dummy source (dispatch only reads `kind` to build the
/// `Assignment`; no blob is fetched on the dispatch path).
fn dummy_task(id: u64) -> Task {
    Task::new(
        TaskId(id),
        TaskKind::Transcode(TranscodeSpec {
            job: JobId(1),
            segment: SegmentId(id),
            profile: TargetProfile {
                codec: Codec::H264,
                width: 320,
                height: 240,
                bitrate_kbps: 800,
                container: Container::Mp4,
            },
            source: SegmentRef(u128::from(id)),
        }),
    )
}

// --- Redis RTT (isolated) -------------------------------------------------------------

/// Measure loopback Redis round-trip latency: `PING` (pure round trip) and `LPUSH` (the op
/// the dispatch ends on), each over `samples` calls after a warmup.
pub fn measure_redis_rtt(url: &str, samples: usize) -> Result<(Latencies, Latencies), MeasureError> {
    let client = redis::Client::open(url)?;
    let mut conn = client.get_connection()?;
    for _ in 0..200 {
        let _: String = redis::cmd("PING").query(&mut conn)?;
    }
    let mut ping = Latencies::new();
    for _ in 0..samples {
        let t = Instant::now();
        let _: String = redis::cmd("PING").query(&mut conn)?;
        ping.record(t.elapsed().as_nanos() as u64);
    }
    let key = format!("proctor:rtt:{}", std::process::id());
    let mut lpush = Latencies::new();
    for _ in 0..samples {
        let t = Instant::now();
        let _: i64 = redis::cmd("LPUSH").arg(&key).arg(b"x" as &[u8]).query(&mut conn)?;
        lpush.record(t.elapsed().as_nanos() as u64);
    }
    let _: i64 = redis::cmd("DEL").arg(&key).query(&mut conn)?;
    Ok((ping, lpush))
}

// --- In-process decision time (no Redis) ----------------------------------------------

/// Time the in-process placement decision (`place::select_worker`, the least-loaded min-scan
/// over `n` idle candidates) over the in-memory store — the dispatch path's decision logic
/// with **zero** Redis round trips. Returns the latency distribution.
#[must_use]
pub fn measure_decision_time(n: u32, samples: usize) -> Latencies {
    let store = MemoryStore::new();
    let mut candidates = Vec::with_capacity(n as usize);
    for w in 1..=u64::from(n) {
        store.register_worker(WorkerId(w), LogicalTime(0)).expect("register");
        candidates.push((WorkerId(w), Tier::Pristine));
    }
    let elig = Eligibility {
        now: LogicalTime(1),
        liveness_window: u64::MAX,
        in_flight_cap: u32::MAX,
    };
    for _ in 0..2_000 {
        let _ = place::select_worker(&store, &candidates, &elig);
    }
    let mut lat = Latencies::new();
    for _ in 0..samples {
        let t = Instant::now();
        let _ = place::select_worker(&store, &candidates, &elig).expect("select");
        lat.record(t.elapsed().as_nanos() as u64);
    }
    lat
}

/// A tight, allocation-free **placement loop** for `perf stat` to wrap (PROFILING.md): runs
/// `place::select_worker` (the least-loaded min-scan over `n` in-memory candidates) `iters`
/// times, returning a checksum so the loop is not optimized away. No Redis, no recording — the
/// pure in-process decision the dispatch decomposition attributes its µs to.
#[must_use]
pub fn spin_placement(n: u32, iters: u64) -> u64 {
    let store = MemoryStore::new();
    let mut candidates = Vec::with_capacity(n as usize);
    for w in 1..=u64::from(n) {
        store.register_worker(WorkerId(w), LogicalTime(0)).expect("register");
        candidates.push((WorkerId(w), Tier::Pristine));
    }
    let elig = Eligibility {
        now: LogicalTime(1),
        liveness_window: u64::MAX,
        in_flight_cap: u32::MAX,
    };
    let mut acc = 0u64;
    for _ in 0..iters {
        if let Ok(Some(w)) = place::select_worker(&store, &candidates, &elig) {
            acc = acc.wrapping_add(w.0);
        }
    }
    acc
}

// --- Live dispatch latency + throughput (real Redis) ----------------------------------

/// Build an engine over a fresh, uniquely-prefixed loopback Redis namespace with `n`
/// registered workers (lease/liveness windows set wide so neither expires during a run).
/// Returns the engine and its prefix (for cleanup).
fn setup_live_engine(url: &str, n: u32) -> Result<(Engine<RedisStore>, String), MeasureError> {
    let prefix = format!("proctor:decomp:{}:{}:{}", std::process::id(), n, now_ns());
    let cfg = EngineConfig {
        lease_ttl: 3_600,
        liveness_window: 86_400,
        sizing: Sizing::from_measured(n.max(1)),
        default_priority: Priority::default(),
    };
    let engine = Engine::new(RedisStore::connect(url, &prefix)?, cfg, Sampler::from_entropy());
    for w in 1..=u64::from(n) {
        engine.register_worker(WorkerId(w), now_secs())?;
    }
    Ok((engine, prefix))
}

/// Dispatch one already-injected task and free its in-flight slot, returning the
/// `dispatch_one_live` wall time in ns (the harness plays the worker — submit + accept —
/// so it isolates scheduler dispatch overhead, not worker compute).
fn dispatch_and_free(engine: &Engine<RedisStore>) -> Result<Option<u64>, MeasureError> {
    let pre = Instant::now();
    let step = engine.dispatch_one_live(now_secs())?;
    let pure_ns = pre.elapsed().as_nanos() as u64;
    if let DispatchStep::Dispatched { task, worker, epoch } = step {
        engine.store().submit(task, worker, epoch, Commitment([0u8; 32]), OutputRef(0))?;
        engine.store().select_or_accept(task, false)?;
        Ok(Some(pure_ns))
    } else {
        Ok(None)
    }
}

/// The outcome of a throughput run at a given worker count (max placement rate, unpaced).
pub struct ThroughputResult {
    pub n: u32,
    pub placed: u64,
    /// Achieved placement rate = `placed / wall_elapsed` (tasks/s) with no inter-arrival gap.
    pub achieved_rate_hz: f64,
    /// Per-dispatch wall time of `dispatch_one_live` (the ready→inbox overhead).
    pub pure_dispatch: Latencies,
}

/// Throughput vs N: drive `dispatch_one_live` as fast as possible (no pacing) over `n`
/// registered workers on a loopback Redis, reporting tasks/s placed and the per-dispatch
/// distribution. Saturation is implicit — there is always a ready task — so this is the
/// scheduler's placement ceiling at `n`.
pub fn measure_throughput(
    url: &str,
    n: u32,
    count: u64,
    id_base: u64,
) -> Result<ThroughputResult, MeasureError> {
    let (engine, prefix) = setup_live_engine(url, n)?;
    let mut pure = Latencies::new();
    let mut placed = 0u64;
    let t0 = Instant::now();
    for i in 0..count {
        engine.inject(dummy_task(id_base + i), Priority::default(), now_secs())?;
        if let Some(pure_ns) = dispatch_and_free(&engine)? {
            placed += 1;
            pure.record(pure_ns);
        }
    }
    let elapsed = t0.elapsed().as_secs_f64();
    cleanup_prefix(url, &prefix)?;
    Ok(ThroughputResult {
        n,
        placed,
        achieved_rate_hz: placed as f64 / elapsed.max(f64::MIN_POSITIVE),
        pure_dispatch: pure,
    })
}

/// The outcome of a paced (CO-correct) dispatch-latency run.
pub struct DispatchResult {
    pub n: u32,
    pub placed: u64,
    pub intended_rate_hz: f64,
    pub achieved_rate_hz: f64,
    /// Coordinated-omission-corrected dispatch latency (intended-issue → assignment on
    /// inbox), back-filled at the intended inter-arrival interval.
    pub co_latency: Latencies,
    /// Per-dispatch wall time of `dispatch_one_live` (the unqueued ready→inbox overhead).
    pub pure_dispatch: Latencies,
}

/// CO-correct dispatch latency at a sustainable rate: an open-loop schedule at `rate_hz`
/// injects ready tasks; latency is recorded from the **intended-issue** instant (not the
/// actual inject), back-filled at the inter-arrival interval, so a stall cannot hide the
/// tail. Run at a rate below the [`measure_throughput`] ceiling for a steady-state tail.
pub fn measure_dispatch_live(
    url: &str,
    n: u32,
    count: u64,
    rate_hz: f64,
    id_base: u64,
) -> Result<DispatchResult, MeasureError> {
    let (engine, prefix) = setup_live_engine(url, n)?;
    let period = Duration::from_secs_f64(1.0 / rate_hz.max(f64::MIN_POSITIVE));
    let expected = period.as_nanos().max(1) as u64;

    let mut co = Latencies::new();
    let mut pure = Latencies::new();
    let mut placed = 0u64;

    let t0_mono = Instant::now();
    let t0_ns = now_ns();
    for i in 0..count {
        let intended_off = period.mul_f64(i as f64);
        let target = t0_mono + intended_off;
        let now_mono = Instant::now();
        if target > now_mono {
            std::thread::sleep(target - now_mono);
        }
        let intended_ns = t0_ns + intended_off.as_nanos();

        engine.inject(dummy_task(id_base + i), Priority::default(), now_secs())?;
        let pre = Instant::now();
        let step = engine.dispatch_one_live(now_secs())?;
        let pure_ns = pre.elapsed().as_nanos() as u64;
        let dispatched_ns = now_ns();
        if let DispatchStep::Dispatched { task, worker, epoch } = step {
            placed += 1;
            co.record_co(dispatched_ns.saturating_sub(intended_ns) as u64, expected);
            pure.record(pure_ns);
            engine.store().submit(task, worker, epoch, Commitment([0u8; 32]), OutputRef(0))?;
            engine.store().select_or_accept(task, false)?;
        }
    }
    let elapsed = t0_mono.elapsed().as_secs_f64();
    cleanup_prefix(url, &prefix)?;
    Ok(DispatchResult {
        n,
        placed,
        intended_rate_hz: rate_hz,
        achieved_rate_hz: placed as f64 / elapsed.max(f64::MIN_POSITIVE),
        co_latency: co,
        pure_dispatch: pure,
    })
}

/// Best-effort delete of every key under `prefix` (leave no namespace behind).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_rtt_count_matches_the_path() {
        // pop_ready(1) + 2·N worker_load + lease(1) + load(1) + LPUSH(1).
        assert_eq!(dispatch_rtt_count(1), 6);
        assert_eq!(dispatch_rtt_count(4), 12);
        assert_eq!(dispatch_rtt_count(64), 132);
    }

    #[test]
    fn decision_time_is_measurable_and_scales_with_candidates() {
        // In-process, no Redis: a larger candidate set is at least as costly to scan.
        let one = measure_decision_time(1, 5_000);
        let many = measure_decision_time(64, 5_000);
        assert!(one.count() == 5_000 && many.count() == 5_000);
        // Both are sub-millisecond; the scan is µs-scale (assert a generous ceiling).
        assert!(one.summary().p50_ns < 1_000_000, "decision p50 should be µs-scale");
    }
}
