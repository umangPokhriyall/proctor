//! `saturation` — the backpressure overload run and the fault-injection reclaim latency
//! (phase6-spec.md §5). Both drive the **real** epoch-fenced `RedisStore` + `dispatch_one_live`
//! path over a loopback Redis.
//!
//! **Overload (`run_saturation`).** An open-loop injector offers ≈`overload`× aggregate worker
//! capacity. Each offer passes the **real** Little's-law intake gate
//! ([`sched::backpressure::Sizing::admit`]) against the live ready-queue depth (`ZCARD`); over
//! the global cap it is **shed** with the `Backpressure` error. Worker compute is modelled as an
//! aggregate service rate `μ = N / W` (`W` = the Phase-2-measured transcode service time) so the
//! run is fast and `W`-controlled; the backpressure property under test — bounded resident work,
//! intake shed, flat memory — is a function of the queue cap vs offered load, not of whether `W`
//! is real ffmpeg or modelled. The ready-queue, the caps, the shed, and the dispatch are all real.
//!
//! **Reclaim (`measure_reclaim_latency`).** Lease a task, let the holder "die" (no submit, no
//! heartbeat), then time the **mechanism**: `reclaim_expired` (the single authority re-enqueues)
//! → `dispatch_one_live` (re-lease at a strictly greater fencing epoch). The total production
//! reclaim latency is `lease_ttl` (the liveness-timeout detection delay, a config) **plus** this
//! mechanism cost; we measure the mechanism distribution and confirm the fencing epoch advances.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proctor_core::{
    Codec, Commitment, Container, Epoch, JobId, LogicalTime, OutputRef, SegmentId, SegmentRef,
    Task, TargetProfile, TaskId, TaskKind, TranscodeSpec, WorkerId,
};
use sched::backpressure::{Backpressure, Sizing, MEASURED_SERVICE_TIME_S};
use sched::engine::{DispatchStep, Engine, EngineConfig};
use sched::sample::Sampler;
use sched::store::{Priority, RedisStore, Store};

use crate::decomp::MeasureError;
use crate::metrics::{now_ns, Latencies};

fn now_secs() -> LogicalTime {
    LogicalTime(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

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

/// Resident-set size of this process in KiB (from `/proc/self/statm`), or 0 if unavailable.
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1).and_then(|p| p.parse::<u64>().ok()))
        .map_or(0, |pages| pages * 4) // 4 KiB pages
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

// --- overload / backpressure ----------------------------------------------------------

/// How to run the overload.
pub struct SatConfig {
    pub redis_url: String,
    pub n_workers: u32,
    /// Offered load as a multiple of aggregate capacity `N/W` (≈10× per the spec).
    pub overload: f64,
    /// Modelled per-segment service time `W` in seconds (default: the Phase-2-measured 0.099 s).
    pub service_time_s: f64,
    pub duration_s: f64,
    pub sample_interval_ms: u64,
}

impl SatConfig {
    #[must_use]
    pub fn defaults(redis_url: String, n_workers: u32) -> Self {
        SatConfig {
            redis_url,
            n_workers,
            overload: 10.0,
            service_time_s: MEASURED_SERVICE_TIME_S,
            duration_s: 15.0,
            sample_interval_ms: 50,
        }
    }
}

/// One timeseries sample.
pub struct SatSample {
    pub t_ms: u64,
    pub offered: u64,
    pub admitted: u64,
    pub shed: u64,
    pub completed: u64,
    pub ready_depth: u64,
    pub in_flight: u64,
    pub rss_kb: u64,
}

/// The overload result: the timeseries plus the derived steady-state summary.
pub struct SatReport {
    pub n_workers: u32,
    pub service_time_s: f64,
    pub global_queue_cap: u32,
    pub per_worker_cap: u32,
    pub offered: u64,
    pub admitted: u64,
    pub shed: u64,
    pub completed: u64,
    pub duration_s: f64,
    pub offered_rate_hz: f64,
    pub admitted_rate_hz: f64,
    pub capacity_hz: f64,
    pub max_ready_depth: u64,
    pub max_in_flight: u64,
    /// Steady-state mean in-flight over the back half of the run (Little's-law `L`).
    pub mean_in_flight_steady: f64,
    pub rss_min_kb: u64,
    pub rss_max_kb: u64,
    pub samples: Vec<SatSample>,
}

/// Run the ≈`overload`× backpressure overload over a loopback Redis. Single-threaded,
/// time-stepped: completions accrue at the aggregate service rate `μ = N/W`; an open-loop
/// injector at `λ = overload·μ` offers tasks through the real `admit` gate; the real dispatch
/// loop leases ready tasks to free workers up to the per-worker in-flight cap.
pub fn run_saturation(cfg: &SatConfig) -> Result<SatReport, MeasureError> {
    let n = cfg.n_workers.max(1);
    let w = cfg.service_time_s.max(1e-6);
    let mu = f64::from(n) / w; // aggregate capacity (segments/s)
    let lambda = cfg.overload * mu; // offered rate
    let period = 1.0 / lambda;

    let sizing = Sizing::from_measured(n);
    let global_cap = sizing.global_queue_cap();
    let per_worker_cap = sizing.per_worker_in_flight_cap();

    let prefix = format!("proctor:sat:{}:{}", std::process::id(), now_ns());
    let cfg_engine = EngineConfig {
        lease_ttl: 3_600,
        liveness_window: 86_400,
        sizing,
        default_priority: Priority::default(),
    };
    let engine = Engine::new(RedisStore::connect(&cfg.redis_url, &prefix)?, cfg_engine, Sampler::from_entropy());
    for wk in 1..=u64::from(n) {
        engine.register_worker(WorkerId(wk), now_secs())?;
    }
    // A side connection for the live ready-queue depth (ZCARD) the injector gates on.
    let depth_client = redis::Client::open(cfg.redis_url.as_str())?;
    let mut depth_conn = depth_client.get_connection()?;
    let ready_key = format!("{prefix}:ready");

    let (dummy_c, dummy_o) = (Commitment([0u8; 32]), OutputRef(0));
    let mut leased: VecDeque<(TaskId, WorkerId, Epoch)> = VecDeque::new();

    let (mut offered, mut admitted, mut shed, mut completed) = (0u64, 0u64, 0u64, 0u64);
    let mut next_id = 1u64;
    let mut complete_credit = 0.0f64;
    let mut next_intended = 0.0f64;
    let mut samples = Vec::new();
    let mut last_sample = 0u64;

    let start = Instant::now();
    let mut last = start;
    while start.elapsed().as_secs_f64() < cfg.duration_s {
        let now = start.elapsed().as_secs_f64();
        let dt = last.elapsed().as_secs_f64();
        last = Instant::now();

        // 1. Completions accrue at the aggregate service rate μ; free in-flight slots.
        complete_credit += mu * dt;
        while complete_credit >= 1.0 {
            if let Some((task, worker, epoch)) = leased.pop_front() {
                engine.store().submit(task, worker, epoch, dummy_c, dummy_o)?;
                engine.store().select_or_accept(task, false)?;
                completed += 1;
                complete_credit -= 1.0;
            } else {
                complete_credit = complete_credit.min(1.0); // nothing in service; don't bank credit
                break;
            }
        }

        // 2. Open-loop injection caught up to `now`, gated by the real Little's-law admit.
        while next_intended <= now {
            let depth: u64 = redis::cmd("ZCARD").arg(&ready_key).query(&mut depth_conn)?;
            offered += 1;
            match sizing.admit(u32::try_from(depth).unwrap_or(u32::MAX)) {
                Ok(()) => {
                    engine.inject(dummy_task(next_id), Priority::default(), now_secs())?;
                    next_id += 1;
                    admitted += 1;
                }
                Err(Backpressure::QueueFull { .. }) => shed += 1,
            }
            next_intended += period;
        }

        // 3. Dispatch ready tasks to free workers (real lease, respects the in-flight cap).
        while let DispatchStep::Dispatched { task, worker, epoch } =
            engine.dispatch_one_live(now_secs())?
        {
            leased.push_back((task, worker, epoch));
        }

        // 4. Sample the timeseries.
        let t_ms = (now * 1000.0) as u64;
        if t_ms >= last_sample + cfg.sample_interval_ms || samples.is_empty() {
            let depth: u64 = redis::cmd("ZCARD").arg(&ready_key).query(&mut depth_conn)?;
            samples.push(SatSample {
                t_ms,
                offered,
                admitted,
                shed,
                completed,
                ready_depth: depth,
                in_flight: leased.len() as u64,
                rss_kb: rss_kb(),
            });
            last_sample = t_ms;
        }

        std::thread::sleep(Duration::from_millis(1));
    }
    let duration = start.elapsed().as_secs_f64();
    cleanup_prefix(&cfg.redis_url, &prefix)?;

    // Steady-state (back half) means.
    let half = samples.len() / 2;
    let steady = &samples[half..];
    let mean_in_flight = if steady.is_empty() {
        0.0
    } else {
        steady.iter().map(|s| s.in_flight as f64).sum::<f64>() / steady.len() as f64
    };
    let max_ready = samples.iter().map(|s| s.ready_depth).max().unwrap_or(0);
    let max_inflight = samples.iter().map(|s| s.in_flight).max().unwrap_or(0);
    let rss_min = samples.iter().map(|s| s.rss_kb).min().unwrap_or(0);
    let rss_max = samples.iter().map(|s| s.rss_kb).max().unwrap_or(0);

    Ok(SatReport {
        n_workers: n,
        service_time_s: w,
        global_queue_cap: global_cap,
        per_worker_cap,
        offered,
        admitted,
        shed,
        completed,
        duration_s: duration,
        offered_rate_hz: offered as f64 / duration,
        admitted_rate_hz: admitted as f64 / duration,
        capacity_hz: mu,
        max_ready_depth: max_ready,
        max_in_flight: max_inflight,
        mean_in_flight_steady: mean_in_flight,
        rss_min_kb: rss_min,
        rss_max_kb: rss_max,
        samples,
    })
}

// --- reclaim latency (fault injection) ------------------------------------------------

/// Measure the reclaim **mechanism** latency over `trials`: lease a task to a worker that then
/// "dies", and time `reclaim_expired` (re-enqueue) → `dispatch_one_live` (re-lease). Confirms
/// the fencing epoch strictly advances on every reclaim (`e2 > e1`). Returns the distribution
/// and the count of fencing-epoch advances observed (== placed, if fencing holds).
pub fn measure_reclaim_latency(
    url: &str,
    trials: usize,
) -> Result<(Latencies, usize, usize), MeasureError> {
    let prefix = format!("proctor:reclaim:{}:{}", std::process::id(), now_ns());
    // Short lease so the deadline is in the past the instant we reclaim with a future `now`.
    let cfg = EngineConfig {
        lease_ttl: 1,
        liveness_window: 86_400,
        sizing: Sizing::from_measured(2),
        default_priority: Priority::default(),
    };
    let engine = Engine::new(RedisStore::connect(url, &prefix)?, cfg, Sampler::from_entropy());
    engine.register_worker(WorkerId(1), now_secs())?;
    engine.register_worker(WorkerId(2), now_secs())?;

    let mut lat = Latencies::new();
    let mut placed = 0usize;
    let mut epoch_advances = 0usize;
    for i in 0..trials {
        let id = i as u64 + 1;
        engine.inject(dummy_task(id), Priority::default(), now_secs())?;
        let e1 = match engine.dispatch_one_live(now_secs())? {
            DispatchStep::Dispatched { epoch, .. } => epoch,
            _ => continue, // no eligible worker (shouldn't happen) — skip the trial
        };
        // The holder "dies": no submit, no heartbeat. Reclaim with a `now` past the deadline.
        let future = LogicalTime(now_secs().0 + 10);
        let t0 = Instant::now();
        let reclaimed = engine.reclaim(future)?;
        let (worker2, e2) = match engine.dispatch_one_live(now_secs())? {
            DispatchStep::Dispatched { worker, epoch, .. } => (worker, epoch),
            _ => continue,
        };
        let elapsed = t0.elapsed();
        if reclaimed.contains(&TaskId(id)) {
            placed += 1;
            lat.record(elapsed.as_nanos() as u64);
            if e2.0 > e1.0 {
                epoch_advances += 1;
            }
            // Drive the re-leased task terminal so the next trial starts clean.
            engine.store().submit(TaskId(id), worker2, e2, Commitment([0u8; 32]), OutputRef(0))?;
            engine.store().select_or_accept(TaskId(id), false)?;
        }
    }
    cleanup_prefix(url, &prefix)?;
    Ok((lat, placed, epoch_advances))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_is_readable_on_this_host() {
        assert!(rss_kb() > 0, "RSS should be readable from /proc/self/statm");
    }

    #[test]
    fn sat_defaults_are_sane() {
        let c = SatConfig::defaults("redis://127.0.0.1:6390".into(), 4);
        assert!((c.overload - 10.0).abs() < 1e-9);
        assert!(c.service_time_s > 0.0);
    }
}
