//! `backpressure` — Little's-law sizing and shed-at-saturation (§6, amendment §1.4).
//!
//! Bound growth with arithmetic, not vibes. The caps come from **Little's law**
//! `L = λ × W`, where `W` is the mean service time (the Phase-2-measured ffmpeg transcode
//! wall time) and `λ` is the target arrival rate. From `L` we derive a per-worker
//! in-flight cap (consumed by [`crate::place`] eligibility) and a global ready-queue cap;
//! at the global cap, intake **sheds** — [`Sizing::admit`] returns [`Backpressure`] rather
//! than letting the queue grow unbounded, so memory stays flat under sustained overload (a
//! Phase 6 assertion). There is no ingest API (locked decision #2): the bench injector
//! calls `admit` before `enqueue_ready` and handles the shed.
//!
//! ## The numbers (measured, single host)
//! - **`W` (service time):** mean ffmpeg `transcode_no_disk` wall time
//!   ≈ **0.099 s** (range 0.059–0.179 s over 12 (profile, segment) points,
//!   `bench/results/crypto/crypto_pct_transcode.csv`). Segments are GOP-bounded ≈2 s.
//! - **`λ` (arrival rate):** a design input. [`Sizing::from_measured`] sizes for the
//!   saturation knee, `λ = N / W` (aggregate capacity), giving `L = λW = N` — exactly one
//!   in-flight segment per worker, which is right for CPU-bound, one-at-a-time workers.
//! - **Per-worker in-flight cap:** `⌈L/N⌉ (≥1) + pipeline_headroom`. The headroom
//!   (default one) lets a worker hold its next segment while finishing the current one, so
//!   it is not idle across the dispatch round trip. At `from_measured` this is `1 + 1 = 2`.
//! - **Global ready-queue cap:** `queue_factor × ⌈L⌉` (default factor 4). Beyond this,
//!   intake sheds. Total resident work is then `O(N)` — `≤ per_worker_cap·N` in flight plus
//!   `≤ global_queue_cap` queued — independent of offered load.
//!
//! ## Pre-committed Phase 6 dispatch-latency decomposition (amendment §1.4)
//! Predicted before measuring, so Phase 6 confirms rather than discovers. One dispatch is
//! **[`DISPATCH_REDIS_RTTS`] Redis round trips** — the lease Lua (one `EVALSHA`: the
//! epoch-fenced `HSET`+`ZADD`+`in_flight` `HINCRBY` in a single atomic script) and the
//! inbox `LPUSH` of the encoded `Assignment` — plus an in-process decision (a min-scan
//! over candidate workers, ~µs). Prediction: **in-process decision ≈ X µs; p99 dispatch
//! ≈ DISPATCH_REDIS_RTTS × RTT and is ~95% Redis RTTs** — which preempts the dismissal
//! "your scheduler is just Redis latency." Session 6 records this in `ARCHITECTURE.md`.

use thiserror::Error;

/// Mean ffmpeg transcode wall time `W` (seconds), measured single-host in Phase 2
/// (`bench/results/crypto/crypto_pct_transcode.csv`: mean of 12 (profile, segment)
/// points; range 0.059–0.179 s). The service time for Little's law.
pub const MEASURED_SERVICE_TIME_S: f64 = 0.099;

/// Default per-worker pipeline headroom: extra in-flight slots beyond the Little's-law
/// share so a worker is not idle between segments while the next is dispatched.
pub const DEFAULT_PIPELINE_HEADROOM: u32 = 1;

/// Default global-queue multiplier: the ready queue may hold `queue_factor × ⌈L⌉` tasks
/// before intake sheds.
pub const DEFAULT_QUEUE_FACTOR: u32 = 4;

/// Redis round trips per dispatch: lease Lua (1) + inbox `LPUSH` (1). The in-flight
/// accounting is folded into the lease script, so it adds no extra trip. Used by the
/// pre-committed dispatch-latency decomposition above (amendment §1.4).
pub const DISPATCH_REDIS_RTTS: u32 = 2;

/// Little's-law-derived capacity sizing for the scheduler. All caps are pure functions of
/// the documented inputs (`workers`, `service_time_s`, `arrival_rate_hz`) — auditably so.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sizing {
    /// `N` — number of pinned workers (locked decision #5: single host, N workers).
    pub workers: u32,
    /// `W` — mean service time in seconds.
    pub service_time_s: f64,
    /// `λ` — target arrival rate in segments/second.
    pub arrival_rate_hz: f64,
    /// Extra per-worker in-flight slots beyond the Little's-law share (anti-idle headroom).
    pub pipeline_headroom: u32,
    /// Global ready-queue cap multiplier on `⌈L⌉`.
    pub queue_factor: u32,
}

impl Sizing {
    /// Size from explicit Little's-law inputs.
    #[must_use]
    pub fn new(workers: u32, service_time_s: f64, arrival_rate_hz: f64) -> Self {
        Sizing {
            workers,
            service_time_s,
            arrival_rate_hz,
            pipeline_headroom: DEFAULT_PIPELINE_HEADROOM,
            queue_factor: DEFAULT_QUEUE_FACTOR,
        }
    }

    /// Size from a worker count using the Phase-2-measured service time and a target
    /// arrival rate equal to aggregate capacity (`λ = N / W`) — i.e. sized for running at
    /// the saturation knee (`ρ = λW/N = 1`), the worst case backpressure must hold under.
    #[must_use]
    pub fn from_measured(workers: u32) -> Self {
        let w = MEASURED_SERVICE_TIME_S;
        let lambda = f64::from(workers.max(1)) / w;
        Sizing::new(workers, w, lambda)
    }

    /// `L = λ × W` (Little's law): the target number of segments in service.
    #[must_use]
    pub fn target_in_flight(&self) -> f64 {
        self.arrival_rate_hz * self.service_time_s
    }

    /// Per-worker in-flight cap: the Little's-law share `⌈L/N⌉` (at least 1) plus pipeline
    /// headroom. [`crate::place`] treats a worker at or above this as ineligible.
    #[must_use]
    pub fn per_worker_in_flight_cap(&self) -> u32 {
        let n = f64::from(self.workers.max(1));
        let share = positive_ceil_u32(self.target_in_flight() / n);
        share.saturating_add(self.pipeline_headroom)
    }

    /// Global ready-queue cap: `queue_factor × ⌈L⌉`. Beyond this, intake sheds.
    #[must_use]
    pub fn global_queue_cap(&self) -> u32 {
        positive_ceil_u32(self.target_in_flight()).saturating_mul(self.queue_factor)
    }

    /// The intake gate: admit one new ready task at the observed `ready_depth`, or **shed**
    /// with [`Backpressure`] when the queue is at/over its cap. The caller (bench injector)
    /// calls this *before* `Store::enqueue_ready` and handles the shed; the queue therefore
    /// never grows past [`Self::global_queue_cap`].
    pub fn admit(&self, ready_depth: u32) -> Result<(), Backpressure> {
        let cap = self.global_queue_cap();
        if ready_depth >= cap {
            Err(Backpressure::QueueFull {
                depth: ready_depth,
                cap,
            })
        } else {
            Ok(())
        }
    }
}

/// `⌈x⌉` as a `u32`, clamped to at least 1 (a degenerate or non-finite `L` still yields a
/// usable cap; a cap of 0 would wedge the scheduler).
fn positive_ceil_u32(x: f64) -> u32 {
    let c = x.ceil();
    if c.is_finite() && c >= 1.0 {
        // Clamp above u32 range defensively; real sizings are tiny.
        if c >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            c as u32
        }
    } else {
        1
    }
}

/// Saturation signal: the ready queue is at capacity, so this intake is shed rather than
/// enqueued. The injector must handle it (retry/drop) — it is not a store failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Backpressure {
    #[error("ready queue saturated: depth {depth} >= cap {cap}; shedding intake")]
    QueueFull { depth: u32, cap: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn littles_law_holds_for_explicit_inputs() {
        // λ = 20/s, W = 0.1 s ⇒ L = 2.0.
        let s = Sizing::new(4, 0.1, 20.0);
        assert!((s.target_in_flight() - 2.0).abs() < 1e-9);
        // Per-worker: ⌈2/4⌉ = 1, + headroom 1 = 2.
        assert_eq!(s.per_worker_in_flight_cap(), 2);
        // Global: ⌈2⌉ × 4 = 8.
        assert_eq!(s.global_queue_cap(), 8);
    }

    #[test]
    fn from_measured_sizes_one_in_flight_per_worker() {
        for n in [1u32, 4, 16, 64] {
            let s = Sizing::from_measured(n);
            // λ = N/W and W cancel: L = N.
            assert!((s.target_in_flight() - f64::from(n)).abs() < 1e-6, "L = N for n={n}");
            // One Little's-law slot per worker + 1 headroom.
            assert_eq!(s.per_worker_in_flight_cap(), 2, "per-worker cap for n={n}");
            // Global queue = 4·⌈L⌉ = 4N.
            assert_eq!(s.global_queue_cap(), 4 * n, "global cap for n={n}");
        }
    }

    #[test]
    fn cap_holds_and_intake_sheds_at_saturation() {
        let s = Sizing::from_measured(2); // global cap = 8
        let cap = s.global_queue_cap();
        assert_eq!(cap, 8);

        // Below the cap: every intake is admitted.
        for depth in 0..cap {
            assert_eq!(s.admit(depth), Ok(()), "depth {depth} below cap is admitted");
        }
        // At and above the cap: shed, with the diagnostic depth/cap.
        assert_eq!(s.admit(cap), Err(Backpressure::QueueFull { depth: 8, cap: 8 }));
        assert_eq!(s.admit(cap + 5), Err(Backpressure::QueueFull { depth: 13, cap: 8 }));
    }

    #[test]
    fn sustained_overload_keeps_resident_work_bounded() {
        // Model: offered load far exceeds capacity; the queue is pinned at the cap because
        // every over-cap intake sheds. Resident work stays O(N), not unbounded.
        let s = Sizing::from_measured(8);
        let cap = s.global_queue_cap();
        let mut queue_depth = 0u32;
        let mut shed = 0u32;
        // Offer 10× the cap worth of intake.
        for _ in 0..(cap * 10) {
            match s.admit(queue_depth) {
                Ok(()) => queue_depth += 1, // enqueued
                Err(Backpressure::QueueFull { .. }) => shed += 1,
            }
        }
        assert_eq!(queue_depth, cap, "queue never grows past the cap");
        assert_eq!(shed, cap * 10 - cap, "the rest is shed, not buffered");
    }

    #[test]
    fn degenerate_inputs_still_yield_usable_caps() {
        // Zero arrival rate ⇒ L = 0; caps clamp to a usable minimum rather than 0.
        let s = Sizing::new(0, 0.0, 0.0);
        assert!(s.per_worker_in_flight_cap() >= 1);
        assert!(s.global_queue_cap() >= 1);
    }
}
