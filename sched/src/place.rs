//! `place` — least-loaded **push** placement and the aging anti-starvation policy (§4).
//!
//! The scheduler is the **placement authority**: workers receive, never self-select (the
//! legacy reversal). This module is the *decision* logic, written over the [`Store`]
//! trait and pure helpers — no Redis specifics. The dispatch loop (Session 5) wires it:
//! it reads live worker load through the store, picks the next ready task by the aging
//! policy, picks the least-loaded eligible worker, then atomically leases + pushes.
//!
//! Two selections live here:
//! - **Which worker** — [`least_loaded`] / [`select_worker`]: minimum in-flight lease
//!   count, tie-broken by a higher EWMA of recent completion throughput (a faster worker
//!   is preferred at equal load), among workers that are *eligible* (alive, reputation
//!   not suspended/banned, under the per-worker in-flight cap).
//! - **Which task** — [`select_task`]: highest *effective* priority, where effective
//!   priority rises with a task's age ([`effective_priority`]) so a low-priority task
//!   cannot starve under a sustained stream of higher-priority arrivals — the legacy
//!   strict-priority bug, fixed with arithmetic.
//!
//! The store's `pop_ready` gives strict priority-then-FIFO ordering; the aging-aware
//! [`select_task`] is the policy the dispatch loop applies over the ready candidates so
//! starvation is bounded. These functions are clock-free: the scheduler injects `now` as
//! [`LogicalTime`], exactly as `core` does.

use std::cmp::Reverse;

use proctor_core::{LogicalTime, TaskId, WorkerId};

use crate::store::{Priority, Store, StoreError, Tier};

/// EWMA smoothing factor for per-worker throughput (§4: "EWMA is pure math; document the
/// smoothing factor"). At `α = 0.3` the estimate weights roughly the last ~3 heartbeats:
/// reactive enough to follow a worker speeding up or slowing down, smooth enough that one
/// slow heartbeat does not bounce placement. The dispatch loop folds each heartbeat's
/// observed throughput in via [`ewma`]; placement only *reads* the stored estimate.
pub const EWMA_ALPHA: f64 = 0.3;

/// Logical-time units a ready task must wait to gain one unit of effective priority. This
/// is the anti-starvation knob: smaller promotes starved low-priority work faster. It is
/// a tuning parameter (the dispatch loop passes it to [`select_task`]); this default sits
/// well above a typical lease deadline so aging only bites genuinely stalled work.
pub const AGING_INTERVAL: u64 = 1_000;

/// One step of an exponentially-weighted moving average: `α·sample + (1−α)·prev`. Pure;
/// the dispatch loop uses it to update a worker's throughput estimate from heartbeats.
#[must_use]
pub fn ewma(prev: f64, sample: f64, alpha: f64) -> f64 {
    alpha * sample + (1.0 - alpha) * prev
}

/// A snapshot of a worker used for placement. Assembled by the caller from the store's
/// `worker_load` plus the worker's reputation `tier` (the store exposes tier via
/// `update_standing`; the engine threads it in — Session 4/5). Kept as a plain value so
/// the selection logic is pure and trivially testable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkerView {
    pub id: WorkerId,
    /// Primary load metric: in-flight (held) lease count.
    pub in_flight: u32,
    /// Tiebreak: EWMA of recent completion throughput (higher = preferred at equal load).
    pub ewma_throughput: f64,
    /// Liveness: logical time of the worker's last heartbeat/registration.
    pub last_heartbeat: LogicalTime,
    /// Reputation tier; `Suspended`/`Banned` are ineligible (§5 gate).
    pub tier: Tier,
}

/// The eligibility envelope for placement at a given instant.
#[derive(Debug, Clone, Copy)]
pub struct Eligibility {
    /// Injected current logical time.
    pub now: LogicalTime,
    /// A worker is alive if `now − last_heartbeat ≤ liveness_window`.
    pub liveness_window: u64,
    /// Per-worker in-flight cap (from [`crate::backpressure`]); a worker at or above it is
    /// ineligible.
    pub in_flight_cap: u32,
}

/// Whether `w` may receive a dispatch: alive, reputation-eligible, and under its in-flight
/// cap (§4 eligibility = liveness ∧ reputation gate ∧ backpressure).
#[must_use]
pub fn is_eligible(w: &WorkerView, e: &Eligibility) -> bool {
    w.tier.is_eligible()
        && w.in_flight < e.in_flight_cap
        && e.now.0.saturating_sub(w.last_heartbeat.0) <= e.liveness_window
}

/// The least-loaded eligible worker: minimum `in_flight`, tie-broken by **higher**
/// `ewma_throughput`, then by smallest id for determinism. `None` if none are eligible
/// (the dispatch loop then holds the task ready — backpressure governs intake, §6).
#[must_use]
pub fn least_loaded(workers: &[WorkerView], e: &Eligibility) -> Option<WorkerId> {
    workers
        .iter()
        .filter(|w| is_eligible(w, e))
        .min_by(|a, b| {
            a.in_flight
                .cmp(&b.in_flight)
                // Higher throughput is better, so it must compare as "less" for `min_by`.
                .then_with(|| {
                    b.ewma_throughput
                        .partial_cmp(&a.ewma_throughput)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.id.0.cmp(&b.id.0))
        })
        .map(|w| w.id)
}

/// Least-loaded selection over the [`Store`]: reads live load (`worker_load`) for each
/// candidate and applies [`least_loaded`]. Tier is supplied per candidate by the caller
/// because the store surfaces tier only through `update_standing` (a dedicated reputation
/// read lands with the engine, Session 5); in-flight, throughput, and liveness are read
/// live here.
pub fn select_worker<S: Store>(
    store: &S,
    candidates: &[(WorkerId, Tier)],
    e: &Eligibility,
) -> Result<Option<WorkerId>, StoreError> {
    let mut views = Vec::with_capacity(candidates.len());
    for &(id, tier) in candidates {
        let load = store.worker_load(id)?;
        views.push(WorkerView {
            id,
            in_flight: load.in_flight,
            ewma_throughput: load.ewma_throughput,
            last_heartbeat: load.last_heartbeat,
            tier,
        });
    }
    Ok(least_loaded(&views, e))
}

/// A ready task as the placement layer sees it: its id, base priority class, and when it
/// was enqueued (for aging).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadyTask {
    pub id: TaskId,
    pub priority: Priority,
    pub enqueued: LogicalTime,
}

/// A task's **effective** priority: base class plus one unit per `interval` of waiting.
/// This is the anti-starvation rule — a task that has waited long enough outranks a
/// stream of freshly-arrived higher-priority tasks. Saturating, clock-free.
#[must_use]
pub fn effective_priority(
    base: Priority,
    enqueued: LogicalTime,
    now: LogicalTime,
    interval: u64,
) -> u64 {
    let waited = now.0.saturating_sub(enqueued.0);
    let bonus = waited.checked_div(interval).unwrap_or(0);
    u64::from(base.0).saturating_add(bonus)
}

/// Choose the next task to dispatch from `candidates` under **priority + aging**: highest
/// effective priority, then earliest enqueued (FIFO within a class), then smallest id.
/// `None` for an empty candidate set. This is what bounds starvation: a low-priority
/// task's effective priority climbs with age until it overtakes newer high-priority work.
#[must_use]
pub fn select_task(candidates: &[ReadyTask], now: LogicalTime, interval: u64) -> Option<TaskId> {
    candidates
        .iter()
        .max_by_key(|t| {
            (
                effective_priority(t.priority, t.enqueued, now, interval),
                // Earliest enqueued and smallest id win ties → reverse them for `max`.
                Reverse(t.enqueued.0),
                Reverse(t.id.0),
            )
        })
        .map(|t| t.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, Store};
    use proctor_core::{
        Codec, Container, JobId, SegmentId, SegmentRef, Task, TargetProfile, TaskKind,
        TranscodeSpec,
    };

    fn view(id: u64, in_flight: u32, ewma: f64, last: u64, tier: Tier) -> WorkerView {
        WorkerView {
            id: WorkerId(id),
            in_flight,
            ewma_throughput: ewma,
            last_heartbeat: LogicalTime(last),
            tier,
        }
    }

    fn elig(now: u64, window: u64, cap: u32) -> Eligibility {
        Eligibility {
            now: LogicalTime(now),
            liveness_window: window,
            in_flight_cap: cap,
        }
    }

    fn ready(id: u64, prio: u32, enq: u64) -> ReadyTask {
        ReadyTask {
            id: TaskId(id),
            priority: Priority(prio),
            enqueued: LogicalTime(enq),
        }
    }

    fn task(id: u64) -> Task {
        Task::new(
            TaskId(id),
            TaskKind::Transcode(TranscodeSpec {
                job: JobId(1),
                segment: SegmentId(id),
                profile: TargetProfile {
                    codec: Codec::H264,
                    width: 1280,
                    height: 720,
                    bitrate_kbps: 3000,
                    container: Container::Mp4,
                },
                source: SegmentRef(id as u128),
            }),
        )
    }

    // --- EWMA math ----------------------------------------------------------

    #[test]
    fn ewma_blends_prev_and_sample() {
        // 0.3·20 + 0.7·10 = 13.
        assert!((ewma(10.0, 20.0, EWMA_ALPHA) - 13.0).abs() < 1e-9);
        // α = 1 ignores history; α = 0 ignores the sample.
        assert!((ewma(10.0, 20.0, 1.0) - 20.0).abs() < 1e-9);
        assert!((ewma(10.0, 20.0, 0.0) - 10.0).abs() < 1e-9);
    }

    // --- least-loaded worker selection --------------------------------------

    #[test]
    fn least_loaded_picks_minimum_in_flight() {
        let ws = [
            view(1, 3, 100.0, 0, Tier::Pristine),
            view(2, 1, 1.0, 0, Tier::Pristine),
            view(3, 2, 100.0, 0, Tier::Pristine),
        ];
        // Worker 2 has the fewest in-flight, despite the lowest throughput.
        assert_eq!(least_loaded(&ws, &elig(0, 1000, 8)), Some(WorkerId(2)));
    }

    #[test]
    fn equal_in_flight_breaks_to_higher_throughput() {
        let ws = [
            view(1, 1, 5.0, 0, Tier::Pristine),
            view(2, 1, 9.0, 0, Tier::Pristine),
            view(3, 1, 7.0, 0, Tier::Pristine),
        ];
        // All tied at in_flight = 1; the fastest (worker 2) wins.
        assert_eq!(least_loaded(&ws, &elig(0, 1000, 8)), Some(WorkerId(2)));
    }

    #[test]
    fn eligibility_excludes_suspended_dead_and_capped() {
        let now = 1_000;
        let ws = [
            // Suspended: reputation gate excludes it even though it is idle.
            view(1, 0, 50.0, now, Tier::Suspended),
            // Banned: likewise ineligible.
            view(2, 0, 50.0, now, Tier::Banned),
            // Dead: last heartbeat is older than the liveness window.
            view(3, 0, 50.0, now - 500, Tier::Pristine),
            // At the in-flight cap: ineligible (backpressure).
            view(4, 2, 50.0, now, Tier::Pristine),
            // Eligible: alive, eligible tier, under cap.
            view(5, 1, 1.0, now, Tier::Watch),
        ];
        let e = elig(now, 100, 2);
        assert_eq!(least_loaded(&ws, &e), Some(WorkerId(5)));
        assert!(!is_eligible(&ws[0], &e));
        assert!(!is_eligible(&ws[2], &e), "stale heartbeat is dead");
        assert!(!is_eligible(&ws[3], &e), "at cap is ineligible");
        assert!(is_eligible(&ws[4], &e));
    }

    #[test]
    fn no_eligible_worker_yields_none() {
        let ws = [view(1, 0, 1.0, 0, Tier::Banned)];
        assert_eq!(least_loaded(&ws, &elig(0, 1000, 8)), None);
    }

    // --- aging / anti-starvation --------------------------------------------

    #[test]
    fn effective_priority_rises_with_age() {
        let interval = 10;
        // Fresh task: just its base class.
        assert_eq!(effective_priority(Priority(0), LogicalTime(100), LogicalTime(100), interval), 0);
        // Waited 100 with interval 10 → +10.
        assert_eq!(effective_priority(Priority(0), LogicalTime(0), LogicalTime(100), interval), 10);
        // Base adds on top.
        assert_eq!(effective_priority(Priority(5), LogicalTime(0), LogicalTime(30), interval), 8);
    }

    #[test]
    fn low_priority_task_is_not_starved_by_sustained_high_priority() {
        let interval = 10;
        let low = ready(1, 0, 0); // low priority, enqueued at t = 0
        // A fresh high-priority arrival at each instant (age 0 ⇒ effective priority = 5).
        let high_at = |t: u64| ready(2, 5, t);

        // Early on, the high-priority task is dispatched first.
        let now = 40; // low effective = 0 + 40/10 = 4 < 5
        assert_eq!(select_task(&[low, high_at(now)], LogicalTime(now), interval), Some(TaskId(2)));

        // Once the low task has aged past the priority gap it wins — even though the
        // competing high-priority task is brand new. Starvation is bounded by ~5·interval.
        let now = 60; // low effective = 6 > 5
        assert_eq!(select_task(&[low, high_at(now)], LogicalTime(now), interval), Some(TaskId(1)));
        // And it stays selected as time advances under continued high-priority load.
        let now = 500;
        assert_eq!(select_task(&[low, high_at(now)], LogicalTime(now), interval), Some(TaskId(1)));
    }

    #[test]
    fn equal_effective_priority_is_fifo_then_id() {
        // Aging off (huge interval): two same-class tasks resolve by earliest enqueue.
        let a = ready(7, 0, 5);
        let b = ready(3, 0, 10);
        assert_eq!(select_task(&[a, b], LogicalTime(100), u64::MAX), Some(TaskId(7)));
        // Same enqueue time → smallest id wins.
        let a = ready(7, 0, 5);
        let b = ready(3, 0, 5);
        assert_eq!(select_task(&[a, b], LogicalTime(100), u64::MAX), Some(TaskId(3)));
    }

    #[test]
    fn select_task_empty_is_none() {
        assert_eq!(select_task(&[], LogicalTime(0), AGING_INTERVAL), None);
    }

    // --- placement over the real Store --------------------------------------

    #[test]
    fn select_worker_over_store_picks_least_loaded() {
        let store = MemoryStore::new();
        // Three workers registered "now"; load them by leasing tasks (worker_load derives
        // in-flight from held leases).
        for w in 1..=3 {
            store.register_worker(WorkerId(w), LogicalTime(0)).unwrap();
        }
        // Worker 1 holds 2 leases, worker 2 holds 1, worker 3 holds none.
        let mut next = 1u64;
        let mut lease_n = |store: &MemoryStore, w: u64, n: u64| {
            for _ in 0..n {
                store.create_task(task(next)).unwrap();
                store.lease(TaskId(next), WorkerId(w), LogicalTime(100)).unwrap();
                next += 1;
            }
        };
        lease_n(&store, 1, 2);
        lease_n(&store, 2, 1);

        let candidates = [
            (WorkerId(1), Tier::Pristine),
            (WorkerId(2), Tier::Pristine),
            (WorkerId(3), Tier::Pristine),
        ];
        let picked = select_worker(&store, &candidates, &elig(0, 1000, 8)).unwrap();
        assert_eq!(picked, Some(WorkerId(3)), "idle worker 3 is least-loaded");
    }
}
