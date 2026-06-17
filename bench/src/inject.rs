//! `inject` — the open-loop, coordinated-omission-correct workload injector (phase6-spec.md
//! §3, the signature methodology).
//!
//! There is **no ingest API** (locked decision #2): [`inject_workload`] creates a task and
//! enqueues it ready directly through the [`Store`] — the same Redis the live `sched` process
//! pops from. The injector schedules **intended-issue** timestamps at a fixed target rate λ,
//! *independent of system progress*: it sleeps to the next intended instant and issues there,
//! whether or not the cluster has kept up. Latency is therefore measured from the
//! **intended-issue** time (the `intended` event), not the actual-issue time, so a stall
//! cannot hide the tail (the Rust-Tcp-Server discipline). The injector reports intended λ vs
//! achieved rate; the knee where achieved < intended is the saturation point (measured in
//! Session 3).

use std::time::{Duration, Instant};

use proctor_core::{LogicalTime, Task};
use sched::store::{Priority, Store, StoreError};

use crate::metrics::{event, now_ns, EventLog};

/// Inject one workload item **directly** into the scheduler's queue — no HTTP, no network
/// ingest (locked decision #2). Creates the task `Pending` and enqueues it ready at
/// `priority`; the live `sched` process dispatches it on its next tick.
pub fn inject_workload<S: Store>(
    store: &S,
    task: Task,
    priority: Priority,
    now: LogicalTime,
) -> Result<(), StoreError> {
    let id = task.id;
    store.create_task(task)?;
    store.enqueue_ready(id, priority, now)?;
    Ok(())
}

/// Injector tuning.
pub struct Config {
    /// Target arrival rate λ (segments/second). The intended-issue schedule is `t0 + i/λ`.
    pub rate_hz: f64,
    /// Priority class for injected tasks (the no-API authority chooses it).
    pub priority: Priority,
}

/// The result of an open-loop injection run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Report {
    /// Tasks the schedule intended to issue.
    pub intended: usize,
    /// Tasks actually created + enqueued.
    pub injected: usize,
    /// Tasks rejected by the store (e.g. a duplicate id) — never silently dropped.
    pub failed: usize,
    /// Target λ (segments/second).
    pub intended_rate_hz: f64,
    /// Achieved issue rate = `injected / (last_issue − first_issue)`.
    pub achieved_rate_hz: f64,
}

/// Run the open-loop, CO-correct injector: walk `tasks`, sleeping to each intended-issue
/// instant `t0 + i/λ`, recording the `intended` event at that scheduled time and the
/// `injected` event at the actual issue, then `inject_workload`. `now_logical` supplies the
/// enqueue `LogicalTime` (the scheduler's wall-second clock). The `log` lets the bench merge
/// dispatch latency from the **intended** time (CO-correct).
pub fn run_open_loop<S, F>(
    store: &S,
    tasks: Vec<Task>,
    cfg: &Config,
    log: &EventLog,
    mut now_logical: F,
) -> Report
where
    S: Store,
    F: FnMut() -> LogicalTime,
{
    let intended = tasks.len();
    let rate = if cfg.rate_hz > 0.0 { cfg.rate_hz } else { 1.0 };
    let start_mono = Instant::now();
    let start_wall_ns = now_ns();

    let mut injected = 0usize;
    let mut failed = 0usize;
    let mut first_issue_ns: Option<u128> = None;
    let mut last_issue_ns: u128 = start_wall_ns;

    for (i, task) in tasks.into_iter().enumerate() {
        // The intended-issue instant for item i, fixed by the schedule (not by progress).
        let offset = Duration::from_secs_f64(i as f64 / rate);
        let target = start_mono + offset;
        let now_mono = Instant::now();
        if target > now_mono {
            std::thread::sleep(target - now_mono);
        }
        // CO reference: the *scheduled* wall instant, even if we woke late.
        let intended_ns = start_wall_ns + offset.as_nanos();
        let id = task.id;
        log.record_at(event::INTENDED, id, intended_ns);

        match inject_workload(store, task, cfg.priority, now_logical()) {
            Ok(()) => {
                injected += 1;
                let issue_ns = now_ns();
                log.record_at(event::INJECTED, id, issue_ns);
                first_issue_ns.get_or_insert(issue_ns);
                last_issue_ns = issue_ns;
            }
            Err(e) => {
                failed += 1;
                eprintln!("proctor bench: inject {id:?} failed: {e}");
            }
        }
    }

    let span_ns = last_issue_ns.saturating_sub(first_issue_ns.unwrap_or(last_issue_ns));
    let achieved_rate_hz = if injected > 1 && span_ns > 0 {
        (injected as f64 - 1.0) / (span_ns as f64 / 1e9)
    } else {
        0.0
    };

    Report {
        intended,
        injected,
        failed,
        intended_rate_hz: rate,
        achieved_rate_hz,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proctor_core::{
        Codec, Container, JobId, SegmentId, SegmentRef, TargetProfile, TaskId, TaskKind,
        TranscodeSpec,
    };
    use sched::store::MemoryStore;

    fn task(id: u64) -> Task {
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
                source: SegmentRef(id as u128),
            }),
        )
    }

    #[test]
    fn inject_workload_creates_and_enqueues() {
        let store = MemoryStore::new();
        inject_workload(&store, task(1), Priority::default(), LogicalTime(0)).unwrap();
        // The task exists and is the next ready item.
        assert!(store.load(TaskId(1)).unwrap().is_some());
        assert_eq!(store.pop_ready().unwrap(), Some(TaskId(1)));
    }

    #[test]
    fn open_loop_issues_every_task_co_correct() {
        let store = MemoryStore::new();
        let dir = std::env::temp_dir().join(format!("proctor-inj-{}-{}", std::process::id(), now_ns()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = EventLog::create(dir.join("inject.log")).unwrap();

        let tasks: Vec<Task> = (1..=20).map(task).collect();
        // A high rate keeps the unit test fast; correctness (all issued) is what we assert.
        let report = run_open_loop(
            &store,
            tasks,
            &Config { rate_hz: 5_000.0, priority: Priority::default() },
            &log,
            || LogicalTime(0),
        );
        assert_eq!(report.intended, 20);
        assert_eq!(report.injected, 20);
        assert_eq!(report.failed, 0);
        assert!(report.achieved_rate_hz > 0.0, "an achieved rate is reported");

        // The log carries an `intended` and an `injected` event per task.
        let recs = crate::metrics::read_events(dir.join("inject.log")).unwrap();
        let intended = recs.iter().filter(|r| r.event == event::INTENDED).count();
        let injected = recs.iter().filter(|r| r.event == event::INJECTED).count();
        assert_eq!((intended, injected), (20, 20));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
