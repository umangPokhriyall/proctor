//! `contract` — the shared differential suite run against **every** [`Store`] impl.
//!
//! One suite, two implementations: the in-memory reference (this session) and the Redis
//! store (Session 2) both run it via [`store_contract_suite!`], and they must agree. The
//! headline is the slow-zombie store-level proof (§3.3) and its heartbeat variant — the
//! durable-layer complement to `core`'s in-memory `StaleEpoch` property test. Every
//! scenario is generic over `S: Store` and constructs whatever it needs through the
//! trait, so the same bytes of test logic exercise both backends.

use proctor_core::{
    Codec, Commitment, Container, Epoch, JobId, LogicalTime, OutputRef, ReputationDelta, SegmentId,
    SegmentRef, Task, TaskId, TaskKind, TaskState, TargetProfile, TranscodeSpec, WorkerId,
};

use super::{Priority, Store, StoreError, Tier};

const WA: WorkerId = WorkerId(1);
const WB: WorkerId = WorkerId(2);
const C: Commitment = Commitment([7u8; 32]);
const O_A: OutputRef = OutputRef(0xA);
const O_B: OutputRef = OutputRef(0xB);

/// A fresh `Pending` transcode task with the given id.
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

/// Seed a Pending task and register both workers, returning the task id.
fn seed<S: Store>(s: &S, id: u64) -> TaskId {
    s.create_task(task(id)).expect("create_task");
    s.register_worker(WA, LogicalTime(0)).expect("register WA");
    s.register_worker(WB, LogicalTime(0)).expect("register WB");
    TaskId(id)
}

// --- lifecycle -------------------------------------------------------------

/// The happy path: lease → submit → unsampled accept yields exactly the submitted output.
pub(crate) fn happy_path_lease_submit_accept<S: Store>(s: &S) {
    let t = seed(s, 1);
    let e = s.lease(t, WA, LogicalTime(100)).expect("lease");
    assert_eq!(e, Epoch(1), "first lease mints epoch 1");
    s.submit(t, WA, e, C, O_A).expect("submit");
    s.select_or_accept(t, false).expect("unsampled accept");
    match s.load(t).unwrap().expect("task present").state {
        TaskState::Accepted { output, commitment } => {
            assert_eq!(output, O_A);
            assert_eq!(commitment, C);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
}

/// The sampled path drives Submitted -> Verifying -> Accepted on a passing verdict.
pub(crate) fn sampled_path_verifies_then_accepts<S: Store>(s: &S) {
    let t = seed(s, 1);
    let e = s.lease(t, WA, LogicalTime(100)).expect("lease");
    s.submit(t, WA, e, C, O_A).expect("submit");
    s.select_or_accept(t, true).expect("sampled -> verifying");
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Verifying { .. }
    ));
    s.verify_outcome(t, true).expect("verdict pass");
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Accepted { .. }
    ));
}

/// Leasing a task that is not `Pending` is an illegal transition, not a silent overwrite.
pub(crate) fn double_lease_is_illegal<S: Store>(s: &S) {
    let t = seed(s, 1);
    s.lease(t, WA, LogicalTime(100)).expect("first lease");
    let again = s.lease(t, WB, LogicalTime(200));
    assert!(
        matches!(again, Err(StoreError::IllegalTransition { .. })),
        "second lease on a Leased task must be illegal, got {again:?}"
    );
}

/// A submit with a stale epoch, or from the wrong holder, is rejected without mutation.
pub(crate) fn submit_fencing_rejects_stale_and_wrong_holder<S: Store>(s: &S) {
    let t = seed(s, 1);
    let e = s.lease(t, WA, LogicalTime(100)).expect("lease");

    // Wrong epoch (stale) takes precedence over identity.
    let stale = s.submit(t, WA, Epoch(99), C, O_A);
    assert_eq!(
        stale,
        Err(StoreError::StaleEpoch {
            event_epoch: Epoch(99),
            current: e,
        })
    );
    // Right epoch, wrong holder.
    let wrong = s.submit(t, WB, e, C, O_A);
    assert_eq!(
        wrong,
        Err(StoreError::WrongHolder {
            event_worker: WB,
            current: WA,
        })
    );
    // Neither rejection mutated the task: it is still Leased and the real holder submits.
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Leased { .. }
    ));
    s.submit(t, WA, e, C, O_A).expect("the true holder still submits");
}

/// A heartbeat extends the lease only for the matching `(holder, epoch)`.
pub(crate) fn heartbeat_fencing<S: Store>(s: &S) {
    let t = seed(s, 1);
    let e = s.lease(t, WA, LogicalTime(100)).expect("lease");
    s.extend_lease(t, WA, e, LogicalTime(200))
        .expect("matching heartbeat extends");
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Leased { deadline: LogicalTime(200), .. }
    ));
    assert_eq!(
        s.extend_lease(t, WA, Epoch(99), LogicalTime(300)),
        Err(StoreError::StaleEpoch {
            event_epoch: Epoch(99),
            current: e,
        })
    );
    assert_eq!(
        s.extend_lease(t, WB, e, LogicalTime(300)),
        Err(StoreError::WrongHolder {
            event_worker: WB,
            current: WA,
        })
    );
}

// --- reclaim ---------------------------------------------------------------

/// `reclaim_expired` returns an expired lease to `Pending` and re-enqueues it; an
/// unexpired lease is left alone.
pub(crate) fn reclaim_expires_and_reenqueues<S: Store>(s: &S) {
    let t = seed(s, 1);
    s.lease(t, WA, LogicalTime(100)).expect("lease");

    // Not yet expired: nothing reclaimed.
    assert_eq!(s.reclaim_expired(LogicalTime(99)).unwrap(), vec![]);
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Leased { .. }
    ));

    // Deadline reached (inclusive, per Lease::is_expired): reclaimed and re-enqueued.
    assert_eq!(s.reclaim_expired(LogicalTime(100)).unwrap(), vec![t]);
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Pending
    ));
    assert_eq!(s.pop_ready().unwrap(), Some(t), "reclaim re-enqueues");
}

/// A submitted task is never reclaimed — its work product already exists.
pub(crate) fn reclaim_skips_submitted<S: Store>(s: &S) {
    let t = seed(s, 1);
    let e = s.lease(t, WA, LogicalTime(100)).expect("lease");
    s.submit(t, WA, e, C, O_A).expect("submit");
    assert_eq!(
        s.reclaim_expired(LogicalTime(1000)).unwrap(),
        vec![],
        "a Submitted task is not reclaimed even long past its old deadline"
    );
    assert!(matches!(
        s.load(t).unwrap().unwrap().state,
        TaskState::Submitted { .. }
    ));
}

// --- the headline: the slow-zombie store-level proof (§3.3) ----------------

/// THE §1.1 HEADLINE (§3.3): a slow-but-alive worker that loses its lease to a reclaim
/// cannot commit its late work. The stale-epoch write is rejected at the durable layer,
/// the legitimate re-execution wins, and **exactly one** output exists.
pub(crate) fn slow_zombie_submit_rejected<S: Store>(s: &S) {
    let t = seed(s, 1);

    // 1. Worker A leases T → epoch e1, deadline d1.
    let e1 = s.lease(t, WA, LogicalTime(100)).expect("A leases @ e1");
    assert_eq!(e1, Epoch(1));

    // 2. Advance past d1; reclaim → Pending; re-lease to B → e2 > e1.
    assert_eq!(s.reclaim_expired(LogicalTime(100)).unwrap(), vec![t]);
    assert_eq!(s.pop_ready().unwrap(), Some(t));
    let e2 = s.lease(t, WB, LogicalTime(200)).expect("B re-leases @ e2");
    assert!(e2 > e1, "the re-lease epoch strictly exceeds the zombie's");
    assert_eq!(e2, Epoch(2));

    // 3. Zombie Worker A submits @ e1 → StaleEpoch, no mutation.
    let zombie = s.submit(t, WA, e1, C, O_A);
    assert_eq!(
        zombie,
        Err(StoreError::StaleEpoch {
            event_epoch: e1,
            current: e2,
        }),
        "the zombie's stale-epoch submit must be rejected at the store"
    );
    assert!(
        matches!(s.load(t).unwrap().unwrap().state, TaskState::Leased { .. }),
        "the rejected zombie submit must not mutate the task"
    );

    // 4. Worker B submits @ e2 → Ok.
    s.submit(t, WB, e2, C, O_B).expect("B's legitimate submit");

    // 5. Exactly one output exists, and it is B's.
    s.select_or_accept(t, false).expect("accept B's output");
    match s.load(t).unwrap().unwrap().state {
        TaskState::Accepted { output, .. } => {
            assert_eq!(output, O_B, "the accepted output is the legitimate one (B's)");
        }
        other => panic!("expected a single Accepted output, got {other:?}"),
    }
}

/// The heartbeat variant of §3.3: after a reclaim + re-lease, the zombie's heartbeat at
/// its dead epoch cannot resurrect its lease.
pub(crate) fn heartbeat_after_reclaim_rejected<S: Store>(s: &S) {
    let t = seed(s, 1);
    let e1 = s.lease(t, WA, LogicalTime(100)).expect("A leases @ e1");
    assert_eq!(s.reclaim_expired(LogicalTime(100)).unwrap(), vec![t]);
    let _ = s.pop_ready().unwrap();
    let e2 = s.lease(t, WB, LogicalTime(300)).expect("B re-leases @ e2");

    // A's heartbeat @ e1 after reclaim is rejected — it cannot extend a lease it lost.
    assert_eq!(
        s.extend_lease(t, WA, e1, LogicalTime(500)),
        Err(StoreError::StaleEpoch {
            event_epoch: e1,
            current: e2,
        })
    );
    // B's heartbeat @ e2 is honored.
    s.extend_lease(t, WB, e2, LogicalTime(500))
        .expect("the live holder's heartbeat extends");
}

// --- ready queue & registry (storage sanity; policy lands later) -----------

/// `pop_ready` honors priority first, then FIFO within a class.
pub(crate) fn ready_queue_priority_then_fifo<S: Store>(s: &S) {
    for id in 1..=3 {
        s.create_task(task(id)).expect("create");
    }
    // Enqueue low, high, low — same logical time, distinct sequence.
    s.enqueue_ready(TaskId(1), Priority(0), LogicalTime(10))
        .unwrap();
    s.enqueue_ready(TaskId(2), Priority(5), LogicalTime(10))
        .unwrap();
    s.enqueue_ready(TaskId(3), Priority(0), LogicalTime(10))
        .unwrap();
    // High priority first, then the two low-priority tasks in FIFO order.
    assert_eq!(s.pop_ready().unwrap(), Some(TaskId(2)));
    assert_eq!(s.pop_ready().unwrap(), Some(TaskId(1)));
    assert_eq!(s.pop_ready().unwrap(), Some(TaskId(3)));
    assert_eq!(s.pop_ready().unwrap(), None, "queue drains to empty");
}

/// Enqueuing an unknown task is rejected.
pub(crate) fn enqueue_unknown_task_rejected<S: Store>(s: &S) {
    assert_eq!(
        s.enqueue_ready(TaskId(404), Priority::default(), LogicalTime(0)),
        Err(StoreError::NoSuchTask(TaskId(404)))
    );
}

/// `worker_load` reports in-flight count, the EWMA field, and the last heartbeat; an
/// unregistered worker is an error.
pub(crate) fn worker_load_reports_in_flight<S: Store>(s: &S) {
    assert_eq!(
        s.worker_load(WorkerId(404)),
        Err(StoreError::UnknownWorker(WorkerId(404)))
    );
    let t = seed(s, 1);
    let load = s.worker_load(WA).unwrap();
    assert_eq!(load.in_flight, 0);
    assert_eq!(load.ewma_throughput, 0.0);
    assert_eq!(load.last_heartbeat, LogicalTime(0));

    s.lease(t, WA, LogicalTime(100)).expect("lease");
    assert_eq!(s.worker_load(WA).unwrap().in_flight, 1, "a held lease counts");
    assert_eq!(s.worker_load(WB).unwrap().in_flight, 0);
}

/// Reputation penalties accumulate and escalate the tier monotonically; the eligibility
/// gate flips once a worker is suspended. (The asymmetric policy itself is Session 4 —
/// this only checks the store persists standing and reports a tier.)
pub(crate) fn standing_penalties_escalate_tier<S: Store>(s: &S) {
    assert_eq!(
        s.update_standing(WorkerId(404), ReputationDelta::Timeout),
        Err(StoreError::UnknownWorker(WorkerId(404)))
    );
    seed(s, 1);
    // Pristine until penalized.
    assert_eq!(s.worker_load(WA).unwrap().in_flight, 0);
    // Tiers are ordered Pristine < Watch < Suspect < Suspended < Banned, so escalation
    // is monotonically non-decreasing under repeated penalties.
    let mut last = Tier::Pristine;
    for _ in 0..8 {
        let tier = s
            .update_standing(WA, ReputationDelta::VerificationFailure)
            .unwrap();
        assert!(tier >= last, "tier never improves under repeated penalties");
        last = tier;
    }
    assert!(
        !last.is_eligible(),
        "sustained verification failures suspend the worker (ineligible for dispatch)"
    );
}

/// Generate the full shared contract suite as `#[test]`s, each constructing a fresh
/// store via `$new`. Invoked by `memory` (this session) and `redis` (Session 2) so both
/// backends run byte-identical test logic — the differential oracle.
macro_rules! store_contract_suite {
    ($new:expr) => {
        macro_rules! case {
            ($name:ident) => {
                #[test]
                fn $name() {
                    $crate::store::contract::$name(&$new);
                }
            };
        }
        case!(happy_path_lease_submit_accept);
        case!(sampled_path_verifies_then_accepts);
        case!(double_lease_is_illegal);
        case!(submit_fencing_rejects_stale_and_wrong_holder);
        case!(heartbeat_fencing);
        case!(reclaim_expires_and_reenqueues);
        case!(reclaim_skips_submitted);
        case!(slow_zombie_submit_rejected);
        case!(heartbeat_after_reclaim_rejected);
        case!(ready_queue_priority_then_fifo);
        case!(enqueue_unknown_task_rejected);
        case!(worker_load_reports_in_flight);
        case!(standing_penalties_escalate_tier);
    };
}
pub(crate) use store_contract_suite;
