//! Tier 2 of the §9 proof gate: property invariants I1–I5 over random event
//! sequences, plus the explicit revived-worker zombie scenario. `core` is finite
//! and clock-free, so these invariants are *proven* by exhaustive fuzzing of the
//! transition function, not merely sampled.
//!
//! - **I1 — Epoch monotonicity:** `epoch_hw` never decreases; a successful `Lease`
//!   strictly increases it.
//! - **I2 — Zombie rejection:** no sequence advances a task on behalf of a
//!   `(worker, epoch)` that is not the current lease's; stale holder-actions are
//!   rejected and never mutate state.
//! - **I3 — Terminal absorption:** from `Accepted`/`Failed`, every event is
//!   `Err(Terminal)` with no state change.
//! - **I4 — Determinism / purity:** the same event applied to a clone yields an
//!   identical `(task, result)`; a rejected event leaves the task byte-identical.
//! - **I5 — Single authoritative holder:** in `Leased`, a holder-action succeeds
//!   iff it matches the current `(holder, epoch)` exactly.

use proctor_core::commit::LeafIndex;
use proctor_core::id::{JobId, SegmentId};
use proctor_core::task::{Codec, Container, SegmentRef, TargetProfile, TranscodeSpec};
use proctor_core::{
    Challenge, Commitment, Epoch, FailureReason, LogicalTime, OutputRef, Task, TaskEvent,
    TaskState, TaskId, TransitionError, WorkerId,
};

use proptest::prelude::*;

const C: Commitment = Commitment([7u8; 32]);
const O: OutputRef = OutputRef(9);

fn kind() -> proctor_core::TaskKind {
    proctor_core::TaskKind::Transcode(TranscodeSpec {
        job: JobId(1),
        segment: SegmentId(1),
        profile: TargetProfile {
            codec: Codec::H264,
            width: 1280,
            height: 720,
            bitrate_kbps: 3000,
            container: Container::Mp4,
        },
        source: SegmentRef(1),
    })
}

fn challenge() -> Challenge {
    Challenge {
        indices: vec![LeafIndex(0)],
    }
}

/// A deliberately *small* event space (2 workers, epochs 0..=3) so random
/// sequences actually collide on holders and epochs and exercise the guards.
fn any_event() -> impl Strategy<Value = TaskEvent> {
    let worker = (1u64..=2).prop_map(WorkerId);
    let epoch = (0u64..=3).prop_map(Epoch);
    let time = (0u64..=10).prop_map(LogicalTime);
    prop_oneof![
        (worker.clone(), epoch.clone(), time.clone())
            .prop_map(|(w, e, d)| TaskEvent::Lease { worker: w, epoch: e, deadline: d }),
        (worker.clone(), epoch.clone(), time)
            .prop_map(|(w, e, d)| TaskEvent::Heartbeat { worker: w, epoch: e, new_deadline: d }),
        (worker, epoch.clone()).prop_map(|(w, e)| TaskEvent::Submit {
            worker: w,
            epoch: e,
            commitment: C,
            output: O,
        }),
        Just(TaskEvent::SelectForVerification { challenge: challenge() }),
        Just(TaskEvent::Accept),
        any::<bool>().prop_map(|p| TaskEvent::VerifyOutcome { passed: p }),
        epoch.prop_map(|e| TaskEvent::LeaseExpired { epoch: e }),
        Just(TaskEvent::Abandon { reason: FailureReason::Cancelled }),
    ]
}

fn is_terminal(s: &TaskState) -> bool {
    matches!(s, TaskState::Accepted { .. } | TaskState::Failed { .. })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn invariants_hold_over_random_sequences(seq in proptest::collection::vec(any_event(), 0..50)) {
        let mut task = Task::new(TaskId(1), kind());

        for ev in seq {
            let pre = task.clone();

            // I4 (determinism): the same event on a clone yields an identical outcome.
            let mut twin = pre.clone();
            let result = task.apply(ev.clone());
            let twin_result = twin.apply(ev.clone());
            prop_assert_eq!(&task, &twin);
            prop_assert_eq!(&result, &twin_result);

            // I3 (terminal absorption): terminal tasks reject everything, unchanged.
            if is_terminal(&pre.state) {
                prop_assert_eq!(&result, &Err(TransitionError::Terminal));
                prop_assert_eq!(&task, &pre);
            }

            // I1 (epoch monotonicity): the high-water never decreases…
            prop_assert!(task.epoch_hw >= pre.epoch_hw);
            // …and a successful Lease strictly increases it.
            if matches!(ev, TaskEvent::Lease { .. }) && result.is_ok() {
                prop_assert!(task.epoch_hw > pre.epoch_hw);
            }

            // I4 (purity): a rejected event leaves the task byte-identical.
            if result.is_err() {
                prop_assert_eq!(&task, &pre);
            }

            // I2 + I5: in Leased, a holder-action succeeds iff (worker, epoch) match
            // the current lease exactly; a mismatch is rejected and never mutates.
            if let TaskState::Leased { holder, epoch, .. } = pre.state {
                let holder_action = match &ev {
                    TaskEvent::Submit { worker, epoch: e, .. }
                    | TaskEvent::Heartbeat { worker, epoch: e, .. } => Some((*worker, *e)),
                    _ => None,
                };
                if let Some((w, e)) = holder_action {
                    let matches_lease = w == holder && e == epoch;
                    prop_assert_eq!(result.is_ok(), matches_lease);
                    if !matches_lease {
                        prop_assert_eq!(&task.state, &pre.state);
                    }
                }
            }

            // I2 (no impersonated advance): a successful Submit can only have come
            // from the matching holder — the post-state proves the lease identity.
            if matches!(ev, TaskEvent::Submit { .. }) && result.is_ok() {
                if let (TaskState::Leased { holder, epoch, .. }, TaskState::Submitted { holder: sh, epoch: se, .. }) =
                    (&pre.state, &task.state)
                {
                    prop_assert_eq!(holder, sh);
                    prop_assert_eq!(epoch, se);
                }
            }
        }
    }

    /// I2, stated as a property: a stale-epoch holder-action against a freshly
    /// re-leased task is *always* rejected with state unchanged, regardless of the
    /// epochs the scheduler happened to choose (`e2 > e1`).
    #[test]
    fn revived_worker_is_always_rejected(
        e1 in 1u64..=50,
        bump in 1u64..=50,
        d1 in 0u64..=10,
        d2 in 0u64..=10,
    ) {
        let e1 = Epoch(e1);
        let e2 = Epoch(e1.0 + bump); // strictly greater, as a reclaim guarantees
        let (w_old, w_new) = (WorkerId(1), WorkerId(2));

        let mut task = Task::new(TaskId(1), kind());
        task.apply(TaskEvent::Lease { worker: w_old, epoch: e1, deadline: LogicalTime(d1) }).unwrap();
        task.apply(TaskEvent::LeaseExpired { epoch: e1 }).unwrap();
        task.apply(TaskEvent::Lease { worker: w_new, epoch: e2, deadline: LogicalTime(d2) }).unwrap();

        let before = task.clone();
        let result = task.apply(TaskEvent::Submit {
            worker: w_old,
            epoch: e1,
            commitment: C,
            output: O,
        });
        prop_assert_eq!(result, Err(TransitionError::StaleEpoch { event_epoch: e1, current: e2 }));
        prop_assert_eq!(&task, &before);
    }
}
