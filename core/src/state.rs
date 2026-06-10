//! `state` — the task state machine. See `phase1-spec.md` §6.
//!
//! The sans-IO crown jewel, the direct analogue of a `Connection` returning an
//! action list. [`Task::apply`] consumes a [`TaskEvent`] and, on success, returns
//! the [`TaskAction`]s the I/O layer must perform; on failure it returns a typed
//! [`TransitionError`] and **leaves the task byte-identically unchanged**. The
//! function is deterministic and reads no clock — expiry is computed by the
//! scheduler via [`crate::lease::Lease::is_expired`] and delivered as the
//! [`TaskEvent::LeaseExpired`] *decision*.
//!
//! ## Fencing (the zombie-killer)
//! Every task carries a high-water [`Epoch`] (`epoch_hw`) that never decreases. A
//! new lease must present a strictly greater epoch; a holder-action (`Submit`,
//! `Heartbeat`) must present `(worker, epoch)` matching the current lease exactly.
//! Epoch is checked before holder, so a revived worker presenting an *old* epoch
//! is rejected as [`TransitionError::StaleEpoch`] — even though its identity is
//! also wrong — with state unchanged. The reclaim that requeued the task already
//! advanced `epoch_hw` past it, so it can never move the task again.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::commit::{Challenge, Commitment};
use crate::id::{Epoch, LogicalTime, OutputRef, TaskId, WorkerId};
use crate::task::TaskKind;

/// A task's verification retry budget. After this many failed verifications the
/// task transitions to terminal [`TaskState::Failed`] with
/// [`FailureReason::VerificationExhausted`].
pub const MAX_RETRIES: u8 = 3;

/// One unit of work and its lifecycle. `epoch_hw` is the monotonic non-decreasing
/// fencing high-water mark; `retries` counts consumed verification re-attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub kind: TaskKind,
    pub state: TaskState,
    pub epoch_hw: Epoch,
    pub retries: u8,
}

/// The task lifecycle. Holder-bearing states carry the `(holder, epoch)` fencing
/// pair; terminal states (`Accepted`, `Failed`) absorb every further event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Pending,
    Leased {
        holder: WorkerId,
        epoch: Epoch,
        deadline: LogicalTime,
    },
    Submitted {
        holder: WorkerId,
        epoch: Epoch,
        commitment: Commitment,
        output: OutputRef,
    },
    Verifying {
        holder: WorkerId,
        epoch: Epoch,
        commitment: Commitment,
        output: OutputRef,
        challenge: Challenge,
    },
    /// Terminal (success).
    Accepted {
        output: OutputRef,
        commitment: Commitment,
    },
    /// Terminal (failure).
    Failed {
        reason: FailureReason,
    },
}

/// The inputs to [`Task::apply`]. `LeaseExpired` is the scheduler's expiry
/// *decision* (computed off-clock), not a clock read inside `core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskEvent {
    Lease {
        worker: WorkerId,
        epoch: Epoch,
        deadline: LogicalTime,
    },
    Heartbeat {
        worker: WorkerId,
        epoch: Epoch,
        new_deadline: LogicalTime,
    },
    Submit {
        worker: WorkerId,
        epoch: Epoch,
        commitment: Commitment,
        output: OutputRef,
    },
    /// The scheduler's probabilistic spot-check decision.
    SelectForVerification {
        challenge: Challenge,
    },
    /// Unsampled acceptance — the commitment is already tamper-evident.
    Accept,
    /// The verifier's verdict; the reveal↔commitment binding was checked by the I/O
    /// layer (`commit::verify_inclusion`) before this event was emitted.
    VerifyOutcome {
        passed: bool,
    },
    /// The sweeper expiring a specific lease, referenced by its epoch.
    LeaseExpired {
        epoch: Epoch,
    },
    Abandon {
        reason: FailureReason,
    },
}

/// The side effects the I/O layer must perform after a successful transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskAction {
    /// Task returned to `Pending`; the scheduler assigns a higher epoch next lease.
    Requeue,
    /// Scheduler → worker.
    IssueChallenge(Challenge),
    /// Downstream notification (e.g. stitch-readiness tracking).
    NotifyAccepted(OutputRef),
    MarkFailed(FailureReason),
    /// Scheduler applies this to the worker's standing.
    EmitReputation(ReputationDelta),
}

/// Why a task reached terminal [`TaskState::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    /// Verification failed and the retry budget ([`MAX_RETRIES`]) is exhausted.
    VerificationExhausted,
    /// The job was cancelled upstream.
    Cancelled,
    /// The encrypted source segment could not be retrieved.
    SourceUnavailable,
    /// Explicitly abandoned by the scheduler/operator for an unspecified reason.
    Abandoned,
}

/// A change to a worker's reputation that the scheduler applies. `core` emits the
/// *kind*; the magnitude/weighting (incl. the heavier penalty for a failed
/// reveal↔commitment binding) is the scheduler's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationDelta {
    /// The worker let its lease lapse (timeout / no-show).
    Timeout,
    /// The worker's submission failed verification.
    VerificationFailure,
}

/// Why an event was rejected. On any of these, the task is left unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransitionError {
    /// The zombie-killer: a holder-action (or lease expiry) presented an epoch that
    /// is not the current lease's.
    #[error("stale epoch: event presented {event_epoch:?}, current is {current:?}")]
    StaleEpoch { event_epoch: Epoch, current: Epoch },
    /// Right epoch, wrong worker.
    #[error("wrong holder: event from {event_worker:?}, current holder is {current:?}")]
    WrongHolder {
        event_worker: WorkerId,
        current: WorkerId,
    },
    /// The event type is not valid in the current state at all.
    #[error("illegal transition: {event} is not valid in state {state}")]
    IllegalTransition {
        state: &'static str,
        event: &'static str,
    },
    /// The task is already `Accepted`/`Failed` and absorbs every event.
    #[error("task is terminal (Accepted/Failed)")]
    Terminal,
}

impl Task {
    /// A fresh `Pending` task with a zero high-water epoch and no retries consumed.
    #[must_use]
    pub fn new(id: TaskId, kind: TaskKind) -> Self {
        Task {
            id,
            kind,
            state: TaskState::Pending,
            epoch_hw: Epoch::ZERO,
            retries: 0,
        }
    }

    /// Apply an event, implementing the §6.2 transition table exactly. On `Ok`,
    /// `self` is mutated and the actions are returned; on `Err`, `self` is
    /// unchanged. Deterministic and clock-free.
    pub fn apply(&mut self, ev: TaskEvent) -> Result<Vec<TaskAction>, TransitionError> {
        // Terminal absorption first: Accepted/Failed reject every event (incl. Abandon).
        if matches!(self.state, TaskState::Accepted { .. } | TaskState::Failed { .. }) {
            return Err(TransitionError::Terminal);
        }

        match ev {
            // Abandon fails any non-terminal task.
            TaskEvent::Abandon { reason } => {
                self.state = TaskState::Failed { reason };
                Ok(vec![TaskAction::MarkFailed(reason)])
            }

            TaskEvent::Lease {
                worker,
                epoch,
                deadline,
            } => match &self.state {
                TaskState::Pending => {
                    if epoch > self.epoch_hw {
                        self.epoch_hw = epoch;
                        self.state = TaskState::Leased {
                            holder: worker,
                            epoch,
                            deadline,
                        };
                        Ok(Vec::new())
                    } else {
                        Err(TransitionError::StaleEpoch {
                            event_epoch: epoch,
                            current: self.epoch_hw,
                        })
                    }
                }
                _ => Err(self.illegal("Lease")),
            },

            TaskEvent::Heartbeat {
                worker,
                epoch,
                new_deadline,
            } => match &self.state {
                TaskState::Leased {
                    holder, epoch: le, ..
                } => {
                    let (holder, le) = (*holder, *le);
                    Self::check_holder(worker, epoch, holder, le)?;
                    self.state = TaskState::Leased {
                        holder,
                        epoch: le,
                        deadline: new_deadline,
                    };
                    Ok(Vec::new())
                }
                _ => Err(self.illegal("Heartbeat")),
            },

            TaskEvent::Submit {
                worker,
                epoch,
                commitment,
                output,
            } => match &self.state {
                TaskState::Leased {
                    holder, epoch: le, ..
                } => {
                    let (holder, le) = (*holder, *le);
                    Self::check_holder(worker, epoch, holder, le)?;
                    self.state = TaskState::Submitted {
                        holder,
                        epoch: le,
                        commitment,
                        output,
                    };
                    Ok(Vec::new())
                }
                _ => Err(self.illegal("Submit")),
            },

            TaskEvent::SelectForVerification { challenge } => match &self.state {
                TaskState::Submitted {
                    holder,
                    epoch,
                    commitment,
                    output,
                } => {
                    let (holder, epoch, commitment, output) =
                        (*holder, *epoch, *commitment, *output);
                    self.state = TaskState::Verifying {
                        holder,
                        epoch,
                        commitment,
                        output,
                        challenge: challenge.clone(),
                    };
                    Ok(vec![TaskAction::IssueChallenge(challenge)])
                }
                _ => Err(self.illegal("SelectForVerification")),
            },

            TaskEvent::Accept => match &self.state {
                TaskState::Submitted {
                    commitment, output, ..
                } => {
                    let (commitment, output) = (*commitment, *output);
                    self.state = TaskState::Accepted { output, commitment };
                    Ok(vec![TaskAction::NotifyAccepted(output)])
                }
                _ => Err(self.illegal("Accept")),
            },

            TaskEvent::VerifyOutcome { passed } => match &self.state {
                TaskState::Verifying {
                    commitment, output, ..
                } => {
                    let (commitment, output) = (*commitment, *output);
                    if passed {
                        self.state = TaskState::Accepted { output, commitment };
                        Ok(vec![TaskAction::NotifyAccepted(output)])
                    } else if self.retries < MAX_RETRIES {
                        self.retries += 1;
                        self.state = TaskState::Pending;
                        Ok(vec![
                            TaskAction::Requeue,
                            TaskAction::EmitReputation(ReputationDelta::VerificationFailure),
                        ])
                    } else {
                        self.state = TaskState::Failed {
                            reason: FailureReason::VerificationExhausted,
                        };
                        Ok(vec![
                            TaskAction::MarkFailed(FailureReason::VerificationExhausted),
                            TaskAction::EmitReputation(ReputationDelta::VerificationFailure),
                        ])
                    }
                }
                _ => Err(self.illegal("VerifyOutcome")),
            },

            TaskEvent::LeaseExpired { epoch } => match &self.state {
                TaskState::Leased { epoch: le, .. } => {
                    let le = *le;
                    if epoch == le {
                        self.state = TaskState::Pending;
                        Ok(vec![
                            TaskAction::Requeue,
                            TaskAction::EmitReputation(ReputationDelta::Timeout),
                        ])
                    } else {
                        // A delayed/duplicate expiry for a superseded lease: rejected as
                        // stale so it can never requeue work the current holder owns.
                        Err(TransitionError::StaleEpoch {
                            event_epoch: epoch,
                            current: le,
                        })
                    }
                }
                // Ignored once Submitted: the work product and its commitment already
                // exist, so a dead worker after submission does not cost the output.
                // A deliberate liveness/efficiency call, not an oversight.
                TaskState::Submitted { .. } => Ok(Vec::new()),
                _ => Err(self.illegal("LeaseExpired")),
            },
        }
    }

    /// Holder-action fencing check. Epoch is tested **before** identity, so a stale
    /// epoch is reported as `StaleEpoch` even when the worker also differs.
    fn check_holder(
        ev_worker: WorkerId,
        ev_epoch: Epoch,
        holder: WorkerId,
        lease_epoch: Epoch,
    ) -> Result<(), TransitionError> {
        if ev_epoch != lease_epoch {
            return Err(TransitionError::StaleEpoch {
                event_epoch: ev_epoch,
                current: lease_epoch,
            });
        }
        if ev_worker != holder {
            return Err(TransitionError::WrongHolder {
                event_worker: ev_worker,
                current: holder,
            });
        }
        Ok(())
    }

    fn illegal(&self, event: &'static str) -> TransitionError {
        TransitionError::IllegalTransition {
            state: self.state.name(),
            event,
        }
    }
}

impl TaskState {
    /// Stable state-class name for `IllegalTransition` diagnostics.
    fn name(&self) -> &'static str {
        match self {
            TaskState::Pending => "Pending",
            TaskState::Leased { .. } => "Leased",
            TaskState::Submitted { .. } => "Submitted",
            TaskState::Verifying { .. } => "Verifying",
            TaskState::Accepted { .. } => "Accepted",
            TaskState::Failed { .. } => "Failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::LeafIndex;
    use crate::id::{JobId, SegmentId};
    use crate::task::{Codec, Container, TargetProfile, TranscodeSpec, SegmentRef};

    const W1: WorkerId = WorkerId(1);
    const W2: WorkerId = WorkerId(2);
    const E0: Epoch = Epoch(0);
    const E1: Epoch = Epoch(1);
    const E2: Epoch = Epoch(2);
    const D1: LogicalTime = LogicalTime(100);
    const D2: LogicalTime = LogicalTime(200);
    const C: Commitment = Commitment([7u8; 32]);
    const O: OutputRef = OutputRef(9);

    fn ch() -> Challenge {
        Challenge {
            indices: vec![LeafIndex(0)],
        }
    }

    fn kind() -> TaskKind {
        TaskKind::Transcode(TranscodeSpec {
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

    // --- state builders -----------------------------------------------------

    fn pending() -> Task {
        Task::new(TaskId(1), kind())
    }
    fn leased() -> Task {
        let mut t = pending();
        t.apply(TaskEvent::Lease {
            worker: W1,
            epoch: E1,
            deadline: D1,
        })
        .unwrap();
        t
    }
    fn submitted() -> Task {
        let mut t = leased();
        t.apply(TaskEvent::Submit {
            worker: W1,
            epoch: E1,
            commitment: C,
            output: O,
        })
        .unwrap();
        t
    }
    fn verifying() -> Task {
        let mut t = submitted();
        t.apply(TaskEvent::SelectForVerification { challenge: ch() })
            .unwrap();
        t
    }
    fn accepted() -> Task {
        let mut t = submitted();
        t.apply(TaskEvent::Accept).unwrap();
        t
    }
    fn failed() -> Task {
        let mut t = leased();
        t.apply(TaskEvent::Abandon {
            reason: FailureReason::Cancelled,
        })
        .unwrap();
        t
    }

    // --- assertion helpers --------------------------------------------------

    fn ok(mut t: Task, ev: TaskEvent, want_actions: Vec<TaskAction>, want_state: TaskState) {
        let got = t.apply(ev).expect("expected Ok transition");
        assert_eq!(got, want_actions, "actions mismatch");
        assert_eq!(t.state, want_state, "state mismatch");
    }

    fn err(mut t: Task, ev: TaskEvent, want: TransitionError) {
        let before = t.clone();
        let got = t.apply(ev);
        assert_eq!(got, Err(want));
        assert_eq!(t, before, "rejected event must not mutate the task");
    }

    fn illegal(state: &'static str, event: &'static str) -> TransitionError {
        TransitionError::IllegalTransition { state, event }
    }

    // A representative of every event variant, for the terminal-absorption sweep.
    fn every_event() -> Vec<TaskEvent> {
        vec![
            TaskEvent::Lease {
                worker: W1,
                epoch: E2,
                deadline: D1,
            },
            TaskEvent::Heartbeat {
                worker: W1,
                epoch: E1,
                new_deadline: D2,
            },
            TaskEvent::Submit {
                worker: W1,
                epoch: E1,
                commitment: C,
                output: O,
            },
            TaskEvent::SelectForVerification { challenge: ch() },
            TaskEvent::Accept,
            TaskEvent::VerifyOutcome { passed: true },
            TaskEvent::VerifyOutcome { passed: false },
            TaskEvent::LeaseExpired { epoch: E1 },
            TaskEvent::Abandon {
                reason: FailureReason::Cancelled,
            },
        ]
    }

    // --- tier 1: exhaustive transition table (§6.2) -------------------------

    #[test]
    fn table_pending() {
        ok(
            pending(),
            TaskEvent::Lease {
                worker: W1,
                epoch: E1,
                deadline: D1,
            },
            vec![],
            TaskState::Leased {
                holder: W1,
                epoch: E1,
                deadline: D1,
            },
        );
        // epoch must strictly exceed the high-water (0): epoch 0 is rejected.
        err(
            pending(),
            TaskEvent::Lease {
                worker: W1,
                epoch: E0,
                deadline: D1,
            },
            TransitionError::StaleEpoch {
                event_epoch: E0,
                current: E0,
            },
        );
        err(
            pending(),
            TaskEvent::Heartbeat {
                worker: W1,
                epoch: E1,
                new_deadline: D2,
            },
            illegal("Pending", "Heartbeat"),
        );
        err(
            pending(),
            TaskEvent::Submit {
                worker: W1,
                epoch: E1,
                commitment: C,
                output: O,
            },
            illegal("Pending", "Submit"),
        );
        err(
            pending(),
            TaskEvent::SelectForVerification { challenge: ch() },
            illegal("Pending", "SelectForVerification"),
        );
        err(pending(), TaskEvent::Accept, illegal("Pending", "Accept"));
        err(
            pending(),
            TaskEvent::VerifyOutcome { passed: true },
            illegal("Pending", "VerifyOutcome"),
        );
        err(
            pending(),
            TaskEvent::LeaseExpired { epoch: E1 },
            illegal("Pending", "LeaseExpired"),
        );
        ok(
            pending(),
            TaskEvent::Abandon {
                reason: FailureReason::Cancelled,
            },
            vec![TaskAction::MarkFailed(FailureReason::Cancelled)],
            TaskState::Failed {
                reason: FailureReason::Cancelled,
            },
        );
    }

    #[test]
    fn table_leased() {
        err(
            leased(),
            TaskEvent::Lease {
                worker: W2,
                epoch: E2,
                deadline: D2,
            },
            illegal("Leased", "Lease"),
        );
        ok(
            leased(),
            TaskEvent::Heartbeat {
                worker: W1,
                epoch: E1,
                new_deadline: D2,
            },
            vec![],
            TaskState::Leased {
                holder: W1,
                epoch: E1,
                deadline: D2,
            },
        );
        // wrong epoch (stale) takes precedence over identity
        err(
            leased(),
            TaskEvent::Heartbeat {
                worker: W1,
                epoch: E2,
                new_deadline: D2,
            },
            TransitionError::StaleEpoch {
                event_epoch: E2,
                current: E1,
            },
        );
        // right epoch, wrong holder
        err(
            leased(),
            TaskEvent::Heartbeat {
                worker: W2,
                epoch: E1,
                new_deadline: D2,
            },
            TransitionError::WrongHolder {
                event_worker: W2,
                current: W1,
            },
        );
        ok(
            leased(),
            TaskEvent::Submit {
                worker: W1,
                epoch: E1,
                commitment: C,
                output: O,
            },
            vec![],
            TaskState::Submitted {
                holder: W1,
                epoch: E1,
                commitment: C,
                output: O,
            },
        );
        err(
            leased(),
            TaskEvent::Submit {
                worker: W2,
                epoch: E1,
                commitment: C,
                output: O,
            },
            TransitionError::WrongHolder {
                event_worker: W2,
                current: W1,
            },
        );
        err(
            leased(),
            TaskEvent::Submit {
                worker: W1,
                epoch: E2,
                commitment: C,
                output: O,
            },
            TransitionError::StaleEpoch {
                event_epoch: E2,
                current: E1,
            },
        );
        err(
            leased(),
            TaskEvent::SelectForVerification { challenge: ch() },
            illegal("Leased", "SelectForVerification"),
        );
        err(leased(), TaskEvent::Accept, illegal("Leased", "Accept"));
        err(
            leased(),
            TaskEvent::VerifyOutcome { passed: true },
            illegal("Leased", "VerifyOutcome"),
        );
        ok(
            leased(),
            TaskEvent::LeaseExpired { epoch: E1 },
            vec![
                TaskAction::Requeue,
                TaskAction::EmitReputation(ReputationDelta::Timeout),
            ],
            TaskState::Pending,
        );
        err(
            leased(),
            TaskEvent::LeaseExpired { epoch: E2 },
            TransitionError::StaleEpoch {
                event_epoch: E2,
                current: E1,
            },
        );
        ok(
            leased(),
            TaskEvent::Abandon {
                reason: FailureReason::Cancelled,
            },
            vec![TaskAction::MarkFailed(FailureReason::Cancelled)],
            TaskState::Failed {
                reason: FailureReason::Cancelled,
            },
        );
    }

    #[test]
    fn table_submitted() {
        let sub = TaskState::Submitted {
            holder: W1,
            epoch: E1,
            commitment: C,
            output: O,
        };
        err(
            submitted(),
            TaskEvent::Lease {
                worker: W2,
                epoch: E2,
                deadline: D2,
            },
            illegal("Submitted", "Lease"),
        );
        err(
            submitted(),
            TaskEvent::Heartbeat {
                worker: W1,
                epoch: E1,
                new_deadline: D2,
            },
            illegal("Submitted", "Heartbeat"),
        );
        err(
            submitted(),
            TaskEvent::Submit {
                worker: W1,
                epoch: E1,
                commitment: C,
                output: O,
            },
            illegal("Submitted", "Submit"),
        );
        ok(
            submitted(),
            TaskEvent::SelectForVerification { challenge: ch() },
            vec![TaskAction::IssueChallenge(ch())],
            TaskState::Verifying {
                holder: W1,
                epoch: E1,
                commitment: C,
                output: O,
                challenge: ch(),
            },
        );
        ok(
            submitted(),
            TaskEvent::Accept,
            vec![TaskAction::NotifyAccepted(O)],
            TaskState::Accepted {
                output: O,
                commitment: C,
            },
        );
        err(
            submitted(),
            TaskEvent::VerifyOutcome { passed: true },
            illegal("Submitted", "VerifyOutcome"),
        );
        // LeaseExpired is ignored once Submitted — any epoch, no-op, unchanged.
        ok(
            submitted(),
            TaskEvent::LeaseExpired { epoch: E1 },
            vec![],
            sub.clone(),
        );
        ok(
            submitted(),
            TaskEvent::LeaseExpired { epoch: E2 },
            vec![],
            sub,
        );
        ok(
            submitted(),
            TaskEvent::Abandon {
                reason: FailureReason::Cancelled,
            },
            vec![TaskAction::MarkFailed(FailureReason::Cancelled)],
            TaskState::Failed {
                reason: FailureReason::Cancelled,
            },
        );
    }

    #[test]
    fn table_verifying() {
        err(
            verifying(),
            TaskEvent::Lease {
                worker: W2,
                epoch: E2,
                deadline: D2,
            },
            illegal("Verifying", "Lease"),
        );
        err(
            verifying(),
            TaskEvent::Heartbeat {
                worker: W1,
                epoch: E1,
                new_deadline: D2,
            },
            illegal("Verifying", "Heartbeat"),
        );
        err(
            verifying(),
            TaskEvent::Submit {
                worker: W1,
                epoch: E1,
                commitment: C,
                output: O,
            },
            illegal("Verifying", "Submit"),
        );
        err(
            verifying(),
            TaskEvent::SelectForVerification { challenge: ch() },
            illegal("Verifying", "SelectForVerification"),
        );
        err(verifying(), TaskEvent::Accept, illegal("Verifying", "Accept"));
        ok(
            verifying(),
            TaskEvent::VerifyOutcome { passed: true },
            vec![TaskAction::NotifyAccepted(O)],
            TaskState::Accepted {
                output: O,
                commitment: C,
            },
        );
        // passed:false branches are covered in `verification_failure_retries_then_exhausts`.
        err(
            verifying(),
            TaskEvent::LeaseExpired { epoch: E1 },
            illegal("Verifying", "LeaseExpired"),
        );
        ok(
            verifying(),
            TaskEvent::Abandon {
                reason: FailureReason::Cancelled,
            },
            vec![TaskAction::MarkFailed(FailureReason::Cancelled)],
            TaskState::Failed {
                reason: FailureReason::Cancelled,
            },
        );
    }

    #[test]
    fn table_terminal_absorbs_everything() {
        for base in [accepted(), failed()] {
            for ev in every_event() {
                err(base.clone(), ev, TransitionError::Terminal);
            }
        }
    }

    // --- focused behaviour --------------------------------------------------

    #[test]
    fn verification_failure_retries_then_exhausts() {
        // retries < MAX → requeue and increment.
        let mut t = verifying();
        let got = t.apply(TaskEvent::VerifyOutcome { passed: false }).unwrap();
        assert_eq!(
            got,
            vec![
                TaskAction::Requeue,
                TaskAction::EmitReputation(ReputationDelta::VerificationFailure),
            ]
        );
        assert_eq!(t.state, TaskState::Pending);
        assert_eq!(t.retries, 1);

        // retries == MAX → terminal Failed{VerificationExhausted}.
        let mut t = verifying();
        t.retries = MAX_RETRIES;
        let got = t.apply(TaskEvent::VerifyOutcome { passed: false }).unwrap();
        assert_eq!(
            got,
            vec![
                TaskAction::MarkFailed(FailureReason::VerificationExhausted),
                TaskAction::EmitReputation(ReputationDelta::VerificationFailure),
            ]
        );
        assert_eq!(
            t.state,
            TaskState::Failed {
                reason: FailureReason::VerificationExhausted
            }
        );
    }

    #[test]
    fn revived_worker_zombie_is_rejected() {
        // lease@e1 → expire@e1 → release@e2; the revived old worker submits@e1.
        let mut t = pending();
        t.apply(TaskEvent::Lease {
            worker: W1,
            epoch: E1,
            deadline: D1,
        })
        .unwrap();
        t.apply(TaskEvent::LeaseExpired { epoch: E1 }).unwrap();
        t.apply(TaskEvent::Lease {
            worker: W2,
            epoch: E2,
            deadline: D2,
        })
        .unwrap();

        let before = t.clone();
        let got = t.apply(TaskEvent::Submit {
            worker: W1,
            epoch: E1,
            commitment: C,
            output: O,
        });
        assert_eq!(
            got,
            Err(TransitionError::StaleEpoch {
                event_epoch: E1,
                current: E2,
            }),
            "stale epoch must win over the (also wrong) holder identity"
        );
        assert_eq!(t, before, "the zombie submit must not mutate the task");
    }

    #[test]
    fn requeue_keeps_high_water_so_an_old_epoch_cannot_release() {
        let mut t = pending();
        t.apply(TaskEvent::Lease {
            worker: W1,
            epoch: E2,
            deadline: D1,
        })
        .unwrap();
        t.apply(TaskEvent::LeaseExpired { epoch: E2 }).unwrap();
        assert_eq!(t.state, TaskState::Pending);
        assert_eq!(t.epoch_hw, E2, "high-water survives requeue");

        // A re-lease at an epoch <= high-water is rejected.
        err(
            t.clone(),
            TaskEvent::Lease {
                worker: W2,
                epoch: E1,
                deadline: D2,
            },
            TransitionError::StaleEpoch {
                event_epoch: E1,
                current: E2,
            },
        );
        // A strictly greater epoch succeeds.
        t.apply(TaskEvent::Lease {
            worker: W2,
            epoch: Epoch(3),
            deadline: D2,
        })
        .unwrap();
        assert!(matches!(t.state, TaskState::Leased { .. }));
    }
}
