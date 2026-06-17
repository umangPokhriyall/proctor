//! `engine` — how `core::Task` drives `sched`, and content-addressed release (§7).
//!
//! **`core::Task::apply` is the transition authority.** The engine loads a task, calls
//! [`Task::apply`] to obtain the canonical [`TaskAction`]s, persists the transition through
//! the epoch-fenced [`Store`] (which re-runs the *same* rule — belt and suspenders, §0),
//! and executes the returned actions: `Requeue → enqueue_ready`, `IssueChallenge → push a
//! VerifyRequest`, `NotifyAccepted → content-addressed release`, `MarkFailed → terminal`,
//! `EmitReputation → update_standing`. The engine holds no state machine of its own.
//!
//! For the action-free transitions (`Lease`, `Heartbeat`, `Submit`) the engine just calls
//! the matching store op — the store op *is* the authority, and a zombie's stale-epoch
//! write is rejected there (§1.1). For the branching `VerifyOutcome` it uses the
//! load → apply → execute pattern, because the action set (accept / requeue+penalise /
//! fail+penalise) is exactly what `core::apply` decides.
//!
//! **Release is content-addressed (§7).** The accepted `OutputRef` is the content address
//! of the blob and the recorded `Commitment` binds the exact bytes; the release index is
//! keyed by the `OutputRef`, never the task id. A consumer re-checks
//! `Commitment::commit(&[SHA-256(fetched)]) == recorded` ([`Engine::confirm_release`]) before
//! use, so a post-submit blob swap is detectable — the verified-then-swapped TOCTOU closed,
//! paired with §1.1 fencing.
//!
//! **Two dispatch fabrics, one decision path (phase6-spec.md §2).** The place+lease
//! decision is factored out of the *push* so it feeds both: the live `sched` binary pushes
//! the encoded `Assignment` straight onto the worker's Redis inbox via the store's
//! [`OutboundChannel`] ([`Engine::dispatch_one_live`] / [`Engine::on_submission_live`]),
//! while the `#[cfg(test)]` sim uses the in-process [`Bus`] ([`Engine::dispatch_one`] /
//! [`Engine::on_submission`]). The `Bus` is now **test-only** — it stood in for the Redis
//! inbox lists before Phase 6 completed the real push transport.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use proctor_core::{
    decode, encode, Assignment, Commitment, Epoch, HeartbeatMsg, Lease, LogicalTime, OutputRef,
    SegmentRef, SubmissionMsg, Task, TaskAction, TaskEvent, TaskId, TaskKind, TaskState,
    VerifyRequest, VerifyResult, WorkerId,
};
use rand::rngs::StdRng;
use rand::Rng;
use thiserror::Error;

use crate::backpressure::{Backpressure, Sizing};
use crate::place::{self, Eligibility};
use crate::sample::Sampler;
use crate::store::{OutboundChannel, Priority, Store, StoreError, Tier};

/// What went wrong driving the control plane. Store failures pass through; the rest are
/// engine-level invariants.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("task {0:?} not found in the store")]
    TaskNotFound(TaskId),
    #[error("task {0:?} in an unexpected state for {1}")]
    UnexpectedState(TaskId, &'static str),
    /// A return-channel frame on `sched:inbound` had an unknown tag or undecodable body
    /// (phase5-spec.md §6). The live driver logs and skips it — a malformed frame is never
    /// a safety event.
    #[error("malformed inbound frame on sched:inbound")]
    MalformedInbound,
}

/// Engine tuning. The durations are in injected logical-time units (the bench / real run
/// chooses the unit); the caps come from the Little's-law [`Sizing`].
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// A lease lasts `lease_ttl`: a new/extended lease's deadline is `now + lease_ttl`.
    pub lease_ttl: u64,
    /// A worker is alive for placement if its last heartbeat is within this window.
    pub liveness_window: u64,
    /// Little's-law sizing — supplies the per-worker in-flight cap and the global shed cap.
    pub sizing: Sizing,
    /// Priority a requeued / re-injected task is enqueued at.
    pub default_priority: Priority,
}

impl EngineConfig {
    /// A sensible config for `n` pinned workers: caps from [`Sizing::from_measured`], with
    /// a lease that outlives a transcode and a liveness window half the lease.
    #[must_use]
    pub fn for_workers(n: u32) -> Self {
        EngineConfig {
            lease_ttl: 100,
            liveness_window: 50,
            sizing: Sizing::from_measured(n),
            default_priority: Priority::default(),
        }
    }

    fn in_flight_cap(&self) -> u32 {
        self.sizing.per_worker_in_flight_cap()
    }
}

/// A released, content-addressed output: the `OutputRef` content address and the
/// `Commitment` binding the exact bytes. Stored keyed by `output` (never the task id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Released {
    pub output: OutputRef,
    pub commitment: Commitment,
}

/// The outcome of handling a worker submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Sampled for verification — a `VerifyRequest` was pushed to the verifier.
    Sampled,
    /// Unsampled — content-addressed release with the recorded commitment.
    Accepted(OutputRef),
    /// A stale-epoch / wrong-holder write — the slow zombie, rejected at the store (§1.1).
    RejectedZombie,
}

/// The outcome of handling a verifier verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Accepted(OutputRef),
    /// Failed but within retry budget — requeued, worker standing penalised.
    Requeued,
    /// Failed and the retry budget is exhausted — terminal, worker standing penalised.
    Failed,
}

/// The outcome of a heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    Extended,
    /// Stale epoch / wrong holder — a reclaimed worker cannot resurrect its lease (§1.1).
    Rejected,
}

/// One step of the dispatch loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchStep {
    Dispatched {
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
    },
    /// A task was ready but no worker was eligible; it was held (re-enqueued).
    NoEligibleWorker(TaskId),
    /// The ready queue is empty.
    Empty,
}

/// A planned dispatch step, separated from the *push* so the same place+lease logic feeds
/// both the in-process [`Bus`] (sim) and the live Redis inbox ([`OutboundChannel`]).
enum DispatchPlan {
    /// A task was leased to `worker`; push `assignment` (boxed — it dwarfs the `Idle`
    /// variant), then report `step`.
    Push {
        step: DispatchStep,
        worker: WorkerId,
        assignment: Box<Assignment>,
    },
    /// Nothing to push: a task held with no eligible worker, or an empty ready queue.
    Idle(DispatchStep),
}

/// A decided submission, separated from the verify-request *push* so the same sampling gate
/// feeds both the [`Bus`] (sim) and the live verifier inbox ([`OutboundChannel`]).
enum SubmissionPlan {
    /// Stale-epoch / wrong-holder write — the slow zombie, rejected at the store (§1.1).
    RejectedZombie,
    /// Sampled for verification — the caller pushes this `VerifyRequest` to the verifier.
    Sampled(Box<VerifyRequest>),
    /// Unsampled — already content-addressed released; nothing to push.
    Accepted(OutputRef),
}

/// In-process push fabric — **test-only** since Phase 6 (the live path pushes onto the
/// Redis inboxes via [`OutboundChannel`]). The sim pushes encoded `core::proto` messages
/// here and pulls/decodes them over the wire codec (workers receive, never self-select —
/// the legacy reversal), exercising the real codec without a Redis round trip.
#[derive(Default)]
pub struct Bus {
    worker: Mutex<HashMap<WorkerId, VecDeque<Vec<u8>>>>,
    verifier: Mutex<VecDeque<Vec<u8>>>,
}

impl Bus {
    /// `LPUSH` an encoded `Assignment` to a worker's inbox.
    pub fn push_assignment(&self, worker: WorkerId, a: &Assignment) {
        self.lock_worker()
            .entry(worker)
            .or_default()
            .push_back(encode(a));
    }

    /// `BRPOP`-equivalent: pull and decode the next `Assignment` for a worker, if any.
    pub fn pop_assignment(&self, worker: WorkerId) -> Option<Assignment> {
        let bytes = self.lock_worker().get_mut(&worker)?.pop_front()?;
        decode(&bytes).ok()
    }

    /// `LPUSH` an encoded `VerifyRequest` to the verifier inbox.
    pub fn push_verify(&self, req: &VerifyRequest) {
        self.lock_verifier().push_back(encode(req));
    }

    /// Pull and decode the next `VerifyRequest`, if any.
    pub fn pop_verify(&self) -> Option<VerifyRequest> {
        let bytes = self.lock_verifier().pop_front()?;
        decode(&bytes).ok()
    }

    fn lock_worker(&self) -> std::sync::MutexGuard<'_, HashMap<WorkerId, VecDeque<Vec<u8>>>> {
        self.worker.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn lock_verifier(&self) -> std::sync::MutexGuard<'_, VecDeque<Vec<u8>>> {
        self.verifier.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The content address of a blob and the commitment binding it. `OutputRef` is the leading
/// 128 bits of the blob's hash leaf (the Phase 3 `check_binding` address); the commitment
/// is the frozen single-leaf Merkle root `Commitment::commit(&[leaf])`. The worker computes
/// `leaf = SHA-256(ciphertext)` in Phase 5; here a caller supplies the leaf.
#[must_use]
pub fn content_address(blob_leaf: [u8; 32]) -> (OutputRef, Commitment) {
    let commitment = Commitment::commit(&[blob_leaf]);
    let mut head = [0u8; 16];
    head.copy_from_slice(&blob_leaf[..16]);
    (OutputRef(u128::from_be_bytes(head)), commitment)
}

/// The `core`-driven control-plane engine over a [`Store`] and an injectable RNG.
pub struct Engine<S: Store, R: Rng = StdRng> {
    store: S,
    bus: Bus,
    sampler: Mutex<Sampler<R>>,
    /// Hot-path cache of worker tiers (derived from standing; refreshed on each
    /// `update_standing`). Placement and sampling read it without a store round trip.
    tiers: Mutex<HashMap<WorkerId, Tier>>,
    /// Content-addressed release index, keyed by `OutputRef` — never the task id (§7).
    release: Mutex<HashMap<OutputRef, Released>>,
    cfg: EngineConfig,
}

impl<S: Store, R: Rng> Engine<S, R> {
    /// Build an engine over `store`, `cfg`, and an injected `sampler` (OS-seeded in prod,
    /// seeded/forced in tests).
    pub fn new(store: S, cfg: EngineConfig, sampler: Sampler<R>) -> Self {
        Engine {
            store,
            bus: Bus::default(),
            sampler: Mutex::new(sampler),
            tiers: Mutex::new(HashMap::new()),
            release: Mutex::new(HashMap::new()),
            cfg,
        }
    }

    /// The push fabric (for the sim / worker / verifier to pull from).
    pub fn bus(&self) -> &Bus {
        &self.bus
    }

    /// The underlying store (for injection helpers and test assertions).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The cached tier of a worker, if registered.
    pub fn cached_tier(&self, worker: WorkerId) -> Option<Tier> {
        self.lock_tiers().get(&worker).copied()
    }

    /// Look up a released output by its content address.
    pub fn released(&self, output: OutputRef) -> Option<Released> {
        self.lock_release().get(&output).copied()
    }

    /// How many distinct outputs have been released.
    pub fn release_count(&self) -> usize {
        self.lock_release().len()
    }

    /// Lazy binding (§7): a consumer fetched a blob with hash `fetched_leaf`; re-derive its
    /// content address + commitment and confirm they match what was released. A swapped blob
    /// yields a different address/commitment, so this returns `false` — the anti-swap check.
    #[must_use]
    pub fn confirm_release(&self, fetched_leaf: [u8; 32]) -> bool {
        let (output, commitment) = content_address(fetched_leaf);
        self.lock_release()
            .get(&output)
            .is_some_and(|r| r.commitment == commitment)
    }

    /// Intake gate (§6): the injector calls this before [`Engine::inject`] with the observed
    /// ready-queue depth; it sheds at the Little's-law global cap.
    pub fn admit(&self, ready_depth: u32) -> Result<(), Backpressure> {
        self.cfg.sizing.admit(ready_depth)
    }

    /// Register (or refresh the liveness of) a worker. New workers start `Pristine`; a
    /// refresh preserves the cached tier and only updates the heartbeat clock.
    pub fn register_worker(&self, worker: WorkerId, now: LogicalTime) -> Result<(), EngineError> {
        self.store.register_worker(worker, now)?;
        self.lock_tiers().entry(worker).or_insert(Tier::Pristine);
        Ok(())
    }

    /// Inject a workload directly (there is no ingest API, locked decision #2): create the
    /// task and enqueue it ready. The injector applies [`Engine::admit`] beforehand.
    pub fn inject(
        &self,
        task: Task,
        priority: Priority,
        now: LogicalTime,
    ) -> Result<(), EngineError> {
        let id = task.id;
        self.store.create_task(task)?;
        self.store.enqueue_ready(id, priority, now)?;
        Ok(())
    }

    /// Plan one dispatch step **without** pushing: pop the next ready task, pick the
    /// least-loaded eligible worker, atomically lease (epoch via the store), and build the
    /// `Assignment`. If no worker is eligible the task is held (re-enqueued). Separated from
    /// the push so the same place+lease logic feeds both the in-process [`Bus`] (sim) and
    /// the live Redis inbox ([`OutboundChannel`]). Workers receive; they never self-select.
    fn plan_dispatch(&self, now: LogicalTime) -> Result<DispatchPlan, EngineError> {
        let Some(task) = self.store.pop_ready()? else {
            return Ok(DispatchPlan::Idle(DispatchStep::Empty));
        };
        let candidates: Vec<(WorkerId, Tier)> =
            self.lock_tiers().iter().map(|(&w, &t)| (w, t)).collect();
        let elig = Eligibility {
            now,
            liveness_window: self.cfg.liveness_window,
            in_flight_cap: self.cfg.in_flight_cap(),
        };
        match place::select_worker(&self.store, &candidates, &elig)? {
            Some(worker) => {
                let deadline = LogicalTime(now.0 + self.cfg.lease_ttl);
                let epoch = self.store.lease(task, worker, deadline)?;
                let t = self.store.load(task)?.ok_or(EngineError::TaskNotFound(task))?;
                let assignment = Assignment {
                    task,
                    source: source_of(&t.kind),
                    kind: t.kind,
                    lease: Lease {
                        holder: worker,
                        epoch,
                        deadline,
                    },
                };
                Ok(DispatchPlan::Push {
                    step: DispatchStep::Dispatched {
                        task,
                        worker,
                        epoch,
                    },
                    worker,
                    assignment: Box::new(assignment),
                })
            }
            None => {
                // Hold the task ready for a later tick; backpressure governs intake.
                self.store
                    .enqueue_ready(task, self.cfg.default_priority, now)?;
                Ok(DispatchPlan::Idle(DispatchStep::NoEligibleWorker(task)))
            }
        }
    }

    /// One dispatch step over the **in-process [`Bus`]** (the `#[cfg(test)]` sim). Plans the
    /// dispatch, then pushes the `Assignment` onto the worker's `Bus` inbox. The live binary
    /// uses [`Engine::dispatch_one_live`] (real Redis inbox) instead.
    pub fn dispatch_one(&self, now: LogicalTime) -> Result<DispatchStep, EngineError> {
        match self.plan_dispatch(now)? {
            DispatchPlan::Push {
                step,
                worker,
                assignment,
            } => {
                self.bus.push_assignment(worker, &assignment);
                Ok(step)
            }
            DispatchPlan::Idle(step) => Ok(step),
        }
    }

    /// Handle a heartbeat: extend the lease iff `(worker, epoch)` match, and refresh the
    /// worker's liveness. A stale/wrong heartbeat (a reclaimed worker) is rejected (§1.1).
    pub fn on_heartbeat(
        &self,
        msg: HeartbeatMsg,
        now: LogicalTime,
    ) -> Result<HeartbeatOutcome, EngineError> {
        let deadline = LogicalTime(now.0 + self.cfg.lease_ttl);
        match self
            .store
            .extend_lease(msg.task, msg.worker, msg.epoch, deadline)
        {
            Ok(()) => {
                self.store.register_worker(msg.worker, now)?;
                Ok(HeartbeatOutcome::Extended)
            }
            Err(StoreError::StaleEpoch { .. } | StoreError::WrongHolder { .. }) => {
                Ok(HeartbeatOutcome::Rejected)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Decide a worker submission **without** pushing the verify request: persist the
    /// epoch-fenced `Leased → Submitted` (the slow zombie is rejected here), run the
    /// sampling gate, and — when unsampled — content-address the release. When sampled it
    /// returns the `VerifyRequest` for the caller to push. Separated from the push so the
    /// same gate feeds both the [`Bus`] (sim) and the live verifier inbox.
    fn decide_submission(&self, msg: SubmissionMsg) -> Result<SubmissionPlan, EngineError> {
        match self
            .store
            .submit(msg.task, msg.worker, msg.epoch, msg.commitment, msg.output)
        {
            Ok(()) => {}
            Err(StoreError::StaleEpoch { .. } | StoreError::WrongHolder { .. }) => {
                return Ok(SubmissionPlan::RejectedZombie);
            }
            Err(e) => return Err(e.into()),
        }

        // Sampling gate (§5.3): Bernoulli(p_tier) over the worker's cached tier.
        let tier = self.cached_tier(msg.worker).unwrap_or(Tier::Pristine);
        let sampled = self.lock_sampler().sample_tier(tier);
        self.store.select_or_accept(msg.task, sampled)?;

        if sampled {
            let t = self
                .store
                .load(msg.task)?
                .ok_or(EngineError::TaskNotFound(msg.task))?;
            Ok(SubmissionPlan::Sampled(Box::new(VerifyRequest {
                task: msg.task,
                kind: t.kind,
                commitment: msg.commitment,
                output: msg.output,
            })))
        } else {
            // Unsampled: content-addressed release, bound lazily by the recorded commitment.
            self.do_release(msg.output, msg.commitment);
            Ok(SubmissionPlan::Accepted(msg.output))
        }
    }

    /// Handle a worker submission over the **in-process [`Bus`]** (the `#[cfg(test)]` sim):
    /// decide it, and on a sampled draw push the `VerifyRequest` onto the `Bus`. The live
    /// binary uses [`Engine::on_submission_live`] (real verifier inbox) instead.
    pub fn on_submission(
        &self,
        msg: SubmissionMsg,
        _now: LogicalTime,
    ) -> Result<SubmitOutcome, EngineError> {
        match self.decide_submission(msg)? {
            SubmissionPlan::RejectedZombie => Ok(SubmitOutcome::RejectedZombie),
            SubmissionPlan::Sampled(req) => {
                self.bus.push_verify(&req);
                Ok(SubmitOutcome::Sampled)
            }
            SubmissionPlan::Accepted(output) => Ok(SubmitOutcome::Accepted(output)),
        }
    }

    /// Handle a verifier verdict — the core-driven path. Load the task, compute the actions
    /// via `core::Task::apply(VerifyOutcome)`, persist the transition through the store, and
    /// execute the returned `TaskAction`s.
    pub fn on_verify_result(
        &self,
        result: VerifyResult,
        now: LogicalTime,
    ) -> Result<VerifyOutcome, EngineError> {
        let mut task = self
            .store
            .load(result.task)?
            .ok_or(EngineError::TaskNotFound(result.task))?;
        // Capture holder + commitment from the Verifying state before the transition.
        let holder =
            holder_of(&task.state).ok_or(EngineError::UnexpectedState(result.task, "verdict"))?;
        let commitment = commitment_of(&task.state);

        let actions = task
            .apply(TaskEvent::VerifyOutcome {
                passed: result.passed,
            })
            .map_err(|_| EngineError::UnexpectedState(result.task, "VerifyOutcome"))?;
        // Durable transition (epoch CAS — belt and suspenders).
        self.store.verify_outcome(result.task, result.passed)?;

        // Rich reputation (§6 — closes Phase 4's coarse-reputation seam): apply the verifier's
        // full `VerifyDetail` to the holder's standing on EVERY verdict, not just the failures
        // `core` emits `EmitReputation` for. This is what credits a pass (`Ok`, slow trust) and
        // bans a provable `CommitmentMismatch` in one step; `Inconclusive` changes nothing. A
        // worker that deregistered in the meantime is simply skipped (the verdict still stands).
        match self.store.record_verdict(holder, result.detail) {
            Ok(tier) => {
                self.lock_tiers().insert(holder, tier);
            }
            Err(StoreError::UnknownWorker(_)) => {}
            Err(e) => return Err(e.into()),
        }

        let mut outcome = if result.passed {
            VerifyOutcome::Accepted(OutputRef(0))
        } else {
            VerifyOutcome::Failed
        };
        for action in &actions {
            match action {
                TaskAction::NotifyAccepted(output) => {
                    let c = commitment
                        .ok_or(EngineError::UnexpectedState(result.task, "accept"))?;
                    self.do_release(*output, c);
                    outcome = VerifyOutcome::Accepted(*output);
                }
                TaskAction::Requeue => {
                    self.store
                        .enqueue_ready(result.task, self.cfg.default_priority, now)?;
                    outcome = VerifyOutcome::Requeued;
                }
                TaskAction::EmitReputation(_) => {
                    // Reputation is now applied above from the rich `VerifyDetail` via
                    // `store.record_verdict` (§6). `core` still emits this coarse delta on a
                    // fail, but the detail-aware path supersedes it — applying both would
                    // double-penalize. Intentionally a no-op.
                }
                TaskAction::MarkFailed(_) => { /* terminal; nothing to push */ }
                TaskAction::IssueChallenge(_) => { /* not produced by VerifyOutcome */ }
            }
        }
        Ok(outcome)
    }

    /// Reclaim loop body (§8): the single authority. Expired leases return to `Pending` and
    /// are re-enqueued inside the store; returns the reclaimed task ids.
    pub fn reclaim(&self, now: LogicalTime) -> Result<Vec<TaskId>, EngineError> {
        Ok(self.store.reclaim_expired(now)?)
        // Note: a per-worker Timeout standing penalty (core's LeaseExpired EmitReputation)
        // needs the timed-out holder, which reclaim_expired does not return; attributing it
        // is a store-return enrichment. Safety (fencing) does not depend on it.
    }

    fn do_release(&self, output: OutputRef, commitment: Commitment) {
        self.lock_release()
            .insert(output, Released { output, commitment });
    }

    fn lock_tiers(&self) -> std::sync::MutexGuard<'_, HashMap<WorkerId, Tier>> {
        self.tiers.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn lock_release(&self) -> std::sync::MutexGuard<'_, HashMap<OutputRef, Released>> {
        self.release.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn lock_sampler(&self) -> std::sync::MutexGuard<'_, Sampler<R>> {
        self.sampler.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The **live** push transport (phase6-spec.md §2): the same engine over a store that also
/// backs real Redis inbox lists ([`OutboundChannel`]). These mirror [`Engine::dispatch_one`]
/// / [`Engine::on_submission`] but `LPUSH` the encoded message straight onto the worker /
/// verifier inbox instead of the in-process [`Bus`], so the whole transport is Redis
/// end-to-end and measurable. The `sched` binary drives these; the sim keeps the `Bus`.
impl<S: Store + OutboundChannel, R: Rng> Engine<S, R> {
    /// One dispatch step that `LPUSH`es the encoded `Assignment` onto the worker's Redis
    /// inbox (`{prefix}:inbox:{worker}`), the list the real `worker` bin `BRPOP`s. Same
    /// place+lease decision as [`Engine::dispatch_one`]; only the push fabric differs.
    pub fn dispatch_one_live(&self, now: LogicalTime) -> Result<DispatchStep, EngineError> {
        match self.plan_dispatch(now)? {
            DispatchPlan::Push {
                step,
                worker,
                assignment,
            } => {
                self.store.push_assignment(worker, &encode(&*assignment))?;
                Ok(step)
            }
            DispatchPlan::Idle(step) => Ok(step),
        }
    }

    /// Handle a worker submission and, on a sampled draw, `LPUSH` the encoded `VerifyRequest`
    /// onto `{prefix}:inbox:verifier`, the list the real `verifier` bin `BRPOP`s. Same
    /// epoch-fenced gate as [`Engine::on_submission`]; only the push fabric differs.
    pub fn on_submission_live(
        &self,
        msg: SubmissionMsg,
        _now: LogicalTime,
    ) -> Result<SubmitOutcome, EngineError> {
        match self.decide_submission(msg)? {
            SubmissionPlan::RejectedZombie => Ok(SubmitOutcome::RejectedZombie),
            SubmissionPlan::Sampled(req) => {
                self.store.push_verify_request(&encode(&*req))?;
                Ok(SubmitOutcome::Sampled)
            }
            SubmissionPlan::Accepted(output) => Ok(SubmitOutcome::Accepted(output)),
        }
    }
}

/// The source segment of a task (for the `Assignment`); a stitch has no single source.
fn source_of(kind: &TaskKind) -> SegmentRef {
    match kind {
        TaskKind::Transcode(spec) => spec.source,
        TaskKind::Stitch(_) => SegmentRef(0),
    }
}

/// The holder of a holder-bearing state, if any.
fn holder_of(state: &TaskState) -> Option<WorkerId> {
    match state {
        TaskState::Leased { holder, .. }
        | TaskState::Submitted { holder, .. }
        | TaskState::Verifying { holder, .. } => Some(*holder),
        _ => None,
    }
}

/// The recorded commitment of a state that carries one.
fn commitment_of(state: &TaskState) -> Option<Commitment> {
    match state {
        TaskState::Submitted { commitment, .. }
        | TaskState::Verifying { commitment, .. }
        | TaskState::Accepted { commitment, .. } => Some(*commitment),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_address_binds_the_leaf_and_swaps_are_detectable() {
        let leaf = [9u8; 32];
        let (output, commitment) = content_address(leaf);
        // The commitment is the frozen single-leaf Merkle root over the blob hash.
        assert_eq!(commitment, Commitment::commit(&[leaf]));
        // A different blob → a different content address AND a different commitment.
        let (output2, commitment2) = content_address([10u8; 32]);
        assert_ne!(output, output2);
        assert_ne!(commitment, commitment2);
    }

    #[test]
    fn bus_round_trips_messages_over_the_wire_codec() {
        let bus = Bus::default();
        assert!(bus.pop_verify().is_none());
        assert!(bus.pop_assignment(WorkerId(1)).is_none());
        let req = VerifyRequest {
            task: TaskId(7),
            kind: proctor_core::TaskKind::Transcode(proctor_core::TranscodeSpec {
                job: proctor_core::JobId(1),
                segment: proctor_core::SegmentId(7),
                profile: proctor_core::TargetProfile {
                    codec: proctor_core::Codec::H264,
                    width: 1280,
                    height: 720,
                    bitrate_kbps: 3000,
                    container: proctor_core::Container::Mp4,
                },
                source: SegmentRef(7),
            }),
            commitment: Commitment([3u8; 32]),
            output: OutputRef(42),
        };
        bus.push_verify(&req);
        assert_eq!(bus.pop_verify().unwrap().task, TaskId(7));
        assert!(bus.pop_verify().is_none());
    }
}
