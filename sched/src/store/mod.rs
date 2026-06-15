//! `store` — the atomic, epoch-fenced operation contract and its reference impl.
//!
//! The Store discipline (phase4-spec.md §2, the NORTH-STAR sans-IO idea applied to the
//! control plane): the scheduler's *decision* logic — placement, reputation, sampling,
//! backpressure, engine — is written over the [`Store`] trait, free of Redis specifics.
//! Two implementations, [`memory::MemoryStore`] (the reference, this session) and the
//! Redis store (Session 2), are held to ONE `contract` suite — the differential oracle,
//! the same way one frozen `core` drove eleven server models. The Redis Lua atomics are
//! correct **iff** they pass the same contract as the in-memory reference, including the
//! slow-zombie test (§3.3).
//!
//! ## The contract (§3.1)
//! Every state-mutating operation is **atomic** and **epoch-fenced**: a write naming
//! `(worker, epoch)` is applied *iff* it matches the task's current lease, else rejected
//! without mutation. This mirrors [`proctor_core::Task::apply`]'s `Err(StaleEpoch)` /
//! `WrongHolder` at the durable layer — defense in depth, so even a restarted or racing
//! `sched` instance cannot accept a stale-epoch write.
//!
//! The in-memory reference makes that mirroring literal: it holds each task as a frozen
//! [`proctor_core::Task`] and drives every transition through `Task::apply`, mapping
//! [`proctor_core::TransitionError`] to [`StoreError`]. The transition authority *is*
//! `core`; the Redis store re-derives the identical rule in Lua and must match this
//! reference on the shared suite.

pub mod memory;
pub mod redis;

#[cfg(test)]
mod contract;

pub use memory::MemoryStore;
pub use redis::RedisStore;

use proctor_core::{
    Commitment, Epoch, LogicalTime, OutputRef, ReputationDelta, Task, TaskId, TransitionError,
    VerifyDetail, WorkerId,
};
use thiserror::Error;

/// Priority class for the ready queue. Higher is more urgent; the placement layer
/// (Session 3) adds aging on top so a low-priority task cannot starve indefinitely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Priority(pub u32);

impl Default for Priority {
    /// A normal-priority task. The bench injector (no ingest API) chooses the class.
    fn default() -> Self {
        Priority(0)
    }
}

/// A worker's reputation tier. The ordered non-terminal tiers (`Pristine`, `Watch`,
/// `Suspect`) each map to a sampling fraction `p_tier` in the policy module; the two
/// eligibility states (`Suspended`, `Banned`) exclude the worker from dispatch.
///
/// **Scope:** the *policy* — the asymmetric standing updates, the tier→`p` mapping, and
/// the hard `P_MIN = 0.02` floor (§5) — lands in `reputation.rs` (Session 4). The store
/// only persists a worker's standing and reports the tier it currently sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Pristine,
    Watch,
    Suspect,
    Suspended,
    Banned,
}

impl Tier {
    /// Whether a worker in this tier may receive dispatch. Suspended/Banned workers are
    /// ineligible — the loop is closed; reputation *bites*, unlike the legacy
    /// observe-only system (§5.2).
    #[must_use]
    pub fn is_eligible(self) -> bool {
        !matches!(self, Tier::Suspended | Tier::Banned)
    }
}

/// The penalty a coarse [`ReputationDelta`] subtracts from standing — delegated to the
/// authoritative [`crate::reputation`] policy (Session 4), so the store's `update_standing`
/// and the engine's rich path share one set of magnitudes. Exposed for the Redis store,
/// whose Lua `HINCRBY` needs the magnitude as a plain integer; both stores use it, so the
/// differential oracle compares like with like.
pub(crate) fn standing_penalty(delta: ReputationDelta) -> i32 {
    crate::reputation::penalty(delta)
}

/// Map an accumulated reputation standing to a tier — delegated to the authoritative
/// [`crate::reputation::tier_of`] (Session 4), so a given standing maps to the same tier
/// regardless of backend or call path.
pub(crate) fn tier_from_standing(standing: i32) -> Tier {
    crate::reputation::tier_of(standing)
}

/// A snapshot of a worker's load, read by the placement layer (Session 3) to choose the
/// least-loaded eligible worker.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkerLoad {
    /// Primary load metric: count of leases held in a non-terminal state.
    pub in_flight: u32,
    /// Tiebreak: EWMA of recent completion throughput from heartbeats. The smoothing
    /// factor and the heartbeat-driven update land with `place.rs` (Session 3); the
    /// reference store carries the field and reports it.
    pub ewma_throughput: f64,
    /// Liveness: the logical time of the worker's last registration/heartbeat.
    pub last_heartbeat: LogicalTime,
}

/// Why a store operation was rejected. The fencing variants mirror
/// [`proctor_core::TransitionError`] exactly so the durable layer rejects a stale write
/// with the same diagnosis the in-memory state machine does.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    /// The zombie-killer: a holder-action (or lease expiry) presented an epoch that is
    /// not the current lease's. Mirrors `TransitionError::StaleEpoch`.
    #[error("stale epoch: event presented {event_epoch:?}, current is {current:?}")]
    StaleEpoch { event_epoch: Epoch, current: Epoch },
    /// Right epoch, wrong worker.
    #[error("wrong holder: event from {event_worker:?}, current holder is {current:?}")]
    WrongHolder {
        event_worker: WorkerId,
        current: WorkerId,
    },
    /// The event is not valid in the task's current state at all.
    #[error("illegal transition: {event} is not valid in state {state}")]
    IllegalTransition {
        state: &'static str,
        event: &'static str,
    },
    /// The task is already `Accepted`/`Failed` and absorbs every event.
    #[error("task is terminal (Accepted/Failed)")]
    Terminal,
    /// No task with this id is known to the store.
    #[error("no such task: {0:?}")]
    NoSuchTask(TaskId),
    /// A task with this id already exists (create is not idempotent).
    #[error("task already exists: {0:?}")]
    TaskExists(TaskId),
    /// No worker with this id is registered.
    #[error("unknown worker: {0:?}")]
    UnknownWorker(WorkerId),
    /// A backend/transport failure (used by the Redis store, Session 2).
    #[error("store backend error: {0}")]
    Backend(String),
}

impl From<TransitionError> for StoreError {
    /// Lift `core`'s in-memory rejection into the store's error so the durable layer
    /// speaks the same fencing vocabulary as `Task::apply`.
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::StaleEpoch {
                event_epoch,
                current,
            } => StoreError::StaleEpoch {
                event_epoch,
                current,
            },
            TransitionError::WrongHolder {
                event_worker,
                current,
            } => StoreError::WrongHolder {
                event_worker,
                current,
            },
            TransitionError::IllegalTransition { state, event } => {
                StoreError::IllegalTransition { state, event }
            }
            TransitionError::Terminal => StoreError::Terminal,
        }
    }
}

/// The atomic, epoch-fenced durable contract (§3.1). Every state-mutating op is a
/// compare-and-set against the task's current lease; a stale-epoch write is rejected
/// without mutation. Two impls (memory + Redis) are proven equivalent by the shared
/// `contract` suite.
///
/// All operations take `&self`: a `Store` is a handle over shared durable state
/// (an in-memory `Mutex`, a Redis connection), so concurrent callers share one logical
/// store. There is no async — the Redis client is synchronous (locked decision #1).
pub trait Store {
    /// Insert a fresh `Pending` task. Fails with [`StoreError::TaskExists`] if the id is
    /// already present. There is no ingest API (locked decision #2): the bench injector
    /// and the engine create tasks directly through the store.
    fn create_task(&self, task: Task) -> Result<(), StoreError>;

    /// Read a task snapshot, or `None` if unknown. Read-only; never mutates.
    fn load(&self, task: TaskId) -> Result<Option<Task>, StoreError>;

    /// Lease a `Pending` task to `worker`. Assigns `epoch = epoch_hw.next()` atomically
    /// (so a reclaimed task is always re-leased at a strictly greater epoch) and records
    /// the deadline. Fails if the task is not `Pending`.
    fn lease(
        &self,
        task: TaskId,
        worker: WorkerId,
        deadline: LogicalTime,
    ) -> Result<Epoch, StoreError>;

    /// Heartbeat: extend the deadline **iff** `(worker, epoch)` match the current lease,
    /// else `StaleEpoch`/`WrongHolder`. A heartbeat cannot resurrect a reclaimed lease.
    fn extend_lease(
        &self,
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
        new_deadline: LogicalTime,
    ) -> Result<(), StoreError>;

    /// Worker submission: record `(commitment, output)` and move `Leased -> Submitted`
    /// **iff** `(worker, epoch)` match. THE ZOMBIE-KILLER: a stale epoch ⇒
    /// [`StoreError::StaleEpoch`], no mutation (§3.3).
    fn submit(
        &self,
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
        commitment: Commitment,
        output: OutputRef,
    ) -> Result<(), StoreError>;

    /// Probabilistic gate: `Submitted -> Verifying` (sampled) or `Submitted -> Accepted`
    /// (unsampled, content-addressed). The sampling *decision* (`Bernoulli(p_tier)`) is
    /// the policy layer's (Session 4); the actual challenge frames are chosen by the
    /// engine/verifier (Session 5), so the store records a `Verifying` transition with an
    /// empty placeholder challenge.
    fn select_or_accept(&self, task: TaskId, sampled: bool) -> Result<(), StoreError>;

    /// Apply a verifier verdict: `Verifying -> Accepted` (pass) or `-> Pending`/`Failed`
    /// (fail, retry-aware per [`proctor_core::MAX_RETRIES`]).
    fn verify_outcome(&self, task: TaskId, passed: bool) -> Result<(), StoreError>;

    /// THE SINGLE RECLAIM AUTHORITY: atomically find leases whose deadline has lapsed
    /// (`now >= deadline`), return them to `Pending`, and re-enqueue them to the ready
    /// index. The strictly-greater epoch is minted on the next [`Store::lease`] via
    /// `epoch_hw.next()` (matching `core`'s frozen semantics), so a zombie's stale epoch
    /// can never match. There is **no second reclaim path** (no stream PEL / XAUTOCLAIM).
    /// Returns the reclaimed task ids.
    fn reclaim_expired(&self, now: LogicalTime) -> Result<Vec<TaskId>, StoreError>;

    /// Enqueue a ready (`Pending`) task at `priority`. `now` is the enqueue time, used by
    /// the placement layer for FIFO-with-aging ordering.
    fn enqueue_ready(
        &self,
        task: TaskId,
        priority: Priority,
        now: LogicalTime,
    ) -> Result<(), StoreError>;

    /// Pop the highest-priority ready task (FIFO within a priority class), or `None` if
    /// the queue is empty. Aging (promoting starved low-priority tasks) is layered on in
    /// `place.rs` (Session 3); the store provides priority-then-FIFO ordering.
    fn pop_ready(&self) -> Result<Option<TaskId>, StoreError>;

    /// Register (or refresh the liveness of) a worker in the registry.
    fn register_worker(&self, worker: WorkerId, now: LogicalTime) -> Result<(), StoreError>;

    /// Read a worker's current load (in-flight count, EWMA throughput, last heartbeat).
    fn worker_load(&self, worker: WorkerId) -> Result<WorkerLoad, StoreError>;

    /// Apply a reputation delta to a worker's standing and return its resulting tier.
    /// The asymmetric magnitudes, the `CommitmentMismatch`-is-heaviest weighting, and the
    /// tier→`p` floor are the policy module's (Session 4); the store persists standing
    /// and reports the tier. `core::ReputationDelta` carries only penalties, so this op
    /// only ever lowers standing.
    fn update_standing(&self, worker: WorkerId, delta: ReputationDelta) -> Result<Tier, StoreError>;

    /// Apply a verifier verdict's **rich** [`VerifyDetail`] to a worker's standing and
    /// return the resulting tier (phase5-spec.md §6 — closes Phase 4's coarse-reputation
    /// seam). Unlike [`Store::update_standing`], this carries the full detail, so it can
    /// both *credit* a pass ([`VerifyDetail::Ok`], slow trust, capped at the baseline) and
    /// apply the heaviest penalty for a provable [`VerifyDetail::CommitmentMismatch`]; an
    /// [`VerifyDetail::Inconclusive`] leaves standing unchanged. The magnitudes are the
    /// authoritative [`crate::reputation`] policy's, so both backends agree (the
    /// differential oracle).
    fn record_verdict(&self, worker: WorkerId, detail: VerifyDetail) -> Result<Tier, StoreError>;
}

/// The live **return channel** (phase5-spec.md §6): workers and the verifier `LPUSH`
/// tagged holder-action frames onto a single `sched:inbound` list; `sched::loops` `BRPOP`s
/// and routes them. Only the Redis store backs a real list — the in-memory reference uses
/// the in-process [`crate::engine::Bus`] in the sim — so this capability is separate from
/// the [`Store`] trait and implemented by the Redis backend alone.
pub trait InboundChannel {
    /// `BRPOP` one tagged frame off the `sched:inbound` return list, blocking up to
    /// `timeout_secs`. `Ok(None)` on timeout. The frame is `[tag byte] ++ postcard(msg)`;
    /// [`crate::loops::route_inbound`] decodes the tag and dispatches.
    fn brpop_inbound(&self, timeout_secs: u64) -> Result<Option<Vec<u8>>, StoreError>;
}
