//! `memory` — the deterministic in-memory [`Store`] reference (§2, §3).
//!
//! This is the reference semantics the Redis Lua atomics (Session 2) must match on the
//! shared `contract` suite. It holds each task as a frozen [`Task`] behind a single
//! `Mutex`, so every operation is atomic by construction, and it drives **every**
//! state transition through [`Task::apply`] — the frozen `core` transition authority.
//! The epoch-fenced compare-and-set is therefore not re-implemented here; it is
//! *inherited* from `core`, which is exactly what makes this the trustworthy reference.
//!
//! Where the store owns state `core` does not (the ready queue, the worker registry,
//! per-task priority), that state lives in [`Inner`]; the lease/epoch/state itself is
//! always read out of the `Task`.

use std::collections::HashMap;
use std::sync::Mutex;

use proctor_core::{
    Challenge, Commitment, Epoch, LogicalTime, OutputRef, ReputationDelta, Task, TaskEvent, TaskId,
    TaskState, WorkerId,
};

use super::{standing_penalty, tier_from_standing, Priority, Store, StoreError, Tier, WorkerLoad};

/// A worker's registry entry. Standing accumulates reputation penalties; the tier is
/// derived from it (the policy mapping is finalized in Session 4).
#[derive(Debug, Clone, Copy)]
struct WorkerEntry {
    last_heartbeat: LogicalTime,
    /// EWMA of completion throughput; updated from heartbeats by `place.rs` (Session 3).
    ewma_throughput: f64,
    /// Accumulated reputation standing. Starts at 0 (Pristine); `core::ReputationDelta`
    /// carries only penalties, so this only decreases here.
    standing: i32,
}

/// One ready-queue slot. Ordering is priority-first, then FIFO by enqueue time, with a
/// monotonic sequence number as the final tiebreak for entries enqueued at the same
/// logical time (so `pop_ready` is fully deterministic).
#[derive(Debug, Clone, Copy)]
struct ReadyEntry {
    task: TaskId,
    priority: Priority,
    enqueued: LogicalTime,
    seq: u64,
}

#[derive(Debug, Default)]
struct Inner {
    tasks: HashMap<TaskId, Task>,
    /// Last-known priority per task, so a reclaim can re-enqueue at the same class.
    priority: HashMap<TaskId, Priority>,
    ready: Vec<ReadyEntry>,
    workers: HashMap<WorkerId, WorkerEntry>,
    /// Monotonic FIFO tiebreak counter for `ready`.
    seq: u64,
}

impl Inner {
    /// Push a task onto the ready queue, recording its priority for later re-enqueue.
    fn push_ready(&mut self, task: TaskId, priority: Priority, now: LogicalTime) {
        self.priority.insert(task, priority);
        let seq = self.seq;
        self.seq += 1;
        self.ready.push(ReadyEntry {
            task,
            priority,
            enqueued: now,
            seq,
        });
    }

    /// Count leases held by `worker` in a non-terminal state. Derived by scanning rather
    /// than maintained as a counter, so in-flight accounting can never drift from the
    /// authoritative task states.
    fn in_flight(&self, worker: WorkerId) -> u32 {
        self.tasks
            .values()
            .filter(|t| match &t.state {
                TaskState::Leased { holder, .. }
                | TaskState::Submitted { holder, .. }
                | TaskState::Verifying { holder, .. } => *holder == worker,
                _ => false,
            })
            .count() as u32
    }
}

/// In-memory capture of the live dispatch transport ([`super::OutboundChannel`]) — the
/// in-process analogue of the Redis inbox lists, so the engine's live push path
/// (`dispatch_one_live` / `on_submission_live`) is exercisable without a Redis. A diagnostic
/// tap: drained via [`MemoryStore::take_pushed_assignments`] /
/// [`MemoryStore::take_pushed_verify_requests`].
#[derive(Debug, Default)]
struct Outbox {
    assignments: Vec<(WorkerId, Vec<u8>)>,
    verify_requests: Vec<Vec<u8>>,
}

/// The deterministic in-memory [`Store`] reference. Cheap to construct; clone-free
/// sharing is via `&MemoryStore` (all ops take `&self`).
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
    outbox: Mutex<Outbox>,
}

impl MemoryStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain the captured pushed `Assignment` frames `(worker, encode(assignment))` from the
    /// live dispatch transport tap (the in-memory analogue of `{prefix}:inbox:{worker}`).
    #[must_use]
    pub fn take_pushed_assignments(&self) -> Vec<(WorkerId, Vec<u8>)> {
        std::mem::take(&mut self.lock_outbox().assignments)
    }

    /// Drain the captured pushed `VerifyRequest` frames `encode(req)` from the live transport
    /// tap (the in-memory analogue of `{prefix}:inbox:verifier`).
    #[must_use]
    pub fn take_pushed_verify_requests(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.lock_outbox().verify_requests)
    }

    fn lock_outbox(&self) -> std::sync::MutexGuard<'_, Outbox> {
        self.outbox.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock the inner state. A poisoned lock is unrecoverable program state, so we
    /// surface it as a backend error rather than panicking inside a `Store` op.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for MemoryStore {
    fn create_task(&self, task: Task) -> Result<(), StoreError> {
        let mut inner = self.lock();
        if inner.tasks.contains_key(&task.id) {
            return Err(StoreError::TaskExists(task.id));
        }
        inner.tasks.insert(task.id, task);
        Ok(())
    }

    fn load(&self, task: TaskId) -> Result<Option<Task>, StoreError> {
        Ok(self.lock().tasks.get(&task).cloned())
    }

    fn lease(
        &self,
        task: TaskId,
        worker: WorkerId,
        deadline: LogicalTime,
    ) -> Result<Epoch, StoreError> {
        let mut inner = self.lock();
        let t = inner.tasks.get_mut(&task).ok_or(StoreError::NoSuchTask(task))?;
        // The strictly-greater epoch is minted here, so a reclaimed task is always
        // re-leased above its high-water mark — the durable side of the fencing rule.
        let epoch = t.epoch_hw.next();
        t.apply(TaskEvent::Lease {
            worker,
            epoch,
            deadline,
        })?;
        Ok(epoch)
    }

    fn extend_lease(
        &self,
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
        new_deadline: LogicalTime,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        let t = inner.tasks.get_mut(&task).ok_or(StoreError::NoSuchTask(task))?;
        t.apply(TaskEvent::Heartbeat {
            worker,
            epoch,
            new_deadline,
        })?;
        Ok(())
    }

    fn submit(
        &self,
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
        commitment: Commitment,
        output: OutputRef,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        let t = inner.tasks.get_mut(&task).ok_or(StoreError::NoSuchTask(task))?;
        // `Task::apply` checks epoch before holder, so a revived worker's stale-epoch
        // submit is rejected as StaleEpoch with the task byte-identically unchanged.
        t.apply(TaskEvent::Submit {
            worker,
            epoch,
            commitment,
            output,
        })?;
        Ok(())
    }

    fn select_or_accept(&self, task: TaskId, sampled: bool) -> Result<(), StoreError> {
        let mut inner = self.lock();
        let t = inner.tasks.get_mut(&task).ok_or(StoreError::NoSuchTask(task))?;
        if sampled {
            // The store records the Submitted -> Verifying move; the real challenge
            // indices are chosen by the engine/verifier (Session 5), so we carry an
            // empty placeholder challenge here.
            t.apply(TaskEvent::SelectForVerification {
                challenge: Challenge::default(),
            })?;
        } else {
            t.apply(TaskEvent::Accept)?;
        }
        Ok(())
    }

    fn verify_outcome(&self, task: TaskId, passed: bool) -> Result<(), StoreError> {
        let mut inner = self.lock();
        let t = inner.tasks.get_mut(&task).ok_or(StoreError::NoSuchTask(task))?;
        let actions = t.apply(TaskEvent::VerifyOutcome { passed })?;
        // A failed verify that has retry budget left returns the task to Pending; the
        // store re-enqueues it (the engine, Session 5, also acts on the Requeue action,
        // but the store is self-consistent on its own for the contract suite).
        if matches!(t.state, TaskState::Pending) {
            let prio = inner.priority.get(&task).copied().unwrap_or_default();
            // Re-enqueue at logical time 0; verify_outcome carries no clock and the
            // placement layer re-derives aging from priority. (The engine passes a real
            // `now` when it drives this in Session 5.)
            inner.push_ready(task, prio, LogicalTime(0));
        }
        let _ = actions; // EmitReputation/Requeue are the engine's to act on (Session 5).
        Ok(())
    }

    fn reclaim_expired(&self, now: LogicalTime) -> Result<Vec<TaskId>, StoreError> {
        let mut inner = self.lock();
        // Collect expired leases first (a Leased task whose deadline has lapsed), then
        // reclaim each. `Submitted`/`Verifying` tasks are untouched — their work product
        // already exists, mirroring `core`'s LeaseExpired-on-Submitted no-op.
        let expired: Vec<(TaskId, Epoch)> = inner
            .tasks
            .iter()
            .filter_map(|(&id, t)| match &t.state {
                TaskState::Leased {
                    epoch, deadline, ..
                } if now >= *deadline => Some((id, *epoch)),
                _ => None,
            })
            .collect();

        let mut reclaimed = Vec::with_capacity(expired.len());
        for (id, epoch) in expired {
            let prio = inner.priority.get(&id).copied().unwrap_or_default();
            let t = inner
                .tasks
                .get_mut(&id)
                .expect("task present from the scan above");
            // LeaseExpired{epoch} returns the task to Pending and keeps the high-water
            // mark; the next lease mints a strictly greater epoch via `epoch_hw.next()`.
            t.apply(TaskEvent::LeaseExpired { epoch })?;
            inner.push_ready(id, prio, now);
            reclaimed.push(id);
        }
        // Deterministic order for the differential oracle.
        reclaimed.sort_unstable_by_key(|t| t.0);
        Ok(reclaimed)
    }

    fn enqueue_ready(
        &self,
        task: TaskId,
        priority: Priority,
        now: LogicalTime,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        if !inner.tasks.contains_key(&task) {
            return Err(StoreError::NoSuchTask(task));
        }
        inner.push_ready(task, priority, now);
        Ok(())
    }

    fn pop_ready(&self) -> Result<Option<TaskId>, StoreError> {
        let mut inner = self.lock();
        // Highest priority wins; ties break by earliest enqueue time, then by sequence.
        let best = inner
            .ready
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                b.priority
                    .cmp(&a.priority)
                    .then(a.enqueued.cmp(&b.enqueued))
                    .then(a.seq.cmp(&b.seq))
            })
            .map(|(i, _)| i);
        Ok(best.map(|i| inner.ready.remove(i).task))
    }

    fn register_worker(&self, worker: WorkerId, now: LogicalTime) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner
            .workers
            .entry(worker)
            .and_modify(|e| e.last_heartbeat = now)
            .or_insert(WorkerEntry {
                last_heartbeat: now,
                ewma_throughput: 0.0,
                standing: 0,
            });
        Ok(())
    }

    fn worker_load(&self, worker: WorkerId) -> Result<WorkerLoad, StoreError> {
        let inner = self.lock();
        let entry = *inner
            .workers
            .get(&worker)
            .ok_or(StoreError::UnknownWorker(worker))?;
        Ok(WorkerLoad {
            in_flight: inner.in_flight(worker),
            ewma_throughput: entry.ewma_throughput,
            last_heartbeat: entry.last_heartbeat,
        })
    }

    fn update_standing(
        &self,
        worker: WorkerId,
        delta: ReputationDelta,
    ) -> Result<Tier, StoreError> {
        let mut inner = self.lock();
        let entry = inner
            .workers
            .get_mut(&worker)
            .ok_or(StoreError::UnknownWorker(worker))?;
        // The placeholder magnitudes + tier bands are shared with the Redis store
        // (super::standing_penalty / super::tier_from_standing) so the differential
        // oracle compares like with like; the asymmetric policy + P_MIN floor land in
        // reputation.rs (Session 4).
        entry.standing = entry.standing.saturating_sub(standing_penalty(delta));
        Ok(tier_from_standing(entry.standing))
    }

    fn record_verdict(
        &self,
        worker: WorkerId,
        detail: proctor_core::VerifyDetail,
    ) -> Result<Tier, StoreError> {
        let mut inner = self.lock();
        let entry = inner
            .workers
            .get_mut(&worker)
            .ok_or(StoreError::UnknownWorker(worker))?;
        // The reference path applies the authoritative rich policy directly: asymmetric
        // magnitudes, the Ok credit capped at Pristine, and the standing floor
        // (reputation.rs). The Redis store re-derives the identical result in Lua
        // (verdict_delta + clamp); the contract suite is the differential oracle.
        entry.standing = crate::reputation::record_verdict(entry.standing, detail);
        Ok(tier_from_standing(entry.standing))
    }
}

impl super::OutboundChannel for MemoryStore {
    fn push_assignment(&self, worker: WorkerId, frame: &[u8]) -> Result<(), StoreError> {
        self.lock_outbox().assignments.push((worker, frame.to_vec()));
        Ok(())
    }

    fn push_verify_request(&self, frame: &[u8]) -> Result<(), StoreError> {
        self.lock_outbox().verify_requests.push(frame.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryStore;
    use crate::store::contract::store_contract_suite;

    // Run the full shared differential contract suite (incl. the slow-zombie and
    // heartbeat-after-reclaim tests) against the in-memory reference. The Redis store
    // invokes the identical macro; the in-memory backend is always available, so it
    // hands the macro `Some(store)` unconditionally (no gating).
    store_contract_suite!(Some(MemoryStore::new()));
}
