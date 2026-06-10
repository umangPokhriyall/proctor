//! proctor `core` — sans-IO protocol, task/lease/segment state machine, commit-reveal types.
//!
//! This crate is **sans-IO**: it never touches a socket, Redis, ffmpeg, or the
//! filesystem. It is the single abstraction that drives `crypto`, `verify`,
//! `sched`, `verifier`, and `worker` unmodified.
//!
//! Phase 0 declares **shape only** — every body is `todo!()`. The types below are
//! the intended public surface for the Phase 1 freeze.
//!
//! ============================================================================
//! FROZEN in Phase 1.  Do not add or change public items after the Phase 1
//! freeze ceremony; every later phase consumes this surface unmodified.
//! ============================================================================

use thiserror::Error;

/// Identifies a single GOP-aligned segment within a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentId(pub u64);

/// Identifies a transcoding task (a whole asset, split into segments).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Identifies a worker in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(pub u64);

/// Monotonic lease epoch; bumped on every (re)assignment so a stale holder is detectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u64);

/// A monotonic deadline in milliseconds. Sans-IO: no wall clock is read in `core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(pub u64);

/// A lease: the single authority for "who holds this segment, until when, in which epoch".
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    pub holder: WorkerId,
    pub segment: SegmentId,
    pub deadline: Deadline,
    pub epoch: Epoch,
}

/// The task/segment lifecycle. The single reclaim authority drives every transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Leased,
    Transcoded,
    Verifying,
    Verified,
    Released,
    Stitched,
    Reclaimed,
    Failed,
}

/// A GOP-aligned segment description within a manifest. Sans-IO: timing, not bytes.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    pub id: SegmentId,
    pub start_ms: u64,
    pub duration_ms: u64,
}

/// The full segment manifest for a task.
#[derive(Debug, Clone)]
pub struct SegmentManifest {
    pub task: TaskId,
    pub segments: Vec<Segment>,
}

/// `SHA-256` over a worker's encoded output, committed **before** the worker learns the
/// challenged timestamps (commit-reveal — so it cannot retrofit a tampered result).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);

/// The post-challenge reveal a worker returns so the verifier can check the commitment.
#[derive(Debug, Clone)]
pub struct Reveal {
    pub segment: SegmentId,
    pub commitment: Commitment,
}

/// The sans-IO protocol envelope exchanged across the control plane. Transport is elsewhere.
#[derive(Debug, Clone)]
pub enum Message {
    /// Scheduler -> worker: a pushed lease assignment (the worker never self-selects).
    Assign(Lease),
    /// Worker -> scheduler: heartbeat extending its lease.
    Heartbeat {
        worker: WorkerId,
        segment: SegmentId,
        epoch: Epoch,
    },
    /// Worker -> scheduler: output commitment for a finished segment.
    Commit(Reveal),
    /// Verifier -> worker: a challenge carrying **only** timestamps; the expected hash never leaves the verifier.
    Challenge {
        segment: SegmentId,
        timestamps_ms: Vec<u64>,
    },
}

/// Errors surfaced by the `core` state machine.
#[derive(Debug, Error)]
pub enum CoreError {
    /// An attempted state transition is not permitted by the lifecycle.
    #[error("illegal transition from {from:?} to {to:?}")]
    IllegalTransition { from: TaskState, to: TaskState },
    /// A lease operation referenced a stale epoch.
    #[error("stale epoch: holder presented {held:?}, current is {current:?}")]
    StaleEpoch { held: Epoch, current: Epoch },
}

impl TaskState {
    /// Whether `self` may legally transition to `next`. Phase 1 defines the table.
    pub fn can_transition_to(self, next: TaskState) -> bool {
        todo!("Phase 1: task lifecycle transition table (next = {next:?})")
    }
}

impl Lease {
    /// Whether this lease has expired relative to `now`. Phase 1 defines expiry semantics.
    pub fn is_expired(&self, now: Deadline) -> bool {
        todo!("Phase 1: lease expiry (now = {now:?})")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
