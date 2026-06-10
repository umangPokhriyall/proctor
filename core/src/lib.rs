//! proctor `core` — sans-IO protocol, task/lease/segment state machine, commit-reveal types.
//!
//! This crate is **sans-IO**: it never touches a socket, Redis, ffmpeg, or the
//! filesystem, and it reads no clock and samples no randomness. Time and
//! randomness are *inputs*. It is the single abstraction that drives `crypto`,
//! `verify`, `sched`, `verifier`, and `worker` unmodified.
//!
//! Phase 1 fills this crate module by module (`docs/specs/phase1-spec.md` §2) and
//! then **freezes** it. The module layout being assembled:
//!
//! - [`id`]    — newtype identifiers, the monotonic [`id::Epoch`], injected [`id::LogicalTime`].
//! - [`lease`] — the [`lease::Lease`] with its fencing epoch and the pure expiry predicate.
//! - `task`    — `TaskKind { Transcode, Stitch }` (Session 2).
//! - `commit`  — Merkle commit-reveal over opaque leaves (Session 2).
//! - `state`   — the `Task` state machine and `apply` (Session 3).
//! - `proto`   — the frozen wire messages and canonical encode/decode (Session 4).
//!
//! ============================================================================
//! Becomes FROZEN at the end of Phase 1 (tag `v0.1.0-core-frozen`). Do not add or
//! change public items after the freeze ceremony; every later phase consumes this
//! surface unmodified. If a later phase seems to need a change here, it is wrong.
//! ============================================================================

pub mod id;
pub mod lease;

pub use id::{Epoch, JobId, LogicalTime, OutputRef, SegmentId, TaskId, WorkerId};
pub use lease::Lease;

// ---------------------------------------------------------------------------
// Phase 0 residue — shape-only stubs not yet modularized. These are replaced by
// the `commit` module (Session 2) and resolved when the manifest's home is
// settled. They are retained here only so the Phase 0 dependent stubs (`worker`,
// `bench`, `verify`) keep compiling on a green tree between Phase 1 sessions; no
// Session-1 logic touches them.
// ---------------------------------------------------------------------------

/// `SHA-256` over a worker's encoded output, committed **before** the worker learns the
/// challenged timestamps (commit-reveal). Reworked into a Merkle commitment in Session 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);

/// The post-challenge reveal a worker returns so the verifier can check the commitment.
/// Reworked into the Merkle `Reveal` (`leaves` + `proofs`) in Session 2.
#[derive(Debug, Clone)]
pub struct Reveal {
    pub segment: SegmentId,
    pub commitment: Commitment,
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
