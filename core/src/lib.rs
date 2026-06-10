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
//! - [`id`]     — newtype identifiers, the monotonic [`id::Epoch`], injected [`id::LogicalTime`].
//! - [`lease`]  — the [`lease::Lease`] with its fencing epoch and the pure expiry predicate.
//! - [`task`]   — `TaskKind { Transcode, Stitch }`, strictly distinct.
//! - [`commit`] — Merkle commit-reveal over opaque leaves.
//! - [`state`]  — the `Task` state machine and the pure `apply` transition.
//! - [`proto`]  — the frozen wire messages and canonical postcard encode/decode.
//!
//! ============================================================================
//! Becomes FROZEN at the end of Phase 1 (tag `v0.1.0-core-frozen`). Do not add or
//! change public items after the freeze ceremony; every later phase consumes this
//! surface unmodified. If a later phase seems to need a change here, it is wrong.
//! ============================================================================

pub mod commit;
pub mod id;
pub mod lease;
pub mod proto;
pub mod state;
pub mod task;

pub use commit::{Challenge, Commitment, LeafIndex, MerkleProof, Reveal};
pub use id::{Epoch, JobId, LogicalTime, OutputRef, SegmentId, TaskId, WorkerId};
pub use lease::Lease;
pub use proto::{
    decode, encode, Assignment, ChallengeMsg, HeartbeatMsg, Message, ProtoError, RevealMsg,
    SubmissionMsg, VerifyDetail, VerifyRequest, VerifyResult,
};
pub use state::{
    FailureReason, ReputationDelta, Task, TaskAction, TaskEvent, TaskState, TransitionError,
    MAX_RETRIES,
};
pub use task::{
    Codec, Container, RenditionId, SegmentRef, StitchSpec, TargetProfile, TaskKind, TranscodeSpec,
};

// ---------------------------------------------------------------------------
// Phase 0 residue — shape-only stubs not yet modularized. Retained here only so
// the Phase 0 dependent stub (`bench`) keeps compiling on a green tree between
// Phase 1 sessions; the manifest's permanent home is settled in a later session.
// No Session-2 logic touches them.
// ---------------------------------------------------------------------------

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
