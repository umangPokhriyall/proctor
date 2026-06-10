//! proctor `core` — sans-IO protocol, task/lease/segment state machine, commit-reveal types.
//!
//! ============================================================================
//! FROZEN — see `docs/specs/phase1-spec.md` §0 (tag `v0.1.0-core-frozen`).
//! This crate's public surface is settled. Do **not** add or change public items;
//! `crypto`, `verify`, `sched`, `verifier`, and `worker` consume it unmodified.
//! If a later phase seems to need a `core` change, the later phase is wrong —
//! STOP and ask.
//! ============================================================================
//!
//! This crate is **sans-IO**: it never touches a socket, Redis, ffmpeg, or the
//! filesystem, and it reads no clock and samples no randomness. Time and
//! randomness are *inputs*. The module layout (`docs/specs/phase1-spec.md` §2):
//!
//! - [`id`]     — newtype identifiers, the monotonic [`id::Epoch`], injected [`id::LogicalTime`].
//! - [`lease`]  — the [`lease::Lease`] with its fencing epoch and the pure expiry predicate.
//! - [`task`]   — `TaskKind { Transcode, Stitch }`, strictly distinct.
//! - [`commit`] — Merkle commit-reveal over opaque leaves.
//! - [`state`]  — the `Task` state machine and the pure `apply` transition.
//! - [`proto`]  — the frozen wire messages and canonical postcard encode/decode.

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
