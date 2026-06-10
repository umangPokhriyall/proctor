//! `task` — `TaskKind` and its payloads. See `phase1-spec.md` §5.
//!
//! The legacy `STITCH_`-string-prefix overloading is gone. The two work classes
//! have different inputs, verification semantics, and resource profiles, so the
//! type system represents that boundary as an enum — while the state machine
//! (`state.rs`, Session 3) stays *identical* across kinds: one lease/epoch/reclaim
//! discipline, not two.
//!
//! **Verification semantics differ, but the difference lives in the data, not a
//! forked state graph:**
//! - **Transcode** verification is *fidelity*: the verifier re-encodes challenged
//!   frames and SSIM-compares (Phase 3). Its commitment is a Merkle root over
//!   per-frame hashes.
//! - **Stitch** verification is *integrity*: the output must concatenate exactly
//!   the accepted, committed segment outputs, in order — a hash/manifest check,
//!   no SSIM and no re-encode. Its commitment is a Merkle root over the ordered
//!   input hashes.
//!
//! **Rejected alternative:** `Task<K: TaskKind>` generic over the kind, or two
//! separate state machines. Rejected as premature abstraction and as duplication
//! of the lease/epoch/reclaim logic that is the whole reason to freeze one `core`.
//! One concrete `Task` carries a `kind` field; kind-specific meaning rides in the
//! payloads. The job DAG (which transcodes must be accepted before a stitch is
//! created) is **scheduler** state (Phase 4), not `core` — `core` only knows a
//! single task's lifecycle.
//!
//! **Sans-IO (§11):** these are plain data — opaque refs and hashes, no bytes, no
//! key material, no I/O.

use serde::{Deserialize, Serialize};

use crate::commit::Commitment;
use crate::id::{JobId, OutputRef, SegmentId};

/// The two strictly-distinct classes of work. The state machine is identical
/// across both; only the payload and (later) the verifier's method differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskKind {
    Transcode(TranscodeSpec),
    Stitch(StitchSpec),
}

/// Re-encode one encrypted source segment to a target fidelity contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeSpec {
    pub job: JobId,
    pub segment: SegmentId,
    /// The fidelity contract: codec, resolution, bitrate, container.
    pub profile: TargetProfile,
    /// Opaque ref to the encrypted source segment — **not** bytes, **not** a key.
    pub source: SegmentRef,
}

/// Concatenate accepted, committed segment outputs into one rendition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StitchSpec {
    pub job: JobId,
    pub rendition: RenditionId,
    /// The ordered, content-addressed inputs this stitch concatenates — each is the
    /// accepted `OutputRef` plus its committed hash from a `Transcode` task. Order
    /// is significant: stitch verification is an in-order integrity check.
    pub inputs: Vec<(SegmentId, OutputRef, Commitment)>,
}

/// The fidelity contract a transcode must meet; the verifier re-encodes against the
/// byte-identical parameters this describes (Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProfile {
    pub codec: Codec,
    pub width: u32,
    pub height: u32,
    pub bitrate_kbps: u32,
    pub container: Container,
}

/// Target video codec. An enum, not a string — the type system carries the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Codec {
    H264,
    H265,
    Av1,
    Vp9,
}

/// Target output container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Container {
    Mp4,
    WebM,
    Mkv,
    /// MPEG-TS, the HLS segment container.
    MpegTs,
}

/// An opaque handle to an encrypted source segment in the blob store — **not** the
/// bytes, **not** a key. Resolving it is the I/O layer's concern, never `core`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SegmentRef(pub u128);

/// Identifies an output rendition (one quality variant) of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RenditionId(pub u64);

#[cfg(test)]
mod tests {
    use super::*;

    fn transcode() -> TaskKind {
        TaskKind::Transcode(TranscodeSpec {
            job: JobId(1),
            segment: SegmentId(2),
            profile: TargetProfile {
                codec: Codec::H264,
                width: 1920,
                height: 1080,
                bitrate_kbps: 6000,
                container: Container::Mp4,
            },
            source: SegmentRef(0xDEAD_BEEF),
        })
    }

    fn stitch() -> TaskKind {
        TaskKind::Stitch(StitchSpec {
            job: JobId(1),
            rendition: RenditionId(7),
            inputs: vec![
                (SegmentId(2), OutputRef(10), Commitment([1u8; 32])),
                (SegmentId(3), OutputRef(11), Commitment([2u8; 32])),
            ],
        })
    }

    #[test]
    fn transcode_and_stitch_are_distinct_variants() {
        assert!(matches!(transcode(), TaskKind::Transcode(_)));
        assert!(matches!(stitch(), TaskKind::Stitch(_)));
        assert_ne!(transcode(), stitch());
    }

    #[test]
    fn payloads_are_preserved() {
        let TaskKind::Transcode(spec) = transcode() else {
            panic!("expected transcode");
        };
        assert_eq!(spec.profile.height, 1080);
        assert_eq!(spec.profile.codec, Codec::H264);
        assert_eq!(spec.source, SegmentRef(0xDEAD_BEEF));

        let TaskKind::Stitch(spec) = stitch() else {
            panic!("expected stitch");
        };
        // Stitch inputs are ordered and content-addressed.
        assert_eq!(spec.inputs.len(), 2);
        assert_eq!(spec.inputs[0].0, SegmentId(2));
        assert_eq!(spec.inputs[1].2, Commitment([2u8; 32]));
    }

    #[test]
    fn task_kind_clones_equal() {
        let t = transcode();
        assert_eq!(t.clone(), t);
    }
}
