//! `proto` — the frozen wire messages and their canonical codec. See `phase1-spec.md` §8.
//!
//! Freezing "the protocol" means freezing the messages *and* their serialized
//! bytes. Transport — Redis streams, sockets, TLS — is `sched`/`worker`/`verifier`
//! in later phases; framing and delivery are not `core`'s. Message **shape** and
//! the canonical **encoding** are.
//!
//! ## Fencing at the message boundary
//! Every holder-action message ([`HeartbeatMsg`], [`SubmissionMsg`]) carries
//! `(worker, epoch)`, so the I/O layer hands those straight into the matching
//! [`crate::state::TaskEvent`] and the state machine rejects stale ones. The wire
//! shape makes it impossible to act as a holder without presenting a fencing token.
//!
//! ## Codec
//! [`encode`]/[`decode`] use [`postcard`] — a compact, deterministic, no_std-friendly
//! codec — so a given message has one canonical byte form. `decode` never panics on
//! malformed input; it returns [`ProtoError`].

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::commit::{Challenge, Commitment, Reveal};
use crate::id::{Epoch, OutputRef, TaskId, WorkerId};
use crate::lease::Lease;
use crate::task::{SegmentRef, TaskKind};

/// scheduler → worker: a pushed assignment. The worker **receives**; it never
/// self-selects. Carries the lease (holder + fencing epoch + deadline) it must
/// echo back on every holder-action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub task: TaskId,
    pub kind: TaskKind,
    pub lease: Lease,
    pub source: SegmentRef,
}

/// worker → scheduler: a heartbeat that extends the lease. Holder-action — carries
/// `(worker, epoch)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatMsg {
    pub task: TaskId,
    pub worker: WorkerId,
    pub epoch: Epoch,
}

/// worker → scheduler: a completed output and its pre-challenge commitment.
/// Holder-action — carries `(worker, epoch)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionMsg {
    pub task: TaskId,
    pub worker: WorkerId,
    pub epoch: Epoch,
    pub commitment: Commitment,
    pub output: OutputRef,
}

/// scheduler/verifier → worker: the challenged leaf indices (chosen after the
/// commitment was received).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeMsg {
    pub task: TaskId,
    pub challenge: Challenge,
}

/// worker → scheduler/verifier: the opened leaves and their inclusion proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealMsg {
    pub task: TaskId,
    pub reveal: Reveal,
}

/// scheduler → verifier: the work to independently re-check. `kind` tells the
/// verifier whether to re-encode and SSIM-compare (`Transcode`) or do an ordered
/// integrity check (`Stitch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub task: TaskId,
    pub kind: TaskKind,
    pub commitment: Commitment,
    pub output: OutputRef,
}

/// verifier → scheduler: the verdict and a categorical reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub task: TaskId,
    pub passed: bool,
    pub detail: VerifyDetail,
}

/// The categorical reason behind a [`VerifyResult`]. Deliberately carries no
/// numeric threshold — the SSIM threshold is read from a committed ROC file (a
/// locked decision), never baked into the frozen wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyDetail {
    /// Accepted: the reveal proved inclusion and the kind-specific check passed.
    Ok,
    /// The reveal↔commitment binding failed — the output is tamper-evident.
    CommitmentMismatch,
    /// A `Transcode` fell below the calibrated fidelity threshold.
    FidelityBelowThreshold,
    /// A `Stitch` did not concatenate exactly the accepted inputs in order.
    IntegrityViolation,
    /// The verifier could not reach a verdict (e.g. a re-execution error).
    Inconclusive,
}

/// Marker for the frozen wire messages. The codec is generic over this trait so
/// only message types — not arbitrary serde values — flow across the boundary.
pub trait Message: Serialize + DeserializeOwned {}

impl Message for Assignment {}
impl Message for HeartbeatMsg {}
impl Message for SubmissionMsg {}
impl Message for ChallengeMsg {}
impl Message for RevealMsg {}
impl Message for VerifyRequest {}
impl Message for VerifyResult {}

/// A wire decode failure. Decoupled from `postcard`'s own error type so the frozen
/// public surface does not depend on the codec's internals.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// The bytes were not a valid canonical encoding of the target message.
    #[error("malformed wire bytes: {0}")]
    Malformed(String),
}

/// Encode a message to its canonical bytes. Infallible for the frozen message set
/// (their fields are plain data); a serialization error would be a library bug.
#[must_use]
pub fn encode<M: Message>(m: &M) -> Vec<u8> {
    postcard::to_allocvec(m).expect("encoding a frozen Message is infallible")
}

/// Decode a message from canonical bytes. Returns [`ProtoError`] on any malformed
/// input — never panics.
pub fn decode<M: Message>(b: &[u8]) -> Result<M, ProtoError> {
    postcard::from_bytes(b).map_err(|e| ProtoError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::LeafIndex;
    use crate::id::{JobId, LogicalTime, SegmentId};
    use crate::task::{Codec, Container, RenditionId, StitchSpec, TargetProfile, TranscodeSpec};

    fn transcode_kind() -> TaskKind {
        TaskKind::Transcode(TranscodeSpec {
            job: JobId(42),
            segment: SegmentId(7),
            profile: TargetProfile {
                codec: Codec::Av1,
                width: 3840,
                height: 2160,
                bitrate_kbps: 18000,
                container: Container::Mp4,
            },
            source: SegmentRef(0xFEED_FACE),
        })
    }

    fn stitch_kind() -> TaskKind {
        TaskKind::Stitch(StitchSpec {
            job: JobId(42),
            rendition: RenditionId(3),
            inputs: vec![
                (SegmentId(0), OutputRef(100), Commitment([1u8; 32])),
                (SegmentId(1), OutputRef(101), Commitment([2u8; 32])),
                (SegmentId(2), OutputRef(102), Commitment([3u8; 32])),
            ],
        })
    }

    fn sample_reveal() -> Reveal {
        let leaves: Vec<[u8; 32]> = (0..6u8).map(|i| [i; 32]).collect();
        let challenge = Challenge {
            indices: vec![LeafIndex(1), LeafIndex(4)],
        };
        Reveal::open(&leaves, &challenge).unwrap()
    }

    /// Round-trip helper: `decode(encode(m)) == m`, byte-for-byte canonical.
    fn assert_round_trips<M>(m: M)
    where
        M: Message + Clone + PartialEq + std::fmt::Debug,
    {
        let bytes = encode(&m);
        let back: M = decode(&bytes).expect("a freshly encoded message must decode");
        assert_eq!(back, m, "round-trip must be lossless");
        // Canonical: re-encoding the decoded value yields identical bytes.
        assert_eq!(encode(&back), bytes, "encoding must be canonical");
    }

    #[test]
    fn assignment_round_trips() {
        assert_round_trips(Assignment {
            task: TaskId(1),
            kind: transcode_kind(),
            lease: Lease {
                holder: WorkerId(5),
                epoch: Epoch(9),
                deadline: LogicalTime(1234),
            },
            source: SegmentRef(0xABCD),
        });
        // Also with a Stitch kind (variable-length inputs).
        assert_round_trips(Assignment {
            task: TaskId(2),
            kind: stitch_kind(),
            lease: Lease {
                holder: WorkerId(6),
                epoch: Epoch(10),
                deadline: LogicalTime(5678),
            },
            source: SegmentRef(0),
        });
    }

    #[test]
    fn heartbeat_round_trips() {
        assert_round_trips(HeartbeatMsg {
            task: TaskId(3),
            worker: WorkerId(11),
            epoch: Epoch(4),
        });
    }

    #[test]
    fn submission_round_trips() {
        assert_round_trips(SubmissionMsg {
            task: TaskId(4),
            worker: WorkerId(12),
            epoch: Epoch(5),
            commitment: Commitment([0xAB; 32]),
            output: OutputRef(99),
        });
    }

    #[test]
    fn challenge_round_trips() {
        assert_round_trips(ChallengeMsg {
            task: TaskId(5),
            challenge: Challenge {
                indices: vec![LeafIndex(0), LeafIndex(7), LeafIndex(255)],
            },
        });
        // Empty challenge is a valid shape too.
        assert_round_trips(ChallengeMsg {
            task: TaskId(6),
            challenge: Challenge::default(),
        });
    }

    #[test]
    fn reveal_round_trips() {
        assert_round_trips(RevealMsg {
            task: TaskId(7),
            reveal: sample_reveal(),
        });
    }

    #[test]
    fn verify_request_round_trips() {
        assert_round_trips(VerifyRequest {
            task: TaskId(8),
            kind: stitch_kind(),
            commitment: Commitment([0x11; 32]),
            output: OutputRef(7),
        });
    }

    #[test]
    fn verify_result_round_trips() {
        for detail in [
            VerifyDetail::Ok,
            VerifyDetail::CommitmentMismatch,
            VerifyDetail::FidelityBelowThreshold,
            VerifyDetail::IntegrityViolation,
            VerifyDetail::Inconclusive,
        ] {
            assert_round_trips(VerifyResult {
                task: TaskId(9),
                passed: matches!(detail, VerifyDetail::Ok),
                detail,
            });
        }
    }

    #[test]
    fn corrupted_bytes_error_cleanly_without_panicking() {
        let bytes = encode(&RevealMsg {
            task: TaskId(7),
            reveal: sample_reveal(),
        });

        // Empty input.
        assert!(decode::<RevealMsg>(&[]).is_err());

        // Truncations at every prefix length must error, never panic.
        for cut in 0..bytes.len() {
            assert!(
                decode::<RevealMsg>(&bytes[..cut]).is_err(),
                "truncation at {cut} should fail cleanly"
            );
        }

        // A bogus, over-large length prefix (varint) followed by no data: a Vec
        // field claims many elements that aren't there → unexpected end, not OOM.
        let bogus = [0x01u8, 0xFF, 0xFF, 0xFF, 0x7F];
        assert!(decode::<ChallengeMsg>(&bogus).is_err());

        // High-entropy garbage of various lengths.
        for len in [1usize, 3, 8, 33, 64] {
            let garbage: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
            // Must return a Result (Ok or Err) without panicking; we only assert no panic.
            let _ = decode::<SubmissionMsg>(&garbage);
            let _ = decode::<HeartbeatMsg>(&garbage);
        }
    }

    #[test]
    fn decoding_as_the_wrong_message_does_not_panic() {
        // Bytes valid for one message fed to a different decoder: at worst an Err,
        // never a panic.
        let hb = encode(&HeartbeatMsg {
            task: TaskId(1),
            worker: WorkerId(2),
            epoch: Epoch(3),
        });
        let _ = decode::<RevealMsg>(&hb);
        let _ = decode::<Assignment>(&hb);
        let _ = decode::<VerifyResult>(&hb);
    }
}
