//! `loops` — the dispatch loop and the single reclaim loop (§8).
//!
//! `sched` has no async runtime (locked decision #1): the loops are synchronous *ticks* a
//! driver calls on a cadence (the sim and tests call them directly; `main` spins them).
//! Each tick is bounded and re-entrant.
//!
//! - **Dispatch tick:** drain the ready queue — pop → place → lease + push — until the
//!   queue is empty or no worker is eligible (then the task is held for a later tick).
//! - **Reclaim tick:** one `reclaim_expired(now)` — the single authority (no stream PEL /
//!   second path); a bounded, periodic sweep.
//! - **Inbound handling:** decode a `HeartbeatMsg` / `SubmissionMsg` / `VerifyResult` off
//!   its inbox and route it to the matching engine entry point.

use proctor_core::{decode, HeartbeatMsg, LogicalTime, SubmissionMsg, TaskId, VerifyResult};
use rand::Rng;

use crate::engine::{
    DispatchStep, Engine, EngineError, HeartbeatOutcome, SubmitOutcome, VerifyOutcome,
};
use crate::store::{InboundChannel, Store};

/// Drain the ready queue, dispatching as many tasks as there are eligible workers. Returns
/// the number of tasks dispatched this tick. Stops at the first task with no eligible
/// worker (held for a later tick) so the tick cannot spin.
pub fn dispatch_tick<S: Store, R: Rng>(
    engine: &Engine<S, R>,
    now: LogicalTime,
) -> Result<usize, EngineError> {
    let mut dispatched = 0;
    // Stops at the first non-`Dispatched` step (queue empty, or a held task with no
    // eligible worker), so the tick cannot spin.
    while let DispatchStep::Dispatched { .. } = engine.dispatch_one(now)? {
        dispatched += 1;
    }
    Ok(dispatched)
}

/// One reclaim sweep — the single authority. Returns the reclaimed task ids (already
/// returned to `Pending` and re-enqueued inside the store).
pub fn reclaim_tick<S: Store, R: Rng>(
    engine: &Engine<S, R>,
    now: LogicalTime,
) -> Result<Vec<TaskId>, EngineError> {
    engine.reclaim(now)
}

// --- inbound handlers (decode happens at the inbox; these route typed messages) --------

/// Route a heartbeat to the engine.
pub fn handle_heartbeat<S: Store, R: Rng>(
    engine: &Engine<S, R>,
    msg: HeartbeatMsg,
    now: LogicalTime,
) -> Result<HeartbeatOutcome, EngineError> {
    engine.on_heartbeat(msg, now)
}

/// Route a submission to the engine (epoch-fenced; the slow zombie is rejected there).
pub fn handle_submission<S: Store, R: Rng>(
    engine: &Engine<S, R>,
    msg: SubmissionMsg,
    now: LogicalTime,
) -> Result<SubmitOutcome, EngineError> {
    engine.on_submission(msg, now)
}

/// Route a verifier verdict to the engine.
pub fn handle_verify_result<S: Store, R: Rng>(
    engine: &Engine<S, R>,
    result: VerifyResult,
    now: LogicalTime,
) -> Result<VerifyOutcome, EngineError> {
    engine.on_verify_result(result, now)
}

// --- the live return channel (§6): sched:inbound BRPOP + route -------------------------
//
// Workers and the verifier `LPUSH` their holder-action messages onto one `sched:inbound`
// list. postcard is not self-describing, so each frame is `[tag] ++ postcard(msg)`; the tag
// disambiguates the three message types on the shared list. The worker/verifier do not
// depend on `sched`, so these tag values are a wire convention restated at both ends —
// keep them in lockstep with `worker`/`verifier`.

/// Return-channel frame tags. `[HEARTBEAT|SUBMISSION|VERDICT] ++ postcard(msg)`.
pub mod inbound {
    /// A [`proctor_core::HeartbeatMsg`] frame.
    pub const HEARTBEAT: u8 = 0;
    /// A [`proctor_core::SubmissionMsg`] frame.
    pub const SUBMISSION: u8 = 1;
    /// A [`proctor_core::VerifyResult`] frame.
    pub const VERDICT: u8 = 2;
}

/// What a routed inbound frame turned into — the matching engine outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundRouted {
    Heartbeat(HeartbeatOutcome),
    Submission(SubmitOutcome),
    Verdict(VerifyOutcome),
}

/// Decode one tagged return-channel frame and route it to the matching engine handler.
/// An unknown tag, an empty frame, or an undecodable body is [`EngineError::MalformedInbound`]
/// (the live driver logs and continues — a bad frame is never a safety event).
pub fn route_inbound<S: Store, R: Rng>(
    engine: &Engine<S, R>,
    frame: &[u8],
    now: LogicalTime,
) -> Result<InboundRouted, EngineError> {
    let (tag, body) = frame.split_first().ok_or(EngineError::MalformedInbound)?;
    match *tag {
        inbound::HEARTBEAT => {
            let msg: HeartbeatMsg = decode(body).map_err(|_| EngineError::MalformedInbound)?;
            Ok(InboundRouted::Heartbeat(engine.on_heartbeat(msg, now)?))
        }
        inbound::SUBMISSION => {
            let msg: SubmissionMsg = decode(body).map_err(|_| EngineError::MalformedInbound)?;
            Ok(InboundRouted::Submission(engine.on_submission(msg, now)?))
        }
        inbound::VERDICT => {
            let msg: VerifyResult = decode(body).map_err(|_| EngineError::MalformedInbound)?;
            Ok(InboundRouted::Verdict(engine.on_verify_result(msg, now)?))
        }
        _ => Err(EngineError::MalformedInbound),
    }
}

/// One live inbound tick: `BRPOP` a single frame off `sched:inbound` (blocking up to
/// `timeout_secs`) and route it. `Ok(None)` on idle timeout. The store must back a real
/// inbound list ([`InboundChannel`] — the Redis backend); the sim path uses the in-process
/// [`crate::engine::Bus`] instead and never calls this.
pub fn inbound_tick<S, R>(
    engine: &Engine<S, R>,
    timeout_secs: u64,
    now: LogicalTime,
) -> Result<Option<InboundRouted>, EngineError>
where
    S: Store + InboundChannel,
    R: Rng,
{
    match engine.store().brpop_inbound(timeout_secs)? {
        Some(frame) => Ok(Some(route_inbound(engine, &frame, now)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proctor_core::{
        encode, Codec, Commitment, Container, Epoch, JobId, OutputRef, SegmentId, SegmentRef, Task,
        TargetProfile, TaskKind, TranscodeSpec, VerifyDetail, WorkerId,
    };

    use crate::engine::EngineConfig;
    use crate::sample::Sampler;
    use crate::store::{MemoryStore, Store, Tier};

    const WA: WorkerId = WorkerId(1);
    const C: Commitment = Commitment([7u8; 32]);
    const O: OutputRef = OutputRef(0xA);

    fn engine() -> Engine<MemoryStore, rand::rngs::StdRng> {
        Engine::new(MemoryStore::new(), EngineConfig::for_workers(1), Sampler::seeded(0))
    }

    fn task(id: u64) -> Task {
        Task::new(
            TaskId(id),
            TaskKind::Transcode(TranscodeSpec {
                job: JobId(1),
                segment: SegmentId(id),
                profile: TargetProfile {
                    codec: Codec::H264,
                    width: 1280,
                    height: 720,
                    bitrate_kbps: 3000,
                    container: Container::Mp4,
                },
                source: SegmentRef(id as u128),
            }),
        )
    }

    /// Seed a task and a registered worker, lease it to WA, and return `(task, epoch)`.
    fn seed_leased(e: &Engine<MemoryStore, rand::rngs::StdRng>) -> (TaskId, Epoch) {
        let s = e.store();
        s.create_task(task(1)).unwrap();
        e.register_worker(WA, LogicalTime(0)).unwrap();
        let t = TaskId(1);
        let epoch = s.lease(t, WA, LogicalTime(100)).unwrap();
        (t, epoch)
    }

    fn frame<M: proctor_core::Message>(tag: u8, msg: &M) -> Vec<u8> {
        let mut f = vec![tag];
        f.extend_from_slice(&encode(msg));
        f
    }

    #[test]
    fn routes_a_tagged_heartbeat_to_extend() {
        let e = engine();
        let (t, epoch) = seed_leased(&e);
        let f = frame(
            inbound::HEARTBEAT,
            &HeartbeatMsg { task: t, worker: WA, epoch },
        );
        let routed = route_inbound(&e, &f, LogicalTime(10)).unwrap();
        assert_eq!(routed, InboundRouted::Heartbeat(HeartbeatOutcome::Extended));
    }

    #[test]
    fn routes_a_tagged_submission() {
        let e = engine();
        let (t, epoch) = seed_leased(&e);
        let f = frame(
            inbound::SUBMISSION,
            &SubmissionMsg { task: t, worker: WA, epoch, commitment: C, output: O },
        );
        let routed = route_inbound(&e, &f, LogicalTime(10)).unwrap();
        // Sampled or accepted depending on the gate; either is a Submission route.
        assert!(matches!(routed, InboundRouted::Submission(_)));
    }

    #[test]
    fn routes_a_tagged_verdict_and_applies_rich_reputation() {
        let e = engine();
        let (t, epoch) = seed_leased(&e);
        // Drive the task to Verifying via the store, then route a commitment-mismatch verdict.
        e.store().submit(t, WA, epoch, C, O).unwrap();
        e.store().select_or_accept(t, true).unwrap();

        let f = frame(
            inbound::VERDICT,
            &VerifyResult { task: t, passed: false, detail: VerifyDetail::CommitmentMismatch },
        );
        let routed = route_inbound(&e, &f, LogicalTime(10)).unwrap();
        assert!(matches!(routed, InboundRouted::Verdict(_)));
        // The rich path bans a provable commitment mismatch in one step (§6).
        assert_eq!(e.cached_tier(WA), Some(Tier::Banned));
    }

    #[test]
    fn malformed_frames_are_rejected_without_panicking() {
        let e = engine();
        seed_leased(&e);
        // Empty frame.
        assert!(matches!(
            route_inbound(&e, &[], LogicalTime(0)),
            Err(EngineError::MalformedInbound)
        ));
        // Unknown tag.
        assert!(matches!(
            route_inbound(&e, &[0xFF, 1, 2, 3], LogicalTime(0)),
            Err(EngineError::MalformedInbound)
        ));
        // Known tag, undecodable body.
        assert!(matches!(
            route_inbound(&e, &[inbound::VERDICT, 0xFF, 0xFF], LogicalTime(0)),
            Err(EngineError::MalformedInbound)
        ));
    }
}
