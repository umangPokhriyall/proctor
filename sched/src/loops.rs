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

use proctor_core::{HeartbeatMsg, LogicalTime, SubmissionMsg, TaskId, VerifyResult};
use rand::Rng;

use crate::engine::{
    DispatchStep, Engine, EngineError, HeartbeatOutcome, SubmitOutcome, VerifyOutcome,
};
use crate::store::Store;

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
