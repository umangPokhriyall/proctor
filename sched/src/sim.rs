//! `sim` — a `#[cfg(test)]` simulated worker and verifier over `core::proto` (§8).
//!
//! This drives the whole control plane end-to-end **without** the real binaries (Phase 5):
//! a [`SimWorker`] registers, receives an `Assignment`, and submits a `SubmissionMsg` with a
//! chosen `(worker, epoch)` — honest, or a deliberately stale **zombie**; a [`SimVerifier`]
//! receives a `VerifyRequest` and returns a chosen `VerifyResult`. Together they exercise
//! placement, fencing, sampling, reputation, release, and backpressure through the engine
//! and loops. The real single-host run and the slow-zombie *chaos schedule* are Phase 6.

use proctor_core::{
    Assignment, Codec, Container, Epoch, JobId, LogicalTime, SegmentId, SegmentRef, SubmissionMsg,
    TargetProfile, Task, TaskId, TaskKind, TaskState, TranscodeSpec, VerifyDetail, VerifyRequest,
    VerifyResult, WorkerId,
};

use crate::engine::{
    content_address, Bus, DispatchStep, Engine, EngineConfig, SubmitOutcome, VerifyOutcome,
};
use crate::sample::Sampler;
use crate::store::{MemoryStore, Priority, Store, Tier};
use crate::{backpressure::Backpressure, loops};

/// A deterministic RNG for forcing the sampling decision in tests: `ConstRng(0)` always
/// samples (any `p > 0`), `ConstRng(u64::MAX)` never samples (any `p < 1`). Lets the sim
/// exercise both the sampled (verify) and unsampled (release) paths deterministically.
struct ConstRng(u64);

impl rand::RngCore for ConstRng {
    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0 as u8);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Force-sample sampler (every submission is verified).
fn always_sample() -> Sampler<ConstRng> {
    Sampler::new(ConstRng(0))
}
/// Never-sample sampler (every submission is content-addressed released).
fn never_sample() -> Sampler<ConstRng> {
    Sampler::new(ConstRng(u64::MAX))
}

/// A fresh `Pending` transcode task.
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

/// A simulated worker speaking `core::proto`: pulls its pushed `Assignment`, builds a
/// content-addressed `SubmissionMsg`. The blob hash leaf stands in for `SHA-256(ciphertext)`
/// (computed worker-side in Phase 5); the worker chooses `(worker, epoch)`, so a zombie can
/// present a stale epoch.
struct SimWorker {
    id: WorkerId,
}

impl SimWorker {
    fn recv(&self, bus: &Bus) -> Option<Assignment> {
        bus.pop_assignment(self.id)
    }

    /// Submit with a chosen `(epoch)` — the legitimate holder echoes its lease epoch; a
    /// zombie presents an old one.
    fn submit(&self, task: TaskId, epoch: Epoch, blob_leaf: [u8; 32]) -> SubmissionMsg {
        let (output, commitment) = content_address(blob_leaf);
        SubmissionMsg {
            task,
            worker: self.id,
            epoch,
            commitment,
            output,
        }
    }
}

/// A simulated verifier: pulls a `VerifyRequest` and returns a chosen verdict.
struct SimVerifier;

impl SimVerifier {
    fn recv(&self, bus: &Bus) -> Option<VerifyRequest> {
        bus.pop_verify()
    }
    fn respond(&self, req: &VerifyRequest, passed: bool, detail: VerifyDetail) -> VerifyResult {
        VerifyResult {
            task: req.task,
            passed,
            detail,
        }
    }
}

/// Dispatch one task and assert it landed on `expect_worker`; return `(task, epoch)`.
fn dispatch_to(
    engine: &Engine<MemoryStore, ConstRng>,
    now: LogicalTime,
    expect_worker: WorkerId,
) -> (TaskId, Epoch) {
    match engine.dispatch_one(now).unwrap() {
        DispatchStep::Dispatched {
            task,
            worker,
            epoch,
        } => {
            assert_eq!(worker, expect_worker, "placement put the task on the wrong worker");
            (task, epoch)
        }
        other => panic!("expected a dispatch, got {other:?}"),
    }
}

// --- the end-to-end flows ---------------------------------------------------

#[test]
fn place_lease_submit_sample_verify_release() {
    // The full happy path: place -> lease -> submit -> sampled -> verify(pass) -> release.
    let engine = Engine::new(MemoryStore::new(), EngineConfig::for_workers(1), always_sample());
    let a = SimWorker { id: WorkerId(1) };
    engine.register_worker(a.id, LogicalTime(0)).unwrap();
    engine.inject(task(1), Priority(0), LogicalTime(0)).unwrap();

    let (t, e1) = dispatch_to(&engine, LogicalTime(0), a.id);

    // Worker receives the pushed assignment and submits, echoing its lease epoch.
    let asg = a.recv(engine.bus()).expect("assignment pushed to the worker");
    assert_eq!(asg.task, t);
    assert_eq!(asg.lease.epoch, e1);
    let leaf = [1u8; 32];
    let out = engine
        .on_submission(a.submit(t, asg.lease.epoch, leaf), LogicalTime(1))
        .unwrap();
    assert_eq!(out, SubmitOutcome::Sampled, "forced sampling routes to the verifier");
    assert_eq!(engine.release_count(), 0, "nothing released until the verdict");

    // The verifier receives the request and passes it.
    let v = SimVerifier;
    let req = v.recv(engine.bus()).expect("verify request pushed");
    assert_eq!(req.task, t);
    let vo = engine
        .on_verify_result(v.respond(&req, true, VerifyDetail::Ok), LogicalTime(2))
        .unwrap();

    let (output, _) = content_address(leaf);
    assert_eq!(vo, VerifyOutcome::Accepted(output));
    assert_eq!(engine.release_count(), 1);
    assert!(engine.released(output).is_some(), "content-addressed release recorded");
    // Lazy binding (anti-swap): the genuine blob confirms; a swapped blob does not.
    assert!(engine.confirm_release(leaf));
    assert!(!engine.confirm_release([2u8; 32]));
    assert!(matches!(
        engine.store().load(t).unwrap().unwrap().state,
        TaskState::Accepted { .. }
    ));
}

#[test]
fn unsampled_submission_is_content_addressed_released() {
    let engine = Engine::new(MemoryStore::new(), EngineConfig::for_workers(1), never_sample());
    let a = SimWorker { id: WorkerId(1) };
    engine.register_worker(a.id, LogicalTime(0)).unwrap();
    engine.inject(task(1), Priority(0), LogicalTime(0)).unwrap();

    let (t, e1) = dispatch_to(&engine, LogicalTime(0), a.id);
    let _asg = a.recv(engine.bus()).expect("assignment");
    let leaf = [5u8; 32];
    let out = engine.on_submission(a.submit(t, e1, leaf), LogicalTime(1)).unwrap();

    let (output, _) = content_address(leaf);
    assert_eq!(out, SubmitOutcome::Accepted(output));
    assert_eq!(engine.release_count(), 1);
    assert!(engine.released(output).is_some());
    // Unsampled: no verify request was pushed.
    assert!(engine.bus().pop_verify().is_none());
}

#[test]
fn slow_zombie_submission_is_rejected_end_to_end() {
    // place -> lease@e1(A) -> A goes silent -> reclaim -> re-lease@e2(B) ->
    // zombie A submits@e1 (rejected) -> B submits@e2 -> exactly one release (B's).
    let engine = Engine::new(MemoryStore::new(), EngineConfig::for_workers(2), never_sample());
    let a = SimWorker { id: WorkerId(1) };
    let b = SimWorker { id: WorkerId(2) };
    engine.register_worker(a.id, LogicalTime(0)).unwrap();
    engine.register_worker(b.id, LogicalTime(0)).unwrap();
    engine.inject(task(1), Priority(0), LogicalTime(0)).unwrap();

    // First dispatch goes to A (least-loaded, smallest id at equal load).
    let (t, e1) = dispatch_to(&engine, LogicalTime(0), a.id);
    let asg_a = a.recv(engine.bus()).expect("A's assignment");
    assert_eq!(asg_a.lease.epoch, e1);

    // A is the slow worker: it neither submits nor heartbeats. At now = lease_ttl its lease
    // has expired AND it is past the liveness window (which is why reclaim fires).
    let reclaimed = loops::reclaim_tick(&engine, LogicalTime(100)).unwrap();
    assert_eq!(reclaimed, vec![t], "the expired lease is reclaimed");

    // B is alive (a fresh heartbeat/registration); A, unrefreshed, is now dead for placement.
    engine.register_worker(b.id, LogicalTime(100)).unwrap();
    let (t2, e2) = dispatch_to(&engine, LogicalTime(100), b.id);
    assert_eq!(t2, t);
    assert!(e2 > e1, "the re-lease epoch strictly exceeds the zombie's");
    let asg_b = b.recv(engine.bus()).expect("B's assignment");
    assert_eq!(asg_b.lease.epoch, e2);

    // The zombie A wakes and submits with its STALE epoch e1 — rejected at the durable store.
    let zombie = engine
        .on_submission(a.submit(t, e1, [0xAAu8; 32]), LogicalTime(101))
        .unwrap();
    assert_eq!(zombie, SubmitOutcome::RejectedZombie);
    assert_eq!(engine.release_count(), 0, "the zombie produced no output");

    // B submits legitimately with e2 — accepted, content-addressed released.
    let leaf_b = [0xBBu8; 32];
    let ok = engine
        .on_submission(b.submit(t, e2, leaf_b), LogicalTime(101))
        .unwrap();
    let (output_b, _) = content_address(leaf_b);
    assert_eq!(ok, SubmitOutcome::Accepted(output_b));

    // Exactly one output exists, and it is B's; the zombie's address was never released.
    assert_eq!(engine.release_count(), 1);
    assert!(engine.released(output_b).is_some());
    let (output_a, _) = content_address([0xAAu8; 32]);
    assert!(engine.released(output_a).is_none());
}

#[test]
fn failing_verify_escalates_reputation_and_requeues() {
    let engine = Engine::new(MemoryStore::new(), EngineConfig::for_workers(1), always_sample());
    let a = SimWorker { id: WorkerId(1) };
    engine.register_worker(a.id, LogicalTime(0)).unwrap();
    assert_eq!(engine.cached_tier(a.id), Some(Tier::Pristine));
    engine.inject(task(1), Priority(0), LogicalTime(0)).unwrap();

    let (t, e1) = dispatch_to(&engine, LogicalTime(0), a.id);
    let _asg = a.recv(engine.bus()).expect("assignment");
    let out = engine.on_submission(a.submit(t, e1, [7u8; 32]), LogicalTime(1)).unwrap();
    assert_eq!(out, SubmitOutcome::Sampled);

    // The verifier fails the segment.
    let v = SimVerifier;
    let req = v.recv(engine.bus()).expect("verify request");
    let vo = engine
        .on_verify_result(
            v.respond(&req, false, VerifyDetail::FidelityBelowThreshold),
            LogicalTime(2),
        )
        .unwrap();
    assert_eq!(vo, VerifyOutcome::Requeued, "a failed verify (within budget) requeues");

    // Reputation escalated sharply off Pristine, and the task is back ready.
    assert_eq!(
        engine.cached_tier(a.id),
        Some(Tier::Watch),
        "a failing verify escalates the worker's tier"
    );
    assert!(matches!(
        engine.store().load(t).unwrap().unwrap().state,
        TaskState::Pending
    ));
    assert_eq!(engine.release_count(), 0, "a failed segment is not released");
}

#[test]
fn dispatch_tick_drains_and_intake_sheds_at_the_cap() {
    // Wires the loop + placement caps + Little's-law intake shed together.
    let engine = Engine::new(MemoryStore::new(), EngineConfig::for_workers(2), never_sample());
    for w in [1u64, 2] {
        engine.register_worker(WorkerId(w), LogicalTime(0)).unwrap();
    }
    // Intake gate: admit up to the global queue cap (4·⌈L⌉ = 8 for from_measured(2)), then shed.
    let mut depth = 0u32;
    let mut shed = 0u32;
    for id in 1..=10u64 {
        match engine.admit(depth) {
            Ok(()) => {
                engine.inject(task(id), Priority(0), LogicalTime(0)).unwrap();
                depth += 1;
            }
            Err(Backpressure::QueueFull { .. }) => shed += 1,
        }
    }
    assert_eq!(depth, 8, "intake shed beyond the Little's-law global cap");
    assert_eq!(shed, 2);

    // Dispatch drains up to the per-worker in-flight caps: 2 workers × cap 2 = 4.
    let dispatched = loops::dispatch_tick(&engine, LogicalTime(0)).unwrap();
    assert_eq!(dispatched, 4, "two workers at in-flight cap 2 take four tasks");
}
