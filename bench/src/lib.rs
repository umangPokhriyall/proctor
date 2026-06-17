//! proctor `bench` — the single-host N-worker harness library (phase6-spec.md §2–§3).
//!
//! The harness is split into a small library (these modules — the reusable, unit-tested
//! pieces Sessions 2–6 extend) and a thin binary (`main.rs`, the CLI that wires them for a
//! live run):
//!
//! - [`preprocess`] — the no-API workload authority: segment the deterministic corpus,
//!   `aead::encrypt` each segment, populate the [`crypto::LocalBlobStore`] +
//!   [`crypto::LocalKeySource`], and build the `Transcode` tasks (locked decision #2).
//! - [`orchestrate`] — spawn `sched` + N `worker`s + M `verifier`s as `taskset`-pinned
//!   subprocesses over a loopback Redis; clean teardown (locked decision #5).
//! - [`inject`] — the open-loop, coordinated-omission-correct injector at a target rate λ
//!   from intended-issue timestamps (the Rust-Tcp-Server methodology).
//! - [`metrics`] — per-process timestamped event logs, merged by task id into CO-correct
//!   latency distributions.
//!
//! `#![forbid(unsafe_code)]`, no async (phase6-spec.md hard rule 1): core-pinning is the
//! external `taskset` command, profiling is external `perf` — never FFI.

#![forbid(unsafe_code)]

/// A throwaway `Transcode` task with a dummy source — shared by the measurement/chaos
/// harnesses. Dispatch only reads `kind` to build the `Assignment`; no blob is fetched on the
/// dispatch path, so the source ref need not resolve.
#[must_use]
pub fn dummy_transcode_task(id: u64) -> proctor_core::Task {
    use proctor_core::{
        Codec, Container, JobId, SegmentId, SegmentRef, Task, TargetProfile, TaskId, TaskKind,
        TranscodeSpec,
    };
    Task::new(
        TaskId(id),
        TaskKind::Transcode(TranscodeSpec {
            job: JobId(1),
            segment: SegmentId(id),
            profile: TargetProfile {
                codec: Codec::H264,
                width: 320,
                height: 240,
                bitrate_kbps: 800,
                container: Container::Mp4,
            },
            source: SegmentRef(u128::from(id)),
        }),
    )
}

pub mod adversary;
pub mod decomp;
pub mod inject;
pub mod metrics;
pub mod orchestrate;
pub mod pipeline;
pub mod preprocess;
pub mod report;
pub mod saturation;
pub mod topology;
