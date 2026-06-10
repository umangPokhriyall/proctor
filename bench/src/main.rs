//! proctor `bench` — the single-host N-worker harness.
//!
//! **NO ingest API** (locked decision #2): workloads are injected **directly** into the
//! scheduler's queue via [`inject_workload`]. There is no `api` crate, ever. The harness
//! spins `sched` + `verifier` + N pinned worker processes over loopback against a local
//! blob store, drives the deterministic synthetic corpus (`bench/corpus/`), runs the
//! adversary simulator, and collects metrics into `bench/results/`.
//!
//! Phase 0 is a scaffold; the harness lands in Phase 6.

// Phase 0 scaffold: the entry point below is a stub wired up in Phase 6.
#![allow(dead_code)]

use proctor_core::Task;

fn main() {
    eprintln!("proctor bench — Phase 0 stub; harness lands in Phase 6");
}

/// Inject a workload **directly** into the scheduler queue — no HTTP, no network ingest.
/// This makes the locked no-API decision visible in code from day one. The unit of
/// work is a frozen `proctor_core::Task` (Phase 6 wires the real queue path).
pub fn inject_workload(task: Task) {
    todo!(
        "Phase 6: direct queue injection of task {:?} (kind {:?})",
        task.id,
        task.kind
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
