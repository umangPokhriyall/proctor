//! proctor `sched` — the I/O-bound control plane.
//!
//! Redis-lease least-loaded **push** dispatch, heartbeat-extends-lease, the single
//! `XAUTOCLAIM` reclaim authority, explicit saturation backpressure, and a reputation
//! gate. All coordination state lives in Redis — never an in-process worker map.
//!
//! Phase 0 is a scaffold; the control plane lands in Phase 4.

// Phase 0 scaffold: the entry points below are stubs wired up in Phase 4.
#![allow(dead_code)]

use proctor_core::{Lease, WorkerId};

fn main() {
    eprintln!("proctor sched — Phase 0 stub; control plane lands in Phase 4");
}

/// Place a ready segment on the least-loaded eligible worker (push dispatch).
fn dispatch(candidate: WorkerId) -> Option<Lease> {
    todo!("Phase 4: least-loaded push dispatch (candidate = {candidate:?})")
}

/// The single lease-expiry reclaim authority (`XAUTOCLAIM`) — the sole writer of both
/// DB state and stream state, so they cannot diverge.
fn reclaim() {
    todo!("Phase 4: single lease-expiry reclaim path")
}

/// Apply backpressure when the global queue saturates (shed vs block — decided + documented).
fn backpressure() {
    todo!("Phase 4: explicit saturation backpressure")
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
