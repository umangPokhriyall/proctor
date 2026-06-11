//! proctor `verifier` — the CPU-bound trusted verifier.
//!
//! Re-executes ffmpeg on a random sampled subset of a worker's completed segments with
//! byte-identical parameters, decodes frames at challenged timestamps, and compares to the
//! worker's output via `verify::ssim`. It is a **separate binary** from `sched` (locked
//! decision #3) so CPU-bound re-execution never pollutes the I/O-bound scheduler. The
//! expected hash never leaves this process.
//!
//! Phase 0 is a scaffold; re-execution + SSIM compare land in Phase 3.

// Phase 0 scaffold: the entry points below are stubs wired up in Phase 3.
#![allow(dead_code)]

use proctor_core::SegmentId;
use verify::{ssim, Frame};

fn main() {
    eprintln!("proctor verifier — Phase 0 stub; re-execution lands in Phase 3");
}

/// Re-execute ffmpeg on a sampled segment (byte-identical params), then compare frames via SSIM.
fn reexecute(segment: SegmentId, reference: &Frame, candidate: &Frame) -> f64 {
    // `segment` selects which sampled output to re-encode in Phase 3.
    let _sampled = segment;
    // `ssim` now returns a Result (dimension mismatch is an error); the real per-segment
    // flow lives in verify::compare (a later session). A mismatch ⇒ maximally dissimilar.
    ssim(reference, candidate).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
