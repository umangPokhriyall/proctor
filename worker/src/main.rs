//! proctor `worker` — the untrusted hot loop.
//!
//! Receive a pushed lease -> `crypto` decrypt to anonymous memory -> ffmpeg over
//! `pipe:0`/`pipe:1` -> `crypto` encrypt in RAM -> commit the output hash. The worker
//! **receives** assignments; it never self-selects (locked decision #6). It persists no
//! plaintext and no keys.
//!
//! Phase 0 is a scaffold; the assembled hot loop lands in Phase 5.

// Phase 0 scaffold: the entry points below are stubs wired up in Phase 5.
#![allow(dead_code)]

use crypto::SecretKey;
use proctor_core::{Commitment, Lease};

fn main() {
    eprintln!("proctor worker — Phase 0 stub; hot loop lands in Phase 5");
}

/// Run one leased segment end-to-end and return the committed output hash.
fn run_segment(lease: Lease, key: &SecretKey, ciphertext: &[u8]) -> Commitment {
    // Phase 5: decrypt to anonymous memory, ffmpeg over pipes, encrypt in RAM, commit the hash.
    let _inputs = (key, ciphertext);
    let _lease = lease;
    todo!("Phase 5: lease -> decrypt -> ffmpeg(pipe) -> encrypt -> commit")
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
