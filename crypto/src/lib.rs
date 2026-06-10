//! proctor `crypto` — in-memory, shard-scoped AES-256-GCM (phase2-spec.md).
//!
//! Per-segment keys are delivered over TLS, held `mlock`'d (no swap), and zeroized
//! on drop ([`key::SecretKey`]); each segment is sealed with AES-256-GCM under a
//! fresh 96-bit nonce, bound by AAD to its `(JobId, SegmentId, Role)` identity
//! ([`aead`]). Decryption returns plaintext only inside an `mlock`'d, zeroizing
//! [`aead::SecretBuf`]. This crate never writes a key or plaintext to disk and
//! never logs key material.
//!
//! **The unsafe boundary (phase2-spec.md §2).** `mlock`/`munlock` (and, in
//! Session 2, `memfd_create`) are libc FFI, so a zero-unsafe invariant is
//! impossible here. Instead the crate root is `#![deny(unsafe_code)]` and the
//! single [`sys`] module carries `#![allow(unsafe_code)]` with a `// SAFETY:`
//! comment on every block. Every other crate keeps `#![forbid(unsafe_code)]`.
//!
//! Session 1 lands [`key`] and [`aead`]; the `memfd`/`transcode` no-disk path
//! lands in Session 2.

#![deny(unsafe_code)]

use thiserror::Error;

pub mod aead;
pub mod key;
mod sys;

pub use aead::{decrypt, encrypt, EncryptedSegment, Role, SecretBuf, SegmentAad};
pub use key::SecretKey;

/// Errors surfaced by the in-memory crypto path. Authentication failure is the
/// security-critical one: it returns `Err` and never yields plaintext.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AES-GCM authentication failed — wrong key, nonce, tag, or AAD, or tampered
    /// ciphertext. No plaintext is returned.
    #[error("AES-GCM authentication failed")]
    AuthFailed,
    /// Pinning key/plaintext pages into RAM (`mlock`) failed — e.g. `RLIMIT_MEMLOCK`.
    /// A secret that could swap to disk is never silently accepted.
    #[error("mlock failed (check RLIMIT_MEMLOCK)")]
    MlockFailed,
    /// The OS CSPRNG (`getrandom`) failed to produce key or nonce bytes.
    #[error("OS CSPRNG (getrandom) failed")]
    Csprng,
    /// A buffer presented as an `EncryptedSegment` is too short to be valid.
    #[error("malformed encrypted segment")]
    Malformed,
    /// AES-GCM encryption failed (e.g. plaintext exceeds the GCM length bound).
    #[error("AES-GCM encryption failed")]
    Encrypt,
}
