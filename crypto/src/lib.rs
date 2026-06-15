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
//! Session 1 landed [`key`] and [`aead`]; Session 2 adds the no-disk path —
//! [`memfd`] (anonymous RAM, decrypt-into-memfd, child fd hand-off) and
//! [`transcode`] (ffmpeg over `/proc/self/fd/N`, never a disk path).

#![deny(unsafe_code)]

use thiserror::Error;

pub mod aead;
pub mod blob;
pub mod key;
pub mod keysource;
pub mod memfd;
mod sys;
pub mod transcode;

pub use aead::{decrypt, encrypt, EncryptedSegment, Role, SecretBuf, SegmentAad};
pub use blob::{BlobStore, LocalBlobStore};
pub use key::SecretKey;
pub use keysource::{KeySource, LocalKeySource};
pub use memfd::{decrypt_into_memfd, MemFd};
pub use transcode::{ffmpeg_no_disk, transcode_no_disk};

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
    /// A requested content address (blob) or per-segment key is absent from the
    /// local store. Phase 5 data-plane seams ([`blob`], [`keysource`]).
    #[error("not found in local store")]
    NotFound,
    /// AES-GCM encryption failed (e.g. plaintext exceeds the GCM length bound).
    #[error("AES-GCM encryption failed")]
    Encrypt,
    /// `memfd_create` (or its labelling) failed — no anonymous RAM file available.
    #[error("memfd_create failed")]
    Memfd,
    /// An I/O error on a memfd or the ffmpeg child (read/write/seek/spawn).
    #[error("crypto I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// ffmpeg exited non-zero. Carries a bounded tail of stderr (never media).
    #[error("ffmpeg transcode failed: {stderr_tail}")]
    TranscodeFailed {
        /// The last few KiB of ffmpeg stderr, where the cause is.
        stderr_tail: String,
    },
    /// ffmpeg exceeded the wall-clock budget and was killed.
    #[error("ffmpeg transcode timed out")]
    Timeout,
}
