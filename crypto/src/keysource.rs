//! `keysource` — per-segment [`SecretKey`] delivery (phase5-spec.md §3).
//!
//! Both the worker and the verifier are *key-trusted*: each fetches the per-segment
//! AES key to decrypt its shard. [`KeySource`] is that delivery seam.
//!
//! **The production seam is TLS, and it is deliberately not built here.** In
//! production the key is delivered over an authenticated TLS channel from a key
//! authority (kickoff §6); that authority, its mutual-TLS handshake, and its access
//! policy are out of scope for the single-host benchmark. [`LocalKeySource`] is the
//! benchmark stand-in: an in-process map from `(JobId, SegmentId)` to key bytes,
//! handed out as a freshly `mlock`'d [`SecretKey`] on each fetch.
//!
//! **The honest confidentiality boundary (phase2-spec.md, THREAT-MODEL.md).**
//! Handing the untrusted worker its shard key is *intentional*: the worker must
//! decrypt to transcode, so it can see its shard's plaintext, and root-on-worker
//! defeats confidentiality. This is the documented boundary the microVM flagship
//! exists to close — nothing here pretends otherwise.
//!
//! Note the benchmark store holds raw key bytes in RAM only, wrapped in
//! [`Zeroizing`] so they are scrubbed on drop. They are **never** serialized or
//! written to disk (CLAUDE.md crypto invariants); the delivered [`SecretKey`] keeps
//! the full Phase 2 lifecycle (`mlock`'d, redacted, zeroized).

use std::collections::HashMap;

use proctor_core::{JobId, SegmentId};
use zeroize::Zeroizing;

use crate::{CryptoError, SecretKey};

/// Delivers the per-segment AES key to a key-trusted peer (worker or verifier).
/// The production implementation fetches over TLS from a key authority; the
/// benchmark uses [`LocalKeySource`].
pub trait KeySource {
    /// The 256-bit key sealing `(job, segment)`, as a freshly `mlock`'d
    /// [`SecretKey`]. [`CryptoError::NotFound`] if no key is registered.
    fn key(&self, job: JobId, segment: SegmentId) -> Result<SecretKey, CryptoError>;
}

/// The benchmark key store: an in-memory `(JobId, SegmentId) -> key bytes` map.
/// The production key authority (TLS) is **not** built (kickoff §6). Key bytes are
/// held in [`Zeroizing`] RAM and never persisted.
#[derive(Default)]
pub struct LocalKeySource {
    /// Raw key material, scrubbed on drop; never serialized, never on disk.
    keys: HashMap<(JobId, SegmentId), Zeroizing<[u8; 32]>>,
}

impl LocalKeySource {
    /// An empty key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the key bytes for `(job, segment)`. The benchmark harness calls
    /// this when it stages a segment's encrypted source/output. The caller's
    /// `bytes` array is a separate copy the caller is responsible for scrubbing.
    pub fn insert(&mut self, job: JobId, segment: SegmentId, bytes: [u8; 32]) {
        self.keys.insert((job, segment), Zeroizing::new(bytes));
    }
}

impl KeySource for LocalKeySource {
    fn key(&self, job: JobId, segment: SegmentId) -> Result<SecretKey, CryptoError> {
        let raw = self
            .keys
            .get(&(job, segment))
            .ok_or(CryptoError::NotFound)?;
        // Hand out a fresh, independently `mlock`'d key; the store keeps its copy.
        SecretKey::from_bytes(**raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_key_is_fetched_with_the_right_bytes() {
        let mut src = LocalKeySource::new();
        let bytes = [0x42u8; 32];
        src.insert(JobId(7), SegmentId(3), bytes);

        let key = src.key(JobId(7), SegmentId(3)).expect("key registered");
        // `expose` is pub(crate); within `crypto` we can confirm the delivered key
        // carries exactly the registered bytes.
        assert_eq!(key.expose(), &bytes);
    }

    #[test]
    fn distinct_segments_get_their_own_keys() {
        let mut src = LocalKeySource::new();
        src.insert(JobId(1), SegmentId(1), [0x11; 32]);
        src.insert(JobId(1), SegmentId(2), [0x22; 32]);

        assert_eq!(src.key(JobId(1), SegmentId(1)).unwrap().expose(), &[0x11; 32]);
        assert_eq!(src.key(JobId(1), SegmentId(2)).unwrap().expose(), &[0x22; 32]);
    }

    #[test]
    fn unregistered_segment_is_not_found() {
        let src = LocalKeySource::new();
        assert!(matches!(
            src.key(JobId(0), SegmentId(0)),
            Err(CryptoError::NotFound)
        ));
    }
}
