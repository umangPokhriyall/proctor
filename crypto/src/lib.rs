//! proctor `crypto` — in-memory, shard-scoped AES-256-GCM.
//!
//! Contract: per-segment keys are delivered over TLS, held `mlock`'d (no swap),
//! decrypted into **anonymous memory** (never disk), fed to ffmpeg over a pipe/`memfd`,
//! and zeroized on drop. This crate must never write plaintext or a key to disk, and
//! never log a key.
//!
//! Phase 0 declares **shape only** — every body is `todo!()`. The real implementation
//! (and the `aes-gcm` / `zeroize` deps) lands in Phase 2.

use thiserror::Error;

/// A zeroize-on-drop buffer for plaintext that must never touch disk.
pub struct SecretBuf {
    /// Plaintext bytes — `mlock`'d and zeroized on drop. Read by the ffmpeg pipe in Phase 2.
    #[allow(dead_code)] // Phase 2 wires the mlock'd buffer + zeroize-on-drop.
    bytes: Vec<u8>,
}

/// A per-segment AES-256 key: `mlock`'d, never logged, never written to disk, zeroized on drop.
pub struct SegmentKey {
    #[allow(dead_code)] // Phase 2 wires the mlock'd key material + zeroize-on-drop.
    key: [u8; 32],
}

/// Decrypt ciphertext into anonymous memory (never disk). The key is `mlock`'d and zeroized after use.
pub fn decrypt_in_memory(ciphertext: &[u8], key: &SegmentKey) -> Result<SecretBuf, CryptoError> {
    let _key = key;
    todo!("Phase 2: AES-256-GCM decrypt to anonymous memory ({} bytes)", ciphertext.len())
}

/// Encrypt plaintext in RAM before any buffer touches storage.
pub fn encrypt_in_memory(plaintext: &SecretBuf, key: &SegmentKey) -> Result<Vec<u8>, CryptoError> {
    let _inputs = (plaintext, key);
    todo!("Phase 2: in-RAM AES-256-GCM encrypt")
}

/// Errors surfaced by the in-memory crypto path.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AES-GCM authentication tag verification failed (ciphertext tampered or wrong key).
    #[error("AES-GCM authentication failed")]
    AuthFailed,
    /// Locking the key/plaintext into RAM (`mlock`) failed.
    #[error("mlock failed")]
    MlockFailed,
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
