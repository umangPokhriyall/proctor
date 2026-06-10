//! `key` — the [`SecretKey`] lifecycle (phase2-spec.md §3).
//!
//! A 256-bit AES key whose pages are `mlock`'d on construction (so they cannot
//! swap to a disk surface) and zeroized then `munlock`'d on drop. There is no
//! `Debug`/`Display` that prints bytes, no `Serialize`, no `Clone`, and no
//! `AsRef<[u8]>` that escapes the crate: the bytes are reachable only through the
//! in-crate [`expose`](SecretKey::expose) used by [`crate::aead`].
//!
//! **Rejected alternative (phase2-spec.md §3):** `Vec<u8>` + `buf.fill(0)` on drop.
//! The optimizer is free to elide a final write to memory that is about to be
//! freed; `zeroize` performs a volatile write that cannot be elided. The legacy
//! "secure delete" was theater — this is the real thing.

use core::fmt;

use zeroize::Zeroize;

use crate::{sys, CryptoError};

/// A 256-bit AES key. `mlock`'d against swap on construction; zeroized and
/// `munlock`'d on drop. Never logged, never serialized, never written to disk.
///
/// The backing bytes live in a heap [`Box`] so their address is stable for the
/// lifetime of the `mlock` pin (a moved value would leave the lock on stale pages).
pub struct SecretKey {
    /// `mlock`'d, zeroize-on-drop key material. Boxed so the pinned address is stable.
    key: Box<[u8; 32]>,
}

impl SecretKey {
    /// A fresh key from the OS CSPRNG ([`getrandom`]). The only production
    /// constructor. The key's pages are pinned with `mlock` **before** the random
    /// bytes are written, so the secret never lands on an unpinned (swappable) page.
    ///
    /// Returns `Err(MlockFailed)` if the pages cannot be pinned (document the
    /// `RLIMIT_MEMLOCK` requirement for the worker) or `Err(Csprng)` if the OS
    /// entropy source fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Box::new([0u8; 32]);
        sys::mlock(key.as_ptr(), 32)?;
        if getrandom::getrandom(key.as_mut_slice()).is_err() {
            // Unwind the pin and scrub the (still-zero) buffer before propagating.
            key.zeroize();
            sys::munlock(key.as_ptr(), 32);
            return Err(CryptoError::Csprng);
        }
        Ok(Self { key })
    }

    /// Test-only / key-injection constructor: build a key from caller-supplied
    /// bytes (e.g. a key delivered over TLS by the scheduler). The pages are
    /// `mlock`'d like [`generate`](Self::generate). The caller's `bytes` array is
    /// a separate, unpinned copy the caller is responsible for zeroizing.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        let key = Box::new(bytes);
        sys::mlock(key.as_ptr(), 32)?;
        Ok(Self { key })
    }

    /// In-crate access to the raw key bytes for the AEAD cipher construction.
    /// Deliberately `pub(crate)` — the key never escapes this crate uncontrolled.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Volatile, un-elidable scrub first, then release the pin over the same range.
        self.key.zeroize();
        sys::munlock(self.key.as_ptr(), 32);
    }
}

/// Redacted: never prints key bytes (phase2-spec.md §3 "no leakage surface").
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SecretKey::generate().expect("mlock+csprng available in tests");
        let b = SecretKey::generate().expect("mlock+csprng available in tests");
        // Astronomically unlikely to collide; a real failure means the CSPRNG is stuck.
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn from_bytes_round_trips_into_aead_use() {
        let raw = [7u8; 32];
        let k = SecretKey::from_bytes(raw).expect("mlock available in tests");
        assert_eq!(k.expose(), &raw);
    }

    #[test]
    fn debug_is_redacted_and_leaks_no_bytes() {
        // A pattern whose hex/decimal rendering would be visible if bytes leaked.
        let k = SecretKey::from_bytes([0xAB; 32]).expect("mlock available in tests");
        let s = format!("{k:?}");
        assert_eq!(s, "SecretKey(REDACTED)");
        assert!(!s.contains("ab") && !s.contains("AB") && !s.contains("171"));
    }

    #[test]
    fn zeroize_volatile_scrubs_key_bytes() {
        // Demonstrate the real zeroization the Drop path relies on: a volatile
        // write that the optimizer cannot elide, observed while the buffer is live.
        let mut k = SecretKey::from_bytes([0x5A; 32]).expect("mlock available in tests");
        assert_eq!(k.expose(), &[0x5A; 32]);
        k.key.zeroize();
        assert_eq!(k.expose(), &[0u8; 32]);
    }
}
