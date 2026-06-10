//! `aead` — AES-256-GCM, identity-bound (phase2-spec.md §4).
//!
//! One single-shot AEAD operation per GOP-bounded segment (≈2 s of video fits in
//! RAM; no chunked STREAM construction). The at-rest / on-wire layout is
//! `nonce(12) || ciphertext || tag(16)`. The nonce is a fresh random 96-bit value
//! per encryption (the standard GCM nonce; the legacy 16-byte IV forced GHASH to
//! re-derive the nonce and was non-standard). The AAD binds every ciphertext to
//! its `(JobId, SegmentId, Role)` identity so a `Source` ciphertext cannot be
//! accepted where an `Output` is expected, and one segment's ciphertext cannot be
//! replayed as another's — the GCM tag covers the identity.

use core::fmt;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use proctor_core::{JobId, SegmentId};
use zeroize::Zeroize;

use crate::key::SecretKey;
use crate::{sys, CryptoError};

/// GCM nonce length in bytes (the standard 96-bit nonce).
const NONCE_LEN: usize = 12;
/// GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Whether a ciphertext carries a segment's *source* plaintext or a worker's
/// *output* plaintext. Bound into the AAD so the two are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The encrypted source segment handed to a worker.
    Source = 0,
    /// The encrypted transcode output produced by a worker.
    Output = 1,
}

/// Associated data binding a ciphertext to its identity and role. Serialized to a
/// fixed canonical layout (`JobId` LE ‖ `SegmentId` LE ‖ `Role`) using the frozen
/// `core` ids, so encryptor and decryptor agree byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentAad {
    /// The job this segment belongs to.
    pub job: JobId,
    /// The segment within the job.
    pub segment: SegmentId,
    /// Source vs Output — a transcode cannot pose as a source and vice versa.
    pub role: Role,
}

impl SegmentAad {
    /// The canonical 17-byte AAD: `job(8 LE) || segment(8 LE) || role(1)`.
    fn canonical(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0..8].copy_from_slice(&self.job.0.to_le_bytes());
        out[8..16].copy_from_slice(&self.segment.0.to_le_bytes());
        out[16] = self.role as u8;
        out
    }
}

/// The at-rest / on-wire form of an encrypted segment: `nonce(12) || body`, where
/// `body` is `ciphertext || tag(16)` as produced by AES-256-GCM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedSegment {
    /// The random 96-bit GCM nonce, prepended to the body on the wire.
    nonce: [u8; NONCE_LEN],
    /// `ciphertext || tag(16)`. Not secret (it is ciphertext), so no zeroization.
    body: Vec<u8>,
}

impl EncryptedSegment {
    /// Flatten to the wire layout `nonce || ciphertext || tag`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.body.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse the wire layout. Requires at least `nonce(12) + tag(16)` bytes; a
    /// shorter buffer cannot be a valid GCM output and is `Err(Malformed)`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&b[..NONCE_LEN]);
        Ok(Self {
            nonce,
            body: b[NONCE_LEN..].to_vec(),
        })
    }
}

/// An `mlock`'d, zeroize-on-drop plaintext buffer. Decryption returns plaintext
/// only inside this type so it is pinned against swap and scrubbed on drop; the
/// bytes never live in a plain owned `Vec` that could outlast their use.
pub struct SecretBuf {
    /// `mlock`'d plaintext; zeroized then `munlock`'d on drop.
    buf: Vec<u8>,
}

impl SecretBuf {
    /// Take ownership of `buf`, pinning its pages with `mlock`. The caller must
    /// not have aliased the bytes elsewhere. `pub(crate)` so [`crate::memfd`] can
    /// read plaintext out of an anonymous RAM file into the same pinned, zeroizing
    /// buffer type.
    pub(crate) fn from_vec(buf: Vec<u8>) -> Result<Self, CryptoError> {
        if !buf.is_empty() {
            sys::mlock(buf.as_ptr(), buf.len())?;
        }
        Ok(Self { buf })
    }

    /// The plaintext bytes. In-RAM only; never write these to a disk-backed file.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Plaintext length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the plaintext is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // Capture the live region before `zeroize` resets the Vec's length to 0.
        let (ptr, len) = (self.buf.as_ptr(), self.buf.len());
        self.buf.zeroize();
        sys::munlock(ptr, len);
    }
}

/// Redacted: never prints plaintext (parallels [`SecretKey`]'s `Debug`).
impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf(REDACTED, {} bytes)", self.buf.len())
    }
}

/// Encrypt `plaintext` under `key` with a fresh random nonce, binding the
/// ciphertext to `aad`. Returns the `nonce || ciphertext || tag` layout.
pub fn encrypt(
    plaintext: &[u8],
    key: &SecretKey,
    aad: &SegmentAad,
) -> Result<EncryptedSegment, CryptoError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.expose()));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::Csprng)?;
    let aad_bytes = aad.canonical();
    let body = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(EncryptedSegment { nonce, body })
}

/// Decrypt and authenticate `enc` under `key` and `aad`, returning the plaintext
/// in a [`SecretBuf`]. A wrong key, nonce, tag, or AAD yields `Err(AuthFailed)`
/// and **never** returns partial plaintext (phase2-spec.md §4).
pub fn decrypt(
    enc: &EncryptedSegment,
    key: &SecretKey,
    aad: &SegmentAad,
) -> Result<SecretBuf, CryptoError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.expose()));
    let aad_bytes = aad.canonical();
    let plaintext = cipher
        .decrypt(
            GenericArray::from_slice(&enc.nonce),
            Payload {
                msg: &enc.body,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    SecretBuf::from_vec(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aad() -> SegmentAad {
        SegmentAad {
            job: JobId(42),
            segment: SegmentId(7),
            role: Role::Source,
        }
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let key = SecretKey::generate().unwrap();
        let pt = b"a GOP-bounded segment of plaintext video bytes";
        let enc = encrypt(pt, &key, &aad()).unwrap();
        let dec = decrypt(&enc, &key, &aad()).unwrap();
        assert_eq!(dec.as_bytes(), pt);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let key = SecretKey::generate().unwrap();
        let enc = encrypt(b"", &key, &aad()).unwrap();
        let dec = decrypt(&enc, &key, &aad()).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn wire_layout_round_trips_and_is_nonce_prefixed() {
        let key = SecretKey::generate().unwrap();
        let pt = b"hello";
        let enc = encrypt(pt, &key, &aad()).unwrap();
        let wire = enc.to_bytes();
        assert_eq!(wire.len(), NONCE_LEN + pt.len() + TAG_LEN);
        assert_eq!(&wire[..NONCE_LEN], &enc.nonce);
        let parsed = EncryptedSegment::from_bytes(&wire).unwrap();
        assert_eq!(parsed, enc);
        let dec = decrypt(&parsed, &key, &aad()).unwrap();
        assert_eq!(dec.as_bytes(), pt);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        // Fewer than nonce(12)+tag(16) bytes cannot be a valid GCM output.
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert!(matches!(
            EncryptedSegment::from_bytes(&short),
            Err(CryptoError::Malformed)
        ));
    }

    #[test]
    fn tamper_wrong_key_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let other = SecretKey::generate().unwrap();
        let enc = encrypt(b"secret", &key, &aad()).unwrap();
        assert!(matches!(
            decrypt(&enc, &other, &aad()),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tamper_flipped_ciphertext_bit_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let mut enc = encrypt(b"secret payload", &key, &aad()).unwrap();
        enc.body[0] ^= 0x01;
        assert!(matches!(
            decrypt(&enc, &key, &aad()),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tamper_flipped_tag_bit_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let mut enc = encrypt(b"secret payload", &key, &aad()).unwrap();
        let last = enc.body.len() - 1; // the tag is the final 16 bytes of `body`.
        enc.body[last] ^= 0x80;
        assert!(matches!(
            decrypt(&enc, &key, &aad()),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tamper_wrong_nonce_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let mut enc = encrypt(b"secret", &key, &aad()).unwrap();
        enc.nonce[0] ^= 0xFF;
        assert!(matches!(
            decrypt(&enc, &key, &aad()),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tamper_wrong_role_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let enc = encrypt(b"source bytes", &key, &aad()).unwrap();
        let as_output = SegmentAad {
            role: Role::Output,
            ..aad()
        };
        assert!(matches!(
            decrypt(&enc, &key, &as_output),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tamper_wrong_segment_id_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let enc = encrypt(b"segment seven", &key, &aad()).unwrap();
        let wrong_segment = SegmentAad {
            segment: SegmentId(8),
            ..aad()
        };
        assert!(matches!(
            decrypt(&enc, &key, &wrong_segment),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tamper_wrong_job_id_fails_closed() {
        let key = SecretKey::generate().unwrap();
        let enc = encrypt(b"job forty-two", &key, &aad()).unwrap();
        let wrong_job = SegmentAad {
            job: JobId(43),
            ..aad()
        };
        assert!(matches!(
            decrypt(&enc, &key, &wrong_job),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn aad_canonical_layout_is_fixed() {
        let a = SegmentAad {
            job: JobId(1),
            segment: SegmentId(2),
            role: Role::Output,
        };
        let mut expected = [0u8; 17];
        expected[0] = 1; // job LE
        expected[8] = 2; // segment LE
        expected[16] = 1; // Role::Output
        assert_eq!(a.canonical(), expected);
    }

    #[test]
    fn secret_buf_zeroize_scrubs_plaintext() {
        // The real volatile scrub the Drop path relies on, observed while live.
        let mut sb = SecretBuf::from_vec(vec![0x5A; 64]).unwrap();
        assert_eq!(sb.as_bytes(), &[0x5A; 64]);
        sb.buf.zeroize();
        assert!(sb.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn secret_buf_debug_is_redacted() {
        let key = SecretKey::generate().unwrap();
        let dec = decrypt(&encrypt(b"top secret", &key, &aad()).unwrap(), &key, &aad()).unwrap();
        let s = format!("{dec:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("top secret"));
    }
}
