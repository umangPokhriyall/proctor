//! `memfd` — anonymous RAM, never a disk path (phase2-spec.md §5).
//!
//! [`MemFd`] wraps a `memfd_create` file descriptor: a seekable, RAM-backed file
//! that is **not** present in the filesystem namespace and is reachable only
//! through this process's fd table (or `/proc/self/fd/N`). Plaintext is decrypted
//! straight into a `MemFd` ([`decrypt_into_memfd`]) and handed to ffmpeg as a
//! `/proc/self/fd/N` URL — it never lands on a disk-backed file.
//!
//! **Why `memfd` over the rejected alternatives (phase2-spec.md §5):** a pipe is
//! non-seekable, so a container whose index is not at the front (default MP4 `moov`
//! at the end) fails or forces full buffering; `/dev/shm` is a real tmpfs path that
//! appears in the filesystem namespace and is openable by any process with access.
//! `memfd_create` is seekable *and* anonymous — the correct primitive.
//!
//! **Swap residual (phase2-spec.md §5):** memfd pages are anonymous and can swap
//! under memory pressure (a disk surface). Keys are always `mlock`'d; for plaintext
//! memfds the worker runs swap-off / under a memory-locked cgroup — a documented
//! deployment requirement and a recorded `THREAT-MODEL.md` residual, not hidden.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

use crate::aead::{decrypt, SecretBuf};
use crate::key::SecretKey;
use crate::{aead::EncryptedSegment, aead::SegmentAad, sys, CryptoError};

/// Chunk size for the zeroizing overwrite pass (one page-ish at a time).
const SCRUB_CHUNK: usize = 8192;

/// An anonymous, RAM-backed file. Seekable, never in the filesystem namespace,
/// referenced only via `/proc/self/fd/N`. Its contents are scrubbed (overwritten
/// with zeros + truncated) on [`zeroize_and_close`](MemFd::zeroize_and_close) and,
/// best-effort, on `Drop` — so plaintext never survives a `MemFd` going out of
/// scope on any exit path.
pub struct MemFd {
    /// A `File` view over the `memfd_create` fd. All I/O is safe Rust; only the
    /// fd's creation (in `sys`) needed `unsafe`.
    file: File,
    /// The label passed to `memfd_create` (for diagnostics; not a filesystem name).
    name: String,
}

impl MemFd {
    /// Create a fresh, empty anonymous RAM file labelled `name`.
    pub fn create(name: &str) -> Result<Self, CryptoError> {
        let fd = sys::memfd_create(name)?;
        Ok(Self {
            file: File::from(fd),
            name: name.to_string(),
        })
    }

    /// Overwrite the file's contents with exactly `bytes` (truncating any prior
    /// content). The data lives only in anonymous RAM.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(bytes)?;
        self.file.set_len(bytes.len() as u64)?;
        self.file.flush()?;
        Ok(())
    }

    /// Read the whole file into a pinned, zeroizing [`SecretBuf`] — plaintext never
    /// exists as a plain owned `Vec` longer than the read itself.
    pub fn read_to_secret_buf(&mut self) -> Result<SecretBuf, CryptoError> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf)?;
        SecretBuf::from_vec(buf)
    }

    /// The `/proc/self/fd/N` URL ffmpeg is given as an input/output — never a disk
    /// path. Valid only within this process (and children that inherit the fd).
    pub fn proc_path(&self) -> String {
        format!("/proc/self/fd/{}", self.file.as_raw_fd())
    }

    /// The raw fd, so the spawn path can clear `CLOEXEC` for the ffmpeg child.
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }

    /// Scrub the contents (overwrite with zeros, then `ftruncate(0)`) before the fd
    /// is closed. Explicit, deterministic counterpart to the best-effort `Drop`.
    /// No DoD-5220 theater — a single zero pass over anonymous RAM is the property
    /// ("plaintext overwritten before release"), not a ritual (phase2-spec.md §6).
    pub fn zeroize_and_close(mut self) {
        self.scrub();
        // `self` drops here, closing the fd; `Drop::scrub` re-runs on a now-empty
        // file (a cheap no-op) — idempotent and harmless.
    }

    /// Best-effort overwrite-with-zeros + truncate. Errors are ignored: this runs on
    /// drop / cleanup paths where there is nothing actionable to do, and the fd is
    /// closed (releasing the RAM) regardless.
    fn scrub(&mut self) {
        let len = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        if len > 0 && self.file.seek(SeekFrom::Start(0)).is_ok() {
            let zeros = [0u8; SCRUB_CHUNK];
            let mut remaining = len as usize;
            while remaining > 0 {
                let n = remaining.min(zeros.len());
                if self.file.write_all(&zeros[..n]).is_err() {
                    break;
                }
                remaining -= n;
            }
            let _ = self.file.flush();
        }
        let _ = self.file.set_len(0);
    }
}

impl Drop for MemFd {
    fn drop(&mut self) {
        // Plaintext must not survive a MemFd going out of scope on any exit path.
        self.scrub();
    }
}

impl std::fmt::Debug for MemFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The contents may be plaintext — never print them.
        write!(f, "MemFd(name={:?}, fd={})", self.name, self.file.as_raw_fd())
    }
}

/// Decrypt `enc` straight into a fresh anonymous RAM file. The intermediate
/// [`SecretBuf`] is pinned and zeroized as soon as its bytes are written, so
/// plaintext lives only in the returned `MemFd` (anonymous RAM) — never on disk.
pub fn decrypt_into_memfd(
    enc: &EncryptedSegment,
    key: &SecretKey,
    aad: &SegmentAad,
    name: &str,
) -> Result<MemFd, CryptoError> {
    let plaintext = decrypt(enc, key, aad)?;
    let mut mf = MemFd::create(name)?;
    // On any error after this point `mf` drops and scrubs itself.
    mf.write_all(plaintext.as_bytes())?;
    Ok(mf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{encrypt, Role};
    use proctor_core::{JobId, SegmentId};

    fn aad() -> SegmentAad {
        SegmentAad {
            job: JobId(3),
            segment: SegmentId(9),
            role: Role::Source,
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut mf = MemFd::create("proctor-test").unwrap();
        let data = b"anonymous RAM bytes, never on disk";
        mf.write_all(data).unwrap();
        let got = mf.read_to_secret_buf().unwrap();
        assert_eq!(got.as_bytes(), data);
    }

    #[test]
    fn rewrite_truncates_prior_content() {
        let mut mf = MemFd::create("proctor-test").unwrap();
        mf.write_all(b"the quick brown fox jumped").unwrap();
        mf.write_all(b"short").unwrap();
        let got = mf.read_to_secret_buf().unwrap();
        assert_eq!(got.as_bytes(), b"short");
    }

    #[test]
    fn proc_path_is_anonymous_fd_and_resolves_to_memfd() {
        let mf = MemFd::create("proctor-label").unwrap();
        let path = mf.proc_path();
        assert!(path.starts_with("/proc/self/fd/"));
        // The fd resolves to an anonymous `memfd:` link, not a real filesystem path.
        let target = std::fs::read_link(&path).unwrap();
        let target = target.to_string_lossy();
        assert!(
            target.contains("memfd:"),
            "expected anonymous memfd, got {target}"
        );
    }

    #[test]
    fn decrypt_into_memfd_lands_plaintext_in_ram() {
        let key = SecretKey::generate().unwrap();
        let plaintext = b"decrypted straight into anonymous RAM";
        let enc = encrypt(plaintext, &key, &aad()).unwrap();
        let mut mf = decrypt_into_memfd(&enc, &key, &aad(), "proctor-plain").unwrap();
        assert_eq!(mf.read_to_secret_buf().unwrap().as_bytes(), plaintext);
        // And it is an anonymous fd, not a disk file.
        let target = std::fs::read_link(mf.proc_path()).unwrap();
        assert!(target.to_string_lossy().contains("memfd:"));
    }

    #[test]
    fn decrypt_into_memfd_rejects_tampered_ciphertext() {
        let key = SecretKey::generate().unwrap();
        let mut enc = encrypt(b"secret", &key, &aad()).unwrap();
        let wire = {
            let mut b = enc.to_bytes();
            b[20] ^= 0x01; // flip a ciphertext bit
            b
        };
        enc = EncryptedSegment::from_bytes(&wire).unwrap();
        assert!(matches!(
            decrypt_into_memfd(&enc, &key, &aad(), "proctor-plain"),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn zeroize_and_close_consumes_without_panic() {
        let mut mf = MemFd::create("proctor-test").unwrap();
        mf.write_all(b"scrub me").unwrap();
        mf.zeroize_and_close();
    }
}
