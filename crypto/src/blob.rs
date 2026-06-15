//! `blob` — the content-addressed **ciphertext** store (phase5-spec.md §3).
//!
//! The data plane needs a place for the worker to upload its encrypted output and
//! for the worker/verifier to fetch encrypted sources. That store is **content
//! addressed**: a blob's address is `lead128(SHA-256(ciphertext))` — the leading
//! 128 bits, big-endian, of its SHA-256. This is the exact value
//! [`crate::SecretKey`]-bearing peers already agree on:
//! - the worker computes `commitment = Commitment::commit(&[SHA-256(blob)])` and
//!   `output = OutputRef(lead128(SHA-256(blob)))`;
//! - the verifier's `verify::check_binding` re-derives the same address;
//! - the scheduler releases by that content address, never by task id.
//!
//! So a blob stored by [`LocalBlobStore::put`] returns precisely the `OutputRef`
//! everyone else expects (phase5-spec.md §3, amendment §1.2.4) — and a swapped
//! blob lands at a different address, which is what closes the verified-then-
//! swapped TOCTOU.
//!
//! **Honesty boundary (phase2-spec.md, CLAUDE.md).** Only *ciphertext* is ever
//! written here. Plaintext never touches a disk-backed file — that invariant lives
//! in [`crate::memfd`]/[`crate::transcode`] and is untouched by this seam.
//!
//! [`LocalBlobStore`] is the measured single-host path (tmpfs/filesystem root). An
//! S3-style adapter MAY live behind [`BlobStore`] but is **never** in the measured
//! path (kickoff §6) and is not built here.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use proctor_core::{OutputRef, SegmentRef};
use sha2::{Digest, Sha256};

use crate::CryptoError;

/// A content-addressed store of encrypted blobs. Addresses are `u128` handles
/// ([`OutputRef`] for worker outputs, [`SegmentRef`] for sources) derived from the
/// blob's SHA-256, so identical bytes always resolve to the same slot.
pub trait BlobStore {
    /// Fetch a worker output blob by its content address. [`CryptoError::NotFound`]
    /// if no blob is stored at `addr`.
    fn get(&self, addr: &OutputRef) -> Result<Vec<u8>, CryptoError>;

    /// Store `ciphertext` and return its content address `lead128(SHA-256(...))`.
    /// Idempotent: storing identical bytes resolves to the same address/slot.
    fn put(&self, ciphertext: &[u8]) -> Result<OutputRef, CryptoError>;

    /// Fetch a source blob by its [`SegmentRef`] (the same content-address space).
    /// [`CryptoError::NotFound`] if absent.
    fn get_ref(&self, r: &SegmentRef) -> Result<Vec<u8>, CryptoError>;
}

/// The content address of `ciphertext`: the leading 128 bits, big-endian, of its
/// SHA-256. This is `lead128(SHA-256(ciphertext))` — identical to the address
/// `verify::check_binding` derives and the scheduler releases by.
#[must_use]
pub fn content_address(ciphertext: &[u8]) -> u128 {
    let digest = Sha256::digest(ciphertext);
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(hi)
}

/// The measured single-host blob store: one file per blob under a filesystem root
/// (tmpfs in the live run). The file name is the 32-hex-char content address, so
/// the layout *is* the content addressing and lookups are a single `fs::read`.
pub struct LocalBlobStore {
    /// The directory holding one ciphertext file per content address.
    root: PathBuf,
}

impl LocalBlobStore {
    /// Open (creating if needed) a store rooted at `root`. Only the directory is
    /// created here; blob files are written on [`put`](BlobStore::put).
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CryptoError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The on-disk path for a content address: `<root>/<addr-as-32-hex>`.
    fn path_for(&self, addr: u128) -> PathBuf {
        self.root.join(format!("{addr:032x}"))
    }

    /// Read the blob at a content address, mapping a missing file to
    /// [`CryptoError::NotFound`] (any other I/O error propagates verbatim).
    fn read(&self, addr: u128) -> Result<Vec<u8>, CryptoError> {
        match fs::read(self.path_for(addr)) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(CryptoError::NotFound),
            Err(e) => Err(CryptoError::Io(e)),
        }
    }

    /// Write `ciphertext` at its content address and return that address. Because
    /// the address is the content hash, re-storing identical bytes is a harmless
    /// overwrite of an identical file.
    fn write(&self, ciphertext: &[u8]) -> Result<u128, CryptoError> {
        let addr = content_address(ciphertext);
        fs::write(self.path_for(addr), ciphertext)?;
        Ok(addr)
    }

    /// Seed a source segment: content-address `ciphertext` and return its
    /// [`SegmentRef`] so it is later fetchable via [`get_ref`](BlobStore::get_ref).
    /// The benchmark/live harness uses this to stage encrypted sources; the worker
    /// path only ever calls [`put`](BlobStore::put)/[`get_ref`](BlobStore::get_ref).
    pub fn put_source(&self, ciphertext: &[u8]) -> Result<SegmentRef, CryptoError> {
        Ok(SegmentRef(self.write(ciphertext)?))
    }

    /// The filesystem root, for callers that need to point a peer at the same store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl BlobStore for LocalBlobStore {
    fn get(&self, addr: &OutputRef) -> Result<Vec<u8>, CryptoError> {
        self.read(addr.0)
    }

    fn put(&self, ciphertext: &[u8]) -> Result<OutputRef, CryptoError> {
        Ok(OutputRef(self.write(ciphertext)?))
    }

    fn get_ref(&self, r: &SegmentRef) -> Result<Vec<u8>, CryptoError> {
        self.read(r.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-cleaning unique temp directory (no `tempfile` dep — allowlist §2).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut p = std::env::temp_dir();
            p.push(format!("proctor-blob-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The leading-128-bit content address, computed independently of the store.
    fn lead128(blob: &[u8]) -> u128 {
        let d = Sha256::digest(blob);
        let mut hi = [0u8; 16];
        hi.copy_from_slice(&d[..16]);
        u128::from_be_bytes(hi)
    }

    #[test]
    fn put_get_round_trips_at_the_output_ref_content_address() {
        let dir = TempDir::new("roundtrip");
        let store = LocalBlobStore::open(&dir.0).unwrap();

        let blob = b"nonce || ciphertext || tag :: an encrypted output blob";
        let addr = store.put(blob).unwrap();

        // The returned address is exactly lead128(SHA-256(ciphertext)) — the same
        // OutputRef the worker/verifier/sched derive (phase5-spec.md §3).
        assert_eq!(addr, OutputRef(lead128(blob)));

        // And it round-trips: get(addr) yields the exact bytes stored.
        assert_eq!(store.get(&addr).unwrap(), blob);
    }

    #[test]
    fn put_is_deterministic_and_idempotent() {
        let dir = TempDir::new("idempotent");
        let store = LocalBlobStore::open(&dir.0).unwrap();

        let blob = b"the same bytes twice";
        let a = store.put(blob).unwrap();
        let b = store.put(blob).unwrap();
        assert_eq!(a, b, "content addressing must be deterministic");
        assert_eq!(store.get(&a).unwrap(), blob);
    }

    #[test]
    fn distinct_blobs_get_distinct_addresses() {
        let dir = TempDir::new("distinct");
        let store = LocalBlobStore::open(&dir.0).unwrap();

        let a = store.put(b"blob-a").unwrap();
        let b = store.put(b"blob-b").unwrap();
        assert_ne!(a, b);
        assert_eq!(store.get(&a).unwrap(), b"blob-a");
        assert_eq!(store.get(&b).unwrap(), b"blob-b");
    }

    #[test]
    fn seeded_source_is_fetchable_by_its_ref() {
        let dir = TempDir::new("source");
        let store = LocalBlobStore::open(&dir.0).unwrap();

        let source = b"an encrypted source segment";
        let r = store.put_source(source).unwrap();
        assert_eq!(r, SegmentRef(lead128(source)));
        assert_eq!(store.get_ref(&r).unwrap(), source);
    }

    #[test]
    fn missing_address_is_not_found() {
        let dir = TempDir::new("missing");
        let store = LocalBlobStore::open(&dir.0).unwrap();

        assert!(matches!(
            store.get(&OutputRef(0xDEAD_BEEF)),
            Err(CryptoError::NotFound)
        ));
        assert!(matches!(
            store.get_ref(&SegmentRef(0xABCD)),
            Err(CryptoError::NotFound)
        ));
    }
}
