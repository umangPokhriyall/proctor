//! `transcode_task` — the Transcode hot loop (phase5-spec.md §4.2), the load-bearing
//! proof of the live data plane.
//!
//! Fetch the encrypted source by its content address → decrypt into anonymous RAM
//! (`Role::Source`) → `transcode_no_disk` → encrypt the output in RAM
//! (`Role::Output`) → commit `Commitment::commit(&[SHA-256(blob)])` with
//! `output = lead128(SHA-256(blob))` → upload to the content-addressed blob store →
//! return a [`SubmissionMsg`] **carrying the lease epoch**. The store fences a
//! stale-epoch submit (a slow zombie); the worker does not need to know it lost the
//! lease (§1.1).
//!
//! **No plaintext on disk:** the source and transcoded plaintext live only in
//! [`crypto::MemFd`]s (anonymous RAM). They are `zeroize_and_close`d on the happy
//! path and scrubbed by `MemFd::drop` on every `?`/panic path; the `SecretKey` is
//! `mlock`'d and zeroized on drop; the decrypted output plaintext lives only in an
//! `mlock`'d, zeroizing `SecretBuf`. Only ciphertext is ever uploaded.

use crypto::{
    aead, decrypt_into_memfd, transcode_no_disk, BlobStore, EncryptedSegment, KeySource, Role,
    SegmentAad,
};
use proctor_core::{Assignment, SubmissionMsg, TranscodeSpec, WorkerId};

use crate::{commit_output, WorkerError};

/// Run one leased `Transcode` end-to-end and produce the epoch-carrying submission.
/// `blob` is the content-addressed ciphertext store; `keys` delivers the per-segment
/// key (the documented confidentiality boundary — the untrusted worker holds the
/// key). The returned [`SubmissionMsg`] echoes `assignment.lease.epoch` so the store
/// can reject it if the lease has since been reclaimed.
pub fn run_transcode<B, K>(
    assignment: &Assignment,
    spec: &TranscodeSpec,
    blob: &B,
    keys: &K,
    worker: WorkerId,
) -> Result<SubmissionMsg, WorkerError>
where
    B: BlobStore,
    K: KeySource,
{
    let key = keys.key(spec.job, spec.segment)?;
    let source_aad = SegmentAad {
        job: spec.job,
        segment: spec.segment,
        role: Role::Source,
    };
    let output_aad = SegmentAad {
        job: spec.job,
        segment: spec.segment,
        role: Role::Output,
    };

    // 1–2. Fetch source ciphertext by its content address and decrypt straight into
    // anonymous RAM. On any later `?`, `src` drops and scrubs itself.
    let source_ct = blob.get_ref(&spec.source)?;
    let enc = EncryptedSegment::from_bytes(&source_ct)?;
    let src = decrypt_into_memfd(&enc, &key, &source_aad, "proctor-src")?;

    // 3. Transcode in RAM (ffmpeg over /proc/self/fd/N). `transcode_no_disk` scrubs
    // its own output memfd on error; `src` drops+scrubs on the `?`.
    let mut out = transcode_no_disk(&src, &spec.profile)?;
    src.zeroize_and_close(); // source plaintext no longer needed — scrub it now

    // 4. Read the transcoded plaintext into a pinned, zeroizing buffer and re-encrypt
    // it (Role::Output). The plaintext `SecretBuf` is zeroized when the block ends.
    let out_blob = {
        let plaintext = out.read_to_secret_buf()?;
        aead::encrypt(plaintext.as_bytes(), &key, &output_aad)?.to_bytes()
    };
    out.zeroize_and_close(); // transcoded plaintext scrubbed; only ciphertext remains

    // 5. Commit (single-leaf Merkle over SHA-256(blob)) + content address.
    let (commitment, output) = commit_output(&out_blob);

    // 6. Upload. The store content-addresses by the same lead128(SHA-256), so the
    // returned ref MUST equal our derived `output` — a divergence would mean the
    // blob store and the commitment math disagree (it cannot, by construction).
    let stored = blob.put(&out_blob)?;
    if stored != output {
        return Err(WorkerError::AddressDisagreement);
    }

    // 7. Submit, carrying the lease epoch (the slow zombie is fenced by the store).
    Ok(SubmissionMsg {
        task: assignment.task,
        worker,
        epoch: assignment.lease.epoch,
        commitment,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proctor_core::{
        Codec, Container, Epoch, JobId, Lease, LogicalTime, SegmentId, TargetProfile, TaskId,
        TaskKind, TranscodeSpec,
    };
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    /// A self-cleaning unique temp dir (no `tempfile` dep — allowlist §2).
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut p = std::env::temp_dir();
            p.push(format!("proctor-worker-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ffmpeg_available() -> bool {
        Command::new("ffmpeg")
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The contract that the whole binding chain rests on, proven without ffmpeg:
    /// the worker's `commit_output` is exactly what the verifier's `check_binding`
    /// accepts, and a one-bit swap is rejected. Calls the REAL `verify::check_binding`.
    #[test]
    fn commit_output_is_accepted_by_check_binding_and_swap_is_rejected() {
        let blob = b"nonce || ciphertext || tag :: a worker output blob";
        let (commitment, output) = commit_output(blob);

        // The verifier accepts the honest blob and re-derives the same content address.
        let bound = verify::check_binding(blob, &commitment).expect("honest output must bind");
        assert_eq!(bound, output, "check_binding must agree on the content address");

        // A post-commit swap (one flipped bit) is rejected — the anti-swap chain.
        let mut swapped = blob.to_vec();
        swapped[0] ^= 0x01;
        assert!(
            verify::check_binding(&swapped, &commitment).is_err(),
            "a swapped blob must fail the binding"
        );
    }

    fn corpus(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../bench/corpus")
            .join(name)
    }

    /// End-to-end over the real crypto+ffmpeg path: the worker's *actual* transcode
    /// output binds under `check_binding` at the submitted `output`, a swap of the
    /// uploaded blob is rejected, and the submission carries the lease epoch.
    #[test]
    fn real_transcode_output_binds_and_carries_epoch() {
        if !ffmpeg_available() {
            eprintln!("SKIP real_transcode_output_binds_and_carries_epoch: ffmpeg not found");
            return;
        }
        let bytes = match std::fs::read(corpus("gradient.mp4")) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP: corpus unavailable: {e}");
                return;
            }
        };

        let dir = TempDir::new("transcode");
        let store = crypto::LocalBlobStore::open(&dir.0).unwrap();

        // Seed: one key, the encrypted source staged in the blob store at its address.
        let (job, segment) = (JobId(1), SegmentId(2));
        let raw_key = [0x5Au8; 32];
        let mut keys = crypto::LocalKeySource::new();
        keys.insert(job, segment, raw_key);

        let secret = crypto::SecretKey::from_bytes(raw_key).unwrap();
        let source_aad = SegmentAad {
            job,
            segment,
            role: Role::Source,
        };
        let source_ct = aead::encrypt(&bytes, &secret, &source_aad).unwrap().to_bytes();
        let source_ref = store.put_source(&source_ct).unwrap();

        let spec = TranscodeSpec {
            job,
            segment,
            profile: TargetProfile {
                codec: Codec::H264,
                width: 640,
                height: 360,
                bitrate_kbps: 1500,
                container: Container::Mp4,
            },
            source: source_ref,
        };
        let assignment = Assignment {
            task: TaskId(99),
            kind: TaskKind::Transcode(spec.clone()),
            lease: Lease {
                holder: WorkerId(7),
                epoch: Epoch(42),
                deadline: LogicalTime(1000),
            },
            source: source_ref,
        };

        let sub = run_transcode(&assignment, &spec, &store, &keys, WorkerId(7))
            .expect("honest transcode must succeed");

        // The epoch is carried verbatim (the fencing token) and identity is echoed.
        assert_eq!(sub.epoch, Epoch(42));
        assert_eq!(sub.task, TaskId(99));
        assert_eq!(sub.worker, WorkerId(7));

        // The uploaded blob binds under the REAL verifier check at the submitted ref.
        let uploaded = store.get(&sub.output).unwrap();
        let bound = verify::check_binding(&uploaded, &sub.commitment)
            .expect("the worker's real output must bind");
        assert_eq!(bound, sub.output);

        // The uploaded ciphertext is not the plaintext corpus (it was re-encrypted).
        assert_ne!(uploaded, bytes, "uploaded blob must be ciphertext, not plaintext");

        // A swap of the uploaded blob is caught by the binding (anti-swap chain).
        let mut swapped = uploaded.clone();
        swapped[0] ^= 0x01;
        assert!(verify::check_binding(&swapped, &sub.commitment).is_err());
    }
}
