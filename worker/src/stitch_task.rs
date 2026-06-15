//! `stitch_task` — the Stitch hot loop (phase5-spec.md §4.3), the secondary path.
//!
//! For `TaskKind::Stitch`: fetch each input ciphertext **by its content address**
//! and re-verify that address against the input's committed `(OutputRef,
//! Commitment)` (no post-acceptance swap), decrypt each `Role::Output` into
//! anonymous RAM, concatenate them with one no-disk ffmpeg call (the concat demuxer
//! reading a memfd script, stream-copy — no re-encode), encrypt the rendition,
//! commit single-leaf, upload, and submit carrying the lease epoch.
//!
//! Stitch is mechanically simpler than transcode and is **not** the load-bearing
//! proof (that is [`crate::transcode_task`]). Two honest scope notes (kickoff §6,
//! "Stitch may degrade to content-address checks only"):
//! - The security-critical spine — **content-address re-verification of every
//!   input** — is always enforced; a swapped input is rejected before any ffmpeg.
//! - `StitchSpec` carries no output profile, so the concatenation assumes
//!   MPEG-TS (the HLS streaming case where `-c copy` concat is valid). A
//!   profile-carrying stitch is a future refinement; the transcode path is what the
//!   live smoke (Session 5) exercises.
//!
//! No plaintext on disk: every decrypted input and the concatenated rendition live
//! only in [`crypto::MemFd`]s, `zeroize_and_close`d on the happy path and scrubbed
//! by `MemFd::drop` on every error path.

use std::ffi::OsString;

use crypto::{
    aead, decrypt_into_memfd, ffmpeg_no_disk, BlobStore, EncryptedSegment, KeySource, MemFd, Role,
    SegmentAad,
};
use proctor_core::{Assignment, SegmentId, StitchSpec, SubmissionMsg, WorkerId};

use crate::{commit_output, WorkerError};

/// Run one leased `Stitch` end-to-end. Re-verifies every input's content address,
/// concatenates the decrypted outputs no-disk, and produces the epoch-carrying
/// submission for the final rendition.
pub fn run_stitch<B, K>(
    assignment: &Assignment,
    spec: &StitchSpec,
    blob: &B,
    keys: &K,
    worker: WorkerId,
) -> Result<SubmissionMsg, WorkerError>
where
    B: BlobStore,
    K: KeySource,
{
    // 1. Fetch + content-verify + decrypt every input, in order. A mismatch between
    //    the served bytes and the committed `(OutputRef, Commitment)` is a swap and
    //    is rejected before any ffmpeg runs.
    let mut inputs: Vec<MemFd> = Vec::with_capacity(spec.inputs.len());
    for (segment, output_ref, commitment) in &spec.inputs {
        let ct = blob.get(output_ref)?;
        let (derived_commitment, derived_ref) = commit_output(&ct);
        if &derived_commitment != commitment || derived_ref != *output_ref {
            return Err(WorkerError::InputAddressMismatch);
        }
        let key = keys.key(spec.job, *segment)?;
        let aad = SegmentAad {
            job: spec.job,
            segment: *segment,
            role: Role::Output,
        };
        let enc = EncryptedSegment::from_bytes(&ct)?;
        // On any later `?`, the memfds already in `inputs` drop and scrub themselves.
        inputs.push(decrypt_into_memfd(&enc, &key, &aad, "proctor-stitch-in")?);
    }

    // 2. Concatenate no-disk: a memfd script lists each input's /proc/self/fd path;
    //    the concat demuxer stream-copies them into the output memfd. Every fd is
    //    made inheritable by `ffmpeg_no_disk`.
    let mut script = MemFd::create("proctor-stitch-script")?;
    let mut listing = String::new();
    for mf in &inputs {
        listing.push_str(&format!("file '{}'\n", mf.proc_path()));
    }
    script.write_all(listing.as_bytes())?;

    let mut output = MemFd::create("proctor-stitch-out")?;
    let args: Vec<OsString> = vec![
        "-nostdin".into(),
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-y".into(),
        "-f".into(),
        "concat".into(),
        "-safe".into(),
        "0".into(),
        "-i".into(),
        script.proc_path().into(),
        "-c".into(),
        "copy".into(),
        "-f".into(),
        "mpegts".into(),
        output.proc_path().into(),
    ];

    let mut fds: Vec<&MemFd> = inputs.iter().collect();
    fds.push(&script);
    fds.push(&output);
    ffmpeg_no_disk(&args, &fds)?;
    drop(fds); // release the borrows so the memfds can be consumed below

    // 3. Encrypt the rendition (Role::Output), keyed by the rendition's own segment
    //    slot (SegmentId(rendition)). The plaintext SecretBuf is zeroized at block end.
    let rendition_segment = SegmentId(spec.rendition.0);
    let output_aad = SegmentAad {
        job: spec.job,
        segment: rendition_segment,
        role: Role::Output,
    };
    let key = keys.key(spec.job, rendition_segment)?;
    let out_blob = {
        let plaintext = output.read_to_secret_buf()?;
        aead::encrypt(plaintext.as_bytes(), &key, &output_aad)?.to_bytes()
    };

    // Scrub all plaintext memfds now that only ciphertext remains.
    script.zeroize_and_close();
    output.zeroize_and_close();
    for mf in inputs {
        mf.zeroize_and_close();
    }

    // 4. Commit + content address + upload + submit (carrying the lease epoch).
    let (commitment, output_ref) = commit_output(&out_blob);
    let stored = blob.put(&out_blob)?;
    if stored != output_ref {
        return Err(WorkerError::AddressDisagreement);
    }
    Ok(SubmissionMsg {
        task: assignment.task,
        worker,
        epoch: assignment.lease.epoch,
        commitment,
        output: output_ref,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{LocalBlobStore, LocalKeySource, SecretKey};
    use proctor_core::{Commitment, Epoch, JobId, Lease, LogicalTime, OutputRef, RenditionId, TaskId, TaskKind};
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut p = std::env::temp_dir();
            p.push(format!("proctor-stitch-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A swapped stitch input — bytes that do not match the committed content address
    /// — is rejected before any ffmpeg work (the anti-swap spine, ffmpeg-free).
    #[test]
    fn swapped_input_is_rejected_before_concat() {
        let dir = TempDir::new("swap");
        let store = LocalBlobStore::open(&dir.0).unwrap();
        let (job, segment) = (JobId(1), SegmentId(0));

        // Stage an encrypted input and record its honest commitment/address.
        let raw_key = [0x11u8; 32];
        let mut keys = LocalKeySource::new();
        keys.insert(job, segment, raw_key);
        let secret = SecretKey::from_bytes(raw_key).unwrap();
        let aad = SegmentAad { job, segment, role: Role::Output };
        let ct = aead::encrypt(b"a transcoded segment output", &secret, &aad)
            .unwrap()
            .to_bytes();
        let addr = store.put(&ct).unwrap();
        let (commitment, _) = commit_output(&ct);

        // Build a Stitch whose input claims the real address+commitment, but point the
        // spec's committed Commitment at a different value (simulating a server that
        // serves bytes inconsistent with what was committed/accepted).
        let bogus_commitment = Commitment([0xAB; 32]);
        assert_ne!(bogus_commitment, commitment);
        let spec = StitchSpec {
            job,
            rendition: RenditionId(0),
            inputs: vec![(segment, addr, bogus_commitment)],
        };
        let assignment = Assignment {
            task: TaskId(5),
            kind: TaskKind::Stitch(spec.clone()),
            lease: Lease { holder: WorkerId(1), epoch: Epoch(3), deadline: LogicalTime(10) },
            source: proctor_core::SegmentRef(0),
        };

        let err = run_stitch(&assignment, &spec, &store, &keys, WorkerId(1))
            .expect_err("a content-address mismatch must be rejected");
        assert!(matches!(err, WorkerError::InputAddressMismatch));
    }

    /// A missing input address surfaces cleanly as NotFound (no panic, no partial work).
    #[test]
    fn missing_input_is_not_found() {
        let dir = TempDir::new("missing");
        let store = LocalBlobStore::open(&dir.0).unwrap();
        let keys = LocalKeySource::new();
        let spec = StitchSpec {
            job: JobId(1),
            rendition: RenditionId(0),
            inputs: vec![(SegmentId(0), OutputRef(0xDEAD), Commitment([0; 32]))],
        };
        let assignment = Assignment {
            task: TaskId(5),
            kind: TaskKind::Stitch(spec.clone()),
            lease: Lease { holder: WorkerId(1), epoch: Epoch(1), deadline: LogicalTime(10) },
            source: proctor_core::SegmentRef(0),
        };
        let err = run_stitch(&assignment, &spec, &store, &keys, WorkerId(1)).unwrap_err();
        assert!(matches!(err, WorkerError::Crypto(crypto::CryptoError::NotFound)));
    }
}
