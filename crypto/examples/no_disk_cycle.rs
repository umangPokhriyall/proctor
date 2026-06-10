//! `no_disk_cycle` — one full `decrypt_into_memfd → transcode_no_disk → encrypt`
//! cycle, as a process for the tier-2 `strace` audit (phase2-spec.md §7).
//!
//! Run it under `strace -f -e trace=openat,open,creat,memfd_create` and inspect the
//! syscalls: plaintext appears only behind `memfd_create`; the only *writable*
//! regular files are the ciphertext `.enc` blobs. See
//! `bench/results/crypto/regen-no-disk-audit.sh`.
//!
//! Honesty note: the corpus mp4 is read **once** (`O_RDONLY`) to *seed* the cycle —
//! this stands in for content arriving over TLS in production, where the worker
//! receives ciphertext and never reads plaintext from disk. No plaintext is ever
//! opened for **writing**; the transcode path's plaintext lives only in anonymous
//! RAM (memfd). The blobs written to disk are ciphertext.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use crypto::{
    decrypt_into_memfd, encrypt, transcode_no_disk, EncryptedSegment, Role, SecretKey, SegmentAad,
};
use proctor_core::{Codec, Container, JobId, SegmentId, TargetProfile};

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../bench/corpus")
        .join(name)
}

fn main() -> ExitCode {
    let work = std::env::temp_dir().join("proctor-no-disk-audit");
    let _ = fs::create_dir_all(&work);
    let source_enc = work.join("source.enc");
    let output_enc = work.join("output.enc");

    // --- Seed (harness): read the corpus once and seal it. In production the
    // worker receives this ciphertext over TLS; here we synthesize it on disk so
    // the measured cycle below starts from a ciphertext blob, never plaintext. ---
    let plaintext = match fs::read(corpus("gradient.mp4")) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no_disk_cycle: corpus unavailable: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = SecretKey::generate().expect("mlock + csprng");
    let src_aad = SegmentAad {
        job: JobId(1),
        segment: SegmentId(0),
        role: Role::Source,
    };
    let out_aad = SegmentAad {
        role: Role::Output,
        ..src_aad
    };
    let sealed = encrypt(&plaintext, &key, &src_aad).expect("encrypt");
    fs::write(&source_enc, sealed.to_bytes()).expect("write ciphertext blob");
    drop(plaintext);

    // --- Measured cycle: ciphertext blob -> plaintext in anonymous RAM -> ffmpeg
    // over memfds -> ciphertext blob. No plaintext touches a disk-backed file. ---
    let sealed = EncryptedSegment::from_bytes(&fs::read(&source_enc).expect("read blob"))
        .expect("parse blob");
    let input = decrypt_into_memfd(&sealed, &key, &src_aad, "proctor-source").expect("decrypt");
    let profile = TargetProfile {
        codec: Codec::H264,
        width: 640,
        height: 360,
        bitrate_kbps: 800,
        container: Container::Mp4,
    };
    let mut output = transcode_no_disk(&input, &profile).expect("transcode over memfds");
    let out_plain = output.read_to_secret_buf().expect("read output");
    let resealed = encrypt(out_plain.as_bytes(), &key, &out_aad).expect("re-encrypt");
    fs::write(&output_enc, resealed.to_bytes()).expect("write ciphertext output");

    input.zeroize_and_close();
    output.zeroize_and_close();
    let _ = fs::remove_file(&source_enc);
    let _ = fs::remove_file(&output_enc);

    println!("no_disk_cycle: ok ({} ciphertext bytes out)", resealed.to_bytes().len());
    ExitCode::SUCCESS
}
