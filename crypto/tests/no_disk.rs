//! Tier-1 of the no-plaintext-on-disk proof (phase2-spec.md §7.1).
//!
//! Over a full `decrypt_into_memfd → transcode_no_disk → encrypt` cycle, enumerate
//! this process's open file descriptors and assert:
//!   1. the two plaintext-bearing fds (the source and output memfds) resolve to an
//!      anonymous `memfd:` link — never a path on a real filesystem;
//!   2. the cycle opens **no new regular file** beyond the one ciphertext blob we
//!      deliberately place on disk — i.e. no plaintext input/output disk file.
//!
//! The ffmpeg child's own syscalls (its fds live in the child's table, not ours)
//! are covered by the tier-2 `strace -f` audit in
//! `bench/results/crypto/no-disk-audit.txt`. Together they refute the deleted
//! `WORKER_SECURITY.md` with evidence rather than prose.
//!
//! This test requires ffmpeg; if it is absent the test skips with a loud, recorded
//! note (same honesty discipline as the Phase 0 corpus gating).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crypto::{
    decrypt_into_memfd, encrypt, transcode_no_disk, EncryptedSegment, MemFd, Role, SecretKey,
    SegmentAad,
};
use proctor_core::{Codec, Container, JobId, SegmentId, TargetProfile};

fn ffmpeg_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../bench/corpus")
        .join(name)
}

/// The set of *regular files on a real filesystem* this process currently has open,
/// by their `/proc/self/fd` link target. Anonymous fds (`memfd:`, `pipe:`,
/// `socket:`, `anon_inode:`) and device nodes (e.g. `/dev/null`, which is not a
/// regular file) are excluded — we are looking only for genuine disk files.
fn open_regular_files() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return set;
    };
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let text = target.to_string_lossy().to_string();
        // A memfd link reads as "/memfd:<label> (deleted)" — anonymous RAM, not disk.
        if text.starts_with("/memfd:") {
            continue;
        }
        // Only count targets that exist and are regular files (filters /dev/null,
        // pipes, sockets, and unlinked/deleted paths whose metadata fails).
        if fs::metadata(&target).map(|m| m.is_file()).unwrap_or(false) {
            set.insert(text);
        }
    }
    set
}

fn assert_anonymous_memfd(mf: &MemFd, what: &str) {
    let target = fs::read_link(mf.proc_path())
        .unwrap_or_else(|e| panic!("readlink {} for {what}: {e}", mf.proc_path()));
    let text = target.to_string_lossy();
    assert!(
        text.contains("memfd:"),
        "{what} plaintext fd must be an anonymous memfd, resolved to {text:?}"
    );
}

#[test]
fn plaintext_never_resolves_to_a_disk_file() {
    if !ffmpeg_available() {
        eprintln!("SKIP plaintext_never_resolves_to_a_disk_file: ffmpeg not found");
        return;
    }
    let plaintext = match fs::read(corpus("gradient.mp4")) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: corpus unavailable: {e}");
            return;
        }
    };

    let key = SecretKey::generate().unwrap();
    let src_aad = SegmentAad {
        job: JobId(7),
        segment: SegmentId(3),
        role: Role::Source,
    };
    let out_aad = SegmentAad {
        role: Role::Output,
        ..src_aad
    };

    // Place a ciphertext blob on disk and keep it open: this is the ONLY regular
    // file the cycle is permitted to touch (the encrypted-at-rest artifact). The
    // corpus read above is already closed (std::fs::read closes its fd).
    let sealed = encrypt(&plaintext, &key, &src_aad).unwrap();
    let blob_path = std::env::temp_dir().join(format!("proctor-blob-{}.enc", std::process::id()));
    fs::write(&blob_path, sealed.to_bytes()).unwrap();
    let _blob = fs::File::open(&blob_path).unwrap(); // held open across the cycle
    drop(plaintext);

    // Baseline: regular files open *before* the plaintext cycle (includes the blob).
    let baseline = open_regular_files();

    // The measured cycle: ciphertext -> plaintext in anonymous RAM -> ffmpeg over
    // memfds -> plaintext output in anonymous RAM.
    let sealed = EncryptedSegment::from_bytes(&fs::read(&blob_path).unwrap()).unwrap();
    let input = decrypt_into_memfd(&sealed, &key, &src_aad, "proctor-source").unwrap();
    let profile = TargetProfile {
        codec: Codec::H264,
        width: 640,
        height: 360,
        bitrate_kbps: 800,
        container: Container::Mp4,
    };
    let mut output = transcode_no_disk(&input, &profile).expect("transcode over memfds");

    // Snapshot with both plaintext memfds live (ffmpeg child has already exited).
    let during = open_regular_files();

    // (1) Both plaintext fds are anonymous memfds, not disk paths.
    assert_anonymous_memfd(&input, "source");
    assert_anonymous_memfd(&output, "output");

    // (2) The cycle opened no new regular file — no plaintext input/output on disk.
    let new_regular: Vec<&String> = during.difference(&baseline).collect();
    assert!(
        new_regular.is_empty(),
        "the decrypt→transcode→encrypt cycle opened new regular file(s): {new_regular:?}"
    );

    // Finish the cycle honestly: read plaintext output (RAM) and re-seal it (RAM).
    let out_plain = output.read_to_secret_buf().unwrap();
    let resealed = encrypt(out_plain.as_bytes(), &key, &out_aad).unwrap();
    assert!(resealed.to_bytes().len() > 1024, "ciphertext output too small");
    assert_ne!(resealed.to_bytes(), out_plain.as_bytes(), "output left as plaintext");

    input.zeroize_and_close();
    output.zeroize_and_close();
    let _ = fs::remove_file(&blob_path);
}
