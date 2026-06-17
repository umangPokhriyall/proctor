//! `preprocess` — the no-API workload authority (phase6-spec.md §3, locked decision #2).
//!
//! Segments the Phase 0 deterministic corpus (≈2 s GOP-aligned), seals each segment under a
//! fresh per-segment key (`aead::encrypt(Role::Source)`), and stages it for the live run:
//! the encrypted source goes into a [`LocalBlobStore`] (content-addressed, the address the
//! worker/verifier fetch by), and the key is registered in a [`LocalKeySource`] **and**
//! written to a key directory the worker/verifier processes load (`{job}-{segment}.key`,
//! 32 raw bytes — benchmark keys on disk are permitted; production delivery is TLS, NOT
//! built). It builds one `Transcode` [`Task`] per segment; the injector (open-loop,
//! CO-correct) creates + enqueues them directly into the scheduler — there is **no ingest
//! API** (locked decision #2).
//!
//! Plaintext is the synthetic, copyright-clean corpus, so segmenting it to disk is fine; the
//! honesty boundary (no *worker* plaintext on disk) lives in `crypto::memfd`/`transcode` and
//! is untouched here. Only ciphertext lands in the blob store.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use proctor_core::{
    Codec, Container, JobId, SegmentId, SegmentRef, Task, TargetProfile, TaskId, TaskKind,
    TranscodeSpec,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crypto::{aead, LocalBlobStore, LocalKeySource, Role, SecretKey, SegmentAad};

/// What can go wrong staging the corpus.
#[derive(Debug, thiserror::Error)]
pub enum PreprocessError {
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ffmpeg is required to segment the corpus but was not found on PATH")]
    FfmpegMissing,
    #[error("ffmpeg segmentation of {clip} failed: {stderr_tail}")]
    Segment { clip: String, stderr_tail: String },
    #[error("corpus clip not found: {0}")]
    ClipMissing(PathBuf),
    #[error("segmenting {0} produced no output segments")]
    NoSegments(String),
}

/// How to stage a corpus.
pub struct Config {
    /// Directory holding the corpus clips (`bench/corpus`).
    pub corpus_dir: PathBuf,
    /// Clip file names to segment, in order (one [`JobId`] each).
    pub clips: Vec<String>,
    /// Working root: segments, blobs, and keys are written under here.
    pub work_dir: PathBuf,
    /// Target segment length in seconds (GOP-aligned; the corpus has 1 keyframe/second).
    pub segment_secs: u32,
    /// The transcode target every segment is assigned.
    pub profile: TargetProfile,
    /// Seed for the per-segment key stream (deterministic ⇒ reproducible benchmark keys).
    pub key_seed: u64,
}

impl Config {
    /// The default single-host staging config under `work_dir`, segmenting the committed
    /// three-clip corpus at 2 s to the Phase 5 smoke profile (320×240 H.264).
    #[must_use]
    pub fn defaults(corpus_dir: impl Into<PathBuf>, work_dir: impl Into<PathBuf>) -> Self {
        Config {
            corpus_dir: corpus_dir.into(),
            clips: vec![
                "gradient.mp4".into(),
                "detail.mp4".into(),
                "motion.mp4".into(),
            ],
            work_dir: work_dir.into(),
            segment_secs: 2,
            profile: TargetProfile {
                codec: Codec::H264,
                width: 320,
                height: 240,
                bitrate_kbps: 800,
                container: Container::Mp4,
            },
            key_seed: 0x9E37_79B9_7F4A_7C15,
        }
    }
}

/// The staged workload: the shared blob/key paths the worker/verifier processes point at,
/// and the transcode tasks the injector feeds the scheduler.
pub struct Workload {
    /// `PROCTOR_BLOB_ROOT` for the worker/verifier processes (content-addressed ciphertext).
    pub blob_root: PathBuf,
    /// `PROCTOR_KEY_DIR` for the worker/verifier processes (`{job}-{segment}.key` files).
    pub key_dir: PathBuf,
    /// One `Transcode` task per staged segment, ready to inject (Pending, no lease yet).
    pub tasks: Vec<Task>,
}

/// Whether `ffmpeg` is callable (the segmenter needs it; the caller loud-skips if absent).
#[must_use]
pub fn ffmpeg_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Segment + encrypt + stage the corpus, returning the [`Workload`]. Idempotent w.r.t. the
/// blob store (content addressing) but rewrites the segment/key scratch each call.
pub fn stage(cfg: &Config) -> Result<Workload, PreprocessError> {
    if !ffmpeg_available() {
        return Err(PreprocessError::FfmpegMissing);
    }

    let blob_root = cfg.work_dir.join("blobs");
    let key_dir = cfg.work_dir.join("keys");
    let seg_root = cfg.work_dir.join("segments");
    std::fs::create_dir_all(&key_dir)?;
    std::fs::create_dir_all(&seg_root)?;
    let blob = LocalBlobStore::open(&blob_root)?;
    let mut keys = LocalKeySource::new();

    let mut rng = StdRng::seed_from_u64(cfg.key_seed);
    let mut tasks = Vec::new();
    let mut next_task_id = 1u64;

    for (clip_idx, clip) in cfg.clips.iter().enumerate() {
        let job = JobId(clip_idx as u64 + 1);
        let src = cfg.corpus_dir.join(clip);
        if !src.exists() {
            return Err(PreprocessError::ClipMissing(src));
        }
        let clip_stem = Path::new(clip)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("clip")
            .to_string();
        let out_dir = seg_root.join(&clip_stem);
        std::fs::create_dir_all(&out_dir)?;
        let segment_files = segment_clip(&src, &out_dir, cfg.segment_secs, clip)?;

        for (seg_idx, seg_path) in segment_files.iter().enumerate() {
            let segment = SegmentId(seg_idx as u64);
            let plaintext = std::fs::read(seg_path)?;

            // Fresh per-segment key: register it + write it to the key dir for the bins.
            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            keys.insert(job, segment, raw);
            std::fs::write(key_dir.join(format!("{}-{}.key", job.0, segment.0)), raw)?;

            // Seal the source segment and stage it content-addressed in the blob store.
            let key = SecretKey::from_bytes(raw)?;
            let aad = SegmentAad {
                job,
                segment,
                role: Role::Source,
            };
            let ct = aead::encrypt(&plaintext, &key, &aad)?.to_bytes();
            let source: SegmentRef = blob.put_source(&ct)?;

            tasks.push(Task::new(
                TaskId(next_task_id),
                TaskKind::Transcode(TranscodeSpec {
                    job,
                    segment,
                    profile: cfg.profile,
                    source,
                }),
            ));
            next_task_id += 1;
        }
    }

    Ok(Workload {
        blob_root,
        key_dir,
        tasks,
    })
}

/// Run the ffmpeg segment muxer on one clip, returning the produced segment files in order.
/// `-c copy` splits at keyframes (the corpus is GOP-aligned at 1 keyframe/second), so the
/// segments are reproducible and ≈`segment_secs` long.
fn segment_clip(
    src: &Path,
    out_dir: &Path,
    segment_secs: u32,
    clip: &str,
) -> Result<Vec<PathBuf>, PreprocessError> {
    let pattern = out_dir.join("seg_%03d.mp4");
    let out = Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-i"])
        .arg(src)
        .args(["-f", "segment", "-segment_time", &segment_secs.to_string()])
        .args(["-reset_timestamps", "1", "-c", "copy"])
        .arg(&pattern)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: String = stderr.chars().rev().take(512).collect::<String>().chars().rev().collect();
        return Err(PreprocessError::Segment {
            clip: clip.to_string(),
            stderr_tail: tail,
        });
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(out_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("mp4"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(PreprocessError::NoSegments(clip.to_string()));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "proctor-prep-{tag}-{}-{}",
            std::process::id(),
            crate::metrics::now_ns()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn corpus_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus")
    }

    #[test]
    fn missing_ffmpeg_or_corpus_is_a_loud_error_never_a_panic() {
        // A non-existent clip is rejected cleanly (no panic), proving the error path.
        if !ffmpeg_available() {
            eprintln!("SKIP preprocess staging: ffmpeg not found");
            return;
        }
        let work = scratch("missingclip");
        let mut cfg = Config::defaults(corpus_dir(), &work);
        cfg.clips = vec!["does-not-exist.mp4".into()];
        assert!(matches!(stage(&cfg), Err(PreprocessError::ClipMissing(_))));
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn stages_corpus_into_blobs_keys_and_tasks() {
        if !ffmpeg_available() {
            eprintln!("SKIP stages_corpus_into_blobs_keys_and_tasks: ffmpeg not found");
            return;
        }
        if !corpus_dir().join("gradient.mp4").exists() {
            eprintln!("SKIP stages_corpus_into_blobs_keys_and_tasks: corpus unavailable");
            return;
        }
        let work = scratch("stage");
        let mut cfg = Config::defaults(corpus_dir(), &work);
        cfg.clips = vec!["gradient.mp4".into()]; // one clip keeps the test quick
        let wl = stage(&cfg).expect("staging succeeds");

        assert!(!wl.tasks.is_empty(), "at least one segment task");
        // Every task is a Pending Transcode whose source is staged in the blob store, and
        // whose key file exists for the worker/verifier to load.
        for task in &wl.tasks {
            let TaskKind::Transcode(spec) = &task.kind else {
                panic!("preprocess emits Transcode tasks");
            };
            let key_file = wl.key_dir.join(format!("{}-{}.key", spec.job.0, spec.segment.0));
            assert_eq!(std::fs::read(&key_file).unwrap().len(), 32, "32-byte key on disk");
            // The source ciphertext is fetchable at its content address.
            use crypto::BlobStore;
            let store = LocalBlobStore::open(&wl.blob_root).unwrap();
            assert!(store.get_ref(&spec.source).is_ok(), "source ciphertext staged");
        }
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn key_stream_is_deterministic_under_the_seed() {
        // Two runs at the same seed stage byte-identical keys (reproducibility).
        if !ffmpeg_available() || !corpus_dir().join("gradient.mp4").exists() {
            eprintln!("SKIP key_stream_is_deterministic_under_the_seed: ffmpeg/corpus unavailable");
            return;
        }
        let run = |tag: &str| -> Vec<u8> {
            let work = scratch(tag);
            let mut cfg = Config::defaults(corpus_dir(), &work);
            cfg.clips = vec!["gradient.mp4".into()];
            let wl = stage(&cfg).unwrap();
            let mut bytes = Vec::new();
            let mut files: Vec<_> = std::fs::read_dir(&wl.key_dir).unwrap().flatten().map(|e| e.path()).collect();
            files.sort();
            for f in files {
                bytes.extend(std::fs::read(f).unwrap());
            }
            let _ = std::fs::remove_dir_all(&work);
            bytes
        };
        assert_eq!(run("seedA"), run("seedB"), "same seed ⇒ identical keys");
    }
}
