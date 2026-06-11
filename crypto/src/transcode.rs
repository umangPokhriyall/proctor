//! `transcode` — ffmpeg with no disk surface (phase2-spec.md §6, phase3-spec.md §3.1).
//!
//! [`ffmpeg_no_disk`] is the single no-disk ffmpeg primitive: it runs ffmpeg with a
//! caller-supplied argument vector and a set of [`MemFd`]s made inheritable so the
//! child can open each as `/proc/self/fd/N`. It owns the spawn, stderr drain,
//! wall-clock timeout, and exit→error mapping — keeping all `unsafe` in [`crate::sys`]
//! so consumers like `verify::frame` can stay `#![forbid(unsafe_code)]`.
//!
//! [`transcode_no_disk`] is a thin caller of that primitive: it reads its plaintext
//! input from a [`MemFd`] and writes its plaintext output to a fresh [`MemFd`],
//! passing each to ffmpeg as a `/proc/self/fd/N` URL. There is **no** `-i input.mp4`
//! disk path, ever: the decrypted source and the transcoded output exist only in
//! anonymous RAM.
//!
//! The frozen [`core::TargetProfile`](proctor_core::TargetProfile) is mapped to
//! ffmpeg arguments by the pure [`profile_args`] function. ffmpeg failure (non-zero
//! exit) yields `Err(TranscodeFailed)` carrying a bounded tail of stderr (never the
//! media); a wall-clock timeout kills the child so a hostile/oversized input cannot
//! hang a worker. On every error path the output `MemFd` is `zeroize_and_close`d.
//!
//! **Container choice (phase2-spec.md §6):** output goes to a *seekable* memfd, so
//! standard MP4 (with its trailing `moov`) works — ffmpeg seeks the fd to write the
//! index. `-f` is passed explicitly because the `/proc/self/fd/N` URL has no
//! extension for ffmpeg to infer the muxer from. The corpus is silent, so the video
//! stream is transcoded and audio is dropped (`-an`); audio passthrough is a Phase 5
//! concern, out of this session's scope.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::RawFd;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use proctor_core::{Codec, Container, TargetProfile};

use crate::memfd::MemFd;
use crate::{sys, CryptoError};

/// Wall-clock ceiling for one segment transcode. A GOP-bounded (≈2 s) segment
/// encodes far faster than this; the bound exists so a hostile or oversized input
/// cannot hang a worker indefinitely.
const TRANSCODE_TIMEOUT: Duration = Duration::from_secs(120);

/// How often the wait loop polls the child for exit. Kept at 1 ms so the loop adds
/// at most ~1 ms of latency past ffmpeg's actual exit (the Phase 2 microbench's
/// memfd-vs-disk arm surfaced a coarser interval oversleeping past completion);
/// 1 ms over a ~100 ms transcode is ~100 wakeups — negligible CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Bytes of ffmpeg stderr retained for an error report (the tail, where the cause is).
const STDERR_TAIL_BYTES: usize = 4096;

/// Run `ffmpeg` with `args`, making every fd in `fds` inheritable so the child can
/// open each memfd as `/proc/self/fd/N` (phase3-spec.md §3.1). This is the **single**
/// no-disk ffmpeg primitive: it owns the spawn, the stderr drain, the wall-clock
/// timeout, and the exit→[`CryptoError`] mapping, but it does **not** own the
/// memfds — the caller creates them and is responsible for `zeroize_and_close` on
/// every exit path. `verify::frame` reuses this so all `unsafe` stays in [`crate::sys`]
/// and `verify` can keep `#![forbid(unsafe_code)]`.
///
/// `args` is the full ffmpeg argument vector (everything after the program name); the
/// `proc_path()` of each fd in `fds` must already appear in it. Returns `Ok(())` on a
/// zero exit, `Err(TranscodeFailed)` with a bounded stderr tail on non-zero exit,
/// `Err(Timeout)` if the wall-clock budget is exceeded, or `Err(Io)` on spawn/wait
/// failure.
pub fn ffmpeg_no_disk(args: &[OsString], fds: &[&MemFd]) -> Result<(), CryptoError> {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    // The memfds are CLOEXEC; clear that in the child so ffmpeg can open the fds.
    let raw_fds: Vec<RawFd> = fds.iter().map(|mf| mf.raw_fd()).collect();
    sys::set_fds_inheritable(&mut cmd, raw_fds);

    let mut child = cmd.spawn()?;

    // Drain stderr on a thread so a chatty ffmpeg cannot deadlock on a full pipe.
    let stderr_reader = child.stderr.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + TRANSCODE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(Some(status)),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break Ok(None); // timed out
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => break Err(e),
        }
    };

    let collect_stderr =
        || stderr_reader.map(|h| h.join().unwrap_or_default()).unwrap_or_default();

    match status {
        Ok(Some(status)) if status.success() => Ok(()),
        Ok(Some(_)) => Err(CryptoError::TranscodeFailed {
            stderr_tail: stderr_tail(&collect_stderr()),
        }),
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = collect_stderr();
            Err(CryptoError::Timeout)
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = collect_stderr();
            Err(e.into())
        }
    }
}

/// Transcode the plaintext in `input` to `profile`, returning the plaintext output in
/// a fresh [`MemFd`]. A thin caller of [`ffmpeg_no_disk`]: it owns the output memfd's
/// lifecycle (`zeroize_and_close` on every error) and lets the primitive run ffmpeg
/// over `/proc/self/fd/N`; no plaintext path ever touches disk.
pub fn transcode_no_disk(input: &MemFd, profile: &TargetProfile) -> Result<MemFd, CryptoError> {
    let output = MemFd::create("proctor-output")?;
    let args = transcode_args(input, &output, profile);
    match ffmpeg_no_disk(&args, &[input, &output]) {
        Ok(()) => Ok(output),
        Err(e) => {
            output.zeroize_and_close();
            Err(e)
        }
    }
}

/// Build the full ffmpeg argument vector for a no-disk transcode of `input`→`output`
/// under `profile`. Both endpoints are `/proc/self/fd/N` URLs (anonymous RAM), never
/// disk paths; `-f` is explicit because the proc-path URL carries no extension to
/// infer the muxer from, and `-an` drops audio (the corpus is silent; passthrough is
/// a Phase 5 concern).
fn transcode_args(input: &MemFd, output: &MemFd, profile: &TargetProfile) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "-nostdin".into(),
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-y".into(),
        "-i".into(),
        input.proc_path().into(),
    ];
    args.extend(profile_args(profile).into_iter().map(OsString::from));
    args.push("-an".into());
    args.push("-f".into());
    args.push(container_format(profile.container).into());
    args.push(output.proc_path().into());
    args
}

/// Map the frozen [`TargetProfile`] to the codec/scale/bitrate ffmpeg args. Pure.
fn profile_args(profile: &TargetProfile) -> Vec<String> {
    vec![
        "-c:v".to_string(),
        codec_encoder(profile.codec).to_string(),
        "-vf".to_string(),
        format!("scale={}:{}", profile.width, profile.height),
        "-b:v".to_string(),
        format!("{}k", profile.bitrate_kbps),
    ]
}

/// The ffmpeg encoder name for a target [`Codec`].
fn codec_encoder(codec: Codec) -> &'static str {
    match codec {
        Codec::H264 => "libx264",
        Codec::H265 => "libx265",
        Codec::Av1 => "libsvtav1",
        Codec::Vp9 => "libvpx-vp9",
    }
}

/// The ffmpeg muxer name for a target [`Container`] (passed via explicit `-f`).
fn container_format(container: Container) -> &'static str {
    match container {
        Container::Mp4 => "mp4",
        Container::WebM => "webm",
        Container::Mkv => "matroska",
        Container::MpegTs => "mpegts",
    }
}

/// The last [`STDERR_TAIL_BYTES`] of ffmpeg stderr, lossily decoded — the cause of a
/// failure lives at the end. Never includes media bytes (stderr is diagnostics only).
fn stderr_tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memfd::MemFd;
    use std::path::PathBuf;

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

    fn profile(codec: Codec, w: u32, h: u32, container: Container) -> TargetProfile {
        TargetProfile {
            codec,
            width: w,
            height: h,
            bitrate_kbps: 1500,
            container,
        }
    }

    #[test]
    fn profile_args_map_codec_scale_bitrate() {
        let p = profile(Codec::H264, 1280, 720, Container::Mp4);
        assert_eq!(
            profile_args(&p),
            vec![
                "-c:v", "libx264", "-vf", "scale=1280:720", "-b:v", "1500k",
            ]
        );
        assert_eq!(codec_encoder(Codec::H265), "libx265");
        assert_eq!(container_format(Container::MpegTs), "mpegts");
    }

    #[test]
    fn transcodes_corpus_over_memfds_no_disk_path() {
        if !ffmpeg_available() {
            eprintln!("SKIP transcodes_corpus_over_memfds_no_disk_path: ffmpeg not found");
            return;
        }
        let src = corpus("gradient.mp4");
        let bytes = match std::fs::read(&src) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP: corpus {src:?} unavailable: {e}");
                return;
            }
        };

        let mut input = MemFd::create("proctor-source").unwrap();
        input.write_all(&bytes).unwrap();
        // Sanity: the input we feed ffmpeg is an anonymous fd, not a disk path.
        assert!(std::fs::read_link(input.proc_path())
            .unwrap()
            .to_string_lossy()
            .contains("memfd:"));

        let mut output =
            transcode_no_disk(&input, &profile(Codec::H264, 640, 360, Container::Mp4))
                .expect("ffmpeg transcode over memfds");

        // Output is anonymous RAM and is a non-empty, plausible MP4.
        assert!(std::fs::read_link(output.proc_path())
            .unwrap()
            .to_string_lossy()
            .contains("memfd:"));
        let out = output.read_to_secret_buf().unwrap();
        assert!(out.len() > 1024, "output suspiciously small: {} bytes", out.len());
    }

    #[test]
    fn garbage_input_fails_with_stderr_tail() {
        if !ffmpeg_available() {
            eprintln!("SKIP garbage_input_fails_with_stderr_tail: ffmpeg not found");
            return;
        }
        let mut input = MemFd::create("proctor-garbage").unwrap();
        input.write_all(b"this is not a video container at all").unwrap();
        let err = transcode_no_disk(&input, &profile(Codec::H264, 320, 240, Container::Mp4))
            .expect_err("ffmpeg must reject garbage input");
        match err {
            CryptoError::TranscodeFailed { stderr_tail } => {
                assert!(!stderr_tail.is_empty(), "expected a non-empty stderr tail");
            }
            other => panic!("expected TranscodeFailed, got {other:?}"),
        }
    }
}
