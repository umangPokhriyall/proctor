//! `frame` — Y-plane frame extraction over the no-disk ffmpeg path (phase3-spec.md §3.2).
//!
//! [`extract_y_frame`] decodes a single luma (Y) plane at a timestamp from a plaintext
//! [`MemFd`](crypto::MemFd) by running ffmpeg through [`crypto::ffmpeg_no_disk`]. Both
//! the input media and the raw output land on `/proc/self/fd/N` memfds — **never a disk
//! path** — so the no-disk property is inherited from `crypto` and `verify` needs no
//! `unsafe` of its own.
//!
//! **Pixel format.** Output is `-pix_fmt gray`, `-f rawvideo`: one byte of luminance per
//! pixel, row-major, no header. We compare on luma only (see [`crate::ssim`]); chroma is
//! dropped. The frame is scaled to the caller's `(width, height)` (`-vf scale=w:h`) so the
//! raw buffer is exactly `width * height` bytes and the reference and candidate frames are
//! sampled at one common geometry — a size mismatch is then a hard [`VerifyError::FrameSize`].
//!
//! **Seek.** `-ss T` precedes `-i` (fast, keyframe-accurate seek): cheap, and frame-exact
//! accuracy is unnecessary because the per-segment flow samples the *same* timestamp from
//! both the worker output and the verifier's reference.

use std::ffi::OsString;

use crypto::{ffmpeg_no_disk, MemFd};

use crate::VerifyError;

/// A single decoded luma plane (`y`, one byte per pixel, row-major) at a known geometry.
/// `y.len() == w * h` is an invariant established by [`extract_y_frame`].
pub struct Frame {
    /// Plane width in pixels.
    pub w: u32,
    /// Plane height in pixels.
    pub h: u32,
    /// Row-major 8-bit luminance samples; `len == w * h`.
    pub y: Vec<u8>,
}

/// Extract the luma plane at `timestamp_secs` from the plaintext `media` memfd, scaled to
/// `width × height`, as a [`Frame`]. Runs ffmpeg over memfds only (no disk); the output
/// memfd is scrubbed and closed on every path.
///
/// Errors with [`VerifyError::FrameSize`] if ffmpeg emits other than `width * height` luma
/// bytes, or [`VerifyError::Crypto`] on a spawn/timeout/decode failure.
pub fn extract_y_frame(
    media: &MemFd,
    timestamp_secs: f64,
    width: u32,
    height: u32,
) -> Result<Frame, VerifyError> {
    let mut out = MemFd::create("proctor-frame")?;

    let args: Vec<OsString> = vec![
        "-nostdin".into(),
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-y".into(),
        // Fast seek before -i, then take exactly one frame.
        "-ss".into(),
        format_secs(timestamp_secs).into(),
        "-i".into(),
        media.proc_path().into(),
        "-frames:v".into(),
        "1".into(),
        "-an".into(),
        "-vf".into(),
        format!("scale={width}:{height}").into(),
        "-pix_fmt".into(),
        "gray".into(),
        "-f".into(),
        "rawvideo".into(),
        out.proc_path().into(),
    ];

    if let Err(e) = ffmpeg_no_disk(&args, &[media, &out]) {
        out.zeroize_and_close();
        return Err(e.into());
    }

    // Read the raw gray plane out of anonymous RAM, then scrub + close the memfd.
    let plane = out.read_to_secret_buf()?;
    let y = plane.as_bytes().to_vec();
    out.zeroize_and_close();

    let expected = width as usize * height as usize;
    if y.len() != expected {
        return Err(VerifyError::FrameSize {
            expected,
            got: y.len(),
        });
    }

    Ok(Frame {
        w: width,
        h: height,
        y,
    })
}

/// Render a timestamp as a plain decimal-seconds string for ffmpeg's `-ss` (e.g. `0`,
/// `1.5`). ffmpeg accepts bare seconds; we avoid locale/format surprises by formatting
/// ourselves rather than relying on `Duration` parsing.
fn format_secs(secs: f64) -> String {
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

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

    /// Load a corpus clip into a plaintext memfd (stands in for a decrypted source).
    fn corpus_memfd(name: &str) -> Option<MemFd> {
        let bytes = std::fs::read(corpus(name)).ok()?;
        let mut mf = MemFd::create("proctor-test-src").unwrap();
        mf.write_all(&bytes).unwrap();
        Some(mf)
    }

    #[test]
    fn extracts_a_luma_plane_of_requested_geometry() {
        if !ffmpeg_available() {
            eprintln!("SKIP extracts_a_luma_plane_of_requested_geometry: ffmpeg not found");
            return;
        }
        let Some(src) = corpus_memfd("gradient.mp4") else {
            eprintln!("SKIP: corpus gradient.mp4 unavailable");
            return;
        };
        let frame = extract_y_frame(&src, 0.0, 64, 48).expect("extract Y plane");
        assert_eq!((frame.w, frame.h), (64, 48));
        assert_eq!(frame.y.len(), 64 * 48, "raw gray buffer must be exactly w*h");
        // A gradient clip is not a constant plane.
        let first = frame.y[0];
        assert!(
            frame.y.iter().any(|&p| p != first),
            "expected a non-uniform luma plane from a gradient clip"
        );
        src.zeroize_and_close();
    }

    #[test]
    fn extraction_is_deterministic_round_trip() {
        if !ffmpeg_available() {
            eprintln!("SKIP extraction_is_deterministic_round_trip: ffmpeg not found");
            return;
        }
        let Some(src) = corpus_memfd("gradient.mp4") else {
            eprintln!("SKIP: corpus gradient.mp4 unavailable");
            return;
        };
        let a = extract_y_frame(&src, 0.0, 80, 60).expect("first extract");
        let b = extract_y_frame(&src, 0.0, 80, 60).expect("second extract");
        assert_eq!(a.y, b.y, "same timestamp + geometry must decode identically");
        // Identity SSIM of an extracted plane against itself is 1.0 — frame feeds ssim.
        assert!((crate::ssim::ssim(&a, &b).unwrap() - 1.0).abs() < 1e-9);
        src.zeroize_and_close();
    }
}
