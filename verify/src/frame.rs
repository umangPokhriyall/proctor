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

/// Batched Y-plane extraction — the **named remedy for the Phase 3 ~10× verification
/// cost** (phase5-spec.md §1, §5.1). The Phase 3 cost was per-frame ffmpeg
/// process-spawn (one `-ss` seek + spawn per challenge frame); here the segment is
/// decoded **once** in a single ffmpeg invocation to a raw-gray stream at
/// `width × height`, and the sampled planes are then indexed in-process. So the cost
/// is **one spawn per memfd regardless of frame count** — there is no per-frame spawn.
///
/// `fractions` are normalized positions in `[0, 1)` of the segment; each maps to the
/// frame at `floor(fraction · n_frames)`. Because the verifier extracts both the
/// worker output and its own reference at the *same* geometry and fractions — and both
/// are same-profile transcodes of the same source, so equal frame counts — the
/// returned planes are positionally aligned for SSIM.
///
/// The decoded sequence lives only in an anonymous-RAM memfd, read into a pinned
/// zeroizing buffer and scrubbed on every path. At the calibrated 160×120 comparison
/// geometry a GOP-bounded segment is a few MiB — well within `RLIMIT_MEMLOCK`; an
/// over-budget pin surfaces as a `Crypto` error (→ an `Inconclusive` verdict), never a
/// silent disk spill.
pub fn extract_y_frames(
    media: &MemFd,
    fractions: &[f64],
    width: u32,
    height: u32,
) -> Result<Vec<Frame>, VerifyError> {
    let frame_len = width as usize * height as usize;
    if fractions.is_empty() {
        return Ok(Vec::new());
    }
    if frame_len == 0 {
        return Err(VerifyError::FrameSize { expected: 0, got: 0 });
    }

    let mut out = MemFd::create("proctor-frames")?;
    // One pass: decode the whole segment to raw gray at the common geometry. `-vsync 0`
    // (passthrough) emits every decoded frame once so the stream length is exactly
    // n_frames · w · h.
    let args: Vec<OsString> = vec![
        "-nostdin".into(),
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-y".into(),
        "-i".into(),
        media.proc_path().into(),
        "-an".into(),
        "-vf".into(),
        format!("scale={width}:{height}").into(),
        "-pix_fmt".into(),
        "gray".into(),
        "-vsync".into(),
        "0".into(),
        "-f".into(),
        "rawvideo".into(),
        out.proc_path().into(),
    ];

    if let Err(e) = ffmpeg_no_disk(&args, &[media, &out]) {
        out.zeroize_and_close();
        return Err(e.into());
    }

    let decoded = out.read_to_secret_buf()?;
    out.zeroize_and_close();
    let buf = decoded.as_bytes();

    if buf.is_empty() || buf.len() % frame_len != 0 {
        return Err(VerifyError::FrameSize {
            expected: frame_len,
            got: buf.len(),
        });
    }
    let n_frames = buf.len() / frame_len;

    let frames = fractions
        .iter()
        .map(|&f| {
            let frac = if f.is_finite() { f.clamp(0.0, 1.0) } else { 0.0 };
            let idx = ((frac * n_frames as f64) as usize).min(n_frames - 1);
            let start = idx * frame_len;
            Frame {
                w: width,
                h: height,
                y: buf[start..start + frame_len].to_vec(),
            }
        })
        .collect();
    Ok(frames)
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
    fn batched_extraction_returns_one_plane_per_fraction_in_one_pass() {
        if !ffmpeg_available() {
            eprintln!("SKIP batched_extraction_returns_one_plane_per_fraction_in_one_pass: ffmpeg not found");
            return;
        }
        let Some(src) = corpus_memfd("gradient.mp4") else {
            eprintln!("SKIP: corpus gradient.mp4 unavailable");
            return;
        };
        // Five sampled positions, decoded in a single ffmpeg invocation (no per-frame spawn).
        let fractions = [0.0, 0.25, 0.5, 0.75, 0.9];
        let frames = extract_y_frames(&src, &fractions, 160, 120).expect("batched extract");
        assert_eq!(frames.len(), fractions.len(), "one plane per requested fraction");
        for f in &frames {
            assert_eq!((f.w, f.h), (160, 120));
            assert_eq!(f.y.len(), 160 * 120, "each plane is exactly w*h gray bytes");
        }
        // Deterministic: a second batched pass yields identical planes.
        let again = extract_y_frames(&src, &fractions, 160, 120).expect("second batched extract");
        for (a, b) in frames.iter().zip(&again) {
            assert_eq!(a.y, b.y, "batched extraction must be deterministic");
        }
        // Distinct positions in a gradient clip differ (not a constant stream).
        assert_ne!(frames[0].y, frames[4].y, "different positions decode to different planes");
        // Empty request ⇒ no planes, still no panic.
        assert!(extract_y_frames(&src, &[], 160, 120).unwrap().is_empty());
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
