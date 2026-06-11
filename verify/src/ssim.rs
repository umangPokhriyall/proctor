//! `ssim` — hand-rolled single-scale SSIM over luma (Y) planes (phase3-spec.md §3.3).
//!
//! We own the implementation rather than pull an opaque crate, so every number is
//! explainable (measure-never-guess). SSIM is computed on the luma plane only —
//! structural fidelity lives in luminance; chroma adds little and would dilute the
//! discriminator against cheap-downscale / frame-substitution attacks.
//!
//! **Window.** An 8×8 *uniform* (box) window, stepped with **stride 4** (50% overlap).
//! A uniform window is the explainable choice over the classic 11×11 Gaussian (σ=1.5):
//! every pixel in the window contributes equally, so a window's statistics are a plain
//! mean/variance with no kernel weights to justify. The overlap keeps the windows from
//! tiling hard block edges. MSSIM is the arithmetic mean of the per-window SSIM index.
//!
//! **Constants.** With 8-bit luma the dynamic range is `L = 255`, and the stabilisers
//! are the SSIM-paper defaults: `C1 = (0.01·L)² = 6.5025`, `C2 = (0.03·L)² = 58.5225`.
//! They keep the index finite in flat regions (near-zero means or variances) without
//! materially shifting it elsewhere.
//!
//! **Variance.** Per window we use the *unbiased* (N−1) sample variance/covariance,
//! matching the windowed-statistics formulation; the (N−1) vs (N) choice is a
//! second-order effect at N = 64 and is fixed here for reproducibility.
//!
//! Range: SSIM(x, y) ∈ [−1, 1]; identical planes give exactly 1.0, and the index
//! degrades monotonically as one plane is perturbed away from the other.

use crate::frame::Frame;
use crate::VerifyError;

/// Side length of the (square, uniform) comparison window, in pixels.
const WINDOW: usize = 8;
/// Step between window origins. `< WINDOW` ⇒ overlapping windows.
const STRIDE: usize = 4;
/// Dynamic range of 8-bit luma.
const L: f64 = 255.0;
/// Luminance stabiliser `(0.01·L)²`.
const C1: f64 = (0.01 * L) * (0.01 * L);
/// Contrast/structure stabiliser `(0.03·L)²`.
const C2: f64 = (0.03 * L) * (0.03 * L);

/// Mean structural similarity (MSSIM) between two equal-dimension luma planes.
///
/// Returns a value in `[−1, 1]` (≈ `1.0` for identical planes). Errors with
/// [`VerifyError::DimensionMismatch`] if the frames differ in size — SSIM is undefined
/// across mismatched planes, and the per-segment flow always extracts both at one
/// geometry, so a mismatch is a caller bug rather than worker input.
pub fn ssim(reference: &Frame, candidate: &Frame) -> Result<f64, VerifyError> {
    if (reference.w, reference.h) != (candidate.w, candidate.h) {
        return Err(VerifyError::DimensionMismatch(
            (reference.w, reference.h),
            (candidate.w, candidate.h),
        ));
    }

    let w = reference.w as usize;
    let h = reference.h as usize;

    // A plane smaller than one window is compared as a single window over the whole
    // plane — degenerate, but well-defined (identity still gives 1.0).
    if w < WINDOW || h < WINDOW {
        return Ok(window_ssim(&reference.y, &candidate.y, w, 0, 0, w, h));
    }

    let mut sum = 0.0;
    let mut count = 0usize;
    let mut y0 = 0;
    while y0 + WINDOW <= h {
        let mut x0 = 0;
        while x0 + WINDOW <= w {
            sum += window_ssim(&reference.y, &candidate.y, w, x0, y0, WINDOW, WINDOW);
            count += 1;
            x0 += STRIDE;
        }
        y0 += STRIDE;
    }
    // `count` is ≥ 1 whenever `w, h ≥ WINDOW` (the loops run at least once).
    Ok(sum / count as f64)
}

/// SSIM index over a single `bw × bh` window whose top-left pixel is `(x0, y0)` in a
/// plane of stride `img_w`. Pure: means, unbiased variances, and covariance over the
/// window, combined with the standard SSIM formula.
fn window_ssim(
    a: &[u8],
    b: &[u8],
    img_w: usize,
    x0: usize,
    y0: usize,
    bw: usize,
    bh: usize,
) -> f64 {
    let n = (bw * bh) as f64;

    let mut sum_a = 0.0;
    let mut sum_b = 0.0;
    for j in 0..bh {
        let row = (y0 + j) * img_w + x0;
        for i in 0..bw {
            sum_a += a[row + i] as f64;
            sum_b += b[row + i] as f64;
        }
    }
    let mu_a = sum_a / n;
    let mu_b = sum_b / n;

    let mut var_a = 0.0;
    let mut var_b = 0.0;
    let mut cov = 0.0;
    for j in 0..bh {
        let row = (y0 + j) * img_w + x0;
        for i in 0..bw {
            let da = a[row + i] as f64 - mu_a;
            let db = b[row + i] as f64 - mu_b;
            var_a += da * da;
            var_b += db * db;
            cov += da * db;
        }
    }
    // Unbiased estimator; guarded so a 1-pixel degenerate window cannot divide by zero.
    let denom = (n - 1.0).max(1.0);
    let var_a = var_a / denom;
    let var_b = var_b / denom;
    let cov = cov / denom;

    let numerator = (2.0 * mu_a * mu_b + C1) * (2.0 * cov + C2);
    let denominator = (mu_a * mu_a + mu_b * mu_b + C1) * (var_a + var_b + C2);
    numerator / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic LCG so the synthetic planes are reproducible without `rand`.
    struct Lcg(u64);
    impl Lcg {
        fn next_u8(&mut self) -> u8 {
            // Numerical Recipes LCG constants.
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }
    }

    fn noisy_frame(w: u32, h: u32, seed: u64) -> Frame {
        let mut lcg = Lcg(seed);
        let y = (0..(w * h)).map(|_| lcg.next_u8()).collect();
        Frame { w, h, y }
    }

    /// Add `amplitude` of zero-mean-ish noise to every pixel (saturating), deterministically.
    fn perturb(base: &Frame, amplitude: i32, seed: u64) -> Frame {
        let mut lcg = Lcg(seed);
        let y = base
            .y
            .iter()
            .map(|&px| {
                let delta = (lcg.next_u8() as i32 % (2 * amplitude + 1)) - amplitude;
                (px as i32 + delta).clamp(0, 255) as u8
            })
            .collect();
        Frame {
            w: base.w,
            h: base.h,
            y,
        }
    }

    #[test]
    fn identity_is_one() {
        let f = noisy_frame(40, 40, 0xC0FFEE);
        let s = ssim(&f, &f).unwrap();
        assert!((s - 1.0).abs() < 1e-9, "SSIM(x, x) must be 1.0, got {s}");
    }

    #[test]
    fn identity_is_one_on_sub_window_plane() {
        // A plane smaller than the 8×8 window still gives exactly 1.0 against itself.
        let f = noisy_frame(5, 5, 7);
        let s = ssim(&f, &f).unwrap();
        assert!((s - 1.0).abs() < 1e-9, "sub-window identity must be 1.0, got {s}");
    }

    #[test]
    fn degrades_monotonically_under_noise() {
        let base = noisy_frame(64, 64, 0xABCD);
        let s_self = ssim(&base, &base).unwrap();
        let s_low = ssim(&base, &perturb(&base, 10, 1)).unwrap();
        let s_high = ssim(&base, &perturb(&base, 40, 1)).unwrap();

        assert!((s_self - 1.0).abs() < 1e-9);
        assert!(
            s_self > s_low && s_low > s_high,
            "expected 1.0 > low-noise > high-noise, got {s_self} > {s_low} > {s_high}"
        );
        assert!(s_high >= -1.0 && s_low <= 1.0, "SSIM stays within [-1, 1]");
    }

    #[test]
    fn dimension_mismatch_is_rejected() {
        let a = noisy_frame(16, 16, 1);
        let b = noisy_frame(16, 32, 2);
        assert!(matches!(
            ssim(&a, &b),
            Err(VerifyError::DimensionMismatch((16, 16), (16, 32)))
        ));
    }

    #[test]
    fn flat_planes_are_identical() {
        // Two uniform planes of the same level: zero variance, C1/C2 keep it finite at 1.0.
        let a = Frame { w: 32, h: 32, y: vec![128; 32 * 32] };
        let b = Frame { w: 32, h: 32, y: vec![128; 32 * 32] };
        let s = ssim(&a, &b).unwrap();
        assert!((s - 1.0).abs() < 1e-9, "equal flat planes must be 1.0, got {s}");
    }
}
