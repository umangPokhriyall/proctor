//! `roc` — calibration/held-out ROC study primitives (phase3-spec.md §5, amendment §1.2.2+§1.2.3).
//!
//! The study must not be **circular** (a threshold chosen and scored on the same data) and must
//! not state a **point estimate without an interval**. This module owns the falsifiable parts:
//! the labelled-sample model, FAR/FRR at a threshold, the calibration-only threshold selection,
//! the exact **Clopper–Pearson** confidence interval (Beta quantiles via `statrs`), and the
//! disjointness check between the calibration and held-out partitions. The `verify_eval` example
//! drives ffmpeg to produce the scores; this module is pure and unit-tested.
//!
//! **Convention.** An honest output should *pass* (`score ≥ threshold`); an attack should be
//! *rejected* (`score < threshold`). Therefore:
//! - **FRR** (false-reject rate) = honest samples with `score < threshold` ÷ honest count.
//! - **FAR** (false-accept rate) = attack samples with `score ≥ threshold` ÷ attack count.

use statrs::distribution::{Beta, ContinuousCDF};

/// A content stratum, mapped to the synthetic corpus clips (amendment §1.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Stratum {
    /// `gradient.mp4` (`testsrc2`) — clean, low-entropy.
    SmoothGradient,
    /// `detail.mp4` (`mandelbrot`) — high-detail / grain-like.
    HighDetail,
    /// `motion.mp4` — high motion.
    HighMotion,
}

impl Stratum {
    /// Stable CSV label.
    pub fn label(self) -> &'static str {
        match self {
            Stratum::SmoothGradient => "smooth_gradient",
            Stratum::HighDetail => "high_detail",
            Stratum::HighMotion => "high_motion",
        }
    }
}

/// Which disjoint partition a sample belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DataSet {
    /// Threshold selection only.
    Calibration,
    /// Reported FAR/FRR only (disjoint from calibration).
    HeldOut,
}

impl DataSet {
    /// Stable CSV label.
    pub fn label(self) -> &'static str {
        match self {
            DataSet::Calibration => "calibration",
            DataSet::HeldOut => "held_out",
        }
    }
}

/// The honest transcode plus the attack classes (phase3-spec.md §5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Variant {
    /// A faithful re-encode (should pass).
    Honest,
    /// Minimal-effort low-resolution encode (cheap-downscale).
    CheapDownscale,
    /// Right geometry, far-too-low bitrate (heavy artifacts).
    WrongBitrate,
    /// Frames spliced from a different clip.
    FrameSubstitution,
    /// Blanked / garbage output.
    Garbage,
}

impl Variant {
    /// Stable CSV label.
    pub fn label(self) -> &'static str {
        match self {
            Variant::Honest => "honest",
            Variant::CheapDownscale => "cheap_downscale",
            Variant::WrongBitrate => "wrong_bitrate",
            Variant::FrameSubstitution => "frame_substitution",
            Variant::Garbage => "garbage",
        }
    }

    /// Whether this variant *should* pass (honest) or be rejected (attack).
    pub fn class(self) -> Class {
        match self {
            Variant::Honest => Class::Honest,
            _ => Class::Attack,
        }
    }
}

/// The ground-truth class of a sample.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// Should pass.
    Honest,
    /// Should be rejected.
    Attack,
}

/// One labelled SSIM score: a `(stratum, segment, variant)` triple, its partition, and its score.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    /// Content stratum (the source clip).
    pub stratum: Stratum,
    /// Disjoint partition.
    pub set: DataSet,
    /// Segment (time-window) index within the clip.
    pub segment: u32,
    /// Honest or which attack.
    pub variant: Variant,
    /// The segment's min-MSSIM score for this variant against the reference.
    pub score: f64,
}

impl Sample {
    /// The sample's ground-truth class.
    pub fn class(&self) -> Class {
        self.variant.class()
    }

    /// Identity for disjointness: a sample is uniquely placed by `(stratum, segment, variant)`.
    pub fn key(&self) -> (Stratum, u32, Variant) {
        (self.stratum, self.segment, self.variant)
    }
}

/// FAR/FRR (and the raw counts behind them) at a threshold over a sample slice.
#[derive(Clone, Copy, Debug)]
pub struct Rates {
    /// False-accept rate (attacks accepted ÷ attacks). `NaN` if no attack samples.
    pub far: f64,
    /// Attacks accepted (`score ≥ threshold`).
    pub false_accepts: u64,
    /// Attack sample count.
    pub attacks: u64,
    /// False-reject rate (honest rejected ÷ honest). `NaN` if no honest samples.
    pub frr: f64,
    /// Honest samples rejected (`score < threshold`).
    pub false_rejects: u64,
    /// Honest sample count.
    pub honest: u64,
}

/// Compute FAR/FRR at `threshold` over `samples` (honest passes iff `score ≥ threshold`).
pub fn rates(samples: &[Sample], threshold: f64) -> Rates {
    let (mut fa, mut an, mut fr, mut hn) = (0u64, 0u64, 0u64, 0u64);
    for s in samples {
        match s.class() {
            Class::Honest => {
                hn += 1;
                if s.score < threshold {
                    fr += 1;
                }
            }
            Class::Attack => {
                an += 1;
                if s.score >= threshold {
                    fa += 1;
                }
            }
        }
    }
    Rates {
        far: if an == 0 { f64::NAN } else { fa as f64 / an as f64 },
        false_accepts: fa,
        attacks: an,
        frr: if hn == 0 { f64::NAN } else { fr as f64 / hn as f64 },
        false_rejects: fr,
        honest: hn,
    }
}

/// Candidate thresholds for an ROC sweep: just below the minimum score, just above the maximum,
/// and the midpoint between every pair of adjacent distinct scores. This lets FAR and FRR each
/// reach 0 and 1, so any achievable operating point is on the sweep.
pub fn candidate_thresholds(samples: &[Sample]) -> Vec<f64> {
    let mut scores: Vec<f64> = samples.iter().map(|s| s.score).collect();
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
    scores.dedup();
    if scores.is_empty() {
        return vec![0.0];
    }
    let mut out = Vec::with_capacity(scores.len() + 1);
    out.push(scores[0] - 1e-6);
    for w in scores.windows(2) {
        out.push((w[0] + w[1]) / 2.0);
    }
    out.push(scores[scores.len() - 1] + 1e-6);
    out
}

/// Threshold selected on `calibration` by **Youden's J** (maximize `TPR − FPR =
/// (1 − FRR) − FAR`). Ties are broken toward the **higher** threshold — the more conservative
/// choice, since a higher bar lowers FAR (accepting a cheat is the costly error). Returns
/// `(threshold, youden_j)`.
pub fn select_threshold_youden(calibration: &[Sample]) -> (f64, f64) {
    let mut best_threshold = 0.0;
    let mut best_j = f64::NEG_INFINITY;
    for t in candidate_thresholds(calibration) {
        let r = rates(calibration, t);
        let tpr = if r.honest == 0 { 0.0 } else { 1.0 - r.frr };
        let fpr = if r.attacks == 0 { 0.0 } else { r.far };
        let j = tpr - fpr;
        // `>=` with an ascending candidate list breaks ties toward the higher threshold.
        if j >= best_j {
            best_j = j;
            best_threshold = t;
        }
    }
    (best_threshold, best_j)
}

/// Exact two-sided **Clopper–Pearson** interval for `x` successes in `n` trials at confidence
/// `conf` (e.g. `0.95`), via Beta quantiles. Returns `(lower, upper)`.
///
/// Honest endpoints: `x = 0 ⇒ lower = 0` and `x = n ⇒ upper = 1` (the Beta shape parameter would
/// otherwise be 0). `n = 0` returns the vacuous `(0, 1)`.
pub fn clopper_pearson(x: u64, n: u64, conf: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let alpha = 1.0 - conf;
    let lower = if x == 0 {
        0.0
    } else {
        Beta::new(x as f64, (n - x + 1) as f64)
            .expect("valid Beta(x, n-x+1)")
            .inverse_cdf(alpha / 2.0)
    };
    let upper = if x == n {
        1.0
    } else {
        Beta::new((x + 1) as f64, (n - x) as f64)
            .expect("valid Beta(x+1, n-x)")
            .inverse_cdf(1.0 - alpha / 2.0)
    };
    (lower, upper)
}

/// `true` iff the two partitions share no `(stratum, segment, variant)` key — the disjointness
/// the study asserts so calibration can never leak into the held-out report.
pub fn disjoint(a: &[Sample], b: &[Sample]) -> bool {
    use std::collections::HashSet;
    let keys: HashSet<_> = a.iter().map(Sample::key).collect();
    b.iter().all(|s| !keys.contains(&s.key()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(set: DataSet, variant: Variant, score: f64) -> Sample {
        Sample {
            stratum: Stratum::SmoothGradient,
            set,
            segment: 0,
            variant,
            score,
        }
    }

    #[test]
    fn rates_count_false_accepts_and_rejects() {
        let s = [
            sample(DataSet::HeldOut, Variant::Honest, 0.95), // passes at 0.9
            sample(DataSet::HeldOut, Variant::Honest, 0.80), // rejected at 0.9 → false reject
            sample(DataSet::HeldOut, Variant::Garbage, 0.10), // rejected → correct
            sample(DataSet::HeldOut, Variant::WrongBitrate, 0.93), // accepted at 0.9 → false accept
        ];
        let r = rates(&s, 0.9);
        assert_eq!((r.honest, r.false_rejects), (2, 1));
        assert_eq!((r.attacks, r.false_accepts), (2, 1));
        assert!((r.frr - 0.5).abs() < 1e-12 && (r.far - 0.5).abs() < 1e-12);
    }

    #[test]
    fn youden_separates_clean_data() {
        // Honest scores well above attack scores ⇒ a threshold in the gap gives J = 1.
        let mut s = Vec::new();
        for &h in &[0.97, 0.98, 0.99] {
            s.push(sample(DataSet::Calibration, Variant::Honest, h));
        }
        for &a in &[0.10, 0.40, 0.55] {
            s.push(sample(DataSet::Calibration, Variant::Garbage, a));
        }
        let (t, j) = select_threshold_youden(&s);
        assert!((j - 1.0).abs() < 1e-12, "clean separation should give J=1, got {j}");
        assert!(t > 0.55 && t < 0.97, "threshold should fall in the gap, got {t}");
        // At that threshold both error rates are zero on calibration.
        let r = rates(&s, t);
        assert_eq!((r.false_accepts, r.false_rejects), (0, 0));
    }

    #[test]
    fn clopper_pearson_zero_and_full_match_closed_form() {
        // x=0, n=10: lower=0, upper = 1 − 0.025^(1/10) = 0.30850.
        let (lo, hi) = clopper_pearson(0, 10, 0.95);
        assert_eq!(lo, 0.0);
        assert!((hi - (1.0 - 0.025_f64.powf(0.1))).abs() < 1e-9, "got upper={hi}");
        // x=n=10: upper=1, lower = 0.025^(1/10) = 0.69150.
        let (lo, hi) = clopper_pearson(10, 10, 0.95);
        assert_eq!(hi, 1.0);
        assert!((lo - 0.025_f64.powf(0.1)).abs() < 1e-9, "got lower={lo}");
    }

    #[test]
    fn clopper_pearson_brackets_the_point_estimate() {
        // A two-sided interval must contain x/n and sit within [0,1].
        let (lo, hi) = clopper_pearson(3, 20, 0.95);
        let p = 3.0 / 20.0;
        assert!(lo < p && p < hi, "interval [{lo},{hi}] must bracket {p}");
        assert!(lo >= 0.0 && hi <= 1.0);
        assert!(n_zero_vacuous());
    }

    fn n_zero_vacuous() -> bool {
        clopper_pearson(0, 0, 0.95) == (0.0, 1.0)
    }

    #[test]
    fn disjoint_detects_shared_key() {
        let a = [sample(DataSet::Calibration, Variant::Honest, 0.9)];
        // Same (stratum, segment, variant) ⇒ not disjoint, even with a different score/set.
        let mut shared = sample(DataSet::HeldOut, Variant::Honest, 0.5);
        shared.stratum = Stratum::SmoothGradient;
        shared.segment = 0;
        assert!(!disjoint(&a, &[shared]));
        // A different segment ⇒ disjoint.
        let mut other = shared;
        other.segment = 1;
        assert!(disjoint(&a, &[other]));
    }
}
