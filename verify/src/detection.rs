//! `detection` — falsifiable detection probability (phase3-spec.md §4, amendment §1.2.1+§1.3).
//!
//! The verifier samples `k = ⌈p·n⌉` of a job's `n` segments *without replacement* and
//! re-checks them. With `m = ⌈f·n⌉` segments tampered, the exact probability that at least
//! one tampered segment is sampled (and thus caught) is the **hypergeometric**
//!
//! ```text
//! P_detect(f, n; p) = 1 − C(n−m, k) / C(n, k)
//! ```
//!
//! We compute the survival ratio `C(n−m, k)/C(n, k)` directly as the exact product
//! `∏_{i=0}^{k−1} (n−m−i)/(n−i)` — closed-form, integer-exact for the published grid
//! (`n ≤ 64`), no Gamma function and no stats crate. Every number is owned (measure-never-guess).
//!
//! ## The binomial approximation, and the honest direction of its error
//! The legacy brief published the **binomial** `1 − (1−p)^(⌈f·n⌉)` — the with-replacement /
//! Bernoulli-sampling model. We keep it **only** for the divergence plot. The exact
//! hypergeometric is the published claim.
//!
//! A rigorous fact (and the reason we publish the exact curve): for the "detect ≥ 1 tampered"
//! event, fixed-size sampling *without* replacement **dominates** the with-replacement binomial,
//! so **`P_hyper ≥ P_binomial` pointwise** — the binomial *under*states true detection. Proof:
//! `P(miss)_hyper = ∏_{j=0}^{m−1} (n−k−j)/(n−j)`, and each factor `(n−k−j)/(n−j) ≤ (n−k)/n ≤ 1−p`
//! (the first step because `(n−k−j)·n − (n−k)(n−j) = −kj ≤ 0`, the second because `k = ⌈p·n⌉ ≥ p·n`),
//! so `P(miss)_hyper ≤ (1−p)^m = P(miss)_binomial`. The gap is largest at small `n`, where the
//! `⌈p·n⌉` ceiling lifts the realized sample fraction well above `p`.
//!
//! **Note for reviewers:** this is the *opposite* sign from the amendment's prose, which reads
//! "the binomial overstates detection." The amendment's load-bearing **decision** — *publish the
//! exact hypergeometric, keep the binomial only to show its approximation error* — stands either
//! way; only the divergence's sign is corrected here, by the math and the committed CSV.
//!
//! ## The `P_MIN` floor (amendment §1.3)
//! Adaptive sampling indexes `p` by a worker's reputation tier (the *policy* is Phase 4). Phase 3
//! fixes the **hard floor** [`P_MIN`]: every worker — pristine ones included — is sampled with
//! `p ≥ P_MIN`, so `k = ⌈p·n⌉ ≥ 1` across the whole published grid and **no worker is ever
//! unsampled**. The honest leak (a worker can infer its tier from challenge rate) is *accepted*
//! precisely because the floor guarantees a minimum detection probability regardless.

/// The hard sampling-fraction floor (2%). Applied to every worker including pristine ones, it
/// guarantees `k = ⌈P_MIN·n⌉ ≥ 1` for all `n` in the published grid (`n = 4 → k = 1`,
/// `n = 64 → k = 2`), i.e. at least one challenged segment per verification — no worker is ever
/// unsampled. The tier→`p` mapping above this floor is Phase 4 policy, not Phase 3.
pub const P_MIN: f64 = 0.02;

/// Representative reputation tiers as `(label, p)` — pristine (the floor), a mid tier, and a high
/// tier. Phase 3 publishes the detection curves at these points; the adaptive tier→`p` *policy*
/// that selects among them is Phase 4.
pub const TIERS: [(&str, f64); 3] = [("pristine", P_MIN), ("mid", 0.10), ("high", 0.25)];

/// Segment-count grid for the published family (amendment: short videos, `n ≤ 32`, are where the
/// approximation matters most; `64` anchors the large end).
pub const N_GRID: [u32; 5] = [4, 8, 16, 32, 64];

/// Tamper-fraction grid `f ∈ (0, 1]`. Includes `1/32` so the realistic single-segment tamper
/// (`m = 1` at `n = 32`) is on the curve, up to wholesale tampering (`f = 1`).
pub const F_GRID: [f64; 9] = [0.03125, 0.0625, 0.125, 0.1875, 0.25, 0.375, 0.5, 0.75, 1.0];

/// Tampered-segment count `m = ⌈f·n⌉`, clamped to `[0, n]`. `f` is expected in `(0, 1]`; values
/// outside are clamped so the function is total.
pub fn tampered_count(f: f64, n: u32) -> u32 {
    ceil_count(f, n)
}

/// Sampled-segment count `k = ⌈p·n⌉`, clamped to `[0, n]`. With `p ≥ `[`P_MIN`] this is `≥ 1`.
pub fn sample_count(p: f64, n: u32) -> u32 {
    ceil_count(p, n)
}

/// `⌈frac·n⌉` clamped to `[0, n]`. Shared by [`tampered_count`] and [`sample_count`].
fn ceil_count(frac: f64, n: u32) -> u32 {
    let raw = (frac * n as f64).ceil();
    if raw <= 0.0 {
        0
    } else if raw >= n as f64 {
        n
    } else {
        raw as u32
    }
}

/// Exact hypergeometric detection probability: population `n`, `m = ⌈f·n⌉` tampered,
/// `k = ⌈p·n⌉` sampled without replacement. `P = 1 − C(n−m, k)/C(n, k) ∈ [0, 1]`.
///
/// Edge cases fall out of the formula: `m = 0` (nothing to detect) and `k = 0` (nothing sampled)
/// both give `0`; `k > n−m` gives `1` (more samples than clean segments ⇒ a tampered one is
/// unavoidable), surfaced as a zero factor in the survival product.
pub fn p_detect_hypergeometric(f: f64, n: u32, p: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let m = tampered_count(f, n);
    let k = sample_count(p, n);
    if m == 0 || k == 0 {
        return 0.0;
    }
    1.0 - survival_ratio(n, m, k)
}

/// `C(n−m, k)/C(n, k)` as the exact product `∏_{i=0}^{k−1} (n−m−i)/(n−i)` — the probability that
/// a `k`-sample (without replacement) avoids all `m` tampered segments. When `k > n−m` the factor
/// at `i = n−m` is exactly `0`, so the product is `0` (detection certain), as it should be.
fn survival_ratio(n: u32, m: u32, k: u32) -> f64 {
    let (n, m) = (n as f64, m as f64);
    let mut ratio = 1.0;
    for i in 0..k {
        let i = i as f64;
        ratio *= (n - m - i) / (n - i); // denominator n−i ≥ 1 since k ≤ n ⇒ i ≤ n−1
    }
    ratio.max(0.0)
}

/// Binomial (with-replacement) approximation `1 − (1−p)^(⌈f·n⌉)`. Kept **only** for the divergence
/// plot; it *under*states true detection relative to [`p_detect_hypergeometric`] (see module docs).
pub fn p_detect_binomial(f: f64, n: u32, p: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let m = tampered_count(f, n);
    let p = p.clamp(0.0, 1.0);
    1.0 - (1.0 - p).powi(m as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-computed exact hypergeometric values at small `n` (no library to trust).
    #[test]
    fn hypergeometric_matches_hand_computed_small_n() {
        // n=4, m=⌈0.25·4⌉=1, k=⌈0.5·4⌉=2: 1 − C(3,2)/C(4,2) = 1 − 3/6 = 1/2.
        assert!((p_detect_hypergeometric(0.25, 4, 0.5) - 0.5).abs() < 1e-12);
        // n=4, m=2, k=2: 1 − C(2,2)/C(4,2) = 1 − 1/6 = 5/6.
        assert!((p_detect_hypergeometric(0.5, 4, 0.5) - 5.0 / 6.0).abs() < 1e-12);
        // n=8, m=2, k=2: 1 − C(6,2)/C(8,2) = 1 − 15/28 = 13/28.
        assert!((p_detect_hypergeometric(0.25, 8, 0.25) - 13.0 / 28.0).abs() < 1e-12);
        // k > n−m certainty: n=4, m=3, k=2 ⇒ C(1,2)=0 ⇒ P=1.
        assert!((p_detect_hypergeometric(0.75, 4, 0.5) - 1.0).abs() < 1e-12);
        // m=0 ⇒ nothing to detect ⇒ 0.
        assert_eq!(p_detect_hypergeometric(0.0, 8, 0.5), 0.0);
    }

    /// Binomial closed form, exact hand values.
    #[test]
    fn binomial_matches_hand_computed() {
        // m=1: 1 − (1−0.5)^1 = 0.5.
        assert!((p_detect_binomial(0.25, 4, 0.5) - 0.5).abs() < 1e-12);
        // m=2: 1 − (0.75)^2 = 0.4375.
        assert!((p_detect_binomial(0.25, 8, 0.25) - 0.4375).abs() < 1e-12);
    }

    /// The mathematically true pointwise relationship over the whole published grid:
    /// `hypergeometric ≥ binomial` (the binomial under-states; see module docs and the proof).
    /// This is the corrected direction — the amendment's prose has the sign reversed, but the
    /// *decision* to publish the exact hypergeometric is unaffected.
    #[test]
    fn hypergeometric_dominates_binomial_pointwise() {
        for &n in &N_GRID {
            for &f in &F_GRID {
                for &(_, p) in &TIERS {
                    let h = p_detect_hypergeometric(f, n, p);
                    let b = p_detect_binomial(f, n, p);
                    assert!(
                        h + 1e-12 >= b,
                        "expected hyper ≥ binom at n={n} f={f} p={p}, got hyper={h} binom={b}"
                    );
                }
            }
        }
    }

    /// The `P_MIN` floor guarantees at least one sampled segment for every worker, at every grid
    /// `n` — including the largest (`n = 64`). No worker is ever unsampled.
    #[test]
    fn p_min_floor_yields_at_least_one_sample() {
        assert!(sample_count(P_MIN, 64) >= 1, "P_MIN must sample ≥1 at the largest grid n");
        for &n in &N_GRID {
            assert!(sample_count(P_MIN, n) >= 1, "P_MIN must sample ≥1 at n={n}");
        }
    }

    /// All probabilities stay in `[0, 1]` across the grid (no numerical leakage).
    #[test]
    fn probabilities_stay_in_unit_interval() {
        for &n in &N_GRID {
            for &f in &F_GRID {
                for &(_, p) in &TIERS {
                    for v in [p_detect_hypergeometric(f, n, p), p_detect_binomial(f, n, p)] {
                        assert!((0.0..=1.0).contains(&v), "out of range: {v} at n={n} f={f} p={p}");
                    }
                }
            }
        }
    }

    /// Detection is monotone non-decreasing in the sampling fraction `p` (more sampling never
    /// hurts) and in the tamper fraction `f` (more tampering is never harder to catch).
    #[test]
    fn monotone_in_p_and_f() {
        let n = 32;
        // Increasing p at fixed f.
        let (lo, mid, hi) = (
            p_detect_hypergeometric(0.25, n, 0.02),
            p_detect_hypergeometric(0.25, n, 0.10),
            p_detect_hypergeometric(0.25, n, 0.25),
        );
        assert!(lo <= mid && mid <= hi, "not monotone in p: {lo} {mid} {hi}");
        // Increasing f at fixed p.
        let (a, b) = (
            p_detect_hypergeometric(0.0625, n, 0.10),
            p_detect_hypergeometric(0.5, n, 0.10),
        );
        assert!(a <= b, "not monotone in f: {a} {b}");
    }
}
