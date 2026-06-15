//! `reputation` — the adaptive tier→`p` policy with a hard floor (§5, amendment §1.3).
//!
//! This is the authoritative reputation policy: it owns the [`Standing`] accumulator, the
//! standing→[`Tier`] bands, the **asymmetric** updates from a verifier verdict, and the
//! tier→sampling-fraction map with the hard floor [`P_MIN`]. The store persists a worker's
//! standing and reports the tier; the actual magnitudes, bands, and `p`-values live here —
//! [`crate::store`]'s coarse `update_standing` path delegates its penalty magnitude and
//! tier mapping to this module ([`penalty`], [`tier_of`]), so there is one source of truth.
//!
//! ## Asymmetric updates — the honest response to FAR ≈ 21% (§5.2)
//! Effective detection is `P_hyper × (1 − FAR)`, and the measured held-out FAR ≈ 21%, so a
//! single verify *pass* is weak evidence of honesty. The policy is therefore **fast to
//! distrust, slow to trust**:
//! - A **fail** applies a large penalty — tier escalates sharply, sampling rises fast.
//!   A [`VerifyDetail::CommitmentMismatch`] is the **heaviest**: it is provable byte-swap
//!   cheating (the anti-swap chain, §7), not a fidelity judgment, so one is enough to
//!   `Banned`. A [`VerifyDetail::IntegrityViolation`] (stitch) is likewise provable and
//!   heavy.
//! - A **pass** ([`VerifyDetail::Ok`]) applies only a small credit, capped at the
//!   `Pristine` baseline — trust accrues over *many* independent passes, never on one
//!   (the asymmetry below is ≈ 8 passes to undo a single fidelity fail).
//! - [`VerifyDetail::Inconclusive`] changes nothing; the engine re-samples.
//!
//! ## The floor (§5.1, §1.3)
//! Every non-terminal tier maps to `p ≥ P_MIN = 0.02`, applied to **every** worker
//! including pristine ones, so `k = ⌈p·n⌉ ≥ 1` always and **no worker is ever unsampled**.
//! The eligible-tier `p`-values (`0.02 / 0.10 / 0.25`) are the Phase 3 published-curve
//! family's representative tiers (`verify::detection::TIERS`); the floor matches
//! `verify::detection::P_MIN`. `sched` cannot depend on `verify`, so the constant is
//! restated here, deliberately equal.
//!
//! Pure and clock-free: the engine (Session 5) reads a worker's standing, applies a
//! verdict through here, and persists the result.

use proctor_core::{ReputationDelta, VerifyDetail, VerifyResult};

use crate::store::Tier;

/// A worker's accumulated reputation. `0` is the `Pristine` baseline; penalties drive it
/// negative, pass-credits move it back toward `0`. Plain `i32` to match the store's
/// persisted field (the differential oracle compares like with like).
pub type Standing = i32;

/// The `Pristine` baseline and the ceiling a pass-credit may reach.
pub const PRISTINE: Standing = 0;

/// The hard sampling-fraction floor (2%), applied to every worker including pristine ones
/// so `k = ⌈p·n⌉ ≥ 1` for all `n` — no worker is ever unsampled (amendment §1.3). Equal by
/// construction to the Phase 3 published floor `verify::detection::P_MIN`.
pub const P_MIN: f64 = 0.02;

/// Lower bound on standing, so repeated penalties stay bounded (well past `Banned`).
pub const STANDING_FLOOR: Standing = -128;

// --- update magnitudes (asymmetric: a fail outweighs a pass many-to-one) ----

/// Pass credit: trust accrues slowly (≈ FIDELITY_FAIL passes to undo one fidelity fail).
const PASS_CREDIT: i32 = 1;
/// A fidelity fail (`FidelityBelowThreshold`): a sharp penalty.
const FIDELITY_FAIL: i32 = 8;
/// A stitch integrity violation: provable, heavier — straight to `Suspended`.
const INTEGRITY_FAIL: i32 = 32;
/// A commitment mismatch: provable byte-swap cheating, the **heaviest** — straight to
/// `Banned`.
const COMMITMENT_FAIL: i32 = 64;
/// A lease timeout (no-show): a liveness lapse, not cheating — the lightest penalty.
const TIMEOUT_PENALTY: i32 = 4;

// --- tier bands -------------------------------------------------------------
//
// Chosen so the magnitudes above land cleanly: one fidelity fail (−8) → Watch; two → Suspect;
// four → Suspended; a commitment mismatch (−64) → Banned in one step.

/// Map an accumulated standing to its [`Tier`]. Monotonic: lower standing ⇒ stricter tier.
#[must_use]
pub fn tier_of(standing: Standing) -> Tier {
    match standing {
        s if s >= 0 => Tier::Pristine,
        -8..=-1 => Tier::Watch,
        -31..=-9 => Tier::Suspect,
        -63..=-32 => Tier::Suspended,
        _ => Tier::Banned,
    }
}

/// The sampling fraction `p` for a tier, with the hard [`P_MIN`] floor. The eligible-tier
/// values are the Phase 3 published representative tiers (`0.02 / 0.10 / 0.25`); the
/// (ineligible) `Suspended`/`Banned` tiers map to `1.0` (maximal suspicion) but receive no
/// dispatch, so their `p` is moot. Sampling rises with distrust; every value is `≥ P_MIN`.
#[must_use]
pub fn p_for(tier: Tier) -> f64 {
    let p = match tier {
        Tier::Pristine => P_MIN,
        Tier::Watch => 0.10,
        Tier::Suspect => 0.25,
        Tier::Suspended | Tier::Banned => 1.0,
    };
    p.max(P_MIN)
}

/// Convenience: the sampling fraction for a worker at `standing`.
#[must_use]
pub fn p_for_standing(standing: Standing) -> f64 {
    p_for(tier_of(standing))
}

/// The sampled-segment count `k = ⌈p·n⌉`, clamped to `[0, n]` — the same definition as the
/// verifier's `verify::detection::sample_count`. With `p ≥ P_MIN` this is `≥ 1` for every
/// `n ≥ 1`, which is the floor invariant this module guarantees.
#[must_use]
pub fn challenge_count(p: f64, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let k = (p * f64::from(n)).ceil();
    let k = if k.is_finite() && k > 0.0 { k as u32 } else { 0 };
    k.min(n)
}

// --- standing updates -------------------------------------------------------

fn credit(standing: Standing) -> Standing {
    // Capped at the Pristine baseline: passes never build "super-credit" that would mask a
    // later fail (slow trust, no over-reward).
    standing.saturating_add(PASS_CREDIT).min(PRISTINE)
}

fn penalize(standing: Standing, by: i32) -> Standing {
    standing.saturating_sub(by).max(STANDING_FLOOR)
}

/// Apply a verifier verdict (the categorical [`VerifyDetail`]) to a worker's standing —
/// the rich, asymmetric path used by the engine (Session 5), which has the full detail.
#[must_use]
pub fn record_verdict(standing: Standing, detail: VerifyDetail) -> Standing {
    match detail {
        VerifyDetail::Ok => credit(standing),
        VerifyDetail::FidelityBelowThreshold => penalize(standing, FIDELITY_FAIL),
        VerifyDetail::IntegrityViolation => penalize(standing, INTEGRITY_FAIL),
        VerifyDetail::CommitmentMismatch => penalize(standing, COMMITMENT_FAIL),
        // No verdict reached — re-sample, standing unchanged.
        VerifyDetail::Inconclusive => standing,
    }
}

/// Apply a full [`VerifyResult`] — a thin wrapper over [`record_verdict`] on its detail.
#[must_use]
pub fn record_result(standing: Standing, result: &VerifyResult) -> Standing {
    record_verdict(standing, result.detail)
}

/// The **signed** standing change a verdict applies, before clamping (`+PASS_CREDIT` for
/// `Ok`, the negative fail magnitudes, `0` for `Inconclusive`). The Redis store needs the
/// magnitude as a plain integer for its Lua `HINCRBY`-with-clamp; the in-memory store uses
/// [`record_verdict`] directly. Both clamp to `[STANDING_FLOOR, PRISTINE]`, so
/// `clamp(standing + verdict_delta(d)) == record_verdict(standing, d)` — one source of
/// magnitudes across both backends (proven in tests + the store contract suite).
#[must_use]
pub(crate) fn verdict_delta(detail: VerifyDetail) -> i32 {
    match detail {
        VerifyDetail::Ok => PASS_CREDIT,
        VerifyDetail::FidelityBelowThreshold => -FIDELITY_FAIL,
        VerifyDetail::IntegrityViolation => -INTEGRITY_FAIL,
        VerifyDetail::CommitmentMismatch => -COMMITMENT_FAIL,
        VerifyDetail::Inconclusive => 0,
    }
}

/// Apply a coarse, `core`-emitted [`ReputationDelta`] (lease `Timeout` or a
/// `VerificationFailure` whose detail was already reduced away). The engine prefers
/// [`record_verdict`] when it still holds the `VerifyDetail`; this path keeps the
/// store's `update_standing` and the rich path on identical magnitudes.
#[must_use]
pub fn record_delta(standing: Standing, delta: ReputationDelta) -> Standing {
    penalize(standing, penalty(delta))
}

/// The penalty magnitude a coarse [`ReputationDelta`] subtracts from standing. Exposed for
/// the Redis store, whose Lua `HINCRBY` needs the magnitude as a plain integer; the
/// in-memory store and this module use it too, so all paths agree (§ store delegation).
#[must_use]
pub(crate) fn penalty(delta: ReputationDelta) -> i32 {
    match delta {
        ReputationDelta::VerificationFailure => FIDELITY_FAIL,
        ReputationDelta::Timeout => TIMEOUT_PENALTY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the floor: no worker is ever unsampled ------------------------------

    #[test]
    fn p_min_floor_keeps_k_at_least_one_for_every_eligible_tier() {
        for tier in [Tier::Pristine, Tier::Watch, Tier::Suspect] {
            let p = p_for(tier);
            assert!(p >= P_MIN, "{tier:?} must be at or above the floor");
            for n in [1u32, 4, 8, 32, 64, 1000] {
                assert!(
                    challenge_count(p, n) >= 1,
                    "{tier:?} (p={p}) must sample >=1 at n={n}"
                );
            }
        }
    }

    #[test]
    fn pristine_sits_exactly_on_the_floor() {
        assert!((p_for(Tier::Pristine) - P_MIN).abs() < 1e-12);
    }

    #[test]
    fn sampling_fraction_rises_with_distrust() {
        // Monotonic non-decreasing across the eligible tiers.
        assert!(p_for(Tier::Pristine) <= p_for(Tier::Watch));
        assert!(p_for(Tier::Watch) <= p_for(Tier::Suspect));
        // And the eligible tiers match the Phase 3 published curve family.
        assert!((p_for(Tier::Watch) - 0.10).abs() < 1e-12);
        assert!((p_for(Tier::Suspect) - 0.25).abs() < 1e-12);
    }

    // --- fail escalates sharply ---------------------------------------------

    #[test]
    fn one_fidelity_fail_escalates_off_pristine() {
        let s = record_verdict(PRISTINE, VerifyDetail::FidelityBelowThreshold);
        assert_eq!(s, -8);
        assert_eq!(tier_of(s), Tier::Watch, "a single fail leaves Pristine at once");
    }

    #[test]
    fn commitment_mismatch_is_heaviest_and_bans_in_one_step() {
        let cm = record_verdict(PRISTINE, VerifyDetail::CommitmentMismatch);
        let integ = record_verdict(PRISTINE, VerifyDetail::IntegrityViolation);
        let fid = record_verdict(PRISTINE, VerifyDetail::FidelityBelowThreshold);
        // Heaviest: the commitment mismatch drops standing furthest.
        assert!(cm < integ && integ < fid && fid < PRISTINE);
        assert_eq!(cm, -64);
        // Provable cheating → Banned (ineligible) immediately.
        assert_eq!(tier_of(cm), Tier::Banned);
        assert!(!tier_of(cm).is_eligible());
    }

    // --- pass de-escalates slowly (the asymmetry) ----------------------------

    #[test]
    fn pass_credits_one_step_and_recovery_is_slow() {
        // From a single fidelity fail (Watch, -8): each pass is worth only +1.
        let mut s = record_verdict(PRISTINE, VerifyDetail::FidelityBelowThreshold);
        assert_eq!(s, -8);
        s = record_verdict(s, VerifyDetail::Ok);
        assert_eq!(s, -7, "one pass is a small credit");
        assert_eq!(tier_of(s), Tier::Watch, "still distrusted after one pass");
        // It takes FIDELITY_FAIL (8) passes total to undo one fidelity fail — asymmetry 8:1.
        for _ in 0..7 {
            s = record_verdict(s, VerifyDetail::Ok);
        }
        assert_eq!(s, PRISTINE);
        assert_eq!(tier_of(s), Tier::Pristine);
    }

    #[test]
    fn pass_is_capped_at_pristine() {
        // A pass on an already-pristine worker does not build super-credit.
        assert_eq!(record_verdict(PRISTINE, VerifyDetail::Ok), PRISTINE);
    }

    #[test]
    fn inconclusive_leaves_standing_unchanged() {
        for s in [PRISTINE, -8, -40] {
            assert_eq!(record_verdict(s, VerifyDetail::Inconclusive), s);
        }
    }

    // --- eligibility gate ----------------------------------------------------

    #[test]
    fn eligibility_flips_at_suspended() {
        assert!(tier_of(-31).is_eligible(), "Suspect is still eligible");
        assert!(!tier_of(-32).is_eligible(), "Suspended is ineligible");
        assert!(!tier_of(STANDING_FLOOR).is_eligible(), "Banned is ineligible");
    }

    #[test]
    fn repeated_fidelity_fails_walk_the_ladder_to_ineligible() {
        let mut s = PRISTINE;
        let mut last = Tier::Pristine;
        for _ in 0..4 {
            s = record_verdict(s, VerifyDetail::FidelityBelowThreshold);
            assert!(tier_of(s) >= last, "tier never improves under repeated fails");
            last = tier_of(s);
        }
        // -32 after four fails ⇒ Suspended ⇒ ineligible for dispatch.
        assert_eq!(s, -32);
        assert!(!tier_of(s).is_eligible());
    }

    // --- coarse path agrees with the rich path on magnitudes -----------------

    #[test]
    fn coarse_delta_matches_rich_fidelity_fail() {
        // The store's coarse VerificationFailure must move standing exactly as a rich
        // FidelityBelowThreshold does, so the durable path and the engine path agree.
        assert_eq!(
            record_delta(PRISTINE, ReputationDelta::VerificationFailure),
            record_verdict(PRISTINE, VerifyDetail::FidelityBelowThreshold),
        );
        // A timeout is the lighter, liveness-only penalty.
        assert_eq!(record_delta(PRISTINE, ReputationDelta::Timeout), -4);
        assert_eq!(penalty(ReputationDelta::Timeout), 4);
        assert_eq!(penalty(ReputationDelta::VerificationFailure), 8);
    }

    #[test]
    fn verdict_delta_clamped_matches_record_verdict() {
        // The Redis store applies `clamp(standing + verdict_delta(detail))` in Lua; it must
        // equal the in-memory `record_verdict` for every detail at every reachable standing,
        // so the differential oracle (contract suite) compares like with like.
        let details = [
            VerifyDetail::Ok,
            VerifyDetail::FidelityBelowThreshold,
            VerifyDetail::IntegrityViolation,
            VerifyDetail::CommitmentMismatch,
            VerifyDetail::Inconclusive,
        ];
        for standing in [PRISTINE, -1, -8, -32, -63, -100, STANDING_FLOOR] {
            for d in details {
                let clamped = (standing + verdict_delta(d))
                    .clamp(STANDING_FLOOR, PRISTINE);
                assert_eq!(
                    clamped,
                    record_verdict(standing, d),
                    "clamp(standing+delta) must equal record_verdict for {d:?} at {standing}"
                );
            }
        }
    }

    #[test]
    fn penalties_saturate_at_the_floor() {
        let mut s = PRISTINE;
        for _ in 0..100 {
            s = record_verdict(s, VerifyDetail::CommitmentMismatch);
        }
        assert_eq!(s, STANDING_FLOOR, "standing never underflows past the floor");
        assert_eq!(tier_of(s), Tier::Banned);
    }
}
