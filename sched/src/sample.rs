//! `sample` — the `Bernoulli(p_tier)` verify-sampling decision (§5.3).
//!
//! On a `Submitted` task the scheduler draws `Bernoulli(p_tier)`: a hit routes the
//! submission to the verifier (`select_or_accept(task, true)` → `SelectForVerification`),
//! a miss content-addresses the release (`select_or_accept(task, false)` → `Accept`). The
//! sampling fraction `p` comes from [`crate::reputation`] (tier→`p` with the hard `P_MIN`
//! floor), so **no worker is ever unsampled** — even a pristine worker is drawn at the
//! floor, which is what makes the floor a *guarantee* rather than a hope.
//!
//! The RNG is **injectable** (the §5.3 requirement): production uses an OS-seeded CSPRNG
//! ([`Sampler::from_entropy`], or inject [`rand::rngs::OsRng`] directly via [`Sampler::new`]);
//! tests use a seeded [`rand::rngs::StdRng`] ([`Sampler::seeded`]) so a sampling decision
//! sequence is exactly reproducible. The draw is `Bernoulli(p)` via [`rand::Rng::gen_bool`].

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::reputation;
use crate::store::Tier;

/// A verify-sampling decision source over an injectable RNG `R`. Holds the RNG by value so
/// the draw stream is owned and (when seeded) deterministic.
pub struct Sampler<R: Rng> {
    rng: R,
}

impl<R: Rng> Sampler<R> {
    /// Wrap any RNG — e.g. inject [`rand::rngs::OsRng`] in production or a seeded
    /// [`StdRng`] in tests.
    pub fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Draw `Bernoulli(p)`: `true` (sample → verify) with probability `p`. `p` is clamped to
    /// `[0, 1]` so a caller can pass a raw fraction without panicking.
    pub fn sample_p(&mut self, p: f64) -> bool {
        self.rng.gen_bool(p.clamp(0.0, 1.0))
    }

    /// Draw the sampling decision for a worker at `tier`, using the reputation policy's
    /// tier→`p` map (floored at [`reputation::P_MIN`], so a pristine worker is still drawn).
    pub fn sample_tier(&mut self, tier: Tier) -> bool {
        self.sample_p(reputation::p_for(tier))
    }
}

impl Sampler<StdRng> {
    /// A reproducible sampler seeded from `seed` — for tests and deterministic replays.
    #[must_use]
    pub fn seeded(seed: u64) -> Self {
        Self::new(StdRng::seed_from_u64(seed))
    }

    /// A production sampler seeded from OS entropy (a CSPRNG; no fixed seed).
    #[must_use]
    pub fn from_entropy() -> Self {
        Self::new(StdRng::from_entropy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_under_a_seed() {
        // Two samplers with the same seed produce identical decision streams — the basis
        // for reproducible tests and replayable scheduler runs.
        let mut a = Sampler::seeded(0xC0FFEE);
        let mut b = Sampler::seeded(0xC0FFEE);
        for _ in 0..2000 {
            assert_eq!(a.sample_p(0.3), b.sample_p(0.3));
        }
        // A different seed yields a different stream (almost surely).
        let mut c = Sampler::seeded(1);
        let mut d = Sampler::seeded(2);
        let differ = (0..2000).filter(|_| c.sample_p(0.5) != d.sample_p(0.5)).count();
        assert!(differ > 0, "distinct seeds must diverge");
    }

    #[test]
    fn empirical_rate_tracks_p() {
        let mut s = Sampler::seeded(7);
        let n = 100_000;
        let hits = (0..n).filter(|_| s.sample_p(0.2)).count();
        let rate = hits as f64 / f64::from(n);
        assert!((rate - 0.2).abs() < 0.01, "rate {rate} should be ~0.2");
    }

    #[test]
    fn extremes_are_certain() {
        let mut s = Sampler::seeded(42);
        for _ in 0..1000 {
            assert!(!s.sample_p(0.0), "p=0 never samples");
            assert!(s.sample_p(1.0), "p=1 always samples");
        }
        // Out-of-range inputs clamp rather than panic.
        assert!(!s.sample_p(-5.0));
        assert!(s.sample_p(5.0));
    }

    #[test]
    fn pristine_worker_is_still_sampled_at_the_floor() {
        // The floor guarantees a pristine worker is not unsampled: over a run at P_MIN,
        // at least one challenge is drawn (P(all miss) = 0.98^N is astronomically small).
        let mut s = Sampler::seeded(99);
        let n = 1000;
        let hits = (0..n).filter(|_| s.sample_tier(Tier::Pristine)).count();
        assert!(hits > 0, "no worker is ever unsampled — pristine must still be drawn");
        // And the pristine rate sits near the floor.
        let rate = hits as f64 / f64::from(n);
        assert!((rate - reputation::P_MIN).abs() < 0.02, "pristine rate {rate} ~ P_MIN");
    }

    #[test]
    fn distrust_raises_the_sampling_rate() {
        // A more-distrusted tier is sampled more often than a pristine one.
        let draws = 50_000;
        let rate = |tier: Tier, seed: u64| {
            let mut s = Sampler::seeded(seed);
            (0..draws).filter(|_| s.sample_tier(tier)).count() as f64 / f64::from(draws)
        };
        let pristine = rate(Tier::Pristine, 5);
        let suspect = rate(Tier::Suspect, 5);
        assert!(suspect > pristine, "Suspect ({suspect}) must be sampled more than Pristine ({pristine})");
        assert!((suspect - 0.25).abs() < 0.01);
    }

    #[test]
    fn from_entropy_constructs_and_draws() {
        // Smoke: the production constructor works and produces a usable decision.
        let mut s = Sampler::from_entropy();
        let _ = s.sample_tier(Tier::Watch);
    }
}
