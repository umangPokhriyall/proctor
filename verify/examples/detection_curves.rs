//! `detection_curves` — emit the committed detection-probability artifacts (phase3-spec.md §4).
//!
//! Writes two CSVs to `bench/results/verify/`:
//!   * `detection-family.csv` — the **published** exact hypergeometric family
//!     `P_detect(f, n; p_tier)` over the reputation tiers (pristine = `P_MIN`, mid, high), the
//!     segment grid `n ∈ {4,8,16,32,64}`, and the tamper grid `f ∈ (0,1]`.
//!   * `detection-divergence.csv` — both curves (hypergeometric and the binomial approximation)
//!     plus `divergence = binomial − hypergeometric`, the data behind the divergence plot.
//!
//! Pure arithmetic — no ffmpeg, no corpus, no randomness — so it always runs and is byte-stable.
//! Regenerate with: `cargo run --release --example detection_curves`.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use verify::detection::{
    p_detect_binomial, p_detect_hypergeometric, sample_count, tampered_count, F_GRID, N_GRID,
    P_MIN, TIERS,
};

fn main() {
    let results_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bench/results/verify");
    fs::create_dir_all(&results_dir).expect("create bench/results/verify");

    // 1) The published hypergeometric family across tiers.
    let mut family = String::from("tier,p,n,f,m,k,p_detect_hypergeometric\n");
    for &(label, p) in &TIERS {
        for &n in &N_GRID {
            for &f in &F_GRID {
                let m = tampered_count(f, n);
                let k = sample_count(p, n);
                let ph = p_detect_hypergeometric(f, n, p);
                writeln!(family, "{label},{p},{n},{f},{m},{k},{ph:.6}").unwrap();
            }
        }
    }
    let family_path = results_dir.join("detection-family.csv");
    fs::write(&family_path, &family).expect("write detection-family.csv");

    // 2) Both curves + the binomial−hypergeometric divergence (negative: binomial under-states).
    let mut divergence =
        String::from("tier,p,n,f,m,k,binomial,hypergeometric,divergence_binomial_minus_hyper\n");
    let mut max_abs_div = 0.0f64;
    let mut max_div_at = (0u32, 0.0f64, 0.0f64);
    for &(label, p) in &TIERS {
        for &n in &N_GRID {
            for &f in &F_GRID {
                let m = tampered_count(f, n);
                let k = sample_count(p, n);
                let pb = p_detect_binomial(f, n, p);
                let ph = p_detect_hypergeometric(f, n, p);
                let div = pb - ph;
                writeln!(divergence, "{label},{p},{n},{f},{m},{k},{pb:.6},{ph:.6},{div:+.6}")
                    .unwrap();
                if div.abs() > max_abs_div {
                    max_abs_div = div.abs();
                    max_div_at = (n, f, p);
                }
            }
        }
    }
    let divergence_path = results_dir.join("detection-divergence.csv");
    fs::write(&divergence_path, &divergence).expect("write detection-divergence.csv");

    println!("wrote {}", family_path.display());
    println!("wrote {}", divergence_path.display());
    println!(
        "P_MIN = {P_MIN}; largest |binomial − hypergeometric| = {max_abs_div:.4} at n={}, f={}, p={}",
        max_div_at.0, max_div_at.1, max_div_at.2
    );
    println!("(divergence is ≤ 0 everywhere: the binomial under-states the exact hypergeometric)");
}
