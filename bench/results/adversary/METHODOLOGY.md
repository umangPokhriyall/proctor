# Methodology — adversary suite (`results/adversary/`)

Scope: the §6 falsifiable security proof. The portfolio-wide methodology is consolidated in
Session 5; this records what these CSVs + `ADVERSARY.md` were produced from.

## Host

Intel i5-1135G7 (4 cores / 8 threads, 1 NUMA node); Linux 7.0.0; redis-server v8.8.0 (source
build, loopback `:6390`); ffmpeg 8.0.1; rustc 1.95 `--release`. Committed ROC threshold
0.9328 at the 160×120 comparison plane (`results/verify/roc-threshold.json`, never a literal).

## Adversary location (grep-confirmed)

Every cheat path lives in `bench/src/adversary.rs`. The production `worker/` has **no** cheat
path: `grep -rIn 'downscale\|byte.\?swap\|tamper\|forge\|cheat' worker/ verifier/` returns only
doc-comment prose, never logic. The five classes reuse the Phase-3 attack synthesis
(`verify/examples/verify_eval.rs`): cheap-downscale (96×72 ultrafast), wrong-bitrate (40 kbps),
frame-substitution (a different clip), garbage (drawbox black), and byte-swap (post-commit blob
flip).

## What is measured

- **Per-class FAR/FRR** (`per_class_far.csv`): the three corpus clips are cut into ≈1 s
  keyframe-aligned (`-c copy`) segments (9 total); for each (segment, class) the bench-only
  adversary forges an encrypted output + commitment and the **real** `verify::verify_segment`
  (binding then batched-decode SSIM vs the committed threshold) decides caught/not. FAR =
  attacks accepted ÷ attacks; FRR = honest rejected ÷ honest; each with a 95% Clopper–Pearson
  interval (`verify::roc::clopper_pearson`). Small N → wide intervals, reported honestly.
- **End-to-end detection** (`detection_vs_predicted.csv`): a Monte-Carlo (20 000 jobs/cell,
  seeded) over the **measured** per-segment catch pool — jobs of n=16 segments, m=⌈f·n⌉ tampered
  (each tampered slot's caught/not bootstrapped from the real pool), the verifier samples
  k=⌈p·n⌉ without replacement, the worker is caught iff any sampled tampered slot is a caught
  outcome. Compared to the committed prediction `p_detect_hypergeometric(f,n;p) × (1 − FAR)`,
  measured with its own Clopper–Pearson interval. The randomness modelled (which segments are
  sampled/tampered) is exactly what the hypergeometric models; the per-segment verdicts are
  real ffmpeg.
- **Slow-zombie chaos at scale** (`slow_zombie_chaos.csv`): 1000 tasks over the real
  epoch-fenced `RedisStore` — lease → `reclaim_expired` → re-lease → the zombie's stale-epoch
  submit hits the store CAS. Asserts zero double-outputs and a strictly-advancing fencing epoch.
- **Adaptive escalation** (`escalation_cheap_downscale.csv`): a persistent cheater driven
  through the **real** `sched::reputation` tier policy — a catch applies `record_verdict` (the
  asymmetric penalty), a clean job credits a pass; sampling `p` follows the resulting tier.

## Honest caveats

- The cheap-downscale FAR here (66.7%, CI [29.9%, 92.5%]) reads higher than the Phase-3 study's
  ≈21%: the Phase-3 study scored 4 s clips over 8 time-windows; this suite scores short 1 s
  segments (fewer discriminating frames, smaller N). Both agree cheap-downscale is the hardest
  class; the exact FAR is geometry/segment-length dependent.
- Single host, synthetic corpus, adjacent windows correlated — the effective independent N is
  below the nominal count. The CIs are reported, not smoothed.

## Regenerate

```sh
redis-server --port 6390 --save '' --appendonly no --daemonize yes --dir /tmp
cargo run -p bench --release -- adversary --redis-url redis://127.0.0.1:6390
```

Deterministic: the attack synthesis, the SSIM verdicts, and the seeded Monte-Carlo all
reproduce the committed CSVs byte-for-byte on the same host/ffmpeg.
