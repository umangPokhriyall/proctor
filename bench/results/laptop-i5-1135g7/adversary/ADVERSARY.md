# ADVERSARY — the falsifiable security proof (Phase 6 §6)

Real cheating workers (bench-only; the production `worker/` has no cheat path — grep-confirmed) over the real `verify::verify_segment` detector and the real epoch-fenced Redis store. Comparison plane 160×120, committed ROC threshold **0.9328** (`results/verify/roc-threshold.json`), 9 corpus segments. Source CSVs: `per_class_far.csv`, `detection_vs_predicted.csv`, `slow_zombie_chaos.csv`, `escalation_cheap_downscale.csv`. Every detection rate carries a 95% Clopper–Pearson interval.

## (a) Slow-zombie chaos at scale → zero double-outputs

Across **1000 tasks** under the slow-zombie schedule (lease → reclaim → re-lease → the zombie's epoch-stale submit hits the store CAS): **1000 zombie submits rejected**, **1000 legitimate outputs released**, and the re-lease fencing epoch strictly advanced on **1000/1000** reclaims. **Double-outputs: 0.**

Fencing holds safety **under concurrency at scale**, not just in the unit/smoke case: a heartbeat timeout is a liveness heuristic; the monotonic lease epoch (compare-and-set in the Redis store, mirroring `core::Task::apply`) is the safety mechanism — exactly one output per segment, always (amendment §1.1). The **byte-swap** variant (post-commit blob swap) is the binding-layer analogue, caught deterministically below.

## (b) Per-class detection vs the predicted `hypergeometric × (1 − FAR)`

### Per-segment false-accept rate (the real verifier, 95% CI)

| Class | FAR (events/N) | 95% CI |
|---|---|---|
| cheap_downscale | 6/9 (66.7%) | [29.9%, 92.5%] |
| wrong_bitrate | 0/9 (0.0%) | [0.0%, 33.6%] |
| frame_substitution | 0/9 (0.0%) | [0.0%, 33.6%] |
| garbage | 0/9 (0.0%) | [0.0%, 33.6%] |
| byte_swap | 0/9 (0.0%) | [0.0%, 33.6%] |
| honest (FRR) | 0/9 (0.0%) | [0.0%, 33.6%] |

The corpus is small, so the per-class FAR intervals are wide by construction — that width is the honest statement of confidence, not smoothed over.

### End-to-end worker detection (f=0.25, n=16): measured [95% CI] vs predicted

`p` is the per-tier sampling fraction (Pristine 0.02 / Watch 0.10 / Suspect 0.25). Measured = Monte-Carlo over the real per-segment outcomes; predicted = committed `p_detect_hypergeometric × (1 − FAR)`. Source: `detection_vs_predicted.csv`.

| Class | p | measured [CI] | predicted |
|---|---|---|---|
| cheap_downscale | 0.02 | 8.4% [8.1, 8.8] | 8.3% |
| cheap_downscale | 0.10 | 16.2% [15.7, 16.7] | 15.0% |
| cheap_downscale | 0.25 | 29.9% [29.3, 30.6] | 24.3% |
| wrong_bitrate | 0.02 | 25.0% [24.4, 25.6] | 25.0% |
| wrong_bitrate | 0.10 | 45.3% [44.6, 46.0] | 45.0% |
| wrong_bitrate | 0.25 | 72.7% [72.1, 73.4] | 72.8% |
| frame_substitution | 0.02 | 24.9% [24.3, 25.5] | 25.0% |
| frame_substitution | 0.10 | 44.4% [43.7, 45.0] | 45.0% |
| frame_substitution | 0.25 | 72.9% [72.3, 73.5] | 72.8% |
| garbage | 0.02 | 25.3% [24.7, 25.9] | 25.0% |
| garbage | 0.10 | 45.3% [44.6, 46.0] | 45.0% |
| garbage | 0.25 | 72.4% [71.8, 73.1] | 72.8% |
| byte_swap | 0.02 | 24.9% [24.3, 25.5] | 25.0% |
| byte_swap | 0.10 | 44.8% [44.1, 45.5] | 45.0% |
| byte_swap | 0.25 | 72.5% [71.9, 73.1] | 72.8% |

Measured tracks the predicted curve; where it sits modestly **above** predicted, that is the honest direction — when several tampered segments are sampled, each independently risks a flag, so `P_hyper × (1 − FAR)` (a single-catch composition) is mildly conservative.

### byte-swap: caught deterministically at binding

byte-swap FAR = **0.0%** (9 of 9 caught) → effective detection = the raw hypergeometric (`1 − FAR = 1`): a post-commit blob swap fails `check_binding` (`Commitment::commit(&[SHA-256(blob)]) ≠ submitted`) **before any challenge frame**, so it is a `CommitmentMismatch` every time and a one-step Ban (reputation −64). The integrity guarantee is hard, not statistical.

### cheap-downscale: the hardest class (the elite line)

cheap-downscale is the **hardest** class: FAR = **66.7%** at the 160×120 plane — a low-resolution re-encode stays near the honest SSIM range on smooth/high-detail content, so effective detection sits **materially below** the raw hypergeometric (every row above is scaled by `1 − FAR ≈ 0.33`). This reads higher than the Phase-3 study's published ≈21% (`results/verify/STUDY.md`): that study scored 4 s clips over 8 time-windows, this suite scores short 1 s `-c copy` segments (fewer discriminating frames, small N → the wide CI above), so the point estimate is geometry- and segment-length-dependent. Both agree on the load-bearing conclusion — cheap-downscale is by far the hardest class — and on the remedy. **Remedy** (named, with the calibration sweep as its basis, `results/verify/roc-curve-calibration.csv`): a FAR-constrained threshold (raise it, trading FRR for FAR) or a higher comparison geometry (compare at >160×120, where the downscale artifact is unmissable). The asymmetric reputation policy (fast distrust on a fail, slow trust on a pass — ≈8 passes to undo one fidelity fail) is the second line of defence against this FAR.

## (c) Adaptive escalation, the floor, and the accepted info-leak

A **persistent cheap-downscale cheater** (f=0.5) over the **real** `sched::reputation` policy (`escalation_cheap_downscale.csv`): first caught at job **2** while still at the Pristine floor (p=0.02); each catch (`FidelityBelowThreshold`, −8) escalates the tier, raising `p` (0.02 → 0.10 → 0.25), which accelerates the next catch — Banned at **job 15**. Over 200 seeded runs the mean jobs-to-Ban is **19**.

**The floor catches even a minimal cheater.** A low-rate cheater tampering a single segment of 16 (f=1/16) is still sampled at p ≥ P_MIN = 0.02, so it is caught — mean first catch at job **45** (200 seeds). No worker is ever unsampled (`k = ⌈p·n⌉ ≥ 1`); minimum detection is independent of reputation.

**Accepted information leak (amendment §1.3, stated plainly):** a worker can infer its reputation tier from the rate at which it is challenged. This is *accepted* precisely because the `P_MIN = 0.02` floor guarantees a minimum detection probability **regardless of that inference** — a worker that infers it is Pristine still cannot tamper below the floor's reach. The leak buys the adversary nothing the floor does not already cover.
