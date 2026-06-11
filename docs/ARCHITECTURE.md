# proctor — Architecture

> **Status:** grows as phases land. This file records design decisions and the reasons
> behind them, declaratively, with every claim tied to code or a committed measurement.
> **Phase 3** adds the verification design below; `sched` (dispatch, leases, the fencing
> token, the adaptive policy) and the scheduler/bench decompositions follow in Phases 4–6.

## Verification (Phase 3)

The verifier earns the "verifiable compute" claim: it independently re-checks a random,
unpredictable subset of a worker's segments and compares the result structurally. Every
number it produces is owned and explainable; the threshold is a committed artifact, not a
constant.

### Verifier as a separate binary (locked decision #3)

Re-execution is CPU-bound and must never run inside the I/O-bound scheduler, so the
verifier is a **separate binary** (`verifier/`); the expected output never leaves that
process. `verify/` is a `#![forbid(unsafe_code)]` **library** that the binary consumes;
the only `unsafe` in the whole verification path is `crypto::sys` (the libc FFI for
`memfd`/`mlock`/the child fd hand-off). The verifier re-runs ffmpeg through
`crypto::ffmpeg_no_disk`, so all media — source plaintext, reference output, worker
output — lives only in anonymous RAM (`memfd`), never a disk-backed file (THREAT-MODEL §4).

### The per-segment algorithm (`compare.rs`)

For one segment, entirely in memfds:

1. **Bind** — re-derive the single-leaf commitment and require an exact match before any
   challenge frame is chosen (THREAT-MODEL §4, the commit-binding anti-swap chain). On
   mismatch the verdict is `VerifyDetail::CommitmentMismatch` and nothing is sampled.
2. **Reconstruct ground truth** — decrypt the source (`Role::Source`) into a memfd and
   independently `transcode_no_disk` it with the frozen `TargetProfile`: the verifier's
   reference output, in RAM.
3. **Compare** — decrypt the worker output (`Role::Output`); at seeded random timestamps
   extract Y-plane frames from both worker output and reference and compute SSIM. The
   segment score is the **minimum** MSSIM across the sampled frames — conservative, so a
   single substituted frame drags the score down even when the rest is faithful.
4. **Decide** — pass iff the score ≥ the threshold loaded from the committed ROC file;
   emit the frozen, categorical `VerifyDetail`. No numeric threshold ever crosses the API.

Every memfd is scrubbed and closed on every path.

### SSIM comparator — hand-rolled (`ssim.rs`)

Structural similarity on the **luma** plane only — structural fidelity lives in luminance,
and that is what discriminates a cheap-downscale or frame-substitution from an honest
re-encode. We hand-roll it (no SSIM crate) so every number is explainable:

- **Window:** 8×8 uniform (box) window, stride 4 (overlapping). A uniform window is the
  explainable choice over the classic 11×11 Gaussian — equal weights, plain mean/variance.
- **Constants:** `C1 = (0.01·255)² = 6.5025`, `C2 = (0.03·255)² = 58.5225` (8-bit range,
  the SSIM-paper defaults), with the unbiased (N−1) windowed variance.
- **MSSIM** is the mean of the per-window index; the **segment** score is the *min* MSSIM
  across sampled frames.

The decision threshold comes from `bench/results/verify/roc-threshold.json` via
`RocThreshold::load`, **never** a literal in code (locked decision #4).

### Detection-probability family — exact hypergeometric (`detection.rs`)

The verifier samples `k = ⌈p·n⌉` of a job's `n` segments **without replacement**; with
`m = ⌈f·n⌉` tampered, the exact probability of catching at least one is the
**hypergeometric** `P_detect = 1 − C(n−m, k)/C(n, k)`, computed as the integer-exact
product `∏ (n−m−i)/(n−i)` (no Gamma, no stats crate). It is published as a **family**
`P_detect(f, n; p_tier)` over representative reputation tiers with the hard floor
`P_MIN = 0.02` (so `k ≥ 1` for every worker; THREAT-MODEL §5, the accepted tier-inference
leak). The binomial `1 − (1−p)^⌈f·n⌉` is kept **only** for the divergence plot; the
hypergeometric is the published claim. The tier→`p` adaptive **policy** is Phase 4.

Honest correction (proven and committed): the divergence `binomial − hypergeometric` is
**≤ 0** everywhere on the grid — the binomial *under*-states detection, the opposite sign
from amendment §1.2.1's prose. The amendment's decision (publish the exact hypergeometric)
is unaffected. Source: `bench/results/verify/detection-family.csv`,
`detection-divergence.csv`, and `DETECTION.md` (the proof and the flag for the spec owner).

### The ROC study — calibration, held-out, intervals, strata (`roc.rs`, `verify_eval`)

The threshold must not be circular and no point estimate stands without an interval:

- The corpus is split into a **calibration** set (threshold selection only) and a
  **disjoint held-out** set (the reported rates); disjointness is asserted at runtime.
- The threshold is selected on calibration only (Youden's J) and written with provenance
  (criterion, corpus SHA-256, ffmpeg version, date) to `roc-threshold.json`.
- Held-out **FAR/FRR** carry **95% Clopper–Pearson** intervals (Beta quantiles via
  `statrs`); a zero count is reported honestly as `[0, upper]`, never "0%".
- **FRR is reported per stratum** (smooth/gradient, high-detail, high-motion); where a
  single global threshold over-rejects a stratum, the study states and quantifies it.

Source of truth: `bench/results/verify/STUDY.md` and the CSVs it cites
(`roc-scores.csv`, `roc-curve-calibration.csv`, `heldout-far-frr.csv`,
`per-stratum-frr.csv`).

### Verification cost — the price of trust

Measured per clip (`bench/results/verify/verification-cost.csv`, `STUDY.md`): the
**fundamental** cost of verifying a segment is **one reference re-encode** — mean ≈ 1.2×
the worker's transcode, i.e. the verifier re-does essentially one transcode, as expected.
The frame-extraction term measured by the current example is inflated by **per-frame
ffmpeg process spawns** (`extract_y_frame` launches one ffmpeg per frame); a production
verifier decodes each sampled segment **once** in-process and reads all challenge frames
from that pass, collapsing the term toward the SSIM compute. We report the measured cost
and name the optimization rather than assume it.

**Implication (feeds Phase 4/6 sizing):** with extraction batched, trusted-verifier
capacity must be ≥ `p × worker_throughput`; at the `P_MIN = 0.02` floor that is ≈ 2% of
worker throughput. This is why verification is a *separate, sized* tier, not a tax on every
transcode.
