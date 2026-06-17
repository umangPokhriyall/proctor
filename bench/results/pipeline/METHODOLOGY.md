# Methodology — crypto / verification cost (`results/pipeline/`)

Scope: the §5 crypto-as-%-of-e2e, verification-cost, and verifier-capacity results. The
portfolio-wide methodology is consolidated in Session 5.

## Host

Intel i5-1135G7 (4 cores / 8 threads, 1 NUMA node); Linux 7.0.0; rustc 1.95 `--release`;
ffmpeg 8.0.1. Real `crypto` (AES-256-GCM AEAD, AES-NI; the no-disk memfd transcode path) and
real `verify` (batched-decode SSIM) — no Redis is involved in these measurements.

Corpus: `bench/corpus/detail.mp4` (the high-detail `mandelbrot` clip — real spatial detail so
the SSIM path does meaningful work). The whole clip is treated as one segment (as the Phase 5
smoke does); GOP-aligned sub-segmentation does not change the per-segment cost ratios.

## What is measured

- **`crypto_pct.csv`** — per segment, `decrypt_into_memfd` + `aead::encrypt` (the crypto)
  timed against `transcode_no_disk` (the bulk), across `C = 1/2/4/8` concurrent transcode
  pipelines (one thread each, 30 segments per thread). `crypto% = crypto / (crypto +
  transcode)`. The crypto is the real no-disk AEAD; plaintext lives only in memfds.
- **`verification_cost.csv`** — one `transcode_no_disk` baseline against one
  `verify_segment` (bind → reference transcode → **one batched** ffmpeg decode of all sampled
  frames per memfd → SSIM), 40 samples, ROC threshold loaded from the committed
  `results/verify/roc-threshold.json` at the calibration geometry (160×120, 4 frames). The
  ratio is `verify_p50 / transcode_p50`. All 40 verdicts are `Ok`, confirming the timed path
  is the full SSIM path, not an early binding reject.
- **`verifier_capacity.csv`** — *derived* from the measured verify ratio and the published
  `P_MIN = 0.02` floor (no separate run): verifier utilization at the floor
  `= P_MIN · ratio · N / M` and the saturating sample rate `= M / (ratio · N)`. Worker and
  verifier are assumed equal per-core throughput (the same `transcode_no_disk` core on one
  host).

## Honest divergence

The verification cost measured **≈1.66×**, above the predicted ≈1.20× — stated plainly in
`SUMMARY.md`. The gap is the two batched-decode ffmpeg passes' fixed process-startup cost as a
share of a fast (~270 ms) short-clip transcode; the headline result (far below the Phase-3
~10× per-frame-spawn artifact) holds. The verifier-capacity figures use the measured 1.66×,
so the per-worker floor utilization is 3.3% (the spec's 2.4% assumed ratio 1.2).

## Regenerate

```sh
cargo run -p bench --release -- pipeline --clip detail.mp4
```

Absolute ms depend on the host's ffmpeg + CPU; the **ratios** (crypto sub-percent;
verification ≈1.66× a transcode, ≪ 10×; verifier covers ≈30 workers at the floor) are the
reproducible results.
