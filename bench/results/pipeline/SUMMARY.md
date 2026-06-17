# Crypto / verification cost in the live pipeline

Real `crypto` (no-disk AEAD + transcode) and `verify` (batched-decode SSIM) over real ffmpeg on `corpus/detail.mp4`. Source CSVs: `crypto_pct.csv`, `verification_cost.csv`, `verifier_capacity.csv`.

## Crypto as % of end-to-end (under concurrency)

| concurrency | crypto% p50 | crypto% p99 |
|---|---|---|
| 1 | 0.6575% | 0.7447% |
| 2 | 0.6159% | 0.9319% |
| 4 | 0.3759% | 1.1207% |
| 8 | 0.4243% | 1.2423% |

Crypto stays a **sub-percent** slice of segment latency even under concurrent transcodes — consistent with the Phase-2 standalone 0.10–1.03% baseline; the AES-NI AEAD is dwarfed by the ffmpeg transcode (the no-disk path adds no copy). The transcode is the cost; the confidentiality is nearly free.

## Verification cost (batched decode) — predicted-then-confirmed, honest divergence

Per-sampled-segment verification (bind → reference transcode → **batched** ffmpeg decode of all sampled frames → SSIM) measured **1.66× one transcode** (verify p50 449.3ms vs transcode p50 271.3ms; 40/40 verdicts `Ok`, so the timed path is the full SSIM path, not an early binding reject).

**This is above the predicted ≈1.20×, and we say so.** Verification is one reference transcode (≈1.0×) plus the comparison overhead; the prediction assumed that overhead ≈0.2× a transcode, but here it measured ≈0.66× — the comparison does **two** batched ffmpeg decode passes (one per memfd: the worker output and the freshly re-transcoded reference), and on these short 320×240 clips the fixed ffmpeg process-startup cost of those passes is a larger share of a (fast, ~270ms) transcode than the 1.20× model assumed. The headline result still **holds**: 1.66× is far below the Phase-3 ~10× per-frame-spawn artifact (one ffmpeg process *per frame*) — the batched extractor (`extract_y_frames`, one pass per memfd) is what closed that ~6× gap. The remaining path to ≈1.2× is fewer/cheaper decode passes (e.g. decode straight from the encode), named not built.

## Verifier-capacity utilization at the `P_MIN` floor

At the floor `p = P_MIN = 0.02`, one verifier-equivalent of compute covers **3.3% per worker** (`P_MIN · ratio = 0.02 · 1.66`) — i.e. a single trusted verifier keeps pace with ≈**30 workers** at the floor before it saturates. (The spec's ≈2.4% figure assumed ratio 1.2; at the measured 1.66× it is 3.3% per worker.)

| N workers | M verifiers | verifier util at floor | saturating sample rate p |
|---|---|---|---|
| 1 | 1 | 3.3% | 0.604 |
| 4 | 1 | 13.2% | 0.151 |
| 16 | 1 | 53.0% | 0.038 |
| 64 | 1 | 212.0% ⚠ bottleneck | 0.009 |

Utilization scales with `N/M`: at the floor one verifier is **not** a bottleneck up to ≈30 workers, but at N=64 with a single verifier it is over-subscribed (212%) and the pool must grow to `M ≥ ⌈ratio·P_MIN·N⌉`. The saturating sample rate `p = M/(ratio·N)` is the headroom above the floor before the verifier pool must grow. (Single host, equal per-core transcode throughput for worker and verifier — the same `transcode_no_disk` core.)
