# BENCHMARKS — proctor, the committed numbers (laptop dev baseline)

> **Platform `laptop-i5-1135g7` — the honest dev baseline (phase7-spec.md §3).** Scaling and
> throughput vs N above ≈8 reflect 8-thread oversubscription, not scheduler capacity; those are
> superseded by the bare-metal re-run (`results/metal-<instance>/`). The
> correctness/security/crypto numbers here are hardware-independent and stand. See
> `results/README.md` and (once it lands) `results/PLATFORM-RECONCILIATION.md`.

proctor is a zero-trust control plane for verifiable, confidential transcoding on untrusted
workers: probabilistic re-execution verification, in-memory shard-scoped crypto, and a
backpressure-aware, epoch-fenced scheduler. This file records the measured properties of that
control plane. Every figure cites its source CSV in this tree; conditions (host, versions,
corpus, CO-correction) are in `METHODOLOGY.md`. Numbers are from a real loopback Redis
(`v8.8.0`) and real ffmpeg (`8.0.1`) on a 4-core Intel i5-1135G7, `--release`. Distributions are
p50/p99/p99.9, not averages; honest negatives are stated where they exist.

## 1. Scheduling overhead — predicted-then-confirmed

| Quantity | Value | Source |
|---|---|---|
| Loopback Redis RTT (PING), p50 | 10.87 µs (p99 14.6 µs) | `sched/rtt.csv` |
| In-process placement decision, p50 | 0.047 µs (N=1) → 1.328 µs (N=64) | `sched/decision_time.csv`, `PROFILING.md` |
| Pure dispatch (`dispatch_one_live`), p50 | 94.8 µs (N=1) → 1663 µs (N=64) | `sched/throughput_vs_n.csv` |
| Dispatch latency, CO-correct, p50/p99/p99.9 | 192 / 338 / 479 µs (N=1); 1792 / 2193 / 2763 µs (N=64) | `sched/dispatch_latency.csv` |
| Placement throughput | 5 451 → 3 804 → 1 786 → 557 tasks/s for N = 1 / 4 / 16 / 64 | `sched/throughput_vs_n.csv` |

Phase 4 pre-committed "dispatch is ~95% Redis RTTs." **Confirmed and exceeded:** the in-process
decision is 0.047 µs against 94.8 µs of dispatch, so Redis is **99.95%** of dispatch latency
(`sched/SUMMARY.md`). The pre-committed RTT *count* of 2 was an **undercount** (stated plainly):
the live path issues **2N + 4** round trips per dispatch (`pop_ready` + `select_worker`'s
per-candidate `worker_load` + `lease` + `load` + `LPUSH`), so per-dispatch cost is the round
trips and grows with N via the `2N` placement reads — decision time stays flat per dispatch
(`PROFILING.md`: O(N) but ~93 cycles/candidate, ~1000× cheaper than the round trip it replaces).
Remedy named: fold the placement reads + lease + push into one server-side Lua.

## 2. Reclaim latency (fault injection)

| Quantity | Value | Source |
|---|---|---|
| Reclaim mechanism (reclaim + re-dispatch), p50 / p99 | 158 / 223 µs | `saturation/reclaim_latency.csv` |
| Fencing-epoch advance on reclaim | 300 / 300 | `saturation/reclaim_latency.csv` |

A worker dies mid-task; `reclaim_expired` re-enqueues and `dispatch_one_live` re-leases. The
measured figure is the mechanism cost; total production reclaim latency adds `lease_ttl` (the
liveness-timeout detection delay, a deliberate config). The fencing epoch advanced on every
reclaim — a timeout is a liveness heuristic; the epoch CAS is the safety mechanism.

## 3. Crypto and verification cost in the live pipeline

| Quantity | Value | Source |
|---|---|---|
| Crypto (decrypt+encrypt) as % of segment latency, p50 | 0.38 – 0.66% across 1–8× concurrency | `pipeline/crypto_pct.csv` |
| AEAD throughput (standalone, AES-NI) | 1.55 GB/s encrypt, 0.99 GB/s decrypt | `crypto/aead_throughput.csv`, `PROFILING.md` |
| Verification cost vs one transcode | **1.66×** (verify p50 449 ms, transcode 271 ms; 40/40 Ok) | `pipeline/verification_cost.csv` |
| Verifier utilization at `P_MIN` floor | 3.3% of worker compute per worker → ≈30 workers per verifier | `pipeline/verifier_capacity.csv` |

AES-256-GCM is AES-NI-accelerated and is a sub-percent slice of segment latency under
concurrency — the transcode is the cost; the confidentiality is nearly free. **Honest negative:**
verification measured 1.66× a transcode, **above** the predicted ≈1.20× (the two batched-decode
ffmpeg passes' process-startup cost on short clips); it remains far below the Phase-3 ~10×
per-frame-spawn artifact, which the batched extractor removed. At the floor one verifier keeps
pace with ≈30 workers; at N=64 a single verifier is over-subscribed (212%, flagged in
`pipeline/SUMMARY.md`) and the pool must grow.

## 4. Backpressure under ≈10× overload

| Quantity | Value | Source |
|---|---|---|
| Offered vs capacity | 404 /s offered vs 40 /s capacity (≈10×) | `saturation/overload_timeseries.csv` |
| Intake shed | 89.6% (`Backpressure::QueueFull`) | `saturation/SUMMARY.md` |
| Resident work | ready-queue pinned at the global cap 16 (4N); in-flight at 8 (2N) | `saturation/overload_timeseries.csv` |
| Memory under sustained overload | RSS 4036 → 4072 KiB (+0.9%) — flat | `saturation/overload_timeseries.csv` |
| Achieved vs Little's law | admitted 42 /s ≈ capacity 40 /s; `L = λW = 4.2 ≈ N = 4` | `saturation/SUMMARY.md` |

Resident work is `O(N)`, independent of offered load: over-cap arrivals are shed at admission,
not buffered, so memory stays flat. The per-worker in-flight cap (2) and global queue cap (4N)
are the Little's-law sizing.

## 5. Fencing safety and cheating-worker detection

| Quantity | Value | Source |
|---|---|---|
| Slow-zombie chaos at scale | 1000 tasks → **0 double-outputs**; 1000/1000 zombie submits rejected; 1000/1000 epoch advances | `adversary/slow_zombie_chaos.csv` |
| byte-swap FAR (95% CI) | 0% [0, 33.6%] — caught deterministically at binding | `adversary/per_class_far.csv` |
| wrong-bitrate / frame-substitution / garbage FAR | 0% [0, 33.6%] each | `adversary/per_class_far.csv` |
| honest FRR | 0% [0, 33.6%] | `adversary/per_class_far.csv` |
| cheap-downscale FAR (hardest class) | 66.7% [29.9%, 92.5%] | `adversary/per_class_far.csv` |
| End-to-end detection vs predicted | tracks `hypergeometric × (1 − FAR)` within 95% CIs | `adversary/detection_vs_predicted.csv` |
| Adaptive escalation | Pristine → Banned at job 15 (p: 0.02 → 0.10 → 0.25); floor catches f = 1/16 | `adversary/escalation_cheap_downscale.csv` |

Fencing holds safety under concurrency at scale: across 1000 tasks the slow-zombie's stale-epoch
submit is rejected by the store CAS every time — exactly one output per segment. byte-swap is
caught deterministically at binding (`CommitmentMismatch`, one-step Ban). Measured detection
tracks the committed hypergeometric × (1 − FAR) prediction within confidence intervals. **The
elite line, stated:** cheap-downscale is the hardest class (FAR 66.7% here, ≈21% in the Phase-3
study — geometry/segment-length dependent), so its effective detection sits materially below the
raw hypergeometric; the remedy is a FAR-constrained threshold or a higher comparison geometry,
backed by `../verify/roc-curve-calibration.csv`. The full per-class treatment with CIs and the
accepted tier information-leak is `adversary/ADVERSARY.md`.

## Honest negatives, collected

1. **Dispatch is 2N + 4 Redis round trips, not the pre-committed 2** (§1). The qualitative claim
   — dispatch is Redis-bound, ~99.95% — holds and is exceeded; the constant was optimistic.
2. **Verification is 1.66× a transcode, not the predicted ≈1.20×** (§3) — short-clip ffmpeg
   startup; the batching win over the ~10× per-frame-spawn artifact holds.
3. **cheap-downscale is genuinely hard to catch** (§5): a low-resolution re-encode stays near the
   honest SSIM range at a 160×120 plane; the asymmetric reputation policy and a FAR-constrained
   threshold are the answers, not a claim of perfect fidelity detection.

Public framing: this is a systems artifact — a measured distributed-scheduler + verification
control plane, reported with units, conditions, distributions, and the negatives intact.
