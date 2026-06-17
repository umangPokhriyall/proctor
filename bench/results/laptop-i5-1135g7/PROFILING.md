# PROFILING — the placement loop, and the AES-NI confirmation

`perf stat` on the scheduler's placement decision, interpreted — not a raw dump. Source:
`sched/perf-placement.txt` (the raw counters), `crypto/aead_throughput.csv` (the AEAD
throughput). Host and method in `METHODOLOGY.md`.

## The placement loop (`place::select_worker`)

The decision the dispatch loop makes per task: pick the least-loaded eligible worker — a
min-scan over the candidate set, reading each candidate's load and reputation tier. Profiled in
isolation (in-memory store, no Redis) over 20 M iterations at N = 1 / 16 / 64 candidates.

| N | cycles/call | insns/call | IPC | time/call | branch-miss | L1d-miss rate |
|---|---|---|---|---|---|---|
| 1 | 116 | 453 | 3.90 | 29 ns | 0.005% | ~0.0003% |
| 16 | 1 502 | 4 873 | 3.24 | 364 ns | 0.34% | ~0.04% |
| 64 | 5 957 | 19 389 | 3.26 | 1 523 ns | 0.13% | ~0.03% |

(Cycles/call = cpu-cycles ÷ iterations; the rest likewise, from `sched/perf-placement.txt`.)

**Interpretation.**

- **It is a near-ideal tight loop.** IPC sits at **3.2–3.9** against the core's 4-wide
  retirement ceiling; the L1d miss rate is **≈0%** (the candidate set and the worker table are
  L1/L2-resident); branch mispredicts are **under 0.35%**. There is no cache or
  branch-prediction problem to solve here — the decision runs at the hardware's efficiency
  limit.
- **It is `O(N)`, ~93 cycles per candidate.** The marginal cost of one more worker is
  `(5 957 − 116) / 63 ≈ 93` cycles (a worker-load lookup, a `WorkerView` build, one comparator
  step). At 4 GHz that is 29 ns at N=1, 364 ns at N=16, 1.52 µs at N=64 — matching the
  independently recorded `sched/decision_time.csv` (0.348 µs at N=16, 1.328 µs at N=64; the CSV
  additionally pays the histogram record, the raw loop here does not).
- **This is why dispatch is Redis-bound, confirmed from the other side.** A single live dispatch
  issues `2N + 4` Redis round trips (`sched/SUMMARY.md`), each ≈11–16 µs of loopback
  network+server time. The decision is 0.03–1.5 µs. So the in-process decision is **0.03–0.1% of
  dispatch latency, and Redis is ≈99.95%** (`sched/SUMMARY.md`) — `perf` confirms the decision
  has no headroom worth optimizing; the systems lever is the round-trip count, not the decision
  code.
- **The O(N) growth is dominated by the network, not the CPU.** Each added worker costs ~93
  cycles (~23 ns) of decision CPU but two extra `worker_load` round trips (~22 µs) on the live
  path — the network cost per added candidate is ~1000× the CPU cost. The remedy named in
  `sched/SUMMARY.md` (fold placement reads + lease + push into one server-side Lua) attacks the
  round trips; the decision code is already efficient.

## AES-NI re-confirmation

The crypto path is AES-256-GCM with runtime ISA detection. Three independent confirmations that
the **hardware** path is the one running:

1. **The ISA is present.** `/proc/cpuinfo` carries `aes` (AES-NI), `vaes` (vector AES),
   `pclmulqdq` (the carry-less multiply GCM needs), and `sha_ni`.
2. **The backend self-reports hardware, and the throughput proves it.**
   `crypto/aead_throughput.csv` records `backend = aesni-runtime-detected` and an aggregate
   **1.55 GB/s encrypt / 0.99 GB/s decrypt** over the 1.6 GB corpus. A software AES-GCM on a
   core of this class runs ~150–300 MB/s; 1.55 GB/s is ~5–10× that, reachable only on the
   AES-NI + PCLMULQDQ path. The `aes-gcm` crate's CPUID probe selected it.
3. **It is negligible in the live pipeline.** `pipeline/crypto_pct.csv`: decrypt + encrypt is
   **0.38–0.66% (p50)** of end-to-end segment latency under 1–8× concurrency — the AEAD is
   dwarfed by the ffmpeg transcode (the no-disk memfd path adds no copy). The transcode is the
   cost; with AES-NI, the confidentiality is nearly free.

(The decrypt path is slower than encrypt — 0.99 vs 1.55 GB/s — because GCM authentication is
serialized on the tag check before plaintext is released; this is the expected GCM asymmetry,
not a missing-ISA artifact, and is documented in `crypto/METHODOLOGY.md`.)
