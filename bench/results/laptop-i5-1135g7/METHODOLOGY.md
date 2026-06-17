# METHODOLOGY — proctor Phase 6 measurement (laptop dev baseline)

> **Platform: `laptop-i5-1135g7` — the honest dev baseline (phase7-spec.md §3).** This is the
> Phase 6 result set, measured on a 4c/8t / 8 GB laptop. The hardware-**independent**
> correctness/security/crypto numbers stand as-is; the hardware-**confounded**
> scaling/throughput numbers (N above ≈8 is oversubscription on 8 threads, not scheduler
> capacity) are superseded by the Phase 7 bare-metal re-run under `results/metal-<instance>/`.
> Preserved deliberately, not deleted — see `results/README.md`.

Every number in `BENCHMARKS.md`, `PROFILING.md`, and the per-result-set writeups comes from a
committed CSV in this tree, produced by the `bench` harness against a **real** Redis and a
**real** ffmpeg on the host below. No number is fabricated; where a tool was absent the harness
loud-skips and marks results pending. Each result directory also carries its own
`METHODOLOGY.md` with the specifics; this file is the shared baseline.

## Host

| Field | Value |
|---|---|
| CPU | 11th Gen Intel Core i5-1135G7 @ 2.40 GHz (max 4.20 GHz) |
| Topology | 1 socket · 4 physical cores · 2 threads/core = 8 logical CPUs · **1 NUMA node** |
| Caches | L1d 192 KiB (4×48) · L1i 128 KiB · L2 5 MiB (4×1.25) · L3 8 MiB (shared) |
| Crypto ISA | AES-NI present (`aes`, `vaes`, `pclmulqdq`, `sha_ni` in `/proc/cpuinfo`) |
| OS | Linux 7.0.0 |
| Redis | `redis-server v8.8.0` (built from source, `MALLOC=libc`), loopback `127.0.0.1:6390`, persistence off (`--save '' --appendonly no`) |
| ffmpeg | `ffmpeg version 8.0.1-3ubuntu2` |
| rustc | 1.95.0, all measurement runs `--release` (optimized) |
| perf | `perf_event_paranoid = -1` (full counter access) |

Single host is the documented caveat (locked decision #5): geography is orthogonal to the
properties measured here — placement overhead, crypto/verification cost, backpressure, fencing
safety, and detection. No system Redis was present, so a Redis was built from source on the
host and run on loopback.

## Corpus

The deterministic synthetic corpus (`bench/corpus/`, regenerable byte-for-byte from
`generate.sh` via ffmpeg `lavfi` — copyright-clean, no external media):

| File | SHA-256 | lavfi source |
|---|---|---|
| `gradient.mp4` | `b050f75c59d68909c1456cb2c00ce221175f5c79e0fe628aea2b1cd1e26ed7a3` | `testsrc2` (smooth) |
| `detail.mp4` | `d01460e5ca629a2a02a51f5c451dee26bcad691b938e8a40171ca2f703c2ae97` | `mandelbrot` (high-detail) |
| `motion.mp4` | `a3806b4a6889faf83af528bbaa0b2a8946be8a3d9fb83751b57a4e5c9d415437` | `testsrc2`+rotate+noise (high-motion) |

The Phase-3 ROC study's combined corpus address (file-name-prefixed concatenation) is
`corpus_sha256 = 4737e508ed19452cd746cd3e8e2dc3f9384d14fa42fbb8f21499b2ad7277d152`
(`results/verify/roc-threshold.json`), and the committed comparison threshold is **0.9328** at
the 160×120 plane.

## Coordinated-omission correction

Latency under load is recorded **CO-correct**: the open-loop injector fixes each task's
intended-issue instant at `t0 + i/λ` independent of system progress; latency is measured from
that **intended** instant (not the actual issue), and recorded with `hdrhistogram`'s
expected-interval back-fill at `1/λ`, so a stall back-fills the omitted samples and cannot hide
the tail (the Rust-Tcp-Server discipline). Distributions are reported p50/p99/p99.9, never an
average alone. Micro-benchmarks with no arrival schedule (RTT, the in-process decision, the
unpaced throughput ceiling) are recorded without CO correction — there is nothing to omit
against — and labelled as such.

## What each result set measures, and how to regenerate

All commands assume a loopback Redis is up:
```sh
redis-server --port 6390 --save '' --appendonly no --daemonize yes --dir /tmp
```

| Directory | Content | Regenerate |
|---|---|---|
| `sched/` | dispatch decomposition: RTT, in-process decision, CO-correct dispatch latency, throughput vs N; `perf-placement.txt` | `cargo run -p bench --release -- sched-decomp --redis-url redis://127.0.0.1:6390` |
| `saturation/` | ≈10× overload (bounded resident work, shed, flat memory, Little's law) + fault-injection reclaim latency | `cargo run -p bench --release -- saturation --redis-url redis://127.0.0.1:6390` |
| `pipeline/` | crypto-as-%-of-e2e, batched-decode verification cost, verifier-capacity envelope | `cargo run -p bench --release -- pipeline --clip detail.mp4` |
| `adversary/` | slow-zombie chaos at scale, per-class detection + CIs vs predicted, adaptive escalation | `cargo run -p bench --release -- adversary --redis-url redis://127.0.0.1:6390` |
| `crypto/`, `../verify/` | Phase-2/3 standalone studies (AEAD throughput, no-disk audit, ROC; `verify/` is platform-independent calibration, kept at `results/verify/`) | `cargo run -p crypto --release --example ...` / `cargo run -p verify --release --example verify_eval` |
| `sched/perf-placement.txt` | `perf stat` on the placement loop | `perf stat -d ./target/release/bench profile-placement --n N --iters K` |

## Honesty boundaries (carried into the writeups)

- The sched dispatch decomposition and the saturation run drive the **real** `dispatch_one_live`
  path over a real Redis; for those they model worker compute (the in-process driver plays the
  worker, or an aggregate service rate `W = 0.099 s`) so the run isolates **scheduler** behaviour
  and stays fast. The full multi-process `taskset`-pinned cluster (`bench/src/orchestrate.rs`)
  exists and is the path a geography/latency study would use; it is not the vehicle for a
  scheduler-overhead number. Stated, not hidden.
- The adversary per-segment verdicts are real ffmpeg + the real `verify::verify_segment`; the
  end-to-end detection Monte-Carlo simulates only the sampling combinatorics (exactly what the
  hypergeometric models). Small synthetic corpus ⇒ wide confidence intervals, reported.
- Absolute latencies depend on the host's loopback RTT and ffmpeg/CPU; the **decompositions and
  ratios** (Redis ≈ 100% of dispatch; verification ≈1.66× a transcode; crypto sub-percent;
  verifier ≈30 workers at the floor; zero double-outputs) are the reproducible results.
