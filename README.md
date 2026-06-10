# proctor

A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers, built as three measured systems primitives. The transcoding is the vehicle;
the primitives are the deliverable.

## Status

Under construction. Primitives and benchmarks land per `docs/specs/`. There are no
performance claims in this repository until `bench/results/` exists.

## The three primitives

- **Probabilistic verification** — a trusted verifier re-executes a random subset of a
  worker's segments and compares with SSIM against a calibrated ROC threshold.
- **In-memory shard-scoped AES-256-GCM** — per-segment keys delivered over TLS, held
  `mlock`'d and zeroized; plaintext and keys never touch disk.
- **Backpressure-aware scheduler** — Redis-lease least-loaded push dispatch, a single
  lease-expiry reclaim authority, explicit saturation backpressure, and a reputation gate.

## The honest boundary

Confidentiality here is bounded, not absolute: a root-capable worker can read the
ffmpeg process memory and defeat it. That gap is what the microVM flagship exists to
close, not this repo. See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Repository map

| Crate | Kind | Owns |
|---|---|---|
| `core` | lib | sans-IO protocol, task/lease/segment state machine, commit-reveal types (frozen after Phase 1) |
| `crypto` | lib | in-memory AES-256-GCM, per-segment key lifecycle, ffmpeg pipe/`memfd` plumbing |
| `verify` | lib | SSIM comparison, ROC threshold calibration, detection-probability math, commit-reveal verification |
| `sched` | bin | placement, leases, heartbeats, single reclaim, backpressure, reputation gate |
| `verifier` | bin | re-executes ffmpeg on sampled segments; calls `verify` |
| `worker` | bin | the untrusted hot loop (`core` + `crypto`); receives pushes, never self-selects |
| `bench` | bin | injects workloads directly (no ingest API); single-host run, corpus, adversary simulator, metrics |

## Product origin

The systems substrate was extracted from the original TypeScript transcoding product,
red-teamed, and rebuilt in Rust. The product is frozen at `Stream-hive@v1.0-product`.

## Build

```sh
cargo build
```

No run instructions until the harness (`bench`) exists.
