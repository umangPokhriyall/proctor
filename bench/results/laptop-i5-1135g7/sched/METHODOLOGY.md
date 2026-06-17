# Methodology — scheduling-overhead decomposition (`bench/results/sched/`)

Scope: the §4 dispatch decomposition only. The portfolio-wide `METHODOLOGY.md` (host, all
versions, corpus hash, regen commands for every result set) is consolidated in Session 5;
this file records what these four CSVs + `SUMMARY.md` were produced from, so the numbers are
reproducible in isolation.

## Host

| | |
|---|---|
| CPU | 11th Gen Intel Core i5-1135G7 @ 2.40GHz |
| Topology | 1 socket, 4 physical cores, 2 threads/core → 8 logical CPUs, **1 NUMA node** |
| Redis | `redis-server v8.8.0` (built from source, `MALLOC=libc`), loopback `127.0.0.1:6390` |
| rustc | 1.95.0, `--release` (optimized) |
| OS | Linux 7.0.0 |
| Repo commit | `4cf13ef` (Session 1 head; the `sched` real-dispatch path under measurement) |

No system Redis was present, so a Redis was built from source on the host and run on
loopback with persistence disabled (`--save '' --appendonly no`). Single host is the
documented caveat (locked decision #5): geography is orthogonal to dispatch overhead, which
is what is decomposed here.

## What is measured, and the honest framing of N

The measurement drives the **real** `sched::engine::Engine::dispatch_one_live` — the exact
code path the `sched` binary runs for live Redis dispatch — over the loopback Redis. To
isolate **scheduler dispatch overhead** (not worker compute, which is Session 3's pipeline
measurement), the harness plays the worker role itself: after each placement it `submit`s +
accepts the task to free the in-flight slot. So a "dispatch" here is exactly
`pop_ready → select_worker → lease → load → LPUSH(assignment)`.

**`N` is the number of _registered_ workers** (placement candidates the scan reads), driven
by a single in-process dispatcher — **not** N pinned worker processes. This is deliberate:
the figure of interest is how the scheduler's per-dispatch cost scales with the candidate
set, which is the `2N` per-candidate `worker_load` (EXISTS + HMGET) round trips. The full
multi-process, `taskset`-pinned cluster (`bench/src/orchestrate.rs`) is the path the §5/§6
sessions exercise; here it would only add worker-compute noise to a scheduler-overhead
number. (With 4 physical cores, pinning 64 worker processes would oversubscribe anyway; the
in-process driver measures the scheduler cleanly regardless.)

## Coordinated-omission correction

`dispatch_latency.csv` (`dispatch_co_n*`) is recorded **CO-correct**: an open-loop schedule
fixes each task's intended-issue instant at `t0 + i/λ` independent of progress; latency is
measured from that **intended** instant (not the actual inject), and recorded with
`hdrhistogram`'s expected-interval back-fill at `1/λ`, so a stall back-fills the omitted
samples and cannot hide the tail (the Rust-Tcp-Server discipline). The paced runs use
`λ = 0.5 × measured placement ceiling` for that N, so the tail is steady-state, not
saturated. `dispatch_pure_n*` and `throughput_vs_n.csv` are the *unqueued* per-dispatch wall
time and the unpaced placement ceiling respectively (no CO correction — there is no arrival
schedule to omit against).

Distributions are reported p50/p99/p99.9, never an average alone.

## Files

- `rtt.csv` — loopback Redis RTT: `PING` (pure round trip) and `LPUSH` (the op a dispatch
  ends on), 30 000 samples each after warmup.
- `decision_time.csv` — in-process `place::select_worker` (no Redis) at N = 1/4/16/64,
  100 000 samples each.
- `throughput_vs_n.csv` — unpaced placement ceiling (tasks/s) at N = 1/4/16/64, with the
  per-dispatch p50/p99 and the `2N + 4` round-trip count.
- `dispatch_latency.csv` — CO-correct dispatch latency (`*_co_*`) and unqueued per-dispatch
  time (`*_pure_*`) at N = 1/4/16/64, at half the measured ceiling.
- `SUMMARY.md` — the predicted-then-confirmed writeup (auto-generated from the run).

## Regenerate

```sh
# 1. a loopback Redis (any reachable instance works; this run used a source build on :6390)
redis-server --port 6390 --save '' --appendonly no --daemonize yes --dir /tmp

# 2. the decomposition (writes the CSVs + SUMMARY.md into this directory)
cargo run -p bench --release -- sched-decomp --redis-url redis://127.0.0.1:6390
```

Absolute latencies depend on the host's loopback RTT; the **decomposition** (Redis ≈ 100% of
dispatch; per-dispatch cost = `(2N + 4)` round trips; decision time µs-scale and flat) is the
reproducible result. A number nobody can reproduce is not a number.
