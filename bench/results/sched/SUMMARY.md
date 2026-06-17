# Scheduling-overhead decomposition — predicted-then-confirmed

Source CSVs (this directory): `rtt.csv`, `decision_time.csv`, `throughput_vs_n.csv`, `dispatch_latency.csv`. Methodology + host/versions in `METHODOLOGY.md`. Latencies in microseconds.

## The Phase 4 prediction (pre-committed, `sched::backpressure`)
`DISPATCH_REDIS_RTTS = 2` (lease Lua + inbox LPUSH); "decision ≈ µs; p99 dispatch ≈ count × RTT and is ~95% Redis RTTs."

## Measured (this host, loopback Redis)
- Redis RTT: PING p50 10.9µs / p99 14.6µs; LPUSH p50 11.3µs (`rtt.csv`).
- In-process decision (`place::select_worker`, no Redis): p50 0.047µs at N=1 (`decision_time.csv`).
- Pure dispatch (`dispatch_one_live`) at N=1: p50 94.8µs (`throughput_vs_n.csv`).

## The confirmation, and the honest divergence
The qualitative prediction **holds, and then some**: dispatch is Redis-dominated — the in-process decision is 0.047µs against 94.8µs of dispatch, so Redis is **99.95%** of dispatch latency (the prediction said ~95%).

The **RTT-count constant was an undercount**, and we say so. The predicted `2` counted only lease + LPUSH; the live `dispatch_one_live` path actually issues `2N + 4` round trips — pop_ready (1) + `select_worker` (EXISTS+HMGET = 2 per candidate) + lease (1) + load (1) + LPUSH (1). At N=1 that is 6 RTTs, so the predicted `2 × RTT = 21.7µs` understates the measured 94.8µs. The implied per-round-trip cost 15.8µs is of the order of — and a little above — the bare PING RTT 10.9µs / LPUSH 11.3µs, because the dispatch round trips include heavier ops (an EVALSHA lease script, an HGETALL load, the HMGET worker reads) than a bare PING. So the dispatch time **is** the round trips, exactly as predicted in spirit; only the count was optimistic.

**Remedy (named, not built here):** fold placement reads + lease + push into a single server-side Lua so a dispatch is ~2–3 RTTs regardless of N — the per-candidate `worker_load` reads are the `2N` term and the only part that scales with N.

## Throughput vs N (placement ceiling)
| N | achieved tasks/s | RTT count | decision p50 (µs) |
|---|---|---|---|
| 1 | 5451 | 6 | 0.047 |
| 4 | 3803 | 12 | 0.103 |
| 16 | 1786 | 36 | 0.348 |
| 64 | 557 | 132 | 1.328 |

The in-process decision stays µs-scale and flat-ish per dispatch; the placement ceiling falls as N grows because the `2N` per-candidate `worker_load` round trips are the scaling variable — Redis contention, not decision cost, exactly as predicted. The knee is wherever achieved tasks/s can no longer keep pace with offered load.
