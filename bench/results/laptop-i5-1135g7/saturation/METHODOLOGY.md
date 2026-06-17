# Methodology — saturation / backpressure + reclaim (`results/saturation/`)

## Host
Intel i5-1135G7 (4 cores / 8 threads, 1 NUMA node); Linux 7.0.0; redis-server v8.8.0 (source build, loopback `:6390`); rustc 1.95 `--release`.

## Overload run
The **real** epoch-fenced `RedisStore` + `dispatch_one_live` path, single-threaded and time-stepped. Completions accrue at the aggregate service rate `μ = N/W` with `W = 0.099s` (the Phase-2-measured `transcode_no_disk` wall time, `MEASURED_SERVICE_TIME_S`) — worker compute is *modelled* so the run is fast and `W`-controlled; the ready-queue, the `Sizing::admit` gate, the `Backpressure` shed, the per-worker in-flight cap, and the dispatch are all **real Redis**. The injector is open-loop at `λ = overload·μ`, gating each offer on the live `ZCARD` of the ready queue. The backpressure property (bounded resident work, intake shed, flat memory) is a function of the cap vs offered load, independent of whether `W` is real ffmpeg.

## Reclaim run
Lease a task, the holder "dies" (no submit/heartbeat), then time `reclaim_expired` (re-enqueue) → `dispatch_one_live` (re-lease) over real Redis, asserting the fencing epoch strictly advances. The measured distribution is the *mechanism* cost; total reclaim latency adds `lease_ttl` (the detection delay).

## Regenerate
```sh
redis-server --port 6390 --save '' --appendonly no --daemonize yes --dir /tmp
cargo run -p bench --release -- saturation --redis-url redis://127.0.0.1:6390
```
