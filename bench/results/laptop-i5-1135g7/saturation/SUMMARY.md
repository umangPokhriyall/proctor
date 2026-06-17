# Saturation / backpressure + reclaim latency

Source CSVs: `overload_timeseries.csv`, `reclaim_latency.csv`. Host/method in `METHODOLOGY.md`.

## ≈10× overload (N=4 workers, W=0.099s modelled service time)

- **Offered 404/s vs capacity 40/s** → the injector pushes ~10.0× aggregate worker capacity (`λ = overload · N/W`).
- **Intake shed 89.6%** of offers (5432 of 6061) with the `Backpressure::QueueFull` error — the over-cap arrivals are dropped at admission, not buffered.
- **Bounded resident work:** ready-queue depth peaked at 16 against the global cap 16 (`4N`); in-flight peaked at 8 against the per-worker cap × N = 8. Resident work is `O(N)`, independent of the offered load.
- **Flat memory:** RSS 4036→4072 KiB over the run (+0.9%) — sustained overload does not grow memory, because the queue cannot grow past its cap.
- **Achieved (admitted) 42/s ≈ capacity 40/s** while offered was 404/s — the system runs at ρ≈1 and sheds the rest.
- **Little's law (`L = λ·W`):** admitted 42/s × W 0.099s = **4.2** in service ≈ N = 4 (steady-state mean in-flight 8.0). The per-worker in-flight cap (2) and global cap (4N) are the Little's-law sizing that bounds resident work.

## Reclaim latency (fault injection)

Worker dies mid-task → `reclaim_expired` re-enqueues → `dispatch_one_live` re-leases. The **fencing epoch advanced on 300/300 reclaims** (a strictly greater epoch every time — the zombie's stale write can never match). Mechanism latency (reclaim sweep + re-dispatch, the round trips): p50 **158.1µs**, p99 **223.1µs**, p99.9 524.8µs (`reclaim_latency.csv`).

The **total** production reclaim latency is `lease_ttl` (the liveness-timeout detection delay, a deliberate config) **plus** this mechanism cost; only the mechanism is a distribution worth measuring. A heartbeat timeout is a liveness heuristic — fencing is the safety mechanism (amendment §1.1), confirmed by the epoch advance above.
