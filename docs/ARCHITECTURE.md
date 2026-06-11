# proctor — Architecture

> **Status:** grows as phases land. This file records design decisions and the reasons
> behind them, declaratively, with every claim tied to code or a committed measurement.
> **Phase 3** added the verification design; **Phase 4** adds the scheduler design below
> (push dispatch, the fencing-token store, the adaptive policy, Little's-law sizing). The
> scheduler/bench *measurements* (dispatch-latency p99, saturation) follow in Phase 6.

## Verification (Phase 3)

The verifier earns the "verifiable compute" claim: it independently re-checks a random,
unpredictable subset of a worker's segments and compares the result structurally. Every
number it produces is owned and explainable; the threshold is a committed artifact, not a
constant.

### Verifier as a separate binary (locked decision #3)

Re-execution is CPU-bound and must never run inside the I/O-bound scheduler, so the
verifier is a **separate binary** (`verifier/`); the expected output never leaves that
process. `verify/` is a `#![forbid(unsafe_code)]` **library** that the binary consumes;
the only `unsafe` in the whole verification path is `crypto::sys` (the libc FFI for
`memfd`/`mlock`/the child fd hand-off). The verifier re-runs ffmpeg through
`crypto::ffmpeg_no_disk`, so all media — source plaintext, reference output, worker
output — lives only in anonymous RAM (`memfd`), never a disk-backed file (THREAT-MODEL §4).

### The per-segment algorithm (`compare.rs`)

For one segment, entirely in memfds:

1. **Bind** — re-derive the single-leaf commitment and require an exact match before any
   challenge frame is chosen (THREAT-MODEL §4, the commit-binding anti-swap chain). On
   mismatch the verdict is `VerifyDetail::CommitmentMismatch` and nothing is sampled.
2. **Reconstruct ground truth** — decrypt the source (`Role::Source`) into a memfd and
   independently `transcode_no_disk` it with the frozen `TargetProfile`: the verifier's
   reference output, in RAM.
3. **Compare** — decrypt the worker output (`Role::Output`); at seeded random timestamps
   extract Y-plane frames from both worker output and reference and compute SSIM. The
   segment score is the **minimum** MSSIM across the sampled frames — conservative, so a
   single substituted frame drags the score down even when the rest is faithful.
4. **Decide** — pass iff the score ≥ the threshold loaded from the committed ROC file;
   emit the frozen, categorical `VerifyDetail`. No numeric threshold ever crosses the API.

Every memfd is scrubbed and closed on every path.

### SSIM comparator — hand-rolled (`ssim.rs`)

Structural similarity on the **luma** plane only — structural fidelity lives in luminance,
and that is what discriminates a cheap-downscale or frame-substitution from an honest
re-encode. We hand-roll it (no SSIM crate) so every number is explainable:

- **Window:** 8×8 uniform (box) window, stride 4 (overlapping). A uniform window is the
  explainable choice over the classic 11×11 Gaussian — equal weights, plain mean/variance.
- **Constants:** `C1 = (0.01·255)² = 6.5025`, `C2 = (0.03·255)² = 58.5225` (8-bit range,
  the SSIM-paper defaults), with the unbiased (N−1) windowed variance.
- **MSSIM** is the mean of the per-window index; the **segment** score is the *min* MSSIM
  across sampled frames.

The decision threshold comes from `bench/results/verify/roc-threshold.json` via
`RocThreshold::load`, **never** a literal in code (locked decision #4).

### Detection-probability family — exact hypergeometric (`detection.rs`)

The verifier samples `k = ⌈p·n⌉` of a job's `n` segments **without replacement**; with
`m = ⌈f·n⌉` tampered, the exact probability of catching at least one is the
**hypergeometric** `P_detect = 1 − C(n−m, k)/C(n, k)`, computed as the integer-exact
product `∏ (n−m−i)/(n−i)` (no Gamma, no stats crate). It is published as a **family**
`P_detect(f, n; p_tier)` over representative reputation tiers with the hard floor
`P_MIN = 0.02` (so `k ≥ 1` for every worker; THREAT-MODEL §5, the accepted tier-inference
leak). The binomial `1 − (1−p)^⌈f·n⌉` is kept **only** for the divergence plot; the
hypergeometric is the published claim. The tier→`p` adaptive **policy** is Phase 4.

Honest correction (proven and committed): the divergence `binomial − hypergeometric` is
**≤ 0** everywhere on the grid — the binomial *under*-states detection, the opposite sign
from amendment §1.2.1's prose. The amendment's decision (publish the exact hypergeometric)
is unaffected. Source: `bench/results/verify/detection-family.csv`,
`detection-divergence.csv`, and `DETECTION.md` (the proof and the flag for the spec owner).

### The ROC study — calibration, held-out, intervals, strata (`roc.rs`, `verify_eval`)

The threshold must not be circular and no point estimate stands without an interval:

- The corpus is split into a **calibration** set (threshold selection only) and a
  **disjoint held-out** set (the reported rates); disjointness is asserted at runtime.
- The threshold is selected on calibration only (Youden's J) and written with provenance
  (criterion, corpus SHA-256, ffmpeg version, date) to `roc-threshold.json`.
- Held-out **FAR/FRR** carry **95% Clopper–Pearson** intervals (Beta quantiles via
  `statrs`); a zero count is reported honestly as `[0, upper]`, never "0%".
- **FRR is reported per stratum** (smooth/gradient, high-detail, high-motion); where a
  single global threshold over-rejects a stratum, the study states and quantifies it.

Source of truth: `bench/results/verify/STUDY.md` and the CSVs it cites
(`roc-scores.csv`, `roc-curve-calibration.csv`, `heldout-far-frr.csv`,
`per-stratum-frr.csv`).

### Verification cost — the price of trust

Measured per clip (`bench/results/verify/verification-cost.csv`, `STUDY.md`): the
**fundamental** cost of verifying a segment is **one reference re-encode** — mean ≈ 1.2×
the worker's transcode, i.e. the verifier re-does essentially one transcode, as expected.
The frame-extraction term measured by the current example is inflated by **per-frame
ffmpeg process spawns** (`extract_y_frame` launches one ffmpeg per frame); a production
verifier decodes each sampled segment **once** in-process and reads all challenge frames
from that pass, collapsing the term toward the SSIM compute. We report the measured cost
and name the optimization rather than assume it.

**Implication (feeds Phase 4/6 sizing):** with extraction batched, trusted-verifier
capacity must be ≥ `p × worker_throughput`; at the `P_MIN = 0.02` floor that is ≈ 2% of
worker throughput. This is why verification is a *separate, sized* tier, not a tax on every
transcode.

## Scheduling (Phase 4)

`sched` is the honest control plane: a Redis-backed durable store with epoch-fenced
compare-and-set, least-loaded **push** dispatch, a single reclaim authority, the adaptive
tier→`p` policy with a hard floor, content-addressed release, and Little's-law-sized
backpressure. It is `#![forbid(unsafe_code)]` with no async runtime in the path (locked
decisions #1). The spine: **a heartbeat timeout is a liveness heuristic, never a safety
mechanism** — fencing is safety (THREAT-MODEL §4, Liveness).

### `core::Task::apply` is the transition authority

The frozen `core` state machine *is* the scheduler's authority. The engine loads a task,
calls `core::Task::apply(ev)` to get the canonical `TaskAction`s, persists the transition
through the store, and executes those actions: `Requeue → enqueue_ready`,
`NotifyAccepted → content-addressed release`, `EmitReputation → update_standing`. The
store performs the **same** epoch CAS `apply` does — belt and suspenders, so even a
restarted or racing `sched` instance cannot accept a stale write (`engine.rs`).

### The Store discipline — one contract, two implementations

The decision logic (placement, reputation, sampling, backpressure, engine) is written over
a `Store` trait, free of Redis specifics. Two implementations are held to **one**
`contract.rs` suite — the differential oracle: an in-memory reference that *inherits* its
fencing from `core::Task::apply`, and a Redis store that **re-derives** the identical rule
in `redis::Script` (Lua) over a hash/ZSET data model so each transition's read-compare-write
is atomic with no `WATCH`/retry. The Redis Lua is correct *iff* it passes the same suite as
the reference, including the slow-zombie proof. Both run identically (Redis tier gated on a
reachable Redis; skipped loudly, never faked). `sched/src/store/{mod,memory,redis,contract}.rs`.

### Fencing and the single reclaim authority

Every (re)lease mints a strictly-greater monotonic `Epoch`; every holder-action write
(`submit`, `extend_lease`) carries it; the store rejects any write whose epoch ≠ the current
lease epoch, atomically (`StaleEpoch`, no mutation). `reclaim_expired` is the **single**
authority — `ZRANGEBYSCORE 0 now` over a lease-deadline index plus a per-task Lua reclaim
that returns the task to `Pending` and re-enqueues it — with **no stream-PEL / `XAUTOCLAIM`
second path** (the legacy divergence is structurally absent; the Coingate §1.2 bug class,
foreclosed). `LeaseExpired` keeps the high-water epoch, so the next lease is strictly
greater and the zombie's stale epoch can never match.

### Least-loaded push dispatch (`place.rs`)

The scheduler is the single placement authority — workers receive, never self-select. For
a ready task it picks the least-loaded **eligible** worker: primary metric is in-flight
lease count, tie-broken by a higher EWMA of recent completion throughput (`α = 0.3`, a
faster worker preferred at equal load). Eligibility = alive (recent heartbeat) ∧ reputation
not `Suspended`/`Banned` ∧ under the per-worker in-flight cap. Task selection honours
priority with **aging** — a task's effective priority rises one unit per `AGING_INTERVAL`
of waiting — so a low-priority (e.g. 4K) task cannot starve under sustained higher-priority
arrivals (the legacy strict-priority bug, fixed with arithmetic).

### Adaptive policy with the `P_MIN` floor (`reputation.rs`, `sample.rs`)

Reputation maps verifier verdicts to a standing, standing to a tier, and a tier to a
sampling fraction `p`, with **asymmetric** updates — *fast to distrust, slow to trust* — the
honest response to the measured held-out FAR ≈ 21% (effective detection `= P_hyper ×
(1 − FAR)`, so one pass is weak evidence). A pass credits `+1` capped at the pristine
baseline; a `FidelityBelowThreshold` fails by `−8`; a `CommitmentMismatch` is the
**heaviest** (`−64` → `Banned` in one step: provable byte-swap cheating, not a fidelity
judgement). `Suspended`/`Banned` workers are ineligible for dispatch — reputation *bites*,
unlike the legacy observe-only system. Every non-terminal tier maps to `p ≥ P_MIN = 0.02`
applied to **every** worker including pristine ones, so `k = ⌈p·n⌉ ≥ 1` always and **no
worker is ever unsampled**; the eligible-tier values (`0.02 / 0.10 / 0.25`) are the Phase 3
published-curve family (`verify::detection::TIERS`), and the floor equals
`verify::detection::P_MIN`. Sampling is `Bernoulli(p_tier)` over an injectable RNG
(OS-seeded in production, seeded/forced in tests).

### Little's-law backpressure (`backpressure.rs`)

Caps are arithmetic, not vibes: `L = λ × W` with `W ≈ 0.099 s` (the mean ffmpeg transcode
wall time, measured single-host — `bench/results/crypto/crypto_pct_transcode.csv`, range
0.059–0.179 s). Sizing for `N` workers at the saturation knee (`λ = N/W ⇒ L = N`) gives a
**per-worker in-flight cap** `⌈L/N⌉ + headroom = 2` (one Little's-law slot + one pipeline
slot so a worker isn't idle across the dispatch round trip) and a **global ready-queue cap**
`queue_factor × ⌈L⌉ = 4N`. At the global cap, intake **sheds** (a `Backpressure` error the
injector handles) rather than buffering, so resident work is `O(N)` regardless of offered
load — memory stays flat under sustained overload (a Phase 6 assertion).

### Verifier-capacity sizing

Trusted-verifier capacity must be ≥ `Σ_workers p_tier × throughput × cost_multiplier`. At
the `P_MIN = 0.02` floor and the **fundamental** 1.20× verification cost (one reference
re-encode; § Verification cost above), that is ≈ **2.4%** of aggregate worker compute — the
price of trust, cheap. The ≈ 10× per-frame-spawn artifact measured in Phase 3 would inflate
it to ≈ 20%; the in-process-decode optimisation (the Phase 5 verifier binary) removes that,
collapsing the cost toward the SSIM compute. The floor sets the *minimum* capacity; the tier
policy raises it for distrusted workers.

### Pre-committed dispatch-latency decomposition (Phase 6, amendment §1.4)

Predicted before measuring, so Phase 6 confirms rather than discovers. One dispatch is **two
Redis round trips** (`DISPATCH_REDIS_RTTS = 2`): the lease Lua (one `EVALSHA` doing the
epoch-fenced `HSET` + lease-deadline `ZADD` + in-flight `HINCRBY` atomically) and the inbox
`LPUSH` of the encoded `Assignment`. The in-process decision is a min-scan over the candidate
workers (≈ µs). **Prediction: in-process decision ≈ X µs; p99 dispatch ≈ `2 × RTT` and is
~95% Redis RTTs** — which preempts the dismissal "your scheduler is just Redis latency." The
queue is Little's-law-sized (above); both are confirmed against committed distributions in
Phase 6.
