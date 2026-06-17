# proctor — Phase 6 Specification: `bench` — The Single-Host Harness, the Numbers, and the Adversary Suite

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0–5-spec.md`. Read the amendment (§1.1, §1.2, §1.3, §1.4) first.
**This is the complete, authoritative Phase 6 spec.** It builds `bench` — the single-host N-worker harness over a deterministic corpus and local blob store — completes the real Redis push-dispatch path, and produces the committed numbers the whole portfolio thesis rests on: the **scheduling-overhead decomposition** (Redis-RTT vs decision time, §1.4), the **crypto/verification cost** distributions in the live pipeline, the **saturation/backpressure** run, and the **chaos/adversary suite** — the slow-zombie chaos schedule at scale (§1.1) and the cheating-worker classes caught at the rate the **hypergeometric × (1 − FAR)** math predicts (§1.2), reported with confidence intervals.
**Scope:** `bench/` plus the additive completion of real Redis dispatch in `sched`. The polished `README`, `x-thread`, `SELF-AUDIT`, and distribution are Phase 7. The honest worker is from Phase 5; **cheating workers live only in `bench` (the adversary harness)** — `worker/` stays honest.
**Audience:** Claude Code. Authoritative. **Claude Code commits its own work.** **A real Redis + ffmpeg on a documented host are required** — no fabricated numbers; loud-skip and mark results pending if absent.
**Frozen:** `proctor_core` is FROZEN (`v0.1.0-core-frozen`); `git diff v0.1.0-core-frozen -- core/` stays empty. `sched`/`crypto`/`verify` extend additively; all prior-phase suites stay green. If `core` seems to need a change, STOP and escalate.

---

## 0. Phase 6 in context, and the bar it must clear

Everything so far was a component proven in isolation or a smoke run. Phase 6 is the measurement phase, and its bar is the NORTH-STAR bar: every claim is a committed number with units and conditions, distributions not averages, **coordinated-omission-correct** load, and an honest negative result stated plainly where one exists. Two results are predicted-then-confirmed — the Principal-grade framing that preempts the obvious dismissal:

- **Scheduling (§1.4):** Phase 4 pre-committed `DISPATCH_REDIS_RTTS = 2` and "decision time ≈ µs; p99 dispatch ≈ N × RTT, ~95% Redis." Phase 6 measures RTT and decision time in isolation, then confirms the dispatch p99 is dominated by Redis — so "your scheduler is just Redis latency" is answered with arithmetic, not defensiveness.
- **Detection (§1.2):** Phase 3 published the exact hypergeometric family and measured FAR ≈ 21% for cheap-downscale at the 160×120 plane. The honest composition is **effective detection = P_detect_hypergeometric(f,n;p) × (1 − FAR)**. Phase 6 runs real cheating workers and confirms the measured catch rate matches the prediction within CIs — and states, as the elite line, that cheap-downscale is the hardest class to catch and why, naming the remedy (FAR-constrained threshold / higher comparison geometry).

This phase converts "verifiable compute over untrusted workers" from the legacy lie into a measured fact with error bars.

**Human/Claude split:** Claude Code executes including commits. The committed numbers come from a real run on a documented host (cores, NUMA, Redis + ffmpeg versions in `METHODOLOGY.md`); if the environment lacks Redis/ffmpeg, loud-skip and mark results pending (the Phase 0 corpus discipline).

---

## 1. Phase 6 in one paragraph

Complete the real **Redis push dispatch** in `sched` (the dispatch loop `LPUSH`es the encoded `Assignment` to `{prefix}:inbox:{worker}`; the `Bus` becomes test-only, sim stays green) so the whole transport is Redis end-to-end and measurable. Build `bench` (`#![forbid(unsafe_code)]`, no async): the **preprocessor** (segment the deterministic corpus, `aead::encrypt` per-segment, populate `LocalBlobStore` + `LocalKeySource`), the **orchestrator** (spawn `sched` + N `worker`s + M `verifier`s as `taskset`-pinned subprocesses over a loopback Redis; teardown), an **open-loop, coordinated-omission-correct injector** (`inject_workload` at a target rate from intended-issue timestamps — the Rust-Tcp-Server methodology), and a per-process timestamped **event log** the bench merges by task id into distributions. Measure and commit to `bench/results/`: the **dispatch decomposition** (RTT × count vs decision time, predicted-then-confirmed), **throughput vs N**, **reclaim latency** (fault injection), **crypto/verification cost** in the live pipeline, the **saturation/backpressure** run (bounded resident work, intake shed), and the **chaos/adversary suite** — slow-zombie at scale (zero double-outputs) and per-class cheating detection with **Clopper–Pearson CIs** versus the predicted **hypergeometric × (1 − FAR)** curve, plus the adaptive-escalation demonstration. Write `BENCHMARKS.md`, `PROFILING.md`, `ADVERSARY.md`.

### 1.1 Frozen / consumed (alignment with the real Phase 1–5 code)
- `sched`: the dispatch loop, the `{prefix}:inbox:{worker}` / `{prefix}:inbound` model, the epoch-fenced store (memory + Redis), `reclaim_expired` (single authority), Little's-law caps (`W = 0.099 s`, per-worker in-flight `= 2`, global `= 4N`, `DISPATCH_REDIS_RTTS = 2`), tier→`p` (`P_MIN = 0.02`, tiers `{0.02, 0.10, 0.25}`), rich `record_verdict`.
- `crypto`: `blob` (content-addressed ciphertext), `keysource` (per-segment keys), `aead::encrypt`, the no-disk path (1.55/0.99 GB/s, 0.10–1.03% of transcode baseline from Phase 2).
- `verify`: the committed `roc-threshold.json`, the published detection family + `FAR ≈ 21%` / per-stratum FRR (Phase 3), `frame::extract_y_frames` (batched), `verify_segment`, `integrity`.
- `worker`/`verifier`: the real binaries; honest worker stays honest — adversary logic is `bench`-only.

---

## 2. `bench` layout, dependency allowlist, and the additive `sched` completion

```
sched/src/
  loops.rs        # ADDITIVE: dispatch loop LPUSHes Assignment to {prefix}:inbox:{worker} (real Redis dispatch)
bench/src/
  main.rs         # #![forbid(unsafe_code)] — CLI: preprocess | run <scenario> | adversary <scenario>
  preprocess.rs   # segment corpus + aead::encrypt per segment → LocalBlobStore + LocalKeySource; inject tasks
  orchestrate.rs  # spawn sched + N workers + M verifiers as taskset-pinned subprocesses; teardown
  inject.rs       # open-loop, coordinated-omission-correct injector at target rate λ (intended-issue times)
  metrics.rs      # per-process timestamped event log (event, task_id, monotonic_ns); merge by task id
  report.rs       # distributions (p50/p99/p99.9) via hdrhistogram; CSV + summary writers
  adversary.rs    # bench-only cheating workers (cheap-downscale, frame-substitution, wrong-bitrate, garbage, byte-swap)
bench/results/
  sched/          # dispatch decomposition, throughput vs N, reclaim latency, RTT/decision isolation
  pipeline/       # crypto-as-%-of-e2e, verification-cost distribution, verifier-capacity utilization
  saturation/     # backpressure run: resident work, memory, shed rate
  adversary/      # per-class detection + CIs vs predicted curve, adaptive escalation, slow-zombie chaos
  METHODOLOGY.md  # host (cores/NUMA), Redis + ffmpeg versions, corpus hash, CO-correction, regen commands
  PROFILING.md    # perf stat on the placement loop (+ AES-NI confirm); interpreted
  ADVERSARY.md    # the cheating-worker results writeup (honest, per-class, CI'd)
  BENCHMARKS.md   # the committed headline numbers
```

**Dependency allowlist — Phase 6 adds exactly these to `bench`:**
- `proctor_core`, `crypto`, `verify`, `sched` (workspace) — the real library code under measurement.
- `redis` (sync) — orchestration + metrics readback.
- `rand` — adversary tampering selection + sampling reproducibility.
- `hdrhistogram` — coordinated-omission-correct latency recording and percentiles.
- `thiserror`.

No `tokio`/async, no `unsafe` (forbidden — **core-pinning is `taskset -c`, an external command, not FFI; `perf` is external too**), no plotting runtime dep (commit CSVs; SVGs, if any, dev-only). The additive `sched` dispatch change needs no new `sched` dep.

---

## 3. The harness (`preprocess`, `orchestrate`, `inject`, `metrics`)

- **Preprocessor (the no-API authority, locked decision #1):** segment the Phase 0 deterministic corpus (≈2 s GOP), generate a per-segment `SecretKey`, `aead::encrypt(Role::Source)`, `BlobStore.put_source`, register the key in `LocalKeySource`, and `inject_workload` the `Transcode`/`Stitch` tasks **directly** into `sched` — there is no ingest API. The corpus, keys, and blob store are the bench's to populate; document the corpus hash and ffmpeg version for replay.
- **Orchestrator:** spawn one `sched`, N `worker` subprocesses, and M `verifier` subprocesses, each `taskset -c`-pinned to disjoint cores (mechanical sympathy; NUMA topology documented), all over a **loopback** Redis. Single-host is a documented caveat (locked decision #5): geography is orthogonal to placement/crypto/verification/fencing — the properties measured here. Clean teardown (kill children, flush the test Redis namespace).
- **Open-loop, coordinated-omission-correct injection (the signature methodology):** the injector schedules **intended-issue** timestamps at a fixed target rate λ, independent of system progress. Latency is measured from the **intended-issue** time, not the actual-issue time, so a stall does not hide the tail (record with `hdrhistogram`'s expected-interval correction). Report intended λ vs achieved rate; the knee where achieved < intended is the saturation point and the latency tail there is CO-corrected and honest. This is the Rust-Tcp-Server discipline applied to the scheduler — the portfolio coherence is itself signal.
- **Metrics:** each process appends `(event, task_id, monotonic_ns)` to a per-process log for the lifecycle points (ready, dispatched, leased, submitted, verify-requested, verified, released); the bench merges by `task_id` and computes per-stage distributions. Lightweight, replayable, no heavy telemetry.

---

## 4. The scheduling-overhead decomposition (§1.4) — predicted-then-confirmed

Commit to `bench/results/sched/`:
- **Dispatch latency** (ready → `Assignment` on the worker inbox) distribution: p50 / p99 / p99.9, CO-corrected.
- **Isolation measurements:** (a) Redis RTT — a direct round-trip micro-measurement against the loopback Redis; (b) in-process decision time — the `place` + store-decision logic timed without the Redis round trips. 
- **The confirmation:** show dispatch p99 ≈ `DISPATCH_REDIS_RTTS (=2) × RTT + decision`, and that Redis RTTs are ≈ 95% of it. State the predicted figures (Phase 4) beside the measured — predicted-then-confirmed. If the split differs from the prediction, **say so and explain**; the honest decomposition is the deliverable, not a flattering ratio.
- **Throughput vs N** (= 1 / 4 / 16 / 64 workers): tasks/s placed; the saturation knee; how decision time scales (it should stay flat per-dispatch; Redis contention is the scaling variable).

---

## 5. Crypto/verification cost in the live pipeline, and saturation/backpressure

Commit to `bench/results/pipeline/` and `bench/results/saturation/`:
- **Crypto as % of end-to-end segment latency** under concurrency (cite the Phase 2 standalone 0.10–1.03% baseline; confirm it stays small in the live, contended pipeline).
- **Verification cost distribution** with the Phase 5 batched decode: per-sampled-segment verify time as a fraction of one transcode (confirm ≈ the 1.20× fundamental, far below the Phase 3 ~10× per-frame-spawn artifact). **Verifier-capacity utilization** at `P_MIN`: confirm the M verifiers are not a bottleneck at the floor, and report the sampling rate that would saturate them (the capacity envelope, ≈ 2.4% of worker compute at the floor).
- **Saturation/backpressure run:** offer ≈10× aggregate worker capacity; show **bounded resident work** (global queue cap holds, intake sheds with the `Backpressure` error), **flat memory** under sustained overload, and the achieved-vs-intended rate. Confirm the Little's-law caps (`L = λ × W`) hold in the live system.
- **Reclaim latency (fault injection):** kill a worker mid-task; measure worker-death → `reclaim_expired` → re-dispatch latency, as a distribution. *(Optional, fold in if cheap: have `reclaim_expired` return timed-out holders so a soft `Timeout` reputation penalty applies — the deferred Phase 4 seam. Not required for this DoD; fencing safety does not depend on it.)*

---

## 6. The chaos/adversary suite (the headline — §1.1 + §1.2 + §1.3)

Commit to `bench/results/adversary/` + `ADVERSARY.md`. This is the falsifiable security proof.

### 6.1 Slow-zombie chaos schedule at scale (§1.1)
Across many tasks under load, inject the slow-zombie schedule (pause a worker mid-task past lease expiry → reclaim + re-dispatch → resume the zombie → its epoch-stale submit hits the Redis store CAS). Assert **zero double-outputs** across the whole run — fencing holds safety under concurrency, not just in the unit/smoke case. The byte-swap variant (post-commit blob swap) is caught deterministically at binding (`CommitmentMismatch`).

### 6.2 Cheating-worker classes caught at the predicted rate (§1.2) — the elite artifact
Run `bench`-only adversary workers (the production `worker/` stays honest) that tamper a fraction `f` of their segments in each class — **cheap-downscale, frame-substitution, wrong-bitrate, garbage, byte-swap** (reusing the Phase 3 attack synthesis). Over many trials, measure the **end-to-end detection rate** (per tampered segment and per cheating worker), **per class**, and compare to the prediction:

> effective detection = `P_detect_hypergeometric(f, n; p) × (1 − FAR_class)`

Report each measured rate with a **95% Clopper–Pearson interval** (finite trials — a bare point estimate is the overclaim this repo repudiates), beside the predicted curve. Expected, and to be stated honestly:
- **byte-swap → CommitmentMismatch:** caught deterministically at binding (`FAR ≈ 0`) → one-step Ban. The integrity guarantee is hard.
- **cheap-downscale:** the **hardest** class (`FAR ≈ 21%` at 160×120) → effective detection materially below the raw hypergeometric. This is the elite line: state it, give the number with its CI, and name the remedy (FAR-constrained threshold / higher comparison geometry) with the calibration sweep as its basis.
- **frame-substitution / garbage / wrong-bitrate:** report each class's measured detection + CI versus prediction.
- *(Optional per §1.5, cuttable under clock pressure: per-stratum detection — cheating on high-motion vs smooth content — since FAR/FRR are content-dependent. Never cut the per-class CI'd table or the predicted-vs-measured comparison.)*

### 6.3 Adaptive escalation demonstration (§1.3)
Show a persistently-cheating worker: first catch → tier escalates → sampling `p` rises (`0.02 → 0.10 → 0.25`) → subsequent detection accelerates → eventual Ban; and that the `P_MIN = 0.02` floor catches even a low-rate cheater eventually (no worker is unsampled). State the accepted info-leak honestly (a worker can infer its tier from challenge rate; the floor makes minimum detection independent of that inference — amendment §1.3).

---

## 7. The writeups & profiling

- **`PROFILING.md`:** `perf stat` on the scheduler placement loop (and a re-confirm that crypto is AES-NI-accelerated), **interpreted** — where the decision time goes, why Redis dominates dispatch at N workers — not a raw dump.
- **`ADVERSARY.md`:** the §6 results, honest and per-class, with CIs and the cheap-downscale caveat + remedy.
- **`BENCHMARKS.md`:** the committed headline numbers (dispatch decomposition, throughput vs N, reclaim latency, crypto/verification cost, saturation behavior, detection table). Writing Standard: declarative, units + conditions, no marketing, the honest negatives stated. Public framing is a **systems artifact** (the flagship/AI-infra synergy stays internal per NORTH-STAR / kickoff §6).
- Every figure in every writeup cites its source CSV; nothing is asserted without a committed number behind it.

---

## 8. Correctness, reproducibility & purity (verify before commit)
- `bench` is `#![forbid(unsafe_code)]`; no async; core-pinning via `taskset`, profiling via `perf` (external commands, gated/loud-skip if absent).
- Real Redis dispatch completed in `sched`; the `Bus` is test-only; all Phase 4/5 `sched` + `contract.rs` (both tiers) + sim + `live_smoke` suites stay green.
- **Reproducible:** committed corpus hash, pinned Redis + ffmpeg versions, documented host topology, CO-correction documented, and a regen command per result set. A number nobody can reproduce is not a number.
- Adversary logic exists only in `bench`; `worker/` has no cheat path (grep-confirm).
- Detection results carry CIs; the predicted curve is computed from the committed Phase 3 detection module + the measured FAR; predicted and measured are reported side by side.
- `core` 0-byte diff; allowlist (§2) respected; `cargo build --all-targets && cargo clippy --all-targets -- -D warnings && cargo test` clean.

---

## 9. Commit discipline (carried forward)
- Conventional Commits `<type>(bench|sched): <imperative>`, ≤72 chars; body cites the spec/amendment section and states the rejected alternative where relevant.
- Atomic, one logical change per commit, each on a green tree (prior-phase suites included). Never commit red. No `--no-verify`, no force-push, no `core/` edits. Commit CSVs, JSON, and text writeups — **never media or large binaries** (the corpus stays generated, not committed beyond the seed).

---

## 10. Phase 6 Definition of Done
1. Real Redis push dispatch completed in `sched` (dispatch loop `LPUSH`es `Assignment` to `{prefix}:inbox:{worker}`); `Bus` test-only; all Phase 4/5 suites + `contract.rs` (both tiers) + `live_smoke` green.
2. `bench` (`#![forbid(unsafe_code)]`, no async): preprocessor (segment + `aead::encrypt` + populate blob/key stores + `inject_workload`), `taskset`-pinned subprocess orchestrator over loopback Redis, **open-loop CO-correct** injector, per-process event-log metrics merged by task id.
3. **Scheduling decomposition** committed (§4): CO-corrected dispatch p50/p99/p99.9; RTT and decision-time isolation; the predicted-then-confirmed "~95% Redis, ~2 RTTs" result; throughput vs N (1/4/16/64) with the knee.
4. **Crypto/verification cost** committed (§5): crypto as % of e2e under concurrency; verification-cost distribution confirming ≈1.20× (batched, far below the ~10× artifact); verifier-capacity utilization at `P_MIN`.
5. **Saturation/backpressure** committed (§5): bounded resident work + flat memory under ≈10× overload, intake shed, Little's-law caps confirmed; **reclaim latency** distribution from fault injection.
6. **Chaos/adversary suite** committed (§6): slow-zombie at scale → **zero double-outputs**; **per-class cheating detection with 95% Clopper–Pearson CIs vs the predicted hypergeometric × (1 − FAR)**, with the honest cheap-downscale caveat + named remedy and the byte-swap deterministic-catch result; adaptive-escalation demonstration; the accepted info-leak stated.
7. `PROFILING.md` (`perf`, interpreted), `ADVERSARY.md`, `BENCHMARKS.md` committed; every figure cites its CSV; Writing Standard honored; public framing is a systems artifact.
8. Reproducibility recorded in `METHODOLOGY.md` (host, versions, corpus hash, CO-correction, regen commands); numbers from a real Redis + ffmpeg run (or loud-skip + pending).
9. `core` unchanged since freeze; adversary logic only in `bench`; full gate green; allowlist respected.
10. Commits per §9.

Next: `phase7-spec.md` — closeout & distribution: the 60-second `README`, the `x-thread` built only from committed numbers, the `SELF-AUDIT` (re-derive fencing, the confidentiality boundary, the detection composition from memory), final `ARCHITECTURE` polish, and the proof-first distribution doctrine (NORTH-STAR §7) — the artifact made undeniable and then seen.

---

# Appendix A — `CLAUDE.md` update for Phase 6

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md
- docs/specs/phase0–5-spec.md  — core (FROZEN), crypto, verify, sched, worker+verifier
- docs/specs/phase6-spec.md    — CURRENT: bench (harness, numbers, adversary suite)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- sched/crypto/verify extend ADDITIVELY; ALL prior-phase suites + contract.rs (both tiers) + live_smoke green.

## Hard rules (Phase 6)
1. bench is #![forbid(unsafe_code)], no async. Core-pinning = taskset (external); perf = external. No FFI.
2. Real numbers only: a real Redis + ffmpeg on a documented host. No fabrication; loud-skip + pending if absent.
3. Open-loop, COORDINATED-OMISSION-CORRECT injection: latency from intended-issue time (hdrhistogram expected
   interval). Distributions (p50/p99/p99.9), never averages alone.
4. Predicted-then-confirmed: dispatch decomposition cites Phase 4's 2 RTTs / ~95%-Redis prediction beside the
   measurement; detection cites the published hypergeometric × (1 − FAR) prediction beside the measured rate.
5. Detection rates carry 95% Clopper–Pearson CIs. Per class. State the cheap-downscale hardest-class caveat +
   the remedy (FAR-constrained threshold / higher geometry). byte-swap caught deterministically at binding.
6. Slow-zombie chaos at scale ⇒ ZERO double-outputs (fencing safety under load). Single reclaim authority.
7. Adversary/cheating logic lives ONLY in bench. worker/ stays honest (grep-confirm).
8. Reproducible: corpus hash, pinned versions, host topology, CO-correction, regen commands in METHODOLOGY.md.
   Every figure cites its CSV. Writing Standard; public framing = systems artifact (flagship synergy internal).
9. Phase 6 deps (bench): proctor_core, crypto, verify, sched, redis, rand, hdrhistogram, thiserror.

## Commit discipline
Conventional Commits, atomic, GREEN tree (incl. prior suites), body cites spec/amendment.
Commit CSVs/JSON/text, NEVER media/large binaries. No --no-verify, no force-push, no core/ edits.

## Scope discipline
bench + the real-dispatch sched completion only. NO README/x-thread/SELF-AUDIT/distribution (Phase 7).
End with build+clippy+test, commit(s), change list, STOP.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1 | real dispatch + harness | `sched` Redis dispatch; `bench` preprocess/orchestrate/inject/metrics | live network over real Redis; CO-correct injector; prior suites green; commit |
| 2 | scheduling decomposition | `bench/results/sched/*` | CO-corrected dispatch dist; RTT/decision isolation; ~95%-Redis confirmed; throughput vs N; commit |
| 3 | saturation + reclaim + cost | `bench/results/{saturation,pipeline}/*` | bounded work + shed; reclaim dist; crypto/verify cost + verifier capacity; commit |
| 4 | adversary suite | `bench/results/adversary/*` + `ADVERSARY.md` | per-class detection + CIs vs predicted; slow-zombie zero-double; escalation demo; commit |
| 5 | profiling + benchmarks writeup | `PROFILING.md`, `BENCHMARKS.md`, `METHODOLOGY.md` | perf interpreted; headline numbers; reproducibility recorded; commit |
| 6 | DoD verify | gate + item-by-item | DoD §10 reported with evidence; core 0-byte diff; commit |

Session 4 is the load-bearing security artifact; keep it isolated. Sessions 5–6 may merge if light.

### Exact prompts (one per session; verify + commit before the next)

**Session 1**
> Read `kickoff-amendment-1.md`, `phase6-spec.md` (§2–§3, §8–§10), and `CLAUDE.md`; update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: (a) additively complete real Redis push dispatch in `sched` — the dispatch loop `LPUSH`es the encoded `Assignment` to `{prefix}:inbox:{worker}`; keep the `Bus` for the sim and all Phase 4/5 + `contract.rs` (both tiers) + `live_smoke` green. (b) Build the `bench` harness: `preprocess` (segment corpus + `aead::encrypt` per segment + populate `LocalBlobStore`/`LocalKeySource` + `inject_workload`), `orchestrate` (spawn `sched` + N `worker`s + M `verifier`s as `taskset`-pinned subprocesses over loopback Redis; teardown), `inject` (open-loop CO-correct injector at target λ from intended-issue times), `metrics` (per-process event log merged by task id). `#![forbid(unsafe_code)]`, no async. Build+clippy `-D warnings`+test; commit; STOP.

**Session 2**
> Read `CLAUDE.md` and `phase6-spec.md` §4. Execute **Session 2 only**: measure and commit to `bench/results/sched/` the CO-corrected dispatch-latency distribution (p50/p99/p99.9), the isolated Redis RTT and in-process decision time, the predicted-then-confirmed decomposition (cite Phase 4's `DISPATCH_REDIS_RTTS = 2` / ~95%-Redis prediction beside the measurement; explain any divergence honestly), and throughput vs N (1/4/16/64) with the saturation knee. Commit results + methodology notes; STOP.

**Session 3**
> Read `CLAUDE.md` and `phase6-spec.md` §5. Execute **Session 3 only**: commit to `bench/results/saturation/` the ≈10× overload run (bounded resident work, flat memory, intake shed, achieved-vs-intended rate, Little's-law caps confirmed) and the fault-injection **reclaim-latency** distribution; commit to `bench/results/pipeline/` crypto-as-%-of-e2e under concurrency, the batched-decode **verification-cost** distribution (confirm ≈1.20×), and verifier-capacity utilization at `P_MIN`. Commit results; STOP.

**Session 4**
> Read `CLAUDE.md` and `phase6-spec.md` §6, and amendment §1.1/§1.2/§1.3. Execute **Session 4 only**: build the `bench`-only `adversary` workers (cheap-downscale, frame-substitution, wrong-bitrate, garbage, byte-swap — `worker/` stays honest) and commit to `bench/results/adversary/` + `ADVERSARY.md`: (a) the slow-zombie chaos schedule at scale → **zero double-outputs**; (b) **per-class** end-to-end detection with **95% Clopper–Pearson CIs** beside the predicted `hypergeometric × (1 − FAR)` curve, stating the cheap-downscale hardest-class caveat + remedy and the byte-swap deterministic catch; (c) the adaptive-escalation demonstration + the floor, with the accepted info-leak stated. Build+clippy+test; commit; STOP.

**Session 5**
> Read `CLAUDE.md` and `phase6-spec.md` §7. Execute **Session 5 only**: write `bench/results/PROFILING.md` (`perf stat` on the placement loop + AES-NI re-confirm, interpreted), `bench/results/BENCHMARKS.md` (the committed headline numbers, Writing Standard, every figure citing its CSV, public systems framing), and `bench/results/METHODOLOGY.md` (host topology, Redis/ffmpeg versions, corpus hash, CO-correction, regen commands). Commit; STOP.

**Session 6**
> Read `CLAUDE.md` and `phase6-spec.md` §10. Execute **Session 6 only**: verify the Phase 6 DoD §10 item by item with evidence; confirm `git diff v0.1.0-core-frozen -- core/` is empty, adversary logic is only in `bench` (grep), and all prior-phase suites + both store tiers + `live_smoke` are green against a real Redis. Commit `docs: phase 6 DoD verification`; STOP.
