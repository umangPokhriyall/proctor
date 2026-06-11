# proctor — kickoff-amendment-1.md

**Amends** `docs/specs/kickoff-brief.md`. Does **not** replace it — the brief is structurally sound. This records five upgrades from the Chief Architect directive, maps each to a phase, and states the freeze impact. Where an upgrade refines a number or a claim in the brief, this amendment is authoritative.

---

## 0. Freeze-verification result (the gating check) — PASS, no escalation

The directive instructs: confirm none of these require a change to the frozen `proctor_core`; if one does, STOP and escalate (1.1 touches the lease type). Result:

- **1.1** — the lease's monotonic `Epoch` and the state machine's stale-epoch rejection were built and frozen in Phase 1 (`core` §4/§6; `Task::apply → Err(StaleEpoch)`; the revived-worker zombie scenario is a passing property test). 1.1 is therefore a **Phase-4 store-enforcement** task, not a type change. Freeze holds.
- **1.2.4** — "commitment = SHA-256(ciphertext)" is expressed through the frozen Merkle API as a **single-leaf** commitment, `Commitment::commit(&[SHA-256(ciphertext)])`, checked with `verify_inclusion`. No new constructor, no type change. Freeze holds. The multi-leaf frame-reveal path remains frozen and unused (a harmless superset; it preserves the option of a bandwidth-constrained verifier later).
- **1.2.1–1.2.3, 1.3, 1.4** — all live in `verify`, `sched`, `bench`, and docs. No `core` surface touched.

**`v0.1.0-core-frozen` stands. `git diff v0.1.0-core-frozen -- core/` must remain empty through Phases 3–6.**

---

## 1.1 Fencing tokens on the lease — Phase 4 (sched/store)

The brief's single-reclaim-path prevents *stranded* tasks; it does not prevent *zombie writes*: a slow-but-alive worker that loses its lease (missed heartbeat → reclaim → re-dispatch), then finishes and commits anyway — two outputs for one segment, the zombie racing the legitimate re-execution. Heartbeat timeout is a **liveness heuristic and must never be the safety mechanism**; fencing is the safety mechanism.

Directive (Phase 4):
- The lease's monotonic `Epoch` (already in frozen `core`) is incremented by the scheduler on every reclaim/re-dispatch.
- Every state-mutating write by a worker (hash-commit, upload-complete, transition to `Transcoded`) carries its epoch; the **store rejects any write whose epoch < the current lease epoch, atomically** — a compare-and-set in the same Redis/DB transition, mirroring `core::Task::apply`'s in-memory rule into the durable layer. The in-memory state machine and the store enforce the identical invariant.
- Release is **content-addressed** (references the committed hash, not the task id), closing the verified-then-swapped TOCTOU (see 1.2.4).
- **Phase 6 chaos sim** adds the *slow-zombie schedule*: pause a worker mid-task past lease expiry, let reclaim + re-dispatch occur, resume the zombie, assert its commit is rejected and **exactly one output exists**.
- **Docs:** one paragraph in `THREAT-MODEL.md` and `ARCHITECTURE.md` naming the **fencing-token pattern** and why a timeout is a liveness heuristic, never a safety guarantee. Cross-reference Coingate §1.2 (the XAUTOCLAIM-steal bug class is identical) — the portfolio-level coherence is itself signal.

---

## 1.2 Verification math rigor — Phase 3 (verify/bench/docs)

Four correctness gaps in the brief's §2.1, fixed:

**1.2.1 — Exact hypergeometric, not binomial.** The brief's `1 − (1−p)^(f·n)` models sampling *with replacement*. The verifier samples `k = ⌈p·n⌉` of `n` segments *without* replacement; with `m = ⌈f·n⌉` tampered, `P(detect) = 1 − C(n−m, k)/C(n, k)`. At small `n` (short video, `n ≤ 32`) the binomial **under-states** detection. (Wording correction, folded in Phase 4: the original "overstates" had the sign backwards. Phase 3's committed `bench/results/verify/DETECTION.md` proves `hypergeometric ≥ binomial` — the divergence `binomial − hypergeometric ≤ 0` everywhere on the grid — so the binomial is the *conservative* curve. The decision below is unaffected.) Commit both curves and the divergence plot; **publish the hypergeometric** as the claim.

**1.2.2 — Calibration/held-out split + confidence intervals.** A threshold chosen and scored on the same corpus is circular. Split `bench/corpus/` into a **calibration set** (threshold selection only) and a **disjoint held-out set** (reported FAR/FRR). Report **95% Clopper–Pearson** intervals on FAR/FRR given the finite held-out count. A point estimate ("FAR 0.3%" off 400 samples) without an interval is exactly the overclaim this repo repudiates.

**1.2.3 — Stratify by content class.** Honest re-encode score distributions are content-dependent. Report **per-stratum FRR for ≥3 strata** (mapped to the synthetic corpus: smooth/gradient, high-detail/grain-like, high-motion). If a single global threshold over-rejects high-detail content, **say so** — that caveat is the elite line in the writeup.

**1.2.4 — Explicit, enforced commit binding (the anti-swap chain).** Commit-reveal is decorative unless the chain is enforced. Exact order of operations:
1. Worker uploads the encrypted output blob.
2. Worker submits `commitment = Commitment::commit(&[SHA-256(ciphertext_blob)])` (single-leaf Merkle over the blob hash — the frozen-core expression of "commitment = SHA-256(ciphertext)").
3. **Before** the verifier picks any challenge frames, it downloads the blob and checks `Commitment::commit(&[SHA-256(downloaded_blob)]) == submitted_commitment` (equivalently, `verify_inclusion`). Mismatch ⇒ reject, hard reputation hit.
4. Release is **content-addressed** by the committed hash (the `OutputRef` *is* the blob hash), so a verified blob cannot be swapped post-verification.
- Test: a worker that swaps the blob after committing is rejected at step 3.

**Note on the comparator:** the directive's "pHash" is read as *the comparator metric generally*. Our locked decision #4 is **SSIM** (structural fidelity, not perceptual similarity) precisely because SSIM is what discriminates cheap-downscale and frame-substitution. The math (strata, ROC, CIs) applies identically; we implement SSIM.

---

## 1.3 Adaptive sampling vs. the committed curve — Phases 3 (math) / 4 (policy)

A single fixed-`p` committed curve contradicts adaptive sampling (adaptive `p` makes the curve non-stationary, and a worker can infer its reputation tier from observed challenge frequency — an information leak). Resolution:

- Publish detection probability as a **family of curves** `P_detect(f, n; p_tier)` indexed by reputation tier (Phase 3), with a **hard floor `p_min` applied to every worker including pristine ones** — no worker is ever unsampled (`k = ⌈p·n⌉ ≥ 1` always).
- The tier → `p` mapping and the adaptive policy live in `sched` (Phase 4); Phase 3 publishes the curve family at representative tier `p`-values, `p_min` included.
- **Honest leak statement in `THREAT-MODEL.md`:** a worker can infer its tier from challenge rate; this is *accepted* because the `p_min` floor guarantees a minimum detection probability regardless of inference.

---

## 1.4 Scheduler benchmark decomposition — Phase 6 (sched/bench)

Pre-commit to the honest framing before measuring, so the result is predicted-then-confirmed (mirroring Phase 3's ctx-switch result):
- Decompose dispatch-latency p99 into **per-dispatch Redis RTT count × measured RTT** vs. **in-process decision time**. The expected result — "decision time ≈ X µs; p99 dispatch ≈ Y ms and is ~95% Redis RTTs" — preempts the dismissal "your scheduler is just Redis latency."
- Size the bounded queue with **Little's law**: target in-flight `= λ × service_time`. Backpressure thresholds are justified with arithmetic, not vibes.

---

## 1.5 Scope guard & cut order

None of the above adds product surface (1.1, 1.4 = sched/bench; 1.2, 1.3 = verify/bench/docs). If the clock forces cuts: cut **1.2.3 stratification** down to a single corpus with CIs and an honest note. **Never cut 1.1 (fencing) or 1.2.1–1.2.2 (hypergeometric + split)** — those are the load-bearing signal.

**Housekeeping carried from Phase 2:** the pure crates lacked `#![forbid(unsafe_code)]` (they contain no unsafe). `verify` gets the lint at scaffold time (Phase 3); each remaining pure crate gets it when implemented. Adding the lint to frozen `core` is freeze-compatible (no type/behavior/wire change) but optional — operator's call; default is to leave `core` untouched.

---

## 2. Net effect on the phase plan
- **Phase 3 (`verify`)** — drafted to this amendment: SSIM, single-leaf commit binding, hypergeometric detection family with `p_min`, calibration/held-out ROC with Clopper–Pearson CIs, per-stratum FRR, verification-cost.
- **Phase 4 (`sched`)** — store-level epoch-fenced CAS; tier → `p` adaptive policy with `p_min` floor; content-addressed release; Little's-law-sized backpressure.
- **Phase 6 (`bench`)** — slow-zombie chaos schedule; dispatch-latency decomposition.
- **Docs** — `THREAT-MODEL.md` and `ARCHITECTURE.md` gain the fencing-token, adaptive-leak, and commit-binding/TOCTOU paragraphs (verification items in Phase 3; fencing in Phase 4).
