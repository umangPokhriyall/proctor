# proctor — Untrusted-Worker Threat Model

> **Status:** the headings were committed at Phase 0; the confidentiality boundary in §4 was
> stated verbatim then so it cannot drift, and later phases fill in evidence as primitives
> land (§5 residual risks still complete from measured behavior in Phase 7). **Phase 5**
> reaffirms the worker-holds-key boundary in the **live** data plane and records
> worker-authentication / anti-Sybil as a documented non-goal (§4). This file is the
> antithesis of, and replacement for, the deleted `WORKER_SECURITY.md`.

## 1. Assets
- Content confidentiality; content integrity/fidelity; task liveness.

## 2. Adversaries
- Curious worker; lazy/cheating worker; malicious worker with root;
  colluding workers; network MITM; compromised blob store.

## 3. Trust boundaries
- (diagram + the trusted set: scheduler, verifier; the untrusted set: workers)

## 4. What each primitive defends — and what it does NOT
- Confidentiality (crypto, §2.2 kickoff): defended against the network, the blob
  store, co-tenants, and a NON-root worker process; **NOT defended against a
  root-capable worker**, which can read ffmpeg process memory. Closing that gap is
  the microVM flagship's mandate, not this repo's. (State this plainly. Do not hedge.)
  - **Reaffirmed in the live path (Phase 5).** The boundary is the same now that the
    real `worker` binary runs it: the worker fetches its per-segment key over the
    `crypto::keysource` seam (`LocalKeySource` for the benchmark; the production TLS key
    authority is documented and **not built**, kickoff §6) and decrypts the segment into
    anonymous RAM to transcode. **The untrusted worker holds the key and CAN see its
    shard's plaintext — by design**: a worker that must decode the frame cannot be
    cryptographically blinded to it, so root-on-worker defeats confidentiality regardless
    of the live wiring. This is intentional and unchanged from Phase 2; it is precisely
    the boundary the microVM flagship exists to close (§5). Nothing in Phase 5 pretends
    otherwise — the live `worker`/`verifier` are both key-trusted but no-disk
    (`crypto::keysource`, `worker/src/transcode_task.rs`, `verifier/src/main.rs`).
- **Worker identity is NOT authenticated — a documented non-goal (Phase 5).** A worker
  registers a self-claimed `WorkerId` (identity only); there is no cryptographic worker
  authentication and **no anti-Sybil mechanism**. This is deliberate and out of scope: a
  cheating worker is caught **regardless of its claimed identity** because (i) every
  holder-action is **epoch-fenced** at the durable store, so a forged or replayed identity
  still cannot land a stale-epoch write, and (ii) **probabilistic verification** with the
  `P_MIN` floor catches fabricated output at the rate the hypergeometric × (1 − FAR) math
  predicts. A Sybil worker that spins up many identities still faces the same per-segment
  sampling floor and the same fencing on every write; identity is not load-bearing for
  safety or fidelity. Production worker authentication (mutual TLS to the same key
  authority that delivers keys) is a deployment concern, not built here.
  - **No plaintext on disk — proven, not asserted (Phase 2, phase2-spec.md §7).**
    The decrypted segment lives only in anonymous RAM (`memfd_create`); ffmpeg
    reads and writes it solely through `/proc/self/fd/N` handles to those memfds;
    the only disk files are ciphertext. Evidence: the always-on tier-1
    fd-enumeration test `crypto/tests/no_disk.rs` (asserts no plaintext fd resolves
    to a disk file), and the tier-2 `strace -f` syscall audit committed at
    `bench/results/crypto/no-disk-audit.txt` (regenerate via the sibling
    `regen-no-disk-audit.sh`). This is the direct refutation of the deleted
    `WORKER_SECURITY.md`, which wrote the plaintext segment to `input.mp4`.
  - **Keys never on disk (Phase 2, §3).** 256-bit per-segment keys are `mlock`'d on
    construction (a key that could swap is rejected, not silently accepted) and
    zeroized with a volatile, un-elidable write on drop — not the legacy
    `buf.fill(0)` the optimizer may elide.
- Integrity/fidelity (verify, §2.1 kickoff): a worker that cannot predict which
  segments are checked must do real work or be caught at a measured rate.
  - **Commit-binding anti-swap chain (Phase 3, phase3-spec.md §3.4, amendment §1.2.4).**
    Commit-reveal is decorative unless the ordering is enforced, so the verifier
    enforces it:
    1. The worker uploads its encrypted output blob and submits
       `commitment = Commitment::commit(&[SHA-256(blob)])` — a **single-leaf** Merkle
       root, the frozen-`core` expression of "commitment = SHA-256(ciphertext)".
    2. **Before** any challenge frame is chosen, the verifier re-derives the
       commitment from the bytes it downloaded and requires an exact match
       (`verify::binding::check_binding`). A mismatch is tamper-evident and yields the
       categorical `VerifyDetail::CommitmentMismatch`; no frame is ever sampled from an
       unbound blob, so the worker cannot have predicted — and special-cased — the
       challenged timestamps. The reputation consequence of a mismatch is the
       scheduler's (Phase 4).
    3. The accepted `OutputRef` is the **content address** of the committed bytes (the
       leading 128 bits of the blob hash), so a release that references the `OutputRef`
       references the exact verified bytes — closing the verified-then-swapped TOCTOU.
       The store-level content-addressed release and the **fencing token** that also
       rejects a zombie worker's late re-commit landed in Phase 4 (amendment §1.1; see the
       Liveness section below); a heartbeat timeout is a liveness heuristic there, never
       the safety mechanism.
    Evidence: `verify/src/binding.rs` (a blob mutated after committing is rejected) and
    `verify/src/compare.rs` (binding precedes frame sampling on every path).
- Liveness (sched, §2.3 kickoff): a dead worker never strands a task, a slow-but-alive
  worker never double-commits one, and a flood never grows memory unbounded.
  - **Fencing tokens — a heartbeat timeout is a liveness heuristic, never a safety
    mechanism (Phase 4, amendment §1.1).** The legacy single-reclaim path prevents
    *stranded* tasks but not *zombie writes*: a slow worker that misses heartbeats is
    reclaimed and its task re-dispatched, then finishes and commits anyway — two outputs
    racing for one segment. Reclaim is **liveness** (re-dispatch a missed task); **safety
    is the fencing token**. Every (re)lease mints a strictly-greater monotonic `Epoch`
    (frozen into `core`); every holder-action write carries its lease epoch; and the
    durable store applies a write **iff** its epoch matches the current lease, atomically —
    a compare-and-set that rejects any stale-epoch write with **no mutation**, mirroring
    `core::Task::apply`'s `StaleEpoch` into the durable layer. So a revived zombie's late
    `submit`/`heartbeat` is rejected *at the store*; **exactly one output exists per
    segment**, and release is content-addressed (`OutputRef` = the committed blob hash), so
    the late blob cannot be substituted post-verification either — this pairs with the §4
    commit-binding chain to close the verified-then-swapped TOCTOU. A timeout can never be
    the safety mechanism because "missed a heartbeat" and "is still running" are
    indistinguishable to the scheduler; only the epoch ordering is decisive.
  - **Identical bug class to Coingate §1.2 (the `XAUTOCLAIM`-steal).** That portfolio's
    failure was a *second* reclaim path — a stream consumer that could `XAUTOCLAIM` a
    pending entry a superseded holder was still acting on, letting a stale holder mutate
    state. `proctor` forecloses it two ways, structurally: there is a **single reclaim
    authority** (`reclaim_expired`: epoch-bump + re-enqueue) and **no stream-PEL /
    `XAUTOCLAIM` second path**; and even a stolen or replayed write is inert because the
    epoch CAS rejects it. Same bug class, closed by construction — the portfolio-level
    coherence is itself the signal.
  - **Backpressure — a flood stays bounded (Phase 4, amendment §1.4).** Per-worker
    in-flight and global ready-queue caps are sized by **Little's law** `L = λ × W`
    (`W ≈ 0.099 s`, the measured transcode wall time); at the global cap intake **sheds**
    rather than buffering, so resident work is `O(N)` regardless of offered load.
  - Evidence: the differential store oracle's slow-zombie proof runs against **both** the
    in-memory reference and the Redis Lua store —
    `sched/src/store/contract.rs::{slow_zombie_submit_rejected, heartbeat_after_reclaim_rejected}`
    (re-lease at `e2 > e1`; the zombie's `submit@e1` / `heartbeat@e1` rejected as
    `StaleEpoch`; exactly one `Accepted` output). The end-to-end version is
    `sched/src/sim.rs::slow_zombie_submission_is_rejected_end_to_end`. Backpressure shed:
    `sched/src/backpressure.rs` + `sched/src/sim.rs::dispatch_tick_drains_and_intake_sheds_at_the_cap`.
    **Phase 5** proves the same rejection on the **live** path: a worker reclaimed and
    re-dispatched to another at a strictly-greater epoch has its stale-epoch submit rejected
    by the live Redis store, with exactly one output released
    (`bench/tests/live_smoke.rs::process_level_zombie_submit_is_rejected_with_one_output`).
    The full process-level *chaos schedule* (a fleet paused/resumed on a randomized schedule)
    lands in Phase 6.

## 5. Residual risks
- (most filled from measured behavior in Phase 7)
- **Swap is a disk surface (Phase 2, phase2-spec.md §5).** `memfd` pages holding
  plaintext are anonymous and CAN be paged to swap under memory pressure, which is
  a disk surface. Keys are always `mlock`'d, but the plaintext memfds are not — so
  the worker must run with swap disabled or under a memory-locked cgroup. This is a
  documented deployment requirement, not a defended-in-code property; we state it
  rather than hide it.
- **Root on the worker defeats confidentiality (Phase 2).** A root-capable worker
  can `ptrace` ffmpeg, read its anonymous memory, or read the memfd via `/proc`.
  Cryptography cannot stop the process that must decode the frame; only hardware
  isolation can. This residual *is* the microVM flagship's spec.
- **Accepted information leak: a worker can infer its reputation tier (Phase 3,
  amendment §1.3).** Detection sampling is adaptive — the per-worker sampling fraction
  `p` is indexed by reputation tier (the tier→`p` policy is Phase 4). A worker that
  watches its own challenge rate over time can infer which tier it is in. We do **not**
  hide this leak; we accept it, because a hard floor `P_MIN` (= 0.02;
  `verify::detection::P_MIN`) applies to **every** worker, pristine ones included, so
  `k = ⌈p·n⌉ ≥ 1` for all `n` on the published grid: no worker is ever unsampled, and
  there is always a minimum detection probability regardless of what the worker infers.
  The inference cannot be parlayed into going unchecked. Evidence: the committed
  detection family `bench/results/verify/detection-family.csv` and `verify/src/detection.rs`
  (the `P_MIN ⇒ k ≥ 1` test). The exact per-tier detection probabilities are the
  **hypergeometric** family, not the binomial; see `bench/results/verify/DETECTION.md`.
