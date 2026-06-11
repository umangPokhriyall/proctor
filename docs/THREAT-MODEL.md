# proctor — Untrusted-Worker Threat Model

> **Status (Phase 0):** skeleton. Headings are committed now; §5 (residual risks) is
> filled from measured behavior in Phase 7. The honest confidentiality boundary in §4 is
> stated now, verbatim, so it cannot drift later. This file is the antithesis of, and
> replacement for, the deleted `WORKER_SECURITY.md`.

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
       rejects a zombie worker's late re-commit land in Phase 4 (amendment §1.1); a
       heartbeat timeout is a liveness heuristic there, never the safety mechanism.
    Evidence: `verify/src/binding.rs` (a blob mutated after committing is rejected) and
    `verify/src/compare.rs` (binding precedes frame sampling on every path).
- Liveness (sched, §2.3 kickoff): a dead worker never strands a task; a flood never
  grows memory unbounded.

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
