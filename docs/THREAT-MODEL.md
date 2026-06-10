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
