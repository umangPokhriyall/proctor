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
- Integrity/fidelity (verify, §2.1 kickoff): a worker that cannot predict which
  segments are checked must do real work or be caught at a measured rate.
- Liveness (sched, §2.3 kickoff): a dead worker never strands a task; a flood never
  grows memory unbounded.

## 5. Residual risks
- (filled from measured behavior in Phase 7)
