# proctor — Claude Code guardrail

## What this is
A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers. The transcoding is the vehicle; the three primitives are the deliverable:
probabilistic verification, in-memory shard-scoped crypto, a backpressure-aware
scheduler. The honest confidentiality boundary points at the microVM flagship.

## Authoritative specs (read before any work)
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md  — amendment changes the math
- docs/specs/phase0–3-spec.md  — genesis, core (FROZEN), crypto, verify (SSIM, binding, hypergeometric, ROC)
- docs/specs/phase4-spec.md    — CURRENT: sched (epoch-fenced Redis store, push dispatch, policy, backpressure)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- core::Task::apply is the transition authority; sched executes the TaskActions it returns.
- crypto is NOT frozen: §3.1 adds ffmpeg_no_disk additively; ALL Phase 2 crypto tests must stay green.

## Locked decisions (do not relitigate)
1. Rust in the measured path. No async runtime in sched/worker/crypto/verify hot paths.
2. NO ingest API. bench injects workloads directly. There is no `api` crate.
3. `verifier` is a SEPARATE BINARY. Never put ffmpeg re-execution inside `sched`.
4. Comparator is SSIM + calibrated ROC threshold. NOT pHash.
5. Single host, N pinned workers, loopback, local blob store. Documented caveat.
6. Trusted-verifier capacity + probabilistic sampling. Never verify on untrusted workers.
7. core is SANS-IO and is FROZEN at the end of Phase 1. Until then, shape only.

## Hard rules (Phase 4)
1. sched is #![forbid(unsafe_code)]. All unsafe stays only in crypto::sys. No async/tokio.
2. Every state-mutating store op is ATOMIC and EPOCH-FENCED (Lua in Redis): a write whose epoch <
   current lease epoch is REJECTED, no mutation — mirrors core::apply StaleEpoch. Heartbeat too.
3. ONE reclaim authority (reclaim_expired: epoch++ + re-enqueue). NO stream PEL / XAUTOCLAIM second path.
   A heartbeat timeout is a LIVENESS heuristic, NEVER a safety mechanism — fencing is safety.
4. Least-loaded PUSH dispatch; workers never self-select. Priority + aging (no starvation).
   Suspended/banned workers are INELIGIBLE.
5. tier->p with hard floor P_MIN = 0.02 (no worker ever unsampled). Updates ASYMMETRIC: fast distrust on
   fail, slow trust on pass (effective detection = P_hyper × (1 − FAR), FAR ≈ 21%). CommitmentMismatch heaviest.
6. Content-addressed release anchored by Commitment (eager sampled / lazy unsampled). Release keyed by
   content address, never task id. Closes verified-then-swapped TOCTOU.
7. Backpressure caps from Little's law (L = λ × W, W = measured transcode time). Shed at saturation.
8. Store logic is sans-Redis: memory + redis impls held to ONE contract.rs suite (incl. slow-zombie test).
9. Phase 4 deps (sched): proctor_core, redis, rand, thiserror. Nothing else.

## Crypto invariants still in force (Phase 2, do not regress)
- Keys 256-bit, mlock'd, ZeroizeOnDrop, redacted Debug, no Serialize/disk/log surface.
- AES-256-GCM, 12-byte random nonce, AAD = (JobId, SegmentId, Role); auth failure → Err, never plaintext.
- Plaintext NEVER on a disk-backed file: memfd (anonymous RAM), ffmpeg over /proc/self/fd/N only,
  scrubbed + closed on every exit. UNSAFE confined to crypto/src/sys.rs; crypto root #![deny(unsafe_code)].

## Crypto/honesty rules
- Plaintext NEVER on disk; keys NEVER on disk; keys mlock'd and zeroized (not buf.fill(0)).
- No fabricated security claims. THREAT-MODEL.md states what is NOT defended (root-on-worker).
- The SSIM threshold comes from a committed ROC file — never a hardcoded number.

## Dependency allowlist (per phase; add nothing else)
- Phase 0: thiserror only (if needed). No aes-gcm, no redis, no ssim crate yet.
- Phase 1 (core): sha2, serde, postcard, thiserror; proptest dev-only.
- Phase 2 (crypto): aes-gcm, zeroize, libc, getrandom (+ proctor_core, thiserror).
- Phase 3 (verify): proctor_core, crypto, thiserror, sha2, serde, serde_json, statrs.
- Phase 4 (sched): proctor_core, redis, rand, thiserror. Nothing else.
  Added per-session as the modules that use them land (Session 1: proctor_core + thiserror;
  Session 2: + redis (default-features=false, features=["script"], no async runtime);
  rand lands Session 4).
- Later phases add their deps when reached, recorded here at that time.

## Commit discipline (Claude Code commits)
- Conventional Commits <type>(sched): ..., atomic, GREEN tree (contract.rs green at each commit),
  body cites spec/amendment.
- The in-memory impl lands first, then Redis proven against the same contract.rs.
- Never commit red / secrets / media / large binaries. No --no-verify, no force-push, no core/ edits.
- Freeze tag v0.1.0-core-frozen stands; git diff v0.1.0-core-frozen -- core/ MUST stay empty.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, commit(s), change list, STOP.
sched only. NO real worker/verifier binaries (Phase 5), NO chaos sim / single-host run (Phase 6),
NO transcode/crypto/SSIM. Never touch a future phase or core/.
