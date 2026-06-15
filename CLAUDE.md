# proctor — Claude Code guardrail

## What this is
A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers. The transcoding is the vehicle; the three primitives are the deliverable:
probabilistic verification, in-memory shard-scoped crypto, a backpressure-aware
scheduler. The honest confidentiality boundary points at the microVM flagship.

## Authoritative specs (read before any work)
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md  — amendment changes the math
- docs/specs/phase0–3-spec.md  — genesis, core (FROZEN), crypto, verify (SSIM, binding, hypergeometric, ROC)
- docs/specs/phase4-spec.md    — sched (epoch-fenced Redis store, push dispatch, policy, backpressure)
- docs/specs/phase5-spec.md    — CURRENT: worker + verifier binaries (the live data plane)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- core::Task::apply is the transition authority; sched executes the TaskActions it returns.
- crypto/verify/sched are NOT frozen: §3/§4/§5 add seams ADDITIVELY; ALL prior-phase tests must stay green.

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

## Hard rules (Phase 5)
1. worker and verifier are #![forbid(unsafe_code)]. All unsafe stays only in crypto::sys. NO async/tokio
   anywhere (std threads + blocking redis).
2. Worker concurrency = min(cap, cgroup cpu.max). NEVER host loadavg/num_cpus (the legacy bug).
3. Plaintext NEVER on disk (inherited from crypto): decrypt into memfd, transcode_no_disk, encrypt in RAM.
   Ciphertext and benchmark keys on disk are fine. Keys + memfds zeroized on every path.
4. Worker commitment = core::Commitment::commit(&[SHA-256(ciphertext)]); output = lead128(SHA-256). MUST
   match verify::check_binding and sched content-addressing. Submit + heartbeat CARRY the lease epoch.
5. Verifier: bind (check_binding) BEFORE any challenge frame. Threshold from roc-threshold.json, never a
   literal. BATCHED decode (one ffmpeg call for all sampled frames) — no per-frame spawn (Phase 3 cost fix).
   Stitch verification is integrity, no SSIM.
6. KeySource is the key-delivery seam: LocalKeySource for the benchmark; production = TLS (NOT built).
   Worker-auth / anti-Sybil is a documented non-goal. The worker holds the key (documented confidentiality
   boundary; root-on-worker defeats it; the microVM closes it).
7. Live engine applies rich VerifyDetail via reputation::record_verdict (CommitmentMismatch heaviest);
   sched:inbound is the return channel. Phase 4 sched + contract suites stay green.
8. Phase 5 deps: worker {proctor_core, crypto, redis, sha2, thiserror}; verifier {+verify}. Crypto seams add
   ONLY sha2 (workspace-pinned, already used by core) to content-address by lead128(SHA-256(ciphertext)).

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
  Session 4: + rand 0.8 (Bernoulli verify-sampling, injectable RNG)). Full set now present.
- Phase 5 (worker): proctor_core, crypto, redis, sha2, thiserror. (verifier): + verify.
  Crypto/verify/sched additive seams add NO new deps EXCEPT crypto gains sha2 (workspace-pinned, the same
  hash core/verify use) so blob.rs can content-address by lead128(SHA-256(ciphertext)) — core is frozen and
  exposes only the folded Merkle root, not the raw leaf. Added per-session: Session 1 = crypto + sha2.
- Later phases add their deps when reached, recorded here at that time.

## Commit discipline (Claude Code commits)
- Conventional Commits <type>(sched): ..., atomic, GREEN tree (contract.rs green at each commit),
  body cites spec/amendment.
- The in-memory impl lands first, then Redis proven against the same contract.rs.
- Never commit red / secrets / media / large binaries. No --no-verify, no force-push, no core/ edits.
- Freeze tag v0.1.0-core-frozen stands; git diff v0.1.0-core-frozen -- core/ MUST stay empty.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, commit(s), change list, STOP.
Phase 5 = worker + verifier + the named additive seams (crypto::blob, crypto::keysource, verify::frame
batch, verify::integrity, sched::{loops,engine}) + the live smoke run only. NO full measurement / chaos /
adversary suite (Phase 6). Never touch a future phase or core/.
