# proctor — Claude Code guardrail

## What this is
A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers. The transcoding is the vehicle; the three primitives are the deliverable:
probabilistic verification, in-memory shard-scoped crypto, a backpressure-aware
scheduler. The honest confidentiality boundary points at the microVM flagship.

## Authoritative specs (read before any work)
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md  — amendment changes the math
- docs/specs/phase0/1/2-spec.md  — genesis, core (FROZEN), crypto
- docs/specs/phase3-spec.md      — CURRENT: verify (SSIM, binding, hypergeometric, ROC)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- crypto is NOT frozen: §3.1 adds ffmpeg_no_disk additively; ALL Phase 2 crypto tests must stay green.

## Locked decisions (do not relitigate)
1. Rust in the measured path. No async runtime in sched/worker/crypto/verify hot paths.
2. NO ingest API. bench injects workloads directly. There is no `api` crate.
3. `verifier` is a SEPARATE BINARY. Never put ffmpeg re-execution inside `sched`.
4. Comparator is SSIM + calibrated ROC threshold. NOT pHash.
5. Single host, N pinned workers, loopback, local blob store. Documented caveat.
6. Trusted-verifier capacity + probabilistic sampling. Never verify on untrusted workers.
7. core is SANS-IO and is FROZEN at the end of Phase 1. Until then, shape only.

## Hard rules (Phase 3)
1. verify is #![forbid(unsafe_code)]. All unsafe stays only in crypto::sys.
2. Commitment binding = core::Commitment::commit(&[SHA-256(ciphertext)]) (single leaf, frozen API).
   Check binding BEFORE choosing challenge frames. Release is content-addressed (OutputRef = blob hash).
3. Comparator is hand-rolled SSIM on luma. No SSIM crate. Document window + C1/C2.
4. Detection is EXACT HYPERGEOMETRIC: P=1−C(n−m,k)/C(n,k). Binomial only for the divergence plot.
   Publish a family P_detect(f,n;p_tier) with a hard floor P_MIN (k≥1 for every worker, incl. pristine).
5. Threshold comes from bench/results/verify/roc-threshold.json, NEVER a literal. VerifyDetail is
   categorical — no numeric threshold on the wire.
6. ROC study: calibration/held-out DISJOINT; FAR/FRR with 95% Clopper–Pearson CIs; ≥3-strata FRR with
   honest caveat. No point estimate without an interval. CSVs are source of truth.
7. Phase 3 deps (verify): proctor_core, crypto, thiserror, sha2, serde, serde_json, statrs. No unsafe/async/SSIM-crate.
8. All media stays in memfds; verify flow opens no plaintext disk file.

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
  Added per-session as the modules that use them land (Session 1: crypto only).
- Later phases add their deps when reached, recorded here at that time.

## Commit discipline (Claude Code commits)
- Conventional Commits <type>(verify|crypto): ..., atomic, GREEN tree, body cites spec/amendment.
- crypto §3.1 refactor is its own commit, landed first.
- Never commit red / secrets / media / large binaries. No --no-verify, no force-push, no core/ edits.
- Freeze = final commit + annotated tag v0.1.0-core-frozen.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, commit(s), change list, STOP.
No adaptive POLICY (Phase 4), no sched, no transport. Never touch a future phase or core/.
