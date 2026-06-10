# proctor — Claude Code guardrail

## What this is
A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers. The transcoding is the vehicle; the three primitives are the deliverable:
probabilistic verification, in-memory shard-scoped crypto, a backpressure-aware
scheduler. The honest confidentiality boundary points at the microVM flagship.

## Authoritative specs (read before any work)
- docs/specs/kickoff-brief.md  — strategy, primitives, DoD, synergy
- docs/specs/phase0-spec.md    — genesis + skeleton
- docs/specs/phase1-spec.md    — CURRENT: proctor_core state machine + protocol (FREEZE)

## Frozen
- proctor_core is FROZEN after Phase 1's tag v0.1.0-core-frozen. It must drive
  crypto/verify/sched/verifier/worker UNCHANGED. If a later phase seems to need a
  core change, the later phase is wrong — STOP and ask.

## Locked decisions (do not relitigate)
1. Rust in the measured path. No async runtime in sched/worker/crypto/verify hot paths.
2. NO ingest API. bench injects workloads directly. There is no `api` crate.
3. `verifier` is a SEPARATE BINARY. Never put ffmpeg re-execution inside `sched`.
4. Comparator is SSIM + calibrated ROC threshold. NOT pHash.
5. Single host, N pinned workers, loopback, local blob store. Documented caveat.
6. Trusted-verifier capacity + probabilistic sampling. Never verify on untrusted workers.
7. core is SANS-IO and is FROZEN at the end of Phase 1. Until then, shape only.

## Hard rules (Phase 1)
1. core is SANS-IO: no std::net/fs/time, no tokio/redis/rand, no logging, no
   key material, no plaintext. Time and randomness are inputs.
2. TaskKind = { Transcode, Stitch } — distinct variants, never string prefixes.
3. Lease carries a monotonic Epoch (fencing token). Stale-epoch holder-actions
   are REJECTED, state unchanged. This kills the zombie-worker class of bug.
4. Task::apply implements the §6.2 table exactly. Deterministic, pure.
5. Phase 1 deps (core): sha2, serde, postcard, thiserror; proptest dev-only.
   Add nothing else.

## Crypto/honesty rules
- Plaintext NEVER on disk; keys NEVER on disk; keys mlock'd and zeroized (not buf.fill(0)).
- No fabricated security claims. THREAT-MODEL.md states what is NOT defended (root-on-worker).
- The SSIM threshold comes from a committed ROC file — never a hardcoded number.

## Dependency allowlist (per phase; add nothing else)
- Phase 0: thiserror only (if needed). No aes-gcm, no redis, no ssim crate yet.
- Phase 1 (core): sha2, serde, postcard, thiserror; proptest dev-only.
- Later phases add their deps when reached, recorded here at that time.

## Commit discipline (from Phase 1 on, Claude Code commits)
- Conventional Commits: <type>(core): <imperative>, <=72 chars. Body cites the spec.
- Atomic, one logical change per commit, on a GREEN tree (build+clippy -D warnings+test).
- Never commit red. No --no-verify. No force-push/rewrite of main. No secrets/binaries.
- Freeze = final commit + annotated tag v0.1.0-core-frozen.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, the commit(s), a change
list, and STOP. Never touch a future phase's scope.
