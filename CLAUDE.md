# proctor — Claude Code guardrail

## What this is
A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers. The transcoding is the vehicle; the three primitives are the deliverable:
probabilistic verification, in-memory shard-scoped crypto, a backpressure-aware
scheduler. The honest confidentiality boundary points at the microVM flagship.

## Authoritative specs (read before any work)
- docs/specs/kickoff-brief.md  — strategy, primitives, DoD, synergy
- docs/specs/phase0-spec.md     — genesis + skeleton (CURRENT until Phase 1)

## Locked decisions (do not relitigate)
1. Rust in the measured path. No async runtime in sched/worker/crypto/verify hot paths.
2. NO ingest API. bench injects workloads directly. There is no `api` crate.
3. `verifier` is a SEPARATE BINARY. Never put ffmpeg re-execution inside `sched`.
4. Comparator is SSIM + calibrated ROC threshold. NOT pHash.
5. Single host, N pinned workers, loopback, local blob store. Documented caveat.
6. Trusted-verifier capacity + probabilistic sampling. Never verify on untrusted workers.
7. core is SANS-IO and will be FROZEN at the end of Phase 1. Until then, shape only.

## Crypto/honesty rules
- Plaintext NEVER on disk; keys NEVER on disk; keys mlock'd and zeroized (not buf.fill(0)).
- No fabricated security claims. THREAT-MODEL.md states what is NOT defended (root-on-worker).
- The SSIM threshold comes from a committed ROC file — never a hardcoded number.

## Dependency allowlist (per phase; add nothing else)
- Phase 0: thiserror only (if needed). No aes-gcm, no redis, no ssim crate yet.
- Later phases add their deps when reached, recorded here at that time.

## Scope discipline
Work ONLY on the given session. No primitive logic in Phase 0 — stubs that compile.
End every session with cargo build + clippy + test, list changes, STOP.
Never touch a future phase's scope.
