# proctor — Claude Code guardrail

## What this is
A zero-trust control plane for verifiable, confidential transcoding on untrusted
workers. The transcoding is the vehicle; the three primitives are the deliverable:
probabilistic verification, in-memory shard-scoped crypto, a backpressure-aware
scheduler. The honest confidentiality boundary points at the microVM flagship.

## Authoritative specs (read before any work)
- docs/specs/kickoff-brief.md  — strategy, primitives, DoD, synergy
- docs/specs/phase0-spec.md    — genesis + skeleton
- docs/specs/phase1-spec.md    — proctor_core (FROZEN @ v0.1.0-core-frozen)
- docs/specs/phase2-spec.md    — CURRENT: crypto (in-memory AES-256-GCM, no disk)

## Frozen
- proctor_core is FROZEN. crypto consumes core::{TargetProfile, JobId, SegmentId, ...}
  UNCHANGED. If a phase seems to need a core change, the phase is wrong — STOP and ask.

## Locked decisions (do not relitigate)
1. Rust in the measured path. No async runtime in sched/worker/crypto/verify hot paths.
2. NO ingest API. bench injects workloads directly. There is no `api` crate.
3. `verifier` is a SEPARATE BINARY. Never put ffmpeg re-execution inside `sched`.
4. Comparator is SSIM + calibrated ROC threshold. NOT pHash.
5. Single host, N pinned workers, loopback, local blob store. Documented caveat.
6. Trusted-verifier capacity + probabilistic sampling. Never verify on untrusted workers.
7. core is SANS-IO and is FROZEN at the end of Phase 1. Until then, shape only.

## Hard rules (Phase 2)
1. Keys: 256-bit, mlock'd (fail construction if mlock fails), ZeroizeOnDrop, redacted
   Debug, NO Serialize/Display/disk/log surface. Per-segment unique.
2. AES-256-GCM: 12-byte random nonce; AAD bound to (JobId, SegmentId, Role). Auth
   failure returns Err, never plaintext. Single-shot per GOP-bounded segment.
3. Plaintext NEVER on a disk-backed file. Decrypt into a memfd (anonymous RAM);
   ffmpeg reads/writes /proc/self/fd/N only. memfd zeroized + closed on every exit.
   Swap is a disk surface: keys mlock'd; workers run swap-off / memory-locked cgroup.
4. UNSAFE only in crypto/src/sys.rs (#[allow(unsafe_code)], // SAFETY: on each block).
   crypto root #![deny(unsafe_code)]; every other crate #![forbid(unsafe_code)].
5. Phase 2 deps (crypto): aes-gcm, zeroize, libc, getrandom (+ proctor_core, thiserror).
   No tokio/async/redis/rand.
6. No DoD-5220 / global.gc() theater. The property is "plaintext only in anonymous RAM,
   overwritten on exit" — proven by the §7 fd-enumeration test, not ritual.
7. Measure, never guess: commit AEAD GB/s, latency distributions (p50/p99/p99.9), and
   crypto-as-%-of-transcode to bench/results/crypto/. Writing Standard applies.

## Crypto/honesty rules
- Plaintext NEVER on disk; keys NEVER on disk; keys mlock'd and zeroized (not buf.fill(0)).
- No fabricated security claims. THREAT-MODEL.md states what is NOT defended (root-on-worker).
- The SSIM threshold comes from a committed ROC file — never a hardcoded number.

## Dependency allowlist (per phase; add nothing else)
- Phase 0: thiserror only (if needed). No aes-gcm, no redis, no ssim crate yet.
- Phase 1 (core): sha2, serde, postcard, thiserror; proptest dev-only.
- Phase 2 (crypto): aes-gcm, zeroize, libc, getrandom (+ proctor_core, thiserror).
- Later phases add their deps when reached, recorded here at that time.

## Commit discipline (Claude Code commits)
- Conventional Commits <type>(crypto): ..., atomic, GREEN tree, body cites the spec.
- Never commit red / secrets / media / large binaries. No --no-verify, no force-push.
- Freeze = final commit + annotated tag v0.1.0-core-frozen.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, the commit(s), a change
list, and STOP. Never touch a future phase or core/.
