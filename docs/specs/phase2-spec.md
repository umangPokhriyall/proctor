# proctor — Phase 2 Specification: `crypto` — In-Memory AES-256-GCM, Keys Never on Disk

**Companion to:** `kickoff-brief.md`, `phase0-spec.md`, `phase1-spec.md`. Read all three first.
**This is the complete, authoritative Phase 2 spec.** It implements `crypto` — per-segment AES-256-GCM with `mlock`'d, zeroizing keys; decryption into anonymous memory; the **no-plaintext-on-disk** ffmpeg path over `memfd`; and the crypto-overhead microbench that proves confidentiality at this bound is nearly free relative to the transcode.
**Scope:** `crypto/` only, plus a `crypto` microbench target and committed results under `bench/results/crypto/`. No `verify`/`sched`/`verifier`/`worker`/`bench`-orchestration logic. No transport, no TLS, no Redis, no SSIM, no scheduling. `crypto` does **not** fetch keys (it receives them) and does **not** read from the blob store (it operates on byte buffers and file descriptors).
**Audience:** Claude Code. Authoritative. **Claude Code commits its own work** (§10). **ffmpeg is required this phase** (operator-confirmed installed; the Phase 0 corpus is generated and version-recorded).
**Frozen dependency:** `proctor_core` is FROZEN (`v0.1.0-core-frozen`). `crypto` consumes `core::{TargetProfile, JobId, SegmentId, …}` unmodified. If `crypto` appears to need a `core` change, the design is wrong — STOP and ask.

---

## 0. Phase 2 in context, and the honest boundary restated

The legacy repo's `WORKER_SECURITY.md` claimed "zero-knowledge" processing while the worker received the cleartext key and wrote the full plaintext segment to `input.mp4` on disk. That was the audit's most damaging finding. Phase 2 builds the version that is *true* and states precisely what it does and does not defend.

**What this phase defends:** no plaintext segment ever lands on a disk-backed file; no key is ever persisted, logged, or left in freed memory; each segment has a unique key, so a single compromised task leaks exactly one segment; and a ciphertext is cryptographically bound to its segment identity, so it cannot be replayed as another segment or in another role.

**What this phase does NOT defend, stated plainly (and already in `docs/THREAT-MODEL.md`):** a **root-capable worker** defeats confidentiality — it can `ptrace` ffmpeg, read the process's anonymous memory, or read the `memfd` through `/proc`. We do not pretend otherwise. Closing that gap is the **microVM flagship's** mandate, not this repo's. Saying this is the difference between an artifact a Principal Security Engineer trusts and the fabrication we deleted. Swap is a disk surface; we handle it explicitly (§3, §11) rather than ignore it.

**Human/Claude split:** Claude Code executes the entire phase including commits. The microbench and the no-disk proof require ffmpeg and (for the strongest audit) `strace`/`lsof` on the host; gating rules are in §7–§8.

---

## 1. Phase 2 in one paragraph

Implement `crypto` as five modules — `sys` (the **only** unsafe-bearing file: `memfd_create` and `mlock`/`munlock` FFI, isolated and audited), `key` (`SecretKey`: 256-bit, `mlock`'d, `ZeroizeOnDrop`, no byte-leaking `Debug`, OS-CSPRNG generation), `aead` (AES-256-GCM with a 12-byte random nonce, the `EncryptedSegment` at-rest layout, and AAD bound to segment identity), `memfd` (the `MemFd` anonymous-RAM wrapper and the fd hand-off to a child process), and `transcode` (the ffmpeg invocation that reads and writes only anonymous fds, mapping the frozen `core::TargetProfile` to ffmpeg arguments). Then prove the no-plaintext-on-disk property with a committed fd-enumeration test plus an optional `strace` audit, and measure the crypto overhead — AES-GCM throughput (GB/s, AES-NI confirmed), per-segment decrypt+encrypt latency distributions, the `memfd` path vs a naive disk path, and the headline: **crypto as a percentage of transcode time** — committing every number to `bench/results/crypto/`.

### 1.1 Frozen / consumed
- `proctor_core` is consumed unmodified: `TargetProfile` drives the ffmpeg args; `JobId`/`SegmentId` form the AAD; `SegmentRef`/`OutputRef` are opaque handles. No `core` edits.
- Every other crate keeps `#![forbid(unsafe_code)]`. `crypto` is the sole crate permitted unsafe, confined to `crypto/src/sys.rs` (§2).
- `crypto` is **not** sans-IO — it spawns processes, manages fds, reads the clock for benchmarks. Only `core` is sans-IO. That boundary is unchanged.

---

## 2. `crypto` module layout, dependency allowlist, and the unsafe boundary

```
crypto/src/
  lib.rs        # crate docs + #![deny(unsafe_code)] + re-exports
  sys.rs        # the ONLY unsafe: memfd_create, mlock/munlock FFI — #[allow(unsafe_code)], every block // SAFETY:
  key.rs        # SecretKey (mlock'd, ZeroizeOnDrop, redacted Debug), generation
  aead.rs       # AES-256-GCM, EncryptedSegment layout, nonce policy, AAD binding, SecretBuf
  memfd.rs      # MemFd anonymous-RAM wrapper; decrypt-into-memfd; child fd hand-off
  transcode.rs  # ffmpeg over anonymous fds (no disk); core::TargetProfile -> args
crypto/benches/ (or examples/) crypto_overhead.rs   # the microbench (§8)
bench/results/crypto/                                # committed CSVs + methodology note
```

**Dependency allowlist — Phase 2 adds exactly these to `crypto`:**
- `aes-gcm` (RustCrypto) — AES-256-GCM AEAD; pulls `aes` with runtime AES-NI / ARMv8-crypto detection. Runtime.
- `zeroize` (with `derive`) — volatile, un-elidable zeroization; `ZeroizeOnDrop`. Runtime.
- `libc` — `memfd_create`, `mlock`, `munlock`. Runtime, used only in `sys.rs`.
- `getrandom` — OS CSPRNG for key and nonce bytes (no `rand` needed; construct keys/nonces from raw bytes). Runtime.
- `proctor_core`, `thiserror` — already present.

Nothing else. No `tokio`, no async runtime, no `redis`, no `rand`. The microbench target uses `std` only (`std::process::Command`, `std::time::Instant`); percentiles are computed by sorting samples — no stats crate.

**The unsafe boundary (a deliberate Principal-level call):** `mlock` and `memfd_create` are libc FFI and require `unsafe`; a zero-unsafe invariant is therefore impossible in `crypto` and pretending otherwise would mean using a wrapper crate that hides the same `unsafe` behind someone else's audit. Instead: `crypto/src/lib.rs` carries `#![deny(unsafe_code)]`; **only** `crypto/src/sys.rs` carries `#[allow(unsafe_code)]`; every `unsafe` block in it has a `// SAFETY:` comment justifying the invariant it upholds. The audited unsafe surface is one small file. `core`, `verify`, `sched`, `verifier`, `worker` keep `#![forbid(unsafe_code)]`.

---

## 3. `key.rs` — the key lifecycle

```rust
/// A 256-bit AES key. mlock'd against swap on construction; zeroized and munlock'd on drop.
/// No Debug/Display that prints bytes; no Serialize; never logged; never written to disk.
pub struct SecretKey { /* mlock'd, zeroize-on-drop backing */ }

impl SecretKey {
    /// Fresh key from the OS CSPRNG (getrandom). The only constructor used in production.
    pub fn generate() -> Result<Self, CryptoError>;
    /// Test-only / key-injection constructor. #[cfg(test)] or clearly documented.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError>;
}
```

- **mlock mandatory.** On construction, `mlock` the key's pages so they cannot swap to disk. On drop, zeroize then `munlock`. If `mlock` fails (e.g., `RLIMIT_MEMLOCK`), construction returns `Err` — a key that could swap is not silently accepted. Document the `RLIMIT_MEMLOCK` requirement for the worker.
- **No leakage surface.** Manual `Debug` prints `SecretKey(REDACTED)`. No `Serialize`/`Deserialize`, no `Display`, no `AsRef<[u8]>` that escapes the module uncontrolled. Bytes are reachable only through the `aead` operations in this crate.
- **Per-segment uniqueness** is a usage invariant enforced by callers (the preprocessor/worker generate one key per segment); `crypto` provides `generate()` per segment and never reuses.

**Rejected alternative:** `Vec<u8>` + `buf.fill(0)` on drop (the legacy approach). Rejected — the optimizer is free to elide a final write to memory that is about to be freed; `zeroize` performs a volatile write that cannot be elided. The legacy "secure delete" was theater; this is the real thing.

---

## 4. `aead.rs` — AES-256-GCM, identity-bound

```rust
/// At-rest / on-wire layout of an encrypted segment: nonce(12) || ciphertext || tag(16).
pub struct EncryptedSegment { /* nonce: [u8;12], body: Vec<u8> (ciphertext||tag) */ }
impl EncryptedSegment {
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError>;
}

/// AAD binds the ciphertext to its identity and role so it cannot be replayed
/// as another segment or as output-posing-as-source.
pub struct SegmentAad { pub job: JobId, pub segment: SegmentId, pub role: Role } // Role { Source, Output }

pub fn encrypt(plaintext: &[u8], key: &SecretKey, aad: &SegmentAad) -> Result<EncryptedSegment, CryptoError>;

/// Decrypts into a SecretBuf (mlock'd, zeroize-on-drop). Authentication failure ⇒ Err, no plaintext returned.
pub fn decrypt(enc: &EncryptedSegment, key: &SecretKey, aad: &SegmentAad) -> Result<SecretBuf, CryptoError>;

/// mlock'd, zeroize-on-drop plaintext buffer.
pub struct SecretBuf { /* ... */ }
```

- **Nonce: 12 bytes, random, via getrandom, prepended.** Twelve is the standard GCM nonce; the legacy 16-byte IV forced GHASH to re-derive the nonce and was non-standard — this fixes that audit finding. With a unique key per segment a fixed nonce would be safe, but a random 96-bit nonce is defense-in-depth against any accidental key reuse.
- **AAD bound to `(JobId, SegmentId, Role)`** (canonical fixed-layout bytes, using frozen `core` ids). A `Source` ciphertext cannot be accepted where an `Output` is expected, and a segment's ciphertext cannot be swapped for another's — the GCM tag covers the identity.
- **Single-shot AEAD per segment.** Segments are GOP-bounded (≈2 s); the whole plaintext fits in RAM, so one AEAD operation per segment — no chunked STREAM construction. Document the bounded-segment assumption.
- **Authentication is mandatory and failure is silent of plaintext.** A wrong key, nonce, tag, or AAD yields `Err(AuthFailed)` and never returns partial plaintext.

---

## 5. `memfd.rs` — anonymous RAM, never a disk path

```rust
/// An anonymous, RAM-backed file (memfd_create). Seekable (so any container works),
/// never present in the filesystem namespace, referenced only via /proc/self/fd/N.
pub struct MemFd { /* OwnedFd + name */ }
impl MemFd {
    pub fn create(name: &str) -> Result<Self, CryptoError>;          // sys.rs
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), CryptoError>;
    pub fn read_to_secret_buf(&mut self) -> Result<SecretBuf, CryptoError>;
    pub fn proc_path(&self) -> String;                              // "/proc/self/fd/N"
    /// Zeroize contents (overwrite + ftruncate(0)) before the fd is closed on drop.
    pub fn zeroize_and_close(self);
}

/// Decrypt straight into anonymous RAM — plaintext never exists as an owned Vec longer than necessary.
pub fn decrypt_into_memfd(enc: &EncryptedSegment, key: &SecretKey, aad: &SegmentAad, name: &str)
    -> Result<MemFd, CryptoError>;
```

- **Why `memfd` over pipes or `/dev/shm` (rejected alternatives):** a pipe (`pipe:0`) is non-seekable, so any container whose index is not at the front (default MP4 `moov` at the end) fails or forces full buffering — fragile and container-dependent. `/dev/shm` is a real tmpfs path that appears in the filesystem namespace and can be opened by any process with access. `memfd_create` gives a **seekable, anonymous** RAM file reachable only through the owning process's fd table — container-agnostic and not nameable from outside. It is the correct primitive.
- **Swap.** `memfd` pages are anonymous and can swap under memory pressure (a disk surface). Mitigation: keys are always `mlock`'d (§3); for plaintext `memfd`s, the worker runs with swap disabled or under a memory-locked cgroup — documented as a deployment requirement and recorded as a residual in `THREAT-MODEL.md`. We state this; we do not hide it.
- **Child hand-off.** ffmpeg runs as a child process; it must see the `memfd`. The fd is made inheritable (CLOEXEC cleared on the child's copy via the spawn path) and ffmpeg is given `/proc/self/fd/N` as the input/output URL — never a disk path. The fd-table manipulation that requires `unsafe` lives in `sys.rs`.

---

## 6. `transcode.rs` — ffmpeg with no disk surface

```rust
/// Transcode the plaintext in `input` to the target profile, returning the plaintext
/// output in a fresh MemFd. ffmpeg reads /proc/self/fd/<in> and writes /proc/self/fd/<out>;
/// no plaintext path ever touches disk. Uses the FROZEN core::TargetProfile to build args.
pub fn transcode_no_disk(input: &MemFd, profile: &core::TargetProfile)
    -> Result<MemFd, CryptoError>;
```

- **TargetProfile → ffmpeg args** (codec, resolution, bitrate, container) is a pure mapping in this module, consuming the frozen `core` type. Output container must be seekable-via-`memfd` or fragmented/streamable; document the choice.
- **No `-i input.mp4` disk paths, ever.** Input and output are `/proc/self/fd/N` referring to `MemFd`s. The decrypted plaintext and the transcoded plaintext exist only in anonymous RAM.
- **Robustness:** non-zero ffmpeg exit ⇒ `Err(TranscodeFailed{stderr_tail})` (capture a bounded tail of stderr, never the media); a wall-clock timeout kills the child (a hostile/oversized input must not hang a worker); on any exit path, both `MemFd`s are `zeroize_and_close`d. No `global.gc()`/DoD-5220 theater — the property is "plaintext lived only in anonymous RAM and was overwritten," not ritual.

---

## 7. The no-plaintext-on-disk proof (the headline remediation)

This is the artifact that refutes the deleted `WORKER_SECURITY.md` with evidence rather than prose. Two tiers, both committed.

1. **Programmatic fd-enumeration test (portable, always runs).** During a full `decrypt_into_memfd → transcode_no_disk → encrypt` cycle, enumerate the open file descriptors of the worker process **and** the ffmpeg child (`/proc/<pid>/fd`). Assert that every fd holding plaintext resolves to an anonymous `memfd:` (or pipe), and that **no regular disk-backed file** is opened for the plaintext input or output. The only regular files permitted are the encrypted blobs (ciphertext). Fail the test if any plaintext-bearing fd resolves to a path under a real filesystem.
2. **`strace` audit (stronger, gated on availability).** Run the cycle under `strace -f -e trace=openat,open,creat,memfd_create` and assert the only `openat`/`creat` of writable regular files are the ciphertext blobs; plaintext appears only via `memfd_create`. Commit the trace summary to `bench/results/crypto/no-disk-audit.txt`. If `strace` is unavailable, skip with a loud, recorded note (same honesty discipline as the Phase 0 corpus gating) — never fabricate the trace.

The committed evidence (the passing test + the trace summary) is referenced by `docs/THREAT-MODEL.md` as the proof behind the confidentiality claim.

---

## 8. The crypto-overhead microbench

Measure, never guess. Governed by the Writing Standard (declarative, every number with units and conditions, no marketing language, honesty about what surprised us). Output: CSVs + a short `bench/results/crypto/METHODOLOGY.md`. Distributions, not just means.

Measure over the Phase 0 corpus (`gradient`/`detail`/`motion`), segmented to ≈2 s, across at least two representative profile steps (e.g., 1080p→720p, 720p→480p):

1. **AEAD throughput (GB/s).** Encrypt and decrypt throughput on representative segment sizes. Confirm AES-NI is engaged (report the `aes` backend / a cpuid note). **Optional, honest if feasible:** a forced-software comparison (the `aes` crate `force-soft` feature) to quantify the AES-NI speedup; if not cleanly feasible, report achieved hardware throughput and state that the software comparison was not run.
2. **Per-segment crypto latency** (decrypt + encrypt), as a distribution: p50 / p99 / p99.9 over many segments, per profile. Commit raw samples + summary CSV.
3. **The headline — crypto as a percentage of transcode time.** For each segment: ffmpeg `transcode_no_disk` wall time vs the decrypt+encrypt time. Report the ratio per profile. The expected and intended result is that crypto is a small single-digit percentage — i.e., confidentiality at this bound is nearly free relative to the encode. State the number, whatever it is.
4. **`memfd` path vs naive disk path.** Compare end-to-end latency of the anonymous-RAM path against a (test-only) decrypt-to-disk → ffmpeg-from-file → encrypt path. The disk path is what the legacy code did; show the `memfd` path's latency delta (expected: negligible or favorable) **and** that only the `memfd` path passes §7. This converts the security fix into a measured, defensible decision rather than an assertion.

Every figure cites its source CSV. The polished writeup folds into `docs/BENCHMARKS.md` at close-out; Phase 2 commits the numbers and the methodology note.

---

## 9. Correctness & purity rules (verify before commit)

- **Unsafe isolation:** grep confirms `unsafe` appears only in `crypto/src/sys.rs`; every block has a `// SAFETY:` comment; all other crates still `#![forbid(unsafe_code)]`.
- **AEAD tests:** round-trip (`decrypt(encrypt(p)) == p`); tamper tests — wrong key, flipped ciphertext bit, wrong nonce, wrong AAD (`Source` vs `Output`, wrong `SegmentId`) each yield `Err(AuthFailed)` and never plaintext.
- **Zeroization:** a test demonstrating `SecretKey`/`SecretBuf` backing memory is zeroized on drop (e.g., via a controlled allocation probe or a `zeroize` unit assertion); no `Debug`/`Serialize` leaks key bytes (grep + a compile-fail or manual check).
- **No disk surface:** §7 tier-1 test passes; tier-2 committed when `strace` present.
- **`core` untouched:** `git diff` shows no change under `core/`; `v0.1.0-core-frozen` still describes `core`.
- `cargo build && cargo clippy --all-targets -- -D warnings && cargo test` clean; allowlist (§2) respected — `crypto` runtime deps are exactly `aes-gcm`, `zeroize`, `libc`, `getrandom`, `proctor_core`, `thiserror`.

---

## 10. Commit discipline (Claude Code commits — §10 of phase1 carried forward)

- Conventional Commits: `<type>(crypto): <imperative>`, ≤72 chars; body cites the spec section (`Refs: docs/specs/phase2-spec.md §4`) and states the rejected alternative where a non-obvious call was made.
- Atomic, one logical change per commit, each on a green tree (`build && clippy -D warnings && test`). Never commit red. No `--no-verify`. No force-push/rewrite of `main`. No secrets, no media, no large binaries committed (the corpus stays as generated; commit CSVs and the text trace summary, not video).
- Suggested sequence maps to the §B sessions: key+aead → sys+memfd+transcode → no-disk proof → microbench.

---

## 11. Phase 2 Definition of Done

1. `crypto` implements `sys`, `key`, `aead`, `memfd`, `transcode` per §2–§6; `SecretKey` is `mlock`'d and `ZeroizeOnDrop` with a redacted `Debug` and no serialize/disk surface.
2. AES-256-GCM with a 12-byte random nonce and AAD bound to `(JobId, SegmentId, Role)`; the `EncryptedSegment` layout round-trips; all tamper tests fail closed (§9).
3. The no-disk ffmpeg path works over `memfd` (input and output `/proc/self/fd/N`, never a disk path), built from the frozen `core::TargetProfile`; ffmpeg failure/timeout handled, both `MemFd`s zeroized on every exit.
4. The no-plaintext-on-disk proof (§7): tier-1 fd-enumeration test passes; tier-2 `strace` audit committed to `bench/results/crypto/no-disk-audit.txt` (or skip loudly recorded).
5. Crypto-overhead microbench (§8) committed to `bench/results/crypto/`: AEAD GB/s (AES-NI confirmed), per-segment latency distributions, **crypto-as-%-of-transcode**, and the `memfd`-vs-disk comparison, with `METHODOLOGY.md`. Every figure cites its CSV.
6. Unsafe confined to `crypto/src/sys.rs` with `// SAFETY:` on every block; all other crates `#![forbid(unsafe_code)]`; `crypto` crate root `#![deny(unsafe_code)]`.
7. `core` byte-for-byte unchanged since the freeze; allowlist (§2) respected; `build && clippy -D warnings && test` clean.
8. Commits follow §10; `docs/THREAT-MODEL.md` updated to reference the §7 proof and the swap residual.

Next: `phase3-spec.md` — `verify`: the SSIM comparator, the committed ROC/separation study that sets the threshold (never a constant), commit-reveal verification against `core::commit::verify_inclusion`, and the detection-probability math. The security centerpiece.

---

# Appendix A — `CLAUDE.md` update for Phase 2

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md  — strategy, primitives, DoD, synergy
- docs/specs/phase0-spec.md    — genesis + skeleton
- docs/specs/phase1-spec.md    — proctor_core (FROZEN @ v0.1.0-core-frozen)
- docs/specs/phase2-spec.md    — CURRENT: crypto (in-memory AES-256-GCM, no disk)

## Frozen
- proctor_core is FROZEN. crypto consumes core::{TargetProfile, JobId, SegmentId, ...}
  UNCHANGED. If a phase seems to need a core change, the phase is wrong — STOP and ask.

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

## Commit discipline (Claude Code commits)
- Conventional Commits <type>(crypto): ..., atomic, GREEN tree, body cites the spec.
- Never commit red / secrets / media / large binaries. No --no-verify, no force-push.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, the commit(s), a change
list, and STOP. Never touch a future phase or core/.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1 | Keys + AEAD | `key.rs`, `aead.rs` (+ `SecretBuf`) | round-trip + all tamper tests fail closed; zeroize/redaction tested; commit |
| 2 | No-disk path | `sys.rs`, `memfd.rs`, `transcode.rs` | ffmpeg transcodes over memfds, no disk path; failure/timeout handled; commit |
| 3 | No-disk proof | §7 fd-enumeration test + optional strace audit | tier-1 passes; tier-2 committed or skip recorded; commit |
| 4 | Microbench | `crypto_overhead` target + `bench/results/crypto/` | GB/s + latency dist + %-of-transcode + memfd-vs-disk committed with METHODOLOGY.md; commit |

Session 2 is the heavy one (FFI + child fd hand-off) — if context grows, split at the `memfd` / `transcode` boundary, committing `sys.rs` + `memfd.rs` before `transcode.rs`.

### Exact prompts (paste one per session; verify + commit before the next)

**Session 1**
> Read `docs/specs/kickoff-brief.md` §2.2, `docs/specs/phase2-spec.md` (§2–§4, §9–§11), and `CLAUDE.md`. Update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: implement `crypto/src/key.rs` (`SecretKey`: 256-bit, `mlock`'d via `sys.rs`, `ZeroizeOnDrop`, redacted `Debug`, getrandom `generate`, test-only `from_bytes`) and `crypto/src/aead.rs` (AES-256-GCM, 12-byte random nonce, `EncryptedSegment` layout, `SegmentAad` bound to `(JobId, SegmentId, Role)` using frozen `core` ids, `encrypt`/`decrypt`, `SecretBuf`). Add only the §2 deps you need this session. Tests: round-trip, tamper (wrong key/nonce/tag/AAD ⇒ `Err`, no plaintext), zeroize, no-leak `Debug`. Keep `unsafe` only in `sys.rs` with `// SAFETY:`; do not touch `core/`. Build + clippy `-D warnings` + test; commit per §10; list changes and STOP.

**Session 2**
> Read `CLAUDE.md` and `phase2-spec.md` §5–§6, §9. Execute **Session 2 only**: implement `crypto/src/sys.rs` (the only unsafe file: `memfd_create`, `mlock`/`munlock` with `// SAFETY:` on each block), `crypto/src/memfd.rs` (`MemFd`, `decrypt_into_memfd`, child fd hand-off via `/proc/self/fd/N`, `zeroize_and_close`), and `crypto/src/transcode.rs` (`transcode_no_disk` spawning ffmpeg over input/output memfds, mapping the frozen `core::TargetProfile` to args, ffmpeg failure/timeout handling, memfds zeroized on every exit). No disk path for plaintext, ever. Build + clippy + test (ffmpeg present); commit per §10; list changes and STOP.

**Session 3**
> Read `CLAUDE.md` and `phase2-spec.md` §7, §9. Execute **Session 3 only**: implement the no-plaintext-on-disk proof — the tier-1 fd-enumeration test over a full `decrypt_into_memfd → transcode_no_disk → encrypt` cycle (assert no plaintext-bearing fd resolves to a disk file; only ciphertext blobs may be regular files), and the tier-2 `strace -f` audit committed to `bench/results/crypto/no-disk-audit.txt` (or skip with a loud recorded note if `strace` is absent). Update `docs/THREAT-MODEL.md` to cite this proof and the swap residual. Build + clippy + test; commit per §10; list changes and STOP.

**Session 4**
> Read `CLAUDE.md` and `phase2-spec.md` §8, and the Writing Standard discipline. Execute **Session 4 only**: implement the `crypto_overhead` microbench over the Phase 0 corpus across ≥2 profile steps, and commit to `bench/results/crypto/`: AEAD encrypt/decrypt GB/s (confirm AES-NI; optional forced-software comparison), per-segment decrypt+encrypt latency distributions (p50/p99/p99.9, raw + summary CSV), **crypto-as-%-of-transcode** per profile, and the `memfd`-vs-disk end-to-end comparison — plus `METHODOLOGY.md`. Every figure cites its CSV; state results declaratively with units and conditions; no marketing language. Build + clippy + test; commit per §10; verify the Phase 2 DoD §11 item by item and report each. STOP.
