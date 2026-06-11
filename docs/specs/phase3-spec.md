# proctor — Phase 3 Specification: `verify` — SSIM, Commit-Binding, and Falsifiable Detection

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0/1/2-spec.md`. Read the amendment first — it changes the math.
**This is the complete, authoritative Phase 3 spec.** It implements `verify` — the trusted re-execution comparator (SSIM), the enforced commit-binding chain, the **hypergeometric** detection-probability family with a sampling floor, and the **calibration/held-out ROC study** that sets the threshold with confidence intervals and per-stratum FRR. This is the security centerpiece: it earns the "verifiable compute" claim the legacy repo only pretended to.
**Scope:** `verify/` plus one **additive** primitive in `crypto` (§3.1), the verify eval target, and committed artifacts under `bench/results/verify/`. No `sched`/`verifier`-binary/`worker` logic, no transport, no adaptive *policy* (that is Phase 4 — Phase 3 publishes the *math* the policy will use).
**Audience:** Claude Code. Authoritative. **Claude Code commits its own work.** **ffmpeg required.**
**Frozen:** `proctor_core` is FROZEN (`v0.1.0-core-frozen`); `git diff v0.1.0-core-frozen -- core/` stays empty. `crypto` is **not** frozen — §3.1 extends it additively, and `crypto`'s Phase 2 tests must stay green (regression guard).

---

## 0. Phase 3 in context, and exactly what the verifier does

The legacy verification was theater three ways (the audit): it emitted the expected answer to the worker, its threshold was a near-unconditional accept, and a single-frame perceptual hash verified nothing about the transcode. This phase builds the honest version and, per the amendment, makes its claims *falsifiable* — a threshold chosen on a calibration set and reported on a disjoint held-out set with confidence intervals, and an exact hypergeometric detection curve rather than a binomial that overstates.

**The verifier's algorithm for one segment (trusted, CPU-bound, no disk):**
1. **Bind** (1.2.4): download the worker's encrypted output blob; check `Commitment::commit(&[SHA-256(blob)]) == submitted_commitment` (frozen single-leaf Merkle). Mismatch ⇒ reject. Only *after* binding does the verifier choose challenge frames — the blob is frozen, so the worker could not have predicted them.
2. **Reconstruct ground truth:** decrypt the source segment (`crypto::decrypt_into_memfd`, `Role::Source`) and independently transcode it with the same frozen `core::TargetProfile` (`crypto::transcode_no_disk`) → the verifier's reference output, in anonymous RAM.
3. **Compare:** decrypt the worker's output (`Role::Output`); at randomly chosen frame timestamps, extract Y-plane frames from the worker output and the reference and compute **SSIM**; the segment's score is the **minimum** MSSIM across sampled frames (conservative — catches localized frame-substitution).
4. **Decide:** pass iff score ≥ the threshold **loaded from the committed ROC file** (never a constant). Emit `core`'s categorical `VerifyDetail` — no numeric threshold on the wire (consistent with the frozen `proto`).

Two faithful transcodes of the same source are not bit-identical (encoder nondeterminism) but are perceptually near-identical (high SSIM); a cheap-downscale, wrong-bitrate, or frame-substitution attack scores low. The gap is what the ROC measures.

**Human/Claude split:** Claude Code executes including commits. The eval target and `strace`-free study run with ffmpeg present.

---

## 1. Phase 3 in one paragraph

Implement `verify` (`#![forbid(unsafe_code)]`) as `ssim` (hand-rolled single-scale SSIM over Y planes — owned, not a black box), `frame` (Y-plane frame extraction at timestamps over `crypto`'s no-disk memfd path), `binding` (the single-leaf commit check against frozen `core::Commitment` + content-addressed `OutputRef`), `compare` (the per-segment verify flow above), `detection` (the exact **hypergeometric** `P_detect(f, n; p)` plus the binomial for the divergence plot, evaluated as a **family over `p_tier` with a hard floor `p_min`**), and `roc` (calibration/held-out split, attack synthesis, threshold selection, **Clopper–Pearson** FAR/FRR intervals, per-stratum FRR). Add one additive no-disk ffmpeg primitive to `crypto` so `verify` extracts frames without its own unsafe. Commit the study — ROC, threshold file, detection curves + divergence, FAR/FRR with CIs, per-stratum FRR, and the verification-cost breakdown — to `bench/results/verify/`.

### 1.1 Frozen / consumed (alignment with the real Phase 2 code)
- `proctor_core` (frozen): `Commitment::commit`/`verify_inclusion` (single-leaf binding), `Challenge` (caller-chosen frame indices), `TargetProfile`, `JobId`/`SegmentId`/`OutputRef`, `VerifyResult`/`VerifyDetail` (categorical, no numeric threshold).
- `crypto` (Phase 2, consumed + §3.1 extended): `decrypt_into_memfd(enc, key, aad, name) → MemFd`, `aead::{EncryptedSegment::from_bytes, decrypt, SegmentAad, Role}`, `transcode_no_disk(&MemFd, &TargetProfile) → MemFd`, `MemFd::{proc_path, read_to_secret_buf, zeroize_and_close}`, `CryptoError`.
- The verifier holds the key as an **injected parameter** — `verify` does not fetch keys (consistent with `crypto`). Everything stays in anonymous RAM; the no-disk property is inherited.

---

## 2. `verify` module layout & Phase 3 dependency allowlist

```
verify/src/
  lib.rs        # #![forbid(unsafe_code)] + re-exports
  ssim.rs       # hand-rolled single-scale SSIM over Y planes -> f64
  frame.rs      # extract Y-plane frames at timestamps from a MemFd (crypto no-disk ffmpeg)
  binding.rs    # single-leaf commit check vs core::Commitment; content-addressed OutputRef
  compare.rs    # per-segment verify flow (§0 steps 1-4); loads RocThreshold from committed file
  detection.rs  # hypergeometric P_detect(f,n;p) + binomial; family over p_tier; p_min floor
  roc.rs        # calibration/held-out split, attack synthesis, threshold pick, Clopper-Pearson CIs, strata
verify/examples/verify_eval.rs    # the study; writes bench/results/verify/*
bench/results/verify/             # ROC, roc-threshold.json, detection curves, FAR/FRR+CIs, strata, cost
```

**Dependency allowlist — Phase 3 adds exactly these to `verify`:**
- `proctor_core`, `crypto` (workspace), `thiserror` — core types, no-disk crypto, errors.
- `sha2` — SHA-256 of the ciphertext blob for the binding leaf.
- `serde` + `serde_json` — read `roc-threshold.json` at runtime; emit study artifacts.
- `statrs` — Hypergeometric distribution and Beta quantiles (Clopper–Pearson) for the study/`detection`/`roc` modules.

No `unsafe` (forbidden), no async, no ffmpeg-FFI (uses `crypto`'s primitive), no SSIM crate (hand-rolled), no plotting runtime dep (commit CSVs; an SVG is optional via a dev-only path). `crypto`'s §3.1 addition needs no new `crypto` dep.

---

## 3. The comparator and its plumbing

### 3.1 Additive `crypto` primitive (so `verify` stays unsafe-free)
`verify` must extract frames by running ffmpeg over memfds, but the fd-inheritance hand-off requires `unsafe`, which lives only in `crypto::sys`. Expose a minimal, additive primitive in `crypto` and refactor `transcode_no_disk` onto it:

```rust
// crypto — additive, keeps all unsafe in crypto::sys
pub fn ffmpeg_no_disk(args: &[std::ffi::OsString], fds: &[&MemFd]) -> Result<(), CryptoError>;
```

- `transcode_no_disk` becomes a thin caller of `ffmpeg_no_disk`. **`crypto`'s Phase 2 tests (round-trip, corpus transcode, garbage-input, the no-disk fd-enumeration test) must still pass** — this is a regression guard, run before and after.
- Commit this as its own `refactor(crypto): expose no-disk ffmpeg primitive` (Conventional Commits, green tree). It is additive, not a freeze concern (`crypto` is not frozen).

### 3.2 `frame.rs` — Y-plane extraction
Extract a single Y (luma) plane at a given timestamp from a plaintext `MemFd` via `crypto::ffmpeg_no_disk` (`-ss T -i /proc/self/fd/IN -frames:v 1 -pix_fmt gray -f rawvideo /proc/self/fd/OUT`), read into a buffer with known width/height. No disk. Returns `Frame { w, h, y: Vec<u8> }`. Document the pixel format and that comparison is on luma.

### 3.3 `ssim.rs` — hand-rolled SSIM (owned, explainable)
Single-scale SSIM on luma: sliding window (8×8, or 11×11 Gaussian σ=1.5 — pick one, document it), `C1=(0.01·255)²`, `C2=(0.03·255)²`, MSSIM = mean of windowed SSIM. Two frames of equal dimensions → `f64 ∈ [−1, 1]` (≈1.0 identical). **We hand-roll it** so every number is explainable (measure-never-guess), not delegated to an opaque crate. Tests: SSIM(x, x) ≈ 1.0; SSIM degrades monotonically under added noise; a known reference pair matches an independently computed value within tolerance.

### 3.4 `binding.rs` — the enforced anti-swap chain (1.2.4)
```rust
/// leaf = SHA-256(ciphertext_blob); expected = core::Commitment::commit(&[leaf]).
/// Returns Ok(OutputRef = leaf-as-content-address) iff expected == submitted. No challenge before this passes.
pub fn check_binding(blob: &[u8], submitted: &core::Commitment) -> Result<OutputRef, VerifyError>;
```
- Uses the **frozen** `core::Commitment::commit` (single leaf) — the freeze-compatible expression of "commitment = SHA-256(ciphertext)."
- The accepted `OutputRef` is the content address (the blob hash), so release references the exact verified bytes (closes verified-then-swapped TOCTOU; pairs with Phase 4 §1.1).
- Test: a blob mutated after the commitment fails `check_binding`.

### 3.5 `compare.rs` — per-segment verification
Implements §0 steps 1–4. Loads the threshold via `RocThreshold::load("bench/results/verify/roc-threshold.json")` — **never a literal**. Picks challenge frame timestamps with an injected RNG seed (so the eval is reproducible; production uses OS randomness). All media stays in memfds; on every path the memfds are `zeroize_and_close`d. Emits `core::VerifyDetail` (categorical: `Passed`, `FailedBinding`, `FailedSsimBelowThreshold`, `FailedDecrypt`, `FailedReencode`) — no numeric threshold crosses the API.

---

## 4. `detection.rs` — falsifiable detection probability (1.2.1 + 1.3)

```rust
/// Exact hypergeometric: population n segments, m=⌈f·n⌉ tampered, k=⌈p·n⌉ sampled w/o replacement.
/// P(detect) = 1 − C(n−m, k)/C(n, k).
pub fn p_detect_hypergeometric(f: f64, n: u32, p: f64) -> f64;
/// Binomial approximation (sampling with replacement): 1 − (1−p)^(⌈f·n⌉). For the divergence plot only.
pub fn p_detect_binomial(f: f64, n: u32, p: f64) -> f64;
/// Sampling fraction for a reputation tier, with a hard floor so k = ⌈p·n⌉ ≥ 1 for EVERY worker.
pub const P_MIN: f64 = /* documented floor, e.g. ensures ≥1 sample at the largest expected n */;
```
- Compute the hypergeometric via `statrs` (or log-Gamma) — exact and cheap. Guarantee `k ≥ 1` for all workers via `P_MIN` (no worker is ever unsampled).
- **Publish a family** `P_detect(f, n; p_tier)` over representative tiers (`p_min` pristine, a mid tier, a high tier) and a grid of `n ∈ {4,8,16,32,64}`, `f ∈ (0,1]`. The tier→`p` *policy* is Phase 4; Phase 3 publishes the curves the policy will index.
- Commit both curves and the **divergence plot** (binomial − hypergeometric), showing the binomial overstates at small `n`. The hypergeometric is the published claim.
- Tests: hand-computed small-`n` hypergeometric values; `binomial ≥ hypergeometric` pointwise; `P_MIN` yields `k ≥ 1` at the max grid `n`.

---

## 5. `roc.rs` + the study — calibration, held-out, intervals, strata (1.2.2 + 1.2.3)

The study is the artifact a Principal reviewer will scrutinize hardest. It must not be circular and must not state a point estimate without an interval.

- **Split** `bench/corpus/` into a **calibration set** and a **disjoint held-out set** (by clip and segment, no leakage). Document the split.
- **Attack synthesis:** for each segment generate the honest transcode plus the attack classes — cheap-downscale (minimal-effort encode), wrong-bitrate, frame-substitution (splice frames from elsewhere), and black/garbage — producing labeled (honest=positive-pass, attack=should-reject) SSIM scores.
- **Threshold selection on calibration only:** plot the ROC (honest-pass vs attack-reject across thresholds), pick the threshold (state the criterion — e.g., max FRR budget at a target FAR, or Youden’s J), and write it with provenance to `roc-threshold.json` (value + corpus hash + ffmpeg version + date).
- **Reported FAR/FRR on the held-out set only**, each with a **95% Clopper–Pearson** interval (Beta quantiles via `statrs`) given the finite held-out count. For zero observed false-accepts, report `[0, upper]` honestly (e.g., "0/N → 95% CI [0, x%]") — not "0%".
- **Per-stratum FRR** for ≥3 strata mapped to the synthetic corpus (smooth/gradient, high-detail/grain-like, high-motion). If a single global threshold over-rejects high-detail content, **state it** and quantify it — that caveat is the elite line. (Per amendment 1.5, this is the cuttable item if the clock forces it: degrade to a single corpus with CIs and an explicit note — but never cut the split or the hypergeometric.)
- **Verification cost:** measure the price of trust — reference re-encode time + frame-extraction + SSIM per sampled segment, as a fraction of one transcode (expect ≈ 1 transcode + δ). State the implication: trusted-verifier capacity must be ≥ `p × worker_throughput`. This feeds Phase 4/6 sizing.

All figures cite their source CSV; the writeup is declarative, with units, conditions, and the honest caveats. CSVs are the source of truth; an SVG ROC/divergence plot is optional (dev-only path), never a runtime dep.

---

## 6. Correctness & purity (verify before commit)
- `verify` is `#![forbid(unsafe_code)]`; all `unsafe` remains solely in `crypto::sys`; the §3.1 refactor keeps `crypto`'s Phase 2 tests green.
- Binding: blob-swap-post-commit rejected; challenge frames are chosen only after binding passes.
- SSIM: identity ≈ 1.0; monotone under noise; matches an independent reference within tolerance.
- Detection: hypergeometric matches hand-computed small-`n`; binomial ≥ hypergeometric; `P_MIN` ⇒ `k ≥ 1`.
- ROC: calibration and held-out are disjoint (assert no segment overlap); FAR/FRR carry CIs; ≥3 strata reported.
- No disk: the per-segment flow opens no plaintext disk file (the Phase 2 fd-enumeration discipline applies to `verify`'s flow too — add a `verify`-level fd check or reuse the crypto cycle).
- `core` byte-for-byte unchanged; allowlist (§2) respected; `cargo build && cargo clippy --all-targets -- -D warnings && cargo test` clean.

---

## 7. Commit discipline (carried forward)
- Conventional Commits `<type>(verify|crypto): <imperative>`, ≤72 chars, body cites the spec/amendment section and the rejected alternative where relevant.
- Atomic, one logical change per commit, each on a green tree. Never commit red. No `--no-verify`, no force-push. No media/large binaries (commit CSVs, JSON, and the text study; not video).
- The `crypto` §3.1 refactor is its own commit, landed before `verify` depends on it.

---

## 8. Phase 3 Definition of Done
1. `verify` implements `ssim`, `frame`, `binding`, `compare`, `detection`, `roc` per §2–§5; `#![forbid(unsafe_code)]`.
2. `crypto::ffmpeg_no_disk` added additively; `transcode_no_disk` refactored onto it; **all Phase 2 crypto tests still pass**; unsafe still confined to `crypto::sys`.
3. Commit binding enforced and ordered (§3.4, §0 step 1): single-leaf `core::Commitment` check before any challenge; blob-swap test rejects; release content-addressed via `OutputRef`.
4. SSIM hand-rolled and tested (§3.3); per-segment verify flow loads the threshold from `roc-threshold.json`, never a literal; emits categorical `VerifyDetail`.
5. **Hypergeometric** detection implemented with the binomial divergence and the **`p_tier` family + `P_MIN` floor** (§4); curves + divergence committed to `bench/results/verify/`.
6. ROC study committed (§5): calibration/held-out **disjoint** split; threshold + provenance in `roc-threshold.json`; FAR/FRR on held-out with **95% Clopper–Pearson** CIs; **per-stratum FRR (≥3 strata)** with the honest over-rejection caveat if present; verification-cost breakdown. Every figure cites its CSV.
7. `core` unchanged since freeze; allowlist respected; full gate green; no plaintext on disk in the verify flow.
8. Commits follow §7; `docs/THREAT-MODEL.md` updated with the commit-binding/TOCTOU paragraph and the adaptive-sampling info-leak honest note (1.2.4, 1.3); `docs/ARCHITECTURE.md` gains the verification design (SSIM, hypergeometric family, verifier-as-separate-binary, cost). *(The fencing-token paragraph lands in Phase 4.)*

Next: `phase4-spec.md` — `sched`: Redis-lease least-loaded **push** dispatch, heartbeats, the single epoch-fenced reclaim authority (1.1), the tier→`p` adaptive policy with the `P_MIN` floor (1.3), content-addressed release, and Little's-law-sized backpressure (1.4).

---

# Appendix A — `CLAUDE.md` update for Phase 3

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md  — amendment changes the math
- docs/specs/phase0/1/2-spec.md  — genesis, core (FROZEN), crypto
- docs/specs/phase3-spec.md      — CURRENT: verify (SSIM, binding, hypergeometric, ROC)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- crypto is NOT frozen: §3.1 adds ffmpeg_no_disk additively; ALL Phase 2 crypto tests must stay green.

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

## Commit discipline
Conventional Commits, atomic, GREEN tree, body cites spec/amendment. crypto refactor is its own commit,
landed first. Never commit red/media/binaries. No --no-verify, no force-push, no core/ edits.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, commit(s), change list, STOP.
No adaptive POLICY (Phase 4), no sched, no transport.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1 | crypto primitive + SSIM + frames | `crypto::ffmpeg_no_disk` (refactor); `verify` scaffold (`#![forbid(unsafe_code)]`), `ssim.rs`, `frame.rs` | Phase 2 crypto tests still green; SSIM + extraction tested; 2 commits |
| 2 | binding + compare | `binding.rs`, `compare.rs` | blob-swap rejected; honest passes/attack fails at a fixed test threshold; loads roc-threshold.json; commit |
| 3 | detection | `detection.rs` | hypergeometric matches hand calc; binomial≥hyper; P_MIN⇒k≥1; curves+divergence committed; commit |
| 4 | ROC study | `roc.rs` + `verify_eval` + `bench/results/verify/*` | disjoint split; threshold+provenance; FAR/FRR+CIs; ≥3-strata FRR; cost; commit |
| 5 | docs + DoD | THREAT-MODEL + ARCHITECTURE updates | verification + adaptive-leak + binding/TOCTOU paragraphs; DoD §8 reported; commit |

### Exact prompts (one per session; verify + commit before the next)

**Session 1**
> Read `kickoff-amendment-1.md`, `phase3-spec.md` (§2, §3, §6–§8), and `CLAUDE.md`; update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: (a) add `crypto::ffmpeg_no_disk(args, fds)` and refactor `transcode_no_disk` onto it, keeping ALL Phase 2 crypto tests green and `unsafe` solely in `crypto::sys` — commit `refactor(crypto): expose no-disk ffmpeg primitive`; (b) scaffold `verify` with `#![forbid(unsafe_code)]`, implement hand-rolled `ssim.rs` (document window + C1/C2) and `frame.rs` (Y-plane extraction over the new primitive) with tests (identity≈1.0, monotone-under-noise; extraction round-trip) — commit `feat(verify): SSIM comparator and frame extraction`. Build+clippy `-D warnings`+test; list changes; STOP.

**Session 2**
> Read `CLAUDE.md` and `phase3-spec.md` §3.4–§3.5, §0. Execute **Session 2 only**: `binding.rs` (single-leaf `core::Commitment::commit(&[SHA-256(blob)])` check returning a content-addressed `OutputRef`, binding checked before any challenge) and `compare.rs` (the §0 per-segment flow: bind → decrypt source & output → reference `transcode_no_disk` → sample frames with injected seed → SSIM min → threshold from `roc-threshold.json` → categorical `VerifyDetail`; all media in memfds, zeroized on every path). Tests: blob-swap-post-commit rejected; an honest segment passes and a frame-substituted segment fails at a fixed test threshold. Build+clippy+test; commit; STOP.

**Session 3**
> Read `CLAUDE.md` and `phase3-spec.md` §4. Execute **Session 3 only**: `detection.rs` — exact `p_detect_hypergeometric`, `p_detect_binomial`, and the `p_tier` family with the `P_MIN` floor. Tests: hand-computed small-`n` hypergeometric; `binomial ≥ hypergeometric`; `P_MIN ⇒ k≥1` at max grid `n`. Compute and commit the family curves and the binomial-divergence plot data to `bench/results/verify/`. Build+clippy+test; commit `feat(verify): hypergeometric detection-probability family`; STOP.

**Session 4**
> Read `CLAUDE.md` and `phase3-spec.md` §5, and the Writing Standard. Execute **Session 4 only**: `roc.rs` + `verify_eval`. Split `bench/corpus/` into disjoint calibration/held-out (assert no overlap); synthesize honest + attack variants (cheap-downscale, wrong-bitrate, frame-substitution, garbage); select the threshold on calibration only and write `roc-threshold.json` with provenance; report held-out FAR/FRR with 95% Clopper–Pearson CIs; report per-stratum FRR (≥3 strata) with the honest over-rejection caveat if present; measure verification cost as a fraction of a transcode. Commit all CSVs + study note to `bench/results/verify/`. Build+clippy+test; commit `bench(verify): ROC calibration, held-out CIs, strata, cost`; STOP.

**Session 5**
> Read `CLAUDE.md`, `phase3-spec.md` §8, and `kickoff-amendment-1.md` §1.2.4/§1.3. Execute **Session 5 only**: update `docs/THREAT-MODEL.md` (commit-binding/TOCTOU paragraph; adaptive-sampling info-leak honest note with the `P_MIN` justification) and `docs/ARCHITECTURE.md` (verification design: SSIM, hypergeometric family, verifier-as-separate-binary, verification cost). Verify the Phase 3 DoD §8 item by item and report each with evidence. Confirm `git diff v0.1.0-core-frozen -- core/` is empty. Commit `docs: verification threat model and architecture`; STOP.
