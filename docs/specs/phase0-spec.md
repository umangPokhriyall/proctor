# proctor — Phase 0 Specification: Genesis, Legacy Freeze, and the Frozen-Skeleton

**Companion to:** `kickoff-brief.md`. Read it first.
**This is the complete, authoritative Phase 0 spec.** It establishes the new repository, freezes the legacy product, scaffolds the Rust workspace as compiling stubs, and **locks the architectural decisions** that Phase 1+ may not relitigate.
**Scope:** repo genesis + legacy snapshot freeze (operator runbook), the locked decisions, the workspace skeleton, `CLAUDE.md`, the `docs/THREAT-MODEL.md` skeleton, the deterministic corpus plan, and the README framing. **No primitive logic is written in Phase 0** — that is Phase 1+. Phase 0 ends with a workspace that builds, clippies, and tests clean with stubs.
**Audience:** the human operator (§2 — repo mechanics) and Claude Code (§4–§9 — scaffold). Split called out in §0.
**Repo name:** `proctor` (kickoff recommendation). If overridden, substitute throughout before running §2.

---

## 0. Why a fresh repo, and the human/Claude-Code split

The legacy `Stream-hive` is a working TypeScript product whose security claims the audit refuted. We do not delete from it and we do not fork it. A fork inherits broken history and signals iteration-on-the-broken-thing; a clone drags TS noise into a workspace whose `git log` and `bench/results/` must read as deliberate Rust from the first commit. Instead: a **fresh repository** (`proctor`), and the legacy repo is **frozen in place, public, archived** as honest evidence of the product origin and the rebuild judgment. Only ideas cross over (kickoff §1 preserve table); no code.

**The split (NORTH-STAR §4):** repo creation and the legacy freeze are operator actions over GitHub/git — the human runs §2. The workspace scaffold, `CLAUDE.md`, doc skeletons, and corpus generator are mechanical — Claude Code runs §4–§9 in one scoped session. Phase 0 writes **zero primitive logic**; the freeze ceremony for `core` happens in Phase 1, not here.

---

## 1. Phase 0 in one paragraph

Stand up `proctor` as a clean Rust workspace of seven crates — `core`, `crypto`, `verify` (libs), `sched`, `verifier`, `worker`, `bench` (bins) — each a **compiling stub with its intended public surface sketched and `todo!()` bodies**, behind a `CLAUDE.md` guardrail that encodes the locked decisions and a per-phase dependency allowlist. Commit the `docs/THREAT-MODEL.md` skeleton (with the honest confidentiality boundary already stated so it cannot drift), a deterministic **synthetic** video corpus generator (ffmpeg `lavfi` — copyright-clean and regenerable), and a README that frames the artifact and links the frozen legacy snapshot. Freeze the legacy `Stream-hive` repo. After Phase 0, `cargo build && cargo clippy && cargo test` is green across the workspace and every later phase has a home to drop into.

### 1.1 Locked from Phase 0 onward (Phase 1+ may not relitigate)
- The runtime of the measured path is **Rust**. No async runtime in `sched`/`worker`/`crypto`/`verify` hot paths (Rust-Tcp-Server / Web3-Terminal precedent).
- **No ingest API.** `bench` injects workloads directly into the scheduler's queue. There is no `api` crate, ever. (Authoritative call #1 — keeps control-plane latency metrics free of an HTTP front-end's confounds.)
- **The verifier is a separate binary** (`verifier`), never a module inside `sched`. CPU-bound ffmpeg re-execution must not share a process with the I/O-bound scheduler. (Authoritative call #2.)
- **The comparator is SSIM against an ROC curve, not pHash.** pHash measures visual similarity; we measure *transcode fidelity* against cheap-downscale and frame-substitution attacks, which demands a structural metric. (Authoritative call #3.)
- **Single host, N pinned worker processes, loopback, local blob store.** Geography is orthogonal to the placement/verification/crypto claims and is a documented caveat, not an asterisk (Phase 3-style honesty).
- The corpus is **synthetic** (ffmpeg `lavfi`), committed small, regenerable from a script. No copyrighted video enters the repo.

---

## 2. Repo genesis & legacy freeze — operator runbook (human, not Claude Code)

Pure git/GitHub. No code is written here.

### 2.1 Freeze the legacy product snapshot
In the existing `Stream-hive` repo, on `main`:
```bash
git tag -a v1.0-product -m "Final state of the TypeScript transcoding product, pre-rebuild."
git push origin v1.0-product
```
Prepend a banner to its `README.md` (commit it), then archive the repo in GitHub Settings → **Archive this repository** (makes it read-only):
```markdown
> **Frozen.** This is the original TypeScript transcoding product (tag `v1.0-product`).
> Its systems substrate was extracted, red-teamed, and rebuilt in Rust as
> **proctor** (<NEW_REPO_URL>) with an honest untrusted-worker threat model.
> This repository is archived and read-only.
```

### 2.2 Create the new repository
- New **empty** GitHub repo named `proctor` (no auto-generated README/license/.gitignore — the first commit is the workspace).
- Public. Default branch `main`.
- Local:
```bash
git init proctor && cd proctor
# (Claude Code populates the workspace in §4–§9, then:)
git add -A && git commit -m "phase 0: rust workspace skeleton, CLAUDE.md, threat-model skeleton, corpus generator"
git branch -M main && git remote add origin <NEW_REPO_URL> && git push -u origin main
```

**Do not** copy any file from `Stream-hive`. The only artifacts that cross over are ideas (kickoff §1) and the corpus-generator concept (§8), which Claude Code writes fresh.

---

## 3. The locked architectural decisions (record verbatim in ARCHITECTURE later)

These are settled. Phase 1+ specs cite them; they do not reopen them.

| # | Decision | Rejected alternative + why |
|---|---|---|
| 1 | Rust for the measured path; no async runtime in hot paths. | Keep Node/TS — not the signal; the synergy to the Rust flagship and the AES-NI/`mlock`/`perf` story require it. |
| 2 | No ingest API; `bench` injects workloads directly. | An HTTP ingest tier — adds a front-end confound to control-plane latency we are trying to measure cleanly. |
| 3 | `verifier` is a separate binary. | A verify module inside `sched` — pollutes the I/O-bound scheduler with CPU-bound ffmpeg re-execution; corrupts scheduling-overhead numbers. |
| 4 | SSIM + calibrated ROC comparator. | pHash — measures visual similarity, not transcode fidelity; weak against cheap-downscale and frame-substitution, which is exactly what we must catch. |
| 5 | Single host, N pinned workers, loopback, local blob store. | Real multi-host network — unreproducible bench; geography is orthogonal to the systems claims. Documented caveat. |
| 6 | Trusted verifier capacity, probabilistic sampling. | Verify on untrusted workers — infinite regress; or verify everything — you've done all the work twice. |

---

## 4. Target workspace layout

```
proctor/
  Cargo.toml                  # workspace manifest (members below)
  rust-toolchain.toml         # pin stable channel (record version)
  .gitignore                  # /target, blob-store scratch, *.local
  CLAUDE.md                   # the guardrail (§6)
  README.md                   # framing + links frozen snapshot (§9)
  core/                       # lib — FROZEN in Phase 1
    src/lib.rs                # protocol, task/lease/segment state machine, commit-reveal types — sans-IO
  crypto/                     # lib
    src/lib.rs                # in-memory AES-256-GCM, key handling (mlock+zeroize), pipe/memfd ffmpeg I/O
  verify/                     # lib
    src/lib.rs                # SSIM comparator, ROC calibration, detection-probability math, commit-reveal verify
  sched/                      # bin — I/O-bound control plane
    src/main.rs               # Redis-lease least-loaded PUSH dispatch, heartbeat, single reclaim, backpressure, reputation gate
  verifier/                   # bin — CPU-bound trusted verifier
    src/main.rs               # re-executes ffmpeg on sampled segments, calls verify::ssim
  worker/                     # bin — the untrusted worker
    src/main.rs               # lease -> crypto decrypt -> ffmpeg(pipe) -> crypto encrypt -> commit-hash
  bench/                      # bin — the harness (NO ingest API)
    src/main.rs               # injects workloads directly; spins sched+verifier+N workers; corpus; adversary simulator; metrics
    corpus/                   # COMMITTED synthetic clips + generator (§8)
  docs/
    specs/                    # kickoff-brief.md, phase0-spec.md, phaseN-spec.md (as reached)
    THREAT-MODEL.md           # skeleton committed in Phase 0 (§7)
```

**One-line contract per crate** (sans-IO boundary marked):

| Crate | Owns | Must never |
|---|---|---|
| `core` (lib) | protocol messages, task/lease/segment state machine, commit-reveal types. **Sans-IO.** | touch a socket, Redis, ffmpeg, or the filesystem. |
| `crypto` (lib) | in-memory AES-256-GCM, per-segment key lifecycle, ffmpeg pipe/`memfd` plumbing. | write plaintext or a key to disk; log a key. |
| `verify` (lib) | SSIM comparison, ROC threshold calibration, detection-probability math, commit-reveal verification. | re-execute ffmpeg itself (that is `verifier`'s job); know transport. |
| `sched` (bin) | placement, leases, heartbeats, reclaim, backpressure, reputation gate. | block on CPU-bound work; hold worker state in process memory (Redis is the source of truth). |
| `verifier` (bin) | re-execute ffmpeg on sampled segments; call `verify`. | make placement decisions; share a process with `sched`. |
| `worker` (bin) | the untrusted hot loop; uses `core` + `crypto`. | persist plaintext or keys; self-select tasks (it receives pushes). |
| `bench` (bin) | inject workloads directly; orchestrate the single-host run; corpus; adversary simulation; metrics. | expose an HTTP ingest API; touch the network for workload entry. |

---

## 5. The stubs Claude Code creates (compile-only, no logic)

Every crate compiles with its intended public surface declared and bodies as `todo!()` / `unimplemented!()`. Types may be empty structs/enums with a `// FROZEN in Phase 1` marker on `core`. Add **no external dependencies** in Phase 0 beyond `thiserror` (error enums) if needed — the heavy deps (`aes-gcm`, `redis`, an SSIM crate, etc.) arrive with their phases per the CLAUDE.md allowlist. Each crate gets one trivial test (`#[test] fn builds() {}`) so `cargo test` is green.

Illustrative surfaces (sketch — Claude Code refines, but adds no logic):

```rust
// core/src/lib.rs   — FROZEN in Phase 1; Phase 0 declares shape only.
pub struct SegmentId(/* ... */);
pub struct TaskId(/* ... */);
pub struct Lease { /* holder, deadline, epoch */ }
pub enum TaskState { Pending, Leased, Transcoded, Verifying, Verified, Released, Stitched, Reclaimed, Failed }
pub struct Commitment(/* SHA-256 over worker output, revealed post-challenge */);
// no fn bodies in Phase 0 beyond signatures + todo!()
```

```rust
// verify/src/lib.rs
/// Structural-similarity score in [0.0, 1.0] between a reference frame and a candidate frame.
pub fn ssim(reference: &Frame, candidate: &Frame) -> f64 { todo!() }
/// Threshold read from the committed ROC study (Phase 3) — never a hardcoded constant.
pub struct RocThreshold(/* value + provenance */);
pub struct Frame(/* ... */);
```

```rust
// crypto/src/lib.rs
/// Decrypt to anonymous memory (never disk); key is mlock'd and zeroized after use.
pub fn decrypt_in_memory(/* ciphertext, key */) -> SecretBuf { todo!() }
pub struct SecretBuf(/* zeroize-on-drop */);
```

`bench` declares a `inject_workload(...)` entry point (direct queue push) so the no-API decision is visible in code from day one.

---

## 6. `CLAUDE.md` (the guardrail — Claude Code writes this file)

```markdown
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
```

---

## 7. `docs/THREAT-MODEL.md` skeleton (committed in Phase 0; filled in Phase 7)

Headings only, plus the honest boundary stated now so it cannot drift later:

```markdown
# proctor — Untrusted-Worker Threat Model

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
```

---

## 8. Corpus plan (`bench/corpus/`)

A reproducible benchmark needs a deterministic, copyright-clean event source. Use **synthetic** clips from ffmpeg `lavfi`, committed small, with a `generate.sh` that regenerates them byte-for-byte (record ffmpeg version). Phase 0 commits the generator and a tiny seed set; the full set is generated on the bench host.

- **Clip set (varied, on purpose):** a clean gradient (`testsrc2`), a high-entropy/high-detail source (`mandelbrot` or `rgbtestsrc` + noise), and a high-motion source. Rationale: SSIM needs real spatial/temporal detail to separate an honest transcode from a cheap-downscale or frame-substitution attack — a flat `testsrc` would not exercise the comparator. This choice is itself part of the verification signal.
- **Sizes:** keep committed clips to a few MB total; everything larger is generated on-host from `generate.sh`.
- **Determinism:** fixed duration, resolution, and frame rate per clip; pinned ffmpeg flags; documented version. The corpus is the verification/scheduling analogue of the LOB event corpus.

Phase 0 deliverable here is the **generator script + seed clips + a `corpus/README.md`** stating the regeneration command and the ffmpeg version. No measurement yet.

---

## 9. `README.md` framing (Phase 0 — no results yet)

A short, honest framing with no numbers (numbers arrive in Phase 6+). Order:

1. **One sentence:** what `proctor` is — a zero-trust control plane for verifiable, confidential transcoding on untrusted workers, built as three measured systems primitives.
2. **Status:** under construction; primitives and benchmarks land per `docs/specs/`. No performance claims until `bench/results/` exists.
3. **The three primitives** (one line each): probabilistic verification (SSIM + ROC), in-memory shard-scoped AES-GCM (keys never on disk), backpressure-aware least-loaded scheduler.
4. **The honest boundary** (one line): confidentiality is bounded, not absolute — a root-capable worker defeats it; that gap is what the microVM flagship exists to close. Link `docs/THREAT-MODEL.md`.
5. **Repository map** (the §4 crate table, condensed).
6. **Product origin** (one line + link): the original TypeScript product, frozen at `Stream-hive@v1.0-product`.
7. **Build:** `cargo build`. No run instructions until the harness exists.

No badges, no emoji, no marketing language (kickoff §7 / Phase 2 §8 Writing Standard applies to every doc from day one).

---

## 10. Phase 0 Definition of Done

1. Legacy `Stream-hive` frozen: tag `v1.0-product` pushed, README banner committed, repo archived (read-only).
2. New `proctor` repo created, public, first commit pushed to `main`.
3. Workspace builds: `cargo build && cargo clippy && cargo test` green across all seven crates with stub bodies; no clippy warnings.
4. The seven crates exist with the §4 layout and §5 public-surface sketches; `core` marked `// FROZEN in Phase 1`; `bench` exposes a direct `inject_workload` entry (no API crate anywhere).
5. `CLAUDE.md` present with the locked decisions, crypto/honesty rules, and the Phase-0 dependency allowlist (§6).
6. `docs/THREAT-MODEL.md` skeleton committed with the honest confidentiality-boundary statement already written (§7).
7. `bench/corpus/` has `generate.sh` + seed clips + `corpus/README.md` (ffmpeg version recorded); synthetic only, no copyrighted video (§8).
8. `README.md` frames the artifact and links the frozen snapshot, with no performance claims (§9).
9. No external dependency beyond `thiserror` (if used); no primitive logic implemented anywhere.

Next: `phase1-spec.md` — implement and **freeze** `core` (protocol + task/lease/segment state machine + commit-reveal types), sans-IO, differential-tested.

---

# Appendix A — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 0 (operator) | Genesis + freeze | §2 — tag/archive legacy; create empty `proctor` repo | `v1.0-product` pushed + archived; empty repo on `main` |
| 1 (Claude Code) | Scaffold | §4–§9 — workspace skeleton, `CLAUDE.md`, THREAT-MODEL skeleton, corpus generator + seed, README framing | DoD §3–§9 all green |

The scaffold is one clean session; the run is light enough not to split. The operator step precedes it (the local repo must exist for Claude Code to populate).

### Exact prompt (Claude Code, Session 1)

> Read `docs/specs/kickoff-brief.md` and `docs/specs/phase0-spec.md` in full. Execute **Phase 0 scaffold only**, writing NO primitive logic:
> (1) Create the Rust workspace per §4 — seven crates (`core`, `crypto`, `verify` libs; `sched`, `verifier`, `worker`, `bench` bins), each compiling with the §5 public-surface sketches and `todo!()` bodies, one trivial `builds()` test each. Mark `core` `// FROZEN in Phase 1`. `bench` must expose a direct `inject_workload` entry and there must be no `api` crate.
> (2) Write `CLAUDE.md` exactly per §6 (locked decisions, crypto/honesty rules, Phase-0 dependency allowlist = `thiserror` only).
> (3) Commit `docs/THREAT-MODEL.md` per §7, including the honest confidentiality-boundary statement verbatim.
> (4) Write `bench/corpus/generate.sh` + seed clips (ffmpeg `lavfi`, synthetic only) + `bench/corpus/README.md` recording the ffmpeg version, per §8.
> (5) Write `README.md` per §9 — framing only, no performance claims, links the frozen `Stream-hive@v1.0-product`.
> Add no dependency beyond `thiserror`. Run `cargo build && cargo clippy && cargo test` until green with zero warnings. Show me the workspace tree, the `core` public surface intended for the Phase 1 freeze, and the `CLAUDE.md`. List all created files and STOP.
