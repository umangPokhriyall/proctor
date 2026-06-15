# proctor — Phase 5 Specification: the `worker` and `verifier` Binaries (the Live Data Plane)

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0–4-spec.md`. Read the amendment (§1.1, §1.2.4, §1.3) first.
**This is the complete, authoritative Phase 5 spec.** It builds the two real binaries that turn Phase 4's simulated harness into a live single-host network: the **untrusted `worker`** (lease → in-memory decrypt → ffmpeg over memfd → encrypt → single-leaf commit → epoch-carrying submit) and the **trusted `verifier`** (consume `VerifyRequest` → batched-decode SSIM via `verify` → `VerifyResult`). It adds the minimal data-plane seams (`crypto::blob`, `crypto::keysource`), the batched-decode optimization that removes the Phase 3 ~10× verification-cost artifact, the live Redis transport, and the detail-aware reputation wiring that closes Phase 4's first noted seam.
**Scope:** `worker/`, `verifier/`, additive seams in `crypto`, `verify`, and `sched`, plus a live single-host **smoke** run. Full measurement, the chaos/adversary suite, and the slow-zombie *chaos schedule* are Phase 6. The worker built here is the **honest reference worker**; cheating workers are Phase 6's adversary simulator.
**Audience:** Claude Code. Authoritative. **Claude Code commits its own work.** ffmpeg and a reachable Redis are required.
**Frozen:** `proctor_core` is FROZEN (`v0.1.0-core-frozen`); `git diff v0.1.0-core-frozen -- core/` stays empty. `crypto`, `verify`, `sched` are not frozen — §3/§4/§5 extend them additively, and **all their prior-phase tests must stay green** (regression guard). If a `core` change seems needed, STOP and escalate.

---

## 0. Phase 5 in context, and what "live" must prove

Phases 1–4 built a frozen state machine, an in-memory crypto path, a falsifiable verifier, and an epoch-fenced scheduler — each proven in isolation or against a sim. Phase 5 makes them one running system on a single host, and the bar is that the live path enforces the **same** properties the sim proved: the worker carries its lease epoch so a slow zombie's late submit is rejected (§1.1); the worker's commitment is exactly `Commitment::commit(&[SHA-256(ciphertext)])` so the verifier's binding check and the scheduler's content-addressed release agree (§1.2.4); and the verifier's real `VerifyResult.detail` drives the asymmetric, `P_MIN`-floored reputation policy (§1.3) — closing Phase 4's coarse-reputation seam.

Two honesty obligations carried from earlier phases land here:
- **The verification-cost remedy (Phase 3).** The ~10× verification cost was per-frame ffmpeg process-spawn; the named fix is batched/in-process decode. Phase 5 implements **one ffmpeg invocation per segment extracting all sampled frames** (`verify::frame` batch), driving cost toward the fundamental ≈ 1.20× transcode. The live run spot-checks it; Phase 6 measures it.
- **The confidentiality boundary (Phase 2), reaffirmed in the live path.** The untrusted worker receives the per-segment key and decrypts to anonymous RAM to transcode — it *can* see its shard's plaintext; root-on-worker defeats confidentiality. This is the documented boundary the microVM flagship exists to close. Nothing in Phase 5 pretends otherwise.

**Human/Claude split:** Claude Code executes including commits. The live tiers run where ffmpeg and Redis are reachable; gate and loud-skip otherwise (never fabricate a pass).

---

## 1. Phase 5 in one paragraph

Add the data-plane seams to `crypto` — `blob` (a content-addressed ciphertext store: `LocalBlobStore` on tmpfs/filesystem, an S3 adapter behind the trait but unmeasured) and `keysource` (per-segment `SecretKey` delivery: `LocalKeySource` for the benchmark; production-TLS documented as the seam, not built). Build the **`worker`** (`#![forbid(unsafe_code)]`): register, `BRPOP` an encoded `core::proto::Assignment`, and run the hot loop for both task kinds — `Transcode` (fetch ciphertext → `decrypt_into_memfd(Role::Source)` → `transcode_no_disk(profile)` → `aead::encrypt(Role::Output)` → `commitment = Commitment::commit(&[SHA-256(ciphertext)])`, `OutputRef = lead128(SHA-256)` → upload → `SubmissionMsg` carrying the **lease epoch**), heartbeating during long work, concurrency bounded by the **cgroup cpu quota** (not host load — the legacy bug). Build the **`verifier`** (`#![forbid(unsafe_code)]`): `BRPOP` a `VerifyRequest`, `check_binding` before any frame, reference-`transcode_no_disk` the source, **batch-extract** the sampled frames in one ffmpeg call, SSIM via `verify::verify_segment` against the committed `RocThreshold`, integrity-check `Stitch` (no SSIM), and return `VerifyResult{passed, detail}`. Wire live Redis inboxes and a `sched:inbound` return channel; make `sched`'s engine apply the **rich `VerifyDetail`** reputation magnitudes. Prove it with a live single-host smoke run including the process-level zombie rejection.

### 1.1 Frozen / consumed (alignment with the real Phase 1–4 code)
- `core::proto`: `Assignment{task,kind,lease,source}`, `HeartbeatMsg{task,worker,epoch}`, `SubmissionMsg{task,worker,epoch,commitment,output}`, `VerifyRequest{task,kind,commitment,output}`, `VerifyResult{task,passed,detail}`; `encode`/`decode` (postcard).
- `core`: `TaskKind::{Transcode(TranscodeSpec{job,segment,profile,source}),Stitch(StitchSpec{job,rendition,inputs:Vec<(SegmentId,OutputRef,Commitment)>})}`, `Commitment::commit`, `OutputRef` (u128), `Lease{holder,epoch,deadline}`, `Epoch`, ids.
- `crypto`: `decrypt_into_memfd(enc,key,aad,name)→MemFd`, `aead::{EncryptedSegment,encrypt,decrypt,SegmentAad,Role::{Source,Output}}`, `transcode_no_disk(&MemFd,&TargetProfile)→MemFd`, `ffmpeg_no_disk(args,fds)`, `MemFd::{proc_path,read_to_secret_buf,zeroize_and_close}`, `SecretKey`, `CryptoError`. Unsafe stays only in `crypto::sys`.
- `verify`: `check_binding(blob,&Commitment)→Result<OutputRef,_>`, `verify_segment(inputs,plan,threshold)→Verdict` mapping to `VerifyDetail::{Ok,CommitmentMismatch,FidelityBelowThreshold,Inconclusive}`, `RocThreshold::load`, `frame` extraction, `ssim`.
- `sched`: §3.2 Redis inbox model (`inbox:{worker}` list, `LPUSH`/`BRPOP`, encoded `Assignment`); `reputation::record_verdict(detail)` (the rich asymmetric magnitudes already unit-tested); the engine's content-addressed release anchored by `Commitment`.

---

## 2. Module / binary layout & Phase 5 dependency allowlist

```
crypto/src/
  blob.rs        # ADDITIVE: BlobStore trait + LocalBlobStore (content-addressed CIPHERTEXT, on disk OK)
  keysource.rs   # ADDITIVE: KeySource trait + LocalKeySource (per-segment SecretKey; TLS seam documented)
verify/src/
  frame.rs       # ADDITIVE: batch extraction — one ffmpeg call for all sampled timestamps (cost fix)
  integrity.rs   # ADDITIVE: Stitch integrity check (no SSIM)
sched/src/
  loops.rs       # ADDITIVE: sched:inbound return channel (BRPOP + route) for live bins
  engine.rs      # ADDITIVE: apply rich VerifyDetail via reputation::record_verdict (closes Phase 4 seam)
worker/src/
  main.rs        # #![forbid(unsafe_code)] — register, inbox loop, dispatch by kind, heartbeat, cgroup concurrency
  transcode_task.rs  # the Transcode hot loop
  stitch_task.rs     # the Stitch hot loop (concatenate verified inputs)
verifier/src/
  main.rs        # #![forbid(unsafe_code)] — inbox loop, transcode verification (SSIM), stitch integrity
bench/ (or tests/)
  live_smoke.rs  # the live single-host smoke run (Session 5)
```

**Dependency allowlist — Phase 5 adds exactly:**
- `worker`: `proctor_core`, `crypto`, `redis` (sync, `features=["script"]`, no async), `sha2`, `thiserror`.
- `verifier`: `proctor_core`, `crypto`, `verify`, `redis` (sync), `sha2`, `thiserror`.
- `crypto`/`verify`/`sched` additive seams need **no new deps** (reuse existing). `LocalBlobStore`/`LocalKeySource` use `std::fs` (ciphertext and keys-for-the-benchmark only).

No `tokio`/async (worker/verifier use std threads + blocking Redis), no `unsafe` outside `crypto::sys`. cgroup quota is read from `/sys/fs/cgroup/cpu.max` with `std::fs` — no `num_cpus`/host-load dependency (the legacy `os.loadavg` bug is structurally avoided).

---

## 3. The data-plane seams (`crypto::blob`, `crypto::keysource`) — additive

```rust
// crypto::blob — content-addressed CIPHERTEXT store. Ciphertext on disk is fine; PLAINTEXT never is.
pub trait BlobStore {
    fn get(&self, addr: &OutputRef) -> Result<Vec<u8>, CryptoError>;          // fetch ciphertext by content address
    fn put(&self, ciphertext: &[u8]) -> Result<OutputRef, CryptoError>;       // store, return lead128(SHA-256)
    fn get_ref(&self, r: &SegmentRef) -> Result<Vec<u8>, CryptoError>;        // fetch source by its ref
}
pub struct LocalBlobStore { /* tmpfs/fs root */ }   // the measured path
// (an S3 adapter MAY exist behind the trait but is NEVER in the measured path — kickoff §6)

// crypto::keysource — per-segment key delivery. The honest boundary: the untrusted worker gets the key.
pub trait KeySource { fn key(&self, job: JobId, segment: SegmentId) -> Result<SecretKey, CryptoError>; }
pub struct LocalKeySource { /* benchmark key store */ }   // production = TLS key authority (NOT built — kickoff §6)
```
- `put` content-addresses by the same `lead128(SHA-256(ciphertext))` the worker/verifier/sched all use, so a stored blob's address equals its `OutputRef`.
- `LocalKeySource` is the benchmark seam; the production key delivery is over TLS from a key authority and is explicitly **not** built (kickoff §6). Both worker and verifier hold keys (both are key-trusted; the worker's key-possession is the documented confidentiality boundary).
- Regression guard: `crypto`'s Phase 2/3 tests stay green; `unsafe` still only in `crypto::sys`.

---

## 4. The `worker` binary (`#![forbid(unsafe_code)]`)

### 4.1 Lifecycle
- **Register** a `WorkerId` in the scheduler registry (identity only). *Cryptographic worker auth / anti-Sybil is a documented non-goal* — fencing and verification catch a cheating worker regardless of its claimed identity.
- **Concurrency** = `min(configured_cap, cgroup_cpu_quota)` from `/sys/fs/cgroup/cpu.max` (cgroup v2), **never** host `loadavg`/`num_cpus` — the legacy mechanical-sympathy bug, structurally avoided. One std thread per concurrent task; the scheduler's per-worker in-flight cap (Phase 4 §6) bounds how many it is pushed.
- **Inbox loop:** `BRPOP inbox:{worker}` → `decode` `Assignment` → dispatch by `kind`.

### 4.2 Transcode hot loop (`transcode_task.rs`) — the load-bearing path
1. `key = KeySource.key(job, segment)`; fetch source ciphertext `BlobStore.get_ref(spec.source)`.
2. `src = crypto::decrypt_into_memfd(EncryptedSegment::from_bytes(ct), &key, SegmentAad{job,segment,Role::Source}, "src")` — plaintext only in anonymous RAM.
3. `out = crypto::transcode_no_disk(&src, &spec.profile)` — transcoded plaintext in a memfd, no disk.
4. Read `out` → `enc = crypto::aead::encrypt(plaintext, &key, SegmentAad{job,segment,Role::Output})` → `blob = enc.to_bytes()`; zeroize the plaintext buffer and both memfds.
5. `leaf = SHA-256(blob)`; `commitment = core::Commitment::commit(&[leaf])`; `output = OutputRef(lead128(leaf))` — the exact values `verify::check_binding` and `sched` content-addressing expect.
6. `BlobStore.put(&blob)` (address == `output`).
7. Send `SubmissionMsg{task, worker, epoch: assignment.lease.epoch, commitment, output}` to `sched:inbound`. **The lease epoch is carried** — a stale-epoch submit (slow zombie) is rejected by the store (Phase 4 §3); the worker does not need to know it lost the lease.
- **Heartbeat during work:** a background tick sends `HeartbeatMsg{task, worker, epoch}` at < deadline/2 so a long transcode does not lose its lease for liveness. The heartbeat carries the epoch (a reclaimed zombie cannot resurrect its lease — Phase 4 fencing).
- **No plaintext on disk** (inherited from `crypto`), `SecretKey` zeroized on drop, memfds `zeroize_and_close`d on every path.

### 4.3 Stitch hot loop (`stitch_task.rs`) — the secondary path
For `TaskKind::Stitch(spec)`: fetch each input ciphertext by its content address, **verify each input's address matches its committed `(OutputRef, Commitment)`** (no swap), decrypt each `Role::Output`, concatenate via `ffmpeg_no_disk` (concat over memfds, no disk) into the final rendition, encrypt, commit (single-leaf), upload, submit with the lease epoch. Stitch is mechanically simpler than transcode; the **Transcode path is the load-bearing proof** — if the clock forces cuts, Stitch may degrade to content-address checks only (kickoff §6 scope discipline).

---

## 5. The `verifier` binary (`#![forbid(unsafe_code)]`) — trusted, CPU-bound, separate

### 5.1 Transcode verification (SSIM)
`BRPOP inbox:verifier` → `decode` `VerifyRequest{task, kind, commitment, output}`:
1. `blob = BlobStore.get(&output)`; **bind first:** `verify::check_binding(&blob, &commitment)` — mismatch → `VerifyResult{passed:false, detail:CommitmentMismatch}` and stop (provable byte-swap; heaviest reputation penalty). No challenge frame is chosen before binding passes (§1.2.4).
2. From `kind = Transcode(spec)`: `key = KeySource.key(spec.job, spec.segment)`; decrypt source (`Role::Source`) and worker output (`Role::Output`) into memfds; `ref_out = transcode_no_disk(&src, &spec.profile)` — the independent ground truth.
3. **Batched decode (the cost fix):** choose sampled frame timestamps, then extract **all** of them in **one** `verify::frame` ffmpeg invocation per memfd (select filter) — not per-frame spawn. This is the named remedy for the Phase 3 ~10× artifact; expected cost ≈ the fundamental 1.20× transcode.
4. `verify::verify_segment` → minimum MSSIM vs `RocThreshold::load(ROC_THRESHOLD_PATH)` (the committed calibration/held-out threshold — never a literal) → `VerifyDetail::{Ok | FidelityBelowThreshold}`.
5. Return `VerifyResult{task, passed, detail}` to `sched:inbound`. All media stays in memfds; zeroize on every path; the verifier is key-trusted but no-disk.

### 5.2 Stitch integrity verification (`verify::integrity`, no SSIM)
For `kind = Stitch(spec)`: re-derive the expected rendition by concatenating the **content-verified** input segments (each input's address re-checked against its committed `(OutputRef, Commitment)`) and confirm the worker's output matches the expected concatenation manifest. Integrity, not fidelity — **no SSIM, no re-encode beyond concat**. Cheaper than transcode verification; sampled at the same `p_tier`.

---

## 6. Live transport & the reputation seam (additive `sched`)

- **Return channel:** workers and the verifier `LPUSH` encoded `HeartbeatMsg`/`SubmissionMsg`/`VerifyResult` to a single `sched:inbound` list; `sched`'s `loops.rs` `BRPOP`s and routes to the existing inbound handlers. Additive to Phase 4; the sim path stays green.
- **Rich reputation (closes Phase 4's seam):** the engine's `VerifyResult` handler now calls `reputation::record_verdict(detail)` to apply the **rich asymmetric magnitudes** (`CommitmentMismatch` → Banned in one step; `FidelityBelowThreshold` = sharp; `Ok` = small slow credit; `Inconclusive` = none) rather than the coarse `EmitReputation` delta — so the live verifier's real `VerifyDetail` drives the tier with the `P_MIN` floor intact (§1.3). Phase 4 `sched` tests stay green.
- *(Explicitly deferred, optional, not in this DoD: the per-worker `Timeout` reputation penalty needs `reclaim_expired` to return timed-out holders — a Phase 6/7 polish. Fencing safety does not depend on it.)*

---

## 7. The live single-host smoke run (`live_smoke.rs`)

A gated integration test that stands up, against a local Redis + `LocalBlobStore` (tmpfs) + `LocalKeySource` + a tiny corpus (1–2 segments): the `sched` loops, one or two `worker`s, and one `verifier` (as threads or subprocesses). It must prove the live path enforces the sim's properties:
- **Honest end-to-end:** a `Transcode` task flows place → lease → fetch → decrypt → transcode → encrypt → commit → upload → submit → (sampled) verify → content-addressed release; assert at least one segment is verified `Ok` and released at its content address.
- **Process-level zombie (§1.1):** pause a worker past its lease deadline, let `reclaim_expired` re-dispatch to another worker, resume the zombie; assert its `SubmissionMsg` is rejected (`StaleEpoch`) and **exactly one** output is released. (The full chaos schedule and adversary suite are Phase 6.)
- **Cost spot-check:** record the batched-decode verification cost for one segment and confirm it is far below the Phase 3 per-frame-spawn figure (full distribution → Phase 6).

Gate on ffmpeg + Redis; loud-skip if absent (never fabricate).

---

## 8. Correctness & purity (verify before commit)
- `worker` and `verifier` are `#![forbid(unsafe_code)]`; all `unsafe` remains solely in `crypto::sys`; no async runtime anywhere.
- Worker concurrency derives from the cgroup quota, not host load (assert the read path; no `loadavg`).
- The worker's `commitment`/`output` equal `Commitment::commit(&[SHA-256(blob)])` / `lead128(SHA-256(blob))` — proven by a test that the verifier's `check_binding` accepts the worker's real output and rejects a swapped blob.
- The worker carries the lease epoch on submit/heartbeat; the live zombie smoke proves rejection + single output.
- The verifier binds before sampling; batched decode used (no per-frame spawn — grep/inspect); threshold from `roc-threshold.json`.
- Additive regression: `crypto`, `verify`, `sched` prior-phase suites all green; `contract.rs` both tiers green; `core` 0-byte diff.
- `cargo build --all-targets && cargo clippy --all-targets -- -D warnings && cargo test` clean; allowlist (§2) respected.

---

## 9. Commit discipline (carried forward)
- Conventional Commits `<type>(worker|verifier|crypto|verify|sched): <imperative>`, ≤72 chars; body cites the spec/amendment section and the rejected alternative where relevant.
- Atomic, one logical change per commit, each on a green tree (prior-phase suites included). Never commit red. No `--no-verify`, no force-push, no `core/` edits, no media/large binaries (commit code and the smoke test, not video).

---

## 10. Phase 5 Definition of Done
1. `crypto::blob` (content-addressed ciphertext, `LocalBlobStore`) and `crypto::keysource` (`KeySource` + `LocalKeySource`; TLS production seam documented) added; Phase 2/3 crypto tests green; unsafe still only in `crypto::sys`.
2. `worker` binary (`#![forbid(unsafe_code)]`): registers; cgroup-bounded concurrency (no host load); Transcode hot loop produces `commitment = Commitment::commit(&[SHA-256(blob)])`, `output = lead128(SHA-256)`, uploads, and submits **carrying the lease epoch**; heartbeats during work; Stitch loop handles the second kind; no plaintext on disk, keys/memfds zeroized.
3. `verifier` binary (`#![forbid(unsafe_code)]`): binds before sampling; reference-transcodes; **batched-decode** SSIM (one ffmpeg call for all sampled frames — the Phase 3 cost remedy); threshold from `roc-threshold.json`; `Stitch` integrity (no SSIM); returns `VerifyResult{passed,detail}`.
4. Live transport: `sched:inbound` return channel routed by `sched::loops`; engine applies **rich `VerifyDetail`** via `reputation::record_verdict` (Phase 4 coarse-reputation seam closed); Phase 4 `sched` suite green.
5. Live single-host smoke run (§7): honest end-to-end verified-and-released; **process-level zombie rejected with exactly one output**; batched-decode cost spot-check below the Phase 3 per-frame figure. Gated on ffmpeg + Redis, loud-skip otherwise.
6. `core` unchanged since freeze; additive regression suites all green; full gate green; allowlist respected.
7. Commits per §9; `docs/ARCHITECTURE.md` gains the data-plane section (worker hot loop, verifier, blob store, key-source + TLS seam, batched-decode cost result, cgroup concurrency); `docs/THREAT-MODEL.md` reaffirms the worker-holds-key confidentiality boundary in the live path and records worker-auth/Sybil as a documented non-goal.

Next: `phase6-spec.md` — `bench`: the single-host N-worker harness (deterministic corpus + local blob store), the scheduling-overhead decomposition (Redis-RTT vs decision time, §1.4), the crypto/verification cost distributions, the saturation/backpressure run, and the **chaos/adversary suite** — the slow-zombie chaos schedule (§1.1) and the cheating-worker classes caught at the rate the hypergeometric × (1−FAR) math predicts.

---

# Appendix A — `CLAUDE.md` update for Phase 5

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md
- docs/specs/phase0–4-spec.md  — core (FROZEN), crypto, verify, sched
- docs/specs/phase5-spec.md    — CURRENT: worker + verifier binaries (the live data plane)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- crypto/verify/sched are NOT frozen: §3/§4/§5 add seams ADDITIVELY; ALL prior-phase tests must stay green.

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
8. Phase 5 deps: worker {proctor_core, crypto, redis, sha2, thiserror}; verifier {+verify}. No new crypto/verify/sched deps.

## Commit discipline
Conventional Commits, atomic, GREEN tree (incl. prior-phase suites), body cites spec/amendment.
Never commit red/media/binaries. No --no-verify, no force-push, no core/ edits.

## Scope discipline
worker + verifier + the named additive seams + the smoke run only. NO full measurement / chaos / adversary
suite (Phase 6). End with build+clippy+test, commit(s), change list, STOP.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1 | data-plane seams | `crypto::blob`, `crypto::keysource` | content-addressed put/get + key fetch tested; crypto Phase 2/3 green; commit |
| 2 | worker bin | `worker/` (transcode + stitch + heartbeat + cgroup concurrency) | commitment/output match check_binding; epoch carried; no plaintext on disk; commit |
| 3 | verifier bin | `verifier/` (SSIM + batched decode + stitch integrity) | binds before sampling; batched decode (no per-frame spawn); threshold from file; commit |
| 4 | transport + reputation seam | `sched::{loops,engine}` additive | sched:inbound routed; rich VerifyDetail applied; Phase 4 suites green; commit |
| 5 | live smoke | `live_smoke.rs` | honest e2e released; process-zombie rejected, one output; cost spot-check; commit |
| 6 | docs + DoD | ARCHITECTURE + THREAT-MODEL | data-plane + boundary documented; DoD §10 reported; commit |

Sessions 2 and 3 are the load-bearing bins; keep them separate. If context allows, 1 may bundle with 2.

### Exact prompts (one per session; verify + commit before the next)

**Session 1**
> Read `kickoff-amendment-1.md`, `phase5-spec.md` (§2–§3, §8–§10), and `CLAUDE.md`; update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: add `crypto::blob` (`BlobStore` + `LocalBlobStore`, content-addressed by `lead128(SHA-256(ciphertext))`, ciphertext-on-disk OK) and `crypto::keysource` (`KeySource` + `LocalKeySource`; document the production-TLS seam). Tests: put→get round-trip with address == `OutputRef`; key fetch. Keep `unsafe` only in `crypto::sys`; all Phase 2/3 crypto tests green. Build+clippy `-D warnings`+test; commit `feat(crypto): content-addressed blob store + key-source seam`; STOP.

**Session 2**
> Read `CLAUDE.md` and `phase5-spec.md` §4, §8. Execute **Session 2 only**: build the `worker` binary (`#![forbid(unsafe_code)]`) — register; concurrency from `/sys/fs/cgroup/cpu.max` (never host load); the Transcode hot loop (fetch ciphertext → `decrypt_into_memfd(Role::Source)` → `transcode_no_disk` → `aead::encrypt(Role::Output)` → `commitment=Commitment::commit(&[SHA-256(blob)])`, `output=lead128` → `BlobStore.put` → `SubmissionMsg` carrying `assignment.lease.epoch`); heartbeat-during-work; the Stitch loop (verify input content-addresses → concat no-disk → encrypt → commit → submit). No plaintext on disk; keys/memfds zeroized. Test: the worker's real output passes `verify::check_binding` and a swapped blob fails. Build+clippy+test; commit `feat(worker): transcode/stitch hot loop with epoch-fenced submit`; STOP.

**Session 3**
> Read `CLAUDE.md` and `phase5-spec.md` §5, §8. Execute **Session 3 only**: build the `verifier` binary (`#![forbid(unsafe_code)]`) — `BRPOP` `VerifyRequest`; `check_binding` before any frame; decrypt source+output; reference `transcode_no_disk`; **batched** frame extraction (one ffmpeg call for all sampled timestamps — add `verify::frame` batch; remove per-frame spawn); `verify::verify_segment` vs `RocThreshold::load`; `Stitch` integrity via `verify::integrity` (no SSIM); return `VerifyResult{passed,detail}`. Tests: honest segment `Ok`, frame-substituted `FidelityBelowThreshold`, swapped blob `CommitmentMismatch`; batched decode used. Build+clippy+test; commit `feat(verifier): SSIM + integrity verification with batched decode`; STOP.

**Session 4**
> Read `CLAUDE.md` and `phase5-spec.md` §6, §8. Execute **Session 4 only**: additively wire the live transport — `sched:inbound` return list `BRPOP`+routed by `sched::loops` to the inbound handlers — and make `sched::engine`'s `VerifyResult` path apply the rich magnitudes via `reputation::record_verdict(detail)` (closing Phase 4's coarse-reputation seam). Keep all Phase 4 `sched` + `contract.rs` tests green. Build+clippy+test; commit `feat(sched): live inbound channel + detail-aware reputation`; STOP.

**Session 5**
> Read `CLAUDE.md` and `phase5-spec.md` §7, §8. Execute **Session 5 only**: write `live_smoke.rs` — stand up `sched` loops + 1–2 `worker`s + 1 `verifier` against a local Redis + tmpfs `LocalBlobStore` + `LocalKeySource` + a 1–2 segment corpus; assert (a) honest end-to-end: a Transcode task verified `Ok` and released at its content address; (b) process-level zombie: pause a worker past lease expiry → reclaim → resume → its submit rejected (`StaleEpoch`), exactly one output; (c) spot-check the batched-decode verification cost below the Phase 3 per-frame figure. Gate on ffmpeg+Redis, loud-skip otherwise. Build+clippy+test; commit `test(proctor): live single-host smoke run`; STOP.

**Session 6**
> Read `CLAUDE.md` and `phase5-spec.md` §10. Execute **Session 6 only**: update `docs/ARCHITECTURE.md` (data plane: worker hot loop, verifier with batched-decode cost result, blob store, key-source + production-TLS seam, cgroup-bounded concurrency) and `docs/THREAT-MODEL.md` (reaffirm the worker-holds-key confidentiality boundary in the live path; worker-auth/Sybil documented non-goal). Verify the Phase 5 DoD §10 item by item with evidence; confirm `git diff v0.1.0-core-frozen -- core/` is empty and all prior-phase suites green. Commit `docs: data-plane architecture and threat model`; STOP.
