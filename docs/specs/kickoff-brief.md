# kickoff-brief.md — Zero-Trust Transcoding Network (Repo 3)

*Authoritative kickoff brief. Subordinate to `NORTH-STAR.md`; supersedes the legacy TypeScript `Stream-hive` repo and the fabricated `docs/WORKER_SECURITY.md`. Phase specs live in `docs/specs/phaseN-spec.md` and are written only when reached. Numbers in this repo come from `bench/results/`, never from prose. The executing chat has no other context — read this fully before writing code.*

---

## 0. One-paragraph thesis

A distributed transcoding network is the wrong artifact; the **control plane around untrusted compute** is the right one. This repo keeps the transcoding *vehicle* and rebuilds the substrate as three falsifiable systems primitives, in Rust, measured on one NUMA-isolated host: **(1) probabilistic verification** — a trusted verifier independently re-executes a random subset of a worker's segments and pHash-compares against a threshold that is *measured from an ROC curve*, not invented, with the detection-probability math committed; **(2) shard-scoped, in-memory AES-256-GCM** — per-segment keys delivered over TLS, held `mlock`'d, decrypted to anonymous memory (pipe/`memfd`) and fed to ffmpeg over stdin so **plaintext never touches disk and the key never persists**, with the crypto overhead profiled as a fraction of transcode time; **(3) a backpressure-aware scheduler** — Redis-backed leases, least-loaded *push* dispatch, heartbeats, a **single** lease-expiry reclaim path, explicit saturation backpressure, and reputation that actually gates admission. The deliverable is not the product (no UI, no payments, no chain) — it is the three primitives plus an honest **untrusted-worker threat model** that states plainly what cryptography *cannot* do against a worker that must see plaintext to encode it, and points that residual gap directly at the microVM flagship. The single most important sentence in the repo: *you cannot hide a frame from the process that encodes it; you can bound the exposure and make cheating detectable — and the thing that closes the rest is hardware isolation, which is the flagship.*

---

## 1. Refactor decision table — preserve / drop / rebuild

The legacy repo is a working TypeScript/Turborepo product (`apps/{api,frontend,orchestrator,preprocessor,worker}`, `packages/*`, Prisma/Postgres, S3/CloudFront, Solana). It runs end-to-end. It is also, against the NORTH-STAR values, a **net credibility liability**: the public security doc claims zero-knowledge processing the code refutes, the verification primitive transmits its own answer to the party being tested, and the scheduler's reputation system is observe-only. The audit found these precisely. This is a rebuild of the substrate and a deletion of the product. **The framing language and the runtime change. Calls are final.**

### DROP — delete; do not port (this is the bulk of the legacy repo)

| Item | Reason |
|---|---|
| **`apps/frontend/` (entire Next.js app, landing page, dashboard, video player)** | Product surface. Every component is a feature, not a primitive. A Principal Engineer evaluates the verification math and the scheduler, not a hero section. |
| **`docs/WORKER_SECURITY.md`** | Fabrication: "zero-knowledge… never has access to unencrypted content" while the worker is handed the cleartext key (`presignedUrls.encryptionKey`) and writes plaintext `input.mp4` to disk. Fake gdb/tcpdump/debugfs "proofs," fake SOC 2 / ISO 27001 / bug-bounty claims, container hardening the CD pipeline contradicts. This single file disqualifies on sight. It is replaced by `docs/THREAT-MODEL.md` (§3), which is the opposite: an honest statement of what is and is not defended. |
| **All Solana / payments (`apps/api/routes/worker.ts payWorker`, anchor blocks, `pendingAmount`/`lockedAmount`, `idl/`, `solana-web3.js`)** | On-chain settlement is commented out everywhere; `payWorker` references out-of-scope `programId`/`jobId` and cannot run; `pendingAmount` is a Postgres `int4` that overflows after ~2,147 SOL-tasks. Payment is Coingate's (Repo 5) and solana-mpc-kit's (Repo 4) job — not this repo's. Gone. |
| **The committed Solana keypair `apps/worker/~/.config/solana/id.json`** | A leaked private key in source. Rotate, purge from history, treat its presence as a finding. |
| **`apps/worker/src/security/segmentEncryption.ts` (`SegmentSecurity`)** | Dead code: its `deriveKey(taskId + workerPrivateKey)` can never decrypt content the preprocessor encrypted with a server-generated random key. Two encryption implementations, one fictional. |
| **The HTTP REST task lifecycle (`/tasks/:id/complete`, `/workers/register`)** | A second, weaker state machine that sets `TRANSCODED` and stitches with **no verification** — if ever hit, it bypasses the whole security model. One protocol, not two. |
| **DoD-5220.22-M "secure delete" (3× random overwrite), `global.gc()` "memory clearing"** | Theater on SSD/tmpfs/COW. Replaced by the real property: plaintext never lands on disk in the first place (§2.2). |
| **The TypeScript runtime for the measured path; Express/Socket.IO control plane; the in-memory `connectedWorkers` Map** | Node is not the signal and the in-memory worker map makes the control plane single-instance-by-accident. The substrate is rebuilt in Rust (precedent: Rust-Tcp-Server, Web3-Terminal — no runtime in the measured path). |

### PRESERVE — ideas, not code (almost nothing executable survives)

| Item | How it survives |
|---|---|
| GOP-aligned segmentation + per-segment unique key | Correct instincts. Reborn as the `core` segment manifest + the `crypto` per-segment key (now never persisted). |
| The two-phase intent (transcode → verify → release) | The *idea* that output is withheld until verified is right; the *implementation* (answer leaked, threshold a no-op) is rebuilt in `verify` (§2.1). |
| Priority-by-resolution queueing | The concept survives as scheduler priority classes; the strict-priority-starves-4K bug is fixed with aging. |
| Heartbeat + reclaim-on-death intent | Correct goal; the dual divergent paths (socket-disconnect `reclaimWorkerTasks` vs the DB timeout monitor that never re-queues → zombie tasks) collapse into one lease-expiry authority (§2.3). |
| ffmpeg as the transcode engine | Kept. Writing a transcoder is out of scope and not the signal. ffmpeg is the oracle; we own everything *around* it. |

### REBUILD — the actual work, net-new, in Rust

| Item | Note |
|---|---|
| **`core` — sans-IO protocol + task/lease/segment state machine** | One frozen abstraction, drives every component unmodified (the Rust-Tcp-Server `core` precedent). |
| **`verify` — re-execution spot-check + calibrated pHash + commit-reveal + detection math** | The security centerpiece. Crown-jewel primitive #1. |
| **`crypto` — in-memory shard-scoped AES-GCM, `mlock` + `zeroize`, pipe/`memfd` to ffmpeg** | Crown-jewel primitive #2. |
| **`sched` — Redis-lease least-loaded push dispatch, single reclaim path, backpressure, reputation gate** | Crown-jewel primitive #3. |
| **`bench` — single-host N-worker harness + deterministic corpus + adversary simulator** | Reproducible or it didn't happen. |
| **`docs/THREAT-MODEL.md`** | The highest-signal document. Net-new. |

**The runtime call, stated plainly:** the load-bearing paths are Rust. A Node scheduler doing "least-loaded dispatch" is not a signal; a Rust scheduler with a committed p99 dispatch-latency distribution is. The crypto story (`AES-NI` throughput, `mlock`, `zeroize`, anonymous-memory proof) and the synergy to the Rust microVM flagship only hold if it is the same language and discipline as Repos 1–2. ffmpeg, the blob store, and (if retained) a thin ingest API may stay as out-of-band glue, but they are never in the measured path.

---

## 2. High-signal primitives a Principal Security/Systems Engineer evaluates

Three things a senior reader will actually probe. Each ships with a number and an honest story. The honesty is load-bearing: the previous repo lied about all three, so a rigorous version is a large credibility swing.

### 2.1 Probabilistic transcoding verification — re-execution over a random subset ★

The legacy primitive failed three ways the audit pinned exactly: the orchestrator `socket.emit`'d `expectedPhash` to the untrusted worker (the verifier handed over the answer); the threshold was `< 50` against a 64-char hash while the comment claimed `< 5` (a near-unconditional accept); and a single-frame pHash verifies content *similarity*, not that the *transcode* (codec, bitrate, resolution) was performed. Rebuild:

- **The verifier re-executes, the worker never learns the answer.** A **trusted verifier** (the scheduler host, or a small designated trusted-verifier capacity — never other untrusted workers, which is infinite regress) independently re-transcodes a random subset of a worker's completed segments with byte-identical ffmpeg parameters, decodes frames at random timestamps, and compares to the worker's output. The challenge carries *only* timestamps; the expected hash never leaves the verifier. Worker commits `SHA-256(output)` before it learns which timestamps are challenged (commit-reveal), so it cannot retrofit.
- **The threshold is a measured quantity, not a magic number.** Encoders are not bit-deterministic across builds/hardware, so full-output hashing is wrong; perceptual-hash Hamming distance on decoded frames is the right comparator — *with a calibrated threshold*. Build a **separation study**: measure the Hamming-distance distribution for honest transcodes vs. four attack classes (cheap-downscale, wrong-bitrate, copied-source-frame, black/garbage frame). Plot the **ROC**, pick the threshold at the separating point, and **commit false-accept / false-reject rates**. The threshold is `THRESHOLD = <value from committed ROC>`, traceable to a file — never a constant pulled from the air.
- **Sampling is backed by detection math.** If a fraction `p` of a worker's `n` segments are verified and a cheating worker tampers fraction `f`, per-task detection probability `= 1 − (1 − p)^(f·n)`. Commit the detection-probability curve and pick `p` so the expected cost of cheating exceeds the expected gain (model the economic layer even though payments are descoped). Be explicit about what this proves: not that *every* byte was transcoded correctly, but that **a worker who cannot predict which segments are checked must do the real work or be caught at a known rate** — and any tampered output is tamper-evident via the committed hash.

**Deliverable:** the ROC plot + the detection-probability curve + the honest verdict ("at p=X we catch a worker tampering f=Y% with probability Z per task at false-accept rate R"), and a measured **verification cost** (verifier re-encode time as a percentage of the original transcode — this is the price of trust, and it must be stated).

### 2.2 Shard-scoped, in-memory AES-256-GCM — keys never on disk ★

Rename the legacy "zero-visibility" claim, which was false: the worker received the cleartext key, wrote the full plaintext segment to `input.mp4`, and ran ffmpeg on a file path. The honest, defensible property is **minimal exposure**, and it is real:

- **Plaintext never lands on disk.** Decrypt the segment into anonymous memory and feed ffmpeg over `pipe:0` (stdin) or a `memfd_create`/`/dev/shm` fd that is unlinked on open; take output over `pipe:1` (stdout) and encrypt it in-RAM before any buffer hits storage. **Prove it**: a committed `strace`/`lsof` test showing no disk-backed file descriptor ever holds plaintext. This is the property the legacy doc *claimed* and the code *violated*.
- **Keys never persist.** Per-segment unique key delivered over TLS, held in a single `mlock`'d buffer (no swap), zeroized with `zeroize` (volatile, not `buf.fill(0)` which the optimizer elides), never logged, never written to the database in plaintext (the legacy schema stored `Segment.encryptionKey` cleartext with a comment "will be encrypted itself" that was never honored).
- **Shard-scoping bounds the blast radius.** A worker only ever holds the segments assigned to it, in RAM, for the task window; assignment is randomized so reconstructing a contiguous viewable asset requires collusion covering all `S` segments. Quantify the collusion bound.
- **State the limit honestly.** Against a *root-on-the-worker* adversary this is defeated — they read the ffmpeg process memory. The defended properties are: no *persistent* plaintext artifact, no *key at rest*, no *cross-segment* exposure, no plaintext *in transit* or *in the blob store*. The adversary this does **not** stop is the one the **microVM flagship** exists to stop. Saying this is the elite move; the previous doc's refusal to say it is what made it fabrication.

**Profiling criterion (cryptographic overhead):** committed AES-256-GCM throughput (GB/s) with and without AES-NI; the per-segment latency added by in-memory decrypt+encrypt and the pipe/`memfd` path vs. the legacy file path; and crypto cost as a **percentage of ffmpeg transcode time** (expected to be small — that is the point: confidentiality at this bound is nearly free relative to the encode).

### 2.3 Backpressure-aware scheduler — least-loaded push, single reclaim authority ★

The legacy scheduler was pull-based self-claim over Redis Streams with no placement, an observe-only reputation system (`isSuspicious`/`permanentlyBanned` flagged, never gating the claim), and **two divergent reclaim paths** that strand tasks (socket-disconnect `reclaimWorkerTasks` re-`xAdd`s but never resets the DB row; the 30 s DB monitor sets the row `PENDING` but never re-`xAdd`s → a reclaimed message hits an `ASSIGNED` row, fails the CAS, gets `xAck`'d and dropped → a zombie that is `PENDING` in the DB and absent from every stream, with no `XAUTOCLAIM` sweeper). Rebuild:

- **Least-loaded push dispatch.** The scheduler is the single placement authority: it tracks per-worker in-flight count and an EWMA of recent throughput from heartbeats and *pushes* an assignment (a lease token) to the least-loaded eligible worker. Workers receive; they do not self-select. This is the direct analogue of the microVM control plane placing guests on hosts.
- **One lease, one reclaim path.** Every assignment is a lease with a deadline. A single `XAUTOCLAIM`-based sweeper is the sole authority for *both* DB state and stream state, so they cannot diverge. Re-queue-on-death = lease expiry → one atomic transition (DB `PENDING` + stream re-add). Heartbeats extend the lease; a missed heartbeat lets it expire. The dual-path zombie bug is structurally impossible.
- **Explicit backpressure.** Bounded in-flight per worker (lease count); bounded global queue depth; at saturation the ingest sheds (`429`) or the producer blocks — **decide and document**, exactly as the TCP brief demands for a full accept backlog / job queue. Measure behavior at and past saturation: no unbounded growth, flat memory under sustained overload.
- **Reputation that bites.** The failure stats the legacy repo collected but never used now gate dispatch: rising `verificationFailureRate` / `consecutiveFailures` reduces eligibility, raises that worker's verification sampling rate (adaptive — a suspicious worker gets checked more), and eventually quarantines it. Close the loop.
- **Correct-by-construction for N instances; run one.** All coordination state (worker registry, leases, queues) lives in Redis — no in-memory worker map — so the design admits horizontal scaling. We **run a single scheduler instance and document HA as out-of-scope**, the same honesty as Phase 3's single-host caveat. The signal is the correctness of the scheduling/verification logic, not high availability; HA is the flagship's concern.

**Profiling criterion (scheduling overhead):** committed distributions (p50/p99/p99.9) for dispatch latency (task ready → assigned), scheduler decision time at N = 1/4/16/64 workers, reclaim latency (worker death → task re-dispatched, from a fault-injection run that kills a worker mid-task), and scheduler placement throughput (tasks/s). Demonstrate backpressure holds when offered load exceeds aggregate worker capacity.

---

## 3. Definition of Done + profiling criteria

A hard DoD, mirroring the Rust-Tcp-Server / Web3-Terminal DoD culture. The repo is **not** done until every box is checked.

**Working system behind a clean, frozen abstraction**
- [ ] `core` defines the protocol + task/lease/segment state machine, sans-IO, **frozen after Phase 1** and driving `crypto`, `verify`, `sched`, `worker` unmodified.
- [ ] One task protocol end-to-end (no second HTTP state machine): lease → in-memory decrypt → ffmpeg(pipe) → in-memory encrypt → commit-hash → verify → release → stitch.

**The untrusted-worker threat model (mandatory, the highest-signal artifact)**
- [ ] `docs/THREAT-MODEL.md` defines: **assets** (content confidentiality, content integrity, task liveness); **adversaries** (curious worker, lazy/cheating worker, malicious worker with root, colluding workers, network MITM, compromised blob store); **trust boundaries**; **what each primitive defends and what it explicitly does not** — including the plain statement that a root-on-worker adversary defeats confidentiality and that only the microVM closes it; and the **residual risks**. No marketing language. This file is the antithesis of, and replacement for, the deleted `WORKER_SECURITY.md`.

**Reproducible benchmarks with committed numbers**
- [ ] Committed deterministic video corpus (`bench/corpus/`) + a local blob store (filesystem/tmpfs); the whole network runs on one host with N worker processes pinned to disjoint cores over loopback. Geography is orthogonal to the systems claims and is a documented caveat, not an asterisk.
- [ ] **Cryptographic overhead** committed: AES-GCM GB/s ±AES-NI; in-memory vs file-path latency; crypto as % of transcode time.
- [ ] **Scheduling overhead** committed: dispatch / decision / reclaim latency distributions + placement throughput at N workers; saturation/backpressure run.
- [ ] **Verification** committed: the ROC / separation study (false-accept & false-reject vs threshold), the detection-probability curve, and verification cost as % of transcode time.
- [ ] **Adversary simulation** committed: a cheating worker (cheap-downscale / copied-source / garbage) is caught at the rate the math predicts; a lazy worker (drops segments) is reclaimed; the collusion bound is stated.

**Profiling teardown (mechanical sympathy)**
- [ ] `perf stat` on the crypto hot path (AES-NI confirmed via IPC / instruction mix) and on the scheduler placement loop, committed.
- [ ] The numbers interpreted, not just dumped: where the crypto cost goes, where the scheduler spends its time at 64 workers, why backpressure shape looks as it does.

**Honesty, packaging, ownership**
- [ ] Writeups state where a primitive's guarantee ends and what surprised us (e.g., the false-accept rate at the chosen threshold; the verification cost). A profiled honest limit beats a fabricated guarantee.
- [ ] `docs/BENCHMARKS.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, `docs/PROFILING.md`, a 60-second-graspable `README.md`, `docs/x-thread.md`.
- [ ] **Self-audit passed:** I can re-derive from memory (a) the verification detection-probability argument and why the threshold sits where the ROC put it, (b) the precise confidentiality boundary and why root-on-worker defeats it, and (c) why the single lease-expiry reclaim path cannot strand a task. If I can't explain it, I don't own it, and it can't support the flagship. Generation must never outrun comprehension.

---

## 4. Synergy to the microVM flagship sandbox

Every primitive here is a sandbox component, built and measured in isolation first. The flagship is assembly, not invention — and crucially, the *honest limit* of this repo is the flagship's reason to exist.

- **In-memory shard-scoped crypto + the honest "root-on-worker wins" → the microVM guest-isolation mandate.** This repo proves how far commodity-process confidentiality goes and exactly where it stops. The microVM is the mechanism that hardware-enforces what cryptography alone cannot: a guest that processes content it must decode, without the host operator or a co-tenant reading its memory. The residual risk written in `THREAT-MODEL.md` *is* the flagship's spec.
- **Probabilistic re-execution verification → the sandbox's proof-of-execution / output attestation.** "Did the untrusted worker actually do the work, or fake it?" is identical to "did the sandboxed agent actually run the computation it was paid for?" The re-exec spot-check, commit-reveal, calibrated threshold, and detection math transfer directly to attesting untrusted guest output.
- **Least-loaded push scheduler + lease/heartbeat/single-reclaim + backpressure + reputation gate → the sandbox control plane.** Placing transcode tasks on workers, reaping dead ones via lease expiry, and shedding under overload is precisely placing microVM guests on hosts, reaping crashed guests, and protecting the control plane from a flood. This is the same multi-reactor-control-plane analogue named in the Rust-Tcp-Server brief, now carrying real placement and failure semantics.

By the time the flagship begins, the attestation primitive, the confidentiality boundary, and the untrusted-compute scheduler are already built, measured, and — for the part crypto cannot solve — *honestly scoped to motivate the microVM itself*.

---

## 5. Phase breakdown — autonomous Claude Code sessions

Spec-driven, agent-executed. One session = one deliverable, ends **build + clippy + test green → commit → STOP**. Each phase gets its own `docs/specs/phaseN-spec.md`, written only when reached. A `CLAUDE.md` guardrail forbids touching future phases. Load-bearing phases (the elite-signal ones) flagged ★.

**Phase 0 — Demolition + Rust workspace skeleton + `CLAUDE.md` + threat-model stub.**
Delete `apps/frontend`, all Solana/payments, the committed keypair, `segmentEncryption.ts`, the HTTP REST lifecycle, the DoD-5220 cleanup, and `WORKER_SECURITY.md`. Stand up the new Rust workspace: `core`, `crypto`, `verify`, `sched`, `worker`, `bench` as compiling stubs. Add `CLAUDE.md`. Commit a `docs/THREAT-MODEL.md` skeleton (assets / adversaries / boundaries headings) and the corpus plan. → green + commit + STOP.

**Phase 1 — `core`: protocol + task/lease/segment state machine. FREEZE core.** ★
Define the segment manifest, the task lifecycle (`Pending → Leased → Transcoded → Verifying → Verified → Released → Stitched | Reclaimed | Failed`), the lease type (deadline, holder, epoch), and the commit-reveal types — all sans-IO, no Redis, no ffmpeg, no sockets. Differential/unit tests against hand-verified sequences. After this passes, **`core` is frozen** and drives every later component unmodified. → green + commit + STOP.

**Phase 2 — `crypto`: in-memory AES-256-GCM, `mlock` + `zeroize`, pipe/`memfd` to ffmpeg.** ★
Per-segment key handling (never on disk), decrypt-to-anonymous-memory, ffmpeg over `pipe:0`/`pipe:1`, encrypt output in-RAM. The no-plaintext-on-disk proof (committed `strace`/`lsof` test). Crypto-overhead microbench (GB/s ±AES-NI; in-memory vs file path). → green + commit + numbers + STOP.

**Phase 3 — `verify`: re-execution spot-check + calibrated pHash + commit-reveal + detection math.** ★
Trusted-verifier re-encode of a random subset; commit-reveal so the worker never learns challenged timestamps or expected hashes; the **separation study + ROC** that sets the threshold; the detection-probability curve. Verification cost measured. This is the security centerpiece — do not let it slip. → green + commit + numbers + STOP.

**Phase 4 — `sched`: Redis-lease least-loaded push dispatch + single reclaim + backpressure + reputation gate.** ★
Redis-backed worker registry + lease store (no in-memory map); least-loaded push assignment; heartbeat-extends-lease; the single `XAUTOCLAIM` reclaim authority; explicit saturation backpressure (decide shed-vs-block, document it); reputation-gated admission + adaptive verification sampling. → green + commit + STOP.

**Phase 5 — `worker`: the assembled hot loop.**
Receive lease → in-memory decrypt (`crypto`) → ffmpeg transcode over pipes → in-memory encrypt → commit hash → respond to verification challenge → on release, upload + ack. Honest cleanup (unlink + RAM zeroize; no DoD-5220 theater). Container/cgroup-aware concurrency (read the cgroup limit, not `os.loadavg()` of the host — the legacy bug). → green + commit + STOP.

**Phase 6 — `bench`: single-host N-worker harness + corpus + adversary simulator.** ★
Deterministic corpus + local blob store; N pinned worker processes over loopback; scheduling-overhead, crypto-overhead, and verification-cost distributions; the saturation/backpressure run; a **fault-injection run** (kill a worker mid-task, measure reclaim latency); the **adversary simulator** (cheating / lazy / colluding workers) producing the caught-at-predicted-rate result. Commit everything to `bench/results/`. → commit numbers + STOP.

**Phase 7 — `docs/THREAT-MODEL.md` + `docs/PROFILING.md` + adversary results.** ★
Complete the threat model from the measured behavior; write the profiling teardown (`perf stat` on crypto + scheduler, interpreted); fold in the adversary-simulation numbers and the explicit confidentiality boundary. → commit + STOP.

**Phase 8 — DoD close-out + distribution-ready.**
`docs/BENCHMARKS.md`, `docs/ARCHITECTURE.md`, 60-second `README.md`, `docs/x-thread.md`. Pass the self-audit. Then — and only then — distribution. → commit + STOP.

---

## 6. Out of scope — do NOT do these

- **No frontend, no UI, no landing page, no video player.** The transcoding is the vehicle; the primitives are the deliverable.
- **No Solana, no payments, no on-chain anything, no wallet.** That is Repos 4 and 5. Model the economic layer of verification on paper only.
- **No writing a transcoder.** ffmpeg is the oracle; we own the protocol, crypto, verification, and scheduling around it.
- **No S3 / CloudFront in the measured path.** A local blob store (filesystem/tmpfs) keeps the benchmark reproducible; an S3 adapter may sit behind a trait but is never measured (a benchmark you can't replay is not a benchmark).
- **No real multi-host / HA control plane.** Coordination state is Redis-backed so the design *admits* it; we run one scheduler instance and document HA as out-of-scope, exactly like the Phase 3 single-host caveat.
- **No TLS implementation.** Assume TLS for transport; do not build a TLS stack.
- **No async runtime in the measured path** (Rust-Tcp-Server / Web3-Terminal precedent). The verifier re-encode and ffmpeg invocations are subprocesses; the scheduler and crypto paths are hand-built.
- **Do not chase a confidentiality claim cryptography cannot deliver.** State the root-on-worker limit; point it at the flagship.
- **Do not exceed the phase order.** Resist adding back any product surface.

---

## 7. Non-negotiable engineering rules (carried from NORTH-STAR)

1. **Honesty is the signal.** State the confidentiality boundary, the false-accept rate, the verification cost. The deleted `WORKER_SECURITY.md` is the cautionary tale: an honest negative result with a profile is elite; a fabricated guarantee is disqualifying.
2. **Measure, never guess.** Every claim — threshold, detection probability, crypto overhead, dispatch p99 — traces to a committed file in `bench/results/`. The verification threshold is a value read off a committed ROC, never a constant.
3. **Distributions, not averages.** p99/p99.9 + full histograms for dispatch, reclaim, and verification latency, coordinated-omission-correct.
4. **Mechanical sympathy.** Know the cost of AES-NI vs software AES, the cost of a `memfd` vs a disk write, the scheduler's cache behavior at 64 workers. Pin worker processes to cores; be NUMA-aware on the bench host.
5. **One abstraction, many implementations.** `core` is the product, frozen after Phase 1, driving every component unmodified.
6. **Correctness under failure first.** A dead worker must never strand a task (single reclaim authority). A flood must never grow memory unbounded (explicit backpressure). A cheating worker must be caught at a known rate (detection math).
7. **Scope discipline.** One session, one deliverable, green + commit + STOP. Future phases are off-limits until reached. Generation must never outrun comprehension — the audit and self-audit windows are the actual work.
8. **Simple and fast beats clever and fast.** Do not add a mechanism the threat model or the benchmark does not justify.

Use the vocabulary of this domain — *trust boundary, commit-reveal, detection probability, ROC, blast radius, lease expiry, backpressure, adaptive sampling, AES-NI, anonymous memory* — but **only after the technique is actually applied.** Decorative jargon is detected instantly. The previous repo earned none of its terms; this one earns every one before using it.

---

## 8. First message for the executing chat

Paste this brief, then start with:

> "Execute Phase 0. Per §1 and §5: delete the entire `apps/frontend`, all Solana/payments code, the committed keypair, `segmentEncryption.ts`, the HTTP REST task lifecycle, the DoD-5220 cleanup, and `docs/WORKER_SECURITY.md`. Stand up the new Rust workspace with `core`, `crypto`, `verify`, `sched`, `worker`, and `bench` as compiling stubs. Add the `CLAUDE.md` guardrail and a `docs/THREAT-MODEL.md` skeleton (assets / adversaries / trust boundaries / what-is-and-isn't-defended). Show me the workspace tree, the `core` public types you intend to freeze in Phase 1, and the list of deleted paths before writing any implementation."
