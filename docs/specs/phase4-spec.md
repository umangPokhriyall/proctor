# proctor — Phase 4 Specification: `sched` — Epoch-Fenced Scheduling on a Redis-Backed Store

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0–3-spec.md`. Read the amendment (§1.1, §1.3, §1.4) first.
**This is the complete, authoritative Phase 4 spec.** It implements `sched` — the control plane: a Redis-backed durable store with **epoch-fenced compare-and-set** (the §1.1 fencing-token enforcement that kills zombie *writes*, not just stranded tasks), **least-loaded push** dispatch, a **single** lease-expiry reclaim authority, the **tier→`p` adaptive sampling policy with the `P_MIN` floor** (§1.3), **content-addressed release**, and **Little's-law-sized** backpressure (§1.4). The frozen `core::Task` state machine *is* the scheduler's transition authority; the store enforces the identical epoch rule atomically at the durable layer.
**Scope:** `sched/` plus a deterministic in-memory `Store` and a Redis `Store`, tested against simulated workers/verifier. The **real worker and verifier binaries are Phase 5**; the single-host end-to-end run and chaos sims are Phase 6. No transcode, no crypto, no SSIM in `sched`.
**Audience:** Claude Code. Authoritative. **Claude Code commits its own work.** A reachable Redis is required for the integration tier (gated like ffmpeg was).
**Frozen:** `proctor_core` is FROZEN (`v0.1.0-core-frozen`); `git diff v0.1.0-core-frozen -- core/` stays empty. `sched` consumes the frozen `proto`/`Task`/`Lease`/`Epoch` unmodified — if it appears to need a `core` change, the design is wrong: STOP and escalate.

---

## 0. Phase 4 in context, and the one idea that carries it

The legacy scheduler was pull-based self-claim with an observe-only reputation system and two divergent reclaim paths that stranded tasks; the audit pinned every one. This phase builds the honest control plane, and its spine is a single idea the directive made explicit: **a heartbeat timeout is a liveness heuristic and must never be a safety mechanism.** Reclaim re-dispatches a missed-heartbeat task for liveness; **fencing** — the monotonic `Epoch` already frozen into `core` — is what guarantees safety, by making a slow-zombie's late write *rejected at the durable store*, atomically, so exactly one output ever exists for a segment.

The elegant consequence of the freeze: **`core::Task::apply` is the scheduler's transition authority.** `sched` loads a task's state, applies a `TaskEvent`, gets back `Vec<TaskAction>`, and executes those actions against the store — and the store performs the *same* epoch compare-and-set that `core` does in memory (`Err(StaleEpoch)`). Defense in depth: even if an `sched` instance is restarted or racing, the durable layer cannot accept a stale-epoch write.

**Honest design inputs carried from Phase 3 (not cosmetic):**
- Effective detection `= P_detect_hypergeometric(f,n;p) × (1 − FAR)`. With the measured held-out FAR ≈ 21%, a single verify *pass* is weak evidence of honesty. The reputation policy is therefore **asymmetric** — fast to distrust on a fail, slow to trust on a pass (§5). The verify-side remedy (FAR-constrained threshold / higher comparison plane) is named and tracked, not silently absorbed.
- Verification cost ≈ 1.20× transcode fundamentally (the ~10× measured artifact is per-frame ffmpeg process-spawn, optimizable). This sizes trusted-verifier capacity (§5.4): at `P_MIN = 0.02` and 1.20×, verification is ≈ 2.4% of worker compute — cheap.
- **Carried correction:** amendment §1.2.1's "binomial overstates" is wrong; the published math has `hypergeometric ≥ binomial` (binomial under-states, worst at small `n`), per Phase 3 `DETECTION.md`. `sched` consumes the published **hypergeometric** family as-is; the sign error affects no Phase 4 logic. Recommend folding the one-line wording fix into `kickoff-amendment-1.md` during the docs session.

**Human/Claude split:** Claude Code executes including commits. The Redis integration tier runs where a Redis is reachable; the in-memory tier always runs.

---

## 1. Phase 4 in one paragraph

Implement `sched` (`#![forbid(unsafe_code)]`) over a `Store` trait whose operations are **atomic and epoch-fenced** — `lease`, `extend_lease` (heartbeat), `submit`, `select_or_accept`, `verify_outcome`, `reclaim_expired`, `release` — with a deterministic **in-memory** implementation and a **Redis** implementation (Lua-scripted atomics over ZSET/list/hash), proven equivalent by a shared contract-test suite. The scheduler holds each task as a frozen `core::Task`, drives transitions through `core::Task::apply`, and persists them through the store; **least-loaded push** placement (`place`) picks the least-loaded eligible worker by in-flight count and EWMA throughput from heartbeats, with priority + aging; the **single reclaim authority** (`reclaim`) sweeps the lease-deadline index and atomically re-dispatches with a bumped epoch; the **reputation** module maps verify outcomes to tiers and tiers to a sampling fraction `p` with a hard `P_MIN` floor (asymmetric updates), and the **sampling** decision routes a `p`-fraction of submissions to the verifier; **backpressure** bounds per-worker in-flight and global queue depth from a Little's-law sizing. Prove the slow-zombie write is rejected at the durable layer against both stores, then wire the dispatch and reclaim loops in `main.rs` and exercise them with simulated workers/verifier.

### 1.1 Frozen / consumed (alignment with the real code)
- `core::proto` (postcard `encode`/`decode`): `Assignment`, `HeartbeatMsg`, `SubmissionMsg{task,worker,epoch,commitment,output:OutputRef}`, `ChallengeMsg`, `VerifyRequest{task,kind,commitment,output}`, `VerifyResult{task,passed,detail}`. Holder-action messages carry `(worker, epoch)` — fed straight into `TaskEvent`s.
- `core::Task`/`TaskState{Pending,Leased,Submitted,Verifying,Accepted{output,commitment},Failed}`/`TaskEvent{Lease,Heartbeat,Submit,SelectForVerification,Accept,VerifyOutcome,LeaseExpired,Abandon}`/`TaskAction{Requeue,IssueChallenge,NotifyAccepted,MarkFailed,EmitReputation(ReputationDelta)}`/`TransitionError{StaleEpoch,WrongHolder,IllegalTransition,Terminal}`; `Task::apply(&mut self, ev) -> Result<Vec<TaskAction>, TransitionError>`; `epoch_hw`, `retries`, `MAX_RETRIES=3`.
- `core::Lease{holder,epoch,deadline}`, `Lease::is_expired(now)`, `Epoch` (`Ord`, `ZERO`, `next()`), `LogicalTime`, `WorkerId`, `TaskId`, `OutputRef` (u128), `Commitment`.
- `core::VerifyResult`/`VerifyDetail` (categorical: `Ok`/`CommitmentMismatch`/`FidelityBelowThreshold`/`Inconclusive`) — `sched` consumes these to update reputation; it does **not** depend on `verify` or `crypto`.
- Content addressing: the verified `OutputRef` is the leading 128 bits of `SHA-256(blob)` (Phase 3 `check_binding`), and the recorded `Commitment` anchors the bytes — used for content-addressed release (§7).

---

## 2. `sched` module layout, dependency allowlist, and the Store discipline

```
sched/src/
  main.rs          # binary: config, connect store, run dispatch + reclaim loops
  lib.rs           # #![forbid(unsafe_code)] + re-exports
  store/
    mod.rs         # Store trait — the atomic, epoch-fenced operation contract
    memory.rs      # deterministic in-memory impl (reference semantics; unit tests)
    redis.rs       # Redis impl — Lua-scripted atomics over ZSET/list/hash
    contract.rs    # the shared suite run against BOTH impls (differential oracle)
  place.rs         # least-loaded selection + EWMA + priority/aging
  reputation.rs    # tiers, tier->p with P_MIN floor, asymmetric standing updates from VerifyResult
  sample.rs        # Bernoulli(p_tier) verify-sampling decision (injectable RNG)
  backpressure.rs  # Little's-law sizing; bounded queue + per-worker in-flight; shed-vs-block
  engine.rs        # holds core::Task, applies TaskEvent via core::apply, executes TaskActions against the store
  loops.rs         # the dispatch loop + the reclaim loop
  sim.rs           # #[cfg(test)] simulated worker/verifier that speak core::proto
```

**Dependency allowlist — Phase 4 adds exactly these to `sched`:**
- `proctor_core` (frozen) — proto, Task, Lease, Epoch, ids.
- `redis` (sync client; **no async runtime**) — connections + `redis::Script` for Lua atomics.
- `rand` — `Bernoulli(p)` sampling; injectable RNG (OsRng in prod, seeded in tests). (`core` forbids `rand`; `sched` is not sans-IO, so it is fine here.)
- `thiserror` — error enums.

No `tokio`/async, no `unsafe` (forbidden), no `crypto`, no `verify`. Wire (de)serialization uses `core::proto::encode`/`decode`; store-internal worker-registry fields are discrete Redis hash fields (numbers/strings) — no extra serde dep.

**The Store discipline (NORTH-STAR sans-IO applied to the control plane):** the scheduler's *decision* logic (`place`, `reputation`, `sample`, `backpressure`, `engine`) is written over the `Store` trait, free of Redis specifics. Two implementations — `memory` (the reference) and `redis` — are held to one `contract.rs` suite, the way one frozen `core` drove eleven server models and one LOB `core` drove four books. The Redis Lua atomics are correct iff they pass the same contract as the in-memory reference, including the slow-zombie test (§3.3).

---

## 3. The `Store` trait, epoch-fenced CAS, and the single reclaim authority (§1.1)

### 3.1 The contract
Every state-mutating operation is **atomic** and **epoch-fenced**: a write naming `(worker, epoch)` is applied **iff** it matches the task's current lease, else rejected without mutation. This mirrors `core::Task::apply`'s `Err(StaleEpoch)`/`WrongHolder` at the durable layer.

```rust
pub trait Store {
    /// Lease a Pending task to `worker`. Assigns epoch = epoch_hw.next() atomically;
    /// fails if not Pending. Records deadline in the lease-deadline index.
    fn lease(&self, task: TaskId, worker: WorkerId, deadline: LogicalTime) -> Result<Epoch, StoreError>;

    /// Heartbeat: extend the deadline IFF (holder, epoch) match the current lease. Else StaleEpoch/WrongHolder.
    fn extend_lease(&self, task: TaskId, worker: WorkerId, epoch: Epoch, new_deadline: LogicalTime) -> Result<(), StoreError>;

    /// Worker submission: record (commitment, output) and move Leased->Submitted IFF (worker, epoch) match.
    /// THE ZOMBIE-KILLER: epoch < current ⇒ Err(StaleEpoch), no mutation.
    fn submit(&self, task: TaskId, worker: WorkerId, epoch: Epoch, commitment: Commitment, output: OutputRef) -> Result<(), StoreError>;

    /// Probabilistic gate: Submitted -> Verifying (sampled) or Submitted -> Accepted (unsampled, content-addressed).
    fn select_or_accept(&self, task: TaskId, sampled: bool) -> Result<(), StoreError>;

    /// Apply a verifier verdict: Verifying -> Accepted (pass) or -> Pending/Failed (fail, retry-aware).
    fn verify_outcome(&self, task: TaskId, passed: bool) -> Result<(), StoreError>;

    /// THE SINGLE RECLAIM AUTHORITY: atomically find leases with deadline < now, set Pending,
    /// bump epoch_hw, re-enqueue to the ready index. Returns reclaimed task ids.
    fn reclaim_expired(&self, now: LogicalTime) -> Result<Vec<TaskId>, StoreError>;

    /// Ready-queue + registry ops for placement/backpressure (enqueue, pop-by-priority, worker load, standing).
    fn enqueue_ready(&self, task: TaskId, priority: Priority, now: LogicalTime) -> Result<(), StoreError>;
    fn pop_ready(&self) -> Result<Option<TaskId>, StoreError>;
    fn worker_load(&self, worker: WorkerId) -> Result<WorkerLoad, StoreError>;     // in_flight, ewma_throughput, last_heartbeat
    fn update_standing(&self, worker: WorkerId, delta: ReputationDelta) -> Result<Tier, StoreError>;
    // ... heartbeat registry, in-flight accounting, content-addressed release index
}
```

### 3.2 The Redis data model
- **Ready queue:** a ZSET scored by `priority * BIG − enqueue_time` (priority first, FIFO-with-aging within a class; aging promotes starved low-priority tasks — no strict-priority starvation, the legacy bug).
- **Lease per task:** a hash `task:{id}` `{status, holder, epoch, deadline, commitment, output, retries}`. **All transitions via `redis::Script` (Lua)** so the read-compare-write is atomic — the only way the epoch CAS is race-free without `WATCH` retries.
- **Lease-deadline index:** a ZSET scored by deadline; `reclaim_expired` is one `ZRANGEBYSCORE 0 now` + a Lua reclaim per task (epoch++, status→Pending, re-`enqueue_ready`) — the single authority, with **no `XAUTOCLAIM`/stream PEL second path** (the legacy divergence is structurally absent).
- **Worker registry:** hash `worker:{id}` `{last_heartbeat, in_flight, ewma_throughput, tier, standing}`.
- **Worker inbox (push dispatch):** a list `inbox:{worker}`; the scheduler `LPUSH`es an encoded `core::proto::Assignment`; the worker `BRPOP`s. (Verifier inbox analogous for `VerifyRequest`.)
- **Release index (content-addressed):** keyed by `Commitment`/`OutputRef` → the accepted bytes' location (§7).

### 3.3 The slow-zombie store-level proof (the §1.1 headline test, run against BOTH stores)
1. Worker A `lease(T)` → epoch `e1`, deadline `d1`.
2. Advance now past `d1`; `reclaim_expired(now)` → `T` Pending, `epoch_hw` bumped; re-leased to Worker B → `e2 > e1`.
3. Zombie Worker A `submit(T, A, e1, …)` → **`Err(StoreError::StaleEpoch)`**, no mutation.
4. Worker B `submit(T, B, e2, …)` → `Ok`.
5. Assert **exactly one** `Accepted` output (B's), the zombie rejected, no second output. Heartbeat variant: A's `extend_lease(T, A, e1, …)` after reclaim is likewise rejected (it cannot resurrect its lease).

This is the durable-layer complement to `core`'s in-memory `StaleEpoch` property test, and the chaos/process version lands in Phase 6.

---

## 4. `place.rs` — least-loaded push placement

The scheduler is the **placement authority**; workers receive, never self-select (the legacy reversal). On a ready task, choose the **least-loaded eligible** worker:
- **Eligibility:** alive (recent heartbeat), not suspended/banned (reputation gate, §5), and under its per-worker in-flight cap (backpressure, §6).
- **Load metric:** primary = in-flight lease count; tiebreak = EWMA of recent completion throughput from heartbeats (a faster worker is preferred at equal in-flight). EWMA is pure math; document the smoothing factor.
- **Priority + aging:** `pop_ready` honors priority class with aging so a low-priority (e.g., 4K) task cannot starve indefinitely.
- Dispatch = atomically create the lease (epoch via `lease`) **and** `LPUSH` the encoded `Assignment` to the worker inbox; record in-flight. If no eligible worker, the task stays ready (backpressure/queue depth governs intake, §6).

---

## 5. `reputation.rs` + `sample.rs` — the adaptive policy with a floor (§1.3)

### 5.1 Tiers and the floor
A small ordered set of reputation tiers (e.g., `Pristine`, `Watch`, `Suspect`, then `Suspended`/`Banned` as eligibility states). Each non-terminal tier maps to a sampling fraction `p_tier`, with a **hard floor `P_MIN = 0.02`** applied to *every* worker including pristine — so `k = ⌈p·n⌉ ≥ 1` always and **no worker is ever unsampled** (the §1.3 resolution; this is the published-curve family's floor).

### 5.2 Asymmetric updates (the honest response to FAR ≈ 21%)
A `VerifyResult` updates standing:
- **Fail** (`FidelityBelowThreshold`/`CommitmentMismatch`): a large standing penalty → escalate tier sharply (sampling rises fast). A `CommitmentMismatch` (anti-swap, §7) is the heaviest — it is provable cheating, not a fidelity judgment.
- **Pass** (`Ok`): a small standing credit → de-escalate *slowly* toward the floor. Because effective detection `= P_hyper × (1 − FAR)` and FAR ≈ 21%, one pass is weak evidence; trust accrues over many independent passes, never on one.
- `Inconclusive`: no standing change; re-sample.
- Suspended/Banned workers are **ineligible for dispatch** (§4) — the loop is closed; reputation *bites*, unlike the legacy observe-only system.

### 5.3 Sampling decision (`sample.rs`)
On `Submitted`, draw `Bernoulli(p_tier)` (injectable RNG; seeded in tests). Sampled → `select_or_accept(task, true)` → `SelectForVerification` → push `VerifyRequest` to the verifier inbox. Unsampled → `select_or_accept(task, false)` → `Accept` (content-addressed release, §7). All transitions go through `core::Task::apply` (engine, §7).

### 5.4 Verifier-capacity sizing (documented, feeds Phase 6)
Trusted-verifier capacity must be `≥ Σ_workers p_tier × throughput × cost_multiplier`. With `P_MIN = 0.02` and the fundamental 1.20× cost, that is ≈ 2.4% of aggregate worker compute. The ~10× per-frame-spawn artifact (Phase 3) would raise it to ≈ 20%; the in-process-decode optimization (Phase 5 verifier bin) removes it. State this; it is the price of trust.

---

## 6. `backpressure.rs` — Little's-law sizing (§1.4)

Bound growth with arithmetic, not vibes:
- **Per-worker in-flight cap** and **global ready-queue depth cap** set from Little's law: target in-flight `L = λ × W`, where `W` = mean service time (the measured transcode time from Phase 2/3, cited) and `λ` = target arrival rate. Document the chosen `λ`, `W`, and the resulting caps.
- **At saturation, decide and document:** when the ready queue is at its cap, intake (`enqueue_ready` from the bench injector — there is no API, per locked decision) **sheds** (returns a `Backpressure` error the injector must handle) rather than growing unbounded. Memory stays flat under sustained overload — a Phase 6 assertion.
- **Pre-commit the Phase 6 dispatch-latency decomposition:** count the Redis round trips per dispatch (lease Lua + inbox `LPUSH` + registry update = N RTTs) and predict "in-process decision time ≈ X µs; p99 dispatch ≈ N × RTT and is ~95% Redis." Phase 6 confirms; this framing preempts "your scheduler is just Redis latency."

---

## 7. Content-addressed release, and how `core::Task` drives `sched` (`engine.rs`)

- **`core::Task` is the transition authority.** For each event, `engine` loads the task, calls `core::Task::apply(ev)`, and executes the returned `TaskAction`s against the store: `Requeue` → `enqueue_ready` (+ the reclaim epoch bump already applied), `IssueChallenge` → push `VerifyRequest`, `NotifyAccepted` → content-addressed release, `MarkFailed` → terminal, `EmitReputation` → `update_standing`. The store's epoch CAS enforces the same rule `apply` does — belt and suspenders.
- **Release is anchored by the `Commitment`.** Because `commitment = Commitment::commit(&[SHA-256(blob)])`, the recorded commitment binds the exact bytes. **Sampled** segments are bound *eagerly* (the verifier downloaded the blob and checked it before its verdict). **Unsampled** segments are released with the commitment recorded; any consumer fetching the output re-checks `Commitment::commit(&[SHA-256(fetched)]) == recorded` before use (lazy binding). Either way a post-submit blob swap is detectable, and the `Accepted{output, commitment}` release references the verified bytes — closing the verified-then-swapped TOCTOU (pairs with §1.1 fencing). The release index is keyed by the content address (`OutputRef`), never the task id.

---

## 8. Loops and the simulated harness (`loops.rs`, `sim.rs`)

- **Dispatch loop:** pop ready → place → lease+push (or hold under backpressure).
- **Reclaim loop:** periodic `reclaim_expired(now)` — the single authority; bounded interval, documented.
- **Inbound handling:** decode `HeartbeatMsg`/`SubmissionMsg`/`VerifyResult` → corresponding `TaskEvent` → `engine`.
- **`sim.rs` (`#[cfg(test)]`):** a simulated worker and verifier that speak `core::proto` — register, heartbeat, submit with chosen `(worker, epoch)` (including a deliberately stale zombie), and return chosen `VerifyResult`s. This exercises placement, fencing, reputation, sampling, and backpressure end-to-end **without** the real binaries. The **real worker and verifier bins are Phase 5**; the real single-host run and the slow-zombie *chaos schedule* are Phase 6.

---

## 9. Correctness & purity (verify before commit)
- `sched` is `#![forbid(unsafe_code)]`; all `unsafe` remains solely in `crypto::sys`.
- **Differential store oracle:** `contract.rs` runs the same suite against `memory` and `redis`, including the §3.3 slow-zombie test and the heartbeat-after-reclaim rejection. Both pass identically (Redis tier gated on a reachable Redis; skip loudly if absent — never fabricate).
- Placement chooses least-loaded among eligible; suspended/banned excluded; priority aging prevents starvation (tested).
- Reputation: fail escalates sharply, pass de-escalates slowly, floor keeps `k ≥ 1`; `CommitmentMismatch` is heaviest; eligibility gate enforced.
- Backpressure: queue cap holds; intake sheds at saturation; caps derived from documented Little's-law arithmetic.
- `core::Task::apply` is the sole transition authority; `git diff v0.1.0-core-frozen -- core/` empty; allowlist (§2) respected; `cargo build && cargo clippy --all-targets -- -D warnings && cargo test` clean.

---

## 10. Commit discipline (carried forward)
- Conventional Commits `<type>(sched): <imperative>`, ≤72 chars; body cites the spec/amendment section and the rejected alternative where relevant.
- Atomic, one logical change per commit, each on a green tree. Never commit red. No `--no-verify`, no force-push, no `core/` edits, no media/large binaries.
- The Redis impl and the in-memory impl land such that `contract.rs` is green at each commit (the in-memory impl first, then Redis proven against the same suite).

---

## 11. Phase 4 Definition of Done
1. `sched` implements the §2 modules; `#![forbid(unsafe_code)]`; deps exactly `proctor_core`, `redis`, `rand`, `thiserror`.
2. `Store` trait with **atomic, epoch-fenced** ops; `memory` and `redis` impls pass one shared `contract.rs` suite (Redis tier gated/loud-skip).
3. **The slow-zombie write is rejected at the durable layer** against both stores (§3.3), and the heartbeat-after-reclaim variant; exactly one output exists.
4. **Single reclaim authority** (`reclaim_expired`) with epoch bump + re-enqueue; **no second reclaim path** (no stream PEL/`XAUTOCLAIM`).
5. Least-loaded **push** placement with EWMA + priority aging; eligibility gates on liveness and reputation.
6. Tier→`p` adaptive policy with **`P_MIN = 0.02` floor** (no worker unsampled), **asymmetric** updates (fast distrust / slow trust), `CommitmentMismatch` heaviest; suspended/banned excluded from dispatch.
7. **Content-addressed release** anchored by `Commitment` (eager for sampled, lazy for unsampled); release index keyed by content address; TOCTOU closed.
8. **Little's-law-sized** backpressure (documented `λ`, `W`, caps); intake sheds at saturation; the Phase 6 dispatch-latency-decomposition prediction recorded.
9. `core::Task::apply` is the transition authority (engine executes `TaskAction`s); `core` unchanged since freeze; full gate green.
10. Commits per §10; `docs/THREAT-MODEL.md` gains the **fencing-token** paragraph (heartbeat = liveness heuristic, never safety; cross-reference Coingate §1.2 XAUTOCLAIM-steal) and `docs/ARCHITECTURE.md` gains the scheduler design + the Little's-law sizing + the verifier-capacity sizing; the amendment §1.2.1 wording correction folded in.

Next: `phase5-spec.md` — the **worker** and **verifier** binaries: the worker hot loop (lease → in-memory decrypt → ffmpeg(memfd) → encrypt → commit `Commitment::commit(&[SHA-256(blob)])` → submit with epoch), and the thin verifier (consume `VerifyRequest` → `verify::verify_segment` with the in-process-decode optimization → `VerifyResult`). The real binaries that turn the simulated harness into a live single-host network for Phase 6.

---

# Appendix A — `CLAUDE.md` update for Phase 4

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md
- docs/specs/phase0–3-spec.md  — core (FROZEN), crypto, verify
- docs/specs/phase4-spec.md    — CURRENT: sched (epoch-fenced Redis store, push dispatch, policy, backpressure)

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- core::Task::apply is the transition authority; sched executes the TaskActions it returns.

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

## Commit discipline
Conventional Commits, atomic, GREEN tree (contract.rs green at each commit), body cites spec/amendment.
Never commit red/media/binaries. No --no-verify, no force-push, no core/ edits.

## Scope discipline
sched only. NO real worker/verifier binaries (Phase 5), NO chaos sim / single-host run (Phase 6),
NO transcode/crypto/SSIM. End with build+clippy+test, commit(s), change list, STOP.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1 | Store trait + in-memory + fencing | `store/{mod,memory,contract}.rs` | contract suite incl. slow-zombie + heartbeat-after-reclaim green on memory; commit |
| 2 | Redis store | `store/redis.rs` (Lua atomics) | same `contract.rs` green on Redis (gated); differential parity; commit |
| 3 | placement + backpressure | `place.rs`, `backpressure.rs` | least-loaded + aging + Little's-law caps + shed; tests; commit |
| 4 | reputation + sampling | `reputation.rs`, `sample.rs` | floor P_MIN, asymmetric updates, eligibility gate, Bernoulli(p) seeded; tests; commit |
| 5 | engine + loops + sim | `engine.rs`, `loops.rs`, `sim.rs`, `main.rs` | core::apply-driven; sim exercises end-to-end incl. zombie + reputation; commit |
| 6 | docs + DoD | THREAT-MODEL + ARCHITECTURE + amendment fix | fencing-token para (+ Coingate xref), scheduler design, sizings; DoD §11 reported; commit |

Sessions 3 and 4 may merge if context allows; keep Session 1 (the fencing reference) and Session 2 (the Redis parity) separate — they are the load-bearing proof.

### Exact prompts (one per session; verify + commit before the next)

**Session 1**
> Read `kickoff-amendment-1.md` (§1.1, §1.3, §1.4), `phase4-spec.md` (§2–§3, §9–§11), and `CLAUDE.md`; update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: define the `Store` trait (atomic, epoch-fenced ops per §3.1), implement `store/memory.rs` (the reference), and `store/contract.rs` — the shared suite including the **slow-zombie** test (§3.3: lease@e1 → reclaim → re-lease@e2 → zombie submit@e1 rejected, heartbeat-after-reclaim rejected, exactly one output) — green against memory. `#![forbid(unsafe_code)]`. Build+clippy `-D warnings`+test; commit `feat(sched): epoch-fenced Store trait + in-memory reference`; STOP.

**Session 2**
> Read `CLAUDE.md` and `phase4-spec.md` §3.2, §9. Execute **Session 2 only**: implement `store/redis.rs` using `redis::Script` (Lua) for every epoch-fenced transition over the §3.2 data model (ready ZSET, lease hash, lease-deadline ZSET, registry hash, inbox list), with `reclaim_expired` as the single authority (no stream PEL). Run the **same `contract.rs`** against Redis (gated on a reachable Redis; skip loudly if absent). Build+clippy+test; commit `feat(sched): Redis store with Lua-atomic epoch fencing`; STOP.

**Session 3**
> Read `CLAUDE.md` and `phase4-spec.md` §4, §6. Execute **Session 3 only**: `place.rs` (least-loaded by in-flight + EWMA tiebreak; priority + aging) and `backpressure.rs` (per-worker in-flight cap + global queue cap from documented Little's-law `L = λ × W`; shed at saturation). Tests: least-loaded selection, no starvation under sustained low-priority load, cap holds + shed. Build+clippy+test; commit `feat(sched): least-loaded placement + Little's-law backpressure`; STOP.

**Session 4**
> Read `CLAUDE.md` and `phase4-spec.md` §5. Execute **Session 4 only**: `reputation.rs` (tiers, tier→`p` with hard `P_MIN = 0.02`, **asymmetric** updates — sharp on fail, slow on pass; `CommitmentMismatch` heaviest; suspended/banned ineligible) and `sample.rs` (`Bernoulli(p_tier)`, injectable seeded RNG). Tests: floor keeps `k ≥ 1`, fail escalates / pass de-escalates slowly, eligibility gate, deterministic sampling under a seed. Build+clippy+test; commit `feat(sched): adaptive tier→p policy with P_MIN floor`; STOP.

**Session 5**
> Read `CLAUDE.md` and `phase4-spec.md` §7–§8. Execute **Session 5 only**: `engine.rs` (load task → `core::Task::apply(ev)` → execute `TaskAction`s against the store; content-addressed release anchored by `Commitment`), `loops.rs` (dispatch + single reclaim loops), `sim.rs` (`#[cfg(test)]` simulated worker/verifier over `core::proto`), and `main.rs` wiring. Test: the sim drives place→lease→submit→sample→verify→release end-to-end, including a zombie schedule (rejected) and a failing-verify reputation escalation. Build+clippy+test; commit `feat(sched): core-driven engine, dispatch/reclaim loops, sim harness`; STOP.

**Session 6**
> Read `CLAUDE.md`, `phase4-spec.md` §11, and `kickoff-amendment-1.md` §1.1/§1.2.1. Execute **Session 6 only**: update `docs/THREAT-MODEL.md` (the **fencing-token** paragraph — heartbeat is a liveness heuristic, never safety; cross-reference Coingate §1.2 XAUTOCLAIM-steal as the identical bug class) and `docs/ARCHITECTURE.md` (scheduler design: push dispatch, single reclaim authority, tier→`p` floor, Little's-law sizing, verifier-capacity sizing, the dispatch-latency-decomposition prediction); fold the §1.2.1 "overstates"→"under-states" wording fix into `kickoff-amendment-1.md`. Verify the Phase 4 DoD §11 item by item with evidence; confirm `git diff v0.1.0-core-frozen -- core/` is empty. Commit `docs: scheduler threat model, architecture, sizing`; STOP.
