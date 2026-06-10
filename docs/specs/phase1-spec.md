# proctor — Phase 1 Specification: The `core` State Machine & Protocol Freeze

**Companion to:** `kickoff-brief.md`, `phase0-spec.md`. Read both first.
**This is the complete, authoritative Phase 1 spec.** It implements `proctor_core` — the sans-IO protocol, the task/lease/segment state machine with **epoch fencing**, the commit-reveal types, and the frozen wire messages — and then **freezes it**. After Phase 1, `proctor_core` drives `crypto`, `verify`, `sched`, `verifier`, and `worker` unmodified; a change to `core` after the freeze means a downstream design is wrong.
**Scope:** `core/` only. No `crypto`/`verify`/`sched`/`verifier`/`worker`/`bench` logic. No transport, no Redis, no ffmpeg, no SSIM, no key material. `core` is pure logic and reads no clock.
**Audience:** Claude Code. Authoritative. **Claude Code commits its own work this phase** (§10) — the repo now exists.
**Naming:** package `core`, library target **`proctor_core`** (the Phase 0 std-shadow fix, approved). Dependents import `proctor_core`.

---

## 0. Phase 1 in context, and what "freeze" means

Phase 0 stood up the workspace as compiling stubs. Phase 1 fills exactly one crate — `proctor_core` — and freezes it. The freeze is not ceremony for its own sake: it is the same discipline that let one sans-IO `core::Connection` drive all eleven Rust-Tcp-Server models from blocking to io_uring unmodified, and one frozen LOB `core` drive four book implementations. Here, one frozen task state machine must drive a worker's hot loop, a scheduler's placement and reclaim, and a verifier's spot-check — **without any of them being able to mutate the rules of the protocol.** If a later phase appears to need a `core` change, the later phase is wrong: STOP and ask. The freeze is what makes the zombie-worker problem, the verification protocol, and the lease semantics *provable once* rather than re-argued in every component.

**Human/Claude split:** Claude Code executes the entire phase, including commits (§10). The human reviews the freeze commit and tag before Phase 2 begins.

---

## 1. Phase 1 in one paragraph

Implement `proctor_core` as six modules — `id` (newtype identifiers, monotonic `Epoch`, injected `LogicalTime`), `lease` (the `Lease` with its fencing epoch and the pure expiry predicate), `task` (the `TaskKind` enum: `Transcode` and `Stitch`, strictly distinct), `commit` (a Merkle commitment over opaque leaf hashes, the `Challenge`/`Reveal` types, and the pure inclusion check), `state` (the `Task` state machine: states, events, actions, and the single `apply` transition function that **rejects stale-epoch events instead of applying them**), and `proto` (the frozen wire messages plus canonical `encode`/`decode`). Prove the invariants — epoch monotonicity, zombie rejection, terminal absorption, determinism, commit-reveal soundness — with table-driven and property tests. Then freeze: mark the crate `FROZEN`, update `CLAUDE.md`, and tag `v0.1.0-core-frozen`. After Phase 1, the protocol and the state machine are settled facts the rest of the system is built against.

### 1.1 Reused / unblocked
- The Phase 0 workspace, `CLAUDE.md`, `docs/THREAT-MODEL.md`, and the (now physically generated, version-recorded) corpus stand unchanged.
- Phase 1 touches **no** other crate and needs **no** ffmpeg — `core` is pure logic. This is the one phase that is fully deterministic end to end.

---

## 2. `core` module layout & Phase 1 dependency allowlist

```
core/src/
  lib.rs          # crate docs + FROZEN banner + re-exports
  id.rs           # JobId, SegmentId, TaskId, WorkerId, Epoch, LogicalTime, OutputRef
  lease.rs        # Lease { holder, epoch, deadline }; is_expired predicate
  task.rs         # TaskKind { Transcode(TranscodeSpec), Stitch(StitchSpec) }
  commit.rs       # Commitment(MerkleRoot), Challenge, Reveal, verify_inclusion
  state.rs        # Task, TaskState, TaskEvent, TaskAction, TransitionError, Task::apply
  proto.rs        # wire messages + encode/decode (canonical, frozen)
```

**Dependency allowlist — Phase 1 adds exactly these to `core` (record in `CLAUDE.md`, §A):**
- `sha2` — SHA-256 for the Merkle commitment. Runtime.
- `serde` (with `derive`) — the protocol types are the wire contract; freezing them means freezing their serialized shape. Runtime.
- `postcard` — the canonical, deterministic codec for `proto` encode/decode (no_std-friendly, compact). Runtime.
- `proptest` — invariant property tests. **dev-dependency only.**
- `thiserror` — already present; error enums.

Nothing else. No `tokio`, no `redis`, no `rand` in `core` (a challenge's randomness is chosen by the caller and passed in — `core` does not sample, exactly as it does not read the clock).

---

## 3. `id.rs` — identifiers, epoch, injected time

Opaque newtypes; no behavior beyond construction, equality, ordering where meaningful, and serde. Internals are an implementation detail (`u64`/`u128`/`Uuid` — Claude picks; document it).

```rust
pub struct JobId(/* ... */);       // a source video → many segments
pub struct SegmentId(/* ... */);   // one GOP-aligned segment of a job
pub struct TaskId(/* ... */);      // one unit of work (transcode OR stitch)
pub struct WorkerId(/* ... */);    // an untrusted worker identity (pubkey-derived later; opaque here)
pub struct OutputRef(/* ... */);   // an opaque handle to a worker's produced blob (NOT the bytes, NOT a key)

/// Monotonic fencing token. Strictly increases on every (re)lease of a task.
#[derive(PartialOrd, Ord, ...)] pub struct Epoch(u64);

/// Injected logical time. core NEVER reads a clock; the scheduler passes `now` in.
#[derive(PartialOrd, Ord, ...)] pub struct LogicalTime(u64);
```

**Sans-IO rule, stated once and enforced everywhere:** `core` never calls `Instant::now`, never samples randomness, never touches a socket/file/Redis/ffmpeg. Time and randomness are inputs. This is what makes the state machine deterministic and exhaustively testable.

---

## 4. `lease.rs` — the lease and the fencing epoch (the headline mechanism)

The legacy system's zombie-task bug — a reclaimed task picked up by a revived worker that completes work it no longer holds — is killed structurally here, in the type system, not patched at the I/O layer.

```rust
pub struct Lease {
    pub holder: WorkerId,
    pub epoch: Epoch,          // the fencing token under which this hold is valid
    pub deadline: LogicalTime, // extended by heartbeats; compared against injected `now`
}

impl Lease {
    /// Pure predicate. The scheduler owns the clock and passes `now`.
    pub fn is_expired(&self, now: LogicalTime) -> bool { now >= self.deadline /* ... */ }
}
```

**The fencing invariant (proven in §9):** every task carries a high-water epoch that never decreases; every new lease must present a strictly greater epoch; and any holder-action (submit, heartbeat) must present `(worker, epoch)` matching the *current* lease exactly. A stale-epoch action is **rejected, leaving state unchanged** — never applied late. A revived worker holding an old epoch cannot move the task, because a reclaim has already advanced the high-water epoch past it.

**Rejected alternative:** holder identity alone (no epoch), relying on the I/O layer to "remember" who the current worker is. Rejected — that is exactly the legacy design, where the two reclaim paths disagreed and a stale holder slipped through. The fencing token makes correctness independent of any component's memory.

---

## 5. `task.rs` — `TaskKind`: `Transcode` and `Stitch`, strictly distinct

String-prefix overloading (the legacy `STITCH_` hack) is gone. The two work classes have different inputs, verification semantics, and resource profiles; the type system represents that boundary as an enum, and the state machine is identical across kinds (one lease/epoch/reclaim discipline, not two).

```rust
pub enum TaskKind {
    Transcode(TranscodeSpec),
    Stitch(StitchSpec),
}

pub struct TranscodeSpec {
    pub job: JobId,
    pub segment: SegmentId,
    pub profile: TargetProfile,   // codec, resolution, bitrate, container — the fidelity contract
    pub source: SegmentRef,       // opaque ref to the encrypted source segment (NOT bytes, NOT key)
}

pub struct StitchSpec {
    pub job: JobId,
    pub rendition: RenditionId,
    /// The ordered, content-addressed inputs this stitch concatenates —
    /// each is the accepted OutputRef + its committed hash from a Transcode task.
    pub inputs: Vec<(SegmentId, OutputRef, Commitment)>,
}
```

**Verification semantics differ, and the difference lives in the data, not a forked state graph:**
- **Transcode** verification is *fidelity*: the verifier re-encodes challenged frames and SSIM-compares (Phase 3). Its commitment is a Merkle root over per-frame hashes.
- **Stitch** verification is *integrity*: the output must concatenate exactly the accepted, committed segment outputs, in order — a hash/manifest check, **no SSIM, no re-encode**. Its commitment is a Merkle root over the ordered input hashes.

**Rejected alternative:** `Task<K: TaskKind>` generic over the kind, or two separate state machines. Rejected as premature abstraction and as duplication of the lease/epoch/reclaim logic that is the entire reason to freeze one core. One concrete `Task` with a `kind` field and one transition function; kind-specific meaning rides in the payloads. The job DAG (which transcodes must be `Accepted` before a stitch is created) is **scheduler** state (Phase 4), not `core` — `core` only knows a single task's lifecycle.

---

## 6. `state.rs` — the task state machine

The sans-IO crown jewel, and the direct analogue of `core::Connection` returning `ConnAction`. The machine consumes a `TaskEvent`, and on success returns the `TaskAction`s the I/O layer must perform; on failure it returns a typed error and leaves the task unchanged.

### 6.1 Types

```rust
pub struct Task {
    pub id: TaskId,
    pub kind: TaskKind,
    pub state: TaskState,
    pub epoch_hw: Epoch,   // high-water; monotonic non-decreasing
    pub retries: u8,
}

pub enum TaskState {
    Pending,
    Leased     { holder: WorkerId, epoch: Epoch, deadline: LogicalTime },
    Submitted  { holder: WorkerId, epoch: Epoch, commitment: Commitment, output: OutputRef },
    Verifying  { holder: WorkerId, epoch: Epoch, commitment: Commitment, output: OutputRef, challenge: Challenge },
    Accepted   { output: OutputRef, commitment: Commitment },   // terminal (success)
    Failed     { reason: FailureReason },                       // terminal
}

pub enum TaskEvent {
    Lease                { worker: WorkerId, epoch: Epoch, deadline: LogicalTime },
    Heartbeat            { worker: WorkerId, epoch: Epoch, new_deadline: LogicalTime },
    Submit               { worker: WorkerId, epoch: Epoch, commitment: Commitment, output: OutputRef },
    SelectForVerification{ challenge: Challenge },   // scheduler's probabilistic spot-check decision
    Accept,                                          // unsampled acceptance (commitment already tamper-evident)
    VerifyOutcome        { passed: bool },           // verifier verdict; binding already checked by I/O layer
    LeaseExpired         { epoch: Epoch },            // sweeper, referencing the lease it is expiring
    Abandon              { reason: FailureReason },
}

pub enum TaskAction {
    Requeue,                          // task returns to Pending; scheduler assigns a higher epoch next lease
    IssueChallenge(Challenge),        // scheduler → worker
    NotifyAccepted(OutputRef),        // downstream (e.g., stitch-readiness tracking, scheduler-side)
    MarkFailed(FailureReason),
    EmitReputation(ReputationDelta),  // scheduler applies to the worker's standing
}

pub enum TransitionError {
    StaleEpoch   { event_epoch: Epoch, current: Epoch },   // the zombie-killer
    WrongHolder  { event_worker: WorkerId, current: WorkerId },
    IllegalTransition { state: &'static str, event: &'static str },
    Terminal,    // task already Accepted/Failed
}

/// Apply an event. On Ok, `self` is mutated and the actions are returned.
/// On Err, `self` is UNCHANGED and the error names why. Deterministic; reads no clock.
impl Task {
    pub fn apply(&mut self, ev: TaskEvent) -> Result<Vec<TaskAction>, TransitionError>;
}
```

`LogicalTime`/expiry is computed by the scheduler via `Lease::is_expired(now)`; `core` receives the *decision* as `LeaseExpired`, keeping `apply` clock-free.

### 6.2 The transition table (authoritative — implement exactly this)

| From | Event | Guard | To | Actions |
|---|---|---|---|---|
| `Pending` | `Lease{w,e,dl}` | `e > epoch_hw` | `Leased{w,e,dl}` (set `epoch_hw=e`) | `[]` |
| `Leased{h,le,_}` | `Heartbeat{w,e,dl'}` | `w==h && e==le` | `Leased{h,le,dl'}` | `[]` |
| `Leased{h,le,_}` | `Submit{w,e,c,out}` | `w==h && e==le` | `Submitted{h,le,c,out}` | `[]` |
| `Leased{_,le,_}` | `LeaseExpired{e}` | `e==le` | `Pending` | `[Requeue, EmitReputation(timeout)]` |
| `Leased{h,le,_}` | `Submit`/`Heartbeat` with `w!=h` or `e!=le` | — | **unchanged** | `Err(StaleEpoch \| WrongHolder)` |
| `Submitted{..}` | `SelectForVerification{ch}` | — | `Verifying{..,ch}` | `[IssueChallenge(ch)]` |
| `Submitted{_,_,c,out}` | `Accept` | — | `Accepted{out,c}` | `[NotifyAccepted(out)]` |
| `Submitted{..}` | `LeaseExpired{_}` | — | `Submitted{..}` (**ignored**) | `[]` |
| `Verifying{_,_,c,out,_}` | `VerifyOutcome{passed:true}` | — | `Accepted{out,c}` | `[NotifyAccepted(out)]` |
| `Verifying{..}` | `VerifyOutcome{passed:false}` | `retries < MAX` | `Pending` (`retries+=1`) | `[Requeue, EmitReputation(fail)]` |
| `Verifying{..}` | `VerifyOutcome{passed:false}` | `retries >= MAX` | `Failed{VerificationExhausted}` | `[MarkFailed, EmitReputation(fail)]` |
| any | `Abandon{r}` (non-terminal) | — | `Failed{r}` | `[MarkFailed]` |
| `Accepted`/`Failed` | any | — | unchanged | `Err(Terminal)` |
| any | any unlisted | — | unchanged | `Err(IllegalTransition)` |

**Notes that are part of the contract:**
- `LeaseExpired` is **ignored once `Submitted`**: the work product and its commitment already exist, so a dead worker after submission does not cost the output. Document this explicitly — it is a deliberate liveness/efficiency call, not an oversight.
- The reveal-to-commitment binding (`commit::verify_inclusion`) is checked by the I/O layer *before* it emits `VerifyOutcome`. A failed binding is a hard fail (`passed:false` with a heavier `ReputationDelta`), but `core`'s state graph does not need a separate event for it — keeping the machine minimal.
- `MAX` retries is a `core` constant (document the value); exhaustion is terminal `Failed`.

---

## 7. `commit.rs` — Merkle commit-reveal over opaque leaves

`core` owns the *protocol* of commit-reveal, not its semantics. Leaves are opaque 32-byte hashes; what a leaf *means* (a frame hash for `Transcode`, an ordered-input hash for `Stitch`) is defined above `core`. This keeps the primitive tight and frozen.

```rust
pub struct Commitment(/* 32-byte Merkle root */);     // submitted at task completion, before the challenge
pub struct Challenge(/* the leaf indices to reveal — chosen by the CALLER, not by core */);
pub struct Reveal {
    pub leaves: Vec<(LeafIndex, [u8;32])>,
    pub proofs: Vec<MerkleProof>,
}

/// Pure. True iff every revealed leaf is provably the committed leaf at its index
/// under `root`. The worker cannot alter a leaf after committing, and cannot
/// predict the challenge (the caller chooses indices after receiving the commitment).
pub fn verify_inclusion(root: &Commitment, reveal: &Reveal) -> bool;
```

**Why a Merkle commitment and not a single output hash (rejected alternative):** a single SHA-256 of the whole output is tamper-evident but does not let the verifier challenge a *random subset* with a cheap, sound proof — the worker would have to ship the whole output to prove any part. The Merkle root lets the verifier reveal-and-prove only the challenged leaves. The randomness of the challenge is the caller's (`sched`/`verifier`); `core` neither samples nor stores it — it only verifies inclusion.

---

## 8. `proto.rs` — the frozen wire messages

Freezing "the protocol" means freezing the messages and their serialized bytes, exactly as Rust-Tcp-Server's `core` owned `Response::encode`. Transport (Redis streams, sockets, TLS) is `sched`/`worker`/`verifier` in later phases; **framing and delivery are not `core`'s** — message *shape* and canonical *encoding* are.

```rust
// scheduler → worker
pub struct Assignment { pub task: TaskId, pub kind: TaskKind, pub lease: Lease, pub source: SegmentRef }
// worker → scheduler
pub struct HeartbeatMsg { pub task: TaskId, pub worker: WorkerId, pub epoch: Epoch }
pub struct SubmissionMsg { pub task: TaskId, pub worker: WorkerId, pub epoch: Epoch,
                           pub commitment: Commitment, pub output: OutputRef }
// scheduler → worker (verification), worker → scheduler
pub struct ChallengeMsg { pub task: TaskId, pub challenge: Challenge }
pub struct RevealMsg    { pub task: TaskId, pub reveal: Reveal }
// scheduler → verifier, verifier → scheduler
pub struct VerifyRequest { pub task: TaskId, pub kind: TaskKind, pub commitment: Commitment, pub output: OutputRef }
pub struct VerifyResult  { pub task: TaskId, pub passed: bool, pub detail: VerifyDetail }

/// Canonical, deterministic encode/decode (postcard). Round-trips losslessly.
pub fn encode<M: Message>(m: &M) -> Vec<u8>;
pub fn decode<M: Message>(b: &[u8]) -> Result<M, ProtoError>;
```

**Fencing at the message boundary:** every holder-action message (`HeartbeatMsg`, `SubmissionMsg`) carries `(worker, epoch)`, so the I/O layer hands those straight into the matching `TaskEvent` and the state machine rejects stale ones. The wire shape makes it impossible to act as a holder without presenting a fencing token.

---

## 9. Correctness — the proof gate (this is the artifact's spine, not a checkbox)

`core` is finite and clock-free, so its correctness is *provable*, not merely sampled. Three tiers, all committed:

1. **Exhaustive transition table test.** For every (state-class × event-variant) pair, assert the outcome matches §6.2 exactly — including every `Err` case. No pair is undefined; no input panics. This is the table-driven analogue of the LOB differential oracle.
2. **Property tests (`proptest`)** over random event sequences proving the global invariants:
   - **I1 — Epoch monotonicity:** `epoch_hw` never decreases; every `Leased` transition strictly increased it.
   - **I2 — Zombie rejection (the headline):** no event sequence moves a task to `Submitted`/`Accepted` on behalf of a `(worker, epoch)` that is not the current lease's. Stale-epoch events are always rejected and never mutate state. Construct the explicit revived-worker scenario (lease@e1 → expire → release@e2 → old worker submits@e1) and assert `Err(StaleEpoch)` with state unchanged.
   - **I3 — Terminal absorption:** from `Accepted`/`Failed`, every event yields `Err(Terminal)` and no state change.
   - **I4 — Determinism / purity:** applying the same event to a clone yields identical `(state, actions)`; a rejected event leaves a byte-identical task.
   - **I5 — Single authoritative holder:** in `Leased`/`Submitted`/`Verifying`, exactly one `(worker, epoch)` is accepted for holder-actions.
3. **Commit-reveal soundness (`commit.rs`):** `verify_inclusion` is true iff the revealed leaves match the committed root at their indices; a tampered leaf, a wrong proof, or a leaf not under the root is rejected. Include a negative test: a reveal generated against a *different* root fails.
4. **Wire round-trip (`proto.rs`):** every message `decode(encode(m)) == m`; a corrupted byte stream fails cleanly (`Err(ProtoError)`), never panics.

All tests live under `core/` and run in `cargo test`. `cargo clippy --all-targets -- -D warnings` stays clean.

---

## 10. Commit discipline (Claude Code commits this phase — to a real standard)

Phase 0 was operator-committed because the repo did not yet exist. From Phase 1, **Claude Code makes its own commits**, and they must read like an engineer's, not a dump.

- **Conventional Commits.** Subject `<type>(core): <imperative summary>`, ≤72 chars. Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`.
- **Atomic.** One logical change per commit. A unit and its tests land together (or the tests immediately after), each on a **green tree**.
- **Never commit red.** Before every commit: `cargo build && cargo clippy --all-targets -- -D warnings && cargo test` must pass. No `--no-verify`.
- **Bodies explain *why* and cite the spec.** e.g. `Refs: docs/specs/phase1-spec.md §6.2`. State the rejected alternative when a non-obvious call was made.
- **History is part of the artifact.** No force-push to `main`, no rewriting/squashing landed history, no secrets or large binaries in commits.
- **The freeze is a distinct, final commit + annotated tag.** `chore(core): freeze protocol and state machine [Phase 1 complete]` followed by `git tag -a v0.1.0-core-frozen -m "proctor_core frozen: protocol, state machine, fencing, commit-reveal"`.

Suggested commit sequence maps to the §B sessions: identifiers+lease → task+commit → state machine → proto → freeze.

---

## 11. Sans-IO purity rules (verify before the freeze)

- `core` imports nothing from `std::net`, `std::fs`, `std::time` (no `Instant`/`SystemTime`), no `tokio`, no `redis`, no `rand`. Grep for these before freezing.
- No `println!`/logging in `core`.
- Every transition is a pure function of `(state, event)`; time and randomness are inputs.
- `core` holds no key material and no plaintext — only opaque refs and hashes.

---

## 12. Phase 1 Definition of Done

1. `proctor_core` implements `id`, `lease`, `task`, `commit`, `state`, `proto` per §3–§8; `TaskKind` has exactly `Transcode` and `Stitch`; `Lease` carries a monotonic `Epoch`.
2. `Task::apply` implements §6.2 **exactly**, rejecting stale-epoch holder-actions with state unchanged.
3. The proof gate §9 is green: exhaustive transition table, property invariants I1–I5 (with the explicit revived-worker zombie scenario), commit-reveal soundness, and wire round-trip — all committed under `core/`.
4. Sans-IO purity (§11) verified: no clock, no net, no fs, no randomness, no logging, no secrets in `core`.
5. `cargo build && cargo clippy --all-targets -- -D warnings && cargo test` clean; dependency allowlist (§2) respected — `core` runtime deps are exactly `sha2`, `serde`, `postcard`, `thiserror`; `proptest` dev-only.
6. Commits follow §10; the freeze commit and `v0.1.0-core-frozen` tag exist.
7. `lib.rs` carries a `FROZEN — see docs/specs/phase1-spec.md §0` banner; `CLAUDE.md` updated per Appendix A (core marked FROZEN, Phase 1 deps recorded).

Next: `phase2-spec.md` — `crypto`: in-memory AES-256-GCM, `mlock` + `zeroize`, the pipe/`memfd` no-plaintext-on-disk path, and the crypto-overhead microbench. `core` is consumed unmodified from here on.

---

# Appendix A — `CLAUDE.md` update for Phase 1

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md  — strategy, primitives, DoD, synergy
- docs/specs/phase0-spec.md    — genesis + skeleton
- docs/specs/phase1-spec.md    — CURRENT: proctor_core state machine + protocol (FREEZE)

## Frozen
- proctor_core is FROZEN after Phase 1's tag v0.1.0-core-frozen. It must drive
  crypto/verify/sched/verifier/worker UNCHANGED. If a later phase seems to need a
  core change, the later phase is wrong — STOP and ask.

## Hard rules (Phase 1)
1. core is SANS-IO: no std::net/fs/time, no tokio/redis/rand, no logging, no
   key material, no plaintext. Time and randomness are inputs.
2. TaskKind = { Transcode, Stitch } — distinct variants, never string prefixes.
3. Lease carries a monotonic Epoch (fencing token). Stale-epoch holder-actions
   are REJECTED, state unchanged. This kills the zombie-worker class of bug.
4. Task::apply implements the §6.2 table exactly. Deterministic, pure.
5. Phase 1 deps (core): sha2, serde, postcard, thiserror; proptest dev-only.
   Add nothing else.

## Commit discipline (from Phase 1 on, Claude Code commits)
- Conventional Commits: <type>(core): <imperative>, <=72 chars. Body cites the spec.
- Atomic, one logical change per commit, on a GREEN tree (build+clippy -D warnings+test).
- Never commit red. No --no-verify. No force-push/rewrite of main. No secrets/binaries.
- Freeze = final commit + annotated tag v0.1.0-core-frozen.

## Scope discipline
Work ONLY on the given session. End with build+clippy+test, the commit(s), a change
list, and STOP. Never touch a future phase.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1 | Identifiers + lease + fencing | `id.rs`, `lease.rs` + unit tests | epoch ordering + `is_expired` tested; commit on green |
| 2 | Task kinds + commit-reveal | `task.rs`, `commit.rs` + soundness tests | Merkle inclusion sound (incl. negative test); commit |
| 3 | The state machine | `state.rs` (§6.2) + exhaustive table + property invariants I1–I5 | zombie scenario asserts `Err(StaleEpoch)`; commit(s) |
| 4 | Protocol messages | `proto.rs` + encode/decode + round-trip tests | every message round-trips; corrupt input errs cleanly; commit |
| 5 | Freeze | `lib.rs` FROZEN banner, `CLAUDE.md` update, DoD §12 verify | all of §12 reported; freeze commit + `v0.1.0-core-frozen` tag |

Session 3 is the heavy one — if context grows, split at the table-implementation / property-test boundary, committing the implementation before the property suite.

### Exact prompts (paste one per session; verify + commit before the next)

**Session 1**
> Read `docs/specs/kickoff-brief.md`, `docs/specs/phase1-spec.md` (§3–§4, §10–§12), and `CLAUDE.md`. Update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: implement `core/src/id.rs` (§3) and `core/src/lease.rs` (§4) with the newtype identifiers, monotonic `Epoch`, injected `LogicalTime`, `Lease`, and the pure `is_expired` predicate. Add unit tests for epoch ordering and expiry. Keep `core` sans-IO (§11). Run build + clippy `-D warnings` + test; commit per §10 with a spec-citing body; list changes and STOP.

**Session 2**
> Read `CLAUDE.md` and `phase1-spec.md` §5, §7. Execute **Session 2 only**: implement `core/src/task.rs` (`TaskKind { Transcode, Stitch }` + specs, §5) and `core/src/commit.rs` (Merkle `Commitment`/`Challenge`/`Reveal` + pure `verify_inclusion`, §7). Tests: commit-reveal soundness including a negative test (reveal against a different root fails). Sans-IO; `core` samples no randomness. Build + clippy + test; commit per §10; list changes and STOP.

**Session 3**
> Read `CLAUDE.md` and `phase1-spec.md` §6, §9. Execute **Session 3 only**: implement `core/src/state.rs` — `Task`, `TaskState`, `TaskEvent`, `TaskAction`, `TransitionError`, and `Task::apply` implementing the §6.2 table EXACTLY, including the `LeaseExpired`-ignored-once-`Submitted` rule and stale-epoch rejection. Then the proof gate §9 tiers 1–2: the exhaustive transition-table test and the `proptest` invariants I1–I5, with the explicit revived-worker zombie scenario asserting `Err(StaleEpoch)` and unchanged state. Build + clippy + test; commit the implementation and the property suite per §10 (split commits acceptable); list changes and STOP.

**Session 4**
> Read `CLAUDE.md` and `phase1-spec.md` §8, §9. Execute **Session 4 only**: implement `core/src/proto.rs` — the frozen wire messages and canonical `encode`/`decode` (postcard), with `(worker, epoch)` on every holder-action message. Tests: round-trip every message (`decode(encode(m)) == m`) and clean error on corrupted bytes (no panic). Build + clippy + test; commit per §10; list changes and STOP.

**Session 5**
> Read `CLAUDE.md` and `phase1-spec.md` §11–§12. Execute **Session 5 only**: verify sans-IO purity (§11) by grepping for forbidden imports; add the `FROZEN` banner to `core/src/lib.rs`; re-confirm `CLAUDE.md` marks `proctor_core` FROZEN. Run the full proof gate one final time. Report the Phase 1 DoD §12 item by item. Then make the freeze commit and annotated tag `v0.1.0-core-frozen` per §10. STOP — `proctor_core` is frozen.
