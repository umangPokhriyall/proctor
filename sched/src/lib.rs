//! proctor `sched` — the epoch-fenced control plane (phase4-spec.md).
//!
//! `sched` turns the frozen `core` state machine into a durable, concurrent control
//! plane. The spine is a single idea (amendment §1.1): **a heartbeat timeout is a
//! liveness heuristic and must never be a safety mechanism.** Reclaim re-dispatches a
//! missed-heartbeat task for *liveness*; **fencing** — the monotonic [`proctor_core::Epoch`]
//! already frozen into `core` — is what guarantees *safety*, by making a slow-zombie's
//! late write rejected at the durable [`store::Store`], atomically, so exactly one output
//! ever exists for a segment.
//!
//! `sched` is `#![forbid(unsafe_code)]`: all `unsafe` stays confined to `crypto::sys`,
//! and there is no async runtime anywhere in the measured path (locked decision #1).
//!
//! **Session 1** landed the load-bearing proof: the [`store`] module — the
//! [`store::Store`] trait of atomic, epoch-fenced operations (§3.1), the deterministic
//! in-memory [`store::MemoryStore`] reference, and the shared `contract` suite including
//! the slow-zombie store-level test (§3.3). **Session 2** added the Lua-atomic
//! [`store::RedisStore`], proven equivalent by the same suite. **Session 3** (this commit)
//! adds the placement and backpressure *decision* modules — [`place`] (least-loaded push
//! selection + the aging anti-starvation policy, §4) and [`backpressure`] (Little's-law
//! sizing + shed-at-saturation, §6) — written over the `Store` trait, free of Redis
//! specifics. Later sessions add reputation/sampling, the `core`-driven engine, the
//! dispatch/reclaim loops, and the simulated harness.

#![forbid(unsafe_code)]

pub mod backpressure;
pub mod place;
pub mod store;
