//! proctor `sched` — the epoch-fenced control-plane binary.
//!
//! Wires the Session-5 engine over a [`Store`]: a Redis store when `PROCTOR_REDIS_URL` is
//! set and reachable, else the in-memory store (single host, locked decision #5). It then
//! spins the dispatch + single-reclaim loops. There is no ingest API (locked decision #2):
//! the bench injector and the real worker/verifier bins (Phase 5) feed the loops; the live
//! single-host run and chaos sims are Phase 6. This wiring proves the loops run end-to-end.

#![forbid(unsafe_code)]

use proctor_core::LogicalTime;
use sched::engine::{Engine, EngineConfig};
use sched::loops;
use sched::sample::Sampler;
use sched::store::{MemoryStore, RedisStore, Store};

fn main() {
    match std::env::var("PROCTOR_REDIS_URL") {
        Ok(url) => match RedisStore::connect(&url, "proctor:sched") {
            Ok(store) => {
                eprintln!("proctor sched: Redis store at {url}");
                run(store);
            }
            Err(e) => {
                eprintln!("proctor sched: Redis unavailable ({e}); falling back to in-memory store");
                run(MemoryStore::new());
            }
        },
        Err(_) => {
            eprintln!("proctor sched: in-memory store (set PROCTOR_REDIS_URL to use Redis)");
            run(MemoryStore::new());
        }
    }
}

/// Build the engine and spin a few bounded dispatch + reclaim ticks. No workers or tasks
/// are injected here — the bench injector and the Phase 5 worker/verifier bins drive the
/// loops; the live single-host run is Phase 6. This confirms the wiring runs without panic.
fn run<S: Store>(store: S) {
    let engine = Engine::new(store, EngineConfig::for_workers(4), Sampler::from_entropy());
    for t in 0..3u64 {
        let now = LogicalTime(t);
        if let Err(e) = loops::dispatch_tick(&engine, now) {
            eprintln!("proctor sched: dispatch tick failed: {e}");
            return;
        }
        if let Err(e) = loops::reclaim_tick(&engine, now) {
            eprintln!("proctor sched: reclaim tick failed: {e}");
            return;
        }
    }
    eprintln!(
        "proctor sched: engine wired (Phase 4 Session 5). Real worker/verifier bins are \
         Phase 5; the live single-host run is Phase 6."
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds() {}
}
