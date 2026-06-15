//! `transport` — the worker's blocking-Redis transport (phase5-spec.md §4, §6).
//!
//! No async runtime (locked decision #1): a synchronous Redis connection, `BRPOP`
//! on the worker's inbox for pushed [`Assignment`]s (the worker **receives**, never
//! self-selects), and `LPUSH` of holder-action messages ([`HeartbeatMsg`],
//! [`SubmissionMsg`]) onto the single `sched:inbound` return channel that
//! `sched::loops` drains (wired sched-side in Session 4). Every holder-action
//! carries `(worker, epoch)` so the store can fence a stale one.
//!
//! Keys are derived from a shared prefix (default `proctor:sched`, matching the
//! `sched` binary) — single host, one Redis (locked decision #5):
//! - inbox (dispatch): `{prefix}:inbox:{worker}`
//! - return channel:   `{prefix}:inbound`
//! - registry hash:    `{prefix}:worker:{worker}` (via the [`REGISTER`] script)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use proctor_core::{decode, encode, Assignment, HeartbeatMsg, SubmissionMsg, WorkerId};

use crate::WorkerError;

/// Worker registry registration — mirrors `sched`'s registry schema (single-host,
/// shared Redis). Idempotent: creates the worker hash with neutral standing on first
/// sight, then refreshes `last_heartbeat`. Identity only — cryptographic worker auth
/// / anti-Sybil is a documented non-goal (§4.1); fencing + verification catch a
/// cheating worker regardless of claimed identity.
const REGISTER: &str = r#"
local wkey=ARGV[1]..':worker:'..ARGV[2]
if redis.call('EXISTS',wkey)==0 then
  redis.call('HSET',wkey,'in_flight',0,'ewma_throughput',0,'standing',0)
end
redis.call('HSET',wkey,'last_heartbeat',ARGV[3])
return {'ok'}
"#;

/// A synchronous Redis transport bound to a key `prefix`. Holds a [`redis::Client`]
/// (cloneable, so per-task threads can mint their own connections) and one owned
/// connection for the main loop's `BRPOP`/registration.
pub struct Transport {
    client: redis::Client,
    conn: redis::Connection,
    prefix: String,
}

impl Transport {
    /// Connect to `url` and bind the key `prefix`.
    pub fn connect(url: &str, prefix: impl Into<String>) -> Result<Self, WorkerError> {
        let client = redis::Client::open(url)?;
        let conn = client.get_connection()?;
        Ok(Self {
            client,
            conn,
            prefix: prefix.into(),
        })
    }

    /// A cloneable handle for spawning per-task return-channel senders / heartbeaters.
    #[must_use]
    pub fn handle(&self) -> Sender {
        Sender {
            client: self.client.clone(),
            prefix: self.prefix.clone(),
        }
    }

    fn inbox_key(&self, worker: WorkerId) -> String {
        format!("{}:inbox:{}", self.prefix, worker.0)
    }

    /// Register the worker identity in the scheduler registry (idempotent).
    pub fn register(&mut self, worker: WorkerId, now: u64) -> Result<(), WorkerError> {
        let reply: Vec<String> = redis::Script::new(REGISTER)
            .arg(self.prefix.as_str())
            .arg(worker.0)
            .arg(now)
            .invoke(&mut self.conn)?;
        if reply.first().map(String::as_str) == Some("ok") {
            Ok(())
        } else {
            Err(WorkerError::Script(format!("register: {reply:?}")))
        }
    }

    /// Block up to `timeout_secs` for the next pushed [`Assignment`] (`BRPOP`).
    /// `Ok(None)` on timeout (the loop re-polls); decodes the postcard payload.
    pub fn next_assignment(
        &mut self,
        worker: WorkerId,
        timeout_secs: u64,
    ) -> Result<Option<Assignment>, WorkerError> {
        let key = self.inbox_key(worker);
        let popped: Option<(String, Vec<u8>)> = redis::cmd("BRPOP")
            .arg(&key)
            .arg(timeout_secs)
            .query(&mut self.conn)?;
        match popped {
            Some((_, bytes)) => Ok(Some(decode::<Assignment>(&bytes)?)),
            None => Ok(None),
        }
    }
}

/// A cloneable sender for the `{prefix}:inbound` return channel. Each instance mints
/// its own connection lazily so it can move into a per-task thread.
#[derive(Clone)]
pub struct Sender {
    client: redis::Client,
    prefix: String,
}

impl Sender {
    fn inbound_key(&self) -> String {
        format!("{}:inbound", self.prefix)
    }

    /// `LPUSH` a completed submission (carrying the lease epoch) onto `sched:inbound`.
    pub fn send_submission(&self, msg: &SubmissionMsg) -> Result<(), WorkerError> {
        let mut conn = self.client.get_connection()?;
        let key = self.inbound_key();
        let _: i64 = redis::cmd("LPUSH").arg(&key).arg(encode(msg)).query(&mut conn)?;
        Ok(())
    }

    /// Spawn a background heartbeat that `LPUSH`es `msg` every `interval` until
    /// dropped/stopped, so a long transcode does not lose its lease for liveness. The
    /// heartbeat carries the epoch — a reclaimed zombie cannot resurrect its lease
    /// (Phase 4 fencing). Errors are best-effort (a missed beat is a liveness blip,
    /// never a safety event).
    #[must_use]
    pub fn start_heartbeat(&self, msg: HeartbeatMsg, interval: Duration) -> Heartbeat {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let client = self.client.clone();
        let key = self.inbound_key();
        let handle = thread::spawn(move || {
            let mut conn = match client.get_connection() {
                Ok(c) => c,
                Err(_) => return, // no connection ⇒ no heartbeats; the lease may lapse (safe)
            };
            let bytes = encode(&msg);
            while !sleep_interruptible(&stop_thread, interval) {
                let _: Result<i64, _> = redis::cmd("LPUSH").arg(&key).arg(&bytes).query(&mut conn);
            }
        });
        Heartbeat {
            stop,
            handle: Some(handle),
        }
    }
}

/// A running heartbeat. Stops on [`stop`](Heartbeat::stop) or `Drop` (so a panicking
/// task still tears its heartbeat down).
pub struct Heartbeat {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Heartbeat {
    /// Signal the heartbeat thread to stop and join it.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Sleep `interval` in small steps, returning `true` early if `stop` is set. Keeps a
/// stop signal responsive without a condvar.
fn sleep_interruptible(stop: &AtomicBool, interval: Duration) -> bool {
    const STEP: Duration = Duration::from_millis(100);
    let mut waited = Duration::ZERO;
    while waited < interval {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        let step = STEP.min(interval - waited);
        thread::sleep(step);
        waited += step;
    }
    stop.load(Ordering::Relaxed)
}
