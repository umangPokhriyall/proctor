//! `redis` — the Redis-backed [`Store`], with **every epoch-fenced transition expressed
//! as a `redis::Script` (Lua)** so the read-compare-write is atomic (§3.2).
//!
//! This is the second implementation held to the one `contract` suite — the differential
//! oracle. The in-memory reference *inherits* its fencing from `core::Task::apply`; here
//! the identical rule is **re-derived in Lua** over discrete hash fields. The suite,
//! including the slow-zombie store-level proof (§3.3), is what proves the re-derivation
//! correct. There is no `WATCH`/retry loop and **no second reclaim path** (no stream PEL
//! / `XAUTOCLAIM`): a single Lua compare-and-set is the only writer of each task's state.
//!
//! ## Data model (§3.2)
//! - **Lease per task:** hash `{prefix}:task:{id}` with discrete fields
//!   `{status, holder, epoch, epoch_hw, deadline, commitment, output, retries, priority,
//!   kind}`. Every transition mutates it inside a Lua script.
//! - **Ready queue:** ZSET `{prefix}:ready`, scored `priority·BIG − seq` (priority first,
//!   FIFO within a class via a monotonic `{prefix}:seq` counter). `pop_ready` is
//!   `ZPOPMAX`. Aging (using real enqueue time) is layered on in Session 3.
//! - **Lease-deadline index:** ZSET `{prefix}:deadlines` scored by deadline. `reclaim_expired`
//!   is one `ZRANGEBYSCORE 0 now` + a Lua reclaim per task — the single authority.
//! - **Worker registry:** hash `{prefix}:worker:{id}` `{last_heartbeat, in_flight,
//!   ewma_throughput, standing}` (tier is derived, not stored).
//!
//! ## Single-node assumption
//! Lua scripts compute their keys from a `prefix` ARGV rather than declaring them in
//! `KEYS[]`, which a Redis **Cluster** would reject. That is deliberate and matches the
//! locked decision #5 deployment: a single host, loopback, one Redis. The worker inbox
//! `list` (push dispatch) and the content-addressed release index land with the engine
//! and dispatch loop (Session 5); no `Store` trait op writes them yet.
//!
//! Scoring uses an f64 ZSET score, exact for the small priority classes and short logical
//! times the scheduler uses; large-magnitude inputs are out of scope here.

use std::sync::Mutex;

use proctor_core::{
    decode, encode, Challenge, Commitment, Epoch, FailureReason, LogicalTime, OutputRef,
    ReputationDelta, Task, TaskId, TaskKind, TaskState, VerifyRequest, WorkerId,
};

use super::{standing_penalty, tier_from_standing, Priority, Store, StoreError, Tier, WorkerLoad};

/// Priority-class multiplier for the ready-queue ZSET score (`priority·BIG − seq`).
const BIG: i64 = 1_000_000_000;

// --- Lua: every epoch-fenced transition is one atomic script (§3.2) --------
//
// Convention: `ARGV[1]` is the key prefix, `ARGV[2]` the task (or worker) id, the rest
// are operation parameters. Control replies are arrays whose first element is a tag:
// `ok` (with optional payload), `nosuch`, `exists`, `illegal{state}`, `stale{ev,cur}`,
// `wrong{ev,cur}`, `terminal`, `unknown`. The Rust side maps tags to `StoreError`,
// mirroring `core`'s `TransitionError` at the durable layer.

const CREATE: &str = r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id
if redis.call('EXISTS',task)==1 then return {'exists'} end
redis.call('HSET',task,
  'status','pending','holder','0','epoch','0','epoch_hw','0','deadline','0',
  'commitment','','output','0','retries','0','priority','0','kind',ARGV[3])
return {'ok'}
"#;

const LEASE: &str = r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id; local dz=p..':deadlines'
if redis.call('EXISTS',task)==0 then return {'nosuch'} end
local status=redis.call('HGET',task,'status')
if status~='pending' then return {'illegal',status} end
local ep=tonumber(redis.call('HGET',task,'epoch_hw'))+1
local w=ARGV[3]
redis.call('HSET',task,'status','leased','holder',w,'epoch',ep,'epoch_hw',ep,'deadline',ARGV[4])
redis.call('ZADD',dz,ARGV[4],id)
local wkey=p..':worker:'..w
if redis.call('EXISTS',wkey)==1 then redis.call('HINCRBY',wkey,'in_flight',1) end
return {'ok',tostring(ep)}
"#;

const EXTEND: &str = r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id; local dz=p..':deadlines'
if redis.call('EXISTS',task)==0 then return {'nosuch'} end
local status=redis.call('HGET',task,'status')
if status~='leased' then return {'illegal',status} end
local cur=tonumber(redis.call('HGET',task,'epoch'))
local ev=tonumber(ARGV[4])
if ev~=cur then return {'stale',tostring(ev),tostring(cur)} end
local holder=redis.call('HGET',task,'holder')
if holder~=ARGV[3] then return {'wrong',ARGV[3],holder} end
redis.call('HSET',task,'deadline',ARGV[5])
redis.call('ZADD',dz,ARGV[5],id)
return {'ok'}
"#;

const SUBMIT: &str = r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id; local dz=p..':deadlines'
if redis.call('EXISTS',task)==0 then return {'nosuch'} end
local status=redis.call('HGET',task,'status')
if status~='leased' then return {'illegal',status} end
local cur=tonumber(redis.call('HGET',task,'epoch'))
local ev=tonumber(ARGV[4])
if ev~=cur then return {'stale',tostring(ev),tostring(cur)} end
local holder=redis.call('HGET',task,'holder')
if holder~=ARGV[3] then return {'wrong',ARGV[3],holder} end
redis.call('HSET',task,'status','submitted','commitment',ARGV[5],'output',ARGV[6])
redis.call('ZREM',dz,id)
return {'ok'}
"#;

const SELECT_OR_ACCEPT: &str = r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id
if redis.call('EXISTS',task)==0 then return {'nosuch'} end
local status=redis.call('HGET',task,'status')
if status~='submitted' then return {'illegal',status} end
if ARGV[3]=='1' then
  redis.call('HSET',task,'status','verifying')
else
  redis.call('HSET',task,'status','accepted')
  local wkey=p..':worker:'..redis.call('HGET',task,'holder')
  if redis.call('EXISTS',wkey)==1 then redis.call('HINCRBY',wkey,'in_flight',-1) end
end
return {'ok'}
"#;

/// Enqueue script: score is `priority·BIG − seq` (BIG injected so it is not a Lua nil).
fn enqueue_lua() -> String {
    format!(
        r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id; local ready=p..':ready'
if redis.call('EXISTS',task)==0 then return {{'nosuch'}} end
redis.call('HSET',task,'priority',ARGV[3])
local seq=redis.call('INCR',p..':seq')
redis.call('ZADD',ready, tonumber(ARGV[3])*{big} - seq, id)
return {{'ok'}}
"#,
        big = BIG,
    )
}

/// Per-task reclaim: re-checks status + deadline atomically, then requeues with a bumped
/// score. Returns 1 if it reclaimed the task, 0 otherwise.
fn reclaim_one_lua() -> String {
    format!(
        r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id
local dz=p..':deadlines'; local ready=p..':ready'
if redis.call('EXISTS',task)==0 then return 0 end
if redis.call('HGET',task,'status')~='leased' then return 0 end
if tonumber(redis.call('HGET',task,'deadline'))>tonumber(ARGV[3]) then return 0 end
local holder=redis.call('HGET',task,'holder')
redis.call('HSET',task,'status','pending')
redis.call('ZREM',dz,id)
local wkey=p..':worker:'..holder
if redis.call('EXISTS',wkey)==1 then redis.call('HINCRBY',wkey,'in_flight',-1) end
local prio=tonumber(redis.call('HGET',task,'priority'))
local seq=redis.call('INCR',p..':seq')
redis.call('ZADD',ready, prio*{big} - seq, id)
return 1
"#,
        big = BIG,
    )
}

const REGISTER: &str = r#"
local wkey=ARGV[1]..':worker:'..ARGV[2]
if redis.call('EXISTS',wkey)==0 then
  redis.call('HSET',wkey,'in_flight',0,'ewma_throughput',0,'standing',0)
end
redis.call('HSET',wkey,'last_heartbeat',ARGV[3])
return {'ok'}
"#;

const STANDING: &str = r#"
local wkey=ARGV[1]..':worker:'..ARGV[2]
if redis.call('EXISTS',wkey)==0 then return {'unknown'} end
local s=redis.call('HINCRBY',wkey,'standing', -tonumber(ARGV[3]))
return {'ok',tostring(s)}
"#;

// Rich, detail-aware standing update (§6). ARGV[3] is the SIGNED delta from
// `reputation::verdict_delta` (+1 credit / negative fails / 0 inconclusive); ARGV[4]/[5]
// are the floor/cap. The clamp `s := min(max(s+delta, floor), cap)` reproduces
// `reputation::record_verdict` exactly (the in-memory reference), the differential oracle
// proving it. Atomic: read-modify-write in one script (no WATCH/retry).
const RECORD_VERDICT: &str = r#"
local wkey=ARGV[1]..':worker:'..ARGV[2]
if redis.call('EXISTS',wkey)==0 then return {'unknown'} end
local s=tonumber(redis.call('HGET',wkey,'standing'))+tonumber(ARGV[3])
local floor=tonumber(ARGV[4]); local cap=tonumber(ARGV[5])
if s>cap then s=cap end
if s<floor then s=floor end
redis.call('HSET',wkey,'standing',s)
return {'ok',tostring(s)}
"#;

/// Build the verify-outcome script. `MAX_RETRIES` is injected from frozen `core` rather
/// than written as a Lua literal, so the retry budget is single-sourced.
fn verify_outcome_lua() -> String {
    format!(
        r#"
local p=ARGV[1]; local id=ARGV[2]; local task=p..':task:'..id
local dz=p..':deadlines'; local ready=p..':ready'
if redis.call('EXISTS',task)==0 then return {{'nosuch'}} end
if redis.call('HGET',task,'status')~='verifying' then
  return {{'illegal',redis.call('HGET',task,'status')}} end
local wkey=p..':worker:'..redis.call('HGET',task,'holder')
local function dec() if redis.call('EXISTS',wkey)==1 then redis.call('HINCRBY',wkey,'in_flight',-1) end end
if ARGV[3]=='1' then
  redis.call('HSET',task,'status','accepted'); dec()
else
  local r=tonumber(redis.call('HGET',task,'retries'))
  if r<{max} then
    redis.call('HSET',task,'retries',r+1,'status','pending'); redis.call('ZREM',dz,id); dec()
    local prio=tonumber(redis.call('HGET',task,'priority'))
    local seq=redis.call('INCR',p..':seq')
    redis.call('ZADD',ready, prio*{big} - seq, id)
  else
    redis.call('HSET',task,'status','failed','reason','exhausted'); dec()
  end
end
return {{'ok'}}
"#,
        max = proctor_core::MAX_RETRIES,
        big = BIG,
    )
}

/// The Redis-backed [`Store`]. Holds one synchronous connection behind a `Mutex` (no
/// async runtime — locked decision #1) and a key `prefix` that namespaces all keys.
pub struct RedisStore {
    conn: Mutex<::redis::Connection>,
    prefix: String,
}

impl RedisStore {
    /// Connect to `url` and namespace all keys under `prefix`. Returns a `Backend` error
    /// if the connection cannot be opened.
    pub fn connect(url: &str, prefix: impl Into<String>) -> Result<Self, StoreError> {
        let client = ::redis::Client::open(url).map_err(be)?;
        let conn = client.get_connection().map_err(be)?;
        Ok(Self {
            conn: Mutex::new(conn),
            prefix: prefix.into(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ::redis::Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn task_key(&self, t: TaskId) -> String {
        format!("{}:task:{}", self.prefix, t.0)
    }
    fn worker_key(&self, w: WorkerId) -> String {
        format!("{}:worker:{}", self.prefix, w.0)
    }

    /// Invoke a Lua script: ARGV[1] = prefix, then `args`, parsed as `T`. The script
    /// (`SCRIPT LOAD` + `EVALSHA`, cached by the connection) is the atomic boundary.
    fn call<T: ::redis::FromRedisValue>(&self, lua: &str, args: &[&str]) -> Result<T, StoreError> {
        let script = ::redis::Script::new(lua);
        let mut conn = self.lock();
        let mut inv = script.prepare_invoke();
        inv.arg(self.prefix.as_str());
        for a in args {
            inv.arg(*a);
        }
        inv.invoke(&mut *conn).map_err(be)
    }
}

/// A backend/transport error from the Redis client.
fn be(e: ::redis::RedisError) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Parse the i-th reply element as a `u64` (ids/epochs are non-negative).
fn at_u64(reply: &[String], i: usize) -> u64 {
    reply.get(i).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Parse the i-th reply element as an `i64` (standing can be negative).
fn at_i64(reply: &[String], i: usize) -> i64 {
    reply.get(i).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Map a runtime status string to the stable state-class name `core` uses for
/// `IllegalTransition` diagnostics.
fn state_name(s: &str) -> &'static str {
    match s {
        "pending" => "Pending",
        "leased" => "Leased",
        "submitted" => "Submitted",
        "verifying" => "Verifying",
        "accepted" => "Accepted",
        "failed" => "Failed",
        _ => "Unknown",
    }
}

/// Turn a non-`ok` control reply into the matching [`StoreError`], mirroring `core`'s
/// `TransitionError` (epoch checked before holder).
fn classify(reply: &[String], task: TaskId, event: &'static str) -> StoreError {
    match reply.first().map(String::as_str) {
        Some("nosuch") => StoreError::NoSuchTask(task),
        Some("exists") => StoreError::TaskExists(task),
        Some("illegal") => StoreError::IllegalTransition {
            state: state_name(reply.get(1).map_or("", String::as_str)),
            event,
        },
        Some("stale") => StoreError::StaleEpoch {
            event_epoch: Epoch(at_u64(reply, 1)),
            current: Epoch(at_u64(reply, 2)),
        },
        Some("wrong") => StoreError::WrongHolder {
            event_worker: WorkerId(at_u64(reply, 1)),
            current: WorkerId(at_u64(reply, 2)),
        },
        Some("terminal") => StoreError::Terminal,
        other => StoreError::Backend(format!("{event}: unexpected reply {other:?}")),
    }
}

/// `Ok(())` iff the reply is `ok`, else the classified error.
fn expect_ok(reply: Vec<String>, task: TaskId, event: &'static str) -> Result<(), StoreError> {
    if reply.first().map(String::as_str) == Some("ok") {
        Ok(())
    } else {
        Err(classify(&reply, task, event))
    }
}

// --- kind (de)serialization via the frozen wire codec ----------------------
//
// The lease hash carries the immutable `TaskKind` as a hex blob so `load` can rebuild
// the full `Task`. §2 routes (de)serialization through `core::proto::encode`/`decode`
// rather than a direct serde dep; `VerifyRequest` is the frozen message that carries a
// kind, so we round-trip the kind through it (its other fields are unused placeholders).

fn encode_kind(task: TaskId, kind: &TaskKind) -> String {
    let msg = VerifyRequest {
        task,
        kind: kind.clone(),
        commitment: Commitment([0u8; 32]),
        output: OutputRef(0),
    };
    to_hex(&encode(&msg))
}

fn decode_kind(hex: &str) -> Result<TaskKind, StoreError> {
    let bytes = from_hex(hex)?;
    let msg: VerifyRequest =
        decode(&bytes).map_err(|e| StoreError::Backend(format!("decode kind: {e}")))?;
    Ok(msg.kind)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn from_hex(hex: &str) -> Result<Vec<u8>, StoreError> {
    if !hex.len().is_multiple_of(2) {
        return Err(StoreError::Backend("odd-length hex".into()));
    }
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map_err(|e| StoreError::Backend(format!("bad hex: {e}")))
        })
        .collect()
}

fn commitment_from_hex(hex: &str) -> Result<Commitment, StoreError> {
    let bytes = from_hex(hex)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::Backend("commitment is not 32 bytes".into()))?;
    Ok(Commitment(arr))
}

impl Store for RedisStore {
    fn create_task(&self, task: Task) -> Result<(), StoreError> {
        // The store records a fresh Pending task (as `Task::new` produces); only the kind
        // is carried from the argument, the lifecycle fields start at their Pending zero.
        let id = task.id.0.to_string();
        let kind = encode_kind(task.id, &task.kind);
        let reply: Vec<String> = self.call(CREATE, &[&id, &kind])?;
        if reply.first().map(String::as_str) == Some("ok") {
            Ok(())
        } else {
            Err(classify(&reply, task.id, "Create"))
        }
    }

    fn load(&self, task: TaskId) -> Result<Option<Task>, StoreError> {
        let key = self.task_key(task);
        let map: std::collections::HashMap<String, String> = {
            let mut conn = self.lock();
            ::redis::cmd("HGETALL")
                .arg(&key)
                .query(&mut *conn)
                .map_err(be)?
        };
        if map.is_empty() {
            return Ok(None);
        }
        let get = |k: &str| -> Result<&String, StoreError> {
            map.get(k)
                .ok_or_else(|| StoreError::Backend(format!("task:{} missing field {k}", task.0)))
        };
        let holder = || -> Result<WorkerId, StoreError> { Ok(WorkerId(get("holder")?.parse().unwrap_or(0))) };
        let epoch = || -> Result<Epoch, StoreError> { Ok(Epoch(get("epoch")?.parse().unwrap_or(0))) };
        let deadline =
            || -> Result<LogicalTime, StoreError> { Ok(LogicalTime(get("deadline")?.parse().unwrap_or(0))) };
        let output = || -> Result<OutputRef, StoreError> { Ok(OutputRef(get("output")?.parse().unwrap_or(0))) };
        let commitment = || -> Result<Commitment, StoreError> { commitment_from_hex(get("commitment")?) };

        let state = match get("status")?.as_str() {
            "pending" => TaskState::Pending,
            "leased" => TaskState::Leased {
                holder: holder()?,
                epoch: epoch()?,
                deadline: deadline()?,
            },
            "submitted" => TaskState::Submitted {
                holder: holder()?,
                epoch: epoch()?,
                commitment: commitment()?,
                output: output()?,
            },
            "verifying" => TaskState::Verifying {
                holder: holder()?,
                epoch: epoch()?,
                commitment: commitment()?,
                output: output()?,
                // The real challenge frames live with the engine/verifier (Session 5);
                // the store records the categorical Verifying state only.
                challenge: Challenge::default(),
            },
            "accepted" => TaskState::Accepted {
                output: output()?,
                commitment: commitment()?,
            },
            // The only failure the store itself produces is exhausted verification.
            "failed" => TaskState::Failed {
                reason: FailureReason::VerificationExhausted,
            },
            other => return Err(StoreError::Backend(format!("unknown status {other}"))),
        };
        Ok(Some(Task {
            id: task,
            kind: decode_kind(get("kind")?)?,
            state,
            epoch_hw: Epoch(get("epoch_hw")?.parse().unwrap_or(0)),
            retries: get("retries")?.parse().unwrap_or(0),
        }))
    }

    fn lease(
        &self,
        task: TaskId,
        worker: WorkerId,
        deadline: LogicalTime,
    ) -> Result<Epoch, StoreError> {
        let (id, w, d) = (task.0.to_string(), worker.0.to_string(), deadline.0.to_string());
        let reply: Vec<String> = self.call(LEASE, &[&id, &w, &d])?;
        if reply.first().map(String::as_str) == Some("ok") {
            Ok(Epoch(at_u64(&reply, 1)))
        } else {
            Err(classify(&reply, task, "Lease"))
        }
    }

    fn extend_lease(
        &self,
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
        new_deadline: LogicalTime,
    ) -> Result<(), StoreError> {
        let (id, w, e, d) = (
            task.0.to_string(),
            worker.0.to_string(),
            epoch.0.to_string(),
            new_deadline.0.to_string(),
        );
        let reply: Vec<String> = self.call(EXTEND, &[&id, &w, &e, &d])?;
        expect_ok(reply, task, "Heartbeat")
    }

    fn submit(
        &self,
        task: TaskId,
        worker: WorkerId,
        epoch: Epoch,
        commitment: Commitment,
        output: OutputRef,
    ) -> Result<(), StoreError> {
        let (id, w, e, c, o) = (
            task.0.to_string(),
            worker.0.to_string(),
            epoch.0.to_string(),
            to_hex(&commitment.0),
            output.0.to_string(),
        );
        let reply: Vec<String> = self.call(SUBMIT, &[&id, &w, &e, &c, &o])?;
        expect_ok(reply, task, "Submit")
    }

    fn select_or_accept(&self, task: TaskId, sampled: bool) -> Result<(), StoreError> {
        let (id, s) = (task.0.to_string(), if sampled { "1" } else { "0" }.to_string());
        let reply: Vec<String> = self.call(SELECT_OR_ACCEPT, &[&id, &s])?;
        expect_ok(reply, task, if sampled { "SelectForVerification" } else { "Accept" })
    }

    fn verify_outcome(&self, task: TaskId, passed: bool) -> Result<(), StoreError> {
        let (id, p) = (task.0.to_string(), if passed { "1" } else { "0" }.to_string());
        let reply: Vec<String> = self.call(&verify_outcome_lua(), &[&id, &p])?;
        expect_ok(reply, task, "VerifyOutcome")
    }

    fn reclaim_expired(&self, now: LogicalTime) -> Result<Vec<TaskId>, StoreError> {
        // The single authority: range-scan the deadline index, then a Lua reclaim per
        // candidate (which re-checks status + deadline atomically before requeueing).
        let dz = format!("{}:deadlines", self.prefix);
        let candidates: Vec<String> = {
            let mut conn = self.lock();
            ::redis::cmd("ZRANGEBYSCORE")
                .arg(&dz)
                .arg(0)
                .arg(now.0)
                .query(&mut *conn)
                .map_err(be)?
        };
        let mut reclaimed = Vec::new();
        let reclaim_lua = reclaim_one_lua();
        for id in &candidates {
            let did: i64 = self.call(&reclaim_lua, &[id, &now.0.to_string()])?;
            if did == 1 {
                if let Ok(n) = id.parse() {
                    reclaimed.push(TaskId(n));
                }
            }
        }
        reclaimed.sort_unstable_by_key(|t| t.0);
        Ok(reclaimed)
    }

    fn enqueue_ready(
        &self,
        task: TaskId,
        priority: Priority,
        _now: LogicalTime,
    ) -> Result<(), StoreError> {
        // `_now` feeds the Session-3 aging policy; the score here is priority-then-FIFO.
        let (id, p) = (task.0.to_string(), priority.0.to_string());
        let reply: Vec<String> = self.call(&enqueue_lua(), &[&id, &p])?;
        expect_ok(reply, task, "Enqueue")
    }

    fn pop_ready(&self) -> Result<Option<TaskId>, StoreError> {
        let ready = format!("{}:ready", self.prefix);
        let popped: Vec<String> = {
            let mut conn = self.lock();
            // ZPOPMAX returns [member, score]; highest score = highest priority, earliest seq.
            ::redis::cmd("ZPOPMAX")
                .arg(&ready)
                .query(&mut *conn)
                .map_err(be)?
        };
        Ok(popped.first().and_then(|m| m.parse().ok()).map(TaskId))
    }

    fn register_worker(&self, worker: WorkerId, now: LogicalTime) -> Result<(), StoreError> {
        let (w, n) = (worker.0.to_string(), now.0.to_string());
        let reply: Vec<String> = self.call(REGISTER, &[&w, &n])?;
        if reply.first().map(String::as_str) == Some("ok") {
            Ok(())
        } else {
            Err(StoreError::Backend(format!("register_worker: {reply:?}")))
        }
    }

    fn worker_load(&self, worker: WorkerId) -> Result<WorkerLoad, StoreError> {
        let key = self.worker_key(worker);
        let mut conn = self.lock();
        let exists: bool = ::redis::cmd("EXISTS").arg(&key).query(&mut *conn).map_err(be)?;
        if !exists {
            return Err(StoreError::UnknownWorker(worker));
        }
        let (in_flight, ewma, last): (i64, f64, u64) = ::redis::cmd("HMGET")
            .arg(&key)
            .arg("in_flight")
            .arg("ewma_throughput")
            .arg("last_heartbeat")
            .query(&mut *conn)
            .map_err(be)?;
        Ok(WorkerLoad {
            in_flight: in_flight.max(0) as u32,
            ewma_throughput: ewma,
            last_heartbeat: LogicalTime(last),
        })
    }

    fn update_standing(&self, worker: WorkerId, delta: ReputationDelta) -> Result<Tier, StoreError> {
        let (w, penalty) = (worker.0.to_string(), standing_penalty(delta).to_string());
        let reply: Vec<String> = self.call(STANDING, &[&w, &penalty])?;
        match reply.first().map(String::as_str) {
            // The tier band is the SHARED mapping (super::tier_from_standing), so the
            // Redis backend reports the same tier the in-memory reference would.
            Some("ok") => Ok(tier_from_standing(at_i64(&reply, 1) as i32)),
            Some("unknown") => Err(StoreError::UnknownWorker(worker)),
            other => Err(StoreError::Backend(format!("update_standing: {other:?}"))),
        }
    }

    fn record_verdict(
        &self,
        worker: WorkerId,
        detail: proctor_core::VerifyDetail,
    ) -> Result<Tier, StoreError> {
        // Signed magnitude + clamp bounds, all from the authoritative policy module, so the
        // Lua reproduces `reputation::record_verdict` exactly (the in-memory reference).
        let delta = crate::reputation::verdict_delta(detail).to_string();
        let floor = crate::reputation::STANDING_FLOOR.to_string();
        let cap = crate::reputation::PRISTINE.to_string();
        let w = worker.0.to_string();
        let reply: Vec<String> = self.call(RECORD_VERDICT, &[&w, &delta, &floor, &cap])?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(tier_from_standing(at_i64(&reply, 1) as i32)),
            Some("unknown") => Err(StoreError::UnknownWorker(worker)),
            other => Err(StoreError::Backend(format!("record_verdict: {other:?}"))),
        }
    }
}

impl super::InboundChannel for RedisStore {
    fn brpop_inbound(&self, timeout_secs: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let key = format!("{}:inbound", self.prefix);
        let mut conn = self.lock();
        // BRPOP returns [key, value] or nil on timeout; the value is a raw tagged frame.
        let popped: Option<(String, Vec<u8>)> = ::redis::cmd("BRPOP")
            .arg(&key)
            .arg(timeout_secs)
            .query(&mut *conn)
            .map_err(be)?;
        Ok(popped.map(|(_, frame)| frame))
    }
}

impl super::OutboundChannel for RedisStore {
    fn push_assignment(&self, worker: WorkerId, frame: &[u8]) -> Result<(), StoreError> {
        // The worker `BRPOP`s `{prefix}:inbox:{worker}` and decodes the raw Assignment bytes
        // (worker::transport::next_assignment) — so the frame here is `encode(&assignment)`,
        // no tag. One `LPUSH` is the second of the two `DISPATCH_REDIS_RTTS` (after lease).
        let key = format!("{}:inbox:{}", self.prefix, worker.0);
        let mut conn = self.lock();
        let _: i64 = ::redis::cmd("LPUSH")
            .arg(&key)
            .arg(frame)
            .query(&mut *conn)
            .map_err(be)?;
        Ok(())
    }

    fn push_verify_request(&self, frame: &[u8]) -> Result<(), StoreError> {
        // The verifier `BRPOP`s `{prefix}:inbox:verifier` and decodes the raw VerifyRequest
        // bytes (verifier::serve) — so the frame here is `encode(&req)`, no tag.
        let key = format!("{}:inbox:verifier", self.prefix);
        let mut conn = self.lock();
        let _: i64 = ::redis::cmd("LPUSH")
            .arg(&key)
            .arg(frame)
            .query(&mut *conn)
            .map_err(be)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RedisStore;
    use crate::store::contract::store_contract_suite;

    /// A RedisStore for one test, namespaced by a unique prefix, or `None` if no Redis is
    /// reachable (the contract macro then skips loudly — never fabricates a pass, §9).
    /// Override the endpoint with `PROCTOR_TEST_REDIS_URL`.
    pub(crate) fn test_store() -> Option<RedisStore> {
        let url = std::env::var("PROCTOR_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let store = RedisStore::connect(&url, unique_prefix()).ok()?;
        // Confirm reachability before handing the store to a test.
        {
            let mut conn = store.lock();
            ::redis::cmd("PING").query::<String>(&mut conn).ok()?;
        }
        Some(store)
    }

    /// A process-unique key prefix so parallel tests never collide.
    fn unique_prefix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("proctor:test:{}:{}:{}", std::process::id(), nanos, n)
    }

    // Best-effort namespace cleanup so a test run leaves no keys behind. Test-only: a
    // production RedisStore must never auto-delete its durable state.
    impl Drop for RedisStore {
        fn drop(&mut self) {
            let mut conn = self.lock();
            if let Ok(keys) = ::redis::cmd("KEYS")
                .arg(format!("{}:*", self.prefix))
                .query::<Vec<String>>(&mut conn)
            {
                if !keys.is_empty() {
                    let mut del = ::redis::cmd("DEL");
                    for k in &keys {
                        del.arg(k);
                    }
                    let _ = del.query::<i64>(&mut conn);
                }
            }
        }
    }

    // The SAME contract suite as the in-memory reference — the differential oracle (§9).
    // Gated: skips loudly if no Redis is reachable.
    store_contract_suite!(test_store());
}
