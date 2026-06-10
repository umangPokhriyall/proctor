//! `lease` — the [`Lease`] and its fencing [`Epoch`], plus the pure expiry
//! predicate. See `docs/specs/phase1-spec.md` §4.
//!
//! The legacy zombie-task bug — a reclaimed task picked up by a revived worker
//! that completes work it no longer holds — is killed structurally here, in the
//! type system, rather than patched at the I/O layer. A lease binds a `holder`
//! to a single `epoch`; the task state machine (Phase 1 §6, Session 3) advances
//! a high-water epoch on every (re)lease, so a holder presenting a stale epoch
//! is rejected with its action discarded, never applied late.
//!
//! **Sans-IO (§11):** [`Lease::is_expired`] reads no clock. The scheduler owns
//! the wall clock and injects `now` as [`LogicalTime`].

use serde::{Deserialize, Serialize};

use crate::id::{Epoch, LogicalTime, WorkerId};

/// A single authoritative hold on a task: who holds it, under which fencing epoch,
/// and until when. Heartbeats extend `deadline`; a reclaim mints a new lease with a
/// strictly greater `epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// The worker currently authorized to act on the task.
    pub holder: WorkerId,
    /// The fencing token under which this hold is valid. Strictly increases on every
    /// (re)lease, so a revived holder with an older epoch is detectable.
    pub epoch: Epoch,
    /// Extended by heartbeats; compared against an injected `now` (never a wall clock).
    pub deadline: LogicalTime,
}

impl Lease {
    /// Whether this lease has expired relative to the injected `now`.
    ///
    /// Pure predicate — the scheduler owns the clock and passes `now` in. A lease is
    /// expired once `now` has reached its `deadline` (inclusive), so a deadline that
    /// equals the current time has lapsed; a heartbeat must push `deadline` strictly
    /// past `now` to keep the hold alive.
    #[must_use]
    pub fn is_expired(&self, now: LogicalTime) -> bool {
        now >= self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_with_deadline(deadline: u64) -> Lease {
        Lease {
            holder: WorkerId(7),
            epoch: Epoch(1),
            deadline: LogicalTime(deadline),
        }
    }

    #[test]
    fn not_expired_before_deadline() {
        let lease = lease_with_deadline(100);
        assert!(!lease.is_expired(LogicalTime(0)));
        assert!(!lease.is_expired(LogicalTime(99)));
    }

    #[test]
    fn expired_at_and_after_deadline() {
        let lease = lease_with_deadline(100);
        // Inclusive: a deadline reached exactly is lapsed.
        assert!(lease.is_expired(LogicalTime(100)));
        assert!(lease.is_expired(LogicalTime(101)));
        assert!(lease.is_expired(LogicalTime(u64::MAX)));
    }

    #[test]
    fn heartbeat_extends_the_hold() {
        // Modelling a heartbeat: pushing the deadline strictly past `now` un-expires it.
        let now = LogicalTime(100);
        let mut lease = lease_with_deadline(100);
        assert!(lease.is_expired(now));
        lease.deadline = LogicalTime(150);
        assert!(!lease.is_expired(now));
    }
}
