//! `id` — opaque newtype identifiers, the monotonic fencing [`Epoch`], and the
//! injected [`LogicalTime`]. See `docs/specs/phase1-spec.md` §3.
//!
//! These types carry no behaviour beyond construction, equality, ordering where
//! it is meaningful, and serde. Their internals are an implementation detail:
//! the `*Id` handles wrap a `u64`, [`OutputRef`] wraps a `u128`, and the two
//! ordered counters ([`Epoch`], [`LogicalTime`]) wrap a `u64`. Nothing above
//! `core` should depend on the representation — only on the operations exposed.
//!
//! **Sans-IO (§11):** nothing here reads a clock or samples randomness.
//! [`LogicalTime`] is *injected* by the scheduler, which owns the wall clock;
//! [`Epoch`] is chosen by the scheduler when it (re)leases a task. `core` only
//! compares them.

use serde::{Deserialize, Serialize};

/// A source video: one job fans out into many GOP-aligned segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub u64);

/// One GOP-aligned segment of a [`JobId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SegmentId(pub u64);

/// One unit of work: a transcode of a single segment, or a stitch of many.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub u64);

/// An untrusted worker identity (pubkey-derived later; opaque here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkerId(pub u64);

/// An opaque handle to a worker's produced blob — **not** the bytes, **not** a key.
/// Resolving the handle to storage is the I/O layer's concern, never `core`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputRef(pub u128);

/// Monotonic fencing token. Strictly increases on every (re)lease of a task, so a
/// revived worker holding an old epoch is detectable and its actions rejected.
/// Ordering is the whole point — it is `PartialOrd`/`Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The first epoch. A `Pending` task with high-water [`Epoch::ZERO`] accepts any
    /// strictly-greater lease epoch; the scheduler assigns `1` for the first lease.
    pub const ZERO: Epoch = Epoch(0);

    /// The next epoch above `self`. Used by the scheduler to advance the high-water
    /// mark on every (re)lease; `core` never samples it, it only checks monotonicity.
    #[must_use]
    pub fn next(self) -> Epoch {
        Epoch(self.0 + 1)
    }
}

/// Injected logical time. `core` NEVER reads a clock; the scheduler owns the wall
/// clock and passes `now` into the pure predicates (e.g. [`crate::lease::Lease::is_expired`]).
/// Ordering is meaningful — deadlines are compared against an injected `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogicalTime(pub u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_orders_and_advances_monotonically() {
        assert!(Epoch(1) > Epoch(0));
        assert!(Epoch(0) < Epoch(1));
        assert_eq!(Epoch(0), Epoch(0));

        // `next` is strictly greater — the fencing-token monotonicity guarantee.
        let e = Epoch::ZERO;
        assert!(e.next() > e);
        assert_eq!(Epoch::ZERO.next(), Epoch(1));
        assert!(e.next().next() > e.next());
    }

    #[test]
    fn epoch_sorts_ascending() {
        let mut epochs = [Epoch(3), Epoch(1), Epoch(2), Epoch(0)];
        epochs.sort();
        assert_eq!(epochs, [Epoch(0), Epoch(1), Epoch(2), Epoch(3)]);
    }

    #[test]
    fn logical_time_orders() {
        assert!(LogicalTime(10) > LogicalTime(5));
        assert!(LogicalTime(5) < LogicalTime(10));
        assert_eq!(LogicalTime(7), LogicalTime(7));
    }
}
