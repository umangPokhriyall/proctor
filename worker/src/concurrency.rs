//! `concurrency` — derive the worker's task concurrency from the **cgroup CPU
//! quota**, never host load (phase5-spec.md §4.1, §8).
//!
//! The legacy mechanical-sympathy bug sized a pool from `os.loadavg()`/`num_cpus`:
//! host-wide signals that ignore the container's actual CPU budget, so a worker
//! pinned to 2 CPUs by its cgroup would happily spawn a thread per host core and
//! thrash. This module reads the cgroup-v2 `cpu.max` (`"<quota> <period>"`, both in
//! microseconds, or `"max <period>"` for unlimited) and computes the allowed CPU
//! count as `floor(quota / period)` — the number of whole CPUs the scheduler will
//! actually give us. Effective concurrency is then `min(configured_cap, that)`,
//! always at least 1.
//!
//! There is **no** `num_cpus`/`loadavg` dependency anywhere — the bug is avoided
//! structurally (allowlist §2), and the read path is unit-tested over fixture
//! contents so the parse is verified without a real cgroup.

use std::path::Path;

/// The canonical cgroup-v2 CPU bandwidth file.
pub const CPU_MAX_PATH: &str = "/sys/fs/cgroup/cpu.max";

/// Parse a cgroup-v2 `cpu.max` line into the number of whole CPUs allowed, or
/// `None` for unlimited (`"max ..."`) or an unparseable line. `floor(quota/period)`
/// is the count of CPUs the cgroup will actually schedule us on; a fractional quota
/// (e.g. 1.5 CPUs) floors to 1 — we never oversubscribe past whole granted cores.
fn parse_cpu_max(contents: &str) -> Option<u32> {
    let mut parts = contents.split_whitespace();
    let quota = parts.next()?;
    let period: u64 = parts.next()?.parse().ok()?;
    if quota == "max" || period == 0 {
        return None; // unlimited, or a malformed period we refuse to divide by
    }
    let quota: u64 = quota.parse().ok()?;
    let cpus = quota / period; // floor: only whole granted CPUs
    u32::try_from(cpus.max(1)).ok()
}

/// Read `cpu.max` at `path` and return the cgroup-allowed whole-CPU count, or `None`
/// if the file is absent/unlimited/unparseable (the caller falls back to its cap).
fn cpu_quota_at(path: impl AsRef<Path>) -> Option<u32> {
    let contents = std::fs::read_to_string(path).ok()?;
    parse_cpu_max(&contents)
}

/// Combine a configured cap with an optional cgroup quota: `min(cap, quota)`, at
/// least 1. `None` (unlimited / unreadable cgroup) leaves the cap standing — never a
/// host-load fallback (§4.1). Pure, so the policy is unit-tested without a cgroup.
fn combine(configured_cap: u32, cgroup_quota: Option<u32>) -> u32 {
    let cap = configured_cap.max(1);
    match cgroup_quota {
        Some(quota) => cap.min(quota.max(1)),
        None => cap,
    }
}

/// Effective task concurrency: `min(configured_cap, cgroup_cpu_quota)`, at least 1.
/// Reads the real [`CPU_MAX_PATH`]; if the cgroup is unlimited or the file is
/// unreadable, the configured cap stands (never a host-load fallback — §4.1).
#[must_use]
pub fn effective_concurrency(configured_cap: u32) -> u32 {
    combine(configured_cap, cpu_quota_at(CPU_MAX_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_and_fractional_quota_as_floor() {
        // 2 whole CPUs.
        assert_eq!(parse_cpu_max("200000 100000"), Some(2));
        // 1.5 CPUs floors to 1 — never oversubscribe past granted whole cores.
        assert_eq!(parse_cpu_max("150000 100000"), Some(1));
        // Sub-one quota still yields at least 1 (a worker must make progress).
        assert_eq!(parse_cpu_max("50000 100000"), Some(1));
        // Trailing whitespace / newline tolerated.
        assert_eq!(parse_cpu_max("400000 100000\n"), Some(4));
    }

    #[test]
    fn unlimited_or_malformed_is_none() {
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpu_max("100000 0"), None); // zero period: refuse to divide
        assert_eq!(parse_cpu_max(""), None);
        assert_eq!(parse_cpu_max("garbage"), None);
        assert_eq!(parse_cpu_max("100000"), None); // missing period field
    }

    #[test]
    fn combine_takes_the_min_and_floors_at_one() {
        // Cap is the binding constraint (generous quota).
        assert_eq!(combine(8, Some(16)), 8);
        // Quota is the binding constraint.
        assert_eq!(combine(8, Some(2)), 2);
        // Unlimited / unreadable cgroup ⇒ the cap stands (no host-load fallback).
        assert_eq!(combine(8, None), 8);
        // Always at least 1, even for degenerate inputs.
        assert_eq!(combine(0, None), 1);
        assert_eq!(combine(0, Some(0)), 1);
        assert_eq!(combine(4, Some(0)), 1);
    }

    #[test]
    fn effective_concurrency_is_at_least_one_on_this_host() {
        // Whatever the host's cgroup reports, the result is a usable thread count.
        assert!(effective_concurrency(4) >= 1);
    }
}
