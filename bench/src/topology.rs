//! `topology` — host CPU topology discovery + NUMA-aware core placement (phase7-spec.md §3).
//!
//! Phase 6 pinned processes round-robin over a flat logical-CPU pool — fine on a 4c/8t
//! laptop, but on a bare-metal box the scaling curve is only honest if workers land on
//! **disjoint physical cores** (not hyperthread siblings) and the control/IO/verify roles
//! get **dedicated** cores. This module reads the kernel's topology from `sysfs` (plain file
//! reads — `bench` stays `#![forbid(unsafe_code)]`, no FFI) and turns it into a [`Pinning`]
//! plan the orchestrator hands to `taskset`. Socket placement is recorded in the plan's
//! `description` so the loopback-Redis RTT and any NUMA effects are attributable
//! (phase7-spec.md §2: "document which socket Redis sits on").
//!
//! If `sysfs` is unavailable (non-Linux dev box, container), [`Topology::detect`] falls back
//! to one physical core per logical CPU and a single NUMA node — pinning still works, just
//! without sibling/socket awareness, and `detected` is `false` so callers can say so.

use std::collections::BTreeMap;
use std::path::Path;

/// One physical core: its representative logical CPU (the `taskset` target) and the full set
/// of hyperthread siblings sharing it, plus the NUMA node it lives on.
#[derive(Debug, Clone)]
pub struct PhysicalCore {
    /// The logical CPU id workers/roles are pinned to (the lowest sibling — stable).
    pub rep_cpu: usize,
    /// Every logical CPU (hyperthread) backed by this physical core, ascending.
    pub siblings: Vec<usize>,
    /// The NUMA node (socket) this physical core belongs to.
    pub node: usize,
}

/// The host's CPU topology: physical cores grouped by NUMA node, and the flat logical-CPU
/// list. `detected` is `false` when `sysfs` parsing failed and the fallback was used.
#[derive(Debug, Clone)]
pub struct Topology {
    /// NUMA node ids present on the host, ascending.
    pub nodes: Vec<usize>,
    /// Physical cores, ordered node-major then by representative CPU (so node 0 comes first).
    pub physical_cores: Vec<PhysicalCore>,
    /// Every online logical CPU id, ascending.
    pub logical_cpus: Vec<usize>,
    /// `true` if the topology came from `sysfs`; `false` if the (one-core-per-CPU) fallback ran.
    pub detected: bool,
}

impl Topology {
    /// Discover the topology from `/sys`. Never fails — falls back to a flat single-node view
    /// (one physical core per logical CPU) if `sysfs` is missing or unreadable.
    #[must_use]
    pub fn detect() -> Self {
        Self::detect_from(Path::new("/sys"))
    }

    /// `detect`, rooted at an arbitrary `sysfs` mount (so the parsing is unit-testable).
    #[must_use]
    pub fn detect_from(sysfs: &Path) -> Self {
        match Self::try_detect_from(sysfs) {
            Some(t) if !t.physical_cores.is_empty() => t,
            _ => Self::fallback(),
        }
    }

    fn try_detect_from(sysfs: &Path) -> Option<Self> {
        let online = read_cpu_list(&sysfs.join("devices/system/cpu/online"))?;
        if online.is_empty() {
            return None;
        }
        // node id -> cpu ids, from /sys/devices/system/node/node*/cpulist.
        let node_dir = sysfs.join("devices/system/node");
        let mut cpu_node: BTreeMap<usize, usize> = BTreeMap::new();
        let mut nodes: Vec<usize> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&node_dir) {
            for e in entries.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if let Some(id) = name.strip_prefix("node").and_then(|n| n.parse::<usize>().ok()) {
                    if let Some(cpus) = read_cpu_list(&e.path().join("cpulist")) {
                        nodes.push(id);
                        for c in cpus {
                            cpu_node.insert(c, id);
                        }
                    }
                }
            }
        }
        if nodes.is_empty() {
            nodes.push(0); // a machine with no NUMA node export is a single node.
        }
        nodes.sort_unstable();

        // Group online CPUs into physical cores by (package, core_id); siblings share one.
        let mut cores: BTreeMap<(usize, usize), Vec<usize>> = BTreeMap::new();
        for &cpu in &online {
            let topo = sysfs.join(format!("devices/system/cpu/cpu{cpu}/topology"));
            let pkg = read_usize(&topo.join("physical_package_id")).unwrap_or(0);
            let core_id = read_usize(&topo.join("core_id")).unwrap_or(cpu);
            cores.entry((pkg, core_id)).or_default().push(cpu);
        }
        if cores.is_empty() {
            return None;
        }

        let mut physical_cores: Vec<PhysicalCore> = cores
            .into_values()
            .map(|mut siblings| {
                siblings.sort_unstable();
                let rep_cpu = siblings[0];
                let node = cpu_node.get(&rep_cpu).copied().unwrap_or(0);
                PhysicalCore { rep_cpu, siblings, node }
            })
            .collect();
        // Node-major ordering so the front of the list is node 0 (infra lands there).
        physical_cores.sort_by_key(|c| (c.node, c.rep_cpu));

        let mut logical_cpus = online;
        logical_cpus.sort_unstable();
        Some(Self { nodes, physical_cores, logical_cpus, detected: true })
    }

    /// Single-node, one-physical-core-per-CPU view used when `sysfs` is unavailable.
    fn fallback() -> Self {
        let n = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let logical_cpus: Vec<usize> = (0..n).collect();
        let physical_cores = logical_cpus
            .iter()
            .map(|&c| PhysicalCore { rep_cpu: c, siblings: vec![c], node: 0 })
            .collect();
        Self { nodes: vec![0], physical_cores, logical_cpus, detected: false }
    }

    /// Number of distinct physical cores (the disjoint-pinning ceiling for the worker grid).
    #[must_use]
    pub fn physical_core_count(&self) -> usize {
        self.physical_cores.len()
    }
}

// --- sysfs parsing helpers ------------------------------------------------------------

/// Parse a kernel CPU-list string (`"0-3,8,12-15"`) into the explicit, sorted ids.
fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in s.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                out.extend(a..=b);
            }
        } else if let Ok(v) = part.parse::<usize>() {
            out.push(v);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn read_cpu_list(path: &Path) -> Option<Vec<usize>> {
    std::fs::read_to_string(path).ok().map(|s| parse_cpu_list(&s))
}

fn read_usize(path: &Path) -> Option<usize> {
    std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_list_ranges_and_singletons() {
        assert_eq!(parse_cpu_list("0-7"), (0..=7).collect::<Vec<_>>());
        assert_eq!(parse_cpu_list("0-3,8,12-13"), vec![0, 1, 2, 3, 8, 12, 13]);
        assert_eq!(parse_cpu_list(" 2 , 0 , 1 "), vec![0, 1, 2]);
        assert!(parse_cpu_list("").is_empty());
    }

    #[test]
    fn detect_is_never_empty() {
        let t = Topology::detect();
        assert!(!t.physical_cores.is_empty());
        assert!(!t.logical_cpus.is_empty());
        assert!(!t.nodes.is_empty());
        assert!(t.physical_core_count() <= t.logical_cpus.len());
    }

    #[test]
    fn fallback_is_one_core_per_cpu_single_node() {
        let t = Topology::fallback();
        assert!(!t.detected);
        assert_eq!(t.nodes, vec![0]);
        assert_eq!(t.physical_cores.len(), t.logical_cpus.len());
    }
}
