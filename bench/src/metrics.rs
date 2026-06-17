//! `metrics` — per-process lifecycle event logs, merged by task id (phase6-spec.md §3).
//!
//! Each process (the `sched` binary, the in-process injector, and — in later sessions — the
//! worker/verifier bins) appends a line `event,task_id,ts_ns` to its own log for the
//! lifecycle points (intended-issue, injected, dispatched, leased, submitted,
//! verify-requested, verified, released, reclaimed, shed). The bench reads every log, merges
//! the records **by task id**, and derives per-stage latency distributions.
//!
//! ## On the timestamp
//! `ts_ns` is **wall-clock UNIX nanoseconds** ([`now_ns`]), not a per-process monotonic
//! count — because stage latencies are computed *across* processes and only a shared clock
//! is comparable. On a single host (locked decision #5) CLOCK_REALTIME is that shared clock;
//! a monotonic `Instant` cannot be extracted as a shared raw value without FFI, which `bench`
//! forbids. The injector additionally uses a monotonic `Instant` for **pacing** (sleeping to
//! the intended-issue time) and feeds coordinated-omission-corrected intervals into an
//! [`Latencies`] histogram — that is where the CO discipline (phase6-spec.md §3) lives.
//!
//! ## Coordinated-omission correction
//! [`Latencies::record_co`] wraps `hdrhistogram`'s expected-interval correction: a sample
//! that exceeds the expected inter-arrival interval back-fills the values a coordinated-
//! omission-blind recorder would have missed, so a stall cannot hide the tail (the
//! Rust-Tcp-Server discipline). Distributions are reported as p50/p99/p99.9, never an
//! average alone (phase6-spec.md hard rule 3).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;
use proctor_core::TaskId;

/// The lifecycle event names. Kept as plain `&str` so the `sched` binary (which cannot
/// depend on `bench`) can emit the identical CSV without sharing a type.
pub mod event {
    /// The injector's intended-issue instant (the CO reference for dispatch latency).
    pub const INTENDED: &str = "intended";
    /// The injector actually created + enqueued the task into the store.
    pub const INJECTED: &str = "injected";
    /// Intake was shed at the Little's-law global cap (backpressure).
    pub const SHED: &str = "shed";
    /// `sched` pushed the `Assignment` onto a worker's inbox (real Redis dispatch).
    pub const DISPATCHED: &str = "dispatched";
    /// `sched` reclaimed an expired lease (the single reclaim authority).
    pub const RECLAIMED: &str = "reclaimed";
}

/// Wall-clock UNIX nanoseconds — the single-host shared clock the merge compares across
/// processes.
#[must_use]
pub fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// A per-process append-only event log. Thread-safe (`&self`) so an in-process driver and
/// the injector can share one handle. The line format is `event,task_id,ts_ns`.
pub struct EventLog {
    sink: Mutex<File>,
}

impl EventLog {
    /// Create (truncating) a fresh log at `path`.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            sink: Mutex::new(file),
        })
    }

    /// Open `path` for appending (creating it if absent) — the mode the long-lived `sched`
    /// and worker/verifier processes use so concurrent writers never truncate each other.
    pub fn append(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            sink: Mutex::new(file),
        })
    }

    /// Record `event` for `task` at the current wall-clock instant.
    pub fn record(&self, event: &str, task: TaskId) {
        self.record_at(event, task, now_ns());
    }

    /// Record `event` for `task` at an explicit `ts_ns` (e.g. a captured intended-issue
    /// time). Best-effort: a write error never aborts the run (the log is observational).
    pub fn record_at(&self, event: &str, task: TaskId, ts_ns: u128) {
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(sink, "{event},{},{ts_ns}", task.0);
    }
}

/// One parsed event-log record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub event: String,
    pub task: TaskId,
    pub ts_ns: u128,
}

/// Parse one `event,task_id,ts_ns` line, ignoring blanks and malformed lines.
fn parse_line(line: &str) -> Option<EventRecord> {
    let mut it = line.trim().splitn(3, ',');
    let event = it.next()?.trim().to_string();
    if event.is_empty() {
        return None;
    }
    let task = TaskId(it.next()?.trim().parse().ok()?);
    let ts_ns = it.next()?.trim().parse().ok()?;
    Some(EventRecord { event, task, ts_ns })
}

/// Read every record from one event-log file.
pub fn read_events(path: impl AsRef<Path>) -> io::Result<Vec<EventRecord>> {
    let reader = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    for line in reader.lines() {
        if let Some(rec) = parse_line(&line?) {
            out.push(rec);
        }
    }
    Ok(out)
}

/// Read and concatenate every `*.log` file in `dir` (one per process). Missing dir ⇒ empty.
pub fn read_log_dir(dir: impl AsRef<Path>) -> io::Result<Vec<EventRecord>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("log") {
            out.extend(read_events(&path)?);
        }
    }
    Ok(out)
}

/// Merge records **by task id**, each task's events sorted by timestamp. This is the join
/// the per-stage latency distributions are computed over. (Keyed by a `HashMap` — the frozen
/// `TaskId` is `Hash + Eq` but not `Ord`; per-stage stats are order-independent.)
#[must_use]
pub fn merge_by_task(records: &[EventRecord]) -> HashMap<TaskId, Vec<(String, u128)>> {
    let mut by_task: HashMap<TaskId, Vec<(String, u128)>> = HashMap::new();
    for r in records {
        by_task
            .entry(r.task)
            .or_default()
            .push((r.event.clone(), r.ts_ns));
    }
    for events in by_task.values_mut() {
        events.sort_by_key(|(_, ts)| *ts);
    }
    by_task
}

/// Per-task stage latency in nanoseconds: for every task that has both a `from` and a later
/// `to` event, `min(ts(to)) − min(ts(from))`. Tasks missing either endpoint are skipped.
#[must_use]
pub fn stage_latencies_ns(
    by_task: &HashMap<TaskId, Vec<(String, u128)>>,
    from: &str,
    to: &str,
) -> Vec<u64> {
    let earliest = |events: &[(String, u128)], name: &str| -> Option<u128> {
        events
            .iter()
            .filter(|(e, _)| e == name)
            .map(|(_, ts)| *ts)
            .min()
    };
    by_task
        .values()
        .filter_map(|events| {
            let f = earliest(events, from)?;
            let t = earliest(events, to)?;
            (t >= f).then(|| u64::try_from(t - f).unwrap_or(u64::MAX))
        })
        .collect()
}

/// A coordinated-omission-correct latency histogram over nanoseconds. Range 1 ns .. 1 hour
/// at 3 significant figures (ample for dispatch/pipeline latencies on a single host).
pub struct Latencies {
    h: Histogram<u64>,
}

impl Default for Latencies {
    fn default() -> Self {
        Self::new()
    }
}

impl Latencies {
    /// A fresh histogram.
    #[must_use]
    pub fn new() -> Self {
        // 1 hour in ns; 3 sig figs. new_with_bounds only errors on absurd parameters.
        let h = Histogram::new_with_bounds(1, 3_600_000_000_000, 3)
            .expect("valid hdrhistogram bounds");
        Self { h }
    }

    /// Record a raw latency (clamped to the histogram's range).
    pub fn record(&mut self, ns: u64) {
        let _ = self.h.record(ns.max(1));
    }

    /// Record a latency **with coordinated-omission correction**: if `ns` exceeds
    /// `expected_interval_ns`, hdrhistogram back-fills the intermediate values a CO-blind
    /// recorder would have dropped, so a stall does not hide the tail (phase6-spec.md §3).
    pub fn record_co(&mut self, ns: u64, expected_interval_ns: u64) {
        let _ = self
            .h
            .record_correct(ns.max(1), expected_interval_ns.max(1));
    }

    /// Record every value in `samples` (no CO correction).
    pub fn record_all(&mut self, samples: &[u64]) {
        for &s in samples {
            self.record(s);
        }
    }

    /// The value at quantile `q ∈ [0, 1]`.
    #[must_use]
    pub fn quantile(&self, q: f64) -> u64 {
        self.h.value_at_quantile(q)
    }

    /// Count of recorded samples (including CO back-fill).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.h.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.h.is_empty()
    }

    /// The p50 / p99 / p99.9 summary plus min/max/mean — the reporting shape (never an
    /// average alone).
    #[must_use]
    pub fn summary(&self) -> Percentiles {
        Percentiles {
            count: self.count(),
            min_ns: self.h.min(),
            p50_ns: self.quantile(0.50),
            p99_ns: self.quantile(0.99),
            p999_ns: self.quantile(0.999),
            max_ns: self.h.max(),
            mean_ns: self.h.mean(),
        }
    }
}

/// A latency distribution summary, in nanoseconds (p50/p99/p99.9, with min/max/mean).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Percentiles {
    pub count: u64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(event: &str, task: u64, ts: u128) -> EventRecord {
        EventRecord {
            event: event.to_string(),
            task: TaskId(task),
            ts_ns: ts,
        }
    }

    #[test]
    fn parses_well_formed_and_rejects_garbage() {
        assert_eq!(parse_line("dispatched,7,123"), Some(rec("dispatched", 7, 123)));
        assert_eq!(parse_line("  intended , 4 , 9 "), Some(rec("intended", 4, 9)));
        assert!(parse_line("").is_none());
        assert!(parse_line("only,two").is_none());
        assert!(parse_line(",5,9").is_none(), "empty event name is rejected");
        assert!(parse_line("dispatched,notanid,1").is_none());
    }

    #[test]
    fn merge_groups_by_task_and_sorts_by_time() {
        let records = vec![
            rec(event::DISPATCHED, 1, 30),
            rec(event::INTENDED, 1, 10),
            rec(event::INJECTED, 1, 20),
            rec(event::INTENDED, 2, 5),
        ];
        let by_task = merge_by_task(&records);
        let t1 = &by_task[&TaskId(1)];
        assert_eq!(
            t1.iter().map(|(e, _)| e.as_str()).collect::<Vec<_>>(),
            vec![event::INTENDED, event::INJECTED, event::DISPATCHED],
            "events sorted by timestamp"
        );
        assert_eq!(by_task[&TaskId(2)].len(), 1);
    }

    #[test]
    fn stage_latencies_pair_intended_to_dispatched() {
        let records = vec![
            rec(event::INTENDED, 1, 100),
            rec(event::DISPATCHED, 1, 400), // 300 ns
            rec(event::INTENDED, 2, 100),
            rec(event::DISPATCHED, 2, 1100), // 1000 ns
            rec(event::INTENDED, 3, 100), // never dispatched → skipped
        ];
        let by_task = merge_by_task(&records);
        let mut lat = stage_latencies_ns(&by_task, event::INTENDED, event::DISPATCHED);
        lat.sort_unstable();
        assert_eq!(lat, vec![300, 1000], "only paired tasks contribute");
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "proctor-metrics-{}-{}",
            std::process::id(),
            now_ns()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sched.log");
        {
            let log = EventLog::create(&path).unwrap();
            log.record_at(event::DISPATCHED, TaskId(1), 42);
            log.record_at(event::RECLAIMED, TaskId(2), 99);
        }
        let recs = read_events(&path).unwrap();
        assert_eq!(recs.len(), 2);
        let from_dir = read_log_dir(&dir).unwrap();
        assert_eq!(from_dir.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn histogram_reports_percentiles() {
        let mut h = Latencies::new();
        for v in 1..=1000u64 {
            h.record(v * 1000); // 1µs .. 1ms
        }
        let s = h.summary();
        assert_eq!(s.count, 1000);
        // p50 ≈ 500µs, p99 ≈ 990µs (within hdrhistogram's 3-sig-fig resolution).
        assert!((400_000..=600_000).contains(&s.p50_ns), "p50 {}", s.p50_ns);
        assert!(s.p99_ns >= s.p50_ns && s.p999_ns >= s.p99_ns);
    }

    #[test]
    fn co_correction_inflates_the_tail_past_a_naive_recorder() {
        // One huge sample at a 1ms expected interval back-fills the omitted values, so the
        // CO-corrected count far exceeds the single naive record — the stall cannot hide.
        let mut naive = Latencies::new();
        naive.record(100_000_000); // 100ms, recorded once
        assert_eq!(naive.count(), 1);

        let mut co = Latencies::new();
        co.record_co(100_000_000, 1_000_000); // expected 1ms interval
        assert!(co.count() > 50, "CO back-fill adds the omitted samples: {}", co.count());
        assert!(co.summary().p50_ns < co.summary().max_ns);
    }
}
