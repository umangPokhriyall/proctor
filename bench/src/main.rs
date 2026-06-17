//! proctor `bench` — the single-host N-worker harness (phase6-spec.md).
//!
//! **NO ingest API** (locked decision #2): workloads are injected **directly** into the
//! scheduler's Redis queue via [`inject::inject_workload`]. There is no `api` crate, ever.
//! The harness stages the deterministic synthetic corpus ([`preprocess`]), brings up the
//! `sched` / `worker` / `verifier` processes as `taskset`-pinned subprocesses over a loopback
//! Redis ([`orchestrate`]), drives an open-loop, coordinated-omission-correct injector
//! ([`inject`]), and merges per-process event logs by task id into distributions
//! ([`metrics`]). `#![forbid(unsafe_code)]`, no async (phase6-spec.md hard rule 1).
//!
//! Session 1 builds the harness and the real Redis dispatch path; the measurement result
//! sets (`bench/results/**`) and the adversary suite land in Sessions 2–6. A run needs a
//! real Redis + ffmpeg — it loud-skips and marks results pending if either is absent (no
//! fabricated numbers, phase6-spec.md hard rule 2).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sched::store::{Priority, RedisStore};

use bench::metrics::event;
use bench::{inject, metrics, orchestrate, preprocess};

const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let rc = match cmd {
        Some("preprocess") => cmd_preprocess(&args[2..]),
        Some("run") => cmd_run(&args[2..]),
        _ => {
            usage();
            2
        }
    };
    std::process::exit(rc);
}

fn usage() {
    eprintln!(
        "proctor bench — single-host harness (phase6-spec.md)\n\
         \n\
         USAGE:\n\
         \x20 bench preprocess [--work-dir DIR]\n\
         \x20 bench run [--workers N] [--verifiers M] [--rate HZ] [--duration SECS] \\\n\
         \x20            [--redis-url URL] [--work-dir DIR]\n\
         \n\
         A `run` requires a reachable Redis and ffmpeg; it loud-skips otherwise."
    );
}

// --- argument plumbing ----------------------------------------------------------------

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn flag_parse<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    flag(args, name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_work_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "proctor-bench-{}-{}",
        std::process::id(),
        metrics::now_ns()
    ))
}

fn unique_prefix() -> String {
    format!("proctor:bench:{}:{}", std::process::id(), metrics::now_ns())
}

// --- `preprocess` ---------------------------------------------------------------------

fn cmd_preprocess(args: &[String]) -> i32 {
    if !preprocess::ffmpeg_available() {
        eprintln!("SKIP preprocess: ffmpeg not found (results pending)");
        return 0;
    }
    let work_dir = flag(args, "--work-dir")
        .map(PathBuf::from)
        .unwrap_or_else(unique_work_dir);
    let cfg = preprocess::Config::defaults(manifest_dir().join("corpus"), &work_dir);
    match preprocess::stage(&cfg) {
        Ok(wl) => {
            println!("staged {} segment(s) from {} clip(s)", wl.tasks.len(), cfg.clips.len());
            println!("  blob_root: {}", wl.blob_root.display());
            println!("  key_dir:   {}", wl.key_dir.display());
            0
        }
        Err(e) => {
            eprintln!("proctor bench: preprocess failed: {e}");
            1
        }
    }
}

// --- `run` (the live single-host run) -------------------------------------------------

fn cmd_run(args: &[String]) -> i32 {
    let redis_url = flag(args, "--redis-url").unwrap_or(DEFAULT_REDIS_URL).to_string();
    let workers: u32 = flag_parse(args, "--workers", 4);
    let verifiers: u32 = flag_parse(args, "--verifiers", 1);
    let rate_hz: f64 = flag_parse(args, "--rate", 20.0);
    let duration_secs: u64 = flag_parse(args, "--duration", 10);
    let work_dir = flag(args, "--work-dir")
        .map(PathBuf::from)
        .unwrap_or_else(unique_work_dir);

    // Gate: real Redis + ffmpeg, else loud-skip (no fabricated numbers, hard rule 2).
    if !redis_reachable(&redis_url) {
        eprintln!("SKIP run: no reachable Redis at {redis_url} (results pending)");
        return 0;
    }
    if !preprocess::ffmpeg_available() {
        eprintln!("SKIP run: ffmpeg not found (results pending)");
        return 0;
    }

    // 1. Stage the corpus (segment + encrypt + populate blob/key stores).
    let prep = preprocess::Config::defaults(manifest_dir().join("corpus"), &work_dir);
    let workload = match preprocess::stage(&prep) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("proctor bench: preprocess failed: {e}");
            return 1;
        }
    };
    eprintln!(
        "proctor bench: staged {} segment(s); workers={workers} verifiers={verifiers} \
         rate={rate_hz}hz duration={duration_secs}s",
        workload.tasks.len()
    );

    // 2. Bring up the cluster (sched + workers + verifiers) over loopback Redis.
    let prefix = unique_prefix();
    let event_log_dir = work_dir.join("events");
    let orch = orchestrate::Config {
        redis_url: redis_url.clone(),
        prefix: prefix.clone(),
        blob_root: workload.blob_root.clone(),
        key_dir: workload.key_dir.clone(),
        roc_threshold: manifest_dir().join("results/verify/roc-threshold.json"),
        workers,
        verifiers,
        event_log_dir: event_log_dir.clone(),
        cores: orchestrate::Config::host_cores(),
        bin_dir: orchestrate::Config::sibling_bin_dir(),
        run_secs: None, // teardown kills the cluster; no self-exit race with the injector
    };
    let cluster = match orchestrate::spawn(&orch) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("proctor bench: orchestration failed: {e}");
            return 1;
        }
    };

    // 3. Open-loop, CO-correct injection directly into the shared Redis store.
    let store = match RedisStore::connect(&redis_url, &prefix) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("proctor bench: injector store connect failed: {e}");
            cluster.teardown();
            return 1;
        }
    };
    // Give the worker/verifier processes a moment to register + start their BRPOP loops.
    std::thread::sleep(Duration::from_millis(500));

    let inject_log = match metrics::EventLog::create(event_log_dir.join("inject.log")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("proctor bench: inject log: {e}");
            cluster.teardown();
            return 1;
        }
    };
    let started = Instant::now();
    let report = inject::run_open_loop(
        &store,
        workload.tasks.clone(),
        &inject::Config { rate_hz, priority: Priority::default() },
        &inject_log,
        now_logical,
    );
    eprintln!(
        "proctor bench: injected {}/{} (failed {}); intended {:.1}hz achieved {:.1}hz",
        report.injected, report.intended, report.failed, report.intended_rate_hz,
        report.achieved_rate_hz
    );

    // 4. Let the cluster drain for the remainder of the run window, then tear down.
    let elapsed = started.elapsed();
    if elapsed < Duration::from_secs(duration_secs) {
        std::thread::sleep(Duration::from_secs(duration_secs) - elapsed);
    }
    cluster.teardown();

    // 5. Merge the per-process event logs by task id and report the dispatch distribution.
    report_dispatch(&event_log_dir, rate_hz);
    0
}

/// Wall-clock seconds as the scheduler's logical time (the shared cross-process clock).
fn now_logical() -> proctor_core::LogicalTime {
    proctor_core::LogicalTime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// Read every process event log, merge by task id, and print the **coordinated-omission-
/// correct** dispatch-latency distribution (intended-issue → dispatched). The full,
/// committed result sets land in Sessions 2–6; this proves the live pipeline end-to-end.
fn report_dispatch(event_log_dir: &std::path::Path, rate_hz: f64) {
    let records = match metrics::read_log_dir(event_log_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("proctor bench: reading event logs: {e}");
            return;
        }
    };

    // Per-event counts across every process log (the whole lifecycle vocabulary).
    let count_of = |name: &str| records.iter().filter(|r| r.event == name).count();
    eprintln!(
        "proctor bench: events — intended={} injected={} shed={} dispatched={} reclaimed={}",
        count_of(event::INTENDED),
        count_of(event::INJECTED),
        count_of(event::SHED),
        count_of(event::DISPATCHED),
        count_of(event::RECLAIMED),
    );

    let by_task = metrics::merge_by_task(&records);
    let latencies = metrics::stage_latencies_ns(&by_task, event::INTENDED, event::DISPATCHED);
    eprintln!("proctor bench: {} task(s) seen across logs", by_task.len());

    // CO-correct: a dispatch that exceeds the intended inter-arrival interval back-fills the
    // latencies a coordinated-omission-blind recorder would have dropped.
    let expected_interval_ns = (1.0e9 / rate_hz.max(f64::MIN_POSITIVE)) as u64;
    let mut h = metrics::Latencies::new();
    for &lat in &latencies {
        h.record_co(lat, expected_interval_ns);
    }
    if h.is_empty() {
        eprintln!("proctor bench: no intended→dispatched pairs to summarize");
        return;
    }
    let s = h.summary();
    eprintln!(
        "proctor bench: dispatch latency (intended→dispatched, CO-correct), n={}: \
         p50={:.3}ms p99={:.3}ms p99.9={:.3}ms max={:.3}ms",
        s.count,
        ms(s.p50_ns),
        ms(s.p99_ns),
        ms(s.p999_ns),
        ms(s.max_ns),
    );
}

fn ms(ns: u64) -> f64 {
    ns as f64 / 1e6
}

fn redis_reachable(url: &str) -> bool {
    let Ok(client) = redis::Client::open(url) else {
        return false;
    };
    let Ok(mut conn) = client.get_connection() else {
        return false;
    };
    redis::cmd("PING").query::<String>(&mut conn).is_ok()
}
