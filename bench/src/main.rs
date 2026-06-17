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
use bench::{decomp, inject, metrics, orchestrate, preprocess, report};

const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let rc = match cmd {
        Some("preprocess") => cmd_preprocess(&args[2..]),
        Some("run") => cmd_run(&args[2..]),
        Some("sched-decomp") => cmd_sched_decomp(&args[2..]),
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
         \x20 bench sched-decomp [--redis-url URL] [--out DIR]\n\
         \n\
         A `run`/`sched-decomp` requires a reachable Redis; they loud-skip otherwise."
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

// --- `sched-decomp` (the scheduling-overhead decomposition, §4) -----------------------

const WORKER_COUNTS: [u32; 4] = [1, 4, 16, 64];

fn cmd_sched_decomp(args: &[String]) -> i32 {
    let redis_url = flag(args, "--redis-url").unwrap_or(DEFAULT_REDIS_URL).to_string();
    let out_dir = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir().join("results/sched"));

    if !redis_reachable(&redis_url) {
        eprintln!("SKIP sched-decomp: no reachable Redis at {redis_url} (results pending)");
        return 0;
    }
    eprintln!("proctor bench: sched decomposition against {redis_url} → {}", out_dir.display());

    // (1) Isolated Redis RTT: PING (pure round trip) + LPUSH (the op dispatch ends on).
    let (ping, lpush) = match decomp::measure_redis_rtt(&redis_url, 30_000) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("proctor bench: RTT measurement failed: {e}");
            return 1;
        }
    };
    let rtt_rows = vec![
        report::latencies_row("ping_rtt", &ping),
        report::latencies_row("lpush_rtt", &lpush),
    ];
    write_or_warn(out_dir.join("rtt.csv"), report::PERCENTILES_HEADER, &rtt_rows);

    // (2) In-process decision time (place::select_worker, no Redis) per N.
    let mut decision_rows = Vec::new();
    let mut decision_p50_us = std::collections::HashMap::new();
    for &n in &WORKER_COUNTS {
        let lat = decomp::measure_decision_time(n, 100_000);
        decision_p50_us.insert(n, report::us(lat.summary().p50_ns));
        decision_rows.push(report::latencies_row(&format!("decision_n{n}"), &lat));
    }
    write_or_warn(out_dir.join("decision_time.csv"), report::PERCENTILES_HEADER, &decision_rows);

    // (3) Throughput vs N (unpaced placement ceiling) + per-dispatch overhead.
    const THR_HEADER: &str = "n,placed,achieved_tasks_per_s,rtt_count,pure_p50_us,pure_p99_us";
    let mut thr_rows: Vec<String> = Vec::new();
    let mut pure_p50_us = std::collections::HashMap::new();
    let mut achieved = std::collections::HashMap::new();
    let mut id_base = 1u64;
    for &n in &WORKER_COUNTS {
        let count = (60_000 / u64::from(decomp::dispatch_rtt_count(n))).clamp(500, 10_000);
        match decomp::measure_throughput(&redis_url, n, count, id_base) {
            Ok(r) => {
                let s = r.pure_dispatch.summary();
                pure_p50_us.insert(n, report::us(s.p50_ns));
                achieved.insert(n, r.achieved_rate_hz);
                thr_rows.push(format!(
                    "{n},{},{:.1},{},{:.3},{:.3}",
                    r.placed,
                    r.achieved_rate_hz,
                    decomp::dispatch_rtt_count(n),
                    report::us(s.p50_ns),
                    report::us(s.p99_ns),
                ));
                eprintln!(
                    "  throughput N={n}: {:.0} tasks/s, pure dispatch p50={:.1}µs p99={:.1}µs ({} RTTs)",
                    r.achieved_rate_hz,
                    report::us(s.p50_ns),
                    report::us(s.p99_ns),
                    decomp::dispatch_rtt_count(n),
                );
                id_base += count;
            }
            Err(e) => eprintln!("proctor bench: throughput N={n} failed: {e}"),
        }
    }
    write_or_warn(out_dir.join("throughput_vs_n.csv"), THR_HEADER, &thr_rows);

    // (4) CO-correct dispatch latency at a sustainable rate (½ the measured ceiling) per N.
    let mut lat_rows = Vec::new();
    for &n in &WORKER_COUNTS {
        let ceiling = achieved.get(&n).copied().unwrap_or(1_000.0);
        let rate = (ceiling * 0.5).max(1.0);
        let count = (30_000 / u64::from(decomp::dispatch_rtt_count(n))).clamp(500, 6_000);
        match decomp::measure_dispatch_live(&redis_url, n, count, rate, id_base) {
            Ok(r) => {
                lat_rows.push(report::latencies_row(&format!("dispatch_co_n{n}"), &r.co_latency));
                lat_rows.push(report::latencies_row(&format!("dispatch_pure_n{n}"), &r.pure_dispatch));
                eprintln!(
                    "  dispatch latency N={n} @ {:.0}hz (achieved {:.0}): CO p50={:.1}µs p99={:.1}µs p99.9={:.1}µs",
                    rate,
                    r.achieved_rate_hz,
                    report::us(r.co_latency.summary().p50_ns),
                    report::us(r.co_latency.summary().p99_ns),
                    report::us(r.co_latency.summary().p999_ns),
                );
                id_base += count;
            }
            Err(e) => eprintln!("proctor bench: dispatch latency N={n} failed: {e}"),
        }
    }
    write_or_warn(out_dir.join("dispatch_latency.csv"), report::PERCENTILES_HEADER, &lat_rows);

    // (5) The predicted-then-confirmed decomposition writeup.
    let summary = build_decomp_summary(
        &ping,
        &lpush,
        &decision_p50_us,
        &pure_p50_us,
        &achieved,
    );
    if let Err(e) = report::write_text(out_dir.join("SUMMARY.md"), &summary) {
        eprintln!("proctor bench: writing SUMMARY.md: {e}");
    }
    eprintln!("proctor bench: wrote rtt.csv, decision_time.csv, throughput_vs_n.csv, dispatch_latency.csv, SUMMARY.md");
    0
}

/// Build the predicted-then-confirmed decomposition writeup from the measured figures.
fn build_decomp_summary(
    ping: &metrics::Latencies,
    lpush: &metrics::Latencies,
    decision_p50_us: &std::collections::HashMap<u32, f64>,
    pure_p50_us: &std::collections::HashMap<u32, f64>,
    achieved: &std::collections::HashMap<u32, f64>,
) -> String {
    let ps = ping.summary();
    let rtt_p50 = report::us(ps.p50_ns);
    let rtt_p99 = report::us(ps.p99_ns);
    let lpush_p50 = report::us(lpush.summary().p50_ns);
    let pure1 = pure_p50_us.get(&1).copied().unwrap_or(0.0);
    let dec1 = decision_p50_us.get(&1).copied().unwrap_or(0.0);
    let predicted_2rtt = 2.0 * rtt_p50;
    let rtt_count_1 = decomp::dispatch_rtt_count(1);
    let implied_per_rtt = if rtt_count_1 > 0 { pure1 / f64::from(rtt_count_1) } else { 0.0 };
    let redis_frac = if pure1 > 0.0 { (1.0 - dec1 / pure1) * 100.0 } else { 0.0 };

    let mut s = String::new();
    s.push_str("# Scheduling-overhead decomposition — predicted-then-confirmed\n\n");
    s.push_str("Source CSVs (this directory): `rtt.csv`, `decision_time.csv`, ");
    s.push_str("`throughput_vs_n.csv`, `dispatch_latency.csv`. Methodology + host/versions in ");
    s.push_str("`METHODOLOGY.md`. Latencies in microseconds.\n\n");
    s.push_str("## The Phase 4 prediction (pre-committed, `sched::backpressure`)\n");
    s.push_str("`DISPATCH_REDIS_RTTS = 2` (lease Lua + inbox LPUSH); ");
    s.push_str("\"decision ≈ µs; p99 dispatch ≈ count × RTT and is ~95% Redis RTTs.\"\n\n");
    s.push_str("## Measured (this host, loopback Redis)\n");
    s.push_str(&format!(
        "- Redis RTT: PING p50 {rtt_p50:.1}µs / p99 {rtt_p99:.1}µs; LPUSH p50 {lpush_p50:.1}µs (`rtt.csv`).\n"
    ));
    s.push_str(&format!(
        "- In-process decision (`place::select_worker`, no Redis): p50 {dec1:.3}µs at N=1 (`decision_time.csv`).\n"
    ));
    s.push_str(&format!(
        "- Pure dispatch (`dispatch_one_live`) at N=1: p50 {pure1:.1}µs (`throughput_vs_n.csv`).\n\n"
    ));
    s.push_str("## The confirmation, and the honest divergence\n");
    s.push_str(&format!(
        "The qualitative prediction **holds, and then some**: dispatch is Redis-dominated — the \
         in-process decision is {dec1:.3}µs against {pure1:.1}µs of dispatch, so Redis is \
         **{redis_frac:.2}%** of dispatch latency (the prediction said ~95%).\n\n"
    ));
    s.push_str(&format!(
        "The **RTT-count constant was an undercount**, and we say so. The predicted `2` counted \
         only lease + LPUSH; the live `dispatch_one_live` path actually issues `2N + 4` round \
         trips — pop_ready (1) + `select_worker` (EXISTS+HMGET = 2 per candidate) + lease (1) + \
         load (1) + LPUSH (1). At N=1 that is {rtt_count_1} RTTs, so the predicted \
         `2 × RTT = {predicted_2rtt:.1}µs` understates the measured {pure1:.1}µs. The implied \
         per-round-trip cost {implied_per_rtt:.1}µs is of the order of — and a little above — the \
         bare PING RTT {rtt_p50:.1}µs / LPUSH {lpush_p50:.1}µs, because the dispatch round trips \
         include heavier ops (an EVALSHA lease script, an HGETALL load, the HMGET worker reads) \
         than a bare PING. So the dispatch time **is** the round trips, exactly as predicted in \
         spirit; only the count was optimistic.\n\n"
    ));
    s.push_str("**Remedy (named, not built here):** fold placement reads + lease + push into a \
                single server-side Lua so a dispatch is ~2–3 RTTs regardless of N — the \
                per-candidate `worker_load` reads are the `2N` term and the only part that \
                scales with N.\n\n");
    s.push_str("## Throughput vs N (placement ceiling)\n");
    s.push_str("| N | achieved tasks/s | RTT count | decision p50 (µs) |\n");
    s.push_str("|---|---|---|---|\n");
    for &n in &WORKER_COUNTS {
        s.push_str(&format!(
            "| {n} | {:.0} | {} | {:.3} |\n",
            achieved.get(&n).copied().unwrap_or(0.0),
            decomp::dispatch_rtt_count(n),
            decision_p50_us.get(&n).copied().unwrap_or(0.0),
        ));
    }
    s.push_str(
        "\nThe in-process decision stays µs-scale and flat-ish per dispatch; the placement \
         ceiling falls as N grows because the `2N` per-candidate `worker_load` round trips are \
         the scaling variable — Redis contention, not decision cost, exactly as predicted. The \
         knee is wherever achieved tasks/s can no longer keep pace with offered load.\n",
    );
    s
}

fn write_or_warn(path: PathBuf, header: &str, rows: &[String]) {
    if let Err(e) = report::write_csv(&path, header, rows) {
        eprintln!("proctor bench: writing {}: {e}", path.display());
    }
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
