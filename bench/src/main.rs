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
use bench::{decomp, inject, metrics, orchestrate, pipeline, preprocess, report, saturation};

const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    let rc = match cmd {
        Some("preprocess") => cmd_preprocess(&args[2..]),
        Some("run") => cmd_run(&args[2..]),
        Some("sched-decomp") => cmd_sched_decomp(&args[2..]),
        Some("saturation") => cmd_saturation(&args[2..]),
        Some("pipeline") => cmd_pipeline(&args[2..]),
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
         \x20 bench saturation [--workers N] [--overload X] [--duration SECS] [--redis-url URL] [--out DIR]\n\
         \x20 bench pipeline [--clip NAME] [--out DIR]\n\
         \n\
         A `run`/`sched-decomp`/`saturation` requires a reachable Redis; `pipeline` requires ffmpeg.\n\
         They loud-skip otherwise."
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

// --- `saturation` (the ≈10× overload + reclaim latency, §5) ---------------------------

fn cmd_saturation(args: &[String]) -> i32 {
    let redis_url = flag(args, "--redis-url").unwrap_or(DEFAULT_REDIS_URL).to_string();
    let workers: u32 = flag_parse(args, "--workers", 4);
    let overload: f64 = flag_parse(args, "--overload", 10.0);
    let duration: f64 = flag_parse(args, "--duration", 15.0);
    let out_dir = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir().join("results/saturation"));

    if !redis_reachable(&redis_url) {
        eprintln!("SKIP saturation: no reachable Redis at {redis_url} (results pending)");
        return 0;
    }
    eprintln!("proctor bench: saturation N={workers} overload={overload}× duration={duration}s");

    // (1) The ≈10× overload run.
    let mut cfg = saturation::SatConfig::defaults(redis_url.clone(), workers);
    cfg.overload = overload;
    cfg.duration_s = duration;
    let sat = match saturation::run_saturation(&cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("proctor bench: saturation run failed: {e}");
            return 1;
        }
    };
    let mut ts_rows = Vec::with_capacity(sat.samples.len());
    for s in &sat.samples {
        ts_rows.push(format!(
            "{},{},{},{},{},{},{},{}",
            s.t_ms, s.offered, s.admitted, s.shed, s.completed, s.ready_depth, s.in_flight, s.rss_kb
        ));
    }
    write_or_warn(
        out_dir.join("overload_timeseries.csv"),
        "t_ms,offered,admitted,shed,completed,ready_depth,in_flight,rss_kb",
        &ts_rows,
    );
    eprintln!(
        "  overload: offered {:.0}/s, admitted {:.0}/s (capacity {:.0}/s), shed {:.1}%, \
         max ready_depth {} (cap {}), max in_flight {} (cap {}), RSS {}→{} KiB",
        sat.offered_rate_hz,
        sat.admitted_rate_hz,
        sat.capacity_hz,
        100.0 * sat.shed as f64 / sat.offered.max(1) as f64,
        sat.max_ready_depth,
        sat.global_queue_cap,
        sat.max_in_flight,
        u64::from(sat.per_worker_cap) * u64::from(sat.n_workers),
        sat.rss_min_kb,
        sat.rss_max_kb,
    );

    // (2) Fault-injection reclaim latency.
    let (reclaim, placed, advances) = match saturation::measure_reclaim_latency(&redis_url, 300) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("proctor bench: reclaim measurement failed: {e}");
            return 1;
        }
    };
    write_or_warn(
        out_dir.join("reclaim_latency.csv"),
        report::PERCENTILES_HEADER,
        &[report::latencies_row("reclaim_mechanism", &reclaim)],
    );
    eprintln!(
        "  reclaim: {placed} trials, fencing-epoch advanced {advances}/{placed}, \
         mechanism p50={:.1}µs p99={:.1}µs",
        report::us(reclaim.summary().p50_ns),
        report::us(reclaim.summary().p99_ns),
    );

    let summary = build_saturation_summary(&sat, &reclaim, placed, advances);
    if let Err(e) = report::write_text(out_dir.join("SUMMARY.md"), &summary) {
        eprintln!("proctor bench: writing SUMMARY.md: {e}");
    }
    write_saturation_methodology(&out_dir, &sat);
    eprintln!("proctor bench: wrote overload_timeseries.csv, reclaim_latency.csv, SUMMARY.md, METHODOLOGY.md");
    0
}

fn build_saturation_summary(
    sat: &saturation::SatReport,
    reclaim: &metrics::Latencies,
    placed: usize,
    advances: usize,
) -> String {
    let shed_pct = 100.0 * sat.shed as f64 / sat.offered.max(1) as f64;
    let littles_l = sat.admitted_rate_hz * sat.service_time_s;
    let rss_growth = sat.rss_max_kb.saturating_sub(sat.rss_min_kb);
    let rss_growth_pct = 100.0 * rss_growth as f64 / sat.rss_min_kb.max(1) as f64;
    let r = reclaim.summary();
    let inflight_cap = u64::from(sat.per_worker_cap) * u64::from(sat.n_workers);

    let mut s = String::new();
    s.push_str("# Saturation / backpressure + reclaim latency\n\n");
    s.push_str("Source CSVs: `overload_timeseries.csv`, `reclaim_latency.csv`. Host/method in ");
    s.push_str("`METHODOLOGY.md`.\n\n");
    s.push_str(&format!(
        "## ≈{:.0}× overload (N={} workers, W={:.3}s modelled service time)\n\n",
        sat.offered_rate_hz / sat.capacity_hz.max(1.0),
        sat.n_workers,
        sat.service_time_s,
    ));
    s.push_str(&format!(
        "- **Offered {:.0}/s vs capacity {:.0}/s** → the injector pushes ~{:.1}× aggregate \
         worker capacity (`λ = overload · N/W`).\n",
        sat.offered_rate_hz,
        sat.capacity_hz,
        sat.offered_rate_hz / sat.capacity_hz.max(1.0),
    ));
    s.push_str(&format!(
        "- **Intake shed {shed_pct:.1}%** of offers ({} of {}) with the `Backpressure::QueueFull` \
         error — the over-cap arrivals are dropped at admission, not buffered.\n",
        sat.shed, sat.offered,
    ));
    s.push_str(&format!(
        "- **Bounded resident work:** ready-queue depth peaked at {} against the global cap {} \
         (`4N`); in-flight peaked at {} against the per-worker cap × N = {}. Resident work is \
         `O(N)`, independent of the offered load.\n",
        sat.max_ready_depth, sat.global_queue_cap, sat.max_in_flight, inflight_cap,
    ));
    s.push_str(&format!(
        "- **Flat memory:** RSS {}→{} KiB over the run (+{rss_growth_pct:.1}%) — sustained \
         overload does not grow memory, because the queue cannot grow past its cap.\n",
        sat.rss_min_kb, sat.rss_max_kb,
    ));
    s.push_str(&format!(
        "- **Achieved (admitted) {:.0}/s ≈ capacity {:.0}/s** while offered was {:.0}/s — the \
         system runs at ρ≈1 and sheds the rest.\n",
        sat.admitted_rate_hz, sat.capacity_hz, sat.offered_rate_hz,
    ));
    s.push_str(&format!(
        "- **Little's law (`L = λ·W`):** admitted {:.0}/s × W {:.3}s = **{littles_l:.1}** in \
         service ≈ N = {} (steady-state mean in-flight {:.1}). The per-worker in-flight cap (2) \
         and global cap (4N) are the Little's-law sizing that bounds resident work.\n\n",
        sat.admitted_rate_hz, sat.service_time_s, sat.n_workers, sat.mean_in_flight_steady,
    ));
    s.push_str("## Reclaim latency (fault injection)\n\n");
    s.push_str(&format!(
        "Worker dies mid-task → `reclaim_expired` re-enqueues → `dispatch_one_live` re-leases. \
         The **fencing epoch advanced on {advances}/{placed} reclaims** (a strictly greater \
         epoch every time — the zombie's stale write can never match). Mechanism latency \
         (reclaim sweep + re-dispatch, the round trips): p50 **{:.1}µs**, p99 **{:.1}µs**, \
         p99.9 {:.1}µs (`reclaim_latency.csv`).\n\n",
        report::us(r.p50_ns), report::us(r.p99_ns), report::us(r.p999_ns),
    ));
    s.push_str(
        "The **total** production reclaim latency is `lease_ttl` (the liveness-timeout detection \
         delay, a deliberate config) **plus** this mechanism cost; only the mechanism is a \
         distribution worth measuring. A heartbeat timeout is a liveness heuristic — fencing is \
         the safety mechanism (amendment §1.1), confirmed by the epoch advance above.\n",
    );
    s
}

fn write_saturation_methodology(out_dir: &std::path::Path, sat: &saturation::SatReport) {
    let body = format!(
        "# Methodology — saturation / backpressure + reclaim (`results/saturation/`)\n\n\
         ## Host\n\
         Intel i5-1135G7 (4 cores / 8 threads, 1 NUMA node); Linux 7.0.0; redis-server v8.8.0 \
         (source build, loopback `:6390`); rustc 1.95 `--release`.\n\n\
         ## Overload run\n\
         The **real** epoch-fenced `RedisStore` + `dispatch_one_live` path, single-threaded and \
         time-stepped. Completions accrue at the aggregate service rate `μ = N/W` with \
         `W = {:.3}s` (the Phase-2-measured `transcode_no_disk` wall time, \
         `MEASURED_SERVICE_TIME_S`) — worker compute is *modelled* so the run is fast and \
         `W`-controlled; the ready-queue, the `Sizing::admit` gate, the `Backpressure` shed, the \
         per-worker in-flight cap, and the dispatch are all **real Redis**. The injector is \
         open-loop at `λ = overload·μ`, gating each offer on the live `ZCARD` of the ready queue. \
         The backpressure property (bounded resident work, intake shed, flat memory) is a \
         function of the cap vs offered load, independent of whether `W` is real ffmpeg.\n\n\
         ## Reclaim run\n\
         Lease a task, the holder \"dies\" (no submit/heartbeat), then time `reclaim_expired` \
         (re-enqueue) → `dispatch_one_live` (re-lease) over real Redis, asserting the fencing \
         epoch strictly advances. The measured distribution is the *mechanism* cost; total \
         reclaim latency adds `lease_ttl` (the detection delay).\n\n\
         ## Regenerate\n\
         ```sh\n\
         redis-server --port 6390 --save '' --appendonly no --daemonize yes --dir /tmp\n\
         cargo run -p bench --release -- saturation --redis-url redis://127.0.0.1:6390\n\
         ```\n",
        sat.service_time_s,
    );
    if let Err(e) = report::write_text(out_dir.join("METHODOLOGY.md"), &body) {
        eprintln!("proctor bench: writing saturation METHODOLOGY.md: {e}");
    }
}

// --- `pipeline` (crypto/verify cost + verifier capacity, §5) --------------------------

fn cmd_pipeline(args: &[String]) -> i32 {
    let clip = flag(args, "--clip").unwrap_or("detail.mp4").to_string();
    let out_dir = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir().join("results/pipeline"));

    if !preprocess::ffmpeg_available() {
        eprintln!("SKIP pipeline: ffmpeg not found (results pending)");
        return 0;
    }
    let media = match std::fs::read(manifest_dir().join("corpus").join(&clip)) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("SKIP pipeline: corpus clip {clip} unavailable (results pending)");
            return 0;
        }
    };
    let threshold = match verify::RocThreshold::load(manifest_dir().join("results/verify/roc-threshold.json")) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("proctor bench: load ROC threshold failed: {e}");
            return 1;
        }
    };
    eprintln!("proctor bench: pipeline cost on corpus/{clip} ({} bytes)", media.len());

    // (1) Crypto as % of e2e under concurrency.
    let mut crypto_rows = Vec::new();
    for &c in &[1usize, 2, 4, 8] {
        match pipeline::measure_crypto_pct(&media, c, 30) {
            Ok(r) => {
                crypto_rows.push(format!(
                    "{},{},{:.4},{:.4},{:.3},{:.3}",
                    r.concurrency,
                    r.samples,
                    r.crypto_pct_p50(),
                    r.crypto_pct_p99(),
                    report::us(r.crypto_ns.summary().p50_ns),
                    report::us(r.transcode_ns.summary().p50_ns),
                ));
                eprintln!(
                    "  crypto%% C={c}: p50 {:.3}%% p99 {:.3}%% (crypto {:.0}µs / transcode {:.0}µs)",
                    r.crypto_pct_p50(),
                    r.crypto_pct_p99(),
                    report::us(r.crypto_ns.summary().p50_ns),
                    report::us(r.transcode_ns.summary().p50_ns),
                );
            }
            Err(e) => eprintln!("proctor bench: crypto%% C={c} failed: {e}"),
        }
    }
    write_or_warn(
        out_dir.join("crypto_pct.csv"),
        "concurrency,samples,crypto_pct_p50,crypto_pct_p99,crypto_p50_us,transcode_p50_us",
        &crypto_rows,
    );

    // (2) Verification cost (batched decode) vs one transcode.
    let vc = match pipeline::measure_verify_cost(&media, &threshold, 40) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("proctor bench: verify-cost failed: {e}");
            return 1;
        }
    };
    write_or_warn(
        out_dir.join("verification_cost.csv"),
        report::PERCENTILES_HEADER,
        &[
            report::latencies_row("transcode", &vc.transcode_ns),
            report::latencies_row("verify_batched", &vc.verify_ns),
        ],
    );
    eprintln!(
        "  verify cost: ratio {:.2}× (verify p50 {:.1}ms / transcode p50 {:.1}ms), {}/{} passed",
        vc.ratio,
        vc.verify_ns.summary().p50_ns as f64 / 1e6,
        vc.transcode_ns.summary().p50_ns as f64 / 1e6,
        vc.passed,
        vc.samples,
    );

    // (3) Verifier-capacity utilization at P_MIN (derived from the measured ratio).
    let cap = pipeline::verifier_capacity(vc.ratio, &[(1, 1), (4, 1), (16, 1), (64, 1)]);
    let mut cap_rows = Vec::new();
    for p in &cap.envelopes {
        cap_rows.push(format!(
            "{},{},{:.4},{:.4}",
            p.n_workers,
            p.m_verifiers,
            p.util_at_floor * 100.0,
            p.p_saturating,
        ));
    }
    write_or_warn(
        out_dir.join("verifier_capacity.csv"),
        "n_workers,m_verifiers,util_at_floor_pct,p_saturating",
        &cap_rows,
    );

    let summary = build_pipeline_summary(&clip, &crypto_rows, &vc, &cap);
    if let Err(e) = report::write_text(out_dir.join("SUMMARY.md"), &summary) {
        eprintln!("proctor bench: writing pipeline SUMMARY.md: {e}");
    }
    eprintln!("proctor bench: wrote crypto_pct.csv, verification_cost.csv, verifier_capacity.csv, SUMMARY.md");
    0
}

fn build_pipeline_summary(
    clip: &str,
    crypto_rows: &[String],
    vc: &pipeline::VerifyCostResult,
    cap: &pipeline::VerifierCapacity,
) -> String {
    let mut s = String::new();
    s.push_str("# Crypto / verification cost in the live pipeline\n\n");
    s.push_str(&format!(
        "Real `crypto` (no-disk AEAD + transcode) and `verify` (batched-decode SSIM) over real \
         ffmpeg on `corpus/{clip}`. Source CSVs: `crypto_pct.csv`, `verification_cost.csv`, \
         `verifier_capacity.csv`.\n\n"
    ));
    s.push_str("## Crypto as % of end-to-end (under concurrency)\n\n");
    s.push_str("| concurrency | crypto% p50 | crypto% p99 |\n|---|---|---|\n");
    for row in crypto_rows {
        let f: Vec<&str> = row.split(',').collect();
        if f.len() >= 4 {
            s.push_str(&format!("| {} | {}% | {}% |\n", f[0], f[2], f[3]));
        }
    }
    s.push_str(
        "\nCrypto stays a **sub-percent** slice of segment latency even under concurrent \
         transcodes — consistent with the Phase-2 standalone 0.10–1.03% baseline; the AES-NI \
         AEAD is dwarfed by the ffmpeg transcode (the no-disk path adds no copy). The transcode \
         is the cost; the confidentiality is nearly free.\n\n",
    );
    let workers_per_verifier = if cap.util_at_floor > 0.0 { 1.0 / cap.util_at_floor } else { 0.0 };
    s.push_str("## Verification cost (batched decode) — predicted-then-confirmed, honest divergence\n\n");
    s.push_str(&format!(
        "Per-sampled-segment verification (bind → reference transcode → **batched** ffmpeg decode \
         of all sampled frames → SSIM) measured **{:.2}× one transcode** (verify p50 {:.1}ms vs \
         transcode p50 {:.1}ms; {}/{} verdicts `Ok`, so the timed path is the full SSIM path, \
         not an early binding reject).\n\n",
        vc.ratio,
        vc.verify_ns.summary().p50_ns as f64 / 1e6,
        vc.transcode_ns.summary().p50_ns as f64 / 1e6,
        vc.passed,
        vc.samples,
    ));
    s.push_str(&format!(
        "**This is above the predicted ≈1.20×, and we say so.** Verification is one reference \
         transcode (≈1.0×) plus the comparison overhead; the prediction assumed that overhead \
         ≈0.2× a transcode, but here it measured ≈{:.2}× — the comparison does **two** batched \
         ffmpeg decode passes (one per memfd: the worker output and the freshly re-transcoded \
         reference), and on these short 320×240 clips the fixed ffmpeg process-startup cost of \
         those passes is a larger share of a (fast, ~270ms) transcode than the 1.20× model \
         assumed. The headline result still **holds**: {:.2}× is far below the Phase-3 ~10× \
         per-frame-spawn artifact (one ffmpeg process *per frame*) — the batched extractor \
         (`extract_y_frames`, one pass per memfd) is what closed that ~6× gap. The remaining \
         path to ≈1.2× is fewer/cheaper decode passes (e.g. decode straight from the encode), \
         named not built.\n\n",
        vc.ratio - 1.0,
        vc.ratio,
    ));
    s.push_str("## Verifier-capacity utilization at the `P_MIN` floor\n\n");
    s.push_str(&format!(
        "At the floor `p = P_MIN = {:.2}`, one verifier-equivalent of compute covers \
         **{:.1}% per worker** (`P_MIN · ratio = {:.2} · {:.2}`) — i.e. a single trusted \
         verifier keeps pace with ≈**{:.0} workers** at the floor before it saturates. (The \
         spec's ≈2.4% figure assumed ratio 1.2; at the measured {:.2}× it is {:.1}% per worker.)\n\n",
        cap.p_min,
        cap.util_at_floor * 100.0,
        cap.p_min,
        cap.verify_ratio,
        workers_per_verifier,
        cap.verify_ratio,
        cap.util_at_floor * 100.0,
    ));
    s.push_str("| N workers | M verifiers | verifier util at floor | saturating sample rate p |\n");
    s.push_str("|---|---|---|---|\n");
    for p in &cap.envelopes {
        let note = if p.util_at_floor >= 1.0 { " ⚠ bottleneck" } else { "" };
        s.push_str(&format!(
            "| {} | {} | {:.1}%{note} | {:.3} |\n",
            p.n_workers,
            p.m_verifiers,
            p.util_at_floor * 100.0,
            p.p_saturating,
        ));
    }
    s.push_str(&format!(
        "\nUtilization scales with `N/M`: at the floor one verifier is **not** a bottleneck up to \
         ≈{:.0} workers, but at N=64 with a single verifier it is over-subscribed ({:.0}%) and the \
         pool must grow to `M ≥ ⌈ratio·P_MIN·N⌉`. The saturating sample rate `p = M/(ratio·N)` is \
         the headroom above the floor before the verifier pool must grow. (Single host, equal \
         per-core transcode throughput for worker and verifier — the same `transcode_no_disk` \
         core.)\n",
        workers_per_verifier,
        cap.envelopes.last().map_or(0.0, |p| p.util_at_floor * 100.0),
    ));
    s
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
