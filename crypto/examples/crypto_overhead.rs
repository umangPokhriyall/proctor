//! `crypto_overhead` — the Phase 2 crypto-overhead microbench (phase2-spec.md §8).
//!
//! Measures, over the Phase 0 corpus segmented to ≈2 s, across two downscale profile
//! steps: (1) AEAD encrypt/decrypt throughput in GB/s with the AES-NI backend
//! confirmed; (2) per-segment decrypt+encrypt latency distributions (p50/p99/p99.9);
//! (3) crypto as a percentage of ffmpeg transcode time; (4) the anonymous-RAM
//! (`memfd`) end-to-end path vs a naive decrypt-to-disk path. Results are written as
//! CSVs to `bench/results/crypto/`; `METHODOLOGY.md` (committed alongside) cites them.
//!
//! Std only (no stats crate): percentiles are computed by sorting samples. Run with:
//!   cargo run --release --example crypto_overhead
//!
//! Honesty: the corpus is read and segmented to disk as test fixtures (plaintext
//! fixture generation, not the worker path). The *disk* arm of measurement (4)
//! deliberately writes plaintext to a file — that is the legacy behaviour, kept here
//! only as the measured baseline; it FAILS the §7 no-disk proof that the memfd arm
//! passes. The library never exposes that path.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crypto::{
    decrypt, decrypt_into_memfd, encrypt, transcode_no_disk, EncryptedSegment, Role, SecretKey,
    SegmentAad,
};
use proctor_core::{Codec, Container, JobId, SegmentId, TargetProfile};

/// Bytes to push through AEAD per (segment, op) so the GB/s figure is timer-stable.
const THROUGHPUT_TARGET_BYTES: usize = 256 * 1024 * 1024;
/// Samples per (profile, segment) for the latency distribution.
const LATENCY_SAMPLES: usize = 2000;
/// ffmpeg-bearing measurements are repeated and the median reported.
const FFMPEG_REPS: usize = 5;

/// A ≈2 s source segment: its plaintext, a unique key, and the sealed ciphertext.
struct Segment {
    name: String,
    plaintext: Vec<u8>,
    key: SecretKey,
    src_aad: SegmentAad,
    out_aad: SegmentAad,
    sealed: EncryptedSegment,
}

fn main() {
    if !ffmpeg_available() {
        eprintln!("SKIP crypto_overhead: ffmpeg not found — no results written, numbers never faked.");
        return;
    }

    let results_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bench/results/crypto");
    fs::create_dir_all(&results_dir).expect("create results dir");
    let work = std::env::temp_dir().join("proctor-crypto-overhead");
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create work dir");

    let segments = prepare_segments(&work);
    if segments.is_empty() {
        eprintln!("SKIP crypto_overhead: corpus unavailable — no results written.");
        return;
    }
    let profiles = profiles();

    println!("crypto_overhead: {} segments, {} profiles", segments.len(), profiles.len());
    report_aes_backend();

    aead_throughput(&segments, &results_dir);
    let outputs = transcode_outputs(&segments, &profiles);
    latency_distribution(&segments, &profiles, &outputs, &results_dir);
    crypto_pct_of_transcode(&segments, &profiles, &outputs, &results_dir, &work);
    memfd_vs_disk(&segments, &profiles, &results_dir, &work);

    let _ = fs::remove_dir_all(&work);
    println!("crypto_overhead: wrote CSVs to {}", results_dir.display());
}

// ----------------------------------------------------------------------------
// Setup
// ----------------------------------------------------------------------------

fn prepare_segments(work: &Path) -> Vec<Segment> {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bench/corpus");
    let mut segs = Vec::new();
    let mut seg_id = 0u64;
    for clip in ["gradient", "detail", "motion"] {
        let src = corpus_dir.join(format!("{clip}.mp4"));
        if !src.exists() {
            continue;
        }
        // Split into ≈2 s GOP-aligned segments (copy, so cuts land on keyframes).
        let pattern = work.join(format!("{clip}_%03d.mp4"));
        let status = Command::new("ffmpeg")
            .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
            .arg(&src)
            .args(["-c", "copy", "-map", "0", "-f", "segment", "-segment_time", "2",
                "-reset_timestamps", "1"])
            .arg(&pattern)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn ffmpeg segment");
        if !status.success() {
            continue;
        }
        for idx in 0.. {
            let path = work.join(format!("{clip}_{idx:03}.mp4"));
            if !path.exists() {
                break;
            }
            let plaintext = fs::read(&path).expect("read segment");
            let key = SecretKey::generate().expect("mlock + csprng");
            let src_aad = SegmentAad { job: JobId(1), segment: SegmentId(seg_id), role: Role::Source };
            let out_aad = SegmentAad { role: Role::Output, ..src_aad };
            let sealed = encrypt(&plaintext, &key, &src_aad).expect("seal source");
            segs.push(Segment {
                name: format!("{clip}_{idx:03}"),
                plaintext,
                key,
                src_aad,
                out_aad,
                sealed,
            });
            seg_id += 1;
        }
    }
    segs
}

fn profiles() -> Vec<(&'static str, TargetProfile)> {
    // The committed seed corpus is 320x240; these are two representative downscale
    // steps from it. On-host full runs raise SIZE/DUR via corpus/generate.sh and the
    // same bench applies unchanged.
    vec![
        ("240x180@400k", TargetProfile {
            codec: Codec::H264, width: 240, height: 180, bitrate_kbps: 400, container: Container::Mp4,
        }),
        ("160x120@200k", TargetProfile {
            codec: Codec::H264, width: 160, height: 120, bitrate_kbps: 200, container: Container::Mp4,
        }),
    ]
}

// ----------------------------------------------------------------------------
// (1) AEAD throughput
// ----------------------------------------------------------------------------

fn aead_throughput(segments: &[Segment], dir: &Path) {
    let mut csv = String::from("segment,bytes,op,iters,seconds,gbps,backend\n");
    let backend = "aesni-runtime-detected";
    let (mut enc_bytes, mut enc_secs, mut dec_bytes, mut dec_secs) = (0u128, 0f64, 0u128, 0f64);

    for s in segments {
        let bytes = s.plaintext.len();
        let iters = (THROUGHPUT_TARGET_BYTES / bytes.max(1)).clamp(50, 20_000);

        // Encrypt throughput.
        let t0 = Instant::now();
        for _ in 0..iters {
            let e = encrypt(&s.plaintext, &s.key, &s.src_aad).expect("encrypt");
            std::hint::black_box(&e);
        }
        let secs = t0.elapsed().as_secs_f64();
        let total = (bytes as u128) * (iters as u128);
        writeln!(csv, "{},{},encrypt,{},{:.6},{:.4},{}", s.name, bytes, iters, secs,
            gbps(total, secs), backend).unwrap();
        enc_bytes += total;
        enc_secs += secs;

        // Decrypt throughput (on the sealed source).
        let t0 = Instant::now();
        for _ in 0..iters {
            let p = decrypt(&s.sealed, &s.key, &s.src_aad).expect("decrypt");
            std::hint::black_box(p.as_bytes().len());
        }
        let secs = t0.elapsed().as_secs_f64();
        writeln!(csv, "{},{},decrypt,{},{:.6},{:.4},{}", s.name, bytes, iters, secs,
            gbps(total, secs), backend).unwrap();
        dec_bytes += total;
        dec_secs += secs;
    }

    writeln!(csv, "ALL,{},encrypt,-,{:.6},{:.4},{}", enc_bytes, enc_secs,
        gbps(enc_bytes, enc_secs), backend).unwrap();
    writeln!(csv, "ALL,{},decrypt,-,{:.6},{:.4},{}", dec_bytes, dec_secs,
        gbps(dec_bytes, dec_secs), backend).unwrap();

    fs::write(dir.join("aead_throughput.csv"), csv).expect("write throughput csv");
    println!(
        "  AEAD throughput: encrypt {:.2} GB/s, decrypt {:.2} GB/s (aggregate)",
        gbps(enc_bytes, enc_secs),
        gbps(dec_bytes, dec_secs)
    );
}

fn gbps(bytes: u128, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    (bytes as f64) / 1e9 / secs
}

// ----------------------------------------------------------------------------
// Transcode each (segment, profile) once to capture the plaintext output bytes.
// ----------------------------------------------------------------------------

/// `outputs[profile_idx][seg_idx]` = transcoded plaintext for that pair.
fn transcode_outputs(segments: &[Segment], profiles: &[(&str, TargetProfile)]) -> Vec<Vec<Vec<u8>>> {
    profiles
        .iter()
        .map(|(_, profile)| {
            segments
                .iter()
                .map(|s| {
                    let input =
                        decrypt_into_memfd(&s.sealed, &s.key, &s.src_aad, "bench-src").expect("decrypt");
                    let mut output = transcode_no_disk(&input, profile).expect("transcode");
                    let plain = output.read_to_secret_buf().expect("read output").as_bytes().to_vec();
                    input.zeroize_and_close();
                    output.zeroize_and_close();
                    plain
                })
                .collect()
        })
        .collect()
}

// ----------------------------------------------------------------------------
// (2) Per-segment decrypt+encrypt latency distribution
// ----------------------------------------------------------------------------

fn latency_distribution(
    segments: &[Segment],
    profiles: &[(&str, TargetProfile)],
    outputs: &[Vec<Vec<u8>>],
    dir: &Path,
) {
    let mut raw = String::from("profile,segment,sample,decrypt_us,encrypt_us,total_us\n");
    let mut summary =
        String::from("profile,segment,n,p50_us,p99_us,p999_us,min_us,max_us,mean_us\n");

    for (p_idx, (p_name, _)) in profiles.iter().enumerate() {
        let mut profile_totals: Vec<u128> = Vec::new();
        for (s_idx, s) in segments.iter().enumerate() {
            let out_plain = &outputs[p_idx][s_idx];
            let mut totals: Vec<u128> = Vec::with_capacity(LATENCY_SAMPLES);
            for i in 0..LATENCY_SAMPLES {
                let t0 = Instant::now();
                let p = decrypt(&s.sealed, &s.key, &s.src_aad).expect("decrypt");
                let t1 = Instant::now();
                let e = encrypt(out_plain, &s.key, &s.out_aad).expect("encrypt");
                let t2 = Instant::now();
                std::hint::black_box((p.as_bytes().len(), &e));
                let d = t1.duration_since(t0).as_nanos();
                let en = t2.duration_since(t1).as_nanos();
                let total = t2.duration_since(t0).as_nanos();
                writeln!(raw, "{p_name},{},{i},{:.3},{:.3},{:.3}", s.name,
                    us(d), us(en), us(total)).unwrap();
                totals.push(total);
            }
            write_summary_row(&mut summary, p_name, &s.name, &mut totals);
            profile_totals.extend_from_slice(&totals);
        }
        write_summary_row(&mut summary, p_name, "ALL", &mut profile_totals);
    }

    fs::write(dir.join("crypto_latency_raw.csv"), raw).expect("write latency raw");
    fs::write(dir.join("crypto_latency_summary.csv"), summary).expect("write latency summary");
    println!("  latency: wrote raw + summary ({} samples/group)", LATENCY_SAMPLES);
}

fn write_summary_row(out: &mut String, profile: &str, segment: &str, samples: &mut [u128]) {
    samples.sort_unstable();
    let n = samples.len();
    let mean = if n == 0 { 0.0 } else { samples.iter().sum::<u128>() as f64 / n as f64 };
    writeln!(out, "{profile},{segment},{n},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
        us(percentile(samples, 0.50)),
        us(percentile(samples, 0.99)),
        us(percentile(samples, 0.999)),
        us(*samples.first().unwrap_or(&0)),
        us(*samples.last().unwrap_or(&0)),
        mean / 1000.0)
        .unwrap();
}

/// Nearest-rank percentile over already-sorted nanosecond samples.
fn percentile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (q * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn us(nanos: u128) -> f64 {
    nanos as f64 / 1000.0
}

// ----------------------------------------------------------------------------
// (3) Crypto as a percentage of transcode time
// ----------------------------------------------------------------------------

fn crypto_pct_of_transcode(
    segments: &[Segment],
    profiles: &[(&str, TargetProfile)],
    outputs: &[Vec<Vec<u8>>],
    dir: &Path,
    _work: &Path,
) {
    let mut csv =
        String::from("profile,segment,transcode_ms_median,crypto_us_p50,crypto_pct\n");

    for (p_idx, (p_name, profile)) in profiles.iter().enumerate() {
        for (s_idx, s) in segments.iter().enumerate() {
            // Transcode wall time (real ffmpeg over memfds), median of FFMPEG_REPS.
            let mut t_ns: Vec<u128> = Vec::with_capacity(FFMPEG_REPS);
            for _ in 0..FFMPEG_REPS {
                let input =
                    decrypt_into_memfd(&s.sealed, &s.key, &s.src_aad, "bench-src").expect("decrypt");
                let t0 = Instant::now();
                let output = transcode_no_disk(&input, profile).expect("transcode");
                t_ns.push(t0.elapsed().as_nanos());
                output.zeroize_and_close();
                input.zeroize_and_close();
            }
            t_ns.sort_unstable();
            let transcode_ns = percentile(&t_ns, 0.50);

            // Crypto wall time (decrypt + encrypt), p50 of FFMPEG-independent samples.
            let out_plain = &outputs[p_idx][s_idx];
            let mut c_ns: Vec<u128> = Vec::with_capacity(256);
            for _ in 0..256 {
                let t0 = Instant::now();
                let p = decrypt(&s.sealed, &s.key, &s.src_aad).expect("decrypt");
                let e = encrypt(out_plain, &s.key, &s.out_aad).expect("encrypt");
                std::hint::black_box((p.as_bytes().len(), &e));
                c_ns.push(t0.elapsed().as_nanos());
            }
            c_ns.sort_unstable();
            let crypto_ns = percentile(&c_ns, 0.50);

            let pct = if transcode_ns == 0 {
                0.0
            } else {
                (crypto_ns as f64 / transcode_ns as f64) * 100.0
            };
            writeln!(csv, "{p_name},{},{:.3},{:.3},{:.4}", s.name,
                transcode_ns as f64 / 1e6, us(crypto_ns), pct).unwrap();
        }
    }

    fs::write(dir.join("crypto_pct_transcode.csv"), csv).expect("write pct csv");
    println!("  crypto-as-%-of-transcode: wrote per-segment ratios");
}

// ----------------------------------------------------------------------------
// (4) memfd (anonymous RAM) vs naive disk path, end to end
// ----------------------------------------------------------------------------

fn memfd_vs_disk(
    segments: &[Segment],
    profiles: &[(&str, TargetProfile)],
    dir: &Path,
    work: &Path,
) {
    let mut csv = String::from(
        "profile,segment,memfd_ms_median,disk_ms_median,delta_ms,memfd_passes_no_disk,disk_passes_no_disk\n",
    );

    for (p_name, profile) in profiles {
        for s in segments {
            let mut memfd_ns: Vec<u128> = Vec::with_capacity(FFMPEG_REPS);
            let mut disk_ns: Vec<u128> = Vec::with_capacity(FFMPEG_REPS);
            for _ in 0..FFMPEG_REPS {
                memfd_ns.push(time_memfd_cycle(s, profile));
                disk_ns.push(time_disk_cycle(s, profile, work));
            }
            memfd_ns.sort_unstable();
            disk_ns.sort_unstable();
            let m = percentile(&memfd_ns, 0.50);
            let d = percentile(&disk_ns, 0.50);
            writeln!(csv, "{p_name},{},{:.3},{:.3},{:.3},yes,no", s.name,
                m as f64 / 1e6, d as f64 / 1e6, (d as f64 - m as f64) / 1e6).unwrap();
        }
    }

    fs::write(dir.join("memfd_vs_disk.csv"), csv).expect("write memfd_vs_disk csv");
    println!("  memfd-vs-disk: wrote per-segment end-to-end comparison");
}

/// decrypt → transcode → encrypt, plaintext only in anonymous RAM. Returns ns.
fn time_memfd_cycle(s: &Segment, profile: &TargetProfile) -> u128 {
    let t0 = Instant::now();
    let input = decrypt_into_memfd(&s.sealed, &s.key, &s.src_aad, "bench-src").expect("decrypt");
    let mut output = transcode_no_disk(&input, profile).expect("transcode");
    let out_plain = output.read_to_secret_buf().expect("read output");
    let resealed = encrypt(out_plain.as_bytes(), &s.key, &s.out_aad).expect("re-encrypt");
    let elapsed = t0.elapsed().as_nanos();
    std::hint::black_box(resealed.to_bytes().len());
    output.zeroize_and_close();
    input.zeroize_and_close();
    elapsed
}

/// decrypt → write plaintext to disk → ffmpeg from file → encrypt. The legacy
/// behaviour: plaintext lands on a disk-backed file. Measured as the baseline only;
/// it FAILS the §7 no-disk proof. Returns ns.
fn time_disk_cycle(s: &Segment, profile: &TargetProfile, work: &Path) -> u128 {
    let in_path = work.join("disk_in.bin");
    let out_path = work.join("disk_out.mp4");
    let t0 = Instant::now();
    let plain = decrypt(&s.sealed, &s.key, &s.src_aad).expect("decrypt");
    fs::write(&in_path, plain.as_bytes()).expect("write plaintext to disk"); // legacy: on disk
    let status = Command::new("ffmpeg")
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
        .arg(&in_path)
        .args(ffmpeg_profile_args(profile))
        .args(["-an", "-f", "mp4"])
        .arg(&out_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn ffmpeg (disk)");
    assert!(status.success(), "disk-path ffmpeg failed");
    let out_plain = fs::read(&out_path).expect("read transcoded plaintext from disk");
    let resealed = encrypt(&out_plain, &s.key, &s.out_aad).expect("re-encrypt");
    let elapsed = t0.elapsed().as_nanos();
    std::hint::black_box(resealed.to_bytes().len());
    let _ = fs::remove_file(&in_path);
    let _ = fs::remove_file(&out_path);
    elapsed
}

/// The codec/scale/bitrate args, identical to `transcode_no_disk`'s mapping, so the
/// disk and memfd arms differ only in where plaintext lives.
fn ffmpeg_profile_args(profile: &TargetProfile) -> Vec<String> {
    let codec = match profile.codec {
        Codec::H264 => "libx264",
        Codec::H265 => "libx265",
        Codec::Av1 => "libsvtav1",
        Codec::Vp9 => "libvpx-vp9",
    };
    vec![
        "-c:v".to_string(),
        codec.to_string(),
        "-vf".to_string(),
        format!("scale={}:{}", profile.width, profile.height),
        "-b:v".to_string(),
        format!("{}k", profile.bitrate_kbps),
    ]
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn ffmpeg_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn report_aes_backend() {
    let (aes, pclmul) = aes_features();
    println!(
        "  AES-NI: aes={aes} pclmulqdq={pclmul} (aes-gcm 0.10 runtime-detects AES-NI; \
         forced-software comparison not run — see METHODOLOGY.md)"
    );
}

#[cfg(target_arch = "x86_64")]
fn aes_features() -> (bool, bool) {
    (
        std::is_x86_feature_detected!("aes"),
        std::is_x86_feature_detected!("pclmulqdq"),
    )
}

#[cfg(not(target_arch = "x86_64"))]
fn aes_features() -> (bool, bool) {
    (false, false)
}
