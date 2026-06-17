//! `report` — CSV + percentile-summary writers for the committed result sets (phase6-spec.md
//! §2, §7). No plotting runtime dep: results are committed CSVs (SVGs, if any, are dev-only).
//! Every figure in a writeup cites its source CSV, so these writers are the single source of
//! the numbers.
//!
//! Latencies are emitted in **microseconds** (the dispatch/RTT regime), three decimals; the
//! column unit is in the header so a reader never guesses.

use std::fs;
use std::io;
use std::path::Path;

use crate::metrics::{Latencies, Percentiles};

/// Nanoseconds → microseconds.
#[must_use]
pub fn us(ns: u64) -> f64 {
    ns as f64 / 1_000.0
}

/// The percentile-CSV header (microseconds).
pub const PERCENTILES_HEADER: &str = "label,count,min_us,p50_us,p99_us,p999_us,max_us,mean_us";

/// One percentile row (microseconds) for `label`.
#[must_use]
pub fn percentiles_row(label: &str, p: &Percentiles) -> String {
    format!(
        "{label},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
        p.count,
        us(p.min_ns),
        us(p.p50_ns),
        us(p.p99_ns),
        us(p.p999_ns),
        us(p.max_ns),
        p.mean_ns / 1_000.0,
    )
}

/// One percentile row from a [`Latencies`] histogram.
#[must_use]
pub fn latencies_row(label: &str, lat: &Latencies) -> String {
    percentiles_row(label, &lat.summary())
}

/// Write a CSV: a `header` line followed by `rows` (creating parent dirs).
pub fn write_csv(path: impl AsRef<Path>, header: &str, rows: &[String]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut body = String::with_capacity(header.len() + rows.iter().map(|r| r.len() + 1).sum::<usize>() + 1);
    body.push_str(header);
    body.push('\n');
    for r in rows {
        body.push_str(r);
        body.push('\n');
    }
    fs::write(path, body)
}

/// Write a plain text file (creating parent dirs) — for SUMMARY / methodology notes.
pub fn write_text(path: impl AsRef<Path>, contents: &str) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_row_formats_microseconds() {
        let mut h = Latencies::new();
        for v in 1..=100u64 {
            h.record(v * 1_000); // 1µs .. 100µs
        }
        let row = latencies_row("ping", &h);
        assert!(row.starts_with("ping,100,"), "row: {row}");
        // Eight comma-separated fields: label + count + 6 stats.
        assert_eq!(row.split(',').count(), 8);
    }

    #[test]
    fn write_csv_round_trips() {
        let dir = std::env::temp_dir().join(format!("proctor-report-{}", std::process::id()));
        let path = dir.join("x.csv");
        write_csv(&path, PERCENTILES_HEADER, &["a,1,0.5,0.5,0.5,0.5,0.5,0.5".into()]).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with(PERCENTILES_HEADER));
        assert!(body.trim_end().ends_with("a,1,0.5,0.5,0.5,0.5,0.5,0.5"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
