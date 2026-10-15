//! Where do the bytes actually go, per column?
//!
//! The CPU profile showed the stage everyone assumed was expensive was 1% of the
//! cost. Storage deserves the same treatment before anyone tunes a codec: on a
//! wide OCSF schema a couple of columns usually dominate, and knowing which ones
//! decides whether the lever is encoding, clustering, or simply not storing it.
use std::fs::File;

use parquet::file::reader::{FileReader, SerializedFileReader};

#[test]
fn per_column_compressed_bytes() {
    let Ok(path) = std::env::var("NANO_REAL_PARQUET") else {
        eprintln!("set NANO_REAL_PARQUET; skipping");
        return;
    };
    let reader = SerializedFileReader::new(File::open(&path).expect("open")).expect("reader");
    let meta = reader.metadata();
    let rows: i64 = meta.file_metadata().num_rows();
    let mut totals: std::collections::BTreeMap<String, i64> = Default::default();
    for rg in 0..meta.num_row_groups() {
        let g = meta.row_group(rg);
        for c in 0..g.num_columns() {
            let col = g.column(c);
            *totals
                .entry(col.column_path().string())
                .or_default() += col.compressed_size();
        }
    }
    let grand: i64 = totals.values().sum();
    println!("\n  rows={rows}  row_groups={}  total={:.1} MB", meta.num_row_groups(), grand as f64 / 1e6);
    let mut v: Vec<_> = totals.into_iter().collect();
    v.sort_by_key(|(_, b)| -*b);
    println!("  {:<44}{:>10}{:>9}{:>8}", "column", "MB", "B/row", "share");
    let mut shown = 0i64;
    for (name, bytes) in v.iter().take(15) {
        println!(
            "  {:<44}{:>10.2}{:>9.1}{:>7.1}%",
            name,
            *bytes as f64 / 1e6,
            *bytes as f64 / rows as f64,
            100.0 * *bytes as f64 / grand as f64
        );
        shown += bytes;
    }
    println!(
        "  {:<44}{:>10.2}{:>9.1}{:>7.1}%",
        format!("... {} remaining columns", v.len().saturating_sub(15)),
        (grand - shown) as f64 / 1e6,
        (grand - shown) as f64 / rows as f64,
        100.0 * (grand - shown) as f64 / grand as f64
    );
}

/// Does clustering by class_uid ruin time-range pruning?
///
/// Time is the primary SIEM filter, and a reader skips a row group whose
/// min/max cannot match. Sorting by (class_uid, time) scatters time across
/// groups, so this measures how wide each group's time range becomes — the
/// query cost of the compression win.
#[test]
fn time_range_spread_per_row_group() {
    let Ok(path) = std::env::var("NANO_REAL_PARQUET") else {
        eprintln!("set NANO_REAL_PARQUET; skipping");
        return;
    };
    let reader = SerializedFileReader::new(File::open(&path).expect("open")).expect("reader");
    let meta = reader.metadata();
    let mut spans = Vec::new();
    let mut file_min = i64::MAX;
    let mut file_max = i64::MIN;
    for rg in 0..meta.num_row_groups() {
        let g = meta.row_group(rg);
        for c in 0..g.num_columns() {
            let col = g.column(c);
            if col.column_path().string() != "time" {
                continue;
            }
            if let Some(stats) = col.statistics() {
                // time is stored as an integer millisecond value
                if let (Some(lo), Some(hi)) = (stats.min_bytes_opt(), stats.max_bytes_opt()) {
                    if lo.len() == 8 && hi.len() == 8 {
                        let l = i64::from_le_bytes(lo.try_into().unwrap());
                        let h = i64::from_le_bytes(hi.try_into().unwrap());
                        file_min = file_min.min(l);
                        file_max = file_max.max(h);
                        spans.push((h - l) as f64 / 1000.0);
                    }
                }
            }
        }
    }
    if spans.is_empty() {
        println!("\n  no usable `time` statistics on row groups");
        return;
    }
    let file_span = (file_max - file_min) as f64 / 1000.0;
    let mean = spans.iter().sum::<f64>() / spans.len() as f64;
    println!("\n  row groups: {}", spans.len());
    println!("  file time span:        {:.0}s", file_span);
    println!("  mean row-group span:   {:.0}s", mean);
    println!(
        "  selectivity: a row group covers {:.0}% of the file's time range",
        100.0 * mean / file_span.max(1.0)
    );
    println!("  (100% = time pruning inside this file is useless; low = still selective)");
}
