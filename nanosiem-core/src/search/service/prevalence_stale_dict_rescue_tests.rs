// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5722: a prevalence dict cell cached with a `last_seen` that has since
//! fallen out of a 24h/7d window is masked to the 9999 sentinel until the cell
//! expires, even when the artifact came back. A plain `| prevalence
//! enrich=true` page whose rows prove the artifact was seen inside the window
//! re-checks it against the real-time summary instead of showing no
//! prevalence until the next dictionary refresh.

use super::prevalence_page_rescue::{
    apply_page_rescue, build_miss_probe_sql, collect_miss_keys, parse_probe_rows, row_time_us,
    window_start_us, MissKind, PREVALENCE_STALE_RECHECK_CAP,
};
use super::*;
use chrono::{Duration, Utc};
use serde_json::{json, Value};

const SHA: &str = "5f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5";
const EPOCH: &str = "1970-01-01 00:00:00.000000";

fn ch_time(hours_ago: i64) -> String {
    ch_time_min(hours_ago * 60)
}

fn ch_time_min(minutes_ago: i64) -> String {
    (Utc::now() - Duration::minutes(minutes_ago))
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string()
}

/// A pushdown row carrying only a hash: the dict projection (`_hp_*`) and the
/// row's own event `timestamp`. Domain and IP dimensions are true misses with
/// no key, as on a process-launch row.
fn hash_row(dict_host_count: u64, dict_last_seen: &str, event_timestamp: &str) -> Value {
    keyed_hash_row(SHA, dict_host_count, dict_last_seen, event_timestamp)
}

fn keyed_hash_row(hash: &str, dict_host_count: u64, dict_last_seen: &str, event_timestamp: &str) -> Value {
    let mut o = serde_json::Map::new();
    for p in ["_dp", "_ip"] {
        o.insert(format!("{p}_host_count"), json!(9999));
        o.insert(format!("{p}_first_seen"), json!(EPOCH));
        o.insert(format!("{p}_last_seen"), json!(EPOCH));
        o.insert(format!("{p}_total_occurrences"), json!(0));
    }
    o.insert("_hp_host_count".into(), json!(dict_host_count));
    o.insert("_hp_first_seen".into(), json!(dict_last_seen));
    o.insert("_hp_last_seen".into(), json!(dict_last_seen));
    o.insert("_hp_total_occurrences".into(), json!(4));
    o.insert("_domain_lookup".into(), Value::Null);
    o.insert("_ip_lookup".into(), Value::Null);
    o.insert("_hash_lookup".into(), json!(hash));
    o.insert("timestamp".into(), json!(event_timestamp));
    o.insert("is_rare".into(), json!(0));
    super::prevalence_page_rescue::redecorate(&mut o, 3);
    Value::Object(o)
}

/// The scenario: the dict cached the hash with a `last_seen` 3 days ago (1
/// host); it ran again an hour ago on a second host. At window=24h the cached
/// cell is masked, so the row decorates as "no prevalence". The row's own
/// event proves the cache stale: it is re-checked, and the summary's truth
/// (2 hosts, rare) lands on
/// the row exactly as `POST /api/prevalence/bulk` reports it.
#[test]
fn a_stale_cached_cell_the_row_disproves_is_rechecked_at_24h() {
    let window = window_start_us(PrevalenceTimeWindow::TwentyFourHours);
    let mut rows = vec![hash_row(9999, &ch_time(72), &ch_time(1))];
    assert_eq!(rows[0]["host_count"], Value::Null, "the masked cell decorates as no prevalence");

    let misses = collect_miss_keys(&rows, 100, window);
    assert_eq!(misses.keys, vec![(MissKind::Hash, SHA.to_string())]);

    let ls_us = (Utc::now() - Duration::hours(1)).timestamp_micros();
    let found = parse_probe_rows(vec![json!({
        "kind": "hash", "artifact": SHA, "host_count": "2",
        "fs_us": "1794830400000000", "ls_us": ls_us.to_string(), "total_occurrences": "5"
    })]);
    assert_eq!(apply_page_rescue(&mut rows, &found, 3), 1);
    assert_eq!(rows[0]["host_count"], json!(2));
    assert_eq!(rows[0]["is_rare"], json!(1));
    assert_eq!(rows[0]["prevalence_type"], json!("hash"));
    assert_eq!(rows[0]["total_occurrences"], json!(5));
}

/// The same holds at 7d, and for the ISO 8601 timestamps the executor may
/// hand back.
#[test]
fn seven_day_window_and_iso_timestamps() {
    let window = window_start_us(PrevalenceTimeWindow::SevenDays);
    let iso = (Utc::now() - Duration::hours(2)).to_rfc3339();
    let rows = vec![hash_row(9999, &ch_time(24 * 9), &iso)];
    assert_eq!(collect_miss_keys(&rows, 100, window).keys.len(), 1);
}

/// Nothing else changes:
/// - at 30d the dict mask never hides a cached cell, so only true misses count;
/// - a row whose event is OLDER than the cached `last_seen` proves nothing (a
///   common artifact is cached with the sentinel and its real `last_seen`);
/// - a row whose event is itself outside the window proves nothing;
/// - a dict hit is never a miss.
#[test]
fn only_a_row_that_disproves_the_cache_is_rechecked() {
    let day = window_start_us(PrevalenceTimeWindow::TwentyFourHours);
    assert_eq!(window_start_us(PrevalenceTimeWindow::ThirtyDays), None);

    let stale = vec![hash_row(9999, &ch_time(72), &ch_time(1))];
    assert!(collect_miss_keys(&stale, 100, None).keys.is_empty(), "30d: no stale rule");

    let common_in_window = vec![hash_row(9999, &ch_time(1), &ch_time(2))];
    assert!(collect_miss_keys(&common_in_window, 100, day).keys.is_empty());

    // Review P1: the steady state of every busy (>= 1000-host) artifact. The
    // final table and dict lag ingest, so the cached `last_seen` (15 min ago)
    // is OLDER than the row's event (1 min ago), but it is inside the window:
    // the mask did not hide it, so the sentinel means "common". Never probed.
    let common_live: Vec<Value> = (0..500)
        .map(|i| keyed_hash_row(&format!("{:064x}", i + 1), 9999, &ch_time_min(15), &ch_time_min(1)))
        .collect();
    for window in [day, window_start_us(PrevalenceTimeWindow::SevenDays)] {
        let misses = collect_miss_keys(&common_live, 50_000, window);
        assert!(misses.keys.is_empty() && misses.dropped == 0, "{misses:?}");
    }

    let old_event = vec![hash_row(9999, &ch_time(72), &ch_time(48))];
    assert!(collect_miss_keys(&old_event, 100, day).keys.is_empty());

    let hit = vec![hash_row(4, &ch_time(1), &ch_time(1))];
    assert!(collect_miss_keys(&hit, 100, day).keys.is_empty());

    let no_timestamp = {
        let mut r = hash_row(9999, &ch_time(72), &ch_time(1));
        r.as_object_mut().unwrap().remove("timestamp");
        vec![r]
    };
    assert!(collect_miss_keys(&no_timestamp, 100, day).keys.is_empty());

    // True misses are still misses with or without a window.
    let true_miss = vec![hash_row(9999, EPOCH, &ch_time(1))];
    assert_eq!(collect_miss_keys(&true_miss, 100, day).keys.len(), 1);
    assert_eq!(collect_miss_keys(&true_miss, 100, None).keys.len(), 1);
}

/// The residual (non-pushdown) path re-checks the dict in SQL: a key cached
/// with a `last_seen` the window masks is re-checked too, while a cached
/// common artifact seen inside the window still never reaches `uniqMerge`.
#[test]
fn residual_guard_admits_stale_cells() {
    let keys = vec![(MissKind::Hash, SHA.to_string())];
    let sql = build_miss_probe_sql(&keys, |k| k.summary_table().to_string(), "now() - INTERVAL 1 DAY", true)
        .expect("probe");
    assert!(
        sql.contains(
            "AND (dictGetOrDefault('nanosiem.hash_prevalence_dict', 'last_seen', file_hash, toDateTime64(0, 6)) = toDateTime64(0, 6) \
OR dictGetOrDefault('nanosiem.hash_prevalence_dict', 'last_seen', file_hash, toDateTime64(0, 6)) < now() - INTERVAL 1 DAY) GROUP BY"
        ),
        "{sql}"
    );
    assert!(!sql.contains("PREWHERE"), "{sql}");
}

#[test]
fn row_times_parse_in_every_form_clickhouse_returns() {
    assert_eq!(row_time_us(Some(&json!("1970-01-01 00:00:00.000000"))), Some(0));
    assert_eq!(row_time_us(Some(&json!("1970-01-01 00:00:01"))), Some(1_000_000));
    assert_eq!(row_time_us(Some(&json!("1970-01-01T00:00:01.5Z"))), Some(1_500_000));
    assert_eq!(row_time_us(Some(&json!(42))), Some(42));
    assert_eq!(row_time_us(Some(&json!("not a time"))), None);
    assert_eq!(row_time_us(None), None);
}

/// Review P1: stale re-checks are bounded inside the page's single probe; past
/// the cap they are counted as dropped (PARTIAL), and true misses still fit.
#[test]
fn stale_rechecks_have_their_own_cap() {
    let day = window_start_us(PrevalenceTimeWindow::TwentyFourHours);
    let mut rows: Vec<Value> = (0..PREVALENCE_STALE_RECHECK_CAP + 10)
        .map(|i| keyed_hash_row(&format!("{:064x}", i + 1), 9999, &ch_time(72), &ch_time_min(5)))
        .collect();
    rows.push(hash_row(9999, EPOCH, &ch_time_min(5)));
    let misses = collect_miss_keys(&rows, 50_000, day);
    assert_eq!(misses.keys.len(), PREVALENCE_STALE_RECHECK_CAP + 1);
    assert_eq!(misses.dropped, 10);
    assert!(misses.keys.contains(&(MissKind::Hash, SHA.to_string())), "the true miss is kept");
}

/// Review P2: once an artifact is rescued, EVERY sentinel row of it on the
/// page is decorated, including an older row (48h ago, outside the 24h
/// window) that could not itself prove the cache stale.
#[test]
fn a_rescued_artifact_decorates_every_row_of_it_on_the_page() {
    let day = window_start_us(PrevalenceTimeWindow::TwentyFourHours);
    let mut rows = vec![
        hash_row(9999, &ch_time(72), &ch_time(1)),
        hash_row(9999, &ch_time(72), &ch_time(48)),
    ];
    assert_eq!(collect_miss_keys(&rows, 100, day).keys, vec![(MissKind::Hash, SHA.to_string())]);
    let ls_us = (Utc::now() - Duration::hours(1)).timestamp_micros();
    let found = parse_probe_rows(vec![json!({
        "kind": "hash", "artifact": SHA, "host_count": "2",
        "fs_us": "1794830400000000", "ls_us": ls_us.to_string(), "total_occurrences": "5"
    })]);
    assert_eq!(apply_page_rescue(&mut rows, &found, 3), 2);
    for row in &rows {
        assert_eq!(row["host_count"], json!(2), "{row}");
        assert_eq!(row["is_rare"], json!(1));
    }
}
