// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5271: per-source volume list (pivt "available source types" and
//! briefing ingest volume) reads the live profile-aware rollup.

use super::*;
use chrono::TimeZone;

fn ts(h: u32, m: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 10, h, m, s).unwrap()
}

#[test]
fn rollup_sql_reads_the_active_profile_lane_and_floors_bounds() {
    let sql = build_source_volumes_range_sql(
        "nanosiem.logs_per_source_5m_v2",
        "ocsf",
        ts(10, 3, 7),
        ts(11, 4, 59),
        &BTreeSet::new(),
        50,
    );
    assert!(sql.contains("FROM nanosiem.logs_per_source_5m_v2"), "{sql}");
    assert!(sql.contains("schema_profile = 'ocsf'"), "{sql}");
    assert!(sql.contains("bucket_start >= '2026-11-10 10:00:00'"), "{sql}");
    assert!(sql.contains("bucket_start <= '2026-11-10 11:00:00'"), "{sql}");
    assert!(sql.contains("source_type != 'findings'"), "{sql}");
    assert!(sql.contains("source_type != ''"), "{sql}");
    assert!(sql.contains("LIMIT 50"), "{sql}");
    // Unrestricted readers carry no scope predicate.
    assert!(!sql.contains("scope_source_type"), "{sql}");
    // Never the dead v1 rollup.
    assert!(!sql.contains("logs_per_source_5m "), "{sql}");
}

#[test]
fn rollup_sql_scopes_restricted_readers_on_the_raw_scope_key() {
    let deny: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
    let sql = build_source_volumes_range_sql(
        "nanosiem.logs_per_source_5m_v2",
        "udm",
        ts(10, 0, 0),
        ts(11, 0, 0),
        &deny,
        20,
    );
    assert!(sql.contains("scope_source_type_complete = 1"), "{sql}");
    assert!(sql.contains("scope_source_type"), "{sql}");
    assert!(sql.contains("'audit'"), "{sql}");
}

#[test]
fn raw_fallback_counts_the_logs_table_with_scope_on_source_type() {
    let deny: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
    let sql = build_source_volumes_range_raw_sql(
        "nanosiem.ocsf_logs",
        ts(1, 0, 0),
        ts(2, 0, 0),
        &deny,
        50,
    );
    assert!(sql.contains("FROM nanosiem.ocsf_logs"), "{sql}");
    assert!(
        sql.contains("timestamp BETWEEN '2026-11-10 01:00:00' AND '2026-11-10 02:00:00'"),
        "{sql}"
    );
    assert!(sql.contains("count() AS events"), "{sql}");
    assert!(sql.contains("'audit'"), "{sql}");
    assert!(!sql.contains("PREWHERE"), "{sql}");
}

#[test]
fn rollup_is_used_while_the_window_end_is_retained() {
    let now = ts(12, 0, 0);
    assert!(rollup_covers_window_end(now, now));
    // A 7-day lookback that ends now still uses the rollup.
    assert!(rollup_covers_window_end(now - chrono::Duration::minutes(1), now));
    // A window that ended before retention cannot.
    assert!(!rollup_covers_window_end(
        now - chrono::Duration::hours(ROLLUP_RETENTION_HOURS + 1),
        now
    ));
}

#[test]
fn parse_source_volume_rows_keeps_order_and_string_counts() {
    let body = "{\"source_type\":\"windows_sysmon\",\"events\":\"605153\"}\n\
                {\"source_type\":\"apache_access\",\"events\":151346}\n\
                not json\n";
    let rows = parse_source_volume_rows(body);
    assert_eq!(
        rows,
        vec![
            ("windows_sysmon".to_string(), 605_153),
            ("apache_access".to_string(), 151_346),
        ]
    );
}
