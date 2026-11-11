// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the OCSF legacy-table drop (NAN-4918): the cluster path of
//! every statement, the per-id verdicts and the shard-coverage queries. The
//! live runs are `nanosiem-core/tests/ocsf_legacy_drop_clickhouse.rs`.

use super::*;

fn day(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

fn hour(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
}

fn check(legacy_rows: u64, missing_ids: u64, duplicate_ids: u64) -> LegacyDayCheck {
    LegacyDayCheck { day: day("2026-01-01"), legacy_rows, missing_ids, duplicate_ids }
}

#[test]
fn verdicts_are_per_id() {
    assert_eq!(check(10, 0, 0).status(), LegacyDayStatus::Match);
    assert_eq!(check(10, 10, 0).status(), LegacyDayStatus::Missing);
    assert_eq!(check(10, 1, 0).status(), LegacyDayStatus::Mismatch);
    assert_eq!(check(10, 0, 1).status(), LegacyDayStatus::Mismatch);
    // {A, B} vs {B, B}: equal counts, one missing and one duplicated id.
    assert_eq!(check(2, 1, 1).status(), LegacyDayStatus::Mismatch);
}

#[test]
fn plan_refuses_on_any_blocking_day_and_allows_an_empty_legacy_table() {
    let plan = |days: Vec<LegacyDayCheck>| OcsfLegacyDropPlan { cluster: None, days, drop_sql: String::new() };
    assert!(plan(vec![]).safe_to_drop());
    let ok = check(3, 0, 0);
    let missing = LegacyDayCheck { day: day("2026-01-02"), ..check(2, 2, 0) };
    assert!(plan(vec![ok.clone()]).safe_to_drop());
    let p = plan(vec![ok, missing.clone()]);
    assert!(!p.safe_to_drop());
    assert_eq!(p.blocking_days(), vec![&missing]);
    assert_eq!(p.legacy_rows(), 5);
}

#[test]
fn cloud_never_fans_out() {
    assert_eq!(fan_out_cluster(Some("default"), true), None);
    assert_eq!(fan_out_cluster(Some("nanosiem_cluster"), false), Some("nanosiem_cluster"));
    assert_eq!(fan_out_cluster(None, false), None);
}

const W: &str = "timestamp >= toDateTime64('2026-03-04 05:00:00', 3, 'UTC') \
                 AND timestamp < toDateTime64('2026-03-04 05:00:00', 3, 'UTC') + INTERVAL 1 HOUR";

#[test]
fn single_node_reads_the_local_tables() {
    assert_eq!(
        legacy_hour_counts_sql(None, "nanosiem"),
        "SELECT toString(toStartOfHour(timestamp, 'UTC')) AS hour, count() AS n FROM `nanosiem`.`ocsf_logs_legacy_v179` GROUP BY hour ORDER BY hour"
    );
    let h = hour("2026-03-04 05:00:00");
    assert_eq!(
        missing_ids_sql(None, "nanosiem", "ocsf_logs", h),
        format!("SELECT count() FROM `nanosiem`.`ocsf_logs_legacy_v179` WHERE {W} AND id NOT IN (SELECT id FROM `nanosiem`.`ocsf_logs` WHERE {W})")
    );
    assert_eq!(
        duplicate_ids_sql(None, "nanosiem", "ocsf_logs", h),
        format!(
            "SELECT count() FROM (SELECT id FROM `nanosiem`.`ocsf_logs` WHERE {W} AND id IN (SELECT id FROM `nanosiem`.`ocsf_logs_legacy_v179` WHERE {W}) \
             GROUP BY id HAVING count() > 1)"
        )
    );
    assert_eq!(
        drop_legacy_sql(None, "nanosiem", false),
        "DROP TABLE IF EXISTS nanosiem.ocsf_logs_legacy_v179 SYNC SETTINGS max_table_size_to_drop = 0"
    );
}

#[test]
fn cluster_proof_reads_every_shard_and_checks_ids_shard_locally() {
    let c = Some("nanosiem_cluster");
    let h = hour("2026-03-04 05:00:00");
    assert!(legacy_hour_counts_sql(c, "nanosiem")
        .contains("FROM cluster('nanosiem_cluster', 'nanosiem', 'ocsf_logs_legacy_v179') GROUP BY hour"));
    // Missing: each shard's legacy rows against that shard's own store.
    let missing = missing_ids_sql(c, "nanosiem", "ocsf_logs_local", h);
    assert!(missing.starts_with("SELECT count() FROM cluster('nanosiem_cluster', 'nanosiem', 'ocsf_logs_legacy_v179') WHERE"), "{missing}");
    assert!(missing.contains("id NOT IN (SELECT id FROM `nanosiem`.`ocsf_logs_local` WHERE"), "{missing}");
    // Duplicates: grouped across every shard.
    let dup = duplicate_ids_sql(c, "nanosiem", "ocsf_logs_local", h);
    assert!(dup.contains("SELECT id FROM cluster('nanosiem_cluster', 'nanosiem', 'ocsf_logs_local') WHERE"), "{dup}");
    assert!(dup.contains("id IN (SELECT id FROM `nanosiem`.`ocsf_logs_legacy_v179` WHERE") && dup.contains("HAVING count() > 1"), "{dup}");
    assert!(!missing.contains("GLOBAL") && !dup.contains("GLOBAL"));
}

#[test]
fn shard_coverage_and_proof_settings() {
    assert_eq!(
        expected_shards_sql("nanosiem_cluster"),
        "SELECT uniqExact(shard_num) FROM system.clusters WHERE cluster = 'nanosiem_cluster' AND (database_replica_name = '' OR (SELECT countIf(database_replica_name = '') FROM system.clusters WHERE cluster = 'nanosiem_cluster') = 0)"
    );
    assert_eq!(
        answered_shards_sql("nanosiem_cluster"),
        "SELECT uniqExact(shardNum()) FROM cluster('nanosiem_cluster', system.one)"
    );
    assert_eq!(PROOF_SETTINGS, &[("skip_unavailable_shards", "0")]);
}

#[test]
fn cluster_drop_uses_the_migrator_transform() {
    // Explicit cluster: ON CLUSTER after the name, SYNC kept once, SETTINGS last.
    assert_eq!(
        drop_legacy_sql(Some("nanosiem_cluster"), "nanosiem", false),
        "DROP TABLE IF EXISTS nanosiem.ocsf_logs_legacy_v179 ON CLUSTER 'nanosiem_cluster' SYNC SETTINGS max_table_size_to_drop = 0"
    );
    // Replicated database (cluster == db): the engine propagates the DROP.
    assert_eq!(
        drop_legacy_sql(Some("nanosiem"), "nanosiem", false),
        "DROP TABLE IF EXISTS nanosiem.ocsf_logs_legacy_v179 SYNC SETTINGS max_table_size_to_drop = 0"
    );
}

#[test]
fn quoting_cannot_break_out_of_literals() {
    assert_eq!(all_shards_ref(Some("c' OR 1"), "db", "t"), "cluster('c\\' OR 1', 'db', 't')");
    assert_eq!(all_shards_ref(None, "d`b", "t"), "`d\\`b`.`t`");
    assert_eq!(
        expected_shards_sql("c' OR 1"),
        "SELECT uniqExact(shard_num) FROM system.clusters WHERE cluster = 'c\\' OR 1' AND (database_replica_name = '' OR (SELECT countIf(database_replica_name = '') FROM system.clusters WHERE cluster = 'c\\' OR 1') = 0)"
    );
}
