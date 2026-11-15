// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5346: retention applies to every event table that still holds rows.

use super::*;

#[test]
fn udm_retention_targets_logs_only() {
    assert_eq!(retention_tables_for("logs"), ["logs"]);
}

/// An OCSF install still creates `logs` and keeps its historical rows; the
/// operator's retention applies there too, after the active table.
#[test]
fn ocsf_retention_also_targets_logs() {
    assert_eq!(retention_tables_for("ocsf_logs"), ["ocsf_logs", "logs"]);
}

#[test]
fn ttl_sql_per_table_and_cluster() {
    let tables = retention_tables_for("ocsf_logs");
    let sql: Vec<String> = tables.iter().map(|t| retention_ttl_sql(t, "", 30)).collect();
    assert_eq!(
        sql,
        [
            "ALTER TABLE ocsf_logs MODIFY TTL timestamp + INTERVAL 30 DAY DELETE \
             WHERE timestamp > toDateTime64('2000-01-01 00:00:00', 3, 'UTC')",
            "ALTER TABLE logs MODIFY TTL timestamp + INTERVAL 30 DAY DELETE",
        ]
    );
    assert_eq!(
        retention_ttl_sql("logs", " ON CLUSTER 'nano'", 7),
        "ALTER TABLE logs ON CLUSTER 'nano' MODIFY TTL timestamp + INTERVAL 7 DAY DELETE"
    );
    // The UDM statement is byte-identical to the pre-NAN-5346 one.
    assert_eq!(
        retention_ttl_sql("logs", "", 90),
        format!("ALTER TABLE {}{} MODIFY TTL timestamp + INTERVAL {} DAY DELETE", "logs", "", 90)
    );
}

/// NAN-5449: a retention change keeps migration 127's pre-2000 guard on the
/// OCSF table, so direct-write rows with a garbage timestamp are not deleted
/// at part-write.
#[test]
fn ocsf_ttl_keeps_the_pre_2000_guard() {
    let sql = retention_ttl_sql("ocsf_logs", "", 30);
    assert!(sql.ends_with("DELETE WHERE timestamp > toDateTime64('2000-01-01 00:00:00', 3, 'UTC')"));
    assert!(!retention_ttl_sql("logs", "", 30).contains("WHERE"));
}

#[test]
fn retention_env_parsing() {
    assert_eq!(retention_days_from_env(None).unwrap(), None);
    assert_eq!(retention_days_from_env(Some("")).unwrap(), None);
    assert_eq!(retention_days_from_env(Some("  ")).unwrap(), None);
    assert_eq!(retention_days_from_env(Some("90")).unwrap(), Some(90));
    assert_eq!(retention_days_from_env(Some(" 365 ")).unwrap(), Some(365));
    assert!(retention_days_from_env(Some("0")).is_err());
    assert!(retention_days_from_env(Some("3651")).is_err());
    assert!(retention_days_from_env(Some("90d")).is_err());
    assert!(retention_days_from_env(Some("-1")).is_err());
}

#[test]
fn retention_range() {
    assert!(validate_clickhouse_retention_days(0).is_err());
    assert_eq!(validate_clickhouse_retention_days(1).unwrap(), 1);
    assert_eq!(validate_clickhouse_retention_days(3650).unwrap(), 3650);
    assert!(validate_clickhouse_retention_days(3651).is_err());
}

/// The deployment value wins only when it changed since the migrator last
/// applied it; a plain restart keeps a value set in the UI.
#[test]
fn deployment_retention_precedence() {
    let fresh = ClickHouseRetentionRecord::default();
    assert!(deployment_retention_needs_apply(90, &fresh));

    let applied = ClickHouseRetentionRecord {
        days: Some(90),
        source: Some("deployment".into()),
        env_applied: Some(90),
    };
    assert!(!deployment_retention_needs_apply(90, &applied));

    let ui_changed = ClickHouseRetentionRecord {
        days: Some(30),
        source: Some("ui".into()),
        env_applied: Some(90),
    };
    assert!(!deployment_retention_needs_apply(90, &ui_changed));
    assert!(deployment_retention_needs_apply(120, &ui_changed));
}

/// The real OCSF and UDM DDL as ClickHouse prints it.
#[test]
fn ttl_days_from_event_table_ddl() {
    let ocsf = "CREATE TABLE nanosiem.ocsf_logs (`timestamp` DateTime64(3, 'UTC')) ENGINE = MergeTree \
                PARTITION BY toYYYYMMDD(timestamp) ORDER BY timestamp \
                TTL timestamp + toIntervalDay(30) WHERE timestamp > toDateTime64('2000-01-01 00:00:00', 3, 'UTC') \
                SETTINGS index_granularity = 8192";
    assert_eq!(parse_ttl_days(ocsf), Some(30));
    let udm = "CREATE TABLE nanosiem.logs (`timestamp` DateTime64(3)) ENGINE = MergeTree \
               ORDER BY timestamp TTL timestamp + toIntervalDay(365) SETTINGS index_granularity = 8192";
    assert_eq!(parse_ttl_days(udm), Some(365));
}
