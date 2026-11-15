// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// A `create_table_query` with the given table TTL clause.
fn ddl(name: &str, ttl: &str) -> (String, String) {
    (
        name.to_string(),
        format!(
            "CREATE TABLE nanosiem.{name} (`timestamp` DateTime64(6, 'UTC'), `x` String) ENGINE = MergeTree \
             PARTITION BY toYYYYMMDD(timestamp) ORDER BY timestamp TTL {ttl} SETTINGS index_granularity = 8192"
        ),
    )
}

fn days(n: u32) -> String {
    format!("timestamp + toIntervalDay({n})")
}

const OCSF_TTL: &str = "timestamp + toIntervalDay(365) WHERE timestamp > '2000-01-01'";

fn plan(tables: &[(String, String)], active: &str, env: Option<u32>) -> Vec<TtlRepair> {
    plan_ttl_repairs(&TtlRepairInput { tables, saved_retention: None, retention_env: env, active_table: active })
}

fn repair(table: &str, from: u32, to: u32) -> TtlRepair {
    TtlRepair { table: table.to_string(), from_days: from, to_days: to }
}

fn three(n_logs: u32, n_signals: u32, n_errors: u32) -> Vec<(String, String)> {
    vec![ddl("logs", &days(n_logs)), ddl("signals", &days(n_signals)), ddl("ingestion_errors", &days(n_errors))]
}

/// Review case: an operator deliberately set `logs` to 30 days; signals and
/// ingestion_errors are at their schema defaults. No fingerprint, no change.
#[test]
fn a_deliberate_logs_ttl_with_the_others_at_default_is_kept() {
    assert!(plan(&three(30, 365, 90), "logs", None).is_empty());
    assert!(plan(&three(30, 365, 90), "ocsf_logs", None).is_empty());
}

/// Review case: all three at the old 180-day code default.
#[test]
fn all_three_at_180_are_restored() {
    assert_eq!(
        plan(&three(180, 180, 180), "logs", None),
        vec![repair("logs", 180, 365), repair("signals", 180, 365), repair("ingestion_errors", 180, 90)]
    );
}

/// Review case: a custom Helm `warmDays` (60). The fingerprint does not
/// depend on the old warm value.
#[test]
fn all_three_at_a_custom_warm_value_are_restored() {
    assert_eq!(
        plan(&three(60, 60, 60), "logs", None),
        vec![repair("logs", 60, 365), repair("signals", 60, 365), repair("ingestion_errors", 60, 90)]
    );
    // warmDays 90: ingestion_errors is already at its default, signals is not.
    assert_eq!(plan(&three(90, 90, 90), "logs", None), vec![repair("logs", 90, 365), repair("signals", 90, 365)]);
    assert_eq!(plan(&three(120, 120, 120), "logs", None).len(), 3);
}

#[test]
fn ocsf_install_hit_by_the_bug_is_restored_to_the_ocsf_retention() {
    let mut tables = three(30, 30, 30);
    tables.insert(0, ddl("ocsf_logs", OCSF_TTL));
    assert_eq!(
        plan(&tables, "ocsf_logs", None),
        vec![repair("logs", 30, 365), repair("signals", 30, 365), repair("ingestion_errors", 30, 90)]
    );
}

/// A table changed since the bug (differs from N) is the operator's: never
/// touched, the rest still repaired (signals follow the operator's event
/// retention).
#[test]
fn a_table_changed_since_is_left_alone() {
    assert_eq!(
        plan(&three(400, 30, 30), "logs", None),
        vec![repair("signals", 30, 400), repair("ingestion_errors", 30, 90)]
    );
}

#[test]
fn the_restore_target_follows_the_operator_retention_of_the_uncut_table() {
    let tables = [
        ddl("ocsf_logs", "timestamp + toIntervalDay(180) WHERE timestamp > '2000-01-01'"),
        ddl("signals", &days(30)),
        ddl("ingestion_errors", &days(30)),
    ];
    assert_eq!(plan(&tables, "ocsf_logs", None), vec![repair("signals", 30, 180), repair("ingestion_errors", 30, 90)]);
}

#[test]
fn the_saved_settings_retention_wins_then_the_env() {
    let tables = three(30, 30, 30);
    assert_eq!(plan(&tables, "logs", Some(730))[0], repair("logs", 30, 730));
    let input = TtlRepairInput { tables: &tables, saved_retention: Some(200), retention_env: Some(730), active_table: "logs" };
    assert_eq!(plan_ttl_repairs(&input)[0], repair("logs", 30, 200));
}

#[test]
fn no_fingerprint_without_both_signals_and_ingestion_errors_cut_alike() {
    // Signals alone.
    assert!(plan(&[ddl("signals", &days(30)), ddl("logs", &days(30))], "logs", None).is_empty());
    // Different values.
    assert!(plan(&three(30, 30, 45), "logs", None).is_empty());
    // Both at their defaults.
    assert!(plan(&three(365, 365, 90), "logs", None).is_empty());
}

#[test]
fn only_the_exact_old_rewrite_matches() {
    for ttl in [
        "timestamp + toIntervalDay(30) WHERE timestamp > '2000-01-01'",
        "timestamp + toIntervalDay(30) TO VOLUME 'cold', timestamp + toIntervalDay(30)",
        "toDateTime(timestamp) + toIntervalDay(30)",
        "timestamp + toIntervalMonth(1)",
    ] {
        let tables = [ddl("signals", ttl), ddl("ingestion_errors", ttl)];
        assert!(plan(&tables, "ocsf_logs", None).is_empty(), "{ttl} must not match");
    }
}

#[test]
fn sharded_local_tables_are_repaired_by_their_physical_name() {
    let tables = [ddl("ocsf_logs_local", OCSF_TTL), ddl("signals_local", &days(30)), ddl("ingestion_errors_local", &days(30))];
    assert_eq!(
        plan(&tables, "ocsf_logs", None),
        vec![repair("signals_local", 30, 365), repair("ingestion_errors_local", 30, 90)]
    );
}

#[test]
fn nothing_when_the_target_equals_the_current_value() {
    // The operator really runs 30-day retention on the uncut OCSF table.
    let tables = [
        ddl("ocsf_logs", "timestamp + toIntervalDay(30) WHERE timestamp > '2000-01-01'"),
        ddl("signals", &days(30)),
        ddl("ingestion_errors", &days(30)),
    ];
    assert_eq!(plan(&tables, "ocsf_logs", None), vec![repair("ingestion_errors", 30, 90)]);
}

#[test]
fn env_parsers() {
    assert_eq!(retention_env_days(Some(" 400 ")), Some(400));
    assert_eq!(retention_env_days(Some("0")), None);
    assert_eq!(retention_env_days(Some("forever")), None);
    assert_eq!(retention_env_days(None), None);
}

#[test]
fn restore_runs_recalculate_only_and_rejects_unsafe_names() {
    assert_eq!(
        restore_ttl_sql("nanosiem", "signals_local", " ON CLUSTER 'c'", 365).as_deref(),
        Some("ALTER TABLE nanosiem.signals_local ON CLUSTER 'c' MODIFY TTL timestamp + toIntervalDay(365)")
    );
    assert_eq!(
        recalculate_only_sql("nanosiem", "signals", "").as_deref(),
        Some("ALTER TABLE nanosiem.signals MODIFY SETTING materialize_ttl_recalculate_only = 1")
    );
    assert!(restore_ttl_sql("nanosiem", "signals; DROP", "", 365).is_none());
    assert!(recalculate_only_sql("nanosiem", "signals; DROP", "").is_none());
    // Never the non-materializing form: surviving parts would keep their old
    // expiry (verified on ClickHouse 26.10).
    assert!(!restore_ttl_sql("nanosiem", "signals", "", 365).unwrap().contains("materialize_ttl_after_modify"));
}

/// NAN-5449: only a value saved in Settings is the saved retention.
#[test]
fn saved_settings_retention_reads_only_a_ui_record() {
    use crate::settings::ClickHouseRetentionRecord;
    let rec = |days, source: Option<&str>| ClickHouseRetentionRecord { days, source: source.map(String::from), env_applied: None };
    assert_eq!(saved_settings_retention(&rec(Some(200), Some("ui"))), Some(200));
    assert_eq!(saved_settings_retention(&rec(Some(200), Some("deployment"))), None);
    assert_eq!(saved_settings_retention(&rec(None, Some("ui"))), None);
    assert_eq!(saved_settings_retention(&rec(Some(0), Some("ui"))), None);
    assert_eq!(saved_settings_retention(&ClickHouseRetentionRecord::default()), None);
}
