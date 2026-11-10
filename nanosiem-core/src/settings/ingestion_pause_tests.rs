// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn users(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn guard_sql_single_node_is_additive_readonly_profile() {
    let sql = apply_guard_sql("", &users(&["nanosiem_ingest", "nanosiem_vector"])).unwrap();
    assert_eq!(
        sql,
        "CREATE SETTINGS PROFILE OR REPLACE `nano_ingest_pause` SETTINGS readonly = 1 TO `nanosiem_ingest`, `nanosiem_vector`"
    );
    assert_eq!(remove_guard_sql(""), "DROP SETTINGS PROFILE IF EXISTS `nano_ingest_pause`");
}

#[test]
fn guard_sql_clustered_puts_on_cluster_after_the_name() {
    let oc = crate::db::dual_pool::format_on_cluster(Some("nano"));
    let sql = apply_guard_sql(&oc, &users(&["nanosiem_vector"])).unwrap();
    assert_eq!(
        sql,
        "CREATE SETTINGS PROFILE OR REPLACE `nano_ingest_pause` ON CLUSTER `nano` SETTINGS readonly = 1 TO `nanosiem_vector`"
    );
    assert_eq!(
        remove_guard_sql(&oc),
        "DROP SETTINGS PROFILE IF EXISTS `nano_ingest_pause` ON CLUSTER `nano`"
    );
}

#[test]
fn guard_sql_never_splices_a_non_identifier() {
    assert!(apply_guard_sql("", &[]).is_none());
    assert!(apply_guard_sql("", &users(&["a`; DROP TABLE logs; --"])).is_none());
    let sql = apply_guard_sql("", &users(&["ok_user", "bad name"])).unwrap();
    assert!(sql.ends_with("TO `ok_user`"), "{sql}");
}

#[test]
fn user_list_env_is_trimmed_deduped_and_validated() {
    assert_eq!(
        parse_user_list(" nanosiem_vector, nanosiem_ingest ,nanosiem_vector,,x-y,`q`"),
        users(&["nanosiem_ingest", "nanosiem_vector"])
    );
    assert!(parse_user_list("").is_empty());
}

#[test]
fn default_users_are_the_ingest_writers() {
    assert_eq!(DEFAULT_PAUSE_USERS, &["nanosiem_vector", "nanosiem_ingest"]);
}

#[test]
fn guard_presence_reads_every_node_on_a_cluster() {
    let (p, n) = guard_presence_sql(None);
    assert_eq!(p, "SELECT count() FROM system.settings_profiles WHERE name = ?");
    assert_eq!(n, "SELECT count() FROM system.one");
    let (p, n) = guard_presence_sql(Some("c1"));
    assert!(p.contains("clusterAllReplicas('c1', system.settings_profiles)"), "{p}");
    assert!(n.contains("clusterAllReplicas('c1', system.one)"), "{n}");
    // A quote in the cluster name cannot break out of the literal.
    let (p, _) = guard_presence_sql(Some("c'1"));
    assert!(p.contains("clusterAllReplicas('c1',"), "{p}");
}

#[test]
fn guard_classification() {
    assert_eq!(classify_guard(0, 0), IngestionGuardState::Unknown);
    assert_eq!(classify_guard(0, 4), IngestionGuardState::Absent);
    assert_eq!(classify_guard(4, 4), IngestionGuardState::Applied);
    // A node that missed the DDL: neither, so the reconcile re-applies.
    assert_eq!(classify_guard(3, 4), IngestionGuardState::Unknown);
}

#[test]
fn only_a_non_manual_pause_is_auto_resumable() {
    let mut s = IngestionPauseState { paused: true, ..Default::default() };
    // Paused by a release before NAN-5217 (source NULL): the monitor's own.
    assert!(s.auto_resumable());
    s.source = Some(IngestionPauseSource::DiskPressure);
    assert!(s.auto_resumable());
    s.source = Some(IngestionPauseSource::Manual);
    assert!(!s.auto_resumable());
    assert!(!IngestionPauseState::default().auto_resumable());
}

#[test]
fn source_round_trips_its_column_value() {
    for s in [IngestionPauseSource::DiskPressure, IngestionPauseSource::Manual] {
        assert_eq!(IngestionPauseSource::parse(s.as_str()), Some(s));
    }
    assert_eq!(IngestionPauseSource::parse("other"), None);
    assert_eq!(
        serde_json::to_value(IngestionPauseSource::DiskPressure).unwrap(),
        serde_json::json!("disk_pressure")
    );
}

#[test]
fn reason_is_bounded_and_stripped_of_control_characters() {
    assert_eq!(clean_reason("  disk\nfull\u{7}  "), "diskfull");
    assert_eq!(clean_reason(&"x".repeat(2000)).len(), MAX_REASON_LEN);
}
