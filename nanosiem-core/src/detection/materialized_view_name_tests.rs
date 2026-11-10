// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5018 (security review 2026-11-08): only real-time rule view names may
//! reach `DROP VIEW` on the admin client.

use super::{MaterializedViewError, MaterializedViewGenerator};
use uuid::Uuid;

#[test]
fn derived_names_are_accepted() {
    let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let name = MaterializedViewGenerator::view_name_for_rule_id(id);
    assert_eq!(name, "mv_rt_detection_550e8400e29b41d4a716446655440000");
    assert!(MaterializedViewGenerator::is_rule_view_name(&name));
    assert_eq!(
        MaterializedViewGenerator::drop_view_ddl(&name, "").unwrap(),
        "DROP VIEW IF EXISTS mv_rt_detection_550e8400e29b41d4a716446655440000"
    );
    assert_eq!(
        MaterializedViewGenerator::drop_view_ddl(&name, " ON CLUSTER `c`").unwrap(),
        "DROP VIEW IF EXISTS mv_rt_detection_550e8400e29b41d4a716446655440000 ON CLUSTER `c`"
    );
}

#[test]
fn planted_names_are_refused_before_any_ddl() {
    for name in [
        "nanosiem.ip_prevalence_mv",
        "ip_prevalence_mv",
        "mv_rt_detection_550e8400e29b41d4a716446655440000 SYNC",
        "mv_rt_detection_550e8400e29b41d4a716446655440000; DROP VIEW x",
        "mv_rt_detection_550e8400e29b41d4a716446655440000 --",
        "mv_rt_detection_550E8400E29B41D4A716446655440000",
        "mv_rt_detection_550e8400e29b41d4a71644665544000",
        "mv_rt_detection_",
        "",
    ] {
        assert!(!MaterializedViewGenerator::is_rule_view_name(name), "{name:?}");
        assert!(
            matches!(
                MaterializedViewGenerator::drop_view_ddl(name, ""),
                Err(MaterializedViewError::InvalidViewName(_))
            ),
            "{name:?}"
        );
    }
}

#[test]
fn update_body_cannot_set_the_view_name() {
    let update: crate::models::UpdateDetectionRule =
        serde_json::from_str(r#"{"materialized_view_name":"nanosiem.ip_prevalence_mv"}"#)
            .expect("unknown-to-client fields still deserialize");
    assert_eq!(update.materialized_view_name, None);
}

#[test]
fn cluster_rule_view_ddl_does_not_wait_out_a_down_replica() {
    assert!(MaterializedViewGenerator::ddl_settings("").is_empty());
    assert_eq!(
        MaterializedViewGenerator::ddl_settings(" ON CLUSTER `default`"),
        &[
            ("distributed_ddl_output_mode", "null_status_on_timeout"),
            ("distributed_ddl_task_timeout", "15"),
        ]
    );
}

#[test]
fn reachable_replica_catalogs_decide_rule_view_ddl_success() {
    // NAN-5215: the catalog of every reachable replica, not the DDL status.
    assert!(MaterializedViewGenerator::view_presence_verified(true, 3, 3));
    assert!(!MaterializedViewGenerator::view_presence_verified(true, 3, 2));
    assert!(MaterializedViewGenerator::view_presence_verified(false, 3, 0));
    assert!(!MaterializedViewGenerator::view_presence_verified(false, 3, 1));
    assert!(!MaterializedViewGenerator::view_presence_verified(true, 0, 0));
    assert!(!MaterializedViewGenerator::view_presence_verified(false, 0, 0));
    assert_eq!(
        MaterializedViewGenerator::view_presence_sql(
            "default",
            "nanosiem",
            "mv_rt_detection_550e8400e29b41d4a716446655440000"
        ),
        "SELECT count() FROM clusterAllReplicas('default', system.tables) WHERE database = 'nanosiem' AND name = 'mv_rt_detection_550e8400e29b41d4a716446655440000' SETTINGS skip_unavailable_shards = 1"
    );
    assert_eq!(
        MaterializedViewGenerator::reachable_replicas_sql("default"),
        "SELECT count() FROM clusterAllReplicas('default', system.one) SETTINGS skip_unavailable_shards = 1"
    );
}
