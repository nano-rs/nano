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
