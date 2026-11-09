// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5032 (review): OCSF ingest cannot store a row as `audit` or `findings`.
//!
//! Under the OCSF profile the audit mirror and the risk pipeline trust
//! `ocsf_logs.source_type`. The generic Vector lane and Tenzir's native
//! protocol land in `ocsf_logs_raw`, whose view (ocsf/193) rewrites those
//! values. The genuine writers use the platform-only `ocsf_logs_system_raw`.

const OCSF_INIT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/ocsf/init.sql"));
const MIGRATION_193: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/migrations/193_reserved_source_type_guard.sql"
));
const USERS_XML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/users.d/nanosiem-users.xml"
));
const EMITTER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/audit/emitter.rs"));
const FINDINGS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detection/findings.rs"));

const GUARDED: &str = "    if((if(source_type IN ('', 'unknown'), lower(ifNull(toString(event.metadata.log_source), 'unknown')), lower(source_type))) AS `_nano_st` IN ('audit', 'findings'), 'reserved_spoof', `_nano_st`) AS source_type,";
const PLAIN: &str = "    if(source_type IN ('', 'unknown'), lower(ifNull(toString(event.metadata.log_source), 'unknown')), lower(source_type)) AS source_type,";

fn overlay_view_body() -> &'static str {
    OCSF_INIT
        .split(
            "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv\n\
             TO nanosiem.ocsf_logs\n\
             DEFINER = CURRENT_USER\n\
             SQL SECURITY DEFINER\n\
             AS ",
        )
        .nth(1)
        .and_then(|rest| rest.split("\n;").next())
        .expect("overlay ocsf_logs_raw_mv body")
}

#[test]
fn the_ingest_landing_view_rewrites_reserved_source_types() {
    let body = overlay_view_body();
    assert!(body.contains(GUARDED), "fresh OCSF installs must carry the guard");
    assert!(!body.contains(PLAIN));
    let modified = MIGRATION_193
        .split("ALTER TABLE nanosiem.ocsf_logs_raw_mv\nMODIFY QUERY ")
        .nth(1)
        .and_then(|rest| rest.split(";\n").next())
        .expect("193 MODIFY QUERY body");
    assert_eq!(modified, body, "rerun scripts/gen-ocsf-ddl.py and regenerate ocsf/193");
}

#[test]
fn the_platform_landing_view_is_the_same_body_without_the_rewrite() {
    let system = MIGRATION_193
        .split(
            "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_system_raw_mv\n\
             TO nanosiem.ocsf_logs\n\
             DEFINER = CURRENT_USER\n\
             SQL SECURITY DEFINER\n\
             AS ",
        )
        .nth(1)
        .and_then(|rest| rest.split(";\n").next())
        .expect("193 system view body");
    let expected = overlay_view_body()
        .replace(GUARDED, PLAIN)
        .replace("FROM nanosiem.ocsf_logs_raw", "FROM nanosiem.ocsf_logs_system_raw");
    assert_eq!(system, expected);
    assert!(MIGRATION_193.contains(
        "CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_system_raw AS nanosiem.ocsf_logs_raw\nENGINE = Null;"
    ));
}

#[test]
fn ingest_identities_cannot_write_the_platform_landing() {
    for user in ["nanosiem_vector", "nanosiem_ingest"] {
        let section = USERS_XML
            .split(&format!("<{user}>"))
            .nth(1)
            .and_then(|r| r.split(&format!("</{user}>")).next())
            .unwrap_or_else(|| panic!("{user} section"));
        assert!(!section.contains("ocsf_logs_system_raw"), "{user} must not write the platform landing");
        assert!(!section.contains(" ON nanosiem.*"), "{user} must not hold a database-wide grant");
    }
}

#[test]
fn genuine_audit_and_findings_rows_use_the_platform_landing() {
    assert!(EMITTER.contains(r#".local("ocsf_logs_system_raw")"#));
    assert!(!EMITTER.contains(r#".local("ocsf_logs_raw")"#));
    assert!(FINDINGS.contains(r#".local("ocsf_logs_system_raw")"#));
    assert!(!FINDINGS.contains(r#".local("ocsf_logs_raw")"#));
}

#[test]
fn the_generator_list_matches_the_rust_registry() {
    for v in nanosiem_core::auth::reserved_source_types::ENFORCED {
        assert!(GUARDED.contains(&format!("'{v}'")), "{v}");
    }
    assert!(GUARDED.contains(&format!("'{}'", nanosiem_core::auth::reserved_source_types::SPOOF_MARKER)));
}
