// SPDX-License-Identifier: AGPL-3.0-or-later

//! Schema-shape guards for the aggregation materialized views
//! (NAN-1385 / NAN-1386).
//!
//! ClickHouse attaches a materialized view's insert trigger ONLY to the FIRST
//! SELECT of a `UNION ALL` body — every other branch silently never fires.
//! `entity_time_range_mv` shipped as a UNION ALL and starved its src_host
//! partition for months (and never had the `user` partition the asset reader
//! queries). These tests pin the fixed shape:
//!
//! 1. The aggregation MV family (entity time range, identity observations,
//!    cloud user activity, per-source telemetry — UDM and OCSF sides) is one
//!    MV per branch, with NO `UNION ALL` in any body.
//! 2. Migration 128 and the two init.sql files define byte-equivalent MVs
//!    (modulo comments/markers/whitespace), so migrated deployments and fresh
//!    bootstraps converge on the same schema.
//!
//! NOTE: the *_prevalence_mv / ocsf_*_prevalence_summary_mv family still uses
//! UNION ALL bodies and is therefore NOT covered here — its non-first branches
//! are equally dead (same mechanism) and tracked as separate follow-up work.
//! Do not add new UNION ALL MVs; split per branch instead.

use std::collections::BTreeMap;

const UDM_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/init.sql"
));
const OCSF_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));
const MIGRATION_128: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/128_entity_mv_split_and_ocsf_aggregation_mvs.sql"
));

/// The split-per-branch aggregation MV family this guard pins.
const UDM_AGG_MVS: &[&str] = &[
    "nanosiem.entity_time_range_src_ip_mv",
    "nanosiem.entity_time_range_src_host_mv",
    "nanosiem.entity_time_range_user_mv",
    "nanosiem.identity_observations_mv",
    "nanosiem.cloud_user_activity_mv",
    "nanosiem.logs_per_source_5m_mv",
    "nanosiem.nat_detection_mv",
];
const OCSF_AGG_MVS: &[&str] = &[
    "nanosiem.ocsf_entity_time_range_src_ip_mv",
    "nanosiem.ocsf_entity_time_range_src_host_mv",
    "nanosiem.ocsf_entity_time_range_user_mv",
    "nanosiem.ocsf_identity_observations_mv",
    "nanosiem.ocsf_cloud_user_activity_mv",
    "nanosiem.ocsf_logs_per_source_5m_mv",
];

/// Extract `CREATE MATERIALIZED VIEW` statements keyed by view name, with `--`
/// comments stripped (the migration runner strips them before splitting on
/// `;`), `/* ... */` block markers removed, and whitespace collapsed — i.e.
/// the same normalization under which two definitions are "the same DDL".
fn create_mv_statements(sql: &str) -> BTreeMap<String, String> {
    let stripped: Vec<String> = sql
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => l[..i].to_string(),
            None => l.to_string(),
        })
        .collect();
    let stripped = stripped.join("\n");

    let mut out = BTreeMap::new();
    for stmt in stripped.split(';') {
        let stmt = stmt.trim();
        let Some(rest) = stmt.strip_prefix("CREATE MATERIALIZED VIEW IF NOT EXISTS ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        // Drop block comments (e.g. the `nano:skip-if-unknown-table` marker).
        let mut body = String::new();
        let mut remaining = stmt;
        while let Some(open) = remaining.find("/*") {
            body.push_str(&remaining[..open]);
            match remaining[open..].find("*/") {
                Some(close) => remaining = &remaining[open + close + 2..],
                None => {
                    remaining = "";
                    break;
                }
            }
        }
        body.push_str(remaining);
        let normalized = body.split_whitespace().collect::<Vec<_>>().join(" ");
        out.insert(name, normalized);
    }
    out
}

/// Every aggregation MV must exist in its init file and contain NO `UNION ALL`
/// — ClickHouse would only ever fire the first branch.
#[test]
fn aggregation_mvs_have_no_union_all_bodies() {
    let udm = create_mv_statements(UDM_INIT);
    let ocsf = create_mv_statements(OCSF_INIT);
    let mig = create_mv_statements(MIGRATION_128);

    for name in UDM_AGG_MVS {
        let stmt = udm
            .get(*name)
            .unwrap_or_else(|| panic!("{name} missing from clickhouse/init.sql"));
        assert!(
            !stmt.to_uppercase().contains("UNION ALL"),
            "{name} (init.sql) has a UNION ALL body — only its first SELECT would ever fire"
        );
    }
    for name in OCSF_AGG_MVS {
        let stmt = ocsf
            .get(*name)
            .unwrap_or_else(|| panic!("{name} missing from clickhouse/ocsf/init.sql"));
        assert!(
            !stmt.to_uppercase().contains("UNION ALL"),
            "{name} (ocsf/init.sql) has a UNION ALL body — only its first SELECT would ever fire"
        );
    }
    for (name, stmt) in &mig {
        assert!(
            !stmt.to_uppercase().contains("UNION ALL"),
            "{name} (migration 128) has a UNION ALL body — only its first SELECT would ever fire"
        );
    }
}

/// The pre-split UNION ALL view must not resurface in either init file (fresh
/// bootstraps would recreate the broken shape next to the split MVs).
#[test]
fn legacy_union_all_entity_mv_is_gone() {
    for (label, sql) in [("init.sql", UDM_INIT), ("ocsf/init.sql", OCSF_INIT)] {
        let mvs = create_mv_statements(sql);
        assert!(
            !mvs.contains_key("nanosiem.entity_time_range_mv"),
            "{label} still defines the UNION ALL nanosiem.entity_time_range_mv"
        );
    }
}

/// Migration 128 (existing deployments) and the init files (fresh bootstraps)
/// must define byte-equivalent MVs, or the two paths diverge silently.
#[test]
fn migration_128_matches_init_definitions() {
    let udm = create_mv_statements(UDM_INIT);
    let ocsf = create_mv_statements(OCSF_INIT);
    let mig = create_mv_statements(MIGRATION_128);

    for name in [
        "nanosiem.entity_time_range_src_ip_mv",
        "nanosiem.entity_time_range_src_host_mv",
        "nanosiem.entity_time_range_user_mv",
    ] {
        assert_eq!(
            mig.get(name),
            udm.get(name),
            "{name} differs between migration 128 and clickhouse/init.sql"
        );
    }
    for name in OCSF_AGG_MVS {
        assert_eq!(
            mig.get(*name),
            ocsf.get(*name),
            "{name} differs between migration 128 and clickhouse/ocsf/init.sql"
        );
    }
}

/// The OCSF telemetry rollup depends on the materialized `event_bytes` column;
/// its definition must stay identical between the fresh CREATE TABLE, the
/// existing-tenant overlay ALTER (both in ocsf/init.sql), and migration 128 —
/// or fresh-vs-grown tables diverge.
#[test]
fn event_bytes_definitions_in_lockstep() {
    let def = "`event_bytes` UInt64 MATERIALIZED length(toString(event)) CODEC(T64, LZ4)";
    assert_eq!(
        OCSF_INIT.matches(def).count(),
        2,
        "ocsf/init.sql must define event_bytes exactly twice (CREATE TABLE + overlay ALTER)"
    );
    assert_eq!(
        MIGRATION_128.matches(def).count(),
        1,
        "migration 128 must ADD COLUMN event_bytes with the same definition"
    );
}
