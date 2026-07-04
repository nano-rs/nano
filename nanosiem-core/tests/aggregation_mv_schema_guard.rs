// SPDX-License-Identifier: AGPL-3.0-or-later

//! Schema-shape guards for the aggregation materialized views
//! (NAN-1385 / NAN-1386 / NAN-1393).
//!
//! ClickHouse attaches a materialized view's insert trigger ONLY to the FIRST
//! SELECT of a `UNION ALL` body — every other branch silently never fires.
//! `entity_time_range_mv` shipped as a UNION ALL and starved its src_host
//! partition for months (and never had the `user` partition the asset reader
//! queries); the prevalence MV family had the same shape (NAN-1393), so
//! src_ip / DNS-query-domain / url-domain / process-hash prevalence never
//! accrued on either profile. These tests pin the fixed shape:
//!
//! 1. The aggregation + prevalence MV families (entity time range, identity
//!    observations, cloud user activity, per-source telemetry, ip/domain/hash
//!    prevalence — UDM and OCSF sides) are one MV per branch, with NO
//!    `UNION ALL` in any body. Do not add new UNION ALL MVs; split per branch.
//! 2. Migrations 128/129 and the two init.sql files define byte-equivalent
//!    MVs (modulo comments/markers/whitespace), so migrated deployments and
//!    fresh bootstraps converge on the same schema.

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
const MIGRATION_129: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/129_prevalence_mv_split.sql"
));
// NAN-1443 lean-storage rework: the promote MV in migration 135 populates
// event_bytes on existing tenants; it must match ocsf/init.sql's ingest MV.
const MIGRATION_135: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/135_ocsf_promote_udm_parity.sql"
));
// NAN-1661: migration 150 supersedes migration 129 for the OCSF prevalence
// branch MVs — it retargets them from the entity-keyed *_prevalence_summary
// tables at the hourly *_prevalence_agg tables (the OCSF agg-layer bypass fix).
// So the OCSF prevalence MV lockstep is now init.sql-vs-150, not init.sql-vs-129.
const MIGRATION_152: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/152_ocsf_prevalence_route_through_agg.sql"
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

/// The split-per-branch prevalence MV family (NAN-1393 / migration 129).
const UDM_PREVALENCE_MVS: &[&str] = &[
    "nanosiem.ip_prevalence_dest_ip_mv",
    "nanosiem.ip_prevalence_src_ip_mv",
    "nanosiem.domain_prevalence_dest_host_mv",
    "nanosiem.domain_prevalence_query_mv",
    "nanosiem.domain_prevalence_url_domain_mv",
    "nanosiem.hash_prevalence_file_hash_mv",
    "nanosiem.hash_prevalence_process_hash_mv",
];
const OCSF_PREVALENCE_MVS: &[&str] = &[
    "nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv",
    "nanosiem.ocsf_ip_prevalence_summary_src_ip_mv",
    "nanosiem.ocsf_domain_prevalence_summary_dest_host_mv",
    "nanosiem.ocsf_domain_prevalence_summary_query_mv",
    "nanosiem.ocsf_domain_prevalence_summary_url_mv",
    "nanosiem.ocsf_hash_prevalence_summary_file_hash_mv",
    "nanosiem.ocsf_hash_prevalence_summary_process_hash_mv",
];

/// Pre-split UNION ALL views (and the 055 process-hash workaround that
/// hash_prevalence_process_hash_mv replaces) — none may resurface in an init
/// file, or fresh bootstraps recreate the broken/double-counting shape next
/// to the split MVs.
const LEGACY_MV_NAMES: &[&str] = &[
    "nanosiem.entity_time_range_mv",
    "nanosiem.ip_prevalence_mv",
    "nanosiem.domain_prevalence_mv",
    "nanosiem.hash_prevalence_mv",
    "nanosiem.process_hash_prevalence_mv",
    "nanosiem.ocsf_ip_prevalence_summary_mv",
    "nanosiem.ocsf_domain_prevalence_summary_mv",
    "nanosiem.ocsf_hash_prevalence_summary_mv",
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

    for name in UDM_AGG_MVS.iter().chain(UDM_PREVALENCE_MVS) {
        let stmt = udm
            .get(*name)
            .unwrap_or_else(|| panic!("{name} missing from clickhouse/init.sql"));
        assert!(
            !stmt.to_uppercase().contains("UNION ALL"),
            "{name} (init.sql) has a UNION ALL body — only its first SELECT would ever fire"
        );
    }
    for name in OCSF_AGG_MVS.iter().chain(OCSF_PREVALENCE_MVS) {
        let stmt = ocsf
            .get(*name)
            .unwrap_or_else(|| panic!("{name} missing from clickhouse/ocsf/init.sql"));
        assert!(
            !stmt.to_uppercase().contains("UNION ALL"),
            "{name} (ocsf/init.sql) has a UNION ALL body — only its first SELECT would ever fire"
        );
    }
    for (label, mig_sql) in [("migration 128", MIGRATION_128), ("migration 129", MIGRATION_129)] {
        for (name, stmt) in &create_mv_statements(mig_sql) {
            assert!(
                !stmt.to_uppercase().contains("UNION ALL"),
                "{name} ({label}) has a UNION ALL body — only its first SELECT would ever fire"
            );
        }
    }
}

/// The pre-split UNION ALL views (and the superseded 055 process-hash
/// workaround) must not resurface in either init file (fresh bootstraps would
/// recreate the broken / double-counting shape next to the split MVs).
#[test]
fn legacy_union_all_mvs_are_gone() {
    for (label, sql) in [("init.sql", UDM_INIT), ("ocsf/init.sql", OCSF_INIT)] {
        let mvs = create_mv_statements(sql);
        for legacy in LEGACY_MV_NAMES {
            assert!(
                !mvs.contains_key(*legacy),
                "{label} still defines the legacy {legacy}"
            );
        }
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

/// Migration 129 (existing deployments) and the init files (fresh bootstraps)
/// must define byte-equivalent prevalence MVs, or the two paths diverge
/// silently. NAN-1661: migration 129's OCSF prevalence MVs are SUPERSEDED by
/// migration 150 (which retargets them at *_prevalence_agg), so the OCSF-side
/// lockstep moved to `migration_152_matches_init_definitions`; here we only
/// pin the UDM prevalence MVs (129 remains authoritative for those).
#[test]
fn migration_129_matches_init_definitions() {
    let udm = create_mv_statements(UDM_INIT);
    let mig = create_mv_statements(MIGRATION_129);

    for name in UDM_PREVALENCE_MVS {
        assert_eq!(
            mig.get(*name),
            udm.get(*name),
            "{name} differs between migration 129 and clickhouse/init.sql"
        );
    }
    // Migration 129 physically still defines the 7 UDM + 7 (now-superseded)
    // OCSF prevalence MVs; the count documents that full set.
    assert_eq!(
        mig.len(),
        UDM_PREVALENCE_MVS.len() + OCSF_PREVALENCE_MVS.len(),
        "migration 129 defines MVs not covered by the prevalence guard lists"
    );
}

/// NAN-1661: migration 150 (existing deployments) retargets the OCSF prevalence
/// branch MVs from *_prevalence_summary at *_prevalence_agg. Its DDL must be
/// byte-equivalent to the fresh-bootstrap definitions in clickhouse/ocsf/init.sql,
/// or the migrated-vs-fresh OCSF prevalence chains diverge silently.
#[test]
fn migration_152_matches_init_definitions() {
    let ocsf = create_mv_statements(OCSF_INIT);
    let mig = create_mv_statements(MIGRATION_152);

    for name in OCSF_PREVALENCE_MVS {
        assert_eq!(
            mig.get(*name),
            ocsf.get(*name),
            "{name} differs between migration 150 and clickhouse/ocsf/init.sql"
        );
    }
    assert_eq!(
        mig.len(),
        OCSF_PREVALENCE_MVS.len(),
        "migration 150 defines MVs not covered by the OCSF prevalence guard list"
    );
}

/// The OCSF telemetry rollup depends on `event_bytes` (the serialized-event byte
/// count). NAN-1443 ("OCSF lean storage via Null-table + MV") replaced the old
/// MATERIALIZED-at-insert column with a PLAIN column whose value is computed by
/// the ingest MV (`length(toString(event))` off `ocsf_logs_raw`). Two locksteps
/// must hold or fresh-vs-migrated tables diverge:
///   1. the plain column definition is byte-identical in the fresh CREATE TABLE
///      and the existing-tenant overlay ALTER (both in ocsf/init.sql);
///   2. the MV value expression is byte-identical between ocsf/init.sql's ingest
///      MV and the migration-135 promote MV that populates existing tenants.
///
/// Migration 128's earlier `ADD COLUMN … MATERIALIZED` is SUPERSEDED by the
/// NAN-1443 rework and intentionally not asserted: it survives only as an
/// `ADD COLUMN IF NOT EXISTS` no-op once init.sql has created the plain column.
#[test]
fn event_bytes_definitions_in_lockstep() {
    // 1. Plain column — twice in ocsf/init.sql (CREATE TABLE + overlay ALTER).
    let col_def = "`event_bytes` UInt64 CODEC(T64, LZ4)";
    assert_eq!(
        OCSF_INIT.matches(col_def).count(),
        2,
        "ocsf/init.sql must define the plain event_bytes column exactly twice \
         (CREATE TABLE + overlay ALTER); NAN-1443 dropped the MATERIALIZED form"
    );
    // event_bytes is OCSF-only — it must not leak into the UDM schema.
    assert_eq!(
        UDM_INIT.matches(col_def).count(),
        0,
        "event_bytes is an OCSF-only column; it must not appear in clickhouse/init.sql"
    );

    // 2. The MV value expression must be byte-identical in the fresh ingest MV
    //    (ocsf/init.sql) and the migration-135 promote MV.
    let mv_expr = "length(toString(event)) AS `event_bytes`";
    assert_eq!(
        OCSF_INIT.matches(mv_expr).count(),
        1,
        "ocsf/init.sql's ingest MV must compute event_bytes exactly once"
    );
    assert_eq!(
        MIGRATION_135.matches(mv_expr).count(),
        1,
        "migration 135's promote MV must compute event_bytes identically to ocsf/init.sql"
    );
}
