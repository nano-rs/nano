// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5271 #23: OCSF prevalence covers the parent/actor process hash and the
//! HTTP request URL host.
//!
//! Pinned here:
//! 1. ocsf/197 creates the four new producer views with bodies identical to
//!    clickhouse/ocsf/init.sql, and its two `MODIFY COLUMN` expressions are
//!    identical to the generated `ocsf_logs` columns (fresh == upgraded);
//! 2. ocsf/197 is forward-only and idempotent: `CREATE ... IF NOT EXISTS` and
//!    `MODIFY COLUMN` only, no backfill, no DROP, no `MODIFY QUERY`;
//! 3. the new views are `SQL SECURITY DEFINER` (definer = the migrator), so
//!    they never depend on a `nanosiem_ingest` grant. On `helm upgrade` the
//!    migrate hook runs before the ClickHouseCluster CR (which carries the
//!    users.xml grants) is applied, and a failed or rolled-back upgrade keeps
//!    the views but restores the old grants: an invoker view reading an
//!    ungranted column would fail EVERY ingest insert with ACCESS_DENIED. The
//!    test also pins that this PR does not widen the ingest grant instead;
//! 4. the views skip values an existing producer already counts on the same
//!    row, so total_count is not doubled.

const OCSF_INIT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/ocsf/init.sql"));
const MIGRATION_197: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/migrations/197_prevalence_actor_hash_http_domain.sql"
));

/// Every place the `nanosiem_ingest` column-scoped SELECT on `ocsf_logs` is
/// declared (users.d, the Helm chart, the k8s templates), relative to the repo
/// root. Read at RUNTIME, not with `include_str!`: the open-core mirror strips
/// `deploy/`, and a compile-time include of a stripped path makes this test
/// target unbuildable there, failing sync-mirror after a release build
/// (NAN-2169; burned v2.0.16).
const GRANT_FILES: &[&str] = &[
    "clickhouse/users.d/nanosiem-users.xml",
    "deploy/helm/nano/files/clickhouse/users.json",
    "deploy/k8s/clickhouse/clickhouse.yaml",
    "deploy/k8s/aws-db/clickhouse.yaml.tpl",
    "deploy/k8s/rackspace-db/clickhouse.yaml.tpl",
];

/// Reads a repo file. `None` only when the file is genuinely absent AND it lives
/// under `deploy/` (stripped from the open-core mirror); any other IO error, or
/// a missing non-deploy file, panics so the check can't silently go half-green.
fn read_repo_file(rel: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && rel.starts_with("deploy/") => None,
        Err(e) => panic!("{rel}: {e}"),
    }
}

const NEW_MVS: &[&str] = &[
    "ocsf_hash_prevalence_summary_actor_process_hash_mv",
    "ocsf_domain_prevalence_summary_http_url_mv",
    "hash_prevalence_source_ocsf_actor_process_mv",
    "domain_prevalence_source_ocsf_http_url_mv",
];

const MODIFIED_COLUMNS: &[&str] = &["prevalence_process_hash", "prevalence_dest_domain"];

fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Statements of a migration, split the way the migrator does (strip `--`
/// lines, split on `;`).
fn statements(sql: &str) -> Vec<String> {
    sql.lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(normalize)
        .filter(|s| !s.is_empty())
        .collect()
}

fn create_stmt(sql: &str, mv: &str) -> String {
    let needle = format!("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.{mv} ");
    statements(sql)
        .into_iter()
        .find(|s| s.starts_with(&needle))
        .unwrap_or_else(|| panic!("missing CREATE for {mv}"))
}

/// The definition of `<col>` in the overlay's `ocsf_logs` CREATE TABLE,
/// starting at the type, without the trailing comma.
fn overlay_column(col: &str) -> String {
    let needle = format!("`{col}` UInt16 MATERIALIZED ");
    let line = OCSF_INIT
        .lines()
        .find(|l| l.trim_start().starts_with(&needle))
        .unwrap_or_else(|| panic!("overlay has no MATERIALIZED {col}"));
    let def = line.trim().trim_end_matches(',');
    normalize(&def[format!("`{col}` ").len()..])
}

fn migration_column(col: &str) -> String {
    let needle = format!("ALTER TABLE nanosiem.ocsf_logs MODIFY COLUMN `{col}` ");
    let stmt = statements(MIGRATION_197)
        .into_iter()
        .find(|s| s.starts_with(&needle))
        .unwrap_or_else(|| panic!("ocsf/197 does not MODIFY COLUMN {col}"));
    stmt[needle.len()..].to_string()
}

#[test]
fn migration_197_views_match_the_overlay() {
    for mv in NEW_MVS {
        assert_eq!(
            create_stmt(MIGRATION_197, mv),
            create_stmt(OCSF_INIT, mv),
            "{mv}: ocsf/197 and clickhouse/ocsf/init.sql must stay byte-equivalent"
        );
    }
}

#[test]
fn migration_197_columns_match_the_generated_overlay() {
    for col in MODIFIED_COLUMNS {
        assert_eq!(
            migration_column(col),
            overlay_column(col),
            "{col}: ocsf/197 and the generated ocsf_logs column must stay identical (scripts/gen-ocsf-ddl.py)"
        );
    }
    let process = overlay_column("prevalence_process_hash");
    assert!(process.contains("`actor.process.file.hashes.sha256`"));
    let domain = overlay_column("prevalence_dest_domain");
    for col in ["`http_request.url.hostname`", "`url.hostname`", "`query.hostname`"] {
        assert!(domain.contains(col), "prevalence_dest_domain ignores {col}");
    }
}

#[test]
fn migration_197_is_forward_only_and_idempotent() {
    let stmts = statements(MIGRATION_197);
    assert_eq!(stmts.len(), NEW_MVS.len() + MODIFIED_COLUMNS.len(), "ocsf/197 has unexpected statements");
    for s in &stmts {
        let ok = s.starts_with("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.")
            || s.starts_with("ALTER TABLE nanosiem.ocsf_logs MODIFY COLUMN `prevalence_");
        assert!(ok, "ocsf/197 must only create views idempotently or modify prevalence columns: {s}");
        let upper = s.to_uppercase();
        for banned in ["INSERT INTO", "DROP ", "MODIFY QUERY", "MATERIALIZE COLUMN", "POPULATE", "UNION ALL"] {
            assert!(!upper.contains(banned), "ocsf/197 must not contain {banned}: {s}");
        }
    }
}

#[test]
fn new_views_skip_values_existing_producers_already_count() {
    let hash = create_stmt(OCSF_INIT, "ocsf_hash_prevalence_summary_actor_process_hash_mv");
    assert!(hash.contains("lower(`file.hashes.sha256`) != lower(`actor.process.file.hashes.sha256`)"));
    assert!(hash.contains("lower(`process.file.hashes.sha256`) != lower(`actor.process.file.hashes.sha256`)"));
    let dom = create_stmt(OCSF_INIT, "ocsf_domain_prevalence_summary_http_url_mv");
    for col in ["dst_endpoint.hostname", "query.hostname", "url.hostname"] {
        assert!(dom.contains(&format!("lower(`{col}`) != lower(`http_request.url.hostname`)")), "{col}");
    }
    let src_hash = create_stmt(OCSF_INIT, "hash_prevalence_source_ocsf_actor_process_mv");
    for col in ["file.hashes.sha256", "process.file.hashes.sha256"] {
        assert!(src_hash.contains(&format!("lower(`actor.process.file.hashes.sha256`) != lower(`{col}`)")), "{col}");
    }
    let src_dom = create_stmt(OCSF_INIT, "domain_prevalence_source_ocsf_http_url_mv");
    for col in ["dst_endpoint.hostname", "query.hostname", "url.hostname"] {
        assert!(src_dom.contains(&format!("lower(`http_request.url.hostname`) != lower(`{col}`)")), "{col}");
    }
}

const DEFINER_CLAUSE: &str = " DEFINER = CURRENT_USER SQL SECURITY DEFINER AS SELECT ";

#[test]
fn new_views_run_as_definer_so_no_ingest_grant_is_needed() {
    for sql in [MIGRATION_197, OCSF_INIT] {
        for mv in NEW_MVS {
            let stmt = create_stmt(sql, mv);
            assert!(
                stmt.contains(DEFINER_CLAUSE),
                "{mv}: must be `DEFINER = CURRENT_USER SQL SECURITY DEFINER` so ingest inserts never depend on a \
                 nanosiem_ingest grant that Helm applies only after the migrate hook"
            );
        }
    }
}

#[test]
fn ingest_grant_is_not_widened_for_the_new_views() {
    // The definer view is the fix; widening the grant would reintroduce the
    // Helm ordering dependency for the next view that relies on it.
    for path in GRANT_FILES {
        let Some(contents) = read_repo_file(path) else {
            eprintln!("{path}: absent (open-core mirror strips deploy/); skipped");
            continue;
        };
        let grant = contents
            .lines()
            .find(|l| l.contains("GRANT SELECT(`timestamp`") && l.contains("ON nanosiem.ocsf_logs"))
            .unwrap_or_else(|| panic!("{path}: no column-scoped nanosiem_ingest SELECT on ocsf_logs"));
        assert!(
            !grant.contains("`http_request.url.hostname`"),
            "{path}: nanosiem_ingest must not need SELECT on http_request.url.hostname (the 197 views are SQL SECURITY DEFINER)"
        );
    }
}
