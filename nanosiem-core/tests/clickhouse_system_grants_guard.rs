// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5367: `system.*` is readable only with an explicit grant, and each
//! identity's system grants match what the code reads.
//!
//! * `select_from_system_db_requires_grant` is on in the shipped server config
//!   (Compose / role-split `clickhouse/config.d`, Helm `server.json`).
//! * The runtime user's system grants are exactly [`RUNTIME_SYSTEM_GRANTS`]
//!   (users.d XML), and migration 200 carries the ones SQL-created runtime
//!   users need.
//! * Every system table named in non-test Rust code is mapped: always
//!   readable, granted to the runtime user, read only by the admin identity,
//!   or not a table read at all. A new `system.<x>` read fails here until it
//!   is mapped (and granted when the runtime user, or the remote half of an
//!   admin `cluster()` probe, reads it).
//! * The raw-SQL users hold no system grant at all (no `system.query_log`,
//!   no `system.users`), and nobody but the admin identity reads
//!   `system.query_log.query` or `system.users`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Readable by any user even with the setting on (ClickHouse 26.10,
/// verified against the shipped config): rows are filtered to what the user
/// may SHOW, or the table is constant.
const ALWAYS_READABLE: &[&str] = &["one", "tables", "columns", "databases", "settings", "functions"];

/// The runtime user's (`nanosiem`) system grants: table -> columns ("*" =
/// table-level). Each read: directly by the app, or as the remote half of an
/// admin cluster()/clusterAllReplicas() probe (remote_servers authenticate
/// as the runtime user).
const RUNTIME_SYSTEM_GRANTS: &[(&str, &[&str])] = &[
    // SIEM Health (storage, ingestion), retention, tiering, disk pressure,
    // shard skew, lookup sizes.
    ("parts", &["bytes_on_disk", "rows", "data_uncompressed_bytes", "partition", "database", "table", "active", "disk_name"]),
    // Disk pressure (free space, tiering detection).
    ("disks", &["total_space", "free_space", "type", "name"]),
    ("storage_policies", &["policy_name", "volume_priority", "disks"]),
    // SIEM Health insert integrity. Never the `query` text.
    ("query_log", &["type", "query_kind", "event_time", "tables"]),
    // SIEM Health insert integrity + shard skew.
    ("part_log", &["event_type", "event_time", "database", "table", "event_date", "rows", "part_name"]),
    ("errors", &["name", "value", "last_error_time"]),
    // Shard skew (NAN-5342).
    ("metric_log", &["event_date", "event_time", "metrics", "CurrentMetric_BackgroundMergesAndMutationsPoolTask", "CurrentMetric_BackgroundMergesAndMutationsPoolSize"]),
    ("asynchronous_metric_log", &["event_date", "event_time", "metric", "value"]),
    ("replication_queue", &["database", "type"]),
    // SIEM Health dictionary status, prevalence dict monitor.
    ("dictionaries", &["database", "name", "status", "last_exception", "type", "element_count", "bytes_allocated"]),
    ("server_settings", &["name", "value"]),
    ("asynchronous_insert_log", &["event_time", "database", "table", "status", "exception"]),
    // SIEM Health / ingest watchdog / prevalence view freshness.
    ("view_refreshes", &["database", "view", "exception", "retry", "last_success_time", "last_refresh_time", "status", "next_refresh_time"]),
    // Search cancel / progress (KILL needs table-level).
    ("processes", &["*"]),
    // SIEM Health async-forward backlog.
    ("distribution_queue", &["database", "table", "data_files", "error_count", "last_exception"]),
    // Ingest-pause guard state on every replica.
    ("settings_profiles", &["name"]),
    // Raw-SQL audit row-policy convergence on every replica.
    ("row_policies", &["short_name", "database", "table", "select_filter", "is_restrictive", "apply_to_all", "apply_to_list", "apply_to_except"]),
    // Cluster-name convergence at boot, ingest watchdog replica discovery.
    ("clusters", &["cluster", "shard_num", "replica_num", "host_name", "database_replica_name"]),
    // getMacro('replica') in the clustered refresh-activation probe.
    ("macros", &["macro", "substitution"]),
];

/// Read only by the admin identity on its local node (admin holds ALL):
/// migrator user/profile bootstrap, ingest watchdog pressure samples.
const ADMIN_ONLY: &[&str] = &["users", "scheduler", "asynchronous_inserts", "metrics"];

/// `system.<x>` tokens in code that are not reads of a system table: OCSF
/// field paths (`device.os.system.*`, `autonomous_system.number`), operator
/// messages and comments, and the raw-SQL validator's rejection tests.
const NOT_READS: &[&str] = &[
    "number", "name", "cpu", "memory", "network", "clone", "grants", "stack_trace",
    "distributed_ddl_queue",
];

fn grant_columns(stmt: &str) -> Option<(String, BTreeSet<String>)> {
    let re = regex::Regex::new(r"(?i)^GRANT(?:\s+ON CLUSTER \S+)?\s+SELECT(?:\(([^)]*)\))?\s+ON\s+system\.([a-z_]+)").unwrap();
    let c = re.captures(stmt.trim())?;
    let cols = match c.get(1) {
        Some(m) => m.as_str().split(',').map(|s| s.trim().trim_matches('`').to_string()).collect(),
        None => BTreeSet::from(["*".to_string()]),
    };
    Some((c[2].to_string(), cols))
}

/// `<query>` grants of one user in a users.d XML.
fn xml_user_queries(xml: &str, user: &str) -> Vec<String> {
    let block = xml
        .split(&format!("<{user}>"))
        .nth(1)
        .and_then(|b| b.split(&format!("</{user}>")).next())
        .unwrap_or_else(|| panic!("user {user} not in users.d"));
    block
        .split("<query>")
        .skip(1)
        .filter_map(|q| q.split("</query>").next())
        .map(|q| q.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

fn system_grants(queries: &[String]) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for q in queries {
        if let Some((table, cols)) = grant_columns(q) {
            out.entry(table).or_default().extend(cols);
        }
    }
    out
}

fn expected_runtime() -> BTreeMap<String, BTreeSet<String>> {
    RUNTIME_SYSTEM_GRANTS
        .iter()
        .map(|(t, cols)| (t.to_string(), cols.iter().map(|c| c.to_string()).collect()))
        .collect()
}

#[test]
fn server_config_requires_grants_for_system_and_information_schema() {
    let xml = read("clickhouse/config.d/access_control.xml");
    assert!(xml.contains("<select_from_system_db_requires_grant>true</select_from_system_db_requires_grant>"));
    assert!(xml.contains(
        "<select_from_information_schema_requires_grant>true</select_from_information_schema_requires_grant>"
    ));
    if let Ok(json) = std::fs::read_to_string(repo_root().join("deploy/helm/nano/files/clickhouse/server.json")) {
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["access_control_improvements"]["select_from_system_db_requires_grant"], "true",
            "Helm server.json must carry access_control.xml (run deploy/helm/nano/scripts/sync-files.sh)"
        );
    }
    let render = std::fs::read_to_string(repo_root().join("deploy/compose/render-inventory.py")).unwrap_or_default();
    if !render.is_empty() {
        assert!(
            !render.contains("\"access_control.xml\""),
            "role-split copies every clickhouse/config.d file; access_control.xml must not be excluded"
        );
    }
}

#[test]
fn runtime_system_grants_are_exactly_the_mapped_reads() {
    let xml = read("clickhouse/users.d/nanosiem-users.xml");
    let have = system_grants(&xml_user_queries(&xml, "nanosiem"));
    assert_eq!(have, expected_runtime(), "nanosiem's system grants drifted from RUNTIME_SYSTEM_GRANTS");
    // The Ludus lab copy carries the same runtime user (NAN-5367 review).
    if let Ok(ludus) =
        std::fs::read_to_string(repo_root().join("ludus/roles/nanosiem_stack/files/clickhouse/users.d/nanosiem-users.xml"))
    {
        assert_eq!(
            system_grants(&xml_user_queries(&ludus, "nanosiem")),
            expected_runtime(),
            "ludus nanosiem-users.xml runtime system grants drifted from clickhouse/users.d"
        );
    }
    assert!(
        !have["query_log"].contains("query") && !have["query_log"].contains("*"),
        "the runtime user must never read other users' SQL text"
    );
    assert!(!have.contains_key("users") && !have.contains_key("grants") && !have.contains_key("quotas"));
}

/// Exactly what migration 200 adds for SQL-created runtime users: the eight
/// system reads that had no grant before NAN-5367.
const MIGRATION_200_DELTA: &[(&str, &[&str])] = &[
    ("disks", &["name"]),
    ("storage_policies", &["policy_name", "volume_priority", "disks"]),
    ("parts", &["disk_name"]),
    ("distribution_queue", &["database", "table", "data_files", "error_count", "last_exception"]),
    ("settings_profiles", &["name"]),
    ("row_policies", &["short_name", "database", "table", "select_filter", "is_restrictive", "apply_to_all", "apply_to_list", "apply_to_except"]),
    ("clusters", &["cluster", "shard_num", "replica_num", "host_name", "database_replica_name"]),
    ("macros", &["macro", "substitution"]),
];

#[test]
fn migration_200_reconciles_sql_created_runtime_users() {
    let sql = read("clickhouse/200_system_read_grants.sql");
    let stmts: Vec<String> = sql
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join(" ")
        .split(';')
        .map(|s| s.replace("{grant_on_cluster}", "").split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect();
    assert!(stmts.iter().all(|s| s.contains("TO {clickhouse_runtime_user}")), "{stmts:#?}");
    let granted = system_grants(&stmts);
    let expected: BTreeMap<String, BTreeSet<String>> = MIGRATION_200_DELTA
        .iter()
        .map(|(t, cols)| (t.to_string(), cols.iter().map(|c| c.to_string()).collect()))
        .collect();
    assert_eq!(granted, expected, "migration 200 must grant exactly the NAN-5367 delta");
    assert_eq!(stmts.len(), MIGRATION_200_DELTA.len(), "one GRANT per delta table");
    // Every delta grant is also in the XML runtime user (users.d users can't
    // receive a SQL GRANT).
    let runtime = expected_runtime();
    for (table, cols) in &expected {
        assert!(cols.is_subset(&runtime[table]), "system.{table} delta missing from RUNTIME_SYSTEM_GRANTS");
    }
}

#[test]
fn ingest_and_raw_sql_users_hold_no_system_grant() {
    let xml = read("clickhouse/users.d/nanosiem-users.xml");
    for user in ["nanosiem_rawsql", "nanosiem_rawsql_noaudit", "nanosiem_vector", "nanosiem_ingest"] {
        let queries = xml_user_queries(&xml, user);
        assert!(!queries.is_empty(), "{user} has no grants block (would default to ALL)");
        for q in &queries {
            assert!(
                !q.contains(" system.") && !q.contains("*.*") && !q.to_uppercase().contains("SHOW USERS"),
                "{user} must not read system tables / users: {q}"
            );
        }
    }
    // The k8s / Helm copies of the same users (Helm is generated from this XML).
    if let Ok(json) = std::fs::read_to_string(repo_root().join("deploy/helm/nano/files/clickhouse/users.json")) {
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        for user in ["nanosiem_rawsql", "nanosiem_rawsql_noaudit", "nanosiem_vector", "nanosiem_ingest"] {
            for q in v["users"][user]["grants"]["query"].as_array().unwrap() {
                assert!(!q.as_str().unwrap().contains(" system."), "helm {user}: {q}");
            }
        }
        let helm_runtime: Vec<String> = v["users"]["nanosiem"]["grants"]["query"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| q.as_str().unwrap().to_string())
            .collect();
        assert_eq!(system_grants(&helm_runtime), expected_runtime(), "helm users.json drifted (run sync-files.sh)");
    }
}

/// System tables named by non-test Rust code: `system.<x>` literals plus
/// the cluster-probe helpers that take the bare table name.
fn system_tables_read_by_code() -> BTreeMap<String, Vec<String>> {
    let literal = regex::Regex::new(r"system\.([a-z_]+)").unwrap();
    let helper =
        regex::Regex::new(r#"(?:probe_source|all_replicas_system|cluster_source)\([^()]*?"([a-z_]+)"\s*\)"#).unwrap();
    // Functions that read a system table under select_from_system_db_requires_grant
    // (verified on ClickHouse 26.10): getMacro -> system.macros,
    // getServerSetting -> system.server_settings.
    let functions = [("getMacro(", "macros"), ("getServerSetting(", "server_settings")];
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stack = Vec::new();
    for entry in std::fs::read_dir(repo_root()).unwrap().filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("nanosiem-") && entry.path().join("src").is_dir() {
            stack.push(entry.path().join("src"));
        }
    }
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.is_dir() {
                if name != "tests" {
                    stack.push(path);
                }
                continue;
            }
            if !name.ends_with(".rs") || name.ends_with("_test.rs") || name.ends_with("_tests.rs") || name == "tests.rs"
            {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            // Drop inline #[cfg(test)] modules (everything after the marker).
            let src = src.split("#[cfg(test)]").next().unwrap_or("");
            let rel = path.strip_prefix(repo_root()).unwrap_or(&path).display().to_string();
            for re in [&literal, &helper] {
                for c in re.captures_iter(src) {
                    out.entry(c[1].to_string()).or_default().push(rel.clone());
                }
            }
            for (needle, table) in functions {
                if src.contains(needle) {
                    out.entry(table.to_string()).or_default().push(rel.clone());
                }
            }
        }
    }
    out
}

#[test]
fn every_system_table_the_code_reads_is_mapped() {
    let reads = system_tables_read_by_code();
    let granted: BTreeSet<&str> = RUNTIME_SYSTEM_GRANTS.iter().map(|(t, _)| *t).collect();
    let mut unmapped = Vec::new();
    for (table, files) in &reads {
        let t = table.as_str();
        if !(ALWAYS_READABLE.contains(&t) || granted.contains(t) || ADMIN_ONLY.contains(&t) || NOT_READS.contains(&t)) {
            let mut files = files.clone();
            files.dedup();
            unmapped.push(format!("system.{table} ({})", files.join(", ")));
        }
    }
    assert!(
        unmapped.is_empty(),
        "system tables read by code but not mapped in clickhouse_system_grants_guard.rs. Grant them to \
         the runtime user (users.d/nanosiem-users.xml + a migration) or classify them: {unmapped:#?}"
    );
    // No stale entries: every mapped table is still named somewhere.
    for t in ADMIN_ONLY.iter().chain(NOT_READS).chain(granted.iter()) {
        assert!(reads.contains_key(*t), "system.{t} is mapped but no longer read by code; drop it from the map");
    }
}
