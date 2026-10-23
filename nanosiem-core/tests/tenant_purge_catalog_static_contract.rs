// SPDX-License-Identifier: Proprietary
//! NAN-4052 guard: every table a migration creates in `public` / `nano_shared`
//! with a tenant-like column (the `ILIKE '%tenant%'` rule of
//! `nano_shared.tenant_purge_coverage_gaps()`, 9003420) must be named by a
//! migration that writes `nano_shared.tenant_purge_catalog`. Without that row
//! the gap function reports `unlisted_tenant_column` and `purge_tenant`
//! refuses every offboarding with `coverage_gap` (9013980 shipped exactly
//! that to the region control DBs). Static, no database: runs in plain
//! `cargo test -p nanosiem-core`. The disposable-PG proof of the whole chain
//! is `purge_catalog_covers_the_chain` (scripts/validate-tenant-offboarding.sh).

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Tables created with a tenant column that no catalog migration names, each
/// resolved another way. Do not add to this to silence a new table: register
/// it in `nano_shared.tenant_purge_catalog` (purge / purge_via / exclude /
/// block / secondary, with a reason) in the migration that creates it.
const RESOLVED_ELSEWHERE: &[(&str, &str)] = &[(
    "platform_enrichment_audit",
    "9001400 renames it to platform_enrichment_audit_legacy and moves the data to the catalogued _daily table",
)];

fn migrations() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = Vec::new();
    for dir in ["migrations/postgres", "migrations/postgres-enterprise"] {
        let mut files: Vec<_> = std::fs::read_dir(root.join(dir)).unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, std::fs::read_to_string(&path).unwrap()));
        }
    }
    assert!(out.len() > 300, "the scan must see both migration trees: {}", out.len());
    out
}

fn strip_line_comments(sql: &str) -> String {
    sql.lines().map(|l| l.split("--").next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

/// The column-definition list of a `CREATE TABLE … (` starting at `open`.
fn body(sql: &str, open: usize) -> &str {
    let mut depth = 1;
    for (i, c) in sql[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &sql[open..open + i];
                }
            }
            _ => {}
        }
    }
    &sql[open..]
}

/// The leading identifier of each top-level comma-separated item.
fn column_names(columns: &str) -> Vec<String> {
    let (mut items, mut depth, mut start) = (Vec::new(), 0, 0);
    for (i, c) in columns.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                items.push(&columns[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&columns[start..]);
    items.iter()
        .filter_map(|item| item.split_whitespace().next())
        .map(|name| name.trim_matches('"').to_lowercase())
        .collect()
}

/// Every table name a migration that touches the catalog quotes.
fn catalogued(files: &[(String, String)]) -> BTreeSet<String> {
    let literal = Regex::new(r"'([a-z_][a-z0-9_]*)'").unwrap();
    files.iter()
        .filter(|(_, sql)| sql.contains("tenant_purge_catalog"))
        .flat_map(|(_, sql)| literal.captures_iter(sql).map(|c| c[1].to_string()).collect::<Vec<_>>())
        .collect()
}

/// Tables created in public / nano_shared with a tenant-like column → first migration.
fn tenant_tables(files: &[(String, String)]) -> BTreeMap<String, String> {
    let create = Regex::new(
        r#"(?i)CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"?([a-z_][a-z0-9_]*)"?\.)?"?([a-z_][a-z0-9_]*)"?\s*\("#,
    ).unwrap();
    let mut out = BTreeMap::new();
    for (name, raw) in files {
        let sql = strip_line_comments(raw);
        for m in create.captures_iter(&sql) {
            let schema = m.get(1).map_or("public".to_string(), |s| s.as_str().to_lowercase());
            let table = m[2].to_lowercase();
            if schema != "public" && schema != "nano_shared" {
                continue;
            }
            let columns = body(&sql, m.get(0).unwrap().end());
            if column_names(columns).iter().any(|c| c.contains("tenant")) {
                out.entry(table).or_insert_with(|| name.clone());
            }
        }
    }
    out
}

#[test]
fn every_tenant_table_a_migration_creates_has_a_purge_catalog_row() {
    let files = migrations();
    let catalogued = catalogued(&files);
    let tables = tenant_tables(&files);
    assert!(tables.contains_key("lake_cell_writer_leases"), "the scan must see 9013980's table");
    assert!(catalogued.contains("tenant_ti_providers"), "the scan must see 9013550's catalog rows");
    let resolved: BTreeMap<_, _> = RESOLVED_ELSEWHERE.iter().copied().collect();
    let missing: Vec<_> = tables.iter()
        .filter(|(table, _)| !catalogued.contains(*table) && !resolved.contains_key(table.as_str()))
        .map(|(table, file)| format!("{file}: {table}"))
        .collect();
    assert!(missing.is_empty(),
        "tenant tables with no nano_shared.tenant_purge_catalog row (purge_tenant would refuse with coverage_gap):\n{}\n\
         Register each in tenant_purge_catalog in its migration (see 9014000).", missing.join("\n"));
    for (table, reason) in RESOLVED_ELSEWHERE {
        assert!(tables.contains_key(*table), "{table} is no longer created by any migration; drop it from RESOLVED_ELSEWHERE");
        assert!(!catalogued.contains(*table), "{table} is catalogued now; drop it from RESOLVED_ELSEWHERE");
        assert!(!reason.is_empty());
    }
}
