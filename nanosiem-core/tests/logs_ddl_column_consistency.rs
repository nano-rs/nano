// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1623 (A2) — `logs` DDL ⟷ Rust column source-of-truth drift gate.
//!
//! The physical `nanosiem.logs` columns live in two hand-maintained places that
//! MUST stay in lock-step with the Rust query layer:
//!   * the ClickHouse DDL — `clickhouse/init.sql` (the base CREATE TABLE) PLUS the
//!     column-adding migrations under `clickhouse/` (e.g. migration 141 adds
//!     `trace_id`/`span_id`), and
//!   * the Rust router/codegen lists — `EXPLICIT_COLUMNS` (the field-router
//!     universe: which names are direct columns vs `ext` JSON) and
//!     `MATERIALIZED_COLUMNS` (the CTE re-add list for columns ClickHouse excludes
//!     from `SELECT *`).
//!
//! If they drift, the failure is SILENT, never an error:
//!   * a physical column absent from `EXPLICIT_COLUMNS` → the router treats it as an
//!     `ext` JSON path, so `col=value` reads `ext.col` (always NULL) and returns
//!     nothing, and
//!   * a MATERIALIZED column missing from `MATERIALIZED_COLUMNS` → a multi-stage CTE
//!     stage that references it fails with CH Code 47 "Unknown identifier" (NAN-1147).
//!
//! This test is PURE (no ClickHouse) and always runs in CI — it parses the DDL
//! text. Modelled on `tests/ocsf_manifest_ddl_consistency.rs`.

use std::collections::BTreeSet;

const INIT_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/init.sql"
));

/// Directory holding the base DDL plus the numbered column/index migrations.
fn clickhouse_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("clickhouse")
}

/// `logs` columns the DDL owns for routing/bookkeeping that legitimately have no
/// query-layer wiring. Reuses the OCSF bookkeeping registry (shared single source
/// of truth, NAN-1397) — for `logs` the overlap is `timestamp` / `_inserted_at` /
/// `source_type` (all also in EXPLICIT_COLUMNS anyway); the OCSF-only names
/// (`event`, `unmapped`, `*_unified`, `event_bytes`) simply don't exist on `logs`.
const BOOKKEEPING: &[&str] = nanosiem_core::schema::OCSF_BOOKKEEPING_COLUMNS;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysCol {
    name: String,
    materialized: bool,
}

/// Strip SQL comments so statement parsing isn't fooled by them:
///   * `-- …` line comments — critical, because `split(';')` glues a statement's
///     leading `-- …` header lines onto the statement text, which would otherwise
///     hide the `ALTER TABLE` prefix; and
///   * `/* … */` block comments — e.g. the `/* nano:skip-if-unknown-table */`
///     markers on the OCSF ALTERs.
/// (None of these migrations carry `--` or `/* */` inside string literals.)
fn strip_sql_comments(s: &str) -> String {
    // Line comments first, line by line.
    let mut no_line: String = String::with_capacity(s.len());
    for line in s.lines() {
        let kept = match line.find("--") {
            Some(idx) => &line[..idx],
            None => line,
        };
        no_line.push_str(kept);
        no_line.push('\n');
    }
    // Then block comments.
    let mut out = String::with_capacity(no_line.len());
    let bytes = no_line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            if let Some(end) = no_line[i + 2..].find("*/") {
                i = i + 2 + end + 2;
                out.push(' ');
                continue;
            }
            break;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// `true` if the line/remainder carries a standalone `MATERIALIZED` keyword. The
/// keyword never appears inside a column type or a MATERIALIZED expression in these
/// DDLs, so a whitespace-token match is unambiguous. (ALIAS/DEFAULT are NOT
/// materialized and excluded from the CTE re-add set.)
fn is_materialized(decl_after_name: &str) -> bool {
    decl_after_name
        .split_whitespace()
        .any(|t| t == "MATERIALIZED")
}

/// Read the `\`name\`` immediately following a position (skips an optional
/// `IF NOT EXISTS`). Returns the unquoted column name and the byte offset just
/// past the closing backtick.
fn read_backtick_name(s: &str) -> Option<(String, usize)> {
    let start = s.find('`')?;
    let rest = &s[start + 1..];
    let end = rest.find('`')?;
    Some((rest[..end].to_string(), start + 1 + end + 1))
}

/// Parse the base `CREATE TABLE IF NOT EXISTS nanosiem.logs` body in init.sql.
fn parse_logs_create_table(ddl: &str) -> Vec<PhysCol> {
    let anchor = "CREATE TABLE IF NOT EXISTS nanosiem.logs\n";
    let start = ddl.find(anchor).expect("logs CREATE TABLE must exist");
    let rest = &ddl[start..];
    // The column/index list ends at the table's line-start ENGINE clause.
    let end = rest.find("\nENGINE =").map(|i| i + 1).unwrap_or(rest.len());
    let body = &rest[..end];

    let mut cols = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        // Only column declarations open with a backtick-quoted identifier; INDEX,
        // ORDER BY, comments, and MATERIALIZED-expression continuation lines don't.
        let Some(after_tick) = line.strip_prefix('`') else {
            continue;
        };
        let Some(end_tick) = after_tick.find('`') else {
            continue;
        };
        let name = after_tick[..end_tick].to_string();
        let remainder = &after_tick[end_tick + 1..];
        cols.push(PhysCol {
            name,
            materialized: is_materialized(remainder),
        });
    }
    cols
}

/// Parse `ALTER TABLE nanosiem.logs ... ADD COLUMN IF NOT EXISTS \`name\` ...`
/// statements out of the numbered migrations. The table token is matched EXACTLY,
/// so statements targeting other tables — `nanosiem.ocsf_logs`,
/// `nanosiem.logs_per_source_5m` (both of which have `nanosiem.logs` as a string
/// prefix) — are ignored, as are ADD INDEX / DROP / MATERIALIZE statements.
fn parse_logs_migration_columns() -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(clickhouse_dir())
        .expect("clickhouse/ dir must exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "sql").unwrap_or(false)
                && p.file_name().map(|n| n != "init.sql").unwrap_or(false)
        })
        .collect();
    files.sort();

    for path in files {
        let sql = std::fs::read_to_string(&path).expect("migration readable");
        let sql = strip_sql_comments(&sql);
        // Statement-split on ';' keeps a multi-line `ALTER TABLE … \n ADD COLUMN …`
        // (migrations 134/141) intact within one statement.
        for stmt in sql.split(';') {
            let norm = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
            let Some(after_alter) = norm.strip_prefix("ALTER TABLE ") else {
                continue;
            };
            // Table name is the token right after `ALTER TABLE`; require EXACT match
            // so `nanosiem.ocsf_logs` / `nanosiem.logs_per_source_5m` are excluded.
            let Some((table, tail)) = after_alter.split_once(' ') else {
                continue;
            };
            if table != "nanosiem.logs" {
                continue;
            }
            // Handle EVERY `ADD COLUMN` clause in the statement, not just the first
            // — a single `ALTER TABLE … ADD COLUMN a …, ADD COLUMN b …;` adds both.
            // (ADD INDEX / DROP / MATERIALIZE statements simply have no match here.)
            for (idx, _) in tail.match_indices("ADD COLUMN") {
                let after_add = &tail[idx + "ADD COLUMN".len()..];
                let Some((name, name_end)) = read_backtick_name(after_add) else {
                    // Bare (un-backticked) ADD COLUMN — not used by live migrations.
                    continue;
                };
                // Bound the declaration to before the NEXT `ADD COLUMN` so a later
                // clause's MATERIALIZED keyword can't leak into this column's kind.
                let decl = &after_add[name_end..];
                let decl_bounded = match decl.find("ADD COLUMN") {
                    Some(p) => &decl[..p],
                    None => decl,
                };
                out.push((name, is_materialized(decl_bounded)));
            }
        }
    }
    out
}

/// Full physical column set of `logs` = base CREATE TABLE + migration ADD COLUMNs,
/// with the MATERIALIZED subset.
fn physical_logs_columns() -> (BTreeSet<String>, BTreeSet<String>) {
    let mut all = BTreeSet::new();
    let mut materialized = BTreeSet::new();
    for c in parse_logs_create_table(INIT_SQL) {
        all.insert(c.name.to_string());
        if c.materialized {
            materialized.insert(c.name.to_string());
        }
    }
    for (name, mat) in parse_logs_migration_columns() {
        if mat {
            materialized.insert(name.clone());
        }
        all.insert(name);
    }
    (all, materialized)
}

/// Sanity: the parser actually found the table and a plausible number of columns,
/// including the migration-only `trace_id`/`span_id` (proves migration-awareness).
#[test]
fn ddl_parse_is_sane() {
    let (all, materialized) = physical_logs_columns();
    assert!(
        all.len() > 120,
        "expected >120 physical logs columns, parsed {}",
        all.len()
    );
    assert!(
        all.contains("trace_id") && all.contains("span_id"),
        "migration-141 trace_id/span_id must be picked up (migration-aware parse)"
    );
    assert!(all.contains("ext"), "ext JSON column must be present");
    // A representative MATERIALIZED column and a representative non-materialized one.
    assert!(materialized.contains("enriched_src_country"));
    assert!(!materialized.contains("src_ip"));
    assert!(!materialized.contains("ext"));
}

/// Every physical `logs` column (except `ext` and the bookkeeping registry) must be
/// declared in `EXPLICIT_COLUMNS`. Catches a column added to the DDL but never wired
/// into the field router (it would silently resolve to `ext.<col>` and return NULL).
#[test]
fn every_physical_logs_column_is_in_explicit_columns() {
    let (all, _) = physical_logs_columns();
    let explicit: BTreeSet<&str> = nanosiem_core::query::EXPLICIT_COLUMNS.iter().copied().collect();
    let bookkeeping: BTreeSet<&str> = BOOKKEEPING.iter().copied().collect();

    let missing: Vec<String> = all
        .iter()
        .filter(|c| c.as_str() != "ext")
        .filter(|c| !bookkeeping.contains(c.as_str()))
        .filter(|c| !explicit.contains(c.as_str()))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "physical logs columns missing from EXPLICIT_COLUMNS (would route to ext JSON \
         and silently return NULL): {missing:?}"
    );
}

/// The reverse direction: every `EXPLICIT_COLUMNS` entry must be a real physical
/// `logs` column (or its ALIAS). Catches a typo'd / stale name added to
/// EXPLICIT_COLUMNS that has no backing column — `col=value` would parse as a direct
/// column reference and blow up / silently mis-resolve at query time.
#[test]
fn every_explicit_column_is_a_physical_logs_column() {
    let (all, _) = physical_logs_columns();
    let orphans: Vec<&str> = nanosiem_core::query::EXPLICIT_COLUMNS
        .iter()
        .copied()
        .filter(|c| !all.contains(*c))
        .collect();
    assert!(
        orphans.is_empty(),
        "EXPLICIT_COLUMNS entries with no physical `logs` column in the DDL: {orphans:?}"
    );
}

/// The DDL's MATERIALIZED column set must EXACTLY equal `MATERIALIZED_COLUMNS`.
/// A MATERIALIZED column missing from the Rust re-add list makes any multi-stage
/// CTE that references it fail with CH Code 47; an extra entry re-adds a column
/// that isn't actually MATERIALIZED (also a Code 47 / projection error).
#[test]
fn ddl_materialized_set_equals_materialized_columns() {
    let (_, ddl_materialized) = physical_logs_columns();
    let rust: BTreeSet<String> = nanosiem_core::query::MATERIALIZED_COLUMNS
        .iter()
        .map(|s| s.to_string())
        .collect();

    let in_ddl_not_rust: Vec<&String> = ddl_materialized.difference(&rust).collect();
    let in_rust_not_ddl: Vec<&String> = rust.difference(&ddl_materialized).collect();
    assert!(
        in_ddl_not_rust.is_empty() && in_rust_not_ddl.is_empty(),
        "MATERIALIZED drift — DDL-only (missing from MATERIALIZED_COLUMNS, will Code 47): \
         {in_ddl_not_rust:?}; Rust-only (re-adds a non-materialized column): {in_rust_not_ddl:?}"
    );
}
