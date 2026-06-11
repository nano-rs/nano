// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF Phase 0 (NAN-1242) — manifest ⟷ DDL consistency gate.
//!
//! The promotion manifest (`docs/ocsf/1.8.0/udm_ocsf_mapping.json`) and the
//! canonical DDL (`clickhouse/ocsf/init.sql`) are two hand-maintained artifacts
//! that MUST stay in lock-step: the DDL is the mechanical realization of the
//! manifest, and in Phase 4 the `OcsfProfile` is generated from the manifest.
//! If they drift, the query layer and the physical table silently disagree
//! (wrong / empty results, never an error — exactly the silent-bug class this
//! gate exists to prevent).
//!
//! This test is PURE (no ClickHouse) and always runs in CI. The companion
//! `ocsf_materialization_integration` test proves the DDL's JSONExtract
//! expressions actually produce the right values against a live CH.
//!
//! NAMING (NAN-1242): promoted columns use literal dotted OCSF paths
//! (`src_endpoint.ip`, `actor.process.cmd_line`). `_search` companions append a
//! `.search` SUFFIX to the base column (`actor.process.cmd_line.search`), not an
//! underscore. Array-derived columns that select by a STRING key (enrichments[]
//! by `name`) carry `array_key.key_value_str` instead of the int `key_value`.

use std::collections::{BTreeMap, BTreeSet};

/// Legacy `<col>.search` companion suffix. No such columns exist anymore
/// (NAN-1241 moved full-text to expression indexes); retained so the orphan /
/// stray-column guard tests still reject any regression that re-adds one.
const SEARCH_SUFFIX: &str = ".search";

/// Full-text search no longer materializes a `<col>.search` companion column
/// (NAN-1241): the text skip index is attached to the SAME expression the query
/// generator emits, so it actually prunes. Post-NAN-1247 the generator emits
/// `lower(<col>)` for full-text on any plain String column (message included);
/// only ext/JSON/numeric fields get the `toString` wrapper. Every OCSF full-text
/// field is a promoted String column, so the expected index expression is:
fn expected_search_index_expr(ch_column_name: &str) -> String {
    if ch_column_name == "message" {
        "lower(message)".to_string()
    } else {
        format!("lower(`{ch_column_name}`)")
    }
}

/// Extract the indexed EXPRESSION from every `INDEX <name> <expr> TYPE text(...)`
/// line in the DDL (the text/full-text skip indexes), normalized on whitespace.
fn ddl_text_index_exprs(ddl: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for line in ocsf_logs_table_body(ddl).lines() {
        let t = line.trim().trim_end_matches(',');
        let Some(after_index) = t.strip_prefix("INDEX ") else {
            continue;
        };
        // "<name> <expr> TYPE text(...)" — drop the index name, then take the
        // expression up to ` TYPE text`.
        let Some((_name, expr_and_type)) = after_index.split_once(' ') else {
            continue;
        };
        if let Some(expr) = expr_and_type.split(" TYPE text").next() {
            if expr_and_type.contains(" TYPE text") {
                set.insert(expr.trim().to_string());
            }
        }
    }
    set
}

const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/1.8.0/udm_ocsf_mapping.json"
));
const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

/// Columns the DDL owns for bookkeeping/ingest that legitimately have no
/// manifest promotion entry. Hoisted to
/// `nanosiem_core::schema::OCSF_BOOKKEEPING_COLUMNS` (NAN-1397) so the
/// field-stats inventory regression tests consume the SAME registry this gate
/// enforces — see the const's doc for the per-column rationale.
const BOOKKEEPING: &[&str] = nanosiem_core::schema::OCSF_BOOKKEEPING_COLUMNS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Materialized,
    Alias,
    Default,
    Plain,
}

#[derive(Debug, Clone)]
struct DdlColumn {
    ty: String,
    kind: Kind,
}

/// Collapse a ClickHouse type to its comparable base identifier:
/// `LowCardinality(String)` → `String`, `DateTime64(3, 'UTC')` → `DateTime64`,
/// `Nullable(UInt8)` → `UInt8`. Codecs/precision/timezone are intentionally
/// ignored — we gate on type *kind* (String vs UInt vs DateTime), not on
/// storage-tuning details that legitimately differ between manifest and DDL.
fn normalize_base(ty: &str) -> String {
    let t = ty.trim().trim_end_matches(',').trim();
    for wrap in ["LowCardinality", "Nullable"] {
        let prefix = format!("{wrap}(");
        if let Some(inner) = t.strip_prefix(&prefix) {
            if let Some(inner) = inner.strip_suffix(')') {
                return normalize_base(inner);
            }
        }
    }
    t.split('(').next().unwrap_or(t).trim().to_string()
}

/// Slice the DDL down to just the `nanosiem.ocsf_logs` CREATE TABLE body (from
/// the CREATE line up to its terminating `ENGINE =`). The file also contains the
/// schema-agnostic prevalence infrastructure (summary tables, dicts) and the OCSF
/// prevalence summary MVs (NAN-1248) — those statements carry backtick-quoted
/// column references inside SELECTs (e.g. `\`src_endpoint.ip\` AS ip`) that the
/// naive line parser would misread as column declarations. The manifest⟷DDL gate
/// only concerns the `ocsf_logs` promoted columns, so we parse just that block.
fn ocsf_logs_table_body(ddl: &str) -> &str {
    let start = ddl
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs")
        .expect("ocsf_logs CREATE TABLE must exist");
    let rest = &ddl[start..];
    // The column/index list ends at the table's ENGINE clause; everything after
    // (PARTITION/ORDER/SETTINGS, then the appended prevalence statements) is out
    // of scope for column parsing.
    let end = rest.find("ENGINE =").unwrap_or(rest.len());
    &rest[..end]
}

/// Parse every `\`name\` <Type> [MATERIALIZED|ALIAS|DEFAULT ...]` column line out
/// of the CREATE TABLE body. Multi-line MATERIALIZED expressions are fine — we
/// only read name + type + kind from the column's opening line. Lines that
/// don't start with a backtick (INDEX, ORDER BY, settings, comments) are skipped.
fn parse_ddl_columns(ddl: &str) -> BTreeMap<String, DdlColumn> {
    let mut out = BTreeMap::new();
    for raw in ocsf_logs_table_body(ddl).lines() {
        let line = raw.trim();
        let Some(after_tick) = line.strip_prefix('`') else {
            continue;
        };
        let Some(end) = after_tick.find('`') else {
            continue;
        };
        let name = after_tick[..end].to_string();
        let rest = after_tick[end + 1..].trim();

        // Accumulate whitespace-separated tokens into the type until parens
        // balance (handles `DateTime64(3, 'UTC')` which contains a space).
        let mut toks = rest.split_whitespace();
        let mut ty = String::new();
        for tok in toks.by_ref() {
            if !ty.is_empty() {
                ty.push(' ');
            }
            ty.push_str(tok);
            if ty.matches('(').count() <= ty.matches(')').count() {
                break;
            }
        }
        let ty = ty.trim_end_matches(',').trim().to_string();

        let kind = match toks.next() {
            Some("MATERIALIZED") => Kind::Materialized,
            Some("ALIAS") => Kind::Alias,
            Some("DEFAULT") => Kind::Default,
            _ => Kind::Plain,
        };

        out.insert(name, DdlColumn { ty, kind });
    }
    out
}

#[derive(Debug, Clone)]
struct ManifestEntry {
    ch_column_name: String,
    ch_type: String,
    is_search_col: bool,
}

fn parse_manifest() -> Vec<ManifestEntry> {
    let v: serde_json::Value =
        serde_json::from_str(MANIFEST).expect("udm_ocsf_mapping.json must be valid JSON");
    let arr = v.as_array().expect("manifest must be a JSON array");
    arr.iter()
        .map(|e| ManifestEntry {
            ch_column_name: e["ch_column_name"]
                .as_str()
                .expect("every entry needs ch_column_name")
                .to_string(),
            ch_type: e["ch_type"]
                .as_str()
                .expect("every entry needs ch_type")
                .to_string(),
            is_search_col: e["is_search_col"].as_bool().unwrap_or(false),
        })
        .collect()
}

/// Every promoted column named in the manifest must exist in the DDL.
#[test]
fn every_manifest_column_exists_in_ddl() {
    let ddl = parse_ddl_columns(DDL);
    let missing: Vec<String> = parse_manifest()
        .iter()
        .filter(|e| !ddl.contains_key(&e.ch_column_name))
        .map(|e| e.ch_column_name.clone())
        .collect();
    assert!(
        missing.is_empty(),
        "manifest columns absent from clickhouse/ocsf/init.sql: {missing:?}"
    );
}

/// A manifest entry that declares `is_search_col` must have a text skip index on
/// the exact expression the query generator emits for full-text on that field
/// (NAN-1241). This is what makes full-text hunts index-pruned; a mismatch (e.g.
/// an index on a stored `<col>.search` column while codegen queries the
/// expression) silently degrades to a full scan.
#[test]
fn search_companions_exist_for_search_columns() {
    let exprs = ddl_text_index_exprs(DDL);
    // Guard against regressing to the dead-index design: no stored `.search`
    // companion column should exist anymore.
    let ddl_cols = parse_ddl_columns(DDL);
    let mut problems = Vec::new();
    for e in parse_manifest().iter().filter(|e| e.is_search_col) {
        let expected = expected_search_index_expr(&e.ch_column_name);
        if !exprs.contains(&expected) {
            problems.push(format!("{} (no text index on `{expected}`)", e.ch_column_name));
        }
        let stale_col = format!("{}.search", e.ch_column_name);
        if ddl_cols.contains_key(&stale_col) {
            problems.push(format!("{stale_col} (stale stored .search column — should be dropped)"));
        }
    }
    assert!(
        problems.is_empty(),
        "is_search_col entries without a matching text index on the codegen expression: {problems:?}"
    );
}

/// No orphan promotions: every non-`_search` MATERIALIZED column in the DDL must
/// trace back to a manifest entry (or be bookkeeping). Catches a column added to
/// the DDL without recording it in the manifest — which would make Phase 4's
/// generated `OcsfProfile` blind to a real physical column.
#[test]
fn no_materialized_columns_missing_from_manifest() {
    let ddl = parse_ddl_columns(DDL);
    let manifest_cols: BTreeSet<String> = parse_manifest()
        .into_iter()
        .map(|e| e.ch_column_name)
        .collect();
    let bookkeeping: BTreeSet<&str> = BOOKKEEPING.iter().copied().collect();

    let orphans: Vec<String> = ddl
        .iter()
        .filter(|(name, c)| {
            c.kind == Kind::Materialized
                && !name.ends_with(SEARCH_SUFFIX)
                && !manifest_cols.contains(name.as_str())
                && !bookkeeping.contains(name.as_str())
        })
        .map(|(name, _)| name.clone())
        .collect();
    assert!(
        orphans.is_empty(),
        "DDL MATERIALIZED columns with no manifest entry: {orphans:?}"
    );
}

/// Every `_search` MATERIALIZED column must correspond to a manifest entry that
/// actually declared `is_search_col` — no stray search columns.
#[test]
fn search_columns_trace_back_to_search_entries() {
    let ddl = parse_ddl_columns(DDL);
    let search_stems: BTreeSet<String> = parse_manifest()
        .into_iter()
        .filter(|e| e.is_search_col)
        .map(|e| e.ch_column_name)
        .collect();

    let strays: Vec<String> = ddl
        .iter()
        .filter(|(name, c)| c.kind == Kind::Materialized && name.ends_with(SEARCH_SUFFIX))
        .filter_map(|(name, _)| {
            let stem = name.strip_suffix(SEARCH_SUFFIX).unwrap();
            (!search_stems.contains(stem)).then(|| name.clone())
        })
        .collect();
    assert!(
        strays.is_empty(),
        "_search columns with no is_search_col manifest entry: {strays:?}"
    );
}

/// The CH type kind must agree between manifest and DDL for every promoted
/// column. Gates gross drift (e.g. a column silently changing String→UInt)
/// while tolerating LowCardinality/codec/precision differences.
#[test]
fn column_types_agree_between_manifest_and_ddl() {
    let ddl = parse_ddl_columns(DDL);
    let mut mismatches = Vec::new();
    for e in parse_manifest() {
        let Some(col) = ddl.get(&e.ch_column_name) else {
            continue; // presence is asserted by every_manifest_column_exists_in_ddl
        };
        let want = normalize_base(&e.ch_type);
        let got = normalize_base(&col.ty);
        if want != got {
            mismatches.push(format!(
                "{}: manifest={} ddl={} (base {want} != {got})",
                e.ch_column_name, e.ch_type, col.ty
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "manifest⟷DDL type-kind mismatches: {mismatches:#?}"
    );
}

/// `activity_id` is intentionally shared by two manifest entries (taxonomy
/// `event_type` and `file_action`). If they ever disagree on the physical
/// column or type, the shared-column assumption is broken.
#[test]
fn shared_columns_are_self_consistent() {
    let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in parse_manifest() {
        by_name
            .entry(e.ch_column_name)
            .or_default()
            .insert(normalize_base(&e.ch_type));
    }
    let conflicts: Vec<String> = by_name
        .iter()
        .filter(|(_, types)| types.len() > 1)
        .map(|(name, types)| format!("{name}: {types:?}"))
        .collect();
    assert!(
        conflicts.is_empty(),
        "columns shared across manifest entries with conflicting types: {conflicts:?}"
    );
}
