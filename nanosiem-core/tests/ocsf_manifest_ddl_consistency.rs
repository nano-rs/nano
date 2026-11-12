// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4903 — promotion manifest ⟷ generated DDL ⟷ OCSF contract gate.
//!
//! `nanosiem-core/docs/ocsf/events/promoted.json` is the single source of truth
//! for which OCSF paths are typed columns. `scripts/gen-ocsf-ddl.py` renders the
//! `@generated` block of `clickhouse/ocsf/init.sql` from it, and `OcsfProfile`
//! reads it at runtime. This PURE test (no ClickHouse) fails when any of the
//! three disagree:
//!
//! - every manifest path is an attribute of an embedded OCSF contract, with the
//!   same array-ness the contract declares (Array type ⟺ the path crosses an
//!   OCSF array);
//! - every manifest column exists in `ocsf_logs` with the manifest's type, and
//!   every promoted scalar is `SKIP`ped from the stored `event` JSON (stored
//!   once) while arrays of objects are not (the whole object stays in `event`);
//! - every non-bookkeeping column of `ocsf_logs` is known to `OcsfProfile`, so
//!   nothing physical is invisible to nPL;
//! - the `@generated` markers are present (the file came from the generator).
//!   `python3 scripts/gen-ocsf-ddl.py --check` proves byte-equality in CI.

use std::collections::{BTreeMap, BTreeSet};

use nanosiem_core::schema::ocsf_registry;
use nanosiem_core::schema::{OcsfProfile, SchemaProfile, OCSF_BOOKKEEPING_COLUMNS};

const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/events/promoted.json"
));
const JSON_HINTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/events/json_hints.json"
));
const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Plain,
    Materialized,
    Alias,
    Default,
}

#[derive(Debug, Clone)]
struct DdlColumn {
    ty: String,
    kind: Kind,
}

fn normalize_base(ty: &str) -> String {
    let t = ty.trim().trim_end_matches(',').trim();
    for wrap in ["LowCardinality", "Nullable"] {
        if let Some(inner) = t.strip_prefix(&format!("{wrap}(")) {
            if let Some(inner) = inner.strip_suffix(')') {
                return normalize_base(inner);
            }
        }
    }
    t.to_string()
}

fn ocsf_logs_table_body(ddl: &str) -> &str {
    let start = ddl
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs\n")
        .expect("ocsf_logs CREATE TABLE must exist");
    let rest = &ddl[start..];
    let end = rest.find("\nENGINE =").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

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
        let mut toks = after_tick[end + 1..].split_whitespace();
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
        let kind = match toks.next() {
            Some("MATERIALIZED") => Kind::Materialized,
            Some("ALIAS") => Kind::Alias,
            Some("DEFAULT") => Kind::Default,
            _ => Kind::Plain,
        };
        out.insert(name, DdlColumn { ty: ty.trim_end_matches(',').to_string(), kind });
    }
    out
}

fn manifest() -> Vec<serde_json::Value> {
    serde_json::from_str(MANIFEST).expect("promoted.json must be a JSON array")
}

fn event_column_line(ddl: &str) -> &str {
    ocsf_logs_table_body(ddl)
        .lines()
        .find(|l| l.trim_start().starts_with("`event` JSON("))
        .expect("ocsf_logs must store `event` JSON")
}

#[test]
fn ddl_carries_generated_markers() {
    assert!(DDL.contains("-- @generated begin: scripts/gen-ocsf-ddl.py"));
    assert!(DDL.contains("-- @generated end"));
}

#[test]
fn every_manifest_path_is_an_ocsf_attribute_with_matching_arrayness() {
    let mut bad = Vec::new();
    for e in manifest() {
        let path = e["ocsf_path"].as_str().unwrap();
        let ty = e["ch_type"].as_str().unwrap();
        match ocsf_registry::known(path) {
            None => bad.push(format!("{path}: not an OCSF attribute")),
            Some(info) => {
                if info.is_multi_valued() != ty.starts_with("Array(") {
                    bad.push(format!(
                        "{path}: contract multi-valued={} but ch_type={ty}",
                        info.is_multi_valued()
                    ));
                }
            }
        }
    }
    assert!(bad.is_empty(), "manifest/contract drift:\n{}", bad.join("\n"));
}

#[test]
fn every_manifest_column_exists_with_its_type() {
    let cols = parse_ddl_columns(DDL);
    let mut bad = Vec::new();
    for e in manifest() {
        let c = e["ch_column_name"].as_str().unwrap();
        let ty = e["ch_type"].as_str().unwrap();
        match cols.get(c) {
            None => bad.push(format!("{c}: missing from ocsf_logs")),
            Some(d) if normalize_base(&d.ty) != normalize_base(ty) => {
                bad.push(format!("{c}: manifest {ty} vs DDL {}", d.ty))
            }
            Some(d) if d.kind != Kind::Plain => {
                bad.push(format!("{c}: promoted columns are plain (MV-written), got {:?}", d.kind))
            }
            _ => {}
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn promoted_scalars_are_skipped_from_event_and_arrays_are_kept() {
    let line = event_column_line(DDL);
    let mut bad = Vec::new();
    for e in manifest() {
        let p = e["ocsf_path"].as_str().unwrap();
        let skipped = line.contains(&format!("SKIP `{p}`"));
        let array = e["ch_type"].as_str().unwrap().starts_with("Array(");
        if array == skipped {
            bad.push(format!("{p}: array={array} skipped={skipped}"));
        }
    }
    assert!(line.contains("SKIP `unmapped`"), "`unmapped` is stored in its own column");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// JSON type hints (`json_hints.json`, design doc §3.6) are typed paths inside
/// `event`. They must be OCSF scalar strings that are not promoted, with a
/// String-family Nullable type: any JSON value casts to it, so no INSERT or merge
/// can fail on an off-type producer value, and an absent path stays NULL.
#[test]
fn json_hints_are_unpromoted_scalar_strings_typed_in_event() {
    let hints: Vec<serde_json::Value> =
        serde_json::from_str(JSON_HINTS).expect("json_hints.json must be a JSON array");
    assert!(!hints.is_empty());
    let promoted: BTreeSet<String> = manifest()
        .iter()
        .map(|e| e["ocsf_path"].as_str().unwrap().to_string())
        .collect();
    let line = event_column_line(DDL);
    let mut bad = Vec::new();
    for h in &hints {
        let p = h["ocsf_path"].as_str().unwrap();
        let t = h["ch_type"].as_str().unwrap();
        if promoted.contains(p) {
            bad.push(format!("{p}: promoted; a hint would duplicate the column"));
        }
        if !matches!(t, "Nullable(String)" | "LowCardinality(Nullable(String))") {
            bad.push(format!("{p}: ch_type {t} is not a Nullable String type"));
        }
        match ocsf_registry::known(p) {
            None => bad.push(format!("{p}: not an OCSF attribute")),
            Some(info) => {
                if info.is_multi_valued() || info.leaf != ocsf_registry::OcsfLeafType::String {
                    bad.push(format!("{p}: not a scalar string ({:?})", info.leaf));
                }
            }
        }
        if !line.contains(&format!("`{p}` {t},")) {
            bad.push(format!("{p}: not typed as {t} in the event column"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Boot detection (`event_json_hints_in_type`) must find every manifest hint
/// in the generated `event` type, and none in an unhinted one.
#[test]
fn boot_hint_detection_reads_the_generated_event_type() {
    let line = event_column_line(DDL);
    let found = nanosiem_core::schema::event_json_hints_in_type(line);
    let manifest = nanosiem_core::schema::manifest_event_json_hints();
    assert_eq!(found.len(), manifest.len(), "found {found:?}");
    let unhinted = "JSON(max_dynamic_paths = 1024, SKIP `process.name`, SKIP unmapped)";
    assert!(nanosiem_core::schema::event_json_hints_in_type(unhinted).is_empty());
    // system.columns renders simple names unquoted.
    let rendered = "JSON(action LowCardinality(Nullable(String)), `process.file.name` Nullable(String), SKIP unmapped)";
    let got = nanosiem_core::schema::event_json_hints_in_type(rendered);
    assert!(got.contains("action") && got.contains("process.file.name") && got.len() == 2, "{got:?}");
}

#[test]
fn every_physical_column_is_known_to_the_profile() {
    let profile = OcsfProfile::new();
    let bookkeeping: BTreeSet<&str> = OCSF_BOOKKEEPING_COLUMNS.iter().copied().collect();
    let mut bad = Vec::new();
    for (name, col) in parse_ddl_columns(DDL) {
        if bookkeeping.contains(name.as_str()) || name == "id" || name.starts_with("prevalence_") {
            continue;
        }
        if !profile.is_known_field(&name) {
            bad.push(format!("{name} ({:?})", col.kind));
        }
    }
    assert!(bad.is_empty(), "columns invisible to nPL:\n{}", bad.join("\n"));
}

#[test]
fn lowered_flags_drive_the_profile() {
    let profile = OcsfProfile::new();
    for e in manifest() {
        let c = e["ch_column_name"].as_str().unwrap();
        assert_eq!(
            profile.is_lowercased_at_ingest(c),
            e["lowered_at_ingest"].as_bool().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn array_columns_are_profile_arrays() {
    let profile = OcsfProfile::new();
    for e in manifest() {
        let c = e["ch_column_name"].as_str().unwrap();
        let array = e["ch_type"].as_str().unwrap().starts_with("Array(");
        assert_eq!(profile.is_array_field(c), array, "{c}");
    }
}

const MIGRATION_180: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/180_ocsf_version_agnostic_store.sql"
));

fn sql_statements(sql: &str) -> Vec<String> {
    sql.lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// NAN-4903 (codex P0): migration 180 must never drop the data-bearing
/// `ocsf_logs`. It renames it to `ocsf_logs_legacy_v179`, and it drops exactly
/// the data-free objects the overlay recreates: the ingest MVs, the Null
/// landing tables, the Distributed wrapper and EVERY overlay MV that reads
/// `nanosiem.ocsf_logs` (a RENAME carries MV source bindings with the table, so
/// a reader left out here would silently keep reading the frozen legacy table).
#[test]
fn migration_180_preserves_ocsf_logs_and_drops_only_recreated_views() {
    let stmts = sql_statements(MIGRATION_180);
    let mut dropped_views = BTreeSet::new();
    let mut dropped_tables = BTreeSet::new();
    let mut renames = Vec::new();
    for s in &stmts {
        let u = s.to_uppercase();
        let name = |prefix: &str| {
            s[prefix.len()..]
                .trim()
                .split_whitespace()
                .next()
                .unwrap()
                .trim_start_matches("nanosiem.")
                .to_string()
        };
        if u.starts_with("DROP VIEW IF EXISTS ") {
            dropped_views.insert(name("DROP VIEW IF EXISTS "));
        } else if u.starts_with("DROP TABLE IF EXISTS ") {
            dropped_tables.insert(name("DROP TABLE IF EXISTS "));
        } else if u.starts_with("RENAME TABLE ") {
            renames.push(s.clone());
        } else {
            panic!("unexpected statement in migration 180: {s}");
        }
    }
    assert!(
        !dropped_tables.contains("ocsf_logs") && !dropped_views.contains("ocsf_logs"),
        "migration 180 must not drop the data-bearing ocsf_logs"
    );
    let allowed_tables: BTreeSet<String> = ["ocsf_logs_distributed", "ocsf_logs_native_raw", "ocsf_logs_raw"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(dropped_tables, allowed_tables, "only data-free tables may be dropped");
    assert_eq!(renames.len(), 1, "{renames:?}");
    assert!(
        renames[0].contains("nanosiem.ocsf_logs TO nanosiem.ocsf_logs_legacy_v179")
            && renames[0].contains("nano:skip-if-unknown-table"),
        "{}",
        renames[0]
    );

    // Every overlay MV that reads ocsf_logs (or feeds it) must be in the drop list.
    let mut overlay_views = BTreeSet::new();
    for s in sql_statements(DDL) {
        let Some(rest) = s.strip_prefix("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.") else {
            continue;
        };
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        let reads_store = s.split("FROM nanosiem.ocsf_logs").skip(1).any(|tail| {
            !tail.starts_with(|c: char| c.is_alphanumeric() || c == '_')
        });
        let writes_store = s.contains("TO nanosiem.ocsf_logs\n");
        if reads_store || writes_store {
            overlay_views.insert(name);
        }
    }
    assert!(overlay_views.len() >= 20, "{overlay_views:?}");
    // Views first created AFTER 180 (on an upgrade they are created by a later
    // OCSF migration, which runs after 180 and the overlay), so 180 never sees
    // them and has nothing to drop.
    const CREATED_AFTER_180: &[&str] = &[
        // ocsf/197 (NAN-5271 #23)
        "ocsf_hash_prevalence_summary_actor_process_hash_mv",
        "ocsf_domain_prevalence_summary_http_url_mv",
        "hash_prevalence_source_ocsf_actor_process_mv",
        "domain_prevalence_source_ocsf_http_url_mv",
    ];
    for v in CREATED_AFTER_180 {
        assert!(overlay_views.remove(*v), "{v} is no longer an overlay view over ocsf_logs");
    }
    let missing: Vec<_> = overlay_views.difference(&dropped_views).collect();
    assert!(missing.is_empty(), "overlay MVs on ocsf_logs that 180 does not drop: {missing:?}");
}
