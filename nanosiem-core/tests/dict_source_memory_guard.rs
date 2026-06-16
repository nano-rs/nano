// SPDX-License-Identifier: AGPL-3.0-or-later

//! Memory-bound + staging-indirection guards for ClickHouse dictionary load
//! paths (NAN-1404 / NAN-1407).
//!
//! CH-sourced dictionary loads run their source SELECT inside the SAME
//! ClickHouse server as ingestion. `ip_enrichment_dict`'s source (migration
//! 123 repoint, 126 uncap) dedup-aggregates the full IPinfo Lite set; on
//! Saturn's 8GiB spec node the unbounded GROUP BY hash table hit the server
//! memory cap (`MEMORY_LIMIT_EXCEEDED ... while executing
//! AggregatingTransform`), the dict went FAILED, every insert's MATERIALIZED
//! `dictGetOrDefault` columns THREW at async-insert flush, and 36h of
//! pre-ACKed batches were silently discarded. Migration 130 bounded every
//! aggregating dict source query; migration 133 (NAN-1407) then moved the
//! aggregations off the dict load path for the FIVE FULL-RELOAD dicts — each
//! reads a plain `*_dict_staging` table repopulated by a `*_dict_refresh`
//! refreshable MV, so a failing aggregation degrades to stale enrichment
//! instead of FAILING the dict and halting ingestion. The three prevalence
//! CACHE dicts deliberately stay on migration-130 KEY-PUSHDOWN sources
//! (NAN-1440): their misses are small bounded aggregations, while staging
//! them full-rewrote the entire aggregated keyspace every 10 minutes —
//! measured on Saturn, the 83.8M-row ip_prevalence_summary aggregation OOMed
//! the boot-gating migrator at the 512MiB seed bound. These tests pin that
//! shape:
//!
//! 1. Every aggregating (GROUP BY) load query — whether in a dictionary's
//!    `SOURCE(CLICKHOUSE(... QUERY ...))` or in a `*_dict_refresh`
//!    refreshable-MV body — carries the memory-bound settings, in both init
//!    files AND in every numbered migration >= 130 (applied migrations
//!    121–126 predate the rule and must never be edited), so the next dict
//!    repoint can't ship an unbounded load.
//! 2. Migration 133 (existing deployments) and the init files (fresh
//!    bootstraps) define byte-equivalent dictionaries, staging tables, and
//!    refresh MVs (modulo comments/whitespace/CREATE prefix), so the two
//!    paths converge.
//! 3. Every `*_dict_staging` CREATE TABLE carries the
//!    `nano:keep-local-engine` marker — without it the cluster transform
//!    converts the engine to ReplicatedMergeTree, and ClickHouse REFUSES a
//!    full-replace refreshable MV targeting a replicated table in a
//!    non-Replicated database, aborting the migrate on clustered tenants.

use std::collections::BTreeMap;

const UDM_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/init.sql"
));
const OCSF_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));
const MIGRATION_133: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/133_dict_staging_indirection.sql"
));
/// NAN-1473 lengthened ip_enrichment_dict's IP_TRIE reload LIFETIME (5–10min →
/// 6–12h) to cut rebuild churn on memory-tight boxes. The dict body is
/// otherwise byte-identical to 133; this migration is the canonical definition
/// for the dicts in `DICTS_REDEFINED_BY_136`.
const MIGRATION_136: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/136_lengthen_ip_enrichment_dict_lifetime.sql"
));

/// The first numbered migration written under the NAN-1404 rule. Migrations
/// before this predate it and are immutable (editing them trips
/// ChecksumMismatch), so the guard only scans >= this version.
const FIRST_BOUNDED_MIGRATION: u32 = 130;

/// The full-reload dictionaries migration 133 recreates against a staging
/// source. The canonical definitions live in migration 133 and
/// clickhouse/init.sql; migration 130's (superseded) definitions remain as
/// immutable history.
const STAGED_DICTS: &[&str] = &[
    "nanosiem.ip_enrichment_dict",
    "nanosiem.ioc_enrichment_dict",
    "nanosiem.custom_enrichment_dict",
    "nanosiem.custom_ioc_enrichment_dict",
    "nanosiem.user_registry_dict",
];

/// Staged dicts whose canonical CREATE OR REPLACE moved off migration 133 to a
/// later migration (only the LIFETIME changed — NAN-1473). For these, init.sql
/// must match the LATER migration; their staging table + refresh MV still match
/// 133 (those objects were not touched). Migration 133 stays immutable history.
const DICTS_REDEFINED_BY_136: &[&str] = &["nanosiem.ip_enrichment_dict"];

/// The prevalence CACHE dicts keep migration-130 key-pushdown sources and
/// must NEVER grow staging/refresh objects (NAN-1440 — the full-keyspace
/// rewrite OOMs/overloads Saturn-scale tenants). They are ALSO defined in
/// ocsf/init.sql (the OCSF bootstrap is standalone); the staged dicts live
/// in init.sql only.
const PUSHDOWN_DICTS: &[&str] = &[
    "nanosiem.hash_prevalence_dict",
    "nanosiem.domain_prevalence_dict",
    "nanosiem.ip_prevalence_dict",
];

/// Strip `--` comments (the migration runner strips them before splitting on
/// `;`), drop `/* ... */` block markers, collapse whitespace — the same
/// normalization under which two definitions are "the same DDL".
fn normalize(stmt: &str) -> String {
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
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split SQL into trimmed statements with `--` comments stripped, exactly as
/// the migration runner does before executing.
fn statements(sql: &str) -> Vec<String> {
    let stripped: Vec<String> = sql
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => l[..i].to_string(),
            None => l.to_string(),
        })
        .collect();
    stripped
        .join("\n")
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Extract statements by CREATE prefix, keyed by object name, normalized.
/// The CREATE prefix (`OR REPLACE` vs `IF NOT EXISTS`) is dropped so init
/// bootstraps and migration replacements compare on body alone.
fn create_statements(sql: &str, prefixes: &[&str]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for stmt in statements(sql) {
        let Some(rest) = prefixes.iter().find_map(|p| stmt.strip_prefix(p)) else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        out.insert(name, normalize(rest));
    }
    out
}

fn create_dictionary_statements(sql: &str) -> BTreeMap<String, String> {
    create_statements(
        sql,
        &[
            "CREATE OR REPLACE DICTIONARY ",
            "CREATE DICTIONARY IF NOT EXISTS ",
            "CREATE DICTIONARY ",
        ],
    )
}

fn create_mv_statements(sql: &str) -> BTreeMap<String, String> {
    create_statements(
        sql,
        &[
            "CREATE MATERIALIZED VIEW IF NOT EXISTS ",
            "CREATE MATERIALIZED VIEW ",
        ],
    )
}

fn create_table_statements(sql: &str) -> BTreeMap<String, String> {
    create_statements(sql, &["CREATE TABLE IF NOT EXISTS ", "CREATE TABLE "])
}

/// Extract the SOURCE QUERY string literal from a normalized dictionary
/// statement (handles the `''` escape CH uses inside `'...'` literals).
/// Returns None when the dict has no `QUERY '...'` source.
fn source_query(stmt: &str) -> Option<String> {
    let start = stmt.find("QUERY '")? + "QUERY '".len();
    let bytes = stmt.as_bytes();
    let mut i = start;
    let mut query = String::new();
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                query.push('\'');
                i += 2;
                continue;
            }
            return Some(query);
        }
        query.push(bytes[i] as char);
        i += 1;
    }
    None
}

/// A load query "aggregates" when it has a GROUP BY — that's the
/// memory-ballooning shape (AggregatingTransform) that killed Saturn.
fn aggregates(query: &str) -> bool {
    query.to_uppercase().contains("GROUP BY")
}

/// The memory bounds every aggregating load query must carry, in the query
/// text itself (dict-level SETTINGS(...) are a different clause and do not
/// bound the source query's aggregation).
fn assert_query_memory_bounded(label: &str, name: &str, query: &str) {
    for required in [
        "max_bytes_before_external_group_by",
        "max_memory_usage",
        "max_threads",
    ] {
        assert!(
            query.contains(required),
            "{name} ({label}) has an aggregating load query without `{required}` — an \
             unbounded aggregation OOMs the node (NAN-1404). For dictionary sources that \
             means FAILED + every insert THROWing; for *_dict_refresh MVs it means a stale \
             staging table (survivable, but still avoidable). Add `SETTINGS \
             max_bytes_before_external_group_by = ..., max_memory_usage = ..., \
             max_threads = ...` to the query text."
        );
    }
}

/// Check every aggregating dict QUERY and every aggregating `*_dict_refresh`
/// MV body in `sql`; returns how many aggregating queries were checked.
fn check_memory_bounds(label: &str, sql: &str) -> usize {
    let mut checked = 0;
    for (name, stmt) in &create_dictionary_statements(sql) {
        if !stmt.contains("SOURCE(CLICKHOUSE(") {
            continue;
        }
        let Some(query) = source_query(stmt) else {
            continue;
        };
        if aggregates(&query) {
            assert_query_memory_bounded(label, name, &query);
            checked += 1;
        }
    }
    for (name, stmt) in &create_mv_statements(sql) {
        if !name.ends_with("_dict_refresh") {
            continue;
        }
        if aggregates(stmt) {
            assert_query_memory_bounded(label, name, stmt);
            checked += 1;
        }
    }
    checked
}

/// Every aggregating dictionary load path in the init files (dict source
/// queries and `*_dict_refresh` MV bodies) must be memory-bounded.
#[test]
fn init_dict_load_queries_are_memory_bounded() {
    for (label, sql) in [("init.sql", UDM_INIT), ("ocsf/init.sql", OCSF_INIT)] {
        let checked = check_memory_bounds(label, sql);
        assert!(
            checked > 0,
            "{label}: found no aggregating dictionary load queries — extraction broke?"
        );
    }
}

/// The rule must hold for every numbered migration from 130 on (the next
/// dict repoint can't ship an unbounded load). Earlier migrations are
/// immutable history and exempt.
#[test]
fn numbered_migrations_from_130_have_memory_bounded_dict_queries() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse");
    let mut scanned_130 = false;
    for entry in std::fs::read_dir(dir).expect("read clickhouse/") {
        let path = entry.expect("dir entry").path();
        let Some(fname) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !fname.ends_with(".sql") {
            continue;
        }
        let Some(version) = fname
            .split('_')
            .next()
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue; // init.sql etc. — covered by the init test
        };
        if version < FIRST_BOUNDED_MIGRATION {
            continue;
        }
        scanned_130 |= version == FIRST_BOUNDED_MIGRATION;
        let sql = std::fs::read_to_string(&path).expect("read migration");
        check_memory_bounds(fname, &sql);
    }
    assert!(
        scanned_130,
        "migration {FIRST_BOUNDED_MIGRATION} not found — renumbered? update this guard"
    );
}

/// Migration 133 (existing deployments) and the init files (fresh bootstraps)
/// must define byte-equivalent dictionaries, staging tables, and refresh MVs,
/// or the two paths diverge silently.
#[test]
fn migration_133_matches_init_definitions() {
    let udm_dicts = create_dictionary_statements(UDM_INIT);
    let ocsf_dicts = create_dictionary_statements(OCSF_INIT);
    let mig_dicts = create_dictionary_statements(MIGRATION_133);
    let mig136_dicts = create_dictionary_statements(MIGRATION_136);

    // Migration 136 must redefine exactly the dicts it claims to (catches an
    // accidental extra/missing CREATE OR REPLACE).
    assert_eq!(
        mig136_dicts.keys().map(String::as_str).collect::<Vec<_>>(),
        DICTS_REDEFINED_BY_136.to_vec(),
        "migration 136 redefines a different dict set than DICTS_REDEFINED_BY_136"
    );

    for name in STAGED_DICTS {
        // Redefined dicts' canonical body lives in the later migration; the
        // rest stay pinned to 133. init.sql must match whichever is canonical.
        let (canonical, source) = if DICTS_REDEFINED_BY_136.contains(name) {
            (mig136_dicts.get(*name), "migration 136")
        } else {
            (mig_dicts.get(*name), "migration 133")
        };
        assert_eq!(
            canonical,
            udm_dicts.get(*name),
            "{name} differs between {source} and clickhouse/init.sql"
        );
    }
    for name in PUSHDOWN_DICTS {
        assert_eq!(
            mig_dicts.get(*name),
            udm_dicts.get(*name),
            "{name} differs between migration 133 and clickhouse/init.sql"
        );
        assert_eq!(
            mig_dicts.get(*name),
            ocsf_dicts.get(*name),
            "{name} differs between migration 133 and clickhouse/ocsf/init.sql"
        );
        // NAN-1440: pushdown sources read the *_prevalence_summary tables
        // directly — never a staging table (the full-keyspace staging rewrite
        // OOMed Saturn's boot-gating migrator).
        let query = source_query(mig_dicts.get(*name).expect("pushdown dict in 133"))
            .expect("pushdown dict has a QUERY source");
        assert!(
            query.contains("_prevalence_summary"),
            "{name} must aggregate *_prevalence_summary directly (key pushdown)"
        );
        assert!(
            !query.contains("_dict_staging"),
            "{name} must NOT read a staging table (NAN-1440)"
        );
    }
    assert_eq!(
        mig_dicts.len(),
        STAGED_DICTS.len() + PUSHDOWN_DICTS.len(),
        "migration 133 defines dictionaries not covered by STAGED_DICTS + PUSHDOWN_DICTS"
    );

    // Staging tables + refresh MVs: same equivalence, derived from the dict
    // names (the trio naming `X` / `X_staging` / `X_refresh` is load-bearing
    // for the siem-health staleness probe's `%_dict_refresh` filter).
    let udm_tables = create_table_statements(UDM_INIT);
    let ocsf_tables = create_table_statements(OCSF_INIT);
    let mig_tables = create_table_statements(MIGRATION_133);
    let udm_mvs = create_mv_statements(UDM_INIT);
    let ocsf_mvs = create_mv_statements(OCSF_INIT);
    let mig_mvs = create_mv_statements(MIGRATION_133);

    for name in STAGED_DICTS {
        let staging = format!("{name}_staging");
        let refresh = format!("{name}_refresh");
        assert!(
            mig_tables.contains_key(&staging),
            "{staging} missing from migration 133"
        );
        assert!(
            mig_mvs.contains_key(&refresh),
            "{refresh} missing from migration 133"
        );
        assert_eq!(
            mig_tables.get(&staging),
            udm_tables.get(&staging),
            "{staging} differs between migration 133 and clickhouse/init.sql"
        );
        assert_eq!(
            mig_mvs.get(&refresh),
            udm_mvs.get(&refresh),
            "{refresh} differs between migration 133 and clickhouse/init.sql"
        );
    }
    // NAN-1440: the prevalence CACHE dicts must never grow staging/refresh
    // objects in any of the three files — that shape full-rewrites the whole
    // aggregated keyspace on a 10-minute cadence and broke at Saturn scale.
    for name in PUSHDOWN_DICTS {
        let staging = format!("{name}_staging");
        let refresh = format!("{name}_refresh");
        for (label, tables, mvs) in [
            ("migration 133", &mig_tables, &mig_mvs),
            ("clickhouse/init.sql", &udm_tables, &udm_mvs),
            ("clickhouse/ocsf/init.sql", &ocsf_tables, &ocsf_mvs),
        ] {
            assert!(
                !tables.contains_key(&staging),
                "{staging} must not exist in {label} (NAN-1440: CACHE dicts keep pushdown)"
            );
            assert!(
                !mvs.contains_key(&refresh),
                "{refresh} must not exist in {label} (NAN-1440: CACHE dicts keep pushdown)"
            );
        }
    }
}

/// Every `*_dict_staging` CREATE TABLE must carry the `nano:keep-local-engine`
/// block-comment marker AND a plain MergeTree engine. Without the marker the
/// cluster transform rewrites the engine to ReplicatedMergeTree, and
/// ClickHouse refuses the full-replace refreshable MV that repopulates the
/// table ("no APPEND, non-replicated database, replicated table") — aborting
/// the migrate on every clustered tenant.
#[test]
fn staging_tables_keep_local_engine() {
    // Expected *_dict_staging count per file: the five full-reload dicts in
    // init.sql + migration 133; NONE in ocsf/init.sql (its only dicts are the
    // prevalence CACHE family, which keeps pushdown sources — NAN-1440).
    for (label, sql, expected) in [
        ("init.sql", UDM_INIT, STAGED_DICTS.len()),
        ("ocsf/init.sql", OCSF_INIT, 0),
        (
            "133_dict_staging_indirection.sql",
            MIGRATION_133,
            STAGED_DICTS.len(),
        ),
    ] {
        let mut found = 0;
        for stmt in statements(sql) {
            if !stmt.starts_with("CREATE TABLE") {
                continue;
            }
            let normalized = normalize(&stmt);
            let Some(name_start) = normalized.find("nanosiem.") else {
                continue;
            };
            let name: String = normalized[name_start..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            if !name.ends_with("_dict_staging") {
                continue;
            }
            found += 1;
            assert!(
                stmt.contains("nano:keep-local-engine"),
                "{name} ({label}) is missing the nano:keep-local-engine marker — the \
                 cluster transform would convert it to ReplicatedMergeTree and CH would \
                 refuse its full-replace refreshable MV (NAN-1407)"
            );
            assert!(
                normalized.contains("ENGINE = MergeTree"),
                "{name} ({label}) must be plain MergeTree (per-replica staging): {normalized}"
            );
        }
        assert_eq!(
            found, expected,
            "{label}: expected {expected} *_dict_staging tables, found {found} — \
             extraction broke, or a staging table was added/removed without updating \
             STAGED_DICTS/PUSHDOWN_DICTS"
        );
    }
}
