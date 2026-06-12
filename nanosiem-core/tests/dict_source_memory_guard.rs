// SPDX-License-Identifier: AGPL-3.0-or-later

//! Memory-bound guards for ClickHouse-sourced dictionary load queries
//! (NAN-1404).
//!
//! CH-sourced dictionary loads run their source SELECT inside the SAME
//! ClickHouse server as ingestion. `ip_enrichment_dict`'s source (migration
//! 123 repoint, 126 uncap) dedup-aggregates the full IPinfo Lite set; on
//! Saturn's 8GiB spec node the unbounded GROUP BY hash table hit the server
//! memory cap (`MEMORY_LIMIT_EXCEEDED ... while executing
//! AggregatingTransform`), the dict went FAILED, every insert's MATERIALIZED
//! `dictGetOrDefault` columns THREW at async-insert flush, and 36h of
//! pre-ACKed batches were silently discarded. Migration 130 bounded every
//! aggregating dict source query (`max_bytes_before_external_group_by` spill
//! + `max_memory_usage` cap + `max_threads`); these tests pin that shape:
//!
//! 1. Every `SOURCE(CLICKHOUSE(...))` dictionary whose QUERY aggregates
//!    (GROUP BY) carries the memory-bound settings inside the QUERY text —
//!    in both init files AND in every numbered migration >= 130 (applied
//!    migrations 121–126 predate the rule and must never be edited), so the
//!    next dict repoint can't ship an unbounded load.
//! 2. Migration 130 (existing deployments) and the init files (fresh
//!    bootstraps) define byte-equivalent dictionaries (modulo
//!    comments/whitespace/CREATE prefix), so the two paths converge.

use std::collections::BTreeMap;

const UDM_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/init.sql"
));
const OCSF_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));
const MIGRATION_130: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/130_memory_bound_dict_source_queries.sql"
));

/// The first numbered migration written under the NAN-1404 rule. Migrations
/// before this predate it and are immutable (editing them trips
/// ChecksumMismatch), so the guard only scans >= this version.
const FIRST_BOUNDED_MIGRATION: u32 = 130;

/// Every dictionary migration 130 recreates with a memory-bounded source.
const BOUNDED_DICTS: &[&str] = &[
    "nanosiem.ip_enrichment_dict",
    "nanosiem.ioc_enrichment_dict",
    "nanosiem.custom_enrichment_dict",
    "nanosiem.custom_ioc_enrichment_dict",
    "nanosiem.user_registry_dict",
    "nanosiem.hash_prevalence_dict",
    "nanosiem.domain_prevalence_dict",
    "nanosiem.ip_prevalence_dict",
];

/// The prevalence dicts are ALSO defined in ocsf/init.sql (the OCSF bootstrap
/// is standalone); the rest live in init.sql only.
const OCSF_BOUNDED_DICTS: &[&str] = &[
    "nanosiem.hash_prevalence_dict",
    "nanosiem.domain_prevalence_dict",
    "nanosiem.ip_prevalence_dict",
];

/// Extract `CREATE ... DICTIONARY` statements keyed by dictionary name, with
/// `--` comments stripped (the migration runner strips them before splitting
/// on `;`), `/* ... */` block markers removed, and whitespace collapsed —
/// the same normalization under which two definitions are "the same DDL".
/// The CREATE prefix (`OR REPLACE` vs `IF NOT EXISTS`) is dropped so init
/// bootstraps and migration replacements compare on body alone.
fn create_dictionary_statements(sql: &str) -> BTreeMap<String, String> {
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
        let rest = if let Some(r) = stmt.strip_prefix("CREATE OR REPLACE DICTIONARY ") {
            r
        } else if let Some(r) = stmt.strip_prefix("CREATE DICTIONARY IF NOT EXISTS ") {
            r
        } else if let Some(r) = stmt.strip_prefix("CREATE DICTIONARY ") {
            r
        } else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        // Drop block comments.
        let mut body = String::new();
        let mut remaining = rest;
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

/// A dict source query "aggregates" when it has a GROUP BY — that's the
/// memory-ballooning shape (AggregatingTransform) that killed Saturn.
fn aggregates(query: &str) -> bool {
    query.to_uppercase().contains("GROUP BY")
}

/// The memory bounds every aggregating CH-sourced dict load must carry, in
/// the QUERY text itself (dict-level SETTINGS(...) are a different clause and
/// do not bound the source query's aggregation).
fn assert_query_memory_bounded(label: &str, name: &str, query: &str) {
    for required in [
        "max_bytes_before_external_group_by",
        "max_memory_usage",
        "max_threads",
    ] {
        assert!(
            query.contains(required),
            "{name} ({label}) has an aggregating SOURCE(CLICKHOUSE) QUERY without \
             `{required}` — an unbounded dict load OOMs the node, goes FAILED, and \
             dictGetOrDefault THROWs on every insert: total silent ingestion halt \
             (NAN-1404). Add `SETTINGS max_bytes_before_external_group_by = ..., \
             max_memory_usage = ..., max_threads = ...` to the QUERY text."
        );
    }
}

/// Every CH-sourced dictionary in the init files whose load query aggregates
/// must be memory-bounded.
#[test]
fn init_ch_sourced_dict_queries_are_memory_bounded() {
    for (label, sql) in [("init.sql", UDM_INIT), ("ocsf/init.sql", OCSF_INIT)] {
        let dicts = create_dictionary_statements(sql);
        let mut checked = 0;
        for (name, stmt) in &dicts {
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
        assert!(
            checked > 0,
            "{label}: found no aggregating CH-sourced dictionaries — extraction broke?"
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
        for (name, stmt) in &create_dictionary_statements(&sql) {
            if !stmt.contains("SOURCE(CLICKHOUSE(") {
                continue;
            }
            let Some(query) = source_query(stmt) else {
                continue;
            };
            if aggregates(&query) {
                assert_query_memory_bounded(fname, name, &query);
            }
        }
    }
    assert!(
        scanned_130,
        "migration {FIRST_BOUNDED_MIGRATION} not found — renumbered? update this guard"
    );
}

/// Migration 130 (existing deployments) and the init files (fresh bootstraps)
/// must define byte-equivalent dictionaries, or the two paths diverge
/// silently.
#[test]
fn migration_130_matches_init_definitions() {
    let udm = create_dictionary_statements(UDM_INIT);
    let ocsf = create_dictionary_statements(OCSF_INIT);
    let mig = create_dictionary_statements(MIGRATION_130);

    for name in BOUNDED_DICTS {
        assert_eq!(
            mig.get(*name),
            udm.get(*name),
            "{name} differs between migration 130 and clickhouse/init.sql"
        );
    }
    for name in OCSF_BOUNDED_DICTS {
        assert_eq!(
            mig.get(*name),
            ocsf.get(*name),
            "{name} differs between migration 130 and clickhouse/ocsf/init.sql"
        );
    }
    assert_eq!(
        mig.len(),
        BOUNDED_DICTS.len(),
        "migration 130 defines dictionaries not covered by BOUNDED_DICTS"
    );
}
