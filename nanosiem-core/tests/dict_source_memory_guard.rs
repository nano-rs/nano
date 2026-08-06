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
//!    paths converge. Two fields are canonically redefined by later
//!    migrations and init.sql tracks those: the ip_enrichment_dict body's
//!    LIFETIME (migration 136, NAN-1473) and the `*_dict_refresh` MV REFRESH
//!    cadences (migration 137, NAN-1482) — so refresh MVs are compared modulo
//!    their REFRESH interval, which migration 137 must set to match init.sql.
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
/// NAN-1482 lengthened the five `*_dict_refresh` MV cadences (ip_enrichment →
/// 6 HOUR, the other four → 1 HOUR) via `ALTER TABLE … MODIFY REFRESH`. CH 26.4
/// has no CREATE OR REPLACE for materialized views, so the cadence moves by
/// ALTER, not a new CREATE. The MV SELECT bodies + staging targets are
/// unchanged from 133 — only the REFRESH interval moves — so clickhouse/init.sql
/// matches 133 modulo that interval, which this migration sets.
const MIGRATION_137: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/137_lengthen_dict_refresh_mv_cadence.sql"
));
/// NAN-1588 lowercased the IOC dict keys (`lower(ioc_value)` / `lower(key_value)`
/// in the SOURCE query) so ingest-time matching is case-insensitive — the log
/// side already looks up with `lower(...)`. The dict bodies are otherwise
/// byte-identical to 133; this migration is the canonical definition for the
/// dicts in `DICTS_REDEFINED_BY_148`. The staging tables + refresh MVs are
/// untouched (the dict reloads off the existing staging).
const MIGRATION_148: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/148_lowercase_ioc_dict_keys.sql"
));
/// NAN-1662 recreated the three prevalence CACHE dicts so a dict MISS means
/// "genuinely new" (default 1 at ingest), not "common": the source drops the
/// `HAVING host_count < 1000` filter and stores common as a 9999 cap. It is the
/// canonical definition for the `PUSHDOWN_DICTS`. Source stays key-pushdown over
/// `*_prevalence_summary` and memory-bounded (NAN-1440 / the per-key load).
const MIGRATION_153: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/153_prevalence_new_artifact_default.sql"
));

/// NAN-1732 P2-D phase 2 cut the pushdown dicts' SOURCE over from
/// `*_prevalence_summary` to the pre-finalized `*_prevalence_final` tables — a
/// point lookup via `argMax(col, version)` instead of a per-miss `uniqMerge`
/// fan-out across shards (254 GiB / 16.1B rows / 3h on Saturn, slow enough that
/// batches hit the 6000ms dict-source timeout and fell back to the 9999
/// default, returning genuinely rare artifacts as common — NAN-1761 #2).
///
/// This SUPERSEDES migration 153 as the canonical body for `PUSHDOWN_DICTS`.
/// 153 remains immutable history, exactly as 133 does for the staged dicts.
/// The guard compared init.sql against 153 and never learned about 162, so it
/// reported drift on a pair that had legitimately diverged months earlier
/// (NAN-2197).
const MIGRATION_162: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/162_prevalence_dicts_read_final.sql"
));

/// NAN-2346 replaced the hardcoded `SIZE_IN_CELLS` literals with the
/// `{prevalence_cache_cells*}` placeholders so a small box can size the three
/// prevalence CACHE dicts to its own memory. `COMPLEX_KEY_CACHE` preallocates its
/// whole cell array at first `dictGet` and CH rounds the count up to a power of
/// two, so `5000000` allocated 2^23 cells ≈ 320 MiB to hold (measured) 2 elements;
/// the trio cost ~400 MiB on every box. On a 4 GB tenant that was a quarter of
/// CH's budget and left `ip_enrichment_dict` unable to build its IP_TRIE — it sat
/// `LOADED` with `element_count 0`, silently serving enrichment defaults.
///
/// This SUPERSEDES migration 162 as the canonical body for `PUSHDOWN_DICTS`; 162
/// stays immutable history, exactly as 153 does. Everything else in the bodies is
/// byte-identical to 162 — only the SIZE_IN_CELLS literal moved.
const MIGRATION_172: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/172_prevalence_dict_cache_cells_by_box.sql"
));

/// NAN-1732 P2-C deduplicated the enrichment refresh MVs: the SELECT now wraps
/// its source in an `argMax(col, version) GROUP BY namespace, …` subquery so a
/// re-ingested key does not fan out into duplicate staging rows.
///
/// That rewrite landed in `clickhouse/init.sql` FIRST — fresh installs get it
/// from the `CREATE MATERIALIZED VIEW IF NOT EXISTS` — and migration 161 exists
/// solely to apply the same body to EXISTING installs, where the `IF NOT
/// EXISTS` is a no-op. It therefore uses `ALTER TABLE <mv> MODIFY QUERY`, not
/// `CREATE`, so the CREATE-statement extractor never saw it.
///
/// Net effect: init.sql legitimately diverged from migration 133 for these
/// three MVs, and the guard reported it as drift (NAN-2197). Their canonical
/// body is 161's.
const MIGRATION_161: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/161_enrichment_dict_dedup_existing_installs.sql"
));

/// Refresh MVs whose canonical body moved off migration 133 to migration 161.
const MVS_REDEFINED_BY_161: &[&str] = &[
    "nanosiem.custom_enrichment_dict_refresh",
    "nanosiem.custom_ioc_enrichment_dict_refresh",
    "nanosiem.ioc_enrichment_dict_refresh",
];

/// The SELECT half of an MV body. A CREATE-extracted body reads
/// `<name> TO <target> AS SELECT …` while `MODIFY QUERY` yields the bare
/// SELECT, so only this part is comparable across the two forms.
fn select_body(mv_body: &str) -> String {
    match mv_body.find(" AS SELECT ") {
        Some(i) => mv_body[i + " AS ".len()..].to_string(),
        None => mv_body.to_string(),
    }
}

/// Extract `ALTER TABLE <name> MODIFY QUERY <select>` bodies, keyed by MV name.
///
/// A second extractor is needed because `create_mv_statements` only understands
/// `CREATE MATERIALIZED VIEW`. Note `MODIFY QUERY` has no `AS` before the
/// SELECT, unlike CREATE — a difference that has bitten before.
fn modify_query_statements(sql: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for chunk in sql.split("ALTER TABLE ").skip(1) {
        let Some((name, rest)) = chunk.split_once("MODIFY QUERY") else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        let body = rest.split(';').next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        out.insert(name.to_string(), normalize(body));
    }
    out
}

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

/// Staged dicts whose canonical CREATE OR REPLACE moved off migration 133 to
/// migration 148 (only the SOURCE query key was lowercased — NAN-1588). For
/// these, init.sql must match migration 148; their staging table + refresh MV
/// still match 133 (those objects were not touched).
const DICTS_REDEFINED_BY_148: &[&str] = &[
    "nanosiem.custom_ioc_enrichment_dict",
    "nanosiem.ioc_enrichment_dict",
];

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

/// Extract a refreshable MV's `REFRESH EVERY <interval>` from a normalized MV
/// body (the `EVERY …` portion between `REFRESH EVERY ` and ` TO `), e.g.
/// `"6 HOUR"`. Returns None for a non-refreshable / `TO`-less MV.
fn refresh_interval(mv_body: &str) -> Option<String> {
    let start = mv_body.find("REFRESH EVERY ")? + "REFRESH EVERY ".len();
    let rest = &mv_body[start..];
    let end = rest.find(" TO ")?;
    Some(rest[..end].trim().to_string())
}

/// Drop the `REFRESH EVERY <interval> ` clause from a normalized MV body so two
/// MVs that differ ONLY in cadence (NAN-1482) compare equal. Returns the body
/// unchanged when there is no refresh clause.
fn strip_refresh(mv_body: &str) -> String {
    match (mv_body.find("REFRESH EVERY "), mv_body.find(" TO ")) {
        (Some(s), Some(t)) if t > s => format!("{}{}", &mv_body[..s], &mv_body[t + 1..]),
        _ => mv_body.to_string(),
    }
}

/// Map each `ALTER TABLE <name> MODIFY REFRESH EVERY <interval>` in `sql` to
/// {name → interval} (e.g. `nanosiem.ip_enrichment_dict_refresh → "6 HOUR"`).
/// This is how migration 137 recadences the refresh MVs (CH 26.4 has no
/// CREATE OR REPLACE for MVs).
fn alter_refresh_intervals(sql: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for stmt in statements(sql) {
        let norm = normalize(&stmt);
        let Some(rest) = norm.strip_prefix("ALTER TABLE ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        let Some(pos) = rest.find("MODIFY REFRESH EVERY ") else {
            continue;
        };
        let interval = rest[pos + "MODIFY REFRESH EVERY ".len()..].trim().to_string();
        out.insert(name, interval);
    }
    out
}

/// Extract the SOURCE QUERY string literal from a normalized dictionary
/// statement (handles the `''` escape CH uses inside `'...'` literals).
/// Returns None when the dict has no `QUERY '...'` source.
/// The dictionary's declared `PRIMARY KEY` column.
fn dict_primary_key(stmt: &str) -> Option<String> {
    let start = stmt.find("PRIMARY KEY ")? + "PRIMARY KEY ".len();
    let rest = &stmt[start..];
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let key = rest[..end].trim();
    (!key.is_empty()).then(|| key.to_string())
}

/// True when a CACHE dict's aggregating source is bounded by KEY PUSHDOWN
/// rather than by explicit memory settings (NAN-2197).
///
/// ClickHouse loads a cache dict by WRAPPING the source query:
///
///   SELECT * FROM (<source query>) AS subquery WHERE (`key`) IN ((…))
///
/// When the filtered column is also the GROUP BY key, the optimizer pushes that
/// predicate through the aggregation into the primary-key scan, so the
/// aggregation only ever sees the requested keys' rows — bounded by BATCH SIZE,
/// not table size, and no memory settings are needed.
///
/// Measured against a live ClickHouse (3.5M-row `ip_prevalence_final`):
///   - one present key  -> 24,779 rows read, 326 KiB
///   - absent keys      -> 0 rows read
/// Reading ZERO for an absent key is the proof: an unbounded inner aggregation
/// would have to scan the whole table regardless of the outer filter. For
/// reference the settings migration 153 carried bounded memory at 512 MiB —
/// roughly 1600x what the query actually uses.
///
/// This is why migration 162 dropped the settings, and it is the property worth
/// asserting: the settings were never what made this safe. If a future source
/// query groups by something other than the dict key, pushdown stops and the
/// aggregation really does become unbounded — which this catches, and a
/// settings-presence check would not.
fn is_key_pushdown_bounded(stmt: &str, query: &str) -> bool {
    // ONLY a CACHE layout loads per-key batches with a `WHERE key IN (…)`
    // predicate. HASHED / COMPLEX_KEY_HASHED / IP_TRIE load the ENTIRE source
    // in one query with no predicate at all, so grouping by the key bounds
    // nothing and the memory settings are the only protection. This repo has
    // all three of those layouts (migration 133), so without this check a
    // future HASHED dict grouping by its key would be silently exempted —
    // exactly the NAN-1404 OOM the guard exists to prevent.
    if !stmt.to_uppercase().contains("_CACHE") && !stmt.to_uppercase().contains("LAYOUT(CACHE") {
        return false;
    }
    let Some(key) = dict_primary_key(stmt) else {
        return false;
    };
    let upper = query.to_uppercase();
    let Some(idx) = upper.find("GROUP BY") else {
        return false;
    };
    // The grouping list must be EXACTLY the dict key. Grouping by additional
    // columns emits multiple rows per key, breaking the lookup contract, and
    // means the filter no longer covers the whole grouping set.
    //
    // Read to the end of the clause rather than to the first non-identifier
    // character: stopping at the comma made `GROUP BY file_hash, version` look
    // identical to `GROUP BY file_hash` and wrongly exempted it.
    let after = &query[idx + "GROUP BY".len()..];
    let end = ["SETTINGS", "ORDER BY", "HAVING", "LIMIT", "UNION"]
        .iter()
        .filter_map(|kw| after.to_uppercase().find(kw))
        .min()
        .unwrap_or(after.len());
    after[..end].trim() == key
}

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
            // Count it either way: this counter exists to prove EXTRACTION
            // still works ("found no aggregating queries — extraction broke?"),
            // and an exempted query is just as much evidence of that as an
            // asserted one. Not counting exemptions made that sanity check fire
            // once every dict in a file became pushdown-bounded.
            checked += 1;
            if is_key_pushdown_bounded(stmt, &query) {
                // Bounded by the key predicate the cache dict pushes in; see
                // `is_key_pushdown_bounded` for the measurements. Requiring
                // memory settings here would fail migration 162 for removing
                // bounds that were never doing the work.
                continue;
            }
            assert_query_memory_bounded(label, name, &query);
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
    let mig148_dicts = create_dictionary_statements(MIGRATION_148);
    let mig153_dicts = create_dictionary_statements(MIGRATION_153);
    let mig162_dicts = create_dictionary_statements(MIGRATION_162);
    let mig172_dicts = create_dictionary_statements(MIGRATION_172);

    // Migration 136 must redefine exactly the dicts it claims to (catches an
    // accidental extra/missing CREATE OR REPLACE).
    assert_eq!(
        mig136_dicts.keys().map(String::as_str).collect::<Vec<_>>(),
        DICTS_REDEFINED_BY_136.to_vec(),
        "migration 136 redefines a different dict set than DICTS_REDEFINED_BY_136"
    );
    // Same pin for migration 148 (NAN-1588).
    assert_eq!(
        mig148_dicts.keys().map(String::as_str).collect::<Vec<_>>(),
        DICTS_REDEFINED_BY_148.to_vec(),
        "migration 148 redefines a different dict set than DICTS_REDEFINED_BY_148"
    );

    for name in STAGED_DICTS {
        // Redefined dicts' canonical body lives in the latest migration that
        // recreated them; the rest stay pinned to 133. init.sql must match
        // whichever is canonical.
        let (canonical, source) = if DICTS_REDEFINED_BY_148.contains(name) {
            (mig148_dicts.get(*name), "migration 148")
        } else if DICTS_REDEFINED_BY_136.contains(name) {
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
    // NAN-1662: the pushdown dicts' canonical body moved off 133 to migration
    // 153 (drop `HAVING host_count < 1000`; store common as a 9999 cap so an
    // ingest dict MISS unambiguously means "genuinely new"). init.sql/ocsf must
    // match 153. Migration 153 must redefine exactly the pushdown dict set.
    let mut expected_pushdown = PUSHDOWN_DICTS.to_vec();
    expected_pushdown.sort_unstable(); // BTreeMap keys iterate sorted
    assert_eq!(
        mig153_dicts.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_pushdown,
        "migration 153 redefines a different dict set than PUSHDOWN_DICTS"
    );
    // Migration 162 must redefine exactly the pushdown set — a partial cutover
    // would leave some dicts on `summary` and some on `final`.
    assert_eq!(
        mig162_dicts.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_pushdown,
        "migration 162 redefines a different dict set than PUSHDOWN_DICTS"
    );
    // NAN-2346: same pin for 172, which is now canonical. A partial cutover would
    // leave some dicts sized by the box and others on the fleet-wide literal.
    assert_eq!(
        mig172_dicts.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_pushdown,
        "migration 172 redefines a different dict set than PUSHDOWN_DICTS"
    );
    for name in PUSHDOWN_DICTS {
        let canonical = mig172_dicts.get(*name);
        assert_eq!(
            canonical,
            udm_dicts.get(*name),
            "{name} differs between migration 172 and clickhouse/init.sql"
        );
        assert_eq!(
            canonical,
            ocsf_dicts.get(*name),
            "{name} differs between migration 172 and clickhouse/ocsf/init.sql"
        );
        // NAN-2346: 172 must be 162's body with ONLY the SIZE_IN_CELLS literal
        // parameterised. Comparing the two with the placeholders resolved to the
        // historical defaults proves no other clause drifted in the copy, and
        // proves the unset path stays byte-identical to what 162 deployed.
        //
        // The literals are hardcoded here on purpose rather than imported from
        // sql_transform: this assertion IS the statement that an unset
        // NANO_PREVALENCE_CACHE_CELLS* must reproduce exactly what 162 deployed.
        // If someone changes the runtime default, this test SHOULD fail — that
        // change would silently resize every k8s / BYOC / open-core install.
        let restored = canonical
            .expect("pushdown dict in 172")
            .replace("{prevalence_cache_cells_ip}", "5000000")
            .replace("{prevalence_cache_cells}", "1000000");
        assert_eq!(
            Some(&restored),
            mig162_dicts.get(*name),
            "{name} in migration 172 differs from migration 162 by more than SIZE_IN_CELLS"
        );
        let query = source_query(canonical.expect("pushdown dict in 172"))
            .expect("pushdown dict has a QUERY source");
        // NAN-1440, the invariant that actually matters: a pushdown source must
        // NEVER read a staging table. The full-keyspace staging rewrite OOMed
        // Saturn's boot-gating migrator, which is why these dicts are exempt
        // from the staged trio in the first place.
        //
        // This used to also assert the source read `*_prevalence_summary`,
        // which conflated the invariant with the table that happened to satisfy
        // it. Migration 162 moved to `*_prevalence_final` — still a direct
        // point lookup, still no staging — and the assertion failed on a
        // legitimate change (NAN-2197). Assert the property, not the table.
        assert!(
            !query.contains("_dict_staging"),
            "{name} must NOT read a staging table (NAN-1440)"
        );
        assert!(
            query.contains("_prevalence_final") || query.contains("_prevalence_summary"),
            "{name} must read a prevalence table directly (key pushdown), got: {query}"
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

    // NAN-1482: the *_dict_refresh MV cadences are canonically set by migration
    // 137 (ALTER … MODIFY REFRESH), not 133. It must recadence exactly the five
    // staged refresh MVs and nothing else.
    let mig137_intervals = alter_refresh_intervals(MIGRATION_137);
    let mut expected_137: Vec<String> =
        STAGED_DICTS.iter().map(|n| format!("{n}_refresh")).collect();
    expected_137.sort();
    assert_eq!(
        mig137_intervals.keys().cloned().collect::<Vec<_>>(),
        expected_137,
        "migration 137 must ALTER … MODIFY REFRESH exactly the five *_dict_refresh MVs"
    );

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
        // The refresh MV bodies must match modulo the REFRESH cadence: only the
        // interval moved in 137; the aggregation + staging target are unchanged.
        let mig_mv = mig_mvs.get(&refresh).expect("refresh MV in migration 133");
        let udm_mv = udm_mvs
            .get(&refresh)
            .expect("refresh MV in clickhouse/init.sql");
        if MVS_REDEFINED_BY_161.contains(&refresh.as_str()) {
            // NAN-2197: the dedup rewrite landed in init.sql first and reached
            // existing installs via migration 161's ALTER … MODIFY QUERY, so
            // 133 is no longer canonical for these three. Compare the SELECT
            // halves — the only part the two statement forms share.
            let mig161 = modify_query_statements(MIGRATION_161);
            let canonical = mig161.get(&refresh).unwrap_or_else(|| {
                panic!("{refresh} is listed in MVS_REDEFINED_BY_161 but migration 161 does not MODIFY QUERY it")
            });
            assert_eq!(
                select_body(canonical),
                select_body(&strip_refresh(udm_mv)),
                "{refresh} body differs between migration 161 and clickhouse/init.sql"
            );
        } else {
            assert_eq!(
                strip_refresh(mig_mv),
                strip_refresh(udm_mv),
                "{refresh} body (excluding REFRESH cadence) differs between migration 133 and clickhouse/init.sql"
            );
        }
        // init.sql's cadence must be exactly what migration 137 recadences to,
        // so fresh bootstraps and upgraded tenants converge on the same interval.
        assert_eq!(
            mig137_intervals.get(&refresh),
            refresh_interval(udm_mv).as_ref(),
            "{refresh} REFRESH interval in clickhouse/init.sql must match migration 137's MODIFY REFRESH"
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
