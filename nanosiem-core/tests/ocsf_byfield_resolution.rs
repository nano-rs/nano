// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression: UDM-semantic nPL field tokens (`src_ip`, `user`, …) must resolve
//! to their promoted OCSF column in the GENERAL query path — every multi-stage
//! by-field command, not just the hand-threaded cloud/asset surfaces. (NAN-1248)
//!
//! Before the fix, under OCSF `... | stats count by src_ip` emitted
//! `GROUP BY src_ip` (a column OCSF does not have) → 500, while `where src_ip=x`
//! silently `JSONExtract(event,'src_ip')` → ''. Both now resolve through the
//! manifest `udm_field` map (`src_ip` → `src_endpoint.ip`).
//!
//! UDM output stays byte-identical (the alias map is OcsfProfile-only); the
//! `udm_unchanged` test pins that.

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;
use std::sync::Arc;

fn tr() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

fn ocsf(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::with_table("ocsf_logs")
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

fn udm(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::new()
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

/// True if `token` appears as a standalone SQL identifier that is NOT the output
/// alias `AS <token>` — i.e. an unresolved column reference (the 500 bug).
/// Substring matches inside larger identifiers (`enrichments.ioc_src_ip_tags`)
/// do not count.
fn leaks_bare(sql: &str, token: &str) -> bool {
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = sql.as_bytes();
    let mut from = 0;
    while let Some(rel) = sql[from..].find(token) {
        let s = from + rel;
        let e = s + token.len();
        let bounded = (s == 0 || !is_ident(b[s - 1])) && (e == b.len() || !is_ident(b[e]));
        if bounded && !sql[..s].trim_end().ends_with("AS") {
            return true;
        }
        from = e;
    }
    false
}

/// Every multi-stage by-field command resolves `src_ip` → `src_endpoint.ip`
/// under OCSF, and never leaks a bare `src_ip` into a GROUP BY / PARTITION BY /
/// LIMIT BY position (the bug that 500'd).
#[test]
fn ocsf_by_field_resolves_src_ip() {
    let cases = [
        "* | stats count by src_ip",
        "* | timechart span=1h count by src_ip",
        "* | top src_ip",
        "* | rare src_ip",
        "* | dedup src_ip",
        "* | eventstats count by src_ip",
        "* | streamstats count by src_ip",
        "* | transaction src_ip",
        "* | stats avg(bytes_out) by src_ip",
    ];
    for q in cases {
        let sql = ocsf(q);
        assert!(
            sql.contains("src_endpoint.ip"),
            "OCSF `{q}` must resolve src_ip → src_endpoint.ip.\nSQL:\n{sql}"
        );
        // The ONLY legal `src_ip` token is the output alias `AS src_ip`. ANY other
        // standalone occurrence — a slim stage_0 projection column, a GROUP BY /
        // PARTITION BY / ORDER BY / LIMIT BY reference — is an unresolved column
        // that 500s at execution (the stage_0/stage_1 mismatch a weaker check missed).
        assert!(
            !leaks_bare(&sql, "src_ip"),
            "OCSF `{q}` leaked a bare `src_ip` (only `AS src_ip` is legal).\nSQL:\n{sql}"
        );
    }
}

/// WHERE / search-term path: `src_ip=x` filters the promoted column, not an
/// empty `JSONExtract(event,'src_ip')`.
#[test]
fn ocsf_where_src_ip_hits_promoted_column() {
    let sql = ocsf("src_ip=\"52.23.186.156\"");
    assert!(
        sql.contains("src_endpoint.ip"),
        "OCSF WHERE src_ip must hit src_endpoint.ip.\nSQL:\n{sql}"
    );
    assert!(
        !sql.contains("JSONExtractString(event, 'src_ip')"),
        "OCSF WHERE src_ip must NOT JSONExtract a non-existent key.\nSQL:\n{sql}"
    );
}

/// The ambiguous `user` token resolves to a real OCSF column, not the bare
/// `user` that CH silently resolves to the session username. Since NAN-1333 the
/// class-split concept lands on the indexed unified column (`user_unified`,
/// which materializes the `user.name` / `actor.user.name` union) rather than
/// the manifest primary `user.name` alone — this assertion drifted and is
/// updated to pin the unified form (same union, index-served; see the
/// `GROUP BY user_unified` pin in clickhouse_sql_gen.rs unit tests).
#[test]
fn ocsf_user_maps_to_unified_user_column() {
    let sql = ocsf("* | stats count by user");
    assert!(
        sql.contains("user_unified"),
        "OCSF `stats by user` must resolve to the unified user column (NAN-1333).\nSQL:\n{sql}"
    );
}

/// An UNMAPPED UDM field under OCSF degrades to a read from the `event` tail
/// (graceful empty result), NOT a bare reference that 500s. `status_code`
/// has no OCSF mapping — the manifest maps `http_status_code` → `http_response.code`.
/// NAN-1426: the tail read is native subcolumn access (the ''-defaulting
/// multiIf string form), no longer `JSONExtractString(event, …)` which
/// re-serialized the whole event per row.
#[test]
fn ocsf_unmapped_field_degrades_to_json_extract() {
    let sql = ocsf("* | stats count by status_code");
    assert!(
        sql.contains(
            "multiIf(isNotNull(unmapped.\"status_code\"), toString(unmapped.\"status_code\"), \
             toJSONString(unmapped.^\"status_code\") != '{}', toJSONString(unmapped.^\"status_code\"), '')"
        ) && !sql.contains("JSONExtractString(unmapped"),
        "OCSF unmapped `status_code` must read the `unmapped` spill tail via subcolumn access (NAN-1443; graceful), not emit a bare 500.\nSQL:\n{sql}"
    );
}

/// The same unmapped degradation must NOT touch UDM: `status_code` stays a bare
/// column reference, never JSONExtract (UDM `resolve` never yields a JsonPath).
#[test]
fn udm_unmapped_field_stays_bare() {
    let sql = udm("* | stats count by status_code");
    assert!(
        !sql.contains("JSONExtract"),
        "UDM `status_code` must stay a bare column, never JSONExtract.\nSQL:\n{sql}"
    );
}

/// UDM is byte-identical: the alias layer is OcsfProfile-only. Under UDM the
/// same queries still group on the bare `src_ip` column and never mention any
/// OCSF dotted name.
#[test]
fn udm_unchanged_by_field() {
    for q in [
        "* | stats count by src_ip",
        "* | dedup src_ip",
        "* | eventstats count by src_ip",
    ] {
        let sql = udm(q);
        assert!(sql.contains("src_ip"), "UDM `{q}` keeps src_ip.\nSQL:\n{sql}");
        assert!(
            !sql.contains("src_endpoint.ip"),
            "UDM `{q}` must NOT gain OCSF names.\nSQL:\n{sql}"
        );
    }
}
