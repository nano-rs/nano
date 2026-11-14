// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5416: an nPL regex on a numeric field must not reach ClickHouse as
//! `match(<int col>, …)` / `lower(<int col>)`. Both are a ClickHouse type
//! error (Code 43, "Illegal type Int64 of argument of function match") that
//! failed the whole search as a 500. Found by the public benchmark corpus:
//! `enriched_src_asn=/.+/` on an OCSF install, where the alias resolves to the
//! Int64 `src_endpoint.autonomous_system.number`.
//!
//! The fix reads every non-String target through `toString()` in every regex
//! arm (`match`, `startsWith`, `endsWith`, the literal guards), so a regex on a
//! number matches its decimal text. Plain String columns keep the raw column,
//! so the `lower(<col>)` text indexes still match by expression.

use std::sync::Arc;

use crate::auth::ScopeSet;
use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::{OcsfProfile, SchemaProfile, UdmProfile};
use crate::search::service::npl_golden_corpus_tests::{render, sql_only_service};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-11-13T00:00:00Z".parse().unwrap(),
        end: "2026-11-13T01:00:00Z".parse().unwrap(),
    }
}

fn generate(profile: Arc<dyn SchemaProfile>, npl: &str) -> Result<String, String> {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: parse: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(profile)
        .generate(&query, &time_range())
        .map_err(|e| e.to_string())
}

fn ocsf(npl: &str) -> String {
    generate(Arc::new(OcsfProfile::new()), npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn udm(npl: &str) -> String {
    generate(Arc::new(UdmProfile::new()), npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

/// The regex / substring functions ClickHouse refuses on a non-String argument.
const STRING_ONLY_FNS: &[&str] = &["match(", "lower(", "startsWith(lower(", "endsWith(lower("];

/// Assert `col` is never the direct argument of a String-only function.
fn assert_never_raw(sql: &str, col: &str, npl: &str) {
    for f in STRING_ONLY_FNS {
        let raw = format!("{f}{col}");
        assert!(!sql.contains(&raw), "{npl}: raw `{raw}` is a CH type error:\n{sql}");
    }
    assert!(sql.contains(&format!("toString({col})")), "{npl}: expected toString({col}):\n{sql}");
}

/// Every regex shape the optimizer distinguishes: fallback `match`, anchored
/// prefix / suffix, literal alternation, bloom guard, simple literal, and the
/// negations.
const REGEX_SHAPES: &[&str] = &[
    "/.+/", "/^13/", "/335$/", "/13|15/", "/1.*5$/", "/133/", "/^1[0-9]+$/",
];

// --- numeric columns: OCSF -------------------------------------------------

#[test]
fn ocsf_numeric_promoted_column_regex_reads_tostring() {
    // The benchmark field: a UDM alias onto an Int64 promoted column.
    let col = "\"src_endpoint.autonomous_system.number\"";
    for shape in REGEX_SHAPES {
        for op in ["=", "!="] {
            let npl = format!("enriched_src_asn{op}{shape}");
            assert_never_raw(&ocsf(&npl), col, &npl);
        }
    }
}

#[test]
fn ocsf_udm_alias_onto_numeric_column_is_not_a_string_column() {
    // `is_numeric_field("src_port")` is false under OCSF (the token is not an
    // OCSF name) even though it resolves to the Int32 `src_endpoint.port`.
    for (field, col) in [
        ("src_port", "\"src_endpoint.port\""),
        ("dest_port", "\"dst_endpoint.port\""),
        ("http_status_code", "\"http_response.code\""),
        ("src_endpoint.port", "\"src_endpoint.port\""),
    ] {
        for shape in REGEX_SHAPES {
            let npl = format!("{field}={shape}");
            assert_never_raw(&ocsf(&npl), col, &npl);
        }
    }
}

#[test]
fn ocsf_benchmark_query_compiles_to_tostring_match() {
    let sql = ocsf(
        "(source_type=aws_cloudtrail OR source_type=windows_event) enriched_src_asn=/.+/ \
         | stats dc(user) as users, dc(action) as actions, dc(src_ip) as ips, count \
           by enriched_src_asn, enriched_src_country | sort -count",
    );
    assert!(
        sql.contains("match(toString(\"src_endpoint.autonomous_system.number\"), '(?i).+')"),
        "{sql}"
    );
    // CLAUDE.md query rules still hold.
    assert!(!sql.contains("PREWHERE"), "{sql}");
}

// --- numeric columns: UDM --------------------------------------------------

#[test]
fn udm_numeric_column_regex_reads_tostring() {
    for (field, col) in [
        ("src_port", "src_port"),
        ("dest_port", "dest_port"),
        ("http_status_code", "http_status_code"),
    ] {
        for shape in REGEX_SHAPES {
            for op in ["=", "!="] {
                let npl = format!("{field}{op}{shape}");
                assert_never_raw(&udm(&npl), col, &npl);
            }
        }
    }
}

// --- String columns keep the indexed raw form --------------------------------

#[test]
fn string_columns_keep_the_lower_col_index_form() {
    // UDM `enriched_src_asn` is a String column: no toString, raw lower(col).
    let sql = udm("enriched_src_asn=/133/");
    assert!(sql.contains("lower(enriched_src_asn) LIKE '%133%'"), "{sql}");
    let sql = udm("enriched_src_asn=/^AS13/");
    assert!(sql.contains("startsWith(lower(enriched_src_asn), 'as13')")
        || sql.contains("startsWith(lower(enriched_src_asn), 'AS13')"), "{sql}");
    assert!(!sql.contains("toString(enriched_src_asn)"), "{sql}");

    for (npl, needle) in [
        ("user=/adm.+x/", "lower(user_unified) LIKE '%adm%' AND match(user_unified, '(?i)adm.+x')"),
        ("command_line=/enc.+x/", "match(command_line_unified, '(?i)enc.+x')"),
        ("src_ip=/^10\\./", "match(\"src_endpoint.ip\", '(?i)^10\\\\.')"),
        ("src_host=/ws.+01/", "match(src_host_unified, '(?i)ws.+01')"),
    ] {
        let sql = ocsf(npl);
        assert!(sql.contains(needle), "{npl}: {sql}");
        assert!(!sql.contains("toString(user_unified)"), "{npl}: {sql}");
        assert!(!sql.contains("toString(\"src_endpoint.ip\")"), "{npl}: {sql}");
    }
    for (npl, needle) in [
        ("user=/adm.+x/", "lower(\"user\") LIKE '%adm%' AND match(\"user\", '(?i)adm.+x')"),
        ("command_line=/enc.+x/", "match(command_line, '(?i)enc.+x')"),
    ] {
        let sql = udm(npl);
        assert!(sql.contains(needle), "{npl}: {sql}");
    }
}

// --- ext / unmapped JSON fields ----------------------------------------------

#[test]
fn udm_ext_json_regex_reads_tostring_so_negation_keeps_absent_keys() {
    // A missing ext key is NULL; `match(NULL, p) = 0` is NULL and drops the row.
    for npl in ["ext.foo=/x.+y/", "foo=/x.+y/", "ext.foo=/^ab/", "ext.foo=/ab$/"] {
        let sql = udm(npl);
        assert!(sql.contains("toString(ext.foo)"), "{npl}: {sql}");
        assert!(!sql.contains("match(ext.foo"), "{npl}: {sql}");
        assert!(!sql.contains("lower(ext.foo)"), "{npl}: {sql}");
    }
    let sql = udm("ext.foo!=/x.+y/");
    assert!(sql.contains("match(toString(ext.foo), '(?i)x.+y') = 0"), "{sql}");
}

#[test]
fn ocsf_unmapped_json_regex_reads_a_string() {
    for npl in ["unmapped.foo=/x.+y/", "ext.foo=/x.+y/", "unmapped.foo!=/^ab/"] {
        let sql = ocsf(npl);
        assert!(sql.contains("toString(unmapped.\"foo\")"), "{npl}: {sql}");
        assert!(!sql.contains("match(unmapped.\"foo\""), "{npl}: {sql}");
    }
}

// --- pipeline stages ---------------------------------------------------------

#[test]
fn where_and_search_stages_on_numeric_fields_read_tostring() {
    for npl in [
        "* | where enriched_src_asn=/^13/",
        "* | search enriched_src_asn=/^1.+/",
        "* | stats count by enriched_src_asn | where enriched_src_asn=/^13/",
    ] {
        let sql = ocsf(npl);
        assert!(!sql.contains("match(\"src_endpoint.autonomous_system.number\""), "{npl}: {sql}");
        assert!(!sql.contains("lower(\"src_endpoint.autonomous_system.number\")"), "{npl}: {sql}");
        assert!(!sql.contains("match(enriched_src_asn,"), "{npl}: {sql}");
    }
}

#[test]
fn already_tostring_subjects_are_not_wrapped_twice() {
    // `event_type` under a `| where` stage was `lower(toString(toString(x)))`.
    let sql = udm("* | where event_type=/(List|Describe)/i");
    assert!(!sql.contains("toString(toString("), "{sql}");
    assert!(sql.contains("lower(toString(event_type)) LIKE '%list%'"), "{sql}");
}

// --- invalid regex: a 400, never a 500 -----------------------------------------

#[test]
fn invalid_regex_on_a_numeric_field_is_a_query_error() {
    for profile in [
        Arc::new(OcsfProfile::new()) as Arc<dyn SchemaProfile>,
        Arc::new(UdmProfile::new()),
    ] {
        let err = generate(profile, "enriched_src_asn=/(/").expect_err("unclosed group");
        // SqlGenError::InvalidQuery → SearchError::QueryError → HTTP 400.
        assert!(err.starts_with("Invalid query: Invalid regex pattern"), "{err}");
    }
}

// --- through SearchService::explain (the executed search path) ----------------

#[tokio::test]
async fn benchmark_query_renders_through_the_search_service() {
    let npl = "(source_type=aws_cloudtrail OR source_type=windows_event) enriched_src_asn=/.+/ \
               | stats dc(user) as users, dc(action) as actions, dc(src_ip) as ips, count \
                 by enriched_src_asn, enriched_src_country | sort -count";
    let sql = render(&sql_only_service("ocsf"), npl, &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{sql}");
    assert_never_raw(&sql, "\"src_endpoint.autonomous_system.number\"", npl);

    let sql = render(&sql_only_service("udm"), "src_port=/^44/ | stats count by src_port", &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{sql}");
    assert_never_raw(&sql, "src_port", "src_port=/^44/");
}
