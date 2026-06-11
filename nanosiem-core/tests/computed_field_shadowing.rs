// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression: a field a pipeline command CREATES (rex capture, eval
//! assignment, rename target) whose name normalizes to a UDM canonical alias
//! must SHADOW the schema field for the rest of the pipeline (NAN-1341).
//!
//! Before the fix, `* | rex "(?P<method>GET|POST)" | stats count by method`
//! ran `normalize_field_name("method")` → `http_method` BEFORE consulting the
//! computed-field registry, so the stats stage grouped on the schema column
//! (`http_method` under UDM, `http_request.http_method` under OCSF) and
//! silently discarded the rex capture — and even renamed the output column.
//!
//! The shadow is STAGE-AWARE: a plain `stats count by method` (nothing
//! upstream computed `method`) must keep resolving to the schema column, even
//! though stats self-registers its by-fields in the whole-query computed set.

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
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"))
        ;
    ClickHouseSqlGenerator::new()
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

const REX_STATS: &str = r#"* | rex "(?P<method>GET|POST|PUT|DELETE)" | stats count by method"#;

/// The stats stage after a rex capture named like a UDM alias must GROUP BY
/// the capture column, not the schema field — under BOTH profiles.
#[test]
fn rex_capture_shadows_udm_alias_in_stats_by() {
    for (profile, sql) in [("udm", udm(REX_STATS)), ("ocsf", ocsf(REX_STATS))] {
        // The aggregation stage groups on the bare capture column and keeps
        // the capture's name as the output column.
        assert!(
            sql.contains("GROUP BY method"),
            "{profile}: stats after rex must GROUP BY the capture `method`.\nSQL:\n{sql}"
        );
        assert!(
            sql.contains("method AS method"),
            "{profile}: the by-field output column must stay `method` (not be renamed to the schema alias).\nSQL:\n{sql}"
        );
        assert!(
            !sql.contains("GROUP BY http_method")
                && !sql.contains("GROUP BY `http_request.http_method`"),
            "{profile}: stats after rex must NOT group on the schema column.\nSQL:\n{sql}"
        );
        assert!(
            !sql.contains("AS http_method"),
            "{profile}: the output column must not be renamed to `http_method`.\nSQL:\n{sql}"
        );
    }
}

/// eval-created fields shadow the same way (`uri` → `url` is a UDM alias).
#[test]
fn eval_field_shadows_udm_alias() {
    let q = r#"* | eval uri="/login" | stats count by uri"#;
    for (profile, sql) in [("udm", udm(q)), ("ocsf", ocsf(q))] {
        assert!(
            sql.contains("GROUP BY uri") && sql.contains("uri AS uri"),
            "{profile}: stats after `eval uri=` must group on / output the eval column.\nSQL:\n{sql}"
        );
        assert!(
            !sql.contains("GROUP BY url"),
            "{profile}: must not group on the schema `url` column.\nSQL:\n{sql}"
        );
    }
}

/// Stage-awareness: with NO upstream compute, `stats count by method` still
/// resolves to the schema column exactly as before.
#[test]
fn plain_stats_by_method_still_resolves_to_schema_column() {
    let sql = udm("* | stats count by method");
    assert!(
        sql.contains("http_method AS http_method") && sql.contains("GROUP BY http_method"),
        "UDM plain `stats by method` must keep resolving to http_method.\nSQL:\n{sql}"
    );

    let sql = ocsf("* | stats count by method");
    assert!(
        sql.contains("http_request.http_method"),
        "OCSF plain `stats by method` must keep resolving to the promoted column.\nSQL:\n{sql}"
    );
    assert!(
        !sql.contains("GROUP BY method"),
        "OCSF plain `stats by method` must not emit a bare `method` reference.\nSQL:\n{sql}"
    );
}

/// Stage-awareness in the other direction: a LATER eval must not shadow an
/// EARLIER stats by-field (the whole-query computed set would).
#[test]
fn later_eval_does_not_shadow_earlier_stats_stage() {
    let q = r#"* | stats count by method | eval method="x""#;
    let sql = udm(q);
    assert!(
        sql.contains("GROUP BY http_method"),
        "UDM: the stats stage runs BEFORE the eval — it must still group on the schema column.\nSQL:\n{sql}"
    );
    let sql = ocsf(q);
    assert!(
        sql.contains("http_request.http_method"),
        "OCSF: the stats stage runs BEFORE the eval — it must still resolve the promoted column.\nSQL:\n{sql}"
    );
}

/// Downstream references to the shadowed name keep working: the stats output
/// column is `method`, so `| sort method` / `| where` reference it bare.
#[test]
fn downstream_sort_references_shadowed_output_column() {
    let q = r#"* | rex "(?P<method>GET|POST)" | stats count by method | sort -method"#;
    for (profile, sql) in [("udm", udm(q)), ("ocsf", ocsf(q))] {
        assert!(
            sql.contains("ORDER BY method DESC"),
            "{profile}: sort after the shadowed stats must order by the `method` output column.\nSQL:\n{sql}"
        );
    }
}

/// The shadow also applies to the multi-stage window commands routed through
/// `by_field_sql` (dedup / eventstats partitioning).
#[test]
fn by_field_sql_commands_shadow_rex_capture() {
    // (q, the by-clause that must reference the capture)
    for (q, clause, schema_clause) in [
        (
            r#"* | rex "(?P<method>GET|POST)" | dedup method"#,
            "LIMIT 1 BY method",
            "LIMIT 1 BY http",
        ),
        (
            r#"* | rex "(?P<method>GET|POST)" | eventstats count by method"#,
            "PARTITION BY method",
            "PARTITION BY http",
        ),
    ] {
        for (profile, sql) in [("udm", udm(q)), ("ocsf", ocsf(q))] {
            assert!(
                sql.contains(clause),
                "{profile} `{q}`: by-field must reference the capture (`{clause}`).\nSQL:\n{sql}"
            );
            // Neither `... BY http_method` nor `... BY "http_request.http_method"`.
            assert!(
                !sql.contains(schema_clause),
                "{profile} `{q}`: by-field must not reference the schema column.\nSQL:\n{sql}"
            );
        }
    }
}

/// eventstats appends window columns to UNCHANGED rows — its by-fields are
/// NOT output columns, so they must not shadow downstream schema resolution.
#[test]
fn eventstats_by_field_does_not_shadow_downstream() {
    // `method` normalizes to http_method; eventstats partitions by the schema
    // column but creates no `method` column — the later stats must still
    // resolve the schema column.
    let q = "* | eventstats count by method | stats count by method";
    let sql = udm(q);
    assert!(
        sql.contains("GROUP BY http_method"),
        "UDM: stats after eventstats must still resolve `method` → http_method.\nSQL:\n{sql}"
    );
    let sql = ocsf(q);
    assert!(
        sql.contains("http_request.http_method"),
        "OCSF: stats after eventstats must still resolve the promoted column.\nSQL:\n{sql}"
    );
    assert!(
        !sql.contains("GROUP BY method"),
        "OCSF: stats after eventstats must not emit a bare `method`.\nSQL:\n{sql}"
    );

    // Same shape with a UDM-semantic OCSF field: eventstats by src_ip then
    // stats by src_ip must keep resolving src_ip to the promoted column.
    let sql = ocsf("* | eventstats count by src_ip | stats count by src_ip");
    assert!(
        sql.contains("src_endpoint.ip"),
        "OCSF: stats after eventstats must still resolve src_ip → src_endpoint.ip.\nSQL:\n{sql}"
    );
}

/// A subsearch is its own scope: the outer pipeline's rex capture must not
/// shadow schema resolution INSIDE an appended subsearch.
#[test]
fn subsearch_scope_does_not_inherit_outer_shadow() {
    let q = r#"* | rex "(?P<method>GET|POST)" | stats count by method | append [* | stats count by method]"#;
    let sql = udm(q);
    // Outer arm groups by the capture; subsearch arm still resolves the schema column.
    assert!(
        sql.contains("GROUP BY method"),
        "outer stats must group by the rex capture.\nSQL:\n{sql}"
    );
    assert!(
        sql.contains("GROUP BY http_method"),
        "subsearch stats must keep resolving `method` → http_method (its own scope).\nSQL:\n{sql}"
    );
}

/// UDM safety: representative queries WITHOUT computed-field collisions are
/// byte-identical to the legacy output shape (shadowing must be a no-op).
#[test]
fn udm_noncolliding_queries_unchanged() {
    // Non-colliding rex capture: the capture name is not a UDM alias, the
    // by-field references it bare — exactly the pre-fix behavior (NAN-1340).
    let sql = udm(r#"* | rex "(?P<level>ERROR|WARN)" | stats count by level"#);
    assert!(
        sql.contains("GROUP BY level") && sql.contains("level AS level"),
        "non-colliding rex capture grouping changed.\nSQL:\n{sql}"
    );

    // Plain schema by-field with alias normalization.
    let sql = udm("* | stats count by uri");
    assert!(
        sql.contains("url AS url") && sql.contains("GROUP BY url"),
        "plain `stats by uri` → url resolution changed.\nSQL:\n{sql}"
    );

    // Plain explicit-column pipeline.
    let sql = udm("error | stats count by src_ip | sort -count | head 10");
    assert!(
        sql.contains("src_ip AS src_ip") && sql.contains("GROUP BY src_ip"),
        "plain src_ip stats pipeline changed.\nSQL:\n{sql}"
    );
}
