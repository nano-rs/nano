// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-1911: under the OCSF profile the RBA `risk_score` field has no promoted
//! column — it spills into the `unmapped` JSON tail. A JSON-tail field extracts
//! as `String` by default, which broke every numeric use of `risk_score`:
//!
//! * `risk_entity="x" | stats sum(risk_score)` summed a `toString(...)` →
//!   ClickHouse "Illegal type String of argument for aggregate function sum"
//!   (Code 43).
//! * `* | sort -risk_score` ORDER BY'd a bare `risk_score` the wide `SELECT *`
//!   base scan never materialized → "Unknown identifier" (Code 47), and even
//!   when it resolved it sorted lexicographically (`"100" < "25"`).
//!
//! The fix types `risk_score`/`raw_risk_score` as `Float` on `OcsfProfile`, and
//! every value/group/sort seam picks the numeric `json_tail_access_sql`
//! extractor (`coalesce(accurateCastOrNull(..., 'Float64'), 0.)`) for a numeric
//! JSON-tail field instead of the `String` one:
//!   - the aggregation value seam (`field_to_sql_expr`),
//!   - the base-scan projection (so plain `stats … by risk_score` and any stage
//!     that binds the projected alias see a concrete `Float64`),
//!   - the window-key seam (`by_field_sql`: dedup / eventstats / …),
//!   - the `sort` ORDER BY (which for an unmaterialized tail field emits the
//!     extraction expression, not a bare alias).
//!
//! `risk_entity`/`risk_level` stay `String` (only ever grouped/filtered). UDM
//! never resolves a numeric concept to a JSON path, so the UDM SQL is unchanged
//! (guarded below).

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;
use std::sync::Arc;

fn tr() -> TimeRange {
    TimeRange {
        start: "2026-07-01T00:00:00Z".parse().unwrap(),
        end: "2026-07-19T00:00:00Z".parse().unwrap(),
    }
}

fn ocsf_sql(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::with_table("ocsf_logs")
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

fn udm_sql(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::new()
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

/// The exact numeric subcolumn extractor `json_tail_access_sql` emits for a
/// `"Float"` JSON-tail field. Every seam must reference risk_score through it.
const RISK_SCORE_FLOAT: &str = "coalesce(accurateCastOrNull(unmapped.\"risk_score\", 'Float64'), 0.)";

/// The aggregation stage (after the first stats stage) — where the aggregate
/// over the risk value is rendered.
fn agg_stage(sql: &str) -> String {
    sql.split_once("stage_1")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_else(|| sql.to_string())
}

#[test]
fn ocsf_sum_risk_score_extracts_numeric_not_string() {
    let sql = ocsf_sql(r#"risk_entity="x" | stats sum(risk_score) by risk_entity"#);
    let agg = agg_stage(&sql);
    // The summed value must be the numeric Float64 subcolumn extractor …
    assert!(
        agg.contains(RISK_SCORE_FLOAT),
        "risk_score must be summed as Float64, not String; got:\n{sql}"
    );
    // … and must NOT be a String extraction wrapped in sum() (the CH Code 43 bug).
    assert!(
        !agg.contains("sum(toString("),
        "risk_score aggregate must not sum a toString(...) String expression:\n{sql}"
    );
}

#[test]
fn ocsf_avg_risk_score_extracts_numeric() {
    // avg (and every other numeric aggregate) routes through the same value seam,
    // so they all get the Float64 extractor once risk_score is typed numeric.
    let sql = ocsf_sql(r#"* | stats avg(risk_score)"#);
    let agg = agg_stage(&sql);
    assert!(
        agg.contains(RISK_SCORE_FLOAT),
        "risk_score must extract as Float64 for avg; got:\n{sql}"
    );
    assert!(
        !agg.contains("avg(toString("),
        "risk_score avg must not average a toString(...) String expression:\n{sql}"
    );
}

#[test]
fn ocsf_stats_by_risk_score_projects_numeric() {
    // Plain `stats … by risk_score` GROUP BYs the base-scan projected alias, so
    // the projection itself must be Float64 (not `toString(...) AS risk_score`),
    // else the buckets are lexicographic strings.
    let sql = ocsf_sql(r#"* | stats count by risk_score"#);
    assert!(
        sql.contains(&format!("{RISK_SCORE_FLOAT} AS risk_score")),
        "risk_score must be projected as Float64, not String; got:\n{sql}"
    );
    assert!(
        !sql.contains("toString(") || !sql.contains("AS risk_score"),
        "risk_score projection must not be a toString(...) String alias:\n{sql}"
    );
}

#[test]
fn ocsf_sort_risk_score_orders_by_numeric_extraction() {
    // `* | sort -risk_score` runs over a wide `SELECT *` that does not materialize
    // a bare `risk_score` column — the ORDER BY must emit the extraction
    // expression (which binds to the always-projected `unmapped`), numerically.
    let sql = ocsf_sql(r#"* | sort -risk_score | head 5"#);
    assert!(
        sql.contains(&format!("ORDER BY {RISK_SCORE_FLOAT} DESC")),
        "sort must ORDER BY the numeric risk_score extraction; got:\n{sql}"
    );
    assert!(
        !sql.contains("ORDER BY risk_score DESC"),
        "sort must not ORDER BY a bare risk_score alias (Code 47 on wide scan):\n{sql}"
    );
}

#[test]
fn ocsf_dedup_risk_score_partitions_on_numeric() {
    // Window-key seam (by_field_sql): dedup GROUP BYs the extraction — numeric.
    let sql = ocsf_sql(r#"* | dedup risk_score"#);
    assert!(
        sql.contains(&format!("GROUP BY {RISK_SCORE_FLOAT}")),
        "dedup must GROUP BY the numeric risk_score extraction; got:\n{sql}"
    );
}

#[test]
fn ocsf_risk_entity_stays_string_group_by() {
    // A non-numeric risk field must keep its String extraction — it is only ever
    // grouped/filtered, so numeric-casting it would be wrong. Guards the general
    // `is_numeric_field` gate from over-casting.
    let sql = ocsf_sql(r#"* | stats count by risk_entity"#);
    assert!(
        !sql.contains("accurateCastOrNull(unmapped.\"risk_entity\""),
        "risk_entity must NOT be numeric-cast; got:\n{sql}"
    );
}

#[test]
fn udm_risk_score_seams_unchanged_bare_column() {
    // UDM byte-identical guard: risk_score is a real column under UDM, never a
    // JSON path, so every seam references the bare column with no Float64 cast.
    for q in [
        r#"risk_entity="x" | stats sum(risk_score) by risk_entity"#,
        r#"* | stats count by risk_score"#,
        r#"* | sort -risk_score | head 5"#,
        r#"* | dedup risk_score"#,
    ] {
        let sql = udm_sql(q);
        assert!(
            !sql.contains("accurateCastOrNull"),
            "UDM `{q}` must not gain a Float64 cast:\n{sql}"
        );
    }
    // The aggregate is a bare column sum.
    assert!(
        udm_sql(r#"risk_entity="x" | stats sum(risk_score) by risk_entity"#).contains("sum(risk_score)"),
        "UDM must sum the bare risk_score column"
    );
}
