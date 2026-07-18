// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-1909: `risk_score`/`risk_entity`/`risk_level` are real `logs` columns and
//! must be projected into the base (stage_0) scan when a downstream `stats`
//! stage references them. Regression for `is_post_processing_field` over-matching
//! the `risk_` prefix and pruning the real columns out of the projection, which
//! made `risk_entity="x" | stats sum(risk_score)` fail with
//! "Field 'risk_score' does not exist".

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};

fn tr() -> TimeRange {
    TimeRange {
        start: "2026-07-01T00:00:00Z".parse().unwrap(),
        end: "2026-07-18T00:00:00Z".parse().unwrap(),
    }
}

fn udm_sql(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::new()
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

/// stage_0 (everything before the first stats stage) must carry the column.
fn base_scan(sql: &str) -> String {
    sql.split("stage_1").next().unwrap_or(sql).to_string()
}

#[test]
fn risk_score_projected_into_base_scan_for_stats() {
    let sql = udm_sql(r#"risk_entity="x" | stats sum(risk_score)"#);
    assert!(
        base_scan(&sql).contains("risk_score"),
        "risk_score must be projected into the base scan; got:\n{sql}"
    );
}

#[test]
fn risk_entity_and_score_projected_with_group_by() {
    let sql = udm_sql(r#"risk_entity="x" | stats sum(risk_score) by risk_entity"#);
    let base = base_scan(&sql);
    assert!(base.contains("risk_entity"), "risk_entity must be projected:\n{sql}");
    assert!(base.contains("risk_score"), "risk_score must be projected:\n{sql}");
}

#[test]
fn risk_level_projected_in_group_by() {
    let sql = udm_sql(r#"* | stats count by risk_level"#);
    assert!(
        base_scan(&sql).contains("risk_level"),
        "risk_level must be projected into the base scan:\n{sql}"
    );
}
