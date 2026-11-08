// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4284 review: the join narrowing set is bounded and cluster-safe.
use super::{ClickHouseSqlGenerator, JOIN_NARROW_KEY_BOUND};
use crate::query::{parse_query, TimeRange};

fn sql(gen: &ClickHouseSqlGenerator) -> String {
    let range = TimeRange {
        start: "2026-10-01T00:00:00Z".parse().unwrap(),
        end: "2026-10-01T01:00:00Z".parse().unwrap(),
    };
    let query = parse_query("* | join type=left user [search * | stats count as n by user]").unwrap();
    gen.generate(&query, &range).unwrap()
}

#[test]
fn single_node_narrowing_is_bounded_with_an_overflow_fallback() {
    let sql = sql(&ClickHouseSqlGenerator::new());
    let bound = JOIN_NARROW_KEY_BOUND;
    assert!(sql.contains(&format!("\"user\" IN (SELECT DISTINCT \"user\" FROM stage_0 LIMIT {bound})")), "{sql}");
    assert!(
        sql.contains(&format!(
            "OR (SELECT count() FROM (SELECT DISTINCT \"user\" FROM stage_0 LIMIT {})) > {bound}",
            bound + 1
        )),
        "{sql}"
    );
    assert!(!sql.contains("GLOBAL IN"), "{sql}");
}

#[test]
fn clustered_narrowing_builds_one_coordinator_set() {
    let sql = sql(&ClickHouseSqlGenerator::with_table("logs_distributed").with_cluster_routing(true));
    assert!(sql.contains("\"user\" GLOBAL IN (SELECT DISTINCT \"user\" FROM stage_0 LIMIT"), "{sql}");
    assert!(sql.contains("FROM logs_distributed"), "{sql}");
}
