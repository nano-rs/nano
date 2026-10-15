// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact additive partials for scalar stats count and count histograms.
//! Unrecognized stages/aggregates retain the existing whole-window plan.
use crate::planner::CompiledQuery;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) struct Shape {
    pub kind: &'static str,
    alias: String,
    histogram: bool,
    limit: usize,
}

pub(super) fn shape(query: &CompiledQuery) -> Option<Shape> {
    if query.dataset != "logs" {
        return None;
    }
    static SHAPES: std::sync::OnceLock<(regex::Regex, regex::Regex)> = std::sync::OnceLock::new();
    let (scalar, histogram) = SHAPES.get_or_init(|| (
        regex::Regex::new(r"(?s)^WITH stage_0 AS \(\s*SELECT [^\n]* FROM __nano_lake_source__\s+WHERE .*\n\),\s*stage_1 AS \(\s*SELECT count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s+FROM stage_0\s*\)\s*SELECT \* FROM stage_1 LIMIT [0-9]+ SETTINGS [^;\n]+$").unwrap(),
        regex::Regex::new(r"(?s)^WITH stage_0 AS \(\s*SELECT [^\n]* FROM __nano_lake_source__\s+WHERE .*\n\),\s*stage_1 AS \(\s*SELECT (?:toStartOfMinute|toStartOfFiveMinutes|toStartOfTenMinutes|toStartOfFifteenMinutes|toStartOfHour|toStartOfInterval)\(time(?:, INTERVAL [0-9]+ (?:MINUTE|HOUR))?\) AS time_bucket, count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s+FROM stage_0\s+GROUP BY time_bucket\s+ORDER BY time_bucket\s*\)\s*SELECT \* FROM stage_1 LIMIT [0-9]+ SETTINGS [^;\n]+$").unwrap(),
    ));
    // Nested query stages or sources require a different merge contract.
    if query.sql.matches("__nano_lake_source__").count() != 1 || query.sql.contains("stage_2") {
        return None;
    }
    let (captures, is_histogram) = match scalar.captures(&query.sql) {
        Some(captures) => (captures, false),
        None => (histogram.captures(&query.sql)?, true),
    };
    if is_histogram && &captures[1] == "time_bucket" {
        return None;
    }
    Some(Shape {
        kind: if is_histogram {
            "histogram"
        } else {
            "stats_count_partial"
        },
        alias: captures[1].into(),
        histogram: is_histogram,
        limit: query.limit,
    })
}

impl Shape {
    pub fn merge(&self, partials: Vec<Vec<Value>>) -> anyhow::Result<Vec<Value>> {
        let mut buckets: BTreeMap<String, (Value, u64)> = BTreeMap::new();
        for row in partials.into_iter().flatten() {
            let key = if self.histogram {
                row["time_bucket"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("partial omitted time bucket"))?
                    .to_owned()
            } else {
                String::new()
            };
            let count = row[&self.alias]
                .as_u64()
                .or_else(|| row[&self.alias].as_str().and_then(|s| s.parse().ok()))
                .ok_or_else(|| anyhow::anyhow!("partial omitted integer count"))?;
            let entry = buckets.entry(key).or_insert_with(|| (row, 0));
            entry.1 = entry
                .1
                .checked_add(count)
                .ok_or_else(|| anyhow::anyhow!("partial count overflow"))?;
        }
        if buckets.is_empty() && !self.histogram {
            return Ok(vec![json!({self.alias.clone(): 0})]);
        }
        Ok(buckets
            .into_values()
            .take(self.limit)
            .map(|(mut row, count)| {
                row[&self.alias] = if row[&self.alias].is_string() {
                    json!(count.to_string())
                } else {
                    json!(count)
                };
                row
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_merges_overlap_and_applies_limit_after_sum() {
        let shape = Shape {
            kind: "histogram",
            alias: "n".into(),
            histogram: true,
            limit: 2,
        };
        let rows = shape
            .merge(vec![
                vec![
                    json!({"time_bucket":"2026-10-01 00:00:00","n":"2"}),
                    json!({"time_bucket":"2026-10-01 00:02:00","n":"7"}),
                ],
                vec![
                    json!({"time_bucket":"2026-10-01 00:00:00","n":"3"}),
                    json!({"time_bucket":"2026-10-01 00:01:00","n":"4"}),
                ],
            ])
            .unwrap();
        assert_eq!(
            rows,
            vec![
                json!({"time_bucket":"2026-10-01 00:00:00","n":"5"}),
                json!({"time_bucket":"2026-10-01 00:01:00","n":"4"})
            ]
        );
        assert!(shape.merge(vec![vec![json!({"n":1})]]).is_err());
    }
    #[test]
    fn scalar_empty_and_overflow_are_explicit() {
        let shape = Shape {
            kind: "stats_count_partial",
            alias: "count".into(),
            histogram: false,
            limit: 2,
        };
        assert_eq!(shape.merge(vec![]).unwrap(), vec![json!({"count":0})]);
        assert_eq!(
            shape
                .merge(vec![vec![json!({"count":2})], vec![json!({"count":3})]])
                .unwrap(),
            vec![json!({"count":5})]
        );
        assert!(shape
            .merge(vec![vec![json!({"count":u64::MAX}), json!({"count":1})]])
            .is_err());
    }
}
