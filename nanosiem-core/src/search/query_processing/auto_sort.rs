// SPDX-License-Identifier: AGPL-3.0-or-later

//! Implicit-sort rewrite for trailing `stats` / `chart` commands.
//!
//! A query like `… | stats count by src_host` runs aggregation over the full
//! event set and produces a complete GROUP BY result, but the executor wraps
//! the SQL in an outer `LIMIT N` (default 100; up to a few thousand from the
//! UI). Without an explicit `| sort`, ClickHouse returns groups in
//! hash-bucket order, so the LIMIT trims arbitrarily — analysts think they're
//! seeing the largest groups but they're seeing a random slice.
//!
//! This pass walks the pipeline and, when it ends with a `Stats`/`Chart` that
//! has a `by` clause and nothing downstream re-orders the output, synthesizes
//! a `| sort -<first-numeric-agg>` immediately after the stats command so the
//! outer LIMIT keeps the actual top-N.
//!
//! `top` / `rare` are unaffected (they self-sort). `timechart` is unaffected
//! (its output is time-ordered by design). `streamstats` is unaffected (it's
//! per-row, not a GROUP BY).
//!
//! ## Why the injected `ORDER BY` survives the executor's outer `LIMIT` wrap
//!
//! The executor wraps every generated query in
//! `SELECT * FROM (<inner_sql>) AS subquery LIMIT N OFFSET 0`
//! (see `clickhouse_executor::sql_helpers::wrap_query_with_pagination`).
//! Standard SQL does **not** guarantee that an inner `ORDER BY` survives a
//! wrapping `SELECT *` without an outer `ORDER BY`. ClickHouse, however,
//! preserves row order through subqueries and CTE chaining when no extra
//! operator (JOIN/GROUP BY/DISTINCT) intervenes — which is the case for our
//! outer wrap. The fix depends on that ClickHouse behavior; if the wrap ever
//! grows post-processing, the implicit sort must move to the outer layer.

use crate::query::{AggFunc, Aggregation, Command, Query, SearchExpr, SortField};
use crate::search::types::QueryWarningOutput;

/// Outcome of the auto-sort pass. Callers use the variants for telemetry and
/// user-facing warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoSortDecision {
    /// Pipeline does not end with a `Stats`/`Chart` that has a `by` clause.
    /// Nothing to do.
    NotApplicable,
    /// A `Sort`, `Top`, or `Rare` appears downstream of the trailing stats
    /// command; the user already controls ordering.
    ExplicitOrderPresent,
    /// The trailing stats command has only non-numeric aggregations
    /// (`values`, `list`, `sparkline`, `mode`, `first`, `last`). No implicit
    /// sort makes sense, but the truncation hazard remains — callers should
    /// emit a warning so users add an explicit `| sort` if needed.
    SkippedNonNumeric,
    /// Auto-sort appended, descending on the named output column.
    Applied { field: String },
}

/// Walks the pipeline and injects an implicit descending sort after a trailing
/// `Stats`/`Chart` when no explicit ordering follows it. See module docs.
pub fn apply_auto_sort(query: Query) -> (Query, AutoSortDecision) {
    // Fast path: a bare search has no commands to inspect.
    if matches!(query, Query::Search(_)) {
        return (query, AutoSortDecision::NotApplicable);
    }

    let (base, mut commands) = unzip_pipeline(query);

    // Find the *last* stats/chart with a `by` clause. A bare `stats count`
    // (no group_by) returns a single row, so there's nothing to sort.
    let Some(idx) = commands.iter().rposition(|cmd| {
        matches!(
            cmd,
            Command::Stats {
                group_by: Some(_),
                ..
            } | Command::Chart {
                group_by: Some(_),
                ..
            }
        )
    }) else {
        return (rebuild_pipeline(base, commands), AutoSortDecision::NotApplicable);
    };

    // If anything after the trailing stats re-orders output, leave the user's
    // intent alone.
    let explicit_order_downstream = commands.iter().skip(idx + 1).any(|cmd| {
        matches!(
            cmd,
            Command::Sort { .. } | Command::Top { .. } | Command::Rare { .. }
        )
    });
    if explicit_order_downstream {
        return (
            rebuild_pipeline(base, commands),
            AutoSortDecision::ExplicitOrderPresent,
        );
    }

    let aggregations: &[Aggregation] = match &commands[idx] {
        Command::Stats { aggregations, .. } | Command::Chart { aggregations, .. } => aggregations,
        _ => unreachable!("rposition matched only Stats/Chart"),
    };

    // Prefer the canonical `count` (no field) — it's the most common case and
    // the alias is the well-known string "count". Fall back to the first
    // sortable-numeric aggregation in declaration order.
    let pick = aggregations
        .iter()
        .find(|a| a.func == AggFunc::Count && a.field.is_none())
        .or_else(|| aggregations.iter().find(|a| a.func.is_meaningful_for_top_n()));

    let Some(agg) = pick else {
        return (
            rebuild_pipeline(base, commands),
            AutoSortDecision::SkippedNonNumeric,
        );
    };

    let field = agg.output_alias();
    let sort_cmd = Command::Sort {
        fields: vec![SortField {
            field: field.clone(),
            descending: true,
        }],
        limit: None,
    };
    commands.insert(idx + 1, sort_cmd);

    (
        rebuild_pipeline(base, commands),
        AutoSortDecision::Applied { field },
    )
}

/// Build the user-facing warning that corresponds to an `AutoSortDecision`,
/// or `None` if the decision doesn't warrant surfacing anything. Callers add
/// this to the `warnings` field of `SearchResponse`.
pub fn auto_sort_warning(decision: &AutoSortDecision) -> Option<QueryWarningOutput> {
    match decision {
        AutoSortDecision::Applied { field } => Some(QueryWarningOutput {
            severity: "info".to_string(),
            code: "AUTO_SORT_APPLIED".to_string(),
            message: format!(
                "Results sorted by '{}' descending (implicit).",
                field
            ),
            suggestion: Some(
                "Add an explicit `| sort` clause to control ordering.".to_string(),
            ),
            impact: None,
        }),
        AutoSortDecision::SkippedNonNumeric => Some(QueryWarningOutput {
            severity: "warning".to_string(),
            code: "STATS_NO_IMPLICIT_SORT".to_string(),
            message: "Trailing stats has only non-numeric aggregations \
                (values/list/sparkline/mode/first/last); the engine cannot \
                pick a default sort."
                .to_string(),
            suggestion: Some(
                "Add `| sort` to control ordering; otherwise result-set \
                 truncation may surface arbitrary rows."
                    .to_string(),
            ),
            impact: Some(
                "If the result set is truncated to a row cap, the visible \
                 rows may not be the most relevant ones."
                    .to_string(),
            ),
        }),
        AutoSortDecision::NotApplicable | AutoSortDecision::ExplicitOrderPresent => None,
    }
}

/// Unroll the left-recursive `Query::Piped` spine into `(base_search, commands
/// in pipeline order)`.
fn unzip_pipeline(query: Query) -> (SearchExpr, Vec<Command>) {
    let mut commands = Vec::new();
    let mut cur = query;
    loop {
        match cur {
            Query::Search(expr) => {
                commands.reverse();
                return (expr, commands);
            }
            Query::Piped { source, command } => {
                commands.push(command);
                cur = *source;
            }
        }
    }
}

/// Re-zip a base search and commands back into a `Query` tree.
fn rebuild_pipeline(base: SearchExpr, commands: Vec<Command>) -> Query {
    let mut q = Query::Search(base);
    for cmd in commands {
        q = Query::Piped {
            source: Box::new(q),
            command: cmd,
        };
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    fn parse(q: &str) -> Query {
        parse_query(q).expect("parse")
    }

    fn last_command(q: &Query) -> Option<&Command> {
        match q {
            Query::Search(_) => None,
            Query::Piped { command, .. } => Some(command),
        }
    }

    #[test]
    fn stats_count_by_field_gets_implicit_count_desc() {
        let q = parse("* | stats count by src_host");
        let (rewritten, decision) = apply_auto_sort(q);
        assert_eq!(
            decision,
            AutoSortDecision::Applied {
                field: "count".into()
            }
        );
        match last_command(&rewritten) {
            Some(Command::Sort { fields, limit }) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "count");
                assert!(fields[0].descending);
                assert!(limit.is_none());
            }
            other => panic!("expected trailing Sort, got {:?}", other),
        }
    }

    #[test]
    fn explicit_sort_after_stats_is_left_alone() {
        let q = parse("* | stats count by src_host | sort src_host");
        let (rewritten, decision) = apply_auto_sort(q.clone());
        assert_eq!(decision, AutoSortDecision::ExplicitOrderPresent);
        assert_eq!(rewritten, q);
    }

    #[test]
    fn stats_with_head_sorts_then_heads() {
        let q = parse("* | stats count by user | head 50");
        let (rewritten, decision) = apply_auto_sort(q);
        assert!(matches!(decision, AutoSortDecision::Applied { .. }));
        // Pipeline should now be: stats | sort -count | head 50
        let (_, cmds) = unzip_pipeline(rewritten);
        assert_eq!(cmds.len(), 3);
        assert!(matches!(cmds[0], Command::Stats { .. }));
        assert!(matches!(cmds[1], Command::Sort { .. }));
        assert!(matches!(cmds[2], Command::Head { count: 50 }));
    }

    #[test]
    fn where_between_stats_and_end_still_triggers_auto_sort() {
        let q = parse("* | stats count by user | where count > 10");
        let (rewritten, decision) = apply_auto_sort(q);
        assert!(matches!(decision, AutoSortDecision::Applied { .. }));
        let (_, cmds) = unzip_pipeline(rewritten);
        assert_eq!(cmds.len(), 3);
        assert!(matches!(cmds[0], Command::Stats { .. }));
        // Sort injected right after stats, before the where
        assert!(matches!(cmds[1], Command::Sort { .. }));
        assert!(matches!(cmds[2], Command::Where { .. }));
    }

    #[test]
    fn bare_stats_count_without_by_clause_is_noop() {
        // `stats count` (no `by`) collapses to a single row — nothing to sort.
        let q = parse("* | stats count");
        let (_rewritten, decision) = apply_auto_sort(q);
        assert_eq!(decision, AutoSortDecision::NotApplicable);
    }

    #[test]
    fn plain_search_is_noop() {
        let q = parse("error");
        let (_rewritten, decision) = apply_auto_sort(q);
        assert_eq!(decision, AutoSortDecision::NotApplicable);
    }

    #[test]
    fn timechart_is_untouched() {
        let q = parse("* | timechart span=1h count");
        let (_rewritten, decision) = apply_auto_sort(q);
        // No trailing Stats/Chart with group_by, so NotApplicable.
        assert_eq!(decision, AutoSortDecision::NotApplicable);
    }

    #[test]
    fn top_command_is_untouched() {
        let q = parse("* | top src_host");
        let (_rewritten, decision) = apply_auto_sort(q);
        assert_eq!(decision, AutoSortDecision::NotApplicable);
    }

    #[test]
    fn stats_with_only_non_numeric_aggs_emits_warning() {
        let q = parse("* | stats values(user) by src_ip");
        let (rewritten, decision) = apply_auto_sort(q.clone());
        assert_eq!(decision, AutoSortDecision::SkippedNonNumeric);
        // Pipeline unchanged.
        assert_eq!(rewritten, q);
    }

    #[test]
    fn stats_with_sum_picks_sum_as_sort_key() {
        let q = parse("* | stats sum(bytes_out) by src_ip");
        let (rewritten, decision) = apply_auto_sort(q);
        assert_eq!(
            decision,
            AutoSortDecision::Applied {
                field: "sum".into()
            }
        );
        match last_command(&rewritten) {
            Some(Command::Sort { fields, .. }) => {
                assert_eq!(fields[0].field, "sum");
                assert!(fields[0].descending);
            }
            other => panic!("expected trailing Sort, got {:?}", other),
        }
    }

    #[test]
    fn stats_with_aliased_agg_uses_alias() {
        let q = parse("* | stats sum(bytes_out) as total by src_ip");
        let (rewritten, decision) = apply_auto_sort(q);
        assert_eq!(
            decision,
            AutoSortDecision::Applied {
                field: "total".into()
            }
        );
        match last_command(&rewritten) {
            Some(Command::Sort { fields, .. }) => {
                assert_eq!(fields[0].field, "total");
            }
            other => panic!("expected trailing Sort, got {:?}", other),
        }
    }

    #[test]
    fn count_wins_over_other_aggs_when_both_present() {
        let q = parse("* | stats avg(bytes), count by src_ip");
        let (rewritten, decision) = apply_auto_sort(q);
        // count is the canonical "biggest things first" sort even though it's
        // declared second.
        assert_eq!(
            decision,
            AutoSortDecision::Applied {
                field: "count".into()
            }
        );
        match last_command(&rewritten) {
            Some(Command::Sort { fields, .. }) => assert_eq!(fields[0].field, "count"),
            other => panic!("expected trailing Sort, got {:?}", other),
        }
    }

    #[test]
    fn chart_command_is_treated_like_stats() {
        let q = parse("* | chart count by src_host");
        let (_rewritten, decision) = apply_auto_sort(q);
        assert_eq!(
            decision,
            AutoSortDecision::Applied {
                field: "count".into()
            }
        );
    }
}
