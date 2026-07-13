// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregation and join detection for detection rule validation
//!
//! Functions to check whether a parsed query contains aggregations or joins,
//! which determines whether a detection rule can run in real-time mode.

use crate::query::ast::{Command, Query};

#[allow(unused_imports)]
use crate::query::pretty_print::PrettyPrint;

/// Check if a query contains aggregations
///
/// Real-time detection rules cannot use aggregations because they operate
/// on individual log events as they arrive, not on batches of events.
///
/// Returns true if the query contains any of:
/// - stats command
/// - timechart command
/// - top command
/// - rare command
/// - transaction command (groups events)
pub fn contains_aggregation(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            // Check if this command is an aggregation
            // Audit D34: keep this in lockstep with `is_aggregation_command`
            // below — `Chart` was missing here, so `validate_realtime_rule` gave
            // the wrong error message for a `| chart` rule.
            let is_agg_command = matches!(
                command,
                Command::Stats { .. }
                    | Command::Chart { .. }
                    | Command::Timechart { .. }
                    | Command::Top { .. }
                    | Command::Rare { .. }
                    | Command::Transaction { .. }
            );

            // Recursively check the source query
            is_agg_command || contains_aggregation(source)
        }
    }
}

/// Returns true if a command is an aggregation (collapses rows / loses per-event timestamps).
///
/// Used by `pre_aggregation_subquery` and the rule-test endpoint's bucket
/// histogram, which must compute counts from the pre-aggregation filter.
pub fn is_aggregation_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Stats { .. }
            | Command::Chart { .. }
            | Command::Timechart { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
            | Command::Transaction { .. }
    )
}

/// Return the sub-query before the first aggregation in pipe order, if any.
///
/// `error | where x | stats count` → `Some(error | where x)`
/// `error | where x` → `None` (no aggregation present)
/// `* | stats count` → `Some(*)`
///
/// Used by the rule-test endpoint to compute a meaningful match histogram for
/// aggregated rules: the histogram is based on the row count flowing into the
/// first aggregation, not the (already-collapsed) post-aggregation rows.
pub fn pre_aggregation_subquery(query: &Query) -> Option<&Query> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            if let Some(deeper) = pre_aggregation_subquery(source) {
                return Some(deeper);
            }
            if is_aggregation_command(command) {
                Some(source)
            } else {
                None
            }
        }
    }
}

/// Check if a query contains a `| risk` command (NAN-1805).
///
/// Rules over `dataset=risk` must not carry `| risk`: a detection rule EMITS
/// findings, and findings are the risk dataset's input — a risk-dataset rule
/// stamping risk scores would feed its own input (feedback loop). Rule
/// validation rejects such queries at save time; execution rejects them again
/// as belt-and-suspenders.
pub fn contains_risk_command(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(command, Command::Risk { .. }) || contains_risk_command(source)
        }
    }
}

/// Check if a query contains joins
///
/// Real-time detection rules cannot use joins because they require
/// correlating multiple events, which is not possible in a per-event
/// materialized view.
///
/// Returns true if the query contains any of:
/// - lookup command (enrichment joins)
/// - append command (union/join with subsearch)
/// - transaction command (implicit join by grouping)
pub fn contains_join(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            // Check if this command is a join
            let is_join_command = matches!(
                command,
                Command::Lookup { .. }
                    | Command::Append { .. }
                    | Command::Join { .. }
                    | Command::Transaction { .. }
            );

            // Recursively check the source query
            is_join_command || contains_join(source)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_contains_aggregation_simple_search() {
        let query = parse_query("error").unwrap();
        assert!(!contains_aggregation(&query));
    }

    #[test]
    fn test_contains_aggregation_with_stats() {
        let query = parse_query("error | stats count() by src_ip").unwrap();
        assert!(contains_aggregation(&query));
    }

    #[test]
    fn test_contains_aggregation_with_timechart() {
        let query = parse_query("error | timechart span=1h count()").unwrap();
        assert!(contains_aggregation(&query));
    }

    #[test]
    fn test_contains_aggregation_with_top() {
        let query = parse_query("error | top src_ip").unwrap();
        assert!(contains_aggregation(&query));
    }

    #[test]
    fn test_contains_aggregation_with_rare() {
        let query = parse_query("error | rare src_ip").unwrap();
        assert!(contains_aggregation(&query));
    }

    #[test]
    fn test_contains_aggregation_with_where() {
        let query = parse_query("error | where status=500").unwrap();
        assert!(!contains_aggregation(&query));
    }

    #[test]
    fn test_contains_join_simple_search() {
        let query = parse_query("error").unwrap();
        assert!(!contains_join(&query));
    }

    #[test]
    fn test_contains_join_with_lookup() {
        let query = parse_query("error | lookup assets src_ip").unwrap();
        assert!(contains_join(&query));
    }

    #[test]
    fn test_contains_join_with_transaction() {
        let query = parse_query("error | transaction user").unwrap();
        assert!(contains_join(&query));
    }

    #[test]
    fn test_contains_join_with_where() {
        let query = parse_query("error | where status=500").unwrap();
        assert!(!contains_join(&query));
    }

    #[test]
    fn test_complex_query_with_aggregation() {
        let query = parse_query("error | where status=500 | stats count() by src_ip").unwrap();
        assert!(contains_aggregation(&query));
        assert!(!contains_join(&query));
    }

    #[test]
    fn test_complex_query_with_join() {
        let query = parse_query("error | where status=500 | lookup assets src_ip").unwrap();
        assert!(!contains_aggregation(&query));
        assert!(contains_join(&query));
    }

    #[test]
    fn test_pre_aggregation_subquery_no_agg() {
        let query = parse_query("error | where status=500").unwrap();
        assert!(pre_aggregation_subquery(&query).is_none());
    }

    #[test]
    fn test_pre_aggregation_subquery_stats() {
        let query = parse_query("error | where status=500 | stats count by src_ip").unwrap();
        let base = pre_aggregation_subquery(&query).expect("expected base filter");
        // Base filter should be everything before the stats command.
        assert_eq!(
            crate::query::PrettyPrint::pretty_print(base),
            "error | where status=500"
        );
    }

    #[test]
    fn test_pre_aggregation_subquery_timechart() {
        let query = parse_query("error | timechart span=1h count").unwrap();
        let base = pre_aggregation_subquery(&query).expect("expected base filter");
        assert_eq!(crate::query::PrettyPrint::pretty_print(base), "error");
    }

    #[test]
    fn test_pre_aggregation_subquery_after_stats() {
        // First aggregation wins — commands after stats stay collapsed.
        let query = parse_query("error | stats count by src_ip | where count > 10").unwrap();
        let base = pre_aggregation_subquery(&query).expect("expected base filter");
        assert_eq!(crate::query::PrettyPrint::pretty_print(base), "error");
    }

    #[test]
    fn test_contains_risk_command() {
        // NAN-1805: the feedback-loop guard's `| risk` detector.
        let with_risk = parse_query("error | risk score=50 entity=src_ip").unwrap();
        assert!(contains_risk_command(&with_risk));

        // Buried mid-pipeline still detected.
        let buried =
            parse_query("error | risk score=50 entity=src_ip | where status=500").unwrap();
        assert!(contains_risk_command(&buried));

        // The risk-notable rule shape carries no `| risk`.
        let notable =
            parse_query("* | where score_24h > 500 or score_7d > 1000 | table entity, score_24h")
                .unwrap();
        assert!(!contains_risk_command(&notable));

        // A field merely NAMED risk_score is not the command.
        let field_ref = parse_query("* | where risk_score > 10").unwrap();
        assert!(!contains_risk_command(&field_ref));
    }
}
