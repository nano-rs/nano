// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query enrichment for detection rules
//!
//! Auto-injects `min(timestamp) as _first_seen` and `max(timestamp) as _last_seen`
//! into stats commands so aggregated detection results always carry real event
//! time bounds for latency calculation.

use crate::query::{AggFunc, Aggregation, Command, Query};

/// Enriches stats commands with timestamp bounds so aggregated results
/// always carry event timing information for detection latency calculation.
///
/// Walks the Query AST recursively and for each `Command::Stats`, appends
/// `min(timestamp) as _first_seen` and `max(timestamp) as _last_seen`
/// unless equivalent aggregations already exist.
///
/// Commands NOT modified:
/// - `Timechart` — already groups by time buckets (`_time`)
/// - `EventStats` / `StreamStats` — preserve individual rows with timestamps
/// - `Top` / `Rare` — frequency-based, no aggregation structure to enrich
pub fn inject_timestamp_bounds(query: &Query) -> Query {
    match query {
        Query::Search(expr) => Query::Search(expr.clone()),
        Query::Piped { source, command } => {
            let enriched_source = inject_timestamp_bounds(source);
            let enriched_command = match command {
                Command::Stats {
                    aggregations,
                    group_by,
                } => {
                    let new_aggs = enrich_aggregations(aggregations);
                    Command::Stats {
                        aggregations: new_aggs,
                        group_by: group_by.clone(),
                    }
                }
                Command::Chart {
                    aggregations,
                    group_by,
                } => {
                    let new_aggs = enrich_aggregations(aggregations);
                    Command::Chart {
                        aggregations: new_aggs,
                        group_by: group_by.clone(),
                    }
                }
                other => other.clone(),
            };
            Query::Piped {
                source: Box::new(enriched_source),
                command: enriched_command,
            }
        }
    }
}

/// Append min/max(timestamp) aggregations if not already present.
fn enrich_aggregations(aggregations: &[Aggregation]) -> Vec<Aggregation> {
    let mut new_aggs = aggregations.to_vec();

    if !has_timestamp_agg(&new_aggs, AggFunc::Min, "_first_seen") {
        new_aggs.push(Aggregation::with_alias(
            AggFunc::Min,
            Some("timestamp".to_string()),
            "_first_seen".to_string(),
        ));
    }

    if !has_timestamp_agg(&new_aggs, AggFunc::Max, "_last_seen") {
        new_aggs.push(Aggregation::with_alias(
            AggFunc::Max,
            Some("timestamp".to_string()),
            "_last_seen".to_string(),
        ));
    }

    new_aggs
}

/// Check if aggregations already contain a min/max on timestamp,
/// OR if the target alias is already taken by another aggregation.
fn has_timestamp_agg(aggregations: &[Aggregation], func: AggFunc, alias: &str) -> bool {
    aggregations.iter().any(|agg| {
        // Already has this function on timestamp
        (agg.func == func
            && agg.field.as_deref().map(|f: &str| f.to_lowercase())
                == Some("timestamp".to_string()))
            // Or the alias is already in use
            || agg.alias.as_deref() == Some(alias)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_injects_timestamp_bounds_into_stats() {
        let query = parse_query("error | stats count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // Extract the stats command
        if let Query::Piped { command, .. } = &enriched {
            if let Command::Stats { aggregations, .. } = command {
                assert_eq!(aggregations.len(), 3); // count + _first_seen + _last_seen
                assert_eq!(aggregations[1].alias.as_deref(), Some("_first_seen"));
                assert_eq!(aggregations[1].func, AggFunc::Min);
                assert_eq!(aggregations[1].field.as_deref(), Some("timestamp"));
                assert_eq!(aggregations[2].alias.as_deref(), Some("_last_seen"));
                assert_eq!(aggregations[2].func, AggFunc::Max);
                assert_eq!(aggregations[2].field.as_deref(), Some("timestamp"));
            } else {
                panic!("Expected Stats command");
            }
        } else {
            panic!("Expected Piped query");
        }
    }

    #[test]
    fn test_skips_injection_when_already_present() {
        let query = parse_query(
            "error | stats count, min(timestamp) as first_seen, max(timestamp) as last_seen by src_ip",
        )
        .unwrap();
        let enriched = inject_timestamp_bounds(&query);

        if let Query::Piped { command, .. } = &enriched {
            if let Command::Stats { aggregations, .. } = command {
                // Should not add duplicates
                assert_eq!(aggregations.len(), 3);
            } else {
                panic!("Expected Stats command");
            }
        } else {
            panic!("Expected Piped query");
        }
    }

    #[test]
    fn test_no_modification_for_non_stats_query() {
        let query = parse_query("error | where status=500 | head 10").unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // Should pass through unchanged (no stats command)
        // Just verify it doesn't panic
        assert!(matches!(enriched, Query::Piped { .. }));
    }

    #[test]
    fn test_handles_search_only_query() {
        let query = parse_query("error").unwrap();
        let enriched = inject_timestamp_bounds(&query);
        assert!(matches!(enriched, Query::Search(_)));
    }

    #[test]
    fn test_nested_pipes_with_stats() {
        let query = parse_query("error | where status=500 | stats count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // The stats is the outermost command, should be enriched
        if let Query::Piped { command, .. } = &enriched {
            if let Command::Stats { aggregations, .. } = command {
                assert_eq!(aggregations.len(), 3);
            } else {
                panic!("Expected Stats command");
            }
        } else {
            panic!("Expected Piped query");
        }
    }
}
