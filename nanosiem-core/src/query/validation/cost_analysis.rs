// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query cost analysis and performance warnings
//!
//! Analyzes parsed queries for patterns that could cause performance problems
//! at scale, similar to industry-standard SIEM job inspectors.

use crate::query::ast::{AggFunc, BinSpan, Command, Comparator, Query, SearchExpr, WindowType};
use serde::{Deserialize, Serialize};

/// Severity level for query warnings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WarningSeverity {
    /// Informational - query will work but could be optimized
    Info,
    /// Warning - query may be slow or use significant resources
    Warning,
    /// Error - query is likely to fail or cause issues
    Error,
}

impl std::fmt::Display for WarningSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarningSeverity::Info => write!(f, "INFO"),
            WarningSeverity::Warning => write!(f, "WARNING"),
            WarningSeverity::Error => write!(f, "ERROR"),
        }
    }
}

/// A warning about potential query performance issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryWarning {
    /// Severity of the warning
    pub severity: WarningSeverity,
    /// Warning code for programmatic handling
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Suggestion for how to fix the issue
    pub suggestion: Option<String>,
    /// Estimated impact (e.g., "high memory usage", "full table scan")
    pub impact: Option<String>,
}

impl std::fmt::Display for QueryWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.message)?;
        if let Some(suggestion) = &self.suggestion {
            write!(f, "\n  Suggestion: {}", suggestion)?;
        }
        if let Some(impact) = &self.impact {
            write!(f, "\n  Impact: {}", impact)?;
        }
        Ok(())
    }
}

/// Result of query cost analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryCostAnalysis {
    /// List of warnings found
    pub warnings: Vec<QueryWarning>,
    /// Whether the query has a LIMIT before expensive operations
    pub has_early_limit: bool,
    /// Whether the query uses aggregations (which naturally limit output)
    pub has_aggregation: bool,
    /// Whether the query has unbounded dedup
    pub has_unbounded_dedup: bool,
    /// Whether the query has unbounded sort
    pub has_unbounded_sort: bool,
    /// Estimated cost score (0-100, higher = more expensive)
    pub estimated_cost: u32,
}

impl QueryCostAnalysis {
    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.severity == WarningSeverity::Error)
    }

    /// Check if there are any warnings or errors
    pub fn has_warnings(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.severity >= WarningSeverity::Warning)
    }

    /// Get the highest severity warning
    pub fn max_severity(&self) -> Option<WarningSeverity> {
        self.warnings.iter().map(|w| w.severity).max()
    }
}

/// Analyze a query for potential performance issues
///
/// This function walks through the query AST and identifies patterns that
/// could cause performance problems at scale, similar to industry-standard SIEM's job inspector.
///
/// # Examples
///
/// ```
/// use nanosiem_core::query::{parse_query, validation::analyze_query_cost};
///
/// let query = parse_query("source_type=squid_proxy | dedup src_ip").unwrap();
/// let analysis = analyze_query_cost(&query);
///
/// for warning in &analysis.warnings {
///     println!("{}", warning);
/// }
/// ```
pub fn analyze_query_cost(query: &Query) -> QueryCostAnalysis {
    let mut analysis = QueryCostAnalysis::default();
    let mut context = AnalysisContext::default();

    analyze_query_recursive(query, &mut analysis, &mut context);

    // Calculate overall cost score
    analysis.estimated_cost = calculate_cost_score(&analysis, &context);

    analysis
}

/// Context for tracking state during analysis
#[derive(Default)]
struct AnalysisContext {
    /// Whether we've seen a head/tail command
    seen_limit: bool,
    /// Whether we've seen a stats/timechart command
    seen_aggregation: bool,
    /// Position in the pipeline (0 = first command after search)
    pipeline_position: usize,
    /// Commands that require sorting
    sort_commands: Vec<String>,
    /// Commands that require full scan
    full_scan_commands: Vec<String>,
}

fn analyze_query_recursive(
    query: &Query,
    analysis: &mut QueryCostAnalysis,
    context: &mut AnalysisContext,
) {
    match query {
        Query::Search(search_expr) => {
            analyze_search_expr(search_expr, analysis, context);
        }
        Query::Piped { source, command } => {
            // First analyze the source
            analyze_query_recursive(source, analysis, context);

            // Then analyze this command
            context.pipeline_position += 1;
            analyze_command(command, analysis, context);
        }
    }

    // Update summary flags
    analysis.has_early_limit = context.seen_limit;
    analysis.has_aggregation = context.seen_aggregation;
}

fn analyze_search_expr(
    expr: &SearchExpr,
    analysis: &mut QueryCostAnalysis,
    _context: &mut AnalysisContext,
) {
    match expr {
        SearchExpr::Keyword(kw) if kw == "*" => {
            // Wildcard search without filters
            analysis.warnings.push(QueryWarning {
                severity: WarningSeverity::Info,
                code: "WILDCARD_SEARCH".to_string(),
                message: "Query uses wildcard (*) without field filters".to_string(),
                suggestion: Some(
                    "Add field filters to reduce the amount of data scanned".to_string(),
                ),
                impact: Some("May scan all events in the time range".to_string()),
            });
        }
        SearchExpr::Keyword(kw) if kw != "*" && kw.chars().any(|c| !c.is_alphanumeric()) => {
            // Bare keyword with special chars (IPs, domains, file paths) searches
            // the message column via iLike — much slower than field filters.
            let suggestion = if kw.contains('.') && kw.chars().all(|c| c.is_ascii_digit() || c == '.') {
                // Looks like an IP address
                format!(
                    "Use a field filter for faster results: src_ip=\"{}\" or dest_ip=\"{}\"",
                    kw, kw
                )
            } else {
                "Use a field filter (e.g., src_host=\"...\", url=\"...\") or add sourcetype = \"...\" to narrow the scan".to_string()
            };
            analysis.warnings.push(QueryWarning {
                severity: WarningSeverity::Info,
                code: "UNINDEXED_KEYWORD_SEARCH".to_string(),
                message: format!(
                    "Searching for \"{}\" scans the full message text across all log sources",
                    kw
                ),
                suggestion: Some(suggestion),
                impact: None,
            });
        }
        SearchExpr::FieldFilter {
            op: Comparator::Regex,
            ..
        }
        | SearchExpr::FieldFilter {
            op: Comparator::NotRegex,
            ..
        } => {
            analysis.warnings.push(QueryWarning {
                severity: WarningSeverity::Info,
                code: "REGEX_FILTER".to_string(),
                message: "Query uses regex pattern matching".to_string(),
                suggestion: Some(
                    "Consider using LIKE, CONTAINS, or exact matches for better performance"
                        .to_string(),
                ),
                impact: Some("Regex matching is slower than exact or prefix matches".to_string()),
            });
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            analyze_search_expr(left, analysis, _context);
            analyze_search_expr(right, analysis, _context);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            analyze_search_expr(inner, analysis, _context);
        }
        _ => {}
    }
}

fn analyze_command(
    command: &Command,
    analysis: &mut QueryCostAnalysis,
    context: &mut AnalysisContext,
) {
    match command {
        Command::Dedup { fields, .. } => {
            if !context.seen_limit && !context.seen_aggregation {
                analysis.has_unbounded_dedup = true;
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Error,
                    code: "UNBOUNDED_DEDUP".to_string(),
                    message: format!(
                        "dedup on {} without prior limit may cause memory exhaustion",
                        fields.join(", ")
                    ),
                    suggestion: Some(
                        "Add '| head 10000' before dedup to limit input, or use stats dc() instead".to_string()
                    ),
                    impact: Some(
                        "Requires sorting entire result set in memory. At scale, this can exhaust available memory.".to_string()
                    ),
                });
                context.full_scan_commands.push("dedup".to_string());
            }
        }

        Command::Sort { fields, .. } => {
            if !context.seen_limit && !context.seen_aggregation {
                analysis.has_unbounded_sort = true;
                let field_names: Vec<&str> = fields.iter().map(|sf| sf.field.as_str()).collect();
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Warning,
                    code: "UNBOUNDED_SORT".to_string(),
                    message: format!("sort on '{}' without prior limit may be slow", field_names.join(", ")),
                    suggestion: Some(
                        "Add '| head N' before sort to limit input, or add aggregation first".to_string()
                    ),
                    impact: Some(
                        "Requires loading and sorting entire result set. Consider if you need all results sorted.".to_string()
                    ),
                });
                for sf in fields {
                    context.sort_commands.push(sf.field.clone());
                }
            }
        }

        Command::Top { limit, .. } | Command::Rare { limit, .. } => {
            // These are aggregations that naturally limit output
            context.seen_aggregation = true;
            if *limit > 1000 {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Info,
                    code: "LARGE_TOP_LIMIT".to_string(),
                    message: format!(
                        "top/rare with limit={} may return more data than needed",
                        limit
                    ),
                    suggestion: Some(
                        "Consider reducing the limit if you don't need all results".to_string(),
                    ),
                    impact: None,
                });
            }
        }

        Command::Stats { aggregations, .. } | Command::Chart { aggregations, .. } => {
            context.seen_aggregation = true;
            // Warn when values()/list() aggregation is used without prior limit,
            // since these generate groupArray() calls that accumulate in memory
            if !context.seen_limit {
                let has_array_agg = aggregations
                    .iter()
                    .any(|a| matches!(a.func, AggFunc::Values | AggFunc::List));
                if has_array_agg {
                    analysis.warnings.push(QueryWarning {
                        severity: WarningSeverity::Info,
                        code: "STATS_VALUES_LIST_UNBOUNDED".to_string(),
                        message: "values()/list() results are capped at 100 unique elements per group".to_string(),
                        suggestion: Some("Use dc() for distinct counts, or add '| head N' before stats to limit input".to_string()),
                        impact: None,
                    });
                }
            }
        }

        Command::Timechart { span, .. } => {
            context.seen_aggregation = true;
            // Warn on very small spans that could create millions of time buckets
            // Use as_millis() to catch sub-second spans (as_secs() returns 0 for <1s)
            let span_ms = span.as_millis();
            if span_ms > 0 && span_ms < 10_000 {
                let span_display = if span_ms < 1000 {
                    format!("{}ms", span_ms)
                } else {
                    format!("{}s", span_ms / 1000)
                };
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Warning,
                    code: "TINY_TIMECHART_SPAN".to_string(),
                    message: format!("timechart with span={} may create an excessive number of time buckets over large time ranges", span_display),
                    suggestion: Some("Use span=1m or larger for queries spanning more than a few hours".to_string()),
                    impact: Some("Each time bucket consumes memory; span=1s over 90 days creates 7.7M buckets".to_string()),
                });
            }
        }

        Command::Bin {
            span, window_type, ..
        } => {
            if let (BinSpan::Time(span_dur), WindowType::Hop { advance }) = (span, window_type) {
                let advance_secs = advance.as_secs();
                if advance_secs > 0 {
                    let num_windows = span_dur.as_secs() / advance_secs;
                    if num_windows > 100 {
                        analysis.warnings.push(QueryWarning {
                            severity: WarningSeverity::Warning,
                            code: "LARGE_BIN_HOP_FANOUT".to_string(),
                            message: format!("bin hop creates {} overlapping windows per event (ARRAY JOIN multiplies rows {}x)", num_windows, num_windows),
                            suggestion: Some("Use a larger advance interval or switch to tumbling windows to reduce row multiplication".to_string()),
                            impact: Some("Each input row is expanded to N rows via ARRAY JOIN; this happens before any LIMIT is applied".to_string()),
                        });
                    }
                }
            }
        }

        Command::Sequence { .. } | Command::Funnel { .. } => {
            if !context.seen_limit && !context.seen_aggregation {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Info,
                    code: "SEQUENCE_FUNNEL_NO_FILTER".to_string(),
                    message:
                        "sequence/funnel without prior filters may process a large number of events"
                            .to_string(),
                    suggestion: Some(
                        "Add search filters (e.g., source_type=...) to reduce the input dataset"
                            .to_string(),
                    ),
                    impact: None,
                });
            }
        }

        Command::Head { count } | Command::Tail { count } => {
            context.seen_limit = true;
            if *count > 50000 {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Info,
                    code: "LARGE_LIMIT".to_string(),
                    message: format!("head/tail {} returns a large number of results", count),
                    suggestion: Some(
                        "Consider if you need this many results, or use aggregation".to_string(),
                    ),
                    impact: None,
                });
            }
        }

        Command::Transaction {
            maxspan, maxevents, ..
        } => {
            if maxspan.is_none() && maxevents.is_none() {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Error,
                    code: "UNBOUNDED_TRANSACTION".to_string(),
                    message: "transaction without maxspan or maxevents may accumulate unbounded events per group".to_string(),
                    suggestion: Some(
                        "Add maxspan=1h and maxevents=1000 to limit transaction size".to_string()
                    ),
                    impact: Some("groupArray buffers all events per group in memory; without limits this can cause OOM".to_string()),
                });
            }
        }

        Command::Table { fields } => {
            // Check for SELECT * equivalent
            if fields.iter().any(|f| f.name == "*")
                && !context.seen_limit
                && !context.seen_aggregation
            {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Info,
                    code: "TABLE_WILDCARD".to_string(),
                    message: "table * returns all fields which may include large data".to_string(),
                    suggestion: Some("Specify only the fields you need".to_string()),
                    impact: None,
                });
            }
        }

        Command::EventStats { group_by, .. } => {
            if !context.seen_limit && !context.seen_aggregation {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Error,
                    code: "UNBOUNDED_EVENTSTATS".to_string(),
                    message: "eventstats without prior limit computes window functions over the entire result set".to_string(),
                    suggestion: Some(
                        "Add search filters (e.g., source_type=...) or '| head N' before eventstats to limit input".to_string()
                    ),
                    impact: Some(
                        "Window functions on unbounded data can exhaust memory (OOM). Add filters to reduce the dataset.".to_string()
                    ),
                });
                context.full_scan_commands.push("eventstats".to_string());
            }
            // eventstats with no group_by (OVER ()) is especially expensive
            if group_by.is_none() || group_by.as_ref().map_or(false, |g| g.is_empty()) {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Info,
                    code: "EVENTSTATS_NO_PARTITION".to_string(),
                    message: "eventstats without 'by' clause applies window function to all rows".to_string(),
                    suggestion: Some(
                        "Add 'by field' to partition the computation, or ensure the dataset is well-filtered".to_string()
                    ),
                    impact: None,
                });
            }
        }

        Command::StreamStats { .. } => {
            if !context.seen_limit && !context.seen_aggregation {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Error,
                    code: "UNBOUNDED_STREAMSTATS".to_string(),
                    message: "streamstats without prior limit computes window functions over the entire result set".to_string(),
                    suggestion: Some(
                        "Add search filters (e.g., source_type=...) or '| head N' before streamstats to limit input".to_string()
                    ),
                    impact: Some(
                        "Window functions on unbounded data can exhaust memory (OOM). Add filters to reduce the dataset.".to_string()
                    ),
                });
                context.full_scan_commands.push("streamstats".to_string());
            }
        }

        Command::Join { maxout, .. } => {
            let effective = maxout.unwrap_or(10_000);
            analysis.warnings.push(QueryWarning {
                severity: WarningSeverity::Info,
                code: "SUBSEARCH_RESULT_LIMIT".to_string(),
                message: format!("join subsearch results are capped at {} rows", effective),
                suggestion: Some(
                    format!("Use maxout=N to adjust the limit (max 100,000), or add filters to narrow the subsearch")
                ),
                impact: None,
            });
        }

        Command::Append { maxout, .. } => {
            let effective = maxout.unwrap_or(10_000);
            analysis.warnings.push(QueryWarning {
                severity: WarningSeverity::Info,
                code: "SUBSEARCH_RESULT_LIMIT".to_string(),
                message: format!("append subsearch results are capped at {} rows", effective),
                suggestion: Some(
                    format!("Use maxout=N to adjust the limit (max 100,000), or add filters to narrow the subsearch")
                ),
                impact: None,
            });
        }

        Command::Mvexpand { limit, .. } => {
            if limit.is_none() {
                analysis.warnings.push(QueryWarning {
                    severity: WarningSeverity::Info,
                    code: "UNBOUNDED_MVEXPAND".to_string(),
                    message: "mvexpand without explicit limit will use server default".to_string(),
                    suggestion: Some("Add limit=N to explicitly cap the number of expanded rows".to_string()),
                    impact: None,
                });
            }
        }

        _ => {}
    }
}

fn calculate_cost_score(analysis: &QueryCostAnalysis, context: &AnalysisContext) -> u32 {
    let mut score = 0u32;

    // Base score from warnings
    for warning in &analysis.warnings {
        score += match warning.severity {
            WarningSeverity::Info => 5,
            WarningSeverity::Warning => 20,
            WarningSeverity::Error => 50,
        };
    }

    // Penalty for unbounded operations
    if analysis.has_unbounded_dedup {
        score += 30;
    }
    if analysis.has_unbounded_sort {
        score += 20;
    }

    // Bonus for having limits or aggregations
    if context.seen_limit {
        score = score.saturating_sub(10);
    }
    if context.seen_aggregation {
        score = score.saturating_sub(15);
    }

    // Cap at 100
    score.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_unbounded_dedup_warning() {
        let query = parse_query("source_type=squid_proxy | dedup src_ip").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis.has_unbounded_dedup);
        assert!(analysis.has_errors());
        assert!(analysis
            .warnings
            .iter()
            .any(|w| w.code == "UNBOUNDED_DEDUP"));
    }

    #[test]
    fn test_bounded_dedup_no_warning() {
        let query = parse_query("source_type=squid_proxy | head 1000 | dedup src_ip").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(!analysis.has_unbounded_dedup);
        assert!(!analysis
            .warnings
            .iter()
            .any(|w| w.code == "UNBOUNDED_DEDUP"));
    }

    #[test]
    fn test_dedup_after_stats_no_warning() {
        let query = parse_query("source_type=squid_proxy | stats count() by src_ip | dedup src_ip")
            .unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(!analysis.has_unbounded_dedup);
    }

    #[test]
    fn test_unbounded_sort_warning() {
        let query = parse_query("source_type=squid_proxy | sort timestamp").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis.has_unbounded_sort);
        assert!(analysis.warnings.iter().any(|w| w.code == "UNBOUNDED_SORT"));
    }

    #[test]
    fn test_bounded_sort_no_warning() {
        let query = parse_query("source_type=squid_proxy | head 1000 | sort timestamp").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(!analysis.has_unbounded_sort);
    }

    #[test]
    fn test_wildcard_search_info() {
        let query = parse_query("*").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis
            .warnings
            .iter()
            .any(|w| w.code == "WILDCARD_SEARCH"));
    }

    #[test]
    fn test_stats_is_aggregation() {
        let query = parse_query("source_type=squid_proxy | stats count() by src_ip").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis.has_aggregation);
    }

    #[test]
    fn test_cost_score_calculation() {
        // Simple query should have low cost
        let query = parse_query("source_type=squid_proxy | head 100").unwrap();
        let analysis = analyze_query_cost(&query);
        assert!(analysis.estimated_cost < 20);

        // Unbounded dedup should have high cost
        let query = parse_query("source_type=squid_proxy | dedup src_ip").unwrap();
        let analysis = analyze_query_cost(&query);
        assert!(analysis.estimated_cost >= 50);
    }

    #[test]
    fn test_transaction_without_limits() {
        let query = parse_query("source_type=squid_proxy | transaction user").unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis
            .warnings
            .iter()
            .any(|w| w.code == "UNBOUNDED_TRANSACTION"));
    }

    #[test]
    fn test_unbounded_eventstats_warning() {
        let query = parse_query("source_type=squid_proxy | eventstats avg(bytes_out) as avg_bytes")
            .unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis
            .warnings
            .iter()
            .any(|w| w.code == "UNBOUNDED_EVENTSTATS"));
    }

    #[test]
    fn test_bounded_eventstats_no_error() {
        let query = parse_query(
            "source_type=squid_proxy | head 1000 | eventstats avg(bytes_out) as avg_bytes",
        )
        .unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(!analysis
            .warnings
            .iter()
            .any(|w| w.code == "UNBOUNDED_EVENTSTATS"));
    }

    #[test]
    fn test_eventstats_no_partition_warning() {
        let query = parse_query("source_type=squid_proxy | eventstats avg(bytes_out) as avg_bytes")
            .unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(analysis
            .warnings
            .iter()
            .any(|w| w.code == "EVENTSTATS_NO_PARTITION"));
    }

    #[test]
    fn test_eventstats_with_partition_no_partition_warning() {
        let query = parse_query(
            "source_type=squid_proxy | eventstats avg(bytes_out) as avg_bytes by src_ip",
        )
        .unwrap();
        let analysis = analyze_query_cost(&query);

        assert!(!analysis
            .warnings
            .iter()
            .any(|w| w.code == "EVENTSTATS_NO_PARTITION"));
    }
}
