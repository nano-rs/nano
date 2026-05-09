// SPDX-License-Identifier: AGPL-3.0-or-later

//! Derived field collection from pipeline commands
//!
//! Walks the parsed AST and collects field names that are produced by pipeline
//! commands (stats, eval, rename, rex, bin, etc.). These fields are valid
//! references in downstream pipeline stages even though they don't exist in
//! the UDM schema.

use crate::query::ast::{AggFunc, Aggregation, Command, Query, RexMode, SearchExpr};
use std::collections::HashSet;

/// Collect all field names created by pipeline commands in a query.
///
/// Walks the parsed AST and returns a `HashSet<String>` of field names that
/// are produced by commands like `stats`, `eval`, `rename`, `rex`, `bin`, etc.
/// These fields are valid references in downstream pipeline stages even though
/// they don't exist in the UDM schema.
///
/// Field names are returned in lowercase for case-insensitive matching.
pub fn collect_derived_fields(query: &Query) -> HashSet<String> {
    let mut fields = HashSet::new();
    collect_derived_fields_recursive(query, &mut fields);
    fields
}

/// Extract field names referenced in a search expression (for sequence condition auto-capture)
fn collect_fields_from_expr(expr: &SearchExpr) -> Vec<String> {
    let mut fields = Vec::new();
    match expr {
        SearchExpr::FieldFilter { field, .. }
        | SearchExpr::FieldFunctionFilter { field, .. }
        | SearchExpr::InList { field, .. } => {
            fields.push(field.clone());
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            fields.extend(collect_fields_from_expr(left));
            fields.extend(collect_fields_from_expr(right));
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            fields.extend(collect_fields_from_expr(inner));
        }
        _ => {}
    }
    fields
}

fn collect_derived_fields_recursive(query: &Query, fields: &mut HashSet<String>) {
    match query {
        Query::Search(_) => {
            // Search expressions don't create new fields
        }
        Query::Piped { source, command } => {
            collect_derived_fields_recursive(source, fields);
            collect_command_output_fields(command, fields);
        }
    }
}

/// Get the default output name for an aggregation (mirrors clickhouse_sql_gen.rs alias logic).
fn get_aggregation_output_name(agg: &Aggregation) -> String {
    if let Some(alias) = &agg.alias {
        return alias.to_lowercase();
    }
    // count() with no field → "count"
    if agg.field.is_none() && agg.func == AggFunc::Count {
        return "count".to_string();
    }
    // values(field) / list(field) → "values_field" / "list_field"
    if matches!(agg.func, AggFunc::Values | AggFunc::List) {
        if let Some(field) = &agg.field {
            return format!("{}_{}", agg.func.as_str(), field).to_lowercase();
        }
    }
    // Everything else → function name ("dc", "sum", "avg", etc.)
    agg.func.as_str().to_lowercase()
}

pub(super) fn collect_command_output_fields(command: &Command, fields: &mut HashSet<String>) {
    match command {
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        } => {
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
            }
            if let Some(gb) = group_by {
                for f in gb {
                    fields.insert(f.to_lowercase());
                }
            }
        }
        Command::StreamStats { aggregations, .. } | Command::EventStats { aggregations, .. } => {
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
            }
        }
        Command::Eval { assignments } => {
            for a in assignments {
                fields.insert(a.field.to_lowercase());
            }
        }
        Command::Rename { mappings } => {
            for m in mappings {
                fields.insert(m.to.to_lowercase());
            }
        }
        Command::Rex { pattern, mode, .. } => {
            if matches!(mode, RexMode::Extract) {
                // Extract named capture groups (?<name>...)  and  (?P<name>...)
                for cap in regex::Regex::new(r"\(\?(?:P?<([^>]+)>)")
                    .unwrap()
                    .captures_iter(pattern)
                {
                    if let Some(name) = cap.get(1) {
                        fields.insert(name.as_str().to_lowercase());
                    }
                }
            }
        }
        Command::Bin { field, alias, .. } => {
            if let Some(a) = alias {
                fields.insert(a.to_lowercase());
            } else if let Some(f) = field {
                fields.insert(f.to_lowercase());
            } else {
                fields.insert("time_bucket".to_string());
            }
        }
        Command::Top {
            field,
            show_count,
            show_percent,
            ..
        }
        | Command::Rare {
            field,
            show_count,
            show_percent,
            ..
        } => {
            fields.insert(field.to_lowercase());
            if *show_count {
                fields.insert("count".to_string());
            }
            if *show_percent {
                fields.insert("percent".to_string());
            }
        }
        Command::Timechart {
            aggregations,
            split_by,
            ..
        } => {
            fields.insert("time_bucket".to_string());
            for sb in split_by {
                fields.insert(sb.to_lowercase());
            }
            for agg in aggregations {
                fields.insert(get_aggregation_output_name(agg));
            }
        }
        Command::Risk { .. } => {
            fields.insert("risk_score".to_string());
            fields.insert("risk_factors".to_string());
            fields.insert("risk_level".to_string());
        }
        Command::Prevalence { enrich, .. } => {
            if *enrich {
                fields.insert("host_count".to_string());
                fields.insert("is_rare".to_string());
                fields.insert("prevalence_score".to_string());
                fields.insert("total_occurrences".to_string());
                fields.insert("prevalence_first_seen".to_string());
                fields.insert("prevalence_last_seen".to_string());
                fields.insert("prevalence_type".to_string());
                fields.insert("prevalence_artifact".to_string());
                // Legacy aliases
                fields.insert("hash_prevalence".to_string());
                fields.insert("domain_prevalence".to_string());
                fields.insert("hash_first_seen".to_string());
                fields.insert("domain_first_seen".to_string());
                fields.insert("first_seen".to_string());
                fields.insert("last_seen".to_string());
            }
        }
        Command::Lookup { output_fields, .. } => {
            if let Some(of) = output_fields {
                for f in of {
                    fields.insert(f.to_lowercase());
                }
            }
        }
        Command::Transaction {
            fields: tx_fields, ..
        } => {
            for f in tx_fields {
                fields.insert(f.to_lowercase());
            }
            fields.insert("duration".to_string());
            fields.insert("eventcount".to_string());
            fields.insert("transaction_start".to_string());
            fields.insert("transaction_end".to_string());
        }
        Command::Sequence {
            group_by,
            conditions,
            capture_fields,
            ..
        } => {
            for f in group_by {
                fields.insert(f.to_lowercase());
            }
            // Sequence produces step-prefixed fields for each condition:
            // - step{N}_time, step{N}_event_id (always)
            // - step{N}_{field} for capture_fields and auto-captured condition fields
            for (i, cond) in conditions.iter().enumerate() {
                let n = i + 1;
                fields.insert(format!("step{}_time", n));
                fields.insert(format!("step{}_event_id", n));
                for field in capture_fields {
                    fields.insert(format!("step{}_{}", n, field.to_lowercase()));
                }
                // Auto-captured fields from condition expressions
                let cond_fields = collect_fields_from_expr(cond);
                for field in &cond_fields {
                    fields.insert(format!("step{}_{}", n, field.to_lowercase()));
                }
            }
            fields.insert("sequence_duration_seconds".to_string());
            fields.insert("sequence_duration".to_string());
            fields.insert("sequence_count".to_string());
        }
        Command::Spath { output, .. } => {
            if let Some(o) = output {
                fields.insert(o.to_lowercase());
            }
        }
        Command::Anomaly { .. } => {
            fields.insert("anomaly_score".to_string());
            fields.insert("is_anomaly".to_string());
        }
        // Commands that don't create new field names
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_stats_with_alias() {
        let query = parse_query("* | stats dc(user) as unique_users by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("unique_users"));
        assert!(fields.contains("src_ip"));
    }

    #[test]
    fn test_stats_default_names() {
        let query = parse_query("* | stats count() dc(user) by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("count"));
        assert!(fields.contains("dc"));
        assert!(fields.contains("src_ip"));
    }

    #[test]
    fn test_stats_values_default_name() {
        let query = parse_query("* | stats values(user) by src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("values_user"));
    }

    #[test]
    fn test_eval_assignments() {
        let query =
            parse_query("* | eval total=bytes_in+bytes_out, ratio=bytes_in/bytes_out").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("total"));
        assert!(fields.contains("ratio"));
    }

    #[test]
    fn test_rex_capture_groups() {
        let query =
            parse_query(r#"* | rex field=message "(?<username>\w+)@(?<domain>\w+\.\w+)""#).unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("username"));
        assert!(fields.contains("domain"));
    }

    #[test]
    fn test_multi_stage_pipeline() {
        // stats creates unique_users → where references it → table references it
        let query = parse_query("* | stats dc(user) as unique_users by src_ip | where unique_users > 5 | table src_ip, unique_users").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("unique_users"));
        assert!(fields.contains("src_ip"));
    }

    #[test]
    fn test_risk_command_fields() {
        let query = parse_query("* | risk score=80").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("risk_score"));
        assert!(fields.contains("risk_factors"));
        assert!(fields.contains("risk_level"));
    }

    #[test]
    fn test_bin_default_time_bucket() {
        let query = parse_query("* | bin span=1h").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("time_bucket"));
    }

    #[test]
    fn test_bin_with_alias() {
        let query = parse_query("* | bin span=1h as hourly_bucket").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("hourly_bucket"));
    }

    #[test]
    fn test_rename_creates_new_field() {
        let query = parse_query("* | rename src_ip as source_address").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("source_address"));
    }

    #[test]
    fn test_simple_search_no_derived_fields() {
        let query = parse_query("src_ip=192.168.1.1").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_transaction_derived_fields() {
        let query = parse_query("* | transaction user").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("user"));
        assert!(fields.contains("duration"));
        assert!(fields.contains("eventcount"));
    }

    #[test]
    fn test_timechart_derived_fields() {
        let query = parse_query("* | timechart span=1h count()").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("time_bucket"));
        assert!(fields.contains("count"));
    }

    #[test]
    fn test_top_derived_fields() {
        let query = parse_query("* | top src_ip").unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("src_ip"));
        assert!(fields.contains("count"));
        assert!(fields.contains("percent"));
    }

    #[test]
    #[ignore = "sequence syntax has changed; update derived-field expectations before re-enabling"]
    fn test_sequence_derived_fields() {
        let query = parse_query(
            r#"* | sequence by src_ip [action="login_failed"] [action="login_success"] maxspan=5m"#,
        )
        .unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("src_ip"));
        assert!(fields.contains("sequence_duration_seconds"));
        // Auto-captured condition fields get step prefixes
        assert!(fields.contains("step1_action"));
        assert!(fields.contains("step2_action"));
        assert!(fields.contains("step1_time"));
        assert!(fields.contains("step2_time"));
    }

    #[test]
    #[ignore = "sequence syntax has changed; update derived-field expectations before re-enabling"]
    fn test_sequence_capture_fields_derived() {
        let query = parse_query(r#"* | sequence by user, src_ip fields(user_agent, enriched_src_country) [action="login" status="failure"] [action="login" status="failure"] [action="login" status="success"] maxspan=5m"#).unwrap();
        let fields = collect_derived_fields(&query);
        assert!(fields.contains("user"));
        assert!(fields.contains("src_ip"));
        // capture_fields get step-prefixed for each condition
        assert!(fields.contains("step1_user_agent"));
        assert!(fields.contains("step3_enriched_src_country"));
        assert!(fields.contains("step3_user_agent"));
        assert!(fields.contains("sequence_duration_seconds"));
        assert!(fields.contains("sequence_count"));
    }
}
