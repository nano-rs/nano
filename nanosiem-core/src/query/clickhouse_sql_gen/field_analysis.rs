// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field requirement analysis for query optimization

use super::{is_explicit_column, is_known_metadata_field, normalize_field_name};
use crate::query::ast::*;
use std::collections::HashSet;

/// Analyze query to determine which fields are actually needed
/// Returns None if all fields are needed (SELECT *), or Some(set) for specific fields
///
/// When `table_view` is true, always returns minimal fields for fast table display.
/// Users can fetch full row data on demand when they expand a row.
pub(crate) fn analyze_required_fields(query: &Query, table_view: bool) -> Option<HashSet<String>> {
    let mut fields = HashSet::new();
    let mut needs_all_fields = false;

    collect_required_fields_from_query(query, &mut fields, &mut needs_all_fields);

    // Remove fields that are added by post-processing (ai, anomaly, prevalence, risk).
    // These never exist in ClickHouse columns or ext JSON — they're computed at runtime.
    fields.retain(|f| !is_post_processing_field(f));

    // Always include core fields needed for basic functionality
    fields.insert("id".to_string());
    fields.insert("timestamp".to_string());
    fields.insert("message".to_string());
    fields.insert("source_type".to_string());

    // In table_view mode, optimize column fetching:
    // - If the query has explicit field selection (| table, | fields), just use those
    //   plus core fields — the user chose their columns, respect that
    // - If it's a bare search with no field selection, add default summary fields
    //   so the event row has useful context without fetching all 150+ columns
    // - If the query has aggregation (stats/top/rare/chart), skip summary fields —
    //   the aggregation only needs group_by + aggregation fields, not all 13 defaults
    if table_view && !needs_all_fields {
        let has_explicit_fields = has_table_or_fields_command(query);
        let has_aggregation = has_aggregation_command(query);
        if !has_explicit_fields && !has_aggregation {
            for f in &[
                "src_host",
                "src_ip",
                "dest_host",
                "dest_ip",
                "user",
                "action",
                "status",
                "severity",
                "process_name",
                "src_port",
                "dest_port",
                "protocol",
                "prevalence_min",
                // Enrichment columns are MATERIALIZED in ClickHouse, so they
                // must be explicitly selected (SELECT * excludes them).
                // Including them here ensures enrichment data appears in the
                // initial search results and is visible in the field stats sidebar.
                "enriched_src_country",
                "enriched_src_asn",
                "enriched_src_as_name",
                "enriched_dest_country",
                "enriched_dest_asn",
                "enriched_dest_as_name",
            ] {
                fields.insert(f.to_string());
            }
        }
        return Some(fields);
    }

    // If it's just a search with no piped commands, return all fields
    // (unless table_view already handled it above)
    if matches!(query, Query::Search(_)) {
        return None;
    }

    // If any command needs all fields, we can't optimize
    if needs_all_fields {
        return None;
    }

    // If we have a reasonable number of fields, use field pruning
    // If we need too many fields (>50), it's not worth the optimization
    if fields.len() < 50 {
        Some(fields)
    } else {
        None
    }
}

/// Check if the query has an explicit | table or | fields command
fn has_table_or_fields_command(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(command, Command::Table { .. } | Command::Fields { .. })
                || has_table_or_fields_command(source)
        }
    }
}

/// Check if the query has an aggregation command (stats, top, rare, chart, timechart)
/// Used to skip adding summary fields for aggregation queries — they only need
/// group_by + aggregation fields, not 13 default columns.
fn has_aggregation_command(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(
                command,
                Command::Stats { .. }
                    | Command::Chart { .. }
                    | Command::Timechart { .. }
                    | Command::Top { .. }
                    | Command::Rare { .. }
            ) || has_aggregation_command(source)
        }
    }
}

/// Recursively collect fields referenced in the query
fn collect_required_fields_from_query(
    query: &Query,
    fields: &mut HashSet<String>,
    needs_all: &mut bool,
) {
    match query {
        Query::Search(expr) => {
            collect_fields_from_search_expr(expr, fields);
        }
        Query::Piped { source, command } => {
            collect_required_fields_from_query(source, fields, needs_all);
            collect_fields_from_command(command, fields, needs_all);
        }
    }
}

/// Collect fields from search expressions
fn collect_fields_from_search_expr(expr: &SearchExpr, fields: &mut HashSet<String>) {
    match expr {
        SearchExpr::Keyword(_) => {
            // Keywords search message, already in core fields
        }
        SearchExpr::FieldFilter { field, .. } => {
            fields.insert(normalize_field_name(field).to_string());
        }
        SearchExpr::FunctionFilter { function, .. } => {
            // Collect fields from function arguments
            collect_fields_from_eval_expr(function, fields);
        }
        SearchExpr::FieldFunctionFilter {
            field, function, ..
        } => {
            // Collect the field and fields from function arguments
            fields.insert(normalize_field_name(field).to_string());
            collect_fields_from_eval_expr(function, fields);
        }
        SearchExpr::InList { field, .. } => {
            fields.insert(normalize_field_name(field).to_string());
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            collect_fields_from_search_expr(left, fields);
            collect_fields_from_search_expr(right, fields);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            collect_fields_from_search_expr(inner, fields);
        }
        SearchExpr::BooleanFunction(function) => {
            collect_fields_from_eval_expr(function, fields);
        }
        SearchExpr::LiteralComparison { .. } => {
            // Literal comparisons don't reference any fields
        }
        SearchExpr::InSubsearch { field, .. } => {
            fields.insert(field.clone());
        }
    }
}

/// Collect fields from commands
fn collect_fields_from_command(cmd: &Command, fields: &mut HashSet<String>, needs_all: &mut bool) {
    match cmd {
        Command::Table {
            fields: table_fields,
        } => {
            // Table command explicitly selects fields
            if table_fields.len() == 1 && table_fields[0].name == "*" {
                *needs_all = true;
            } else {
                for tf in table_fields {
                    fields.insert(normalize_field_name(&tf.name).to_string());
                }
            }
        }
        Command::Fields {
            fields: field_list,
            keep,
        } => {
            if *keep {
                // Include mode - only these fields
                for f in field_list {
                    fields.insert(normalize_field_name(f).to_string());
                }
            } else {
                // Exclude mode - we need all fields to know what to exclude
                *needs_all = true;
            }
        }
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        } => {
            // Collect fields from aggregations
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(normalize_field_name(field).to_string());
                }
                // Extract fields from condition if present
                if let Some(condition) = &agg.condition {
                    collect_fields_from_eval_expr(condition, fields);
                }
            }
            // Collect group by fields
            if let Some(group_fields) = group_by {
                for field in group_fields {
                    fields.insert(normalize_field_name(field).to_string());
                }
            }
        }
        Command::StreamStats {
            aggregations,
            group_by,
            ..
        } => {
            // StreamStats needs all fields plus window function fields
            *needs_all = true;
            fields.insert("timestamp".to_string());
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(normalize_field_name(field).to_string());
                }
            }
            if let Some(group_fields) = group_by {
                for field in group_fields {
                    fields.insert(normalize_field_name(field).to_string());
                }
            }
        }
        Command::Timechart {
            aggregations,
            split_by,
            ..
        } => {
            fields.insert("timestamp".to_string());
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(normalize_field_name(field).to_string());
                }
            }
            for field in split_by {
                fields.insert(normalize_field_name(field).to_string());
            }
        }
        Command::Where { condition } => {
            // Where clauses filter results but users expect to see all fields
            *needs_all = true;
            collect_fields_from_search_expr(condition, fields);
        }
        Command::Sort {
            fields: sort_fields,
            ..
        } => {
            // Sort reorders results but users expect to see all fields
            *needs_all = true;
            for sf in sort_fields {
                fields.insert(normalize_field_name(&sf.field).to_string());
            }
        }
        Command::Rename { mappings } => {
            // Rename transforms fields but users expect to see all fields
            *needs_all = true;
            for mapping in mappings {
                fields.insert(normalize_field_name(&mapping.from).to_string());
            }
        }
        Command::Eval { assignments } => {
            // Eval adds computed fields but users expect to see all fields plus new ones
            *needs_all = true;
            for assignment in assignments {
                collect_fields_from_eval_expr(&assignment.expression, fields);
            }
        }
        Command::Dedup {
            fields: dedup_fields,
            ..
        } => {
            // Dedup removes duplicates but users expect to see all fields
            *needs_all = true;
            for field in dedup_fields {
                fields.insert(normalize_field_name(field).to_string());
            }
        }
        Command::Bin { field, .. } => {
            // Bin modifies a field but users expect to see all fields
            *needs_all = true;
            if let Some(f) = field {
                fields.insert(normalize_field_name(f).to_string());
            } else {
                fields.insert("timestamp".to_string());
            }
        }
        Command::Top {
            field, by_fields, ..
        }
        | Command::Rare {
            field, by_fields, ..
        } => {
            fields.insert(normalize_field_name(field).to_string());
            for by in by_fields {
                fields.insert(normalize_field_name(by).to_string());
            }
        }
        Command::Transaction {
            fields: trans_fields,
            ..
        } => {
            for field in trans_fields {
                fields.insert(normalize_field_name(field).to_string());
            }
        }
        Command::Risk {
            score,
            entity_field,
            ..
        } => {
            // Risk adds computed fields, users expect to see all fields
            *needs_all = true;
            if let Some(field) = entity_field {
                fields.insert(normalize_field_name(field).to_string());
            }
            // Extract fields from dynamic score expression
            if let RiskScoreExpr::Dynamic(expr) = score {
                collect_fields_from_eval_expr(expr, fields);
            }
        }
        Command::Prevalence { .. } => {
            // Prevalence needs file_hash, url_domain, etc. - safer to get all fields
            *needs_all = true;
        }
        // Commands that need all fields or don't affect field selection
        Command::Head { .. }
        | Command::Tail { .. }
        | Command::Lookup { .. }
        | Command::Rex { .. }
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. }
        | Command::Append { .. }
        | Command::Join { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::InputLookup { .. }
        | Command::Tree { .. } => {
            // These commands either need all fields or we can't easily determine requirements
            *needs_all = true;
        }
        Command::EventStats {
            aggregations,
            group_by,
        } => {
            // Collect fields from aggregations
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(normalize_field_name(field).to_string());
                }
            }
            // Collect fields from group by
            if let Some(group_fields) = group_by {
                for field in group_fields {
                    fields.insert(normalize_field_name(field).to_string());
                }
            }
            // EventStats preserves all rows, so we need all fields
            *needs_all = true;
        }
        Command::Sequence {
            group_by,
            conditions,
            capture_fields,
            ..
        } => {
            // Collect group by fields
            for field in group_by {
                fields.insert(normalize_field_name(field).to_string());
            }
            // Collect fields from conditions
            for condition in conditions {
                collect_fields_from_search_expr(condition, fields);
            }
            // Collect user-specified capture fields
            for field in capture_fields {
                fields.insert(normalize_field_name(field).to_string());
            }
            // Need timestamp for sequenceMatch and id for event drill-down
            fields.insert("timestamp".to_string());
            fields.insert("id".to_string());
        }
        Command::Funnel {
            group_by, steps, ..
        } => {
            // Collect group by fields
            for field in group_by {
                fields.insert(normalize_field_name(field).to_string());
            }
            // Collect fields from step conditions
            for (_, condition) in steps {
                collect_fields_from_search_expr(condition, fields);
            }
            // Need timestamp for windowFunnel
            fields.insert("timestamp".to_string());
        }
        Command::Anomaly {
            field, by_fields, ..
        } => {
            // Skip aggregation expressions like "count()" — they're computed in the SQL gen,
            // not column references to project
            if !field.contains('(') {
                fields.insert(normalize_field_name(field).to_string());
            }
            for by in by_fields {
                fields.insert(normalize_field_name(by).to_string());
            }
            *needs_all = true; // Need all fields to show anomalous events
        }
        Command::ResolveIdentity { field, .. } => {
            // ResolveIdentity enriches with identity data via ASOF JOIN
            // Need the IP field being resolved plus timestamp for the join
            fields.insert(normalize_field_name(field).to_string());
            fields.insert("timestamp".to_string());
            *needs_all = true; // Need all fields to enrich them
        }
        Command::Asset {
            identifier_field, ..
        } => {
            // Asset command creates a comprehensive view of an asset's activity
            // Need all fields for identity resolution and activity aggregation
            if let Some(field) = identifier_field {
                fields.insert(normalize_field_name(field).to_string());
            }
            fields.insert("timestamp".to_string());
            *needs_all = true; // Need all fields for comprehensive asset view
        }
        Command::Cloud { .. } => {
            // Cloud command re-queries ClickHouse in post-processing
            // Need all fields for facets, events, and resource analysis
            *needs_all = true;
        }
        Command::Lateral { .. } => {
            // Lateral command re-queries ClickHouse in post-processing for movement tracing
            *needs_all = true;
        }
        Command::Ai { .. } => {
            // AI command enriches results in post-processing — need all fields for context
            // but its output columns are added by post-processing, not from the database
            *needs_all = true;
        }
        Command::Output { .. } => {
            // Output is a sink directive, doesn't affect field selection
        }
    }
}

/// Collect fields from eval expressions
fn collect_fields_from_eval_expr(expr: &EvalExpression, fields: &mut HashSet<String>) {
    match expr {
        EvalExpression::Field(field) => {
            fields.insert(normalize_field_name(field).to_string());
        }
        EvalExpression::Literal(_) => {}
        EvalExpression::BinaryOp { left, right, .. } => {
            collect_fields_from_eval_expr(left, fields);
            collect_fields_from_eval_expr(right, fields);
        }
        EvalExpression::FunctionCall { args, .. } => {
            for arg in args {
                collect_fields_from_eval_expr(arg, fields);
            }
        }
    }
}

/// Check if a field is produced by post-processing commands (ai, anomaly, risk, etc.)
/// and does not exist in the database. These must be excluded from SQL SELECT clauses.
fn is_post_processing_field(field: &str) -> bool {
    field.starts_with("ai_")
        || field.starts_with("anomaly_")
        || field.starts_with("risk_")
        || matches!(
            field,
            "is_anomaly" | "is_rare" | "host_count" | "total_occurrences"
        )
}

/// Analyze query to find fields that live in the `ext` JSON column.
///
/// These are fields referenced by the query that are NOT explicit columns,
/// NOT UDM fields, NOT metadata fields, and don't contain dots (which
/// would be handled by JSON path syntax). Fields found here need to be
/// materialized in the base SELECT so they're visible to downstream CTEs.
pub(crate) fn analyze_ext_fields(query: &Query) -> HashSet<String> {
    let mut all_fields = HashSet::new();
    let mut needs_all = false;
    collect_required_fields_from_query(query, &mut all_fields, &mut needs_all);

    // Collect field names that are computed by the query pipeline (stats aliases,
    // sequence outputs, etc.) — these must NOT be materialized from ext JSON
    let computed = collect_computed_field_names(query);

    all_fields
        .into_iter()
        .filter(|f| {
            let f = f.as_str();
            !is_explicit_column(f)
                && !f.starts_with("metadata_")
                && !f.starts_with("metadata.")
                && !is_known_metadata_field(f)
                && !f.contains('.')
                && !computed.contains(f)
                // Skip fields added by post-processing commands (ai, anomaly, risk, etc.)
                // These never exist in the ext JSON column
                && !is_post_processing_field(f)
                // Skip aggregation expressions like "count()", "sum(bytes_out)"
                && !f.contains('(')
                // Skip common computed/result column names
                && !matches!(f,
                    "count" | "sum" | "avg" | "min" | "max" | "total" |
                    "time_bucket" | "bytes" | "total_bytes" | "requests" | "*"
                )
        })
        .collect()
}

/// Collect field names that are created/computed by query pipeline commands.
/// These are output column names from stats, sequence, transaction, eval, etc.
/// that should NOT be treated as ext JSON fields.
fn collect_computed_field_names(query: &Query) -> HashSet<String> {
    let mut computed = HashSet::new();
    collect_computed_from_query(query, &mut computed);
    computed
}

fn collect_computed_from_query(query: &Query, computed: &mut HashSet<String>) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            collect_computed_from_query(source, computed);
            collect_computed_from_command(command, computed);
        }
    }
}

fn collect_computed_from_command(cmd: &Command, computed: &mut HashSet<String>) {
    match cmd {
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        }
        | Command::EventStats {
            aggregations,
            group_by,
        } => {
            for agg in aggregations {
                // Explicit alias takes priority
                if let Some(alias) = &agg.alias {
                    computed.insert(alias.clone());
                } else if let Some(field) = &agg.field {
                    // Default alias: func_name or "values_field"/"list_field" patterns
                    match agg.func {
                        AggFunc::Values => {
                            computed.insert(format!("values_{}", field));
                        }
                        AggFunc::List => {
                            computed.insert(format!("list_{}", field));
                        }
                        _ => {
                            computed.insert(agg.func.as_str().to_string());
                        }
                    }
                } else {
                    computed.insert(agg.func.as_str().to_string());
                }
            }
            // Group by fields become output columns too but they're real fields, not computed
            if let Some(gb) = group_by {
                for f in gb {
                    computed.insert(f.clone());
                }
            }
        }
        Command::StreamStats { aggregations, .. } => {
            for agg in aggregations {
                if let Some(alias) = &agg.alias {
                    computed.insert(alias.clone());
                } else {
                    computed.insert(agg.func.as_str().to_string());
                }
            }
        }
        Command::Timechart { aggregations, .. } => {
            for agg in aggregations {
                if let Some(alias) = &agg.alias {
                    computed.insert(alias.clone());
                } else {
                    computed.insert(agg.func.as_str().to_string());
                }
            }
        }
        Command::Sequence {
            conditions,
            capture_fields,
            ..
        } => {
            // Sequence produces: step{N}_time, step{N}_event_id, step{N}_{field},
            // sequence_duration_seconds, sequence_count, timestamp
            for (i, _) in conditions.iter().enumerate() {
                let n = i + 1;
                computed.insert(format!("step{}_time", n));
                computed.insert(format!("step{}_event_id", n));
            }
            for (i, _) in conditions.iter().enumerate() {
                let n = i + 1;
                for field in capture_fields {
                    computed.insert(format!("step{}_{}", n, field));
                }
            }
            computed.insert("sequence_duration_seconds".to_string());
            computed.insert("sequence_duration".to_string()); // common alias users reference
            computed.insert("sequence_count".to_string());
        }
        Command::Transaction { .. } => {
            computed.insert("eventcount".to_string());
            computed.insert("duration".to_string());
            computed.insert("transaction_start".to_string());
            computed.insert("transaction_end".to_string());
        }
        Command::Top { .. } | Command::Rare { .. } => {
            computed.insert("count".to_string());
            computed.insert("percent".to_string());
        }
        Command::Eval { assignments } => {
            for assignment in assignments {
                computed.insert(assignment.field.clone());
            }
        }
        Command::Risk { .. } => {
            computed.insert("risk_score".to_string());
            computed.insert("risk_factors".to_string());
        }
        Command::Prevalence { .. } => {
            computed.insert("host_count".to_string());
            computed.insert("is_rare".to_string());
            computed.insert("prevalence_score".to_string());
            computed.insert("prevalence_first_seen".to_string());
            computed.insert("prevalence_last_seen".to_string());
            computed.insert("total_occurrences".to_string());
            computed.insert("prevalence_type".to_string());
            computed.insert("prevalence_artifact".to_string());
        }
        Command::Anomaly { .. } => {
            computed.insert("anomaly_score".to_string());
            computed.insert("anomaly_type".to_string());
            computed.insert("is_anomaly".to_string());
        }
        Command::Ai { .. } => {
            computed.insert("ai_verdict".to_string());
            computed.insert("ai_confidence".to_string());
            computed.insert("ai_reasoning".to_string());
        }
        _ => {}
    }
}
