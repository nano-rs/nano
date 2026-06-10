// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field requirement analysis for query optimization

use super::{
    extract_fields_from_search_expr, extract_named_groups, is_known_metadata_field,
    normalize_field_name,
};
use crate::query::ast::*;
use std::collections::HashSet;

/// Analyze query to determine which fields are actually needed
/// Returns None if all fields are needed (SELECT *), or Some(set) for specific fields
///
/// When `table_view` is true, always returns minimal fields for fast table display.
/// Users can fetch full row data on demand when they expand a row.
pub(crate) fn analyze_required_fields(
    query: &Query,
    table_view: bool,
    profile: &dyn crate::schema::SchemaProfile,
) -> Option<HashSet<String>> {
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
            match profile.id() {
                // OCSF (NAN-1241 / NAN-1277): the UDM summary columns below don't
                // exist on `ocsf_logs`. The OCSF profile's `default_table_fields`
                // is the NARROW FieldsPanel column list (class_uid/src/dst ip/
                // user) — using it here left the per-row key chips (activity,
                // status, severity, ports, process, enrichment) empty at display
                // time, so they only filled on the hover full-row fetch. Mirror
                // UDM's deliberately-BROADER table_view summary with the OCSF
                // column equivalents so the slim projection loads them up front.
                crate::schema::SchemaId::Ocsf => {
                    for f in &[
                        "class_uid",
                        "activity",
                        "status",
                        "severity",
                        "src_endpoint.ip",
                        "src_endpoint.hostname",
                        "dst_endpoint.ip",
                        "dst_endpoint.hostname",
                        "user.name",
                        "actor.process.name",
                        "process.name",
                        "src_endpoint.port",
                        "dst_endpoint.port",
                        "connection_info.protocol_num",
                        // Enrichment columns are MATERIALIZED — must be explicitly
                        // selected (SELECT * excludes them) to show up front + in
                        // the field-stats sidebar (parity with the UDM list).
                        "src_endpoint.location.country",
                        "src_endpoint.autonomous_system.number",
                        "src_endpoint.autonomous_system.name",
                        "dst_endpoint.location.country",
                        "dst_endpoint.autonomous_system.number",
                        "dst_endpoint.autonomous_system.name",
                    ] {
                        fields.insert(f.to_string());
                    }
                }
                // UDM: unchanged, byte-for-byte (the epic's invariant). Do not
                // route this through `default_table_fields()` — that set is the
                // narrower FieldsPanel column list; the table_view summary is
                // deliberately broader (ports, process, enrichment).
                crate::schema::SchemaId::Udm => {
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
            // Table command explicitly selects fields. A WILDCARD pattern
            // (`table src_*`) must not be inserted as a literal required field
            // — the slim projection then emits `toString(ext.src_) AS src_*`,
            // a guaranteed CH Code 62 syntax error (NAN-1339). Wildcards
            // expand against the full column set at codegen time, so they
            // need the wide base projection.
            if table_fields.len() == 1 && table_fields[0].name == "*" {
                *needs_all = true;
            } else {
                for tf in table_fields {
                    if tf.name.contains('*') {
                        *needs_all = true;
                    } else {
                        fields.insert(normalize_field_name(&tf.name).to_string());
                    }
                }
            }
        }
        Command::Fields {
            fields: field_list,
            keep,
        } => {
            if *keep {
                // Include mode - only these fields. Wildcards need the wide
                // base projection (same as `table`, NAN-1339).
                for f in field_list {
                    if f.contains('*') {
                        *needs_all = true;
                    } else {
                        fields.insert(normalize_field_name(f).to_string());
                    }
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
            startswith,
            endswith,
            ..
        } => {
            for field in trans_fields {
                fields.insert(normalize_field_name(field).to_string());
            }
            // startswith/endswith markers are evaluated as row flags inside the
            // transaction stage (NAN-1346 #6) — any fields they reference must
            // survive into stage_0 (keywords use the always-projected `message`).
            for marker in [startswith, endswith].into_iter().flatten() {
                collect_fields_from_search_expr(marker, fields);
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
            // The funnel SQL gen argMax's a fixed set of "dropper attribute" columns
            // (process_name, dest_port, user, …) that never appear in the query text.
            // Declare them required so field pruning keeps them in stage_0 — otherwise
            // under OCSF the resolved column (e.g. process_name_unified) is dropped and
            // the argMax 500s with Code 47 (NAN-1346). Fields the active schema has no
            // column for resolve to harmless JSON-tail noise the funnel argMax skips.
            for name in crate::search::query_processing::FUNNEL_DROPPER_FIELDS {
                fields.insert(normalize_field_name(name).to_string());
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
/// Collect reference-side aliases for un-aliased, field-bearing aggregations
/// (see `agg_reference_aliases`). Explicitly-aliased output names (already in
/// `computed`) win; the first un-aliased aggregation claims a given
/// `{func}_{field}` name.
pub(crate) fn collect_agg_reference_aliases(
    query: &Query,
    computed: &HashSet<String>,
) -> std::collections::HashMap<String, String> {
    fn walk(query: &Query, computed: &HashSet<String>, map: &mut std::collections::HashMap<String, String>) {
        let (source, command) = match query {
            Query::Search(_) => return,
            Query::Piped { source, command } => (source, command),
        };
        walk(source, computed, map);
        let aggs = match command {
            Command::Stats { aggregations, .. }
            | Command::Chart { aggregations, .. }
            | Command::Timechart { aggregations, .. }
            | Command::EventStats { aggregations, .. } => aggregations,
            _ => return,
        };
        for agg in aggs {
            if agg.alias.is_some() {
                continue;
            }
            let Some(field) = &agg.field else { continue };
            let name = format!("{}_{}", agg.func.as_str(), field);
            let target = agg.output_alias();
            if name != target && !computed.contains(&name) {
                map.entry(name).or_insert(target);
            }
        }
    }
    let mut map = std::collections::HashMap::new();
    walk(query, computed, &mut map);
    map
}

pub(crate) fn analyze_ext_fields(
    query: &Query,
    profile: &dyn crate::schema::SchemaProfile,
) -> HashSet<String> {
    let mut all_fields = HashSet::new();
    let mut needs_all = false;
    collect_required_fields_from_query(query, &mut all_fields, &mut needs_all);

    // Collect field names that are computed by the query pipeline (stats aliases,
    // sequence outputs, etc.) — these must NOT be materialized from ext JSON
    let computed = collect_computed_field_names(query);
    // {func}_{field} references to un-aliased aggregations resolve to the real
    // output column (NAN-1339) — materializing them from ext would shadow the
    // resolution with JSON junk in stage_0.
    let agg_aliases = collect_agg_reference_aliases(query, &computed);

    all_fields
        .into_iter()
        .filter(|f| {
            let f = f.as_str();
            // A field is an ext/overflow field only when the ACTIVE schema cannot
            // resolve it to a real column/path (UDM: Unknown ≡ !is_explicit_column,
            // byte-identical; OCSF: promoted columns now resolve and are excluded).
            matches!(
                profile.resolve(&profile.canonicalize(f)),
                crate::schema::FieldResolution::Unknown
            )
                && !f.starts_with("metadata_")
                && !f.starts_with("metadata.")
                && !is_known_metadata_field(f)
                && !f.contains('.')
                && !computed.contains(f)
                && !agg_aliases.contains_key(f)
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
pub(crate) fn collect_computed_field_names(query: &Query) -> HashSet<String> {
    let mut computed = HashSet::new();
    collect_computed_from_query(query, &mut computed);
    // resolve_identity output registration (NAN-1346 #5). The always-bare
    // outputs (confidence/observed_at/source/fqdn/ip) are real stage columns
    // whenever any resolve_identity ran; the bare `identity_*` attribute
    // aliases are only emitted when exactly ONE resolve_identity makes them
    // unambiguous (see generate_resolve_identity_sql) — registering them for
    // the two-entity case would emit a bare identifier no stage carries.
    let resolve_identity_count = count_resolve_identity(query);
    if resolve_identity_count >= 1 {
        for f in [
            "identity_confidence",
            "identity_observed_at",
            "identity_source",
            "identity_fqdn",
            "identity_ip",
        ] {
            computed.insert(f.to_string());
        }
    }
    if resolve_identity_count == 1 {
        for (col_suffix, _, _) in super::identity::IDENTITY_COLUMN_FIELDS.iter() {
            computed.insert((*col_suffix).to_string());
        }
        for (col_suffix, _, _) in super::identity::IDENTITY_DICT_ONLY_FIELDS.iter() {
            computed.insert((*col_suffix).to_string());
        }
    }
    computed
}

fn count_resolve_identity(query: &Query) -> usize {
    match query {
        Query::Search(_) => 0,
        Query::Piped { source, command } => {
            count_resolve_identity(source)
                + usize::from(matches!(command, Command::ResolveIdentity { .. }))
        }
    }
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
            for (i, cond) in conditions.iter().enumerate() {
                let n = i + 1;
                computed.insert(format!("step{}_time", n));
                computed.insert(format!("step{}_event_id", n));
                // Per-step captures mirror the SQL generator (commands_advanced):
                // the auto-captured CONDITION fields plus user capture_fields,
                // each normalized then dot-sanitized to match the emitted
                // `step{n}_<ident>` alias (NAN-1294). Registering only the explicit
                // capture_fields (and without sanitizing) missed OCSF dotted
                // captures like `process.name` → emitted `step1_process_name` but
                // unregistered → downstream `| table step1_process_name` JSON-tails
                // it from `event`, which the sequence output stage doesn't carry →
                // `Code 47 UNKNOWN_IDENTIFIER: event` (NAN-1311). UDM fields have no
                // dots, so this is a no-op there.
                let step_fields = extract_fields_from_search_expr(cond)
                    .into_iter()
                    .chain(capture_fields.iter().cloned());
                for field in step_fields {
                    let ident = normalize_field_name(&field).replace('.', "_");
                    computed.insert(format!("step{}_{}", n, ident));
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
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            // The subsearch's computed output columns surface in the
            // joined/unioned result (join re-projects them under their bare
            // names; append name-unions them) — register them so a downstream
            // `| where port_count > 20` references the real column instead of
            // JSON-extracting a string from ext/event (Code 386, NAN-1346 #4).
            collect_computed_from_query(subsearch, computed);
        }
        Command::Risk { .. } => {
            // All real columns the risk command projects. `risk_factors` and
            // `raw_risk_score` also appear in `is_known_metadata_field`, so they
            // must be recorded here to avoid being JSON-extracted from the
            // (now-dropped) `metadata` column downstream (NAN-1236).
            computed.insert("risk_score".to_string());
            computed.insert("raw_risk_score".to_string());
            computed.insert("risk_entity".to_string());
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
        Command::Rename { mappings } => {
            // Each rename produces an output column under its target name. Without
            // registering it, a downstream `| table <alias>` / `| where <alias>`
            // JSON-extracts the alias from the JSON tail (`ext`/`event`) — which a
            // prior aggregation stage has usually dropped — yielding `Code 47
            // UNKNOWN_IDENTIFIER` (NAN-1339). Mirrors the stats/eval registration.
            for m in mappings {
                computed.insert(m.to.clone());
            }
        }
        Command::Rex { pattern, mode, .. } => {
            // rex (extract mode) adds one output column per named capture group; a
            // pattern with no named groups yields the `rex_matches` array; sed mode
            // yields `rex_result`. Register them so downstream commands reference
            // them as real columns instead of JSON-extracting from the tail
            // (NAN-1339). The capture-name parsing mirrors the SQL generator's.
            match mode {
                RexMode::Extract => {
                    let groups = extract_named_groups(pattern);
                    if groups.is_empty() {
                        computed.insert("rex_matches".to_string());
                    } else {
                        for g in groups {
                            computed.insert(g);
                        }
                    }
                }
                RexMode::Sed { .. } => {
                    computed.insert("rex_result".to_string());
                }
            }
        }
        Command::Spath { output, path, .. } => {
            // spath writes its extracted value to the output field, defaulting to
            // `spath_result` when none is given — mirror the SQL generator exactly so
            // a downstream command treats it as a real column rather than
            // JSON-extracting it from the tail (NAN-1339). `path: None` is a no-op
            // pass-through in the generator (no new column), so skip it. The
            // input-tail resolution (`ext` vs OCSF `event`) is a separate concern
            // handled in the spath SQL generator.
            if path.is_some() {
                computed.insert(output.clone().unwrap_or_else(|| "spath_result".to_string()));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod table_view_profile_tests {
    use super::*;
    use crate::query::parser::parse_query;
    use crate::schema::{OcsfProfile, SchemaProfile, UdmProfile};

    // Bare search, table_view: the slim projection's summary set must come from
    // the active profile (NAN-1241 Phase 7). Before the fix, both profiles got
    // the hardcoded UDM list, so OCSF rows rendered "unparsed" (the UDM columns
    // don't exist on ocsf_logs).
    fn required_for(profile: &dyn crate::schema::SchemaProfile) -> HashSet<String> {
        let query = parse_query("source_type=apache").unwrap();
        analyze_required_fields(&query, /* table_view */ true, profile)
            .expect("table_view always returns an explicit field set")
    }

    #[test]
    fn udm_table_view_summary_is_unchanged() {
        let f = required_for(&UdmProfile::new());
        // Core (always-on) + the historical UDM summary set, byte-for-byte.
        for expected in [
            "id",
            "timestamp",
            "message",
            "source_type",
            "src_ip",
            "dest_ip",
            "user",
            "action",
            "status",
            "severity",
            "enriched_src_country",
        ] {
            assert!(f.contains(expected), "UDM table_view missing {expected}");
        }
        // OCSF-only promoted columns must never leak into the UDM projection.
        assert!(!f.contains("src_endpoint.ip"));
        assert!(!f.contains("class_uid"));
    }

    #[test]
    fn ocsf_table_view_summary_has_key_chip_fields() {
        let profile = OcsfProfile::new();
        let f = required_for(&profile);
        // Core fields still present.
        for core in ["id", "timestamp", "message", "source_type"] {
            assert!(f.contains(core), "OCSF table_view missing core {core}");
        }
        // NAN-1277: the per-row key chips (activity/status/severity) + UDM-parity
        // breadth (endpoints, ports, process, enrichment) must be in the slim
        // projection so they load at display time, not on the hover full-row
        // fetch. Includes the narrow default_table_fields as a subset.
        for expected in [
            "class_uid",
            "activity",
            "status",
            "severity",
            "src_endpoint.ip",
            "src_endpoint.hostname",
            "dst_endpoint.ip",
            "user.name",
            "actor.process.name",
            "src_endpoint.port",
            "connection_info.protocol_num",
            "src_endpoint.autonomous_system.number",
        ] {
            assert!(f.contains(expected), "OCSF table_view missing {expected}");
        }
        for field in profile.default_table_fields() {
            assert!(f.contains(*field), "OCSF table_view missing default field {field}");
        }
        // The UDM-only summary columns must not appear (they don't exist on
        // ocsf_logs and selecting them would error / waste the projection).
        assert!(!f.contains("src_ip"));
        assert!(!f.contains("process_name"));
        assert!(!f.contains("enriched_src_country"));
    }
}
