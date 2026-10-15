// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field requirement analysis for query optimization

use super::{
    extract_fields_from_search_expr, extract_named_groups, is_known_metadata_field,
    normalize_field_name,
};
use crate::query::ast::*;
use std::collections::HashSet;

/// NAN-1555: profile-aware field-name canonicalization for the collection
/// helpers. Spans/metrics canonicalize through the profile (so `service_name`
/// stays itself rather than becoming the UDM `cloud_service` alias); logs
/// (UDM/OCSF) keep the exact free `normalize_field_name` alias map, byte-identical.
fn canon_collect(field: &str, profile: &dyn crate::schema::SchemaProfile) -> String {
    match profile.id() {
        crate::schema::SchemaId::Spans | crate::schema::SchemaId::Metrics => {
            profile.canonicalize(field).into_owned()
        }
        _ if profile.uses_strict_canonical_fields() => profile.canonicalize(field).into_owned(),
        _ => normalize_field_name(field).to_string(),
    }
}

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
    let mut wants_full_rows = false;

    collect_required_fields_from_query(
        query,
        &mut fields,
        &mut needs_all_fields,
        &mut wants_full_rows,
        profile,
    );

    // A profile can implement a class-spanning semantic field with a
    // materialized unified column (legacy OCSF) or an inline value-pick over two
    // canonical inputs (the OCSF 1.9 lake contract). The slim projection must
    // retain both inputs for the latter; keeping only the primary makes the
    // downstream GROUP BY/sequence expression fail after stage_0.
    let split_fields: Vec<String> = fields
        .iter()
        .filter(|field| profile.class_split_column(field).is_none())
        .filter(|field| profile.class_split_source_fields(field).is_some())
        .cloned()
        .collect();
    for field in split_fields {
        if let Some((primary, fallback)) = profile.class_split_source_fields(&field) {
            fields.remove(&field);
            fields.insert(primary.to_string());
            fields.insert(fallback.to_string());
        }
    }

    // Remove fields that are added by post-processing (ai, anomaly, prevalence, risk).
    // These never exist in ClickHouse columns or ext JSON — they're computed at runtime.
    fields.retain(|f| !is_post_processing_field(f));

    // NAN-1639 (finding 3.8): pipeline-CREATED output columns — aggregation
    // aliases (`count`, `total`), top/rare's `count`/`percent`, sequence /
    // transaction outputs — referenced by a downstream row command (most
    // commonly the executor-injected `| sort -count` on grouped stats) are
    // stage outputs, not base columns. Leaving them in the required set makes
    // stage_0 emit a bogus `toString(ext.count) AS count`. Group-by
    // passthroughs are NOT in this set — they are real columns (or ext spills)
    // that stage_0 must still project. `{func}_{field}` references to
    // un-aliased aggregations resolve to the real output column downstream
    // (NAN-1339) and aggregation expressions like `count()` are never
    // projectable base columns, so both are dropped too (mirroring
    // `analyze_ext_fields`).
    //
    // A stage-output name that resolves to a REAL physical column is kept: it
    // may be legitimately referenced by a stage BEFORE the one that creates
    // the alias (`… | where status=… | stats sum(x) as status by …`), and
    // projecting the base column is harmless when it is not (an aggregation
    // stage's own output shadows it downstream).
    let stage_outputs = collect_stage_output_names(query);
    let computed = collect_computed_field_names(query);
    let agg_aliases = collect_agg_reference_aliases(query, &computed);
    fields.retain(|f| {
        if f.contains('(') {
            return false;
        }
        if !stage_outputs.contains(f) && !agg_aliases.contains_key(f) {
            return true;
        }
        // NAN-3059: the derived `risk` profile resolves EVERY name to a
        // direct identifier (its unknowns fail loudly at ClickHouse), so the
        // resolution alone kept stage outputs such as `stats … count` in
        // stage 0: `SELECT count, … FROM <risk grain>` then broke every
        // `dataset=risk | stats … by …` on the lean cell. A stage output is a
        // base column only when the profile actually knows that column.
        let canonical = profile.canonicalize(f);
        matches!(
            profile.resolve(&canonical),
            crate::schema::FieldResolution::ExplicitColumn(_)
        ) && profile.is_known_field(&canonical)
    });

    // Always include core fields needed for basic functionality. Profile-driven
    // (NAN-1555): UDM/OCSF logs default to id/timestamp/message/source_type;
    // `otel_spans` has none of those columns and supplies its own identity/time/
    // display core (trace_id/span_id/start_time/span_name/service_name). The
    // default is byte-identical to the historical hard-coded list.
    for f in profile.core_fields() {
        fields.insert((*f).to_string());
    }

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
                    let summary: &[&str] = if profile.uses_strict_canonical_fields() {
                        &[
                            "class_uid",
                            "activity_name",
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
                            "src_endpoint.location.country",
                            "src_endpoint.autonomous_system.number",
                            "src_endpoint.autonomous_system.name",
                            "dst_endpoint.location.country",
                            "dst_endpoint.autonomous_system.number",
                            "dst_endpoint.autonomous_system.name",
                        ]
                    } else {
                        &[
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
                            "prevalence_min",
                            "src_endpoint.location.country",
                            "src_endpoint.autonomous_system.number",
                            "src_endpoint.autonomous_system.name",
                            "dst_endpoint.location.country",
                            "dst_endpoint.autonomous_system.number",
                            "dst_endpoint.autonomous_system.name",
                        ]
                    };
                    for f in summary {
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
                        // NAN-2230: the CANONICAL name. `table_view` goes through
                        // the explicit-fields projection branch, which emits each
                        // required field under its own name with no rewrite — so
                        // listing the physical `action` here put it in every
                        // default search row, and the inspector (which merges the
                        // row with the full-log fetch, correctly keyed
                        // `event_type`) showed both. `event_type` is an ALIAS on
                        // `logs`/`logs_distributed`, so it projects directly.
                        "event_type",
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
                // Spans (NAN-1555): the wide-event summary columns for the
                // table-view grid. All are real `otel_spans` columns (no
                // MATERIALIZED enrichment to name explicitly), so this just loads
                // the analyst-facing span fields up front like the UDM/OCSF lists.
                crate::schema::SchemaId::Spans => {
                    for f in &[
                        "service_name",
                        "span_name",
                        "span_kind",
                        "status_code",
                        "status_message",
                        "duration_ns",
                        "src_ip",
                        "dest_ip",
                        "user",
                        "host",
                    ] {
                        fields.insert(f.to_string());
                    }
                }
                // Metrics (NAN-1555 Phase 2): the wide-event summary for the
                // table-view grid — all real `otel_metrics` columns.
                crate::schema::SchemaId::Metrics => {
                    for f in &[
                        "metric_name",
                        "metric_type",
                        "service_name",
                        "value",
                        "unit",
                    ] {
                        fields.insert(f.to_string());
                    }
                }
                // Risk (NAN-1798 P2): the derived entity grain is 15 columns
                // total and the generator forces `SELECT *` for the risk
                // dataset (`required_fields = None` in `generate_with_options`),
                // so this slim summary is effectively unused; keep it aligned
                // with the profile's triage shape for totality.
                crate::schema::SchemaId::Risk => {
                    use crate::schema::SchemaProfile as _;
                    for f in crate::schema::RiskProfile::new().default_table_fields() {
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

    // NAN-1639 (finding 2.4): row-preserving pipes (where/sort/dedup/head/…)
    // keep the historical full-row projection for NON-table_view callers —
    // API/detection consumers of raw-event output see complete rows,
    // unchanged. Once an aggregation shapes the output, only group/agg
    // columns survive the GROUP BY, so the wide stage_0 is pure coordinator
    // waste (finding 3.8) and pruning applies. table_view was already handled
    // above: the events grid renders the slim summary either way.
    if wants_full_rows && !has_aggregation_command(query) {
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

/// Return every field token referenced by the parsed query before projection
/// pruning removes runtime enrichment fields and pipeline-created outputs.
///
/// Most callers want [`analyze_required_fields`]. The lake compiler also needs
/// this unpruned set because generated SQL can still reference a compatibility
/// column such as `prevalence_file_hash` inside a sequence predicate even when
/// that field is normally supplied by post-processing.
pub(crate) fn collect_referenced_fields(
    query: &Query,
    profile: &dyn crate::schema::SchemaProfile,
) -> HashSet<String> {
    let mut fields = HashSet::new();
    let mut needs_all_fields = false;
    let mut wants_full_rows = false;
    collect_required_fields_from_query(
        query,
        &mut fields,
        &mut needs_all_fields,
        &mut wants_full_rows,
        profile,
    );
    fields
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

/// Check if the query changes the raw-event grain through an aggregation.
/// Used to skip adding table-view summary fields for shaped results — they only
/// need their grouping, marker, and aggregate inputs, not the event-card
/// summary columns. `transaction` is an aggregate too: carrying the summary
/// through each sessionization sort multiplied its memory footprint without
/// exposing those columns in the final transaction row.
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
                    | Command::Transaction { .. }
            ) || has_aggregation_command(source)
        }
    }
}

/// Recursively collect fields referenced in the query.
///
/// `needs_all` — downstream codegen structurally requires the full column set
/// (wildcard projections, lookup/rex/eval/…). `wants_full_rows` — a
/// row-preserving pipe (where/sort/dedup/head/…) whose full-row output is a
/// DISPLAY expectation only: honored for the non-table_view raw-event view,
/// ignored under table_view (the grid renders the slim summary) and after an
/// aggregation (NAN-1639, findings 2.4/3.8).
fn collect_required_fields_from_query(
    query: &Query,
    fields: &mut HashSet<String>,
    needs_all: &mut bool,
    wants_full_rows: &mut bool,
    profile: &dyn crate::schema::SchemaProfile,
) {
    match query {
        Query::Search(expr) => {
            collect_fields_from_search_expr(expr, fields, profile);
        }
        Query::Piped { source, command } => {
            collect_required_fields_from_query(source, fields, needs_all, wants_full_rows, profile);
            collect_fields_from_command(command, fields, needs_all, wants_full_rows, profile);
        }
    }
}

/// Collect fields from search expressions
fn collect_fields_from_search_expr(
    expr: &SearchExpr,
    fields: &mut HashSet<String>,
    profile: &dyn crate::schema::SchemaProfile,
) {
    match expr {
        SearchExpr::Keyword(_) => {
            // A bare keyword is evaluated across every profile-defined keyword
            // column. `message` is a core field, but OCSF also searches
            // `raw_data`. Recording the full set matters when the expression is
            // embedded in a transforming command such as transaction
            // startswith/endswith: stage_0 field pruning must preserve every
            // column that the marker predicate will reference later.
            for column in profile.keyword_search_columns() {
                fields.insert(canon_collect(column, profile));
            }
        }
        SearchExpr::FieldFilter { field, .. } => {
            fields.insert(canon_collect(field, profile));
        }
        SearchExpr::FunctionFilter { function, .. } => {
            // Collect fields from function arguments
            collect_fields_from_eval_expr(function, fields, profile);
        }
        SearchExpr::FieldFunctionFilter {
            field, function, ..
        } => {
            // Collect the field and fields from function arguments
            fields.insert(canon_collect(field, profile));
            collect_fields_from_eval_expr(function, fields, profile);
        }
        SearchExpr::InList { field, .. } => {
            fields.insert(canon_collect(field, profile));
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            collect_fields_from_search_expr(left, fields, profile);
            collect_fields_from_search_expr(right, fields, profile);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            collect_fields_from_search_expr(inner, fields, profile);
        }
        SearchExpr::BooleanFunction(function) => {
            collect_fields_from_eval_expr(function, fields, profile);
        }
        SearchExpr::EvalPredicate(expression) => {
            collect_fields_from_eval_expr(expression, fields, profile);
        }
        SearchExpr::LiteralComparison { .. } => {
            // Literal comparisons don't reference any fields
        }
        SearchExpr::IocMatch { .. } => {
            // NAN-1580: observable-anywhere match — no single field to collect;
            // its expansion targets the base observable columns directly.
        }
        SearchExpr::InSubsearch { field, subsearch, subsearch_dataset, .. } => {
            fields.insert(canon_collect(field, profile));
            // The lake compiler projects only required physical columns from
            // each part before the IN subquery runs. Include the subsearch's
            // filter and return fields when it reads this same dataset; without
            // them ClickHouse sees a valid WHERE over a missing projected
            // column (Code 47). Fields of a different dataset must stay out
            // of this scan's projection.
            let same_dataset = match subsearch_dataset {
                None => true,
                Some(super::otel::Dataset::Logs) => matches!(profile.id(), crate::schema::SchemaId::Udm | crate::schema::SchemaId::Ocsf),
                Some(super::otel::Dataset::Spans) => profile.id() == crate::schema::SchemaId::Spans,
                Some(super::otel::Dataset::Metrics) => profile.id() == crate::schema::SchemaId::Metrics,
                Some(super::otel::Dataset::Risk) => profile.id() == crate::schema::SchemaId::Risk,
            };
            if same_dataset {
                collect_in_subsearch_fields(subsearch, fields, profile);
            }
        }
    }
}

fn collect_in_subsearch_fields(
    query: &Query,
    fields: &mut HashSet<String>,
    profile: &dyn crate::schema::SchemaProfile,
) {
    match query {
        Query::Search(expr) => collect_fields_from_search_expr(expr, fields, profile),
        Query::Piped { source, command } => {
            collect_in_subsearch_fields(source, fields, profile);
            if let Command::Return { fields: returned, .. } = command {
                for field in returned {
                    fields.insert(canon_collect(field, profile));
                }
            }
        }
    }
}

/// Collect fields from commands
fn collect_fields_from_command(
    cmd: &Command,
    fields: &mut HashSet<String>,
    needs_all: &mut bool,
    wants_full_rows: &mut bool,
    profile: &dyn crate::schema::SchemaProfile,
) {
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
                        fields.insert(canon_collect(&tf.name, profile));
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
                        fields.insert(canon_collect(f, profile));
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
                    fields.insert(canon_collect(field, profile));
                }
                // Extract fields from condition if present
                if let Some(condition) = &agg.condition {
                    collect_fields_from_eval_expr(condition, fields, profile);
                }
            }
            // Collect group by fields
            if let Some(group_fields) = group_by {
                for field in group_fields {
                    fields.insert(canon_collect(field, profile));
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
            fields.insert(profile.timestamp_expr().to_string());
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(canon_collect(field, profile));
                }
            }
            if let Some(group_fields) = group_by {
                for field in group_fields {
                    fields.insert(canon_collect(field, profile));
                }
            }
        }
        Command::Timechart {
            aggregations,
            split_by,
            ..
        } => {
            fields.insert(profile.timestamp_expr().to_string());
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(canon_collect(field, profile));
                }
            }
            for field in split_by {
                fields.insert(canon_collect(field, profile));
            }
        }
        Command::Where { condition } => {
            // Row-preserving filter (NAN-1639, finding 2.4): full rows are a
            // display expectation, not a structural need — the stage emits
            // `SELECT * FROM prev WHERE …` over whatever the base projected.
            *wants_full_rows = true;
            collect_fields_from_search_expr(condition, fields, profile);
        }
        Command::Sort {
            fields: sort_fields,
            ..
        } => {
            // Row-preserving reorder (NAN-1639, findings 2.4/3.8): the
            // executor-injected `| sort -count` on grouped stats lands here —
            // it must not force the wide stage_0 (its `count` field is
            // filtered out of the required set in `analyze_required_fields`).
            *wants_full_rows = true;
            for sf in sort_fields {
                fields.insert(canon_collect(&sf.field, profile));
            }
        }
        Command::Rename { mappings } => {
            // Rename transforms fields but users expect to see all fields
            *needs_all = true;
            for mapping in mappings {
                fields.insert(canon_collect(&mapping.from, profile));
            }
        }
        Command::Eval { assignments } => {
            // Eval adds computed fields but users expect to see all fields plus new ones
            *needs_all = true;
            for assignment in assignments {
                collect_fields_from_eval_expr(&assignment.expression, fields, profile);
            }
        }
        Command::Dedup {
            fields: dedup_fields,
            ..
        } => {
            // Row-preserving dedup (NAN-1639, finding 2.4): the stage only
            // needs its keys + timestamp (`ORDER BY <keys>, timestamp LIMIT 1
            // BY <keys>` over the base projection); full rows are display-only.
            *wants_full_rows = true;
            for field in dedup_fields {
                fields.insert(canon_collect(field, profile));
            }
        }
        Command::Bin { field, .. } => {
            // Bin modifies a field but users expect to see all fields
            *needs_all = true;
            if let Some(f) = field {
                fields.insert(canon_collect(f, profile));
            } else {
                fields.insert(profile.timestamp_expr().to_string());
            }
        }
        Command::Top {
            field,
            by_fields,
            inject_bounds,
            ..
        }
        | Command::Rare {
            field,
            by_fields,
            inject_bounds,
            ..
        } => {
            fields.insert(canon_collect(field, profile));
            for by in by_fields {
                fields.insert(canon_collect(by, profile));
            }
            // NAN-1711 / audit D15: the injected canonical window aggregates
            // `min/max(timestamp)`, so the base stage must project the column.
            if *inject_bounds {
                fields.insert(profile.timestamp_expr().to_string());
            }
        }
        Command::Transaction {
            fields: trans_fields,
            startswith,
            endswith,
            ..
        } => {
            for field in trans_fields {
                fields.insert(canon_collect(field, profile));
            }
            // startswith/endswith markers are evaluated as row flags inside the
            // transaction stage (NAN-1346 #6) — any fields they reference must
            // survive into stage_0 (keywords use the always-projected `message`).
            for marker in [startswith, endswith].into_iter().flatten() {
                collect_fields_from_search_expr(marker, fields, profile);
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
                fields.insert(canon_collect(field, profile));
            }
            // Extract fields from dynamic score expression
            if let RiskScoreExpr::Dynamic(expr) = score {
                collect_fields_from_eval_expr(expr, fields, profile);
            }
        }
        Command::Prevalence { .. } => {
            // Prevalence needs file_hash, url_domain, etc. - safer to get all fields
            *needs_all = true;
        }
        // Row-preserving slicers (NAN-1639, finding 2.4): head/tail/sample/
        // reverse reference no fields of their own — head is a bare LIMIT;
        // tail/reverse order by `timestamp` (core) or rowNumberInAllBlocks();
        // sample hashes `id` (core). Full rows are a display expectation only.
        Command::Head { .. } | Command::Tail { .. } | Command::Sample { .. } | Command::Reverse => {
            *wants_full_rows = true;
        }
        // Join/append structurally need the wide base on BOTH sides, and their
        // subsearch is a full pipeline of its own: walk it so fields it
        // references (in particular ext/overflow fields, which must be
        // materialized in the subsearch's base scan via `analyze_ext_fields`)
        // are collected (NAN-1644).
        Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
            *needs_all = true;
            collect_required_fields_from_query(
                subsearch,
                fields,
                needs_all,
                wants_full_rows,
                profile,
            );
        }
        // Wide commands that also reference specific event-side fields: the
        // wide base still needs their ext/overflow references collected so
        // `analyze_ext_fields` materializes them in stage_0 — the command SQL
        // binds the projected alias (NAN-1644).
        Command::Lookup { event_field, .. } => {
            *needs_all = true;
            fields.insert(canon_collect(event_field, profile));
        }
        Command::Fillnull {
            fields: fill_fields,
            ..
        } => {
            *needs_all = true;
            if let Some(fs) = fill_fields {
                for f in fs {
                    fields.insert(canon_collect(f, profile));
                }
            }
        }
        Command::Mvexpand { field, .. } => {
            *needs_all = true;
            fields.insert(canon_collect(field, profile));
        }
        Command::Return {
            fields: return_fields,
            ..
        } => {
            *needs_all = true;
            for f in return_fields {
                fields.insert(canon_collect(f, profile));
            }
        }
        // Commands that need all fields or don't affect field selection
        Command::Rex { field, .. } => {
            *needs_all = true;
            // NAN-3327: the source column must be DECLARED — the lake worker's
            // projection is derived from this set, and `SELECT *` alone never
            // carries a wide column like `raw_data` ("Unknown identifier
            // `raw_data` in scope stage_1").
            fields.insert(canon_collect(field.as_deref().unwrap_or("message"), profile));
        }
        Command::Format { .. } | Command::InputLookup { .. } => {
            // These commands either need all fields or we can't easily determine requirements
            *needs_all = true;
        }
        Command::Tree {
            parent_field,
            child_field,
            label_field,
            detail_field,
            prevalence_field,
            ..
        } => {
            // The tree builder reads these off result rows, so they must be
            // DECLARED referenced fields: the lake compiler derives the
            // worker's Parquet projection from this set, and after NAN-2361
            // the generated SQL no longer re-names columns that `SELECT *`
            // already carries — without this declaration the columns would
            // never be projected at all.
            *needs_all = true;
            for f in [parent_field, child_field, label_field]
                .into_iter()
                .chain(detail_field.as_ref())
                .chain(prevalence_field.as_ref())
            {
                if !f.is_empty() {
                    fields.insert(canon_collect(f, profile));
                }
            }
        }
        Command::Spath { input, path, .. } => {
            *needs_all = true;
            if profile.id() == crate::schema::SchemaId::Ocsf {
                if let Some(path) = path {
                    let path = path.trim_end_matches("{}");
                    // NAN-3327: JSON text in a scalar column — project the column.
                    if super::helpers::spath_reads_column_text(profile, input.as_deref(), path) {
                        fields.insert(canon_collect(input.as_deref().unwrap_or_default(), profile));
                        return;
                    }
                    let logical_field = if input
                        .as_deref()
                        .is_none_or(|name| matches!(name, "ext" | "event" | "unmapped"))
                    {
                        format!("{}.{}", profile.json_tail_column(), path)
                    } else {
                        format!("{}.{}", input.as_deref().unwrap_or_default(), path)
                    };
                    fields.insert(logical_field);
                }
            }
        }
        Command::EventStats {
            aggregations,
            group_by,
        } => {
            // Collect fields from aggregations
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    fields.insert(canon_collect(field, profile));
                }
            }
            // Collect fields from group by
            if let Some(group_fields) = group_by {
                for field in group_fields {
                    fields.insert(canon_collect(field, profile));
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
                fields.insert(canon_collect(field, profile));
            }
            // Collect fields from conditions
            for condition in conditions {
                collect_fields_from_search_expr(condition, fields, profile);
            }
            // Collect user-specified capture fields
            for field in capture_fields {
                fields.insert(canon_collect(field, profile));
            }
            // Need timestamp for sequenceMatch and id for event drill-down
            fields.insert(profile.timestamp_expr().to_string());
            fields.insert(
                if profile.core_fields().contains(&"metadata.uid") {
                    "metadata.uid"
                } else {
                    "id"
                }
                .to_string(),
            );
        }
        Command::Funnel {
            group_by, steps, ..
        } => {
            // Collect group by fields
            for field in group_by {
                fields.insert(canon_collect(field, profile));
            }
            // Collect fields from step conditions
            for (_, condition) in steps {
                collect_fields_from_search_expr(condition, fields, profile);
            }
            // The funnel SQL gen argMax's a fixed set of "dropper attribute" columns
            // (process_name, dest_port, user, …) that never appear in the query text.
            // Declare them required so field pruning keeps them in stage_0 — otherwise
            // under OCSF the resolved column (e.g. process_name_unified) is dropped and
            // the argMax 500s with Code 47 (NAN-1346). Fields the active schema has no
            // column for resolve to harmless JSON-tail noise the funnel argMax skips.
            for name in crate::search::query_processing::funnel_dropper_fields(profile) {
                fields.insert(canon_collect(name, profile));
            }
            // Need timestamp for windowFunnel
            fields.insert(profile.timestamp_expr().to_string());
        }
        Command::Anomaly {
            field, by_fields, ..
        } => {
            // Aggregation-first anomaly stores `sum(field)` as one string in
            // the AST. Keep the inner physical field in stage_0; only an
            // argument-free aggregate such as count() needs no input column.
            if let (Some(open), Some(close)) = (field.find('('), field.rfind(')')) {
                if close > open {
                    let inner = field[open + 1..close].trim();
                    if !inner.is_empty() && inner != "*" {
                        fields.insert(canon_collect(inner, profile));
                    }
                }
            } else {
                fields.insert(canon_collect(field, profile));
            }
            for by in by_fields {
                fields.insert(canon_collect(by, profile));
            }
            *needs_all = true; // Need all fields to show anomalous events
        }
        Command::ResolveIdentity { field, .. } => {
            // ResolveIdentity enriches with identity data via ASOF JOIN
            // Need the IP field being resolved plus timestamp for the join
            fields.insert(canon_collect(field, profile));
            fields.insert(profile.timestamp_expr().to_string());
            *needs_all = true; // Need all fields to enrich them
        }
        Command::Asset {
            identifier_field, ..
        } => {
            // Asset command creates a comprehensive view of an asset's activity
            // Need all fields for identity resolution and activity aggregation
            if let Some(field) = identifier_field {
                fields.insert(canon_collect(field, profile));
            }
            fields.insert(profile.timestamp_expr().to_string());
            *needs_all = true; // Need all fields for comprehensive asset view
        }
        Command::Cloud { .. } => {
            // Cloud command re-queries ClickHouse in post-processing
            // Need all fields for facets, events, and resource analysis
            *needs_all = true;
        }
        Command::Baseline { .. } => {
            // Baseline (NAN-1868) re-queries ClickHouse in post-processing
            // (build_baseline_view); the throwaway initial fetch just needs the
            // entity-bearing columns, so keep the wide projection available.
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
        Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. } => {
            // Command-page directives short-circuit before codegen (NAN-1560);
            // they don't drive field selection.
        }
        // NAN-1580: the retro directive drives the retro-hunt surface, not the
        // base log projection — it doesn't add required fields here.
        Command::Retro { .. } => {}
    }
}

/// Collect fields from eval expressions
fn collect_fields_from_eval_expr(
    expr: &EvalExpression,
    fields: &mut HashSet<String>,
    profile: &dyn crate::schema::SchemaProfile,
) {
    match expr {
        EvalExpression::Field(field) => {
            fields.insert(canon_collect(field, profile));
        }
        EvalExpression::Literal(_) => {}
        EvalExpression::BinaryOp { left, right, .. } => {
            collect_fields_from_eval_expr(left, fields, profile);
            collect_fields_from_eval_expr(right, fields, profile);
        }
        EvalExpression::FunctionCall { args, .. } => {
            // `searchmatch("user.name=j*")` references fields inside its
            // string literal; the projection must keep them.
            if let Some(search) = crate::query::searchmatch_search_expr(expr) {
                collect_fields_from_search_expr(&search, fields, profile);
                return;
            }
            for arg in args {
                collect_fields_from_eval_expr(arg, fields, profile);
            }
        }
    }
}

/// Delegates to the canonical [`crate::search::field_utils::is_post_processing_field`]
/// so the projection analysis and the rest of the search layer agree on which
/// fields are runtime-only (never physical columns).
///
/// NAN-1909: this was a hand-copied duplicate that drifted from the canonical
/// version — it still matched `starts_with("risk_")`, so the real `logs` columns
/// `risk_score`/`risk_entity`/`risk_level` were pruned from the base projection
/// (`… | stats sum(risk_score)` then referenced a column absent from the inner
/// scan). Delegating keeps the two in lockstep.
fn is_post_processing_field(field: &str) -> bool {
    crate::search::field_utils::is_post_processing_field(field)
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
    fn walk(
        query: &Query,
        computed: &HashSet<String>,
        map: &mut std::collections::HashMap<String, String>,
    ) {
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
                map.entry(name).or_insert_with(|| target.clone());
            }
            if let Some(leaf) = field.rsplit('.').next().filter(|leaf| *leaf != field) {
                let leaf_name = format!("{}_{}", agg.func.as_str(), leaf);
                if leaf_name != target && !computed.contains(&leaf_name) {
                    map.entry(leaf_name).or_insert_with(|| target.clone());
                }
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
    let mut wants_full_rows = false;
    collect_required_fields_from_query(
        query,
        &mut all_fields,
        &mut needs_all,
        &mut wants_full_rows,
        profile,
    );

    // Collect field names that are computed by the query pipeline (stats aliases,
    // sequence outputs, etc.) — these must NOT be materialized from ext JSON
    let computed = collect_computed_field_names(query);
    // {func}_{field} references to un-aliased aggregations resolve to the real
    // output column (NAN-1339) — materializing them from ext would shadow the
    // resolution with JSON junk in stage_0.
    let agg_aliases = collect_agg_reference_aliases(query, &computed);
    // NAN-1644 (finding 2.6): group-by passthroughs ARE registered in
    // `computed`, so dotted `ext.*` fields gate on the stage-OUTPUT set
    // instead (names a stage creates with a NEW value — rename/spath targets —
    // still lose; a group-by on `ext.foo` must be materialized in stage_0).
    let stage_outputs = collect_stage_output_names(query);

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
                // NAN-1644 (finding 2.6): a dotted `ext.*` path the schema
                // cannot resolve is a NATIVE ext-tail access, not metadata
                // JSON — materialize `toString(ext.<key>) AS "ext.<key>"` in
                // stage_0 exactly like the undotted spill fields, so every
                // downstream GROUP BY / SORT / projection binds the stage_0
                // alias (evaluated in the base scan, where ClickHouse 26.4
                // JSON-subcolumn pruning applies). Other dotted names keep
                // the legacy metadata JSON path and stay excluded here.
                && (if f.contains('.') {
                    f.starts_with("ext.") && !stage_outputs.contains(f)
                } else {
                    !computed.contains(f)
                })
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

/// Output column names CREATED by pipeline stages — everything
/// [`collect_computed_field_names`] registers EXCEPT stats/chart/eventstats
/// group-by passthroughs, which are real base columns (or ext spills) that
/// stage_0 must still project (NAN-1639). Used by `analyze_required_fields`
/// to keep stage outputs referenced by downstream row commands (the injected
/// `| sort -count`, `| where count > 10`) out of the stage_0 projection.
fn collect_stage_output_names(query: &Query) -> HashSet<String> {
    let mut out = collect_computed_field_names(query);
    /// Returns the names created (with new values) by the stages of `query`,
    /// so a later group-by over one of them stays a stage output.
    fn strip_group_bys(query: &Query, out: &mut HashSet<String>) -> HashSet<String> {
        let (source, command) = match query {
            Query::Search(_) => return HashSet::new(),
            Query::Piped { source, command } => (source, command),
        };
        let mut created = strip_group_bys(source, out);
        match command {
            Command::Stats {
                group_by: Some(gb), ..
            }
            | Command::Chart {
                group_by: Some(gb), ..
            }
            | Command::EventStats {
                group_by: Some(gb), ..
            } => {
                for f in gb {
                    // NAN-3314: a group-by over a column an earlier stage
                    // created (`table user.name as u | stats count by u`) is
                    // not a base column; projecting it from stage_0 read a
                    // bogus `ext.u`.
                    if !created.contains(f.as_str()) {
                        out.remove(f.as_str());
                    }
                }
            }
            // A join/append surfaces the SUBSEARCH's output columns —
            // `collect_computed_from_command` registered its group-bys too,
            // so they must be stripped as passthroughs here (NAN-1644).
            Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
                strip_group_bys(subsearch, out);
            }
            _ => {}
        }
        if !matches!(command, Command::Join { .. } | Command::Append { .. }) {
            let mut added = HashSet::new();
            collect_computed_from_command(command, &mut added);
            if let Command::Stats {
                group_by: Some(gb), ..
            }
            | Command::Chart {
                group_by: Some(gb), ..
            }
            | Command::EventStats {
                group_by: Some(gb), ..
            } = command
            {
                for f in gb {
                    if !created.contains(f.as_str()) {
                        added.remove(f.as_str());
                    }
                }
            }
            created.extend(added);
        }
        created
    }
    strip_group_bys(query, &mut out);
    out
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

/// The fields `cmd` creates with NEW VALUES (rex captures, eval assignments,
/// rename targets, aggregation aliases, command outputs) — the names that must
/// SHADOW a same-named schema field / UDM alias for the pipeline stages after
/// it (NAN-1341). `upstream` is the same set accumulated over the stages
/// before `cmd`.
///
/// Differs from [`collect_computed_from_command`] in one way: a
/// stats/chart/eventstats BY-field is a passthrough of an existing column, not
/// a new value — it surfaces under its OUTPUT alias (the raw name when it was
/// itself upstream-computed, the normalized canonical name otherwise — see
/// `by_field_output_name`), never under a raw name that still resolves to the
/// schema. Registering the raw name (as the NAN-1236 set does) would make a
/// plain `stats count by method` shadow its own schema resolution.
pub(crate) fn upstream_computed_added_by_command(
    cmd: &Command,
    upstream: &HashSet<String>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    match cmd {
        // A join/append surfaces the SUBSEARCH's output columns into the outer
        // pipeline — fold the subsearch's own stages from an empty scope.
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            out.extend(collect_upstream_computed_from_query(subsearch));
        }
        _ => {
            collect_computed_from_command(cmd, &mut out);
            match cmd {
                // stats/chart project their by-fields as `<expr> AS <output
                // alias>` (aggregation.rs) — surface them under that alias.
                Command::Stats {
                    group_by: Some(gb), ..
                }
                | Command::Chart {
                    group_by: Some(gb), ..
                } => {
                    for f in gb {
                        if !upstream.contains(f.as_str()) {
                            out.remove(f.as_str());
                            out.insert(normalize_field_name(f).to_string());
                        }
                    }
                }
                // eventstats appends window columns to UNCHANGED input rows
                // (`SELECT *, … OVER (PARTITION BY …)`) — its by-fields are not
                // output columns at all. Registering them (raw OR normalized)
                // would shadow downstream schema resolution toward a column
                // the stage never created.
                Command::EventStats {
                    group_by: Some(gb), ..
                } => {
                    for f in gb {
                        if !upstream.contains(f.as_str()) {
                            out.remove(f.as_str());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// The value-computed fields visible AFTER the final stage of `query` — i.e.
/// the output columns a join/append subsearch surfaces into the outer
/// pipeline (NAN-1341).
pub(crate) fn collect_upstream_computed_from_query(query: &Query) -> HashSet<String> {
    match query {
        Query::Search(_) => HashSet::new(),
        Query::Piped { source, command } => {
            let mut upstream = collect_upstream_computed_from_query(source);
            let added = upstream_computed_added_by_command(command, &upstream);
            upstream.extend(added);
            upstream
        }
    }
}

fn collect_computed_from_command(cmd: &Command, computed: &mut HashSet<String>) {
    // NAN-3328 / NAN-3314: the shared created-column registry (also used by
    // the field validator). Lateral is excluded: its view rows are built in
    // Rust after the SQL stages are stripped, and its names (`timestamp`,
    // `user`, …) must never shadow real columns in generated SQL.
    if !matches!(cmd, Command::Lateral { .. }) {
        computed.extend(crate::query::command_outputs::command_created_columns(cmd));
    }
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
            // NAN-3150: the bucket column every timechart emits. Unregistered,
            // a downstream `| sort time_bucket` (the search service's lake
            // timechart wrapper) resolved it as the ext path `ext.time_bucket`
            // and stage_0 projected `toString(ext.time_bucket)`: Code 47.
            computed.insert("time_bucket".to_string());
            for agg in aggregations {
                if let Some(alias) = &agg.alias {
                    computed.insert(alias.clone());
                } else {
                    computed.insert(agg.func.as_str().to_string());
                }
            }
        }
        Command::Sequence {
            group_by,
            conditions,
            capture_fields,
            ..
        } => {
            // Sequence produces: step{N}_time, step{N}_event_id, step{N}_{field},
            // sequence_duration_seconds, sequence_count, timestamp
            for field in group_by {
                computed.insert(normalize_field_name(field).to_string());
            }
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
        Command::Top { inject_bounds, .. } | Command::Rare { inject_bounds, .. } => {
            computed.insert("count".to_string());
            computed.insert("percent".to_string());
            // NAN-1711 / audit D15: the detection-injected canonical window
            // columns are real output columns of this stage.
            if *inject_bounds {
                computed.insert("_first_seen".to_string());
                computed.insert("_last_seen".to_string());
            }
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
            // The scored columns, `expected` and the aggregation-first
            // `{func}_{field}` come from the shared registry (kept in lockstep
            // with `generate_anomaly_sql`); `anomaly_type` is kept as before.
            computed.insert("anomaly_type".to_string());
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
                // NAN-3327: sed rewrites its source field in place.
                RexMode::Sed { .. } => {}
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
            "event_type",
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

    // ── NAN-1639 (findings 2.4 / 3.8): projection width under row-preserving
    // pipes and pipeline-output references ─────────────────────────────────

    fn analyze(q: &str, table_view: bool) -> Option<HashSet<String>> {
        let query = parse_query(q).unwrap();
        analyze_required_fields(&query, table_view, &UdmProfile::new())
    }

    /// Finding 2.4: every SAFE row-preserving pipe keeps the slim table_view
    /// projection (plus its own referenced fields) instead of flipping to the
    /// wide `SELECT *` + 78 MATERIALIZED re-adds (Saturn: 4.4x wall, 8-12x
    /// memory at LIMIT 100).
    #[test]
    fn table_view_slim_projection_survives_safe_row_preserving_pipes() {
        for (q, referenced) in [
            ("error | where status=\"failure\"", Some("status")),
            ("error | sort -bytes_out", Some("bytes_out")),
            ("error | dedup src_ip", Some("src_ip")),
            ("error | head 100", None),
            ("error | tail 50", None),
            ("error | reverse", None),
            ("error | sample 10", None),
        ] {
            let fields = analyze(q, true)
                .unwrap_or_else(|| panic!("safe pipe flipped to wide projection: {q}"));
            // Core + the UDM summary set still present (same grid as bare searches).
            for f in [
                "id",
                "timestamp",
                "message",
                "source_type",
                "src_ip",
                "user",
            ] {
                assert!(fields.contains(f), "{q}: slim projection missing {f}");
            }
            if let Some(f) = referenced {
                assert!(fields.contains(f), "{q}: pipe-referenced field {f} missing");
            }
        }
    }

    /// Finding 2.4: commands that genuinely need the full column set keep the
    /// wide projection, even in table_view.
    #[test]
    fn table_view_wide_projection_retained_for_structural_commands() {
        for q in [
            "error | lookup assets host AS src_host",
            "error | rex \"(?P<foo>bar)\"",
            "error | spath path=a.b",
            "error | join src_ip [search error]",
            "error | append [search error]",
            "error | fillnull value=\"-\"",
            "error | fields - message",
            "error | table src_*",
        ] {
            assert!(
                analyze(q, true).is_none(),
                "structural command must keep the wide projection: {q}"
            );
        }
    }

    /// Finding 2.4 scope guard: NON-table_view raw-event output under a
    /// row-preserving pipe keeps the historical full-row projection —
    /// API/detection consumers see complete rows, unchanged.
    #[test]
    fn non_table_view_row_preserving_pipe_keeps_full_rows() {
        for q in [
            "error | where status=\"failure\"",
            "error | sort -bytes_out",
            "error | dedup src_ip",
            "error | head 100",
        ] {
            assert!(
                analyze(q, false).is_none(),
                "non-table_view raw output must stay full-row: {q}"
            );
        }
    }

    /// Finding 3.8: the executor-injected `| sort -count` on grouped stats
    /// must not force the wide stage_0, and the aggregation output alias must
    /// NOT enter the required set (stage_0 would emit a bogus
    /// `toString(ext.count) AS count`).
    #[test]
    fn injected_sort_on_grouped_stats_prunes_and_excludes_agg_outputs() {
        for table_view in [false, true] {
            let fields = analyze("* | stats count by src_ip | sort -count", table_view)
                .expect("grouped stats + sort must keep the pruned projection");
            assert!(
                fields.contains("src_ip"),
                "group-by passthrough must be projected"
            );
            assert!(
                !fields.contains("count"),
                "aggregation output alias leaked into stage_0 required fields"
            );
        }
        // Explicit alias and `{func}_{field}` reference forms are excluded too.
        let fields = analyze(
            "* | stats sum(bytes_out) as total by src_ip | sort -total",
            false,
        )
        .unwrap();
        assert!(fields.contains("bytes_out"));
        assert!(!fields.contains("total"));
        let fields = analyze(
            "* | stats sum(bytes_out) by src_ip | sort -sum_bytes_out",
            false,
        )
        .unwrap();
        assert!(!fields.contains("sum_bytes_out"));
        // `| where` on an aggregation output is the same class of reference.
        let fields = analyze("* | stats count by user | where count > 10", false).unwrap();
        assert!(!fields.contains("count"));
    }

    /// A group-by passthrough that only exists in ext JSON must SURVIVE the
    /// stage-output exclusion — required_fields is what materializes
    /// `toString(ext.threat_name) AS threat_name` in stage_0.
    #[test]
    fn ext_group_by_passthrough_survives_stage_output_exclusion() {
        let fields = analyze("* | stats count by threat_name | sort -count", false).unwrap();
        assert!(fields.contains("threat_name"));
        assert!(!fields.contains("count"));
    }

    /// A stage-output alias that COLLIDES with a real column referenced by an
    /// EARLIER stage must not be evicted from stage_0 — the pre-stats
    /// `where status=…` filters against the base column, which only exists
    /// downstream if stage_0 projects it (codex second-pass finding).
    #[test]
    fn stage_output_alias_colliding_with_real_column_is_kept() {
        let fields = analyze(
            "error | where status=\"failure\" | stats sum(bytes_out) as status by src_ip",
            false,
        )
        .expect("aggregated pipeline must prune");
        assert!(
            fields.contains("status"),
            "base column referenced before the aliasing stage must stay projected"
        );
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
            assert!(
                f.contains(*field),
                "OCSF table_view missing default field {field}"
            );
        }
        // The UDM-only summary columns must not appear (they don't exist on
        // ocsf_logs and selecting them would error / waste the projection).
        assert!(!f.contains("src_ip"));
        assert!(!f.contains("process_name"));
        assert!(!f.contains("enriched_src_country"));
    }

    #[test]
    fn ocsf_transaction_table_view_does_not_carry_event_card_summary_fields() {
        use crate::schema::OcsfProfile;

        let query = crate::query::parse_query(
            r#"metadata.log_source="windows_sysmon" | transaction user.name startswith="login" endswith="logout""#,
        )
        .expect("parse transaction");
        let fields = analyze_required_fields(&query, true, &OcsfProfile::lake_1_9())
            .expect("transaction uses a bounded projection");

        for required in [
            "time",
            "metadata.uid",
            "metadata.log_source",
            "message",
            "raw_data",
            "user.name",
        ] {
            assert!(fields.contains(required), "missing {required}: {fields:?}");
        }
        for summary_only in [
            "dst_endpoint.ip",
            "dst_endpoint.hostname",
            "src_endpoint.port",
            "actor.process.name",
            "severity",
        ] {
            assert!(
                !fields.contains(summary_only),
                "transaction sort carried unrelated {summary_only}: {fields:?}"
            );
        }
    }

    #[test]
    fn canonical_lake_table_view_contains_no_legacy_or_serving_aliases() {
        let profile = OcsfProfile::lake_1_9();
        let query = parse_query("metadata.log_source=edr").unwrap();
        let fields = analyze_required_fields(&query, true, &profile)
            .expect("canonical table view must use a bounded projection");
        for required in [
            "metadata.uid",
            "time",
            "metadata.log_source",
            "activity_name",
            "src_endpoint.ip",
        ] {
            assert!(
                fields.contains(required),
                "missing canonical field {required}"
            );
        }
        for forbidden in [
            "id",
            "timestamp",
            "source_type",
            "activity",
            "prevalence_min",
        ] {
            assert!(
                !fields.contains(forbidden),
                "legacy or derived serving alias leaked into lake projection: {forbidden}"
            );
        }
    }

    #[test]
    fn in_subsearch_filter_fields_survive_lake_projection() {
        let profile = OcsfProfile::lake_1_9();
        let query = parse_query(
            "device.hostname IN [metadata.log_source=windows_sysmon class_uid=4001 | return device.hostname] | stats count",
        ).unwrap();
        let fields = analyze_required_fields(&query, false, &profile).unwrap();
        for required in ["device.hostname", "metadata.log_source", "class_uid"] {
            assert!(fields.contains(required), "missing {required}: {fields:?}");
        }

        let cross_dataset = parse_query(
            "user.name IN [dataset=spans service_name=checkout | return service_name]",
        ).unwrap();
        let fields = analyze_required_fields(&cross_dataset, true, &profile).unwrap();
        assert!(!fields.contains("service_name"), "spans fields leaked into the logs projection: {fields:?}");
    }
}
