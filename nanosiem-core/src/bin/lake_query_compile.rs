// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compile one Nano nPL request into OCSF ClickHouse SQL for a lake worker.
//!
//! The output deliberately contains a fixed table placeholder rather than an
//! object URI or credentials. A worker replaces that exact token with its
//! tenant-fenced `s3(...)`/`gcs(...)`/`azureBlobStorage(...)` table function and
//! binds credentials as query parameters.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use nanosiem_core::query::{
    ClickHouseSqlGenerator, Command, Query, QueryOptions, SearchExpr,
    TimeRange,
    parse_query, validate_query_fields_with_profile,
};
use nanosiem_core::schema::{
    FieldResolution, FieldType, OcsfProfile, RiskProfile, SchemaId, SchemaProfile, profile_for_id,
};
use nanosiem_core::search::lake_candidate_hints::{CandidateHint, candidate_hints};
#[cfg(test)]
use nanosiem_core::search::lake_candidate_hints::source_search_expression;
use nanosiem_core::search::query_processing::{
    apply_auto_sort, apply_profile_product_semantics, contains_lake_post_processing_anywhere,
    query_has_nested_scan,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

/// The scalar `prevalence_*` names an OCSF 1.9 lake derives from its stamp
/// arrays (NAN-3451) or, on lean parts, stores physically.
const PREVALENCE_SCALARS: [&str; 5] = [
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_min",
];

const SOURCE_PLACEHOLDER: &str = "__nano_lake_source__";
const RISK_SOURCE_PLACEHOLDER: &str = "__nano_risk_source__";
/// The public result limit is one million rows. The trusted worker asks the
/// compiler for one additional row so it can prove whether that public page is
/// complete instead of silently claiming completeness at the boundary.
const MAX_COMPILE_RESULT_LIMIT: usize = 1_000_001;
const INTERNAL_DISTINCT_VALUES_ALIAS: &str = "__nano_distinct_values";
const INTERNAL_DISTINCT_VALUES_LIMIT: usize = 10_001;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompileRequest {
    query: String,
    /// Internal interactive-page opt-in; durable exports keep their full SQL.
    #[serde(default)]
    stats_page: bool,
    #[serde(default)]
    stats_page_offset: usize,
    #[serde(default = "default_dataset")]
    dataset: String,
    start: String,
    end: String,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default = "default_table_view")]
    table_view: bool,
    #[serde(default = "default_event_contract")]
    event_contract: String,
    /// Exact typed leaves beneath OCSF's producer-owned `unmapped` object.
    /// The tenant-pinned worker derives this from its immutable source manifest.
    #[serde(default)]
    unmapped_field_types: BTreeMap<String, FieldType>,
    /// Typed physical leaves from the immutable, schema-validated snapshot.
    /// Native OCSF paths remain native; this inventory creates no aliases.
    #[serde(default)]
    snapshot_field_types: BTreeMap<String, FieldType>,
    /// NAN-2869: paths every part of the window proves lowercased at rest
    /// (signed provenance). Equality on them compares raw, literal lowered.
    #[serde(default)]
    lowercased_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CompileResponse {
    schema_version: u8,
    profile: &'static str,
    dataset: &'static str,
    source_placeholder: &'static str,
    query_sha256: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: usize,
    table_view: bool,
    /// True only when the compiler proves the output is an event timeline in
    /// descending event-time order. Workers may use this to execute disjoint
    /// newest-first source windows without changing result semantics.
    newest_first_event_rows: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stats_page: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    candidate_hints: Vec<CandidateHint>,
    required_columns: Vec<RequiredColumn>,
    /// Physical event columns the transformed query can actually read.
    /// Empty means the worker must conservatively charge the full event row.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    projected_scan_columns: Vec<String>,
    sql: String,
}

#[derive(Debug, Serialize)]
struct RequiredColumn {
    name: String,
    field_type: FieldType,
}

fn default_limit() -> usize {
    100
}

fn default_dataset() -> String {
    "logs".to_string()
}

fn default_table_view() -> bool {
    true
}

fn default_event_contract() -> String {
    "ocsf-1.9".to_string()
}

fn parse_timestamp(value: &str, name: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{name} must be RFC3339"))?
        .with_timezone(&Utc))
}

fn quoted_identifiers(sql: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut identifier = String::new();
        while let Some(ch) = chars.next() {
            if ch != '"' {
                identifier.push(ch);
                continue;
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                identifier.push('"');
                continue;
            }
            break;
        }
        if !identifier.is_empty() {
            identifiers.push(identifier);
        }
    }
    identifiers
}

fn required_columns(
    query: &nanosiem_core::query::Query,
    sql: &str,
    table_view: bool,
    generator: &ClickHouseSqlGenerator,
    profile: &dyn SchemaProfile,
) -> Vec<RequiredColumn> {
    let mut columns = BTreeMap::new();
    for field in generator
        .required_fields_for_query(query, table_view)
        .unwrap_or_default()
        .into_iter()
        .chain(generator.referenced_fields_for_query(query))
    {
        if let Some((_, inputs)) = profile.source_computed_column(&field) {
            for input in inputs {
                columns.entry(input.to_string()).or_insert_with(|| profile.field_type(input).unwrap_or(FieldType::Array));
            }
            continue;
        }
        let canonical = profile.canonicalize(&field);
        // NAN-3059: a class-scoped enum (OCSF `activity_id`) compares a text
        // label against its SIBLING label column (`event_type=process_start`
        // emits `lower(activity_name) = …`). That column is never quoted in
        // the SQL, so the generated-SQL pass below cannot see it; without it
        // stage 0 of a projected plan (tree, stats, …) fails with Code 47.
        if let Some(nanosiem_core::schema::EnumIntMapping::LabelColumn(label)) =
            profile.enum_int_mapping(canonical.as_ref())
        {
            if let FieldResolution::ExplicitColumn(column) = profile.resolve(label) {
                columns
                    .entry(column)
                    .or_insert_with(|| profile.field_type(label).unwrap_or(FieldType::String));
            }
        }
        match profile.resolve(canonical.as_ref()) {
            FieldResolution::ExplicitColumn(column) => {
                if let Some(field_type) = profile.field_type(canonical.as_ref()) {
                    columns.entry(column).or_insert(field_type);
                }
            }
            FieldResolution::JsonPath { col, path }
                if matches!(col.as_str(), "unmapped" | "ext" | "event") && !path.is_empty() =>
            {
                let path = path.join(".");
                let field_type = profile
                    .field_type(canonical.as_ref())
                    .unwrap_or(FieldType::String);
                columns.entry(format!("{col}.{path}")).or_insert(field_type);
            }
            _ => {}
        }
    }
    for identifier in quoted_identifiers(sql) {
        if profile.source_computed_column(&identifier).is_some() {
            continue;
        }

        // A quoted output alias (for example stats BY `user`) is not a
        // physical Parquet column. Resolve it exactly as the generator does.
        // Class-spanning aliases need both inputs, never a synthetic source
        // column named after the alias.
        if let Some((primary, fallback)) = profile.class_split_source_fields(&identifier) {
            for column in [primary, fallback] {
                columns
                    .entry(column.to_string())
                    .or_insert_with(|| profile.field_type(column).unwrap_or(FieldType::String));
            }
        } else if let FieldResolution::ExplicitColumn(column) = profile.resolve(&identifier) {
            let field_type = profile.field_type(&column).unwrap_or(FieldType::String);
            columns.entry(column).or_insert(field_type);
        } else if identifier.starts_with("unmapped.")
            || identifier.starts_with("ext.")
            || identifier.starts_with("event.")
        {
            columns
                .entry(identifier.clone())
                .or_insert_with(|| profile.field_type(&identifier).unwrap_or(FieldType::String));
        }
    }
    // Keyword and transaction SQL quote their profile-owned body columns, so
    // the generated-SQL pass above declares exactly the bodies that query can
    // read. Do not add `message` and `raw_data` to every transforming query:
    // those wide columns would defeat Parquet projection and make a narrow
    // stats query look like a full-event scan to the admission controller.
    // Every generated log query is fenced by its requested time range, even
    // when the analyst's transforming pipeline does not mention event time.
    // The object worker projects only this declared input set for Iceberg, so
    // leaving the profile timestamp out produces a stage-0 predicate against a
    // column that was never exposed.
    let timestamp = profile.timestamp_expr();
    if let FieldResolution::ExplicitColumn(column) = profile.resolve(timestamp) {
        columns.entry(column).or_insert_with(|| {
            profile
                .field_type(timestamp)
                .unwrap_or(FieldType::Timestamp)
        });
    }
    columns
        .into_iter()
        .map(|(name, field_type)| RequiredColumn { name, field_type })
        .collect()
}

fn insert_physical_field(field: &str, profile: &dyn SchemaProfile, columns: &mut BTreeSet<String>) {
    if let Some((_, inputs)) = profile.source_computed_column(field) {
        columns.extend(inputs.into_iter().map(str::to_string));
        return;
    }

    let canonical = profile.canonicalize(field);
    if let Some((primary, fallback)) = profile.class_split_source_fields(canonical.as_ref()) {
        insert_physical_field(primary, profile, columns);
        insert_physical_field(fallback, profile, columns);
        return;
    }
    match profile.resolve(canonical.as_ref()) {
        FieldResolution::ExplicitColumn(column) => {
            columns.insert(column);
        }
        FieldResolution::JsonPath { col, path }
            if matches!(col.as_str(), "unmapped" | "ext" | "event") && !path.is_empty() =>
        {
            columns.insert(format!("{col}.{}", path.join(".")));
        }
        _ => {}
    }
}

fn expression_has_keyword(expression: &SearchExpr) -> bool {
    match expression {
        SearchExpr::Keyword(value) => !value.trim().is_empty() && value.trim() != "*",
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            expression_has_keyword(left) || expression_has_keyword(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => expression_has_keyword(inner),
        _ => false,
    }
}

fn query_needs_message(query: &Query) -> bool {
    match query {
        Query::Search(expression) => expression_has_keyword(expression),
        Query::Piped { source, command } => {
            // The shared field analyzer does not retain `rex`'s input field.
            // Today the command's only supported storage input is the event
            // message, whether it was implicit or written as `field=message`.
            query_needs_message(source)
                || matches!(command, Command::Rex { .. } | Command::Transaction { .. })
                || matches!(
                    command,
                    Command::Transaction {
                        startswith: Some(expression),
                        ..
                    } | Command::Transaction {
                        endswith: Some(expression),
                        ..
                    } if expression_has_keyword(expression)
                )
        }
    }
}

fn query_needs_raw_data(query: &Query) -> bool {
    match query {
        Query::Search(expression) => expression_has_keyword(expression),
        Query::Piped { source, command } => {
            query_needs_raw_data(source)
                || matches!(
                    command,
                    Command::Transaction {
                        startswith: Some(expression),
                        ..
                    } | Command::Transaction {
                        endswith: Some(expression),
                        ..
                    } if expression_has_keyword(expression)
                )
        }
    }
}

fn projected_scan_columns(
    query: &Query,
    generator: &ClickHouseSqlGenerator,
    profile: &dyn SchemaProfile,
    transformed_rows: bool,
) -> Vec<String> {
    if !transformed_rows {
        return Vec::new();
    }
    let mut columns = BTreeSet::new();
    for field in generator.referenced_fields_for_query(query) {
        insert_physical_field(&field, profile, &mut columns);
    }
    if query_needs_message(query) {
        insert_physical_field("message", profile, &mut columns);
    }
    if query_needs_raw_data(query) {
        insert_physical_field("raw_data", profile, &mut columns);
    }
    insert_physical_field(profile.timestamp_expr(), profile, &mut columns);
    columns.into_iter().collect()
}

fn compile(request: CompileRequest) -> Result<CompileResponse> {
    if request.query.trim().is_empty() {
        bail!("query must be non-empty");
    }
    if request.limit == 0 || request.limit > MAX_COMPILE_RESULT_LIMIT {
        bail!("limit must be between 1 and {MAX_COMPILE_RESULT_LIMIT}");
    }
    let start = parse_timestamp(&request.start, "start")?;
    let end = parse_timestamp(&request.end, "end")?;
    if start >= end {
        bail!("start must be earlier than end");
    }
    let mut query = parse_query(&request.query).context("invalid nPL query")?;
    let (dataset, source_placeholder, profile): (
        &'static str,
        &'static str,
        std::sync::Arc<dyn SchemaProfile>,
    ) = match request.dataset.trim().to_ascii_lowercase().as_str() {
        "logs" | "log" => {
            if !request.lowercased_fields.is_empty() && request.event_contract != "ocsf-1.9" {
                bail!("lowercased_fields requires the ocsf-1.9 lake contract");
            }
            let profile: std::sync::Arc<dyn SchemaProfile> = match request.event_contract.as_str() {
                "legacy-flat-ocsf-1.8" => profile_for_id(SchemaId::Ocsf),
                "ocsf-1.9" => std::sync::Arc::new(
                    OcsfProfile::try_lake_1_9_with_snapshot_field_types(
                        if request.snapshot_field_types.is_empty() {
                            request.unmapped_field_types.clone()
                        } else {
                            request.snapshot_field_types.clone()
                        },
                    )
                    .and_then(|profile| profile.with_lake_lowercased_at_rest(&request.lowercased_fields))
                    .map_err(anyhow::Error::msg)?,
                ),

                other => bail!("unsupported lake event contract: {other}"),
            };
            ("logs", SOURCE_PLACEHOLDER, profile)
        }
        "risk" => (
            "risk",
            RISK_SOURCE_PLACEHOLDER,
            std::sync::Arc::new(RiskProfile::new()),
        ),
        other => bail!("unsupported lake dataset: {other}"),
    };
    apply_profile_product_semantics(&mut query, profile.as_ref());
    if dataset == "logs" && contains_lake_post_processing_anywhere(&query) {
        // NAN-4287: a 400 the analyst can act on, naming the supported shape.
        bail!(
            "lake compiler cannot execute Nano-side lookup, prevalence, inputlookup, identity, or AI stages here. {}",
            nanosiem_core::search::service::LAKE_LOOKUP_ALTERNATIVE
        );
    }
    let field_errors = validate_query_fields_with_profile(&query, Some(profile.as_ref()));
    if !field_errors.is_empty() {
        // NAN-3451: every `prevalence_*` scalar is derived from the same
        // stamp arrays, so an unstamped snapshot rejects all of them alike.
        let is_prevalence_scalar = |name: &str| PREVALENCE_SCALARS.contains(&name);
        if request.event_contract == "ocsf-1.9"
            && field_errors
                .iter()
                .any(|error| is_prevalence_scalar(&error.field_name))
        {
            let mut unstamped = field_errors
                .iter()
                .filter(|error| is_prevalence_scalar(&error.field_name))
                .map(|error| error.field_name.as_str())
                .collect::<Vec<_>>();
            unstamped.sort_unstable();
            unstamped.dedup();
            let other_errors = field_errors
                .iter()
                .filter(|error| !is_prevalence_scalar(&error.field_name))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            bail!(
                "query field validation failed: {}: field not searchable on this lake yet (snapshot lacks the prevalence stamp arrays){}",
                unstamped.join(", "),
                if other_errors.is_empty() {
                    String::new()
                } else {
                    format!("; {}", other_errors.join("; "))
                }
            );
        }
        bail!(
            "query field validation failed: {}",
            field_errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let candidate_hints = candidate_hints(&query, dataset, profile.as_ref());
    let internal_distinct_state = has_internal_distinct_state(&query);
    // NAN-2961: progressive newest-first paging fences each chunk in time; a
    // subsearch must see the whole range, so nested scans never page.
    let mut newest_first_event_rows = dataset == "logs"
        && is_newest_first_event_projection(&query)
        && !query_has_nested_scan(&query);
    // A newest-first timeline with `head N` returns at most N rows. The worker
    // pages it by running the SQL once per disjoint time chunk and
    // concatenating newest-first, so the global top-N is the first N rows it
    // sees -- but only if it can read N off the statement's trailing
    // `ORDER BY time DESC … LIMIT N`. Clamp the outer LIMIT to N so staged
    // shapes (`| sort -time | head N`) carry it; a shape that still does not
    // end that way is executed over the whole window instead (below).
    let head_cap = if newest_first_event_rows {
        newest_first_head_cap(&query)
    } else {
        None
    };
    let output_limit = head_cap.map_or(request.limit, |cap| cap.min(request.limit));
    // Match SearchService: raw event timelines are newest-first and grouped
    // aggregations receive their deterministic implicit top-value sort.
    let (query, _) = apply_auto_sort(query);
    // NAN-3162: the event-UID tie-break on every window, so a `head N`
    // timeline over more than 24 h still ends in the cursor order and pages
    // progressively (the worker bounds that sort; see the builder's docs).
    let mut generator = ClickHouseSqlGenerator::with_table(source_placeholder)
        .with_profile(profile.clone())
        .with_uid_tiebreak_any_window(true)
        // NAN-4164: multi-token bare keywords match as an adjacent term.
        .with_keyword_term_adjacency(true);
    if internal_distinct_state {
        // SearchService merges these exact, bounded values states across
        // scan-budgeted slices. The normal user-facing values() cap of 100
        // would silently undercount dc() after the merge.
        generator = generator.with_max_group_array_size(INTERNAL_DISTINCT_VALUES_LIMIT);
    }
    let stats_page = request.stats_page && dataset == "logs" && !query_has_nested_scan(&query)
        && nanosiem_core::query::stats_page::eligible(&query);
    let options = QueryOptions {
        use_cache: false,
        table_view: request.table_view,
        limit: if stats_page { None } else { Some(output_limit) },
        unordered: false,
    };
    let mut sql = generator
        .generate_with_options(&query, &TimeRange::new(start, end), &options)
        .context("failed to generate OCSF lake SQL")?;
    if stats_page {
        // The window runs AFTER the entire user pipeline (including head),
        // BEFORE the display limit. It counts groups, never source events.
        // Generated grouped pipelines always have a final SELECT * FROM CTE.
        let (body, settings) = sql.rsplit_once(" SETTINGS ")
            .context("grouped page SQL omitted settings")?;
        let (stages, final_select) = body.rsplit_once("\nSELECT * FROM ")
            .context("grouped page SQL omitted final projection")?;
        // Repeat the last stage's exact generated ordering at the window
        // projection. A window operator must not rely on inherited CTE order.
        let statements =
            parse_generated_sql(&sql).context("failed to parse generated grouped page SQL")?;
        let sqlparser::ast::Statement::Query(statement) = &statements[0] else {
            bail!("grouped page SQL is not a query");
        };
        let ordering = statement.with.as_ref().and_then(|with| {
            with.cte_tables.iter().rev().find_map(|cte| cte.query.order_by.as_ref())
        }).map(|order| format!("{order} ")).unwrap_or_default();
        let offset = request.stats_page_offset;
        if offset >= output_limit {
            bail!("stats page offset must be below the compiler bound");
        }
        // Retain the first ranked group as a cardinality carrier even when
        // the requested offset is beyond the final group. No second scan and
        // no transfer of the preceding offset groups is needed. The worker
        // removes the carrier and ordinal before returning the display page.
        let end = output_limit;
        let row_limit = output_limit - offset + usize::from(offset > 0);
        sql = format!("{stages},\n__nano_stats_ranked AS (\n  SELECT *, {}, row_number() OVER ({ordering}) AS __nano_stats_ordinal FROM {final_select}\n)\nSELECT * FROM __nano_stats_ranked WHERE __nano_stats_ordinal = 1 OR (__nano_stats_ordinal > {offset} AND __nano_stats_ordinal <= {end}) ORDER BY __nano_stats_ordinal LIMIT {row_limit} SETTINGS {settings}",
            nanosiem_core::query::stats_page::TOTAL_EXPRESSION);
    }
    // NAN-3060: "newest-first event rows" is a promise about the SQL's
    // output order: the (time, metadata.uid) cursor of a page's last row
    // continues the result, and progressive chunks concatenate newest first.
    // Only a statement that ENDS in that order keeps it. `| table`, `| fields`,
    // `| rename` and `| sort -time` shapes compiled to an unordered outer
    // `SELECT … LIMIT n`: cursor pages over it repeated and skipped rows
    // (6,377 rows returned for a 5,981-row result).
    if newest_first_event_rows && !ends_in_event_cursor_order(&sql) {
        newest_first_event_rows = false;
    }
    if head_cap.is_some() && trailing_newest_first_limit(&sql) != Some(output_limit) {
        // Per-chunk execution would return up to N rows per chunk.
        newest_first_event_rows = false;
    }
    let required_columns = required_columns(
        &query,
        &sql,
        request.table_view,
        &generator,
        profile.as_ref(),
    );
    let mut required_columns = required_columns;
    if dataset == "logs"
        && query_needs_message(&query)
        && !required_columns
            .iter()
            .any(|column| column.name == "message")
    {
        required_columns.push(RequiredColumn {
            name: "message".to_string(),
            field_type: profile.field_type("message").unwrap_or(FieldType::String),
        });
        required_columns.sort_by(|left, right| left.name.cmp(&right.name));
    }
    if dataset == "logs"
        && query_needs_raw_data(&query)
        && !required_columns
            .iter()
            .any(|column| column.name == "raw_data")
    {
        required_columns.push(RequiredColumn {
            name: "raw_data".to_string(),
            field_type: profile.field_type("raw_data").unwrap_or(FieldType::String),
        });
        required_columns.sort_by(|left, right| left.name.cmp(&right.name));
    }
    let transformed_rows = !is_full_event_sql(&sql);
    let projected_scan_columns =
        projected_scan_columns(&query, &generator, profile.as_ref(), transformed_rows);
    if !sql.contains(source_placeholder) {
        bail!("query does not target the tenant lake source");
    }
    for forbidden in [
        "nanosiem.",
        "FROM logs",
        "FROM ocsf_logs",
        "FROM otel_",
        "FROM risk_findings",
        "FROM identity_observations",
    ] {
        if sql.contains(forbidden) {
            bail!("query requires an unsupported non-lake dataset: {forbidden}");
        }
    }
    let query_sha256 = hex::encode(Sha256::digest(request.query.as_bytes()));
    Ok(CompileResponse {
        schema_version: 1,
        profile: if dataset == "risk" { "risk" } else { "ocsf" },
        dataset,
        source_placeholder,
        query_sha256,
        start,
        end,
        limit: request.limit,
        table_view: request.table_view,
        newest_first_event_rows,
        stats_page,
        candidate_hints,
        required_columns,
        projected_scan_columns,
        sql,
    })
}

/// NAN-3276: generated SQL nests as deep as the user's expression does, and
/// a filter over many values is legitimately deep. sqlparser's default depth
/// (50) refused a 50-artifact prevalence read; ClickHouse itself accepts up to
/// its `max_parser_depth` (1000), and sqlparser's recursion protection grows
/// the stack, so the compiler accepts what the engine accepts.
const GENERATED_SQL_PARSER_DEPTH: usize = 1_000;

fn parse_generated_sql(
    sql: &str,
) -> Result<Vec<sqlparser::ast::Statement>, sqlparser::parser::ParserError> {
    sqlparser::parser::Parser::new(&sqlparser::dialect::ClickHouseDialect {})
        .with_recursion_limit(GENERATED_SQL_PARSER_DEPTH)
        .try_with_sql(sql)?
        .parse_statements()
}

fn is_full_event_sql(sql: &str) -> bool {
    let selects = regex::Regex::new(r"(?i)\bSELECT\b")
        .expect("static regex")
        .find_iter(sql)
        .count();
    let full_rows = regex::Regex::new(r"(?i)\bSELECT\s+\*\s+FROM\b")
        .expect("static regex")
        .find_iter(sql)
        .count();
    selects > 0 && selects == full_rows
}

fn has_internal_distinct_state(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            let current = match command {
                Command::Stats { aggregations, .. } => aggregations.iter().any(|aggregation| {
                    aggregation.func == nanosiem_core::query::AggFunc::Values
                        && aggregation.alias.as_deref() == Some(INTERNAL_DISTINCT_VALUES_ALIAS)
                }),
                _ => false,
            };
            current || has_internal_distinct_state(source)
        }
    }
}

/// Row-preserving projections retain the implicit newest-first event order.
/// Membership-changing and stateful commands deliberately fail this proof.
/// The smallest `head N` (or `sort … N`) bound in a newest-first timeline.
fn newest_first_head_cap(query: &Query) -> Option<usize> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            let current = match command {
                Command::Head { count } => Some(*count),
                Command::Sort { limit, .. } => *limit,
                _ => None,
            };
            match (newest_first_head_cap(source), current) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            }
        }
    }
}

/// `N` when the statement ends `ORDER BY time DESC [, "metadata.uid" DESC]
/// LIMIT N` (an optional trailing `SETTINGS …` aside). Mirrors the lake
/// worker's `newest_first_row_cap`, which is what actually stops the walk.
fn trailing_newest_first_limit(sql: &str) -> Option<usize> {
    let body = sql.rfind(" SETTINGS ").map_or(sql, |at| &sql[..at]);
    let (head, limit) = body.trim_end().rsplit_once(" LIMIT ")?;
    let limit = limit.trim().parse::<usize>().ok()?;
    let order = head.trim_end();
    let order = order
        .strip_suffix(", \"metadata.uid\" DESC")
        .unwrap_or(order)
        .trim_end();
    (order.ends_with("ORDER BY time DESC") || order.ends_with("ORDER BY \"time\" DESC"))
        .then_some(limit)
}

/// The statement's outer order is exactly the event cursor order,
/// `ORDER BY time DESC, "metadata.uid" DESC LIMIT n`.
fn ends_in_event_cursor_order(sql: &str) -> bool {
    let body = sql.rfind(" SETTINGS ").map_or(sql, |at| &sql[..at]);
    let Some((head, limit)) = body.trim_end().rsplit_once(" LIMIT ") else { return false };
    if limit.trim().parse::<usize>().is_err() {
        return false;
    }
    let head = head.trim_end();
    head.ends_with("ORDER BY time DESC, \"metadata.uid\" DESC")
        || head.ends_with("ORDER BY \"time\" DESC, \"metadata.uid\" DESC")
}

fn is_newest_first_event_projection(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            is_newest_first_event_projection(source)
                && (matches!(
                    command,
                    Command::Table { .. }
                        | Command::Fields { .. }
                        | Command::Head { .. }
                        // NAN-4236: a row filter keeps the newest-first
                        // order and is exact per disjoint time chunk.
                        | Command::Where { .. }
                        | Command::Rename { .. }
                        | Command::Fillnull { .. }
                        | Command::Eval { .. }
                        | Command::Rex { .. }
                )
                    // NAN-2869: an explicit `sort -time` restates the
                    // default newest-first event order, so a timeline
                    // (`… | sort -time | head N`) pages newest-first too.
                    || matches!(
                        command,
                        Command::Sort { fields, .. }
                            if fields.len() == 1
                                && fields[0].descending
                                && matches!(fields[0].field.as_str(), "time" | "timestamp" | "_time")
                    ))
        }
    }
}

fn run() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read compile request from stdin")?;
    let request: CompileRequest =
        serde_json::from_str(&input).context("compile request must be JSON")?;
    let response = compile(request)?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lake query compile failed: {error:#}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_pages_count_the_complete_pipeline_before_the_display_limit() {
        for query in [
            "* | stats count by src_endpoint.ip, actor.process.name",
            "* | stats count, max(timestamp) as last_seen by src_endpoint.ip | sort -count | head 500",
            "* | stats count by src_endpoint.ip | head 20",
        ] {
            let mut input = request(query);
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(output.stats_page, "{query}");
            assert!(output.sql.contains("SELECT *, count() OVER () AS __nano_stats_total"), "{}", output.sql);
            let final_sql = output.sql.rsplit_once("\nSELECT ").unwrap().1;
            assert!(output.sql.contains("OVER (ORDER BY count DESC"), "{}", output.sql);
            assert!(final_sql.contains("ORDER BY __nano_stats_ordinal"), "{final_sql}");
            assert!(final_sql.contains("LIMIT 100 SETTINGS"), "{final_sql}");
            // User head is in an earlier CTE, so cardinality counts its output.
            if query.ends_with("head 20") {
                assert!(output.sql.contains("\n  LIMIT 20"));
            }
        }
        for query in [
            "* | stats count by src_endpoint.ip | where count > 10",
            "* | stats count by src_endpoint.ip | eventstats sum(count) as total",
            "* | stats count by src_endpoint.ip | stats count",
            "* | timechart span=1h count",
        ] {
            let mut input = request(query);
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(!output.stats_page, "{query}");
            assert!(!output.sql.contains("__nano_stats_total"), "{query}");
        }
    }

    /// NAN-3276: the Asset dossier's global prevalence read (a grouped
    /// `stats` over an OR of per-artifact groups) compiled to SQL nested one
    /// parenthesis level per OR node, and the stats-page parse refused it at
    /// 50 artifacts: "failed to parse generated grouped page SQL: sql parser
    /// error: recursion limit exceeded". OR chains now compile flat, so that
    /// shape and a many-thousand-value list both page.
    #[test]
    fn grouped_pages_compile_for_long_or_chains_and_value_lists() {
        let group = |i: usize| {
            format!(
                "(query.hostname=\"d{i}.example\" OR http_request.url.hostname=\"d{i}.example\" \
                 OR url.hostname=\"d{i}.example\" OR dst_endpoint.hostname=\"d{i}.example\")"
            )
        };
        let groups = (0..50).map(group).collect::<Vec<_>>().join(" OR ");
        let values = (0..8_000)
            .map(|i| format!("\"d{i}.ex\""))
            .collect::<Vec<_>>()
            .join(", ");
        for predicate in [
            format!("({groups})"),
            format!("(query.hostname IN ({values}) OR file.hashes.value IN ({values}) OR dst_endpoint.hostname IN ({values}))"),
        ] {
            let mut input = request(&format!(
                "{predicate} | stats count() by query.hostname, file.hashes.value, device.hostname, src_endpoint.ip"
            ));
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(output.stats_page);
            assert!(output.sql.contains("__nano_stats_ordinal"), "{}", &output.sql[..300]);
            assert!(!output.sql.contains("(((("), "OR chains must not nest per node");
            // The same parser, at its default depth, accepts the result.
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::ClickHouseDialect {}, &output.sql)
                .expect("generated grouped page SQL parses at the default depth");
        }
    }

    /// NAN-3325: `stats sparkline` compiled to `sumMap(…).2`, which the
    /// grouped-page rewrite could not re-parse ("Expected: ), found: .2").
    #[test]
    fn grouped_sparkline_page_compiles() {
        let mut input = request("class_uid=4002 | stats sparkline by metadata.log_source");
        input.stats_page = true;
        let output = compile(input).expect("sparkline grouped page must compile");
        assert!(output.sql.contains("tupleElement(sumMap("), "{}", output.sql);
    }

    /// NAN-3385: `timechart bins=N` compiles on the lake against the request
    /// window (24 h / 10 → 3 h buckets), identical to the explicit span.
    #[test]
    fn timechart_bins_compiles_to_the_round_span() {
        let bins = compile(request("metadata.log_source=windows_event | timechart bins=10 count"))
            .expect("timechart bins= must compile");
        let span = compile(request("metadata.log_source=windows_event | timechart span=3h count"))
            .expect("timechart span= must compile");
        assert_eq!(bins.sql, span.sql);
    }

    #[test]
    fn lake_compile_uses_splunk_search_precedence() {
        let query = "class_uid=3002 activity_id=1 OR activity_id=2";
        let parsed = parse_query(query).unwrap();
        assert!(matches!(source_search_expression(&parsed), SearchExpr::And(_, right) if matches!(&**right, SearchExpr::Or(_, _))));
        let output = compile(request(query)).unwrap();
        assert!(output.sql.contains(" OR ") && output.sql.contains(" AND "), "{}", output.sql);
    }

    /// NAN-3150: the search service's lake timechart wrapper (`… | timechart
    /// … | sort time_bucket`) resolved the bucket as `ext.time_bucket` in
    /// stage_0 (`Code: 47. Unknown … identifier ext.time_bucket`).
    #[test]
    fn timechart_bucket_is_a_pipeline_output_not_an_ext_path() {
        for query in [
            "metadata.log_source=conduit_proxy src_endpoint.ip=10.1.5.242 | timechart span=1h sum(traffic.bytes_out) as bytes_out_total | sort time_bucket",
            "metadata.log_source=conduit_proxy | timechart span=1h count | sort time_bucket",
            "metadata.log_source=conduit_proxy | timechart span=10m count | where time_bucket > 0 | sort -time_bucket",
        ] {
            let mut input = request(query);
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(!output.sql.contains("ext."), "{query}: {}", output.sql);
            assert!(!output.required_columns.iter().any(|column| column.name.contains("time_bucket")), "{query}");
            assert!(output.sql.contains("AS time_bucket"), "{}", output.sql);
        }
    }

    fn request(query: &str) -> CompileRequest {
        CompileRequest {
            query: query.to_string(),
            stats_page: false,
            stats_page_offset: 0,
            dataset: default_dataset(),
            start: "2026-08-07T00:00:00Z".to_string(),
            end: "2026-08-08T00:00:00Z".to_string(),
            limit: 100,
            table_view: true,
            event_contract: default_event_contract(),
            unmapped_field_types: BTreeMap::new(),
            snapshot_field_types: BTreeMap::new(),
            lowercased_fields: Vec::new(),
        }
    }

    #[test]
    fn launch_auth_enum_queries_compile_to_ids() {
        for field in ["auth_result", "status_id"] {
            for label in ["failure", "Failure", "FAILURE"] {
                let output = compile(request(&format!("class_name=Authentication {field}={label} | stats count"))).unwrap();
                assert!(output.sql.contains("status_id"), "{}", output.sql);
                assert!(!output.sql.to_lowercase().contains("'failure'"), "{}", output.sql);
                assert!(output.sql.contains("= 2"), "{}", output.sql);
            }
            for suffix in ["=not_an_outcome", " IN (failure, not_an_outcome)"] {
                assert!(compile(request(&format!("{field}{suffix} | stats count"))).is_err());
            }
            assert!(compile(request(&format!("{field} IN (failure, success) | stats count"))).unwrap().sql.contains("IN (2, 1)"));
            assert!(compile(request(&format!("{field}!=Failure | stats count"))).unwrap().sql.contains("!= 2"));
        }
        let disposition = compile(request("disposition_id=Blocked | stats count")).unwrap();
        assert!(disposition.sql.contains("= 2"), "{}", disposition.sql);
        assert!(compile(request("unresolvable_auth_alias=failure | stats count")).is_err());
        let file = compile(request("class_uid=1001 file_action=create | stats count")).unwrap();
        assert!(file.sql.contains("activity_name"), "{}", file.sql);
    }

    #[test]
    fn launch_protocol_queries_use_iana_ids_and_declare_fallback_columns() {
        for field in ["protocol", "protocol_name", "connection_info.protocol_name", "connection_info.protocol_num"] {
            for label in ["tcp", "TCP", "Tcp"] {
                let output = compile(request(&format!("class_name=\"Network Activity\" {field}={label} | stats count"))).unwrap();
                assert!(output.sql.contains("connection_info.protocol_num"), "{}", output.sql);
                assert!(output.sql.contains("= 6"), "{}", output.sql);
                if field != "connection_info.protocol_num" {
                    assert!(output.sql.contains("connection_info.protocol_name"), "{}", output.sql);
                }
                assert!(output.required_columns.iter().any(|c| c.name == "connection_info.protocol_num"));
            }
            assert!(compile(request(&format!("{field}=not_a_protocol | stats count"))).is_err());
            let output = compile(request(&format!("{field} IN (tcp, udp) | stats count"))).unwrap();
            assert!(output.sql.contains("connection_info.protocol_num"), "{}", output.sql);
        }
    }

    /// NAN-3059: `event_type=<label>` compares the class-scoped enum's label
    /// column (`lower(activity_name) = …`). A projected plan such as the
    /// documented process tree must declare that column, or stage 0 fails on
    /// the lean cell with `Unknown expression identifier activity_name`.
    #[test]
    fn enum_label_filter_declares_its_label_column() {
        for query in [
            r#"src_host="ws-1" event_type=process_start | tree parent=parent_process_guid child=process_guid label=process_name"#,
            "event_type=logon | stats count() by device.hostname",
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.sql.contains("activity_name"), "{}", output.sql);
            assert!(
                output.required_columns.iter().any(|c| c.name == "activity_name"),
                "{query}: {:?}",
                output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    /// NAN-2869: raw equality only for paths the window proves lowercased at
    /// rest; the literal is lowered at compile time. Everything else keeps
    /// `lower(col)` (mixed-case producers, e.g. `WINDOWS_EVENT`).
    #[test]
    fn lowercased_at_rest_paths_compare_raw_with_a_lowered_literal() {
        let query = r#"metadata.log_source="WinEvent_Security" | stats count by user.name"#;
        let unproven = compile(request(query)).expect("compiles");
        assert!(unproven.sql.contains(r#"lower("metadata.log_source") = 'winevent_security'"#), "{}", unproven.sql);
        let mut proven = request(query);
        proven.snapshot_field_types = BTreeMap::from([
            ("metadata.log_source".to_string(), FieldType::String),
            ("user.name".to_string(), FieldType::String),
            ("time".to_string(), FieldType::Timestamp),
        ]);
        proven.lowercased_fields = vec!["metadata.log_source".to_string()];
        let proven = compile(proven).expect("compiles");
        assert!(proven.sql.contains(r#""metadata.log_source" = 'winevent_security'"#), "{}", proven.sql);
        assert!(!proven.sql.contains(r#"lower("metadata.log_source")"#), "{}", proven.sql);
        // A path outside the snapshot's string leaves is refused, and the
        // hint needs the lake contract.
        let mut bad = request(query);
        bad.lowercased_fields = vec!["user.name".to_string()];
        assert!(compile(bad).is_err());
        let mut legacy = request(query);
        legacy.event_contract = "legacy-flat-ocsf-1.8".to_string();
        legacy.lowercased_fields = vec!["metadata.log_source".to_string()];
        assert!(compile(legacy).is_err());
    }

    /// NAN-3154: ingest-lowercased identity paths compare RAW against the
    /// lowered literal on the lake -- including both legs of the dotless
    /// hostname expansion -- so chDB's Parquet bloom/min-max push-down can
    /// prune. Every other string field keeps `lower(col)`, and negations keep
    /// `lower()` (an uppercase row must stay excluded).
    #[test]
    fn lowercased_identity_paths_compare_raw_and_others_keep_lower() {
        let where_of = |query: &str| {
            let sql = compile(request(query)).expect("compiles").sql;
            sql[sql.find(" WHERE ").expect("where")..].to_string()
        };
        for (query, raw) in [
            (r#"device.hostname="WS-1.Corp.Local" | head 5"#, r#""device.hostname" = 'ws-1.corp.local'"#),
            (
                r#"device.hostname="WS-1" | head 5"#,
                r#"("device.hostname" = 'ws-1' OR startsWith("device.hostname", 'ws-1.'))"#,
            ),
            (
                r#"src_endpoint.hostname IN ("WS-1", "db.corp") | head 5"#,
                r#"("src_endpoint.hostname" IN ('ws-1', 'db.corp') OR startsWith("src_endpoint.hostname", 'ws-1.'))"#,
            ),
            (r#"src_endpoint.ip="10.1.1.46" | head 5"#, r#""src_endpoint.ip" = '10.1.1.46'"#),
            (r#"dst_endpoint.mac="AA:BB:CC:DD:EE:FF" | head 5"#, r#""dst_endpoint.mac" = 'aa:bb:cc:dd:ee:ff'"#),
        ] {
            let clause = where_of(query);
            assert!(clause.contains(raw), "{query}: {clause}");
            assert!(!clause.contains("lower(\""), "{query}: {clause}");
        }
        for (query, lowered) in [
            (r#"user.name="Bob" | head 5"#, r#"lower("user.name") = 'bob'"#),
            (r#"process.name="CMD.exe" | head 5"#, r#"lower("process.name") = 'cmd.exe'"#),
            (
                r#"device.hostname!="WS-1" | head 5"#,
                r#"(lower("device.hostname") != 'ws-1' AND NOT startsWith(lower("device.hostname"), 'ws-1.'))"#,
            ),
            (r#"src_endpoint.hostname NOT IN ("WS-1") | head 5"#, r#"NOT startsWith(lower("src_endpoint.hostname"), 'ws-1.')"#),
        ] {
            let clause = where_of(query);
            assert!(clause.contains(lowered), "{query}: {clause}");
        }
    }

    /// NAN-2994: the whole gen1 k6 realistic corpus (94 queries plus the 14
    /// NAN-4164 keyword-class queries, also driven
    /// by `benchmarks/k6/lean_gate_search.js`) passes BOTH lean validation
    /// hops: the Search front door, whose cell-tenant profile has no snapshot
    /// inventory, and query[T]'s compile against a stored lake schema (the
    /// live read-schema fixture plus the NAN-2915 lean prevalence column).
    #[test]
    fn nan2994_k6_corpus_passes_front_door_and_cell_compile() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../benchmarks/results/soc_ir_corpus.json"
        ))
        .unwrap();
        let queries: Vec<&str> = corpus["domains"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|domain| domain["queries"].as_array().unwrap())
            .map(|query| query["query"].as_str().unwrap())
            .collect();
        assert_eq!(queries.len(), 108);
        assert!(queries
            .iter()
            .any(|query| query.contains("metadata.event_code")));
        assert!(queries.iter().any(|query| query.contains("action_id")));

        let front_door = nanosiem_core::schema::tenant_lake_schema::canonical_shared_lake_profile();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../nanosiem-lake-worker/tests/fixtures/nan2469-live-tail-read-schema.json"
        ))
        .unwrap();
        let mut stored: BTreeMap<String, FieldType> =
            serde_json::from_value::<Vec<String>>(fixture["available_paths"].clone())
                .unwrap()
                .into_iter()
                .map(|path| (path, FieldType::String))
                .collect();
        stored.insert("prevalence_dest_ip".into(), FieldType::Integer);

        let mut front_door_rejects = Vec::new();
        let mut compile_failures = Vec::new();
        for query in &queries {
            let parsed = parse_query(query).unwrap();
            for error in validate_query_fields_with_profile(&parsed, Some(front_door.as_ref())) {
                front_door_rejects.push(format!("{}: {query}", error.field_name));
            }
            let mut input = request(query);
            input.snapshot_field_types = stored.clone();
            if let Err(error) = compile(input) {
                compile_failures.push(format!("{error:#}: {query}"));
            }
        }
        assert!(compile_failures.is_empty(), "{compile_failures:#?}");
        // `prevalence_dest_ip` is not an OCSF path: only a tenant inventory can
        // vouch for the NAN-2915 stamp column, and the front door has none.
        assert!(
            front_door_rejects
                .iter()
                .all(|reject| reject.starts_with("prevalence_dest_ip: ")),
            "{front_door_rejects:#?}"
        );
    }

    #[test]
    fn nan2912_unstamped_prevalence_queries_fail_instead_of_injecting_a_constant() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../benchmarks/results/soc_ir_corpus.json"
        ))
        .unwrap();
        let query = corpus["domains"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|domain| domain["queries"].as_array().unwrap())
            .nth(88)
            .unwrap()["query"]
            .as_str()
            .unwrap();
        assert!(query.contains("prevalence_dest_ip<50"));
        for query in [query, "prevalence_dest_ip<50 | stats count"] {
            let error = compile(request(query)).unwrap_err().to_string();
            assert!(error.contains("prevalence_dest_ip"), "{error}");
            assert!(error.contains("field not searchable on this lake yet"), "{error}");
            assert!(!error.contains("Unknown canonical OCSF field"), "{error}");
        }
        let mut partial = request("prevalence_dest_ip<50 | stats count");
        partial.snapshot_field_types.insert("enrichments.data.host_count".into(), FieldType::Array);
        assert!(compile(partial).unwrap_err().to_string().contains("field not searchable on this lake yet"));
        // NAN-2915: lean signed parts carry a physical ingest-time stamp column.
        let mut lean = request("prevalence_dest_ip<50 | stats count");
        lean.snapshot_field_types.insert("prevalence_dest_ip".into(), FieldType::Integer);
        let sql = compile(lean).unwrap().sql;
        assert!(sql.contains("prevalence_dest_ip"), "{sql}");
    }

    /// NAN-3188: a mandatory `class_uid = N` becomes a whole-file class
    /// hint; under OR or NOT it must not (another branch / the complement
    /// can match rows of any class).
    /// NAN-4291 (F6): an ungrouped `stats` over no rows is one row with count
    /// 0 and every other aggregate null, not its type default (1970 for
    /// `max(time)`, `''` for `values`, 0 / NaN for `sum` / `avg`). Counts and
    /// distinct counts stay 0. Grouped stats over no rows have no rows, so
    /// their aggregates are unchanged.
    #[test]
    fn ungrouped_aggregates_are_null_over_no_rows() {
        let compiled = compile(request(
            "* | stats count, dc(actor.user.name) as users, max(time) as mt, \
             values(actor.user.name) as v, avg(dst_endpoint.port) as a, sum(eval(dst_endpoint.port=443)) as tls",
        ))
        .unwrap();
        for wrapped in ["max(", "arrayStringConcat(", "avg(", "sumIf("] {
            assert!(
                compiled.sql.contains(&format!("if(count() = 0, NULL, {wrapped}")),
                "{wrapped} is null over no rows: {}",
                compiled.sql
            );
        }
        assert!(compiled.sql.contains("count() AS `count`") || compiled.sql.contains("count() AS count"), "{}", compiled.sql);
        assert!(!compiled.sql.contains("NULL, uniqExact("), "{}", compiled.sql);

        let grouped = compile(request("* | stats count, max(time) as mt by actor.user.name")).unwrap();
        assert!(!grouped.sql.contains("if(count() = 0"), "{}", grouped.sql);
    }

    #[test]
    fn class_uid_equality_under_and_is_a_class_hint_only() {
        let classes = |query: &str| {
            compile(request(query))
                .unwrap_or_else(|error| panic!("{query}: {error:#}"))
                .candidate_hints
                .into_iter()
                .filter(|hint| matches!(hint, CandidateHint::Class { .. }))
                .collect::<Vec<_>>()
        };
        let class = |value| vec![CandidateHint::Class { value }];
        // The two NAN-3188 7d hunts.
        assert_eq!(
            classes("metadata.log_source=windows_sysmon (class_uid=201002 activity_id=2) CurrentVersion Run | stats count() by device.hostname"),
            class(201002)
        );
        assert_eq!(classes("(class_uid=4001 activity_id=1) dst_endpoint.port=445 | stats count() by device.hostname"), class(4001));
        assert_eq!(classes("class_uid=4001"), class(4001));
        assert_eq!(classes(r#"class_uid="4001" activity_id=1"#), class(4001));
        assert_eq!(classes("class_uid=4001 class_uid=4001"), class(4001), "deduplicated");
        for query in [
            "class_uid=4001 OR class_uid=1001",
            "(class_uid=4001 OR dst_endpoint.port=445) activity_id=1",
            "class_uid=4001 OR metadata.log_source=windows_sysmon",
            "NOT class_uid=4001",
            "NOT (class_uid=4001 activity_id=1)",
            "class_uid!=4001",
            "class_uid>4000",
            r#"class_uid="04001""#,
            "class_uid=4001.5",
            "class_uid IN (4001, 1001)",
            // A where after a row-changing command is no candidate superset.
            "dst_endpoint.port=445 | head 10 | where class_uid=4001",
        ] {
            assert!(classes(query).is_empty(), "{query}");
        }
        // NAN-3341 (#7013) made a non-numeric label on a numeric OCSF field a
        // loud compile error (it silently matched nothing before), so this
        // case no longer compiles at all, let alone hints a class.
        // NAN-4155 (#7215) made a where over raw events hint like its
        // search-term spelling (same or narrower predicate), so a class where
        // is a class hint too.
        assert_eq!(classes("dst_endpoint.port=445 | where class_uid=4001"), class(4001));
        let label = compile(request(r#"class_uid="4001x""#)).unwrap_err();
        assert!(format!("{label:#}").contains("Cannot resolve label '4001x'"), "{label:#}");
        let output = compile(request("class_uid=4001 dst_endpoint.port=445")).unwrap();
        assert!(output.sql.contains("4001"), "the SQL still filters rows: {}", output.sql);
        let wire = serde_json::to_value(&output.candidate_hints).unwrap();
        assert!(wire.as_array().unwrap().contains(&serde_json::json!({"kind": "class", "value": 4001})), "{wire}");
    }

    #[test]
    fn non_equality_entity_literals_have_no_candidate_hints() {
        for npl in [
            "user.name=jsm*",
            "user.name=*",
            r#"user.name="""#,
            "user.name=jsm?th",
            "src_endpoint.ip=10.0.0.0/8",
            "dst_endpoint.ip=10.0.0.0/8",
        ] {
            for query in [npl.to_string(), format!(r#"({npl} OR user.name="bob")"#)] {
                let output = compile(request(&query)).unwrap();
                assert!(output.candidate_hints.is_empty(), "{query}: {:?}", output.candidate_hints);
            }
        }
        // A slash in a non-IP identity remains literal equality.
        assert!(matches!(
            compile(request(r#"user.name="domain/jsmith""#)).unwrap().candidate_hints.as_slice(),
            [CandidateHint::Entity { .. }]
        ));
    }

    /// NAN-2961: a correlation query binds one candidate part set for every
    /// scan, so outer-search hints (which would hide subsearch-only parts)
    /// and progressive time-fenced paging are both off for it.
    #[test]
    fn correlation_queries_are_never_pruned_or_paged_by_the_outer_search() {
        let plain = compile(request(r#"user.name="bob""#)).unwrap();
        assert!(!plain.candidate_hints.is_empty());
        assert!(plain.newest_first_event_rows);
        for query in [
            r#"user.name="bob" | join device.hostname [search user.name="alice"]"#,
            r#"user.name="bob" | append [search user.name="alice"]"#,
            r#"user.name="bob" device.hostname IN [search user.name="alice" | return device.hostname]"#,
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.candidate_hints.is_empty(), "{query}: {:?}", output.candidate_hints);
            assert!(!output.newest_first_event_rows, "{query}");
        }
    }

    #[test]
    fn disjunction_requires_every_branch_and_preserves_boolean_groups() {
        let wide_or = (0..8).map(|i| format!("user.name=\"user{i}\"")).collect::<Vec<_>>().join(" OR ");
        let bounded = compile(request(&format!("user.uid=\"mandatory\" ({wide_or})"))).unwrap();
        assert!(matches!(bounded.candidate_hints.as_slice(), [CandidateHint::Entity { source_path, .. }] if source_path == "user.uid"));
        let uid = compile(request(r#"actor.user.uid="S-1-5-21""#)).unwrap();
        assert!(matches!(uid.candidate_hints.as_slice(), [CandidateHint::Entity { source_path, .. }] if source_path == "actor.user.uid"));
        let q = compile(request(r#"(actor.user.name="jsmith" OR user.name="jsmith")"#)).unwrap();
        assert!(matches!(q.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));
        for npl in [r#"user.name="jsmith" OR class_uid=3002"#, r#"NOT user.name="jsmith""#, r#"user.name="jsmith" OR class_uid!=3002"#] {
            assert!(compile(request(npl)).unwrap().candidate_hints.is_empty(), "{npl}");
        }
    }

    #[test]
    fn nan2455_corpus_compile_and_sidecar_hints() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!("../../../benchmarks/results/soc_ir_corpus.json")).unwrap();
        for (prefix, hint) in [
            ("Registry Run-key", "currentversion"),
            ("Single-host egress", "10.1.5.242"),
            ("Encoded-PowerShell", "enc"),
            ("Triage: any new scheduled-task", ""),
            ("Hunt: process_create invoking PowerShell with -ExecutionPolicy", "xecution"),
            ("Retro IR: rare external destinations", ""),
            ("AD account & group enumeration", "net"),
        ] {
            let query = corpus["domains"].as_array().unwrap().iter()
                .flat_map(|d| d["queries"].as_array().unwrap())
                .find(|q| q["use_case"].as_str().unwrap().starts_with(prefix)).unwrap();
            let mut input = request(query["query"].as_str().unwrap());
            for field in ["enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
                input.snapshot_field_types.insert(field.into(), FieldType::Array);
            }
            let output = compile(input).unwrap_or_else(|e| panic!("{prefix}: {e:#}"));
            if !hint.is_empty() {
                assert!(output.candidate_hints.iter().any(|h| match h {
                    CandidateHint::Entity { value, .. } | CandidateHint::Keyword { value, .. } | CandidateHint::SourceFamily { value } => value.eq_ignore_ascii_case(hint),
                    CandidateHint::Any { .. } | CandidateHint::Class { .. } => false,
                }), "{prefix}: {:?}", output.candidate_hints);
            }
            println!("NAN2455_COMPILE {}", serde_json::to_string(&output).unwrap());
        }
    }

    #[test]
    fn stored_enrichment_selectors_correlate_and_preserve_unknown() {
        for field in ["enriched_src_country", "src_is_tor", "ioc_src_ip_threat_type", "synthient_src_vpn"] {
            let query = format!("* | stats count by {field} | sort -count | head 10");
            let old = compile(request(&query)).unwrap();
            assert!(old.sql.contains("CAST(NULL AS Nullable("), "{}", old.sql);
            assert!(!old.sql.contains("JOIN"));
            let mut input = request(&query);
            for name in ["enrichments.name", "enrichments.provider", "enrichments.data.status", "enrichments.data.country_name", "enrichments.data.owned_fields", "enrichments.data.is_tor", "enrichments.data.threat_type", "enrichments.data.vpn"] {
                input.snapshot_field_types.insert(name.into(), FieldType::Array);
            }
            let output = compile(input).unwrap();
            assert!(output.sql.contains("arrayFirstIndex((n, p, s"), "{}", output.sql);
            assert!(!output.sql.contains("JOIN"));
            assert!(!output.required_columns.iter().any(|c| c.name == field));
        }
        assert!(compile(request("synthient_src_vpp=true | stats count")).is_err());
        let country = compile(request("* | table enriched_src_country, enriched_src_country_code, enriched_src_asn")).unwrap();
        assert!(country.sql.contains("src_endpoint.location.country"));
        assert!(country.sql.contains("src_endpoint.autonomous_system.number"));
    }

    #[test]
    fn ipinfo_lite_text_arrays_use_case_insensitive_membership() {
        for (field, value, lowered) in [
            ("enrichments.data.country_name", "United States", "united states"),
            ("enrichments.data.continent_code", "NA", "na"),
            ("enrichments.data.as_domain", "Fixture.Example", "fixture.example"),
        ] {
            for op in ["=", "!="] {
                let mut input = request(&format!("{field}{op}\"{value}\" | stats count"));
                input.snapshot_field_types.insert(field.into(), FieldType::Array);
                let output = compile(input).unwrap();
                let predicate = format!("arrayExists(x -> lower(toString(x)) = '{lowered}', \"{field}\")");
                assert!(output.sql.contains(&predicate), "{}", output.sql);
                if op == "!=" { assert!(output.sql.contains(&format!("NOT {predicate}"))); }
                assert!(output.required_columns.iter().any(|column| column.name == field));
            }
        }
    }

    #[test]
    fn nan2455_prevalence_declares_derivative_stamp_inputs_not_a_phantom_column() {
        let mut input = request("prevalence_dest_ip<50 | stats count by dst_endpoint.ip,prevalence_dest_ip");
        for name in ["enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
            input.snapshot_field_types.insert(name.into(), FieldType::Array);
        }
        let output = compile(input).unwrap();
        assert!(output.sql.contains("arrayFirstIndex"), "{}", output.sql);
        for name in ["dst_endpoint.ip", "enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
            assert!(output.required_columns.iter().any(|c| c.name == name), "missing {name}");
            assert!(output.projected_scan_columns.iter().any(|c| c == name), "missing scan {name}");
        }
        assert!(!output.required_columns.iter().any(|c| c.name == "prevalence_dest_ip"));
        assert!(!output.projected_scan_columns.iter().any(|c| c == "prevalence_dest_ip"));
        assert!(compile(request("prevalence_dest_ip<50 | stats count")).is_err());
    }

    /// NAN-3451: the same prevalence nPL compiles on an open-core lake (derived
    /// from the stamp arrays, reading only real columns) and on lean (the
    /// physical stamp columns), and fails clearly on an unstamped snapshot.
    #[test]
    fn nan3451_prevalence_scalars_compile_on_open_core_and_lean() {
        let open_core = |query: &str| {
            let mut input = request(query);
            for name in [
                "enrichments.name",
                "enrichments.provider",
                "enrichments.value",
                "enrichments.data.host_count",
                "enrichments.data.host_count_saturated",
                "file.hashes.value",
                "process.file.hashes.value",
            ] {
                input.snapshot_field_types.insert(name.into(), FieldType::Array);
            }
            compile(input)
        };
        for query in [
            "* | where prevalence_min <= 3 | stats count",
            "prevalence_file_hash<5 | stats count by file.hashes.value",
            "prevalence_process_hash=1 OR prevalence_dest_domain<10 | stats count",
            "* | stats min(prevalence_min) as rarest by device.hostname",
        ] {
            let output = open_core(query).unwrap_or_else(|error| panic!("{query}: {error:#}"));
            assert!(output.sql.contains("arrayFirstIndex"), "{query}: {}", output.sql);
            for phantom in super::PREVALENCE_SCALARS {
                assert!(!output.required_columns.iter().any(|c| c.name == phantom), "{query}: {phantom}");
                assert!(!output.projected_scan_columns.iter().any(|c| c == phantom), "{query}: {phantom}");
            }
            assert!(output.required_columns.iter().any(|c| c.name == "enrichments.value"), "{query}");
        }
        let min = open_core("* | where prevalence_min <= 3 | stats count").unwrap();
        for input in ["file.hashes.value", "process.file.hashes.value", "dst_endpoint.ip"] {
            assert!(min.required_columns.iter().any(|c| c.name == input), "missing {input}");
        }

        let mut lean = request("* | where prevalence_min <= 3 | stats count");
        for name in super::PREVALENCE_SCALARS {
            lean.snapshot_field_types.insert(name.into(), FieldType::Integer);
        }
        lean.snapshot_field_types.insert("enrichments.value".into(), FieldType::Array);
        let lean = compile(lean).unwrap();
        assert!(!lean.sql.contains("arrayFirstIndex"), "{}", lean.sql);
        assert!(lean.required_columns.iter().any(|c| c.name == "prevalence_min"));

        let error = compile(request("* | where prevalence_min <= 3 | stats count"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("prevalence_min: field not searchable on this lake yet"), "{error}");
    }

    /// NAN-2707: `field=*` on a typed non-string scalar emitted `col != ''`,
    /// which chDB rejects (`converting '' to UInt16`); the worker 500 then
    /// surfaced as a 503 "search service unavailable" on every attempt.
    #[test]
    fn nan2707_existence_on_typed_scalars_never_compares_with_empty_string() {
        let stamped = |query: &str| {
            let mut input = request(query);
            for name in ["enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
                input.snapshot_field_types.insert(name.into(), FieldType::Array);
            }
            compile(input).unwrap().sql
        };
        for sql in [
            stamped("prevalence_dest_ip=* | stats count"),
        ] {
            assert!(
                sql.contains("(prevalence_dest_ip IS NOT NULL AND prevalence_dest_ip != 65535)"),
                "prevalence existence must exclude the N/A sentinel: {sql}"
            );
            assert!(!sql.contains("prevalence_dest_ip != ''"), "{sql}");
        }
        let absent = stamped("prevalence_dest_ip!=* | stats count");
        assert!(
            absent.contains("NOT (prevalence_dest_ip IS NOT NULL AND prevalence_dest_ip != 65535)"),
            "{absent}"
        );
        for (query, column) in [
            ("dst_endpoint.port=* | stats count", "\"dst_endpoint.port\""),
            ("time=* | stats count", "time"),
        ] {
            let sql = compile(request(query)).unwrap().sql;
            assert!(
                sql.contains(&format!("({column} IS NOT NULL AND toString({column}) != '')")),
                "{query}: {sql}"
            );
            assert!(!sql.contains(&format!("{column} != ''")), "{query}: {sql}");
        }
        // String leaves keep the unchanged (index-neutral) form.
        let ip = compile(request("src_endpoint.ip=* | stats count")).unwrap().sql;
        assert!(ip.contains("\"src_endpoint.ip\" != ''"), "{ip}");
        // The post-pipe `where` arm agrees on the sentinel.
        let piped = stamped("* | where prevalence_dest_ip=* | stats count");
        assert!(piped.contains("prevalence_dest_ip != 65535"), "{piped}");
    }

    #[test]
    fn lake_udm_aliases_validate_and_compile_to_physical_columns() {
        let mut queries = vec![
            "user=* | stats count by user".to_string(),
            "src_ip=10.0.0.1 | stats count by src_ip".to_string(),
            "source_type=windows_sysmon process_name=powershell.exe | table command_line, parent_command_line, src_host".to_string(),
            "file_hash=abc OR process_hash=abc | stats count by dest_ip".to_string(),
            "process_hash IN (\"abc\", \"def\") | stats count by user".to_string(),
            "* | stats count by uri | append [search * | stats count by src_ip]".to_string(),
        ];
        #[cfg(feature = "enterprise")]
        {
            let settings =
                nanosiem_core::enterprise_shared_identity_sync::TenantIdentitySyncSettings::default(
                );
            queries.push(settings.observed_users_query());
            queries.push(settings.last_sign_in_query());
        }
        for query in queries {
            let profile = OcsfProfile::lake_1_9();
            let parsed = parse_query(&query).unwrap();
            let errors = validate_query_fields_with_profile(&parsed, Some(&profile));
            assert!(errors.is_empty(), "{query}: {errors:?}");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(!output.sql.contains("JSONExtract"), "{}", output.sql);
            assert!(!output.sql.contains("_unified"), "{}", output.sql);
            if query.starts_with("user=") {
                assert!(output.sql.contains("\"user.name\""), "{}", output.sql);
                assert!(output.sql.contains("\"actor.user.name\""), "{}", output.sql);
                for name in ["user.name", "actor.user.name"] {
                    assert!(
                        output.required_columns.iter().any(|c| c.name == name),
                        "missing {name}: {}",
                        output.sql
                    );
                    assert!(
                        output.projected_scan_columns.iter().any(|c| c == name),
                        "missing scan {name}"
                    );
                }
            }
            for column in &output.required_columns {
                assert_ne!(column.name, "user");
                assert_ne!(column.name, "timestamp");
                assert_ne!(column.name, "src_ip");
            }
            if query.starts_with("src_ip=") {
                assert!(output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
            }
            if query.starts_with("process_hash IN") {
                assert!(output.sql.contains("arrayExists("), "{}", output.sql);
                assert!(output.sql.contains("\"actor.process.file.hashes.value\""), "{}", output.sql);
            }
            if query.contains("append") {
                assert!(!output.sql.contains("\"url\""), "output alias uri must not become url: {}", output.sql);
            }
        }
    }

    #[test]
    fn lake_unknown_alias_keeps_suggestions() {
        let profile = OcsfProfile::lake_1_9();
        let parsed = parse_query("src_ipp=10.0.0.1").unwrap();
        let errors = validate_query_fields_with_profile(&parsed, Some(&profile));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].suggestions.contains(&"src_ip".to_string()));
        assert!(compile(request("src_ipp=10.0.0.1")).is_err());
        assert!(compile(request("user_identity_emali=x")).is_err());
    }

    #[test]
    fn legacy_contract_remains_explicit_during_migration() {
        let mut legacy = request(
            r#"source_type="windows_sysmon" process.name="powershell.exe" | table process.name, device.hostname"#,
        );
        legacy.event_contract = "legacy-flat-ocsf-1.8".to_string();
        let output = compile(legacy).expect("explicit legacy query should compile");

        assert_eq!(output.profile, "ocsf");
        assert!(output.sql.contains("FROM __nano_lake_source__"));
        assert!(output.sql.contains("\"process.name\""));
        assert!(output.sql.contains("\"device.hostname\""));
        assert!(!output.sql.contains("nanosiem."));
    }

    #[test]
    fn rejects_invalid_window_and_limit() {
        let mut invalid_window = request("error");
        invalid_window.end = invalid_window.start.clone();
        assert!(compile(invalid_window).is_err());

        let mut invalid_limit = request("error");
        invalid_limit.limit = 0;
        assert!(compile(invalid_limit).is_err());

        let mut truncation_sentinel = request("error");
        truncation_sentinel.limit = 1_000_001;
        assert!(compile(truncation_sentinel).is_ok());

        let mut above_internal_limit = request("error");
        above_internal_limit.limit = 1_000_002;
        assert!(compile(above_internal_limit).is_err());
    }

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity { source_path: path.to_string(), value: value.to_string() }
    }

    /// NAN-3162: analysts type barewords. A bareword the generator reads as a
    /// VALUE compiles to exactly the SQL of its quoted spelling, so it must
    /// carry exactly the same candidate hints -- without them the query
    /// skipped the bloom sidecar, entity locators, density-seeded progressive
    /// and raw-equality pushdown.
    #[test]
    fn bareword_entity_values_hint_exactly_like_quoted() {
        for (bare, quoted, expected) in [
            ("device.hostname=web1.corp.local", r#"device.hostname="web1.corp.local""#,
             vec![entity("device.hostname", "web1.corp.local")]),
            ("user.name=alice", r#"user.name="alice""#, vec![entity("user.name", "alice")]),
            ("src_endpoint.ip=10.1.2.3", r#"src_endpoint.ip="10.1.2.3""#,
             vec![entity("src_endpoint.ip", "10.1.2.3")]),
            ("file.hashes.value=d41d8cd98f00b204e9800998ecf8427e",
             r#"file.hashes.value="d41d8cd98f00b204e9800998ecf8427e""#,
             vec![entity("file.hashes.value", "d41d8cd98f00b204e9800998ecf8427e")]),
            ("process.name=cmd.exe", r#"process.name="cmd.exe""#, vec![entity("process.name", "cmd.exe")]),
            // Product aliases resolve exactly as the SQL generator resolves them.
            ("host=web1.corp.local", r#"host="web1.corp.local""#,
             vec![entity("device.hostname", "web1.corp.local")]),
            ("src_ip=10.1.2.3", r#"src_ip="10.1.2.3""#, vec![entity("src_endpoint.ip", "10.1.2.3")]),
            ("dest_host=web1.corp.local", r#"dest_host="web1.corp.local""#,
             vec![entity("dst_endpoint.hostname", "web1.corp.local")]),
            // A class-split alias lowers to `if(a != '', a, b) = v`: the
            // union of both exact lookups is a superset of its rows.
            ("user=alice", r#"user="alice""#, vec![CandidateHint::Any {
                alternatives: vec![entity("user.name", "alice"), entity("actor.user.name", "alice")],
            }]),
            ("process_name=cmd.exe", r#"process_name="cmd.exe""#, vec![CandidateHint::Any {
                alternatives: vec![entity("process.name", "cmd.exe"), entity("actor.process.name", "cmd.exe")],
            }]),
        ] {
            for shape in [" | head 20", " | sort -time | head 50", ""] {
                let bare_out = compile(request(&format!("{bare}{shape}"))).expect(bare);
                let quoted_out = compile(request(&format!("{quoted}{shape}"))).expect(quoted);
                assert_eq!(bare_out.sql, quoted_out.sql, "{bare}{shape}: identical SQL");
                assert_eq!(bare_out.candidate_hints, quoted_out.candidate_hints, "{bare}{shape}");
                assert_eq!(bare_out.candidate_hints, expected, "{bare}{shape}");
                assert_eq!(bare_out.newest_first_event_rows, quoted_out.newest_first_event_rows, "{bare}{shape}");
            }
        }
    }

    /// NAN-3162: what must still get NO exact entity hint.
    #[test]
    fn bareword_non_values_get_no_entity_hint() {
        let no_entity = |hints: &[CandidateHint]| !hints.iter().any(|hint| matches!(hint,
            CandidateHint::Entity { .. } | CandidateHint::Any { .. }));
        for query in [
            // Field references (NAN-2380): a column NAME is not a value.
            "user.name=actor.user.name",
            "user.name=user",
            // Wildcards and regexes are not exact equality.
            "user.name=web*",
            "host=web*",
            "user.name=/adm.*/",
            "user=/adm.*/",
            // Dotless host names expand to an FQDN prefix match (NAN-2361).
            "device.hostname=ws1",
            "host=ws1",
            "src_host=ws1",
            // Numeric barewords are typed literals, never entity values.
            "src_endpoint.port=443",
            "process.uid=1234",
            "user.uid=1001",
            // CIDR membership is a range, not equality.
            "src_ip=10.0.0.0/8",
        ] {
            let output = compile(request(&format!("{query} | head 5"))).expect(query);
            assert!(no_entity(&output.candidate_hints), "{query}: {:?}", output.candidate_hints);
        }
    }

    /// A class-split alias inside an OR contributes its alternatives to the
    /// OR's one flat union.
    #[test]
    fn class_split_alias_flattens_into_or_union() {
        let output = compile(request("user=alice OR src_ip=10.1.2.3 | head 5")).unwrap();
        assert_eq!(output.candidate_hints, vec![CandidateHint::Any {
            alternatives: vec![
                entity("user.name", "alice"),
                entity("actor.user.name", "alice"),
                entity("src_endpoint.ip", "10.1.2.3"),
            ],
        }]);
    }

    /// NAN-3162: windows over 24 h keep the event-UID tie-break on the lake,
    /// so `head N` timelines page newest first (progressive + cursor).
    #[test]
    fn long_window_timelines_keep_cursor_order_on_the_lake() {
        for query in [
            "src_endpoint.ip=10.1.2.3 | head 50",
            "host=web1.corp.local | sort -time | head 50",
            "* | sort -time | head 20",
            "user.name=alice",
        ] {
            for end in ["2026-08-08T00:00:00Z", "2026-08-14T00:00:00Z", "2026-09-06T00:00:00Z"] {
                let mut input = request(query);
                input.end = end.to_string();
                let output = compile(input).expect(query);
                assert!(output.newest_first_event_rows, "{query} to {end}: {}", output.sql);
                assert!(ends_in_event_cursor_order(&output.sql), "{query} to {end}: {}", output.sql);
            }
        }
        // ClickHouse generators keep the 24 h cap byte-identically.
        let query = parse_query("* | head 5").unwrap();
        let range = TimeRange::new(
            parse_timestamp("2026-08-07T00:00:00Z", "start").unwrap(),
            parse_timestamp("2026-08-14T00:00:00Z", "end").unwrap(),
        );
        let options = QueryOptions { use_cache: false, table_view: true, limit: Some(5), unordered: false };
        let profile = std::sync::Arc::new(OcsfProfile::lake_1_9());
        let default = ClickHouseSqlGenerator::with_table(SOURCE_PLACEHOLDER)
            .with_profile(profile.clone())
            .generate_with_options(&query, &range, &options)
            .unwrap();
        assert!(!default.contains("\"metadata.uid\" DESC"), "{default}");
        let lake = ClickHouseSqlGenerator::with_table(SOURCE_PLACEHOLDER)
            .with_profile(profile)
            .with_uid_tiebreak_any_window(true)
            .generate_with_options(&query, &range, &options)
            .unwrap();
        assert!(lake.contains("ORDER BY time DESC, \"metadata.uid\" DESC"), "{lake}");
    }

    /// NAN-2361: a candidate hint must never be NARROWER than the SQL it ships
    /// with — candidates prune the source, so anything the hint excludes is a
    /// row the query can no longer return.
    ///
    /// A dotless hostname compiles to `= v OR startsWith(col, 'v.')`, but the
    /// entity hint carried the bare literal. Objects holding only
    /// `ws-fin-011.corp.local` were pruned before the SQL ran, so
    /// `device.hostname="ws-fin-011"` returned zero rows on promoted data while
    /// the same query worked against the hot tail, which has no entity sidecar
    /// to prune with.
    #[test]
    fn dotless_hostname_equality_emits_no_entity_hint() {
        let short = compile(request(r#"device.hostname="ws-fin-011" | head 5"#))
            .expect("short hostname query should compile");
        assert!(
            short.sql.contains("startsWith"),
            "the dotless form must still expand to the FQDN-prefix match: {}",
            short.sql
        );
        // It degrades to the substring lane rather than losing pruning
        // entirely: `ws-fin-011.corp.local` CONTAINS `ws-fin-011`, so a
        // contains-hint stays a superset of the expanded predicate. Only the
        // exact-value entity hint is unsound here.
        assert!(
            !short
                .candidate_hints
                .iter()
                .any(|hint| matches!(hint, CandidateHint::Entity { .. })),
            "an exact-value entity hint cannot accompany an expanded predicate: {:?}",
            short.candidate_hints
        );
        assert_eq!(
            short.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "contains",
                value: "ws-fin-011".to_string(),
            }]
        );

        // An FQDN is genuine exact equality, so it keeps its (sound) hint.
        let fqdn = compile(request(r#"device.hostname="ws-fin-011.corp.local" | head 5"#))
            .expect("fqdn hostname query should compile");
        assert!(!fqdn.sql.contains("startsWith"), "fqdn must not expand");
        assert_eq!(
            fqdn.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "device.hostname".to_string(),
                value: "ws-fin-011.corp.local".to_string(),
            }]
        );
    }

    #[test]
    fn emits_only_compiler_proven_sidecar_hints() {
        let event_uid = compile(request(
            r#"metadata.uid="scale03-ramp-1tb-0000000000000042" | head 1"#,
        ))
        .expect("event uid query should compile");
        assert_eq!(
            event_uid.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "metadata.uid".to_string(),
                value: "scale03-ramp-1tb-0000000000000042".to_string(),
            }]
        );

        let entity = compile(request(
            r#"src_endpoint.ip="198.51.100.25" | stats count() as events"#,
        ))
        .expect("entity query should compile");
        assert_eq!(
            entity.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "src_endpoint.ip".to_string(),
                value: "198.51.100.25".to_string(),
            }]
        );

        let signal_resource = compile(request(
            r#"resources.ip="45.155.205.233" | table metadata.uid, risk_score"#,
        ))
        .expect("Signal resource query should compile");
        assert_eq!(
            signal_resource.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "resources.ip".to_string(),
                value: "45.155.205.233".to_string(),
            }]
        );

        let keyword = compile(request("gpupdate | head 20")).expect("keyword query should compile");
        assert_eq!(
            keyword.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "token",
                value: "gpupdate".to_string(),
            }]
        );

        let unsafe_or = compile(request(
            r#"src_endpoint.ip="198.51.100.25" OR user.name="alice""#,
        ))
        .expect("OR query should still compile through the broad path");
        assert!(matches!(unsafe_or.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));

        // NAN-3694: the asset IP pivot keeps its pruning once `device.ip`
        // joins the OR.
        let ip_pivot = compile(request(
            r#"(src_endpoint.ip="10.1.4.63" OR dst_endpoint.ip="10.1.4.63" OR device.ip="10.1.4.63") | stats count"#,
        ))
        .expect("IP pivot should compile");
        assert!(
            matches!(ip_pivot.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }]
                if alternatives.len() == 3 && alternatives.contains(&CandidateHint::Entity {
                    source_path: "device.ip".to_string(),
                    value: "10.1.4.63".to_string(),
                })),
            "{:?}",
            ip_pivot.candidate_hints
        );
        for path in ["device.uid", "user.email_addr", "actor.user.email_addr", "actor.process.user.name"] {
            let compiled = compile(request(&format!(r#"{path}="Alice@Example.com" | head 1"#)))
                .expect("asset identity should compile");
            assert_eq!(
                compiled.candidate_hints,
                vec![CandidateHint::Entity { source_path: path.to_string(), value: "Alice@Example.com".to_string() }],
                "{path}"
            );
        }

        let event_uid_or = compile(request(
            r#"metadata.uid="scale03-a" OR metadata.uid="scale03-b""#,
        ))
        .expect("event uid OR query should still compile through the broad path");
        assert!(matches!(event_uid_or.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));

        let negated_event_uid = compile(request(r#"NOT metadata.uid="scale03-a""#))
            .expect("negated event uid query should still compile through the broad path");
        assert!(negated_event_uid.candidate_hints.is_empty());

        let structured_contains = compile(request(r#"process.cmd_line contains "gpupdate""#))
            .expect("structured contains should use the canonical text sidecar");
        assert_eq!(
            structured_contains.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "contains",
                value: "gpupdate".to_string(),
            }]
        );

        let mut trace = request(r#"unmapped.trace_id="4bf92f3577b34da6a3ce929d0e0e4736""#);
        trace
            .unmapped_field_types
            .insert("unmapped.trace_id".to_string(), FieldType::String);
        let trace = compile(trace).expect("generic OCSF trace fallback should compile");
        assert_eq!(
            trace.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "unmapped.trace_id".to_string(),
                value: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            }]
        );
    }

    /// NAN-3041: the eval/`if()` predicates rule authors need compile through
    /// the whole lean front door (validation included), with where/search
    /// semantics, and a post-pipe `where` resolves the `user` alias.
    #[test]
    fn eval_predicates_and_post_pipe_aliases_compile_on_the_lake() {
        let output = compile(request(
            r#"actor.process.name=* | eval a=if(actor.process.name CONTAINS "EDGE", 1, 0), b=if(actor.process.name=/edge.*update/i, 1, 0), c=if(actor.process.name IN ("MicrosoftEdgeUpdate.exe", "x"), 1, 0), d=if(in(actor.process.name, "svchost.exe"), 1, 0), e=if(NOT actor.process.name IN ("a"), 1, 0) | stats sum(a) as a, sum(b) as b, sum(c) as c, sum(d) as d, sum(e) as e"#,
        ))
        .expect("eval predicates compile on the lake");
        for needle in [
            r#"positionCaseInsensitiveUTF8(toString("actor.process.name"), toString('EDGE'))"#,
            r#"match(toString("actor.process.name"), '(?i)edge.*update')"#,
            r#"(lower(toString("actor.process.name")) IN ('microsoftedgeupdate.exe', 'x'))"#,
            r#"(lower(toString("actor.process.name")) IN ('svchost.exe'))"#,
        ] {
            assert!(output.sql.contains(needle), "{needle}\n{}", output.sql);
        }
        let output = compile(request(r#"user.name=* | where NOT user="x" | stats count"#)).expect("compiles");
        assert!(
            output.sql.contains(r#"NOT ifNull((lower(toString(if("user.name" != '', "user.name", "actor.user.name"))) = 'x'), false)"#),
            "{}",
            output.sql
        );
        assert!(!output.sql.contains(r#"toString("user")"#), "{}", output.sql);
    }

    /// NAN-3034: `*kw*` searches message AND raw_data (sysmon parts carry no
    /// message), projects both, and its hint is a substring (`contains`) hint:
    /// `*svchost*` must never make an index require the whole token.
    #[test]
    fn wildcard_keywords_search_every_body_column_with_substring_hints() {
        for (query, body_predicate) in [
            (
                "*svchost* | head 20",
                "(lower(message) iLike '%svchost%' OR lower(raw_data) iLike '%svchost%')".to_string(),
            ),
            // NAN-3041: `svch*` is a TERM prefix (any word starting `svch`),
            // not a body prefix. The substring guard stays, so its `contains`
            // hint below remains a superset and never prunes a match.
            (
                "svch* | head 20",
                ["message", "raw_data"]
                    .map(|col| {
                        format!(
                            "(lower({col}) iLike '%svch%' AND match({col}, '(?i)(?:^|[^a-z0-9])svch'))"
                        )
                    })
                    .join(" OR "),
            ),
        ] {
            let output = compile(request(query)).expect("wildcard keyword should compile");
            assert!(
                output.sql.contains(&format!("({body_predicate})")),
                "{query}: both body columns, got:\n{}",
                output.sql
            );
            assert!(!output.sql.contains("iLike 'svch%'"), "{query}: {}", output.sql);
            assert!(output.projected_scan_columns.iter().any(|c| c == "raw_data"), "{query}");
            assert!(output.projected_scan_columns.iter().any(|c| c == "message"), "{query}");
            let [CandidateHint::Keyword { mode, value }] = output.candidate_hints.as_slice() else {
                panic!("{query}: expected one keyword hint, got {:?}", output.candidate_hints);
            };
            assert_eq!(*mode, "contains", "{query}: a partial token is never a token hint");
            assert_eq!(value, query.split(' ').next().unwrap());
        }
    }

    /// NAN-3037: keyword NOT over nullable Parquet columns keeps rows whose
    /// `message` (or `raw_data`) is NULL, and a negated term adds no hint.
    #[test]
    fn keyword_not_is_null_safe_on_the_lake() {
        let kw = |t: &str| {
            format!("(hasAllTokens(lower(message), '{t}') OR hasAllTokens(lower(raw_data), '{t}'))")
        };
        let output = compile(request("svchost NOT zzqq | stats count")).expect("compiles");
        assert!(
            output.sql.contains(&format!("{} AND NOT ifNull(({}), false)", kw("svchost"), kw("zzqq"))),
            "got:\n{}",
            output.sql
        );
        assert_eq!(
            output.candidate_hints,
            vec![CandidateHint::Keyword { mode: "token", value: "svchost".to_string() }]
        );

        let output = compile(request("svchost NOT (aa OR (bb NOT cc)) | stats count")).expect("compiles");
        assert_eq!(output.sql.matches("NOT ifNull(").count(), 2, "got:\n{}", output.sql);
        assert!(!output.sql.contains("NOT (("), "got:\n{}", output.sql);
    }

    /// NAN-3221: `source_type` / `sourcetype` lower to the same
    /// `metadata.log_source` predicate, so they carry the same source-family
    /// hint (file pruning by the signed family label); other fields never do.
    #[test]
    fn source_type_aliases_carry_the_log_source_family_hint() {
        let canonical = compile(request("metadata.log_source=audit")).expect("compiles");
        for alias in [
            "source_type=audit",
            "sourcetype=audit",
            r#"source_type="audit""#,
        ] {
            let output = compile(request(alias)).expect("compiles");
            assert_eq!(output.sql, canonical.sql, "{alias}");
            assert_eq!(
                output.candidate_hints,
                vec![CandidateHint::SourceFamily {
                    value: "audit".to_string()
                }],
                "{alias}"
            );
        }
        for other in [
            "metadata.product.name=audit",
            "source_type=aud*",
            "source_type!=audit",
        ] {
            let output = compile(request(other)).expect("compiles");
            assert!(
                !output
                    .candidate_hints
                    .iter()
                    .any(|hint| matches!(hint, CandidateHint::SourceFamily { .. })),
                "{other}: {:?}",
                output.candidate_hints
            );
        }
    }

    /// NAN-3224: `risk` is a query-time alias of the findings that added
    /// risk. It compiles to exactly the findings predicate plus
    /// `risk_score > 0`, prunes by the real `findings` family, and never
    /// emits a `risk` family hint (no part carries that label).
    #[test]
    fn risk_source_alias_compiles_to_scored_findings() {
        let canonical = compile(request(r#"(metadata.log_source="findings" AND risk_score>0)"#))
            .expect("compiles");
        assert!(canonical.sql.contains("'findings'"), "{}", canonical.sql);
        assert!(canonical.sql.contains("risk_score"), "{}", canonical.sql);
        for alias in [
            "metadata.log_source=risk",
            "source_type=risk",
            "sourcetype=risk",
            r#"metadata.log_source="risk""#,
            "metadata.log_source IN (risk)",
        ] {
            let output = compile(request(alias)).expect("compiles");
            assert_eq!(output.sql, canonical.sql, "{alias}");
            assert_eq!(
                output.candidate_hints,
                vec![CandidateHint::SourceFamily { value: "findings".to_string() }],
                "{alias}"
            );
            assert!(!output.sql.contains("'risk'"), "{alias}: {}", output.sql);
        }
        let rba = compile(request(
            "metadata.log_source=risk | stats sum(risk_score) as risk_score by resources.type, resources.name",
        ))
        .expect("the RBA starter search compiles");
        assert!(rba.sql.contains("'findings'"), "{}", rba.sql);
    }

    /// NAN-3224: the "Risk by entity (RBA)" starter search seeded by
    /// enterprise migration 9011150 compiles against the lake.
    #[test]
    fn risk_by_entity_starter_search_compiles() {
        // Read at runtime, not `include_str!`: the open-core mirror strips
        // the enterprise migrations , and a compile-time include there
        // breaks every test target in this crate (NAN-2169, NAN-3307). Skip
        // only when the file is genuinely absent; any other IO error fails.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../migrations/postgres-enterprise/9011150_risk_by_entity_saved_search.sql"
        );
        let migration = match std::fs::read_to_string(path) {
            Ok(migration) => migration,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: {path} is absent (open-core tree)");
                return;
            }
            Err(err) => panic!("read {path}: {err}"),
        };
        let query = migration
            .split("$rba$")
            .nth(1)
            .expect("the starter query is $rba$-quoted");
        let output = compile(request(query)).expect("the RBA starter search compiles");
        assert!(output.sql.contains("'findings'"), "{}", output.sql);
        assert!(output.sql.contains("risk_score"), "{}", output.sql);
        assert!(!output.sql.contains("'risk'"), "{}", output.sql);
    }

    #[test]
    fn extracts_process_name_from_safe_conjunctions_only() {
        let compound = compile(request(
            r#"metadata.log_source="windows_sysmon" actor.process.name="ngen.exe""#,
        ))
        .expect("compound process query should compile");
        assert!(compound.newest_first_event_rows);
        assert_eq!(
            compound.candidate_hints,
            vec![
                CandidateHint::SourceFamily { value: "windows_sysmon".to_string() },
                CandidateHint::Entity {
                    source_path: "actor.process.name".to_string(),
                    value: "ngen.exe".to_string(),
                },
            ]
        );

        let two_entities = compile(request(
            r#"device.hostname="lt-hr-023.corp.local" actor.process.name="ngen.exe""#,
        ))
        .expect("two-entity conjunction should compile");
        assert_eq!(
            two_entities.candidate_hints,
            vec![
                CandidateHint::Entity {
                    source_path: "device.hostname".to_string(),
                    value: "lt-hr-023.corp.local".to_string(),
                },
                CandidateHint::Entity {
                    source_path: "actor.process.name".to_string(),
                    value: "ngen.exe".to_string(),
                },
            ]
        );

        let unsafe_or = compile(request(
            r#"actor.process.name="ngen.exe" OR actor.process.name="powershell.exe""#,
        ))
        .expect("OR query should compile through the broad path");
        assert!(matches!(unsafe_or.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));

        let required_outer = compile(request(
            r#"device.hostname="lt-hr-023.corp.local" (actor.process.name="ngen.exe" OR actor.process.name="powershell.exe")"#,
        ))
        .expect("outer conjunct should remain safe");
        assert_eq!(
            required_outer.candidate_hints[..1],
            vec![CandidateHint::Entity {
                source_path: "device.hostname".to_string(),
                value: "lt-hr-023.corp.local".to_string(),
            }]
        );

        let negated = compile(request(r#"NOT actor.process.name="ngen.exe""#))
            .expect("negated query should compile through the broad path");
        assert!(negated.candidate_hints.is_empty());

        let explicitly_oldest_first =
            compile(request(r#"actor.process.name="ngen.exe" | sort +time"#))
                .expect("explicit ordering should compile");
        assert!(!explicitly_oldest_first.newest_first_event_rows);
    }

    #[test]
    fn row_preserving_ocsf_projection_retains_newest_first_proof() {
        // NAN-3060: a shape that compiles to an UNORDERED outer `SELECT …
        // LIMIT n` never claims a cursor-continuable newest-first order
        // (cursor pages over them repeated and skipped rows).
        for query in [
            "* | table time, src_endpoint.ip | where isnotnull(src_endpoint.ip)",
            "* | table time, metadata.uid | rename metadata.uid AS u",
            "* | sort time",
        ] {
            let output = compile(request(query)).expect("projection should compile");
            assert!(!ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
            assert!(!output.newest_first_event_rows, "{query}: {}", output.sql);
        }
        // NAN-4263: a projection only picks columns. It now ends in the
        // event cursor order itself (ordered by the source key it reads), so
        // it keeps the proof; `sort -time` restates the implicit order.
        for query in [
            "* | table time, src_endpoint.ip, process.cmd_line",
            "* | fields time, metadata.uid",
            "* | rename raw_data AS r",
            "* | sort -time",
            "* | table time, metadata.uid | sort -time",
        ] {
            let output = compile(request(query)).expect("projection should compile");
            assert!(ends_in_event_cursor_order(&output.sql) && output.newest_first_event_rows, "{query}: {}", output.sql);
        }
        for query in ["*", "* | eval x=1", "* | sort -time | head 50", "* | head 5"] {
            let output = compile(request(query)).expect("event query should compile");
            assert!(ends_in_event_cursor_order(&output.sql) && output.newest_first_event_rows, "{query}: {}", output.sql);
        }

        // NAN-4236: a row filter keeps the newest-first order (like a search
        // term) and is exact per disjoint time chunk, so it pages too.
        let filtered = compile(request("* | where isnotnull(src_endpoint.ip)"))
            .expect("filtered event query should compile");
        assert!(filtered.newest_first_event_rows && ends_in_event_cursor_order(&filtered.sql), "{}", filtered.sql);

        let headed = compile(request(
            r#"metadata.log_source="windows_sysmon" | head 3"#,
        ))
        .expect("head preserves the implicit newest-first event order");
        assert!(headed.newest_first_event_rows);
        for (query, newest_first) in [
            ("device.hostname=\"h\" | sort -time | head 100", true),
            ("device.hostname=\"h\" | sort time | head 100", false),
            ("device.hostname=\"h\" | sort -count | head 100", false),
        ] {
            let parsed = nanosiem_core::query::parse_query(query).unwrap();
            assert_eq!(is_newest_first_event_projection(&parsed), newest_first, "{query}");
        }
        assert!(
            headed
                .sql
                .contains("ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 3"),
            "{}",
            headed.sql
        );
    }

    /// Audit #3: `| sort -time | head N` compiled to a staged statement whose
    /// outer LIMIT was the page limit, so the worker ran `head N` per
    /// progressive chunk and concatenated k*N rows. The outer LIMIT now
    /// carries N, which is what the worker reads to stop the walk.
    #[test]
    fn newest_first_head_caps_the_trailing_limit_the_worker_reads() {
        for (query, cap) in [
            ("device.hostname=\"h\" | sort -time | head 7", 7),
            ("device.hostname=\"h\" | head 7", 7),
            ("device.hostname=\"h\" | sort -time | head 500", 100),
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.newest_first_event_rows, "{query}");
            assert_eq!(trailing_newest_first_limit(&output.sql), Some(cap), "{query}: {}", output.sql);
            assert_eq!(output.limit, 100, "{query}");
        }
        // A head the worker cannot read off the statement is never paged
        // (these stage an unordered `LIMIT` before the final projection).
        for (query, cap) in [
            ("device.hostname=\"h\" | head 7 | sort -time", 7),
            ("device.hostname=\"h\" | head 9 | table time | head 4", 4),
        ] {
            let output = compile(request(query)).unwrap();
            assert!(
                !output.newest_first_event_rows || trailing_newest_first_limit(&output.sql) == Some(cap),
                "{query}: {}",
                output.sql
            );
        }
        // Without a head the page limit is unchanged.
        let plain = compile(request("device.hostname=\"h\"")).unwrap();
        assert!(plain.newest_first_event_rows);
        assert_eq!(trailing_newest_first_limit(&plain.sql), Some(100));
    }

    /// NAN-4278 (searchfuzz F4/F8): an explicit order survives to the end of
    /// the statement, and `tail N` / `reverse` invert the order the rows are
    /// actually in. Before, `sort -x | head N` was re-sorted newest-first by
    /// the implicit outer order, and `tail N` took the NEWEST N rows.
    #[test]
    fn explicit_orders_end_the_statement_and_tail_inverts_the_current_order() {
        let final_statement = |sql: &str| sql.rsplit_once("\nSELECT ").map(|(_, last)| last.to_string()).unwrap();
        const OLDEST_FIRST: &str = "ORDER BY time ASC NULLS FIRST, \"metadata.uid\" ASC NULLS FIRST";
        const BY_LENGTH: &str = "ORDER BY \"http_response.length\" DESC, time DESC, \"metadata.uid\" DESC";
        // Default newest-first listing: `tail N` is the oldest N, oldest first.
        for query in ["* | tail 5", "* | tail 5 | table time, metadata.uid", "* | tail 5 | fields time, metadata.uid"] {
            let output = compile(request(query)).unwrap();
            assert!(output.sql.contains(&format!("  SELECT * FROM stage_0\n  {OLDEST_FIRST}\n  LIMIT 5\n")), "{query}: {}", output.sql);
            assert!(!final_statement(&output.sql).contains("DESC"), "{query}: {}", output.sql);
            assert!(!output.newest_first_event_rows, "{query}");
        }
        // `sort x | head/where` ends in the user's order, never the time cursor.
        for query in [
            "* | sort -http_response.length | head 20",
            "* | sort -http_response.length | where severity_id=1 | head 20",
            "* | sort -http_response.length",
        ] {
            let output = compile(request(query)).unwrap();
            assert!(final_statement(&output.sql).contains(&format!("{BY_LENGTH} LIMIT ")), "{query}: {}", output.sql);
            assert!(!output.newest_first_event_rows, "{query}");
        }
        // A projection after the sorted head keeps the head's order (no re-sort).
        for query in [
            "* | sort -http_response.length | head 20 | table http_response.length, time",
            "* | sort -http_response.length | head 20 | fields http_response.length, time",
        ] {
            let output = compile(request(query)).unwrap();
            assert!(!final_statement(&output.sql).contains("ORDER BY"), "{query}: {}", output.sql);
            assert!(output.sql.contains(&format!("  SELECT * FROM stage_0\n  {BY_LENGTH}\n)")), "{query}: {}", output.sql);
        }
        // `sort x | tail N`: the last N of the sort, last first.
        let output = compile(request("* | sort -http_response.length | tail 3")).unwrap();
        assert!(output.sql.contains("ORDER BY \"http_response.length\" ASC NULLS FIRST, time ASC NULLS FIRST, \"metadata.uid\" ASC NULLS FIRST\n  LIMIT 3"), "{}", output.sql);
        // `reverse` then `head`: the oldest rows, oldest first, to the end.
        let output = compile(request("* | reverse | head 3")).unwrap();
        assert!(final_statement(&output.sql).contains(&format!("{OLDEST_FIRST} LIMIT ")), "{}", output.sql);
        // `tail` twice is the identity order again (NULL placement included).
        let output = compile(request("* | tail 9 | tail 3")).unwrap();
        assert!(output.sql.contains("ORDER BY time DESC NULLS LAST, \"metadata.uid\" DESC NULLS LAST\n  LIMIT 3"), "{}", output.sql);
        // After an aggregation the sort keys are the group's: `tail` inverts them.
        let output = compile(request("* | stats count by device.hostname | sort -count | tail 2")).unwrap();
        assert!(output.sql.contains("ORDER BY count ASC NULLS FIRST, \"device.hostname\" DESC NULLS FIRST\n  LIMIT 2"), "{}", output.sql);
        // Default listings and #7371 / #7343 shapes are unchanged.
        for query in ["* | head 5", "* | table time, metadata.uid | head 5", "* | sort -time | head 5"] {
            let output = compile(request(query)).unwrap();
            assert!(output.newest_first_event_rows && ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
        }
    }

    /// NAN-4284 (searchfuzz F19-F21) through the lake compile entry point:
    /// a join narrows its subsearch to the main side's keys BEFORE the cap
    /// and reads unmatched rows as NULL; `IN [… | fields f]` and
    /// `time_diff(t1, t2)` compile.
    #[test]
    fn joins_cap_after_the_key_semi_join_and_read_misses_as_null() {
        let join = "metadata.log_source=apache_access | head 20 | join type=left src_endpoint.ip \
                    [search metadata.log_source=apache_access | stats count as total by src_endpoint.ip]";
        let sql = compile(request(join)).unwrap().sql;
        // The keys are the head's own (a totally ordered head re-reads the
        // same rows), and the cap follows the narrowing.
        assert!(sql.contains("AND \"src_endpoint.ip\" IN (SELECT \"src_endpoint.ip\" FROM stage_1)\n    LIMIT 1 BY \"src_endpoint.ip\"\n    LIMIT 10000\n"), "{sql}");
        assert!(!sql.contains("GROUP BY \"src_endpoint.ip\")) LIMIT"), "the subsearch body is uncapped: {sql}");
        assert!(sql.ends_with("join_use_nulls=1"), "{sql}");
        let inner = compile(request("metadata.log_source=apache_access | join src_endpoint.ip \
            [search metadata.log_source=apache_access | stats count as total by src_endpoint.ip]")).unwrap().sql;
        assert!(inner.contains("IN (SELECT \"src_endpoint.ip\" FROM stage_0)\n    LIMIT 1 BY \"src_endpoint.ip\"\n    LIMIT 10000"), "{inner}");
        let fields = compile(request("* src_endpoint.ip IN [search http_response.code=500 | fields src_endpoint.ip] | stats count")).unwrap().sql;
        let returned = compile(request("* src_endpoint.ip IN [search http_response.code=500 | return src_endpoint.ip] | stats count")).unwrap().sql;
        assert_eq!(fields, returned);
        let gap = compile(request("* | head 5 | eval gap=time_diff(time, time)")).unwrap().sql;
        assert!(gap.contains("dateDiff('second', time, time) AS gap"), "{gap}");
    }

    /// NAN-4236: a newest-first `head N` behind a row filter or ahead of a
    /// projection ends in the event cursor order with the head as its
    /// trailing limit, so the worker walks it newest-first and stops at N
    /// rows instead of ranking the whole window. A projection with no head
    /// pages the same way (NAN-4263).
    #[test]
    fn filtered_and_projected_heads_page_newest_first() {
        for query in [
            "device.hostname=\"h\" | where severity_id=1 | head 7",
            "device.hostname=\"h\" | table metadata.uid, device.hostname | head 7",
            "device.hostname=\"h\" | head 7 | table metadata.uid",
            "device.hostname=\"h\" | fields metadata.uid | head 7",
            "device.hostname=\"h\" | where severity_id=1 | table metadata.uid | head 7",
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.newest_first_event_rows, "{query}: {}", output.sql);
            assert_eq!(trailing_newest_first_limit(&output.sql), Some(7), "{query}: {}", output.sql);
            assert!(ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
        }
        let output = compile(request("device.hostname=\"h\" | table metadata.uid | head 7")).unwrap();
        assert!(output.sql.contains("\nSELECT \"metadata.uid\" FROM stage_1 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 7"), "{}", output.sql);
        // An alias that reuses an order key would reorder by the alias.
        let output = compile(request("device.hostname=\"h\" | table device.hostname as time | head 7")).unwrap();
        assert!(!output.newest_first_event_rows, "{}", output.sql);
        // NAN-4263: a projection with no head is the newest events too
        // (the search service pulls `head N` out and sends the limit).
        for query in ["device.hostname=\"h\" | table metadata.uid"] {
            let output = compile(request(query)).unwrap();
            assert!(output.newest_first_event_rows && ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
        }
    }

    /// NAN-4263 (FP T67): a bare `*` with `head N` and a projection, in
    /// either order, is the N newest events newest first, paged newest-first
    /// chunk by chunk -- exactly like `* | head N`. The lake search service
    /// pulls the head out of row-preserving pipelines (`lake_head_page_plan`)
    /// and sends `* | table …` with limit N; query[T] compiles with limit
    /// offset + limit + 1. That projection compiled to an unordered `SELECT
    /// … FROM stage_1 LIMIT 201` without the newest-first proof, so the
    /// worker read the whole 7 d window (2291 files) and returned whichever
    /// 200 rows it produced first (10:00Z and 2 days back, not 20:17Z).
    #[test]
    fn bare_star_projection_heads_page_newest_first_in_either_order() {
        let compile_with = |query: &str, limit: usize| {
            let mut request = request(query);
            request.end = "2026-08-14T00:00:00Z".to_string();
            request.limit = limit;
            compile(request).unwrap_or_else(|error| panic!("{query}: {error}"))
        };
        // As sent to query[T] by the search service (head pulled out).
        for query in [
            "* | table time, metadata.uid",
            "* | table time, device.hostname, metadata.log_source",
            "* | fields time, metadata.uid",
            "* | fields - message",
            "* | rename device.hostname AS host",
            "* | eval x=1 | table time, x",
            "* | sort -time | table time, metadata.uid",
            "* | sort -_time | table time, metadata.uid",
            "* | table time, metadata.uid | sort -_time",
        ] {
            let output = compile_with(query, 201);
            assert!(output.newest_first_event_rows, "{query}: {}", output.sql);
            assert!(ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
            assert!(output.sql.trim_end().contains(" LIMIT 201 SETTINGS "), "{query}: {}", output.sql);
            assert!(!output.sql.contains(" _time "), "{query}: {}", output.sql);
        }
        // As typed (a direct query[T] caller, the head kept), both orders.
        for query in [
            "* | head 200 | table time, metadata.uid",
            "* | table time, metadata.uid | head 200",
            "* | head 200 | fields time, metadata.uid",
            "* | fields time, metadata.uid | head 200",
            "* | head 200 | rename device.hostname AS host",
            "* | rename device.hostname AS host | head 200",
            "* | head 200 | eval x=1",
            "* | eval x=1 | head 200",
            "* | sort -_time | head 200 | table time, metadata.uid",
            "* | sort -_time | table time, metadata.uid | head 200",
            "* | table time, metadata.uid | sort -_time | head 200",
        ] {
            let output = compile_with(query, 201);
            assert!(output.newest_first_event_rows, "{query}: {}", output.sql);
            assert_eq!(trailing_newest_first_limit(&output.sql), Some(200), "{query}: {}", output.sql);
            assert!(ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
        }
        let output = compile_with("* | table time, metadata.uid", 201);
        assert!(
            output.sql.contains("\nSELECT time, \"metadata.uid\" FROM stage_0 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 201 "),
            "{}", output.sql
        );
        // Order-changing stages keep their own order and never claim the
        // newest-first event order.
        for query in [
            "* | sort device.hostname | table device.hostname | head 5",
            "* | sort time | table time, metadata.uid | head 5",
            "* | stats count by device.hostname | head 5",
            "* | dedup device.hostname | table device.hostname | head 5",
            "* | top 5 device.hostname",
            "* | sort -_time | dedup device.hostname | head 5",
        ] {
            let output = compile_with(query, 201);
            assert!(!output.newest_first_event_rows, "{query}: {}", output.sql);
        }
        // An explicit sort ahead of an order-sensitive stage is kept (only
        // its `_time` now names the time column).
        let output = compile_with("* | sort -_time | dedup device.hostname | head 5", 201);
        assert!(output.sql.contains("ORDER BY time DESC"), "{}", output.sql);
        // A rename onto an order key would order by the renamed value.
        let output = compile_with("* | rename device.hostname AS time | head 5", 201);
        assert!(!output.newest_first_event_rows, "{}", output.sql);
    }

    #[test]
    fn internal_distinct_merge_state_is_not_truncated_to_user_values_cap() {
        let output = compile(request(
            "* | stats values(dst_endpoint.ip) as __nano_distinct_values by src_endpoint.ip",
        ))
        .expect("internal distinct state should compile");

        assert!(output.sql.contains("groupUniqArray(10001)"));

        let ordinary = compile(request(
            "* | stats values(dst_endpoint.ip) by src_endpoint.ip",
        ))
        .expect("ordinary values query should compile");
        assert!(ordinary.sql.contains("groupUniqArray(100)"));
    }

    #[test]
    fn regex_hints_require_a_literal_present_in_every_match() {
        let guarded = compile(request("message=/rundll3[0-9].*/ | head 20"))
            .expect("guarded regex should compile");
        assert_eq!(
            guarded.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "regex_guard",
                value: "rundll3".to_string(),
            }]
        );

        let structured = compile(request(
            "process.cmd_line=/(?i).*powershell.*encodedcommand/ | head 20",
        ))
        .expect("structured regex should compile");
        assert_eq!(
            structured.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "regex_guard",
                value: "encodedcommand".to_string(),
            }]
        );

        let common = compile(request("message=/(foo.*admin|bar.*admin)/ | head 20"))
            .expect("common-literal alternation should compile");
        assert_eq!(
            common.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "regex_guard",
                value: "admin".to_string(),
            }]
        );

        // NAN-4186: an alternation without a common literal guards each
        // branch; every match holds one of them.
        let branches = compile(request("message=/(rundll32|powershell)/ | head 20")).unwrap();
        assert_eq!(
            branches.candidate_hints,
            vec![CandidateHint::Any { alternatives: ["rundll32", "powershell"].into_iter()
                .map(|value| CandidateHint::Keyword { mode: "regex_guard", value: value.to_string() }).collect() }]
        );

        for query in [
            "message=/(rundll32|ab)/ | head 20",
            "message=/(admin)?.*/ | head 20",
            "message=/.*/ | head 20",
            "message!=/rundll3[0-9].*/ | head 20",
        ] {
            let output = compile(request(query)).expect("regex should still compile");
            assert!(
                output.candidate_hints.is_empty(),
                "unsafe guard for {query}"
            );
        }
    }

    #[test]
    fn canonical_hash_arrays_use_entity_and_fragment_accelerators() {
        let exact = compile(request(
            r#"file.hashes.value="175f1e89ea77f991487f7932be495aa777d53d6e6a934aee5b9c7066750b93c2""#,
        ))
        .expect("exact hash query should compile");
        assert_eq!(
            exact.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "file.hashes.value".to_string(),
                value: "175f1e89ea77f991487f7932be495aa777d53d6e6a934aee5b9c7066750b93c2"
                    .to_string(),
            }]
        );

        let fragment = compile(request("file.hashes.value contains 175f1e89"))
            .expect("hash fragment query should compile");
        assert_eq!(
            fragment.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "contains",
                value: "175f1e89".to_string(),
            }]
        );
    }

    #[test]
    fn rejects_request_supplied_storage_fields() {
        let input = r#"{
            "query":"error",
            "start":"2026-08-07T00:00:00Z",
            "end":"2026-08-08T00:00:00Z",
            "source":"s3://attacker-controlled/**"
        }"#;
        assert!(serde_json::from_str::<CompileRequest>(input).is_err());
    }

    #[test]
    fn canonical_ocsf_1_9_fields_compile_only_for_lake_contract() {
        let mut lake =
            request("metadata.log_source=edr | table metadata.uid, time, metadata.log_source");
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("canonical OCSF 1.9 query should compile");
        assert!(output.sql.contains("\"metadata.log_source\""));
        assert!(output.sql.contains("\"metadata.uid\""));
        assert!(!output.sql.contains("unmapped.\"metadata\".\"log_source\""));

        let mut unsupported = request("*");
        unsupported.event_contract = "vendor-schema".to_string();
        assert!(compile(unsupported).is_err());
    }

    #[test]
    fn reports_only_referenced_canonical_ocsf_columns() {
        let mut lake = request(
            r#"metadata.log_source=proxy http_request.url.url_string="/downloads/example.zip" dst_endpoint.autonomous_system.name=example"#,
        );
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake query should compile");
        let columns: BTreeMap<_, _> = output
            .required_columns
            .iter()
            .map(|column| (column.name.as_str(), column.field_type))
            .collect();

        assert_eq!(
            columns.get("http_request.url.url_string"),
            Some(&FieldType::String)
        );
        assert_eq!(columns.get("url.url_string"), None);
        assert_eq!(columns.get("prevalence_file_hash"), None);
        assert_eq!(
            columns.get("unmapped.parent_process_name"),
            None,
            "unreferenced JSON-tail fields must not be added"
        );
        assert_eq!(
            columns.get("dst_endpoint.autonomous_system.name"),
            Some(&FieldType::String)
        );
        assert_eq!(columns.get("time"), Some(&FieldType::Timestamp));
    }

    #[test]
    fn transaction_declares_quoted_canonical_row_identity_for_worker_projection() {
        let output = compile(request(
            r#"metadata.log_source="proxy" | transaction session.uid startswith="login" endswith="logout" maxspan=8h | table session.uid, user.name"#,
        ))
        .expect("canonical transaction should compile");
        let columns: BTreeMap<_, _> = output
            .required_columns
            .iter()
            .map(|column| (column.name.as_str(), column.field_type))
            .collect();

        assert_eq!(columns.get("metadata.uid"), Some(&FieldType::String));
        assert!(
            output
                .sql
                .contains(r#""metadata.uid" AS __nano_txn_row_identity"#)
        );
        assert!(
            output
                .sql
                .contains("ORDER BY __nano_txn_time, __nano_txn_row_identity")
        );
    }

    #[test]
    fn reports_typed_struct_paths_for_explicit_unmapped_tail() {
        let mut lake = request(r#"unmapped.parent_process_name="wscript.exe""#);
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake tail query should compile");
        let columns: BTreeMap<_, _> = output
            .required_columns
            .iter()
            .map(|column| (column.name.as_str(), column.field_type))
            .collect();

        assert_eq!(
            columns.get("unmapped.parent_process_name"),
            Some(&FieldType::String)
        );
        assert_eq!(columns.get("unmapped.^parent_process_name"), None);
        assert!(!output.sql.contains(".^"));
    }

    #[test]
    fn compiles_standard_ocsf_ioc_enrichment_arrays_from_snapshot_schema() {
        let mut lake = request(
            r#"enrichments.type=threat_intelligence enrichments.provider=tenant_feed | table time, enrichments.name, enrichments.value, enrichments.data.confidence"#,
        );
        lake.table_view = false;
        for field in [
            "enrichments.type",
            "enrichments.provider",
            "enrichments.name",
            "enrichments.value",
            "enrichments.data.confidence",
        ] {
            lake.snapshot_field_types
                .insert(field.to_string(), FieldType::Array);
        }

        let output = compile(lake).expect("canonical OCSF IOC enrichment should compile");

        assert!(
            output
                .sql
                .contains("arrayExists(x -> lower(toString(x)) = 'threat_intelligence', \"enrichments.type\")")
        );
        assert!(
            output
                .sql
                .contains("arrayExists(x -> lower(toString(x)) = 'tenant_feed', \"enrichments.provider\")")
        );
        assert!(output.sql.contains("\"enrichments.data.confidence\""));
        assert!(!output.sql.contains("ioc_src_ip_threat_type"));
        assert!(!output.sql.contains("custom_src_ip"));
    }

    #[test]
    fn compiles_manifest_typed_unmapped_numeric_leaf_without_json_probe() {
        let mut lake = request(r#"unmapped.threat_score>0.5 | stats max(unmapped.threat_score)"#);
        lake.event_contract = "ocsf-1.9".to_string();
        lake.unmapped_field_types
            .insert("unmapped.threat_score".to_string(), FieldType::Float);
        let output = compile(lake).expect("typed OCSF lake tail should compile");

        assert!(output.sql.contains("\"unmapped.threat_score\" > 0.5"));
        assert!(output.sql.contains("max(\"unmapped.threat_score\")"));
        assert!(!output.sql.contains(".^"));
        assert_eq!(
            output
                .required_columns
                .iter()
                .find(|column| column.name == "unmapped.threat_score")
                .map(|column| column.field_type),
            Some(FieldType::Float)
        );
    }

    #[test]
    fn preserves_canonical_sequence_group_for_outer_stages() {
        let mut lake = request(
            r#"metadata.log_source=proxy OR metadata.log_source=windows_sysmon | sequence by user.name maxspan=5m [metadata.log_source=proxy] [metadata.log_source=windows_sysmon] | table user.name, step1_time, step2_time"#,
        );
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake sequence should compile");

        assert!(
            output.sql.contains("SELECT \"user.name\", step1_time"),
            "outer sequence stages must address the grouped value by alias: {}",
            output.sql
        );
    }

    #[test]
    fn canonical_tree_preset_compiles_without_udm_aliases() {
        let mut lake = request("metadata.log_source=sysmon | tree process");
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("canonical tree preset should compile");
        assert!(!output.sql.contains("parent_process_guid"));
        assert!(!output.sql.contains("process_guid"));
        // NAN-2361: the tree fields are real lake columns already inside
        // `SELECT *` — naming them again next to `*` is a duplicate column
        // chDB rejects with ILLEGAL_COLUMN ("Cannot add column …").
        assert!(
            !output.sql.contains("*, \"actor.process.uid\""),
            "tree must not re-add columns already carried by SELECT *: {}",
            output.sql
        );
        // They still have to be REQUESTED from the source so the tree builder
        // can read them off result rows.
        assert!(
            output
                .required_columns
                .iter()
                .any(|column| column.name == "actor.process.uid"),
            "tree parent column must stay a required column"
        );
        assert!(
            output
                .required_columns
                .iter()
                .any(|column| column.name == "process.uid"),
            "tree child column must stay a required column"
        );
    }

    /// NAN-3257 repro + fix. The worker used to receive `… | tree process`
    /// and ran `SELECT *` of full-width events: every column of every matching
    /// event, ~360k wide rows for an hour of endpoint data, mostly with no
    /// parent/child edge. Search now sends the narrow, edge-only candidate.
    #[test]
    fn lean_tree_candidate_compiles_to_a_narrow_edge_scan() {
        let lake_profile = OcsfProfile::lake_1_9();
        for (query, child, parent_paths) in [
            // Non-Sysmon endpoint shapes: EDR / osquery, keyed on fields only.
            (
                r#"device.hostname="ws1" | tree process"#,
                "process.uid",
                &["actor.process.uid", "process.parent_process.uid"][..],
            ),
            // Non-proxy HTTP shape: web server / WAF / CDN.
            (
                "http_request.http_method=GET | tree web",
                "http_request.url.url_string",
                &["http_request.referrer"][..],
            ),
        ] {
            let mut old = request(query);
            old.event_contract = "ocsf-1.9".to_string();
            old.limit = 10_000;
            old.table_view = false;
            let old_output = compile(old).expect("pass-through tree compiles");
            assert!(old_output.sql.contains("SELECT * FROM __nano_lake_source__"), "repro: {}", old_output.sql);

            let mut parsed = parse_query(query).unwrap();
            apply_profile_product_semantics(&mut parsed, &lake_profile);
            let candidate = nanosiem_core::search::query_processing::lake_tree_candidate_query(
                &parsed,
                &lake_profile,
            )
            .expect("lean tree projects");
            use nanosiem_core::query::PrettyPrint;
            let mut lake = request(&candidate.pretty_print());
            lake.event_contract = "ocsf-1.9".to_string();
            lake.limit = 10_000;
            lake.table_view = false;
            let output = compile(lake).expect("narrow tree candidate compiles");
            assert!(!output.sql.contains("SELECT *, "), "{}", output.sql);
            assert!(
                !output.sql.contains("SELECT * FROM __nano_lake_source__"),
                "stage_0 must read only the tree columns: {}",
                output.sql
            );
            assert!(output.sql.contains(&format!("\"{child}\") != ''")), "{}", output.sql);
            for parent in parent_paths {
                assert!(output.sql.contains(&format!("\"{parent}\"")), "{parent}: {}", output.sql);
            }
            assert!(output.sql.contains("LIMIT 10000"), "{}", output.sql);
            assert!(
                output.required_columns.len() < 20,
                "projection must stay narrow: {:?}",
                output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            // NAN-3261: an access log with only `http_request.url.path` set
            // (no url_string, no hostname) is still an edge for `tree web`.
            if child == "http_request.url.url_string" {
                assert!(output.sql.contains("\"http_request.url.path\") != ''"), "{}", output.sql);
                assert!(
                    output.required_columns.iter().any(|c| c.name == "http_request.url.path"),
                    "{:?}",
                    output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>()
                );
                assert!(!output.sql.contains("http_request.url.hostname+"), "{}", output.sql);
            }
        }
    }

    /// NAN-3451 follow-up: the narrow tree candidate now names the
    /// prevalence scalars (and, with `prevalence=`, that field plus the
    /// stamp arrays). On an open-core lake they compile to the
    /// `enrichments[]` derivation over real columns only; on lean they read
    /// the physical stamp columns. Neither duplicates a column.
    #[test]
    fn nan3451_tree_candidate_prevalence_compiles_on_open_core_and_lean() {
        let query = "nanosmoke | tree parent=actor.user.name child=device.hostname \
                     label=device.hostname prevalence=file.hashes.value";
        let compile_candidate = |snapshot: BTreeMap<String, FieldType>| {
            let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(snapshot.clone()).unwrap();
            let mut parsed = parse_query(query).unwrap();
            apply_profile_product_semantics(&mut parsed, &profile);
            let candidate =
                nanosiem_core::search::query_processing::lake_tree_candidate_query(&parsed, &profile)
                    .expect("lake tree projects");
            use nanosiem_core::query::PrettyPrint;
            let mut lake = request(&candidate.pretty_print());
            lake.event_contract = "ocsf-1.9".to_string();
            lake.limit = 10_000;
            lake.table_view = false;
            lake.snapshot_field_types = snapshot;
            let text = candidate.pretty_print();
            (text, compile(lake).expect("tree candidate compiles"))
        };
        let mut open_core = BTreeMap::new();
        for name in [
            "enrichments.name",
            "enrichments.provider",
            "enrichments.value",
            "enrichments.data.host_count",
            "enrichments.data.host_count_saturated",
            "file.hashes.value",
            "process.file.hashes.value",
        ] {
            open_core.insert(name.to_string(), FieldType::Array);
        }
        let (text, output) = compile_candidate(open_core.clone());
        assert!(text.contains("prevalence_min"), "{text}");
        assert!(output.sql.contains("arrayFirstIndex"), "{}", output.sql);
        for phantom in super::PREVALENCE_SCALARS {
            assert!(!output.required_columns.iter().any(|c| c.name == phantom), "{phantom}");
            assert!(!output.projected_scan_columns.iter().any(|c| c == phantom), "{phantom}");
        }
        for input in ["enrichments.value", "file.hashes.value", "device.hostname", "actor.user.name"] {
            assert!(output.required_columns.iter().any(|c| c.name == input), "missing {input}");
        }
        let mut names = output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate required column");
        assert!(total < 20, "projection must stay narrow: {names:?}");

        let mut lean = open_core;
        for name in super::PREVALENCE_SCALARS {
            lean.insert(name.to_string(), FieldType::Integer);
        }
        let (_, output) = compile_candidate(lean);
        assert!(!output.sql.contains("arrayFirstIndex"), "{}", output.sql);
        for name in super::PREVALENCE_SCALARS {
            assert!(output.required_columns.iter().any(|c| c.name == name), "lean {name}");
        }
    }

    /// NAN-3257 part 2: every requested column comes back under the name the
    /// analyst typed, including UDM concepts the lake resolves to another
    /// expression.
    #[test]
    fn table_columns_keep_the_typed_names() {
        let mut lake = request(
            r#"device.hostname="ws1" | table process_guid, parent_process_guid, process_name, process.uid"#,
        );
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("UDM-named table compiles on the lake");
        for alias in ["process_guid", "parent_process_guid", "process_name"] {
            assert!(
                output.sql.contains(&format!(" AS {alias},"))
                    || output.sql.contains(&format!(" AS \"{alias}\"")),
                "{alias} must be aliased back: {}",
                output.sql
            );
        }
        assert!(!output.sql.contains("AS \"process.uid\""), "{}", output.sql);
        assert!(!output.sql.contains(") AS if("), "{}", output.sql);
    }

    #[test]
    fn canonical_contract_rejects_unknown_fields_and_post_processing() {
        for query in [
            "parent_process_name=wscript.exe",
            "error | resolve_identity field=src_ip",
        ] {
            let mut lake = request(query);
            lake.event_contract = "ocsf-1.9".to_string();
            assert!(compile(lake).is_err(), "strict OCSF accepted {query}");
        }
    }

    #[test]
    fn canonical_contract_rejects_nano_side_post_processing() {
        for query in [
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence"#,
            r#"metadata.log_source="windows_sysmon" | prevalence hash_prevalence < 5"#,
            r#"metadata.log_source="windows_sysmon" | resolve_identity field=src_endpoint.ip"#,
            r#"metadata.log_source="windows_sysmon" | inputlookup url="https://example.test/{src_endpoint.ip}" key=src_endpoint.ip"#,
            r#"metadata.log_source="windows_sysmon" | ai "classify these events""#,
            r#"* | append [* | lookup iocs src_endpoint.ip OUTPUT confidence]"#,
            r#"* | join src_endpoint.ip [* | prevalence enrich=true]"#,
            r#"* | where src_endpoint.ip IN [* | resolve_identity field=src_endpoint.ip | return src_endpoint.ip]"#,
        ] {
            let mut lake = request(query);
            lake.event_contract = "ocsf-1.9".to_string();
            let error = compile(lake).expect_err("Nano-side command reached lake compiler");
            assert!(error.to_string().contains("Nano-side"), "{query}: {error}");
        }
    }

    #[test]
    fn legacy_contract_also_rejects_nano_side_post_processing() {
        let mut lake = request(
            r#"* | append [* | lookup iocs src_endpoint.ip OUTPUT confidence]"#,
        );
        lake.event_contract = "legacy-flat-ocsf-1.8".to_string();
        let error = compile(lake).expect_err("legacy contract must not bypass SQL-only guard");
        assert!(error.to_string().contains("Nano-side"));
    }

    #[test]
    fn compiles_derived_risk_dataset_against_pinned_placeholder() {
        let mut lake = request(
            "* | where score_24h > 500 or score_7d > 1000 | table entity, entity_type, score_24h, score_7d, distinct_rules_7d, last_rule_name",
        );
        lake.dataset = "risk".to_string();
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("risk nPL should compile");
        assert_eq!(output.profile, "risk");
        assert_eq!(output.dataset, "risk");
        assert_eq!(output.source_placeholder, RISK_SOURCE_PLACEHOLDER);
        assert!(output.sql.contains(RISK_SOURCE_PLACEHOLDER));
        assert!(output.sql.contains("score_24h > 500"));
        assert!(!output.sql.contains("risk_findings"));
    }

    /// NAN-3059: the derived risk grain (one row per entity) has no event
    /// UID and no pipeline outputs. `* | head 5` must not tie-break on
    /// `metadata.uid`, and `stats … by entity_type` must not project its own
    /// `count` output from the source; both failed with Code 47/215 on lean.
    #[test]
    fn risk_dataset_event_pages_and_stats_read_only_real_risk_columns() {
        let risk = |query: &str| {
            let mut input = request(query);
            input.dataset = "risk".to_string();
            input.event_contract = "ocsf-1.9".to_string();
            compile(input).unwrap_or_else(|error| panic!("{query}: {error:#}"))
        };
        let head = risk("* | head 5");
        assert!(!head.sql.contains("metadata.uid"), "{}", head.sql);
        assert!(!head.required_columns.iter().any(|c| c.name == "metadata.uid"));

        let stats = risk("* | stats count() by entity_type");
        let stage_0 = stats.sql.split("stage_1 AS").next().unwrap();
        assert!(!stage_0.contains(" count,") && !stage_0.contains("SELECT count"), "{}", stats.sql);
        assert!(!stats.required_columns.iter().any(|c| c.name == "count"));

        let top = risk("* | where score_24h > 0 | stats max(score_24h) as top by entity | sort -top | head 10");
        let stage_0 = top.sql.split("stage_1 AS").next().unwrap();
        assert!(!stage_0.contains("top,") && !stage_0.contains(", top"), "{}", top.sql);
    }

    #[test]
    fn declares_profile_keyword_body() {
        let mut lake = request("powershell");
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake keyword should compile");

        assert!(
            output.required_columns.iter().any(|column| {
                column.name == "message" && column.field_type == FieldType::String
            })
        );
        assert!(
            output
                .projected_scan_columns
                .iter()
                .any(|column| column == "message")
        );
        assert!(
            output
                .required_columns
                .iter()
                .any(|column| column.name == "raw_data")
        );
        assert!(
            output
                .projected_scan_columns
                .iter()
                .any(|column| column == "raw_data")
        );
    }

    #[test]
    fn narrow_aggregation_does_not_project_keyword_bodies() {
        let output = compile(request(
            r#"metadata.log_source="windows_sysmon" | stats count() by src_endpoint.ip"#,
        ))
        .expect("narrow aggregation should compile");
        let columns = output
            .projected_scan_columns
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();

        assert!(columns.contains("metadata.log_source"));
        assert!(columns.contains("src_endpoint.ip"));
        assert!(columns.contains("time"));
        assert!(!columns.contains("message"));
        assert!(!columns.contains("raw_data"));
    }

    #[test]
    fn source_family_where_hint_requires_row_and_field_preservation() {
        let direct = compile(request(r#"* | eval command=process.cmd_line | where metadata.log_source=windows_sysmon | stats count by device.hostname"#)).unwrap();
        assert!(direct.candidate_hints.iter().any(|hint| matches!(hint,
            CandidateHint::SourceFamily { value } if value == "windows_sysmon")));

        let union = compile(request(r#"* | where (metadata.log_source=aws_cloudtrail OR metadata.log_source=windows_event) | stats count by user.name"#)).unwrap();
        assert!(union.candidate_hints.iter().any(|hint| matches!(hint,
            CandidateHint::Any { alternatives } if alternatives.len() == 2
                && alternatives.iter().all(|child| matches!(child, CandidateHint::SourceFamily { .. })))));

        let limited = compile(request(r#"* | head 10 | where metadata.log_source=windows_sysmon | stats count by device.hostname"#)).unwrap();
        assert!(limited.candidate_hints.is_empty());

        let renamed_source = compile(request(r#"* | eval metadata.log_source="x" | where metadata.log_source=windows_sysmon | stats count()"#)).unwrap();
        assert!(renamed_source.candidate_hints.is_empty(), "{:?}", renamed_source.candidate_hints);
    }

    /// NAN-4155: `* | where <entity>=v` must plan like `<entity>=v`: the same
    /// sidecar pruning hints and the same narrow scan columns. It used to
    /// carry no entity hint and declare `message`/`raw_data` (from the bare
    /// `*`), so a 7 d `* | where device.hostname=…` read raw_data from every
    /// part (k6 parity 10-19: 504 after 345 s vs 27 s for the filter form).
    #[test]
    fn where_after_bare_star_plans_like_the_filter_form() {
        for predicate in [
            r#"device.hostname="ws-hr-132.corp.local""#,
            r#"process.file.hashes.value="0faafb1b35275f3912da163319c87e224985b26b36e662f813897f22445e187e""#,
            r#"src_endpoint.ip="10.1.7.226""#,
            r#"user.name="svc_dc""#,
            r#"class_uid=4001"#,
        ] {
            let filter = compile(CompileRequest { query: format!("{predicate} | stats count() as n"), ..request("") }).unwrap();
            let piped = compile(CompileRequest { query: format!("* | where {predicate} | stats count() as n"), ..request("") }).unwrap();
            assert!(!filter.candidate_hints.is_empty(), "{predicate}");
            assert_eq!(piped.candidate_hints, filter.candidate_hints, "{predicate}");
            assert_eq!(piped.projected_scan_columns, filter.projected_scan_columns, "{predicate}");
            assert!(!piped.projected_scan_columns.iter().any(|c| c == "raw_data" || c == "message"), "{predicate}");
            assert!(!piped.required_columns.iter().any(|c| c.name == "raw_data"), "{predicate}");
        }

        // `* | stats count()` reads no body column either.
        let count = compile(request("* | stats count() as n")).unwrap();
        assert!(!count.projected_scan_columns.iter().any(|c| c == "raw_data" || c == "message"), "{:?}", count.projected_scan_columns);
        assert!(!count.required_columns.iter().any(|c| c.name == "raw_data"));
    }

    #[test]
    fn where_entity_hint_requires_row_and_field_preservation() {
        let host = |query: &str| compile(request(query)).unwrap().candidate_hints.iter().any(|hint| matches!(hint,
            CandidateHint::Entity { source_path, value } if source_path == "device.hostname" && value == "h1.corp.local"));
        assert!(host(r#"* | where device.hostname="h1.corp.local" | head 10"#));
        assert!(host(r#"* | eval x=1 | where device.hostname="h1.corp.local" | stats count()"#));
        // An eval that rewrites the hinted field (directly or via its alias)
        // makes the stored value irrelevant; rows must not be pruned by it.
        assert!(!host(r#"* | eval device.hostname="h1.corp.local" | where device.hostname="h1.corp.local" | stats count()"#));
        assert!(!host(r#"* | eval host="h1.corp.local" | where device.hostname="h1.corp.local" | stats count()"#));
        // A row-changing command before the where stops the pushdown.
        assert!(!host(r#"* | head 10 | where device.hostname="h1.corp.local""#));
        assert!(!host(r#"* | stats count() by device.hostname | where device.hostname="h1.corp.local""#));
        // NAN-4186: a field predicate's substring guard may come from a
        // where; a bare where keyword (whose semantics differ) never does.
        let keyword = compile(request(r#"* | where message="svchost" | stats count()"#)).unwrap();
        assert_eq!(keyword.candidate_hints, vec![CandidateHint::Keyword { mode: "contains", value: "svchost".to_string() }]);
        let bare = compile(request(r#"* | where svchost | stats count()"#)).unwrap();
        assert!(!bare.candidate_hints.iter().any(|hint| matches!(hint, CandidateHint::Keyword { .. })));
    }

    #[test]
    fn message_commands_keep_their_physical_input() {
        for query in [
            r#"metadata.log_source="windows_sysmon" | rex "(?P<level>INFO|ERROR)" | stats count() by level"#,
            r#"metadata.log_source="windows_sysmon" | rex field=message "(?P<level>INFO|ERROR)" | stats count() by level"#,
            r#"metadata.log_source="windows_sysmon" | transaction user.name maxspan=30m | stats count()"#,
            r#"metadata.log_source="windows_sysmon" | transaction session.uid startswith="login" endswith="logout" | stats count()"#,
        ] {
            let output = compile(request(query)).expect("message command should compile");
            assert!(
                output
                    .required_columns
                    .iter()
                    .any(|column| column.name == "message")
            );
            assert!(
                output
                    .projected_scan_columns
                    .iter()
                    .any(|column| column == "message")
            );
            if query.contains("startswith") {
                assert!(
                    output
                        .required_columns
                        .iter()
                        .any(|column| column.name == "raw_data")
                );
                assert!(
                    output
                        .projected_scan_columns
                        .iter()
                        .any(|column| column == "raw_data")
                );
            }
        }
    }

    /// NAN-3328: every documented output column of a command is a real
    /// column of the later stages -- never rejected as an unknown OCSF field,
    /// never read from a bogus `ext.<name>`.
    #[test]
    fn nan3328_command_created_columns_flow_to_later_stages() {
        for (query, column) in [
            ("* | bin span=1h hop=30m | stats count by time_bucket_end", "time_bucket_end"),
            ("* | bin time span=1h hop=30m | stats count by time_end", "time_end"),
            ("* | anomaly field=traffic.bytes_out | table expected, avg_val, stddev_val", "expected"),
            ("* | anomaly field=traffic.bytes_out method=mad | table median_val, mad_val", "mad_val"),
            (
                "* | funnel by user.name window=1h [class_uid=3002] [class_uid=1007] | table funnel_level, step_name",
                "funnel_level",
            ),
            ("* | risk score=10 entity=user.name | table risk_entity, raw_risk_score", "risk_entity"),
        ] {
            let output = compile(request(query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(!output.sql.contains("ext."), "{query}: {}", output.sql);
            assert!(!output.sql.contains("unmapped."), "{query}: {}", output.sql);
            assert!(
                !output.required_columns.iter().any(|c| c.name == column),
                "{query}: stage output {column} declared as a source column"
            );
        }
    }

    /// NAN-3314: a `table` alias is usable downstream.
    #[test]
    fn nan3314_table_alias_is_a_later_stage_column() {
        for query in [
            "metadata.log_source=windows_event | table user.name as u, time | sort u",
            "metadata.log_source=windows_event | table user.name as u, time | where isnotnull(u)",
            "* | table user.name as u, time | stats count by u",
        ] {
            let output = compile(request(query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(output.sql.contains("\"user.name\" AS u"), "{query}: {}", output.sql);
            assert!(!output.sql.contains("ext."), "{query}: {}", output.sql);
        }
    }

    /// NAN-3336: `rename a as b` onto an existing OCSF column replaces it.
    #[test]
    fn nan3336_rename_onto_existing_column_replaces_it() {
        let output = compile(request(
            "class_uid=1007 actor.user.name=* | rename actor.user.name as user.name | table user.name",
        ))
        .unwrap();
        assert!(
            output
                .sql
                .contains("SELECT * EXCEPT (\"user.name\"), \"actor.user.name\" AS \"user.name\""),
            "{}",
            output.sql
        );
        // A swap keeps both inputs visible to the projection.
        let swap = compile(request("* | rename src_endpoint.ip as dst_endpoint.ip, dst_endpoint.ip as src_endpoint.ip")).unwrap();
        assert!(!swap.sql.contains("EXCEPT"), "{}", swap.sql);
    }

    /// NAN-3316: wildcards expand against OCSF 1.9 paths.
    #[test]
    fn nan3316_wildcards_expand_against_ocsf_paths() {
        let output = compile(request("* | fields src_endpoint.*")).unwrap();
        assert!(output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
        assert!(output.sql.contains("\"src_endpoint.port\""), "{}", output.sql);

        let output = compile(request("* | table src_*")).unwrap();
        assert!(output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
        assert!(!output.sql.contains("AS src_ip"), "{}", output.sql);
        assert!(!output.sql.contains("unmapped.src_"), "{}", output.sql);

        let output = compile(request("* | fields *.ip")).unwrap();
        assert!(output.sql.contains("\"dst_endpoint.ip\""), "{}", output.sql);
        assert!(!output.sql.contains("prevalence_dest_ip"), "{}", output.sql);
        assert!(!output.sql.contains("dvc_ip"), "{}", output.sql);

        let output = compile(request("* | fields - src_endpoint.*")).unwrap();
        assert!(output.sql.contains("EXCEPT (") && output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
    }

    /// The stage-1 `| where` predicate of a compiled lake query.
    fn where_stage(sql: &str) -> String {
        sql.lines()
            .filter(|line| line.trim_start().starts_with("WHERE ") && !line.contains("time "))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// NAN-4276 (F1): `| where <String column> <op> <number>` was emitted with a
    /// bare numeric literal (`"metadata.event_code" = 7`), which chDB refuses
    /// ("No supertype for types String, UInt8"). Through the production
    /// compile: equality/IN compare the literal as text, exactly like the
    /// search term, ranges compare the column's numeric value, and numeric
    /// columns and computed outputs keep their numeric compare.
    #[test]
    fn where_numeric_literal_is_typed_against_string_columns() {
        let base = "metadata.log_source=windows_sysmon";
        let term = compile(request(&format!("{base} metadata.event_code=7 | stats count"))).unwrap();
        assert!(term.sql.contains(r#""metadata.event_code" = '7'"#), "{}", term.sql);
        for (pipe, expected) in [
            ("where metadata.event_code=7", r#"lower("metadata.event_code") = '7'"#),
            ("where metadata.event_code==7", r#"lower("metadata.event_code") = '7'"#),
            ("where metadata.event_code!=7", r#"lower(toString("metadata.event_code")) != '7'"#),
            ("where metadata.event_code>4000", r#"toFloat64OrNull(toString("metadata.event_code")) > 4000"#),
            ("where metadata.event_code<=4000", r#"toFloat64OrNull(toString("metadata.event_code")) <= 4000"#),
            ("where metadata.event_code IN (1, 7)", r#"IN ('1', '7')"#),
            ("where metadata.event_code NOT IN (1, \"7\")", r#"lower("metadata.event_code") NOT IN ('1', '7')"#),
            ("where metadata.event_code=7 OR metadata.event_code=1", r#"lower("metadata.event_code") = '1'"#),
            ("where user=7", "= '7'"),
        ] {
            let query = format!("{base} | {pipe} | stats count");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            let stage = where_stage(&output.sql);
            assert!(stage.contains(expected), "{query}: {stage}\n{}", output.sql);
            assert!(!stage.contains("= 7") && !stage.contains("(1, 7)"), "{query}: {stage}");
        }
        // Numeric columns and computed numbers stay numeric.
        for (pipe, expected) in [
            ("where class_uid=1007", "class_uid = 1007"),
            ("where severity_id>=3", "severity_id >= 3"),
            ("where src_endpoint.port=443", r#""src_endpoint.port" = 443"#),
            ("where process.pid > 4 AND metadata.event_code=7", r#""process.pid" > 4"#),
            ("stats count by metadata.event_code | where count > 10", "count > 10"),
            ("stats count as total by metadata.event_code | where total=10", "total = 10"),
            ("eval n=len(message) | where n=7", "n = 7"),
        ] {
            let query = format!("{base} | {pipe}");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            let stage = where_stage(&output.sql);
            assert!(stage.contains(expected), "{query}: {stage}\n{}", output.sql);
            assert!(!stage.contains("toFloat64OrNull") || pipe.contains("event_code"), "{query}: {stage}");
        }
    }

    /// NAN-4276 follow-up: a stats by-field that passes a String column
    /// through, and an eval output of a String expression, are String in
    /// the stages after them, so `| where <name>=7` types the literal as
    /// text (it was `= 7`, a chDB String/UInt8 400). A numeric eval output
    /// and an aggregation output stay numeric.
    #[test]
    fn where_after_by_field_and_string_eval_types_numeric_literals_as_text() {
        let base = "metadata.log_source=windows_sysmon";
        for (pipe, expected) in [
            ("stats count by metadata.event_code | where metadata.event_code=7", r#"lower(toString("metadata.event_code")) = '7'"#),
            ("stats count by metadata.event_code | where metadata.event_code IN (1, 7)", "IN ('1', '7')"),
            ("timechart span=1h count by metadata.event_code | where metadata.event_code=7", r#"lower("metadata.event_code") = '7'"#),
            ("eval x=metadata.event_code | where x=7", "lower(toString(x)) = '7'"),
            ("eval x=lower(metadata.event_code) | where x>4000", "toFloat64OrNull(toString(x)) > 4000"),
            ("eval x=metadata.event_code | stats count by x | where x=7", "lower(toString(x)) = '7'"),
        ] {
            let query = format!("{base} | {pipe}");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            let stage = where_stage(&output.sql);
            assert!(stage.contains(expected), "{query}: {stage}\n{}", output.sql);
        }
        for (pipe, expected) in [
            ("eval x=len(message) | where x=7", "x = 7"),
            ("eval x=metadata.event_code | eval x=len(message) | where x=7", "x = 7"),
            ("stats count by metadata.event_code | where count > 10", "count > 10"),
            ("stats count by severity_id | where severity_id=3", "severity_id = 3"),
        ] {
            let query = format!("{base} | {pipe}");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            let stage = where_stage(&output.sql);
            assert!(stage.contains(expected), "{query}: {stage}\n{}", output.sql);
        }
    }

    /// NAN-4280: the source time bound is half-open `[start, end)` as one
    /// plain conjunction in the single WHERE (partition/min-max pruning and
    /// move-to-PREWHERE unchanged), so adjacent windows never count an event
    /// on their shared boundary twice.
    #[test]
    fn source_time_bound_is_half_open() {
        for query in ["* | stats count", "powershell | timechart span=5m count() as count", "metadata.log_source=windows_sysmon | head 10"] {
            let output = compile(request(query)).unwrap();
            assert!(
                output.sql.contains("WHERE time >= '2026-08-07 00:00:00.000000' AND time < '2026-08-08 00:00:00.000000'"),
                "{query}: {}",
                output.sql
            );
            assert!(!output.sql.contains("BETWEEN"), "{query}: {}", output.sql);
            assert!(!output.sql.contains("PREWHERE"), "{query}: {}", output.sql);
        }
        // The user predicate stays parenthesized behind the bound, so an OR
        // in it can never escape the window.
        let output = compile(request("user=a OR user=b | stats count")).unwrap();
        assert!(output.sql.contains("time < '2026-08-08 00:00:00.000000'\n  AND ("), "{}", output.sql);
    }

    /// NAN-4276: a search-term range on a String column compares numerically.
    /// It used to quote the number and compare text (`'500' > '4000'`).
    #[test]
    fn search_term_numeric_range_on_string_column_is_numeric() {
        let output = compile(request("metadata.event_code>4000 | stats count")).unwrap();
        assert!(
            output.sql.contains(r#"toFloat64OrNull(toString("metadata.event_code")) > 4000"#),
            "{}",
            output.sql
        );
        let numeric = compile(request("severity_id>3 | stats count")).unwrap();
        assert!(numeric.sql.contains("severity_id > 3"), "{}", numeric.sql);
    }

    /// NAN-4285: a CIDR inside `IN (...)` / `NOT IN (...)` on an IP field is
    /// network membership (as `ip=10.0.0.0/8` is), in search terms and in
    /// `| where`; exact addresses keep the prunable IN-list. The list used to
    /// compile to `ip IN ('10.0.0.0/8')`, a string compare that matched nothing.
    #[test]
    fn cidr_in_lists_compile_to_network_membership() {
        let range = |cidr: &str| format!("isIPAddressInRange(toString(\"dst_endpoint.ip\"), '{cidr}')");
        for prefix in ["", "* | where "] {
            let all = compile(request(&format!(
                "{prefix}dst_endpoint.ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) | stats count"
            ))).unwrap().sql;
            for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
                assert!(all.contains(&range(cidr)), "{prefix}: {all}");
            }
            assert!(!all.contains("IN ('10.0.0.0/8'") && !all.contains("'10.0.0.0/8', '172"), "{prefix}: {all}");
            assert!(all.contains("isIPv4String(toString(\"dst_endpoint.ip\"))"), "guarded against non-IP values: {all}");

            let mixed = compile(request(&format!("{prefix}dst_endpoint.ip IN (10.0.0.0/8, 8.8.8.8) | stats count"))).unwrap().sql;
            assert!(mixed.contains(&range("10.0.0.0/8")), "{prefix}: {mixed}");
            assert!(mixed.contains("IN ('8.8.8.8')") && !mixed.contains("IN ('10.0.0.0/8'") && !mixed.contains("'8.8.8.8', '10."), "{prefix}: {mixed}");
            assert!(mixed.contains(" OR ifNull((isIPv4String"), "exact list OR the ranges: {mixed}");

            let negated = compile(request(&format!("{prefix}dst_endpoint.ip NOT IN (10.0.0.0/8, 8.8.8.8) | stats count"))).unwrap().sql;
            assert!(negated.contains(&range("10.0.0.0/8")) && negated.contains("NOT ifNull(("), "{prefix}: {negated}");
            assert!(negated.contains("length(toString("), "NOT IN needs the field present: {negated}");
            assert!(!negated.contains("NOT IN ('10.0.0.0/8'"), "{prefix}: {negated}");

            let v6 = compile(request(&format!(r#"{prefix}dst_endpoint.ip IN ("fe80::/10", "2001:db8::1") | stats count"#))).unwrap().sql;
            assert!(v6.contains(&range("fe80::/10")) && v6.contains("IN ('2001:db8::1')"), "{prefix}: {v6}");

            for bad in ["10.0.0.0/33", "fe80::/129", "10.0.0/8x", "host/8"] {
                assert!(compile(request(&format!("{prefix}dst_endpoint.ip IN (\"{bad}\", 8.8.8.8) | stats count"))).is_err(), "{prefix}{bad}");
            }
        }
        // The OCSF alias of a UDM IP field resolves the same way.
        let alias = compile(request("src_ip NOT IN (10.0.0.0/8, 192.168.0.0/16) | stats count")).unwrap().sql;
        assert!(alias.contains("isIPAddressInRange(toString(\"src_endpoint.ip\"), '10.0.0.0/8')"), "{alias}");
        // `| where ip=cidr` matches the search-term form.
        let eq = compile(request(r#"* | where dst_endpoint.ip="10.0.0.0/8" | stats count"#)).unwrap().sql;
        assert!(eq.contains(&range("10.0.0.0/8")), "{eq}");
        let ne = compile(request(r#"* | where dst_endpoint.ip!="10.0.0.0/8" | stats count"#)).unwrap().sql;
        assert!(ne.contains(&range("10.0.0.0/8")) && ne.contains("NOT ifNull(("), "{ne}");
        // After an aggregation the by-field is still an IP column.
        let by = compile(request("* | stats count by dst_endpoint.ip | where dst_endpoint.ip IN (10.0.0.0/8)")).unwrap().sql;
        assert!(by.contains("isIPAddressInRange(toString("), "{by}");
        // A slash in a non-IP field stays a plain string value.
        let path = compile(request(r#"http_request.url.path IN ("/a/b", "/c") | stats count"#)).unwrap().sql;
        assert!(path.contains("'/a/b', '/c'") && !path.contains("isIPAddressInRange"), "{path}");
        // CIDR lists name no exact entity, so they must not prune candidates.
        let hinted = compile(request("dst_endpoint.ip IN (10.0.0.0/8, 8.8.8.8) | stats count")).unwrap();
        assert!(hinted.candidate_hints.is_empty(), "{:?}", hinted.candidate_hints);
    }

    /// NAN-4279 searchfuzz F9–F13, through the lake's production compile
    /// entry point. Each query is also compiled from its pretty-printed form,
    /// which is what the front door sends the worker.
    fn compile_both_ways(input: CompileRequest) -> CompileResponse {
        use nanosiem_core::query::PrettyPrint;
        let printed = parse_query(&input.query).unwrap().pretty_print();
        let direct = compile(CompileRequest { query: input.query.clone(), ..clone_request(&input) })
            .unwrap_or_else(|error| panic!("{}: {error:#}", input.query));
        let reprinted = compile(CompileRequest { query: printed.clone(), ..input })
            .unwrap_or_else(|error| panic!("{printed}: {error:#}"));
        assert_eq!(direct.sql, reprinted.sql, "printed form {printed} compiled differently");
        direct
    }

    fn clone_request(input: &CompileRequest) -> CompileRequest {
        CompileRequest {
            query: input.query.clone(),
            unmapped_field_types: input.unmapped_field_types.clone(),
            snapshot_field_types: input.snapshot_field_types.clone(),
            lowercased_fields: input.lowercased_fields.clone(),
            dataset: input.dataset.clone(),
            start: input.start.clone(),
            end: input.end.clone(),
            event_contract: input.event_contract.clone(),
            ..request("")
        }
    }

    #[test]
    fn nan4279_earliest_latest_pick_by_event_time_not_value() {
        for query in [
            "metadata.log_source=apache_access | stats earliest(http_response.length) as e, latest(http_response.length) as l",
            "metadata.log_source=apache_access | stats earliest(http_response.length) as e, latest(http_response.length) as l by http_request.http_method",
            "metadata.log_source=apache_access | timechart span=1h earliest(http_response.length) as e",
        ] {
            let sql = compile_both_ways(request(query)).sql;
            assert!(
                sql.contains("argMin(\"http_response.length\", (time, toString(\"http_response.length\")))"),
                "{query}: {sql}"
            );
            assert!(!sql.contains("min(\"http_response.length\")"), "{query}: {sql}");
            if query.contains("latest(") {
                assert!(
                    sql.contains("argMax(\"http_response.length\", (time, toString(\"http_response.length\")))"),
                    "{query}: {sql}"
                );
            }
        }
    }

    #[test]
    fn nan4279_same_function_aggregates_get_unique_display_names() {
        let output = compile_both_ways(request(
            "metadata.log_source=windows_sysmon | stats dc(device.hostname), dc(actor.user.name), dc(actor.process.name)",
        ));
        for name in ["dc(device.hostname)", "dc(actor.user.name)", "dc(actor.process.name)"] {
            assert!(output.sql.contains(&format!("AS \"{name}\"")), "{name}: {}", output.sql);
        }
        assert!(!output.sql.contains("AS dc"), "{}", output.sql);
        for column in &output.required_columns {
            assert!(!column.name.contains('('), "display name leaked as a column: {}", column.name);
        }
        // Mixed families and repeats stay unique; a lone aggregate keeps its
        // short name, so existing `| where dc > N` pipelines are unchanged.
        let mixed = compile_both_ways(request(
            "* | stats count, count(actor.user.name), avg(traffic.bytes_in), avg(traffic.bytes_out), dc(src_endpoint.ip), dc(src_endpoint.ip), max(time) by device.hostname",
        ))
        .sql;
        for name in ["count(actor.user.name)", "avg(traffic.bytes_in)", "avg(traffic.bytes_out)", "dc(src_endpoint.ip)", "dc(src_endpoint.ip)_2"] {
            assert!(mixed.contains(&format!("AS \"{name}\"")), "{name}: {mixed}");
        }
        assert!(mixed.contains("count() AS count") && mixed.contains("AS max"), "{mixed}");
        let single = compile_both_ways(request("* | stats dc(src_endpoint.ip) by device.hostname | where dc > 5")).sql;
        assert!(single.contains("AS dc"), "{single}");
    }

    #[test]
    fn nan4279_any_documented_percentile_shorthand_parses() {
        for (query, level) in [
            ("* | stats perc99(http_response.length) as v", "0.99"),
            ("* | stats perc50(http_response.length) as v", "0.5"),
            ("* | stats p90(http_response.length) as v", "0.9"),
            ("* | stats perc95(http_response.length) as v", "0.95"),
            ("* | stats p99(http_response.length) as v", "0.99"),
        ] {
            let sql = compile_both_ways(request(query)).sql;
            assert!(sql.contains(&format!("quantile({level})(\"http_response.length\")")), "{query}: {sql}");
        }
        assert!(parse_query("* | stats perc101(http_response.length) as v").is_err());
        let both = compile_both_ways(request(
            "* | stats perc90(http_response.length), perc99(http_response.length)",
        ))
        .sql;
        assert!(both.contains("AS \"perc90(http_response.length)\"") && both.contains("AS \"perc99(http_response.length)\""), "{both}");
    }

    #[test]
    fn nan4279_dedup_keeps_the_first_row_in_newest_first_order() {
        let newest = compile_both_ways(request("metadata.log_source=apache_access | dedup http_request.http_method")).sql;
        let oldest = compile_both_ways(request("metadata.log_source=apache_access | dedup http_request.http_method keepfirst=false")).sql;
        let keeplast = compile_both_ways(request("metadata.log_source=apache_access | dedup http_request.http_method keeplast=true")).sql;
        assert_eq!(oldest, keeplast);
        assert_ne!(newest, oldest, "keepfirst=false must change the survivor");
        let keeps = |sql: &str, newest: bool| {
            if sql.contains("(time) FROM") {
                sql.contains(if newest { "max(time) FROM" } else { "min(time) FROM" })
            } else {
                sql.contains("time DESC\n  LIMIT 1 BY") == newest
            }
        };
        assert!(keeps(&newest, true), "{newest}");
        assert!(keeps(&oldest, false), "{oldest}");
        // A non-base source takes the sort shape; the same rule holds.
        let staged = compile_both_ways(request("metadata.log_source=apache_access | where http_response.code=200 | dedup http_request.http_method")).sql;
        assert!(staged.contains("ORDER BY \"http_request.http_method\", time DESC\n  LIMIT 1 BY"), "{staged}");
    }

    #[test]
    fn nan4279_object_roots_project_exclude_and_expand_their_leaves() {
        let mut snapshot = BTreeMap::new();
        for leaf in ["http_request.http_method", "http_request.url.hostname", "http_request.user_agent"] {
            snapshot.insert(leaf.to_string(), FieldType::String);
        }
        for leaf in ["enrichments.name", "enrichments.value", "enrichments.provider", "enrichments.data.country_name"] {
            snapshot.insert(leaf.to_string(), FieldType::Array);
        }
        let with_snapshot = |query: &str| {
            let mut input = request(query);
            input.snapshot_field_types = snapshot.clone();
            input
        };

        let table = compile_both_ways(with_snapshot("* | table http_request, src_endpoint.ip"));
        for leaf in ["http_request.http_method", "http_request.url.hostname", "http_request.user_agent", "src_endpoint.ip"] {
            assert!(table.sql.contains(&format!("\"{leaf}\"")), "{leaf}: {}", table.sql);
            assert!(table.required_columns.iter().any(|column| column.name == leaf), "{leaf} not declared");
        }
        assert!(!table.sql.contains("\"http_request\""), "{}", table.sql);

        let excluded = compile_both_ways(with_snapshot("* | fields - raw_data, enrichments"));
        assert!(excluded.sql.contains("EXCEPT ("), "{}", excluded.sql);
        assert!(excluded.sql.contains("raw_data"), "{}", excluded.sql);
        for leaf in ["enrichments.name", "enrichments.value", "enrichments.data.country_name"] {
            assert!(excluded.sql.contains(&format!("\"{leaf}\"")), "{leaf}: {}", excluded.sql);
        }
        // Every excluded leaf must exist in the projected view, or EXCEPT
        // refuses it: the worker supplies a declared leaf the parts lack as a
        // typed NULL.
        let excepted = excluded.sql.split("EXCEPT (").nth(1).unwrap().split(')').next().unwrap();
        for leaf in excepted.split(", ").map(|leaf| leaf.trim_matches('"')).filter(|leaf| leaf.starts_with("enrichments.")) {
            assert!(
                excluded.required_columns.iter().any(|column| column.name == leaf),
                "{leaf} excluded but not declared: {:?}",
                excluded.required_columns
            );
        }

        let expanded = compile_both_ways(with_snapshot("* | mvexpand enrichments | table enrichments.name, enrichments.value"));
        // One ARRAY JOIN zips every leaf array (separate arrayJoins would
        // multiply them), and every joined leaf is declared to the worker.
        let joined = expanded.sql.split("ARRAY JOIN ").nth(1).unwrap().split(" LIMIT").next().unwrap();
        assert_eq!(expanded.sql.matches("ARRAY JOIN").count(), 1, "{}", expanded.sql);
        assert!(!expanded.sql.contains("arrayJoin("), "{}", expanded.sql);
        for leaf in ["enrichments.name", "enrichments.value", "enrichments.provider", "enrichments.data.country_name"] {
            assert!(joined.contains(&format!("\"{leaf}\"")), "{leaf}: {}", expanded.sql);
        }
        for leaf in joined.split(", ").map(|leaf| leaf.trim_matches('"')) {
            assert!(expanded.required_columns.iter().any(|column| column.name == leaf), "{leaf} not declared");
        }
        assert!(!expanded.sql.contains("ext.enrichments"), "{}", expanded.sql);

        // The front door validates without the snapshot inventory.
        let profile = OcsfProfile::lake_1_9();
        for query in ["* | table http_request, src_endpoint.ip", "* | fields - raw_data, enrichments", "* | mvexpand enrichments"] {
            let mut parsed = parse_query(query).unwrap();
            apply_profile_product_semantics(&mut parsed, &profile);
            let errors = validate_query_fields_with_profile(&parsed, Some(&profile));
            assert!(errors.is_empty(), "{query}: {errors:?}");
        }
        // A pipeline column that shares an object's name is left alone.
        let derived = compile(with_snapshot("* | stats count as device by src_endpoint.ip | table device, src_endpoint.ip")).unwrap();
        assert!(derived.sql.contains("device") && !derived.sql.contains("\"device."), "{}", derived.sql);
        // A misspelt root is still an unknown field.
        assert!(compile(with_snapshot("* | table http_requestt")).is_err());
    }

    /// NAN-4288 (F15): the documented `prevalence <prevalence column> <op> N`
    /// form parses (it was "Unexpected token '<'"). The lake compiler then
    /// refuses it as a Nano-side stage, which the front door runs.
    #[test]
    fn nan4288_documented_prevalence_filter_parses() {
        use nanosiem_core::query::{PrevalenceField, PrevalenceThreshold};
        for (query, field) in [
            ("metadata.log_source=windows_sysmon metadata.event_code=1 | prevalence prevalence_process_hash < 5 window=24h | stats count", PrevalenceField::HashPrevalence),
            ("* | prevalence prevalence_file_hash < 5 window=24h", PrevalenceField::HashPrevalence),
            ("* | prevalence prevalence_dest_domain <= 3", PrevalenceField::DomainPrevalence),
        ] {
            let parsed = parse_query(query).unwrap_or_else(|error| panic!("{query}: {error}"));
            let mut found = None;
            let mut cursor = &parsed;
            while let Query::Piped { source, command } = cursor {
                if let Command::Prevalence { conditions, .. } = command {
                    found = conditions.first().cloned();
                }
                cursor = source;
            }
            let condition = found.unwrap_or_else(|| panic!("{query}: no prevalence condition"));
            assert_eq!(condition.field, field, "{query}");
            assert!(matches!(condition.threshold, PrevalenceThreshold::Count(_)), "{query}");
            let error = compile(request(query)).unwrap_err().to_string();
            assert!(error.contains("prevalence"), "{query}: {error}");
            assert!(!error.contains("invalid nPL query"), "{query}: {error}");
        }
    }

    /// NAN-4288 (F17): a quoted Windows path reaches the worker as a term
    /// regex whose backslashes match the JSON-escaped raw text.
    #[test]
    fn nan4288_backslash_phrase_matches_escaped_raw_text() {
        let output = compile(request(r#""C:\Windows\System32\svchost.exe" | stats count by metadata.log_source"#)).unwrap();
        assert!(output.sql.contains(r"\\\\+"), "{}", output.sql);
    }

    /// NAN-4283 (searchfuzz F22): `arr=v` on an array-valued OCSF leaf means
    /// "any element equals v", case-insensitively, whether `v` is bare or
    /// quoted. It used to emit `has(arr, '<lowered>')`, a case-sensitive match
    /// against display-case elements (`SeImpersonatePrivilege`, `Hostname`,
    /// `T1110`), so it silently returned 0.
    #[test]
    fn nan4283_every_advertised_array_leaf_compares_bare_and_quoted_the_same() {
        let profile = OcsfProfile::lake_1_9();
        let arrays: Vec<&str> = profile
            .fields()
            .iter()
            .filter(|field| profile.field_type(field.name) == Some(FieldType::Array))
            .map(|field| field.name)
            .collect();
        assert!(arrays.len() >= 60, "array leaves: {arrays:?}");
        for field in arrays {
            if profile.is_lowercased_at_ingest(field) {
                continue; // raw has(): nan4283_lowercased_at_ingest_array_keeps_raw_has
            }
            let bare = compile(request(&format!("{field}=MixedCase | stats count")))
                .unwrap_or_else(|e| panic!("{field} bare: {e:#}"));
            let quoted = compile(request(&format!("{field}=\"MixedCase\" | stats count")))
                .unwrap_or_else(|e| panic!("{field} quoted: {e:#}"));
            assert_eq!(bare.sql, quoted.sql, "{field}");
            assert!(
                bare.sql.contains(&format!(
                    "arrayExists(x -> lower(toString(x)) = 'mixedcase', {})",
                    if field.contains('.') { format!("\"{field}\"") } else { field.to_string() }
                )),
                "{field}: {}",
                bare.sql
            );
            assert!(!bare.sql.contains("has(\""), "{field}: {}", bare.sql);
        }
    }

    /// Arrays the profile marks lowercased at ingest keep the raw `has()`
    /// compare (`email.to` is in the OCSF lowercased-at-ingest set).
    #[test]
    fn nan4283_lowercased_at_ingest_array_keeps_raw_has() {
        let output = compile(request("email.to=Victim@Example.com | stats count")).unwrap();
        assert!(output.sql.contains("has(\"email.to\", 'victim@example.com')"), "{}", output.sql);
    }

    /// Review of #7396: a 7-30d hash hunt must keep its file pruning. Pruning
    /// keys on the candidate hints (entity sidecars, part blooms), which come
    /// from the parsed query, not the SQL predicate. The hash hunt still emits
    /// its `file.hashes.value` entity hint, and the predicate is the
    /// case-insensitive element test.
    #[test]
    fn nan4283_hash_hunt_keeps_its_pruning_hint() {
        let sha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let output = compile(request(&format!("file.hashes.value={sha} | stats count"))).unwrap();
        assert!(
            output.candidate_hints.iter().any(|hint| matches!(
                hint,
                CandidateHint::Entity { source_path, value }
                    if source_path == "file.hashes.value" && value.eq_ignore_ascii_case(sha)
            )),
            "{:?}",
            output.candidate_hints
        );
        let lowered = sha.to_ascii_lowercase();
        assert!(
            output.sql.contains(&format!("arrayExists(x -> lower(toString(x)) = '{lowered}', \"file.hashes.value\")")),
            "{}",
            output.sql
        );
    }

    /// The F22 repros: search terms and `| where`, bare and quoted, for
    /// string-enum arrays, object-array leaves and IP/bool/number leaves.
    #[test]
    fn nan4283_array_equality_repros_are_any_element_case_insensitive() {
        let member = |field: &str, needle: &str| {
            let column = if field.contains('.') { format!("\"{field}\"") } else { field.to_string() };
            format!("arrayExists(x -> lower(toString(x)) = '{needle}', {column})")
        };
        let compile_typed = |query: String, typed: &[&str]| {
            let mut input = request(&query);
            for field in typed {
                input.snapshot_field_types.insert((*field).into(), FieldType::Array);
            }
            compile(input).unwrap_or_else(|e| panic!("{query}: {e:#}"))
        };
        for (field, value, needle) in [
            ("privileges", "SeImpersonatePrivilege", "seimpersonateprivilege"),
            ("observables.type", "Hostname", "hostname"),
            ("finding_info.attacks.technique.uid", "T1110", "t1110"),
            ("observables.value", "10.1.5.40", "10.1.5.40"),
            ("evidences.src_endpoint.ip", "10.1.1.68", "10.1.1.68"),
            ("evidences.device.hostname", "LT-Support-015", "lt-support-015"),
            ("enrichments.data.is_rare", "true", "true"),
            ("enrichments.data.host_count", "3", "3"),
        ] {
            let typed = [field];
            let predicate = member(field, needle);
            for query in [
                format!("{field}={value} | stats count"),
                format!("{field}=\"{value}\" | stats count"),
                format!("* | where {field}={value} | stats count"),
                format!("* | where {field}=\"{value}\" | stats count"),
            ] {
                let output = compile_typed(query.clone(), &typed);
                assert!(output.sql.contains(&predicate), "{query}: {}", output.sql);
                assert!(!output.sql.contains(&format!("NOT {predicate}")), "{query}");
            }
            let negated = compile_typed(format!("{field}!={value} | stats count"), &typed);
            assert!(negated.sql.contains(&format!("NOT {predicate}")), "{}", negated.sql);
        }
    }

    /// NAN-4283 (searchfuzz F24): a URL value is never a comment, so the rest
    /// of the query, including the pipeline, survives.
    #[test]
    fn nan4283_url_value_is_not_a_comment() {
        let output = compile(request(
            "http_request.url.url_string=https://stackoverflow.com/robots.txt | stats count",
        ))
        .unwrap();
        assert!(output.sql.contains("https://stackoverflow.com/robots.txt"), "{}", output.sql);
        assert!(output.sql.contains("count()"), "{}", output.sql);
        let wildcard = compile(request("http_request.url.url_string=https://x.example/* | stats count")).unwrap();
        assert!(wildcard.sql.contains("https://x.example/%"), "{}", wildcard.sql);
        // Documented comments still strip.
        let commented = compile(request("// header\nhttp_request.url.url_string=\"a\" /* note */ | stats count // tail")).unwrap();
        assert!(!commented.sql.contains("header") && !commented.sql.contains("note"), "{}", commented.sql);
    }

    /// NAN-4289 (searchfuzz F26): a pasted allow-list of a few hundred
    /// `NOT field=v` terms compiled to one parenthesis level per AND node and
    /// hit ClickHouse's `Maximum parse depth (1000) exceeded` (Code 306) at
    /// about 250 terms. AND chains are flat now, like OR chains (NAN-3276), so
    /// the predicate's nesting is constant in the number of terms, in search
    /// terms and in `| where`.
    #[test]
    fn nan4289_long_conjunctions_compile_flat() {
        let max_depth = |sql: &str| {
            let (mut depth, mut max) = (0i32, 0i32);
            for c in sql.chars() {
                match c {
                    '(' => { depth += 1; max = max.max(depth); }
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            max
        };
        let terms = |n: usize, prefix: &str| {
            (0..n).map(|i| format!("{prefix}http_request.url.path=\"/zz{i}\"")).collect::<Vec<_>>().join(" ")
        };
        let few = compile(request(&format!("metadata.log_source=apache_access {} | stats count", terms(10, "NOT ")))).unwrap();
        for n in [250, 400, 1000] {
            for query in [
                format!("metadata.log_source=apache_access {} | stats count", terms(n, "NOT ")),
                format!("metadata.log_source=apache_access {} | stats count", terms(n, "")),
                format!("metadata.log_source=apache_access | where {} | stats count",
                    (0..n).map(|i| format!("http_request.url.path!=\"/zz{i}\"")).collect::<Vec<_>>().join(" AND ")),
            ] {
                let output = compile(request(&query)).unwrap_or_else(|e| panic!("{n}: {e:#}"));
                assert!(
                    max_depth(&output.sql) <= max_depth(&few.sql) + 2,
                    "{n} terms nest {} deep vs {} for 10",
                    max_depth(&output.sql),
                    max_depth(&few.sql)
                );
                assert!(output.sql.contains(&format!("/zz{}", n - 1)));
            }
        }
    }

    /// NAN-4286 (F28): a bare RHS naming a field, or a column the pipeline
    /// computed upstream, is a column reference in `| where`; it used to be
    /// the literal text (`= 'http_response.code'`, `= 'c'`, always 0 rows)
    /// or, for `>`/`<`, a column stage_0 never projected (chDB Code 47).
    #[test]
    fn nan4286_where_compares_two_fields() {
        let base = "metadata.log_source=apache_access";
        for (pipe, expected) in [
            (
                "where http_response.code=http_response.code",
                r#""http_response.code" = "http_response.code""#,
            ),
            (
                "where http_response.code > http_request.length",
                r#""http_response.code" > "http_request.length""#,
            ),
            (
                "where src_endpoint.ip=dst_endpoint.ip",
                r#"lower("src_endpoint.ip") = lower("dst_endpoint.ip")"#,
            ),
            (
                "eval c=404 | where http_response.code=c",
                r#"lower(toString("http_response.code")) = lower(toString(c))"#,
            ),
            (
                "eval c=404 | where c=http_response.code",
                r#"lower(toString(c)) = lower(toString("http_response.code"))"#,
            ),
            ("eval c=404 | where http_response.code > c", r#""http_response.code" > c"#),
        ] {
            let query = format!("{base} | {pipe} | stats count");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(output.sql.contains(expected), "{query}: {}", output.sql);
            // Every column the comparison reads is projected by stage_0.
            let stage_0 = output.sql.split("stage_1 AS").next().unwrap();
            for column in ["\"dst_endpoint.ip\"", "\"http_request.length\""] {
                if pipe.contains(column.trim_matches('"')) {
                    assert!(stage_0.contains(column), "{query}: {stage_0}");
                    assert!(
                        output.required_columns.iter().any(|c| format!("\"{}\"", c.name) == column),
                        "{query}: required_columns lacks {column}"
                    );
                }
            }
        }
        // A quoted RHS is still the literal text.
        let quoted = compile(request(&format!(
            "{base} | eval c=404 | where http_response.code=\"c\" | stats count"
        )))
        .unwrap();
        assert!(!quoted.sql.contains("toString(c)"), "{}", quoted.sql);
    }

    /// NAN-4286 (F29): arithmetic or a literal on the LEFT of a `where`
    /// comparison, with or without spaces, was "Unexpected token".
    #[test]
    fn nan4286_where_expressions_on_either_side() {
        for (pipe, expected) in [
            (
                "where http_response.code-http_request.length=0",
                r#"(toFloat64OrNull(toString("http_response.code")) - toFloat64OrNull(toString("http_request.length"))) = 0"#,
            ),
            (
                "where http_response.code+http_request.length>1000",
                r#"(toFloat64OrNull(toString("http_response.code")) + toFloat64OrNull(toString("http_request.length"))) > 1000"#,
            ),
            (
                "where 1000 < http_response.code + http_request.length",
                r#"1000 < (toFloat64OrNull(toString("http_response.code")) + toFloat64OrNull(toString("http_request.length")))"#,
            ),
            ("where 404 = http_response.code", r#"404 = "http_response.code""#),
            ("eval c=404 | where c-http_response.code=0", r#"(c - toFloat64OrNull(toString("http_response.code"))) = 0"#),
        ] {
            let query = format!("metadata.log_source=apache_access | {pipe} | stats count");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(output.sql.contains(expected), "{query}: {}", output.sql);
        }
        // A hyphenated bare keyword is still a keyword.
        let keyword = compile(request("metadata.log_source=apache_access | where foo-bar | stats count")).unwrap();
        assert!(keyword.sql.contains("[Ff][Oo][Oo]\\\\-[Bb][Aa][Rr]"), "{}", keyword.sql);
    }

    /// NAN-4310: the searchfuzz post-aggregation shapes (`stats … by`,
    /// `where <alias> > N`, `sort -<alias>`, `head`) compile, and every source
    /// column stage_0 reads is a declared required column, so the planner
    /// binds it (a part without the OCSF `count` leaf gets a typed NULL).
    /// An undeclared bare `count` would read as the aggregate function
    /// (Code 215). The alias filter runs after the aggregation, on its output.
    #[test]
    fn nan4310_aggregate_alias_where_sort_head_shapes() {
        for (query, alias_filter) in [
            ("* | stats count by metadata.log_source | where count > 5", "WHERE count > 5"),
            ("* | stats count by metadata.log_source | where count>5 | sort -count | head 10", "WHERE count > 5"),
            ("* | stats count by metadata.log_source | sort -count | head 3", "ORDER BY count DESC"),
            ("* | stats count | where count > 5", "WHERE count > 5"),
            ("* | stats count as n by metadata.log_source | where n > 5 | sort -n", "WHERE n > 5"),
            ("* | stats dc(src_endpoint.ip) as hosts by metadata.log_source | where hosts > 1", "WHERE hosts > 1"),
            ("* | stats dc(src_endpoint.ip) by metadata.log_source | where dc_src_endpoint.ip > 1", "> 1"),
            (
                "* | stats sum(http_request.length) as bytes, count by src_endpoint.ip | where bytes > 100 AND count > 1 | sort -bytes | head 5",
                "WHERE (bytes > 100 AND count > 1)",
            ),
            ("* | top limit=5 metadata.log_source | where count > 1", "WHERE count > 1"),
        ] {
            let output = compile(request(query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            let (stage_0, rest) = output.sql.split_once("stage_1 AS").expect("staged plan");
            let select = stage_0
                .split_once("SELECT ")
                .and_then(|(_, tail)| tail.split_once(" FROM __nano_lake_source__"))
                .map(|(columns, _)| columns)
                .unwrap_or_else(|| panic!("{query}: {stage_0}"));
            for column in select.split(", ") {
                let name = column.trim().trim_matches('"');
                assert!(
                    output.required_columns.iter().any(|c| c.name == name),
                    "{query}: stage_0 reads undeclared {name}: {}",
                    output.sql
                );
            }
            assert!(rest.contains(alias_filter), "{query}: {}", output.sql);
            assert!(!stage_0.contains(alias_filter), "{query}: {}", output.sql);
        }
    }

    /// NAN-4303: `+` with a string operand concatenates (`"a"+"b"` was
    /// chDB Code 43 Float64 + String); number + number stays a numeric add,
    /// and an untyped stage alias keeps the numeric add.
    #[test]
    fn nan4303_plus_concatenates_strings_and_adds_numbers() {
        for (pipe, expected) in [
            (r#"eval s="a"+"b""#, "concat(toString('a'), toString('b')) AS s"),
            (
                r#"eval s=metadata.log_source + "_x""#,
                r#"concat(toString("metadata.log_source"), toString('_x')) AS s"#,
            ),
            (
                r#"eval s="code " + http_response.code"#,
                r#"concat(toString('code '), toString("http_response.code")) AS s"#,
            ),
            (r#"eval s=1 + 2 + "x""#, "concat(toString((1 + 2)), toString('x')) AS s"),
            (
                r#"rex field=metadata.log_source "(?<w>[a-z]+)_" | eval s=w + "!""#,
                "concat(toString(w), toString('!')) AS s",
            ),
            (
                r#"where src_endpoint.ip + ":" + http_response.code = "10.0.0.1:404""#,
                r#"concat(toString(concat(toString("src_endpoint.ip"), toString(':'))), toString("http_response.code"))"#,
            ),
            // Number + number, and an untyped alias + number: numeric add.
            (
                "eval s=http_response.code + 1",
                r#"(toFloat64OrNull(toString("http_response.code")) + 1) AS s"#,
            ),
            (
                "eval s=http_response.code + http_request.length",
                r#"(toFloat64OrNull(toString("http_response.code")) + toFloat64OrNull(toString("http_request.length"))) AS s"#,
            ),
            ("eval s=http_response.code | eval t=s + 1", "(coalesce(toFloat64OrNull(toString(s))"),
        ] {
            let query = format!("metadata.log_source=apache_access | {pipe} | stats count");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(output.sql.contains(expected), "{query}: {}", output.sql);
        }
        let numeric = compile(request(
            "metadata.log_source=apache_access | eval s=http_response.code + 1 | stats count",
        ))
        .unwrap();
        assert!(!numeric.sql.contains("concat("), "{}", numeric.sql);
    }

    /// NAN-4286 (F30): time literals compare as instants in both the search
    /// term and `| where` (RFC3339 was Code 53, minute precision Code 41, an
    /// epoch silently 0 rows), and `relative_time()` honours the modifier
    /// grammar instead of `DateTime64 + '-1h'` (Code 43).
    #[test]
    fn nan4286_time_literals_and_relative_time() {
        let at = "toDateTime64('2026-10-20 22:30:00.000', 3, 'UTC')";
        for query in [
            "* | where time > \"2026-10-20T22:30:00Z\" | stats count",
            "* | where time > \"2026-10-20T23:30:00+01:00\" | stats count",
            "* | where time > \"2026-10-20 22:30\" | stats count",
            "* | where time > \"2026-10-20 22:30:00.000\" | stats count",
            "* time>\"2026-10-20T22:30:00Z\" | stats count",
        ] {
            let output = compile(request(query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(output.sql.contains(&format!("time > {at}")), "{query}: {}", output.sql);
        }
        let epoch = compile(request("* | where time > 1792535400 | stats count")).unwrap();
        assert!(epoch.sql.contains("time > toDateTime64(1792535400, 3, 'UTC')"), "{}", epoch.sql);
        let error = compile(request("* | where time > \"yesterday\" | stats count")).unwrap_err();
        assert!(format!("{error:#}").contains("write a time as RFC3339"), "{error:#}");

        let relative = compile(request(
            "* | where time > relative_time(now(), \"-1h\") | eval d=relative_time(time, \"-1d@d\") | stats count by d",
        ))
        .unwrap();
        assert!(relative.sql.contains("addHours(toDateTime64(now(), 3, 'UTC'), -1)"), "{}", relative.sql);
        assert!(
            relative.sql.contains("toDateTime64(toStartOfDay(addDays(toDateTime64(time, 3, 'UTC'), -1)), 3, 'UTC')"),
            "{}",
            relative.sql
        );
        assert!(compile(request("* | eval d=relative_time(time, \"-1x\") | stats count by d")).is_err());
        let parsed = compile(request(
            "* | eval p=strptime(\"2026-10-20 22:30\", \"%Y-%m-%d %H:%M\") | where time > p | stats count",
        ))
        .unwrap();
        assert!(parsed.sql.contains("parseDateTimeOrNull("), "{}", parsed.sql);
    }

    /// NAN-4295 (F22, second half): `stats … by <array>` groups by each
    /// element (SPL multivalue `by`), never by the whole array, and drops
    /// NULL elements (the `[null]` groups of repeated-object leaves).
    #[test]
    fn nan4295_stats_by_array_field_groups_by_element() {
        let mut input = request("* | stats count by privileges, evidences.src_endpoint.hostname");
        input.snapshot_field_types.insert("privileges".into(), FieldType::Array);
        input.snapshot_field_types.insert("evidences.src_endpoint.hostname".into(), FieldType::Array);
        let sql = compile(input).unwrap().sql;
        assert!(sql.contains("arrayJoin(arrayFilter(x -> x IS NOT NULL, privileges)) AS _mv_privileges"), "{sql}");
        assert!(
            sql.contains(
                "arrayJoin(arrayFilter(x -> x IS NOT NULL, \"evidences.src_endpoint.hostname\")) AS \"_mv_evidences.src_endpoint.hostname\""
            ),
            "{sql}"
        );
        // ClickHouse's analyzer rejects a repeated arrayJoin in GROUP BY
        // (Code 43); the group key is the per-element alias, named back to
        // the field (first, in by-clause order) outside the aggregation.
        let group_by = &sql[sql.find("GROUP BY").expect("GROUP BY")..];
        assert!(!group_by.contains("arrayJoin"), "{sql}");
        assert!(group_by.contains("_mv_privileges"), "{sql}");
        assert!(
            sql.contains(
                "SELECT _mv_privileges AS privileges, \"_mv_evidences.src_endpoint.hostname\" AS \"evidences.src_endpoint.hostname\", * EXCEPT("
            ),
            "{sql}"
        );

        // A search filter on the same array is evaluated on the array column
        // (the element alias must not shadow it in the WHERE).
        let mut input = request("privileges=SeDebugPrivilege | stats count by privileges");
        input.snapshot_field_types.insert("privileges".into(), FieldType::Array);
        let sql = compile(input).unwrap().sql;
        assert!(sql.contains("arrayExists(x -> lower(toString(x)) = 'sedebugprivilege', privileges)"), "{sql}");
        assert!(sql.contains("AS _mv_privileges"), "{sql}");

        // Downstream, the by-field is a scalar per row: `where` compares it
        // directly instead of as array membership.
        let mut input = request("* | stats count by privileges | where privileges=\"Admin\"");
        input.snapshot_field_types.insert("privileges".into(), FieldType::Array);
        let sql = compile(input).unwrap().sql;
        let tail = &sql[sql.find("GROUP BY").expect("GROUP BY")..];
        assert!(!tail.contains("arrayExists"), "{sql}");
        assert!(!tail.contains("has("), "{sql}");

        // A non-string repeated leaf splits the same way.
        let sql = compile(request("* | stats count by module.file.signatures.algorithm_id")).unwrap().sql;
        assert!(
            sql.contains("arrayJoin(arrayFilter(x -> x IS NOT NULL, \"module.file.signatures.algorithm_id\"))"),
            "{sql}"
        );

        // After `mvexpand` the column already holds one element per row.
        let mut input = request("* | mvexpand privileges | stats count by privileges");
        input.snapshot_field_types.insert("privileges".into(), FieldType::Array);
        let sql = compile(input).unwrap().sql;
        assert!(sql.contains("arrayJoin(privileges) AS privileges"), "{sql}");
        assert!(!sql.contains("_mv_privileges") && !sql.contains("arrayFilter"), "{sql}");

        // A scalar by-field is unchanged.
        let sql = compile(request("* | stats count by src_endpoint.ip")).unwrap().sql;
        assert!(!sql.contains("arrayJoin"), "{sql}");
    }
}
