// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stats, top/rare, and timechart aggregation post-processing
//!
//! This module provides aggregation functions applied after SQL query execution:
//! - Stats aggregation with group-by support
//! - Top/rare value analysis
//! - Timechart time-bucketed aggregation

use chrono::{DateTime, Timelike, Utc};

use crate::query::{AggFunc, Aggregation};
use crate::search::evaluator::helpers::parse_datetime_flexible;
use crate::search::SearchError;

use super::helpers::{get_nested_value, json_value_to_raw_string};

// ============================================================================
// Stats Aggregation
// ============================================================================

/// Prevalence fields to auto-preserve through stats aggregation.
/// These fields are added by prevalence enrichment and should be preserved
/// with sensible aggregation functions so they're available for post-stats filtering.
const PREVALENCE_FIELDS_TO_PRESERVE: &[(&str, AggFunc)] = &[
    ("host_count", AggFunc::Min), // Catches the rarest (most suspicious)
    ("is_rare", AggFunc::Max),    // If ANY was rare, flag it
    ("prevalence_score", AggFunc::Max), // Highest rarity score
    ("prevalence_first_seen", AggFunc::Min), // Earliest observation
    ("prevalence_last_seen", AggFunc::Max), // Most recent observation
    ("total_occurrences", AggFunc::Sum), // Total activity count
];

/// Default cap on post-processing group count to prevent OOM from high-cardinality GROUP BY
const DEFAULT_MAX_POST_PROCESSING_GROUPS: usize = 1_000_000;

/// Apply stats aggregation with a configurable group limit
pub fn apply_stats_post_processing_with_limit(
    results: &[serde_json::Value],
    aggregations: &[Aggregation],
    group_by: Option<&Vec<String>>,
    max_groups: usize,
) -> Result<(Vec<serde_json::Value>, bool), SearchError> {
    use std::collections::HashMap;
    use std::collections::HashSet;

    // Check which prevalence fields exist in the input data
    let prevalence_fields_present: HashSet<&str> = if let Some(first_row) = results.first() {
        if let Some(obj) = first_row.as_object() {
            PREVALENCE_FIELDS_TO_PRESERVE
                .iter()
                .filter(|(field, _)| obj.contains_key(*field))
                .map(|(field, _)| *field)
                .collect()
        } else {
            HashSet::new()
        }
    } else {
        HashSet::new()
    };

    // Check which fields are already being aggregated or in group_by
    let existing_output_fields: HashSet<String> = {
        let mut fields = HashSet::new();
        // Add explicit aggregation output fields
        for agg in aggregations {
            fields.insert(agg.output_alias());
        }
        // Add group_by fields
        if let Some(gb) = group_by {
            for field in gb {
                fields.insert(field.clone());
            }
        }
        fields
    };

    // Build list of prevalence aggregations to auto-add
    let auto_prevalence_aggs: Vec<Aggregation> = PREVALENCE_FIELDS_TO_PRESERVE
        .iter()
        .filter(|(field, _)| {
            prevalence_fields_present.contains(*field) && !existing_output_fields.contains(*field)
        })
        .map(|(field, func)| Aggregation {
            func: func.clone(),
            field: Some(field.to_string()),
            alias: Some(field.to_string()),
            condition: None,
            field_expr: None,
        })
        .collect();

    if !auto_prevalence_aggs.is_empty() {
        tracing::debug!(
            "Auto-preserving {} prevalence fields through stats: {:?}",
            auto_prevalence_aggs.len(),
            auto_prevalence_aggs
                .iter()
                .map(|a| a.alias.as_ref().unwrap())
                .collect::<Vec<_>>()
        );
    }

    // Group results - store both the key string and original values for each field
    let mut groups: HashMap<String, (Vec<serde_json::Value>, Vec<&serde_json::Value>)> =
        HashMap::new();

    let mut groups_capped = false;
    for row in results {
        let (key, field_values) = match group_by {
            Some(fields) => {
                let values: Vec<serde_json::Value> = fields
                    .iter()
                    .map(|f| {
                        get_nested_value(row, f)
                            .cloned()
                            .unwrap_or(serde_json::Value::Null)
                    })
                    .collect();
                let key = values
                    .iter()
                    .map(|v| json_value_to_raw_string(v))
                    .collect::<Vec<_>>()
                    .join("|");
                (key, values)
            }
            None => (String::new(), vec![]),
        };
        // Cap the number of groups to prevent OOM from high-cardinality GROUP BY
        if !groups.contains_key(&key) && groups.len() >= max_groups {
            groups_capped = true;
            continue;
        }
        groups
            .entry(key)
            .or_insert_with(|| (field_values, Vec::new()))
            .1
            .push(row);
    }
    if groups_capped {
        tracing::warn!(
            "Post-processing stats: group count capped at {} (some groups dropped)",
            max_groups
        );
    }

    // Compute aggregations for each group
    let mut output = Vec::new();
    for (_key, (field_values, rows)) in groups {
        let mut result_obj = serde_json::Map::new();

        // Add group by fields - preserve original types
        if let Some(fields) = group_by {
            for (i, field) in fields.iter().enumerate() {
                if let Some(val) = field_values.get(i) {
                    result_obj.insert(field.clone(), val.clone());
                }
            }
        }

        // Compute each explicit aggregation
        for agg in aggregations {
            let agg_value = compute_aggregation(&rows, agg);
            // The SQL generator's column name (`count`, `sum`, `avg`,
            // `values_<field>`, …). The old default was the input field name
            // or `{:?}` of the function, so `stats count by a | stats
            // avg(count), max(count)` wrote both into `count` and `stats
            // count` came back as `Count`.
            result_obj.insert(agg.output_alias(), agg_value);
        }

        // Compute auto-added prevalence aggregations
        for agg in &auto_prevalence_aggs {
            let agg_value = compute_aggregation(&rows, agg);
            if let Some(output_name) = &agg.alias {
                result_obj.insert(output_name.clone(), agg_value);
            }
        }

        output.push(serde_json::Value::Object(result_obj));
    }

    Ok((output, groups_capped))
}

/// Compute a single aggregation over a set of rows
///
/// # Arguments
/// * `rows` - The rows to aggregate
/// * `agg` - The aggregation to compute
///
/// # Returns
/// * `serde_json::Value` - The aggregated value
pub fn compute_aggregation(rows: &[&serde_json::Value], agg: &Aggregation) -> serde_json::Value {
    // NAN-2361: honour CONDITIONAL aggregation (`func(eval(<predicate>))`).
    //
    // The parser builds these as `Aggregation.condition` and the ClickHouse
    // generator compiles them to `countIf`/`sumIf`/`avgIf` — but this
    // post-processing path ignored `condition` entirely, so `count(eval(x))`
    // returned `rows.len()`: the TOTAL row count, whatever the predicate said.
    // Measured live on 2,345 proxy events, `count(eval(query.hostname=<value>))`
    // returned 2,345 for a column that is NULL on every one of those rows,
    // while the same predicate in a `| where` correctly returned 0.
    //
    // Every branch below reads `agg.field`; none consulted `condition`. Rather
    // than special-case `Count`, restrict the row set ONCE up front so all
    // aggregates (sum/avg/min/max/dc/…) become conditional together and no
    // future variant can silently miss it.
    //
    // Truthiness matches the `where` seam (`condition.rs`): a row counts only
    // when the predicate evaluates to boolean true. A row whose fields are
    // missing evaluates to `None` and is EXCLUDED — the same "not proven true"
    // rule the filter path uses, so the two never disagree.
    let filtered: Vec<&serde_json::Value>;
    let rows = match &agg.condition {
        // Only the functions the SQL generator will actually compile
        // conditionally. `aggregation.rs` returns `UnsupportedOperation` for
        // every other `AggFunc` with a condition; honouring it here too would
        // make `min(eval(...))` succeed on this path and error on the compiled
        // one — the same nPL answering two different ways depending on which
        // lane ran it. Ignoring the predicate is the safe divergence (an
        // over-broad aggregate) versus inventing a result the other lane
        // refuses to produce.
        Some(_) if !matches!(agg.func, AggFunc::Count | AggFunc::Sum | AggFunc::Avg) => rows,
        None => rows,
        Some(condition) => {
            filtered =
                rows.iter()
                    .copied()
                    .filter(|row| {
                        row.as_object().is_some_and(|object| {
                            crate::search::processing::post_processing::eval::
                            evaluate_eval_expression(condition, object)
                            .and_then(|value| value.as_bool())
                            .unwrap_or(false)
                        })
                    })
                    .collect();
            &filtered
        }
    };
    match &agg.func {
        AggFunc::Count => serde_json::Value::Number(serde_json::Number::from(rows.len())),
        // NAN-2361: a CONDITIONAL aggregate with no field aggregates the
        // constant 1 per matching row, exactly as the ClickHouse generator
        // emits (`sumIf(1, cond)` / `avgIf(1, cond)`). `rows` is already
        // restricted to matches above. Without this, sum returned 0 and avg
        // returned null here while ClickHouse returned a count and 1.0 — the
        // same query answering differently per backend, silently.
        AggFunc::Sum if agg.condition.is_some() && agg.field.is_none() => {
            serde_json::json!(rows.len() as f64)
        }
        AggFunc::Avg if agg.condition.is_some() && agg.field.is_none() => {
            if rows.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(1.0)
            }
        }
        AggFunc::Sum => {
            let sum: f64 = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
                .filter_map(|v| v.as_f64())
                .sum();
            serde_json::json!(sum)
        }
        AggFunc::Avg => {
            let values: Vec<f64> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
                .filter_map(|v| v.as_f64())
                .collect();
            if values.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(values.iter().sum::<f64>() / values.len() as f64)
            }
        }
        AggFunc::Min => rows
            .iter()
            .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
            .filter_map(|v| v.as_f64())
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
        AggFunc::Max => rows
            .iter()
            .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
            .filter_map(|v| v.as_f64())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
        // estdc() is approximate at the SQL layer only; client-side
        // post-processing over already-fetched rows counts exactly.
        AggFunc::Dc | AggFunc::EstDc => {
            let unique: std::collections::HashSet<String> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
                .map(|v| v.to_string())
                .collect();
            serde_json::Value::Number(serde_json::Number::from(unique.len()))
        }
        AggFunc::Values => {
            // Return comma-separated unique values as a string (matching ClickHouse behavior)
            let mut seen = std::collections::HashSet::new();
            let values: Vec<String> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
                .filter_map(|v| {
                    let s = json_value_to_raw_string(v);
                    if !s.is_empty() && seen.insert(s.clone()) {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect();
            serde_json::Value::String(values.join(", "))
        }
        AggFunc::First => rows
            .first()
            .and_then(|r| {
                agg.field
                    .as_ref()
                    .and_then(|f| get_nested_value(r, f).cloned())
            })
            .unwrap_or(serde_json::Value::Null),
        AggFunc::Last => rows
            .last()
            .and_then(|r| {
                agg.field
                    .as_ref()
                    .and_then(|f| get_nested_value(r, f).cloned())
            })
            .unwrap_or(serde_json::Value::Null),
        AggFunc::List => {
            // Return comma-separated values as a string (matching ClickHouse behavior)
            // Unlike values(), this includes duplicates
            let values: Vec<String> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| get_nested_value(r, f)))
                .map(|v| json_value_to_raw_string(v))
                .filter(|s| !s.is_empty())
                .collect();
            serde_json::Value::String(values.join(", "))
        }
        _ => serde_json::Value::Null,
    }
}

// ============================================================================
// Top/Rare Analysis
// ============================================================================

/// Apply top/rare command as post-processing
///
/// # Arguments
/// * `results` - The results to analyze
/// * `field` - The field to count occurrences of
/// * `limit` - Maximum number of results to return
/// * `_by_fields` - Fields to partition by (not yet implemented)
/// * `show_count` - Whether to include count in output
/// * `show_percent` - Whether to include percentage in output
/// * `is_rare` - True for rare (ascending), false for top (descending)
///
/// # Returns
/// * `Ok(Vec<serde_json::Value>)` - The top/rare results
/// * `Err(SearchError)` - If processing fails
pub fn apply_top_rare_post_processing(
    results: &[serde_json::Value],
    field: &str,
    limit: usize,
    _by_fields: &[String],
    show_count: bool,
    show_percent: bool,
    is_rare: bool,
) -> Result<(Vec<serde_json::Value>, bool), SearchError> {
    use std::collections::HashMap;

    // Count occurrences (cap at 1M unique values to prevent OOM). Keyed by
    // the JSON encoding so values keep their type in the output: the SQL
    // path returns `404` as a number and NULL as null, and so must this one
    // (it used to stringify both, `"404"` / `"null"`).
    let mut counts: HashMap<String, (serde_json::Value, usize)> = HashMap::new();
    let mut counts_capped = false;
    for row in results {
        if let Some(val) = get_nested_value(row, field) {
            let key = val.to_string();
            if !counts.contains_key(&key) && counts.len() >= DEFAULT_MAX_POST_PROCESSING_GROUPS {
                counts_capped = true;
                continue;
            }
            counts.entry(key).or_insert_with(|| (val.clone(), 0)).1 += 1;
        }
    }
    if counts_capped {
        tracing::warn!(
            "Post-processing top/rare: unique value count capped at {} for field '{}'",
            DEFAULT_MAX_POST_PROCESSING_GROUPS,
            field
        );
    }

    // Sort by count, ties by value for a deterministic page.
    let mut sorted: Vec<(String, (serde_json::Value, usize))> = counts.into_iter().collect();
    if is_rare {
        sorted.sort_by(|a, b| a.1 .1.cmp(&b.1 .1).then_with(|| a.0.cmp(&b.0)));
    } else {
        sorted.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then_with(|| a.0.cmp(&b.0)));
    }
    sorted.truncate(limit);

    // Build output
    let total: usize = results.len();
    let output: Vec<serde_json::Value> = sorted
        .into_iter()
        .map(|(_, (value, count))| {
            let mut obj = serde_json::Map::new();
            obj.insert(field.to_string(), value);
            if show_count {
                obj.insert("count".to_string(), serde_json::Value::Number(count.into()));
            }
            if show_percent && total > 0 {
                // Same rounding as the SQL path (`round(…, 2)`).
                let percent = (count as f64 * 100.0 / total as f64 * 100.0).round() / 100.0;
                obj.insert("percent".to_string(), serde_json::json!(percent));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    Ok((output, counts_capped))
}

// ============================================================================
// Timechart Aggregation
// ============================================================================

/// Apply timechart command as post-processing
///
/// # Arguments
/// * `results` - The results to aggregate over time
/// * `span` - The time bucket duration
/// * `aggregations` - The aggregation functions to apply
/// * `split_by` - Fields to split by
///
/// # Returns
/// * `Ok(Vec<serde_json::Value>)` - The timechart results
/// * `Err(SearchError)` - If processing fails
pub fn apply_timechart_post_processing(
    results: &[serde_json::Value],
    span: std::time::Duration,
    aggregations: &[Aggregation],
    split_by: &[String],
) -> Result<Vec<serde_json::Value>, SearchError> {
    use std::collections::HashMap;

    // NAN-2010 (F28): a zero span (`timechart span=0s count`) would
    // divide-by-zero panic `round_to_bucket` below. Reject before touching rows.
    if span.as_secs() == 0 {
        return Err(SearchError::ParseError(
            "timechart span must be greater than 0".to_string(),
        ));
    }

    // Group results by time bucket (and optionally by split field)
    let mut groups: HashMap<(String, Option<String>), Vec<&serde_json::Value>> = HashMap::new();

    for row in results {
        // Extract timestamp
        let timestamp_str = row
            .get("timestamp")
            .or_else(|| row.get("_time"))
            .or_else(|| row.get("time"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SearchError::ParseError("Timechart requires timestamp field".to_string())
            })?;

        let dt = parse_datetime_flexible(timestamp_str).ok_or_else(|| {
            SearchError::ParseError(format!("Invalid timestamp: {}", timestamp_str))
        })?;

        // Round down to time bucket
        let bucket = round_to_bucket(dt, span);
        let bucket_str = bucket.to_rfc3339();

        // Get split value if specified (use first split_by field)
        let split_value = split_by.first().and_then(|field| {
            get_nested_value(row, field.as_str())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

        groups
            .entry((bucket_str, split_value))
            .or_default()
            .push(row);
    }

    // Compute aggregations for each group
    let mut output = Vec::new();
    for ((bucket, split_value), rows) in groups {
        let mut result_obj = serde_json::Map::new();

        // Add time bucket
        result_obj.insert("time_bucket".to_string(), serde_json::Value::String(bucket));

        // Add split field if present
        if let Some(field) = split_by.first() {
            if let Some(value) = &split_value {
                result_obj.insert(field.clone(), serde_json::Value::String(value.clone()));
            }
        }

        // Compute each aggregation
        for agg in aggregations {
            let agg_value = compute_aggregation(&rows, agg);
            let output_name = agg
                .alias
                .as_ref()
                .or(agg.field.as_ref())
                .map(|s| s.clone())
                .unwrap_or_else(|| "count".to_string());
            result_obj.insert(output_name, agg_value);
        }

        output.push(serde_json::Value::Object(result_obj));
    }

    // Sort by time bucket
    output.sort_by(|a, b| {
        let a_time = a.get("time_bucket").and_then(|v| v.as_str()).unwrap_or("");
        let b_time = b.get("time_bucket").and_then(|v| v.as_str()).unwrap_or("");
        a_time.cmp(b_time)
    });

    Ok(output)
}

/// Round a datetime down to the nearest time bucket
fn round_to_bucket(dt: DateTime<Utc>, span: std::time::Duration) -> DateTime<Utc> {
    let span_secs = span.as_secs() as i64;

    // Handle common intervals efficiently
    match span_secs {
        60 => dt.with_second(0).unwrap().with_nanosecond(0).unwrap(), // 1 minute
        300 => {
            // 5 minutes
            let minute = (dt.minute() / 5) * 5;
            dt.with_minute(minute)
                .unwrap()
                .with_second(0)
                .unwrap()
                .with_nanosecond(0)
                .unwrap()
        }
        600 => {
            // 10 minutes
            let minute = (dt.minute() / 10) * 10;
            dt.with_minute(minute)
                .unwrap()
                .with_second(0)
                .unwrap()
                .with_nanosecond(0)
                .unwrap()
        }
        900 => {
            // 15 minutes
            let minute = (dt.minute() / 15) * 15;
            dt.with_minute(minute)
                .unwrap()
                .with_second(0)
                .unwrap()
                .with_nanosecond(0)
                .unwrap()
        }
        1800 => {
            // 30 minutes
            let minute = (dt.minute() / 30) * 30;
            dt.with_minute(minute)
                .unwrap()
                .with_second(0)
                .unwrap()
                .with_nanosecond(0)
                .unwrap()
        }
        3600 => dt
            .with_minute(0)
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap(), // 1 hour
        86400 => {
            // 1 day
            dt.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc()
        }
        _ => {
            // NAN-2010 (F28): defensive — a zero/negative span must never
            // divide-by-zero panic here. Callers reject span=0 (a stack overflow
            // / abort is uncatchable), so this only guards a direct misuse.
            if span_secs <= 0 {
                return dt;
            }
            // Generic bucketing for other intervals
            let timestamp = dt.timestamp();
            let bucket_timestamp = (timestamp / span_secs) * span_secs;
            DateTime::from_timestamp(bucket_timestamp, 0).unwrap_or(dt)
        }
    }
}

#[cfg(test)]
mod tests {
    /// NAN-2361: `count(eval(<predicate>))` must count only MATCHING rows.
    ///
    /// This path ignored `Aggregation.condition` and returned `rows.len()`, so
    /// every conditional aggregate reported the total. Live proof before the
    /// fix: 2,345 proxy events, and `count(eval(query.hostname=<value>))`
    /// returned 2,345 for a column NULL on all of them — while the identical
    /// predicate in `| where` returned 0.
    ///
    /// The aggregation is built by PARSING REAL nPL rather than hand-assembled:
    /// an earlier version of this test constructed an `Aggregation` carrying
    /// both a field and a condition, which the parser cannot produce
    /// (`func(eval(..))` always yields `field: None`), so it proved nothing
    /// about real queries.
    #[test]
    fn nan2361_conditional_aggregation_counts_only_matching_rows() {
        use crate::query::{parse_query, Command, Query};

        fn aggregation_of(npl: &str) -> Aggregation {
            let query = parse_query(npl).expect("parses");
            let Query::Piped { command, .. } = query else {
                panic!("expected a piped query");
            };
            let Command::Stats { aggregations, .. } = command else {
                panic!("expected stats");
            };
            aggregations.into_iter().next().expect("one aggregation")
        }

        let rows = vec![
            serde_json::json!({"kind": "dns"}),
            serde_json::json!({"kind": "proxy"}),
            serde_json::json!({"kind": "proxy"}),
            serde_json::json!({"other": true}),
        ];
        let refs = rows.iter().collect::<Vec<_>>();

        // Sanity: the parser really does give us a condition and no field.
        let proxy_agg = aggregation_of(r#"* | stats count(eval(kind="proxy")) as c"#);
        assert!(
            proxy_agg.condition.is_some(),
            "parser must carry the predicate"
        );
        assert!(proxy_agg.field.is_none(), "func(eval(..)) yields no field");

        assert_eq!(
            compute_aggregation(&refs, &proxy_agg),
            serde_json::json!(2),
            "must count matching rows, not the row total"
        );

        // A predicate true for NO row yields 0 — the exact failure that made
        // matched_fields report every path at the full hit count.
        let never = aggregation_of(r#"* | stats count(eval(kind="nothing-matches")) as c"#);
        assert_eq!(compute_aggregation(&refs, &never), serde_json::json!(0));

        // A row missing the field entirely is NOT proven true, so it is excluded
        // — matching the `where` seam rather than diverging from it.
        let unconditional = aggregation_of("* | stats count() as c");
        assert_eq!(
            compute_aggregation(&refs, &unconditional),
            serde_json::json!(4),
            "unconditional count is unchanged"
        );
    }

    use super::*;
    use chrono::TimeZone;

    /// NAN-2010 (F28): a zero timechart span must return a clean error, not a
    /// divide-by-zero panic in `round_to_bucket`.
    #[test]
    fn timechart_span_zero_is_rejected() {
        let rows = vec![serde_json::json!({ "timestamp": "2024-01-01T00:00:00Z" })];
        let out =
            apply_timechart_post_processing(&rows, std::time::Duration::from_secs(0), &[], &[]);
        assert!(out.is_err(), "timechart span=0 must error, not panic");
    }

    /// Defensive: `round_to_bucket` must not divide-by-zero even if handed a
    /// zero span directly.
    #[test]
    fn round_to_bucket_zero_span_returns_input() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 12, 34, 56).unwrap();
        assert_eq!(round_to_bucket(dt, std::time::Duration::from_secs(0)), dt);
    }
}
