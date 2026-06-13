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

use super::helpers::json_value_to_raw_string;

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
            let default_name = agg
                .field
                .clone()
                .unwrap_or_else(|| format!("{:?}", agg.func));
            let output_name = agg.alias.as_ref().unwrap_or(&default_name);
            fields.insert(output_name.clone());
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
                    .map(|f| row.get(f).cloned().unwrap_or(serde_json::Value::Null))
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
            let default_name = agg
                .field
                .clone()
                .unwrap_or_else(|| format!("{:?}", agg.func));
            let output_name = agg.alias.as_ref().unwrap_or(&default_name);
            result_obj.insert(output_name.clone(), agg_value);
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
    match &agg.func {
        AggFunc::Count => serde_json::Value::Number(serde_json::Number::from(rows.len())),
        AggFunc::Sum => {
            let sum: f64 = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
                .filter_map(|v| v.as_f64())
                .sum();
            serde_json::json!(sum)
        }
        AggFunc::Avg => {
            let values: Vec<f64> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
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
            .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
            .filter_map(|v| v.as_f64())
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
        AggFunc::Max => rows
            .iter()
            .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
            .filter_map(|v| v.as_f64())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
        // estdc() is approximate at the SQL layer only; client-side
        // post-processing over already-fetched rows counts exactly.
        AggFunc::Dc | AggFunc::EstDc => {
            let unique: std::collections::HashSet<String> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
                .map(|v| v.to_string())
                .collect();
            serde_json::Value::Number(serde_json::Number::from(unique.len()))
        }
        AggFunc::Values => {
            // Return comma-separated unique values as a string (matching ClickHouse behavior)
            let mut seen = std::collections::HashSet::new();
            let values: Vec<String> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
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
            .and_then(|r| agg.field.as_ref().and_then(|f| r.get(f).cloned()))
            .unwrap_or(serde_json::Value::Null),
        AggFunc::Last => rows
            .last()
            .and_then(|r| agg.field.as_ref().and_then(|f| r.get(f).cloned()))
            .unwrap_or(serde_json::Value::Null),
        AggFunc::List => {
            // Return comma-separated values as a string (matching ClickHouse behavior)
            // Unlike values(), this includes duplicates
            let values: Vec<String> = rows
                .iter()
                .filter_map(|r| agg.field.as_ref().and_then(|f| r.get(f)))
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

    // Count occurrences (cap at 1M unique values to prevent OOM)
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut counts_capped = false;
    for row in results {
        if let Some(val) = row.get(field) {
            let key = val.to_string();
            if !counts.contains_key(&key) && counts.len() >= DEFAULT_MAX_POST_PROCESSING_GROUPS {
                counts_capped = true;
                continue;
            }
            *counts.entry(key).or_default() += 1;
        }
    }
    if counts_capped {
        tracing::warn!(
            "Post-processing top/rare: unique value count capped at {} for field '{}'",
            DEFAULT_MAX_POST_PROCESSING_GROUPS,
            field
        );
    }

    // Sort by count
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    if is_rare {
        sorted.sort_by(|a, b| a.1.cmp(&b.1)); // Ascending for rare
    } else {
        sorted.sort_by(|a, b| b.1.cmp(&a.1)); // Descending for top
    }
    sorted.truncate(limit);

    // Build output
    let total: usize = results.len();
    let output: Vec<serde_json::Value> = sorted
        .into_iter()
        .map(|(value, count)| {
            let mut obj = serde_json::Map::new();
            // Remove quotes from string values
            let clean_value = value.trim_matches('"');
            obj.insert(
                field.to_string(),
                serde_json::Value::String(clean_value.to_string()),
            );
            if show_count {
                obj.insert("count".to_string(), serde_json::Value::Number(count.into()));
            }
            if show_percent && total > 0 {
                let percent = (count as f64 / total as f64) * 100.0;
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

    // Group results by time bucket (and optionally by split field)
    let mut groups: HashMap<(String, Option<String>), Vec<&serde_json::Value>> = HashMap::new();

    for row in results {
        // Extract timestamp
        let timestamp_str = row
            .get("timestamp")
            .or_else(|| row.get("_time"))
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
            row.get(field.as_str())
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
            // Generic bucketing for other intervals
            let timestamp = dt.timestamp();
            let bucket_timestamp = (timestamp / span_secs) * span_secs;
            DateTime::from_timestamp(bucket_timestamp, 0).unwrap_or(dt)
        }
    }
}
