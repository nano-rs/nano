// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment utilities for search results
//!
//! This module provides functions to enrich search results with lookup table data
//! and external URL-based data via inputlookup.

use crate::inputlookup::{InputLookupParams, InputLookupService};
use crate::lookup::{BatchLookupQuery, LookupService};
use crate::search::{
    query_processing::{InputLookupCommandInfo, LookupCommandInfo},
    SearchError,
};
use tracing::{debug, info, warn};

/// Apply lookup enrichment to search results
///
/// For each lookup command, this function:
/// 1. Extracts the key values from the results
/// 2. Performs a batch lookup against the lookup table (PostgreSQL)
/// 3. Merges the lookup results into the original results
///
/// Requirements: 5.2, 5.5
pub async fn apply_lookup_enrichment(
    mut results: Vec<serde_json::Value>,
    lookup_commands: &[LookupCommandInfo],
    lookup_service: Option<&LookupService>,
) -> Result<Vec<serde_json::Value>, SearchError> {
    let lookup_service = match lookup_service {
        Some(service) => service,
        None => {
            warn!("Lookup command found but no lookup service configured");
            return Ok(results);
        }
    };

    for lookup_cmd in lookup_commands {
        debug!(
            "Applying lookup enrichment: table={}, key_field={}, output_fields={:?}, case_insensitive={}",
            lookup_cmd.table_name, lookup_cmd.key_field, lookup_cmd.output_fields, lookup_cmd.case_insensitive
        );

        // Extract unique key values from results
        let key_values: Vec<serde_json::Value> = results
            .iter()
            .filter_map(|row| row.get(&lookup_cmd.key_field).cloned())
            .filter(|v| !v.is_null())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if key_values.is_empty() {
            debug!(
                "No key values found for lookup field: {}",
                lookup_cmd.key_field
            );
            continue;
        }

        debug!(
            "Performing batch lookup for {} unique keys",
            key_values.len()
        );

        // Perform batch lookup (always uses PostgreSQL)
        let batch_query = BatchLookupQuery {
            table_name: lookup_cmd.table_name.clone(),
            key_field: lookup_cmd.key_field.clone(),
            key_values,
            output_fields: lookup_cmd.output_fields.clone(),
            case_insensitive: lookup_cmd.case_insensitive,
        };

        let batch_result = match lookup_service.lookup_batch(batch_query).await {
            Ok(result) => result,
            Err(e) => {
                warn!("Lookup failed for table {}: {}", lookup_cmd.table_name, e);
                continue;
            }
        };

        debug!(
            "Lookup returned {} matches out of {} keys",
            batch_result.matched_count, batch_result.total_count
        );

        // Merge lookup results into original results
        for row in &mut results {
            if let Some(obj) = row.as_object_mut() {
                // Get the key value from this row
                let key_value = match obj.get(&lookup_cmd.key_field) {
                    Some(v) if !v.is_null() => v.clone(),
                    _ => continue,
                };

                // Convert key to string for lookup in results map
                let key_str = match &key_value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                // Look up the enrichment data
                if let Some(lookup_fields) = batch_result.results.get(&key_str) {
                    // Add lookup fields to the row with a prefix to indicate source
                    for (field_name, field_value) in lookup_fields {
                        let enriched_field_name = format!("lookup_{}", field_name);
                        obj.insert(enriched_field_name, field_value.clone());
                    }
                } else {
                    // No match found - add null values for output fields if specified
                    if let Some(output_fields) = &lookup_cmd.output_fields {
                        for field_name in output_fields {
                            let enriched_field_name = format!("lookup_{}", field_name);
                            obj.insert(enriched_field_name, serde_json::Value::Null);
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Apply inputlookup enrichment to search results
///
/// For each inputlookup command, this function:
/// 1. In data source mode: Fetches the URL and returns parsed data
/// 2. In enrichment mode: Substitutes key values into URL, fetches, and merges
///
/// Fetched fields are prefixed with "inputlookup_" to indicate source.
pub async fn apply_inputlookup_enrichment(
    results: Vec<serde_json::Value>,
    inputlookup_commands: &[InputLookupCommandInfo],
    inputlookup_service: Option<&InputLookupService>,
) -> Result<Vec<serde_json::Value>, SearchError> {
    let inputlookup_service = match inputlookup_service {
        Some(service) => service,
        None => {
            if !inputlookup_commands.is_empty() {
                warn!("InputLookup command found but no inputlookup service configured");
            }
            return Ok(results);
        }
    };

    let mut current_results = results;

    for cmd in inputlookup_commands {
        debug!(
            "Applying inputlookup enrichment: url={}, format={:?}, key_field={:?}",
            cmd.url.template, cmd.format, cmd.key_field
        );

        // Build params from command info
        let params = InputLookupParams {
            url: cmd.url.clone(),
            format: cmd.format,
            key_field: cmd.key_field.clone(),
            timeout_secs: cmd.timeout_secs,
            max_rows: cmd.max_rows,
            cache_ttl_secs: cmd.cache_ttl_secs,
        };

        match inputlookup_service
            .execute(current_results.clone(), &params)
            .await
        {
            Ok(enriched) => {
                info!(
                    "InputLookup enrichment complete: {} results",
                    enriched.len()
                );
                current_results = enriched;
            }
            Err(e) => {
                // Log at error level to make failures more visible
                tracing::error!(
                    "InputLookup failed for url='{}': {}. Returning original results.",
                    cmd.url.template,
                    e
                );
                // Continue with original results on failure
            }
        }
    }

    Ok(current_results)
}
