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

/// Pre-validate that every `| lookup` table referenced by the query exists.
///
/// Returns an actionable 400-class error naming the missing lookup (and the
/// available tables) instead of letting execution proceed to a masked failure
/// or silently un-enriched results (NAN-1389).
///
/// A registry read failure (PostgreSQL hiccup) skips the pre-check rather than
/// failing the search — the enrichment step downstream surfaces its own error.
pub async fn validate_lookup_tables(
    lookup_commands: &[LookupCommandInfo],
    lookup_service: Option<&LookupService>,
) -> Result<(), SearchError> {
    let Some(lookup_service) = lookup_service else {
        // No service wired (test/minimal construction) — the enrichment step
        // logs and skips, matching pre-existing behavior.
        return Ok(());
    };

    for cmd in lookup_commands {
        match lookup_service.table_exists(&cmd.table_name).await {
            Ok(true) => {}
            Ok(false) => {
                let available: Vec<String> = match lookup_service.list_tables().await {
                    Ok(tables) => tables.into_iter().map(|t| t.name).collect(),
                    Err(_) => Vec::new(),
                };
                return Err(SearchError::SqlValidationError(missing_lookup_message(
                    &cmd.table_name,
                    &available,
                )));
            }
            Err(e) => {
                warn!(
                    "Lookup table existence pre-check failed for '{}' (skipping): {}",
                    cmd.table_name, e
                );
            }
        }
    }

    Ok(())
}

/// The search error for a failed lookup read.
///
/// NAN-3334: a read failure used to be logged and SKIPPED, so the search
/// returned 200 with every row un-enriched and no warning — on hosted, where
/// the tenant lookup store refused every read, `| lookup` silently did
/// nothing. Un-enriched rows read as "no match", a wrong answer; the search
/// must fail and say why.
fn lookup_batch_failure(table: &str, error: crate::lookup::LookupError) -> SearchError {
    match error {
        // The pre-check passed, so the table was dropped mid-flight (NAN-1389).
        crate::lookup::LookupError::TableNotFound(name) => SearchError::SqlValidationError(format!(
            "Lookup table '{name}' does not exist (it may have been deleted \
             while the search was running)"
        )),
        error => {
            warn!("Lookup failed for table {}: {}", table, error);
            // clickhouse/dev has no ServiceUnavailable variant: a store read
            // failure is a database error (HTTP 500, logged with this text).
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Lookup table '{table}' could not be read, so `| lookup {table}` was not \
                 applied: {error}. Retry the search."
            )))
        }
    }
}

/// Merge one lookup's batch result into the rows (in place).
pub fn merge_lookup_batch(
    results: &mut [serde_json::Value],
    lookup_cmd: &LookupCommandInfo,
    batch_result: &crate::lookup::BatchLookupResult,
) {
    // NAN-4933: a CASE_INSENSITIVE batch compares LOWER(key) but returns
    // the map under the table's stored spelling (`Admin`); probing it with
    // the event's spelling (`admin`) missed and wrote null outputs. Both
    // sides are folded the same way.
    let fold = |key: &str| {
        if lookup_cmd.case_insensitive {
            key.to_lowercase()
        } else {
            key.to_string()
        }
    };
    let matches: std::collections::HashMap<String, &std::collections::HashMap<String, serde_json::Value>> =
        batch_result
            .results
            .iter()
            .map(|(key, fields)| (fold(key), fields))
            .collect();

    // Merge lookup results into original results
    for row in results.iter_mut() {
        if let Some(obj) = row.as_object_mut() {
            // Get the key value from this row
            // NAN-3466 / f6a341e5a: read the EVENT field, match the
            // table's KEY column (they differ in `lookup t ip AS src_ip`).
            let key_value = match lookup_event_value(obj, &lookup_cmd.event_field) {
                Some(v) => v,
                None => continue,
            };

            // Convert key to string for lookup in results map
            let key_str = match &key_value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };

            // Look up the enrichment data
            if let Some(lookup_fields) = matches.get(&fold(&key_str)) {
                // Write each output under its name (or OUTPUT rename)
                for (field_name, field_value) in lookup_fields.iter() {
                    insert_lookup_output(obj, lookup_cmd, field_name, field_value.clone());
                }
            } else {
                // No match found - add null values for output fields if specified
                if let Some(output_fields) = &lookup_cmd.output_fields {
                    for field_name in output_fields {
                        insert_lookup_output(obj, lookup_cmd, field_name, serde_json::Value::Null);
                    }
                }
            }
        }
    }
}

/// The event value a lookup reads: the flat column (`src_endpoint.ip` as
/// ClickHouse returns it), else the nested object path. NULL is no value.
fn lookup_event_value(
    row: &serde_json::Map<String, serde_json::Value>,
    event_field: &str,
) -> Option<serde_json::Value> {
    if let Some(v) = row.get(event_field) {
        return (!v.is_null()).then(|| v.clone());
    }
    let mut parts = event_field.split('.');
    let first = row.get(parts.next()?)?;
    let v = parts.try_fold(first, |value, part| value.get(part))?;
    (!v.is_null()).then(|| v.clone())
}

/// Write one lookup output column (f6a341e5a / NAN-3466).
///
/// Outputs keep their table column name, or the `OUTPUT a AS b` rename — the
/// documented contract (`lookup assets src_ip as ip | table asset_owner`).
/// clickhouse/dev wrote them as `lookup_<column>`, so every documented
/// downstream reference (and the validator's derived field) named a column
/// that was never there. `OUTPUTNEW` keeps an existing non-null value. The key
/// column, returned with every match, never replaces the parent object of a
/// dotted event field (`user` for `user.name`) unless OUTPUT names it.
fn insert_lookup_output(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    command: &LookupCommandInfo,
    source: &str,
    value: serde_json::Value,
) {
    let target = command
        .output_renames
        .iter()
        .find(|r| r.from == source)
        .map_or(source, |r| r.to.as_str());
    let explicit = command
        .output_fields
        .as_ref()
        .is_some_and(|fields| fields.iter().any(|field| field == source));
    if !explicit
        && command
            .event_field
            .strip_prefix(target)
            .is_some_and(|rest| rest.starts_with('.'))
    {
        return;
    }
    if command.output_new
        && lookup_event_value(obj, target).is_some()
    {
        return;
    }
    obj.insert(target.to_string(), value);
}

/// Build the user-facing message for a `| lookup` against a missing table.
fn missing_lookup_message(table_name: &str, available: &[String]) -> String {
    const MAX_LISTED: usize = 10;
    if available.is_empty() {
        format!(
            "Lookup table '{}' does not exist and no lookup tables are defined. \
             Create the lookup table first, or remove the `| lookup {}` stage.",
            table_name, table_name
        )
    } else {
        let mut listed = available
            .iter()
            .take(MAX_LISTED)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if available.len() > MAX_LISTED {
            listed.push_str(", …");
        }
        format!(
            "Lookup table '{}' does not exist. Available lookup tables: {}",
            table_name, listed
        )
    }
}

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
            .filter_map(|row| lookup_event_value(row.as_object()?, &lookup_cmd.event_field))
            .filter(|v| !v.is_null())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if key_values.is_empty() {
            debug!(
                "No key values found for lookup field: {}",
                lookup_cmd.event_field
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
            // The pre-check (`validate_lookup_tables`) runs before execution,
            // but the table can be dropped mid-flight — surface that the same
            // actionable way instead of silently returning un-enriched rows
            // (NAN-1389).
            Err(error) => return Err(lookup_batch_failure(&lookup_cmd.table_name, error)),
        };

        debug!(
            "Lookup returned {} matches out of {} keys",
            batch_result.matched_count, batch_result.total_count
        );

        merge_lookup_batch(&mut results, lookup_cmd, &batch_result);
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
///
/// Failure surfacing (NAN-1389): an inputlookup that cannot produce data is an
/// error, not a silent no-op. Previously a failed fetch was logged and the
/// original rows returned as HTTP 200 — in data-source mode that substituted
/// raw log rows for the requested external data, and in enrichment mode it fed
/// silently un-enriched rows into downstream `where`/`stats` stages. Partial
/// enrichment failures (some keys fetched, some failed) degrade gracefully and
/// are reported through `warnings`.
pub async fn apply_inputlookup_enrichment(
    results: Vec<serde_json::Value>,
    inputlookup_commands: &[InputLookupCommandInfo],
    inputlookup_service: Option<&InputLookupService>,
    warnings: &mut Vec<String>,
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
            Ok(outcome) => {
                info!(
                    "InputLookup enrichment complete: {} results ({} warnings)",
                    outcome.results.len(),
                    outcome.warnings.len()
                );
                warnings.extend(outcome.warnings);
                current_results = outcome.results;
            }
            Err(e) => {
                tracing::error!("InputLookup failed for url='{}': {}", cmd.url.template, e);
                return Err(SearchError::SqlValidationError(format!(
                    "inputlookup failed for URL '{}': {}. Verify the URL is reachable \
                     and returns the expected format, or remove the `| inputlookup` stage.",
                    cmd.url.template, e
                )));
            }
        }
    }

    Ok(current_results)
}

#[cfg(test)]
#[path = "lookup_join_tests.rs"]
mod lookup_join_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inputlookup::{InputLookupConfig, InputLookupFormat, UrlTemplate};

    /// NAN-3334: a lookup read failure fails the search instead of returning
    /// silently un-enriched rows.
    #[test]
    fn lookup_read_failure_is_an_error_not_a_skip_nan3334() {
        let err = lookup_batch_failure(
            "threat_iocs",
            crate::lookup::LookupError::RepositoryError("tenant context key unavailable".into()),
        );
        assert!(
            matches!(&err, SearchError::DatabaseError(sqlx::Error::Protocol(m)) if m.contains("threat_iocs") && m.contains("key unavailable")),
            "{err:?}"
        );
        assert!(matches!(
            lookup_batch_failure("t", crate::lookup::LookupError::TableNotFound("t".into())),
            SearchError::SqlValidationError(_)
        ));
    }

    /// NAN-1389: the missing-lookup message must name the table and guide the
    /// user (it surfaces verbatim through the 400 QUERY_ERROR mapping).
    #[test]
    fn missing_lookup_message_names_table_and_lists_available() {
        let msg = missing_lookup_message("nonexistent", &[]);
        assert!(msg.contains("'nonexistent'"), "must name the table: {msg}");
        assert!(
            msg.contains("no lookup tables are defined"),
            "empty registry guidance: {msg}"
        );

        let available = vec!["assets".to_string(), "threat_actors".to_string()];
        let msg = missing_lookup_message("asets", &available);
        assert!(msg.contains("'asets'"), "must name the table: {msg}");
        assert!(
            msg.contains("assets") && msg.contains("threat_actors"),
            "must list available tables: {msg}"
        );

        // Long registries are capped at 10 entries + ellipsis
        let many: Vec<String> = (0..15).map(|i| format!("t{i}")).collect();
        let msg = missing_lookup_message("missing", &many);
        assert!(msg.contains('…'), "long lists are truncated: {msg}");
    }

    /// NAN-1389 regression: a failed inputlookup execution must surface as an
    /// error (mapped to 400 by the search service), never a clean Ok with
    /// un-enriched rows. Induced failure: the default SSRF guard blocks the
    /// private-range URL synchronously, no network needed.
    #[tokio::test]
    async fn apply_inputlookup_enrichment_surfaces_fetch_failure() {
        let service = InputLookupService::new(InputLookupConfig::default());
        let cmd = InputLookupCommandInfo {
            url: UrlTemplate::new("https://10.255.255.1/feed.csv"),
            format: InputLookupFormat::Csv,
            key_field: None, // data source mode
            timeout_secs: 1,
            max_rows: 100,
            cache_ttl_secs: 0,
        };
        let mut warnings = Vec::new();
        let err = apply_inputlookup_enrichment(
            vec![serde_json::json!({"src_ip": "1.2.3.4"})],
            &[cmd],
            Some(&service),
            &mut warnings,
        )
        .await
        .expect_err("failed fetch must error, not silently return un-enriched rows");
        match err {
            SearchError::SqlValidationError(msg) => {
                assert!(
                    msg.contains("inputlookup failed for URL"),
                    "actionable message expected: {msg}"
                );
                assert!(
                    msg.contains("10.255.255.1"),
                    "message must name the URL: {msg}"
                );
            }
            other => panic!("expected SqlValidationError (→ 400), got: {other:?}"),
        }
    }
}
