// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment utilities for search results
//!
//! This module provides functions to enrich search results with lookup table data
//! and external URL-based data via inputlookup.

use super::post_processing::get_nested_values;
use crate::inputlookup::{InputLookupParams, InputLookupService};
use crate::lookup::{BatchLookupQuery, LookupError, LookupService, LookupTable};
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
        match lookup_service.get_table(&cmd.table_name).await {
            Ok(table) => validate_lookup_columns(cmd, &table)?,
            Err(LookupError::TableNotFound(_)) => {
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
fn lookup_batch_failure(table: &str, error: LookupError) -> SearchError {
    match error {
        // The pre-check passed, so the table was dropped mid-flight (NAN-1389).
        LookupError::TableNotFound(name) => SearchError::SqlValidationError(format!(
            "Lookup table '{name}' does not exist (it may have been deleted \
             while the search was running)"
        )),
        // NAN-4287: a refusal of the REQUEST (a key the table cannot hold, a
        // limit) is deterministic. As a 503 it read as an outage and asked the
        // analyst to retry a search that could never succeed.
        error @ (LookupError::InvalidColumn(_)
        | LookupError::InvalidTableName(_)
        | LookupError::InvalidData(_)
        | LookupError::RowLimitExceeded(_)
        | LookupError::PrimaryKeyNotFound(_)) => SearchError::SqlValidationError(format!(
            "`| lookup {table}` cannot be applied: {error}"
        )),
        error => {
            warn!("Lookup failed for table {}: {}", table, error);
            SearchError::ServiceUnavailable(format!(
                "Lookup table '{table}' could not be read, so `| lookup {table}` was not \
                 applied: {error}. Retry the search."
            ))
        }
    }
}

/// Validate lookup projection columns against registry metadata before event
/// execution. A misspelled or stale OUTPUT column is a query error, not an
/// infrastructure failure and never a reason to return silently unenriched
/// rows after performing the event scan.
fn validate_lookup_columns(
    command: &LookupCommandInfo,
    table: &LookupTable,
) -> Result<(), SearchError> {
    let available = table
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    if !available.contains(command.key_field.as_str()) {
        let mut available = available.into_iter().collect::<Vec<_>>();
        available.sort_unstable();
        return Err(SearchError::SqlValidationError(format!(
            "Lookup table '{}' does not contain key column '{}'. Available columns: {}. Use lookup <table> <lookup_column> AS <event_field>; ambiguous flat-field pairs use this order",
            command.table_name,
            command.key_field,
            available.join(", ")
        )));
    }
    let Some(output_fields) = &command.output_fields else {
        return Ok(());
    };
    let missing = output_fields
        .iter()
        .filter(|field| !available.contains(field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    let mut available = available.into_iter().collect::<Vec<_>>();
    available.sort_unstable();
    Err(SearchError::SqlValidationError(format!(
        "Lookup table '{}' does not contain requested OUTPUT column(s): {}. Available columns: {}",
        command.table_name,
        missing.join(", "),
        available.join(", ")
    )))
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

/// NAN-3466: whether a lookup output named `output` is a parent object of
/// the dotted event field (`user` for `user.name`).
pub(crate) fn lookup_output_shadows_event_field(event_field: &str, output: &str) -> bool {
    event_field
        .strip_prefix(output)
        .is_some_and(|rest| rest.starts_with('.'))
}

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
    // NAN-3466: the key column comes back with every match. Written as a
    // flat `user` it replaced the nested `user` object the event field
    // `user.name` lives in, so `| table user.name, dept` lost the key. An
    // output naming the event field's parent object is written only when
    // OUTPUT asked for it by name.
    let explicit = command
        .output_fields
        .as_ref()
        .is_some_and(|fields| fields.iter().any(|field| field == source));
    if !explicit
        && lookup_output_shadows_event_field(&command.event_field, target)
    {
        return;
    }
    let nested = || {
        let (first, rest) = target.split_once('.')?;
        rest.split('.')
            .try_fold(obj.get(first)?, |value, part| value.get(part))
    };
    if command.output_new
        && (obj.get(target).is_some_and(|v| !v.is_null())
            || nested().is_some_and(|v| !v.is_null()))
    {
        return;
    }
    obj.insert(target.to_string(), value);
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
            "Applying lookup enrichment: table={}, event_field={}, key_field={}, output_fields={:?}, case_insensitive={}",
            lookup_cmd.table_name,
            lookup_cmd.event_field,
            lookup_cmd.key_field,
            lookup_cmd.output_fields,
            lookup_cmd.case_insensitive
        );

        // Extract unique key values from results
        let key_values: Vec<serde_json::Value> = results
            .iter()
            .flat_map(|row| get_nested_values(row, &lookup_cmd.event_field))
            .cloned()
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

        // Merge lookup results into original results
        for row in &mut results {
            let key_values = get_nested_values(row, &lookup_cmd.event_field)
                .into_iter()
                .filter(|value| !value.is_null())
                .cloned()
                .collect::<Vec<_>>();
            if let Some(obj) = row.as_object_mut() {
                let lookup_fields = key_values.iter().find_map(|key_value| {
                    let key = match key_value {
                        serde_json::Value::String(value) => value.clone(),
                        serde_json::Value::Number(value) => value.to_string(),
                        serde_json::Value::Bool(value) => value.to_string(),
                        _ => return None,
                    };
                    batch_result.results.get(&key)
                });

                if let Some(lookup_fields) = lookup_fields {
                    // SPL-style `lookup ... OUTPUT field` exposes `field` under
                    // its requested name. This is intentionally different from
                    // URL `inputlookup` enrichment, whose untrusted payload is
                    // namespaced under `inputlookup_`.
                    for (field_name, field_value) in lookup_fields {
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
            crate::inputlookup::storage_policy::redact_single_url(&cmd.url.template), cmd.format, cmd.key_field
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
                let safe_url = crate::inputlookup::storage_policy::redact_single_url(&cmd.url.template);
                let safe_error = crate::inputlookup::storage_policy::redact_url_credentials(&e.to_string());
                tracing::error!("InputLookup failed for url='{}': {}", safe_url, safe_error);
                return Err(SearchError::SqlValidationError(format!(
                    "inputlookup failed for URL '{}': {}. Verify the URL is reachable \
                     and returns the expected format, or remove the `| inputlookup` stage.",
                    safe_url, safe_error
                )));
            }
        }
    }

    Ok(current_results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inputlookup::{InputLookupConfig, InputLookupFormat, UrlTemplate};
    use crate::lookup::LookupColumn;
    use crate::ColumnType;
    use chrono::Utc;
    use uuid::Uuid;

    fn lookup_table_with_columns(names: &[&str]) -> LookupTable {
        LookupTable {
            id: Uuid::new_v4(),
            name: "assets".to_string(),
            description: None,
            table_name: "lookup_assets".to_string(),
            columns: names
                .iter()
                .map(|name| LookupColumn {
                    name: (*name).to_string(),
                    data_type: ColumnType::Text,
                    nullable: false,
                })
                .collect(),
            primary_key: Some("ip".to_string()),
            row_count: 1,
            size_bytes: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
        }
    }

    /// NAN-3334: a lookup read failure fails the search instead of returning
    /// silently un-enriched rows.
    #[test]
    fn lookup_read_failure_is_an_error_not_a_skip_nan3334() {
        let err = lookup_batch_failure(
            "threat_iocs",
            LookupError::RepositoryError("tenant context key unavailable".into()),
        );
        assert!(
            matches!(&err, SearchError::ServiceUnavailable(m) if m.contains("threat_iocs") && m.contains("key unavailable")),
            "{err:?}"
        );
        assert!(matches!(
            lookup_batch_failure("t", LookupError::TableNotFound("t".into())),
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

    #[test]
    fn lookup_renames_and_outputnew_preserve_existing_values() {
        let query = crate::query::parse_query(
            "* | lookup assets ip AS src_endpoint.ip OUTPUTNEW owner AS asset_owner, hostname AS device.hostname"
        ).unwrap();
        let command = crate::search::query_processing::extract_lookup_commands(&query).remove(0);
        let mut row = serde_json::json!({"asset_owner": "alice", "device": {"hostname": "existing"}})
            .as_object().unwrap().clone();
        insert_lookup_output(&mut row, &command, "owner", serde_json::json!("bob"));
        insert_lookup_output(&mut row, &command, "hostname", serde_json::json!("replacement"));
        assert_eq!(row["asset_owner"], "alice");
        assert!(!row.contains_key("device.hostname"));
        row.insert("asset_owner".into(), serde_json::Value::Null);
        insert_lookup_output(&mut row, &command, "owner", serde_json::json!("bob"));
        assert_eq!(row["asset_owner"], "bob");
        assert!(!row.contains_key("owner"));
        let mut overwrite = command.clone();
        overwrite.output_new = false;
        insert_lookup_output(&mut row, &overwrite, "owner", serde_json::Value::Null);
        assert!(row["asset_owner"].is_null());
    }

    /// NAN-3466: `lookup users user AS user.name` returns the key column
    /// `user` with each match; written flat it replaced the nested `user`
    /// object and `| table user.name, dept` lost the key field.
    #[test]
    fn lookup_key_column_never_overwrites_the_dotted_event_field_parent() {
        let query = crate::query::parse_query(
            "* | lookup oc_sweep_users user AS user.name | table user.name, dept",
        )
        .unwrap();
        let command = crate::search::query_processing::extract_lookup_commands(&query).remove(0);
        assert_eq!((command.key_field.as_str(), command.event_field.as_str()), ("user", "user.name"));
        let mut row = serde_json::json!({"user": {"name": "oc-sweep-alice"}})
            .as_object().unwrap().clone();
        insert_lookup_output(&mut row, &command, "user", serde_json::json!("oc-sweep-alice"));
        insert_lookup_output(&mut row, &command, "dept", serde_json::json!("finance"));
        assert_eq!(row["user"]["name"], "oc-sweep-alice");
        assert_eq!(row["dept"], "finance");
        // An explicit OUTPUT of that name is honored.
        let explicit = crate::query::parse_query(
            "* | lookup oc_sweep_users user AS user.name OUTPUT user AS user",
        )
        .unwrap();
        let explicit = crate::search::query_processing::extract_lookup_commands(&explicit).remove(0);
        insert_lookup_output(&mut row, &explicit, "user", serde_json::json!("flat"));
        assert_eq!(row["user"], "flat");
        assert!(lookup_output_shadows_event_field("user.name", "user"));
        assert!(!lookup_output_shadows_event_field("user.name", "use"));
        assert!(!lookup_output_shadows_event_field("user", "user"));
    }

    #[test]
    fn lookup_output_columns_are_validated_before_event_scan() {
        let table = lookup_table_with_columns(&["ip", "hostname", "owner"]);
        let valid = LookupCommandInfo {
            table_name: "assets".to_string(),
            event_field: "src_endpoint.ip".to_string(),
            key_field: "ip".to_string(),
            output_fields: Some(vec!["hostname".to_string(), "owner".to_string()]),
            output_renames: Vec::new(),
            output_new: false,
            case_insensitive: false,
        };
        validate_lookup_columns(&valid, &table).expect("known columns must pass");

        let stale = LookupCommandInfo {
            output_fields: Some(vec!["hostname".to_string(), "os".to_string()]),
            ..valid
        };
        let error = validate_lookup_columns(&stale, &table).expect_err("unknown column");
        let SearchError::SqlValidationError(message) = error else {
            panic!("expected SQL validation error")
        };
        assert!(message.contains("os"), "missing column named: {message}");
        assert!(
            message.contains("hostname, ip, owner"),
            "available columns listed: {message}"
        );

        let stale_key = LookupCommandInfo {
            key_field: "src_ip".to_string(),
            output_fields: None,
            ..LookupCommandInfo {
                table_name: "assets".to_string(),
                event_field: "src_endpoint.ip".to_string(),
                key_field: "ip".to_string(),
                output_fields: None,
                output_renames: Vec::new(),
                output_new: false,
                case_insensitive: false,
            }
        };
        let error = validate_lookup_columns(&stale_key, &table).expect_err("unknown key column");
        let SearchError::SqlValidationError(message) = error else {
            panic!("expected SQL validation error")
        };
        assert!(message.contains("src_ip"), "missing key named: {message}");
    }

    /// NAN-1389 regression: a failed inputlookup execution must surface as an
    /// error (mapped to 400 by the search service), never a clean Ok with
    /// un-enriched rows. Induced failure: the default SSRF guard blocks the
    /// private-range URL synchronously, no network needed.
    #[tokio::test]
    async fn apply_inputlookup_enrichment_surfaces_fetch_failure_and_redacts_signature() {
        let service = InputLookupService::new(InputLookupConfig::default());
        let cmd = InputLookupCommandInfo {
            url: UrlTemplate::new("https://10.255.255.1/feed.csv?sig=TEST_SIGNATURE"),
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
                assert!(!msg.contains("TEST_SIGNATURE"), "signed URL must be redacted");
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

    /// NAN-4287 (searchfuzz F31): a `| lookup` over a lake candidate set with
    /// more distinct keys than the tenant store reads per batch (10k) was a
    /// 503 on every run. Through the production `LookupService` and
    /// `apply_lookup_enrichment`: every row is enriched, including keys past
    /// the first batch.
    #[tokio::test]
    async fn nan4287_lookup_reads_more_keys_than_one_store_batch() {
        use crate::search::service::ioc_lookup_resolve::tests::{make_table, service_with};
        let table = make_table(
            "easy_intel",
            vec![LookupColumn::text("value", false), LookupColumn::text("ioc_type", false)],
            Some("value"),
        );
        let ip = |i: usize| format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
        // Two IOCs, one in the first and one in the last key batch.
        let iocs = [7usize, 24_993];
        let rows = iocs
            .iter()
            .map(|&i| {
                std::collections::HashMap::from([
                    ("value".to_string(), serde_json::json!(ip(i))),
                    ("ioc_type".to_string(), serde_json::json!("ip")),
                ])
            })
            .collect();
        let service = service_with(table, rows);
        let events: Vec<_> = (0..25_000)
            .map(|i| serde_json::json!({"src_endpoint": {"ip": ip(i)}}))
            .collect();
        let query = crate::query::parse_query(
            "* | lookup easy_intel value as src_endpoint.ip OUTPUT ioc_type | stats count by ioc_type",
        )
        .unwrap();
        let commands = crate::search::query_processing::extract_lookup_commands(&query);
        let enriched = apply_lookup_enrichment(events, &commands, Some(&service))
            .await
            .expect("a lookup over more than one store batch of keys must succeed");
        let hits: Vec<usize> = enriched
            .iter()
            .enumerate()
            .filter(|(_, row)| row.get("ioc_type") == Some(&serde_json::json!("ip")))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits, iocs);
    }

    /// NAN-4287: a deterministic refusal of the lookup REQUEST is a 400, not a
    /// 503 asking the analyst to retry; a store failure stays retryable.
    #[test]
    fn nan4287_lookup_request_refusals_are_4xx() {
        for error in [
            LookupError::InvalidColumn("at most 10000 key values per batch lookup".into()),
            LookupError::InvalidData("bad".into()),
            LookupError::RowLimitExceeded(1),
        ] {
            assert!(
                matches!(lookup_batch_failure("easy_intel", error), SearchError::SqlValidationError(_)),
            );
        }
        assert!(matches!(
            lookup_batch_failure("easy_intel", LookupError::RepositoryError("pool timed out".into())),
            SearchError::ServiceUnavailable(_)
        ));
    }
}
