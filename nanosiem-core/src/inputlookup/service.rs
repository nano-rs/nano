// SPDX-License-Identifier: AGPL-3.0-or-later

//! InputLookup service for URL-based enrichment
//!
//! This service provides the high-level API for the inputlookup command,
//! handling both data source mode (fetch URL as results) and enrichment mode
//! (join URL results with search results).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;
use tracing::{debug, info, warn};

use super::fetcher::{FetchError, UrlFetcher};
use super::response_parser::{parse_response, ParseError};
use super::types::{InputLookupConfig, InputLookupParams};
use crate::lookup::{LookupError, LookupService};
use crate::query::{InputLookupFormat, UrlTemplate};

/// URL scheme that addresses an INTERNAL lookup table (resolved through
/// [`LookupService`]) rather than an external HTTP(S) feed. The parser emits
/// `inputlookup <name>` as a `lookup://<name>` URL (see
/// `query::parser::commands_security`). These URLs must NEVER reach the HTTP
/// [`UrlFetcher`] (NAN-1581 Phase 5).
const LOOKUP_SCHEME: &str = "lookup://";

/// Errors that can occur during inputlookup execution
#[derive(Debug, Error)]
pub enum InputLookupError {
    #[error("Fetch error: {0}")]
    FetchError(#[from] FetchError),

    #[error("Parse error: {0}")]
    ParseError(#[from] ParseError),

    #[error("Missing required key field '{0}' in search results")]
    MissingKeyField(String),

    #[error("URL template substitution failed: missing field '{0}'")]
    TemplateSubstitutionFailed(String),

    #[error("No data returned from URL")]
    EmptyResponse,

    #[error("all {attempted} enrichment fetch(es) failed; last error: {last_error}")]
    AllFetchesFailed { attempted: usize, last_error: String },

    /// A `lookup://<name>` URL was used but no internal lookup service is wired
    /// into this `InputLookupService` (some minimal construction paths).
    #[error(
        "inputlookup against internal table '{0}' is not available: \
         no lookup service is configured"
    )]
    LookupServiceUnavailable(String),

    /// The named internal lookup table does not exist. Mirrors the NAN-1389
    /// `| lookup` missing-table message: names the table and lists available
    /// tables when the registry can be enumerated.
    #[error("{0}")]
    LookupTableNotFound(String),

    /// Reading the internal lookup table failed (registry/storage error).
    #[error("inputlookup failed to read internal table '{table}': {source}")]
    LookupReadError {
        table: String,
        source: LookupError,
    },
}

/// Result of an inputlookup execution: the (possibly enriched) rows plus any
/// non-fatal warnings — e.g. a subset of per-key enrichment fetches failed and
/// the affected rows are un-enriched (NAN-1389).
#[derive(Debug)]
pub struct InputLookupOutcome {
    pub results: Vec<Value>,
    pub warnings: Vec<String>,
}

/// InputLookup service for URL-based data fetching and enrichment.
///
/// Handles two URL families:
/// - real `http(s)://` feeds → fetched through the SSRF-guarded [`UrlFetcher`].
/// - `lookup://<name>` internal tables → resolved through the optional
///   [`LookupService`], bypassing the fetcher entirely (NAN-1581 Phase 5).
#[derive(Clone)]
pub struct InputLookupService {
    fetcher: Arc<UrlFetcher>,
    config: InputLookupConfig,
    /// Internal lookup layer for `lookup://` URLs. `None` on minimal
    /// construction paths — a `lookup://` URL then errors clearly rather than
    /// silently falling through to an HTTP attempt.
    lookup_service: Option<Arc<LookupService>>,
}

impl InputLookupService {
    /// Create a new InputLookup service with the given configuration.
    ///
    /// No internal lookup layer is wired; `lookup://` URLs will error. Use
    /// [`with_lookup_service`](Self::with_lookup_service) to enable
    /// `| inputlookup <internal_table>`.
    pub fn new(config: InputLookupConfig) -> Self {
        let fetcher = Arc::new(UrlFetcher::new(config.clone()));
        Self {
            fetcher,
            config,
            lookup_service: None,
        }
    }

    /// Attach the internal [`LookupService`] so `lookup://<name>` URLs resolve
    /// to a full read of the named internal lookup table.
    pub fn with_lookup_service(mut self, lookup_service: Arc<LookupService>) -> Self {
        self.lookup_service = Some(lookup_service);
        self
    }

    /// Detect a `lookup://<name>` URL and return the (trimmed) table name.
    fn internal_lookup_table(url: &str) -> Option<&str> {
        url.strip_prefix(LOOKUP_SCHEME).map(str::trim)
    }

    /// Read EVERY row of an internal lookup table as JSON search results,
    /// matching the shape the HTTP/CSV data-source path produces (user columns
    /// only; internal columns stripped by `LookupService::read_all_rows`).
    ///
    /// Errors clearly when no lookup service is wired, when the table doesn't
    /// exist (naming available tables, mirroring the NAN-1389 message), or when
    /// the read fails. NEVER touches the HTTP fetcher.
    async fn read_internal_lookup(
        &self,
        table_name: &str,
    ) -> Result<Vec<Value>, InputLookupError> {
        let lookup_service = self.lookup_service.as_ref().ok_or_else(|| {
            InputLookupError::LookupServiceUnavailable(table_name.to_string())
        })?;

        match lookup_service.read_all_rows(table_name).await {
            Ok(rows) => {
                let results = rows
                    .into_iter()
                    .map(|row| Value::Object(row.into_iter().collect()))
                    .collect::<Vec<_>>();
                info!(
                    "inputlookup read {} rows from internal table '{}'",
                    results.len(),
                    table_name
                );
                Ok(results)
            }
            Err(LookupError::TableNotFound(_)) => {
                // List available tables for an actionable message (best-effort).
                let available: Vec<String> = match lookup_service.list_tables().await {
                    Ok(tables) => tables.into_iter().map(|t| t.name).collect(),
                    Err(_) => Vec::new(),
                };
                Err(InputLookupError::LookupTableNotFound(
                    missing_internal_lookup_message(table_name, &available),
                ))
            }
            Err(e) => Err(InputLookupError::LookupReadError {
                table: table_name.to_string(),
                source: e,
            }),
        }
    }

    /// Execute an inputlookup command in data source mode
    ///
    /// Fetches the URL and returns the parsed rows as search results.
    pub async fn fetch_data_source(
        &self,
        params: &InputLookupParams,
    ) -> Result<Vec<Value>, InputLookupError> {
        // INTERNAL lookup table (`lookup://<name>`): read it directly through the
        // lookup layer and bypass the HTTP fetcher entirely (NAN-1581 Phase 5).
        if let Some(table) = Self::internal_lookup_table(&params.url.template) {
            debug!("inputlookup data source: internal table '{}'", table);
            return self.read_internal_lookup(table).await;
        }

        debug!(
            "Fetching data source: url={}, format={:?}",
            params.url.template, params.format
        );

        // URL should not have placeholders in data source mode
        if params.url.has_placeholders() {
            warn!("URL has placeholders but no key field specified, fetching as-is");
        }

        let result = self
            .fetcher
            .fetch(
                &params.url.template,
                Some(params.timeout_secs),
                params.cache_ttl_secs,
            )
            .await?;

        let rows = parse_response(&result.body, params.format, params.max_rows)?;

        info!(
            "Fetched {} rows from URL (from_cache={})",
            rows.len(),
            result.from_cache
        );

        Ok(rows)
    }

    /// Enrich `results` by joining an INTERNAL lookup table on `key_field`.
    ///
    /// Reads the whole table once (deduped) and builds a key→row index, then
    /// merges matched rows into each input row with the same `inputlookup_`
    /// prefix the HTTP path uses. The join key on the lookup side is its FIRST
    /// column's value — matching how internal lookups are keyed in the registry.
    async fn enrich_results_internal(
        &self,
        results: Vec<Value>,
        table_name: &str,
        key_field: &str,
    ) -> Result<InputLookupOutcome, InputLookupError> {
        let rows = self.read_internal_lookup(table_name).await?;

        // Index lookup rows by their join-key value. Each lookup row's key is
        // the value of `key_field` if present, else its first column's value.
        let mut index: HashMap<String, Value> = HashMap::new();
        for row in rows {
            let Some(obj) = row.as_object() else { continue };
            let key_val = obj
                .get(key_field)
                .or_else(|| obj.values().next())
                .and_then(value_as_key_string);
            if let Some(k) = key_val {
                index.entry(k).or_insert(row);
            }
        }

        let enriched = results
            .into_iter()
            .map(|mut row| {
                if let Some(obj) = row.as_object_mut() {
                    let key = obj.get(key_field).and_then(value_as_key_string);
                    if let Some(key) = key {
                        if let Some(enrich_obj) = index.get(&key).and_then(|v| v.as_object()) {
                            for (field_name, field_value) in enrich_obj {
                                obj.insert(
                                    format!("inputlookup_{}", field_name),
                                    field_value.clone(),
                                );
                            }
                        }
                    }
                }
                row
            })
            .collect();

        Ok(InputLookupOutcome {
            results: enriched,
            warnings: Vec::new(),
        })
    }

    /// Execute an inputlookup command in enrichment mode
    ///
    /// For each unique key value in the search results:
    /// 1. Substitutes the key value into the URL template
    /// 2. Fetches the URL
    /// 3. Merges the fetched fields into the original results
    ///
    /// Fetched fields are prefixed with "inputlookup_" to avoid collisions.
    pub async fn enrich_results(
        &self,
        results: Vec<Value>,
        params: &InputLookupParams,
    ) -> Result<InputLookupOutcome, InputLookupError> {
        let key_field = params
            .key_field
            .as_ref()
            .ok_or_else(|| InputLookupError::MissingKeyField("(none)".to_string()))?;

        // INTERNAL lookup table (`lookup://<name>`) in enrichment mode: read the
        // whole table once and join in-memory on the key field, bypassing the
        // HTTP fetcher entirely (NAN-1581 Phase 5).
        if let Some(table) = Self::internal_lookup_table(&params.url.template) {
            return self
                .enrich_results_internal(results, table, key_field)
                .await;
        }

        debug!(
            "Enriching {} results with inputlookup: url={}, key_field={}, format={:?}",
            results.len(),
            params.url.template,
            key_field,
            params.format
        );

        // Extract unique key values from results
        let unique_keys: HashSet<String> = results
            .iter()
            .filter_map(|row| {
                row.get(key_field).and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
            })
            .collect();

        if unique_keys.is_empty() {
            debug!("No key values found in results for field '{}'", key_field);
            return Ok(InputLookupOutcome {
                results,
                warnings: Vec::new(),
            });
        }

        debug!(
            "Found {} unique key values for enrichment",
            unique_keys.len()
        );

        // Fetch data for each unique key, tracking failures so they can be
        // surfaced instead of silently producing un-enriched rows (NAN-1389)
        let mut enrichment_data: HashMap<String, Value> = HashMap::new();
        let mut failed_fetches = 0usize;
        let mut last_error: Option<String> = None;

        for key_value in &unique_keys {
            // Substitute key value into URL template
            let mut values = HashMap::new();

            // For templates that use the key field name directly
            values.insert(key_field.clone(), key_value.clone());

            // Also try with any other placeholder names (in case template uses different name)
            for field in &params.url.fields {
                if field != key_field {
                    values.insert(field.clone(), key_value.clone());
                }
            }

            let url = params.url.substitute(&values).ok_or_else(|| {
                // Find which field is missing
                let missing = params
                    .url
                    .fields
                    .iter()
                    .find(|f| !values.contains_key(*f))
                    .cloned()
                    .unwrap_or_else(|| "(unknown)".to_string());
                InputLookupError::TemplateSubstitutionFailed(missing)
            })?;

            // Fetch and parse the URL
            match self
                .fetcher
                .fetch(&url, Some(params.timeout_secs), params.cache_ttl_secs)
                .await
            {
                Ok(result) => {
                    match parse_response(&result.body, params.format, params.max_rows) {
                        Ok(rows) => {
                            // For enrichment, we expect a single result per key
                            // If multiple rows returned, use the first one
                            if let Some(first_row) = rows.into_iter().next() {
                                enrichment_data.insert(key_value.clone(), first_row);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse response for key '{}': {}", key_value, e);
                            failed_fetches += 1;
                            last_error = Some(e.to_string());
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch URL for key '{}': {}", key_value, e);
                    failed_fetches += 1;
                    last_error = Some(e.to_string());
                }
            }
        }

        info!(
            "Fetched enrichment data for {}/{} keys ({} failed)",
            enrichment_data.len(),
            unique_keys.len(),
            failed_fetches
        );

        // Every fetch failed: the enrichment cannot happen at all — surface an
        // error instead of returning every row silently un-enriched.
        if failed_fetches == unique_keys.len() {
            return Err(InputLookupError::AllFetchesFailed {
                attempted: unique_keys.len(),
                last_error: last_error.unwrap_or_else(|| "unknown error".to_string()),
            });
        }

        // Some fetches failed: degrade gracefully (matched rows are enriched)
        // but report the gap as a response warning.
        let mut warnings = Vec::new();
        if failed_fetches > 0 {
            warnings.push(format!(
                "inputlookup: {}/{} enrichment fetches failed for '{}' (last error: {}); \
                 rows for the failed keys are un-enriched",
                failed_fetches,
                unique_keys.len(),
                params.url.template,
                last_error.unwrap_or_else(|| "unknown error".to_string()),
            ));
        }

        // Merge enrichment data into results
        let enriched_results = results
            .into_iter()
            .map(|mut row| {
                if let Some(obj) = row.as_object_mut() {
                    // Get the key value from this row
                    let key_value = obj.get(key_field).and_then(|v| match v {
                        Value::String(s) => Some(s.clone()),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    });

                    if let Some(key) = key_value {
                        if let Some(enrichment) = enrichment_data.get(&key) {
                            if let Some(enrich_obj) = enrichment.as_object() {
                                // Add enrichment fields with prefix
                                for (field_name, field_value) in enrich_obj {
                                    let prefixed_name = format!("inputlookup_{}", field_name);
                                    obj.insert(prefixed_name, field_value.clone());
                                }
                            }
                        }
                    }
                }
                row
            })
            .collect();

        Ok(InputLookupOutcome {
            results: enriched_results,
            warnings,
        })
    }

    /// Execute an inputlookup command (auto-detects mode based on params)
    pub async fn execute(
        &self,
        results: Vec<Value>,
        params: &InputLookupParams,
    ) -> Result<InputLookupOutcome, InputLookupError> {
        if params.is_data_source_mode() {
            // Data source mode: ignore input results, return fetched data.
            // A failed fetch here is always an error — the user asked for the
            // URL's data, so substituting the original rows would be wrong.
            let results = self.fetch_data_source(params).await?;
            Ok(InputLookupOutcome {
                results,
                warnings: Vec::new(),
            })
        } else {
            // Enrichment mode: join fetched data with input results
            self.enrich_results(results, params).await
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> super::fetcher::CacheStats {
        self.fetcher.cache_stats()
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        self.fetcher.clear_cache();
    }

    /// Get the service configuration
    pub fn config(&self) -> &InputLookupConfig {
        &self.config
    }
}

/// Coerce a JSON value to its string join-key form (String / Number / Bool).
/// Other shapes (null, array, object) are not joinable keys.
fn value_as_key_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Build the user-facing message for an `| inputlookup <name>` against a missing
/// INTERNAL table. Mirrors the NAN-1389 `| lookup` missing-table message: names
/// the table and lists available tables (capped) when the registry can be read.
fn missing_internal_lookup_message(table_name: &str, available: &[String]) -> String {
    const MAX_LISTED: usize = 10;
    if available.is_empty() {
        format!(
            "inputlookup table '{}' does not exist and no lookup tables are defined. \
             Create the lookup table first, or remove the `| inputlookup {}` stage.",
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
            "inputlookup table '{}' does not exist. Available lookup tables: {}",
            table_name, listed
        )
    }
}

/// Create InputLookupParams from parsed query command parameters
pub fn params_from_command(
    url_template: &str,
    format: InputLookupFormat,
    key_field: Option<String>,
    timeout_secs: u32,
    max_rows: usize,
    cache_ttl_secs: u32,
) -> InputLookupParams {
    InputLookupParams {
        url: UrlTemplate::new(url_template),
        format,
        key_field,
        timeout_secs,
        max_rows,
        cache_ttl_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_service() -> InputLookupService {
        InputLookupService::new(InputLookupConfig {
            allow_http: true,
            ..Default::default()
        })
    }

    // ---- Internal lookup (`lookup://`) test scaffolding (NAN-1581 Phase 5) ----

    use crate::lookup::repository::{LookupRepositoryError, LookupStore, RuleReferenceRow};
    use crate::lookup::types::{LookupColumn, LookupTable, NewLookupTable};
    use crate::upload::ColumnType;
    use async_trait::async_trait;
    use std::collections::HashMap as StdHashMap;

    /// Minimal in-memory [`LookupStore`] for routing tests: only the registry +
    /// full-read methods used by `read_all_rows` are implemented; the rest panic
    /// (they must never be reached on the `lookup://` data-source path).
    struct FakeStore {
        /// logical name -> rows (each row already user-column-only + a `_row_id`
        /// internal column to prove it gets stripped).
        tables: StdHashMap<String, Vec<StdHashMap<String, Value>>>,
    }

    impl FakeStore {
        fn table_meta(name: &str) -> LookupTable {
            LookupTable {
                id: uuid::Uuid::new_v4(),
                name: name.to_string(),
                description: None,
                table_name: format!("lookup_{name}"),
                columns: vec![LookupColumn {
                    name: "host".to_string(),
                    data_type: ColumnType::Text,
                    nullable: false,
                }],
                primary_key: Some("host".to_string()),
                row_count: 0,
                size_bytes: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                created_by: None,
            }
        }
    }

    #[async_trait]
    impl LookupStore for FakeStore {
        async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError> {
            Ok(self.tables.keys().map(|n| Self::table_meta(n)).collect())
        }
        async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
            if self.tables.contains_key(name) {
                Ok(Self::table_meta(name))
            } else {
                Err(LookupRepositoryError::TableNotFound(name.to_string()))
            }
        }
        async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError> {
            Ok(self.tables.contains_key(name))
        }
        async fn list_rows(
            &self,
            table_name: &str,
            limit: i64,
            offset: i64,
        ) -> Result<(Vec<StdHashMap<String, Value>>, i64), LookupRepositoryError> {
            // physical name is `lookup_<logical>`; map back.
            let logical = table_name.strip_prefix("lookup_").unwrap_or(table_name);
            let rows = self.tables.get(logical).cloned().unwrap_or_default();
            let total = rows.len() as i64;
            let page = rows
                .into_iter()
                .skip(offset.max(0) as usize)
                .take(limit.max(0) as usize)
                .collect();
            Ok((page, total))
        }

        // --- everything below must never be hit on the lookup:// read path ---
        async fn register_table(
            &self,
            _: &NewLookupTable,
            _: &str,
            _: Option<uuid::Uuid>,
        ) -> Result<LookupTable, LookupRepositoryError> {
            unimplemented!()
        }
        async fn update_table_stats(
            &self,
            _: &str,
            _: i64,
            _: i64,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn unregister_table(&self, _: &str) -> Result<LookupTable, LookupRepositoryError> {
            unimplemented!()
        }
        async fn update_table_columns(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: Option<&str>,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn find_rules_referencing(
            &self,
            _: &str,
        ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn create_dynamic_table(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: Option<&str>,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn drop_dynamic_table(&self, _: &str) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn truncate_dynamic_table(&self, _: &str) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn swap_staged_table(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &[LookupColumn],
            _: Option<&str>,
            _: i64,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn insert_records(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: &[StdHashMap<String, Value>],
        ) -> Result<usize, LookupRepositoryError> {
            unimplemented!()
        }
        async fn get_table_row_count(&self, _: &str) -> Result<i64, LookupRepositoryError> {
            unimplemented!()
        }
        async fn get_table_size(&self, _: &str) -> Result<i64, LookupRepositoryError> {
            unimplemented!()
        }
        async fn lookup(
            &self,
            _: &str,
            _: &str,
            _: &Value,
            _: Option<&[String]>,
            _: bool,
        ) -> Result<Option<StdHashMap<String, Value>>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn lookup_batch(
            &self,
            _: &str,
            _: &str,
            _: &[Value],
            _: Option<&[String]>,
            _: bool,
        ) -> Result<StdHashMap<String, StdHashMap<String, Value>>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn sample_rows(
            &self,
            _: &str,
            _: i64,
        ) -> Result<Vec<StdHashMap<String, Value>>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn insert_row(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: &StdHashMap<String, Value>,
        ) -> Result<i64, LookupRepositoryError> {
            unimplemented!()
        }
        async fn update_row(
            &self,
            _: &str,
            _: i64,
            _: &[LookupColumn],
            _: &StdHashMap<String, Value>,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn delete_row(&self, _: &str, _: i64) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn delete_rows(&self, _: &str, _: &[i64]) -> Result<u64, LookupRepositoryError> {
            unimplemented!()
        }
    }

    fn service_with_lookup(store: FakeStore) -> InputLookupService {
        let lookup = Arc::new(LookupService::from_store(Arc::new(store)));
        InputLookupService::new(InputLookupConfig {
            allow_http: true,
            ..Default::default()
        })
        .with_lookup_service(lookup)
    }

    fn lookup_params(table: &str, key_field: Option<&str>) -> InputLookupParams {
        params_from_command(
            &format!("lookup://{table}"),
            InputLookupFormat::Json,
            key_field.map(str::to_string),
            30,
            10000,
            0,
        )
    }

    /// `lookup://my_table` (data-source mode) routes to the internal lookup
    /// layer, reads ALL rows, and strips internal columns (`_row_id`).
    #[tokio::test]
    async fn lookup_url_reads_internal_table_and_strips_internal_columns() {
        let mut tables = StdHashMap::new();
        tables.insert(
            "my_table".to_string(),
            vec![
                {
                    let mut r = StdHashMap::new();
                    r.insert("host".to_string(), json!("web01"));
                    r.insert("_row_id".to_string(), json!(1)); // internal — must be stripped
                    r
                },
                {
                    let mut r = StdHashMap::new();
                    r.insert("host".to_string(), json!("web02"));
                    r.insert("_row_id".to_string(), json!(2));
                    r
                },
            ],
        );
        let service = service_with_lookup(FakeStore { tables });

        let outcome = service
            .execute(vec![], &lookup_params("my_table", None))
            .await
            .expect("internal lookup data-source read should succeed");

        assert_eq!(outcome.results.len(), 2);
        for row in &outcome.results {
            let obj = row.as_object().unwrap();
            assert!(obj.contains_key("host"), "user column present: {obj:?}");
            assert!(
                !obj.contains_key("_row_id"),
                "internal _row_id must be stripped: {obj:?}"
            );
        }
    }

    /// An unknown internal table yields a clear error naming the table and the
    /// available tables — never a silent HTTP attempt.
    #[tokio::test]
    async fn lookup_url_unknown_table_is_a_clear_error() {
        let mut tables = StdHashMap::new();
        tables.insert("assets".to_string(), Vec::new());
        tables.insert("threat_actors".to_string(), Vec::new());
        let service = service_with_lookup(FakeStore { tables });

        let err = service
            .execute(vec![], &lookup_params("asets", None))
            .await
            .expect_err("unknown internal table must error");
        match err {
            InputLookupError::LookupTableNotFound(msg) => {
                assert!(msg.contains("'asets'"), "names the table: {msg}");
                assert!(
                    msg.contains("assets") && msg.contains("threat_actors"),
                    "lists available tables: {msg}"
                );
            }
            other => panic!("expected LookupTableNotFound, got {other:?}"),
        }
    }

    /// A `lookup://` URL with no lookup service wired errors clearly instead of
    /// silently falling through to the HTTP fetcher.
    #[tokio::test]
    async fn lookup_url_without_service_errors_not_http() {
        let service = test_service(); // no lookup service
        let err = service
            .execute(vec![], &lookup_params("my_table", None))
            .await
            .expect_err("lookup:// with no service must error");
        assert!(
            matches!(err, InputLookupError::LookupServiceUnavailable(t) if t == "my_table"),
            "expected LookupServiceUnavailable"
        );
    }

    /// Enrichment mode (`lookup://my_table key=host`) joins internal rows onto
    /// input rows by the key field with the `inputlookup_` prefix.
    #[tokio::test]
    async fn lookup_url_enrichment_mode_joins_on_key() {
        let mut tables = StdHashMap::new();
        tables.insert(
            "my_table".to_string(),
            vec![{
                let mut r = StdHashMap::new();
                r.insert("host".to_string(), json!("web01"));
                r.insert("owner".to_string(), json!("alice"));
                r.insert("_row_id".to_string(), json!(1));
                r
            }],
        );
        let service = service_with_lookup(FakeStore { tables });

        let outcome = service
            .execute(
                vec![json!({"host": "web01"}), json!({"host": "web99"})],
                &lookup_params("my_table", Some("host")),
            )
            .await
            .expect("enrichment-mode internal lookup should succeed");

        assert_eq!(outcome.results[0]["inputlookup_owner"], json!("alice"));
        // internal columns never leak even through enrichment
        assert!(outcome.results[0].get("inputlookup__row_id").is_none());
        // unmatched row is untouched
        assert!(outcome.results[1].get("inputlookup_owner").is_none());
    }

    /// A real `https://` URL still routes to the SSRF-guarded fetcher even when a
    /// lookup service is wired (proven by the private-IP SSRF rejection).
    #[tokio::test]
    async fn https_url_still_uses_fetcher_when_lookup_wired() {
        let service = service_with_lookup(FakeStore {
            tables: StdHashMap::new(),
        });
        let params = params_from_command(
            "https://10.255.255.1/feed.csv",
            InputLookupFormat::Csv,
            None,
            1,
            100,
            0,
        );
        let err = service
            .execute(vec![], &params)
            .await
            .expect_err("https private IP must be SSRF-rejected by the fetcher");
        assert!(
            matches!(err, InputLookupError::FetchError(_)),
            "real https URL must go through the fetcher, got {err:?}"
        );
    }

    #[test]
    fn test_params_from_command() {
        let params = params_from_command(
            "https://api.example.com/{ip}/json",
            InputLookupFormat::Json,
            Some("src_ip".to_string()),
            30,
            10000,
            300,
        );

        assert!(params.is_enrichment_mode());
        assert!(!params.is_data_source_mode());
        assert_eq!(params.url.fields, vec!["ip"]);
    }

    #[test]
    fn test_params_data_source_mode() {
        let params = params_from_command(
            "https://feeds.example.com/iocs.csv",
            InputLookupFormat::Csv,
            None,
            30,
            10000,
            300,
        );

        assert!(params.is_data_source_mode());
        assert!(!params.is_enrichment_mode());
        assert!(!params.url.has_placeholders());
    }

    #[tokio::test]
    async fn test_enrich_results_missing_key() {
        let service = test_service();
        let results = vec![json!({"other_field": "value"})];
        let params = params_from_command(
            "https://api.example.com/{ip}",
            InputLookupFormat::Json,
            Some("src_ip".to_string()),
            30,
            100,
            0,
        );

        // Should return original results when key field not found
        let outcome = service
            .enrich_results(results.clone(), &params)
            .await
            .unwrap();
        assert_eq!(outcome.results.len(), 1);
        assert_eq!(outcome.results[0]["other_field"], "value");
        assert!(outcome.warnings.is_empty());
    }

    /// NAN-1389 regression: when every enrichment fetch fails, the inputlookup
    /// must surface an error instead of returning the rows silently
    /// un-enriched. The default SSRF guard blocks private addresses, so a
    /// 10.x target fails synchronously without touching the network.
    #[tokio::test]
    async fn test_enrich_results_all_fetches_failed_is_an_error() {
        let service = test_service();
        let results = vec![json!({"src_ip": "1.2.3.4"})];
        let params = params_from_command(
            "https://10.255.255.1/{src_ip}",
            InputLookupFormat::Json,
            Some("src_ip".to_string()),
            1,
            100,
            0,
        );

        let err = service
            .enrich_results(results, &params)
            .await
            .expect_err("all fetches failed — must be an error, not a silent 200");
        match err {
            InputLookupError::AllFetchesFailed { attempted, .. } => assert_eq!(attempted, 1),
            other => panic!("expected AllFetchesFailed, got: {other:?}"),
        }
    }

    /// NAN-1389 regression: a failed data-source fetch must bubble out of
    /// `execute` (previously the caller swallowed it and returned the raw log
    /// rows in place of the requested external data).
    #[tokio::test]
    async fn test_execute_data_source_fetch_failure_is_an_error() {
        let service = test_service();
        let params = params_from_command(
            "https://10.255.255.1/feed.csv",
            InputLookupFormat::Csv,
            None,
            1,
            100,
            0,
        );

        let err = service
            .execute(vec![json!({"src_ip": "1.2.3.4"})], &params)
            .await
            .expect_err("data-source fetch failure must be an error");
        assert!(matches!(err, InputLookupError::FetchError(_)));
    }
}
