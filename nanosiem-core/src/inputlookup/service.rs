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
use crate::query::{InputLookupFormat, UrlTemplate};

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
}

/// Result of an inputlookup execution: the (possibly enriched) rows plus any
/// non-fatal warnings — e.g. a subset of per-key enrichment fetches failed and
/// the affected rows are un-enriched (NAN-1389).
#[derive(Debug)]
pub struct InputLookupOutcome {
    pub results: Vec<Value>,
    pub warnings: Vec<String>,
}

/// InputLookup service for URL-based data fetching and enrichment
#[derive(Clone)]
pub struct InputLookupService {
    fetcher: Arc<UrlFetcher>,
    config: InputLookupConfig,
}

impl InputLookupService {
    /// Create a new InputLookup service with the given configuration
    pub fn new(config: InputLookupConfig) -> Self {
        let fetcher = Arc::new(UrlFetcher::new(config.clone()));
        Self { fetcher, config }
    }

    /// Execute an inputlookup command in data source mode
    ///
    /// Fetches the URL and returns the parsed rows as search results.
    pub async fn fetch_data_source(
        &self,
        params: &InputLookupParams,
    ) -> Result<Vec<Value>, InputLookupError> {
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
