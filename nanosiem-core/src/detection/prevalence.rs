// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Condition Evaluation for Detection Rules
//!
//! This module provides functionality to evaluate prevalence-based conditions
//! in detection rules. It integrates with the PrevalenceService to query
//! real-time prevalence data and filter/enrich detection results.
//!
//! Supports conditions like:
//! - `hash_prevalence < 5` - Filter to hashes seen on fewer than 5 hosts
//! - `domain_first_seen > now() - 24h` - Filter to newly observed domains
//!
//! Requirements: 6.1, 6.2, 6.3, 6.4, 6.5

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::prevalence::{PrevalenceData, PrevalenceError, PrevalenceService, TimeWindow};
use crate::query::{
    Command, PrevalenceField, PrevalenceOperator, PrevalenceThreshold, PrevalenceTimeWindow, Query,
};

/// Prevalence context to be included in alerts
///
/// Contains prevalence information for artifacts found in matched events.
/// This is added to alert metadata when prevalence-based rules match.
///
/// Requirements: 6.5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrevalenceContext {
    /// Prevalence data for file hashes found in the matched events
    pub hash_prevalence: Vec<ArtifactPrevalenceInfo>,
    /// Prevalence data for domains found in the matched events
    pub domain_prevalence: Vec<ArtifactPrevalenceInfo>,
}

impl PrevalenceContext {
    /// Create an empty prevalence context
    pub fn empty() -> Self {
        Self {
            hash_prevalence: Vec::new(),
            domain_prevalence: Vec::new(),
        }
    }

    /// Check if the context has any prevalence data
    pub fn is_empty(&self) -> bool {
        self.hash_prevalence.is_empty() && self.domain_prevalence.is_empty()
    }

    /// Convert to JSON value for inclusion in alert metadata
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hash_prevalence": self.hash_prevalence,
            "domain_prevalence": self.domain_prevalence
        })
    }
}

/// Prevalence information for a single artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPrevalenceInfo {
    /// The artifact value (hash or domain)
    pub artifact: String,
    /// Type of artifact
    pub artifact_type: String,
    /// Number of unique hosts that have seen this artifact
    pub host_count: u64,
    /// First time this artifact was observed
    pub first_seen: DateTime<Utc>,
    /// Last time this artifact was observed
    pub last_seen: DateTime<Utc>,
    /// Whether this artifact is considered rare
    pub is_rare: bool,
    /// Prevalence score (0-100, lower = rarer)
    pub prevalence_score: u8,
}

impl From<PrevalenceData> for ArtifactPrevalenceInfo {
    fn from(data: PrevalenceData) -> Self {
        Self {
            artifact: data.artifact,
            artifact_type: data.artifact_type.to_string(),
            host_count: data.host_count,
            first_seen: data.first_seen,
            last_seen: data.last_seen,
            is_rare: data.is_rare,
            prevalence_score: data.prevalence_score,
        }
    }
}

/// Information about a prevalence condition extracted from a detection rule query
#[derive(Debug, Clone)]
pub struct PrevalenceCondition {
    /// Field to check (hash_prevalence, domain_prevalence, hash_first_seen, domain_first_seen)
    pub field: PrevalenceField,
    /// Comparison operator
    pub operator: PrevalenceOperator,
    /// Threshold value
    pub threshold: PrevalenceThreshold,
    /// Time window for prevalence calculation
    pub time_window: TimeWindow,
}

impl PrevalenceCondition {
    /// Create a new prevalence condition
    pub fn new(
        field: PrevalenceField,
        operator: PrevalenceOperator,
        threshold: PrevalenceThreshold,
        time_window: Option<PrevalenceTimeWindow>,
    ) -> Self {
        Self {
            field,
            operator,
            threshold,
            time_window: ast_time_window_to_service(time_window),
        }
    }
}

/// Convert AST time window to service time window
fn ast_time_window_to_service(ast_tw: Option<PrevalenceTimeWindow>) -> TimeWindow {
    match ast_tw {
        Some(PrevalenceTimeWindow::OneHour) => TimeWindow::OneHour,
        Some(PrevalenceTimeWindow::TwentyFourHours) => TimeWindow::TwentyFourHours,
        Some(PrevalenceTimeWindow::SevenDays) => TimeWindow::SevenDays,
        Some(PrevalenceTimeWindow::ThirtyDays) => TimeWindow::ThirtyDays,
        None => TimeWindow::TwentyFourHours, // Default
    }
}

/// Extract prevalence conditions from a parsed query
///
/// Recursively traverses the query AST to find all prevalence commands
/// that have filtering conditions (not just enrichment mode).
pub fn extract_prevalence_conditions(query: &Query) -> Vec<PrevalenceCondition> {
    let mut conditions = Vec::new();
    extract_prevalence_conditions_recursive(query, &mut conditions);
    conditions
}

fn extract_prevalence_conditions_recursive(
    query: &Query,
    conditions: &mut Vec<PrevalenceCondition>,
) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // First process the source
            extract_prevalence_conditions_recursive(source, conditions);

            // Then check if this command is a prevalence command with filtering
            if let Command::Prevalence {
                conditions: ast_conditions,
                time_window,
                enrich: _,
            } = command
            {
                // Convert each AST condition to a runtime PrevalenceCondition
                for ast_cond in ast_conditions {
                    conditions.push(PrevalenceCondition::new(
                        ast_cond.field,
                        ast_cond.operator,
                        ast_cond.threshold.clone(),
                        *time_window,
                    ));
                }
            }
        }
    }
}

/// Check if a query contains any prevalence conditions
pub fn has_prevalence_conditions(query: &Query) -> bool {
    !extract_prevalence_conditions(query).is_empty()
}

/// Evaluator for prevalence conditions in detection rules
///
/// This struct provides methods to evaluate prevalence-based conditions
/// against search results and to enrich alerts with prevalence context.
pub struct PrevalenceEvaluator {
    service: PrevalenceService,
}

impl PrevalenceEvaluator {
    /// Create a new prevalence evaluator
    pub fn new(service: PrevalenceService) -> Self {
        Self { service }
    }

    /// Evaluate prevalence conditions against a set of events
    ///
    /// Returns the events that satisfy all prevalence conditions.
    ///
    /// Requirements: 6.1, 6.2
    pub async fn evaluate_conditions(
        &self,
        events: Vec<serde_json::Value>,
        conditions: &[PrevalenceCondition],
    ) -> Result<Vec<serde_json::Value>, PrevalenceError> {
        if conditions.is_empty() || events.is_empty() {
            return Ok(events);
        }

        let mut filtered_events = events;

        for condition in conditions {
            filtered_events = self.apply_condition(filtered_events, condition).await?;
        }

        Ok(filtered_events)
    }

    /// Apply a single prevalence condition to filter events
    async fn apply_condition(
        &self,
        events: Vec<serde_json::Value>,
        condition: &PrevalenceCondition,
    ) -> Result<Vec<serde_json::Value>, PrevalenceError> {
        if events.is_empty() {
            return Ok(events);
        }

        // Determine which field to extract based on the condition. The
        // dict-based service routes by artifact kind internally, so we no
        // longer need to thread is_hash through to `get_prevalence_map`.
        let field_name = match condition.field {
            PrevalenceField::HashPrevalence | PrevalenceField::HashFirstSeen => "file_hash",
            PrevalenceField::DomainPrevalence | PrevalenceField::DomainFirstSeen => "dest_host",
        };

        // Extract unique artifacts from events
        let artifacts: Vec<String> = events
            .iter()
            .filter_map(|event| extract_field_value(event, field_name))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if artifacts.is_empty() {
            debug!(
                "No {} values found in events for prevalence filtering",
                field_name
            );
            return Ok(events);
        }

        // Query prevalence for all artifacts
        let prevalence_map = self
            .get_prevalence_map(&artifacts, condition.time_window)
            .await?;

        // Filter events based on the condition
        let original_count = events.len();
        let filtered: Vec<serde_json::Value> = events
            .into_iter()
            .filter(|event| {
                if let Some(artifact) = extract_field_value(event, field_name) {
                    // Dict-based map keys are lowercase for hash/domain
                    // (the only kinds this filter handles).
                    if let Some(prevalence) = prevalence_map.get(&artifact.to_lowercase()) {
                        return self.evaluate_single_condition(prevalence, condition);
                    }
                }
                // If no artifact or prevalence data, include the event
                // (conservative approach - don't filter out events we can't evaluate)
                true
            })
            .collect();

        debug!(
            "Prevalence filter: {} events -> {} events (condition: {} {} {:?})",
            original_count,
            filtered.len(),
            condition.field.as_str(),
            condition.operator.as_str(),
            condition.threshold
        );

        Ok(filtered)
    }

    /// Get prevalence data for a list of artifacts.
    ///
    /// NAN-701: Previously chunked artifacts by 100 but inside each chunk
    /// looped per-artifact calling the *singular* `get_hash_prevalence` /
    /// `get_domain_prevalence` — one CH round trip per artifact. Now uses
    /// `get_bulk_prevalence_via_dict`, which categorizes by artifact kind
    /// internally (via `ArtifactType::detect`) and issues one dict query
    /// per kind, regardless of N.
    ///
    /// Map keys are lowercase for hash/domain (matching dict storage); the
    /// caller in `apply_condition` lowercases lookups to match.
    async fn get_prevalence_map(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
    ) -> Result<HashMap<String, PrevalenceData>, PrevalenceError> {
        let mut map = HashMap::new();
        if artifacts.is_empty() {
            return Ok(map);
        }
        let data = self
            .service
            .get_bulk_prevalence_via_dict(artifacts, time_window)
            .await?;
        for d in data {
            map.insert(d.artifact.clone(), d);
        }
        Ok(map)
    }

    /// Evaluate a single prevalence condition against prevalence data
    fn evaluate_single_condition(
        &self,
        prevalence: &PrevalenceData,
        condition: &PrevalenceCondition,
    ) -> bool {
        match (&condition.field, &condition.threshold) {
            // Count-based conditions (hash_prevalence, domain_prevalence)
            (
                PrevalenceField::HashPrevalence | PrevalenceField::DomainPrevalence,
                PrevalenceThreshold::Count(threshold),
            ) => {
                let count = prevalence.host_count;
                match condition.operator {
                    PrevalenceOperator::Lt => count < *threshold,
                    PrevalenceOperator::Lte => count <= *threshold,
                    PrevalenceOperator::Gt => count > *threshold,
                    PrevalenceOperator::Gte => count >= *threshold,
                    PrevalenceOperator::Eq => count == *threshold,
                    PrevalenceOperator::Ne => count != *threshold,
                }
            }
            // Timestamp-based conditions (hash_first_seen, domain_first_seen)
            (
                PrevalenceField::HashFirstSeen | PrevalenceField::DomainFirstSeen,
                PrevalenceThreshold::Duration(duration),
            ) => {
                let threshold_time = Utc::now() - Duration::from_std(*duration).unwrap_or_default();
                let first_seen = prevalence.first_seen;
                match condition.operator {
                    PrevalenceOperator::Lt => first_seen < threshold_time,
                    PrevalenceOperator::Lte => first_seen <= threshold_time,
                    PrevalenceOperator::Gt => first_seen > threshold_time,
                    PrevalenceOperator::Gte => first_seen >= threshold_time,
                    PrevalenceOperator::Eq => {
                        // For timestamps, equality is approximate (within 1 second)
                        (first_seen - threshold_time).num_seconds().abs() < 1
                    }
                    PrevalenceOperator::Ne => {
                        (first_seen - threshold_time).num_seconds().abs() >= 1
                    }
                }
            }
            // Mismatched threshold type - shouldn't happen with proper parsing
            _ => {
                warn!(
                    "Mismatched prevalence condition: field={:?}, threshold={:?}",
                    condition.field, condition.threshold
                );
                true // Don't filter on invalid conditions
            }
        }
    }

    /// Build prevalence context for matched events
    ///
    /// Extracts file hashes and domains from the events and queries
    /// their prevalence data to include in the alert.
    ///
    /// Requirements: 6.5
    pub async fn build_prevalence_context(
        &self,
        events: &[serde_json::Value],
        time_window: TimeWindow,
    ) -> Result<PrevalenceContext, PrevalenceError> {
        let mut context = PrevalenceContext::empty();

        // Extract unique file hashes
        let hashes: Vec<String> = events
            .iter()
            .filter_map(|event| extract_field_value(event, "file_hash"))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Extract unique domains
        let domains: Vec<String> = events
            .iter()
            .filter_map(|event| extract_field_value(event, "dest_host"))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // NAN-701: One dict-based call covers both hash and domain. The
        // service categorizes via `ArtifactType::detect`; we re-split into
        // the right context vec on the way out.
        let mut combined: Vec<String> = Vec::with_capacity(hashes.len() + domains.len());
        combined.extend(hashes.iter().cloned());
        combined.extend(domains.iter().cloned());

        if !combined.is_empty() {
            match self
                .service
                .get_bulk_prevalence_via_dict(&combined, time_window)
                .await
            {
                Ok(data) => {
                    for d in data {
                        if d.artifact_type.is_hash() {
                            context
                                .hash_prevalence
                                .push(ArtifactPrevalenceInfo::from(d));
                        } else if d.artifact_type.is_domain() {
                            context
                                .domain_prevalence
                                .push(ArtifactPrevalenceInfo::from(d));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get bulk prevalence for alert context: {}", e);
                }
            }
        }

        Ok(context)
    }
}

/// Extract a string field value from a JSON event
fn extract_field_value(event: &serde_json::Value, field: &str) -> Option<String> {
    // Support dot notation for nested fields
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = event;

    for part in parts {
        match current.get(part) {
            Some(v) => current = v,
            None => return None,
        }
    }

    match current {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_extract_prevalence_conditions_hash_filter() {
        let query = parse_query("file_hash=* | prevalence hash_prevalence < 5").unwrap();
        let conditions = extract_prevalence_conditions(&query);

        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].field, PrevalenceField::HashPrevalence);
        assert_eq!(conditions[0].operator, PrevalenceOperator::Lt);
        assert!(matches!(
            conditions[0].threshold,
            PrevalenceThreshold::Count(5)
        ));
    }

    #[test]
    fn test_extract_prevalence_conditions_domain_first_seen() {
        let query =
            parse_query("dest_host=* | prevalence domain_first_seen > now() - 24h").unwrap();
        let conditions = extract_prevalence_conditions(&query);

        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].field, PrevalenceField::DomainFirstSeen);
        assert_eq!(conditions[0].operator, PrevalenceOperator::Gt);
        assert!(matches!(
            conditions[0].threshold,
            PrevalenceThreshold::Duration(_)
        ));
    }

    #[test]
    fn test_extract_prevalence_conditions_with_window() {
        let query = parse_query("file_hash=* | prevalence hash_prevalence < 3 window=7d").unwrap();
        let conditions = extract_prevalence_conditions(&query);

        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].time_window, TimeWindow::SevenDays);
    }

    #[test]
    fn test_extract_prevalence_conditions_enrichment_only() {
        // Enrichment mode should not create conditions
        let query = parse_query("file_hash=* | prevalence enrich=true").unwrap();
        let conditions = extract_prevalence_conditions(&query);

        assert!(conditions.is_empty());
    }

    #[test]
    fn test_extract_prevalence_conditions_multiple() {
        let query = parse_query(
            "file_hash=* | prevalence hash_prevalence < 5 | prevalence domain_prevalence < 10",
        )
        .unwrap();
        let conditions = extract_prevalence_conditions(&query);

        assert_eq!(conditions.len(), 2);
    }

    #[test]
    fn test_has_prevalence_conditions() {
        let query_with = parse_query("file_hash=* | prevalence hash_prevalence < 5").unwrap();
        let query_without = parse_query("file_hash=* | stats count()").unwrap();
        let query_enrich = parse_query("file_hash=* | prevalence enrich=true").unwrap();

        assert!(has_prevalence_conditions(&query_with));
        assert!(!has_prevalence_conditions(&query_without));
        assert!(!has_prevalence_conditions(&query_enrich));
    }

    #[test]
    fn test_extract_field_value() {
        let event = serde_json::json!({
            "file_hash": "abc123",
            "dest_host": "example.com",
            "nested": {
                "field": "value"
            }
        });

        assert_eq!(
            extract_field_value(&event, "file_hash"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_field_value(&event, "dest_host"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_field_value(&event, "nested.field"),
            Some("value".to_string())
        );
        assert_eq!(extract_field_value(&event, "missing"), None);
    }

    #[test]
    fn test_prevalence_context_empty() {
        let context = PrevalenceContext::empty();
        assert!(context.is_empty());
    }

    #[test]
    fn test_artifact_prevalence_info_from_data() {
        use crate::prevalence::ArtifactType;

        let data = PrevalenceData {
            artifact: "abc123".to_string(),
            artifact_type: ArtifactType::HashMd5,
            host_count: 5,
            total_occurrences: 10,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            is_rare: false,
            prevalence_score: 50,
        };

        let info = ArtifactPrevalenceInfo::from(data);
        assert_eq!(info.artifact, "abc123");
        assert_eq!(info.host_count, 5);
        assert!(!info.is_rare);
    }
}
