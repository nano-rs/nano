// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helpers and Utilities
//!
//! Entity grouping, event deduplication, detection match storage,
//! query/cron validation, and version management.

use chrono::{DateTime, Utc};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{DetectionRule, NewDetectionRule, RuleMode};
use crate::query::parse_query;

use super::DetectionError;
use super::DetectionService;

/// Inject `_nano_detected_at` into each matched event so the frontend can always
/// compute detection latency regardless of whether the event has a timestamp field.
pub(crate) fn inject_detected_at(events: &mut [serde_json::Value], detected_at: DateTime<Utc>) {
    let detected_at_str = detected_at.to_rfc3339();
    for event in events.iter_mut() {
        if let Some(obj) = event.as_object_mut() {
            obj.insert(
                "_nano_detected_at".to_string(),
                serde_json::Value::String(detected_at_str.clone()),
            );
        }
    }
}

impl DetectionService {
    // ========================================================================
    // Entity Grouping Helpers
    // ========================================================================

    /// Filter out events that have already been matched by this rule
    ///
    /// This prevents re-detection when rules have long lookback windows that overlap
    /// with previous runs. For example, a rule running every 10 seconds with a 15-minute
    /// lookback would otherwise re-detect the same events 90 times.
    ///
    /// This function:
    /// 1. Extracts event IDs from the results
    /// 2. Queries the detection_matched_events table to find which ones were already matched
    /// 3. Filters out the already-matched events
    /// 4. Records the new events as matched
    ///
    /// Returns only the events that haven't been matched before.
    pub(super) async fn filter_already_matched_events(
        &self,
        rule_id: Uuid,
        events: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // Extract event IDs and timestamps from events
        let mut event_ids = Vec::new();
        let mut event_map = std::collections::HashMap::new();

        for event in events {
            // Try to get a unique ID for this event
            // Priority: log_id > id > compute hash from event
            let event_id = if let Some(log_id) = event.get("log_id").and_then(|v| v.as_str()) {
                log_id.to_string()
            } else if let Some(id) = event.get("id").and_then(|v| v.as_str()) {
                id.to_string()
            } else {
                // Compute a hash of the event as fallback
                use sha2::{Digest, Sha256};
                let event_str = serde_json::to_string(event).unwrap_or_default();
                let hash = Sha256::digest(event_str.as_bytes());
                hex::encode(hash)
            };

            event_ids.push(event_id.clone());
            event_map.insert(event_id, event.clone());
        }

        // Query which events have already been matched
        let already_matched: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT event_id
            FROM detection_matched_events
            WHERE rule_id = $1 AND event_id = ANY($2)
            "#,
        )
        .bind(rule_id)
        .bind(&event_ids)
        .fetch_all(&self.pg_pool)
        .await
        .unwrap_or_else(|e| {
            // If query fails (e.g., table doesn't exist yet), log warning and continue
            warn!(
                "Failed to query detection_matched_events: {}. Deduplication disabled.",
                e
            );
            Vec::new()
        });

        // Filter out already-matched events
        let already_matched_set: std::collections::HashSet<_> =
            already_matched.into_iter().collect();
        let new_events: Vec<_> = event_map
            .into_iter()
            .filter(|(id, _)| !already_matched_set.contains(id))
            .collect();

        // Record the new events as matched
        if !new_events.is_empty() {
            if let Err(e) = self.record_matched_events(rule_id, &new_events).await {
                // Log error but don't fail the detection
                warn!(
                    "Failed to record matched events: {}. Events may be re-detected.",
                    e
                );
            }
        }

        Ok(new_events.into_iter().map(|(_, event)| event).collect())
    }

    /// Record events as matched by a rule to prevent re-detection
    async fn record_matched_events(
        &self,
        rule_id: Uuid,
        events: &[(String, serde_json::Value)],
    ) -> Result<(), DetectionError> {
        if events.is_empty() {
            return Ok(());
        }

        // Build bulk insert query
        let mut query_builder = sqlx::QueryBuilder::new(
            "INSERT INTO detection_matched_events (rule_id, event_id, event_timestamp) ",
        );

        query_builder.push_values(events, |mut b, (event_id, event)| {
            // Extract timestamp from event
            let timestamp = event
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);

            b.push_bind(rule_id)
                .push_bind(event_id)
                .push_bind(timestamp);
        });

        query_builder.push(" ON CONFLICT (rule_id, event_id) DO NOTHING");

        query_builder
            .build()
            .execute(&self.pg_pool)
            .await
            .map_err(|e| DetectionError::DatabaseError(e))?;

        Ok(())
    }

    /// Store a detection match for review (used in both live and alerting modes)
    /// This allows users to see what actually matched when rules were running
    ///
    /// Uses event hash deduplication to prevent storing the same events multiple times
    /// when a rule runs frequently with a long lookback window.
    pub(super) async fn store_detection_match(
        &self,
        rule: &DetectionRule,
        events: &[serde_json::Value],
    ) -> Result<(), DetectionError> {
        let event_count = events.len() as i32;
        let severity_str = format!("{:?}", rule.severity).to_lowercase();
        let matched_events = serde_json::Value::Array(events.to_vec());

        // Compute event hash for deduplication
        let event_hash = crate::db::repository::compute_event_hash(&matched_events);

        // Try to insert, but ignore if duplicate (same rule_id + event_hash)
        // This prevents storing the same match multiple times when a rule runs
        // frequently with a long lookback window
        let result = sqlx::query(
            r#"
            INSERT INTO detection_matches (rule_id, rule_name, severity, matched_events, event_count, event_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (rule_id, event_hash) DO NOTHING
            "#
        )
        .bind(rule.id)
        .bind(&rule.name)
        .bind(severity_str)
        .bind(matched_events)
        .bind(event_count)
        .bind(&event_hash)
        .execute(&self.pg_pool)
        .await?;

        if result.rows_affected() == 0 {
            tracing::debug!(
                "Skipped duplicate detection match for rule {} with event_hash {}",
                rule.name,
                event_hash
            );
        }

        Ok(())
    }

    /// Group events by entity value for per-entity risk scoring
    ///
    /// When a detection rule matches multiple events, we need to create separate
    /// signals for each unique entity so that each entity gets its own risk score.
    ///
    /// If entity_field is specified, groups by that field only.
    /// If entity_field is None (auto-detect), extracts ALL entities from each event
    /// and creates a group for each unique entity value found.
    ///
    /// Returns: HashMap<(entity_value, field_name), events>
    pub(super) fn group_events_by_entity(
        &self,
        entity_field: Option<&str>,
        events: &[serde_json::Value],
    ) -> std::collections::HashMap<(String, String), Vec<serde_json::Value>> {
        use std::collections::HashMap;

        let mut grouped: HashMap<(String, String), Vec<serde_json::Value>> = HashMap::new();

        match entity_field {
            Some(field) => {
                // Specific field: group by that field only
                for event in events {
                    let entity = Self::get_string_field_from_event(event, field)
                        .unwrap_or_else(|| "unknown".to_string());
                    let key = (entity, field.to_string());
                    grouped.entry(key).or_default().push(event.clone());
                }
            }
            None => {
                // Auto-detect: Extract ALL entities from each event
                // This ensures every entity in the event gets risk scored
                let common_fields = [
                    // IP addresses
                    "src_ip",
                    "dest_ip",
                    "dvc_ip",
                    "src_translated_ip",
                    "dest_translated_ip",
                    // Hostnames
                    "src_host",
                    "dest_host",
                    "host",
                    "hostname",
                    "dest_nt_host",
                    "src_nt_host",
                    "dvc",
                    // Users
                    "src_user",
                    "dest_user",
                    "user",
                    "src_user_name",
                    "dest_user_name",
                    // File hashes
                    "file_hash",
                    "process_hash",
                    "service_hash",
                    "service_dll_hash",
                    "ssl_hash",
                ];

                for event in events {
                    let mut found_any = false;

                    // Extract ALL entity values from this event
                    for field in &common_fields {
                        if let Some(entity_value) = Self::get_string_field_from_event(event, field)
                        {
                            debug!(
                                "Auto-detect: Found entity '{}' in field '{}'",
                                entity_value, field
                            );
                            let key = (entity_value, field.to_string());
                            grouped.entry(key).or_default().push(event.clone());
                            found_any = true;
                        }
                    }

                    // If no entities found, add to "unknown" group
                    if !found_any {
                        let key = ("unknown".to_string(), "unknown".to_string());
                        grouped.entry(key).or_default().push(event.clone());
                    }
                }
            }
        }

        grouped
    }

    /// Get a string field value from an event (supports dot notation)
    fn get_string_field_from_event(event: &serde_json::Value, field: &str) -> Option<String> {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = event;

        for part in parts {
            match current.get(part) {
                Some(v) => current = v,
                None => return None,
            }
        }

        match current {
            serde_json::Value::String(s) => {
                // Filter out empty strings - treat them as missing values
                if s.is_empty() {
                    None
                } else {
                    Some(s.clone())
                }
            }
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    // ========================================================================
    // Validation Helpers
    // ========================================================================

    /// Validate a piped query syntax
    pub(super) fn validate_query(&self, query: &str) -> Result<(), DetectionError> {
        parse_query(query).map_err(|e| DetectionError::QueryParseError(e.to_string()))?;
        Ok(())
    }

    /// Validate that a rule is compatible with real-time execution
    ///
    /// Real-time rules are implemented using ClickHouse materialized views,
    /// which have the following limitations:
    /// - No aggregations (stats, timechart, top, rare, transaction)
    /// - No joins (lookup, append, transaction)
    /// - risk_entity_field is optional (auto-detects from query or defaults to src_ip)
    ///
    /// Requirements: 5.2
    pub fn validate_realtime_rule(&self, rule: &NewDetectionRule) -> Result<(), DetectionError> {
        Self::validate_realtime_rule_static(rule)
    }

    /// Static version of validate_realtime_rule for testing
    pub(super) fn validate_realtime_rule_static(
        rule: &NewDetectionRule,
    ) -> Result<(), DetectionError> {
        // Parse the query
        let query =
            parse_query(&rule.query).map_err(|e| DetectionError::QueryParseError(e.to_string()))?;

        // Check for aggregations
        if crate::query::contains_aggregation(&query) {
            return Err(DetectionError::InvalidRealtimeRule(
                "Real-time rules cannot contain aggregations (stats, timechart, top, rare, transaction). \
                 Use scheduled mode for aggregation-based detections.".to_string()
            ));
        }

        // Check for joins
        if crate::query::contains_join(&query) {
            return Err(DetectionError::InvalidRealtimeRule(
                "Real-time rules cannot contain joins (lookup, append, transaction). \
                 Use scheduled mode for correlation-based detections."
                    .to_string(),
            ));
        }

        // risk_entity_field is optional - will auto-detect if not specified (defaults to src_ip)

        Ok(())
    }

    /// Validate a cron expression using the cron crate
    pub(super) fn validate_cron(&self, cron: &str) -> Result<(), DetectionError> {
        super::super::scheduler::validate_cron_expression(cron)
    }

    /// Create a version entry for a rule update
    ///
    /// This is called after successful rule updates to track version history.
    /// If version creation fails, it logs a warning but doesn't fail the update.
    pub(super) async fn create_version_entry(
        &self,
        rule: &DetectionRule,
        created_by: Option<Uuid>,
        change_reason: &str,
        tuning_proposal_id: Option<i32>,
    ) {
        use crate::tuning::types::RuleVersion;
        use chrono::Utc;

        // Create version entry with placeholder values for auto-generated fields
        // The version_manager will handle version_number calculation
        let severity_str = match rule.severity {
            crate::models::detection_rule::Severity::Critical => "critical",
            crate::models::detection_rule::Severity::High => "high",
            crate::models::detection_rule::Severity::Medium => "medium",
            crate::models::detection_rule::Severity::Low => "low",
            crate::models::detection_rule::Severity::Informational => "informational",
        };

        let version = RuleVersion {
            id: 0, // Will be set by database
            rule_id: rule.id,
            version_number: 0, // Will be calculated by create_version
            query: rule.query.clone(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            severity: severity_str.to_string(),
            enabled: rule.mode != RuleMode::Paused && rule.mode != RuleMode::Staging,
            is_active: true,
            created_at: Utc::now(), // Will be set by database
            created_by,
            change_reason: change_reason.to_string(),
            tuning_proposal_id: tuning_proposal_id.map(|id| Uuid::from_u128(id as u128)),
            reverted_from_version: None,
        };

        match self.version_manager.create_version(version).await {
            Ok(version_id) => {
                info!(
                    "Created version {} for rule {} (reason: {})",
                    version_id, rule.name, change_reason
                );
            }
            Err(e) => {
                warn!(
                    "Failed to create version entry for rule {}: {}",
                    rule.name, e
                );
            }
        }
    }
}
