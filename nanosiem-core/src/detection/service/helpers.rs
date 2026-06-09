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

use super::alerts::ClaimedFinding;
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

    /// Build one [`ClaimedFinding`] candidate per `(entity, field, events)`
    /// group, computing each one's stable cross-execution identity (NAN-1305).
    /// This does NOT touch the database — callers pass the result to
    /// [`retain_unemitted`] (read) and [`record_finding_emissions`] (write).
    pub(super) fn build_finding_candidates(
        kind: &str,
        rule_id: Uuid,
        groups: impl IntoIterator<Item = (String, String, Vec<serde_json::Value>)>,
    ) -> Vec<ClaimedFinding> {
        groups
            .into_iter()
            .map(|(entity, field, events)| {
                let (finding_hash, window_end) =
                    Self::finding_dedup_identity(kind, rule_id, &field, &entity, &events);
                ClaimedFinding {
                    entity,
                    field,
                    events,
                    window_end,
                    finding_hash,
                }
            })
            .collect()
    }

    /// Filter `candidates` down to the findings NOT yet emitted for this rule —
    /// a single batched `SELECT ... = ANY($hashes)` against the dedup store
    /// (NAN-1305). Fails open: on a query error every candidate is treated as new
    /// (emit rather than silently drop).
    pub(super) async fn retain_unemitted(
        &self,
        rule_id: Uuid,
        candidates: Vec<ClaimedFinding>,
    ) -> Vec<ClaimedFinding> {
        if candidates.is_empty() {
            return candidates;
        }

        let hashes: Vec<String> = candidates.iter().map(|c| c.finding_hash.clone()).collect();
        let existing: std::collections::HashSet<String> = match sqlx::query_scalar::<_, String>(
            r#"
            SELECT finding_hash
            FROM detection_finding_emissions
            WHERE rule_id = $1 AND finding_hash = ANY($2)
            "#,
        )
        .bind(rule_id)
        .bind(&hashes)
        .fetch_all(&self.pg_pool)
        .await
        {
            Ok(rows) => rows.into_iter().collect(),
            Err(e) => {
                warn!(
                    "finding-emission dedup read failed for rule {}: {}. Emitting all without dedup.",
                    rule_id, e
                );
                std::collections::HashSet::new()
            }
        };

        candidates
            .into_iter()
            .filter(|c| !existing.contains(&c.finding_hash))
            .collect()
    }

    /// Record `findings` as emitted in the dedup store — a single batched
    /// `INSERT ... ON CONFLICT DO NOTHING` (NAN-1305). Best-effort: a failure is
    /// logged, not propagated (the finding has been / will be emitted regardless;
    /// at worst it can re-emit on a later overlapping run).
    pub(super) async fn record_finding_emissions(
        &self,
        rule_id: Uuid,
        findings: &[ClaimedFinding],
    ) {
        if findings.is_empty() {
            return;
        }

        let mut qb = sqlx::QueryBuilder::new(
            "INSERT INTO detection_finding_emissions (rule_id, entity, finding_hash, window_end) ",
        );
        qb.push_values(findings, |mut b, f| {
            b.push_bind(rule_id)
                .push_bind(&f.entity)
                .push_bind(&f.finding_hash)
                .push_bind(f.window_end);
        });
        qb.push(" ON CONFLICT (rule_id, finding_hash) DO NOTHING");

        if let Err(e) = qb.build().execute(&self.pg_pool).await {
            warn!(
                "Failed to record {} finding emissions for rule {}: {}. They may re-emit on a later overlapping run.",
                findings.len(),
                rule_id,
                e
            );
        }
    }

    /// Derive the stable cross-execution identity of a finding:
    /// `(finding_hash, window_end)`.
    ///
    /// The hash is keyed on `kind + rule_id + field + entity + identity payload`,
    /// NEVER the detection execution time:
    /// - **Aggregate** rows (carrying a `_first_seen`/`_last_seen` window) key on
    ///   `_last_seen` ONLY — the entity's newest-activity time. Re-evaluating the
    ///   same entity collides and dedups; a later `_last_seen` (new activity)
    ///   re-emits. `_first_seen` is deliberately NOT in the key: a sliding
    ///   lookback's trailing edge drifts it upward every cycle on static data
    ///   (NAN-1309). Intra-window count drift also does NOT bust dedup.
    /// - **Raw** groups (no window bounds) key on the **content** of the matched
    ///   events (via [`compute_event_hash`], which strips `_nano_*` timing), so
    ///   identical re-matches collide but genuinely new events still emit.
    ///
    /// `window_end` is the source-event time the finding is stamped with
    /// (`_last_seen`, else the latest event `timestamp`, else now()).
    ///
    /// `kind` namespaces live (`"live"`) vs alerting (`"alert"`) emissions so a
    /// bake-in live match does not suppress the first real alert once a rule is
    /// promoted Live → Alerting over an overlapping window.
    pub(super) fn finding_dedup_identity(
        kind: &str,
        rule_id: Uuid,
        field: &str,
        entity: &str,
        events: &[serde_json::Value],
    ) -> (String, DateTime<Utc>) {
        use sha2::{Digest, Sha256};

        // Prefer the canonical, system-injected `_first_seen`/`_last_seen`
        // (query_enrichment guarantees these on every aggregate, NAN-1308). The
        // user-aliased `first_seen`/`last_seen` are a defensive fallback only —
        // we never key dedup on a user-chosen name as the primary signal, since
        // a rule could alias its window to anything (`window_start`, `bucket_end`).
        let first_seen = events
            .iter()
            .filter_map(|e| {
                Self::event_field_time(e, "_first_seen")
                    .or_else(|| Self::event_field_time(e, "first_seen"))
            })
            .min();
        let last_seen = events
            .iter()
            .filter_map(|e| {
                Self::event_field_time(e, "_last_seen")
                    .or_else(|| Self::event_field_time(e, "last_seen"))
            })
            .max();

        let mut hasher = Sha256::new();
        hasher.update(kind.as_bytes());
        hasher.update(b"|");
        hasher.update(rule_id.as_bytes());
        hasher.update(b"|");
        hasher.update(field.as_bytes());
        hasher.update(b"|");
        hasher.update(entity.as_bytes());
        hasher.update(b"|");

        let window_end = match (first_seen, last_seen) {
            // Aggregate (a real activity window — both bounds present, which
            // also distinguishes it from a stray `last_seen` on a raw event):
            // key on `last_seen` ONLY, never `_first_seen` (NAN-1309).
            //
            // A sliding lookback (`lookback_minutes` + cron) re-evaluates an
            // overlapping window every cycle; on static data the newest event
            // (`last_seen`) is fixed but the oldest events age out of the
            // trailing edge, so `_first_seen = min(timestamp)` creeps upward
            // each cycle. Including it re-keyed every cycle → re-emit. Keying on
            // `last_seen` makes the dedup store a per-entity finding watermark:
            // re-emit only when an entity's newest activity actually advances.
            // (We still re-scan the window, so windowed correlation is intact.)
            (Some(_first), Some(l)) => {
                hasher.update(l.timestamp_millis().to_le_bytes());
                l
            }
            // Raw / non-aggregate: identity is the event content (each distinct
            // match matters). compute_event_hash strips `_nano_*` so the
            // execution time doesn't bust dedup.
            _ => {
                let arr = serde_json::Value::Array(events.to_vec());
                hasher.update(crate::db::repository::compute_event_hash(&arr).as_bytes());
                events
                    .iter()
                    .filter_map(|e| Self::event_field_time(e, "timestamp"))
                    .max()
                    .unwrap_or_else(Utc::now)
            }
        };

        (hex::encode(hasher.finalize()), window_end)
    }

    /// Parse a ClickHouse / ISO-8601 timestamp string from an event field into
    /// a UTC instant. Handles CH's offset-less `YYYY-MM-DD HH:MM:SS[.fff]`
    /// (assumed UTC) and RFC 3339.
    fn event_field_time(event: &serde_json::Value, key: &str) -> Option<DateTime<Utc>> {
        let s = event.get(key)?.as_str()?;
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
            return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
        }
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
        }
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
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
                // This ensures every entity in the event gets risk scored.
                // The candidate physical fields come from the active profile's
                // entity-extraction order (NAN-1241 Phase 5): for UDM this is the
                // byte-identical superset list; for OCSF it yields the OCSF
                // physical fields (`src_endpoint.ip`, `user.name`, …).
                let order = self.active_profile.entity_extraction_order();

                for event in events {
                    let mut found_any = false;

                    // Extract ALL entity values from this event
                    for &(_role, field) in order {
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

    /// Get a string field value from an event.
    ///
    /// ClickHouse `JSONEachRow` rows have FLAT keys that ARE the (possibly
    /// dotted) physical column names: `SELECT *` over `ocsf_logs` returns a key
    /// literally named `src_endpoint.ip`, not a nested object. So we resolve
    /// `field` as a FLAT key first, and only fall back to walking it as a nested
    /// JSON path when no such flat key exists.
    ///
    /// UDM stays byte-for-byte identical: single-segment UDM fields (`src_ip`)
    /// hit the flat lookup; the UDM legacy paths (`metadata.src_ip`,
    /// `metadata.user`, `metadata.hostname`) have no flat key and resolve through
    /// the nested fall-back exactly as before. OCSF promoted dotted columns
    /// (`src_endpoint.ip`, `user.name`, …) now resolve via the flat lookup
    /// instead of collapsing every event into the `unknown` group (NAN-1241).
    fn get_string_field_from_event(event: &serde_json::Value, field: &str) -> Option<String> {
        // 1. Flat key: the dotted column name as-is (OCSF + single-segment UDM).
        if let Some(v) = event.get(field) {
            return Self::value_to_string(v);
        }

        // 2. Fall back to nested-path walk (UDM `metadata.*` legacy paths).
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = event;
        for part in parts {
            match current.get(part) {
                Some(v) => current = v,
                None => return None,
            }
        }
        Self::value_to_string(current)
    }

    /// Coerce a JSON leaf to a non-empty string, treating empty strings as
    /// missing (shared by flat + nested resolution above).
    fn value_to_string(current: &serde_json::Value) -> Option<String> {
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

#[cfg(test)]
mod finding_dedup_tests {
    use super::*;
    use serde_json::json;

    fn rule_id() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap()
    }

    /// NAN-1305: re-evaluating the same entity over the same aggregated window
    /// must yield the same dedup identity — even though each execution stamps a
    /// fresh `_nano_detected_at`. This is the core of the bug: aggregate findings
    /// were keyed on execution time, so they never collided.
    #[test]
    fn same_window_same_identity_regardless_of_execution_time() {
        let run1 = vec![json!({
            "src_ip": "10.1.1.10",
            "count": 7,
            "_first_seen": "2026-06-07 10:00:00.000",
            "_last_seen": "2026-06-07 11:00:00.000",
            "_nano_detected_at": "2026-06-07T23:30:00Z",
        })];
        let run2 = vec![json!({
            "src_ip": "10.1.1.10",
            "count": 7,
            "_first_seen": "2026-06-07 10:00:00.000",
            "_last_seen": "2026-06-07 11:00:00.000",
            // Different execution → different detection stamp, same activity window.
            "_nano_detected_at": "2026-06-08T11:40:00Z",
        })];

        let (h1, end1) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &run1);
        let (h2, end2) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &run2);

        assert_eq!(h1, h2, "same entity + window must collide across executions");
        assert_eq!(end1, end2);
        // window_end is the source event time (_last_seen), not now().
        assert_eq!(end1.to_rfc3339(), "2026-06-07T11:00:00+00:00");
    }

    /// A wider window with a later `_last_seen` (genuinely new activity) must NOT
    /// dedup — it should produce a distinct identity and still emit.
    #[test]
    fn extended_window_produces_new_identity() {
        let earlier = vec![json!({
            "src_ip": "10.1.1.10",
            "_first_seen": "2026-06-07 10:00:00.000",
            "_last_seen": "2026-06-07 11:00:00.000",
        })];
        let later = vec![json!({
            "src_ip": "10.1.1.10",
            "_first_seen": "2026-06-07 10:00:00.000",
            "_last_seen": "2026-06-07 12:30:00.000",
        })];

        let (h1, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &earlier);
        let (h2, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &later);
        assert_ne!(h1, h2, "a later _last_seen is new activity and must re-emit");
    }

    /// Different entities (same window) must not collide.
    #[test]
    fn distinct_entities_distinct_identity() {
        let mk = |ip: &str| {
            vec![json!({
                "src_ip": ip,
                "_first_seen": "2026-06-07 10:00:00.000",
                "_last_seen": "2026-06-07 11:00:00.000",
            })]
        };
        let (a, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &mk("10.1.1.10"));
        let (b, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.100", &mk("10.1.1.100"));
        assert_ne!(a, b);
    }

    /// Raw (non-aggregate) groups dedup by event *content*: the same entity with
    /// different matched events re-emits, while an identical re-match collides.
    /// (Aggregate rows dedup by window instead — see the window tests above.)
    #[test]
    fn raw_groups_dedup_by_content() {
        let ev_a = vec![json!({
            "src_ip": "10.1.1.10",
            "message": "evt-a",
            "timestamp": "2026-06-07 11:00:00.000",
        })];
        let ev_a_again = vec![json!({
            "src_ip": "10.1.1.10",
            "message": "evt-a",
            "timestamp": "2026-06-07 11:00:00.000",
            // Re-evaluation stamps a fresh detection time — must not bust dedup.
            "_nano_detected_at": "2026-06-08T00:00:00Z",
        })];
        let ev_b = vec![json!({
            "src_ip": "10.1.1.10",
            "message": "evt-b",
            "timestamp": "2026-06-07 11:00:00.000",
        })];

        let (a, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev_a);
        let (a_again, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev_a_again);
        let (b, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev_b);

        assert_eq!(a, a_again, "identical content (modulo _nano_) must collide");
        assert_ne!(a, b, "different content for the same entity must re-emit");
    }

    /// Non-aggregate groups (no `_first_seen`/`_last_seen`) take `window_end`
    /// from the latest event `timestamp`, and still collide on identical
    /// re-matches.
    #[test]
    fn falls_back_to_event_timestamp_when_no_bounds() {
        let ev = vec![json!({
            "src_ip": "10.1.1.10",
            "timestamp": "2026-06-07 11:00:00.000",
            "_nano_detected_at": "2026-06-07T23:30:00Z",
        })];
        let ev2 = vec![json!({
            "src_ip": "10.1.1.10",
            "timestamp": "2026-06-07 11:00:00.000",
            "_nano_detected_at": "2026-06-08T11:40:00Z",
        })];
        let (h1, end1) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev);
        let (h2, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev2);
        assert_eq!(h1, h2);
        assert_eq!(end1.to_rfc3339(), "2026-06-07T11:00:00+00:00");
    }

    /// Live (bake-in) and alerting emissions must NOT share a dedup slot for the
    /// same entity+window, or promoting a rule Live → Alerting over an
    /// overlapping window would suppress its first real alert.
    #[test]
    fn live_and_alert_kinds_do_not_collide() {
        let ev = vec![json!({
            "src_ip": "10.1.1.10",
            "_first_seen": "2026-06-07 10:00:00.000",
            "_last_seen": "2026-06-07 11:00:00.000",
        })];
        let (live, _) = DetectionService::finding_dedup_identity("live", rule_id(), "src_ip", "10.1.1.10", &ev);
        let (alert, _) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev);
        assert_ne!(live, alert, "live and alert emissions must be namespaced apart");
    }

    /// NAN-1308 regression: the real OCSF aggregate row shape uses USER-aliased
    /// `first_seen`/`last_seen` (not `_first_seen`/`_last_seen`) and carries a
    /// fluctuating `failures` count. Over a stable activity window the dedup key
    /// must collide despite the count drift — previously this content-hashed the
    /// whole row (including `failures`) and re-emitted every cycle (the flood).
    #[test]
    fn user_aliased_window_dedups_across_count_drift() {
        // Same window (first_seen/last_seen), different `failures` each cycle.
        let cycle1 = vec![json!({
            "src_endpoint.ip": "10.1.4.238",
            "first_seen": "2026-06-08T13:45:33.138Z",
            "last_seen": "2026-06-08T13:49:59.473Z",
            "failures": 6,
            "users": "kmiller, rmartin",
            "_nano_detected_at": "2026-06-08T14:00:29.374Z",
        })];
        let cycle2 = vec![json!({
            "src_endpoint.ip": "10.1.4.238",
            "first_seen": "2026-06-08T13:45:33.138Z",
            "last_seen": "2026-06-08T13:49:59.473Z",
            "failures": 9, // count drifted
            "users": "kmiller, rmartin",
            "_nano_detected_at": "2026-06-08T14:05:31.001Z", // later execution
        })];

        let (h1, end1) = DetectionService::finding_dedup_identity(
            "alert", rule_id(), "src_endpoint.ip", "10.1.4.238", &cycle1,
        );
        let (h2, _) = DetectionService::finding_dedup_identity(
            "alert", rule_id(), "src_endpoint.ip", "10.1.4.238", &cycle2,
        );

        assert_eq!(h1, h2, "same window must collide despite count/exec-time drift");
        // window_end is stamped from last_seen (source time), not now().
        assert_eq!(end1.to_rfc3339(), "2026-06-08T13:49:59.473+00:00");
    }

    /// The canonical `_last_seen` wins over a user-aliased `last_seen` when both
    /// are present (post-injection rows carry both), so the dedup identity is
    /// anchored to the system field.
    #[test]
    fn canonical_window_preferred_over_user_alias() {
        let ev = vec![json!({
            "src_ip": "10.1.1.10",
            "_first_seen": "2026-06-07 10:00:00.000",
            "_last_seen": "2026-06-07 11:00:00.000",
            "first_seen": "1999-01-01 00:00:00.000",
            "last_seen": "1999-01-01 00:00:00.000",
        })];
        let (_, end) = DetectionService::finding_dedup_identity("alert", rule_id(), "src_ip", "10.1.1.10", &ev);
        assert_eq!(end.to_rfc3339(), "2026-06-07T11:00:00+00:00", "must use canonical _last_seen");
    }

    /// NAN-1309 regression: a sliding lookback window's trailing edge drops the
    /// oldest events each cycle, so `_first_seen` drifts upward even on static
    /// data while `_last_seen` (newest activity) stays put. The dedup key must
    /// NOT include the drifting `_first_seen` — same entity + same `_last_seen`
    /// must collide regardless of `_first_seen`, else every cron cycle re-emits
    /// (the static-data flood that survived NAN-1305/1308).
    #[test]
    fn trailing_edge_first_seen_drift_does_not_re_emit() {
        let cycle1 = vec![json!({
            "src_endpoint.ip": "10.1.1.234",
            "_first_seen": "2026-06-08 13:35:00.000",
            "_last_seen": "2026-06-08 13:50:16.652",
        })];
        let cycle2 = vec![json!({
            "src_endpoint.ip": "10.1.1.234",
            // window slid 5 min → oldest events aged out → first_seen advanced...
            "_first_seen": "2026-06-08 13:40:00.000",
            // ...but newest activity (last_seen) is unchanged (static data).
            "_last_seen": "2026-06-08 13:50:16.652",
        })];
        let (h1, _) = DetectionService::finding_dedup_identity(
            "alert", rule_id(), "src_endpoint.ip", "10.1.1.234", &cycle1,
        );
        let (h2, _) = DetectionService::finding_dedup_identity(
            "alert", rule_id(), "src_endpoint.ip", "10.1.1.234", &cycle2,
        );
        assert_eq!(
            h1, h2,
            "first_seen drift on static data must NOT create a new finding"
        );
    }

    /// But genuinely new activity — a later `_last_seen` — must still re-emit.
    #[test]
    fn advancing_last_seen_re_emits() {
        let earlier = vec![json!({
            "src_endpoint.ip": "10.1.1.234",
            "_first_seen": "2026-06-08 13:35:00.000",
            "_last_seen": "2026-06-08 13:50:16.652",
        })];
        let later = vec![json!({
            "src_endpoint.ip": "10.1.1.234",
            "_first_seen": "2026-06-08 13:35:00.000",
            "_last_seen": "2026-06-08 13:58:42.100", // new logon arrived
        })];
        let (h1, _) = DetectionService::finding_dedup_identity(
            "alert", rule_id(), "src_endpoint.ip", "10.1.1.234", &earlier,
        );
        let (h2, _) = DetectionService::finding_dedup_identity(
            "alert", rule_id(), "src_endpoint.ip", "10.1.1.234", &later,
        );
        assert_ne!(h1, h2, "a later last_seen is new activity and must re-emit");
    }
}
