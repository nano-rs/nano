// SPDX-License-Identifier: AGPL-3.0-or-later

//! Finding Logging Service
//!
//! Logs detection matches and alerts as searchable events with source_type="findings".
//! This enables:
//! - Searching for all detection activity
//! - Building dashboards on detection metrics
//! - Creating meta-detections (detections that fire on other detections)
//! - Correlating alerts with original log events
//!
//! Finding types:
//! - `detection_match`: Live mode rule matched (for tuning, no alert created)
//! - `alert`: Alerting mode rule matched (alert was created)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::db::DualPool;
use crate::detection::risk::RiskResult;
use crate::models::{Alert, DetectionRule, RuleMode, Severity};

/// Finding type distinguishes between live mode matches and actual alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    /// Live mode rule matched - for tuning, no alert created
    DetectionMatch,
    /// Alerting mode rule matched - alert was created
    Alert,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::DetectionMatch => write!(f, "detection_match"),
            FindingType::Alert => write!(f, "alert"),
        }
    }
}

/// A finding event to be logged
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvent {
    /// Type of finding (detection_match or alert)
    pub finding_type: FindingType,
    /// Rule that fired
    pub rule_id: Uuid,
    pub rule_name: String,
    pub rule_query: String,
    /// Severity of the rule
    pub severity: Severity,
    /// Rule mode when it fired
    pub rule_mode: RuleMode,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Alert ID (only for finding_type=alert)
    pub alert_id: Option<Uuid>,
    /// Number of events that matched
    pub matched_event_count: usize,
    /// Sample of matched events (first few for context)
    pub matched_events_sample: Vec<serde_json::Value>,
    /// Whether this was a realtime detection
    pub realtime: bool,
    /// Timestamp when the detection occurred
    pub detected_at: DateTime<Utc>,
    /// Raw risk score before global weight applied
    pub raw_risk_score: i32,
    /// Weighted risk score (raw * global_weight)
    pub risk_score: i32,
    /// Entity being scored (extracted from risk_entity_field)
    pub risk_entity: String,
    /// Field name that the risk entity was extracted from (e.g., "src_ip", "user", "dest_host")
    pub risk_entity_field: Option<String>,
    /// Risk factors explaining the score
    pub risk_factors: Vec<String>,
}

impl FindingEvent {
    /// Remove empty/null fields from an event to reduce storage size
    fn strip_empty_fields(event: &serde_json::Value) -> serde_json::Value {
        match event {
            serde_json::Value::Object(map) => {
                let filtered: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .filter_map(|(k, v)| {
                        // Keep the field if it's not empty/null
                        match v {
                            serde_json::Value::Null => None,
                            serde_json::Value::String(s) if s.is_empty() => None,
                            serde_json::Value::Number(n) if n.as_f64() == Some(0.0) => None,
                            serde_json::Value::Bool(false) => None,
                            serde_json::Value::Array(arr) if arr.is_empty() => None,
                            serde_json::Value::Object(obj) if obj.is_empty() => None,
                            // Recursively strip nested objects
                            serde_json::Value::Object(_) => {
                                let stripped = Self::strip_empty_fields(v);
                                if stripped.as_object().map(|o| o.is_empty()).unwrap_or(false) {
                                    None
                                } else {
                                    Some((k.clone(), stripped))
                                }
                            }
                            _ => Some((k.clone(), v.clone())),
                        }
                    })
                    .collect();
                serde_json::Value::Object(filtered)
            }
            _ => event.clone(),
        }
    }

    /// Create a finding event for a live mode detection match
    pub fn detection_match(
        rule: &DetectionRule,
        matched_events: &[serde_json::Value],
        realtime: bool,
        risk_result: RiskResult,
    ) -> Self {
        let sample_count = matched_events.len().min(5);
        // Strip empty fields from sample events to reduce storage
        let stripped_sample: Vec<serde_json::Value> = matched_events[..sample_count]
            .iter()
            .map(|e| Self::strip_empty_fields(e))
            .collect();

        Self {
            finding_type: FindingType::DetectionMatch,
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            rule_query: rule.query.clone(),
            severity: rule.severity,
            rule_mode: rule.mode,
            mitre_tactics: rule.mitre_tactics.clone(),
            mitre_techniques: rule.mitre_techniques.clone(),
            alert_id: None,
            matched_event_count: matched_events.len(),
            matched_events_sample: stripped_sample,
            realtime,
            detected_at: Utc::now(),
            raw_risk_score: risk_result.raw_score,
            risk_score: risk_result.weighted_score,
            risk_entity: risk_result.entity,
            risk_entity_field: risk_result.entity_field,
            risk_factors: risk_result.factors,
        }
    }

    /// Create a finding event for an alert
    pub fn alert(
        rule: &DetectionRule,
        alert: &Alert,
        realtime: bool,
        risk_result: RiskResult,
    ) -> Self {
        let matched_events = alert
            .matched_events
            .as_array()
            .map(|arr| arr.to_vec())
            .unwrap_or_default();
        let sample_count = matched_events.len().min(5);
        // Strip empty fields from sample events to reduce storage
        let stripped_sample: Vec<serde_json::Value> = matched_events[..sample_count]
            .iter()
            .map(|e| Self::strip_empty_fields(e))
            .collect();

        Self {
            finding_type: FindingType::Alert,
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            rule_query: rule.query.clone(),
            severity: rule.severity,
            rule_mode: rule.mode,
            mitre_tactics: rule.mitre_tactics.clone(),
            mitre_techniques: rule.mitre_techniques.clone(),
            alert_id: Some(alert.id),
            matched_event_count: matched_events.len(),
            matched_events_sample: stripped_sample,
            realtime,
            detected_at: Utc::now(),
            raw_risk_score: risk_result.raw_score,
            risk_score: risk_result.weighted_score,
            risk_entity: risk_result.entity,
            risk_entity_field: risk_result.entity_field,
            risk_factors: risk_result.factors,
        }
    }

    /// Convert to a log-compatible JSON structure
    pub fn to_log_json(&self) -> serde_json::Value {
        json!({
            "signal_type": self.finding_type.to_string(),
            "rule_id": self.rule_id.to_string(),
            "rule_name": self.rule_name,
            "rule_query": self.rule_query,
            "severity": format!("{:?}", self.severity).to_lowercase(),
            "rule_mode": self.rule_mode.to_string(),
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "alert_id": self.alert_id.map(|id| id.to_string()),
            "matched_event_count": self.matched_event_count,
            "matched_events_sample": self.matched_events_sample,
            "realtime": self.realtime,
            "detected_at": self.detected_at.to_rfc3339(),
            "raw_risk_score": self.raw_risk_score,
            "risk_score": self.risk_score,
            "risk_entity": self.risk_entity,
            "risk_entity_field": self.risk_entity_field,
            "risk_factors": self.risk_factors,
        })
    }

    /// Generate a human-readable message for the finding
    pub fn message(&self) -> String {
        let entities = self.extract_entity_summary();

        match self.finding_type {
            FindingType::DetectionMatch => {
                if entities.is_empty() {
                    format!(
                        "{} [LIVE] - {} event(s)",
                        self.rule_name, self.matched_event_count
                    )
                } else {
                    format!("{} [LIVE] - {}", self.rule_name, entities)
                }
            }
            FindingType::Alert => {
                if entities.is_empty() {
                    format!("{} - {} event(s)", self.rule_name, self.matched_event_count)
                } else {
                    format!("{} - {}", self.rule_name, entities)
                }
            }
        }
    }

    /// Extract a summary of key entities from matched events for display
    fn extract_entity_summary(&self) -> String {
        // Priority fields to extract (most interesting first)
        const ENTITY_FIELDS: &[&str] = &[
            "src_user",
            "dest_user",
            "user",
            "src_ip",
            "dest_ip",
            "dvc_ip",
            "src_host",
            "dest_host",
            "host",
            "hostname",
            "app",
            "action",
            "file_name",
            "process_name",
        ];

        let mut found: Vec<(String, String)> = Vec::new();
        let mut seen_values: std::collections::HashSet<String> = std::collections::HashSet::new();

        // First, add the risk entity if we have it
        if !self.risk_entity.is_empty() && self.risk_entity != "unknown" {
            if let Some(ref field) = self.risk_entity_field {
                found.push((field.clone(), self.risk_entity.clone()));
                seen_values.insert(self.risk_entity.clone());
            }
        }

        // Then extract from the first matched event
        if let Some(first_event) = self.matched_events_sample.first() {
            if let Some(obj) = first_event.as_object() {
                for field in ENTITY_FIELDS {
                    if found.len() >= 4 {
                        break; // Limit to 4 entities for readability
                    }
                    if let Some(value) = obj.get(*field) {
                        let value_str = match value {
                            serde_json::Value::String(s) if !s.is_empty() => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            _ => continue,
                        };
                        // Skip if we already have this value (avoid duplicates)
                        if seen_values.contains(&value_str) {
                            continue;
                        }
                        found.push((field.to_string(), value_str.clone()));
                        seen_values.insert(value_str);
                    }
                }
            }
        }

        if found.is_empty() {
            return String::new();
        }

        // Format as "field=value, field=value"
        found
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Service for logging findings to the log store
#[derive(Clone)]
pub struct FindingLogger {
    pg_pool: PgPool,
    dual_pool: DualPool,
    enabled: bool,
}

impl FindingLogger {
    /// Create a new finding logger backed by a DualPool. ClickHouse is the
    /// findings log store; PostgreSQL is used for the entity-risk-score
    /// rollup table.
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        Self {
            pg_pool: dual_pool.postgres().clone(),
            dual_pool: dual_pool.clone(),
            enabled: true,
        }
    }

    /// Enable or disable finding logging
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if finding logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Log a finding event
    #[instrument(skip(self, finding), fields(finding_type = %finding.finding_type, rule_id = %finding.rule_id))]
    pub async fn log_finding(&self, finding: &FindingEvent) -> Result<(), FindingLogError> {
        if !self.enabled {
            debug!("Finding logging disabled, skipping");
            return Ok(());
        }

        let metadata = finding.to_log_json();
        let message = finding.message();
        let timestamp = finding.detected_at;

        self.log_to_clickhouse(&self.dual_pool, &message, &metadata, timestamp)
            .await?;

        // Update entity risk score if we have a valid entity and risk score
        if finding.risk_score > 0
            && !finding.risk_entity.is_empty()
            && finding.risk_entity != "unknown"
        {
            if let Err(e) = self.update_entity_risk_score(finding).await {
                tracing::error!(
                    "Failed to update entity risk score for {}: {}",
                    finding.risk_entity,
                    e
                );
            }
        } else {
            debug!(
                "Skipping entity risk update: score={}, entity='{}' (empty={}, unknown={})",
                finding.risk_score,
                finding.risk_entity,
                finding.risk_entity.is_empty(),
                finding.risk_entity == "unknown"
            );
        }

        Ok(())
    }

    /// Update entity risk score in the database
    async fn update_entity_risk_score(
        &self,
        finding: &FindingEvent,
    ) -> Result<(), FindingLogError> {
        let now = Utc::now();
        let severity = format!("{:?}", finding.severity).to_lowercase();

        // Determine entity type from the risk_entity_field if available, otherwise infer from value
        let entity_type =
            Self::infer_entity_type(&finding.risk_entity, finding.risk_entity_field.as_deref());

        sqlx::query(
            r#"
            INSERT INTO entity_risk_scores (
                entity, entity_type, risk_score, signal_count,
                last_signal_at, first_signal_at, last_rule_name, last_severity,
                created_at, updated_at
            ) VALUES ($1, $2, $3, 1, $4, $4, $5, $6, $4, $4)
            ON CONFLICT (entity, entity_type) DO UPDATE SET
                risk_score = entity_risk_scores.risk_score + $3,
                signal_count = entity_risk_scores.signal_count + 1,
                last_signal_at = $4,
                last_rule_name = $5,
                last_severity = $6,
                updated_at = $4
            "#,
        )
        .bind(&finding.risk_entity)
        .bind(entity_type)
        .bind(finding.risk_score)
        .bind(now)
        .bind(&finding.rule_name)
        .bind(&severity)
        .execute(&self.pg_pool)
        .await
        .map_err(FindingLogError::DatabaseError)?;

        debug!(
            "Updated entity risk score: entity={}, type={}, score=+{}",
            finding.risk_entity, entity_type, finding.risk_score
        );
        Ok(())
    }

    /// Infer entity type from the entity value and optional field name
    ///
    /// If field_name is provided, use it directly for better accuracy.
    /// Otherwise, infer from the value format (legacy behavior).
    fn infer_entity_type_from_value(entity: &str) -> &'static str {
        // Check if it looks like an IP address
        if entity.parse::<std::net::IpAddr>().is_ok() {
            return "ip";
        }

        // Check if it looks like a hostname (contains dots but not an IP)
        if entity.contains('.') && !entity.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return "hostname";
        }

        // Check if it looks like an email
        if entity.contains('@') {
            return "email";
        }

        // Check if it looks like a hash (32+ hex chars)
        if entity.len() >= 32 && entity.chars().all(|c| c.is_ascii_hexdigit()) {
            return "hash";
        }

        // Default to user
        "user"
    }

    /// Infer entity type from field name, falling back to value-based inference
    fn infer_entity_type(entity: &str, field_name: Option<&str>) -> &'static str {
        // If we have the field name, use it for accurate classification
        if let Some(field) = field_name {
            // IP address fields
            if field.contains("ip") || field == "dvc" {
                return "ip";
            }
            // Hostname fields
            if field.contains("host") || field == "hostname" || field == "dvc" {
                return "hostname";
            }
            // User fields
            if field.contains("user") {
                return "user";
            }
            // Hash fields
            if field.contains("hash") {
                return "hash";
            }
            // Domain fields
            if field.contains("domain") {
                return "domain";
            }
        }

        // Fall back to value-based inference
        Self::infer_entity_type_from_value(entity)
    }

    /// Log a detection match (live mode)
    pub async fn log_detection_match(
        &self,
        rule: &DetectionRule,
        matched_events: &[serde_json::Value],
        realtime: bool,
        risk_result: RiskResult,
    ) -> Result<(), FindingLogError> {
        self.log_detection_match_at(rule, matched_events, realtime, risk_result, None)
            .await
    }

    /// Log a detection match, optionally overriding the finding timestamp.
    ///
    /// Grouped / aggregate live-mode rules pass the aggregated event window end
    /// (`_last_seen`) so the live finding is stamped with the source-event time,
    /// keeping `(rule, entity, time)` stable across re-evaluations (NAN-1305).
    /// `None` preserves the legacy `now()` stamp.
    pub async fn log_detection_match_at(
        &self,
        rule: &DetectionRule,
        matched_events: &[serde_json::Value],
        realtime: bool,
        risk_result: RiskResult,
        detected_at: Option<DateTime<Utc>>,
    ) -> Result<(), FindingLogError> {
        let mut finding =
            FindingEvent::detection_match(rule, matched_events, realtime, risk_result);
        if let Some(ts) = detected_at {
            finding.detected_at = ts;
        }
        info!(
            "Logging detection match finding: rule='{}', events={}, realtime={}",
            rule.name,
            matched_events.len(),
            realtime
        );
        self.log_finding(&finding).await
    }

    /// Log an alert (alerting mode)
    pub async fn log_alert(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        realtime: bool,
        risk_result: RiskResult,
    ) -> Result<(), FindingLogError> {
        self.log_alert_at(rule, alert, realtime, risk_result, None)
            .await
    }

    /// Log an alert, optionally overriding the finding timestamp.
    ///
    /// Grouped / aggregate rules pass the aggregated event window end
    /// (`_last_seen`) as `detected_at` so the finding is stamped with the
    /// source-event time rather than the detection execution time (NAN-1305).
    /// This keeps `(rule, entity, time)` stable across re-evaluations and sorts
    /// the finding by when the activity happened. `None` preserves the legacy
    /// `now()` stamp.
    pub async fn log_alert_at(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        realtime: bool,
        risk_result: RiskResult,
        detected_at: Option<DateTime<Utc>>,
    ) -> Result<(), FindingLogError> {
        let mut finding = FindingEvent::alert(rule, alert, realtime, risk_result);
        if let Some(ts) = detected_at {
            finding.detected_at = ts;
        }
        info!(
            "Logging alert finding: rule='{}', alert_id={}, realtime={}",
            rule.name, alert.id, realtime
        );
        self.log_finding(&finding).await
    }

    /// Log to ClickHouse
    async fn log_to_clickhouse(
        &self,
        dual_pool: &DualPool,
        message: &str,
        metadata: &serde_json::Value,
        timestamp: DateTime<Utc>,
    ) -> Result<(), FindingLogError> {
        let client = dual_pool.clickhouse();
        let now = Utc::now();

        // Extract fields from metadata for direct column storage
        let signal_type = metadata
            .get("signal_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let severity = metadata
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let rule_id = metadata
            .get("rule_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let rule_name = metadata
            .get("rule_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let risk_score = metadata
            .get("risk_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let risk_entity = metadata
            .get("risk_entity")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // NAN-1254: under the OCSF profile, emit a standards-compliant OCSF
        // Detection Finding (class_uid 2004) into `ocsf_logs` instead of a
        // UDM-shaped row into `logs`, so findings are searchable in the OCSF
        // surface and the risk pipeline reads a single table. The UDM path
        // below stays byte-identical (the branch only fires under OCSF).
        let profile = crate::schema::active_profile_from_env()
            .map_err(|e| FindingLogError::ClickHouseError(format!("schema profile: {e}")))?;
        if profile.id() == crate::schema::SchemaId::Ocsf {
            let event = Self::build_ocsf_finding_event(metadata, message, timestamp);
            // event (JSON) + explicit timestamp (DateTime64(3) → millis) +
            // source_type='findings' (operational column, so the read path's
            // `WHERE source_type='findings'` is unchanged across modes). `id`
            // and `_inserted_at` are server-defaulted; everything else
            // materializes from `event`.
            let ocsf_query = r#"
                INSERT INTO ocsf_logs (event, timestamp, source_type)
                VALUES (?, ?, 'findings')
            "#;
            client
                .query(ocsf_query)
                .bind(event.to_string())
                .bind(timestamp.timestamp_millis())
                .execute()
                .await
                .map_err(|e| FindingLogError::ClickHouseError(e.to_string()))?;

            debug!(
                "OCSF Detection Finding (2004) logged to ocsf_logs with risk_score={}, risk_entity={}",
                risk_score, risk_entity
            );
            return Ok(());
        }

        // Insert into ClickHouse logs table with UDM fields as direct columns
        let query = r#"
            INSERT INTO logs (
                timestamp, message, metadata, source_type,
                action, status, rule_id, rule_name, severity,
                risk_score, risk_entity, ingest_time
            ) VALUES (?, ?, ?, 'findings', ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        client
            .query(query)
            .bind(timestamp.timestamp_micros())
            .bind(message)
            .bind(metadata.to_string())
            .bind(signal_type) // action = signal_type for easy filtering
            .bind(severity) // status = severity for easy filtering
            .bind(rule_id)
            .bind(rule_name)
            .bind(severity) // severity as direct column
            .bind(risk_score)
            .bind(risk_entity)
            .bind(now.timestamp_micros())
            .execute()
            .await
            .map_err(|e| FindingLogError::ClickHouseError(e.to_string()))?;

        debug!(
            "Finding logged to ClickHouse with risk_score={}, risk_entity={}",
            risk_score, risk_entity
        );
        Ok(())
    }

    /// Build a standards-compliant OCSF Detection Finding (`class_uid` 2004)
    /// `event` JSON from the nano finding metadata (NAN-1254).
    ///
    /// Native OCSF fields carry the parts OCSF models first-class: `risk_score`,
    /// `severity[_id]`, `status_id`, `finding_info{title,uid,types,analytic}`.
    /// The nano-specific risk attribution (`risk_entity` / `risk_entity_field`)
    /// and the rest of the nano finding payload live under OCSF `unmapped` — the
    /// sanctioned vendor-extension object — so the OCSF record stays valid while
    /// the risk repository read path can pull `unmapped.risk_entity` etc. back.
    pub fn build_ocsf_finding_event(
        metadata: &serde_json::Value,
        message: &str,
        timestamp: DateTime<Utc>,
    ) -> serde_json::Value {
        let get_str = |k: &str| metadata.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let cloned = |k: &str, default: serde_json::Value| {
            metadata.get(k).cloned().unwrap_or(default)
        };

        // nano Severity (lowercased) -> OCSF severity_id + Title-case sibling.
        let (severity_id, severity_title) = match get_str("severity") {
            "critical" => (5, "Critical"),
            "high" => (4, "High"),
            "medium" => (3, "Medium"),
            "low" => (2, "Low"),
            "info" | "informational" => (1, "Informational"),
            _ => (0, "Unknown"),
        };

        const CLASS_UID: i64 = 2004; // Detection Finding
        const ACTIVITY_ID: i64 = 1; // Create

        let risk_score = metadata
            .get("risk_score")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let signal_type = get_str("signal_type");
        let rule_id = get_str("rule_id");
        let rule_name = get_str("rule_name");

        json!({
            "class_uid": CLASS_UID,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": ACTIVITY_ID,
            "activity_name": "Create",
            "type_uid": CLASS_UID * 100 + ACTIVITY_ID, // 200401
            // OCSF `time` is epoch milliseconds.
            "time": timestamp.timestamp_millis(),
            "severity_id": severity_id,
            "severity": severity_title,
            "status_id": 1, // New
            "risk_score": risk_score,
            "message": message,
            "count": cloned("matched_event_count", json!(1)),
            "metadata": {
                "product": { "name": "nano", "vendor_name": "nano" },
                "log_name": "findings",
                "uid": cloned("alert_id", serde_json::Value::Null),
            },
            "finding_info": {
                "title": rule_name,
                "uid": rule_id,
                "types": [signal_type],
                "analytic": { "name": rule_name, "uid": rule_id, "type_id": 1 },
            },
            // nano vendor extension — read back by risk/repository.rs under OCSF.
            "unmapped": {
                "signal_type": signal_type,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "risk_score": risk_score,
                "risk_entity": get_str("risk_entity"),
                "risk_entity_field": cloned("risk_entity_field", serde_json::Value::Null),
                "rule_mode": get_str("rule_mode"),
                "realtime": cloned("realtime", json!(false)),
                "raw_risk_score": cloned("raw_risk_score", json!(0)),
                "mitre_tactics": cloned("mitre_tactics", json!([])),
                "mitre_techniques": cloned("mitre_techniques", json!([])),
                "risk_factors": cloned("risk_factors", json!([])),
                "matched_events_sample": cloned("matched_events_sample", json!([])),
            },
        })
    }
}

/// Errors that can occur during finding logging
#[derive(Debug, thiserror::Error)]
pub enum FindingLogError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),
}

/// NAN-1254: the OCSF Detection Finding (class_uid 2004) write contract.
/// Validates that `build_ocsf_finding_event` produces a spec-shaped 2004 event
/// whose native fields + `unmapped` vendor extension match exactly what the risk
/// repository read path extracts (`JSONExtract*(event, ...)`). Keeping these in
/// lockstep is the whole point — write and read must agree.
#[cfg(test)]
mod ocsf_finding_tests {
    use super::*;

    fn sample_metadata() -> serde_json::Value {
        json!({
            "signal_type": "detection_match",
            "rule_id": "rule-abc-123",
            "rule_name": "Suspicious Login",
            "rule_query": "user=admin failed",
            "severity": "high",
            "rule_mode": "live",
            "mitre_tactics": ["TA0001"],
            "mitre_techniques": ["T1078"],
            "alert_id": null,
            "matched_event_count": 3,
            "matched_events_sample": [],
            "realtime": false,
            "raw_risk_score": 50,
            "risk_score": 75,
            "risk_entity": "10.0.0.5",
            "risk_entity_field": "src_ip",
            "risk_factors": ["off-hours"]
        })
    }

    #[test]
    fn builds_spec_shaped_detection_finding_2004() {
        let ts = DateTime::parse_from_rfc3339("2026-06-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = FindingLogger::build_ocsf_finding_event(&sample_metadata(), "Suspicious Login - src_ip=10.0.0.5", ts);

        // OCSF Detection Finding taxonomy
        assert_eq!(event["class_uid"], 2004);
        assert_eq!(event["category_uid"], 2);
        assert_eq!(event["activity_id"], 1);
        assert_eq!(event["type_uid"], 200401); // class_uid*100 + activity_id
        assert_eq!(event["class_name"], "Detection Finding");
        assert_eq!(event["time"], ts.timestamp_millis());

        // severity mapping: nano "high" -> OCSF severity_id 4 + Title-case sibling
        assert_eq!(event["severity_id"], 4);
        assert_eq!(event["severity"], "High");

        // native OCSF risk_score (Integer)
        assert_eq!(event["risk_score"], 75);

        // finding_info carries rule identity (read path: finding_info.title)
        assert_eq!(event["finding_info"]["title"], "Suspicious Login");
        assert_eq!(event["finding_info"]["uid"], "rule-abc-123");

        // nano vendor extension under `unmapped` — read back by risk/repository.rs
        assert_eq!(event["unmapped"]["risk_entity"], "10.0.0.5");
        assert_eq!(event["unmapped"]["risk_entity_field"], "src_ip");
        assert_eq!(event["unmapped"]["rule_id"], "rule-abc-123");
        assert_eq!(event["unmapped"]["signal_type"], "detection_match");
        assert_eq!(event["unmapped"]["risk_score"], 75);

        // product provenance (so OCSF consumers attribute it to nano)
        assert_eq!(event["metadata"]["product"]["name"], "nano");
    }

    #[test]
    fn severity_id_mapping_covers_all_levels() {
        let ts = Utc::now();
        for (nano, expect_id, expect_title) in [
            ("critical", 5, "Critical"),
            ("high", 4, "High"),
            ("medium", 3, "Medium"),
            ("low", 2, "Low"),
            ("info", 1, "Informational"),
            ("bogus", 0, "Unknown"),
        ] {
            let md = json!({ "severity": nano, "risk_score": 1, "rule_id": "r", "rule_name": "n", "signal_type": "alert", "risk_entity": "e" });
            let ev = FindingLogger::build_ocsf_finding_event(&md, "m", ts);
            assert_eq!(ev["severity_id"], expect_id, "severity_id for {nano}");
            assert_eq!(ev["severity"], expect_title, "severity title for {nano}");
        }
    }
}

#[cfg(any())]
mod tests {
    use super::*;
    use crate::detection::risk::RiskResult;

    #[test]
    fn test_finding_type_display() {
        assert_eq!(FindingType::DetectionMatch.to_string(), "detection_match");
        assert_eq!(FindingType::Alert.to_string(), "alert");
    }

    #[test]
    fn test_finding_event_message() {
        let rule = DetectionRule {
            id: Uuid::now_v7(),
            name: "Test Rule".to_string(),
            description: None,
            query: "error".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            enabled: true,
            mode: RuleMode::Live,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: sqlx::types::Json(vec![]),
            detection_mode: crate::models::detection_rule::DetectionMode::Scheduled,
            materialized_view_name: None,
            archived: false,
            lookback_minutes: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
        };

        let events = vec![serde_json::json!({"message": "test"})];
        let risk_result = RiskResult::new(
            75,
            75,
            "192.168.1.1".to_string(),
            Some("src_ip".to_string()),
            vec!["severity_default:High".to_string()],
        );
        let finding = FindingEvent::detection_match(&rule, &events, true, risk_result);

        assert!(finding.message().contains("[LIVE]"));
        assert!(finding.message().contains("Test Rule"));
        // Should include the entity info
        assert!(finding.message().contains("src_ip=192.168.1.1"));
        assert_eq!(finding.matched_event_count, 1);
        assert_eq!(finding.raw_risk_score, 75);
        assert_eq!(finding.risk_score, 75);
        assert_eq!(finding.risk_entity, "192.168.1.1");
    }

    #[test]
    fn test_finding_event_to_json() {
        let rule = DetectionRule {
            id: Uuid::now_v7(),
            name: "Test Rule".to_string(),
            description: None,
            query: "error".to_string(),
            severity: Severity::Critical,
            mitre_tactics: vec!["TA0001".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
            schedule_cron: None,
            enabled: true,
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: sqlx::types::Json(vec![]),
            detection_mode: crate::models::detection_rule::DetectionMode::Scheduled,
            materialized_view_name: None,
            archived: false,
            lookback_minutes: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
        };

        let events = vec![
            serde_json::json!({"message": "test1"}),
            serde_json::json!({"message": "test2"}),
        ];
        let risk_result = RiskResult::new(
            90,
            45,
            "admin".to_string(),
            Some("user".to_string()),
            vec!["severity_default:Critical".to_string()],
        );
        let finding = FindingEvent::detection_match(&rule, &events, false, risk_result);
        let json = finding.to_log_json();

        assert_eq!(json["signal_type"], "detection_match");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["matched_event_count"], 2);
        assert_eq!(json["mitre_tactics"][0], "TA0001");
        assert_eq!(json["raw_risk_score"], 90);
        assert_eq!(json["risk_score"], 45);
        assert_eq!(json["risk_entity"], "admin");
        assert_eq!(json["risk_factors"][0], "severity_default:Critical");
    }

    #[test]
    fn test_finding_event_risk_fields() {
        let rule = DetectionRule {
            id: Uuid::now_v7(),
            name: "Risk Test Rule".to_string(),
            description: None,
            query: "error".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            enabled: true,
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            detection_mode: crate::models::detection_rule::DetectionMode::Scheduled,
            materialized_view_name: None,
            match_count: 0,
            live_match_count: 0,
            risk_score: Some(85),
            risk_entity_field: Some("user".to_string()),
            risk_modifiers: sqlx::types::Json(vec![]),
            archived: false,
            lookback_minutes: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
        };

        let events = vec![serde_json::json!({"user": "attacker", "action": "login_failed"})];
        let risk_result = RiskResult::new(
            85,
            42,
            "attacker".to_string(),
            Some("user".to_string()),
            vec!["modifier:count > 5".to_string(), "brute_force".to_string()],
        );
        let finding = FindingEvent::detection_match(&rule, &events, true, risk_result);

        // Verify risk fields are set correctly
        assert_eq!(finding.raw_risk_score, 85);
        assert_eq!(finding.risk_score, 42);
        assert_eq!(finding.risk_entity, "attacker");
        assert_eq!(finding.risk_factors.len(), 2);
        assert!(finding
            .risk_factors
            .contains(&"modifier:count > 5".to_string()));
        assert!(finding.risk_factors.contains(&"brute_force".to_string()));

        // Verify JSON output includes risk fields
        let json = finding.to_log_json();
        assert_eq!(json["raw_risk_score"], 85);
        assert_eq!(json["risk_score"], 42);
        assert_eq!(json["risk_entity"], "attacker");
        assert!(json["risk_factors"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn test_strip_empty_fields() {
        // Test event with many empty fields (like UDM schema)
        let event = serde_json::json!({
            "src_ip": "10.0.1.30",
            "dest_host": "legacy-erp-2015.internal",
            "user": "vendor_globex",
            "bytes_out": 49885,
            "status_code": 200,
            "url": "http://legacy-erp-2015.internal/",
            // Empty fields that should be stripped
            "action_mode": "",
            "action_name": "",
            "access_count": 0,
            "access_time": 0,
            "additional_answer_count": 0,
            "app": "",
            "app_id": 0,
            "auth_result": "",
            "auth_type": "",
            "empty_array": [],
            "empty_object": {},
            "null_field": null,
            "false_bool": false,
            "nested": {
                "has_value": "test",
                "empty_string": "",
                "zero_number": 0,
                "empty_nested": {}
            }
        });

        let stripped = FindingEvent::strip_empty_fields(&event);
        let obj = stripped.as_object().unwrap();

        // Verify non-empty fields are kept
        assert!(obj.contains_key("src_ip"));
        assert!(obj.contains_key("dest_host"));
        assert!(obj.contains_key("user"));
        assert!(obj.contains_key("bytes_out"));
        assert!(obj.contains_key("status_code"));
        assert!(obj.contains_key("url"));

        // Verify empty fields are removed
        assert!(!obj.contains_key("action_mode"));
        assert!(!obj.contains_key("action_name"));
        assert!(!obj.contains_key("access_count"));
        assert!(!obj.contains_key("access_time"));
        assert!(!obj.contains_key("additional_answer_count"));
        assert!(!obj.contains_key("app"));
        assert!(!obj.contains_key("app_id"));
        assert!(!obj.contains_key("auth_result"));
        assert!(!obj.contains_key("auth_type"));
        assert!(!obj.contains_key("empty_array"));
        assert!(!obj.contains_key("empty_object"));
        assert!(!obj.contains_key("null_field"));
        assert!(!obj.contains_key("false_bool"));

        // Verify nested object handling
        assert!(obj.contains_key("nested"));
        let nested = obj["nested"].as_object().unwrap();
        assert!(nested.contains_key("has_value"));
        assert!(!nested.contains_key("empty_string"));
        assert!(!nested.contains_key("zero_number"));
        assert!(!nested.contains_key("empty_nested"));
    }

    #[test]
    fn test_detection_match_strips_empty_fields() {
        let rule = DetectionRule {
            id: Uuid::now_v7(),
            name: "Test Rule".to_string(),
            description: None,
            query: "error".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            enabled: true,
            mode: RuleMode::Live,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: sqlx::types::Json(vec![]),
            detection_mode: crate::models::detection_rule::DetectionMode::Scheduled,
            materialized_view_name: None,
            archived: false,
            lookback_minutes: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
        };

        // Event with many empty UDM fields
        let events = vec![serde_json::json!({
            "src_ip": "192.168.1.1",
            "message": "test error",
            "action": "",
            "app": "",
            "bytes": "",
            "count": 0,
            "empty_field": null,
        })];

        let risk_result = RiskResult::new(
            70,
            70,
            "192.168.1.1".to_string(),
            Some("src_ip".to_string()),
            vec![],
        );
        let finding = FindingEvent::detection_match(&rule, &events, true, risk_result);

        // Verify sample has stripped empty fields
        assert_eq!(finding.matched_events_sample.len(), 1);
        let sample = &finding.matched_events_sample[0];
        let obj = sample.as_object().unwrap();

        // Should keep non-empty fields
        assert!(obj.contains_key("src_ip"));
        assert!(obj.contains_key("message"));

        // Should remove empty fields
        assert!(!obj.contains_key("action"));
        assert!(!obj.contains_key("app"));
        assert!(!obj.contains_key("bytes"));
        assert!(!obj.contains_key("count"));
        assert!(!obj.contains_key("empty_field"));
    }
}
