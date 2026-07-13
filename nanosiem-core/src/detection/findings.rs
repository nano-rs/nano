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
    /// Write-side entity type, inferred from the field name (falling back to
    /// the value) at finding construction (NAN-1806). Stamped into the finding
    /// row so the read side can honor types the value inference can never
    /// produce — `cloud_account` first (the cloud-overview fan-out keyed on it
    /// but nothing emitted it). Empty on findings without a risk entity.
    #[serde(default)]
    pub risk_entity_type: String,
    /// Risk factors explaining the score
    pub risk_factors: Vec<String>,
    /// NAN-1800: distinct normalized (trim + lowercase) `source_type` values of
    /// the matched origin events. Empty when the origin cannot be determined
    /// (aggregate rules whose result rows drop `source_type`). Used by the
    /// write-side redaction policy AND persisted as a marker so readers can
    /// scope findings by origin.
    #[serde(default)]
    pub origin_source_types: Vec<String>,
    /// NAN-1800: true when `matched_events_sample` was redacted at write time
    /// because the finding originated (or may have originated) from a
    /// restricted `source_type`. When set, `matched_events_sample` is empty and
    /// `risk_entity` / `risk_entity_field` are neutralized; counts and rule
    /// metadata are kept.
    #[serde(default)]
    pub matched_events_redacted: bool,
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
                            // Audit D37: `0` and `false` are MEANINGFUL evidence
                            // (status: 0, auth_result: false, port 0) — only
                            // genuinely empty values (null, "", [], {}) are stripped.
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

    /// Derive the finding timestamp from the source events (R7 — consistent
    /// timestamp basis across alert modes).
    ///
    /// Grouped/aggregate rules already stamp findings with the source-event
    /// window end (`_last_seen`, passed explicitly to `log_*_at`). Per-event
    /// rules previously fell back to `Utc::now()` (detection execution time),
    /// giving the same activity two different time bases depending on rule mode.
    /// This makes BOTH modes source-event based: the newest `timestamp` present
    /// on any matched event (mirroring the aggregate window end), falling back
    /// to `now()` only when no event carries a parseable timestamp.
    fn source_event_time(events: &[serde_json::Value]) -> Option<DateTime<Utc>> {
        events
            .iter()
            .filter_map(|e| {
                let s = e.get("timestamp")?.as_str()?;
                // Match the ClickHouse/serialized formats detection events use
                // (see detection::service::helpers::event_field_time).
                if let Ok(naive) =
                    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                {
                    return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
                }
                if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                    return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
                }
                DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            })
            .max()
    }

    /// Distinct normalized `source_type` values carried by the matched events
    /// (NAN-1800). Normalization is trim + lowercase — OCSF `source_type` is
    /// NOT ingest-lowercased, and the restricted-source registry stores
    /// normalized values. Events without a `source_type` string contribute
    /// nothing; an all-empty result means "origin unknown" and the write-side
    /// policy treats that conservatively (see `FindingLogger::origin_restricted`).
    fn origin_source_types_from(events: &[serde_json::Value]) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for event in events {
            if let Some(st) = event.get("source_type").and_then(|v| v.as_str()) {
                let normalized = st.trim().to_lowercase();
                if !normalized.is_empty() {
                    set.insert(normalized);
                }
            }
        }
        set.into_iter().collect()
    }

    /// Redact restricted-origin evidence from this finding (NAN-1800).
    ///
    /// MUST be applied on the `FindingEvent` itself, BEFORE `to_log_json()` —
    /// that method is pure and cannot self-redact, and its JSON feeds BOTH
    /// physical write branches (UDM `logs.metadata` and the OCSF
    /// `build_ocsf_finding_event` path). Redacting here guarantees the empty
    /// sample flows to both.
    ///
    /// Keeps counts + rule metadata (rule id/name/query, severity, MITRE,
    /// risk scores, risk factors); removes the event sample and neutralizes
    /// the risk entity so no restricted entity VALUE leaks via the
    /// `risk_entity` column, the CH-derived risk aggregation, or the
    /// `message()` entity summary (which derives from `risk_entity` + the
    /// sample).
    pub fn redact_matched_events(&mut self) {
        self.matched_events_sample = Vec::new();
        self.matched_events_redacted = true;
        // Neutralize the entity VALUE. Emptying it also (a) makes
        // `extract_entity_summary()` skip it, so `message()` falls back to the
        // count-only form, and (b) excludes the finding from every CH risk
        // aggregation (the shared risk builder filters `risk_entity != ''` —
        // NAN-1798/NAN-1810 replaced the PG `entity_risk_scores` rollup with
        // read-time aggregation over these rows), so a restricted entity value
        // never surfaces on the risk page / `dataset=risk` either.
        self.risk_entity = String::new();
        self.risk_entity_field = None;
        // risk_factors can carry `toString(<field>)` values for `factors=<field-expr>`
        // rules (clickhouse_sql_gen commands) — a second event-value channel that
        // egresses to both write branches. Clear it unconditionally on redaction;
        // at this layer label-only factors can't be distinguished from value-bearing ones.
        self.risk_factors = Vec::new();
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
            // R7: source-event time (newest matched-event timestamp), consistent
            // with the aggregate window end used by grouped rules. Falls back to
            // now() only when no event carries a parseable timestamp.
            detected_at: Self::source_event_time(matched_events).unwrap_or_else(Utc::now),
            raw_risk_score: risk_result.raw_score,
            risk_score: risk_result.weighted_score,
            risk_entity_type: Self::stamp_entity_type(&risk_result),
            risk_entity: risk_result.entity,
            risk_entity_field: risk_result.entity_field,
            risk_factors: risk_result.factors,
            origin_source_types: Self::origin_source_types_from(matched_events),
            matched_events_redacted: false,
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
            // R7: source-event time (see detection_match).
            detected_at: Self::source_event_time(&matched_events).unwrap_or_else(Utc::now),
            raw_risk_score: risk_result.raw_score,
            risk_score: risk_result.weighted_score,
            risk_entity_type: Self::stamp_entity_type(&risk_result),
            risk_entity: risk_result.entity,
            risk_entity_field: risk_result.entity_field,
            risk_factors: risk_result.factors,
            origin_source_types: Self::origin_source_types_from(&matched_events),
            matched_events_redacted: false,
        }
    }

    /// Write-side entity type for the finding row (NAN-1806): field-name
    /// inference falling back to value inference, empty when the finding has
    /// no real entity.
    fn stamp_entity_type(risk_result: &RiskResult) -> String {
        if risk_result.entity.is_empty() || risk_result.entity == "unknown" {
            return String::new();
        }
        FindingLogger::infer_entity_type(&risk_result.entity, risk_result.entity_field.as_deref())
            .to_string()
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
            // NAN-1800: redaction markers. `to_log_json` is PURE — it must not
            // decide redaction itself; `FindingLogger::log_finding` applies
            // `redact_matched_events()` on the event BEFORE this is called so
            // both write branches (UDM metadata + OCSF event) agree.
            "origin_source_types": self.origin_source_types,
            "matched_events_redacted": self.matched_events_redacted,
            "realtime": self.realtime,
            "detected_at": self.detected_at.to_rfc3339(),
            "raw_risk_score": self.raw_risk_score,
            "risk_score": self.risk_score,
            "risk_entity": self.risk_entity,
            "risk_entity_field": self.risk_entity_field,
            "risk_entity_type": self.risk_entity_type,
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
    dual_pool: DualPool,
    /// NAN-1800: restricted-source registry used to redact
    /// `matched_events_sample` at WRITE time for findings whose origin events
    /// come from a restricted `source_type`. Self-built from the PG pool (no
    /// external wiring); the resolver is Arc-backed and cheap to clone. The
    /// fail-closed policy itself lives in
    /// `SourceScopeResolver::any_restricted` — registry unavailable ⇒ treat as
    /// restricted ⇒ redact (safe: findings are best-effort analytics).
    source_scopes: crate::auth::source_scope_resolver::SourceScopeResolver,
}

impl FindingLogger {
    /// Create a new finding logger backed by a DualPool. ClickHouse is the
    /// findings log store — the append-only contribution stream every risk
    /// score is computed from. (The per-finding Postgres accumulator on
    /// `entity_risk_scores` was removed in NAN-1810 along with the table;
    /// accumulated/decayed scores are derived from these finding rows at
    /// read time.)
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        Self {
            source_scopes: crate::auth::source_scope_resolver::SourceScopeResolver::new(
                dual_pool.postgres().clone(),
            ),
            dual_pool: dual_pool.clone(),
        }
    }

    /// NAN-1800: should this finding's matched-event evidence be redacted?
    ///
    /// - Known origin (`origin_source_types` non-empty): delegate to
    ///   `SourceScopeResolver::any_restricted` — THE home of the fail-closed
    ///   policy (restricted match ⇒ true; registry unavailable ⇒ true).
    /// - Unknown origin (empty — aggregate rules whose result rows drop
    ///   `source_type`): `any_restricted(&[])` would return false, which is
    ///   fail-OPEN for evidence we cannot attribute. Be conservative instead:
    ///   redact whenever ANY restriction exists at all, and redact when the
    ///   registry is unavailable. An empty registry (no restrictions
    ///   configured — the pre-feature default) stays visible, so deployments
    ///   without source scoping are byte-identical to before.
    async fn origin_restricted(&self, finding: &FindingEvent) -> bool {
        if finding.origin_source_types.is_empty() {
            match self.source_scopes.restricted_snapshot().await {
                Ok(restricted) => !restricted.is_empty(),
                // FAIL-CLOSED: registry never loaded + PG down ⇒ redact.
                Err(_) => true,
            }
        } else {
            self.source_scopes
                .any_restricted(&finding.origin_source_types)
                .await
        }
    }

    /// Log a finding event
    #[instrument(skip(self, finding), fields(finding_type = %finding.finding_type, rule_id = %finding.rule_id))]
    pub async fn log_finding(&self, finding: &FindingEvent) -> Result<(), FindingLogError> {
        // NAN-1800: redact restricted-origin evidence BEFORE serialization.
        // `to_log_json()` is pure and feeds BOTH physical write branches (UDM
        // `logs.metadata` below and the OCSF `build_ocsf_finding_event` path
        // inside `log_to_clickhouse`), so the redaction must happen here on
        // the event itself — a downstream no-op "redaction" would still write
        // the sample.
        let redacted_finding;
        let finding = if !finding.matched_events_redacted && self.origin_restricted(finding).await
        {
            let mut event = finding.clone();
            event.redact_matched_events();
            debug!(
                rule_id = %event.rule_id,
                origin_source_types = ?event.origin_source_types,
                "redacting matched_events_sample: restricted (or undeterminable) origin"
            );
            redacted_finding = event;
            &redacted_finding
        } else {
            finding
        };

        let metadata = finding.to_log_json();
        let message = finding.message();
        let timestamp = finding.detected_at;

        self.log_to_clickhouse(&self.dual_pool, &message, &metadata, timestamp)
            .await
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

    /// True if `field` carries `token` as a delimited word — split on any
    /// non-alphanumeric char — rather than as a raw substring. UDM/OCSF field
    /// names are delimited (`src_ip`, `dest_host`, `file_hash`,
    /// `src_endpoint.ip`), so token matching classifies them correctly while
    /// single-word names that merely *contain* the substring — `principal` and
    /// `description` both contain "ip" — no longer misclassify as IP entities
    /// (audit R4d). Matches are case-insensitive.
    fn field_has_token(field: &str, token: &str) -> bool {
        field
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| word.eq_ignore_ascii_case(token))
    }

    /// Infer entity type from field name, falling back to value-based inference.
    ///
    /// Field-name matching is token-based, not substring-based (audit R4d): a
    /// raw `field.contains("ip")` misclassified `principal`/`description` (which
    /// contain the substring "ip") as IP entities, corrupting the stored
    /// `entity_type` and the `WHERE entity_type = …` filter.
    fn infer_entity_type(entity: &str, field_name: Option<&str>) -> &'static str {
        // If we have the field name, use it for accurate classification.
        if let Some(field) = field_name {
            // Cloud account fields (UDM `cloud_account_id`, OCSF
            // `cloud.account.uid`) — checked FIRST because an account id's
            // VALUE is an opaque string that would otherwise infer as "user".
            // This is the type the cloud-overview risk fan-out filters on
            // (NAN-1806); requires BOTH tokens so a bare `account_name` (a
            // user-ish field) is not swallowed.
            if Self::field_has_token(field, "cloud") && Self::field_has_token(field, "account") {
                return crate::risk::clickhouse_sql::CLOUD_ACCOUNT_ENTITY_TYPE;
            }
            // IP address fields. `dvc` (device) is intentionally NOT forced to
            // "ip" — a device identifier may be an IP or a hostname, so it falls
            // through to value-based inference which types it by its actual value.
            if Self::field_has_token(field, "ip") {
                return "ip";
            }
            // Hostname fields (`host`, `src_host`, `hostname`, `dest_hostname`)
            if Self::field_has_token(field, "host") || Self::field_has_token(field, "hostname") {
                return "hostname";
            }
            // User fields
            if Self::field_has_token(field, "user") {
                return "user";
            }
            // Hash fields (`file_hash`, and OCSF plural `file.hashes.sha256`)
            if Self::field_has_token(field, "hash") || Self::field_has_token(field, "hashes") {
                return "hash";
            }
            // Domain fields
            if Self::field_has_token(field, "domain") {
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
    /// `None` uses the finding's own source-event basis (newest matched-event
    /// timestamp, falling back to `now()`); both modes are source-event based (R7).
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
    /// the finding by when the activity happened. `None` uses the finding's own
    /// source-event basis (newest matched-event timestamp, falling back to
    /// `now()`); both modes are source-event based (R7).
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
        // R6 (prevalence/risk audit): findings are best-effort analytics rows,
        // not durable ingest. The ambient ClickHouse client used for logs/audit
        // runs with `wait_for_async_insert=1`, so a per-finding single-row
        // INSERT blocks until the server's adaptive async-insert buffer flushes
        // (2–10s each) — serializing the whole emission loop at one finding per
        // flush. Emit findings fire-and-forget: keep server-side async batching
        // ON but do NOT wait for the flush. A dropped finding row on crash is
        // acceptable (the entity-risk rollup below is written synchronously to
        // Postgres, and findings are searchable analytics, not the audit trail).
        let client = dual_pool
            .clickhouse()
            .clone()
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "0");
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
            // materializes from `event`. NAN-1443: insert into the `ocsf_logs_raw`
            // ENGINE=Null landing table — the `ocsf_logs_raw_mv` MV derives the
            // stored row into `ocsf_logs` (which no longer stores `event`).
            // R7: `ocsf_logs_raw` is an ENGINE=Null landing table with no
            // distributed wrapper, so it resolves to the local name (same as the
            // audit emitter) — but route it through the resolver rather than a
            // bare literal so the `nanosiem.` qualification is consistent.
            let ocsf_raw_table = dual_pool.table_names().local("ocsf_logs_raw");
            let ocsf_query = format!(
                "INSERT INTO {} (event, timestamp, source_type) VALUES (?, ?, 'findings')",
                ocsf_raw_table
            );
            client
                .query(&ocsf_query)
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

        // Insert into ClickHouse logs table with UDM fields as direct columns.
        // R7: route the write through the DualPool distributed-wrapper resolver
        // instead of a bare `logs` literal. On a clustered deployment a bare
        // `INSERT INTO logs` hits the node-local MergeTree only; the resolver
        // returns `logs_distributed` so the row fans out across the cluster
        // (matching SignalProcessor's read routing and the audit emitter).
        let logs_table = dual_pool.table_names().read("logs");
        let query = format!(
            r#"
            INSERT INTO {} (
                timestamp, message, metadata, source_type,
                action, status, rule_id, rule_name, severity,
                risk_score, risk_entity, ingest_time
            ) VALUES (?, ?, ?, 'findings', ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
            logs_table
        );

        client
            .query(&query)
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
                "risk_entity_type": get_str("risk_entity_type"),
                "rule_mode": get_str("rule_mode"),
                "realtime": cloned("realtime", json!(false)),
                "raw_risk_score": cloned("raw_risk_score", json!(0)),
                "mitre_tactics": cloned("mitre_tactics", json!([])),
                "mitre_techniques": cloned("mitre_techniques", json!([])),
                "risk_factors": cloned("risk_factors", json!([])),
                "matched_events_sample": cloned("matched_events_sample", json!([])),
                // NAN-1800: redaction markers — mirrored from `to_log_json`
                // so the OCSF surface carries the same origin/redaction
                // signal as the UDM `metadata` column.
                "origin_source_types": cloned("origin_source_types", json!([])),
                "matched_events_redacted": cloned("matched_events_redacted", json!(false)),
            },
        })
    }
}

/// Errors that can occur during finding logging
#[derive(Debug, thiserror::Error)]
pub enum FindingLogError {
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
            "risk_entity_type": "ip",
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
        // NAN-1806: the write-side type stamp rides the same spill so the
        // shared risk builder's cloud_account branch can read it under OCSF.
        assert_eq!(event["unmapped"]["risk_entity_type"], "ip");
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

/// NAN-1800: write-side redaction of restricted-origin finding evidence.
/// These tests pin the PURE seams: origin derivation from matched events and
/// `redact_matched_events()` flowing through BOTH physical write shapes
/// (`to_log_json` → UDM `logs.metadata`, and `build_ocsf_finding_event` →
/// `ocsf_logs_raw`). The async fail-closed policy itself lives in — and is
/// tested with — `SourceScopeResolver::any_restricted`.
#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn origin_source_types_normalized_and_deduped() {
        let events = vec![
            json!({ "source_type": "  Windows Event Log ", "user": "a" }),
            json!({ "source_type": "windows event log", "user": "b" }),
            json!({ "source_type": "syslog", "user": "c" }),
            json!({ "user": "no-source-type" }),
            json!({ "source_type": "   " }), // whitespace-only → contributes nothing
        ];
        assert_eq!(
            FindingEvent::origin_source_types_from(&events),
            vec!["syslog".to_string(), "windows event log".to_string()],
        );
        // Aggregate-shaped rows (no source_type at all) ⇒ unknown origin.
        assert!(FindingEvent::origin_source_types_from(&[json!({ "count": 7 })]).is_empty());
    }

    #[test]
    fn redaction_flows_to_both_write_branches() {
        let mut finding = FindingEvent {
            finding_type: FindingType::Alert,
            rule_id: Uuid::now_v7(),
            rule_name: "Restricted Origin Rule".to_string(),
            rule_query: "source_type=hr_system secret".to_string(),
            severity: Severity::High,
            rule_mode: crate::models::RuleMode::Alerting,
            mitre_tactics: vec!["TA0006".to_string()],
            mitre_techniques: vec![],
            alert_id: Some(Uuid::now_v7()),
            matched_event_count: 3,
            matched_events_sample: vec![json!({ "user": "ceo", "source_type": "hr_system" })],
            realtime: false,
            detected_at: Utc::now(),
            raw_risk_score: 50,
            risk_score: 75,
            risk_entity: "ceo".to_string(),
            risk_entity_field: Some("user".to_string()),
            risk_entity_type: "user".to_string(),
            risk_factors: vec!["severity_default:High".to_string()],
            origin_source_types: vec!["hr_system".to_string()],
            matched_events_redacted: false,
        };

        finding.redact_matched_events();

        // Struct-level: sample gone, entity neutralized, counts/metadata kept.
        assert!(finding.matched_events_sample.is_empty());
        assert!(finding.matched_events_redacted);
        assert_eq!(finding.risk_entity, "");
        assert_eq!(finding.risk_entity_field, None);
        assert_eq!(finding.matched_event_count, 3);
        assert_eq!(finding.risk_score, 75);

        // Branch 1: UDM `logs.metadata` (to_log_json).
        let metadata = finding.to_log_json();
        assert_eq!(metadata["matched_events_sample"], json!([]));
        assert_eq!(metadata["matched_events_redacted"], json!(true));
        assert_eq!(metadata["origin_source_types"], json!(["hr_system"]));
        assert_eq!(metadata["risk_entity"], json!(""));
        assert_eq!(metadata["matched_event_count"], 3);
        assert!(!metadata.to_string().contains("ceo"), "entity leaked into UDM metadata");

        // Branch 2: OCSF `ocsf_logs_raw` (build_ocsf_finding_event) — built
        // from the SAME metadata JSON, so a no-op redaction upstream would
        // still write the sample here. Both must be empty.
        let message = finding.message();
        let ocsf = FindingLogger::build_ocsf_finding_event(&metadata, &message, finding.detected_at);
        assert_eq!(ocsf["unmapped"]["matched_events_sample"], json!([]));
        assert_eq!(ocsf["unmapped"]["matched_events_redacted"], json!(true));
        assert_eq!(ocsf["unmapped"]["origin_source_types"], json!(["hr_system"]));
        assert_eq!(ocsf["unmapped"]["risk_entity"], json!(""));
        assert!(!ocsf.to_string().contains("ceo"), "entity leaked into OCSF event");

        // The human-readable message falls back to the count-only form — the
        // entity summary (seeded from risk_entity + sample) is neutralized.
        assert_eq!(message, "Restricted Origin Rule - 3 event(s)");
    }

    #[test]
    fn constructors_stamp_origin_and_unredacted() {
        // Deserialization back-compat: rows written before NAN-1800 lack the
        // marker fields entirely — serde defaults must fill them.
        let legacy = json!({
            "finding_type": "alert",
            "rule_id": Uuid::now_v7(),
            "rule_name": "r",
            "rule_query": "q",
            "severity": "high",
            "rule_mode": "alerting",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "alert_id": null,
            "matched_event_count": 1,
            "matched_events_sample": [{"user": "a"}],
            "realtime": false,
            "detected_at": Utc::now().to_rfc3339(),
            "raw_risk_score": 1,
            "risk_score": 1,
            "risk_entity": "a",
            "risk_entity_field": "user",
            "risk_factors": [],
        });
        let event: FindingEvent = serde_json::from_value(legacy).expect("legacy deserializes");
        assert!(event.origin_source_types.is_empty());
        assert!(!event.matched_events_redacted);
    }
}

/// R7: the per-event finding timestamp basis must match the grouped/aggregate
/// basis (source-event time), not the detection execution wall-clock. These
/// tests pin `FindingEvent::source_event_time` — the seam that makes both alert
/// modes consistent.
#[cfg(test)]
mod timestamp_basis_tests {
    use super::*;

    #[test]
    fn source_event_time_picks_newest_event_timestamp() {
        // ClickHouse `DateTime64` serialization ("YYYY-MM-DD HH:MM:SS.fff").
        let events = vec![
            json!({ "timestamp": "2026-06-01 10:00:00.000", "user": "a" }),
            json!({ "timestamp": "2026-06-01 12:30:15.500", "user": "b" }),
            json!({ "timestamp": "2026-06-01 11:00:00.000", "user": "c" }),
        ];
        let got = FindingEvent::source_event_time(&events).expect("some timestamp");
        let want = DateTime::parse_from_rfc3339("2026-06-01T12:30:15.5Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(got, want, "should stamp the newest matched-event time");
    }

    #[test]
    fn source_event_time_parses_rfc3339() {
        let events = vec![json!({ "timestamp": "2026-06-01T09:15:00Z" })];
        let got = FindingEvent::source_event_time(&events).expect("some timestamp");
        assert_eq!(got.to_rfc3339(), "2026-06-01T09:15:00+00:00");
    }

    #[test]
    fn source_event_time_none_when_no_parseable_timestamp() {
        // No `timestamp` field, or an unparseable one -> None (caller falls back
        // to now()). This must NOT panic or silently pick a wrong basis.
        assert!(FindingEvent::source_event_time(&[json!({ "user": "a" })]).is_none());
        assert!(
            FindingEvent::source_event_time(&[json!({ "timestamp": "not-a-time" })]).is_none()
        );
        assert!(FindingEvent::source_event_time(&[]).is_none());
    }

    #[test]
    fn infer_entity_type_matches_delimited_tokens_not_substrings() {
        use FindingLogger as F;
        // Real UDM/OCSF field names still classify correctly.
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("src_ip")), "ip");
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("dest_ip")), "ip");
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("dvc_ip")), "ip");
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("src_endpoint.ip")), "ip");
        // `dvc` (device) is typed by its value, not hardcoded to "ip": an IP
        // value → "ip", a dotted hostname value → "hostname".
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("dvc")), "ip");
        assert_eq!(F::infer_entity_type("host1.corp.example", Some("dvc")), "hostname");
        assert_eq!(F::infer_entity_type("host1", Some("src_host")), "hostname");
        assert_eq!(F::infer_entity_type("host1", Some("hostname")), "hostname");
        assert_eq!(F::infer_entity_type("host1", Some("dest_hostname")), "hostname");
        assert_eq!(F::infer_entity_type("bob", Some("src_user")), "user");
        assert_eq!(F::infer_entity_type("abc", Some("file_hash")), "hash");
        // OCSF plural hash path (tokenizes to `hashes`, not `hash`).
        assert_eq!(F::infer_entity_type("abc", Some("file.hashes.sha256")), "hash");
        assert_eq!(F::infer_entity_type("x.com", Some("dest_domain")), "domain");

        // R4d: field names that merely CONTAIN the substring "ip" must NOT be
        // classified as IP — they fall through to value-based inference.
        assert_ne!(F::infer_entity_type("bob", Some("principal")), "ip");
        assert_ne!(F::infer_entity_type("bob", Some("description")), "ip");
        // A principal/description value that is plainly a username infers "user".
        assert_eq!(F::infer_entity_type("bob", Some("principal")), "user");
    }

    /// NAN-1806: cloud-account fields stamp `cloud_account` — the one type
    /// value inference can never produce (an account id is an opaque string
    /// that would otherwise infer "user"), which left the cloud-overview
    /// `entity_type = 'cloud_account'` risk fan-out permanently empty.
    #[test]
    fn infer_entity_type_stamps_cloud_account_from_field() {
        use FindingLogger as F;
        // UDM + OCSF cloud-account field spellings.
        assert_eq!(
            F::infer_entity_type("123456789012", Some("cloud_account_id")),
            "cloud_account"
        );
        assert_eq!(
            F::infer_entity_type("123456789012", Some("cloud.account.uid")),
            "cloud_account"
        );
        // Requires BOTH tokens: `account_name` is a user-ish field, and a
        // bare `cloud` field says nothing about accounts.
        assert_eq!(F::infer_entity_type("bob", Some("account_name")), "user");
        assert_ne!(F::infer_entity_type("bob", Some("cloud_provider")), "cloud_account");
        // Value-only inference still can't produce it (write-side stamp only).
        assert_ne!(F::infer_entity_type("123456789012", None), "cloud_account");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::risk::RiskResult;
    use crate::models::detection_rule::{AlertMode, DetectionMode};

    /// Minimal valid `DetectionRule` for finding tests. Override only the fields
    /// under test via struct-update syntax:
    /// `DetectionRule { mode: RuleMode::Live, ..sample_rule() }`.
    ///
    /// Keeping the full field list in one place means a schema change is a
    /// one-line fix here instead of across every test — this module sat disabled
    /// behind `#[cfg(any())]` for months precisely because inline struct literals
    /// went stale (NAN-1722).
    fn sample_rule() -> DetectionRule {
        DetectionRule {
            id: Uuid::now_v7(),
            name: "Test Rule".to_string(),
            description: None,
            query: "error".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            detection_mode: DetectionMode::Scheduled,
            materialized_view_name: None,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            archived: false,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
            lookback_minutes: None,
            dataset: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            case_visibility: "private".to_string(),
            case_assigned_group: None,
            alert_mode: AlertMode::Grouped,
            next_run_at: None,
            claimed_by: None,
            claimed_at: None,
            playbook_selector_mode: "none".to_string(),
            playbook_id: None,
            source_path: None,
            source_repo_url: None,
            kind: "standard".to_string(),
            alert_cooldown_minutes: None,
        }
    }

    #[test]
    fn test_finding_type_display() {
        assert_eq!(FindingType::DetectionMatch.to_string(), "detection_match");
        assert_eq!(FindingType::Alert.to_string(), "alert");
    }

    #[test]
    fn test_finding_event_message() {
        let rule = DetectionRule {
            mode: RuleMode::Live,
            ..sample_rule()
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
        // The entity summary is seeded from the risk entity (src_ip) even when
        // the sample event itself doesn't carry the field.
        assert!(finding.message().contains("src_ip=192.168.1.1"));
        assert_eq!(finding.matched_event_count, 1);
        assert_eq!(finding.raw_risk_score, 75);
        assert_eq!(finding.risk_score, 75);
        assert_eq!(finding.risk_entity, "192.168.1.1");
    }

    #[test]
    fn test_finding_event_to_json() {
        let rule = DetectionRule {
            severity: Severity::Critical,
            mitre_tactics: vec!["TA0001".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
            realtime_enabled: true,
            ..sample_rule()
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
        // NAN-1806: the finding row carries the write-side type stamp.
        assert_eq!(json["risk_entity_type"], "user");
        assert_eq!(json["risk_factors"][0], "severity_default:Critical");
    }

    /// NAN-1806: a cloud-account-attributed finding stamps
    /// `risk_entity_type = "cloud_account"` into the log JSON — the seam the
    /// shared risk builder's read-side branch and the PG accumulator both
    /// consume, making the cloud-overview fan-out resolvable.
    #[test]
    fn test_finding_event_stamps_cloud_account_type() {
        let rule = DetectionRule {
            risk_score: Some(60),
            risk_entity_field: Some("cloud_account_id".to_string()),
            ..sample_rule()
        };
        let events = vec![serde_json::json!({"cloud_account_id": "123456789012"})];
        let risk_result = RiskResult::new(
            60,
            60,
            "123456789012".to_string(),
            Some("cloud_account_id".to_string()),
            vec![],
        );
        let finding = FindingEvent::detection_match(&rule, &events, false, risk_result);
        assert_eq!(finding.risk_entity_type, "cloud_account");
        let json = finding.to_log_json();
        assert_eq!(json["risk_entity_type"], "cloud_account");

        // Entityless findings stamp nothing.
        let empty = RiskResult::new(0, 0, String::new(), None, vec![]);
        let finding = FindingEvent::detection_match(&sample_rule(), &[], false, empty);
        assert_eq!(finding.risk_entity_type, "");
    }

    #[test]
    fn test_finding_event_risk_fields() {
        let rule = DetectionRule {
            name: "Risk Test Rule".to_string(),
            risk_score: Some(85),
            risk_entity_field: Some("user".to_string()),
            ..sample_rule()
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

        // Risk fields are surfaced verbatim on the finding.
        assert_eq!(finding.raw_risk_score, 85);
        assert_eq!(finding.risk_score, 42);
        assert_eq!(finding.risk_entity, "attacker");
        assert_eq!(finding.risk_factors.len(), 2);
        assert!(finding
            .risk_factors
            .contains(&"modifier:count > 5".to_string()));
        assert!(finding.risk_factors.contains(&"brute_force".to_string()));

        // And in the log JSON.
        let json = finding.to_log_json();
        assert_eq!(json["raw_risk_score"], 85);
        assert_eq!(json["risk_score"], 42);
        assert_eq!(json["risk_entity"], "attacker");
        assert_eq!(json["risk_factors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_strip_empty_fields() {
        // Event mixing genuinely-empty fields with meaningful falsy values.
        let event = serde_json::json!({
            "src_ip": "10.0.1.30",
            "dest_host": "legacy-erp-2015.internal",
            "user": "vendor_globex",
            "bytes_out": 49885,
            "status_code": 200,
            "url": "http://legacy-erp-2015.internal/",
            // Meaningful falsy evidence — MUST be kept (audit D37).
            "access_count": 0,
            "access_time": 0,
            "additional_answer_count": 0,
            "app_id": 0,
            "false_bool": false,
            // Genuinely empty — stripped.
            "action_mode": "",
            "action_name": "",
            "app": "",
            "auth_result": "",
            "auth_type": "",
            "empty_array": [],
            "empty_object": {},
            "null_field": null,
            "nested": {
                "has_value": "test",
                "zero_number": 0,
                "empty_string": "",
                "empty_nested": {}
            }
        });

        let stripped = FindingEvent::strip_empty_fields(&event);
        let obj = stripped.as_object().unwrap();

        // Non-empty scalars kept.
        assert!(obj.contains_key("src_ip"));
        assert!(obj.contains_key("dest_host"));
        assert!(obj.contains_key("user"));
        assert!(obj.contains_key("bytes_out"));
        assert!(obj.contains_key("status_code"));
        assert!(obj.contains_key("url"));

        // Audit D37: 0 and false are MEANINGFUL evidence (status 0, port 0,
        // auth_result false) — kept, not stripped.
        assert!(obj.contains_key("access_count"));
        assert!(obj.contains_key("access_time"));
        assert!(obj.contains_key("additional_answer_count"));
        assert!(obj.contains_key("app_id"));
        assert!(obj.contains_key("false_bool"));

        // Only genuinely empty values (null / "" / [] / {}) are stripped.
        assert!(!obj.contains_key("action_mode"));
        assert!(!obj.contains_key("action_name"));
        assert!(!obj.contains_key("app"));
        assert!(!obj.contains_key("auth_result"));
        assert!(!obj.contains_key("auth_type"));
        assert!(!obj.contains_key("empty_array"));
        assert!(!obj.contains_key("empty_object"));
        assert!(!obj.contains_key("null_field"));

        // Nested objects are stripped recursively with the same rule.
        assert!(obj.contains_key("nested"));
        let nested = obj["nested"].as_object().unwrap();
        assert!(nested.contains_key("has_value"));
        assert!(nested.contains_key("zero_number")); // 0 kept (D37)
        assert!(!nested.contains_key("empty_string"));
        assert!(!nested.contains_key("empty_nested"));
    }

    #[test]
    fn test_detection_match_strips_empty_fields() {
        let rule = DetectionRule {
            mode: RuleMode::Live,
            ..sample_rule()
        };

        let events = vec![serde_json::json!({
            "src_ip": "192.168.1.1",
            "message": "test error",
            "count": 0,          // meaningful falsy — kept (D37)
            "action": "",        // empty — stripped
            "app": "",
            "bytes": "",
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

        assert_eq!(finding.matched_events_sample.len(), 1);
        let sample = &finding.matched_events_sample[0];
        let obj = sample.as_object().unwrap();

        // Non-empty + meaningful-falsy kept.
        assert!(obj.contains_key("src_ip"));
        assert!(obj.contains_key("message"));
        assert!(obj.contains_key("count")); // 0 kept (D37)

        // Genuinely-empty stripped.
        assert!(!obj.contains_key("action"));
        assert!(!obj.contains_key("app"));
        assert!(!obj.contains_key("bytes"));
        assert!(!obj.contains_key("empty_field"));
    }
}
