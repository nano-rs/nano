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
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::db::DualPool;
use crate::detection::risk::RiskResult;
use crate::models::{Alert, DetectionRule, RuleMode, Severity};
use crate::schema::{active_profile_from_env, SchemaProfile};

/// Finding type distinguishes between live mode matches and actual alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    /// Live mode rule matched - for tuning, no alert created
    DetectionMatch,
    /// Alerting mode rule matched - alert was created
    Alert,
}

/// Pure, transaction-ready lake handoff payload. Shared detection execution
/// uses this to keep the finding outbox write in the same tenant transaction
/// as matches, alerts, risk evidence, and execution completion.
pub(crate) struct LakeFindingPayload {
    pub finding_id: String,
    pub compact_finding: serde_json::Value,
    pub ocsf_event: serde_json::Value,
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
    /// NAN-3224: earliest / latest event time across ALL matched events (not
    /// just the sample). Aggregate rows contribute their `_first_seen` /
    /// `_last_seen` window. Emitted as OCSF `finding_info.first_seen_time` /
    /// `last_seen_time` and `start_time` / `end_time`. Times are not entity
    /// values, so redaction keeps them.
    #[serde(default)]
    pub first_seen_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
    /// NAN-3224: when Nano raised the finding's alert (`alerts.created_at`),
    /// emitted as `finding_info.created_time`. `None` for Live matches, which
    /// use the source-event `detected_at` instead. Never `now()`: a replayed
    /// outbox row must be byte-identical.
    #[serde(default)]
    pub alert_created_at: Option<DateTime<Utc>>,
}

impl FindingEvent {
    fn event_value_at_path<'a>(
        event: &'a serde_json::Value,
        field: &str,
    ) -> Option<&'a serde_json::Value> {
        event.get(field).or_else(|| {
            field
                .split('.')
                .try_fold(event, |current, component| current.get(component))
        })
    }

    fn event_string_values_at_path<'a>(event: &'a serde_json::Value, field: &str) -> Vec<&'a str> {
        fn descend<'a>(
            value: &'a serde_json::Value,
            components: &[&str],
            values: &mut Vec<&'a str>,
        ) {
            if components.is_empty() {
                match value {
                    serde_json::Value::String(value) if !value.trim().is_empty() => {
                        values.push(value)
                    }
                    serde_json::Value::Array(items) => {
                        for item in items {
                            descend(item, components, values);
                        }
                    }
                    _ => {}
                }
                return;
            }
            match value {
                serde_json::Value::Object(object) => {
                    if let Some(next) = object.get(components[0]) {
                        descend(next, &components[1..], values);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        descend(item, components, values);
                    }
                }
                _ => {}
            }
        }

        let mut values = Vec::new();
        if let Some(literal) = event.get(field) {
            descend(literal, &[], &mut values);
        } else {
            let components = field.split('.').collect::<Vec<_>>();
            descend(event, &components, &mut values);
        }
        values
    }

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
            .filter_map(|event| {
                ["time", "timestamp", "start_time", "last_finding_at"]
                    .into_iter()
                    .find_map(|field| {
                        Self::event_value_at_path(event, field)
                            .and_then(Self::parse_source_event_time)
                    })
            })
            .max()
    }

    /// NAN-3224: the matched events' event-time window (see `first_seen_at`).
    fn seen_window(events: &[serde_json::Value]) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        match crate::detection::finding_ocsf::seen_window_ms(events, Self::parse_source_event_time) {
            Some((first, last)) => (
                DateTime::from_timestamp_millis(first),
                DateTime::from_timestamp_millis(last),
            ),
            None => (None, None),
        }
    }

    fn parse_source_event_time(value: &serde_json::Value) -> Option<DateTime<Utc>> {
        if let Some(timestamp) = value.as_str() {
            // Match the ClickHouse/serialized formats detection events use
            // (see detection::service::helpers::event_field_time).
            if let Ok(naive) =
                chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.f")
            {
                return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
            }
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S")
            {
                return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
            }
            return DateTime::parse_from_rfc3339(timestamp)
                .ok()
                .map(|date_time| date_time.with_timezone(&Utc));
        }

        // OCSF 1.9 serializes `time` as Unix epoch milliseconds. Native data
        // sources can also surface seconds, microseconds, or nanoseconds as a
        // JSON integer, so select the unit by contemporary epoch magnitude.
        // Keeping the event timestamp deterministic is part of the finding ID:
        // falling back to `Utc::now()` on every outbox retry would mint duplicate
        // findings and double-count risk for the same alert.
        let epoch = value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))?;
        let magnitude = epoch.unsigned_abs();
        if magnitude >= 100_000_000_000_000_000 {
            let seconds = epoch.div_euclid(1_000_000_000);
            let nanos = epoch.rem_euclid(1_000_000_000) as u32;
            DateTime::from_timestamp(seconds, nanos)
        } else if magnitude >= 100_000_000_000_000 {
            DateTime::from_timestamp_micros(epoch)
        } else if magnitude >= 100_000_000_000 {
            DateTime::from_timestamp_millis(epoch)
        } else {
            DateTime::from_timestamp(epoch, 0)
        }
    }

    /// Distinct normalized `source_type` values carried by the matched events
    /// (NAN-1800). Normalization is trim + lowercase — OCSF `source_type` is
    /// NOT ingest-lowercased, and the restricted-source registry stores
    /// normalized values. Events without a `source_type` string contribute
    /// nothing; an all-empty result means "origin unknown" and the write-side
    /// policy treats that conservatively (see `FindingLogger::origin_restricted`).
    ///
    /// NAN-2001: aggregate rules (stats/timechart/top/rare) collapse the raw
    /// stream, so their result rows carry NO per-event `source_type` — origin
    /// would come out empty and the audit sentinel in `origin_restricted` would
    /// never see the audit actor that leaked in via `risk_entity`. The detection
    /// engine stamps such rows with the window's distinct source types under
    /// `_nano_source_types` (the same array that fills `alerts.source_types`,
    /// via `annotate_source_types_for_scoping`); harvest it here so aggregate
    /// audit findings become KNOWN-origin and are redacted precisely (no
    /// over-redaction of non-audit aggregate findings). Mirrors
    /// `db::repository::alerts::distinct_source_types`.
    fn origin_source_types_from(events: &[serde_json::Value]) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut insert_normalized = |raw: &str| {
            let normalized = raw.trim().to_lowercase();
            if !normalized.is_empty() {
                set.insert(normalized);
            }
        };
        for event in events {
            // NAN-2155 (codex round 3): the per-event `source_type` is
            // ingest-controlled; only the engine's `_nano_source_types` stamp
            // may carry the reserved unresolved-provenance sentinel.
            if let Some(st) = Self::event_value_at_path(event, "metadata.log_source")
                .or_else(|| Self::event_value_at_path(event, "source_type"))
                .and_then(|v| v.as_str())
                .filter(|st| !crate::auth::is_reserved_source_type(st))
            {
                insert_normalized(st);
            }
            if let Some(arr) = event.get("_nano_source_types").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(st) = v.as_str() {
                        insert_normalized(st);
                    }
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
        let (first_seen_at, last_seen_at) = Self::seen_window(matched_events);

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
            first_seen_at,
            last_seen_at,
            alert_created_at: None,
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
        let (first_seen_at, last_seen_at) = Self::seen_window(&matched_events);

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
            first_seen_at,
            last_seen_at,
            alert_created_at: Some(alert.created_at),
        }
    }

    /// NAN-3226: a `domain`-typed risk object under one of the tenant's
    /// internal suffixes (built-in or tenant-added) is an internal HOST, not an
    /// internet domain: re-type it `hostname` so it is never scored or
    /// projected as a domain (OCSF `evidences.query.hostname`). Host risk
    /// objects are untouched. Returns whether the type changed.
    pub fn retype_internal_domain(
        &mut self,
        internal: &crate::internal_domains::InternalDomains,
    ) -> bool {
        if self.risk_entity_type == "domain" && internal.is_internal(&self.risk_entity) {
            self.risk_entity_type = "hostname".to_string();
            return true;
        }
        false
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
            // NAN-3224: OCSF timing inputs (epoch milliseconds).
            "first_seen_time": self.first_seen_at.map(|t| t.timestamp_millis()),
            "last_seen_time": self.last_seen_at.map(|t| t.timestamp_millis()),
            "alert_created_time": self.alert_created_at.map(|t| t.timestamp_millis()),
        })
    }

    /// Generate a human-readable message for the finding
    pub fn message(&self) -> String {
        self.message_with_entities(self.extract_entity_summary())
    }

    /// [`Self::message`] under an explicit schema profile (tests pin the
    /// profile instead of depending on the process environment).
    #[cfg(test)]
    fn message_with_profile(&self, profile: &dyn SchemaProfile) -> String {
        self.message_with_entities(self.extract_entity_summary_with_profile(profile))
    }

    fn message_with_entities(&self, entities: String) -> String {
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
        // NAN-2361: no UdmProfile substitution. `extract_entity_summary_with_profile`
        // walks `profile.entity_extraction_order()`, so the wrong profile names
        // fields that do not exist in the event and the summary is wrong (or
        // empty) with no explanation. An empty summary is already a supported
        // degradation here — `message()` falls back to the count-only form (see
        // `redact_matched_events`) — so fail closed and log the reason.
        let Ok(profile) = active_profile_from_env().inspect_err(|error| {
            tracing::error!(
                %error,
                "finding entity summary omitted: cannot resolve the active schema profile"
            );
        }) else {
            return String::new();
        };
        self.extract_entity_summary_with_profile(profile.as_ref())
    }

    fn extract_entity_summary_with_profile(&self, profile: &dyn SchemaProfile) -> String {
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
            for (_, field) in profile.entity_extraction_order() {
                if found.len() >= 4 {
                    break;
                }
                for value in Self::event_string_values_at_path(first_event, field) {
                    if found.len() >= 4 {
                        break;
                    }
                    if seen_values.insert(value.to_string()) {
                        found.push((field.to_string(), value.to_string()));
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

    /// NAN-1800 / NAN-2001: should this finding's matched-event evidence be
    /// redacted?
    ///
    /// - Always-restricted sentinel origin (`'audit'`, NAN-2001): redact,
    ///   checked FIRST and WITHOUT any PostgreSQL access, so audit findings
    ///   redact even when the registry is empty or PG is unreachable. Aggregate
    ///   audit rules reach this branch because `origin_source_types_from`
    ///   harvests the engine's `_nano_source_types` stamp (NAN-2001 Change 2).
    /// - Known origin (`origin_source_types` non-empty): delegate to
    ///   `SourceScopeResolver::any_restricted` — THE home of the fail-closed
    ///   policy (restricted match ⇒ true; registry unavailable ⇒ true).
    /// - Unknown origin (empty — a finding with no attributable source, e.g. a
    ///   retro-hunt indicator summary): `any_restricted(&[])` would return
    ///   false, which is fail-OPEN for evidence we cannot attribute. Be
    ///   conservative instead: redact whenever ANY restriction exists at all,
    ///   and redact when the registry is unavailable. An empty registry (no
    ///   restrictions configured — the pre-feature default) stays visible, so
    ///   deployments without source scoping are byte-identical to before.
    async fn origin_restricted(&self, finding: &FindingEvent) -> bool {
        // NAN-2001: audit origin is ALWAYS restricted — short-circuit before any
        // PG access so this holds on every deployment and during a PG outage.
        if crate::auth::is_always_restricted_origin(&finding.origin_source_types) {
            return true;
        }
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
        let finding = if !finding.matched_events_redacted && self.origin_restricted(finding).await {
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

        // NAN-3226: internal names are host risk objects, never domains.
        let retyped_finding;
        let finding = if finding.risk_entity_type == "domain" {
            let internal =
                crate::internal_domains::dedicated_cached(self.dual_pool.postgres()).await;
            let mut event = finding.clone();
            if event.retype_internal_domain(&internal) {
                retyped_finding = event;
                &retyped_finding
            } else {
                finding
            }
        } else {
            finding
        };

        let metadata = finding.to_log_json();
        let message = finding.message();
        let timestamp = finding.detected_at;

        if crate::schema::log_query_backend_is_lake() {
            return self.log_to_lake_outbox(finding).await;
        }

        self.log_to_clickhouse(&self.dual_pool, &message, &metadata, timestamp)
            .await
    }

    fn stable_finding_id(finding: &FindingEvent) -> String {
        if let Some(alert_id) = finding.alert_id {
            // A grouped alert can emit one risk finding per entity. The alert
            // UUID alone therefore is not a finding identity: using it as the
            // outbox key makes the first entity win and every later entity
            // look like a conflicting replay. Bind the alert to the same
            // source-event window + entity dimensions that distinguish the
            // compact risk rows. Deliberately leave score/rule payload out of
            // the identity so a replay whose content changed still fails the
            // immutable conflict check below instead of silently becoming a
            // second finding.
            let identity = json!({
                "alert_id": alert_id,
                "detected_at_us": finding.detected_at.timestamp_micros(),
                "risk_entity": finding.risk_entity,
                "risk_entity_field": finding.risk_entity_field,
                "risk_entity_type": finding.risk_entity_type,
            });
            let bytes = serde_json::to_vec(&identity).unwrap_or_default();
            return format!("alert:{alert_id}:{}", hex::encode(Sha256::digest(bytes)));
        }
        let identity = json!({
            "finding_type": finding.finding_type,
            "rule_id": finding.rule_id,
            "detected_at_us": finding.detected_at.timestamp_micros(),
            "risk_entity": finding.risk_entity,
            "risk_score": finding.risk_score,
            "origin_source_types": finding.origin_source_types,
        });
        let bytes = serde_json::to_vec(&identity).unwrap_or_default();
        format!("detection:{}", hex::encode(Sha256::digest(bytes)))
    }

    pub(crate) fn prepare_lake_outbox_payload(
        finding: &FindingEvent,
        logical_tenant_id: &str,
    ) -> Result<LakeFindingPayload, FindingLogError> {
        if logical_tenant_id.trim().is_empty() {
            return Err(FindingLogError::LakeOutboxError(
                "logical lake tenant is required for finding publication".to_string(),
            ));
        }
        let finding_id = Self::stable_finding_id(finding);
        let metadata = finding.to_log_json();
        let message = finding.message();
        let timestamp = finding.detected_at;
        let compact_finding = json!({
            "id": finding_id,
            "timestamp_us": timestamp.timestamp_micros(),
            "entity": if finding.risk_entity.trim().is_empty() { "unknown" } else { finding.risk_entity.as_str() },
            "stamped_entity_type": finding.risk_entity_type,
            "risk_score": finding.risk_score,
            "rule_id": finding.rule_id.to_string(),
            "rule_name": finding.rule_name,
            "severity": format!("{:?}", finding.severity).to_lowercase(),
            "origin_source_types": finding.origin_source_types,
            "mitre_tactics": finding.mitre_tactics,
        });
        let ocsf_event = Self::build_ocsf_finding_event_for_lake(
            &metadata,
            &message,
            timestamp,
            &finding_id,
            logical_tenant_id,
        );
        Ok(LakeFindingPayload {
            finding_id,
            compact_finding,
            ocsf_event,
        })
    }

    async fn log_to_lake_outbox(&self, finding: &FindingEvent) -> Result<(), FindingLogError> {
        let tenant_id = std::env::var("NANO_LAKE_TENANT_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        if tenant_id.is_empty() {
            return Err(FindingLogError::LakeOutboxError(
                "NANO_LAKE_TENANT_ID is required for lake finding publication".to_string(),
            ));
        }
        let security_tenant_id = Self::lake_outbox_security_tenant(
            &tenant_id,
            crate::search::lake_cell::trusted_local_from_env(),
        )?;
        let payload = Self::prepare_lake_outbox_payload(finding, &tenant_id)?;
        let finding_id = payload.finding_id;
        let compact = payload.compact_finding;
        let ocsf_event = payload.ocsf_event;
        let mut transaction = self
            .dual_pool
            .postgres()
            .begin()
            .await
            .map_err(|error| FindingLogError::LakeOutboxError(error.to_string()))?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO detection_finding_lake_outbox
                (security_tenant_id, tenant_id, finding_id, compact_finding, ocsf_event)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(security_tenant_id)
        .bind(&tenant_id)
        .bind(&finding_id)
        .bind(&compact)
        .bind(&ocsf_event)
        .execute(&mut *transaction)
        .await
        .map_err(|error| FindingLogError::LakeOutboxError(error.to_string()))?
        .rows_affected();
        if inserted == 0 {
            let existing = sqlx::query_as::<_, (serde_json::Value, serde_json::Value)>(
                r#"
                SELECT compact_finding, ocsf_event
                FROM detection_finding_lake_outbox
                WHERE security_tenant_id = $1 AND tenant_id = $2 AND finding_id = $3
                "#,
            )
            .bind(security_tenant_id)
            .bind(&tenant_id)
            .bind(&finding_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| FindingLogError::LakeOutboxError(error.to_string()))?;
            if !Self::outbox_replay_matches(&existing.0, &existing.1, &compact, &ocsf_event) {
                return Err(FindingLogError::LakeOutboxError(format!(
                    "finding ID {finding_id} was replayed with different content"
                )));
            }
        }
        transaction
            .commit()
            .await
            .map_err(|error| FindingLogError::LakeOutboxError(error.to_string()))?;
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

        // An email address commonly contains a dot as well. Check it before
        // the hostname heuristic so `alice@example.com` is not stamped as a
        // hostname in the risk projection.
        if entity.contains('@') {
            return "email";
        }

        // Check if it looks like a hostname (contains dots but not an IP)
        if entity.contains('.') && !entity.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return "hostname";
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

    fn ocsf_risk_level(risk_score: i64) -> (i64, &'static str) {
        match risk_score {
            ..=30 => (1, "Low"),
            31..=50 => (2, "Medium"),
            51..=70 => (3, "High"),
            _ => (4, "Critical"),
        }
    }

    fn metadata_strings(metadata: &serde_json::Value, field: &str) -> Vec<String> {
        metadata
            .get(field)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect()
    }

    /// OCSF `analytic.state_id` / `state` for a Nano rule mode (OCSF 1.9.0
    /// captions). Lossless: Alerting=Active, Live=Experimental (bake-in),
    /// Paused=Suppressed, anything else (Staging rule tests) is Other with the
    /// Nano mode as its `state`.
    fn ocsf_analytic_state(rule_mode: &str) -> (i64, String) {
        match rule_mode {
            "alerting" => (1, "Active".to_string()),
            "paused" => (2, "Suppressed".to_string()),
            "live" => (3, "Experimental".to_string()),
            "" => (0, "Unknown".to_string()),
            other => (99, other.to_string()),
        }
    }

    /// The scored entity as the finding's per-entity risk object (NAN-3224).
    ///
    /// Findings are the risk index: every finding scores exactly one entity
    /// (grouped rules emit one finding per entity, NAN-2713), so the risk
    /// object is `resources[0]` with a uniform `name` (the entity value) and
    /// `type` (Nano's entity type: `user`, `hostname`, `ip`, `email`, `hash`,
    /// `domain`, `url`, `cloud_account`), and the score added to it is the
    /// finding's top-level `risk_score`. Where OCSF 1.9 has a typed risk home
    /// (`user.risk_score`, `device.risk_score`) it is filled as well. Returns
    /// `(resources, observables)`; the entity observable points at
    /// `resources[0]`.
    fn ocsf_entity_projection(
        metadata: &serde_json::Value,
        risk_score: i64,
        risk_level_id: i64,
        risk_level: &str,
    ) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
        use crate::detection::finding_ocsf::{observable, observable_type as kind};
        let entity = metadata
            .get("risk_entity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim();
        if entity.is_empty() || entity == "unknown" {
            return (Vec::new(), Vec::new());
        }
        let field = metadata
            .get("risk_entity_field")
            .and_then(serde_json::Value::as_str);
        let stamped_type = metadata
            .get("risk_entity_type")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| Self::infer_entity_type(entity, field));
        let risk = json!({
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_level_id": risk_level_id,
        });
        let mut resource = serde_json::Map::from_iter([
            ("name".to_string(), json!(entity)),
            ("type".to_string(), json!(stamped_type)),
            ("role".to_string(), json!("Affected")),
            ("role_id".to_string(), json!(3)),
        ]);
        let (extra, observable) = match stamped_type {
            "ip" if entity.parse::<std::net::IpAddr>().is_ok() => (
                json!({ "ip": entity }),
                observable("resources[0].ip", kind::IP_ADDRESS, entity),
            ),
            "hostname" | "host" | "device" => {
                let mut device = json!({ "name": entity, "hostname": entity, "type_id": 0 });
                device.as_object_mut().expect("object").extend(risk.as_object().expect("object").clone());
                (
                    json!({ "hostname": entity, "device": device }),
                    observable("resources[0].hostname", kind::HOSTNAME, entity),
                )
            }
            "user" => {
                let mut user = json!({ "name": entity });
                user.as_object_mut().expect("object").extend(risk.as_object().expect("object").clone());
                (
                    json!({ "user": user }),
                    observable("resources[0].user.name", kind::USER_NAME, entity),
                )
            }
            "email" => (json!({}), observable("resources[0].name", kind::EMAIL_ADDRESS, entity)),
            "domain" => (
                json!({ "hostname": entity }),
                observable("resources[0].hostname", kind::HOSTNAME, entity),
            ),
            "hash" => (json!({}), observable("resources[0].name", kind::HASH, entity)),
            "url" => (json!({}), observable("resources[0].name", kind::URL_STRING, entity)),
            "cloud_account" => (
                json!({ "uid": entity }),
                observable("resources[0].uid", kind::RESOURCE_UID, entity),
            ),
            _ => (json!({}), observable("resources[0].name", kind::OTHER, entity)),
        };
        if let Some(extra) = extra.as_object() {
            resource.extend(extra.clone());
        }
        (vec![serde_json::Value::Object(resource)], vec![observable])
    }

    /// Build a backward-compatible OCSF Detection Finding (`class_uid` 2004)
    /// for the temporary ClickHouse path. New lake publication uses
    /// [`Self::build_ocsf_finding_event_for_lake`] so event and tenant identity
    /// are explicit and Nano compatibility duplicates are omitted.
    pub fn build_ocsf_finding_event(
        metadata: &serde_json::Value,
        message: &str,
        timestamp: DateTime<Utc>,
    ) -> serde_json::Value {
        Self::build_ocsf_finding_event_inner(metadata, message, timestamp, None, None, true)
    }

    fn build_ocsf_finding_event_for_lake(
        metadata: &serde_json::Value,
        message: &str,
        timestamp: DateTime<Utc>,
        finding_id: &str,
        tenant_id: &str,
    ) -> serde_json::Value {
        Self::build_ocsf_finding_event_inner(
            metadata,
            message,
            timestamp,
            Some(finding_id),
            Some(tenant_id),
            false,
        )
    }

    /// NAN-3224: the app-relative deep link of a finding's alert, the same
    /// form in-app notifications use (`/alerts/<alert typeid>`). Relative so
    /// the stored row never embeds a tenant host that can change.
    fn alert_src_url(alert_id: &str) -> Option<String> {
        let alert_id = Uuid::parse_str(alert_id).ok()?;
        Some(format!(
            "/alerts/{}",
            crate::typeid::encode(crate::typeid::alert::PREFIX, &alert_id)
        ))
    }

    /// NAN-3224 shape, every Nano `unmapped` key now has an OCSF 1.9 home
    /// unless the spec has none:
    ///
    /// | was                         | now (OCSF 1.9)                                   |
    /// |-----------------------------|--------------------------------------------------|
    /// | `unmapped.alert_id`         | `finding_info.uid_alt` (+ `finding_info.src_url`) |
    /// | `unmapped.signal_type`      | `is_alert` (+ `finding_info.types`, unchanged)    |
    /// | `unmapped.rule_mode`        | `finding_info.analytic.state_id` / `state`        |
    /// | `unmapped.risk_factors`     | `risk_details` (already emitted, joined)          |
    /// | `unmapped.matched_events_sample` | `evidences[]` (curated + raw `data`)         |
    /// | `unmapped.raw_risk_score`   | stays: OCSF has no pre-weight score attribute     |
    /// | `unmapped.realtime`         | stays: no OCSF attribute                          |
    /// | `unmapped.matched_events_redacted` | stays: no OCSF attribute                   |
    ///
    /// The ClickHouse compatibility event keeps every historical `unmapped`
    /// key too (its readers extract them), and adds the native fields.
    fn build_ocsf_finding_event_inner(
        metadata: &serde_json::Value,
        message: &str,
        timestamp: DateTime<Utc>,
        event_uid: Option<&str>,
        tenant_uid: Option<&str>,
        include_clickhouse_compat: bool,
    ) -> serde_json::Value {
        use crate::detection::finding_ocsf;
        let get_str = |k: &str| metadata.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let cloned =
            |k: &str, default: serde_json::Value| metadata.get(k).cloned().unwrap_or(default);

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
        let (risk_level_id, risk_level) = Self::ocsf_risk_level(risk_score);
        let signal_type = get_str("signal_type");
        let rule_id = get_str("rule_id");
        let rule_name = get_str("rule_name");
        let alert_id = metadata
            .get("alert_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        let event_uid = event_uid.unwrap_or(alert_id.unwrap_or(rule_id));
        let data_sources = metadata
            .get("origin_source_types")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let attacks = finding_ocsf::attacks(
            &Self::metadata_strings(metadata, "mitre_tactics"),
            &Self::metadata_strings(metadata, "mitre_techniques"),
        );
        let risk_details = Self::metadata_strings(metadata, "risk_factors").join("; ");
        let (resources, mut observables) =
            Self::ocsf_entity_projection(metadata, risk_score, risk_level_id, risk_level);
        // The sample is already redaction-filtered (`log_finding` /
        // `redact_matched_events` empty it), so restricted evidence never
        // reaches `evidences[]` or the observables derived from it.
        let sample = metadata
            .get("matched_events_sample")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let projection = finding_ocsf::evidences(&sample);
        finding_ocsf::evidence_observables(&mut observables, &projection.evidences);
        // NAN-4169: a retro IOC match (an auto retro-hunt hit: the indicator
        // was learned after the event was ingested) is a searchable signal of
        // its own. The rule query marker survives sample redaction.
        let retro_ioc = get_str("rule_query").starts_with("retro-hunt:")
            || sample
                .iter()
                .any(|event| event.get("retro_ioc").and_then(serde_json::Value::as_bool) == Some(true));

        let time_ms = timestamp.timestamp_millis();
        let first_seen = metadata.get("first_seen_time").and_then(serde_json::Value::as_i64);
        let last_seen = metadata.get("last_seen_time").and_then(serde_json::Value::as_i64);
        let created_time = metadata
            .get("alert_created_time")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(time_ms);
        let (state_id, state) = Self::ocsf_analytic_state(get_str("rule_mode"));

        let mut finding_info = json!({
            "title": rule_name,
            "uid": event_uid,
            "types": if retro_ioc { json!([signal_type, "retro_ioc"]) } else { json!([signal_type]) },
            "data_sources": data_sources,
            "attacks": attacks,
            "analytic": {
                "name": rule_name,
                "uid": rule_id,
                "type": "Rule",
                "type_id": 1,
                "state": state,
                "state_id": state_id,
            },
            "created_time": created_time,
            "first_seen_time": first_seen,
            "last_seen_time": last_seen,
            "related_events": projection.related_events,
            "uid_alt": alert_id,
            "src_url": alert_id.and_then(Self::alert_src_url),
        });
        finding_info = FindingEvent::strip_empty_fields(&finding_info);

        let mut unmapped = json!({
            "realtime": cloned("realtime", json!(false)),
            "raw_risk_score": cloned("raw_risk_score", json!(0)),
            "matched_events_redacted": cloned("matched_events_redacted", json!(false)),
        });
        if retro_ioc {
            unmapped["retro"] = json!(true);
            unmapped["retro_ioc"] = json!(true);
        }
        if include_clickhouse_compat {
            // ClickHouse readers (risk SQL, tuning, nPL bare-field aliases)
            // extract these from the stored `unmapped` spill.
            let compatibility = json!({
                "rule_mode": get_str("rule_mode"),
                "risk_factors": cloned("risk_factors", json!([])),
                "matched_events_sample": cloned("matched_events_sample", json!([])),
                "signal_type": signal_type,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "risk_score": risk_score,
                "risk_entity": get_str("risk_entity"),
                "risk_entity_field": cloned("risk_entity_field", serde_json::Value::Null),
                "risk_entity_type": get_str("risk_entity_type"),
                "mitre_tactics": cloned("mitre_tactics", json!([])),
                "mitre_techniques": cloned("mitre_techniques", json!([])),
                "origin_source_types": cloned("origin_source_types", json!([])),
            });
            if let (Some(target), Some(values)) =
                (unmapped.as_object_mut(), compatibility.as_object())
            {
                target.extend(values.clone());
            }
        } else if !projection.unmapped_samples.is_empty() {
            // Matched rows with no OCSF evidence attribute (bare aggregate
            // results) keep the historical home: canonical JSON strings, so
            // free-form shapes never become typed lake columns.
            unmapped["matched_events_sample"] = serde_json::Value::Array(projection.unmapped_samples);
        }

        let mut event = json!({
            "class_uid": CLASS_UID,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": ACTIVITY_ID,
            "activity_name": "Create",
            "type_uid": CLASS_UID * 100 + ACTIVITY_ID, // 200401
            // OCSF `time` is epoch milliseconds.
            "time": time_ms,
            "start_time": first_seen,
            "end_time": last_seen,
            "severity_id": severity_id,
            "severity": severity_title,
            "status_id": 1,
            "status": "New",
            "is_alert": signal_type == "alert",
            "risk_score": risk_score,
            "risk_level_id": risk_level_id,
            "risk_level": risk_level,
            "risk_details": risk_details,
            "message": message,
            "count": cloned("matched_event_count", json!(1)),
            "metadata": {
                "product": { "name": "nano", "vendor_name": "nano" },
                "version": "1.9.0",
                "log_name": FINDINGS_LOG_NAME,
                // The lean drain stamps `findings` on the lake row; the outbox
                // copy keeps `signals`, the durable event-kind contract of
                // the hosted Iceberg publisher (`iceberg.rs`). ClickHouse
                // rows carry `findings` like their `source_type` column.
                "log_source": if include_clickhouse_compat { FINDINGS_LOG_NAME } else { "signals" },
                "tenant_uid": tenant_uid,
                "uid": event_uid,
            },
            "finding_info": finding_info,
            "resources": resources,
            "evidences": projection.evidences,
            "observables": observables,
            "unmapped": unmapped,
        });
        event = FindingEvent::strip_empty_fields(&event);
        event
    }

    /// The outbox row's `security_tenant_id` (NAN-3492). A UUID lake tenant
    /// is its own security tenant: the lean finding drain selects, and its
    /// hosted RLS policy scopes, on `security_tenant_id = <tenant uuid>`
    /// (`part_ingest/finding_outbox.rs`). A non-UUID (legacy gen1) tenant
    /// keeps the migration-336 compatibility tenant. Only the trusted-local
    /// install is strict: it must carry a non-nil UUID tenant, never the
    /// compatibility fallback, because its drain would never select it.
    pub(crate) fn lake_outbox_security_tenant(
        lake_tenant_id: &str,
        trusted_local: bool,
    ) -> Result<Uuid, FindingLogError> {
        if !trusted_local {
            return Ok(Uuid::parse_str(lake_tenant_id)
                .unwrap_or(crate::reports::COMPATIBILITY_TENANT_ID));
        }
        Uuid::parse_str(lake_tenant_id)
            .ok()
            .filter(|tenant| !tenant.is_nil())
            .ok_or_else(|| {
                FindingLogError::LakeOutboxError(
                    "a trusted-local install needs a UUID NANO_LAKE_TENANT_ID for finding publication"
                        .to_string(),
                )
            })
    }

    /// NAN-3224: is a stored outbox row an acceptable replay of `compact` /
    /// `ocsf_event`? The compact finding (the risk record) must match exactly.
    /// The OCSF event must match too, except that a row stored by a
    /// pre-NAN-3224 producer (`metadata.log_name = "signals"`) is a valid
    /// replay of the same finding re-emitted after the deploy: the stored
    /// row wins and nothing is rewritten.
    pub(crate) fn outbox_replay_matches(
        stored_compact: &serde_json::Value,
        stored_event: &serde_json::Value,
        compact: &serde_json::Value,
        ocsf_event: &serde_json::Value,
    ) -> bool {
        stored_compact == compact
            && (stored_event == ocsf_event
                || stored_event.pointer("/metadata/log_name").and_then(serde_json::Value::as_str)
                    == Some(LEGACY_SIGNALS_LOG_NAME))
    }
}

/// `metadata.log_name` of every Detection Finding Nano emits (NAN-3224).
pub const FINDINGS_LOG_NAME: &str = "findings";
/// `metadata.log_name` of findings emitted before NAN-3224.
pub const LEGACY_SIGNALS_LOG_NAME: &str = "signals";

/// Errors that can occur during finding logging
#[derive(Debug, thiserror::Error)]
pub enum FindingLogError {
    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),
    #[error("Lake finding outbox error: {0}")]
    LakeOutboxError(String),
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
            "risk_factors": ["off-hours"],
            "origin_source_types": ["windows_security"]
        })
    }

    #[test]
    fn builds_spec_shaped_detection_finding_2004() {
        let ts = DateTime::parse_from_rfc3339("2026-06-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = FindingLogger::build_ocsf_finding_event(
            &sample_metadata(),
            "Suspicious Login - src_ip=10.0.0.5",
            ts,
        );

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
        assert_eq!(event["metadata"]["version"], "1.9.0");
    }

    /// NAN-4169: a retro-hunt hit is flagged on the finding itself, so
    /// `finding_info.types="retro_ioc"` / `unmapped.retro_ioc=true` find it
    /// even when the matched-event sample is redacted.
    #[test]
    fn retro_hunt_findings_carry_the_retro_ioc_flag() {
        let ts = DateTime::parse_from_rfc3339("2026-10-19T12:00:00Z").unwrap().with_timezone(&Utc);
        let mut metadata = sample_metadata();
        metadata["rule_query"] = json!("retro-hunt: new IOCs from all feeds over last 5d");
        metadata["risk_entity"] = json!("198.51.100.9:443");
        metadata["risk_entity_field"] = json!("indicator");
        let event = FindingLogger::build_ocsf_finding_event(&metadata, "retro", ts);
        assert_eq!(event["finding_info"]["types"], json!(["detection_match", "retro_ioc"]));
        assert_eq!(event["unmapped"]["retro_ioc"], true);
        assert_eq!(event["unmapped"]["retro"], true);
        let mut sampled = sample_metadata();
        sampled["matched_events_sample"] = json!([{"indicator": "evil.example", "retro_ioc": true}]);
        let event = FindingLogger::build_ocsf_finding_event(&sampled, "retro", ts);
        assert_eq!(event["unmapped"]["retro_ioc"], true);
        let plain = FindingLogger::build_ocsf_finding_event(&sample_metadata(), "plain", ts);
        assert_eq!(plain["finding_info"]["types"], json!(["detection_match"]));
        assert!(plain["unmapped"].get("retro_ioc").is_none());
    }

    #[test]
    fn lake_finding_uses_native_ocsf_identity_risk_and_observables() {
        let ts = DateTime::parse_from_rfc3339("2026-06-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = FindingLogger::build_ocsf_finding_event_for_lake(
            &sample_metadata(),
            "Suspicious Login - src_endpoint.ip=10.0.0.5",
            ts,
            "detection:stable-finding-id",
            "tenant-a",
        );

        assert_eq!(event["metadata"]["uid"], "detection:stable-finding-id");
        assert_eq!(event["metadata"]["tenant_uid"], "tenant-a");
        // NAN-3224: one name. The drain stamps `log_source=findings` on the
        // lake row; the outbox copy keeps the publisher's `signals` kind.
        assert_eq!(event["metadata"]["log_name"], "findings");
        assert_eq!(event["metadata"]["log_source"], "signals");
        assert_eq!(event["finding_info"]["uid"], "detection:stable-finding-id");
        assert_eq!(event["finding_info"]["analytic"]["uid"], "rule-abc-123");
        assert_eq!(event["finding_info"]["analytic"]["type"], "Rule");
        // rule_mode=live -> analytic state Experimental (bake-in).
        assert_eq!(event["finding_info"]["analytic"]["state_id"], 3);
        assert_eq!(event["finding_info"]["analytic"]["state"], "Experimental");
        assert_eq!(
            event["finding_info"]["data_sources"],
            json!(["windows_security"])
        );
        // NAN-3224: one attack per technique, paired with its tactic, named.
        assert_eq!(
            event["finding_info"]["attacks"],
            json!([{
                "technique": {"uid": "T1078", "name": "Valid Accounts"},
                "tactic": {"uid": "TA0001", "name": "Initial Access"},
                "version": "19.1",
            }])
        );
        assert_eq!(event["risk_score"], 75);
        assert_eq!(event["risk_level_id"], 4);
        assert_eq!(event["risk_level"], "Critical");
        assert_eq!(event["risk_details"], "off-hours");
        // Per-entity risk object: resources[0] {name, type} + the score.
        assert_eq!(event["resources"][0]["ip"], "10.0.0.5");
        assert_eq!(event["resources"][0]["name"], "10.0.0.5");
        assert_eq!(event["resources"][0]["type"], "ip");
        assert_eq!(event["resources"][0]["role_id"], 3);
        assert_eq!(event["observables"][0]["name"], "resources[0].ip");
        assert_eq!(event["observables"][0]["type_id"], 2);
        assert_eq!(event["observables"][0]["value"], "10.0.0.5");
        assert_eq!(event["is_alert"], false);
        assert_eq!(event["finding_info"]["types"], json!(["detection_match"]));
        // No alert: nothing to pivot to.
        assert!(event["finding_info"].get("uid_alt").is_none());
        assert!(event["finding_info"].get("src_url").is_none());

        // Every former Nano key with an OCSF home is gone from `unmapped`.
        for gone in [
            "risk_entity", "risk_entity_field", "risk_entity_type", "risk_score", "rule_id",
            "mitre_tactics", "signal_type", "alert_id", "rule_mode", "risk_factors",
            "matched_events_sample",
        ] {
            assert!(event["unmapped"].get(gone).is_none(), "unmapped.{gone}");
        }
        // Keys OCSF 1.9 has no attribute for stay in `unmapped`.
        assert_eq!(event["unmapped"]["raw_risk_score"], 50);
        assert_eq!(event["unmapped"]["realtime"], false);
        assert_eq!(event["unmapped"]["matched_events_redacted"], false);

        let mut alerting = sample_metadata();
        alerting["signal_type"] = json!("alert");
        alerting["rule_mode"] = json!("alerting");
        alerting["alert_id"] = json!("5f0c7c9e-7f5a-4d0e-9a51-2b4f7a0e9c11");
        alerting["alert_created_time"] = json!(1_780_000_123_000_i64);
        let alert_event = FindingLogger::build_ocsf_finding_event_for_lake(
            &alerting,
            "alert",
            ts,
            "alert:stable-finding-id",
            "tenant-a",
        );
        assert_eq!(alert_event["metadata"]["uid"], "alert:stable-finding-id");
        assert_eq!(alert_event["is_alert"], true);
        assert_eq!(alert_event["finding_info"]["types"], json!(["alert"]));
        assert_eq!(alert_event["finding_info"]["analytic"]["state"], "Active");
        assert_eq!(
            alert_event["finding_info"]["uid_alt"],
            "5f0c7c9e-7f5a-4d0e-9a51-2b4f7a0e9c11"
        );
        let alert_uuid = Uuid::parse_str("5f0c7c9e-7f5a-4d0e-9a51-2b4f7a0e9c11").unwrap();
        assert_eq!(
            alert_event["finding_info"]["src_url"],
            format!(
                "/alerts/{}",
                crate::typeid::encode(crate::typeid::alert::PREFIX, &alert_uuid)
            )
        );
        assert_eq!(alert_event["finding_info"]["created_time"], 1_780_000_123_000_i64);
        assert!(alert_event["unmapped"].get("alert_id").is_none());
        assert!(alert_event["unmapped"].get("signal_type").is_none());

        // A matched event becomes structured evidence, with the raw event
        // losslessly kept as a JSON string in `evidences[].data`.
        let mut metadata = sample_metadata();
        metadata["matched_events_sample"] = json!([{
            "device.hostname": "WS-01",
            "user": { "name": "Alice" }
        }]);
        let encoded = FindingLogger::build_ocsf_finding_event_for_lake(
            &metadata,
            "sample",
            ts,
            "detection:sample-json",
            "tenant-a",
        );
        assert_eq!(encoded["evidences"][0]["device"]["hostname"], "WS-01");
        assert_eq!(encoded["evidences"][0]["user"]["name"], "Alice");
        let data = encoded["evidences"][0]["data"]
            .as_str()
            .expect("lake evidence data must be JSON text");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(data).unwrap(),
            metadata["matched_events_sample"][0]
        );
        assert!(encoded["unmapped"].get("matched_events_sample").is_none());
    }

    /// The live load-test tenant finding (rule persistence_registry_run_key), built
    /// end to end from a `FindingEvent`: paired ATT&CK, evidence, entity and
    /// evidence observables, timing, and a valid OCSF 1.9.0 event.
    fn registry_run_key_finding() -> FindingEvent {
        let first = json!({
            "metadata": {"uid": "evt-1", "log_source": "windows_sysmon"},
            "class_name": "Registry Value Activity",
            "type_uid": 201_403,
            "time": "2026-10-07 14:00:00.000000",
            "actor": {
                "user": {"name": "CORP\\alice"},
                "process": {"pid": 4242, "name": "reg.exe",
                            "cmd_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d c:\\x.exe",
                            "file": {"path": "C:\\Windows\\System32\\reg.exe",
                                     "hashes": [{"algorithm_id": 3, "value": "ab".repeat(32)}]}},
            },
            "device": {"hostname": "ws-fin-011", "ip": "10.1.2.3"},
            "reg_key": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            "reg_value": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "x"},
        });
        let mut second = first.clone();
        second["metadata"]["uid"] = json!("evt-2");
        second["time"] = json!("2026-10-07 14:05:00.000000");
        let mut rule = super::tests::sample_rule();
        rule.mitre_tactics = vec!["TA0003".into()];
        rule.mitre_techniques = vec!["T1547.001".into()];
        let alert = Alert {
            id: Uuid::parse_str("5f0c7c9e-7f5a-4d0e-9a51-2b4f7a0e9c11").unwrap(),
            rule_id: Some(rule.id),
            rule_name: Some(rule.name.clone()),
            severity: Severity::High,
            status: crate::models::AlertStatus::New,
            disposition: None,
            matched_events: json!([first, second]),
            matched_event_count: Some(2),
            event_hash: None,
            assigned_to: None,
            acknowledged_by: None,
            acknowledged_at: None,
            closed_by: None,
            closed_at: None,
            created_at: DateTime::parse_from_rfc3339("2026-10-07T14:06:00Z")
                .unwrap()
                .with_timezone(&Utc),
            triage_verdict: None,
            triage_confidence: None,
            triage_verdict_details: None,
            case_id: None,
            kind: "detection".into(),
            source_id: None,
            source_types: vec![],
        };
        FindingEvent::alert(
            &rule,
            &alert,
            false,
            RiskResult::new(
                40,
                60,
                "ws-fin-011".into(),
                Some("device.hostname".into()),
                vec!["run key".into()],
            ),
        )
    }

    #[test]
    fn registry_run_key_finding_has_the_nan3224_shape() {
        let finding = registry_run_key_finding();
        assert_eq!(
            finding.first_seen_at.map(|t| t.to_rfc3339()),
            Some("2026-10-07T14:00:00+00:00".into())
        );
        let payload = FindingLogger::prepare_lake_outbox_payload(&finding, "tenant-a").unwrap();
        let event = &payload.ocsf_event;

        assert_eq!(
            event["finding_info"]["attacks"],
            json!([{
                "technique": {"uid": "T1547", "name": "Boot or Logon Autostart Execution"},
                "sub_technique": {"uid": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
                "tactic": {"uid": "TA0003", "name": "Persistence"},
                "version": "19.1",
            }])
        );
        // Timing: matched-event window, alert creation, finding time.
        let first_ms = 1_791_381_600_000_i64; // 2026-10-07T14:00:00Z
        assert_eq!(event["finding_info"]["first_seen_time"], first_ms);
        assert_eq!(event["finding_info"]["last_seen_time"], first_ms + 300_000);
        assert_eq!(event["start_time"], first_ms);
        assert_eq!(event["end_time"], first_ms + 300_000);
        assert_eq!(event["time"], first_ms + 300_000);
        assert_eq!(event["finding_info"]["created_time"], first_ms + 360_000);
        // Evidence: structured actor.user / process / device / registry.
        let evidence = &event["evidences"][0];
        assert_eq!(evidence["actor"]["user"]["name"], "CORP\\alice");
        assert_eq!(evidence["actor"]["process"]["name"], "reg.exe");
        assert_eq!(evidence["actor"]["process"]["file"]["hashes"][0]["algorithm_id"], 3);
        assert_eq!(evidence["device"]["hostname"], "ws-fin-011");
        assert_eq!(evidence["reg_value"]["name"], "x");
        assert_eq!(event["evidences"].as_array().unwrap().len(), 2);
        assert_eq!(
            event["finding_info"]["related_events"],
            json!([{"uid": "evt-1", "type_uid": 201_403}, {"uid": "evt-2", "type_uid": 201_403}])
        );
        // Observables: the scored host first, then evidence-derived ones,
        // de-duplicated, with OCSF type_ids.
        let observables = event["observables"].as_array().unwrap();
        assert_eq!(observables[0]["name"], "resources[0].hostname");
        let kinds = observables
            .iter()
            .map(|o| (o["type_id"].as_i64().unwrap(), o["value"].as_str().unwrap()))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&(1, "ws-fin-011")));
        assert!(kinds.contains(&(2, "10.1.2.3")));
        assert!(kinds.contains(&(4, "CORP\\alice")));
        assert!(kinds.contains(&(9, "reg.exe")));
        assert!(kinds.contains(&(8, "ab".repeat(32).as_str())));
        assert_eq!(kinds.iter().filter(|(_, v)| *v == "ws-fin-011").count(), 1);
        // Per-entity risk object.
        assert_eq!(event["resources"][0]["name"], "ws-fin-011");
        assert_eq!(event["resources"][0]["type"], "hostname");
        assert_eq!(event["resources"][0]["device"]["risk_score"], 60);
        assert_eq!(event["risk_score"], 60);
        assert_eq!(event["unmapped"]["raw_risk_score"], 40);
        // The compact risk record is unchanged by NAN-3224.
        assert_eq!(
            payload.compact_finding.as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
            ["entity", "id", "mitre_tactics", "origin_source_types", "risk_score", "rule_id",
             "rule_name", "severity", "stamped_entity_type", "timestamp_us"]
        );
    }

    /// Both emitted shapes validate against the bundled OCSF 1.9.0 contract,
    /// so no attribute here is invented.
    #[test]
    fn emitted_findings_validate_against_bundled_ocsf_1_9_schema() {
        let finding = registry_run_key_finding();
        let lake = FindingLogger::prepare_lake_outbox_payload(&finding, "tenant-a")
            .unwrap()
            .ocsf_event;
        let clickhouse = FindingLogger::build_ocsf_finding_event(
            &finding.to_log_json(),
            &finding.message(),
            finding.detected_at,
        );
        let mut redacted = finding.clone();
        redacted.redact_matched_events();
        let redacted = FindingLogger::prepare_lake_outbox_payload(&redacted, "tenant-a")
            .unwrap()
            .ocsf_event;
        let mut entity_kinds = Vec::new();
        for (entity, kind) in [
            ("10.0.0.5", "ip"), ("alice", "user"), ("a@example.com", "email"),
            ("example.com", "domain"), (&"0".repeat(64), "hash"), ("https://x.test/a", "url"),
            ("123456789012", "cloud_account"), ("thing", "other"),
        ] {
            let mut metadata = sample_metadata();
            metadata["risk_entity"] = json!(entity);
            metadata["risk_entity_type"] = json!(kind);
            entity_kinds.push(FindingLogger::build_ocsf_finding_event_for_lake(
                &metadata, "m", Utc::now(), "detection:x", "tenant-a",
            ));
        }
        for event in [&lake, &clickhouse, &redacted].into_iter().chain(entity_kinds.iter()) {
            let result = crate::parsers::validate_ocsf_event(event);
            assert!(result.valid, "{:#?}\n{event:#}", result.errors);
        }
        assert!(redacted.get("evidences").is_none());
        assert!(redacted.get("resources").is_none());
        assert!(redacted.get("observables").is_none());
    }

    #[test]
    fn outbox_replay_accepts_only_identical_or_pre_nan3224_rows() {
        let compact = json!({"id": "alert:x", "risk_score": 60});
        let event = json!({"metadata": {"log_name": "findings"}, "is_alert": true});
        let legacy = json!({"metadata": {"log_name": "signals"}, "unmapped": {"alert_id": "x"}});
        let other = json!({"metadata": {"log_name": "findings"}, "is_alert": false});
        assert!(FindingLogger::outbox_replay_matches(&compact, &event, &compact, &event));
        assert!(FindingLogger::outbox_replay_matches(&compact, &legacy, &compact, &event));
        assert!(!FindingLogger::outbox_replay_matches(&compact, &other, &compact, &event));
        let changed = json!({"id": "alert:x", "risk_score": 61});
        assert!(!FindingLogger::outbox_replay_matches(&changed, &legacy, &compact, &event));
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
            first_seen_at: None,
            last_seen_at: None,
            alert_created_at: None,
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
        assert!(
            !metadata.to_string().contains("ceo"),
            "entity leaked into UDM metadata"
        );

        // Branch 2: OCSF `ocsf_logs_raw` (build_ocsf_finding_event) — built
        // from the SAME metadata JSON, so a no-op redaction upstream would
        // still write the sample here. Both must be empty.
        let message = finding.message();
        let ocsf =
            FindingLogger::build_ocsf_finding_event(&metadata, &message, finding.detected_at);
        assert!(
            ocsf["unmapped"].get("matched_events_sample").is_none(),
            "the compact OCSF writer removes the empty redacted sample"
        );
        assert_eq!(ocsf["unmapped"]["matched_events_redacted"], json!(true));
        assert_eq!(
            ocsf["unmapped"]["origin_source_types"],
            json!(["hr_system"])
        );
        assert!(
            ocsf["unmapped"].get("risk_entity").is_none(),
            "the compact OCSF writer removes the empty redacted entity"
        );
        assert!(
            !ocsf.to_string().contains("ceo"),
            "entity leaked into OCSF event"
        );
        // NAN-3224: no evidence, risk object or observable survives redaction.
        assert!(ocsf.get("evidences").is_none());
        assert!(ocsf.get("resources").is_none());
        assert!(ocsf.get("observables").is_none());
        assert!(ocsf["finding_info"].get("related_events").is_none());

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

    /// NAN-2001 Change 2: aggregate rules drop per-event `source_type`; the
    /// engine stamps the window's distinct sources under `_nano_source_types`.
    /// The finding must harvest that stamp so aggregate audit findings become
    /// KNOWN-origin (the audit sentinel then redacts them). Mirrors
    /// `db::repository::alerts::distinct_source_types`.
    #[test]
    fn origin_source_types_harvests_nano_annotation_for_aggregate_rows() {
        // Pure aggregate row: no `source_type`, only the engine annotation.
        let rows = vec![json!({ "count": 42, "_nano_source_types": ["Audit"] })];
        assert_eq!(
            FindingEvent::origin_source_types_from(&rows),
            vec!["audit".to_string()],
            "aggregate audit rows must resolve to audit origin via _nano_source_types"
        );

        // Mixed batch: per-event `source_type` AND the annotation, deduped +
        // normalized (trim + lowercase).
        let rows = vec![
            json!({ "source_type": "syslog", "user": "a" }),
            json!({ "count": 5, "_nano_source_types": ["audit", " Windows Event Log "] }),
        ];
        assert_eq!(
            FindingEvent::origin_source_types_from(&rows),
            vec![
                "audit".to_string(),
                "syslog".to_string(),
                "windows event log".to_string(),
            ],
        );
    }

    /// NAN-2001 Change 1: 'audit' is an ALWAYS-restricted origin sentinel,
    /// independent of the PG registry. Pure classification — no database.
    #[test]
    fn audit_origin_is_always_restricted_sentinel() {
        let audit = |v: &[&str]| {
            crate::auth::is_always_restricted_origin(
                &v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        // Audit origin (and case/whitespace variants) is always restricted.
        assert!(audit(&["audit"]));
        assert!(audit(&["Audit"]));
        assert!(audit(&["  AUDIT "]));
        // Any audit member in a mixed origin flags the whole finding.
        assert!(audit(&["syslog", "audit"]));
        // Non-audit origins are NOT force-restricted — they defer to the
        // registry, so deployments without audit rules stay byte-identical.
        assert!(!audit(&["syslog"]));
        assert!(!audit(&["windows event log"]));
        assert!(!audit(&["auditbeat"])); // substring, not the token — not audit
        assert!(!audit(&[]));
    }

    /// NAN-2001: an audit-origin finding redacts the actor (message collapses to
    /// the count-only form, `risk_entity` / sample / factors cleared) while a
    /// non-audit finding built identically is byte-identical (no regression).
    #[test]
    fn audit_origin_finding_redacts_actor_while_nonaudit_untouched() {
        // Distinctive audit actor (matches the live-repro IP from the design).
        let actor = "10.98.1.1";
        let make = |origin: &str| FindingEvent {
            finding_type: FindingType::Alert,
            rule_id: Uuid::now_v7(),
            rule_name: "Audit Actor Rule".to_string(),
            rule_query: "source_type=audit | stats count by src_ip".to_string(),
            severity: Severity::High,
            rule_mode: crate::models::RuleMode::Alerting,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            alert_id: Some(Uuid::now_v7()),
            matched_event_count: 3,
            matched_events_sample: vec![json!({ "src_ip": actor })],
            realtime: false,
            detected_at: Utc::now(),
            raw_risk_score: 50,
            risk_score: 75,
            risk_entity: actor.to_string(),
            risk_entity_field: Some("src_ip".to_string()),
            risk_entity_type: "ip".to_string(),
            risk_factors: vec![format!("factor:src_ip={actor}")],
            origin_source_types: vec![origin.to_string()],
            matched_events_redacted: false,
            first_seen_at: None,
            last_seen_at: None,
            alert_created_at: None,
        };

        // Sentinel decision is pure (no PG): audit yes, syslog no.
        let mut audit = make("audit");
        let nonaudit = make("syslog");
        // Snapshot the non-audit finding's serialization up front; the audit
        // path must not touch it, so it stays byte-identical.
        let nonaudit_before = nonaudit.to_log_json();
        assert!(crate::auth::is_always_restricted_origin(
            &audit.origin_source_types
        ));
        assert!(!crate::auth::is_always_restricted_origin(
            &nonaudit.origin_source_types
        ));

        // Apply exactly what `log_finding` applies when the origin is restricted.
        audit.redact_matched_events();
        assert_eq!(
            audit.message(),
            "Audit Actor Rule - 3 event(s)",
            "message must collapse to the count-only form"
        );
        assert_eq!(audit.risk_entity, "", "risk_entity must be emptied");
        assert_eq!(audit.risk_entity_field, None);
        assert!(audit.matched_events_sample.is_empty());
        assert!(audit.matched_events_redacted);
        assert_eq!(audit.matched_event_count, 3, "count is preserved");
        assert_eq!(audit.risk_score, 75, "score is preserved");
        // The audit actor must NOT survive into EITHER physical write branch.
        let audit_md = audit.to_log_json();
        assert!(
            !audit_md.to_string().contains(actor),
            "actor leaked into UDM metadata"
        );
        let ocsf =
            FindingLogger::build_ocsf_finding_event(&audit_md, &audit.message(), audit.detected_at);
        assert!(
            !ocsf.to_string().contains(actor),
            "actor leaked into OCSF event"
        );

        // The non-audit finding is left fully intact — byte-identical to its
        // pre-snapshot, and the actor is still present (redaction did not
        // over-reach onto a non-audit origin).
        assert_eq!(nonaudit.to_log_json(), nonaudit_before);
        assert!(nonaudit.to_log_json().to_string().contains(actor));
        assert!(nonaudit
            .message_with_profile(&crate::schema::UdmProfile::new())
            .contains(actor));
        assert!(!nonaudit.matched_events_redacted);
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
    fn source_event_time_accepts_ocsf_epoch_milliseconds() {
        let events = vec![json!({ "time": 1_780_317_300_500_i64 })];
        let got = FindingEvent::source_event_time(&events).expect("OCSF event time");
        assert_eq!(got.to_rfc3339(), "2026-06-01T12:35:00.500+00:00");
    }

    #[test]
    fn numeric_source_event_time_normalizes_common_epoch_units() {
        let expected = "2026-06-01T12:35:00.500+00:00";
        for value in [
            json!(1_780_317_300_500_i64),
            json!(1_780_317_300_500_000_i64),
            json!(1_780_317_300_500_000_000_i64),
        ] {
            assert_eq!(
                FindingEvent::parse_source_event_time(&value)
                    .expect("numeric event time")
                    .to_rfc3339(),
                expected
            );
        }
    }

    #[test]
    fn source_event_time_none_when_no_parseable_timestamp() {
        // No `timestamp` field, or an unparseable one -> None (caller falls back
        // to now()). This must NOT panic or silently pick a wrong basis.
        assert!(FindingEvent::source_event_time(&[json!({ "user": "a" })]).is_none());
        assert!(FindingEvent::source_event_time(&[json!({ "timestamp": "not-a-time" })]).is_none());
        assert!(FindingEvent::source_event_time(&[]).is_none());
    }

    #[test]
    fn source_event_time_accepts_native_otel_span_time() {
        let events = vec![json!({ "start_time": "2026-06-01T09:15:00Z" })];
        let got = FindingEvent::source_event_time(&events).expect("span time");
        assert_eq!(got.to_rfc3339(), "2026-06-01T09:15:00+00:00");
    }

    #[test]
    fn infer_entity_type_matches_delimited_tokens_not_substrings() {
        use FindingLogger as F;
        // Real UDM/OCSF field names still classify correctly.
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("src_ip")), "ip");
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("dest_ip")), "ip");
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("dvc_ip")), "ip");
        assert_eq!(
            F::infer_entity_type("1.2.3.4", Some("src_endpoint.ip")),
            "ip"
        );
        // `dvc` (device) is typed by its value, not hardcoded to "ip": an IP
        // value → "ip", a dotted hostname value → "hostname".
        assert_eq!(F::infer_entity_type("1.2.3.4", Some("dvc")), "ip");
        assert_eq!(
            F::infer_entity_type("host1.corp.example", Some("dvc")),
            "hostname"
        );
        assert_eq!(F::infer_entity_type("host1", Some("src_host")), "hostname");
        assert_eq!(F::infer_entity_type("host1", Some("hostname")), "hostname");
        assert_eq!(
            F::infer_entity_type("host1", Some("dest_hostname")),
            "hostname"
        );
        assert_eq!(F::infer_entity_type("bob", Some("src_user")), "user");
        assert_eq!(F::infer_entity_type("abc", Some("file_hash")), "hash");
        // OCSF plural hash path (tokenizes to `hashes`, not `hash`).
        assert_eq!(
            F::infer_entity_type("abc", Some("file.hashes.sha256")),
            "hash"
        );
        assert_eq!(F::infer_entity_type("x.com", Some("dest_domain")), "domain");
        assert_eq!(F::infer_entity_type("alice@example.com", None), "email");

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
        assert_ne!(
            F::infer_entity_type("bob", Some("cloud_provider")),
            "cloud_account"
        );
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
    #[test]
    fn lake_outbox_security_tenant_keeps_hosted_uuid_and_is_strict_on_trusted_local() {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        // Hosted / default: a UUID lake tenant is its own security tenant
        // (the hosted drain and RLS select by it); a gen1 name keeps the
        // migration-336 compatibility tenant.
        assert_eq!(
            FindingLogger::lake_outbox_security_tenant(tenant, false).unwrap(),
            Uuid::parse_str(tenant).unwrap()
        );
        assert_eq!(
            FindingLogger::lake_outbox_security_tenant("acme-gen1", false).unwrap(),
            crate::reports::COMPATIBILITY_TENANT_ID
        );
        // Trusted-local: the install's own tenant; a non-UUID one is refused.
        assert_eq!(
            FindingLogger::lake_outbox_security_tenant(tenant, true).unwrap(),
            Uuid::parse_str(tenant).unwrap()
        );
        assert!(FindingLogger::lake_outbox_security_tenant("acme-gen1", true).is_err());
        assert!(FindingLogger::lake_outbox_security_tenant(&Uuid::nil().to_string(), true).is_err());
    }

    pub(super) fn sample_rule() -> DetectionRule {
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
            near_real_time_interval_seconds: None,
            execution_mode: None,
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
    fn lake_outbox_finding_id_is_deterministic() {
        let rule = DetectionRule {
            mode: RuleMode::Live,
            ..sample_rule()
        };
        let events = vec![serde_json::json!({
            "time": "2026-08-11T00:00:00Z",
            "metadata.log_source": "edr"
        })];
        let risk_result = RiskResult::new(
            75,
            75,
            "192.0.2.10".to_string(),
            Some("src_endpoint.ip".to_string()),
            vec!["test".to_string()],
        );
        let first = FindingEvent::detection_match(&rule, &events, false, risk_result.clone());
        let second = FindingEvent::detection_match(&rule, &events, false, risk_result);
        assert_eq!(
            FindingLogger::stable_finding_id(&first),
            FindingLogger::stable_finding_id(&second)
        );
        assert!(FindingLogger::stable_finding_id(&first).starts_with("detection:"));
    }

    #[test]
    fn lake_outbox_grouped_alert_ids_are_entity_scoped() {
        let alert_id = Uuid::now_v7();
        let detected_at = Utc::now();
        let make = |entity: &str| FindingEvent {
            finding_type: FindingType::Alert,
            rule_id: Uuid::now_v7(),
            rule_name: "Grouped host rule".to_string(),
            rule_query: "* | stats count() by device.hostname".to_string(),
            severity: Severity::Low,
            rule_mode: RuleMode::Alerting,
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            alert_id: Some(alert_id),
            matched_event_count: 1,
            matched_events_sample: Vec::new(),
            realtime: false,
            detected_at,
            raw_risk_score: 25,
            risk_score: 25,
            risk_entity: entity.to_string(),
            risk_entity_field: Some("device.hostname".to_string()),
            risk_entity_type: "hostname".to_string(),
            risk_factors: Vec::new(),
            origin_source_types: vec!["windows_sysmon".to_string()],
            matched_events_redacted: false,
            first_seen_at: None,
            last_seen_at: None,
            alert_created_at: None,
        };

        let first = make("host-a.example");
        let replay = first.clone();
        let second_entity = make("host-b.example");
        let first_id = FindingLogger::stable_finding_id(&first);

        assert_eq!(first_id, FindingLogger::stable_finding_id(&replay));
        assert_ne!(
            first_id,
            FindingLogger::stable_finding_id(&second_entity),
            "distinct entities in one grouped alert require distinct outbox rows"
        );
        assert!(first_id.starts_with(&format!("alert:{alert_id}:")));
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
        assert!(finding
            .message_with_profile(&crate::schema::UdmProfile::new())
            .contains("src_ip=192.168.1.1"));
        assert_eq!(finding.matched_event_count, 1);
        assert_eq!(finding.raw_risk_score, 75);
        assert_eq!(finding.risk_score, 75);
        assert_eq!(finding.risk_entity, "192.168.1.1");
    }

    #[test]
    fn finding_message_summary_reads_nested_and_repeated_ocsf_entities() {
        let rule = DetectionRule {
            mode: RuleMode::Live,
            ..sample_rule()
        };
        let events = vec![serde_json::json!({
            "actor": { "user": { "name": "alice" } },
            "device": { "hostname": "ws-01" },
            "src_endpoint": { "ip": "192.0.2.10" },
            "file": { "hashes": [{
                "algorithm_id": 3,
                "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }] }
        })];
        let risk = RiskResult::new(0, 0, "unknown".to_string(), None, Vec::new());
        let finding = FindingEvent::detection_match(&rule, &events, false, risk);
        let summary =
            finding.extract_entity_summary_with_profile(&crate::schema::OcsfProfile::lake_1_9());

        for expected in [
            "src_endpoint.ip=192.0.2.10",
            "actor.user.name=alice",
            "device.hostname=ws-01",
            "file.hashes.value=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                summary.contains(expected),
                "missing `{expected}`: {summary}"
            );
        }
        for legacy in ["src_ip=", "user=", "src_host=", "file_hash="] {
            assert!(
                !summary.contains(legacy),
                "legacy key `{legacy}` leaked: {summary}"
            );
        }
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

    /// NAN-3226: a domain risk object under an internal suffix is re-typed as
    /// a host; external domains and host objects are untouched.
    #[test]
    fn internal_domain_risk_objects_are_hosts() {
        use crate::internal_domains::InternalDomains;
        let finding_for = |entity: &str| {
            let rule = DetectionRule {
                risk_score: Some(40),
                risk_entity_field: Some("domain".to_string()),
                ..sample_rule()
            };
            let risk_result = RiskResult::new(
                40,
                40,
                entity.to_string(),
                Some("domain".to_string()),
                vec![],
            );
            FindingEvent::detection_match(&rule, &[], false, risk_result)
        };
        let internal = InternalDomains::with_tenant(["prod"]);
        let mut finding = finding_for("db1.prod");
        assert_eq!(finding.risk_entity_type, "domain");
        assert!(finding.retype_internal_domain(&internal));
        assert_eq!(finding.risk_entity_type, "hostname");
        assert_eq!(finding.to_log_json()["risk_entity_type"], "hostname");

        let mut builtin = finding_for("fileserver.corp.local");
        assert!(builtin.retype_internal_domain(&InternalDomains::builtin()));

        let mut external = finding_for("myprod.com");
        assert!(!external.retype_internal_domain(&internal));
        assert_eq!(external.risk_entity_type, "domain");

        // Tenant isolation: another tenant's list does not re-type it.
        let mut other = finding_for("db1.prod");
        assert!(!other.retype_internal_domain(&InternalDomains::with_tenant(["cloud"])));
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
