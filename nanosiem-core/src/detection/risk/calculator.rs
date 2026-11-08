// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk score calculation
//!
//! Contains the core score calculation logic:
//! - `RiskResult` - Result of a risk score calculation
//! - `ScoreCalculator` - Stateless calculator for risk scores with entity extraction

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::Severity;
use crate::schema::{SchemaProfile, UdmProfile};

use super::defaults::default_score_for_severity;
use super::types::{RiskError, RiskModifier};

/// Result of risk score calculation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct RiskResult {
    /// Raw risk score before global weight applied
    pub raw_score: i32,

    /// Weighted risk score (raw * global_weight)
    pub weighted_score: i32,

    /// Entity being scored (extracted from risk_entity_field)
    pub entity: String,

    /// Field name that the entity was extracted from (e.g., "src_ip", "user", "dest_host")
    pub entity_field: Option<String>,

    /// Risk factors explaining the score
    pub factors: Vec<String>,
}

impl RiskResult {
    /// Create a new risk result
    pub fn new(
        raw_score: i32,
        weighted_score: i32,
        entity: String,
        entity_field: Option<String>,
        factors: Vec<String>,
    ) -> Self {
        Self {
            raw_score,
            weighted_score,
            entity,
            entity_field,
            factors,
        }
    }

    /// Create a default risk result with zero scores
    pub fn default_with_entity(entity: String) -> Self {
        Self {
            raw_score: 0,
            weighted_score: 0,
            entity,
            entity_field: None,
            factors: Vec::new(),
        }
    }
}

/// Service for calculating risk scores
///
/// The ScoreCalculator is designed to be fast (no I/O, pure computation)
/// for use in realtime detection scenarios.
#[derive(Clone)]
pub struct ScoreCalculator {
    /// Default entity value when extraction fails
    default_entity: String,
    /// Active schema profile. Drives auto-detect entity extraction
    /// (`entity_extraction_order()`) so an OCSF deployment extracts OCSF
    /// physical fields (`src_endpoint.ip`, …) while UDM stays byte-identical.
    /// Defaults to [`UdmProfile`] so existing call sites/tests are unchanged.
    profile: Arc<dyn SchemaProfile>,
}

impl std::fmt::Debug for ScoreCalculator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScoreCalculator")
            .field("default_entity", &self.default_entity)
            .field("profile", &self.profile.id())
            .finish()
    }
}

impl Default for ScoreCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl ScoreCalculator {
    /// Create a new score calculator (UDM profile).
    pub fn new() -> Self {
        Self {
            default_entity: "unknown".to_string(),
            profile: Arc::new(UdmProfile::new()),
        }
    }

    /// Set the active schema profile (OCSF Phase 5, NAN-1241). Drives the
    /// auto-detect entity-extraction order. UDM is the default.
    pub fn with_profile(mut self, profile: Arc<dyn SchemaProfile>) -> Self {
        self.profile = profile;
        self
    }

    /// Calculate risk score for a detection match
    ///
    /// This is designed to be fast (no I/O) for realtime use:
    /// - Base score lookup: O(1)
    /// - Modifier evaluation: O(n) where n = number of modifiers (typically < 10)
    /// - Weight multiplication: O(1)
    /// - Entity extraction: O(1) field lookup
    pub fn calculate(
        &self,
        base_score: Option<i32>,
        severity: Severity,
        entity_field: Option<&str>,
        modifiers: &[RiskModifier],
        matched_events: &[Value],
        global_weight: f64,
    ) -> RiskResult {
        // 1. Get base score (explicit or severity default)
        let base = base_score.unwrap_or_else(|| self.severity_to_score(severity));

        // 2. Evaluate modifiers, use highest matching score
        let raw_score = self.evaluate_modifiers(base, modifiers, matched_events);

        // 3. Apply global weight (clamp to valid range)
        let clamped_weight = global_weight.clamp(0.0, 1.0);
        let weighted_score = (raw_score as f64 * clamped_weight).round() as i32;

        // 4. Extract entity value and field name
        let (entity, extracted_field) = self.extract_entity(entity_field, matched_events);

        // 5. Build factors list
        let mut factors = Vec::new();
        if base_score.is_none() {
            factors.push(format!("severity_default:{:?}", severity));
        }
        for modifier in modifiers {
            if modifier.evaluate(matched_events) {
                factors.push(format!("modifier:{}", modifier.condition));
            }
        }

        RiskResult {
            raw_score,
            weighted_score,
            entity,
            entity_field: extracted_field,
            factors,
        }
    }

    /// Calculate risk score from query-derived values
    ///
    /// This method is used when a query contains a `| risk score=<expr>` command.
    /// The raw_risk_score is already computed in the query results.
    ///
    /// Parameters:
    /// - event: Single event with raw_risk_score, risk_entity, risk_factors columns
    /// - global_weight: System-wide risk weight multiplier
    ///
    /// If the event has a risk_weight column (from weight= parameter), that overrides global_weight.
    pub fn calculate_from_query_result(
        &self,
        event: &Value,
        global_weight: f64,
    ) -> Option<RiskResult> {
        // Extract raw_risk_score from event.
        // Audit D39: clamp to the valid 0-100 range. The `| risk` SQL generator
        // clamps, but a query that sets `raw_risk_score` another way (e.g.
        // `eval raw_risk_score=...`) would otherwise bypass it and yield an
        // out-of-range score.
        let raw_score = Self::get_numeric_field(event, "raw_risk_score")?.clamp(0.0, 100.0);

        // Check for weight override from query
        let weight = Self::get_numeric_field(event, "risk_weight")
            .unwrap_or(global_weight)
            .clamp(0.0, 1.0);

        // Apply weight
        let weighted_score = (raw_score * weight).round() as i32;
        let raw_score = raw_score as i32;

        // Extract entity and field name from query results
        let entity = Self::get_string_field(event, "risk_entity")
            .unwrap_or_else(|| self.default_entity.clone());

        // Try to determine entity field from the event
        // The risk command may have set this explicitly
        let entity_field = Self::get_string_field(event, "risk_entity_field");

        // Extract factors from query results
        let factors = Self::get_string_array_field(event, "risk_factors").unwrap_or_default();

        Some(RiskResult {
            raw_score,
            weighted_score,
            entity,
            entity_field,
            factors,
        })
    }

    /// Check if an event has a query-derived risk score.
    ///
    /// Audit D10: a JSON `null` `raw_risk_score` (e.g. from `| risk
    /// score=if(cond, X, null)` when `cond` is false) counts as ABSENT, not
    /// present. Counting null as present made a null-scored batch look like it
    /// had query scores, then `calculate_from_query_result` dropped every null
    /// row (`filter_map`) → empty groups → the grouped path misread that as
    /// "already alerted" and suppressed the whole alert.
    pub fn has_query_risk_score(event: &Value) -> bool {
        event
            .get("raw_risk_score")
            .is_some_and(|v| !v.is_null())
    }

    /// Get a numeric field value from an event
    fn get_numeric_field(event: &Value, field: &str) -> Option<f64> {
        event.get(field).and_then(|v| match v {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        })
    }

    /// Get a string array field value from an event
    fn get_string_array_field(event: &Value, field: &str) -> Option<Vec<String>> {
        event.get(field).and_then(|v| match v {
            Value::Array(arr) => {
                let strings: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if strings.is_empty() {
                    None
                } else {
                    Some(strings)
                }
            }
            _ => None,
        })
    }

    /// Map severity to default risk score.
    ///
    /// Delegates to [`default_score_for_severity`] so the real-time MV path
    /// and the scheduled path share a single source of truth.
    pub fn severity_to_score(&self, severity: Severity) -> i32 {
        default_score_for_severity(severity)
    }

    /// Evaluate modifiers and return the final score
    ///
    /// If no modifiers match, returns the base score.
    /// If one or more modifiers match, returns the highest matching score.
    pub fn evaluate_modifiers(
        &self,
        base_score: i32,
        modifiers: &[RiskModifier],
        events: &[Value],
    ) -> i32 {
        if modifiers.is_empty() {
            return base_score;
        }

        let matching_scores: Vec<i32> = modifiers
            .iter()
            .filter(|m| m.evaluate(events))
            .map(|m| m.score)
            .collect();

        if matching_scores.is_empty() {
            base_score
        } else {
            // Return the highest matching score
            matching_scores.into_iter().max().unwrap_or(base_score)
        }
    }

    /// Extract entity value from matched events
    ///
    /// Returns (entity_value, field_name)
    ///
    /// If entity_field is specified:
    /// - Try to extract from the first event that has the field
    /// - Return ("unknown", None) if field not found in any event
    ///
    /// If entity_field is not specified:
    /// - Try common UDM fields in priority order:
    ///   1. IP addresses (src_ip, dest_ip, dvc_ip, etc.)
    ///   2. Hostnames (src_host, dest_host, host, etc.)
    ///   3. Users (src_user, dest_user, user, etc.)
    ///   4. File hashes (file_hash, process_hash, service_hash, ssl_hash)
    /// - Return ("unknown", None) if none found
    pub fn extract_entity(
        &self,
        entity_field: Option<&str>,
        events: &[Value],
    ) -> (String, Option<String>) {
        if events.is_empty() {
            return (self.default_entity.clone(), None);
        }

        match entity_field {
            Some(field) => {
                // Try to extract the specified field from any event
                for event in events {
                    if let Some(value) = Self::get_string_field(event, field) {
                        return (value, Some(field.to_string()));
                    }
                }
                (self.default_entity.clone(), None)
            }
            None => {
                // Auto-detect: walk the active profile's entity-extraction order
                // (semantic role → physical field, in priority order). For UDM this
                // is the byte-identical superset list (IPs > Hostnames > Users >
                // Hashes > legacy paths); for OCSF it yields `src_endpoint.ip`,
                // `user.name`, etc. (NAN-1241 Phase 5).
                for &(_role, field) in self.profile.entity_extraction_order() {
                    for event in events {
                        if let Some(value) = Self::get_string_field(event, field) {
                            return (value, Some(field.to_string()));
                        }
                    }
                }
                (self.default_entity.clone(), None)
            }
        }
    }

    /// Get a string field value from an event.
    ///
    /// ClickHouse `JSONEachRow` rows have FLAT keys that ARE the (possibly
    /// dotted) physical column names: `SELECT *` over `ocsf_logs` returns a key
    /// literally named `src_endpoint.ip`, not a nested `{"src_endpoint": {"ip":
    /// …}}` object. So we resolve `field` as a FLAT key first.
    ///
    /// Only when the flat key is absent do we fall back to walking `field` as a
    /// nested JSON path. This preserves UDM byte-for-byte:
    /// - UDM entity fields are single-segment (`src_ip`) → flat lookup returns
    ///   them exactly as the old nested walk did.
    /// - UDM legacy paths (`metadata.src_ip`, `metadata.user`,
    ///   `metadata.hostname`) have no flat key, so the nested fall-back resolves
    ///   them through the `metadata` object — identical to the prior behavior.
    /// - OCSF promoted dotted columns (`src_endpoint.ip`, `user.name`, …) now
    ///   resolve via the flat lookup instead of collapsing to `unknown`
    ///   (NAN-1241).
    fn get_string_field(event: &Value, field: &str) -> Option<String> {
        // 1. Flat key: the dotted column name as-is (OCSF + single-segment UDM).
        if let Some(v) = event.get(field) {
            return Self::value_to_string(v);
        }

        // 2. Fall back to nested-path walk (UDM `metadata.*` legacy paths, or
        //    any genuinely nested ext/metadata access).
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
    fn value_to_string(current: &Value) -> Option<String> {
        match current {
            Value::String(s) => {
                // Filter out empty strings - treat them as missing values
                if s.is_empty() {
                    None
                } else {
                    Some(s.clone())
                }
            }
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// Validate a risk score is within bounds (0-100)
    pub fn validate_score(score: i32) -> Result<(), RiskError> {
        RiskModifier::validate_score(score)
    }

    /// Validate a global weight is within bounds (0.0-1.0)
    pub fn validate_weight(weight: f64) -> Result<(), RiskError> {
        if weight < 0.0 || weight > 1.0 {
            return Err(RiskError::WeightOutOfBounds(weight));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
