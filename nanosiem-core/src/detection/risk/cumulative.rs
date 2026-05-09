// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cumulative risk detection helpers
//!
//! Provides configuration and helpers for cumulative risk meta-detections:
//! - `CumulativeRiskConfig` - Time window and threshold configuration
//! - `CumulativeRiskResult` - Aggregated risk result for an entity
//! - Query parsing helpers to extract cumulative risk parameters from detection rules

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::models::DetectionRule;

/// Configuration for cumulative risk detection
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CumulativeRiskConfig {
    /// Time window for risk aggregation (in seconds)
    pub window_seconds: i64,
    /// Risk threshold that triggers an alert
    pub threshold: i32,
    /// Entity field to group by (e.g., "risk_entity")
    pub entity_field: String,
}

impl Default for CumulativeRiskConfig {
    fn default() -> Self {
        Self {
            window_seconds: 3600, // 1 hour default
            threshold: 100,
            entity_field: "risk_entity".to_string(),
        }
    }
}

impl CumulativeRiskConfig {
    /// Create a new cumulative risk config
    pub fn new(window_seconds: i64, threshold: i32) -> Self {
        Self {
            window_seconds,
            threshold,
            entity_field: "risk_entity".to_string(),
        }
    }

    /// Get the time window as a Duration
    pub fn window_duration(&self) -> Duration {
        Duration::seconds(self.window_seconds)
    }

    /// Get the start time for the window based on current time
    pub fn window_start(&self) -> DateTime<Utc> {
        Utc::now() - self.window_duration()
    }
}

/// Result of cumulative risk aggregation for an entity
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CumulativeRiskResult {
    /// Entity being scored
    pub entity: String,
    /// Total risk score within the time window
    pub total_risk: i64,
    /// Number of signals contributing to the total
    pub signal_count: i64,
    /// Whether the threshold was exceeded
    pub threshold_exceeded: bool,
    /// The threshold that was checked
    pub threshold: i32,
    /// Time window in seconds
    pub window_seconds: i64,
}

impl CumulativeRiskResult {
    /// Create a new cumulative risk result
    pub fn new(
        entity: String,
        total_risk: i64,
        signal_count: i64,
        threshold: i32,
        window_seconds: i64,
    ) -> Self {
        Self {
            entity,
            total_risk,
            signal_count,
            threshold_exceeded: total_risk >= threshold as i64,
            threshold,
            window_seconds,
        }
    }
}

/// Check if a detection rule is a cumulative risk meta-detection rule
///
/// A cumulative risk rule is identified by:
/// - Querying source_type=findings
/// - Using stats sum(risk_score) aggregation
/// - Having a where clause with a threshold comparison
///
/// Example query: `source_type=findings | stats sum(risk_score) as total by risk_entity | where total > 100`
pub fn is_cumulative_risk_rule(rule: &DetectionRule) -> bool {
    let query = rule.query.to_lowercase();

    // Must query findings
    if !query.contains("source_type=findings") && !query.contains("source_type = findings") {
        return false;
    }

    // Must aggregate risk_score
    if !query.contains("sum(risk_score)") {
        return false;
    }

    // Must have a threshold comparison
    if !query.contains("where") {
        return false;
    }

    // Must group by entity
    if !query.contains("by risk_entity")
        && !query.contains("by src_ip")
        && !query.contains("by user")
        && !query.contains("by hostname")
    {
        return false;
    }

    true
}

/// Extract cumulative risk configuration from a detection rule query
///
/// Parses the query to extract:
/// - Time window from bin span (defaults to 1h)
/// - Threshold from where clause
/// - Entity field from group by clause
///
/// Returns None if the rule is not a valid cumulative risk rule
pub fn extract_cumulative_risk_config(rule: &DetectionRule) -> Option<CumulativeRiskConfig> {
    if !is_cumulative_risk_rule(rule) {
        return None;
    }

    let query = &rule.query;
    let query_lower = query.to_lowercase();

    // Extract time window from bin span (e.g., "bin span=1h" or "bin span=30m")
    let window_seconds = extract_bin_span(&query_lower).unwrap_or(3600);

    // Extract threshold from where clause (e.g., "where total > 100" or "where total_risk >= 50")
    let threshold = extract_threshold(&query_lower).unwrap_or(100);

    // Extract entity field from group by clause
    let entity_field =
        extract_entity_field(&query_lower).unwrap_or_else(|| "risk_entity".to_string());

    Some(CumulativeRiskConfig {
        window_seconds,
        threshold,
        entity_field,
    })
}

/// Extract bin span from a query string
/// Supports formats: 1h, 30m, 1d, 15m, etc.
fn extract_bin_span(query: &str) -> Option<i64> {
    // Look for "bin span=Xh" or "bin span=Xm" or "bin span=Xd"
    let patterns = [("bin span=", true), ("bin  span=", true), ("| bin ", false)];

    for (pattern, direct) in patterns {
        if let Some(pos) = query.find(pattern) {
            let start = if direct {
                pos + pattern.len()
            } else {
                // Find the span= part after "| bin "
                if let Some(span_pos) = query[pos..].find("span=") {
                    pos + span_pos + 5
                } else {
                    continue;
                }
            };

            // Extract the duration value
            let rest = &query[start..];
            let end = rest
                .find(|c: char| !c.is_alphanumeric())
                .unwrap_or(rest.len());
            let duration_str = &rest[..end];

            return parse_duration_to_seconds(duration_str);
        }
    }

    None
}

/// Parse a duration string (e.g., "1h", "30m", "1d") to seconds
fn parse_duration_to_seconds(duration: &str) -> Option<i64> {
    let duration = duration.trim();
    if duration.is_empty() {
        return None;
    }

    let (num_str, unit) = if duration.ends_with('h') {
        (&duration[..duration.len() - 1], 'h')
    } else if duration.ends_with('m') {
        (&duration[..duration.len() - 1], 'm')
    } else if duration.ends_with('d') {
        (&duration[..duration.len() - 1], 'd')
    } else if duration.ends_with('s') {
        (&duration[..duration.len() - 1], 's')
    } else {
        return None;
    };

    let num: i64 = num_str.parse().ok()?;

    Some(match unit {
        'h' => num * 3600,
        'm' => num * 60,
        'd' => num * 86400,
        's' => num,
        _ => return None,
    })
}

/// Extract threshold from a where clause
/// Supports formats: "where total > 100", "where total_risk >= 50", etc.
fn extract_threshold(query: &str) -> Option<i32> {
    // Look for "where" followed by a comparison
    if let Some(where_pos) = query.find("where") {
        let rest = &query[where_pos + 5..];

        // Look for comparison operators
        let operators = [">=", "<=", ">", "<", "="];
        for op in operators {
            if let Some(op_pos) = rest.find(op) {
                let after_op = &rest[op_pos + op.len()..];
                // Extract the number
                let trimmed = after_op.trim_start();
                let end = trimmed
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(trimmed.len());
                if end > 0 {
                    return trimmed[..end].parse().ok();
                }
            }
        }
    }

    None
}

/// Extract entity field from group by clause
fn extract_entity_field(query: &str) -> Option<String> {
    // Look for "by <field>" pattern
    if let Some(by_pos) = query.rfind(" by ") {
        let rest = &query[by_pos + 4..];
        let trimmed = rest.trim_start();

        // Extract the field name (until space, pipe, or end)
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '|')
            .unwrap_or(trimmed.len());
        if end > 0 {
            return Some(trimmed[..end].to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_to_seconds() {
        assert_eq!(parse_duration_to_seconds("1h"), Some(3600));
        assert_eq!(parse_duration_to_seconds("2h"), Some(7200));
        assert_eq!(parse_duration_to_seconds("30m"), Some(1800));
        assert_eq!(parse_duration_to_seconds("1d"), Some(86400));
        assert_eq!(parse_duration_to_seconds("60s"), Some(60));
        assert_eq!(parse_duration_to_seconds(""), None);
        assert_eq!(parse_duration_to_seconds("invalid"), None);
    }
}
