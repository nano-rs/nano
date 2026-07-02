// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk Analytics Types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// TTL decay configuration for risk scores (Google SecOps-style)
///
/// Decay factors are applied based on signal age:
/// - 0-24h:  decay_0_24h (default 1.0 = full weight)
/// - 1-3d:   decay_1_3d  (default 0.7)
/// - 3-5d:   decay_3_5d  (default 0.4)
/// - 5-7d:   decay_5_7d  (default 0.2)
/// - >7d:    excluded (0.0)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RiskDecayConfig {
    /// Decay factor for signals 0-24 hours old (0.0-1.0)
    pub decay_0_24h: f64,
    /// Decay factor for signals 1-3 days old (0.0-1.0)
    pub decay_1_3d: f64,
    /// Decay factor for signals 3-5 days old (0.0-1.0)
    pub decay_3_5d: f64,
    /// Decay factor for signals 5-7 days old (0.0-1.0)
    pub decay_5_7d: f64,
}

impl Default for RiskDecayConfig {
    fn default() -> Self {
        Self {
            decay_0_24h: 1.0,
            decay_1_3d: 0.7,
            decay_3_5d: 0.4,
            decay_5_7d: 0.2,
        }
    }
}

impl RiskDecayConfig {
    /// Validate that all decay factors are within bounds (0.0-1.0)
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(0.0..=1.0).contains(&self.decay_0_24h) {
            return Err("decay_0_24h must be between 0.0 and 1.0");
        }
        if !(0.0..=1.0).contains(&self.decay_1_3d) {
            return Err("decay_1_3d must be between 0.0 and 1.0");
        }
        if !(0.0..=1.0).contains(&self.decay_3_5d) {
            return Err("decay_3_5d must be between 0.0 and 1.0");
        }
        if !(0.0..=1.0).contains(&self.decay_5_7d) {
            return Err("decay_5_7d must be between 0.0 and 1.0");
        }
        Ok(())
    }
}

/// Entity risk score record
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityRiskScore {
    pub id: i32,
    pub entity: String,
    pub entity_type: String,
    pub risk_score: i32,
    #[serde(rename = "finding_count")]
    pub signal_count: i32,
    #[serde(rename = "last_finding_at")]
    pub last_signal_at: Option<DateTime<Utc>>,
    #[serde(rename = "first_finding_at")]
    pub first_signal_at: Option<DateTime<Utc>>,
    pub last_rule_name: Option<String>,
    pub last_severity: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Time-windowed risk score for an entity (calculated from signals)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TimeWindowedRiskScore {
    pub entity: String,
    pub entity_type: String,
    /// Raw sum of risk scores in 24h window (no decay)
    pub risk_score_24h: i64,
    /// Raw sum of risk scores in 7d window (no decay)
    pub risk_score_7d: i64,
    /// Decayed risk score for 24h window (with TTL decay applied)
    pub decayed_score_24h: i64,
    /// Decayed risk score for 7d window (with TTL decay applied)
    pub decayed_score_7d: i64,
    pub finding_count_24h: i64,
    pub finding_count_7d: i64,
    pub last_finding_at: Option<DateTime<Utc>>,
    pub last_rule_name: Option<String>,
    pub last_severity: Option<String>,
}

/// Summary of entity risk for API responses
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityRiskSummary {
    pub entity: String,
    pub entity_type: String,
    pub risk_score: i32,
    #[serde(rename = "finding_count")]
    pub signal_count: i32,
    #[serde(rename = "last_finding_at")]
    pub last_signal_at: Option<DateTime<Utc>>,
    pub last_rule_name: Option<String>,
    pub last_severity: Option<String>,
    pub risk_level: RiskLevel,
}

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: i32) -> Self {
        match score {
            0..=30 => RiskLevel::Low,
            31..=50 => RiskLevel::Medium,
            51..=70 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Risk analytics overview stats
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RiskAnalyticsOverview {
    pub total_entities: i64,
    pub critical_entities: i64,
    pub high_entities: i64,
    pub medium_entities: i64,
    pub low_entities: i64,
    #[serde(rename = "total_findings")]
    pub total_signals: i64,
    pub avg_risk_score: f64,
}

/// Filter options for risk queries
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RiskFilter {
    pub entity_type: Option<String>,
    pub min_score: Option<i32>,
    pub risk_level: Option<RiskLevel>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Time window for risk queries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskTimeWindow {
    Last24Hours,
    Last7Days,
    All,
}

impl RiskTimeWindow {
    pub fn hours(&self) -> Option<i64> {
        match self {
            RiskTimeWindow::Last24Hours => Some(24),
            RiskTimeWindow::Last7Days => Some(168),
            RiskTimeWindow::All => None,
        }
    }
}

/// Daily finding count for a single entity (used for activity heatmaps)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityDailyCount {
    pub date: String,
    pub count: i64,
}

/// Response for entity activity heatmap data
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityActivityResponse {
    /// Map of "entity|entity_type" → daily counts
    pub activity: std::collections::HashMap<String, Vec<EntityDailyCount>>,
}

/// Summary of a recent detection-rule firing for an entity, sourced from
/// ClickHouse `logs WHERE source_type = 'findings'`.
///
/// Unlike alerts (which only exist for rules in `alerting` mode), every
/// rule firing — regardless of mode — produces a finding row, so this
/// surfaces baking detections that would otherwise be invisible on the
/// entity drawer.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntitySignalSummary {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    /// Detection rule UUID as a string. May be empty for ad-hoc findings.
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub risk_score: i32,
    /// `signal_type` (e.g. `detection_match`, `alert`) — stored on the
    /// finding row's `action` column.
    pub signal_type: String,
}

/// Exact per-rule contribution to an entity's decayed risk score (NAN-1658).
///
/// Computed with the SAME source, window, and decay curve as the entity's
/// `decayed_score_24h/7d`, grouped by rule — so summing these per window
/// reproduces the headline score. This exists because the recent-matches feed
/// is capped (`ENTITY_MATCHES_LIMIT`), and a breakdown derived from that
/// sample understated hot entities (25 fires / +1875 shown against a 21600
/// headline).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityRuleContribution {
    /// Detection rule UUID as a string. May be empty for ad-hoc findings.
    pub rule_id: String,
    pub rule_name: String,
    /// Severity of the most recent fire.
    pub severity: String,
    /// Fires inside the trailing 24h window.
    pub fires_24h: i64,
    /// Fires inside the trailing 7d window.
    pub fires_7d: i64,
    /// Decay-weighted score contribution inside 24h — sums to the entity's
    /// `decayed_score_24h` across rules.
    pub decayed_contribution_24h: i64,
    /// Decay-weighted score contribution inside 7d — sums to the entity's
    /// `decayed_score_7d` across rules.
    pub decayed_contribution_7d: i64,
    pub last_fire_at: DateTime<Utc>,
    /// The per-fire score of the most recent fire (undecayed).
    pub last_fire_score: i32,
}
