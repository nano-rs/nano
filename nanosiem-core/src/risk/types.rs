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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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

/// Fixed UUID of the seeded default risk-notable detection rule (NAN-1805).
///
/// Seeded NON-ALERTING (Live) by enterprise migration
/// `9000033_default_risk_notable_rule.sql` — the literal there must match this
/// constant (pinned by a test). The `/api/settings/risk-notables` card is a
/// thin editor over this rule: thresholds → the rule's WHERE, cooldown → its
/// `alert_cooldown_minutes`, enabled → Live vs Alerting mode.
pub const DEFAULT_RISK_NOTABLE_RULE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0xb8f3_d2a1_6c4e_4f7a_9d2b_3e5a_7c90_1f44);

/// Optional per-entity-type threshold overrides for risk notables (NAN-1792).
///
/// `None` fields fall back to the global [`RiskNotableConfig`] thresholds, so
/// an override can raise/lower just one window for one entity type (e.g. a
/// higher bar for `ip` entities that naturally accumulate more findings).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RiskNotableTypeThresholds {
    /// Override for the 24h decayed-score threshold (None = global default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_24h: Option<i32>,
    /// Override for the 7d decayed-score threshold (None = global default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_7d: Option<i32>,
}

/// Risk-notable generation settings (NAN-1792, repointed in NAN-1805).
///
/// A risk notable is an alert raised when an entity's ACCUMULATED decayed risk
/// score crosses a threshold — many low-severity risk contributions collapse
/// into one high-signal alert. Since NAN-1805 these settings are a thin editor
/// over the seeded default `dataset=risk` detection rule
/// ([`DEFAULT_RISK_NOTABLE_RULE_ID`]): thresholds/overrides regenerate its
/// query ([`Self::default_rule_query`]), the cooldown maps to its
/// `alert_cooldown_minutes`, and `enabled` maps to Live vs Alerting mode.
/// (The retired scheduler raised `kind = "risk_notable"` alerts; historical
/// rows stay valid.)
///
/// Thresholds compare against the same unbounded decayed sums the Risk page
/// shows (`decayed_score_24h` / `decayed_score_7d`), NOT a 0-100 band.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RiskNotableConfig {
    /// Master switch. Default OFF so an upgrade never starts alerting
    /// until thresholds have been reviewed for the deployment's score scale.
    pub enabled: bool,
    /// 24h decayed-score threshold (exclusive: fires when score > threshold)
    pub threshold_24h: i32,
    /// 7d decayed-score threshold (exclusive: fires when score > threshold)
    pub threshold_7d: i32,
    /// Minimum minutes between notables for the SAME entity (hysteresis).
    /// While an entity stays above threshold it re-fires at most once per
    /// cooldown window; the durable authority is the alerts table.
    pub cooldown_minutes: i32,
    /// Per-entity-type threshold overrides. Keyed by the entity type the risk
    /// threshold view emits — `ip`, `email`, `hostname`, `user` (that query
    /// infers type from the value with a coarse multiIf and does not produce
    /// `hash`/`domain`). Keys outside that set are accepted for forward
    /// compatibility but never match a candidate today.
    #[serde(default)]
    pub entity_type_overrides: std::collections::HashMap<String, RiskNotableTypeThresholds>,
}

impl Default for RiskNotableConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold_24h: 500,
            threshold_7d: 1000,
            cooldown_minutes: 240,
            entity_type_overrides: std::collections::HashMap::new(),
        }
    }
}

impl RiskNotableConfig {
    /// Validate thresholds/cooldown are positive (0 would fire on every
    /// scored entity every cycle; negatives are meaningless).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.threshold_24h <= 0 {
            return Err("threshold_24h must be greater than 0");
        }
        if self.threshold_7d <= 0 {
            return Err("threshold_7d must be greater than 0");
        }
        if self.cooldown_minutes <= 0 {
            return Err("cooldown_minutes must be greater than 0");
        }
        for override_ in self.entity_type_overrides.values() {
            if matches!(override_.threshold_24h, Some(t) if t <= 0) {
                return Err("entity-type threshold_24h override must be greater than 0");
            }
            if matches!(override_.threshold_7d, Some(t) if t <= 0) {
                return Err("entity-type threshold_7d override must be greater than 0");
            }
        }
        Ok(())
    }

    /// Effective 24h threshold for an entity type (override or global).
    pub fn threshold_24h_for(&self, entity_type: &str) -> i32 {
        self.entity_type_overrides
            .get(entity_type)
            .and_then(|o| o.threshold_24h)
            .unwrap_or(self.threshold_24h)
    }

    /// Effective 7d threshold for an entity type (override or global).
    pub fn threshold_7d_for(&self, entity_type: &str) -> i32 {
        self.entity_type_overrides
            .get(entity_type)
            .and_then(|o| o.threshold_7d)
            .unwrap_or(self.threshold_7d)
    }

    /// Render this config as the default risk-notable rule's nPL query
    /// (NAN-1805): the body of the seeded `dataset=risk` detection rule that
    /// replaced the RiskNotableScheduler.
    ///
    /// Without overrides:
    /// `* | where score_24h > T24 or score_7d > T7 | table …`
    ///
    /// With per-entity-type overrides, each overridden type gets its own
    /// branch and the remaining types fall to the global thresholds:
    /// `* | where (entity_type = "ip" and (score_24h > 800 or score_7d > 1000))
    ///    or (entity_type != "ip" and (score_24h > 500 or score_7d > 1000)) | table …`
    ///
    /// Deterministic (override keys sorted). Override keys outside the safe
    /// `[A-Za-z0-9_.-]` charset are skipped: they can never match the risk
    /// dataset's inferred entity types (`ip`/`email`/`hostname`/`user`) and
    /// must not be interpolated into query text verbatim.
    pub fn default_rule_query(&self) -> String {
        const TABLE_TAIL: &str =
            "| table entity, entity_type, score_24h, score_7d, distinct_rules_7d, last_rule_name";

        let mut typed: Vec<(&str, &RiskNotableTypeThresholds)> = self
            .entity_type_overrides
            .iter()
            .filter(|(t, _)| {
                !t.is_empty()
                    && t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            })
            .map(|(t, o)| (t.as_str(), o))
            .collect();
        typed.sort_by_key(|(t, _)| *t);

        if typed.is_empty() {
            return format!(
                "* | where score_24h > {} or score_7d > {} {}",
                self.threshold_24h, self.threshold_7d, TABLE_TAIL
            );
        }

        let mut branches: Vec<String> = typed
            .iter()
            .map(|(t, _)| {
                format!(
                    "(entity_type = \"{t}\" and (score_24h > {} or score_7d > {}))",
                    self.threshold_24h_for(t),
                    self.threshold_7d_for(t)
                )
            })
            .collect();
        let exclusions = typed
            .iter()
            .map(|(t, _)| format!("entity_type != \"{t}\""))
            .collect::<Vec<_>>()
            .join(" and ");
        branches.push(format!(
            "({exclusions} and (score_24h > {} or score_7d > {}))",
            self.threshold_24h, self.threshold_7d
        ));
        format!("* | where {} {}", branches.join(" or "), TABLE_TAIL)
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

#[cfg(test)]
#[path = "types_tests.rs"]
mod types_tests;

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
