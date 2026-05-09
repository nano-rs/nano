// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration types for real-time rule evaluation.

use super::super::risk::CumulativeRiskConfig;
use crate::models::DetectionRule;
use crate::query::Query;

/// Configuration for real-time evaluation
#[derive(Debug, Clone)]
pub struct RealtimeConfig {
    /// Maximum number of rules to evaluate per event
    pub max_rules_per_event: usize,
    /// Whether to enable real-time evaluation
    pub enabled: bool,
    /// Whether to log findings for detection matches and alerts
    pub signal_logging_enabled: bool,
    /// Whether to enable cumulative risk detection
    pub cumulative_risk_enabled: bool,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            max_rules_per_event: 100,
            enabled: true,
            signal_logging_enabled: true,
            cumulative_risk_enabled: true,
        }
    }
}

/// Compiled rule for efficient evaluation
#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    pub(crate) rule: DetectionRule,
    pub(crate) query: Query,
}

/// Compiled cumulative risk rule with extracted configuration
#[derive(Debug, Clone)]
pub(crate) struct CompiledCumulativeRiskRule {
    pub(crate) rule: DetectionRule,
    pub(crate) config: CumulativeRiskConfig,
}
