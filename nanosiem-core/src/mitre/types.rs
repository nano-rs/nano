// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A MITRE ATT&CK tactic
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct MitreTactic {
    /// Tactic ID (e.g., "TA0001")
    pub id: String,
    /// Tactic name (e.g., "Initial Access")
    pub name: String,
    /// Short name for kill chain (e.g., "initial-access")
    pub short_name: String,
    /// Description of the tactic
    pub description: Option<String>,
    /// URL to MITRE ATT&CK page
    pub url: Option<String>,
}

/// A MITRE ATT&CK technique
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MitreTechnique {
    /// Technique ID (e.g., "T1059" or "T1059.001")
    pub id: String,
    /// Technique name
    pub name: String,
    /// Description of the technique
    pub description: Option<String>,
    /// URL to MITRE ATT&CK page
    pub url: Option<String>,
    /// Whether this is a sub-technique
    pub is_subtechnique: bool,
    /// Parent technique ID (for sub-techniques)
    pub parent_id: Option<String>,
    /// Associated tactic IDs
    pub tactic_ids: Vec<String>,
    /// Whether the technique is deprecated
    pub deprecated: bool,
    /// MITRE-declared required data sources for this technique
    /// (e.g. `["Process: Process Creation", "Network Traffic: Flow"]`).
    /// Used by the coverage API to derive `connected` data sources.
    #[serde(default)]
    pub data_sources: Vec<String>,
}

/// Metadata about the last MITRE sync
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MitreSyncMetadata {
    pub last_sync_at: DateTime<Utc>,
    pub version: Option<String>,
    pub technique_count: i32,
    pub tactic_count: i32,
}

/// STIX bundle from MITRE CTI repository
#[derive(Debug, Deserialize)]
pub struct StixBundle {
    pub objects: Vec<StixObject>,
}

/// A STIX object (can be tactic, technique, or other types)
#[derive(Debug, Deserialize)]
pub struct StixObject {
    #[serde(rename = "type")]
    pub object_type: String,
    #[allow(dead_code)]
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub external_references: Option<Vec<ExternalReference>>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    pub x_mitre_shortname: Option<String>,
    pub x_mitre_is_subtechnique: Option<bool>,
    pub x_mitre_deprecated: Option<bool>,
    /// MITRE-declared required data sources for this technique
    /// (e.g. `["Process: Process Creation", "Network Traffic: Flow"]`)
    pub x_mitre_data_sources: Option<Vec<String>>,
    pub revoked: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ExternalReference {
    pub source_name: Option<String>,
    pub external_id: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: Option<String>,
    pub phase_name: Option<String>,
}

// Coverage types for the MITRE ATT&CK coverage visualization page

/// Coverage level based on number of rules covering a technique
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CoverageLevel {
    None,
    Low,
    Medium,
    High,
}

impl CoverageLevel {
    /// Determine coverage level from rule count
    /// 0 = none, 1 = low, 2-3 = medium, 4+ = high
    pub fn from_rule_count(count: i32) -> Self {
        match count {
            0 => CoverageLevel::None,
            1 => CoverageLevel::Low,
            2..=3 => CoverageLevel::Medium,
            _ => CoverageLevel::High,
        }
    }
}

/// A detection rule that covers a technique
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CoveringRule {
    pub id: uuid::Uuid,
    pub name: String,
    pub severity: String,
    pub mode: String,
    /// Primary `source_type` extracted from the rule's nPL query
    /// (e.g. `"aws_cloudtrail"`, `"windows_sysmon"`, `"okta"`).
    /// Empty string when the query does not constrain a source type.
    pub source: String,
}

/// A required MITRE data source for a technique, with whether the
/// nanosiem deployment currently has any rule referencing a matching
/// source type.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DataSource {
    /// Stable id (e.g. `"netflow"`, `"sysmon"`). Lowercase, snake_case.
    pub id: String,
    /// Display label (e.g. `"NetFlow"`, `"Sysmon"`) — taken from the
    /// MITRE STIX bundle's `x_mitre_data_sources` string.
    pub name: String,
    /// True when at least one detection rule in this deployment queries
    /// a `source_type` mapped to this MITRE data source. Heuristic — see
    /// `nanosiem_core::mitre::data_sources` for the mapping.
    pub connected: bool,
}

/// Coverage information for a single technique
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TechniqueCoverage {
    pub technique_id: String,
    pub technique_name: String,
    pub is_subtechnique: bool,
    pub parent_id: Option<String>,
    pub tactic_ids: Vec<String>,
    pub rule_count: i32,
    pub coverage_level: CoverageLevel,
    pub rules: Vec<CoveringRule>,
    /// Required data sources for this technique (MITRE-declared).
    /// Each entry carries a `connected` flag indicating whether this
    /// deployment has any rule referencing a matching source type.
    /// Empty when the technique has no declared data sources.
    pub data_sources: Vec<DataSource>,
}

/// Coverage summary for a tactic
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TacticCoverage {
    pub tactic_id: String,
    pub tactic_name: String,
    pub short_name: String,
    pub total_techniques: i32,
    pub covered_techniques: i32,
}

/// Overall coverage summary
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CoverageSummary {
    pub total_techniques: i32,
    pub covered_techniques: i32,
    pub coverage_percentage: f64,
    pub total_rules_with_mitre: i32,
}

/// Full MITRE coverage response
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MitreCoverageResponse {
    pub tactics: Vec<TacticCoverage>,
    pub techniques: Vec<TechniqueCoverage>,
    pub summary: CoverageSummary,
}
