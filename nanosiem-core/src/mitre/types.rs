// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A configured source becomes stale when no event has arrived for this many
/// minutes. This matches the existing log-source health contract, which
/// requires at least one event in the last hour to report healthy ingestion.
pub const TELEMETRY_STALE_AFTER_MINUTES: i64 = 60;

/// The per-source telemetry rollup retains seven days. Readiness queries use
/// the full retained window so stale sources retain their last-seen evidence.
pub const TELEMETRY_READINESS_LOOKBACK_HOURS: i64 = 7 * 24;

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
    /// Whether the technique is deprecated.
    ///
    /// Always `false` on anything the sync produces: `parse_catalog` drops
    /// `revoked` and `x_mitre_deprecated` objects, so a technique that reaches
    /// this struct is current by construction (NAN-1921). The field and its
    /// database column exist for rows written before catalog enforcement, which
    /// the validation trigger still screens. Do not "simplify" it away.
    pub deprecated: bool,
    /// MITRE-declared required data sources for this technique
    /// (e.g. `["Process: Process Creation", "Network Traffic: Flow"]`).
    /// Used by the coverage API to derive `connected` data sources.
    #[serde(default)]
    pub data_sources: Vec<String>,
}

/// A technique ID that ATT&CK revoked in favour of another, harvested from the
/// bundle's `revoked-by` relationships.
///
/// ATT&CK renumbers techniques across releases (v19 moved `T1562.001` to
/// `T1685` when it split Impair Defenses into its own tactic). Without these
/// edges a sync deletes the old ID and every rule referencing it loses its
/// mapping, so they are persisted and used to migrate mappings forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MitreTechniqueAlias {
    /// The revoked technique ID (e.g. `T1562.001`).
    pub old_id: String,
    /// The technique that replaced it (e.g. `T1685`).
    pub new_id: String,
}

/// What a catalog sync did to existing detection-rule mappings.
///
/// Before NAN-1918 this was a single quarantine count, which conflated "we
/// carried the mapping forward" with "we deleted it".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MitreReconcileOutcome {
    /// Mappings migrated onto the new catalog via the alias map.
    pub remapped: u64,
    /// Mappings restored from quarantine that an earlier sync had destroyed.
    pub repaired: u64,
    /// Mappings cleared because no alias path resolves them.
    pub quarantined: u64,
    /// Exactly which rules lost their mapping. Reported by the reconcile pass
    /// itself rather than inferred from a timestamp window, so the sync log can
    /// name them without guessing.
    pub quarantined_rule_ids: Vec<uuid::Uuid>,
}

/// A rule mapping that a catalog sync could not resolve, plus the repair
/// outcome if a later sync managed to restore it.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct MitreQuarantinedMapping {
    pub id: i64,
    pub rule_id: uuid::Uuid,
    /// `None` when the rule has since been deleted.
    pub rule_name: Option<String>,
    pub original_tactics: Vec<String>,
    pub original_techniques: Vec<String>,
    pub reason: String,
    pub quarantined_at: DateTime<Utc>,
    pub repaired_at: Option<DateTime<Utc>>,
    pub repaired_tactics: Option<Vec<String>>,
    pub repaired_techniques: Option<Vec<String>>,
}

/// Metadata about the last MITRE sync
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MitreSyncMetadata {
    pub last_sync_at: DateTime<Utc>,
    pub version: Option<String>,
    pub technique_count: i32,
    pub tactic_count: i32,
}

/// Durable state for the latest catalog synchronization attempt.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct MitreSyncState {
    pub status: String,
    pub release_version: Option<String>,
    pub source_url: Option<String>,
    pub source_sha256: Option<String>,
    pub tactic_count: Option<i32>,
    pub technique_count: Option<i32>,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_completed_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub consecutive_failures: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// STIX bundle from MITRE CTI repository
#[derive(Debug, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
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
    /// MITRE-declared required data sources for this technique in the pre-v10
    /// ATT&CK format (e.g. `["Process: Process Creation", "Network Traffic: Flow"]`).
    /// Absent from v10+ bundles, which model detection via the fields below.
    pub x_mitre_data_sources: Option<Vec<String>>,
    /// On an `x-mitre-detection-strategy` (ATT&CK v19+): ids of the
    /// `x-mitre-analytic` objects that implement it.
    pub x_mitre_analytic_refs: Option<Vec<String>>,
    /// On an `x-mitre-analytic` (ATT&CK v19+): the log sources it consumes,
    /// each naming the `x-mitre-data-component` it observes.
    pub x_mitre_log_source_references: Option<Vec<LogSourceReference>>,
    /// On a `relationship`: the relationship kind (e.g. `"detects"`).
    pub relationship_type: Option<String>,
    /// On a `relationship`: the source/target STIX ids. For a `detects`
    /// relationship the source is a data-component (v10–v18) or a
    /// detection-strategy (v19+); the target is the technique (attack-pattern).
    pub source_ref: Option<String>,
    pub target_ref: Option<String>,
    pub revoked: Option<bool>,
}

/// A log source referenced by an `x-mitre-analytic`, naming the ATT&CK data
/// component it observes (ATT&CK v19+).
#[derive(Debug, Deserialize)]
pub struct LogSourceReference {
    pub x_mitre_data_component_ref: Option<String>,
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

/// Current ingestion readiness for a required ATT&CK data source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceReadiness {
    /// A matching source is configured and has ingested within the freshness
    /// window.
    Active,
    /// A matching source is configured but has not ingested within the
    /// freshness window. `last_seen_at = null` means it has not been observed
    /// during the retained telemetry window.
    Stale,
    /// Readiness cannot be established because no matching source is
    /// configured or ingestion health is unavailable.
    Unknown,
}

/// Point-in-time configuration and ingestion evidence used to derive ATT&CK
/// data-source readiness.
#[derive(Debug, Clone)]
pub struct TelemetryReadinessSnapshot {
    configured_source_types: HashSet<String>,
    last_seen_by_source_type: Option<HashMap<String, DateTime<Utc>>>,
    observed_at: DateTime<Utc>,
}

impl TelemetryReadinessSnapshot {
    /// Build a snapshot after a successful ingestion-health read. An empty
    /// `last_seen_by_source_type` map is meaningful: health was available but
    /// the configured sources were idle throughout the retained window.
    pub fn observed(
        configured_source_types: HashSet<String>,
        last_seen_by_source_type: HashMap<String, DateTime<Utc>>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            configured_source_types: normalize_source_set(configured_source_types),
            last_seen_by_source_type: Some(normalize_last_seen(last_seen_by_source_type)),
            observed_at,
        }
    }

    /// Build a snapshot when ClickHouse ingestion health could not be read.
    /// Configured sources remain visible, but their readiness is unknown.
    pub fn unavailable(
        configured_source_types: HashSet<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            configured_source_types: normalize_source_set(configured_source_types),
            last_seen_by_source_type: None,
            observed_at,
        }
    }

    pub(crate) fn classify(&self, mapped_source_types: &[&str]) -> ReadinessEvidence {
        let configured: Vec<String> = mapped_source_types
            .iter()
            .map(|source| source.to_ascii_lowercase())
            .filter(|source| self.configured_source_types.contains(source))
            .collect();

        if configured.is_empty() {
            return ReadinessEvidence {
                configured: false,
                readiness: DataSourceReadiness::Unknown,
                last_seen_at: None,
            };
        }

        let Some(last_seen_by_source_type) = &self.last_seen_by_source_type else {
            return ReadinessEvidence {
                configured: true,
                readiness: DataSourceReadiness::Unknown,
                last_seen_at: None,
            };
        };

        let last_seen_at = configured
            .iter()
            .filter_map(|source| last_seen_by_source_type.get(source).copied())
            .max();
        let stale_cutoff =
            self.observed_at - chrono::Duration::minutes(TELEMETRY_STALE_AFTER_MINUTES);
        let readiness = if last_seen_at.is_some_and(|last_seen| last_seen >= stale_cutoff) {
            DataSourceReadiness::Active
        } else {
            DataSourceReadiness::Stale
        };

        ReadinessEvidence {
            configured: true,
            readiness,
            last_seen_at,
        }
    }
}

fn normalize_source_set(source_types: HashSet<String>) -> HashSet<String> {
    source_types
        .into_iter()
        .map(|source| source.to_ascii_lowercase())
        .collect()
}

fn normalize_last_seen(
    last_seen_by_source_type: HashMap<String, DateTime<Utc>>,
) -> HashMap<String, DateTime<Utc>> {
    last_seen_by_source_type
        .into_iter()
        .map(|(source, last_seen)| (source.to_ascii_lowercase(), last_seen))
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadinessEvidence {
    pub configured: bool,
    pub readiness: DataSourceReadiness,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// A required MITRE data source and the deployment's current ingestion
/// readiness for matching nano source types.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DataSource {
    /// Stable id (e.g. `"netflow"`, `"sysmon"`). Lowercase, snake_case.
    pub id: String,
    /// Display label (e.g. `"NetFlow"`, `"Sysmon"`) — taken from the
    /// MITRE STIX bundle's `x_mitre_data_sources` string.
    pub name: String,
    /// Whether nano has a source-type mapping for this ATT&CK label. False
    /// means configuration readiness cannot be evaluated truthfully.
    pub mapping_known: bool,
    /// Whether at least one matching source type is enabled and deployed.
    pub configured: bool,
    /// Readiness derived from configuration plus recent ingestion evidence.
    pub readiness: DataSourceReadiness,
    /// Most recent event for a configured matching source within the retained
    /// telemetry window. Null for idle, unconfigured, or unavailable health.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Compatibility alias for older clients. True only when `readiness` is
    /// `active`; stale and unknown sources never claim to be connected.
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
    /// Required data sources for this technique (MITRE-declared), enriched
    /// with configured-source and recent-ingestion readiness.
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
    /// Counting contract used by every coverage aggregate. Each ATT&CK
    /// technique ID is independent, including parent and sub-technique IDs.
    pub coverage_unit: CoverageUnit,
    pub total_techniques: i32,
    pub covered_techniques: i32,
    pub coverage_percentage: f64,
    pub total_rules_with_mitre: i32,
}

/// The atomic item counted by MITRE coverage summaries.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoverageUnit {
    Technique,
}

/// Full MITRE coverage response
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MitreCoverageResponse {
    pub tactics: Vec<TacticCoverage>,
    pub techniques: Vec<TechniqueCoverage>,
    pub summary: CoverageSummary,
}
