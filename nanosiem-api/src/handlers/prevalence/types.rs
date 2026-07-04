// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request/response types for prevalence endpoints

use nanosiem_core::prevalence::PrevalenceData;
use serde::{Deserialize, Serialize};

/// Query parameters for single artifact prevalence endpoints
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct PrevalenceQuery {
    /// Time window for prevalence calculation (1h, 24h, 7d, 30d)
    pub window: Option<String>,
}

/// Query parameters for rare artifacts endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct RareArtifactsQuery {
    /// Time window for prevalence calculation
    pub window: Option<String>,
    /// Filter by artifact type (hash, domain)
    #[serde(rename = "type")]
    pub artifact_type: Option<String>,
    /// Maximum number of results per page
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// Query parameters for new artifacts endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct NewArtifactsQuery {
    /// ISO 8601 timestamp for "since" filter
    pub since: Option<String>,
    /// Filter by artifact type (hash, domain)
    #[serde(rename = "type")]
    pub artifact_type: Option<String>,
    /// Maximum number of results per page
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// Query parameters for export endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ExportQuery {
    /// Time window for prevalence calculation
    pub window: Option<String>,
    /// Filter by artifact type (hash, domain)
    #[serde(rename = "type")]
    pub artifact_type: Option<String>,
    /// Maximum prevalence (host count) to include
    pub max_prevalence: Option<u64>,
    /// Export format (csv, json)
    pub format: Option<String>,
}

/// Request body for bulk prevalence lookup
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BulkPrevalenceRequest {
    /// List of artifacts to look up
    pub artifacts: Vec<String>,
    /// Time window for prevalence calculation
    pub window: Option<String>,
}

/// Request body for query artifacts endpoint
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct QueryArtifactsRequest {
    /// The search query to extract artifacts from
    pub query: String,
    /// Time range for the query
    pub time_range: serde_json::Value,
}

/// Response for query artifacts endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct QueryArtifactsResponse {
    pub hash_points: Vec<ArtifactPoint>,
    pub domain_points: Vec<ArtifactPoint>,
    pub rarity_threshold: u64,
    /// True when the distinct-artifact extraction hit its cap and only a
    /// subset of matching artifacts was scored. Lets the caller distinguish
    /// "the query matched nothing" from "the query matched too much to score
    /// in one pass" (audit P8) — previously an over-cap result was silently
    /// swallowed into an empty 200.
    #[serde(default)]
    pub artifacts_truncated: bool,
}

/// Single artifact point for scatter/chart visualization
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ArtifactPoint {
    pub artifact: String,
    pub host_count: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub total_occurrences: u64,
    pub is_rare: bool,
    pub prevalence_score: u8,
}

/// Request body for scatter plot data
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ScatterPlotRequest {
    /// Artifacts to include in scatter plot
    pub artifacts: ScatterArtifacts,
    /// Time window for prevalence calculation
    pub window: Option<String>,
}

/// Artifacts for scatter plot request
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ScatterArtifacts {
    /// Hash artifacts
    #[serde(default)]
    pub hashes: Vec<String>,
    /// Domain artifacts
    #[serde(default)]
    pub domains: Vec<String>,
    /// IP address artifacts
    #[serde(default)]
    pub ips: Vec<String>,
}

/// Response for single artifact prevalence
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PrevalenceResponse {
    pub data: PrevalenceData,
}

/// Response for bulk prevalence lookup
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BulkPrevalenceResponse {
    pub data: Vec<PrevalenceData>,
    pub total: usize,
}

/// Response for rare/new artifacts
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ArtifactListResponse {
    pub artifacts: Vec<PrevalenceData>,
    pub total: usize,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
}

/// Query parameters for artifact explorer endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ArtifactExplorerQuery {
    /// Time window for prevalence calculation (1h, 24h, 7d, 30d)
    pub window: Option<String>,
    /// Filter by artifact type (hash, domain, ip)
    #[serde(rename = "type")]
    pub artifact_type: Option<String>,
    /// Risk level filter (rare, new)
    pub risk_level: Option<String>,
    /// Search term to filter artifacts
    pub search: Option<String>,
    /// Maximum number of results per page
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// Query parameters for artifact detail endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ArtifactDetailQuery {
    /// The artifact value (hash, domain, or IP)
    pub artifact: String,
    /// Time window for detail queries (1h, 24h, 7d, 30d)
    pub window: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit P8: an over-cap query must be distinguishable on the wire from
    /// "matched nothing". The response carries an explicit `artifacts_truncated`
    /// flag; empty points + `true` means "too much to score in one pass".
    #[test]
    fn query_artifacts_response_exposes_truncation_signal() {
        let truncated = QueryArtifactsResponse {
            hash_points: vec![],
            domain_points: vec![],
            rarity_threshold: 3,
            artifacts_truncated: true,
        };
        let json = serde_json::to_value(&truncated).unwrap();
        assert_eq!(json["artifacts_truncated"], serde_json::json!(true));

        // Default (not truncated) path stays false so a genuinely-empty match
        // reads as empty, not truncated.
        let empty = QueryArtifactsResponse {
            hash_points: vec![],
            domain_points: vec![],
            rarity_threshold: 3,
            artifacts_truncated: false,
        };
        let json = serde_json::to_value(&empty).unwrap();
        assert_eq!(json["artifacts_truncated"], serde_json::json!(false));
    }
}
