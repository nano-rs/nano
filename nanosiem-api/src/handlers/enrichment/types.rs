// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request/response types for enrichment endpoints

use serde::{Deserialize, Serialize};

/// Response for listing enrichment sources
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EnrichmentSourcesResponse {
    pub sources: Vec<EnrichmentSourceInfo>,
}

/// Enrichment source info
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EnrichmentSourceInfo {
    pub id: String,
    pub name: String,
    pub source_type: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub last_sync_at: Option<String>,
    pub last_sync_status: Option<String>,
    pub record_count: i64,
    /// NAN-1124: rows deprovisioned by the reconcile job (push sources).
    pub deprovisioned_count: i64,
    /// Sanitized config (API keys masked)
    pub config: serde_json::Value,
}

/// Response for enrichment stats
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EnrichmentStatsResponse {
    pub enabled_sources: i64,
    pub total_ip_records: i64,
}

/// Response for IP lookup
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IpLookupResponse {
    pub ip: String,
    pub found: bool,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub continent: Option<String>,
    pub continent_code: Option<String>,
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub as_domain: Option<String>,
}

// NAN-1111: ConfigureThreatFoxRequest, IocLookupResponse, IocStatsResponse,
// and ConfigureTorRequest used to live here. Both providers sunset to the
// marketplace + Deno (nano-rs/nano-enrichments); the IOC lookup/stats
// endpoints they shared had no remaining UI callers and were deleted with
// the rest. IPinfo Lite comes from nano's signed platform feed bundle
// (NAN-4959).

/// Request to look up an artifact via agent enrichment providers
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AgentLookupRequest {
    /// The artifact value (IP, domain, hash, URL)
    pub artifact: String,
    /// Optional artifact type hint. If omitted, auto-detected.
    pub artifact_type: Option<String>,
}

/// Result from a single agent enrichment provider
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AgentLookupProviderResult {
    pub provider_id: String,
    pub is_malicious: bool,
    pub confidence: f64,
    pub reputation_score: Option<i32>,
    pub categories: Vec<String>,
    pub raw_data: serde_json::Value,
    pub error: Option<String>,
}

/// Aggregated agent enrichment lookup response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AgentLookupResponse {
    pub artifact: String,
    pub artifact_type: String,
    pub results: Vec<AgentLookupProviderResult>,
    /// Why no external provider was called (`internal_domain` when the
    /// artifact is under an internal DNS suffix; privacy and cost).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}
