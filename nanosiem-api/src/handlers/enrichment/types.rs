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
    pub download_url: Option<String>,
    pub enabled: bool,
    pub last_sync_at: Option<String>,
    pub last_sync_status: Option<String>,
    pub record_count: i64,
    /// Sanitized config (API keys masked)
    pub config: serde_json::Value,
}

/// Request to configure an enrichment source
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfigureEnrichmentRequest {
    pub download_url: String,
}

/// Response for sync operation (synchronous - legacy)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SyncResponse {
    pub success: bool,
    pub records_loaded: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Response for async sync operation (202 Accepted or 409 Conflict)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AsyncSyncResponse {
    pub source_id: String,
    pub status: String,
    pub message: String,
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

/// Request to configure auto-sync settings
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AutoSyncConfigRequest {
    /// Enable or disable auto-sync
    pub enabled: bool,
    /// Sync interval in hours (default: 24)
    #[serde(default = "default_sync_interval")]
    pub interval_hours: u64,
}

fn default_sync_interval() -> u64 {
    24
}

/// Response for auto-sync configuration
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AutoSyncConfigResponse {
    pub source_id: String,
    pub auto_sync_enabled: bool,
    pub sync_interval_hours: u64,
    pub next_sync_at: Option<String>,
}

/// Request to configure ThreatFox enrichment source
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfigureThreatFoxRequest {
    /// API key (optional but recommended for higher rate limits)
    pub api_key: Option<String>,
    /// Sync interval in hours (default: 6)
    pub sync_interval_hours: Option<u64>,
    /// IOC TTL in days (default: 7)
    pub ttl_days: Option<i64>,
    /// Enable auto-sync
    pub auto_sync_enabled: Option<bool>,
}

/// Response for IOC lookup
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IocLookupResponse {
    pub value: String,
    pub found: bool,
    pub ioc_type: Option<String>,
    pub source_id: Option<String>,
    pub threat_type: Option<String>,
    pub malware: Option<String>,
    pub confidence_level: Option<i32>,
    pub tags: Vec<String>,
}

/// Response for IOC statistics
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IocStatsResponse {
    pub ip_count: i64,
    pub domain_count: i64,
    pub hash_count: i64,
    pub url_count: i64,
    pub total: i64,
}

/// Request to configure TOR Exit Nodes enrichment source
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfigureTorRequest {
    /// Sync interval in hours (default: 6)
    pub sync_interval_hours: Option<u64>,
    /// IOC TTL in days (default: 1)
    pub ttl_days: Option<i64>,
    /// Confidence level for TOR exit node IOCs (default: 85)
    pub confidence_level: Option<i32>,
    /// Enable auto-sync
    pub auto_sync_enabled: Option<bool>,
}

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
}
