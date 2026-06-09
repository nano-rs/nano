// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment data types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Enrichment source configuration
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct EnrichmentSource {
    pub id: String,
    pub name: String,
    pub source_type: String,
    pub description: Option<String>,
    pub download_url: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub record_count: i64,
    /// NAN-1124: rows soft-deleted by the reconcile job (push deprovisioning).
    #[sqlx(default)]
    pub deprovisioned_count: i64,
    pub file_hash: Option<String>,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update an enrichment source
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EnrichmentSourceConfig {
    pub id: String,
    pub name: String,
    pub source_type: String,
    pub description: Option<String>,
    pub download_url: Option<String>,
    pub config: Option<serde_json::Value>,
    pub enabled: bool,
}

// NAN-1117: the PG-shaped `IpEnrichment` row struct (id/extra/created_at) was
// removed when the IP enrichment payload moved to ClickHouse. The CSV-shaped
// `IpInfoLiteRecord` (sync input) and `IpEnrichmentResult` (lookup output)
// remain.

/// IP enrichment lookup result (for query-time enrichment)
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct IpEnrichmentResult {
    pub source_id: Option<String>,
    pub network: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub continent: Option<String>,
    pub continent_code: Option<String>,
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub as_domain: Option<String>,
}

/// IPinfo Lite CSV record format
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct IpInfoLiteRecord {
    pub network: String,
    pub country: String,
    pub country_code: String,
    pub continent: String,
    pub continent_code: String,
    pub asn: String,
    pub as_name: String,
    pub as_domain: String,
}

/// Sync status for enrichment sources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Success,
    Failed,
    InProgress,
    /// Queued for an immediate (re)sync. The scheduler's `needs_sync` honors
    /// this unconditionally — no interval wait, no failure cooldown. Used to
    /// recover a sync orphaned by a restart (NAN-1280): the prior process was
    /// killed mid-sync, so we re-queue rather than mark it `Failed` (a restart
    /// is not a feed failure, and the anti-hammer cooldown would be wrong).
    Pending,
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncStatus::Success => write!(f, "success"),
            SyncStatus::Failed => write!(f, "failed"),
            SyncStatus::InProgress => write!(f, "in_progress"),
            SyncStatus::Pending => write!(f, "pending"),
        }
    }
}
