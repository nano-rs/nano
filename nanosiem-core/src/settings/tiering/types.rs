// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types and data structures for storage tiering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during tiering operations
#[derive(Error, Debug)]
pub enum TieringError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("ClickHouse error: {0}")]
    ClickHouse(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("S3 connection error: {0}")]
    S3Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Tiering not configured")]
    NotConfigured,
}

/// Tiering configuration status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TieringStatus {
    /// No tiering configured yet
    Unconfigured,
    /// Configuration saved but not applied to ClickHouse
    Pending,
    /// Currently applying configuration
    Applying,
    /// Tiering is active and working
    Active,
    /// Configuration failed - check status_message
    Error,
}

impl TieringStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TieringStatus::Unconfigured => "unconfigured",
            TieringStatus::Pending => "pending",
            TieringStatus::Applying => "applying",
            TieringStatus::Active => "active",
            TieringStatus::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => TieringStatus::Pending,
            "applying" => TieringStatus::Applying,
            "active" => TieringStatus::Active,
            "error" => TieringStatus::Error,
            _ => TieringStatus::Unconfigured,
        }
    }
}

/// S3 credentials for tiering storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// Tiering configuration
///
/// Customer-facing model: the only time-based knob is `retention_days` (when
/// data is DELETEd from ClickHouse). Movement of parts from hot local storage
/// to warm S3 is driven by ClickHouse's `move_factor` on the storage policy —
/// volume size + ingest rate + move_factor jointly determine effective hot
/// retention, so there's no per-day "move-to-warm" knob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieringConfig {
    /// Whether tiering is enabled
    pub enabled: bool,
    /// S3 endpoint URL (custom for MinIO/R2/B2, None for AWS)
    pub s3_endpoint: Option<String>,
    /// S3 bucket name
    pub s3_bucket: Option<String>,
    /// S3 region
    pub s3_region: String,
    /// Use path-style access (required for MinIO)
    pub s3_path_style: bool,
    /// Whether credentials are configured (never expose actual keys)
    pub has_credentials: bool,
    /// Days before data is DELETEd from ClickHouse (compliance cap).
    pub retention_days: u32,
    /// Automatic move factor (0 = TTL-only, 0.1 = move when 90% full).
    /// Tunable for self-hosted / BYO-S3 users; managed deployments set this
    /// in the storage policy XML at provisioning time.
    pub move_factor: f32,
    /// Current tiering status
    pub status: TieringStatus,
    /// Status message (error description if status is Error)
    pub status_message: Option<String>,
    /// When config was last applied to ClickHouse
    pub last_applied_at: Option<DateTime<Utc>>,
}

impl Default for TieringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            s3_endpoint: None,
            s3_bucket: None,
            s3_region: "us-east-1".to_string(),
            s3_path_style: false,
            has_credentials: false,
            retention_days: 365,
            move_factor: 0.0,
            status: TieringStatus::Unconfigured,
            status_message: None,
            last_applied_at: None,
        }
    }
}

/// Request to update tiering configuration
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateTieringRequest {
    pub enabled: Option<bool>,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_path_style: Option<bool>,
    pub retention_days: Option<u32>,
    pub move_factor: Option<f32>,
}

/// Statistics for a single storage tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierInfo {
    pub size_bytes: u64,
    pub size_pretty: String,
    pub row_count: u64,
}

/// Statistics for all storage tiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierStats {
    pub hot: TierInfo,
    pub warm: TierInfo,
    pub total_size_bytes: u64,
    pub total_size_pretty: String,
    pub total_row_count: u64,
    pub last_updated: DateTime<Utc>,
}

/// Result of S3 connection test
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionTestResult {
    pub success: bool,
    pub message: String,
    pub latency_ms: Option<u64>,
}

/// Database row for tiering configuration
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct TieringConfigRow {
    pub enabled: bool,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: String,
    pub s3_path_style: bool,
    pub has_credentials: bool,
    pub retention_days: i32,
    pub move_factor: f32,
    pub status: String,
    pub status_message: Option<String>,
    pub last_applied_at: Option<DateTime<Utc>>,
}

impl From<TieringConfigRow> for TieringConfig {
    fn from(row: TieringConfigRow) -> Self {
        Self {
            enabled: row.enabled,
            s3_endpoint: row.s3_endpoint,
            s3_bucket: row.s3_bucket,
            s3_region: row.s3_region,
            s3_path_style: row.s3_path_style,
            has_credentials: row.has_credentials,
            retention_days: row.retention_days as u32,
            move_factor: row.move_factor,
            status: TieringStatus::from_str(&row.status),
            status_message: row.status_message,
            last_applied_at: row.last_applied_at,
        }
    }
}
