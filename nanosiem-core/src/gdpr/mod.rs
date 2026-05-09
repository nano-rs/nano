// SPDX-License-Identifier: AGPL-3.0-or-later

//! GDPR Data Subject Anonymization
//!
//! Implements the "right to erasure" by anonymizing PII fields in ClickHouse logs
//! using HMAC-SHA256 hashing with a per-deployment salt. This preserves event
//! correlation (same user hashes to same value) while destroying PII.
//!
//! Two-step flow: submit (preview affected rows) → execute (run mutations).
//! The original identifier is never persisted — only its HMAC hash.

mod service;

pub use service::AnonymizationService;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of identifier being anonymized
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IdentifierType {
    Username,
    Email,
    Ip,
}

impl std::fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Username => write!(f, "username"),
            Self::Email => write!(f, "email"),
            Self::Ip => write!(f, "ip"),
        }
    }
}

/// Status of an anonymization request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnonymizationStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for AnonymizationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// An anonymization request record (no original PII stored)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AnonymizationRequest {
    pub id: Uuid,
    pub identifier_type: IdentifierType,
    /// HMAC-SHA256 hash of the original identifier — plaintext never stored
    pub identifier_hash: String,
    pub status: AnonymizationStatus,
    pub logs_affected: i64,
    pub identity_observations_affected: i64,
    pub cloud_activity_affected: i64,
    pub user_registry_affected: i64,
    pub mutation_ids: serde_json::Value,
    pub justification: Option<String>,
    pub error_message: Option<String>,
    pub requested_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Preview returned after submitting a request (before execution)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AnonymizationPreview {
    pub request_id: Uuid,
    pub identifier_type: IdentifierType,
    pub status: AnonymizationStatus,
    pub estimated_logs: i64,
    pub estimated_identity_observations: i64,
    pub estimated_cloud_activity: i64,
    pub estimated_user_registry: i64,
    pub limitations: Vec<String>,
}

/// Errors from the anonymization service
#[derive(Debug, thiserror::Error)]
pub enum AnonymizationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("ClickHouse error: {0}")]
    ClickHouse(String),

    #[error("Request not found: {0}")]
    NotFound(Uuid),

    #[error("Request is not in pending status")]
    NotPending,

    #[error("ClickHouse is not available")]
    ClickHouseUnavailable,

    #[error("GDPR salt not configured")]
    SaltNotConfigured,

    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(String),
}
