// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data models for the detection-as-code push target (NAN-1745).
//!
//! A push target is a customer's own detection-as-code GitHub repo that AI
//! tuning opens Pull Requests into. It is push-only — nano never pulls rules
//! from it. The GitHub PAT is stored encrypted and is never serialized back to
//! the API; callers only see `has_token`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A configured detection-as-code push target (secret-free view).
///
/// The encrypted PAT columns (`token_encrypted`, `token_nonce`) are deliberately
/// absent — the SELECTs project `(token_encrypted IS NOT NULL) AS has_token`
/// instead so the secret never leaves the repository layer.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct DetectionCodeTarget {
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub repo_url: String,
    pub base_branch: String,
    pub path_template: String,
    pub pr_branch_prefix: String,
    pub rule_format: String,
    pub enabled: bool,
    /// True when a GitHub PAT has been stored for this target.
    pub has_token: bool,
    pub last_pr_url: Option<String>,
    pub last_pr_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

/// Request to create a push target. `token` (the fine-grained PAT) is optional
/// at create time — it can be set later via the write-only token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct NewDetectionCodeTarget {
    pub name: String,
    pub repo_url: String,
    pub base_branch: Option<String>,
    pub path_template: Option<String>,
    pub pr_branch_prefix: Option<String>,
    pub rule_format: Option<String>,
    pub enabled: Option<bool>,
    /// Plaintext PAT; encrypted before storage. Never echoed back.
    pub token: Option<String>,
}

/// Partial update of a push target's metadata. The PAT is rotated separately
/// via `set_token` so it never rides on a generic metadata update.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateDetectionCodeTarget {
    pub name: Option<String>,
    pub repo_url: Option<String>,
    pub base_branch: Option<String>,
    pub path_template: Option<String>,
    pub pr_branch_prefix: Option<String>,
    pub enabled: Option<bool>,
}
