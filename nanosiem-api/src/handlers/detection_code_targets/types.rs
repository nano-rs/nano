// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request/response DTOs for detection-as-code push target endpoints.

use nanosiem_core::detection_code_target::DetectionCodeTarget;
use serde::{Deserialize, Serialize};

/// Response wrapping the list of configured push targets.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListTargetsResponse {
    pub targets: Vec<DetectionCodeTarget>,
}

/// Create a new push target. `token` (the fine-grained PAT) is optional here —
/// it can be set later via the token endpoint. It is never echoed back.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTargetRequest {
    pub name: String,
    pub repo_url: String,
    pub base_branch: Option<String>,
    pub path_template: Option<String>,
    pub pr_branch_prefix: Option<String>,
    pub rule_format: Option<String>,
    pub enabled: Option<bool>,
    /// Fine-grained GitHub PAT (Contents + Pull requests: write). Write-only.
    pub token: Option<String>,
}

/// Partial update of a push target's metadata (not the token).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateTargetRequest {
    pub name: Option<String>,
    pub repo_url: Option<String>,
    pub base_branch: Option<String>,
    pub path_template: Option<String>,
    pub pr_branch_prefix: Option<String>,
    pub enabled: Option<bool>,
}

/// Set (or replace) the stored GitHub PAT for a target.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetTokenRequest {
    pub token: String,
}

/// Result of probing the target repo with the stored token.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub can_read: bool,
    pub can_write: bool,
    pub default_branch: Option<String>,
    pub message: String,
}
