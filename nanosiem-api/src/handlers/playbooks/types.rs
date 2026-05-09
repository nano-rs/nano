// SPDX-License-Identifier: AGPL-3.0-or-later

//! Handler-local DTOs for the playbooks API.

use nanosiem_core::playbooks::{
    Playbook, PlaybookCategory, PlaybookStatus,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Response for listing playbooks (with total count for pagination).
#[derive(Debug, Serialize, ToSchema)]
pub struct ListPlaybooksResponse {
    pub playbooks: Vec<Playbook>,
    pub total: i64,
}

/// Query parameters for listing playbooks.
#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct ListPlaybooksParams {
    /// Filter by category.
    pub category: Option<PlaybookCategory>,
    /// Filter by status.
    pub status: Option<PlaybookStatus>,
    /// Match playbooks whose `match_signals` contains this signal.
    pub signal: Option<String>,
    /// Free-text search across title and subtitle.
    pub search: Option<String>,
    /// Sort mode: `recent` (default) | `title` | `attached`.
    pub sort: Option<String>,
    /// Page size (default 100, max 1000).
    pub limit: Option<i64>,
    /// Offset for pagination.
    pub offset: Option<i64>,
    /// Filter to adaptive (agent-composed) playbooks.
    pub adaptive: Option<bool>,
}
