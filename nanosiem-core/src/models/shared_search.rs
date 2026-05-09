// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared search model for URL shortening

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// A shared search with a short URL ID
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct SharedSearch {
    pub id: String, // Short alphanumeric ID
    pub query: String,
    pub query_mode: String,      // 'piped' or 'sql'
    pub time_range_type: String, // 'preset' or 'custom'
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub access_count: i32,
    pub last_accessed_at: Option<DateTime<Utc>>,
}

/// Input for creating a new shared search
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewSharedSearch {
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
}

/// Response for shared search (simplified for frontend)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SharedSearchResponse {
    pub id: String,
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<String>,
    pub time_range_end: Option<String>,
}

impl From<SharedSearch> for SharedSearchResponse {
    fn from(s: SharedSearch) -> Self {
        Self {
            id: s.id,
            query: s.query,
            query_mode: s.query_mode,
            time_range_type: s.time_range_type,
            time_range_preset: s.time_range_preset,
            time_range_start: s.time_range_start.map(|t| t.to_rfc3339()),
            time_range_end: s.time_range_end.map(|t| t.to_rfc3339()),
        }
    }
}
