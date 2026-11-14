// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed types and data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// A feed definition (log sourcetype)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Feed {
    #[serde(with = "typeid::feed")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// Field to match on (e.g., 'metadata.source', 'src_host', 'source_type')
    pub match_field: Option<String>,
    /// Regex pattern to match against the field value
    pub match_pattern: Option<String>,
    /// Exact values to match (alternative to pattern)
    pub match_values: Option<Vec<String>>,
    /// Category (e.g., 'network', 'endpoint', 'cloud', 'application')
    pub category: Option<String>,
    /// Vendor name (e.g., 'Cisco', 'Palo Alto', 'AWS')
    pub vendor: Option<String>,
    /// Product name (e.g., 'ASA', 'Firewall', 'CloudTrail')
    pub product: Option<String>,
    /// Icon name for UI
    pub icon: Option<String>,
    /// Color for UI badges
    pub color: Option<String>,
    /// Whether the feed is enabled
    pub enabled: bool,
    /// Whether to alert when feed becomes stale
    pub stale_alert_enabled: bool,
    /// Minutes without data before considered stale
    pub stale_threshold_minutes: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Feed category for grouping
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, utoipa::ToSchema)]
pub enum FeedCategory {
    Network,
    Endpoint,
    Cloud,
    Application,
    Security,
    System,
    Other,
}

impl FeedCategory {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "network" => Self::Network,
            "endpoint" => Self::Endpoint,
            "cloud" => Self::Cloud,
            "application" => Self::Application,
            "security" => Self::Security,
            "system" => Self::System,
            _ => Self::Other,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Endpoint => "endpoint",
            Self::Cloud => "cloud",
            Self::Application => "application",
            Self::Security => "security",
            Self::System => "system",
            Self::Other => "other",
        }
    }
}
