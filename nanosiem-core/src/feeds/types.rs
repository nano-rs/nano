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

/// Request to create a new feed
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewFeed {
    pub name: String,
    pub description: Option<String>,
    pub match_field: Option<String>,
    pub match_pattern: Option<String>,
    pub match_values: Option<Vec<String>>,
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
}

/// Request to update a feed
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateFeed {
    pub name: Option<String>,
    pub description: Option<String>,
    pub match_field: Option<String>,
    pub match_pattern: Option<String>,
    pub match_values: Option<Vec<String>>,
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub enabled: Option<bool>,
    pub stale_alert_enabled: Option<bool>,
    pub stale_threshold_minutes: Option<i32>,
}

/// Feed statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FeedStats {
    #[serde(with = "typeid::feed")]
    #[schema(value_type = String)]
    pub feed_id: Uuid,
    pub feed_name: String,
    pub event_count: i64,
    pub last_event_at: Option<DateTime<Utc>>,
}

/// Detailed health metrics for a feed
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FeedHealthMetrics {
    #[serde(with = "typeid::feed")]
    #[schema(value_type = String)]
    pub feed_id: Uuid,
    pub feed_name: String,
    pub total_events: i64,
    pub events_last_24h: i64,
    pub events_last_hour: i64,
    pub avg_events_per_hour: f64,
    pub last_event_at: Option<DateTime<Utc>>,
    pub first_event_at: Option<DateTime<Utc>>,
    pub data_freshness_hours: Option<f64>,
    pub ingestion_rate_trend: String, // "increasing", "decreasing", "stable", "no_data"
    pub health_status: String,        // "healthy", "stale", "no_data", "disabled"
    pub total_size_bytes: i64,        // Total storage size in bytes
    pub avg_event_size_bytes: f64,    // Average event size in bytes
    pub error_rate_24h: f64,          // Error rate in last 24h (0.0 to 1.0)
    pub parse_errors_24h: i64,        // Parse errors in last 24h
    pub storage_errors_24h: i64,      // Storage errors in last 24h
}

/// Historical data point for charts
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FeedHistoryPoint {
    pub time: DateTime<Utc>,
    pub event_count: i64,
    pub hour_label: String, // e.g., "14:00", "Dec 22 14:00"
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
