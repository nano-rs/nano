// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health monitoring types and data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// Type of health issue being tracked
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum HealthIssueType {
    /// AI provider is down or unreachable
    AiProvider,
    /// Data feed is stale (no recent events)
    DataFeed,
    /// Disk pressure detected on ClickHouse storage
    DiskPressure,
    /// Agent is using a deprecated model
    ModelDeprecated,
}

impl std::fmt::Display for HealthIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthIssueType::AiProvider => write!(f, "ai_provider"),
            HealthIssueType::DataFeed => write!(f, "data_feed"),
            HealthIssueType::DiskPressure => write!(f, "disk_pressure"),
            HealthIssueType::ModelDeprecated => write!(f, "model_deprecated"),
        }
    }
}

impl HealthIssueType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ai_provider" => Some(HealthIssueType::AiProvider),
            "data_feed" => Some(HealthIssueType::DataFeed),
            "disk_pressure" => Some(HealthIssueType::DiskPressure),
            "model_deprecated" => Some(HealthIssueType::ModelDeprecated),
            _ => None,
        }
    }
}

/// A tracked health issue
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HealthIssue {
    #[serde(with = "typeid::health")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub issue_type: String,
    pub issue_key: String,
    pub first_detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub notification_sent: bool,
}

/// Status of an AI provider
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AiProviderStatus {
    #[serde(with = "typeid::health")]
    #[schema(value_type = String)]
    pub provider_id: Uuid,
    pub provider_name: String,
    pub provider_type: String,
    pub is_healthy: bool,
    pub error_message: Option<String>,
    pub checked_at: DateTime<Utc>,
}

/// Status of a data feed regarding staleness
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FeedStalenessStatus {
    #[serde(with = "typeid::feed")]
    #[schema(value_type = String)]
    pub feed_id: Uuid,
    pub feed_name: String,
    pub last_event_at: Option<DateTime<Utc>>,
    pub stale_threshold_minutes: i32,
    pub minutes_since_last_event: Option<i64>,
    pub is_stale: bool,
}

/// Configuration for the health scheduler
#[derive(Debug, Clone)]
pub struct HealthSchedulerConfig {
    /// How often to run health checks (in seconds)
    pub check_interval_secs: u64,
    /// Default staleness threshold in minutes for feeds without custom config
    pub default_stale_threshold_minutes: i32,
}

impl Default for HealthSchedulerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 300, // 5 minutes
            default_stale_threshold_minutes: 15,
        }
    }
}
