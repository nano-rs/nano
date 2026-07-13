// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notification model for in-app notifications

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// Notification type
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    CaseMention,
    CaseAssigned,
    CaseStatusChange,
    AlertAssigned,
    SearchAccessRemoved,
    CaseAccessRemoved,
    CaseShared,
    AiProviderDown,
    DataFeedStale,
    System,
    TuningTriggered,
    TuningValidationComplete,
    TuningStagingDeployed,
    TuningPromoted,
    TuningReverted,
    SearchCompleted,
    SearchFailed,
    NotebookMention,
    DiskPressureWarning,
    DiskPressurePartitionDropped,
    ModelDeprecated,
    CaseEscalated,
    /// A scheduled report finished and its artifacts are ready to download.
    ReportReady,
}

impl std::fmt::Display for NotificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationType::CaseMention => write!(f, "case_mention"),
            NotificationType::CaseAssigned => write!(f, "case_assigned"),
            NotificationType::CaseStatusChange => write!(f, "case_status_change"),
            NotificationType::AlertAssigned => write!(f, "alert_assigned"),
            NotificationType::SearchAccessRemoved => write!(f, "search_access_removed"),
            NotificationType::CaseAccessRemoved => write!(f, "case_access_removed"),
            NotificationType::CaseShared => write!(f, "case_shared"),
            NotificationType::AiProviderDown => write!(f, "ai_provider_down"),
            NotificationType::DataFeedStale => write!(f, "data_feed_stale"),
            NotificationType::System => write!(f, "system"),
            NotificationType::TuningTriggered => write!(f, "tuning_triggered"),
            NotificationType::TuningValidationComplete => write!(f, "tuning_validation_complete"),
            NotificationType::TuningStagingDeployed => write!(f, "tuning_staging_deployed"),
            NotificationType::TuningPromoted => write!(f, "tuning_promoted"),
            NotificationType::TuningReverted => write!(f, "tuning_reverted"),
            NotificationType::SearchCompleted => write!(f, "search_completed"),
            NotificationType::SearchFailed => write!(f, "search_failed"),
            NotificationType::NotebookMention => write!(f, "notebook_mention"),
            NotificationType::DiskPressureWarning => write!(f, "disk_pressure_warning"),
            NotificationType::DiskPressurePartitionDropped => {
                write!(f, "disk_pressure_partition_dropped")
            }
            NotificationType::ModelDeprecated => write!(f, "model_deprecated"),
            NotificationType::CaseEscalated => write!(f, "case_escalated"),
            NotificationType::ReportReady => write!(f, "report_ready"),
        }
    }
}

/// A notification for a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Notification {
    #[serde(with = "typeid::notification")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub notification_type: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[sqlx(default)]
    pub metadata: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new notification
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewNotification {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub notification_type: NotificationType,
    pub title: String,
    pub message: Option<String>,
    pub link: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Response for unread notification count
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UnreadCountResponse {
    pub count: i64,
}
