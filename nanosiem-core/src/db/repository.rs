// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repository implementations

pub mod alerts;
pub mod cases;
pub mod dashboards;
pub mod detection_rules;
pub mod feedback;
pub mod folder_settings;
pub mod incidents;
pub mod notebooks;
pub mod notifications;
pub mod query_explanations;
pub mod rate_limit;
pub mod recent_activity;
pub mod saved_searches;
pub mod search_history;
pub mod shared_searches;

pub use alerts::{compute_event_hash, AlertRepository, AlertRepositoryError};
pub use cases::{CaseRepository, CaseRepositoryError, CaseWorkflowRepository};
pub use dashboards::{DashboardRepository, DashboardRepositoryError};
pub use detection_rules::{DailyStat, DetectionRuleRepository};
pub use feedback::{
    CreateFeedbackRequest, Feedback, FeedbackError, FeedbackQuery, FeedbackRepository,
    FeedbackWithUser, UpdateFeedbackRequest,
};
pub use folder_settings::{FolderSetting, FolderSettingsError, FolderSettingsRepository};
pub use incidents::{IncidentRepository, IncidentRepositoryError};
pub use notebooks::{NotebookRepository, NotebookRepositoryError};
pub use notifications::{NotificationError, NotificationRepository};
pub use query_explanations::{
    NewQueryExplanation, QueryExplanation, QueryExplanationError, QueryExplanationRepository,
    ReasoningStepRow,
};
pub use rate_limit::{RateLimitRepository, RateLimitRepositoryError};
pub use recent_activity::{
    RecentActivityError, RecentActivityItem, RecentActivityRepository, RecentItemType,
};
pub use saved_searches::{SavedSearchRepository, SavedSearchRepositoryError};
pub use search_history::{
    NewSearchHistoryEntry, SearchHistoryEntry, SearchHistoryError, SearchHistoryRepository,
};
pub use shared_searches::{SharedSearchRepository, SharedSearchRepositoryError};
