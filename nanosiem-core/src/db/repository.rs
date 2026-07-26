// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repository implementations

pub mod alerts;
pub mod artifacts;
// Cases & incidents are an enterprise feature (NAN-744): the API routes that
// expose them live in nanosiem-enterprise, no open-core code calls these repos,
// and the `ai_*` columns they SELECT only exist in the enterprise migration
// overlay. Gate the repo layer out of the open edition entirely (NAN-1298),
// matching the airgap/license precedent — so the open binary never compiles SQL
// against columns its database doesn't have.
#[cfg(feature = "enterprise")]
pub mod cases;
// NAN-2075/2077: the case-visibility predicate itself is NOT gated. Open-core
// surfaces (playbooks, notebooks) legitimately need to answer "can this user see
// this case?" without depending on the enterprise-gated `CaseRepository` type,
// and having ONE definition is the whole point — see the module docs.
pub mod case_visibility;
pub mod dashboards;
pub mod detection_rules;
pub mod feedback;
pub mod folder_settings;
#[cfg(feature = "enterprise")]
pub mod incidents;
pub mod notebooks;
pub mod notifications;
pub mod query_explanations;
pub mod rate_limit;
pub mod recent_activity;
pub mod retro_hunt;
pub mod saved_searches;
pub mod search_history;
pub mod shared_searches;
pub mod source_scope;

pub use alerts::{compute_event_hash, AlertInsert, AlertRepository, AlertRepositoryError};
pub use artifacts::{ArtifactRepository, ArtifactRepositoryError};
#[cfg(feature = "enterprise")]
pub use cases::{CaseRepository, CaseRepositoryError, CaseWorkflowRepository};
pub use dashboards::{DashboardRepository, DashboardRepositoryError};
pub use detection_rules::{DailyStat, DetectionRuleRepository};
pub use feedback::{
    CreateFeedbackRequest, Feedback, FeedbackError, FeedbackQuery, FeedbackRepository,
    FeedbackWithUser, UpdateFeedbackRequest,
};
pub use folder_settings::{FolderSetting, FolderSettingsError, FolderSettingsRepository};
#[cfg(feature = "enterprise")]
pub use incidents::{IncidentRepository, IncidentRepositoryError};
pub use notebooks::{NotebookRepository, NotebookRepositoryError};
pub use notifications::{NotificationError, NotificationRepository};
pub use retro_hunt::{RetroHuntRepository, RetroHuntRepositoryError};
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
pub use source_scope::{
    RestrictedSourceType, SourceScopeError, SourceScopeRepository, SourceTypeGrant,
};
