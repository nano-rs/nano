// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database models for NanoSIEM

pub mod alert;
pub mod case;
pub mod dashboard;
pub mod detection_rule;
pub mod incident;
pub mod log;
pub mod notebook;
pub mod notification;
pub mod queue;
pub mod saved_search;
pub mod shared_search;

pub use alert::{AcknowledgeAlert, Alert, AlertStatus, CloseAlert, Disposition, NewAlert};
pub use case::{
    AddAlertToCase,
    AiRecommendation,
    AiSummaryResponse,
    AssignCase,
    Case,
    CaseAffectedUser,
    CaseAlert,
    CaseAlertDetail,
    // Workflow models (NAN-415)
    CaseCloseNote,
    CaseDisposition,
    CaseEntity,
    CaseEntityType,
    CaseEscalation,
    CaseFilter,
    CaseFullResponse,
    CaseGroupingRule,
    CaseHandoff,
    CasePendingState,
    // Linked-case lookup (NAN-422)
    LinkedCaseRef,
    CaseRelation,
    CaseRelationType,
    CaseResponseStats,
    CaseShareResult,
    CaseStats,
    CaseStatus,
    CaseSummary,
    CaseWallEntry,
    CaseWallEntryType,
    CaseWallEntryWithCreator,
    CaseWithDetails,
    CaseWithDetailsRow,
    CaseWorkflowEvent,
    ChangeCaseStatus,
    EntityTypeSummary,
    EscalateCase,
    GenerateAiSummaryRequest,
    GroupingType,
    NewCase,
    NewCaseCloseNote,
    NewCaseCloseNoteInline,
    NewCaseEntity,
    NewCaseEscalation,
    NewCaseGroupingRule,
    NewCaseHandoff,
    NewCaseRelation,
    NewCaseWallEntry,
    NewCaseWorkflowEvent,
    DuplicateCandidate,
    RelatedCaseSummary,
    SeverityRule,
    ShareCaseRequest,
    // Sharing types
    SharedGroup as CaseSharedGroup,
    UpdateCase,
    UpdateCaseGroupingRule,
    UpdateEntityEnrichment,
};
pub use dashboard::{
    Dashboard, DashboardAffectedUser, DashboardShareResult, DashboardSharedGroup,
    DashboardWithContext, DashboardWithOwner, NewDashboard, ShareDashboardRequest, UpdateDashboard,
};
pub use detection_rule::{
    AiTriageHints, AlertMode, DetectionMode, DetectionRule, DetectionRuleWithCaseGroups,
    NewDetectionRule, RiskValidationError, RuleMode, Severity, UpdateDetectionRule,
    UpdateRuleCasePermissionsRequest,
};
pub use incident::{
    CreateIncidentRequest, Incident, IncidentSource, IncidentStatus, IncidentSummary,
    IncidentWithCases, NewIncident,
};
pub use log::{Log, NewLog};
pub use notebook::{
    NewNotebook, NewNotebookEntry, NewNotebookReference, NewNotebookShare, Notebook, NotebookEntry,
    NotebookEntryType, NotebookEntryWithCreator, NotebookReference, NotebookShare,
    NotebookShareWithNames, NotebookStatus, NotebookSummary, NotebookVisibility, NotebookWithOwner,
    ReferenceType, SharePermission, UpdateNotebook,
};
pub use notification::{NewNotification, Notification, NotificationType, UnreadCountResponse};
pub use queue::{
    NewQueue, NewQueueRoutingRule, Queue, QueueKind, QueueRoutingPreviewRequest,
    QueueRoutingPreviewResponse, QueueRoutingRule, QueueRoutingRuleUpdate, QueueUpdate,
    QueueWithMembership, QueueWithMembershipRow,
};
pub use saved_search::{
    AffectedUser, NewSavedSearch, SavedSearch, SavedSearchWithContext, ShareResult,
    ShareSavedSearchRequest, SharedGroup, UpdateSavedSearch,
};
pub use shared_search::{NewSharedSearch, SharedSearch, SharedSearchResponse};
