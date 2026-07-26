// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled reports (NAN-1793).
//!
//! A report definition schedules (cron) a saved SEARCH or a DASHBOARD to produce
//! downloadable artifacts (CSV / self-contained HTML) on a recurrence. The
//! distributed scheduler reuses the scheduled-jobs SKIP LOCKED claiming pattern;
//! completed runs notify the owner in-app and fire a `report_ready` webhook.

pub mod authz;
pub mod render;
pub mod repository;
pub mod service;
pub mod types;

#[cfg(test)]
mod tests;

pub use render::PanelOutput;
pub use repository::{ReportRepository, ReportRepositoryError};
pub use service::{report_artifact_download_allowed, ReportError, ReportService};
pub use types::{
    report_run_requires_search_sql, ArtifactScope, ClaimedReportDefinition, NewReportDefinition,
    RenderedArtifact, ReportArtifactContent, ReportArtifactMeta, ReportDefinition, ReportRun,
    ReportRunAuthorizationScope, ReportRunStatus, ReportSourceType, UpdateReportDefinition,
};
pub use authz::{
    dashboard_executes_search_sql, dashboard_panel_executes_search_sql,
    required_report_permissions, ReportAuthorizationError, ReportAuthorizationIntent,
    ReportAuthorizer, ReportDashboardAuthorization, ReportExecutionAuthorization,
};
