// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled reports (NAN-1793).
//!
//! A report definition schedules (cron) a saved SEARCH or a DASHBOARD to produce
//! downloadable artifacts (CSV / self-contained HTML) on a recurrence. The
//! distributed scheduler reuses the scheduled-jobs SKIP LOCKED claiming pattern;
//! completed runs notify the owner in-app and fire a `report_ready` webhook.

pub mod render;
pub mod repository;
pub mod service;
pub mod types;

#[cfg(test)]
mod tests;

pub use render::PanelOutput;
pub use repository::{ReportRepository, ReportRepositoryError};
pub use service::{ReportError, ReportService};
pub use types::{
    ClaimedReportDefinition, NewReportDefinition, RenderedArtifact, ReportArtifactContent,
    ReportArtifactMeta, ReportDefinition, ReportRun, ReportRunStatus, ReportSourceType,
    UpdateReportDefinition,
};
