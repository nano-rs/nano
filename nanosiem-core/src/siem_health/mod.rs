// SPDX-License-Identifier: AGPL-3.0-or-later

//! SIEM Health Check module
//!
//! Provides periodic AI-driven analysis of SIEM data quality across three dimensions:
//! - **Ingestion**: Source type volumes, gaps, and anomalies
//! - **Parsing**: Field coverage, ext column usage, parsing failures
//! - **Detection**: Stale rules, noisy rules, alert volumes
//!
//! Runs as a leader-only scheduled task every 12 hours and stores structured
//! reports in PostgreSQL. Reports include AI-generated narrative summaries,
//! scores, and prioritized recommendations.

pub mod analyzer;
pub mod collector;
// NAN-5097: reads an enterprise table (migration 9000094).
#[cfg(feature = "enterprise")]
pub mod enrichment_wasm_findings;
pub mod finding_signature;
pub mod repository;
pub mod scheduler;
pub mod suppressions_repository;
pub mod types;

pub use repository::{SiemHealthRepository, SiemHealthRepositoryError};
pub use suppressions_repository::{
    FindingSuppression, SuppressionRepository, SuppressionRepositoryError,
};
pub use types::{SiemHealthReport, SiemHealthReportSummary};
