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

// NAN-5360 + NAN-5362: Agent Lane findings (active-token cap from enterprise
// migration 9000096; query-audit conditions from the enterprise harvester).
#[cfg(feature = "enterprise")]
pub mod agentlane_findings;
// NAN-5622: SOAR dead letters, trigger backlog and dropped events.
#[cfg(feature = "enterprise")]
pub mod soar_findings;
pub mod analyzer;
// NAN-5470: nano's ClickHouse users meeting their hourly quota.
pub mod clickhouse_quota;
// NAN-5390: ClickHouse refusing nano's logins or writes.
pub mod clickhouse_refusals;
pub mod collector;
// NAN-5450: data volumes at 80 % / 90 %.
pub mod disk_findings;
// NAN-5097: reads an enterprise table (migration 9000094).
#[cfg(feature = "enterprise")]
pub mod enrichment_wasm_findings;
pub mod finding_signature;
// NAN-5431: events Vector discarded after ingest accepted them.
pub mod pipeline_drops;
pub mod repository;
pub mod scheduler;
pub mod shard_skew;
pub mod suppressions_repository;
pub mod types;
// NAN-5567: batches ClickHouse permanently rejected, kept by Vector.
pub mod vector_dead_letters;
pub mod vector_pipeline_gate;

pub use repository::{SiemHealthRepository, SiemHealthRepositoryError};
pub use suppressions_repository::{
    FindingSuppression, SuppressionRepository, SuppressionRepositoryError,
};
pub use types::{SiemHealthReport, SiemHealthReportSummary};
