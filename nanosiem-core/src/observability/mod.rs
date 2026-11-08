// SPDX-License-Identifier: AGPL-3.0-or-later

//! Observability console support (NAN-1536).
//!
//! Today this is the SLO (service-level objective) definition store. SLO
//! *definitions* are tenant metadata kept in PostgreSQL; their live
//! *attainment* (current SLI / error budget / burn rate / status) is computed
//! from `otel_spans` by the search layer
//! ([`crate::search::SearchService::observability_slo_compute_with_coverage`]
//! + [`crate::query::slo_compute_sql`]). The SLO scheduler persists its latest
//! result ([`evaluation_state`], NAN-3894) and the list endpoint serves it
//! while fresh, falling back to a live compute when no scheduler is running.

pub mod eval;
pub mod evaluation_state;
pub mod metric_alert_lifecycle;
pub mod metric_monitor_repository;
pub mod slo_repository;
pub mod synthetic_check_repository;
pub mod synthetic_runner;

pub use metric_monitor_repository::{
    MetricMonitor, MetricMonitorRepository, MetricMonitorRepositoryError, MonitorComparator,
    MonitorTagFilter,
};
pub use slo_repository::{SloDefinition, SloRepository, SloRepositoryError, SloSliKind};
pub use synthetic_check_repository::{
    SyntheticCheck, SyntheticCheckRepository, SyntheticCheckRepositoryError,
    SYNTHETIC_CHECK_TYPES, SYNTHETIC_MAX_INTERVAL_SECS, SYNTHETIC_MIN_INTERVAL_SECS,
};
pub use synthetic_runner::SyntheticRunner;
