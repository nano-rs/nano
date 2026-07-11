// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK Framework Module
//!
//! This module provides functionality to fetch, store, and query MITRE ATT&CK
//! tactics and techniques from the official MITRE CTI repository.

pub mod data_sources;
pub(crate) mod mapping;
mod repository;
mod sync;
mod types;

pub use repository::MitreRepository;
pub use sync::{MitreSync, MitreSyncError, MitreSyncOutcome, MitreSyncResult};
pub use types::{
    CoverageLevel, CoverageSummary, CoverageUnit, CoveringRule, DataSource, DataSourceReadiness,
    MitreCoverageResponse, MitreSyncMetadata, MitreSyncState, MitreTactic, MitreTechnique,
    TacticCoverage, TechniqueCoverage, TelemetryReadinessSnapshot,
    TELEMETRY_READINESS_LOOKBACK_HOURS, TELEMETRY_STALE_AFTER_MINUTES,
};
