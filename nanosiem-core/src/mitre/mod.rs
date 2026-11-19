// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK Framework Module
//!
//! This module provides functionality to fetch, store, and query MITRE ATT&CK
//! tactics and techniques from the official MITRE CTI repository.

pub mod attack_names;
pub mod data_sources;
pub(crate) mod mapping;
pub use mapping::{
    effective_mitre_mapping, mitre_mapping_unchanged, validate_mitre_mapping_for_write,
};
mod repository;
mod stix_stream;
mod sync;
mod types;

pub use repository::MitreRepository;
pub use stix_stream::{decode_filtered_bundle, FilteredBundle};
pub use sync::{MitreCatalog, MitreSync, MITRE_CONTENT_PATH, MitreSyncError, MitreSyncOutcome, MitreSyncResult};
pub use types::{
    CoverageLevel, CoverageSummary, CoverageUnit, CoveringRule, DataSource, DataSourceReadiness,
    MitreCoverageResponse, MitreQuarantinedMapping, MitreReconcileOutcome, MitreSyncMetadata,
    MitreSyncState, MitreTactic, MitreTechnique, MitreTechniqueAlias, StixBundle, StixObject,
    TacticCoverage, TechniqueCoverage, TelemetryReadinessSnapshot,
    TELEMETRY_READINESS_LOOKBACK_HOURS, TELEMETRY_STALE_AFTER_MINUTES,
};
