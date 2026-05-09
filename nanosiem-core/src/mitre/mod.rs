// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK Framework Module
//!
//! This module provides functionality to fetch, store, and query MITRE ATT&CK
//! tactics and techniques from the official MITRE CTI repository.

pub mod data_sources;
mod repository;
mod sync;
mod types;

pub use repository::MitreRepository;
pub use sync::MitreSync;
pub use types::{
    CoverageLevel, CoverageSummary, CoveringRule, DataSource, MitreCoverageResponse,
    MitreSyncMetadata, MitreTactic, MitreTechnique, TacticCoverage, TechniqueCoverage,
};
