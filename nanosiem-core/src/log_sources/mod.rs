// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Sources module
//!
//! Unified log source management combining ingestion configuration,
//! VRL transformation, and metadata into a single entity.

pub mod activation;
pub mod cadence;
pub mod change_batch;
#[cfg(test)]
#[path = "cadence_tests.rs"]
mod cadence_tests;
pub mod connect;
pub mod deploy_jobs;
pub mod feed_lane_setup;
#[cfg(test)]
#[path = "connect_tests.rs"]
mod connect_tests;
#[cfg(test)]
#[path = "connect_removed_tests.rs"]
mod connect_removed_tests;
pub mod health_series;
pub mod ingest_transport;
pub mod source_binding;
#[cfg(test)]
#[path = "health_series_tests.rs"]
mod health_series_tests;
mod repository;
mod service;
mod tier_guard;
mod types;
mod version_repository;

pub use repository::{LogSourceRepository, LogSourceRepositoryError};
pub use service::pipe::{pipe_route_key, pipe_tap_component, MAX_PIPE_SAMPLES};
pub use service::{
    DeletedLogSource, LogSourceService, LogSourceServiceError, OcsfGateInput, OcsfGateOutcome, OcsfPrecheck,
};
pub use service::ocsf_attestation::run_ocsf_samples;
pub use tier_guard::{data_source_cap, enforce_data_source_limit, DataSourceCap};
pub use types::*;
pub use version_repository::{DiscardOutcome, LogSourceVersionError, LogSourceVersionRepository};
