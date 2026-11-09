// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Sources module
//!
//! Unified log source management combining ingestion configuration,
//! VRL transformation, and metadata into a single entity.

pub mod connect;
#[cfg(test)]
#[path = "connect_tests.rs"]
mod connect_tests;
pub mod health_series;
pub mod ingest_transport;
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
pub use service::{LogSourceService, LogSourceServiceError};
pub use tier_guard::{data_source_cap, enforce_data_source_limit, DataSourceCap};
pub use types::*;
pub use version_repository::{DiscardOutcome, LogSourceVersionError, LogSourceVersionRepository};
