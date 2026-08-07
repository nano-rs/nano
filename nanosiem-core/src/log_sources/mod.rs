// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Sources module
//!
//! Unified log source management combining ingestion configuration,
//! VRL transformation, and metadata into a single entity.

mod repository;
mod service;
mod tier_guard;
mod types;
mod version_repository;

pub use repository::{LogSourceRepository, LogSourceRepositoryError};
pub use service::{LogSourceService, LogSourceServiceError};
pub use tier_guard::{data_source_cap, enforce_data_source_limit, DataSourceCap};
pub use types::*;
pub use version_repository::{LogSourceVersionError, LogSourceVersionRepository};
