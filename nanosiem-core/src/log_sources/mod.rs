// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Sources module
//!
//! Unified log source management combining ingestion configuration,
//! VRL transformation, and metadata into a single entity.

mod lake_diagnostics;
pub(crate) mod repository;
pub(crate) mod service;
mod tier_guard;
mod types;
mod version_repository;

pub use lake_diagnostics::{
    LakeCollectorDiagnostics, LakeCollectorDiagnosticsClient, LakeCollectorDiagnosticsError,
};
pub use repository::collector_error_hint;
pub use repository::{LogSourceRepository, LogSourceRepositoryError};
pub use service::{LogSourceService, LogSourceServiceError};
pub use tier_guard::{data_source_cap, enforce_data_source_limit, DataSourceCap};
pub use types::*;
pub use version_repository::{LogSourceVersionError, LogSourceVersionRepository};

/// Canonical parser identities for source telemetry and visibility.
pub fn source_labels(source: &LogSource) -> Vec<String> {
    source_labels_for(source.match_values.as_deref(), &source.source_type)
}

/// [`source_labels`] over the two columns it reads, for callers that select
/// only those columns (the NAN-3196 feed-staleness monitor).
pub fn source_labels_for(match_values: Option<&[String]>, source_type: &str) -> Vec<String> {
    let mut labels: Vec<String> = match_values
        .unwrap_or_default()
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    let transport = source_type.trim().to_ascii_lowercase();
    if labels.is_empty() && transport != "routed" && !transport.is_empty() {
        labels.push(transport);
    }
    labels.sort_unstable();
    labels.dedup();
    labels
}
