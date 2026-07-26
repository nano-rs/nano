// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log telemetry rollup access (NAN-733).
//!
//! Reads from `nanosiem.logs_per_source_5m_v2`, a profile-aware
//! AggregatingMergeTree populated by separate UDM and OCSF materialized views.
//! Readers select the active profile and authorize against the preserved raw
//! scope key. Replaces the dozen+ ad-hoc raw-table scans used by source health,
//! feeds, system overview, meloD briefing, and feed staleness.
//!
//! Schema: see `clickhouse/169_profile_aware_logs_per_source_5m.sql`.

pub mod repository;
pub mod service;
pub mod types;

pub use repository::LogTelemetryRepository;
pub use service::{LogTelemetryError, LogTelemetryService};
pub use types::{BucketSize, HourlyPoint, SourceTypeStats};
