// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log telemetry rollup access (NAN-733).
//!
//! Reads from `nanosiem.logs_per_source_5m`, an AggregatingMergeTree rollup
//! populated by a materialized view from `nanosiem.logs`. Replaces the dozen+
//! ad-hoc `FROM logs ... GROUP BY source_type` scans that previously hit the
//! raw logs table from source-configs, log-sources health, feeds, system
//! overview, meloD briefing, and the feed-staleness scheduler.
//!
//! Schema: see `clickhouse/116_logs_per_source_5m.sql`.

pub mod repository;
pub mod service;
pub mod types;

pub use repository::LogTelemetryRepository;
pub use service::{LogTelemetryError, LogTelemetryService};
pub use types::{BucketSize, HourlyPoint, SourceTypeStats};
