// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log telemetry service — thin wrapper over `LogTelemetryRepository`.
//!
//! Exists so handlers depend on a service trait surface (matching the
//! `PrevalenceService` / `LogSourceService` pattern) rather than reaching
//! directly into the repo.

use clickhouse::Client as ClickHouseClient;
use std::collections::HashMap;

use super::repository::{LogTelemetryRepository, RepoError};
use super::types::{BucketSize, HourlyPoint, SourceTypeStats};
use crate::db::TableNames;

#[derive(Debug, thiserror::Error)]
pub enum LogTelemetryError {
    #[error("Log telemetry repository error: {0}")]
    Repo(#[from] RepoError),
}

#[derive(Clone)]
pub struct LogTelemetryService {
    repo: LogTelemetryRepository,
}

impl LogTelemetryService {
    pub fn new(client: ClickHouseClient, table_names: TableNames) -> Self {
        Self {
            repo: LogTelemetryRepository::new(client, table_names),
        }
    }

    /// Returns rollup stats for each requested source_type, summed over the
    /// last `window_hours` hours.
    pub async fn stats_by_source_type(
        &self,
        source_types: &[String],
        window_hours: i64,
        deny_set: &std::collections::BTreeSet<String>,
    ) -> Result<HashMap<String, SourceTypeStats>, LogTelemetryError> {
        Ok(self
            .repo
            .stats_by_source_type(source_types, window_hours, deny_set)
            .await?)
    }

    pub async fn stats_all(
        &self,
        window_hours: i64,
    ) -> Result<HashMap<String, SourceTypeStats>, LogTelemetryError> {
        Ok(self.repo.stats_all(window_hours).await?)
    }

    pub async fn buckets(
        &self,
        source_types: &[String],
        window_hours: i64,
        bucket: BucketSize,
        deny_set: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<HourlyPoint>, LogTelemetryError> {
        Ok(self
            .repo
            .buckets(source_types, window_hours, bucket, deny_set)
            .await?)
    }

    /// Per-bucket totals summed across every source the caller may see. Used by
    /// the dashboard activity timeline.
    ///
    /// NAN-2060: `deny_set` is the caller's effective source deny-set; empty
    /// means unrestricted and keeps the cluster-wide total exact.
    pub async fn buckets_all(
        &self,
        window_hours: i64,
        bucket: BucketSize,
        deny_set: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<HourlyPoint>, LogTelemetryError> {
        Ok(self.repo.buckets_all(window_hours, bucket, deny_set).await?)
    }

    /// Total event count for the window across every source the caller may see.
    /// Used by dashboard headline numbers.
    pub async fn total_events(
        &self,
        window_hours: i64,
        deny_set: &std::collections::BTreeSet<String>,
    ) -> Result<i64, LogTelemetryError> {
        Ok(self.repo.total_events(window_hours, deny_set).await?)
    }

    /// Scoped event total over an explicit `[start, end)` range (NAN-2060) —
    /// the previous-period comparison window the dashboard tiles need.
    pub async fn total_events_range(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        deny_set: &std::collections::BTreeSet<String>,
    ) -> Result<i64, LogTelemetryError> {
        Ok(self.repo.total_events_range(start, end, deny_set).await?)
    }
}
