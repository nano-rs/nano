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
    ) -> Result<HashMap<String, SourceTypeStats>, LogTelemetryError> {
        Ok(self.repo.stats_by_source_type(source_types, window_hours).await?)
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
    ) -> Result<Vec<HourlyPoint>, LogTelemetryError> {
        Ok(self.repo.buckets(source_types, window_hours, bucket).await?)
    }

    /// Cluster-wide per-bucket totals (no source_type filter). Used by the
    /// dashboard activity timeline.
    pub async fn buckets_all(
        &self,
        window_hours: i64,
        bucket: BucketSize,
    ) -> Result<Vec<HourlyPoint>, LogTelemetryError> {
        Ok(self.repo.buckets_all(window_hours, bucket).await?)
    }

    /// Cluster-wide total event count for the window. Used by dashboard
    /// headline numbers.
    pub async fn total_events(&self, window_hours: i64) -> Result<i64, LogTelemetryError> {
        Ok(self.repo.total_events(window_hours).await?)
    }
}
