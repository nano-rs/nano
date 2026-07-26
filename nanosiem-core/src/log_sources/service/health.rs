// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health metrics operations for log sources

use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::auth::ScopeSet;
use crate::log_sources::types::{
    HistoryPoint, IngestionHistoryPoint, LogSourceHealth, LogSourceHealthSummary,
};

impl LogSourceService {
    /// Get health metrics for a log source.
    ///
    /// NAN-2059: `scope` is the CALLER's effective source deny-set. Log-source
    /// telemetry is derived from the logs table, so it is subject to the same
    /// per-source boundary as search — otherwise a principal denied a feed
    /// still recovers its exact volume, first/last-seen, byte totals and
    /// operating pattern. Pass [`ScopeSet::unrestricted`] for SYSTEM callers.
    pub async fn get_health(
        &self,
        id: Uuid,
        scope: &ScopeSet,
    ) -> Result<LogSourceHealth, LogSourceServiceError> {
        Ok(self.repository().get_health(id, scope).await?)
    }

    /// Get health summary for every log source.
    ///
    /// Returns `(log_source_id, summary)` tuples. When ClickHouse is
    /// unavailable, totals are reported as 0 with a degraded health status.
    /// `scope` carries the same per-source boundary as [`Self::get_health`].
    pub async fn get_all_health_summary(
        &self,
        scope: &ScopeSet,
    ) -> Result<Vec<(Uuid, LogSourceHealthSummary)>, LogSourceServiceError> {
        Ok(self.repository().get_all_health_summary(scope).await?)
    }

    /// Get ingestion history for charting
    pub async fn get_ingestion_history(
        &self,
        id: Uuid,
        hours: Option<i64>,
    ) -> Result<Vec<HistoryPoint>, LogSourceServiceError> {
        Ok(self
            .repository()
            .get_ingestion_history(id, hours.unwrap_or(24))
            .await?)
    }

    /// Get ingestion history for all log sources (for area chart).
    ///
    /// NAN-2059: denied source types are excluded from the series.
    pub async fn get_all_ingestion_history(
        &self,
        hours: Option<i64>,
        scope: &ScopeSet,
    ) -> Result<Vec<IngestionHistoryPoint>, LogSourceServiceError> {
        Ok(self
            .repository()
            .get_all_ingestion_history(hours.unwrap_or(24), scope)
            .await?)
    }
}
