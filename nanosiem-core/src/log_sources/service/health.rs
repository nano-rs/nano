// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health metrics operations for log sources

use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    HistoryPoint, IngestionHistoryPoint, LogSourceHealth, LogSourceHealthSummary,
};

impl LogSourceService {
    /// Get health metrics for a log source
    pub async fn get_health(&self, id: Uuid) -> Result<LogSourceHealth, LogSourceServiceError> {
        Ok(self.repository().get_health(id).await?)
    }

    /// Get health summary for every log source.
    ///
    /// Returns `(log_source_id, summary)` tuples. When ClickHouse is
    /// unavailable, totals are reported as 0 with a degraded health status.
    pub async fn get_all_health_summary(
        &self,
    ) -> Result<Vec<(Uuid, LogSourceHealthSummary)>, LogSourceServiceError> {
        Ok(self.repository().get_all_health_summary().await?)
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

    /// Get ingestion history for all log sources (for area chart)
    pub async fn get_all_ingestion_history(
        &self,
        hours: Option<i64>,
    ) -> Result<Vec<IngestionHistoryPoint>, LogSourceServiceError> {
        Ok(self
            .repository()
            .get_all_ingestion_history(hours.unwrap_or(24))
            .await?)
    }
}
