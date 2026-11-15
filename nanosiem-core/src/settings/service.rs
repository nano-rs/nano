// SPDX-License-Identifier: AGPL-3.0-or-later

//! System Settings Service
//!
//! Aggregates all system settings into a single service.

use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;

use super::retention::{
    read_clickhouse_retention_record, record_ui_clickhouse_retention,
    validate_clickhouse_retention_days, ClickHouseStorageService, ClickHouseStorageStats,
    RetentionConfig, RetentionError, RetentionService, StorageStats,
};

/// Aggregated system settings service
pub struct SystemSettings {
    retention: RetentionService,
}

impl SystemSettings {
    pub fn new(pool: PgPool) -> Self {
        Self {
            retention: RetentionService::new(pool),
        }
    }

    // Retention settings
    pub async fn get_retention_config(&self) -> Result<RetentionConfig, RetentionError> {
        self.retention.get_config().await
    }

    pub async fn update_retention_config(
        &self,
        config: RetentionConfig,
    ) -> Result<RetentionConfig, RetentionError> {
        self.retention.update_config(config).await
    }

    pub async fn get_storage_stats(&self) -> Result<StorageStats, RetentionError> {
        self.retention.get_storage_stats().await
    }

    pub async fn run_retention_now(&self) -> Result<i64, RetentionError> {
        self.retention.run_retention_now().await
    }
}

/// System settings service with ClickHouse support
pub struct DualSystemSettings {
    retention: RetentionService,
    clickhouse_storage: ClickHouseStorageService,
}

impl DualSystemSettings {
    pub fn new(pool: PgPool, clickhouse: ClickHouseClient) -> Self {
        Self {
            retention: RetentionService::new(pool),
            clickhouse_storage: ClickHouseStorageService::new(clickhouse),
        }
    }

    /// NAN-5367: admin client for cross-shard storage stats (REMOTE).
    pub fn with_fanout_client(mut self, client: Option<ClickHouseClient>) -> Self {
        self.clickhouse_storage = self.clickhouse_storage.with_fanout_client(client);
        self
    }

    // PostgreSQL retention settings (for metadata tables)
    pub async fn get_pg_retention_config(&self) -> Result<RetentionConfig, RetentionError> {
        self.retention.get_config().await
    }

    pub async fn update_pg_retention_config(
        &self,
        config: RetentionConfig,
    ) -> Result<RetentionConfig, RetentionError> {
        self.retention.update_config(config).await
    }

    pub async fn get_pg_storage_stats(&self) -> Result<StorageStats, RetentionError> {
        self.retention.get_storage_stats().await
    }

    pub async fn run_pg_retention_now(&self) -> Result<i64, RetentionError> {
        self.retention.run_retention_now().await
    }

    // ClickHouse storage settings (for log telemetry)
    pub async fn get_clickhouse_storage_stats(
        &self,
    ) -> Result<ClickHouseStorageStats, RetentionError> {
        let mut stats = self.clickhouse_storage.get_storage_stats().await?;
        // NAN-5449: who set the retention last. A PG read failure leaves the
        // fields empty rather than failing the ClickHouse stats.
        match read_clickhouse_retention_record(self.retention.pool()).await {
            Ok(record) => {
                stats.retention_source = record.source;
                stats.deployment_retention_days = record.env_applied;
            }
            Err(e) => tracing::warn!("Failed to read the retention record: {e}"),
        }
        Ok(stats)
    }

    /// Apply a retention set in Settings -> Storage (or the API) and record
    /// it, so the migrator does not overwrite it on a plain restart.
    pub async fn update_clickhouse_retention(&self, days: u32) -> Result<(), RetentionError> {
        let days = validate_clickhouse_retention_days(days)?;
        self.clickhouse_storage.update_retention(days).await?;
        record_ui_clickhouse_retention(self.retention.pool(), days).await
    }

    pub async fn run_clickhouse_retention_now(&self) -> Result<u64, RetentionError> {
        self.clickhouse_storage.run_retention_now().await
    }
}
