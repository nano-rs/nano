// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud and cluster environment detection for ClickHouse.

use super::{ClickHouseMigrateError, ClickHouseMigrator};

impl ClickHouseMigrator {
    /// Detect whether we're running against ClickHouse Cloud.
    /// CH Cloud restricts certain settings (storage_policy, experimental indexes).
    pub(super) async fn detect_cloud(&mut self) -> Result<bool, ClickHouseMigrateError> {
        if let Some(is_cloud) = self.is_cloud {
            return Ok(is_cloud);
        }

        // CH Cloud uses `cloud_mode` or restricts `storage_policy` changes.
        // The most reliable check: try to query the cloud_mode setting.
        let is_cloud = match self
            .client
            .query("SELECT value FROM system.settings WHERE name = 'cloud_mode'")
            .fetch_one::<String>()
            .await
        {
            Ok(val) => val == "1" || val == "true",
            // If cloud_mode setting doesn't exist, check for the display_name
            // which CH Cloud sets to the cluster name
            Err(_) => match self
                .client
                .query("SELECT value FROM system.settings WHERE name = 'display_name'")
                .fetch_one::<String>()
                .await
            {
                Ok(val) => !val.is_empty() && val != "clickhouse",
                Err(_) => false,
            },
        };

        if is_cloud {
            tracing::info!("Detected ClickHouse Cloud environment - will sanitize migration SQL");
        }
        self.is_cloud = Some(is_cloud);
        Ok(is_cloud)
    }

    /// Detect whether we're running against a ClickHouse cluster.
    /// Returns the cluster name if found (e.g., "nanosiem_cluster"), None for single-node.
    pub(super) async fn detect_cluster(
        &mut self,
    ) -> Result<Option<String>, ClickHouseMigrateError> {
        if let Some(ref cluster) = self.cluster {
            return Ok(cluster.clone());
        }

        // Look for a cluster with multiple shards in system.clusters.
        // The operator creates a 'default' cluster automatically.
        // Exclude built-in system clusters: '_all_databases' and 'system'.
        let cluster_name = self
            .client
            .query(
                "SELECT cluster FROM system.clusters \
                 WHERE cluster NOT IN ('_all_databases', 'system') \
                 GROUP BY cluster HAVING count() > 1 \
                 ORDER BY count() DESC LIMIT 1",
            )
            .fetch_one::<String>()
            .await
            .ok();

        if let Some(ref name) = cluster_name {
            tracing::info!(
                "Detected ClickHouse cluster '{}' - will transform DDL for replicated mode",
                name
            );
        }

        self.cluster = Some(cluster_name.clone());
        Ok(cluster_name)
    }
}
