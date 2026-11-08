// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud and cluster environment detection for ClickHouse.

use super::{ClickHouseMigrateError, ClickHouseMigrator};

const CLUSTER_DETECTION_SQL: &str = "SELECT cluster FROM system.clusters \
     WHERE cluster NOT IN ('_all_databases', 'system') \
     GROUP BY cluster HAVING count() > 1 \
     ORDER BY count() DESC, cluster ASC LIMIT 1";

/// Resolve the explicit operator cluster or probe the same deterministic
/// `system.clusters` candidate used by the migrator. Runtime repair code calls
/// this only after observing a Distributed wrapper and fails closed when the
/// result is absent or the probe cannot be executed.
pub(crate) async fn configured_or_detected_cluster(
    client: &clickhouse::Client,
) -> Result<Option<String>, clickhouse::error::Error> {
    if let Ok(env_cluster) = std::env::var("CLICKHOUSE_CLUSTER") {
        let trimmed = env_cluster.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    let rows = client
        .query(CLUSTER_DETECTION_SQL)
        .fetch_all::<String>()
        .await?;
    Ok(rows.into_iter().next())
}

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

    /// Detect the server's `(major, minor)` version (NAN-4906), cached.
    ///
    /// Used to drop DDL settings that only exist on newer servers (see
    /// `strip_settings_unsupported_by`). A failed probe or an unparsable
    /// version yields `None`, which callers treat as a current server: every
    /// pinned deployment runs the current release, so the SQL stays untouched.
    pub(super) async fn detect_server_version(&mut self) -> Option<(u32, u32)> {
        if let Some(v) = self.server_version {
            return v;
        }
        let v = match self.client.query("SELECT version()").fetch_one::<String>().await {
            Ok(raw) => Self::parse_server_version(&raw),
            Err(e) => {
                tracing::warn!("Could not read ClickHouse version(): {e}; assuming a current server");
                None
            }
        };
        self.server_version = Some(v);
        v
    }

    /// Parse `"26.10.3.7"` (or `"26.4.5.143 (official build)"`) into `(26, 10)`.
    pub(super) fn parse_server_version(raw: &str) -> Option<(u32, u32)> {
        let mut parts = raw.trim().split(|c: char| c == '.' || c.is_whitespace());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some((major, minor))
    }

    /// Detect whether we're running against a ClickHouse cluster.
    /// Returns the cluster name if found (e.g., "nanosiem_cluster"), None for single-node.
    pub(super) async fn detect_cluster(
        &mut self,
    ) -> Result<Option<String>, ClickHouseMigrateError> {
        if let Some(ref cluster) = self.cluster {
            return Ok(cluster.clone());
        }

        // NAN-1728 (M-8/D10): prefer the explicit `CLICKHOUSE_CLUSTER` env var
        // when the deploy sets it. The deploy sets it only on clustered
        // ClickHouse and knows the operator's authoritative cluster name, so this
        // avoids the ambiguity of auto-detecting between e.g. an operator's
        // `nanosiem_cluster` and an auto-created `default`. Empty/whitespace is
        // treated as unset (open-core / single-node), falling through to probing.
        // Look for a configured cluster first, then a cluster with multiple
        // shards in system.clusters.
        // The operator creates a 'default' cluster automatically.
        // Exclude built-in system clusters: '_all_databases' and 'system'.
        //
        // The `cluster ASC` secondary sort is a deterministic tiebreak: without
        // it, two clusters with the same node count (e.g. an operator
        // `nanosiem_cluster` and an auto `default`) would be picked
        // nondeterministically across runs, so a migrator could target a
        // different cluster each time (M-8/D10).
        let cluster_name = configured_or_detected_cluster(&self.client)
            .await
            .ok()
            .flatten();

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
