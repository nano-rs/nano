// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed table management for ClickHouse clusters.

use super::{ClickHouseMigrateError, ClickHouseMigrator};

impl ClickHouseMigrator {
    /// Tables that need Distributed wrappers for cross-shard queries.
    pub(super) const DISTRIBUTED_TABLES: &'static [&'static str] = &[
        "logs",
        "signals",
        "domain_prevalence_agg",
        "hash_prevalence_agg",
        "ip_prevalence_agg",
        "entity_time_range_agg",
        "cloud_user_activity_agg",
        "ingestion_errors",
        "custom_enrichment_results",
        "identity_observations",
        "logs_per_source_5m",
    ];

    /// ALIAS / MATERIALIZED columns that must be re-applied to Distributed
    /// wrappers after they've been added to the underlying local table.
    ///
    /// Distributed tables snapshot the column list of `source_table` at
    /// `CREATE TABLE ... AS source_table` time. Any column added to the local
    /// table afterwards (`ALTER TABLE source_table ADD COLUMN ...`) does NOT
    /// propagate. The wrapper has to be ALTERed independently or recreated.
    ///
    /// Format: `(table, column_name, column_definition_after_name)`.
    /// Example: ("logs", "event_type", "LowCardinality(String) ALIAS action").
    pub(super) const DISTRIBUTED_ALIASES: &'static [(&'static str, &'static str, &'static str)] = &[
        // NAN-700 / migration 113: event_type is a read alias for action.
        ("logs", "event_type", "LowCardinality(String) ALIAS action"),
    ];

    /// Create Distributed table wrappers for cross-shard queries.
    ///
    /// For each data table, creates `{table}_distributed` using Distributed engine.
    /// These tables route queries to all shards transparently.
    /// Only runs in cluster mode; no-op on single-node.
    pub async fn ensure_distributed_tables(&mut self) -> Result<usize, ClickHouseMigrateError> {
        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0), // Not a cluster, nothing to do
        };

        let mut created = 0;

        for table in Self::DISTRIBUTED_TABLES {
            let dist_name = format!("{}_distributed", table);

            // Check if distributed table already exists
            let exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, dist_name
                ))
                .fetch_one()
                .await
                .unwrap_or(0);

            if exists > 0 {
                continue;
            }

            // Check if source table exists
            let source_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, table
                ))
                .fetch_one()
                .await
                .unwrap_or(0);

            if source_exists == 0 {
                tracing::debug!(
                    "Source table {}.{} doesn't exist, skipping distributed table",
                    self.database,
                    table
                );
                continue;
            }

            let sql = format!(
                "CREATE TABLE IF NOT EXISTS {db}.{dist} ON CLUSTER '{cluster}' \
                 AS {db}.{table} \
                 ENGINE = Distributed('{cluster}', '{db}', '{table}', rand())",
                db = self.database,
                dist = dist_name,
                cluster = cluster_name,
                table = table,
            );

            match self.client.query(&sql).execute().await {
                Ok(_) => {
                    tracing::info!("Created distributed table {}.{}", self.database, dist_name);
                    created += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to create distributed table {}.{}: {}",
                        self.database,
                        dist_name,
                        e
                    );
                }
            }
        }

        if created > 0 {
            tracing::info!("Created {} distributed table(s)", created);
        }
        Ok(created)
    }

    /// Sync ALIAS / MATERIALIZED columns from local tables onto their existing
    /// Distributed wrappers (NAN-700).
    ///
    /// Distributed tables don't pick up `ALTER TABLE source ADD COLUMN`
    /// applied to their backing table — the wrapper's column list is fixed
    /// at create time. Without this step, a migration that adds an alias to
    /// `nanosiem.logs` (e.g. migration 113's `event_type ALIAS action`) leaves
    /// `nanosiem.logs_distributed` without that column, and any read query
    /// that references the alias fails with `UNKNOWN_IDENTIFIER` because the
    /// search service queries the wrapper in cluster mode.
    ///
    /// Idempotent — uses `ADD COLUMN IF NOT EXISTS` and pre-checks
    /// `system.columns`. No-op on single-node deployments (no cluster
    /// detected, hence no `_distributed` wrappers).
    pub async fn sync_distributed_aliases(&mut self) -> Result<usize, ClickHouseMigrateError> {
        // `self.database` is configured at migrator startup (CLICKHOUSE_DATABASE
        // env / config), trusted to the same degree as every other DDL string
        // we splice in this module. ClickHouse identifiers can't be supplied
        // via bind parameters, so callers must keep the value to a plain
        // identifier (alphanumeric + underscore).
        debug_assert!(
            is_safe_identifier(&self.database),
            "CLICKHOUSE_DATABASE must be a plain identifier, got: {}",
            self.database
        );

        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0),
        };

        // Replicated database (cluster_name == database) auto-propagates DDL
        // without an explicit ON CLUSTER clause — same convention as
        // `transform_for_cluster`. Explicit clusters (e.g. operator's
        // `nanosiem_cluster`) need the clause to fan the ALTER out.
        let on_cluster = if cluster_name == self.database {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        let mut applied = 0;
        for (table, col_name, col_def) in Self::DISTRIBUTED_ALIASES {
            let dist_name = format!("{}_distributed", table);

            let dist_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, dist_name
                ))
                .fetch_one()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            if dist_exists == 0 {
                continue;
            }

            // `"table"` is quoted because `table` is a SQL keyword shadowed by
            // the `system.columns.table` column; CH parses it as a column name
            // only when quoted.
            let col_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.columns WHERE database = '{}' AND \"table\" = '{}' AND name = '{}'",
                    self.database, dist_name, col_name
                ))
                .fetch_one()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            if col_exists > 0 {
                continue;
            }

            let sql = format!(
                "ALTER TABLE {db}.{dist}{on_cluster} ADD COLUMN IF NOT EXISTS {col} {def}",
                db = self.database,
                dist = dist_name,
                on_cluster = on_cluster,
                col = col_name,
                def = col_def,
            );

            match self.client.query(&sql).execute().await {
                Ok(_) => {
                    tracing::info!(
                        "Added alias column {} to {}.{}",
                        col_name,
                        self.database,
                        dist_name
                    );
                    applied += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to add alias column {} to {}.{}: {}",
                        col_name,
                        self.database,
                        dist_name,
                        e
                    );
                }
            }
        }

        if applied > 0 {
            tracing::info!(
                "Synced {} alias column(s) onto distributed wrappers",
                applied
            );
        }
        Ok(applied)
    }
}

/// True when `s` is a plain ClickHouse identifier (alphanumeric + `_`,
/// non-empty, doesn't start with a digit). Used as a debug-only sanity check
/// on the configured database name before splicing it into DDL.
pub(super) fn is_safe_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
