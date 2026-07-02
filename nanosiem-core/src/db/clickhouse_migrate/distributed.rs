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

    /// Converge each Distributed wrapper's column set to its backing local table
    /// (NAN-1652 drop half + NAN-1655 add half).
    ///
    /// Distributed wrappers snapshot the source column list at CREATE and don't
    /// track `ALTER TABLE source ADD/DROP COLUMN`. Search queries the wrapper in
    /// cluster mode, so any drift breaks reads with `UNKNOWN_IDENTIFIER`:
    /// - **Drop drift**: a column dropped from the source (e.g. migration 149's
    ///   flexible-enrichment cleanup) lingers on the wrapper; `SELECT *` expands
    ///   it and forwards it to shards that dropped it → every fetch-by-id /
    ///   row-expand `SELECT *, <materialized_cols>` 400s.
    /// - **Add drift**: a column added to the source after the wrapper snapshot
    ///   (e.g. `tags`, `trace_id`, the `process` alias) never reaches the
    ///   wrapper, so `SELECT tags FROM logs_distributed` / an nPL `tags=` filter
    ///   fails on the cluster.
    ///
    /// Both are invisible on single-node (no wrapper), so migrations that only
    /// ALTER the local table pass every test yet break clusters. This makes the
    /// wrapper converge on every migrate: ADD each source column the wrapper
    /// lacks (definition reconstructed from `system.columns`), then DROP each
    /// wrapper column the source no longer has. Idempotent (`ADD/DROP COLUMN IF
    /// [NOT] EXISTS`), no-op on single-node (no cluster detected), non-fatal per
    /// column. This subsumes the hardcoded `DISTRIBUTED_ALIASES` add.
    pub async fn reconcile_distributed_columns(&mut self) -> Result<usize, ClickHouseMigrateError> {
        debug_assert!(
            is_safe_identifier(&self.database),
            "CLICKHOUSE_DATABASE must be a plain identifier, got: {}",
            self.database
        );

        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0),
        };

        // Same ON CLUSTER convention as sync_distributed_aliases: a Replicated
        // database (cluster == db) auto-propagates DDL, explicit clusters need
        // the clause to fan the ALTER out to every node's wrapper.
        let on_cluster = if cluster_name == self.database {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        let mut changed = 0;
        for table in Self::DISTRIBUTED_TABLES {
            let dist_name = format!("{}_distributed", table);

            // Wrapper must exist (created by ensure_distributed_tables in
            // cluster mode). `"table"` is quoted because it shadows the
            // system.columns.table column otherwise.
            let dist_cols: Vec<String> = self
                .client
                .query(&format!(
                    "SELECT name FROM system.columns WHERE database = '{}' AND \"table\" = '{}'",
                    self.database, dist_name
                ))
                .fetch_all::<String>()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            if dist_cols.is_empty() {
                continue;
            }

            // Full source specs so a missing column can be re-added with its
            // exact definition (type + DEFAULT/MATERIALIZED/ALIAS expression).
            let source_specs: Vec<(String, String, String, String)> = self
                .client
                .query(&format!(
                    "SELECT name, type, default_kind, default_expression \
                     FROM system.columns WHERE database = '{}' AND \"table\" = '{}'",
                    self.database, table
                ))
                .fetch_all()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            // A missing/empty source is not a signal to touch the wrapper —
            // skip rather than strip every column.
            if source_specs.is_empty() {
                continue;
            }

            // ADD source columns the wrapper lacks. ALIAS columns are ordered
            // last so their referenced base columns are already present.
            for (name, typ, kind, expr) in columns_to_add(&dist_cols, &source_specs) {
                // Names are spliced into DDL — keep the module's identifier
                // guard. (`type`/`default_expression` come from ClickHouse's own
                // catalog for our schema, spliced verbatim like the hardcoded
                // `DISTRIBUTED_ALIASES` definitions.)
                if !is_safe_identifier(name) {
                    tracing::warn!(
                        "Skipping reconcile add of non-identifier column {:?} on {}.{}",
                        name,
                        self.database,
                        dist_name
                    );
                    continue;
                }
                let clause = build_add_column_clause(name, typ, kind, expr);
                let sql = format!(
                    "ALTER TABLE {db}.{dist}{on_cluster} ADD COLUMN IF NOT EXISTS {clause}",
                    db = self.database,
                    dist = dist_name,
                    on_cluster = on_cluster,
                    clause = clause,
                );
                match self.client.query(&sql).execute().await {
                    Ok(_) => {
                        tracing::info!(
                            "Added missing column {} to {}.{} (present on source {})",
                            name,
                            self.database,
                            dist_name,
                            table
                        );
                        changed += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to add column {} to {}.{}: {}",
                            name,
                            self.database,
                            dist_name,
                            e
                        );
                    }
                }
            }

            // DROP wrapper columns the source no longer has.
            let source_names: Vec<String> =
                source_specs.iter().map(|(n, ..)| n.clone()).collect();
            for col in stale_wrapper_columns(&dist_cols, &source_names) {
                if !is_safe_identifier(&col) {
                    tracing::warn!(
                        "Skipping reconcile drop of non-identifier column {:?} on {}.{}",
                        col,
                        self.database,
                        dist_name
                    );
                    continue;
                }

                let sql = format!(
                    "ALTER TABLE {db}.{dist}{on_cluster} DROP COLUMN IF EXISTS {col}",
                    db = self.database,
                    dist = dist_name,
                    on_cluster = on_cluster,
                    col = col,
                );

                match self.client.query(&sql).execute().await {
                    Ok(_) => {
                        tracing::info!(
                            "Dropped stale column {} from {}.{} (absent on source {})",
                            col,
                            self.database,
                            dist_name,
                            table
                        );
                        changed += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to drop stale column {} from {}.{}: {}",
                            col,
                            self.database,
                            dist_name,
                            e
                        );
                    }
                }
            }
        }

        if changed > 0 {
            tracing::info!(
                "Reconciled {} column(s) on distributed wrappers",
                changed
            );
        }
        Ok(changed)
    }
}

/// Columns present on the Distributed wrapper but absent from its source table.
/// These are stale (the source dropped them) and must be dropped from the
/// wrapper so `SELECT *` doesn't forward a non-existent column to the shards.
///
/// Split out from [`ClickHouseMigrator::reconcile_distributed_columns`] so the
/// set difference is unit-testable without a live cluster.
pub(super) fn stale_wrapper_columns(wrapper: &[String], source: &[String]) -> Vec<String> {
    let source_set: std::collections::HashSet<&str> =
        source.iter().map(String::as_str).collect();
    wrapper
        .iter()
        .filter(|c| !source_set.contains(c.as_str()))
        .cloned()
        .collect()
}

/// Source columns (as `(name, type, default_kind, default_expression)` specs
/// from `system.columns`) that the wrapper is missing and must gain. ALIAS
/// columns are ordered LAST so the base columns they reference are added first.
///
/// Split out so the selection + ordering is unit-testable without a cluster.
pub(super) fn columns_to_add<'a>(
    wrapper: &[String],
    source_specs: &'a [(String, String, String, String)],
) -> Vec<(&'a String, &'a String, &'a String, &'a String)> {
    let wrapper_set: std::collections::HashSet<&str> =
        wrapper.iter().map(String::as_str).collect();
    let mut missing: Vec<_> = source_specs
        .iter()
        .filter(|(name, ..)| !wrapper_set.contains(name.as_str()))
        .map(|(n, t, k, e)| (n, t, k, e))
        .collect();
    // Stable partition: non-ALIAS first, ALIAS last (they reference other cols).
    missing.sort_by_key(|(_, _, kind, _)| kind.as_str() == "ALIAS");
    missing
}

/// Build the `ADD COLUMN` clause body (`name type [DEFAULT|MATERIALIZED|ALIAS
/// expr]`) from a `system.columns` spec. `default_kind` is `''` for a plain
/// column, else `DEFAULT` / `MATERIALIZED` / `ALIAS`.
pub(super) fn build_add_column_clause(
    name: &str,
    typ: &str,
    default_kind: &str,
    default_expr: &str,
) -> String {
    match default_kind {
        "DEFAULT" => format!("{name} {typ} DEFAULT {default_expr}"),
        "MATERIALIZED" => format!("{name} {typ} MATERIALIZED {default_expr}"),
        "ALIAS" => format!("{name} {typ} ALIAS {default_expr}"),
        _ => format!("{name} {typ}"),
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
