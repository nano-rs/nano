// SPDX-License-Identifier: AGPL-3.0-or-later

//! Migration tracking: recording applied migrations and seeding baselines.

use super::{ClickHouseMigrateError, ClickHouseMigrator, Migration};
use std::collections::HashSet;

impl ClickHouseMigrator {
    /// Ensure the _migrations table exists
    pub(super) async fn ensure_migrations_table(&self) -> Result<(), ClickHouseMigrateError> {
        // NAN-811: ensure the target database exists before any statement that
        // references it. Pre-NAN-810 the CH entrypoint pre-created the database
        // via `CLICKHOUSE_DB`; that path was always brittle (it ran the DDL as
        // the `default` user, whose profile sets allow_ddl=0 — see
        // clickhouse/users.d/query_limits.xml), and was removed in NAN-810. The
        // migrator now owns DB creation.
        //
        // `self.client` is constructed with `.with_database(&self.database)`,
        // which embeds `?database=<self.database>` into every request URL — CH
        // rejects the session with UNKNOWN_DATABASE before any statement runs
        // when that database doesn't exist yet. Clone the client and swap to
        // the always-present `default` database just for this one statement.
        // The CREATE DATABASE itself is idempotent and safe in all modes:
        // cloud already has a Replicated target DB (no-op); cluster mode
        // creates per-node, matching the per-node pattern we use for the
        // _migrations table itself below.
        let bootstrap_client = self.client.clone().with_database("default");
        bootstrap_client
            .query(&format!("CREATE DATABASE IF NOT EXISTS {}", self.database))
            .execute()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;

        // Pick the engine + ON CLUSTER form to match the deployment topology.
        // Three modes — same shape as `transform_for_cluster` post-NAN-1092:
        //   - CH Cloud OR self-hosted Replicated database (cluster == db name):
        //     Replicated engine manages zoo paths automatically. Empty args, no
        //     ON CLUSTER. Cloud rejects explicit args with BAD_ARGUMENTS (36),
        //     and the Replicated DB auto-propagates DDL so ON CLUSTER would be
        //     redundant. See NAN-1094.
        //   - Explicit operator-managed cluster (e.g. nanosiem_cluster from the
        //     CH operator): supply a CLUSTER-WIDE zoo path + replica macro + ON
        //     CLUSTER.
        //   - No cluster (single-node): plain MergeTree.
        //
        // NAN-1728 (C6/D1): the explicit-cluster zoo path OMITS the `{shard}`
        // macro. Migration state must be GLOBAL, not per-shard. With `{shard}` in
        // the path each shard was an independent replication group, so a migrator
        // connection that the LB pinned to shard 0 recorded state only there;
        // the next run landing on shard 1 saw an empty `_migrations` and
        // re-applied every migration (double-counting non-idempotent backfills),
        // while api/search pods on other shards failed `check_schema_up_to_date`
        // with `SchemaBehind`. Dropping `{shard}` makes every node across all
        // shards one replication group — a single, complete, globally-consistent
        // `_migrations`. Single-node and Replicated-DB/cloud paths are unchanged.
        let is_cloud = self.is_cloud.unwrap_or(false);
        let (on_cluster, engine) = match self.cluster.as_ref().and_then(|c| c.as_ref()) {
            Some(cluster) if is_cloud || cluster == &self.database => (
                String::new(),
                "ReplicatedMergeTree()".to_string(),
            ),
            Some(cluster) => {
                // No `{shard}` → one cluster-wide replication group.
                let zoo_path = format!("/clickhouse/tables/{}/_migrations", self.database);
                (
                    format!(" ON CLUSTER '{}'", cluster),
                    format!("ReplicatedMergeTree('{}', '{{replica}}')", zoo_path),
                )
            }
            None => (String::new(), "MergeTree".to_string()),
        };

        let sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}._migrations{}
            (
                `version` String,
                `name` String,
                `applied_at` DateTime64(6, 'UTC') DEFAULT now64(6),
                `checksum` String DEFAULT ''
            )
            ENGINE = {}
            ORDER BY (version)
            SETTINGS index_granularity = 8192
            "#,
            self.database, on_cluster, engine
        );

        self.client
            .query(&sql)
            .execute()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;

        Ok(())
    }

    /// Get list of already applied migration versions
    pub(super) async fn get_applied_migrations(
        &self,
    ) -> Result<HashSet<String>, ClickHouseMigrateError> {
        let sql = format!(
            "SELECT version FROM {}._migrations ORDER BY version",
            self.database
        );

        let rows: Vec<String> = self
            .client
            .query(&sql)
            .fetch_all()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;

        Ok(rows.into_iter().collect())
    }

    /// Get applied migrations with their stored content checksums.
    /// Empty checksums (default) come from rows seeded by `seed_baseline_migrations`
    /// or from migrations applied before NAN-607 added checksum tracking; callers
    /// should treat empty checksums as "skip content verification" since there's
    /// no recorded hash to compare against.
    pub(super) async fn get_applied_migration_checksums(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, ClickHouseMigrateError> {
        // `_migrations` is plain MergeTree with no unique constraint on version.
        // If concurrent applies (or a DELETE-then-reapply) leave duplicate rows,
        // use the latest one by `applied_at`. argMax handles both single-row and
        // duplicate-row cases correctly.
        let sql = format!(
            "SELECT version, argMax(checksum, applied_at) FROM {}._migrations GROUP BY version",
            self.database
        );

        let rows: Vec<(String, String)> = self
            .client
            .query(&sql)
            .fetch_all()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;

        Ok(rows.into_iter().collect())
    }

    /// Record a migration as applied. Stores a SHA-256 hash of the migration
    /// SQL content so `check_schema_up_to_date` can detect post-apply edits to
    /// migration files (which would otherwise pass the version-presence check
    /// while leaving the schema diverged from the file content).
    pub(super) async fn record_migration(
        &self,
        migration: &Migration,
    ) -> Result<(), ClickHouseMigrateError> {
        use sha2::{Digest, Sha256};
        let checksum = hex::encode(Sha256::digest(migration.sql.as_bytes()));

        let sql = format!(
            "INSERT INTO {}._migrations (version, name, checksum) VALUES ('{}', '{}', '{}')",
            self.database,
            crate::sql_hygiene::escape_sql_string(&migration.version),
            crate::sql_hygiene::escape_sql_string(&migration.name),
            checksum
        );

        self.client
            .query(&sql)
            .execute()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;

        Ok(())
    }

    /// All migration versions baked into init.sql.
    /// When init.sql creates a fresh schema, these are seeded into `_migrations`
    /// so the runner doesn't try to re-apply them.
    pub(super) const BASELINE_MIGRATIONS: &'static [(&'static str, &'static str)] = &[
        ("001", "init_clickhouse"),
        ("002", "rename_raw_content_to_message"),
        ("003", "add_enrich_time"),
        ("004", "add_source_column"),
        ("005", "ip_prevalence_table"),
        ("006", "ip_prevalence_mv"),
        ("007", "ioc_enrichment_columns"),
        ("008", "add_missing_enrichment_columns"),
        ("075", "create_identity_observations"),
        ("075a", "create_identity_mv"),
        ("075b", "create_nat_detection"),
        ("076", "add_identity_source_priority"),
        ("078", "full_text_search_index"),
        ("079", "add_namespace_column"),
        ("079a", "update_identity_mv_namespace"),
        ("080", "custom_enrichment_results"),
        ("081", "custom_enrichment_dictionary"),
        ("082", "add_process_guids"),
        ("083", "grant_dictionary_permissions"),
        ("084", "add_geo_enrichment_columns"),
        ("085", "add_sample_by_key"),
        ("086", "cim_alignment_and_indexes"),
        ("087", "add_query_projections"),
        ("088", "extend_identity_ttl"),
        ("089", "log_deduplication"),
        ("090", "entity_time_range_mv"),
        ("091", "restore_geo_enrichment_defaults"),
        ("092", "cloud_user_activity_mv"),
        ("093", "ipv6_enrichment_fix"),
        ("094", "storage_optimization"),
        ("095", "drop_message_search_column"),
        ("097", "user_registry_dictionary"),
        ("098", "identity_enrichment_columns"),
        ("103", "flexible_enrichment_columns"),
        // 104-108 baseline names match the original /migrations/clickhouse/
        // history applied to existing tenants by the pre-NAN-606 runner.
        // Seeding by version number is what the runner dedupes on, so the
        // exact name strings here are informational — they just need to be
        // recognizable in `_migrations` rows.
        ("104", "drop_log_hash_uuid_v7"),
        ("105", "remove_hardcoded_ttl"),
        ("106", "rename_process_to_command_line"),
        ("107", "logs_ttl_hard_cap"),
        ("108", "prevalence_min_inline_default"),
        // 109-112 are the post-108 migrations whose effects are now in
        // init.sql (109/110/111 already; 112 folded in for NAN-606). On
        // a fresh deploy init.sql creates the post-state, so we seed these
        // versions to stop the runner from re-applying their files.
        ("109", "drop_windowed_prevalence_dicts"),
        ("110", "prevalence_summary_tables"),
        ("111", "filter_internal_tlds_domain_prevalence"),
        ("112", "fix_prevalence_dict_layout"),
        ("168", "parser_health_5m"),
        ("169", "profile_aware_logs_per_source_5m"),
    ];

    /// Seed all baseline migration versions into `_migrations`.
    /// Called after init.sql on a fresh deployment so the runner won't re-apply them.
    pub(super) async fn seed_baseline_migrations(&self) -> Result<usize, ClickHouseMigrateError> {
        let applied = self.get_applied_migrations().await?;
        if !applied.is_empty() {
            tracing::debug!(
                "Migrations table already has {} entries, skipping baseline seed",
                applied.len()
            );
            return Ok(0);
        }

        let mut seeded = 0;
        for (version, name) in Self::BASELINE_MIGRATIONS {
            let sql = format!(
                "INSERT INTO {}._migrations (version, name) VALUES ('{}', '{}')",
                self.database,
                crate::sql_hygiene::escape_sql_string(version),
                crate::sql_hygiene::escape_sql_string(name)
            );
            self.client
                .query(&sql)
                .execute()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            seeded += 1;
        }

        tracing::info!("Seeded {} baseline migration records", seeded);
        Ok(seeded)
    }
}
