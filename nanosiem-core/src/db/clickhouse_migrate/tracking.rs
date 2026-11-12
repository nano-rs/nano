// SPDX-License-Identifier: AGPL-3.0-or-later

//! Migration tracking: recording applied migrations and seeding baselines.

use super::{ClickHouseMigrateError, ClickHouseMigrator, Migration};
use std::collections::HashSet;
use std::time::Duration;

const DATABASE_BOOTSTRAP_VISIBILITY_TIMEOUT: Duration = Duration::from_secs(60);
const DATABASE_BOOTSTRAP_VISIBILITY_POLL: Duration = Duration::from_millis(250);
const DATABASE_BOOTSTRAP_DDL_OUTPUT_MODE: &str = "throw";

/// Every table `ensure_migrations_table` creates. The NAN-5215 skip check
/// requires all of them on every reachable replica.
const TRACKING_TABLES: &[&str] = &[
    "_migrations",
    crate::db::migration_refresh::MIGRATION_REFRESH_TABLE,
    crate::db::future_timestamp_repair::FUTURE_REPAIR_SET_TABLE,
    crate::db::future_timestamp_repair::FUTURE_IP_REPAIR_ROWS_TABLE,
];

#[derive(clickhouse::Row, serde::Deserialize)]
struct DatabaseBootstrapVisibility {
    visible_nodes: u64,
    /// Nodes that answered the `clusterAllReplicas` read (NAN-5255): tells
    /// "a replica is down" apart from "every replica answers but the
    /// database is missing on some".
    answering_nodes: u64,
    expected_nodes: Option<u64>,
}

/// NAN-5255: operator-facing summary of one visibility observation. Never
/// blames an unreachable replica when every configured replica answered.
fn describe_visibility(visible: u64, answering: u64, expected: Option<u64>) -> String {
    match expected {
        None => format!(
            "database visible on {visible} of {answering} answering nodes; cluster size unavailable"
        ),
        Some(expected) if answering < expected => format!(
            "database visible on {visible}/{expected} nodes; only {answering}/{expected} \
             configured replicas answer"
        ),
        Some(expected) => format!(
            "database visible on {visible}/{expected} nodes although all {answering} configured \
             replicas answer (CREATE DATABASE ON CLUSTER has not reached every replica: check \
             system.distributed_ddl_queue)"
        ),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineMigration {
    version: String,
    name: String,
}

const BASELINE_MIGRATIONS_JSON: &str =
    include_str!("../../../../clickhouse/baseline_migrations.json");

impl ClickHouseMigrator {
    pub(super) fn database_bootstrap_sql(&self) -> String {
        let is_cloud = self.is_cloud.unwrap_or(false);
        match self.cluster.as_ref().and_then(|cluster| cluster.as_ref()) {
            Some(cluster) if !is_cloud && cluster != &self.database => format!(
                "CREATE DATABASE IF NOT EXISTS {} ON CLUSTER '{}'",
                self.database, cluster
            ),
            _ => format!("CREATE DATABASE IF NOT EXISTS {}", self.database),
        }
    }

    pub(super) fn database_bootstrap_visibility_sql(&self) -> Option<String> {
        let is_cloud = self.is_cloud.unwrap_or(false);
        let cluster = self.cluster.as_ref().and_then(|cluster| cluster.as_ref())?;
        if is_cloud || cluster == &self.database {
            return None;
        }

        let database = crate::sql_hygiene::escape_sql_string(&self.database);
        let cluster = crate::sql_hygiene::escape_sql_string(cluster);
        // NAN-5255: count only the remote_servers rows. The operator's
        // Replicated `default` database registers a second `default` cluster
        // in system.clusters that clusterAllReplicas never reaches.
        let rows = super::cluster_reachability::server_cluster_rows_predicate(&format!("'{cluster}'"));
        Some(format!(
            "SELECT countIf(name = '{database}') AS visible_nodes, \
             uniqExact(shardNum()) AS answering_nodes, \
             (SELECT count() FROM system.clusters WHERE {rows}) AS expected_nodes \
             FROM clusterAllReplicas('{cluster}', system.databases)"
        ))
    }

    async fn wait_for_database_bootstrap_visibility(
        &self,
        bootstrap_client: &clickhouse::Client,
    ) -> Result<(), ClickHouseMigrateError> {
        let Some(sql) = self.database_bootstrap_visibility_sql() else {
            return Ok(());
        };

        let deadline = tokio::time::Instant::now() + DATABASE_BOOTSTRAP_VISIBILITY_TIMEOUT;
        loop {
            let last_observation =
                match bootstrap_client
                    .query(&sql)
                    .fetch_one::<DatabaseBootstrapVisibility>()
                    .await
                {
                    Ok(DatabaseBootstrapVisibility {
                        visible_nodes,
                        expected_nodes: Some(expected_nodes),
                        ..
                    }) if expected_nodes > 0 && visible_nodes == expected_nodes =>
                    {
                        return Ok(());
                    }
                    Ok(DatabaseBootstrapVisibility {
                        visible_nodes,
                        answering_nodes,
                        expected_nodes,
                    }) => describe_visibility(visible_nodes, answering_nodes, expected_nodes),
                    Err(error) => format!("cluster visibility query failed: {error}"),
                };

            if tokio::time::Instant::now() >= deadline {
                return Err(ClickHouseMigrateError::ClickHouse(format!(
                    "timed out waiting for database {} after ON CLUSTER bootstrap: {}",
                    self.database, last_observation
                )));
            }
            tokio::time::sleep(DATABASE_BOOTSTRAP_VISIBILITY_POLL).await;
        }
    }

    /// Execute one tracking-table DDL statement; a failure names the
    /// unreachable replicas when ON CLUSTER could not finish (NAN-5215).
    async fn execute_tracking_ddl(&self, sql: &str) -> Result<(), ClickHouseMigrateError> {
        match self.client.query(sql).execute().await {
            Ok(()) => Ok(()),
            Err(error) => Err(self
                .with_unreachable_replicas(ClickHouseMigrateError::ClickHouse(error.to_string()))
                .await),
        }
    }

    /// NAN-5215: the "nothing to ensure" check for an explicit cluster. True
    /// only when the database and every tracking table exist (and the
    /// repair-row buffer no longer carries its retired TTL) on EVERY replica
    /// that answers, with at least the connected one answering. Any probe
    /// error, a missing object, or a non-cluster topology returns false so
    /// the caller runs the unchanged bootstrap path.
    async fn tracking_tables_present_on_reachable_replicas(
        &self,
        bootstrap_client: &clickhouse::Client,
    ) -> bool {
        let Some(cluster) = self.explicit_cluster_name() else {
            return false;
        };
        let reachability = match Self::probe_reachability(bootstrap_client, cluster).await {
            Ok(reachability) => reachability,
            Err(error) => {
                tracing::debug!("NAN-5215: replica reachability probe failed: {error}");
                return false;
            }
        };
        let present: u64 = match bootstrap_client
            .query(&self.tracking_tables_presence_sql(cluster))
            .fetch_one()
            .await
        {
            Ok(present) => present,
            Err(error) => {
                tracing::debug!("NAN-5215: tracking-table presence probe failed: {error}");
                return false;
            }
        };
        if !super::cluster_reachability::present_on_every_reachable_replica(
            reachability.reachable_count(),
            TRACKING_TABLES.len() as u64,
            present,
        ) {
            return false;
        }
        if reachability.all_reachable() {
            tracing::debug!(
                "Tracking tables present on every replica of '{cluster}'; skipping ON CLUSTER ensure"
            );
        } else {
            tracing::warn!(
                "NAN-5215: tracking tables present on every reachable replica of '{cluster}' \
                 ({}); skipping ON CLUSTER ensure. The missing replica catches up from the \
                 DDL queue when it returns.",
                reachability.describe()
            );
        }
        true
    }

    /// Count of tracking tables across the reachable replicas of `cluster`.
    /// The repair-row buffer counts only once its retired TTL is gone, so a
    /// pending `REMOVE TTL` still takes the full path.
    pub(super) fn tracking_tables_presence_sql(&self, cluster: &str) -> String {
        let cluster = crate::sql_hygiene::escape_sql_string(cluster);
        let database = crate::sql_hygiene::escape_sql_string(&self.database);
        let names = TRACKING_TABLES
            .iter()
            .map(|name| format!("'{}'", crate::sql_hygiene::escape_sql_string(name)))
            .collect::<Vec<_>>()
            .join(", ");
        let ip_rows = crate::sql_hygiene::escape_sql_string(
            crate::db::future_timestamp_repair::FUTURE_IP_REPAIR_ROWS_TABLE,
        );
        format!(
            "SELECT count() FROM clusterAllReplicas('{cluster}', system.tables) \
             WHERE database = '{database}' AND name IN ({names}) \
             AND NOT (name = '{ip_rows}' AND position(create_table_query, 'TTL') > 0) \
             SETTINGS skip_unavailable_shards = 1"
        )
    }

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
        // The CREATE DATABASE itself is idempotent and safe in all modes.
        // Explicit operator clusters require ON CLUSTER so the very first
        // `_migrations` DDL can address the database on every blank shard.
        // Cloud/Replicated-database and implicit/single-node modes deliberately
        // retain the exact historical statement without an ON CLUSTER clause.
        // This is the ordering barrier for every later cluster DDL statement.
        // Never inherit an asynchronous/none output mode from a deployment
        // profile: that lets CREATE TABLE reach another blank shard before its
        // CREATE DATABASE task has executed there. `throw` waits for every
        // active host and propagates a remote failure instead of publishing a
        // partially bootstrapped cluster.
        let bootstrap_client = self
            .client
            .clone()
            .with_database("default")
            .with_option(
                "distributed_ddl_output_mode",
                DATABASE_BOOTSTRAP_DDL_OUTPUT_MODE,
            );

        // NAN-5215: on an already-bootstrapped explicit cluster this whole
        // function is a no-op, and its ON CLUSTER statements wait for EVERY
        // replica. Skip them when every reachable replica already holds the
        // database and all tracking tables, so one hard-down replica cannot
        // block the migrator (and the app tier gated on it). The returning
        // replica replays anything it missed from the Keeper DDL queue. A
        // blank or partially bootstrapped cluster falls through to the
        // unchanged all-node path below.
        if self
            .tracking_tables_present_on_reachable_replicas(&bootstrap_client)
            .await
        {
            return Ok(());
        }

        if let Err(error) = bootstrap_client
            .query(&self.database_bootstrap_sql())
            .execute()
            .await
        {
            return Err(self
                .with_unreachable_replicas(ClickHouseMigrateError::ClickHouse(error.to_string()))
                .await);
        }
        // Keep an explicit all-node visibility assertion after the synchronous
        // ON CLUSTER DDL barrier. Do not let init.sql or `_migrations` rely on
        // implicit observation timing or stale cluster membership on a blank
        // cluster. The non-cluster, implicit-cluster, Replicated-DB, and cloud
        // paths skip this wait and retain their historical statement/ordering.
        if let Err(error) = self
            .wait_for_database_bootstrap_visibility(&bootstrap_client)
            .await
        {
            return Err(self.with_unreachable_replicas(error).await);
        }

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
            Some(cluster) if is_cloud || cluster == &self.database => {
                (String::new(), "ReplicatedMergeTree()".to_string())
            }
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

        self.execute_tracking_ddl(&sql).await?;

        // NAN-4977: durable work queue for refreshable-view query changes.
        // It deliberately shares `_migrations`' cluster-global replication
        // group shape (no `{shard}`), so whichever jobs replica becomes leader
        // sees the same pending/failed/succeeded state.
        let refresh_engine = replacing_revision_engine(&global_table_engine(
            &engine,
            crate::db::migration_refresh::MIGRATION_REFRESH_TABLE,
        ));
        let refresh_sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{}{}
            (
                `version` String,
                `view` String,
                `reload_target` String,
                `state` LowCardinality(String),
                `revision` UInt64,
                `phase` LowCardinality(String) DEFAULT 'refresh',
                `attempts` UInt8 DEFAULT 0,
                `next_attempt_at` DateTime64(6, 'UTC') DEFAULT now64(6),
                `last_error` String DEFAULT '',
                `updated_at` DateTime64(6, 'UTC') DEFAULT now64(6)
            )
            ENGINE = {}
            ORDER BY (version, view)
            SETTINGS index_granularity = 8192
            "#,
            self.database,
            crate::db::migration_refresh::MIGRATION_REFRESH_TABLE,
            on_cluster,
            refresh_engine
        );
        self.execute_tracking_ddl(&refresh_sql).await?;

        // NAN-4939: exact, immutable membership for an operator repair run.
        // This has the same cluster-global topology as `_migrations`, allowing
        // every shard-local DELETE mutation to see the identical repair set.
        let repair_set_engine = global_table_engine(
            &engine,
            crate::db::future_timestamp_repair::FUTURE_REPAIR_SET_TABLE,
        );
        let repair_set_sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{}{}
            (
                `repair_id` UUID,
                `source_table` LowCardinality(String),
                `event_id` UUID,
                `source_timestamp` DateTime64(6, 'UTC'),
                `created_at` DateTime64(6, 'UTC') DEFAULT now64(6)
            )
            ENGINE = {}
            ORDER BY (repair_id, source_table, event_id, source_timestamp)
            TTL created_at + INTERVAL 7 DAY DELETE
            SETTINGS index_granularity = 8192
            "#,
            self.database,
            crate::db::future_timestamp_repair::FUTURE_REPAIR_SET_TABLE,
            on_cluster,
            repair_set_engine
        );
        self.execute_tracking_ddl(&repair_set_sql).await?;

        // `ip_enrichments.updated_at` is the ReplacingMergeTree version and
        // ClickHouse therefore forbids ALTER UPDATE on it. A corrected copy has
        // a lower version than the bad far-future tombstone, so copying beside
        // the original can also be merged away before deletion. Persist the
        // exact confirmed tombstone rows in a cluster-global buffer first;
        // NAN-4939 can then delete the bad winners and restore from this durable
        // copy without risking resurrection or payload loss.
        let ip_repair_rows_engine = global_table_engine(
            &engine,
            crate::db::future_timestamp_repair::FUTURE_IP_REPAIR_ROWS_TABLE,
        );
        let ip_repair_rows_sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.{}{}
            (
                `repair_id` UUID,
                `network` String,
                `source_id` LowCardinality(String),
                `country` String DEFAULT '',
                `country_code` String DEFAULT '',
                `continent` String DEFAULT '',
                `continent_code` String DEFAULT '',
                `asn` String DEFAULT '',
                `as_name` String DEFAULT '',
                `as_domain` String DEFAULT '',
                `updated_at` DateTime64(3, 'UTC'),
                `deleted` UInt8,
                `created_at` DateTime64(6, 'UTC') DEFAULT now64(6)
            )
            ENGINE = {}
            ORDER BY (repair_id, source_id, network, updated_at)
            SETTINGS index_granularity = 8192
            "#,
            self.database,
            crate::db::future_timestamp_repair::FUTURE_IP_REPAIR_ROWS_TABLE,
            on_cluster,
            ip_repair_rows_engine
        );
        self.execute_tracking_ddl(&ip_repair_rows_sql).await?;

        // The buffer becomes the only authoritative tombstone payload after
        // the bad ReplacingMergeTree winner is deleted. It must never expire
        // automatically. Upgrade the first NAN-4939 schema, which briefly
        // shipped with a seven-day TTL, in place. Normal and manual cleanup are
        // both scoped to a verified repair_id.
        let escaped_database = crate::sql_hygiene::escape_sql_string(&self.database);
        let escaped_table = crate::sql_hygiene::escape_sql_string(
            crate::db::future_timestamp_repair::FUTURE_IP_REPAIR_ROWS_TABLE,
        );
        let ip_buffer_has_ttl: u64 = self
            .client
            .query(&format!(
                "SELECT count() FROM system.tables WHERE database = '{escaped_database}' \
                 AND name = '{escaped_table}' AND position(create_table_query, 'TTL') > 0"
            ))
            .fetch_one()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
        if ip_buffer_has_ttl > 0 {
            self.execute_tracking_ddl(&format!(
                "ALTER TABLE {}.{}{} REMOVE TTL",
                self.database,
                crate::db::future_timestamp_repair::FUTURE_IP_REPAIR_ROWS_TABLE,
                on_cluster
            ))
            .await?;
        }

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

        // NAN-5296: by now every statement of the migration has applied. Say
        // so, because a failure here looks like a failed migration when only
        // the ledger row is missing. Re-running is safe: migrations are
        // idempotent and this version is still pending.
        self.execute_with_busy_retry(&sql).await.map_err(|e| {
            ClickHouseMigrateError::ClickHouse(format!(
                "migration {} applied all of its statements, but recording it in \
                 {}._migrations failed; re-run the migrator once ClickHouse accepts \
                 inserts again: {e}",
                migration.filename, self.database
            ))
        })?;

        Ok(())
    }

    /// Record refresh invalidations declared by a migration. Called after its
    /// SQL succeeds but before `_migrations` is advanced, so a queue-write
    /// failure leaves the migration retryable instead of silently losing the
    /// activation request.
    pub(super) async fn record_refresh_invalidations(
        &self,
        migration: &Migration,
        directives: &[crate::db::migration_refresh::MigrationRefreshDirective],
    ) -> Result<usize, ClickHouseMigrateError> {
        let table = format!(
            "{}.{}",
            self.database,
            crate::db::migration_refresh::MIGRATION_REFRESH_TABLE
        );
        for directive in directives {
            let version = crate::sql_hygiene::escape_sql_string(&migration.version);
            let view = crate::sql_hygiene::escape_sql_string(&directive.view);
            let reload = crate::sql_hygiene::escape_sql_string(&directive.reload_target);
            let sql = format!(
                "INSERT INTO {table} \
                    (version, view, reload_target, state, revision, phase, attempts, next_attempt_at) \
                 SELECT '{version}', '{view}', '{reload}', 'pending', ifNull(max(revision), 0) + 1, \
                        'refresh', 0, now64(6) \
                 FROM {table} FINAL WHERE version = '{version}' AND view = '{view}'"
            );
            self.execute_with_busy_retry(&sql)
                .await
                .map_err(ClickHouseMigrateError::ClickHouse)?;
        }
        Ok(directives.len())
    }

    /// All migration versions baked into init.sql. The same JSON contract is
    /// consumed by the upgrade validator when it permits checksum-less fresh
    /// seed rows; keeping the identities in one file prevents contract drift.
    fn baseline_migrations() -> Result<Vec<BaselineMigration>, ClickHouseMigrateError> {
        let migrations: Vec<BaselineMigration> = serde_json::from_str(BASELINE_MIGRATIONS_JSON)
            .map_err(|error| {
                ClickHouseMigrateError::ClickHouse(format!(
                    "invalid embedded baseline migration contract: {error}"
                ))
            })?;
        if migrations.is_empty() {
            return Err(ClickHouseMigrateError::ClickHouse(
                "embedded baseline migration contract is empty".to_string(),
            ));
        }
        let mut versions = HashSet::new();
        for migration in &migrations {
            let digit_count = migration
                .version
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .count();
            if digit_count == 0
                || migration.version[digit_count..]
                    .chars()
                    .any(|character| !character.is_ascii_lowercase())
                || migration.name.is_empty()
                || migration.name.chars().any(|character| {
                    !character.is_ascii_lowercase()
                        && !character.is_ascii_digit()
                        && character != '_'
                })
                || !versions.insert(migration.version.clone())
            {
                return Err(ClickHouseMigrateError::ClickHouse(
                    "invalid embedded baseline migration contract entry".to_string(),
                ));
            }
        }
        Ok(migrations)
    }

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
        for migration in Self::baseline_migrations()? {
            let sql = format!(
                "INSERT INTO {}._migrations (version, name) VALUES ('{}', '{}')",
                self.database,
                crate::sql_hygiene::escape_sql_string(&migration.version),
                crate::sql_hygiene::escape_sql_string(&migration.name)
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

fn global_table_engine(base: &str, table: &str) -> String {
    base.replace("/_migrations", &format!("/{table}"))
}

fn replacing_revision_engine(base: &str) -> String {
    if base == "MergeTree" {
        return "ReplacingMergeTree(revision)".to_string();
    }
    let Some(args) = base
        .strip_prefix("ReplicatedMergeTree(")
        .and_then(|value| value.strip_suffix(')'))
    else {
        return base.to_string();
    };
    if args.is_empty() {
        "ReplicatedReplacingMergeTree(revision)".to_string()
    } else {
        format!("ReplicatedReplacingMergeTree({args}, revision)")
    }
}

#[cfg(test)]
#[path = "tracking_tests.rs"]
mod tests;
