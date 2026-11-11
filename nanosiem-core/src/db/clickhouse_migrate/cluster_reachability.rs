// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5215: replica reachability for the migrator's per-boot cluster steps.
//!
//! A clustered install runs every shard with two replicas, so the app tier
//! must be recreatable while ONE replica is hard-down. Every `ON CLUSTER`
//! statement waits for every host (`distributed_ddl_output_mode = throw`), so
//! the per-boot "ensure" steps first ask whether there is anything to do:
//! they read the objects on every *reachable* replica through
//! `clusterAllReplicas(...)` with `skip_unavailable_shards = 1` (each replica
//! is its own shard there) and only fall back to the DDL when a reachable
//! replica lacks something. A returning replica applies the statements it
//! missed from the Keeper DDL queue.
//!
//! When DDL genuinely has to run with a replica down it still fails; the
//! helpers here name the unreachable replicas in that error.

use super::ClickHouseMigrator;
use std::collections::HashSet;

/// One row of `system.clusters`, in `(shard_num, replica_num)` order.
#[derive(Debug, Clone, PartialEq, Eq, clickhouse::Row, serde::Deserialize)]
pub(super) struct ClusterReplica {
    pub shard_num: u32,
    pub replica_num: u32,
    pub host_name: String,
    pub port: u16,
}

/// Which replicas answered a `clusterAllReplicas` probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reachability {
    /// Every replica configured for the cluster, `(shard, replica)` order.
    pub replicas: Vec<ClusterReplica>,
    /// 1-based `shardNum()` ordinals that answered. `clusterAllReplicas`
    /// turns each configured replica into its own shard, numbered in
    /// `system.clusters` `(shard_num, replica_num)` order.
    pub reachable: HashSet<u32>,
}

impl Reachability {
    pub fn reachable_count(&self) -> usize {
        self.reachable.len()
    }

    pub fn all_reachable(&self) -> bool {
        !self.replicas.is_empty()
            && (1..=self.replicas.len() as u32).all(|ordinal| self.reachable.contains(&ordinal))
    }

    pub fn unreachable(&self) -> Vec<&ClusterReplica> {
        self.replicas
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.reachable.contains(&(*index as u32 + 1)))
            .map(|(_, replica)| replica)
            .collect()
    }

    /// Human summary, e.g. `3/4 replicas reachable; unreachable:
    /// ch-2b:9000 (shard 2, replica 2)`.
    pub fn describe(&self) -> String {
        let total = self.replicas.len();
        let reachable = self.reachable_count();
        let down = self.unreachable();
        if down.is_empty() {
            return format!("{reachable}/{total} replicas reachable");
        }
        let names = down
            .iter()
            .map(|replica| {
                format!(
                    "{}:{} (shard {}, replica {})",
                    replica.host_name, replica.port, replica.shard_num, replica.replica_num
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("{reachable}/{total} replicas reachable; unreachable: {names}")
    }
}

/// NAN-5255: `system.clusters` predicate selecting the rows of the
/// `remote_servers` cluster named `cluster` -- the topology
/// `clusterAllReplicas('<cluster>', ...)` and `ON CLUSTER '<cluster>'` fan out
/// to.
///
/// A `Replicated` database registers its OWN cluster in `system.clusters`
/// under the database's name, with `database_shard_name` /
/// `database_replica_name` set and `host_name` = the replica's FQDN. The
/// ClickHouse operator's database sync (`enableDatabaseSync`, default on)
/// turns database `default` into a Replicated database, so a remote_servers
/// cluster also called `default` shows up twice: a 1x2 install lists 4 rows
/// while `clusterAllReplicas('default', ...)` reaches 2 nodes. Counting every
/// row made the migrator wait for 2/4 forever and blame a replica that was
/// reachable.
///
/// Prefer the remote_servers rows (`database_replica_name = ''`); a name that
/// exists ONLY as a Replicated database keeps its rows so that topology is not
/// reported as empty. `cluster` must already be a quoted SQL literal.
pub(crate) fn server_cluster_rows_predicate(cluster_literal: &str) -> String {
    format!(
        "cluster = {cluster_literal} AND (database_replica_name = '' OR \
         (SELECT countIf(database_replica_name = '') FROM system.clusters \
         WHERE cluster = {cluster_literal}) = 0)"
    )
}

/// `system.clusters` rows for `cluster`, ordered like `clusterAllReplicas`
/// numbers its per-replica shards.
pub(super) fn cluster_replicas_sql(cluster: &str) -> String {
    let cluster = crate::sql_hygiene::escape_sql_string(cluster);
    let rows = server_cluster_rows_predicate(&format!("'{cluster}'"));
    format!(
        "SELECT shard_num, replica_num, host_name, port FROM system.clusters \
         WHERE {rows} ORDER BY shard_num, replica_num"
    )
}

/// The ordinal of every replica that answers. `skip_unavailable_shards = 1`
/// drops a dead replica instead of failing the whole probe.
pub(super) fn reachable_ordinals_sql(cluster: &str) -> String {
    let cluster = crate::sql_hygiene::escape_sql_string(cluster);
    format!(
        "SELECT shardNum() FROM clusterAllReplicas('{cluster}', system.one) \
         SETTINGS skip_unavailable_shards = 1"
    )
}

/// The cluster per-boot steps address with `ON CLUSTER`: an explicit
/// operator cluster that is not a Replicated database. Cloud and
/// Replicated-database modes propagate DDL without the clause.
pub(super) fn explicit_cluster<'a>(
    cluster: Option<&'a str>,
    database: &str,
    is_cloud: bool,
) -> Option<&'a str> {
    cluster.filter(|cluster| !is_cloud && *cluster != database)
}

/// True when every reachable replica already holds all `per_replica`
/// objects: `present` counts matching rows summed over the reachable
/// replicas, and each replica can hold each object at most once.
pub(super) fn present_on_every_reachable_replica(
    reachable_replicas: usize,
    per_replica: u64,
    present: u64,
) -> bool {
    reachable_replicas > 0 && per_replica > 0 && present == per_replica * reachable_replicas as u64
}

impl ClickHouseMigrator {
    /// Probe which replicas of `cluster` answer. `client` must be usable
    /// before the target database exists (pass a `default`-database client
    /// during bootstrap).
    pub(super) async fn probe_reachability(
        client: &clickhouse::Client,
        cluster: &str,
    ) -> Result<Reachability, clickhouse::error::Error> {
        let replicas = client
            .query(&cluster_replicas_sql(cluster))
            .fetch_all::<ClusterReplica>()
            .await?;
        let reachable = client
            .query(&reachable_ordinals_sql(cluster))
            .fetch_all::<u32>()
            .await?
            .into_iter()
            .collect();
        Ok(Reachability {
            replicas,
            reachable,
        })
    }

    /// The explicit cluster this migrator fans DDL out to, if any.
    pub(super) fn explicit_cluster_name(&self) -> Option<&str> {
        explicit_cluster(
            self.cluster.as_ref().and_then(|cluster| cluster.as_deref()),
            &self.database,
            self.is_cloud.unwrap_or(false),
        )
    }

    /// Suffix for an error raised by cluster DDL: names the replicas that do
    /// not answer, so an operator sees "replica X is down" instead of a bare
    /// distributed-DDL timeout. Empty outside explicit clusters or when every
    /// replica answers.
    pub(super) async fn unreachable_replicas_note(&self) -> String {
        let Some(cluster) = self.explicit_cluster_name() else {
            return String::new();
        };
        let client = self.client.clone().with_database("default");
        match Self::probe_reachability(&client, cluster).await {
            Ok(reachability) if reachability.all_reachable() => String::new(),
            Ok(reachability) => format!(
                " [cluster '{cluster}': {}. ON CLUSTER DDL waits for every replica; \
                 restore the replica (or wait for it to return) and rerun the migrator]",
                reachability.describe()
            ),
            Err(error) => format!(" [cluster '{cluster}': replica reachability probe failed: {error}]"),
        }
    }

    /// Append [`Self::unreachable_replicas_note`] to a ClickHouse error.
    pub(super) async fn with_unreachable_replicas(
        &self,
        error: super::ClickHouseMigrateError,
    ) -> super::ClickHouseMigrateError {
        match error {
            super::ClickHouseMigrateError::ClickHouse(message) => {
                let note = self.unreachable_replicas_note().await;
                super::ClickHouseMigrateError::ClickHouse(format!("{message}{note}"))
            }
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "cluster_reachability_tests.rs"]
mod tests;
