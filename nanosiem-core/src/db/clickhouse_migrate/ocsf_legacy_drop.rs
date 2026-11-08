// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator-run drop of the OCSF 1.8 legacy store (NAN-4918).
//!
//! Migration 180 RENAMEs the 1.8-shaped `ocsf_logs` to `ocsf_logs_legacy_v179`
//! and keeps every row; `scripts/ocsf-legacy-backfill.py` copies them into the
//! version-agnostic `ocsf_logs`. This module is the explicit last step: it
//! proves the copy is complete and only then drops the legacy table. It never
//! runs at boot or from the migration path; the default for a tenant that does
//! nothing is the legacy table's own 365-day TTL emptying it.
//!
//! The proof is per id: every legacy `id` must have exactly one row in
//! `ocsf_logs` (an anti-join finds missing ids, a GROUP BY ... HAVING
//! count() > 1 finds duplicated ones). It runs one hour at a time so each id
//! set stays bounded on large tenants, and is reported per UTC day. Matching
//! by `id` (the backfill keeps it) means post-cutover ingest on the same day
//! cannot hide a missing copy. Any missing or duplicated id refuses the drop.
//!
//! Every proof query pins `skip_unavailable_shards = 0`, and on a cluster the
//! command first checks that every shard in `system.clusters` answers: a
//! partial cluster is never verified.
//!
//! Cluster-aware: on a cluster the counts read every shard through the
//! `cluster()` table function (the legacy table and the backfilled rows are
//! shard-local, and the `IN` subquery runs against each shard's own legacy
//! table), and the DROP goes through the migrator's own
//! [`transform_for_cluster`](ClickHouseMigrator::transform_for_cluster), so it
//! gets `ON CLUSTER` + `SYNC` exactly like migration DDL.

use chrono::{NaiveDate, NaiveDateTime};

use super::{ClickHouseMigrateError, ClickHouseMigrator};

/// The renamed OCSF 1.8 store (migration 180).
pub const OCSF_LEGACY_TABLE: &str = "ocsf_logs_legacy_v179";
/// The version-agnostic store the backfill writes to.
pub const OCSF_STORE_TABLE: &str = "ocsf_logs";

/// Result of comparing one UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyDayStatus {
    /// Every legacy id of the day is in `ocsf_logs` exactly once.
    Match,
    /// Some legacy ids are missing, or some appear more than once.
    Mismatch,
    /// No legacy id of the day is in `ocsf_logs` (day not backfilled).
    Missing,
}

/// One UTC day of the comparison. The proof is per id, never an aggregate
/// count: legacy `{A, B}` against target `{B, B}` has equal counts but one
/// missing and one duplicated id, and is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDayCheck {
    /// `YYYY-MM-DD` (UTC).
    pub day: NaiveDate,
    /// Rows the legacy table holds for the day.
    pub legacy_rows: u64,
    /// Legacy ids of the day with no row in `ocsf_logs`.
    pub missing_ids: u64,
    /// Legacy ids of the day with more than one row in `ocsf_logs`.
    pub duplicate_ids: u64,
}

impl LegacyDayCheck {
    pub fn status(&self) -> LegacyDayStatus {
        if self.missing_ids == 0 && self.duplicate_ids == 0 {
            LegacyDayStatus::Match
        } else if self.missing_ids >= self.legacy_rows {
            LegacyDayStatus::Missing
        } else {
            LegacyDayStatus::Mismatch
        }
    }
}

/// What the command found and would run.
#[derive(Debug, Clone)]
pub struct OcsfLegacyDropPlan {
    /// Cluster the counts and the DROP fan out over (`None` on a single node
    /// or ClickHouse Cloud).
    pub cluster: Option<String>,
    /// Every day the legacy table still holds rows, oldest first.
    pub days: Vec<LegacyDayCheck>,
    /// The exact DROP statement (after cluster transformation).
    pub drop_sql: String,
}

impl OcsfLegacyDropPlan {
    /// Days that refuse the drop.
    pub fn blocking_days(&self) -> Vec<&LegacyDayCheck> {
        self.days
            .iter()
            .filter(|d| d.status() != LegacyDayStatus::Match)
            .collect()
    }

    /// True when every legacy day matched (an empty legacy table is safe).
    pub fn safe_to_drop(&self) -> bool {
        self.blocking_days().is_empty()
    }

    pub fn legacy_rows(&self) -> u64 {
        self.days.iter().map(|d| d.legacy_rows).sum()
    }
}

/// What [`ClickHouseMigrator::drop_ocsf_legacy`] did.
#[derive(Debug)]
pub enum OcsfLegacyDropOutcome {
    /// The legacy table does not exist (fresh install, UDM, or already dropped).
    Absent,
    /// A day mismatched or is missing; nothing was dropped.
    Refused(OcsfLegacyDropPlan),
    /// Safe to drop, but `--confirm` was not given; nothing was dropped.
    DryRun(OcsfLegacyDropPlan),
    /// The legacy table was dropped.
    Dropped(OcsfLegacyDropPlan),
}

/// Single-quoted ClickHouse string literal.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// Backtick-quoted identifier.
fn ident(s: &str) -> String {
    format!("`{}`", s.replace('\\', "\\\\").replace('`', "\\`"))
}

/// The cluster to fan out over: `None` on a single node and on ClickHouse
/// Cloud (SharedMergeTree: every replica sees all data, no shards).
pub(super) fn fan_out_cluster(cluster: Option<&str>, is_cloud: bool) -> Option<&str> {
    if is_cloud {
        None
    } else {
        cluster
    }
}

/// A table reference that reads every shard: `cluster('c', 'db', 't')` on a
/// cluster (one replica per shard), the plain table otherwise.
pub(super) fn all_shards_ref(cluster: Option<&str>, db: &str, table: &str) -> String {
    match cluster {
        Some(c) => format!("cluster({}, {}, {})", quote(c), quote(db), quote(table)),
        None => format!("{}.{}", ident(db), ident(table)),
    }
}

/// `timestamp` bounds of one UTC hour (`hour` = `YYYY-MM-DD HH:00:00`).
fn hour_window(hour: NaiveDateTime) -> String {
    format!(
        "timestamp >= toDateTime64({h}, 3, 'UTC') AND timestamp < toDateTime64({h}, 3, 'UTC') + INTERVAL 1 HOUR",
        h = quote(&hour.format("%Y-%m-%d %H:%M:%S").to_string())
    )
}

/// Per-hour legacy row counts across every shard. Hours, not days, bound the
/// id set the copy check below builds: at 50-100 GB/day a whole day's ids
/// would be a multi-GB `IN` set per shard.
pub(super) fn legacy_hour_counts_sql(cluster: Option<&str>, db: &str) -> String {
    format!(
        "SELECT toString(toStartOfHour(timestamp, 'UTC')) AS hour, count() AS n FROM {} GROUP BY hour ORDER BY hour",
        all_shards_ref(cluster, db, OCSF_LEGACY_TABLE)
    )
}

/// Legacy ids of `hour` with no row in the new store. Under `cluster()` the
/// `NOT IN` subquery names the shard-local store, so each shard checks its own
/// legacy rows against the rows the per-shard backfill wrote there. The set
/// holds one hour of store ids.
pub(super) fn missing_ids_sql(
    cluster: Option<&str>,
    db: &str,
    store_physical: &str,
    hour: NaiveDateTime,
) -> String {
    let window = hour_window(hour);
    format!(
        "SELECT count() FROM {legacy} WHERE {window} AND id NOT IN (SELECT id FROM {store} WHERE {window})",
        legacy = all_shards_ref(cluster, db, OCSF_LEGACY_TABLE),
        store = format!("{}.{}", ident(db), ident(store_physical)),
    )
}

/// Legacy ids of `hour` that occur more than once in the new store (counted
/// across every shard: the GROUP BY merges shards).
pub(super) fn duplicate_ids_sql(
    cluster: Option<&str>,
    db: &str,
    store_physical: &str,
    hour: NaiveDateTime,
) -> String {
    let window = hour_window(hour);
    format!(
        "SELECT count() FROM (SELECT id FROM {store} WHERE {window} AND id IN (SELECT id FROM {legacy} WHERE {window}) \
         GROUP BY id HAVING count() > 1)",
        store = all_shards_ref(cluster, db, store_physical),
        legacy = format!("{}.{}", ident(db), ident(OCSF_LEGACY_TABLE)),
    )
}

/// Shards the cluster defines.
pub(super) fn expected_shards_sql(cluster: &str) -> String {
    format!("SELECT uniqExact(shard_num) FROM system.clusters WHERE cluster = {}", quote(cluster))
}

/// Shards that answered a `cluster()` read.
pub(super) fn answered_shards_sql(cluster: &str) -> String {
    format!("SELECT uniqExact(shardNum()) FROM cluster({}, system.one)", quote(cluster))
}

/// Settings every proof and existence query runs with: an unavailable shard
/// is an error, never silently skipped, whatever the admin profile says.
pub(super) const PROOF_SETTINGS: &[(&str, &str)] = &[("skip_unavailable_shards", "0")];

/// The DROP, transformed like migration DDL: `ON CLUSTER` + `SYNC` on an
/// explicit cluster, untouched on a single node / Replicated database / Cloud.
/// `max_table_size_to_drop = 0` lifts the 50 GB drop guard for this statement
/// only: the per-day proof above is the guard here.
pub(super) fn drop_legacy_sql(cluster: Option<&str>, db: &str, is_cloud: bool) -> String {
    let base = format!(
        "DROP TABLE IF EXISTS {db}.{OCSF_LEGACY_TABLE} SYNC SETTINGS max_table_size_to_drop = 0"
    );
    match cluster {
        Some(c) => ClickHouseMigrator::transform_for_cluster(&base, c, db, is_cloud),
        None => base,
    }
}

impl ClickHouseMigrator {
    /// Test seam: the cluster to use instead of detecting one (`None` = single
    /// node). Production relies on `CLICKHOUSE_CLUSTER` / `system.clusters`.
    #[doc(hidden)]
    pub fn with_cluster(mut self, cluster: Option<String>) -> Self {
        self.cluster = Some(cluster);
        self
    }

    /// The migrator's client with [`PROOF_SETTINGS`] pinned.
    fn proof_client(&self) -> clickhouse::Client {
        PROOF_SETTINGS
            .iter()
            .fold(self.client.clone(), |c, (k, v)| c.with_option(*k, *v))
    }

    async fn proof_count(&self, sql: &str) -> Result<u64, ClickHouseMigrateError> {
        self.proof_client()
            .query(sql)
            .fetch_one::<u64>()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))
    }

    /// Refuse unless every shard the cluster defines answers.
    async fn require_all_shards(&self, cluster: &str) -> Result<(), ClickHouseMigrateError> {
        let expected = self.proof_count(&expected_shards_sql(cluster)).await?;
        if expected == 0 {
            return Err(ClickHouseMigrateError::ClickHouse(format!(
                "cluster '{cluster}' is not defined in system.clusters"
            )));
        }
        let answered = self.proof_count(&answered_shards_sql(cluster)).await.map_err(|e| {
            ClickHouseMigrateError::ClickHouse(format!(
                "not every shard of '{cluster}' answered ({e}); refusing to verify a partial cluster"
            ))
        })?;
        if answered != expected {
            return Err(ClickHouseMigrateError::ClickHouse(format!(
                "{answered} of {expected} shards of '{cluster}' answered; refusing to verify a partial cluster"
            )));
        }
        Ok(())
    }

    /// Whether `table` exists on any node of the fan-out cluster.
    async fn table_exists_anywhere(
        &self,
        cluster: Option<&str>,
        table: &str,
    ) -> Result<bool, ClickHouseMigrateError> {
        let tables = match cluster {
            Some(c) => format!("cluster({}, system.tables)", quote(c)),
            None => "system.tables".to_string(),
        };
        let n = self
            .proof_count(&format!(
                "SELECT count() FROM {tables} WHERE database = {} AND name = {}",
                quote(&self.database),
                quote(table)
            ))
            .await?;
        Ok(n > 0)
    }

    /// Compare legacy and new per-day counts without changing anything.
    /// `Ok(None)` when the legacy table does not exist.
    pub async fn plan_ocsf_legacy_drop(
        &mut self,
    ) -> Result<Option<OcsfLegacyDropPlan>, ClickHouseMigrateError> {
        let is_cloud = self.detect_cloud().await?;
        let detected = self.detect_cluster().await?;
        let cluster = fan_out_cluster(detected.as_deref(), is_cloud).map(str::to_string);
        let c = cluster.as_deref();
        let db = self.database.clone();

        if let Some(cluster) = c {
            self.require_all_shards(cluster).await?;
        }
        if !self.table_exists_anywhere(c, OCSF_LEGACY_TABLE).await? {
            return Ok(None);
        }
        // Same physical-table rule as the row-policy reconciler: the data sits
        // in `<t>_local` where a Distributed split exists.
        let store_local = format!("{OCSF_STORE_TABLE}_local");
        let store = if self.table_exists_anywhere(c, &store_local).await? {
            store_local
        } else if self.table_exists_anywhere(c, OCSF_STORE_TABLE).await? {
            OCSF_STORE_TABLE.to_string()
        } else {
            return Err(ClickHouseMigrateError::ClickHouse(format!(
                "{db}.{OCSF_STORE_TABLE} does not exist: run the migrator with \
                 NANO_SCHEMA_PROFILE=ocsf and the backfill before dropping the legacy table"
            )));
        };

        let rows = self
            .proof_client()
            .query(&legacy_hour_counts_sql(c, &db))
            .fetch_all::<(String, u64)>()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
        let mut days: Vec<LegacyDayCheck> = Vec::new();
        for (hour, legacy_rows) in rows {
            let hour = NaiveDateTime::parse_from_str(&hour, "%Y-%m-%d %H:%M:%S").map_err(|e| {
                ClickHouseMigrateError::ClickHouse(format!("unexpected hour {hour:?}: {e}"))
            })?;
            let missing_ids = self.proof_count(&missing_ids_sql(c, &db, &store, hour)).await?;
            let duplicate_ids = self.proof_count(&duplicate_ids_sql(c, &db, &store, hour)).await?;
            // Rows arrive ordered by hour, so a day's hours are contiguous.
            match days.last_mut() {
                Some(d) if d.day == hour.date() => {
                    d.legacy_rows += legacy_rows;
                    d.missing_ids += missing_ids;
                    d.duplicate_ids += duplicate_ids;
                }
                _ => days.push(LegacyDayCheck {
                    day: hour.date(),
                    legacy_rows,
                    missing_ids,
                    duplicate_ids,
                }),
            }
        }
        Ok(Some(OcsfLegacyDropPlan {
            drop_sql: drop_legacy_sql(c, &db, is_cloud),
            cluster,
            days,
        }))
    }

    /// Verify, then drop `ocsf_logs_legacy_v179` only when `confirm` is set and
    /// every legacy day matched. Never called from the migration path.
    pub async fn drop_ocsf_legacy(
        &mut self,
        confirm: bool,
    ) -> Result<OcsfLegacyDropOutcome, ClickHouseMigrateError> {
        let Some(plan) = self.plan_ocsf_legacy_drop().await? else {
            return Ok(OcsfLegacyDropOutcome::Absent);
        };
        if !plan.safe_to_drop() {
            return Ok(OcsfLegacyDropOutcome::Refused(plan));
        }
        if !confirm {
            return Ok(OcsfLegacyDropOutcome::DryRun(plan));
        }
        self.client
            .query(&plan.drop_sql)
            .execute()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
        tracing::warn!(
            cluster = ?plan.cluster,
            legacy_rows = plan.legacy_rows(),
            days = plan.days.len(),
            "Dropped {}.{} after a matching per-day comparison (NAN-4918)",
            self.database,
            OCSF_LEGACY_TABLE
        );
        Ok(OcsfLegacyDropOutcome::Dropped(plan))
    }
}

#[cfg(test)]
#[path = "ocsf_legacy_drop_tests.rs"]
mod tests;
