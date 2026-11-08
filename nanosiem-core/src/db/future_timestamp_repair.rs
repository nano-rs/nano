// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit repair for events already stored in far-future partitions.
//!
//! This is deliberately not part of boot migration. The operator previews the
//! exact row set, pauses ingest, and opts in to a copy/verify/delete sequence.
//! A corrected copy is written before any original row is removed. Re-running
//! after a completed repair is a no-op because no row remains beyond cutoff.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use uuid::Uuid;

use crate::schema::SchemaId;

pub const FUTURE_REPAIR_SET_TABLE: &str = "_future_timestamp_repair_set";
pub const FUTURE_IP_REPAIR_ROWS_TABLE: &str = "_future_timestamp_ip_repair_rows";
pub const FUTURE_REPAIR_LOCK_TABLE: &str = "_future_timestamp_repair_lock";
const FUTURE_REPAIR_LOCK_LEASE_SECONDS: i64 = 6 * 60 * 60;

// A correctly stored contemporary DateTime64(3) has about 1.8e12 millisecond
// ticks. NAN-4938's bare epoch-millisecond literal was interpreted as seconds,
// leaving about 1.8e15 millisecond ticks. Keep the detection entirely in the
// integer domain: comparing a DateTime64 column to a bare integer is the same
// coercion trap that caused the incident.
const EPOCH_MILLIS_AS_SECONDS_MIN_TICKS: i64 = 100_000_000_000_000;
const MIN_PLAUSIBLE_SOURCE_EPOCH_MS: i64 = 946_684_800_000; // 2000-01-01 UTC

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FutureTimestampRepairPreview {
    pub table: String,
    pub future_rows: u64,
    pub distinct_ids: u64,
    pub existing_id_collisions: u64,
    pub oldest_future: String,
    pub newest_future: String,
    pub recoverable_epoch_millis_rows: u64,
    pub cutoff: DateTime<Utc>,
    pub clamped_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochMillisRepairPreview {
    pub table: String,
    pub source_table: String,
    pub affected_rows: u64,
    pub distinct_rows: u64,
    pub pending_buffer_rows: u64,
    pub oldest_recovered: String,
    pub newest_recovered: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochMillisRepairOutcome {
    pub table: String,
    pub repaired_rows: u64,
    pub deleted_originals: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FutureTimestampRepairPurgePreview {
    pub repair_id: Uuid,
    pub staged_rows: u64,
    pub buffered_rows: u64,
    pub staged_originals_remaining: u64,
    pub buffered_distinct_rows: u64,
    pub buffered_verified_rows: u64,
    pub owns_lock: bool,
    pub owns_expired_lock: bool,
    pub lock_lease_until: String,
}

pub struct FutureTimestampRepairLock {
    client: clickhouse::Client,
    database: String,
    on_cluster: String,
    owner: Uuid,
    comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FutureTimestampRepairOutcome {
    pub copied_ids: u64,
    pub deleted_rows: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairShape {
    table: &'static str,
    precision: u8,
    preserves_original_column: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EpochMillisRepairShape {
    IpEnrichments,
    CustomEnrichmentResults,
    UserRegistry,
    SyntheticCheckResults,
}

impl EpochMillisRepairShape {
    const ALL: [Self; 4] = [
        Self::IpEnrichments,
        Self::CustomEnrichmentResults,
        Self::UserRegistry,
        Self::SyntheticCheckResults,
    ];

    const fn table(self) -> &'static str {
        match self {
            Self::IpEnrichments => "ip_enrichments",
            Self::CustomEnrichmentResults => "custom_enrichment_results",
            Self::UserRegistry => "user_registry",
            Self::SyntheticCheckResults => "synthetic_check_results",
        }
    }

    const fn uses_update_mutation(self) -> bool {
        matches!(self, Self::UserRegistry)
    }
}

impl RepairShape {
    fn for_schema(schema: SchemaId) -> Result<Self> {
        match schema {
            SchemaId::Udm => Ok(Self {
                table: "logs",
                precision: 6,
                preserves_original_column: true,
            }),
            SchemaId::Ocsf => Ok(Self {
                table: "ocsf_logs",
                precision: 3,
                // OCSF preserves the sender's time inside event.time.
                preserves_original_column: false,
            }),
            other => bail!("future timestamp repair does not support the {other:?} dataset"),
        }
    }
}

pub struct FutureTimestampRepair<'a> {
    client: &'a clickhouse::Client,
    database: &'a str,
    shape: RepairShape,
    read_table: String,
    cutoff: DateTime<Utc>,
    clamped_at: DateTime<Utc>,
    repair_id: Uuid,
    on_cluster: String,
}

impl<'a> FutureTimestampRepair<'a> {
    pub async fn new(
        client: &'a clickhouse::Client,
        database: &'a str,
        schema: SchemaId,
        skew_seconds: u64,
    ) -> Result<Self> {
        let shape = RepairShape::for_schema(schema)?;
        let distributed = format!("{}_distributed", shape.table);
        let distributed_exists: u64 = client
            .query(&format!(
                "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                crate::sql_hygiene::escape_sql_string(database),
                distributed
            ))
            .fetch_one()
            .await
            .context("checking for the distributed repair target")?;
        let read_table = if distributed_exists > 0 {
            format!("{database}.{distributed}")
        } else {
            format!("{database}.{}", shape.table)
        };
        let clamped_at = Utc::now();
        let skew = i64::try_from(skew_seconds).context("timestamp skew is too large")?;
        let cutoff = clamped_at + Duration::seconds(skew);
        let on_cluster = resolve_repair_on_cluster(client, database).await?;
        Ok(Self {
            client,
            database,
            shape,
            read_table,
            cutoff,
            clamped_at,
            repair_id: Uuid::now_v7(),
            on_cluster,
        })
    }

    pub const fn repair_id(&self) -> Uuid {
        self.repair_id
    }

    pub async fn preview(&self) -> Result<FutureTimestampRepairPreview> {
        let sql = preview_sql(&self.read_table, self.shape.precision, self.cutoff);
        let (
            future_rows,
            distinct_ids,
            oldest_future,
            newest_future,
            recoverable_epoch_millis_rows,
        ): (u64, u64, String, String, u64) = self
            .client
            .query(&sql)
            .fetch_one()
            .await
            .context("previewing far-future events")?;
        let collisions: u64 = self
            .client
            .query(&collision_sql(
                &self.read_table,
                self.shape.precision,
                self.cutoff,
            ))
            .fetch_one()
            .await
            .context("checking repair id collisions")?;
        Ok(FutureTimestampRepairPreview {
            table: self.read_table.clone(),
            future_rows,
            distinct_ids,
            existing_id_collisions: collisions,
            oldest_future,
            newest_future,
            recoverable_epoch_millis_rows,
            cutoff: self.cutoff,
            clamped_at: self.clamped_at,
        })
    }

    /// Preview the four NAN-4938 DateTime64(3) table classes. Missing tables
    /// are omitted so the same operator binary works during partial upgrades.
    /// Every predicate proves the stored raw ticks have the exact
    /// epoch-milliseconds-as-seconds shape and that `/ 1000` lands in the
    /// deployment's plausible source-time window.
    pub async fn preview_epoch_millis_tables(&self) -> Result<Vec<EpochMillisRepairPreview>> {
        let mut previews = Vec::new();
        for shape in EpochMillisRepairShape::ALL {
            let Some(table) = self.resolve_read_table(shape.table()).await? else {
                continue;
            };
            let (affected_rows, distinct_rows, oldest_recovered, newest_recovered): (
                u64,
                u64,
                String,
                String,
            ) = self
                .client
                .query(&epoch_millis_preview_sql(shape, &table, self.cutoff))
                .fetch_one()
                .await
                .with_context(|| format!("previewing NAN-4938 rows in {table}"))?;
            previews.push(EpochMillisRepairPreview {
                table,
                source_table: shape.table().to_string(),
                affected_rows,
                distinct_rows,
                pending_buffer_rows: if shape == EpochMillisRepairShape::IpEnrichments {
                    self.client
                        .query(&format!(
                            "SELECT count() FROM {}.{}",
                            self.database, FUTURE_IP_REPAIR_ROWS_TABLE
                        ))
                        .fetch_one()
                        .await
                        .context("previewing pending buffered IP repair rows")?
                } else {
                    0
                },
                oldest_recovered,
                newest_recovered,
            });
        }
        Ok(previews)
    }

    async fn resolve_read_table(&self, table: &str) -> Result<Option<String>> {
        let escaped_database = crate::sql_hygiene::escape_sql_string(self.database);
        let escaped_table = crate::sql_hygiene::escape_sql_string(table);
        let distributed = format!("{table}_distributed");
        let escaped_distributed = crate::sql_hygiene::escape_sql_string(&distributed);
        let (local_exists, distributed_exists): (u64, u64) = self
            .client
            .query(&format!(
                "SELECT countIf(name = '{escaped_table}'), countIf(name = '{escaped_distributed}') \
                 FROM system.tables WHERE database = '{escaped_database}'"
            ))
            .fetch_one()
            .await
            .with_context(|| {
                format!(
                    "resolving repair table {self_database}.{table}",
                    self_database = self.database
                )
            })?;
        if local_exists == 0 {
            return Ok(None);
        }
        Ok(Some(if distributed_exists > 0 {
            format!("{}.{}", self.database, distributed)
        } else {
            format!("{}.{}", self.database, table)
        }))
    }

    /// Atomically serialize confirmed repairs through database-object
    /// existence. `CREATE TABLE` is the compare-and-set: on explicit clusters
    /// the already-derived ON CLUSTER clause makes the object global, while a
    /// Replicated database propagates the same DDL itself. A killed owner leaves
    /// the table in place (fail closed) with an inspectable lease; only the
    /// explicit purge command may remove an expired lock.
    pub async fn acquire_confirm_lock(&self) -> Result<FutureTimestampRepairLock> {
        let table = format!("{}.{}", self.database, FUTURE_REPAIR_LOCK_TABLE);
        let lease_until = Utc::now() + Duration::seconds(FUTURE_REPAIR_LOCK_LEASE_SECONDS);
        let comment = repair_lock_comment(self.repair_id, lease_until);
        let escaped_comment = crate::sql_hygiene::escape_sql_string(&comment);
        let create = format!(
            "CREATE TABLE {table}{} \
             (owner UUID, lease_until DateTime64(6, 'UTC'), acquired_at DateTime64(6, 'UTC')) \
             ENGINE=MergeTree ORDER BY tuple() COMMENT '{escaped_comment}'",
            self.on_cluster
        );
        if let Err(error) = self.client.query(&create).execute().await {
            let existing = read_lock_comment(self.client, self.database)
                .await
                .unwrap_or_else(|_| "owner/lease unavailable".to_string());
            bail!(
                "another confirmed future-timestamp repair owns {table} ({existing}); \
                 no data changed: {error}"
            );
        }

        let foreground = self
            .client
            .clone()
            .with_option("async_insert", "0")
            .with_option("wait_for_async_insert", "1");
        foreground
            .query(&format!(
                "INSERT INTO {table} VALUES (toUUID('{}'), {}, now64(6))",
                self.repair_id,
                dt(lease_until, 6)
            ))
            .execute()
            .await
            .context(
                "the repair lock table was created but its owner row could not be recorded; \
                 leave it in place and use the expired-lock purge after the recorded lease",
            )?;

        Ok(FutureTimestampRepairLock {
            client: self.client.clone(),
            database: self.database.to_string(),
            on_cluster: self.on_cluster.clone(),
            owner: self.repair_id,
            comment,
        })
    }

    /// Inspect whether metadata for a completed repair id can be removed. This
    /// never changes tenant tables. It refuses purge while any staged bad
    /// original remains or an IP buffer row lacks a verified corrected copy.
    pub async fn preview_purge(
        &self,
        repair_id: Uuid,
    ) -> Result<FutureTimestampRepairPurgePreview> {
        let repair_set = format!("{}.{}", self.database, FUTURE_REPAIR_SET_TABLE);
        let ip_buffer = format!("{}.{}", self.database, FUTURE_IP_REPAIR_ROWS_TABLE);
        let staged_rows: u64 = self
            .client
            .query(&format!(
                "SELECT count() FROM {repair_set} WHERE repair_id=toUUID('{repair_id}')"
            ))
            .fetch_one()
            .await
            .context("reading staged repair metadata for purge")?;
        let buffered_rows: u64 = self
            .client
            .query(&format!(
                "SELECT count() FROM {ip_buffer} WHERE repair_id=toUUID('{repair_id}')"
            ))
            .fetch_one()
            .await
            .context("reading buffered IP rows for purge")?;

        let mut staged_originals_remaining = 0;
        let source_tables: Vec<String> = self
            .client
            .query(&format!(
                "SELECT DISTINCT source_table FROM {repair_set} \
                 WHERE repair_id=toUUID('{repair_id}')"
            ))
            .fetch_all()
            .await
            .context("reading staged repair table names for purge")?;
        for source_table in source_tables {
            if let Some(shape) = repair_shape_for_table(&source_table) {
                let Some(table) = self.resolve_read_table(shape.table).await? else {
                    bail!("cannot verify completed repair: {} is absent", shape.table);
                };
                staged_originals_remaining += self
                    .client
                    .query(&remaining_set_sql(&repair_set, &table, shape, repair_id))
                    .fetch_one::<u64>()
                    .await
                    .with_context(|| format!("checking remaining {source_table} originals"))?;
            } else if let Some(shape) = EpochMillisRepairShape::ALL
                .into_iter()
                .find(|shape| shape.table() == source_table)
            {
                let Some(table) = self.resolve_read_table(shape.table()).await? else {
                    bail!(
                        "cannot verify completed repair: {} is absent",
                        shape.table()
                    );
                };
                staged_originals_remaining += self
                    .client
                    .query(&epoch_millis_remaining_sql(
                        shape,
                        &repair_set,
                        &table,
                        repair_id,
                        self.cutoff,
                    ))
                    .fetch_one::<u64>()
                    .await
                    .with_context(|| format!("checking remaining {source_table} originals"))?;
            } else {
                bail!("cannot verify unknown staged repair table {source_table}");
            }
        }

        let (buffered_distinct_rows, buffered_verified_rows) = if buffered_rows == 0 {
            (0, 0)
        } else {
            let Some(table) = self.resolve_read_table("ip_enrichments").await? else {
                bail!("cannot verify buffered repair: ip_enrichments is absent");
            };
            let distinct = self
                .client
                .query(&ip_buffer_distinct_sql(&ip_buffer, repair_id, self.cutoff))
                .fetch_one()
                .await
                .context("counting buffered IP fingerprints for purge")?;
            let verified = self
                .client
                .query(&ip_buffer_verified_sql(
                    &ip_buffer,
                    &table,
                    repair_id,
                    self.cutoff,
                ))
                .fetch_one()
                .await
                .context("verifying buffered IP fingerprints for purge")?;
            (distinct, verified)
        };

        let lock_status = self.read_lock_status().await?;
        let owns_lock = lock_status
            .as_ref()
            .is_some_and(|status| status.0 == repair_id);
        let owns_expired_lock = lock_status
            .as_ref()
            .is_some_and(|status| status.0 == repair_id && status.1 <= Utc::now());
        let lock_lease_until = lock_status
            .filter(|status| status.0 == repair_id)
            .map(|status| status.1.to_rfc3339())
            .unwrap_or_default();
        Ok(FutureTimestampRepairPurgePreview {
            repair_id,
            staged_rows,
            buffered_rows,
            staged_originals_remaining,
            buffered_distinct_rows,
            buffered_verified_rows,
            owns_lock,
            owns_expired_lock,
            lock_lease_until,
        })
    }

    pub async fn purge_completed_repair(
        &self,
        preview: &FutureTimestampRepairPurgePreview,
    ) -> Result<()> {
        if preview.staged_originals_remaining != 0 {
            bail!(
                "repair {} is not complete: {} staged bad original(s) remain",
                preview.repair_id,
                preview.staged_originals_remaining
            );
        }
        if preview.buffered_verified_rows != preview.buffered_distinct_rows {
            bail!(
                "repair {} is not complete: verified {} of {} buffered IP fingerprint(s)",
                preview.repair_id,
                preview.buffered_verified_rows,
                preview.buffered_distinct_rows
            );
        }
        if preview.owns_lock && !preview.owns_expired_lock {
            bail!(
                "repair {} still holds an unexpired lock until {}; refusing purge",
                preview.repair_id,
                preview.lock_lease_until
            );
        }
        if preview.owns_expired_lock {
            self.drop_lock_for_owner(preview.repair_id).await?;
        }
        let ip_buffer = format!("{}.{}", self.database, FUTURE_IP_REPAIR_ROWS_TABLE);
        self.client
            .query(&ip_buffer_cleanup_sql(&ip_buffer, preview.repair_id))
            .execute()
            .await
            .context("purging verified IP repair buffer rows")?;
        let repair_set = format!("{}.{}", self.database, FUTURE_REPAIR_SET_TABLE);
        self.client
            .query(&cleanup_repair_id_sql(&repair_set, preview.repair_id))
            .execute()
            .await
            .context("purging completed staged repair metadata")?;
        Ok(())
    }

    async fn read_lock_status(&self) -> Result<Option<(Uuid, DateTime<Utc>)>> {
        let comment = read_lock_comment(self.client, self.database).await?;
        if comment.is_empty() {
            return Ok(None);
        }
        parse_repair_lock_comment(&comment).map(Some)
    }

    async fn drop_lock_for_owner(&self, owner: Uuid) -> Result<()> {
        let status = self.read_lock_status().await?;
        if !status.is_some_and(|status| status.0 == owner) {
            bail!("repair lock owner changed; refusing to drop the lock table");
        }
        self.client
            .query(&drop_lock_sql(
                self.database,
                &self.on_cluster,
                FUTURE_REPAIR_LOCK_TABLE,
            ))
            .execute()
            .await
            .context("dropping expired future repair lock")
    }

    /// Materialize the repair membership, copy that exact set to the clamped
    /// instant, verify it, then synchronously remove only those originals.
    ///
    /// The operator must pause ingest before calling this. New ingest is guarded
    /// by NAN-4939, but pausing also makes the preview and final verification a
    /// closed set. Incremental MVs receive the corrected copy. This operation
    /// repairs the authoritative event table; it deliberately does not issue
    /// broad mutations against independently retained aggregate tables.
    pub async fn execute(
        &self,
        preview: &FutureTimestampRepairPreview,
    ) -> Result<FutureTimestampRepairOutcome> {
        if preview.future_rows == 0 {
            return Ok(FutureTimestampRepairOutcome {
                copied_ids: 0,
                deleted_rows: 0,
            });
        }
        let repair_set = format!("{}.{}", self.database, FUTURE_REPAIR_SET_TABLE);

        // The preview is advisory. Freeze the authoritative membership at the
        // start of the confirmed run so a later future row can never be swept
        // into its DELETE mutation.
        let foreground = self
            .client
            .clone()
            .with_option("async_insert", "0")
            .with_option("wait_for_async_insert", "1")
            .with_option("insert_distributed_sync", "1");
        foreground
            .query(&materialize_sql(
                &repair_set,
                &self.read_table,
                self.shape,
                self.repair_id,
                self.cutoff,
            ))
            .execute()
            .await
            .context("materializing the exact future timestamp repair set")?;

        // The explicit-cluster staging table is one replication group across
        // every shard. Wait for every replica to receive the membership before
        // shard-local DELETE mutations evaluate their staging-table subquery.
        if let Some(sync) = sync_repair_set_sql(&repair_set, &self.on_cluster) {
            self.client
                .query(&sync)
                .execute()
                .await
                .context("synchronizing the future timestamp repair set")?;
        }

        let (repair_rows, distinct_ids): (u64, u64) = self
            .client
            .query(&repair_set_shape_sql(
                &repair_set,
                self.shape,
                self.repair_id,
            ))
            .fetch_one()
            .await
            .context("reading the materialized future timestamp repair set")?;
        if repair_rows == 0 {
            return Ok(FutureTimestampRepairOutcome {
                copied_ids: 0,
                deleted_rows: 0,
            });
        }
        let collisions: u64 = self
            .client
            .query(&repair_collision_sql(
                &repair_set,
                &self.read_table,
                self.shape,
                self.repair_id,
                self.cutoff,
            ))
            .fetch_one()
            .await
            .context("checking materialized repair id collisions")?;
        if collisions != 0 {
            bail!(
                "refusing repair: {collisions} materialized future event id(s) already collide with a non-future row"
            );
        }

        // A Distributed table normally acknowledges before its background
        // queue reaches the destination shard. Force this repair copy into the
        // foreground so verification cannot race an acknowledged, not-yet-
        // visible row (or strand a copy if the operator exits).
        foreground
            .query(&copy_sql(
                &repair_set,
                &self.read_table,
                self.shape,
                self.repair_id,
                self.clamped_at,
                self.cutoff,
            ))
            .execute()
            .await
            .context("copying future events at the clamped timestamp")?;

        let verification_sql = copied_ids_sql(
            &repair_set,
            &self.read_table,
            self.shape,
            self.repair_id,
            self.cutoff,
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let copied_ids = loop {
            let copied_ids: u64 = self
                .client
                .query(&verification_sql)
                .fetch_one()
                .await
                .context("verifying corrected event copies")?;
            if copied_ids == distinct_ids || tokio::time::Instant::now() >= deadline {
                break copied_ids;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        };
        if copied_ids != distinct_ids {
            bail!(
                "refusing to delete originals: copied {copied_ids} of {distinct_ids} distinct materialized ids"
            );
        }

        let copied_rows: u64 = self
            .client
            .query(&copied_rows_sql(
                &repair_set,
                &self.read_table,
                self.shape,
                self.repair_id,
                self.cutoff,
            ))
            .fetch_one()
            .await
            .context("verifying the corrected event row count")?;
        if copied_rows != repair_rows {
            bail!(
                "refusing to delete originals: copied {copied_rows} of {repair_rows} materialized rows"
            );
        }

        let local_table = format!("{}.{}", self.database, self.shape.table);
        let delete = delete_sql(
            &repair_set,
            &local_table,
            self.shape,
            self.repair_id,
            self.cutoff,
            &self.on_cluster,
        );
        self.client
            .query(&delete)
            .execute()
            .await
            .context("deleting verified future originals")?;

        let remaining: u64 = self
            .client
            .query(&remaining_set_sql(
                &repair_set,
                &self.read_table,
                self.shape,
                self.repair_id,
            ))
            .fetch_one()
            .await
            .context("verifying future originals were removed")?;
        if remaining != 0 {
            bail!("repair mutation completed but {remaining} materialized original rows remain");
        }

        self.client
            .query(&cleanup_sql(&repair_set, self.repair_id, self.shape.table))
            .execute()
            .await
            .context("cleaning the completed future timestamp repair set")?;

        Ok(FutureTimestampRepairOutcome {
            copied_ids,
            deleted_rows: repair_rows,
        })
    }

    /// Repair one table-specific NAN-4938 set. The authoritative membership is
    /// materialized before any write and every mutation is restricted to that
    /// fingerprint set. `user_registry` is updated in place. IP tombstones are
    /// durably buffered before delete/restore because copying a lower corrected
    /// `updated_at` beside the bad winner would let ReplacingMergeTree discard
    /// the repair before deletion. Partition-key tables use the framework's
    /// copy/verify/delete sequence so corrected rows land in the right part.
    pub async fn execute_epoch_millis_table(
        &self,
        preview: &EpochMillisRepairPreview,
    ) -> Result<EpochMillisRepairOutcome> {
        let shape = EpochMillisRepairShape::ALL
            .into_iter()
            .find(|shape| shape.table() == preview.source_table)
            .with_context(|| {
                format!(
                    "unsupported epoch-millisecond repair table {}",
                    preview.source_table
                )
            })?;
        if preview.affected_rows == 0 && preview.pending_buffer_rows == 0 {
            return Ok(EpochMillisRepairOutcome {
                table: preview.table.clone(),
                repaired_rows: 0,
                deleted_originals: 0,
            });
        }

        let Some(read_table) = self.resolve_read_table(shape.table()).await? else {
            bail!("repair table {} disappeared after preview", shape.table());
        };
        let repair_set = format!("{}.{}", self.database, FUTURE_REPAIR_SET_TABLE);
        let foreground = self
            .client
            .clone()
            .with_option("async_insert", "0")
            .with_option("wait_for_async_insert", "1")
            .with_option("insert_distributed_sync", "1");
        let ip_buffer = format!("{}.{}", self.database, FUTURE_IP_REPAIR_ROWS_TABLE);
        let mut resumed_rows = 0;
        if shape == EpochMillisRepairShape::IpEnrichments {
            // Snapshot exact ids after the confirmed-run lock is held. Every
            // restore, verification, and cleanup below is scoped to one member
            // of this immutable list; a later/manual id can never be swept by
            // another run's cleanup.
            let pending_ids: Vec<String> = self
                .client
                .query(&format!(
                    "SELECT DISTINCT toString(repair_id) FROM {ip_buffer} ORDER BY repair_id"
                ))
                .fetch_all()
                .await
                .context("snapshotting pending buffered IP repair ids")?;
            for pending_id in pending_ids {
                let pending_id =
                    Uuid::parse_str(&pending_id).context("parsing pending IP repair id")?;
                let pending_rows: u64 = self
                    .client
                    .query(&format!(
                        "SELECT count() FROM {ip_buffer} WHERE repair_id=toUUID('{pending_id}')"
                    ))
                    .fetch_one()
                    .await
                    .context("counting pending buffered IP repair rows")?;
                let pending_distinct: u64 = self
                    .client
                    .query(&ip_buffer_distinct_sql(&ip_buffer, pending_id, self.cutoff))
                    .fetch_one()
                    .await
                    .context("reading pending buffered IP repair rows")?;
                foreground
                    .query(&ip_buffer_restore_sql(&ip_buffer, &read_table, pending_id))
                    .execute()
                    .await
                    .context("resuming buffered ip_enrichments repair rows")?;
                let verified: u64 = self
                    .client
                    .query(&ip_buffer_verified_sql(
                        &ip_buffer,
                        &read_table,
                        pending_id,
                        self.cutoff,
                    ))
                    .fetch_one()
                    .await
                    .context("verifying resumed ip_enrichments repair rows")?;
                if verified != pending_distinct {
                    bail!(
                        "refusing to clear IP repair buffer {pending_id}: verified {verified} of {pending_distinct} pending rows"
                    );
                }
                self.client
                    .query(&ip_buffer_cleanup_sql(&ip_buffer, pending_id))
                    .execute()
                    .await
                    .context("cleaning resumed ip_enrichments repair rows")?;
                resumed_rows += pending_rows;
            }
        }
        if preview.affected_rows == 0 {
            return Ok(EpochMillisRepairOutcome {
                table: read_table,
                repaired_rows: resumed_rows,
                deleted_originals: 0,
            });
        }
        foreground
            .query(&epoch_millis_materialize_sql(
                shape,
                &repair_set,
                &read_table,
                self.repair_id,
                self.cutoff,
            ))
            .execute()
            .await
            .with_context(|| format!("materializing the exact {} repair set", shape.table()))?;

        if let Some(sync) = sync_repair_set_sql(&repair_set, &self.on_cluster) {
            self.client
                .query(&sync)
                .execute()
                .await
                .with_context(|| format!("synchronizing the {} repair set", shape.table()))?;
        }

        let (repair_rows, distinct_rows): (u64, u64) = self
            .client
            .query(&epoch_millis_repair_set_shape_sql(
                &repair_set,
                shape,
                self.repair_id,
            ))
            .fetch_one()
            .await
            .with_context(|| format!("reading the materialized {} repair set", shape.table()))?;
        if repair_rows == 0 {
            return Ok(EpochMillisRepairOutcome {
                table: read_table,
                repaired_rows: 0,
                deleted_originals: 0,
            });
        }

        let local_table = format!("{}.{}", self.database, shape.table());
        let mut deleted_originals = 0;
        if shape == EpochMillisRepairShape::IpEnrichments {
            foreground
                .query(&ip_buffer_materialize_sql(
                    &ip_buffer,
                    &repair_set,
                    &read_table,
                    self.repair_id,
                    self.cutoff,
                ))
                .execute()
                .await
                .context("durably buffering exact ip_enrichments tombstones")?;
            if let Some(sync) = sync_repair_set_sql(&ip_buffer, &self.on_cluster) {
                self.client
                    .query(&sync)
                    .execute()
                    .await
                    .context("synchronizing buffered ip_enrichments tombstones")?;
            }
            let buffered_distinct: u64 = self
                .client
                .query(&ip_buffer_distinct_sql(
                    &ip_buffer,
                    self.repair_id,
                    self.cutoff,
                ))
                .fetch_one()
                .await
                .context("verifying buffered ip_enrichments tombstones")?;
            if buffered_distinct != distinct_rows {
                bail!(
                    "refusing IP repair: durably buffered {buffered_distinct} of {distinct_rows} distinct tombstones"
                );
            }
            self.client
                .query(&epoch_millis_delete_sql(
                    shape,
                    &repair_set,
                    &local_table,
                    self.repair_id,
                    self.cutoff,
                    &self.on_cluster,
                ))
                .execute()
                .await
                .context("deleting exact bad ip_enrichments winners")?;
            foreground
                .query(&ip_buffer_restore_sql(
                    &ip_buffer,
                    &read_table,
                    self.repair_id,
                ))
                .execute()
                .await
                .context("restoring corrected ip_enrichments tombstones")?;
            deleted_originals = repair_rows;
        } else if shape.uses_update_mutation() {
            self.client
                .query(&epoch_millis_update_sql(
                    shape,
                    &repair_set,
                    &local_table,
                    self.repair_id,
                    self.cutoff,
                    &self.on_cluster,
                ))
                .execute()
                .await
                .with_context(|| format!("updating exact {} repair rows", shape.table()))?;
        } else {
            foreground
                .query(&epoch_millis_copy_sql(
                    shape,
                    &repair_set,
                    &read_table,
                    self.repair_id,
                    self.cutoff,
                ))
                .execute()
                .await
                .with_context(|| format!("copying corrected {} rows", shape.table()))?;
        }

        let verified_distinct: u64 = self
            .client
            .query(&epoch_millis_verified_sql(
                shape,
                &repair_set,
                &read_table,
                self.repair_id,
                self.cutoff,
            ))
            .fetch_one()
            .await
            .with_context(|| format!("verifying corrected {} rows", shape.table()))?;
        if verified_distinct != distinct_rows {
            bail!(
                "refusing to remove originals: verified {verified_distinct} of {distinct_rows} distinct {} repair rows",
                shape.table()
            );
        }

        if !shape.uses_update_mutation() && shape != EpochMillisRepairShape::IpEnrichments {
            self.client
                .query(&epoch_millis_delete_sql(
                    shape,
                    &repair_set,
                    &local_table,
                    self.repair_id,
                    self.cutoff,
                    &self.on_cluster,
                ))
                .execute()
                .await
                .with_context(|| format!("deleting exact {} originals", shape.table()))?;
            deleted_originals = repair_rows;
        }

        let remaining: u64 = self
            .client
            .query(&epoch_millis_remaining_sql(
                shape,
                &repair_set,
                &read_table,
                self.repair_id,
                self.cutoff,
            ))
            .fetch_one()
            .await
            .with_context(|| format!("verifying {} originals were removed", shape.table()))?;
        if remaining != 0 {
            bail!(
                "{} repair completed but {remaining} staged original row(s) remain",
                shape.table()
            );
        }

        self.client
            .query(&cleanup_sql(&repair_set, self.repair_id, shape.table()))
            .execute()
            .await
            .with_context(|| format!("cleaning the completed {} repair set", shape.table()))?;
        if shape == EpochMillisRepairShape::IpEnrichments {
            self.client
                .query(&ip_buffer_cleanup_sql(&ip_buffer, self.repair_id))
                .execute()
                .await
                .context("cleaning the completed ip_enrichments repair buffer")?;
        }

        Ok(EpochMillisRepairOutcome {
            table: read_table,
            repaired_rows: repair_rows + resumed_rows,
            deleted_originals,
        })
    }
}

impl FutureTimestampRepairLock {
    pub const fn owner(&self) -> Uuid {
        self.owner
    }

    pub async fn release(self) -> Result<()> {
        let current = read_lock_comment(&self.client, &self.database)
            .await
            .context("reading future repair lock before release")?;
        if current != self.comment {
            bail!(
                "future repair lock owner changed before release; expected {}, found {current:?}",
                self.owner
            );
        }
        self.client
            .query(&drop_lock_sql(
                &self.database,
                &self.on_cluster,
                FUTURE_REPAIR_LOCK_TABLE,
            ))
            .execute()
            .await
            .context("releasing the confirmed future repair lock")
    }
}

async fn resolve_repair_on_cluster(client: &clickhouse::Client, database: &str) -> Result<String> {
    let escaped_database = crate::sql_hygiene::escape_sql_string(database);
    let distributed_wrappers: u64 = client
        .query(&format!(
            "SELECT count() FROM system.tables WHERE database='{escaped_database}' AND name IN \
             ('logs_distributed','ocsf_logs_distributed','ip_enrichments_distributed', \
              'custom_enrichment_results_distributed','user_registry_distributed', \
              'synthetic_check_results_distributed')"
        ))
        .fetch_one()
        .await
        .context("detecting Distributed tables for future timestamp repair")?;
    if distributed_wrappers == 0 {
        return Ok(String::new());
    }
    let cluster = super::clickhouse_migrate::configured_or_detected_cluster(client)
        .await
        .context(
            "Distributed repair tables exist but the ClickHouse cluster name could not be probed",
        )?
        .context(
            "Distributed repair tables exist but no multi-node cluster is configured or detectable; \
             refusing a cluster-wide stage followed by node-local mutations",
        )?;
    let database_engine: String = client
        .query(&format!(
            "SELECT engine FROM system.databases WHERE name='{escaped_database}'"
        ))
        .fetch_one()
        .await
        .context("detecting whether the repair database propagates DDL")?;
    if database_engine == "Replicated" {
        // Replicated databases route CREATE/ALTER/DROP through their Keeper DDL
        // log. Adding ON CLUSTER would duplicate that propagation (and CH Cloud
        // rejects several explicit-cluster forms), matching migrator behavior.
        return Ok(String::new());
    }
    Ok(super::dual_pool::format_on_cluster(Some(&cluster)))
}

fn repair_shape_for_table(table: &str) -> Option<RepairShape> {
    match table {
        "logs" => Some(RepairShape {
            table: "logs",
            precision: 6,
            preserves_original_column: true,
        }),
        "ocsf_logs" => Some(RepairShape {
            table: "ocsf_logs",
            precision: 3,
            preserves_original_column: false,
        }),
        _ => None,
    }
}

fn repair_lock_comment(owner: Uuid, lease_until: DateTime<Utc>) -> String {
    format!(
        "owner={owner};lease_until={}",
        lease_until.to_rfc3339_opts(SecondsFormat::Micros, true)
    )
}

fn parse_repair_lock_comment(comment: &str) -> Result<(Uuid, DateTime<Utc>)> {
    let (owner, lease) = comment
        .strip_prefix("owner=")
        .and_then(|rest| rest.split_once(";lease_until="))
        .context("invalid future repair lock metadata")?;
    let owner = Uuid::parse_str(owner).context("invalid future repair lock owner")?;
    let lease = DateTime::parse_from_rfc3339(lease)
        .map(|value| value.with_timezone(&Utc))
        .context("invalid future repair lock lease")?;
    Ok((owner, lease))
}

async fn read_lock_comment(client: &clickhouse::Client, database: &str) -> Result<String> {
    let escaped_database = crate::sql_hygiene::escape_sql_string(database);
    let rows: Vec<String> = client
        .query(&format!(
            "SELECT comment FROM system.tables WHERE database='{escaped_database}' \
             AND name='{FUTURE_REPAIR_LOCK_TABLE}'"
        ))
        .fetch_all()
        .await
        .context("reading future repair lock metadata")?;
    Ok(rows.into_iter().next().unwrap_or_default())
}

fn drop_lock_sql(database: &str, on_cluster: &str, table: &str) -> String {
    format!("DROP TABLE {database}.{table}{on_cluster} SYNC")
}

fn dt(value: DateTime<Utc>, precision: u8) -> String {
    let value = value.to_rfc3339_opts(SecondsFormat::Micros, true);
    format!("toDateTime64('{value}', {precision}, 'UTC')")
}

fn predicate(precision: u8, cutoff: DateTime<Utc>) -> String {
    format!("timestamp > {}", dt(cutoff, precision))
}

fn timestamp_ticks(column: &str, precision: u8) -> String {
    match precision {
        3 => format!("toUnixTimestamp64Milli({column})"),
        6 => format!("toUnixTimestamp64Micro({column})"),
        _ => unreachable!("repair supports only DateTime64(3) and DateTime64(6)"),
    }
}

/// Encode raw DateTime64 ticks losslessly in the staging table's DateTime64(6)
/// column. `toDateTime64(dt3, 6)` is not safe here: 26.10 saturates a NAN-4938
/// far-future value while 26.8 retains it. Treating the raw integer as
/// microseconds is stable on both versions and remains exactly reversible.
fn staged_timestamp(column: &str, precision: u8) -> String {
    format!(
        "fromUnixTimestamp64Micro({}, 'UTC')",
        timestamp_ticks(column, precision)
    )
}

fn epoch_millis_as_seconds_predicate(column: &str, cutoff: DateTime<Utc>) -> String {
    let ticks = timestamp_ticks(column, 3);
    format!(
        "({ticks} >= {EPOCH_MILLIS_AS_SECONDS_MIN_TICKS} AND \
         intDiv({ticks}, 1000) BETWEEN {MIN_PLAUSIBLE_SOURCE_EPOCH_MS} AND {})",
        cutoff.timestamp_millis()
    )
}

fn recovered_epoch_millis(column: &str) -> String {
    format!(
        "fromUnixTimestamp64Milli(intDiv({}, 1000), 'UTC')",
        timestamp_ticks(column, 3)
    )
}

fn preview_sql(table: &str, precision: u8, cutoff: DateTime<Utc>) -> String {
    let recoverable = if precision == 3 {
        format!(
            "countIf({})",
            epoch_millis_as_seconds_predicate("timestamp", cutoff)
        )
    } else {
        "toUInt64(0)".to_string()
    };
    format!(
        "SELECT count(), uniqExact(id), if(count() = 0, '', toString(min(timestamp))), \
         if(count() = 0, '', toString(max(timestamp))), {recoverable} \
         FROM {table} WHERE {}",
        predicate(precision, cutoff)
    )
}

fn collision_sql(table: &str, precision: u8, cutoff: DateTime<Utc>) -> String {
    let cutoff = dt(cutoff, precision);
    format!(
        "SELECT count() FROM (SELECT id FROM {table} \
         WHERE id GLOBAL IN (SELECT id FROM {table} WHERE timestamp > {cutoff}) \
         GROUP BY id HAVING countIf(timestamp <= {cutoff}) > 0)"
    )
}

fn repair_filter(_repair_set: &str, shape: RepairShape, repair_id: Uuid) -> String {
    format!(
        "repair_id = toUUID('{repair_id}') AND source_table = '{}'",
        shape.table
    )
}

fn materialize_sql(
    repair_set: &str,
    table: &str,
    shape: RepairShape,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    format!(
        "INSERT INTO {repair_set} (repair_id, source_table, event_id, source_timestamp) \
         SELECT toUUID('{repair_id}'), '{}', id, {} \
         FROM {table} WHERE {}",
        shape.table,
        staged_timestamp("timestamp", shape.precision),
        predicate(shape.precision, cutoff)
    )
}

fn repair_set_shape_sql(repair_set: &str, shape: RepairShape, repair_id: Uuid) -> String {
    format!(
        "SELECT count(), uniqExact(event_id) FROM {repair_set} WHERE {}",
        repair_filter(repair_set, shape, repair_id)
    )
}

fn repair_collision_sql(
    repair_set: &str,
    table: &str,
    shape: RepairShape,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    format!(
        "SELECT count() FROM (SELECT id FROM {table} \
         WHERE id GLOBAL IN (SELECT event_id FROM {repair_set} WHERE {}) \
         GROUP BY id HAVING countIf(timestamp <= {}) > 0)",
        repair_filter(repair_set, shape, repair_id),
        dt(cutoff, shape.precision)
    )
}

fn copy_sql(
    repair_set: &str,
    table: &str,
    shape: RepairShape,
    repair_id: Uuid,
    clamped_at: DateTime<Utc>,
    cutoff: DateTime<Utc>,
) -> String {
    let clamped = dt(clamped_at, shape.precision);
    let replacement_timestamp = if shape.precision == 3 {
        format!(
            "if({}, {}, {clamped})",
            epoch_millis_as_seconds_predicate("source.timestamp", cutoff),
            recovered_epoch_millis("source.timestamp")
        )
    } else {
        clamped.clone()
    };
    let replacements = if shape.preserves_original_column {
        format!(
            "{replacement_timestamp} AS timestamp, \
             if(source.original_timestamp = '', toString(source.timestamp), source.original_timestamp) AS original_timestamp"
        )
    } else {
        format!("{replacement_timestamp} AS timestamp")
    };
    format!(
        "INSERT INTO {table} SELECT * REPLACE({replacements}) FROM {table} AS source \
         WHERE (source.id, {}) GLOBAL IN \
         (SELECT event_id, source_timestamp FROM {repair_set} WHERE {})",
        staged_timestamp("source.timestamp", shape.precision),
        repair_filter(repair_set, shape, repair_id)
    )
}

fn copied_ids_sql(
    repair_set: &str,
    table: &str,
    shape: RepairShape,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    format!(
        "SELECT uniqExact(id) FROM {table} WHERE timestamp <= {} \
         AND id GLOBAL IN (SELECT event_id FROM {repair_set} WHERE {})",
        dt(cutoff, shape.precision),
        repair_filter(repair_set, shape, repair_id)
    )
}

fn copied_rows_sql(
    repair_set: &str,
    table: &str,
    shape: RepairShape,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    format!(
        "SELECT count() FROM {table} WHERE timestamp <= {} \
         AND id GLOBAL IN (SELECT event_id FROM {repair_set} WHERE {})",
        dt(cutoff, shape.precision),
        repair_filter(repair_set, shape, repair_id)
    )
}

fn delete_sql(
    repair_set: &str,
    local_table: &str,
    shape: RepairShape,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
    on_cluster: &str,
) -> String {
    format!(
        "ALTER TABLE {local_table}{on_cluster} DELETE WHERE {} AND \
         (id, {}) IN \
         (SELECT event_id, source_timestamp FROM {repair_set} WHERE {}) \
         SETTINGS mutations_sync = 2",
        predicate(shape.precision, cutoff),
        staged_timestamp("timestamp", shape.precision),
        repair_filter(repair_set, shape, repair_id)
    )
}

fn remaining_set_sql(repair_set: &str, table: &str, shape: RepairShape, repair_id: Uuid) -> String {
    format!(
        "SELECT count() FROM {table} WHERE \
         (id, {}) GLOBAL IN \
         (SELECT event_id, source_timestamp FROM {repair_set} WHERE {})",
        staged_timestamp("timestamp", shape.precision),
        repair_filter(repair_set, shape, repair_id)
    )
}

fn column(alias: &str, name: &str) -> String {
    if alias.is_empty() {
        name.to_string()
    } else {
        format!("{alias}.{name}")
    }
}

fn normalized_epoch_millis(column: &str, row_is_bad: &str) -> String {
    let ticks = timestamp_ticks(column, 3);
    format!("if({row_is_bad}, intDiv({ticks}, 1000), {ticks})")
}

fn epoch_millis_target_predicate(
    shape: EpochMillisRepairShape,
    alias: &str,
    cutoff: DateTime<Utc>,
) -> String {
    let timestamp = match shape {
        EpochMillisRepairShape::IpEnrichments => column(alias, "updated_at"),
        EpochMillisRepairShape::CustomEnrichmentResults => column(alias, "fetched_at"),
        EpochMillisRepairShape::UserRegistry => column(alias, "last_synced_at"),
        EpochMillisRepairShape::SyntheticCheckResults => column(alias, "timestamp"),
    };
    let epoch_shape = epoch_millis_as_seconds_predicate(&timestamp, cutoff);
    if shape == EpochMillisRepairShape::IpEnrichments {
        format!("({} = 1 AND {epoch_shape})", column(alias, "deleted"))
    } else {
        epoch_shape
    }
}

/// Stable semantic row identity. The source's bad timestamp and the repaired
/// row intentionally fingerprint identically: the former is normalized by
/// `/ 1000`, while the latter is already a normal DateTime64(3). Including the
/// natural key, generation/version, and relevant values makes the staged set
/// exact without widening the existing cluster-global staging-table schema.
fn epoch_millis_fingerprint(
    shape: EpochMillisRepairShape,
    alias: &str,
    cutoff: DateTime<Utc>,
) -> String {
    let bad = epoch_millis_target_predicate(shape, alias, cutoff);
    let fields = match shape {
        EpochMillisRepairShape::IpEnrichments => vec![
            column(alias, "source_id"),
            column(alias, "network"),
            normalized_epoch_millis(&column(alias, "updated_at"), &bad),
            column(alias, "deleted"),
        ],
        EpochMillisRepairShape::CustomEnrichmentResults => vec![
            column(alias, "namespace"),
            column(alias, "enrichment_id"),
            column(alias, "enrichment_name"),
            column(alias, "key_type"),
            column(alias, "key_value"),
            normalized_epoch_millis(&column(alias, "fetched_at"), &bad),
            normalized_epoch_millis(&column(alias, "expires_at"), &bad),
            column(alias, "version"),
        ],
        EpochMillisRepairShape::UserRegistry => vec![
            column(alias, "provider_id"),
            column(alias, "external_id"),
            normalized_epoch_millis(&column(alias, "last_sign_in_at"), &bad),
            normalized_epoch_millis(&column(alias, "created_in_directory_at"), &bad),
            normalized_epoch_millis(&column(alias, "last_synced_at"), &bad),
            column(alias, "version"),
            column(alias, "account_status"),
        ],
        EpochMillisRepairShape::SyntheticCheckResults => vec![
            column(alias, "check_id"),
            normalized_epoch_millis(&column(alias, "timestamp"), &bad),
            column(alias, "success"),
            column(alias, "latency_ms"),
            column(alias, "status_code"),
            column(alias, "error"),
        ],
    };
    format!(
        "reinterpretAsUUID(sipHash128(tuple({})))",
        fields.join(", ")
    )
}

fn epoch_millis_recovered_primary(shape: EpochMillisRepairShape, alias: &str) -> String {
    let timestamp = match shape {
        EpochMillisRepairShape::IpEnrichments => column(alias, "updated_at"),
        EpochMillisRepairShape::CustomEnrichmentResults => column(alias, "fetched_at"),
        EpochMillisRepairShape::UserRegistry => column(alias, "last_synced_at"),
        EpochMillisRepairShape::SyntheticCheckResults => column(alias, "timestamp"),
    };
    recovered_epoch_millis(&timestamp)
}

fn epoch_millis_preview_sql(
    shape: EpochMillisRepairShape,
    table: &str,
    cutoff: DateTime<Utc>,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "", cutoff);
    let recovered = epoch_millis_recovered_primary(shape, "");
    format!(
        "SELECT count(), uniqExact({fingerprint}), \
         if(count() = 0, '', toString(min({recovered}))), \
         if(count() = 0, '', toString(max({recovered}))) \
         FROM {table} WHERE {predicate}"
    )
}

fn epoch_millis_filter(shape: EpochMillisRepairShape, repair_id: Uuid) -> String {
    format!(
        "repair_id = toUUID('{repair_id}') AND source_table = '{}'",
        shape.table()
    )
}

fn epoch_millis_materialize_sql(
    shape: EpochMillisRepairShape,
    repair_set: &str,
    table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "source", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "source", cutoff);
    let recovered_ms = normalized_epoch_millis(
        &match shape {
            EpochMillisRepairShape::IpEnrichments => column("source", "updated_at"),
            EpochMillisRepairShape::CustomEnrichmentResults => column("source", "fetched_at"),
            EpochMillisRepairShape::UserRegistry => column("source", "last_synced_at"),
            EpochMillisRepairShape::SyntheticCheckResults => column("source", "timestamp"),
        },
        &predicate,
    );
    format!(
        "INSERT INTO {repair_set} (repair_id, source_table, event_id, source_timestamp) \
         SELECT toUUID('{repair_id}'), '{}', {fingerprint}, \
                fromUnixTimestamp64Micro({recovered_ms} * 1000, 'UTC') \
         FROM {table} AS source WHERE {predicate}",
        shape.table()
    )
}

fn epoch_millis_repair_set_shape_sql(
    repair_set: &str,
    shape: EpochMillisRepairShape,
    repair_id: Uuid,
) -> String {
    format!(
        "SELECT count(), uniqExact(event_id) FROM {repair_set} WHERE {}",
        epoch_millis_filter(shape, repair_id)
    )
}

fn epoch_millis_replacements(shape: EpochMillisRepairShape, alias: &str) -> String {
    match shape {
        EpochMillisRepairShape::CustomEnrichmentResults => format!(
            "{} AS fetched_at, {} AS expires_at",
            recovered_epoch_millis(&column(alias, "fetched_at")),
            recovered_epoch_millis(&column(alias, "expires_at"))
        ),
        EpochMillisRepairShape::SyntheticCheckResults => format!(
            "{} AS timestamp",
            recovered_epoch_millis(&column(alias, "timestamp"))
        ),
        _ => unreachable!("only partition-key repairs use copy replacements"),
    }
}

fn epoch_millis_copy_sql(
    shape: EpochMillisRepairShape,
    repair_set: &str,
    table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "source", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "source", cutoff);
    let corrected_predicate = epoch_millis_target_predicate(shape, "corrected", cutoff);
    let corrected_fingerprint = epoch_millis_fingerprint(shape, "corrected", cutoff);
    let filter = epoch_millis_filter(shape, repair_id);
    format!(
        "INSERT INTO {table} SELECT * REPLACE({}) FROM {table} AS source \
         WHERE {predicate} AND {fingerprint} GLOBAL IN \
         (SELECT event_id FROM {repair_set} WHERE {filter}) \
         AND {fingerprint} GLOBAL NOT IN \
         (SELECT {corrected_fingerprint} FROM {table} AS corrected \
          WHERE NOT {corrected_predicate} AND {corrected_fingerprint} GLOBAL IN \
          (SELECT event_id FROM {repair_set} WHERE {filter}))",
        epoch_millis_replacements(shape, "source"),
    )
}

fn epoch_millis_update_sql(
    shape: EpochMillisRepairShape,
    repair_set: &str,
    local_table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
    on_cluster: &str,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "", cutoff);
    let assignments = match shape {
        EpochMillisRepairShape::IpEnrichments => {
            format!("updated_at = {}", recovered_epoch_millis("updated_at"))
        }
        EpochMillisRepairShape::UserRegistry => format!(
            "last_sign_in_at = {}, created_in_directory_at = {}, last_synced_at = {}",
            recovered_epoch_millis("last_sign_in_at"),
            recovered_epoch_millis("created_in_directory_at"),
            recovered_epoch_millis("last_synced_at")
        ),
        _ => unreachable!("copy repairs do not use UPDATE"),
    };
    format!(
        "ALTER TABLE {local_table}{on_cluster} UPDATE {assignments} \
         WHERE {predicate} AND {fingerprint} IN \
         (SELECT event_id FROM {repair_set} WHERE {}) \
         SETTINGS mutations_sync = 2",
        epoch_millis_filter(shape, repair_id)
    )
}

fn epoch_millis_verified_sql(
    shape: EpochMillisRepairShape,
    repair_set: &str,
    table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "", cutoff);
    format!(
        "SELECT uniqExact({fingerprint}) FROM {table} WHERE NOT {predicate} \
         AND {fingerprint} GLOBAL IN \
         (SELECT event_id FROM {repair_set} WHERE {})",
        epoch_millis_filter(shape, repair_id)
    )
}

fn epoch_millis_delete_sql(
    shape: EpochMillisRepairShape,
    repair_set: &str,
    local_table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
    on_cluster: &str,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "", cutoff);
    format!(
        "ALTER TABLE {local_table}{on_cluster} DELETE WHERE {predicate} \
         AND {fingerprint} IN (SELECT event_id FROM {repair_set} WHERE {}) \
         SETTINGS mutations_sync = 2",
        epoch_millis_filter(shape, repair_id)
    )
}

fn epoch_millis_remaining_sql(
    shape: EpochMillisRepairShape,
    repair_set: &str,
    table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    let predicate = epoch_millis_target_predicate(shape, "", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "", cutoff);
    format!(
        "SELECT count() FROM {table} WHERE {predicate} AND {fingerprint} GLOBAL IN \
         (SELECT event_id FROM {repair_set} WHERE {})",
        epoch_millis_filter(shape, repair_id)
    )
}

const IP_BUFFER_COLUMNS: &str = "network, source_id, country, country_code, continent, \
    continent_code, asn, as_name, as_domain, updated_at, deleted";

fn ip_buffer_materialize_sql(
    buffer: &str,
    repair_set: &str,
    table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    let shape = EpochMillisRepairShape::IpEnrichments;
    let predicate = epoch_millis_target_predicate(shape, "source", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "source", cutoff);
    format!(
        "INSERT INTO {buffer} (repair_id, {IP_BUFFER_COLUMNS}) \
         SELECT toUUID('{repair_id}'), {IP_BUFFER_COLUMNS} FROM {table} AS source \
         WHERE {predicate} AND {fingerprint} GLOBAL IN \
         (SELECT event_id FROM {repair_set} WHERE {})",
        epoch_millis_filter(shape, repair_id)
    )
}

fn ip_buffer_distinct_sql(buffer: &str, repair_id: Uuid, cutoff: DateTime<Utc>) -> String {
    format!(
        "SELECT uniqExact({}) FROM {buffer} WHERE repair_id = toUUID('{repair_id}')",
        epoch_millis_fingerprint(EpochMillisRepairShape::IpEnrichments, "", cutoff)
    )
}

fn ip_buffer_restore_sql(buffer: &str, table: &str, repair_id: Uuid) -> String {
    format!(
        "INSERT INTO {table} ({IP_BUFFER_COLUMNS}) \
         SELECT network, source_id, country, country_code, continent, continent_code, \
                asn, as_name, as_domain, {}, deleted \
         FROM {buffer} WHERE repair_id = toUUID('{repair_id}')",
        recovered_epoch_millis("updated_at")
    )
}

fn ip_buffer_verified_sql(
    buffer: &str,
    table: &str,
    repair_id: Uuid,
    cutoff: DateTime<Utc>,
) -> String {
    let shape = EpochMillisRepairShape::IpEnrichments;
    let predicate = epoch_millis_target_predicate(shape, "", cutoff);
    let fingerprint = epoch_millis_fingerprint(shape, "", cutoff);
    let buffered_fingerprint = epoch_millis_fingerprint(shape, "buffered", cutoff);
    format!(
        "SELECT uniqExact({fingerprint}) FROM {table} WHERE NOT {predicate} \
         AND {fingerprint} GLOBAL IN \
         (SELECT {buffered_fingerprint} FROM {buffer} AS buffered \
          WHERE repair_id=toUUID('{repair_id}'))"
    )
}

fn ip_buffer_cleanup_sql(buffer: &str, repair_id: Uuid) -> String {
    format!(
        "ALTER TABLE {buffer} DELETE WHERE repair_id = toUUID('{repair_id}') \
         SETTINGS mutations_sync = 2"
    )
}

fn cleanup_sql(repair_set: &str, repair_id: Uuid, source_table: &str) -> String {
    format!(
        "ALTER TABLE {repair_set} DELETE WHERE repair_id = toUUID('{repair_id}') \
         AND source_table = '{source_table}' \
         SETTINGS mutations_sync = 2"
    )
}

fn cleanup_repair_id_sql(repair_set: &str, repair_id: Uuid) -> String {
    format!(
        "ALTER TABLE {repair_set} DELETE WHERE repair_id = toUUID('{repair_id}') \
         SETTINGS mutations_sync = 2"
    )
}

fn sync_repair_set_sql(repair_set: &str, on_cluster: &str) -> Option<String> {
    (!on_cluster.is_empty()).then(|| format!("SYSTEM SYNC REPLICA{on_cluster} {repair_set}"))
}

#[cfg(test)]
#[path = "future_timestamp_repair_tests.rs"]
mod tests;
