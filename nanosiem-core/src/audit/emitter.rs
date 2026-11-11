// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Event Emitter
//!
//! Writes audit events directly to ClickHouse for searchability.

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use super::outbox::SecurityAuditOutbox;
use super::AuditEvent;
use crate::db::DualPool;
use crate::ingestion::ClickHouseLogRow;

/// Audit event emitter for storing platform audit events
///
/// This writes audit events directly to ClickHouse as searchable logs
/// with source_type='audit'.
///
/// The UDM row always goes to the shard-local UDM logs table. Clustered reads
/// still use the distributed wrapper, so the audit page sees the complete
/// canonical audit store without re-fanning an already shard-routed write.
/// Under the OCSF profile an OCSF API Activity (6003) mirror row is
/// additionally written to the profile's `ocsf_logs` table so AUDIT_VIEW
/// principals can find audit events from the search bar, which reads
/// `ocsf_logs` under OCSF (NAN-1390 / G16).
///
/// Security-critical events ([`Self::emit_durable`]) are first recorded in the
/// PostgreSQL `security_audit_events` table (NAN-4954), so a ClickHouse
/// failure defers their delivery instead of losing them.
pub struct AuditEmitter {
    dual_pool: DualPool,
    /// Whether the active schema profile is OCSF (resolved once at
    /// construction; the profile is boot-fixed env config). Drives the
    /// `ocsf_logs` mirror write.
    mirror_to_ocsf: bool,
    /// PostgreSQL record of truth + delivery outbox for security-critical
    /// events (NAN-4954).
    outbox: SecurityAuditOutbox,
}

/// How a security-critical event was persisted by [`AuditEmitter::emit_durable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableOutcome {
    /// Recorded in PostgreSQL and written to ClickHouse.
    Delivered,
    /// Recorded in PostgreSQL; the ClickHouse write failed. The outbox drainer
    /// delivers it once ClickHouse accepts writes again. Not a loss.
    Deferred { clickhouse_error: String },
    /// Written to ClickHouse, but the PostgreSQL record failed. The ClickHouse
    /// copy is durable (synchronous insert); only the PostgreSQL copy is missing.
    DeliveredWithoutRecord { record_error: String },
}

/// Content-derived id of an event's UDM row (stable across re-deliveries
/// because the row is dated at `occurred_at`).
pub(crate) fn udm_row_id(event: &AuditEvent) -> uuid::Uuid {
    ClickHouseLogRow::from_parsed_log(&event.to_parsed_log(), Utc::now()).id
}

/// Bound on the PostgreSQL outbox write, so a stuck control-plane DB cannot
/// hold an audit task (the ClickHouse write is still attempted after it).
const OUTBOX_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a bounded ClickHouse insert did not land.
#[derive(Debug)]
enum InsertFailure {
    /// The process-global insert bound was full.
    Saturated,
    /// The insert exceeded the backstop timeout.
    Timeout,
    /// ClickHouse returned an error.
    Storage(String),
}

impl std::fmt::Display for InsertFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saturated => write!(f, "audit insert concurrency bound saturated"),
            Self::Timeout => write!(f, "audit insert timed out"),
            Self::Storage(e) => write!(f, "{e}"),
        }
    }
}

/// Process-global backstop bound on concurrent audit ClickHouse inserts
/// (NAN-1625). EVERY audit insert — whether dispatched by the API layer
/// (`AppState::emit_audit`) or issued by a DIRECT caller that holds its own
/// `AuditEmitter` (the health scheduler, the disk-pressure monitor, …) — funnels
/// through [`AuditEmitter::emit_batch_inner`], which acquires a permit here. That
/// makes the whole audit subsystem provably bounded with no bypass: at most this
/// many audit inserts hit ClickHouse concurrently, regardless of caller. It is a
/// `static` (not a struct field) precisely because direct callers each construct
/// their own emitter — a per-instance bound would not be global.
///
/// Sized well above the API-layer caps (`DURABLE_AUDIT_INSERTS` 12 +
/// `ROUTINE_AUDIT_INSERTS` 64 = 76) so it never throttles the normal dispatch
/// path; it is the ceiling that also covers the low-volume direct callers.
static AUDIT_INSERT_BOUND: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(128);

/// Backstop timeout for a single audit insert at the emitter level. Generous on
/// purpose — API callers wrap their own tighter 4s/5s bounds on top of this; the
/// backstop only exists so a slow/unresponsive ClickHouse can never hold a permit
/// (or block a direct caller's background loop) indefinitely.
const AUDIT_INSERT_BACKSTOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Record an audit event (or batch) dropped by the emitter-level backstop —
/// loud + observable + log-recoverable, consistent with the API-layer drop
/// semantics. Logs the FULL event and increments the shared
/// `nanosiem_audit_emit_failures_total{action, critical, reason}` counter.
/// `reason` is `emitter_saturated` (concurrency bound full) or `emitter_timeout`
/// (insert exceeded the backstop timeout).
fn record_dropped(events: &[AuditEvent], durable: bool, reason: &'static str) {
    for event in events {
        let event_json =
            serde_json::to_string(event).unwrap_or_else(|_| "<unserializable>".to_string());
        tracing::error!(
            source = %event.source,
            action = %event.action,
            reason = %reason,
            event = %event_json,
            "Audit event dropped at emitter concurrency backstop — full event logged for recovery",
        );
        metrics::counter!(
            "nanosiem_audit_emit_failures_total",
            "action" => event.action.clone(),
            "critical" => if durable { "true" } else { "false" },
            "reason" => reason,
        )
        .increment(1);
    }
}

impl AuditEmitter {
    /// Create a new audit emitter with DualPool for ClickHouse storage
    pub fn new(dual_pool: DualPool) -> Self {
        let mirror_to_ocsf = crate::schema::active_profile_from_env()
            .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
            // A malformed profile env fails boot before this (NAN-800
            // fail-fast); defaulting UDM here just keeps audit emission alive
            // no matter what.
            .unwrap_or(false);
        let outbox = SecurityAuditOutbox::new(dual_pool.postgres().clone());
        Self {
            dual_pool,
            mirror_to_ocsf,
            outbox,
        }
    }

    /// Whether this emitter writes the OCSF `ocsf_logs` mirror row.
    pub fn mirrors_ocsf(&self) -> bool {
        self.mirror_to_ocsf
    }

    /// The security-critical event outbox this emitter records into.
    pub fn outbox(&self) -> &SecurityAuditOutbox {
        &self.outbox
    }

    /// Record a security-critical event in the PostgreSQL outbox WITHOUT an
    /// inline ClickHouse attempt; the drainer delivers it. Used when the
    /// API-layer durable-insert cap is saturated (NAN-4954), so a burst of
    /// security events degrades to "delivered a few seconds later" instead of
    /// to the lossy async-insert path.
    pub async fn enqueue_only(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        match tokio::time::timeout(OUTBOX_WRITE_TIMEOUT, self.outbox.enqueue(event, true)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(AuditEmitError::Storage(format!("audit outbox write failed: {e}"))),
            Err(_) => Err(AuditEmitError::Storage("audit outbox write timed out".to_string())),
        }
    }

    /// Emit an audit event to ClickHouse (default fire-and-forget async-insert
    /// semantics — see [`Self::emit_durable`] for the synchronous variant).
    pub async fn emit(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        self.emit_batch(std::slice::from_ref(event)).await?;

        tracing::debug!(
            source = %event.source,
            action = %event.action,
            "Emitted audit event"
        );

        Ok(())
    }

    /// Emit a single security-critical audit event **durably** (NAN-1625,
    /// NAN-4954).
    ///
    /// 1. Record the event in the PostgreSQL `security_audit_events` outbox.
    /// 2. Write it to ClickHouse synchronously: `async_insert=0` +
    ///    `wait_end_of_query=1` hold the response until the row is flushed to a
    ///    part (under the default async-insert path ClickHouse acks on
    ///    *receipt*, so only this form proves the row landed).
    /// 3. On ClickHouse success stamp the outbox row delivered; on failure leave
    ///    it pending for [`super::AuditOutboxDrainer`].
    ///
    /// Returns `Ok` whenever at least one store holds the event (see
    /// [`DurableOutcome`]), and [`AuditEmitError::NotDurable`] only when both
    /// writes failed — the one case where the event is genuinely lost.
    ///
    /// Reserved for the low-volume, non-floodable security actions in
    /// [`crate::audit::SECURITY_CRITICAL_ACTIONS`]; routine events keep the
    /// cheaper async-insert path.
    pub async fn emit_durable(&self, event: &AuditEvent) -> Result<DurableOutcome, AuditEmitError> {
        match self.record(event).await {
            Ok(()) => Ok(self.deliver_recorded(event).await),
            Err(record_error) => match self.bounded_insert(std::slice::from_ref(event), true).await {
                Ok(()) => {
                    tracing::warn!(
                        source = %event.source,
                        action = %event.action,
                        event_id = %event.event_id,
                        error = %record_error,
                        "Security-critical audit event written to ClickHouse but its PostgreSQL record failed",
                    );
                    metrics::counter!(
                        "nanosiem_audit_outbox_record_failures_total",
                        "action" => event.action.clone(),
                    )
                    .increment(1);
                    Ok(DurableOutcome::DeliveredWithoutRecord { record_error })
                }
                Err(failure) => {
                    metrics::counter!(
                        "nanosiem_audit_security_events_lost_total",
                        "action" => event.action.clone(),
                    )
                    .increment(1);
                    Err(AuditEmitError::NotDurable {
                        record_error,
                        clickhouse_error: failure.to_string(),
                    })
                }
            },
        }
    }

    /// Step 1 of the durable path: record the event in the PostgreSQL outbox
    /// (bounded in time). Once this returns `Ok`, the event can no longer be
    /// lost — the drainer delivers it even if this process dies (NAN-4954).
    pub async fn record(&self, event: &AuditEvent) -> Result<(), String> {
        match tokio::time::timeout(OUTBOX_WRITE_TIMEOUT, self.outbox.enqueue(event, false)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("audit outbox write failed: {e}")),
            Err(_) => Err("audit outbox write timed out".to_string()),
        }
    }

    /// Step 2 of the durable path, for an event ALREADY recorded in the outbox
    /// (by [`Self::record`] or [`SecurityAuditOutbox::enqueue_tx`]): write it
    /// to ClickHouse synchronously and stamp the outbox row, or leave it
    /// pending for the drainer. Never loses the event, so it returns the
    /// outcome rather than an error.
    pub async fn deliver_recorded(&self, event: &AuditEvent) -> DurableOutcome {
        match self.bounded_insert(std::slice::from_ref(event), true).await {
            Ok(()) => {
                if let Err(e) = self.outbox.mark_delivered(event.event_id, self.mirror_to_ocsf).await {
                    // Harmless: the drainer re-checks ClickHouse for the row
                    // ids before re-inserting, then stamps it.
                    tracing::warn!(event_id = %event.event_id, error = %e,
                        "Audit outbox delivery stamp failed; the drainer will reconcile it");
                }
                tracing::debug!(
                    source = %event.source,
                    action = %event.action,
                    "Emitted audit event (durable, synchronous insert)"
                );
                DurableOutcome::Delivered
            }
            Err(failure) => {
                let error = failure.to_string();
                if let Err(e) = self.outbox.record_inline_failure(event.event_id, &error).await {
                    tracing::warn!(event_id = %event.event_id, error = %e,
                        "Could not record the inline audit insert failure on the outbox row");
                }
                tracing::warn!(
                    source = %event.source,
                    action = %event.action,
                    event_id = %event.event_id,
                    clickhouse_error = %error,
                    "Security-critical audit event recorded in PostgreSQL; ClickHouse delivery deferred to the outbox drainer",
                );
                metrics::counter!(
                    "nanosiem_audit_outbox_deferred_total",
                    "action" => event.action.clone(),
                )
                .increment(1);
                DurableOutcome::Deferred { clickhouse_error: error }
            }
        }
    }

    /// Emit multiple audit events in a batch (async-insert / fire-and-forget).
    pub async fn emit_batch(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        self.emit_batch_inner(events, false).await
    }

    /// Shared batch-insert entry point for the routine (non-outbox) paths —
    /// applies the emitter-level backstop via [`Self::bounded_insert`]. On
    /// saturation or backstop timeout the batch is DROPPED (full event logged +
    /// metric, via [`record_dropped`]) rather than blocking a caller's loop.
    async fn emit_batch_inner(
        &self,
        events: &[AuditEvent],
        durable: bool,
    ) -> Result<(), AuditEmitError> {
        match self.bounded_insert(events, durable).await {
            Ok(()) => Ok(()),
            Err(InsertFailure::Saturated) => {
                record_dropped(events, durable, "emitter_saturated");
                Ok(())
            }
            Err(InsertFailure::Timeout) => {
                record_dropped(events, durable, "emitter_timeout");
                Ok(())
            }
            Err(InsertFailure::Storage(e)) => Err(AuditEmitError::Storage(e)),
        }
    }

    /// The single chokepoint every audit ClickHouse insert funnels through:
    /// acquires the process-global backstop permit ([`AUDIT_INSERT_BOUND`],
    /// never blocking) and bounds the insert in time
    /// ([`AUDIT_INSERT_BACKSTOP_TIMEOUT`]), so no caller can issue an unbounded
    /// audit insert. Reports WHY an insert did not land; callers decide whether
    /// that is a drop (routine) or a deferral (outbox-backed).
    async fn bounded_insert(&self, events: &[AuditEvent], durable: bool) -> Result<(), InsertFailure> {
        if events.is_empty() {
            return Ok(());
        }
        let _permit = AUDIT_INSERT_BOUND
            .try_acquire()
            .map_err(|_| InsertFailure::Saturated)?;
        match tokio::time::timeout(
            AUDIT_INSERT_BACKSTOP_TIMEOUT,
            self.perform_insert(events, durable),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(InsertFailure::Storage(e.to_string())),
            Err(_) => Err(InsertFailure::Timeout),
        }
        // `_permit` released here.
    }

    /// Outbox-drainer delivery of the UDM half (synchronous insert, bounded).
    /// Each event keeps its own `occurred_at`, so re-deliveries produce the same
    /// content-derived row id.
    pub(crate) async fn deliver_udm(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        self.bounded_call(self.insert_udm(&self.write_client(true), events))
            .await
    }

    /// Write ONLY the OCSF `ocsf_logs` mirror rows for `events`, through the same
    /// bounded, fire-and-forget path as routine audit events (NAN-5271). For
    /// callers that already write their own UDM `logs` row (case lifecycle
    /// audit) but whose events must also be searchable on an OCSF tenant. A
    /// no-op under UDM.
    pub async fn emit_ocsf_mirror(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        if events.is_empty() || !self.mirror_to_ocsf {
            return Ok(());
        }
        self.bounded_call(self.insert_ocsf_mirror(&self.write_client(false), events))
            .await
    }

    /// Outbox-drainer delivery of the OCSF mirror half (synchronous, bounded).
    pub(crate) async fn deliver_ocsf(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        if !self.mirror_to_ocsf {
            return Ok(());
        }
        self.bounded_call(self.insert_ocsf_mirror(&self.write_client(true), events))
            .await
    }

    async fn bounded_call<F>(&self, fut: F) -> Result<(), AuditEmitError>
    where
        F: std::future::Future<Output = Result<(), AuditEmitError>>,
    {
        let _permit = AUDIT_INSERT_BOUND.try_acquire().map_err(|_| {
            AuditEmitError::Storage(InsertFailure::Saturated.to_string())
        })?;
        match tokio::time::timeout(AUDIT_INSERT_BACKSTOP_TIMEOUT, fut).await {
            Ok(res) => res,
            Err(_) => Err(AuditEmitError::Storage(InsertFailure::Timeout.to_string())),
        }
    }

    /// Ids of `events` whose UDM row is already in ClickHouse (NAN-4954). The
    /// drainer skips those, so a row whose inline write landed but whose
    /// delivery stamp was lost is not inserted twice.
    pub(crate) async fn existing_udm_ids(
        &self,
        events: &[AuditEvent],
    ) -> Result<HashSet<uuid::Uuid>, AuditEmitError> {
        if events.is_empty() {
            return Ok(HashSet::new());
        }
        let ingest_time = Utc::now();
        let mut ids = Vec::with_capacity(events.len());
        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        for e in events {
            let row = ClickHouseLogRow::from_parsed_log(&e.to_parsed_log(), ingest_time);
            min_ts = min_ts.min(row.timestamp);
            max_ts = max_ts.max(row.timestamp);
            ids.push(row.id.to_string());
        }
        let placeholders = vec!["?"; ids.len()].join(", ");
        let sql = format!(
            "SELECT toString(id) FROM {} \
             WHERE timestamp >= fromUnixTimestamp64Micro(toInt64(?), 'UTC') \
               AND timestamp <= fromUnixTimestamp64Micro(toInt64(?), 'UTC') \
               AND source_type = 'audit' AND toString(id) IN ({})",
            self.dual_pool.logs_table(),
            placeholders
        );
        let mut q = self.dual_pool.clickhouse().query(&sql).bind(min_ts).bind(max_ts);
        for id in &ids {
            q = q.bind(id.as_str());
        }
        let found: Vec<String> = self
            .bounded_call_value(q.fetch_all::<String>())
            .await?;
        Ok(found
            .into_iter()
            .filter_map(|s| uuid::Uuid::parse_str(&s).ok())
            .collect())
    }

    /// Event ids of `events` whose OCSF mirror row is already in `ocsf_logs`
    /// (NAN-4954). The mirror row's `id` is the event's `event_id`, so the
    /// drainer can skip mirrors that landed before a delivery stamp was lost.
    pub(crate) async fn existing_ocsf_ids(
        &self,
        events: &[AuditEvent],
    ) -> Result<HashSet<uuid::Uuid>, AuditEmitError> {
        if events.is_empty() || !self.mirror_to_ocsf {
            return Ok(HashSet::new());
        }
        let min_ms = events.iter().map(|e| e.occurred_at.timestamp_millis()).min().unwrap_or(0);
        let max_ms = events.iter().map(|e| e.occurred_at.timestamp_millis()).max().unwrap_or(0);
        let placeholders = vec!["toUUID(?)"; events.len()].join(", ");
        let sql = format!(
            "SELECT toString(id) FROM {} \
             WHERE timestamp >= fromUnixTimestamp64Milli(toInt64(?), 'UTC') \
               AND timestamp <= fromUnixTimestamp64Milli(toInt64(?), 'UTC') \
               AND source_type = 'audit' AND id IN ({})",
            self.dual_pool.table_names().read("ocsf_logs"),
            placeholders
        );
        let mut q = self.dual_pool.clickhouse().query(&sql).bind(min_ms).bind(max_ms);
        for e in events {
            q = q.bind(e.event_id.to_string());
        }
        let found: Vec<String> = self.bounded_call_value(q.fetch_all::<String>()).await?;
        Ok(found
            .into_iter()
            .filter_map(|s| uuid::Uuid::parse_str(&s).ok())
            .collect())
    }

    async fn bounded_call_value<T, F>(&self, fut: F) -> Result<T, AuditEmitError>
    where
        F: std::future::Future<Output = Result<T, clickhouse::error::Error>>,
    {
        match tokio::time::timeout(AUDIT_INSERT_BACKSTOP_TIMEOUT, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(AuditEmitError::Storage(e.to_string())),
            Err(_) => Err(AuditEmitError::Storage(InsertFailure::Timeout.to_string())),
        }
    }

    /// Perform the actual ClickHouse insert(s) for a batch: the UDM row, then
    /// (under the OCSF profile) the `ocsf_logs` mirror row.
    ///
    /// Callers reach this only via [`Self::bounded_insert`], which holds the
    /// [`AUDIT_INSERT_BOUND`] permit and applies the backstop timeout.
    async fn perform_insert(
        &self,
        events: &[AuditEvent],
        durable: bool,
    ) -> Result<(), AuditEmitError> {
        let client = self.write_client(durable);
        self.insert_udm(&client, events).await?;
        if self.mirror_to_ocsf {
            self.insert_ocsf_mirror(&client, events).await?;
        }
        tracing::debug!(count = events.len(), "Emitted batch of audit events");
        Ok(())
    }

    /// The ClickHouse client for an audit write.
    ///
    /// When `durable` is true the client carries synchronous-write options
    /// (`async_insert=0` + `wait_end_of_query=1`) so the await blocks until the
    /// write is flushed to a part rather than merely received (NAN-1625).
    ///
    /// NAN-1724: the NON-durable (routine) path must be genuinely
    /// fire-and-forget. The server default is `async_insert=0`, so without an
    /// explicit option the "async" routine path was a SYNCHRONOUS insert that
    /// blocked on the `logs` table's MATERIALIZED-column + MV cascade and the
    /// OCSF mirror write. `async_insert=1, wait_for_async_insert=0` makes
    /// ClickHouse buffer the row and ACK on receipt.
    fn write_client(&self, durable: bool) -> clickhouse::Client {
        // The writer targets a fully-qualified local table (`nanosiem.logs`).
        // clickhouse-rs 0.14's validation metadata query does not split a
        // qualified name: it looks for table=`nanosiem.logs` inside database
        // `nanosiem`, gets an empty schema, and rejects every row before an
        // INSERT is sent. The row type and target schema are pinned together
        // in this crate, so use the direct RowBinary path, as the other
        // fully-qualified native writers do.
        let base = self.dual_pool.clickhouse().clone().with_validation(false);
        if durable {
            base
                .with_option("async_insert", "0")
                .with_option("wait_end_of_query", "1")
        } else {
            base.with_option("async_insert", "1")
                .with_option("wait_for_async_insert", "0")
        }
    }

    /// Insert the UDM rows into the local logs table. The service connection is
    /// already routed to one shard; distributed reads provide cluster-wide
    /// visibility. Each row is dated at its event's `occurred_at`.
    async fn insert_udm(
        &self,
        client: &clickhouse::Client,
        events: &[AuditEvent],
    ) -> Result<(), AuditEmitError> {
        let ingest_time = Utc::now();
        let logs_table = self.dual_pool.table_names().local("logs");
        let mut insert = client
            .insert::<ClickHouseLogRow>(&logs_table)
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;
        for e in events {
            let row = ClickHouseLogRow::from_parsed_log(&e.to_parsed_log(), ingest_time);
            insert
                .write(&row)
                .await
                .map_err(|e| AuditEmitError::Storage(e.to_string()))?;
        }
        insert
            .end()
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))
    }

    /// Under the OCSF profile, mirror each event into `ocsf_logs` as an OCSF
    /// API Activity (6003) record so the search bar — which reads `ocsf_logs`
    /// under OCSF — can surface audit events to AUDIT_VIEW principals
    /// (NAN-1390 / G16). NAN-1443: write into the `ocsf_logs_raw` ENGINE=Null
    /// landing table — the `ocsf_logs_raw_mv` MV derives the stored row. Always
    /// the local table: a Null landing table has no distributed wrapper.
    async fn insert_ocsf_mirror(
        &self,
        client: &clickhouse::Client,
        events: &[AuditEvent],
    ) -> Result<(), AuditEmitError> {
        // NAN-5032: the platform-only landing (ocsf/193). `ocsf_logs_raw`, the
        // INGEST landing, rewrites `audit` to `reserved_spoof`.
        let ocsf_table = self.dual_pool.table_names().local("ocsf_logs_system_raw");
        // NAN-4939: omit the storage timestamp. Migration ocsf/190 derives and
        // clamps it from event.time, while the OCSF payload keeps the exact
        // occurred_at value for audit semantics and provenance.
        // NAN-4954: the row `id` is the event's own `event_id` (a UUIDv7, the
        // same type the column defaults to), so a retried delivery is
        // recognisable and the drainer can skip mirrors that already landed.
        let ocsf_query = ocsf_mirror_insert_sql(&ocsf_table, events.len());
        let mut query = client.query(&ocsf_query);
        for event in events {
            let time: DateTime<Utc> = event.occurred_at;
            query = query
                .bind(event.to_ocsf_event(time).to_string())
                .bind(event.event_id.to_string());
        }
        query
            .execute()
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))
    }
}

fn ocsf_mirror_insert_sql(table: &str, rows: usize) -> String {
    let placeholders = vec!["(?, 'audit', toUUID(?))"; rows].join(", ");
    format!("INSERT INTO {table} (event, source_type, id) VALUES {placeholders}")
}

#[cfg(test)]
#[path = "emitter_future_timestamp_tests.rs"]
mod future_timestamp_tests;

/// Errors that can occur when emitting audit events
#[derive(Debug, thiserror::Error)]
pub enum AuditEmitError {
    #[error("Storage error: {0}")]
    Storage(String),
    /// A security-critical event reached neither PostgreSQL nor ClickHouse.
    #[error("security-critical audit event not persisted: PostgreSQL: {record_error}; ClickHouse: {clickhouse_error}")]
    NotDurable {
        record_error: String,
        clickhouse_error: String,
    },
}
