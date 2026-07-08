// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Event Emitter
//!
//! Writes audit events directly to ClickHouse for searchability.

use chrono::Utc;

use super::AuditEvent;
use crate::db::DualPool;
use crate::ingestion::ClickHouseLogRow;

/// Audit event emitter for storing platform audit events
///
/// This writes audit events directly to ClickHouse as searchable logs
/// with source_type='audit'.
///
/// The UDM row always goes to the cluster-aware UDM logs table
/// (`DualPool::logs_table()`): the audit *page* reads that table under both
/// schema profiles (`audit/query.rs`), so it is the canonical audit store.
/// Under the OCSF profile an OCSF API Activity (6003) mirror row is
/// additionally written to the profile's `ocsf_logs` table so AUDIT_VIEW
/// principals can find audit events from the search bar, which reads
/// `ocsf_logs` under OCSF (NAN-1390 / G16).
pub struct AuditEmitter {
    dual_pool: DualPool,
    /// Whether the active schema profile is OCSF (resolved once at
    /// construction; the profile is boot-fixed env config). Drives the
    /// `ocsf_logs` mirror write.
    mirror_to_ocsf: bool,
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
        Self {
            dual_pool,
            mirror_to_ocsf,
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

    /// Emit a single audit event **durably** (NAN-1625).
    ///
    /// Unlike [`Self::emit`], this forces a *synchronous* ClickHouse write:
    /// `async_insert=0` disables server-side insert buffering and
    /// `wait_end_of_query=1` holds the HTTP response until the data has been
    /// flushed to a part. Awaiting this call therefore genuinely guarantees the
    /// row landed on disk.
    ///
    /// This is the key correctness point: under the *default* async-insert
    /// path, ClickHouse acks on **receipt**, not flush (which is also why
    /// `written_rows` is always 0), so merely awaiting `emit` does NOT prove
    /// durability. Only `emit_durable` does.
    ///
    /// Reserved for the low-volume, non-floodable security actions in
    /// [`crate::audit::SECURITY_CRITICAL_ACTIONS`]; routine events keep the
    /// cheaper async-insert path.
    pub async fn emit_durable(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        self.emit_batch_inner(std::slice::from_ref(event), true)
            .await?;

        tracing::debug!(
            source = %event.source,
            action = %event.action,
            "Emitted audit event (durable, synchronous insert)"
        );

        Ok(())
    }

    /// Emit multiple audit events in a batch (async-insert / fire-and-forget).
    pub async fn emit_batch(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        self.emit_batch_inner(events, false).await
    }

    /// Shared batch-insert entry point — applies the emitter-level global
    /// concurrency backstop ([`AUDIT_INSERT_BOUND`]) + timeout
    /// ([`AUDIT_INSERT_BACKSTOP_TIMEOUT`]) around every audit insert, then
    /// delegates to [`Self::perform_insert`]. This is the single chokepoint all
    /// three public entry points (`emit`, `emit_batch`, `emit_durable`) funnel
    /// through, so no caller can issue an unbounded audit insert.
    ///
    /// On saturation of the bound we DROP the batch (log full event + metric,
    /// via [`record_dropped`]) rather than block/queue; on backstop-timeout we
    /// likewise drop. Never blocks a caller's background loop on a slow CH.
    async fn emit_batch_inner(
        &self,
        events: &[AuditEvent],
        durable: bool,
    ) -> Result<(), AuditEmitError> {
        if events.is_empty() {
            return Ok(());
        }

        // Acquire the process-global backstop permit. `try_acquire` never
        // blocks — on saturation drop-with-log+metric and return Ok (the event
        // has been recorded to logs, so the caller neither blocks nor errors).
        let _permit = match AUDIT_INSERT_BOUND.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                record_dropped(events, durable, "emitter_saturated");
                return Ok(());
            }
        };

        // Bound the insert in time so a stuck CH can't hold the permit or block
        // a direct caller (health/disk-pressure loops) indefinitely.
        match tokio::time::timeout(
            AUDIT_INSERT_BACKSTOP_TIMEOUT,
            self.perform_insert(events, durable),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => {
                record_dropped(events, durable, "emitter_timeout");
                Ok(())
            }
        }
        // `_permit` released here.
    }

    /// Perform the actual ClickHouse insert(s) for a batch.
    ///
    /// When `durable` is true, both the UDM insert and the OCSF mirror write go
    /// through a client cloned with synchronous-write options
    /// (`async_insert=0` + `wait_end_of_query=1`) so the await blocks until the
    /// write is flushed. When false (routine events), the client is cloned with
    /// fire-and-forget options (`async_insert=1` + `wait_for_async_insert=0`) so
    /// the write ACKs on receipt and never blocks on the `logs` materialized-
    /// column + MV cascade (NAN-1724).
    ///
    /// Callers reach this only via [`Self::emit_batch_inner`], which holds the
    /// [`AUDIT_INSERT_BOUND`] permit and applies the backstop timeout.
    async fn perform_insert(
        &self,
        events: &[AuditEvent],
        durable: bool,
    ) -> Result<(), AuditEmitError> {
        let ingest_time = Utc::now();

        // Convert all events to ClickHouse rows
        let rows: Vec<ClickHouseLogRow> = events
            .iter()
            .map(|e| {
                let parsed_log = e.to_parsed_log();
                ClickHouseLogRow::from_parsed_log(&parsed_log, ingest_time)
            })
            .collect();

        // Insert into the cluster-aware UDM logs table ("logs_distributed" on
        // clustered deployments, "logs" otherwise) — previously hardcoded
        // "logs", which wrote to the local shard only under clustering.
        //
        // For the durable path, clone the client with synchronous-write options
        // so the insert (and the OCSF mirror write below) genuinely block until
        // the row is flushed to a part rather than merely received (NAN-1625).
        // The options are HTTP query params applied to every request the client
        // makes, so both writes inherit them.
        //
        // NAN-1724: the NON-durable (routine) path must be genuinely
        // fire-and-forget. The ambient `dual_pool.clickhouse()` sets no
        // async_insert option and the server default is `async_insert=0`, so the
        // "async" routine path was in fact a SYNCHRONOUS insert — it blocked on
        // the `logs` table's ~79 MATERIALIZED-column (dictGet) computation + ~13
        // MVs + the OCSF mirror write, and under CH load intermittently exceeded
        // the caller's timeout (`ASYNC_AUDIT_EMIT_TIMEOUT`). Setting
        // `async_insert=1, wait_for_async_insert=0` makes ClickHouse buffer the
        // row and ACK on receipt (the materialized-column + MV work runs in the
        // background on flush), so a routine audit write can never block on that
        // cascade. Routine events tolerate this fire-and-forget contract (the
        // path already drops under extreme pressure); security-critical events
        // use the durable branch above, which stays fully synchronous.
        let write_client;
        let client = if durable {
            let mut c = self
                .dual_pool
                .clickhouse()
                .clone()
                .with_option("async_insert", "0")
                .with_option("wait_end_of_query", "1");
            // NAN-1728 (H7): on a clustered deployment the durable insert targets
            // `logs_distributed`. With the default `insert_distributed_sync=0` the
            // ACK only means "queued in the receiving node's `.bin` distribution
            // send buffer", NOT committed on a shard — so an acked security-audit
            // event can be lost if that node dies before the buffer forwards,
            // breaking the NAN-1625 durability contract. `insert_distributed_sync=1`
            // makes the write block until the row is committed on the target shard,
            // so the ACK means durable. No-op on single-node: `is_clustered()` is
            // false there and the write goes to the local `logs` MergeTree (not a
            // Distributed table), so the emitted request is byte-identical.
            if self.dual_pool.is_clustered() {
                c = c.with_option("insert_distributed_sync", "1");
            }
            write_client = c;
            &write_client
        } else {
            write_client = self
                .dual_pool
                .clickhouse()
                .clone()
                .with_option("async_insert", "1")
                .with_option("wait_for_async_insert", "0");
            &write_client
        };
        let mut insert = client
            .insert::<ClickHouseLogRow>(self.dual_pool.logs_table())
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

        for row in &rows {
            insert
                .write(row)
                .await
                .map_err(|e| AuditEmitError::Storage(e.to_string()))?;
        }

        insert
            .end()
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

        // Under the OCSF profile, mirror each event into `ocsf_logs` as an
        // OCSF API Activity (6003) record so the search bar — which reads
        // `ocsf_logs` under OCSF — can surface audit events to AUDIT_VIEW
        // principals (NAN-1390 / G16). Same write contract as the NAN-1254
        // Detection Finding writer: `event` JSON + explicit `timestamp`
        // (DateTime64(3) ← millis) + operational `source_type`; `id` and
        // `_inserted_at` are server-defaulted, everything else derives from
        // `event`. NAN-1443: write into the `ocsf_logs_raw` ENGINE=Null landing
        // table — the `ocsf_logs_raw_mv` MV derives the stored row into
        // `ocsf_logs` (which no longer stores `event`). Always the local table:
        // a Null landing table has no distributed wrapper.
        if self.mirror_to_ocsf {
            let ocsf_table = self.dual_pool.table_names().local("ocsf_logs_raw");
            let placeholders = vec!["(?, ?, 'audit')"; events.len()].join(", ");
            let ocsf_query = format!(
                "INSERT INTO {} (event, timestamp, source_type) VALUES {}",
                ocsf_table, placeholders
            );
            let mut query = client.query(&ocsf_query);
            for event in events {
                query = query
                    .bind(event.to_ocsf_event(ingest_time).to_string())
                    .bind(ingest_time.timestamp_millis());
            }
            query
                .execute()
                .await
                .map_err(|e| AuditEmitError::Storage(e.to_string()))?;
        }

        tracing::debug!(count = events.len(), "Emitted batch of audit events");

        Ok(())
    }
}

/// Errors that can occur when emitting audit events
#[derive(Debug, thiserror::Error)]
pub enum AuditEmitError {
    #[error("Storage error: {0}")]
    Storage(String),
}
