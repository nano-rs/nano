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

    /// Emit an audit event to ClickHouse
    pub async fn emit(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        self.emit_batch(std::slice::from_ref(event)).await?;

        tracing::debug!(
            source = %event.source,
            action = %event.action,
            "Emitted audit event"
        );

        Ok(())
    }

    /// Emit multiple audit events in a batch
    pub async fn emit_batch(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        if events.is_empty() {
            return Ok(());
        }

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
        let client = self.dual_pool.clickhouse();
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
        // `_inserted_at` are server-defaulted, everything else materializes
        // from `event`.
        if self.mirror_to_ocsf {
            let ocsf_table = self.dual_pool.table_names().read_bare("ocsf_logs");
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
