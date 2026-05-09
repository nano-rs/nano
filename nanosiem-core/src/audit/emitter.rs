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
pub struct AuditEmitter {
    dual_pool: Option<DualPool>,
}

impl AuditEmitter {
    /// Create a new audit emitter with DualPool for ClickHouse storage
    pub fn new(dual_pool: DualPool) -> Self {
        Self {
            dual_pool: Some(dual_pool),
        }
    }

    /// Create a no-op audit emitter (for testing or when ClickHouse is disabled)
    pub fn noop() -> Self {
        Self { dual_pool: None }
    }

    /// Emit an audit event to ClickHouse
    pub async fn emit(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        let dual_pool = match &self.dual_pool {
            Some(pool) => pool,
            None => return Ok(()), // No-op mode
        };

        let parsed_log = event.to_parsed_log();
        let ingest_time = Utc::now();

        // Convert to ClickHouse row
        let row = ClickHouseLogRow::from_parsed_log(&parsed_log, ingest_time);

        // Insert into ClickHouse
        let client = dual_pool.clickhouse();
        let mut insert = client
            .insert::<ClickHouseLogRow>("logs")
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

        insert
            .write(&row)
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

        insert
            .end()
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

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

        let dual_pool = match &self.dual_pool {
            Some(pool) => pool,
            None => return Ok(()), // No-op mode
        };

        let ingest_time = Utc::now();

        // Convert all events to ClickHouse rows
        let rows: Vec<ClickHouseLogRow> = events
            .iter()
            .map(|e| {
                let parsed_log = e.to_parsed_log();
                ClickHouseLogRow::from_parsed_log(&parsed_log, ingest_time)
            })
            .collect();

        // Insert into ClickHouse
        let client = dual_pool.clickhouse();
        let mut insert = client
            .insert::<ClickHouseLogRow>("logs")
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
