// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse log row mapping
//!
//! Maps a `ParsedLog` to the column layout of the ClickHouse `logs` table.
//! The full in-process `IngestionService` was removed when ingestion was moved
//! to Vector → ClickHouse direct writes (see `config/vector/DIRECT_CLICKHOUSE_SETUP.md`).
//! This row type survives because audit emitters still write to the `logs`
//! table directly.

use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ParsedLog;

/// ClickHouse row structure for log insertion
/// This struct maps to the ClickHouse logs table schema
///
/// Note: We use i64 timestamps (microseconds since epoch) for compatibility
/// with ClickHouse's DateTime64(6) type.
/// Note: The `id` field uses a content-based UUID computed from (source_type + timestamp + message)
/// to ensure idempotent inserts - retrying the same batch produces the same IDs.
#[derive(Debug, Clone, Row, Serialize)]
pub struct ClickHouseLogRow {
    /// Content-based UUID for idempotent inserts (derived from source_type + timestamp + message hash)
    #[serde(with = "clickhouse::serde::uuid")]
    pub id: Uuid,
    pub timestamp: i64, // Microseconds since epoch for DateTime64(6)
    pub message: String,
    pub metadata: String,
    pub source_type: String,
    pub source: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_host: String,
    pub dest_host: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub user: String,
    pub action: String,
    pub status: String,
    pub severity: String,
    pub auth_type: String,
    pub auth_result: String,
    pub session_id: String,
    pub process_name: String,
    pub process_id: u32,
    /// Full command line (command_line = path + exe + args)
    pub command_line: String,
    /// Parent exe filename only
    pub parent_process_name: String,
    /// Full parent command line (parent_command_line = path + exe + args)
    pub parent_command_line: String,
    pub file_path: String,
    pub file_name: String,
    pub file_hash: String,
    pub file_action: String,
    pub user_agent: String,
    pub ingest_time: i64, // Microseconds since epoch for DateTime64(6)
}

impl ClickHouseLogRow {
    /// Convert a chrono DateTime to microseconds since epoch
    fn datetime_to_micros(dt: DateTime<Utc>) -> i64 {
        dt.timestamp_micros()
    }

    /// Compute a content-based UUID for idempotent inserts
    ///
    /// The UUID is derived from SHA256(source_type + timestamp_micros + message), using
    /// the first 16 bytes as a UUID. This ensures:
    /// - Same log content always produces the same UUID
    /// - Retrying failed batches doesn't create duplicate entries with different IDs
    /// - Logs with identical content (true duplicates) get the same ID
    fn compute_content_uuid(source_type: &str, timestamp_micros: i64, message: &str) -> Uuid {
        let mut hasher = Sha256::new();
        hasher.update(source_type.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp_micros.to_le_bytes());
        hasher.update(b"|");
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        // Use first 16 bytes of SHA256 as UUID (version 8, variant 2)
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        // Set version to 8 (custom) and variant to RFC 4122
        bytes[6] = (bytes[6] & 0x0f) | 0x80; // Version 8
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant RFC 4122
        Uuid::from_bytes(bytes)
    }

    /// Convert a ParsedLog to a ClickHouseLogRow
    pub fn from_parsed_log(log: &ParsedLog, ingest_time: DateTime<Utc>) -> Self {
        let timestamp_micros = Self::datetime_to_micros(log.timestamp);
        let id = Self::compute_content_uuid(&log.source_type, timestamp_micros, &log.message);

        Self {
            id,
            timestamp: timestamp_micros,
            message: log.message.clone(),
            metadata: log.metadata.to_string(),
            source_type: log.source_type.clone(),
            source: log.source.clone().unwrap_or_default(),
            src_ip: log.src_ip.clone().unwrap_or_default(),
            dest_ip: log.dest_ip.clone().unwrap_or_default(),
            src_host: log.src_host.clone().unwrap_or_default(),
            dest_host: log.dest_host.clone().unwrap_or_default(),
            src_port: log.src_port.map(|p| p as u16).unwrap_or(0),
            dest_port: log.dest_port.map(|p| p as u16).unwrap_or(0),
            protocol: log.protocol.clone().unwrap_or_default(),
            bytes_in: log.bytes_in.map(|b| b as u64).unwrap_or(0),
            bytes_out: log.bytes_out.map(|b| b as u64).unwrap_or(0),
            user: log.user.clone().unwrap_or_default(),
            action: log.action.clone().unwrap_or_default(),
            status: log.status.clone().unwrap_or_default(),
            severity: log.severity.clone().unwrap_or_default(),
            auth_type: log.auth_type.clone().unwrap_or_default(),
            auth_result: log.auth_result.clone().unwrap_or_default(),
            session_id: log.session_id.clone().unwrap_or_default(),
            process_name: log.process_name.clone().unwrap_or_default(),
            process_id: log.process_id.map(|p| p as u32).unwrap_or(0),
            command_line: log.command_line.clone().unwrap_or_default(),
            parent_process_name: log.parent_process_name.clone().unwrap_or_default(),
            parent_command_line: log.parent_command_line.clone().unwrap_or_default(),
            file_path: log.file_path.clone().unwrap_or_default(),
            file_name: log.file_name.clone().unwrap_or_default(),
            file_hash: log.file_hash.clone().unwrap_or_default(),
            file_action: log.file_action.clone().unwrap_or_default(),
            user_agent: log.user_agent.clone().unwrap_or_default(),
            ingest_time: Self::datetime_to_micros(ingest_time),
        }
    }
}
