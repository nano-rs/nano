// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types and structs for the ClickHouse executor
//!
//! Contains the `ClickHouseLogReadRow` struct for typed query results,
//! the column list constant, and the `ClickHouseExecutor` struct definition.

use clickhouse::Row;
use serde::Deserialize;

/// Row type for reading log data from ClickHouse
/// This struct maps to the ClickHouse logs table schema for reading
#[derive(Debug, Clone, Row, Deserialize)]
pub struct ClickHouseLogReadRow {
    pub id: String,
    pub timestamp: i64, // Microseconds since epoch for DateTime64(6)
    pub message: String,
    pub metadata: String,
    pub source_type: String,
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
    pub enriched_src_country: String,
    pub enriched_src_country_code: String,
    pub enriched_src_continent: String,
    pub enriched_src_continent_code: String,
    pub enriched_src_asn: String,
    pub enriched_src_as_name: String,
    pub enriched_src_as_domain: String,
    pub enriched_dest_country: String,
    pub enriched_dest_country_code: String,
    pub enriched_dest_continent: String,
    pub enriched_dest_continent_code: String,
    pub enriched_dest_asn: String,
    pub enriched_dest_as_name: String,
    pub enriched_dest_as_domain: String,
    pub ingest_time: i64, // Microseconds since epoch for DateTime64(6)
    pub enrich_time: i64, // 0 if not enriched, microseconds since epoch otherwise
    pub ext: String,      // JSON string containing extended fields (non-explicit UDM fields)
}

/// Columns to SELECT for ClickHouseLogReadRow struct
/// This must match the struct fields exactly to avoid deserialization errors
pub(crate) const CLICKHOUSE_LOG_COLUMNS: &str = "id, toUnixTimestamp64Micro(timestamp) as timestamp, message, metadata, source_type, \
    src_ip, dest_ip, src_host, dest_host, src_port, dest_port, protocol, bytes_in, bytes_out, \
    user, action, status, auth_type, auth_result, session_id, \
    process_name, process_id, command_line, parent_process_name, parent_command_line, \
    file_path, file_name, file_hash, file_action, user_agent, \
    enriched_src_country, enriched_src_country_code, enriched_src_continent, enriched_src_continent_code, \
    enriched_src_asn, enriched_src_as_name, enriched_src_as_domain, \
    enriched_dest_country, enriched_dest_country_code, enriched_dest_continent, enriched_dest_continent_code, \
    enriched_dest_asn, enriched_dest_as_name, enriched_dest_as_domain, \
    toUnixTimestamp64Micro(ingest_time) as ingest_time, toUnixTimestamp64Micro(enrich_time) as enrich_time, \
    toString(ext) as ext";

/// ClickHouse query executor
#[derive(Clone)]
pub struct ClickHouseExecutor {
    pub(crate) client: clickhouse::Client,
}

impl ClickHouseExecutor {
    /// Create a new ClickHouse executor
    pub fn new(client: clickhouse::Client) -> Self {
        Self { client }
    }
}
