// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types and structs for the ClickHouse executor
//!
//! Contains the `ClickHouseLogReadRow` struct for typed query results,
//! the column list constant, and the `ClickHouseExecutor` struct definition.

use clickhouse::Row;
use serde::Deserialize;

/// Row type for reading log data from ClickHouse.
///
/// NAN-1034: the three time-column fields use `#[serde(rename = "..._micros")]` so the
/// SQL aliases (`ts_micros`, `ingest_time_micros`, `enrich_time_micros`) do NOT shadow
/// the underlying DateTime64 columns. When the alias matches the column name,
/// ClickHouse's optimizer substitutes the alias expression back into the WHERE clause
/// (`WHERE timestamp BETWEEN '...string...'` → `WHERE toUnixTimestamp64Micro(timestamp)
/// BETWEEN '...string...'` → Code 53 Int64-vs-String type mismatch). Rust field names
/// stay `timestamp`/`ingest_time`/`enrich_time` so `clickhouse_row_to_json` keeps the
/// same JSON output keys and downstream consumers don't notice.
#[derive(Debug, Clone, Row, Deserialize)]
pub struct ClickHouseLogReadRow {
    pub id: String,
    #[serde(rename = "ts_micros")]
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
    #[serde(rename = "ingest_time_micros")]
    pub ingest_time: i64, // Microseconds since epoch for DateTime64(6)
    #[serde(rename = "enrich_time_micros")]
    pub enrich_time: i64, // 0 if not enriched, microseconds since epoch otherwise
    pub ext: String,      // JSON string containing extended fields (non-explicit UDM fields)
}

/// Columns to SELECT for ClickHouseLogReadRow struct.
/// Must match the struct fields exactly (including serde renames) to avoid deserialization errors.
///
/// NAN-1034: the three time aliases use `_micros` suffixes to avoid colliding with the
/// underlying column names. See `ClickHouseLogReadRow` docs for why.
pub(crate) const CLICKHOUSE_LOG_COLUMNS: &str = "id, toUnixTimestamp64Micro(timestamp) as ts_micros, message, metadata, source_type, \
    src_ip, dest_ip, src_host, dest_host, src_port, dest_port, protocol, bytes_in, bytes_out, \
    user, action, status, auth_type, auth_result, session_id, \
    process_name, process_id, command_line, parent_process_name, parent_command_line, \
    file_path, file_name, file_hash, file_action, user_agent, \
    enriched_src_country, enriched_src_country_code, enriched_src_continent, enriched_src_continent_code, \
    enriched_src_asn, enriched_src_as_name, enriched_src_as_domain, \
    enriched_dest_country, enriched_dest_country_code, enriched_dest_continent, enriched_dest_continent_code, \
    enriched_dest_asn, enriched_dest_as_name, enriched_dest_as_domain, \
    toUnixTimestamp64Micro(ingest_time) as ingest_time_micros, toUnixTimestamp64Micro(enrich_time) as enrich_time_micros, \
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-1034: the SELECT-list aliases for the three time columns must NOT match the
    /// underlying column names, or ClickHouse's optimizer substitutes the alias
    /// expression back into the WHERE clause and breaks `WHERE timestamp BETWEEN
    /// '...string...'` with `Code: 53. Cannot convert string ... to type Int64`.
    /// The dynamic fallback masked this in production but every typed-path query was
    /// silently re-running. Renaming the aliases is what prevents the shadow.
    #[test]
    fn log_columns_aliases_do_not_shadow_underlying_column_names() {
        let cols = CLICKHOUSE_LOG_COLUMNS;
        // The shadowing forms that triggered NAN-1034 must not be present.
        // Trailing comma forces an exact-token match so `ingest_time_micros` doesn't
        // false-positive on `ingest_time`.
        for forbidden in [
            "toUnixTimestamp64Micro(timestamp) as timestamp,",
            "toUnixTimestamp64Micro(ingest_time) as ingest_time,",
            "toUnixTimestamp64Micro(enrich_time) as enrich_time,",
        ] {
            assert!(
                !cols.contains(forbidden),
                "CLICKHOUSE_LOG_COLUMNS reintroduces the alias-shadows-column bug \
                 (NAN-1034) with `{forbidden}` — pick a distinct alias like \
                 `ts_micros`/`ingest_time_micros`/`enrich_time_micros` instead."
            );
        }
        // Sanity: the distinct aliases the fix introduced are still present.
        for required in [
            "as ts_micros,",
            "as ingest_time_micros,",
            "as enrich_time_micros,",
        ] {
            assert!(
                cols.contains(required),
                "CLICKHOUSE_LOG_COLUMNS missing expected alias `{required}` — the \
                 typed-query path will return the wrong column name and fail to \
                 deserialize into ClickHouseLogReadRow."
            );
        }
    }
}
