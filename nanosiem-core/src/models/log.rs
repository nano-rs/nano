// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log model for stored log events

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// A stored log event
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Log {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub metadata: serde_json::Value,
    pub source_type: Option<String>,

    // UDM fields - using String for IP addresses for SQLx compatibility
    pub src_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub src_host: Option<String>,
    pub dest_host: Option<String>,
    pub src_port: Option<i32>,
    pub dest_port: Option<i32>,
    pub protocol: Option<String>,
    #[sqlx(rename = "user")]
    pub user: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub auth_type: Option<String>,
    pub auth_result: Option<String>,
    pub session_id: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<i32>,
    /// Full command line (command_line = path + exe + args)
    pub command_line: Option<String>,
    /// Parent exe filename only
    pub parent_process_name: Option<String>,
    /// Full parent command line (parent_command_line = path + exe + args)
    pub parent_command_line: Option<String>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_action: Option<String>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub user_agent: Option<String>,

    // Enrichment fields (populated at ingest time)
    pub enriched_src_country: Option<String>,
    pub enriched_src_country_code: Option<String>,
    pub enriched_src_continent: Option<String>,
    pub enriched_src_continent_code: Option<String>,
    pub enriched_src_asn: Option<String>,
    pub enriched_src_as_name: Option<String>,
    pub enriched_src_as_domain: Option<String>,
    pub enriched_dest_country: Option<String>,
    pub enriched_dest_country_code: Option<String>,
    pub enriched_dest_continent: Option<String>,
    pub enriched_dest_continent_code: Option<String>,
    pub enriched_dest_asn: Option<String>,
    pub enriched_dest_as_name: Option<String>,
    pub enriched_dest_as_domain: Option<String>,

    // Processing timestamps
    pub ingest_time: DateTime<Utc>,
    pub enrich_time: Option<DateTime<Utc>>,
}

/// Input for creating a new log entry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewLog {
    pub timestamp: Option<DateTime<Utc>>,
    pub message: String,
    pub metadata: serde_json::Value,
    pub source_type: Option<String>,
    pub src_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub src_host: Option<String>,
    pub dest_host: Option<String>,
    pub src_port: Option<i32>,
    pub dest_port: Option<i32>,
    pub protocol: Option<String>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub auth_type: Option<String>,
    pub auth_result: Option<String>,
    pub session_id: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<i32>,
    /// Full command line (command_line = path + exe + args)
    pub command_line: Option<String>,
    /// Parent exe filename only
    pub parent_process_name: Option<String>,
    /// Full parent command line (parent_command_line = path + exe + args)
    pub parent_command_line: Option<String>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_action: Option<String>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub user_agent: Option<String>,
    /// Extended/overflow fields as JSON
    pub ext: Option<serde_json::Value>,
}
