// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parsed log row
//!
//! `ParsedLog` is the structured row written into the ClickHouse `logs` table.
//! It is constructed directly by the audit writers (`nanosiem-core::audit` and
//! `nanosiem-enterprise::cases::audit`) and mapped to columns by
//! `ingestion::row::ClickHouseLogRow`. The in-process log-format parser was
//! removed when ingestion moved to Vector → ClickHouse direct writes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A parsed log entry ready for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedLog {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Raw log content for full-text search
    pub message: String,
    /// Parsed metadata as JSON
    pub metadata: serde_json::Value,
    /// Source type (syslog, json, cef, leef, unknown)
    pub source_type: String,
    /// Source/subsystem that generated the log (e.g., auth, detection, firewall)
    pub source: Option<String>,

    // UDM fields
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
    /// Full command line (nano UDM: command_line = path + exe + args)
    pub command_line: Option<String>,
    /// Parent process name (nano UDM: parent_process_name = just the exe)
    pub parent_process_name: Option<String>,
    /// Full parent command line (nano UDM: parent_command_line = path + exe + args)
    pub parent_command_line: Option<String>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_action: Option<String>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub user_agent: Option<String>,
    /// Extended/overflow fields as JSON (stored in ClickHouse ext column)
    pub ext: Option<serde_json::Value>,
}
