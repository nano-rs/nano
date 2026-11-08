// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection engine error types

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur in the detection engine
#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Detection rule not found: {0}")]
    RuleNotFound(Uuid),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Query parse error: {0}")]
    QueryParseError(String),

    #[error("Query execution error: {0}")]
    QueryExecutionError(String),

    #[error("Invalid cron expression: {0}")]
    InvalidCronExpression(String),

    #[error("Rule is paused: {0}")]
    RulePaused(Uuid),

    #[error("Alert not found: {0}")]
    AlertNotFound(Uuid),

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Rule is still executing: {0}")]
    RuleExecuting(Uuid),

    #[error("Search error: {0}")]
    SearchError(String),

    #[error("Repository error: {0}")]
    RepositoryError(String),

    #[error("Prevalence error: {0}")]
    PrevalenceError(String),

    #[error("Invalid real-time rule: {0}")]
    InvalidRealtimeRule(String),

    #[error("Invalid MITRE ATT&CK mapping: {0}")]
    InvalidMitreMapping(String),

    #[error("Materialized view error: {0}")]
    MaterializedViewError(String),

    #[error("Concurrent modification detected for rule {0} - refresh and try again")]
    ConcurrentModification(Uuid),
}

impl DetectionError {
    /// NAN-4910: whether the failure was caused by the SIZE of the evaluated
    /// window — a smaller window can succeed where re-running the same one
    /// cannot. The scheduler shrinks a catch-up slice on these and, once the
    /// minimum slice keeps failing, records a coverage gap instead of pinning
    /// the rule on that window forever.
    ///
    /// Only explicit ClickHouse size-limit refusals qualify, because a gap
    /// advances the high-water mark past events that were never evaluated:
    /// - memory limit (MEMORY_LIMIT_EXCEEDED, 241);
    /// - result / read limits (TOO_MANY_ROWS 158, TOO_MANY_BYTES 307,
    ///   TOO_MANY_ROWS_OR_BYTES 396) and an oversized response;
    /// - a SERVER-SIDE `max_execution_time` timeout that reports the time the
    ///   query actually ran (`TIMEOUT_EXCEEDED ... elapsed N ms`, surfaced as
    ///   `Query timeout after Nms` with N > 0) — ClickHouse was executing it.
    ///
    /// Everything else keeps the high-water mark and is retried as-is: in
    /// particular the scheduler's own outer timeout (`Rule execution timed
    /// out`), which also fires on a stalled connection, an outage or a lock,
    /// a timeout with no elapsed time, connection errors, bad queries.
    ///
    /// ClickHouse errors reach the detection engine as text (see
    /// `search::types::parse_clickhouse_error`), so this matches both the raw
    /// ClickHouse error names and the friendly messages they are mapped to.
    pub fn is_window_size_dependent(&self) -> bool {
        let message = match self {
            Self::QueryExecutionError(message) | Self::SearchError(message) => message,
            _ => return false,
        };
        if message.contains("Rule execution timed out") {
            return false;
        }
        const SIZE_LIMIT_MARKERS: &[&str] = &[
            "MEMORY_LIMIT_EXCEEDED",
            "exceeded memory limit",
            "TOO_MANY_ROWS",
            "TOO_MANY_BYTES",
            "too many rows",
            "Response too large",
        ];
        if SIZE_LIMIT_MARKERS.iter().any(|marker| message.contains(marker)) {
            return true;
        }
        server_side_timeout_with_progress(message)
    }
}

/// A ClickHouse `max_execution_time` refusal that proves the server ran the
/// query: raw `TIMEOUT_EXCEEDED` carrying `elapsed`, or the mapped
/// `Query timeout after Nms` with a parsed, non-zero N (N is 0 when no
/// elapsed time could be read).
fn server_side_timeout_with_progress(message: &str) -> bool {
    if message.contains("TIMEOUT_EXCEEDED") && message.contains("elapsed") {
        return true;
    }
    const MAPPED: &str = "Query timeout after ";
    message
        .find(MAPPED)
        .map(|at| {
            let digits: String = message[at + MAPPED.len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            digits.parse::<u64>().map(|ms| ms > 0).unwrap_or(false)
        })
        .unwrap_or(false)
}

impl From<crate::db::repository::detection_rules::DetectionRuleRepositoryError> for DetectionError {
    fn from(err: crate::db::repository::detection_rules::DetectionRuleRepositoryError) -> Self {
        match err {
            crate::db::repository::detection_rules::DetectionRuleRepositoryError::NotFound(id) => {
                DetectionError::RuleNotFound(id)
            }
            crate::db::repository::detection_rules::DetectionRuleRepositoryError::DatabaseError(e) => {
                DetectionError::DatabaseError(e)
            }
            crate::db::repository::detection_rules::DetectionRuleRepositoryError::ConcurrentModification(id) => {
                DetectionError::ConcurrentModification(id)
            }
            crate::db::repository::detection_rules::DetectionRuleRepositoryError::InvalidModeTransition(id, mode) => {
                DetectionError::InvalidStateTransition(format!("Rule {} is currently in '{}' mode", id, mode))
            }
            crate::db::repository::detection_rules::DetectionRuleRepositoryError::InvalidMitreMapping(message) => {
                DetectionError::InvalidMitreMapping(message)
            }
        }
    }
}

impl From<crate::db::repository::alerts::AlertRepositoryError> for DetectionError {
    fn from(err: crate::db::repository::alerts::AlertRepositoryError) -> Self {
        match err {
            crate::db::repository::alerts::AlertRepositoryError::NotFound(id) => {
                DetectionError::AlertNotFound(id)
            }
            crate::db::repository::alerts::AlertRepositoryError::DatabaseError(e) => {
                DetectionError::DatabaseError(e)
            }
            crate::db::repository::alerts::AlertRepositoryError::InvalidStateTransition(msg) => {
                DetectionError::InvalidStateTransition(msg)
            }
            crate::db::repository::alerts::AlertRepositoryError::DuplicateAlert(rule_id, hash) => {
                // Duplicate alerts are not really errors - they're expected during deduplication
                // Log it and return a generic error (callers should handle DuplicateAlert specifically)
                tracing::debug!("Duplicate alert for rule {} with hash {}", rule_id, hash);
                DetectionError::DatabaseError(sqlx::Error::RowNotFound)
            }
        }
    }
}
