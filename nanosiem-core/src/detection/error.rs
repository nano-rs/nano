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

    /// NAN-5424: the backend could not be reached or stalled (identified by
    /// the client error type, or the scheduler's own timeout). Says nothing
    /// about the query or the data.
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    /// NAN-4910 / NAN-5424: ClickHouse refused the window for its size
    /// (identified by error code / typed variant). A smaller window can work.
    #[error("Window too large: {0}")]
    WindowTooLarge(String),

    /// NAN-5424: ClickHouse failed on the stored values in the window
    /// (identified by error code). The message carries the code only.
    #[error("Query failed on the stored data: {0}")]
    QueryDataError(String),
}

impl DetectionError {
    /// NAN-4910: whether the failure was caused by the SIZE of the evaluated
    /// window — a smaller window can succeed where re-running the same one
    /// cannot. The scheduler shrinks a catch-up slice on these and, once the
    /// minimum slice keeps failing, records a coverage gap instead of pinning
    /// the rule on that window forever.
    ///
    /// NAN-5424: decided by TYPE only. `WindowTooLarge` is produced from the
    /// ClickHouse error code (memory limit 241, too many rows / bytes 158 /
    /// 307 / 396), a server-side timeout that reports elapsed time, or an
    /// oversized response ([`crate::detection::service::detection_error_from_search`]).
    /// Error text is never scanned: ClickHouse quotes event values in it.
    pub fn is_window_size_dependent(&self) -> bool {
        matches!(self, Self::WindowTooLarge(_))
    }

    /// NAN-5424: the failure is POSITIVELY identified as caused by the data
    /// in the window: PostgreSQL refused the data being persisted (SQLSTATE
    /// class 22 data exception, e.g. 22P05 / 22021, or 54 program limit), or
    /// ClickHouse failed on a stored value (by error code). Re-running the
    /// same window fails the same way, so these get a short retry budget.
    pub fn is_persistence_data_error(&self) -> bool {
        match self {
            Self::QueryDataError(_) => true,
            Self::DatabaseError(e) => sqlx_error_is_data(e),
            _ => false,
        }
    }

    /// NAN-5424: the BACKEND was unreachable or stalled, identified by type:
    /// a ClickHouse transport failure or the scheduler's own timeout
    /// (`BackendUnavailable`), a PostgreSQL connection-level sqlx error, or a
    /// PostgreSQL SQLSTATE in class 08 (connection), 40 (transaction
    /// rollback, e.g. 40P01 deadlock / 40001 serialization), 53
    /// (insufficient resources), 57 (operator intervention) or 58 (system
    /// error). Re-running the same window later is expected to work, so the
    /// scheduler keeps the window much longer (an outage is caught up, not
    /// gapped). Never decided by message text.
    pub fn is_transient_infrastructure(&self) -> bool {
        match self {
            Self::BackendUnavailable(_) => true,
            Self::DatabaseError(e) => sqlx_error_is_transient(e),
            _ => false,
        }
    }

    /// NAN-5424: the error as shown on the rule, in coverage gaps and in SIEM
    /// Health. Database / ClickHouse error text can quote event values, so it
    /// is reduced to the error class plus the ClickHouse code or PostgreSQL
    /// SQLSTATE; messages nano writes itself (query validation, our own
    /// timeouts) are kept. The full text goes to the jobs log only.
    pub fn redacted_summary(&self) -> String {
        let text = match self {
            Self::DatabaseError(sqlx::Error::Database(db)) => match db.code() {
                Some(code) => format!("PostgreSQL error (SQLSTATE {code})"),
                None => "PostgreSQL error".to_string(),
            },
            Self::DatabaseError(e) => format!("Database error ({})", sqlx_error_kind(e)),
            Self::SearchError(message) | Self::QueryExecutionError(message) | Self::RepositoryError(message) => {
                match crate::search::clickhouse_error_code(message) {
                    Some(code) => format!("ClickHouse error (Code {code})"),
                    None => "Execution error (details in the jobs log)".to_string(),
                }
            }
            Self::BackendUnavailable(_) => "Backend unavailable (connection failed or timed out)".to_string(),
            // Our own templates (code-mapped), no event text.
            Self::WindowTooLarge(m) | Self::QueryDataError(m) | Self::InvalidQuery(m) | Self::QueryParseError(m) => {
                m.clone()
            }
            other => other.to_string(),
        };
        crate::db::pg_text::pg_safe_error_text(&text)
    }
}

/// See [`DetectionError::is_persistence_data_error`]: PostgreSQL refused the
/// data being written (SQLSTATE class 22 data exception or 54 program limit).
/// Shared with the real-time signal processor (NAN-5428).
pub(crate) fn sqlx_error_is_data(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db) => db
            .code()
            .is_some_and(|code| code.starts_with("22") || code.starts_with("54")),
        _ => false,
    }
}

/// See [`DetectionError::is_transient_infrastructure`]. Shared with the
/// real-time signal processor (NAN-5428).
pub(crate) fn sqlx_error_is_transient(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Io(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::Tls(_) => true,
        sqlx::Error::Database(db) => db.code().is_some_and(|code| {
            ["08", "40", "53", "57", "58"].iter().any(|class| code.starts_with(class))
        }),
        _ => false,
    }
}

fn sqlx_error_kind(e: &sqlx::Error) -> &'static str {
    match e {
        sqlx::Error::Io(_) => "io",
        sqlx::Error::PoolTimedOut => "pool timed out",
        sqlx::Error::PoolClosed => "pool closed",
        sqlx::Error::WorkerCrashed => "worker crashed",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Protocol(_) => "protocol",
        sqlx::Error::RowNotFound => "row not found",
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode",
        _ => "other",
    }
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
