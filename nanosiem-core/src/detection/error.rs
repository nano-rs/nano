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

    #[error("Search error: {0}")]
    SearchError(String),

    #[error("Repository error: {0}")]
    RepositoryError(String),

    #[error("Prevalence error: {0}")]
    PrevalenceError(String),

    #[error("Invalid real-time rule: {0}")]
    InvalidRealtimeRule(String),

    #[error("Materialized view error: {0}")]
    MaterializedViewError(String),

    #[error("Concurrent modification detected for rule {0} - refresh and try again")]
    ConcurrentModification(Uuid),
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
