// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core types, error definitions, and repository struct for detection rules

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum DetectionRuleRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Detection rule not found: {0}")]
    NotFound(Uuid),
    #[error(
        "Concurrent modification detected for rule {0} - rule was modified by another request"
    )]
    ConcurrentModification(Uuid),
    #[error("Invalid mode transition for rule {0}: rule is currently in '{1}' mode")]
    InvalidModeTransition(Uuid, String),
}

/// Daily stats for a detection rule
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DailyStat {
    pub date: NaiveDate,
    pub match_count: i64,
    pub alert_count: i64,
}

/// Repository for detection rule operations
#[derive(Clone)]
pub struct DetectionRuleRepository {
    pub(super) pool: PgPool,
}

impl DetectionRuleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
