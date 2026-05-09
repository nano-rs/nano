// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate limit repository backed by PostgreSQL
//!
//! Provides shared, cross-node rate limiting using sliding-window counters
//! stored in the `rate_limit_buckets` table.

use sqlx::PgPool;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RateLimitRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}

/// Repository for rate limit operations
#[derive(Clone)]
pub struct RateLimitRepository {
    pool: PgPool,
}

impl RateLimitRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check and increment a rate limit bucket.
    ///
    /// Performs an atomic upsert that either resets the window (if expired)
    /// or increments the token count. Returns the current token count
    /// within the active window.
    pub async fn check_rate_limit(
        &self,
        category: &str,
        key: &str,
        window_secs: f64,
    ) -> Result<i32, RateLimitRepositoryError> {
        let row: (i32,) = sqlx::query_as(
            r#"
            INSERT INTO rate_limit_buckets (category, key, tokens, window_start)
            VALUES ($1, $2, 1, NOW())
            ON CONFLICT (category, key) DO UPDATE
            SET tokens = CASE
                WHEN rate_limit_buckets.window_start < NOW() - make_interval(secs => $3)
                THEN 1
                ELSE rate_limit_buckets.tokens + 1
                END,
                window_start = CASE
                WHEN rate_limit_buckets.window_start < NOW() - make_interval(secs => $3)
                THEN NOW()
                ELSE rate_limit_buckets.window_start
                END
            RETURNING tokens
            "#,
        )
        .bind(category)
        .bind(key)
        .bind(window_secs)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }

    /// Delete expired rate limit buckets (older than 2 hours).
    ///
    /// Called periodically from the cleanup cycle.
    pub async fn cleanup_expired(&self) -> Result<u64, RateLimitRepositoryError> {
        let result = sqlx::query(
            "DELETE FROM rate_limit_buckets WHERE window_start < NOW() - INTERVAL '2 hours'",
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
