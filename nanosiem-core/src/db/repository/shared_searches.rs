// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared search repository for URL shortening

use rand::Rng;
use sqlx::PgPool;
use thiserror::Error;

use crate::models::{NewSharedSearch, SharedSearch};

#[derive(Error, Debug)]
pub enum SharedSearchRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Shared search not found: {0}")]
    NotFound(String),
}

/// Repository for shared search operations
#[derive(Clone)]
pub struct SharedSearchRepository {
    pool: PgPool,
}

impl SharedSearchRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a short alphanumeric ID
    fn generate_short_id() -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::rng();
        (0..8)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create a new shared search with a short ID
    pub async fn create(
        &self,
        search: &NewSharedSearch,
    ) -> Result<SharedSearch, SharedSearchRepositoryError> {
        // Try up to 5 times to generate a unique ID
        for _ in 0..5 {
            let id = Self::generate_short_id();

            let result = sqlx::query_as::<_, SharedSearch>(
                r#"
                INSERT INTO shared_searches (id, query, query_mode, time_range_type, time_range_preset, time_range_start, time_range_end)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (id) DO NOTHING
                RETURNING *
                "#,
            )
            .bind(&id)
            .bind(&search.query)
            .bind(&search.query_mode)
            .bind(&search.time_range_type)
            .bind(&search.time_range_preset)
            .bind(&search.time_range_start)
            .bind(&search.time_range_end)
            .fetch_optional(&self.pool)
            .await?;

            if let Some(shared) = result {
                return Ok(shared);
            }
        }

        Err(SharedSearchRepositoryError::DatabaseError(
            sqlx::Error::Protocol("Failed to generate unique ID after 5 attempts".to_string()),
        ))
    }

    /// Find a shared search by ID and increment access count
    pub async fn find_by_id(&self, id: &str) -> Result<SharedSearch, SharedSearchRepositoryError> {
        // Update access count and last accessed time, then return
        let result = sqlx::query_as::<_, SharedSearch>(
            r#"
            UPDATE shared_searches 
            SET access_count = access_count + 1, last_accessed_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SharedSearchRepositoryError::NotFound(id.to_string()))?;

        Ok(result)
    }

    /// Find a shared search by ID without incrementing access count (for preview)
    pub async fn peek(&self, id: &str) -> Result<SharedSearch, SharedSearchRepositoryError> {
        let result =
            sqlx::query_as::<_, SharedSearch>(r#"SELECT * FROM shared_searches WHERE id = $1"#)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| SharedSearchRepositoryError::NotFound(id.to_string()))?;

        Ok(result)
    }

    /// Delete old unused shared searches (cleanup)
    pub async fn cleanup_old(&self, days: i32) -> Result<u64, SharedSearchRepositoryError> {
        let result = sqlx::query(
            r#"
            DELETE FROM shared_searches 
            WHERE created_at < NOW() - ($1 || ' days')::INTERVAL 
            AND access_count = 0
            "#,
        )
        .bind(days)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
