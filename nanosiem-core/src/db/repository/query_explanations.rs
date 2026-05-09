// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository for query explanation cache
//!
//! Stores AI-generated explanations for queries so they can be
//! retrieved when users share query URLs.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;

/// Errors that can occur in the query explanation repository
#[derive(Debug, Error)]
pub enum QueryExplanationError {
    #[error("Query explanation not found: {0}")]
    NotFound(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// A cached query explanation
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QueryExplanation {
    pub query_hash: String,
    pub query: String,
    pub query_mode: String,
    pub natural_language_prompt: Option<String>,
    pub explanation: Option<String>,
    pub reasoning_steps: Option<sqlx::types::Json<Vec<ReasoningStepRow>>>,
    pub fields_used: Option<sqlx::types::Json<Vec<String>>>,
    pub generated_sql: Option<String>,
    pub complexity: Option<String>,
    pub suggested_time_range: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub access_count: i32,
    pub last_accessed_at: Option<DateTime<Utc>>,
}

/// Reasoning step stored in JSON
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReasoningStepRow {
    pub step_type: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Data for creating a new query explanation
#[derive(Debug, Clone)]
pub struct NewQueryExplanation {
    pub query: String,
    pub query_mode: String,
    pub natural_language_prompt: Option<String>,
    pub explanation: Option<String>,
    pub reasoning_steps: Option<Vec<ReasoningStepRow>>,
    pub fields_used: Option<Vec<String>>,
    pub generated_sql: Option<String>,
    pub complexity: Option<String>,
    pub suggested_time_range: Option<String>,
}

/// Repository for query explanation operations
pub struct QueryExplanationRepository {
    pool: PgPool,
}

impl QueryExplanationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Compute the hash for a query (normalized: lowercase, trimmed)
    pub fn compute_query_hash(query: &str) -> String {
        let normalized = query.trim().to_lowercase();
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Store a query explanation (upsert - updates if exists)
    pub async fn upsert(
        &self,
        data: &NewQueryExplanation,
    ) -> Result<QueryExplanation, QueryExplanationError> {
        let query_hash = Self::compute_query_hash(&data.query);

        let reasoning_steps_json = data
            .reasoning_steps
            .as_ref()
            .map(|steps| serde_json::to_value(steps).unwrap_or(serde_json::Value::Null));

        let fields_used_json = data
            .fields_used
            .as_ref()
            .map(|fields| serde_json::to_value(fields).unwrap_or(serde_json::Value::Null));

        let row = sqlx::query_as::<_, QueryExplanation>(
            r#"
            INSERT INTO query_explanations (
                query_hash, query, query_mode, natural_language_prompt,
                explanation, reasoning_steps, fields_used, generated_sql,
                complexity, suggested_time_range
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (query_hash) DO UPDATE SET
                explanation = COALESCE(EXCLUDED.explanation, query_explanations.explanation),
                reasoning_steps = COALESCE(EXCLUDED.reasoning_steps, query_explanations.reasoning_steps),
                fields_used = COALESCE(EXCLUDED.fields_used, query_explanations.fields_used),
                generated_sql = COALESCE(EXCLUDED.generated_sql, query_explanations.generated_sql),
                complexity = COALESCE(EXCLUDED.complexity, query_explanations.complexity),
                suggested_time_range = COALESCE(EXCLUDED.suggested_time_range, query_explanations.suggested_time_range),
                natural_language_prompt = COALESCE(EXCLUDED.natural_language_prompt, query_explanations.natural_language_prompt),
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(&query_hash)
        .bind(&data.query)
        .bind(&data.query_mode)
        .bind(&data.natural_language_prompt)
        .bind(&data.explanation)
        .bind(reasoning_steps_json)
        .bind(fields_used_json)
        .bind(&data.generated_sql)
        .bind(&data.complexity)
        .bind(&data.suggested_time_range)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Find explanation by query hash
    pub async fn find_by_hash(
        &self,
        query_hash: &str,
    ) -> Result<QueryExplanation, QueryExplanationError> {
        let row = sqlx::query_as::<_, QueryExplanation>(
            r#"
            UPDATE query_explanations
            SET access_count = access_count + 1,
                last_accessed_at = NOW()
            WHERE query_hash = $1
            RETURNING *
            "#,
        )
        .bind(query_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| QueryExplanationError::NotFound(query_hash.to_string()))?;

        Ok(row)
    }

    /// Find explanation by query text
    pub async fn find_by_query(
        &self,
        query: &str,
    ) -> Result<QueryExplanation, QueryExplanationError> {
        let query_hash = Self::compute_query_hash(query);
        self.find_by_hash(&query_hash).await
    }

    /// Delete old explanations (for cleanup)
    pub async fn delete_old(&self, days: i32) -> Result<u64, QueryExplanationError> {
        let result = sqlx::query(
            r#"
            DELETE FROM query_explanations
            WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
              AND (last_accessed_at IS NULL OR last_accessed_at < NOW() - ($1 || ' days')::INTERVAL)
            "#,
        )
        .bind(days)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
