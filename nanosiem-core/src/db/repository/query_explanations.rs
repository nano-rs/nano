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

    /// Compute the cache key for a query (normalized: lowercase, trimmed),
    /// bound to the caller's effective source-scope fingerprint (NAN-2049).
    ///
    /// The explanation record carries the generated ClickHouse SQL, which is
    /// scope-specific (it embeds the caller's source-scope exclusion). Hashing
    /// the query text ALONE made the cache global, so a source-restricted
    /// principal could retrieve — and see the generated SQL of — an entry
    /// cached under a broader-scope principal. Folding the scope fingerprint
    /// into the key partitions the cache by effective visibility: callers with
    /// the *same* scope still collide (so shared-URL explanations keep working
    /// for them), while a differently-scoped caller gets a distinct key and
    /// recomputes its own scope-correct entry. `scope_fingerprint` is a stable
    /// string derived from the caller's sorted effective deny-set; pass `""`
    /// for the unrestricted (empty deny-set) scope.
    pub fn compute_query_hash(query: &str, scope_fingerprint: &str) -> String {
        let normalized = query.trim().to_lowercase();
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        // Domain separator so (query, scope) can't be reassociated into a
        // different (query', scope') pair that hashes the same.
        hasher.update([0u8]);
        hasher.update(scope_fingerprint.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Store a query explanation (upsert - updates if exists), bound to the
    /// caller's effective source-scope fingerprint (NAN-2049 — see
    /// [`compute_query_hash`](Self::compute_query_hash)).
    pub async fn upsert(
        &self,
        data: &NewQueryExplanation,
        scope_fingerprint: &str,
    ) -> Result<QueryExplanation, QueryExplanationError> {
        let query_hash = Self::compute_query_hash(&data.query, scope_fingerprint);

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

    /// Find explanation by query text, scoped to the caller's effective
    /// source-scope fingerprint (NAN-2049 — see
    /// [`compute_query_hash`](Self::compute_query_hash)). A caller only ever
    /// resolves an entry stored under its own effective scope.
    pub async fn find_by_query(
        &self,
        query: &str,
        scope_fingerprint: &str,
    ) -> Result<QueryExplanation, QueryExplanationError> {
        let query_hash = Self::compute_query_hash(query, scope_fingerprint);
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

#[cfg(test)]
mod tests {
    use super::QueryExplanationRepository as R;

    #[test]
    fn hash_is_stable_for_same_query_and_scope() {
        // Deterministic: identical (query, scope) always produce the same key,
        // so same-scope callers still share the cached entry (shared URLs work).
        assert_eq!(
            R::compute_query_hash("error | limit 1", "sysmon\nwineventlog"),
            R::compute_query_hash("error | limit 1", "sysmon\nwineventlog"),
        );
    }

    #[test]
    fn hash_is_normalized_on_query_text() {
        // Trim + lowercase normalization is unchanged by scope binding.
        assert_eq!(
            R::compute_query_hash("  ERROR | LIMIT 1 ", ""),
            R::compute_query_hash("error | limit 1", ""),
        );
    }

    #[test]
    fn different_scope_partitions_the_cache_key() {
        // NAN-2049: the SAME query under DIFFERENT effective scopes must hash to
        // DIFFERENT keys, so a source-restricted principal can never resolve an
        // entry stored under a broader-scope principal (and vice-versa).
        let unrestricted = R::compute_query_hash("error | limit 1", "");
        let restricted = R::compute_query_hash("error | limit 1", "restricted_source");
        let other_scope = R::compute_query_hash("error | limit 1", "sysmon");
        assert_ne!(unrestricted, restricted);
        assert_ne!(unrestricted, other_scope);
        assert_ne!(restricted, other_scope);
    }

    #[test]
    fn scope_binding_cannot_collide_with_a_longer_query() {
        // The domain separator prevents a (query, scope) pair from being
        // reassociated into a different (query', scope') that hashes the same —
        // e.g. query "a" + scope "b" must not equal query "a\0b" + scope "".
        assert_ne!(
            R::compute_query_hash("a", "b"),
            R::compute_query_hash("a\u{0}b", ""),
        );
    }
}
