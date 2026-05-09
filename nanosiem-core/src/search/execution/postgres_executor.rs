// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL query executor
//!
//! This module provides the PostgreSQL implementation of the SqlExecutor trait.

use sqlx::PgPool;
use tracing::debug;

use super::traits::SqlExecutor;
use crate::search::evaluator::helpers::pg_row_to_json;
use crate::search::SearchError;

/// PostgreSQL query executor
#[derive(Clone)]
pub struct PostgresExecutor {
    pool: PgPool,
}

impl PostgresExecutor {
    /// Create a new PostgreSQL executor
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SqlExecutor for PostgresExecutor {
    async fn execute_sql(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        // Wrap the query to add limit/offset and get total count
        let count_sql = format!("SELECT COUNT(*) as total FROM ({}) as subquery", sql);
        let paginated_sql = format!(
            "SELECT * FROM ({}) as subquery LIMIT {} OFFSET {}",
            sql, limit, offset
        );

        debug!("Executing PostgreSQL count query: {}", count_sql);
        debug!("Executing PostgreSQL paginated query: {}", paginated_sql);

        // Execute count query
        let total_count: i64 = sqlx::query_scalar(&count_sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        // Execute main query and convert rows to JSON
        let rows = sqlx::query(&paginated_sql).fetch_all(&self.pool).await?;

        let results: Vec<serde_json::Value> = rows.iter().map(|row| pg_row_to_json(row)).collect();

        Ok((results, total_count as u64))
    }

    async fn execute_sql_to_json(&self, sql: &str) -> Result<Vec<serde_json::Value>, SearchError> {
        debug!("Executing PostgreSQL query: {}", sql);

        let rows = sqlx::query(sql).fetch_all(&self.pool).await?;

        let results: Vec<serde_json::Value> = rows.iter().map(|row| pg_row_to_json(row)).collect();

        Ok(results)
    }
}
