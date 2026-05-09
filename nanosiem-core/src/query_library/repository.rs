// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query Library Repository

use sqlx::{FromRow, PgPool, Row};
use tracing::{debug, instrument, warn};

use super::types::*;

/// Internal row type for database queries
#[derive(Debug, FromRow)]
struct LibraryQueryRow {
    id: i32,
    name: String,
    description: String,
    query: String,
    category: String,
    tags: Vec<String>,
    difficulty: String,
    use_case: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    is_builtin: bool,
}

impl LibraryQueryRow {
    fn into_library_query(self) -> LibraryQuery {
        LibraryQuery {
            id: self.id,
            name: self.name,
            description: self.description,
            query: self.query,
            category: self.category,
            tags: self.tags,
            difficulty: self.difficulty.parse().unwrap_or(QueryDifficulty::Beginner),
            use_case: self.use_case,
            created_at: self.created_at,
            updated_at: self.updated_at,
            is_builtin: self.is_builtin,
        }
    }
}

/// Repository for query library operations
#[derive(Clone)]
pub struct QueryLibraryRepository {
    pool: PgPool,
    table_verified: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl QueryLibraryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            table_verified: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Check if the query_library table exists
    async fn table_exists(&self) -> bool {
        if self
            .table_verified
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return true;
        }

        let result = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'query_library')"
        )
        .fetch_one(&self.pool)
        .await;

        let exists = result.unwrap_or(false);
        if exists {
            self.table_verified
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        exists
    }

    /// List all queries with optional filtering
    #[instrument(skip(self))]
    pub async fn list(&self, filter: &LibraryFilter) -> Result<Vec<LibraryQuery>, sqlx::Error> {
        if !self.table_exists().await {
            warn!("query_library table does not exist");
            return Ok(Vec::new());
        }

        let rows: Vec<LibraryQueryRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, query, category, tags, difficulty, use_case, created_at, updated_at, is_builtin
            FROM query_library
            WHERE ($1::TEXT IS NULL OR category = $1)
              AND ($2::TEXT IS NULL OR difficulty = $2)
              AND ($3::TEXT IS NULL OR use_case = $3)
              AND ($4::TEXT IS NULL OR $4 = ANY(tags))
              AND ($5::TEXT IS NULL OR name ILIKE '%' || $5 || '%' OR description ILIKE '%' || $5 || '%' OR query ILIKE '%' || $5 || '%')
              AND ($6::BOOLEAN IS NULL OR is_builtin = $6)
            ORDER BY category, difficulty, name
            "#,
        )
        .bind(filter.category.as_deref())
        .bind(filter.difficulty.map(|d| d.to_string()))
        .bind(filter.use_case.as_deref())
        .bind(filter.tag.as_deref())
        .bind(filter.search.as_deref())
        .bind(filter.builtin_only)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_library_query()).collect())
    }

    /// Get a query by ID
    #[instrument(skip(self))]
    pub async fn get(&self, id: i32) -> Result<Option<LibraryQuery>, sqlx::Error> {
        if !self.table_exists().await {
            return Ok(None);
        }

        let row: Option<LibraryQueryRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, query, category, tags, difficulty, use_case, created_at, updated_at, is_builtin
            FROM query_library
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_library_query()))
    }

    /// Get a query by name
    #[instrument(skip(self))]
    pub async fn get_by_name(&self, name: &str) -> Result<Option<LibraryQuery>, sqlx::Error> {
        if !self.table_exists().await {
            return Ok(None);
        }

        let row: Option<LibraryQueryRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, query, category, tags, difficulty, use_case, created_at, updated_at, is_builtin
            FROM query_library
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_library_query()))
    }

    /// Create a new query
    #[instrument(skip(self))]
    pub async fn create(&self, query: &NewLibraryQuery) -> Result<LibraryQuery, sqlx::Error> {
        if !self.table_exists().await {
            return Err(sqlx::Error::Protocol(
                "query_library table does not exist".to_string(),
            ));
        }

        let row: LibraryQueryRow = sqlx::query_as(
            r#"
            INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case, is_builtin)
            VALUES ($1, $2, $3, $4, $5, $6, $7, false)
            RETURNING id, name, description, query, category, tags, difficulty, use_case, created_at, updated_at, is_builtin
            "#,
        )
        .bind(&query.name)
        .bind(&query.description)
        .bind(&query.query)
        .bind(&query.category)
        .bind(&query.tags)
        .bind(query.difficulty.to_string())
        .bind(&query.use_case)
        .fetch_one(&self.pool)
        .await?;

        debug!("Created query library entry: {}", query.name);
        Ok(row.into_library_query())
    }

    /// Delete a query (only non-builtin)
    #[instrument(skip(self))]
    pub async fn delete(&self, id: i32) -> Result<bool, sqlx::Error> {
        if !self.table_exists().await {
            return Ok(false);
        }

        let result = sqlx::query("DELETE FROM query_library WHERE id = $1 AND is_builtin = false")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all categories with counts
    #[instrument(skip(self))]
    pub async fn get_categories(&self) -> Result<Vec<CategoryCount>, sqlx::Error> {
        if !self.table_exists().await {
            return Ok(Vec::new());
        }

        let rows = sqlx::query(
            r#"
            SELECT category, COUNT(*) as count
            FROM query_library
            GROUP BY category
            ORDER BY count DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| CategoryCount {
                category: r.get("category"),
                count: r.get("count"),
            })
            .collect())
    }

    /// Get all unique tags
    #[instrument(skip(self))]
    pub async fn get_tags(&self) -> Result<Vec<String>, sqlx::Error> {
        if !self.table_exists().await {
            return Ok(Vec::new());
        }

        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT unnest(tags) as tag
            FROM query_library
            ORDER BY tag
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(t,)| t).collect())
    }
}
