// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feedback Repository
//!
//! Stores and retrieves user feedback from PostgreSQL.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum FeedbackError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Feedback not found: {0}")]
    NotFound(Uuid),
}

/// A feedback entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Feedback {
    pub id: Uuid,
    pub user_id: Uuid,
    pub category: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub admin_notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Feedback with user name for admin list view
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct FeedbackWithUser {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub category: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub admin_notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create new feedback
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateFeedbackRequest {
    pub category: String,
    pub title: String,
    pub description: String,
}

/// Request to update feedback (admin only)
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateFeedbackRequest {
    pub status: Option<String>,
    pub admin_notes: Option<String>,
}

/// Query parameters for listing feedback
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FeedbackQuery {
    pub category: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Feedback repository
pub struct FeedbackRepository {
    pool: PgPool,
}

impl FeedbackRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create new feedback
    pub async fn create(
        &self,
        user_id: Uuid,
        request: &CreateFeedbackRequest,
    ) -> Result<Feedback, FeedbackError> {
        let result = sqlx::query_as::<_, Feedback>(
            r#"
            INSERT INTO feedback (user_id, category, title, description)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(&request.category)
        .bind(&request.title)
        .bind(&request.description)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get feedback by ID
    pub async fn get(&self, id: Uuid) -> Result<Feedback, FeedbackError> {
        let result = sqlx::query_as::<_, Feedback>(
            r#"
            SELECT * FROM feedback WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FeedbackError::NotFound(id))?;

        Ok(result)
    }

    /// List all feedback with optional filters (for admins)
    pub async fn list(
        &self,
        query: &FeedbackQuery,
    ) -> Result<(Vec<FeedbackWithUser>, i64), FeedbackError> {
        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0);

        // Build dynamic query based on filters
        let mut sql = String::from(
            r#"
            SELECT f.*, u.name as user_name, u.email as user_email
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.id
            WHERE 1=1
            "#,
        );
        let mut count_sql = String::from(
            r#"
            SELECT COUNT(*) FROM feedback f WHERE 1=1
            "#,
        );

        if query.category.is_some() {
            sql.push_str(" AND f.category = $3");
            count_sql.push_str(" AND f.category = $1");
        }
        if query.status.is_some() {
            let param_num = if query.category.is_some() { 4 } else { 3 };
            let count_param = if query.category.is_some() { 2 } else { 1 };
            sql.push_str(&format!(" AND f.status = ${}", param_num));
            count_sql.push_str(&format!(" AND f.status = ${}", count_param));
        }

        sql.push_str(" ORDER BY f.created_at DESC LIMIT $1 OFFSET $2");

        // Execute queries based on filters
        let (entries, total): (Vec<FeedbackWithUser>, i64) = match (&query.category, &query.status)
        {
            (Some(cat), Some(status)) => {
                let entries = sqlx::query_as::<_, FeedbackWithUser>(&sql)
                    .bind(limit)
                    .bind(offset)
                    .bind(cat)
                    .bind(status)
                    .fetch_all(&self.pool)
                    .await?;
                let total: i64 = sqlx::query_scalar(&count_sql)
                    .bind(cat)
                    .bind(status)
                    .fetch_one(&self.pool)
                    .await?;
                (entries, total)
            }
            (Some(cat), None) => {
                let entries = sqlx::query_as::<_, FeedbackWithUser>(&sql)
                    .bind(limit)
                    .bind(offset)
                    .bind(cat)
                    .fetch_all(&self.pool)
                    .await?;
                let total: i64 = sqlx::query_scalar(&count_sql)
                    .bind(cat)
                    .fetch_one(&self.pool)
                    .await?;
                (entries, total)
            }
            (None, Some(status)) => {
                let sql = sql.replace("$3", "$3").replace("$4", "$3");
                let entries = sqlx::query_as::<_, FeedbackWithUser>(&sql)
                    .bind(limit)
                    .bind(offset)
                    .bind(status)
                    .fetch_all(&self.pool)
                    .await?;
                let total: i64 = sqlx::query_scalar(&count_sql)
                    .bind(status)
                    .fetch_one(&self.pool)
                    .await?;
                (entries, total)
            }
            (None, None) => {
                let sql = r#"
                        SELECT f.*, u.name as user_name, u.email as user_email
                        FROM feedback f
                        LEFT JOIN users u ON f.user_id = u.id
                        ORDER BY f.created_at DESC
                        LIMIT $1 OFFSET $2
                    "#;
                let entries = sqlx::query_as::<_, FeedbackWithUser>(sql)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await?;
                let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feedback")
                    .fetch_one(&self.pool)
                    .await?;
                (entries, total)
            }
        };

        Ok((entries, total))
    }

    /// List feedback for a specific user
    pub async fn list_by_user(
        &self,
        user_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<Feedback>, FeedbackError> {
        let limit = limit.unwrap_or(50);

        let entries = sqlx::query_as::<_, Feedback>(
            r#"
            SELECT * FROM feedback
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    /// Update feedback (admin: status and notes)
    pub async fn update(
        &self,
        id: Uuid,
        request: &UpdateFeedbackRequest,
    ) -> Result<Feedback, FeedbackError> {
        // First check if it exists
        self.get(id).await?;

        let result = sqlx::query_as::<_, Feedback>(
            r#"
            UPDATE feedback
            SET status = COALESCE($2, status),
                admin_notes = COALESCE($3, admin_notes)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&request.status)
        .bind(&request.admin_notes)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Delete feedback
    pub async fn delete(&self, id: Uuid) -> Result<bool, FeedbackError> {
        let result = sqlx::query(
            r#"
            DELETE FROM feedback WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
